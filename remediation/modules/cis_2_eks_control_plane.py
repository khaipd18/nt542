import boto3
import time
import json
import sys
from botocore.exceptions import ClientError

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def wait_for_cluster_active(eks_client, cluster_name):
    print(f"   {YELLOW}⏳ Đang chờ cụm EKS chuyển sang trạng thái ACTIVE...{RESET}")
    while True:
        try:
            status = eks_client.describe_cluster(name=cluster_name)['cluster']['status']
            if status == 'ACTIVE':
                break
            time.sleep(10)
        except Exception as e:
            print(f"   {RED}✖ Lỗi khi kiểm tra trạng thái: {e}{RESET}")
            break

# ĐÃ SỬA: Bổ sung thêm tham số addon_name
def wait_for_eks_update(eks_client, cluster_name, update_id, action_desc, addon_name=None):
    print(f"   {YELLOW}⏳ Đang chờ AWS EKS áp dụng [{action_desc}] (Khoảng 1-3 phút)...{RESET}")
    while True:
        try:
            # Phân biệt rạch ròi giữa kiểm tra Cluster Update và Addon Update
            if addon_name:
                response = eks_client.describe_update(name=cluster_name, updateId=update_id, addonName=addon_name)
            else:
                response = eks_client.describe_update(name=cluster_name, updateId=update_id)
                
            status = response['update']['status']
            if status == 'Successful':
                print(f"   {GREEN}✔ [{action_desc}] hoàn tất thành công!{RESET}")
                break
            elif status in ['Failed', 'Cancelled']:
                errors = response['update'].get('errors', [])
                print(f"   {RED}✖ [{action_desc}] thất bại! Chi tiết AWS: {errors}{RESET}")
                break
            time.sleep(15)
        except Exception as e:
            print(f"   {RED}✖ Lỗi khi theo dõi cập nhật: {e}{RESET}")
            break

def remediate_eks_core(cluster_name, region):
    print(f"{BLUE}======================================================================{RESET}")
    print(f"{BLUE}  AWS EKS REMEDIATION - TỰ ĐỘNG VÁ LỖI MỤC 2 & 5 (BẢN HOÀN MỸ)  {RESET}")
    print(f"{BLUE}======================================================================{RESET}")
    
    eks_client = boto3.client('eks', region_name=region)
    kms_client = boto3.client('kms', region_name=region)

    wait_for_cluster_active(eks_client, cluster_name)
    cluster_info = eks_client.describe_cluster(name=cluster_name)['cluster']

    # ---------------------------------------------------------
    # [1A] VÁ LỖI ENDPOINT (CIS 5.4.1 & 5.4.2)
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[1A] Đang đóng Public Endpoint và mở Private Endpoint...{RESET}")
    vpc_config = cluster_info['resourcesVpcConfig']
    is_pub = vpc_config.get('endpointPublicAccess')
    is_priv = vpc_config.get('endpointPrivateAccess')
    
    if is_pub is False and is_priv is True:
        print(f"   {GREEN}✔ Endpoint đã đạt chuẩn (Public=False, Private=True), bỏ qua.{RESET}")
    else:
        try:
            res_vpc = eks_client.update_cluster_config(
                name=cluster_name,
                resourcesVpcConfig={'endpointPublicAccess': False, 'endpointPrivateAccess': True}
            )
            wait_for_eks_update(eks_client, cluster_name, res_vpc['update']['id'], "Cập nhật Endpoint")
        except ClientError as e:
            print(f"   {RED}✖ Lỗi: {e}{RESET}")

    # ---------------------------------------------------------
    # [1B] VÁ LỖI LOGGING (CIS 2.1.1)
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[1B] Đang kích hoạt toàn bộ Audit Logs cho Control Plane...{RESET}")
    enabled_logs = set()
    for log_setup in cluster_info.get('logging', {}).get('clusterLogging', []):
        if log_setup.get('enabled', False):
            enabled_logs.update(log_setup.get('types', []))
            
    if {'api', 'audit', 'authenticator', 'controllerManager', 'scheduler'}.issubset(enabled_logs):
        print(f"   {GREEN}✔ Cụm đã bật đủ 5 loại Logs từ trước, bỏ qua.{RESET}")
    else:
        wait_for_cluster_active(eks_client, cluster_name)
        try:
            res_log = eks_client.update_cluster_config(
                name=cluster_name,
                logging={'clusterLogging': [{'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'], 'enabled': True}]}
            )
            wait_for_eks_update(eks_client, cluster_name, res_log['update']['id'], "Bật Logs")
        except ClientError as e:
            print(f"   {RED}✖ Lỗi: {e}{RESET}")

    # ---------------------------------------------------------
    # [2] VÁ LỖI KMS ENCRYPTION (CIS 5.3.1)
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[2] Mã hóa Kubernetes Secrets tĩnh bằng AWS KMS...{RESET}")
    is_encrypted = any('secrets' in conf.get('resources', []) for conf in cluster_info.get('encryptionConfig', []))
    
    if is_encrypted:
        print(f"   {GREEN}✔ Secrets đã được mã hóa bằng KMS từ trước, bỏ qua.{RESET}")
    else:
        wait_for_cluster_active(eks_client, cluster_name)
        try:
            print(f"   {YELLOW}   -> Đang tạo chìa khóa KMS mới...{RESET}")
            kms_res = kms_client.create_key(Description="EKS Secrets Encryption Key")
            key_arn = kms_res['KeyMetadata']['Arn']
            
            print(f"   {YELLOW}   -> Đang nhúng KMS Key vào EKS Cluster...{RESET}")
            enc_res = eks_client.associate_encryption_config(
                clusterName=cluster_name,
                encryptionConfig=[{'resources': ['secrets'], 'provider': {'keyArn': key_arn}}]
            )
            wait_for_eks_update(eks_client, cluster_name, enc_res['update']['id'], "Mã hóa KMS")
        except ClientError as e:
            print(f"   {RED}✖ Lỗi: {e}{RESET}")

    # ---------------------------------------------------------
    # [3] VÁ LỖI VPC CNI NETWORK POLICIES (CIS 5.4.4)
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[3] Kích hoạt Network Policies cho VPC CNI Addon...{RESET}")
    wait_for_cluster_active(eks_client, cluster_name)
    
    schemas_to_try = [
        {"enableNetworkPolicy": "true"},                
        {"env": {"ENABLE_NETWORK_POLICY": "true"}}      
    ]
    
    success = False
    for i, schema_payload in enumerate(schemas_to_try):
        print(f"   {YELLOW}   -> Đang thử áp dụng Schema định dạng {i+1}...{RESET}")
        try:
            addon_res = eks_client.update_addon(
                clusterName=cluster_name,
                addonName='vpc-cni',
                configurationValues=json.dumps(schema_payload),
                resolveConflicts='OVERWRITE'
            )
            # ĐÃ SỬA: Truyền thêm addon_name='vpc-cni' vào hàm wait
            wait_for_eks_update(eks_client, cluster_name, addon_res['update']['id'], "Cập nhật Addon CNI", addon_name='vpc-cni')
            success = True
            break
        except ClientError as e:
            error_msg = str(e)
            if 'ConfigurationValues is same' in error_msg or 'No changes needed' in error_msg:
                 print(f"   {GREEN}✔ Addon VPC CNI đã bật Network Policies.{RESET}")
                 success = True
                 break
            elif 'is not defined in the schema' in error_msg or 'InvalidParameterException' in error_msg:
                 print(f"   {YELLOW}      (Schema {i+1} bị AWS từ chối, đang chuyển sang cách tiếp theo...){RESET}")
                 continue
            else:
                 print(f"   {RED}✖ Lỗi không xác định: {e}{RESET}")
                 break
                 
    if not success:
        print(f"   {RED}✖ Bất lực! Phiên bản VPC CNI hiện tại không hỗ trợ API. Vui lòng nâng cấp Addon.{RESET}")

    print(f"\n{BLUE}================ HOÀN TẤT VÁ LỖI HẠ TẦNG ================{RESET}")

if __name__ == "__main__":
    CLUSTER_NAME = "ctf-eks-arena" 
    REGION_CODE = "ap-southeast-1"
    remediate_eks_core(CLUSTER_NAME, REGION_CODE)