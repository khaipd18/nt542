import boto3
from botocore.exceptions import ClientError
import sys
import json

# ==========================================
# CẤU HÌNH MÀU SẮC CHO TERMINAL
# ==========================================
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def audit_cis_eks_benchmark(cluster_name, region):
    print(f"{BLUE}======================================================================{RESET}")
    print(f"{BLUE}  AWS EKS AUDIT - CIS BENCHMARK v1.8.0 (CONTROL PLANE & MANAGED SVCS) {RESET}")
    print(f"{BLUE}======================================================================{RESET}")
    print(f"Đang phân tích API cụm: {YELLOW}{cluster_name}{RESET} tại Region: {YELLOW}{region}{RESET}...\n")

    eks_client = boto3.client('eks', region_name=region)

    # Lấy thông tin cấu hình toàn cụm EKS
    try:
        cluster = eks_client.describe_cluster(name=cluster_name)['cluster']
    except ClientError as e:
        print(f"{RED}[LỖI] Không thể kết nối tới cụm EKS. Chi tiết: {e}{RESET}")
        sys.exit(1)

    # ---------------------------------------------------------
    # KIỂM TRA LỖI 7 | CIS 2.1.1
    # ---------------------------------------------------------
    print(f"{YELLOW}[+] CIS 2.1.1: Ensure that the cluster control plane logging is enabled{RESET}")
    required_logs = {'api', 'audit', 'authenticator', 'controllerManager', 'scheduler'}
    enabled_logs = set()
    
    for log_setup in cluster.get('logging', {}).get('clusterLogging', []):
        if log_setup.get('enabled', False):
            for l_type in log_setup.get('types', []):
                enabled_logs.add(l_type)
                
    missing_logs = required_logs - enabled_logs
    if not missing_logs:
        print(f" └─ {GREEN}[PASS] Toàn bộ 5 loại log Control Plane đã được bật.{RESET}")
    else:
        print(f" └─ {RED}[FAIL] Cụm đang bị tắt các log: {', '.join(missing_logs)}. Vi phạm tiêu chuẩn giám sát.{RESET}")

    # ---------------------------------------------------------
    # KIỂM TRA LỖI 8 | CIS 5.3.1
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[+] CIS 5.3.1: Ensure that Kubernetes Secrets are encrypted using AWS Key Management Service (KMS){RESET}")
    encryption_config = cluster.get('encryptionConfig', [])
    
    is_encrypted = False
    used_key_arn = None
    
    for conf in encryption_config:
        # Lấy giá trị keyArn từ provider
        key_arn = conf.get('provider', {}).get('keyArn')
        
        # Bắt buộc phải thỏa mãn 2 điều kiện: mã hóa 'secrets' VÀ có KMS keyArn
        if 'secrets' in conf.get('resources', []) and key_arn:
            is_encrypted = True
            used_key_arn = key_arn
            break # Tìm thấy cấu hình chuẩn thì thoát vòng lặp
            
    if is_encrypted:
        print(f" └─ {GREEN}[PASS] Kubernetes Secrets đã được mã hóa bằng KMS (Key ARN: {used_key_arn}).{RESET}")
    else:
        print(f" └─ {RED}[FAIL] Không tìm thấy KMS Key ARN cho tài nguyên 'secrets' trong 'encryptionConfig'. Dữ liệu nhạy cảm chưa được bảo vệ bằng CMK.{RESET}")

    # ---------------------------------------------------------
    # KIỂM TRA LỖI 5 | CIS 5.4.1
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[+] CIS 5.4.1: Ensure that the cluster endpoint restricts public access from the internet{RESET}")
    vpc_config = cluster.get('resourcesVpcConfig', {})
    
    is_private = vpc_config.get('endpointPrivateAccess', False)
    is_public = vpc_config.get('endpointPublicAccess', False)
    public_cidrs = vpc_config.get('publicAccessCidrs', [])

    if not is_private:
        print(f" └─ {RED}[FAIL] Endpoint Private Access đang TẮT. Mục 5.4.1 yêu cầu bắt buộc phải BẬT tính năng này.{RESET}")
    elif is_public and "0.0.0.0/0" in public_cidrs:
        print(f" └─ {RED}[FAIL] Endpoint Public Access đang BẬT và CIDR là 0.0.0.0/0. Control Plane phơi nhiễm toàn cầu.{RESET}")
    else:
        print(f" └─ {GREEN}[PASS] Private Endpoint đã BẬT và Public Endpoint đã được giới hạn CIDR an toàn (hoặc tắt hoàn toàn).{RESET}")

    # ---------------------------------------------------------
    # KIỂM TRA LỖI 6 | CIS 5.4.2
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[+] CIS 5.4.2: Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled{RESET}")
    
    is_private = vpc_config.get('endpointPrivateAccess', False)
    is_public = vpc_config.get('endpointPublicAccess', True) # Lấy giá trị Public Access

    # Phải thỏa mãn đồng thời: Private BẬT và Public TẮT
    if is_private and not is_public:
        print(f" └─ {GREEN}[PASS] Endpoint Private Access đã BẬT và Public Access đã TẮT an toàn.{RESET}")
    else:
        print(f" └─ {RED}[FAIL] Cấu hình không đạt. Mục 5.4.2 yêu cầu Private Access BẬT (hiện tại: {is_private}) VÀ Public Access TẮT (hiện tại: {is_public}).{RESET}")

    # ---------------------------------------------------------
    # KIỂM TRA LỖI 9 | CIS 4.3.1 & 5.4.4
    # ---------------------------------------------------------
    print(f"\n{YELLOW}[+] CIS 5.4.4: Ensure that the VPC CNI plugin is configured to support Network Policies{RESET}")
    try:
        addon = eks_client.describe_addon(clusterName=cluster_name, addonName='vpc-cni')['addon']
        config_str = addon.get('configurationValues', '{}')
        config_json = json.loads(config_str)
        
        net_policy_enabled = config_json.get('enableNetworkPolicy', "false")
        
        if str(net_policy_enabled).lower() == "true":
            print(f" └─ {GREEN}[PASS] Tham số 'enableNetworkPolicy' đã được bật cho VPC CNI Addon.{RESET}")
        else:
            print(f" └─ {RED}[FAIL] Tham số 'enableNetworkPolicy' bị ép tắt ('false'). Cụm không có khả năng thực thi NetworkPolicy.{RESET}")
            
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f" └─ {YELLOW}[WARN] Addon 'vpc-cni' không được quản lý qua EKS Addons API. Cần kiểm tra DaemonSet thủ công theo chuẩn CIS 4.3.1.{RESET}")
        else:
            print(f" └─ {RED}[LỖI] API từ chối đọc cấu hình Addon vpc-cni: {e}{RESET}")

    print(f"\n{BLUE}================ HOÀN TẤT QUÉT BỀ MẶT CLUSTER ================{RESET}")


if __name__ == "__main__":
    # Tên cụm và Region khớp với file main.tf của bạn
    CLUSTER_NAME = "ctf-eks-arena" 
    REGION_CODE = "ap-southeast-1"
    
    audit_cis_eks_benchmark(CLUSTER_NAME, REGION_CODE)