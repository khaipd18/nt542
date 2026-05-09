import boto3
import time

# ==========================================
# CẤU HÌNH MÀU SẮC CHO TERMINAL TRỰC QUAN
# ==========================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_success(msg):
    print(f"{Colors.GREEN}  [🔧] FIXED:{Colors.ENDC} {msg}")

def print_manual(cis_id, msg, instructions):
    print(f"{Colors.WARNING}{Colors.BOLD}  [⚠️] MANUAL ACTION CẦN THIẾT ({cis_id}):{Colors.ENDC} {msg}")
    print(f"       {Colors.BLUE}↳ Hướng dẫn khắc phục:{Colors.ENDC}")
    if isinstance(instructions, list):
        for inst in instructions:
            print(f"         - {inst}")
    else:
        print(f"         - {instructions}")

def print_error(msg):
    print(f"  {Colors.FAIL}[!] LỖI THỰC THI:{Colors.ENDC} {msg}")

# ==========================================
# LOGIC REMEDIATION PHẦN 1 (CIS MỤC 5)
# ==========================================
def remediate_section_1_infrastructure(cluster_name, repo_name, node_role_name):
    print(f"\n{Colors.BOLD}{Colors.HEADER}===================================================================={Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER} THỰC THI REMEDIATION: HẠ TẦNG MẠNG & AWS IAM (CIS MỤC 5){Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}===================================================================={Colors.ENDC}\n")

    eks = boto3.client('eks')
    ecr = boto3.client('ecr')
    iam = boto3.client('iam')

    # ---------------------------------------------------------
    # 🔧 SỬA LỖI: CIS 5.4.3 - Ensure clusters are created with Private Nodes [cite: 2038, 2039]
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Khắc phục CIS 5.4.3: Cập nhật Endpoint Private/Public cho Cluster{Colors.ENDC}")
    try:
        # Cập nhật API Server thành private, tắt public [cite: 2038]
        eks.update_cluster_config(
            name=cluster_name,
            resourcesVpcConfig={
                'endpointPublicAccess': False,
                'endpointPrivateAccess': True
            }
        )
        print_success(f"Đã cập nhật cluster '{cluster_name}': endpointPublicAccess=False, endpointPrivateAccess=True[cite: 2038].")
        
        # In ra hướng dẫn manual cho phần Node Group [cite: 2039]
        manual_instructions_543 = [
            "Việc cập nhật API Server không ảnh hưởng đến IP của các node hiện tại[cite: 2038].",
            "Để đảm bảo các node chỉ dùng IP Private, hãy tạo lại Node Group với các private subnets[cite: 2039].",
            "Đảm bảo associatePublicIpAddress được set thành false trong cấu hình mạng[cite: 2036, 2037]."
        ]
        print_manual("CIS 5.4.3", "Node Group Migration", manual_instructions_543)
        
    except Exception as e:
        print_error(f"CIS 5.4.3: {e}")
    print("")

    # ---------------------------------------------------------
    # 🔧 SỬA LỖI: CIS 5.1.1 - Ensure Image Vulnerability Scanning [cite: 1842]
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Khắc phục CIS 5.1.1: Bật ECR Scan on Push{Colors.ENDC}")
    try:
        # Chỉnh sửa settings của repository hiện tại để bật scanOnPush [cite: 1842]
        ecr.put_image_scanning_configuration(
            repositoryName=repo_name,
            imageScanningConfiguration={
                'scanOnPush': True
            }
        )
        print_success(f"Đã bật 'scanOnPush=True' cho repository '{repo_name}'[cite: 1842].")
    except Exception as e:
        print_error(f"CIS 5.1.1: {e}")
    print("")

    # ---------------------------------------------------------
    # ⚠️ MANUAL: CIS 5.1.2 - Minimize user access to Amazon ECR (Manual) [cite: 1857, 1859]
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Khắc phục CIS 5.1.2: Minimize user access to Amazon ECR{Colors.ENDC}")
    manual_instructions_512 = [
        "Hiểu các tính năng IAM có sẵn để sử dụng với ECR trước khi quản lý quyền truy cập[cite: 1857].",
        "Áp dụng Identity-Based Policies, Resource-Based Policies và Tags để siết chặt quyền[cite: 1859].",
        f"Hãy xóa policy chứa 'Principal: *' và 'Action: ecr:*' khỏi repository '{repo_name}' bằng Terraform hoặc AWS Console."
    ]
    print_manual("CIS 5.1.2", "Review và siết chặt ECR Policies", manual_instructions_512)
    print("")

    # ---------------------------------------------------------
    # 🔧 SỬA LỖI: CIS 5.1.3 - Minimize cluster access to read-only for Amazon ECR [cite: 1903, 1904]
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Khắc phục CIS 5.1.3: Cập nhật quyền IAM cho NodeInstanceRole{Colors.ENDC}")
    try:
        attached_policies = iam.list_attached_role_policies(RoleName=node_role_name)['AttachedPolicies']
        needs_fix = False
        full_access_arn = ""
        
        for policy in attached_policies:
            if policy['PolicyName'] == 'AmazonEC2ContainerRegistryFullAccess':
                needs_fix = True
                full_access_arn = policy['PolicyArn']
                break
                
        if needs_fix:
            # Gỡ bỏ Full Access
            iam.detach_role_policy(RoleName=node_role_name, PolicyArn=full_access_arn)
            print_success(f"Đã gỡ policy 'AmazonEC2ContainerRegistryFullAccess' khỏi '{node_role_name}'.")
            
            # Khuyến nghị gắn policy ReadOnly chuẩn của AWS chứa ecr:BatchCheckLayerAvailability, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer, ecr:GetAuthorizationToken [cite: 1904]
            iam.attach_role_policy(RoleName=node_role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly")
            print_success(f"Đã gắn policy 'AmazonEC2ContainerRegistryReadOnly' vào '{node_role_name}'[cite: 1904].")
        else:
            print(f"  {Colors.GREEN}[✔️] Role '{node_role_name}' đã ở trạng thái an toàn.{Colors.ENDC}")
    except Exception as e:
        print_error(f"CIS 5.1.3: {e}")

    print(f"\n{Colors.BOLD}{Colors.HEADER}=================== HOÀN TẤT REMEDIATION ==================={Colors.ENDC}\n")

if __name__ == "__main__":
    CLUSTER_NAME = "ctf-eks-arena"
    REPO_NAME = "malicious-repo"
    NODE_ROLE_NAME = "vuln-node-role"
    
    remediate_section_1_infrastructure(CLUSTER_NAME, REPO_NAME, NODE_ROLE_NAME)