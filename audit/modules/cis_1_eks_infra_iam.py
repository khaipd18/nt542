import boto3
import json

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

def print_pass(msg):
    print(f"{Colors.GREEN}  [✔️] PASS:{Colors.ENDC} {msg}")

def print_fail(cis_id, msg, details):
    print(f"{Colors.FAIL}{Colors.BOLD}  [❌] LỖI {cis_id}:{Colors.ENDC} {msg}")
    print(f"       {Colors.WARNING}↳ Chi tiết:{Colors.ENDC}")
    
    # Kiểm tra xem details là một list (nhiều lỗi) hay chuỗi (1 lỗi)
    if isinstance(details, list):
        for detail in details:
            print(f"         - {detail}")
    else:
        print(f"         - {details}")

# ==========================================
# LOGIC AUDIT PHẦN 1 (CIS MỤC 5)
# ==========================================
def audit_section_1_infrastructure(cluster_name, repo_name, node_role_name):
    print(f"\n{Colors.BOLD}{Colors.HEADER}===================================================================={Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER} PHẦN 1: HẠ TẦNG MẠNG & AWS IAM (CIS MỤC 5){Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}===================================================================={Colors.ENDC}\n")

    # Khởi tạo AWS Clients
    eks = boto3.client('eks')
    ecr = boto3.client('ecr')
    iam = boto3.client('iam')
    ec2 = boto3.client('ec2')

    # ---------------------------------------------------------
    # ❌ LỖI 1: CIS 5.4.3 - Ensure clusters are created with Private Nodes
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Kiểm tra CIS 5.4.3: Ensure clusters are created with Private Nodes{Colors.ENDC}")
    try:
        cluster_info = eks.describe_cluster(name=cluster_name)
        vpc_config = cluster_info['cluster']['resourcesVpcConfig']
        
        errors = []
        
        # Kiểm tra API Endpoints theo chuẩn CIS
        if not vpc_config.get('endpointPrivateAccess'):
            errors.append("endpointPrivateAccess đang bị tắt (phải là True).")
            
        public_cidrs = vpc_config.get('publicAccessCidrs', [])
        if vpc_config.get('endpointPublicAccess') and '0.0.0.0/0' in public_cidrs:
            errors.append("endpointPublicAccess đang bật và publicAccessCidrs chứa 0.0.0.0/0.")

        # Kiểm tra Subnets: MapPublicIpOnLaunch và Route Table (IGW)
        subnet_ids = vpc_config.get('subnetIds', [])
        subnets = ec2.describe_subnets(SubnetIds=subnet_ids)['Subnets']
        
        for subnet in subnets:
            subnet_id = subnet['SubnetId']
            # Kiểm tra IP công cộng
            if subnet.get('MapPublicIpOnLaunch', False):
                errors.append(f"Subnet {subnet_id} có MapPublicIpOnLaunch=True.")
            
            # Kiểm tra Route Table xem có trỏ ra IGW không
            route_tables = ec2.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])['RouteTables']
            for rt in route_tables:
                for route in rt.get('Routes', []):
                    if route.get('GatewayId', '').startswith('igw-'):
                        errors.append(f"Subnet {subnet_id} có Route Table chứa Internet Gateway (IGW).")
        
        if errors:
            print_fail("CIS 5.4.3", "Cluster/Nodes không tuân thủ Private Network", errors)
        else:
            print_pass("Cluster và Nodes được cấu hình hoàn toàn Private theo chuẩn CIS.")
    except Exception as e:
        print(f"  {Colors.WARNING}Không thể kiểm tra CIS 5.4.3: {e}{Colors.ENDC}")

    print("")

    # ---------------------------------------------------------
    # ❌ LỖI 2: CIS 5.1.1 - Ensure Image Vulnerability Scanning
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Kiểm tra CIS 5.1.1: Ensure Image Vulnerability Scanning{Colors.ENDC}")
    try:
        repos = ecr.describe_repositories(repositoryNames=[repo_name])
        scan_config = repos['repositories'][0].get('imageScanningConfiguration', {})
        if not scan_config.get('scanOnPush', False):
            print_fail("CIS 5.1.1", "Không quét lỗ hổng ảnh Container (scanOnPush = false)", f"Repository '{repo_name}' đang tắt tính năng quét ảnh tự động khi push.")
        else:
            print_pass(f"Repository '{repo_name}' đã bật Scan on Push.")
    except Exception as e:
        print(f"  {Colors.WARNING}Không thể kiểm tra CIS 5.1.1: {e}{Colors.ENDC}")

    print("")

    # ---------------------------------------------------------
    # ❌ LỖI 3: CIS 5.1.2 - Minimize user access to Amazon ECR (Manual)
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Kiểm tra CIS 5.1.2: Minimize user access to Amazon ECR{Colors.ENDC}")
    try:
        policy_resp = ecr.get_repository_policy(repositoryName=repo_name)
        policy_text = json.loads(policy_resp['policyText'])
        is_open = False
        
        for statement in policy_text.get('Statement', []):
            if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*' and statement.get('Action') == 'ecr:*':
                is_open = True
                break
                
        if is_open:
            print_fail("CIS 5.1.2", "Mở toang quyền truy cập ECR cho tất cả mọi người (*)", f"Policy của '{repo_name}' chứa Action='ecr:*' và Principal='*'.")
        else:
            print_pass(f"Quyền truy cập ECR '{repo_name}' được kiểm soát tốt.")
    except ecr.exceptions.RepositoryPolicyNotFoundException:
        print_pass(f"Không có policy công khai nào được gắn vào '{repo_name}'.")
    except Exception as e:
        print(f"  {Colors.WARNING}Không thể kiểm tra CIS 5.1.2: {e}{Colors.ENDC}")

    print("")

    # ---------------------------------------------------------
    # ❌ LỖI 4: CIS 5.1.3 - Minimize cluster access to read-only for Amazon ECR (Manual)
    # ---------------------------------------------------------
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Kiểm tra CIS 5.1.3: Minimize cluster access to read-only for Amazon ECR{Colors.ENDC}")
    try:
        attached_policies = iam.list_attached_role_policies(RoleName=node_role_name)['AttachedPolicies']
        has_full_access = False
        
        for policy in attached_policies:
            if policy['PolicyName'] == 'AmazonEC2ContainerRegistryFullAccess':
                has_full_access = True
                break
                
        if has_full_access:
            print_fail("CIS 5.1.3", "Gán luôn quyền Admin ECR cho Node thao tác", f"Role '{node_role_name}' đang gắn policy 'AmazonEC2ContainerRegistryFullAccess' thay vì ReadOnly.")
        else:
            print_pass(f"Role '{node_role_name}' sử dụng quyền truy cập tối thiểu (không chứa Full Access).")
    except Exception as e:
        print(f"  {Colors.WARNING}Không thể kiểm tra CIS 5.1.3: {e}{Colors.ENDC}")

    print(f"\n{Colors.BOLD}{Colors.HEADER}=================== HOÀN TẤT AUDIT PHẦN 1 ==================={Colors.ENDC}\n")

if __name__ == "__main__":
    CLUSTER_NAME = "ctf-eks-arena"
    REPO_NAME = "malicious-repo"
    NODE_ROLE_NAME = "vuln-node-role"
    
    audit_section_1_infrastructure(CLUSTER_NAME, REPO_NAME, NODE_ROLE_NAME)