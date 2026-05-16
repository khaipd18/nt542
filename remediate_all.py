#!/usr/bin/env python3
import os
import importlib.util
from pathlib import Path
import time
import subprocess

import boto3
from botocore.exceptions import ClientError

from remediation.modules.cis_2_eks_control_plane import remediate_eks_core
from remediation.modules.cis_3_eks_worker_nodes import main as remediate_worker_nodes_main
from remediation.modules.cis_4_eks_workloads_policies import main as remediate_workloads_main


def load_remediation_section_1():
    path = Path("remediation/modules/cis_1_eks_infra_iam copy.py")
    spec = importlib.util.spec_from_file_location("cis_1_eks_infra_iam_copy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore
    return module.remediate_section_1_infrastructure


def env_or_prompt(key, default=None, required=False):
    val = os.getenv(key)
    if val:
        return val
    prompt = f"{key}"
    if default:
        prompt += f" (default: {default})"
    prompt += ": "
    val = input(prompt).strip()
    if not val and default:
        val = default
    if required and not val:
        raise SystemExit(f"Thiếu {key}, không thể chạy.")
    return val


def wait_for_cluster_idle(cluster_name, region, timeout_seconds=1800, poll_seconds=15):
    """Chờ đến khi EKS cluster không còn update đang chạy."""
    eks_client = boto3.client("eks", region_name=region)
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            updates = eks_client.list_updates(name=cluster_name).get("updateIds", [])
            in_progress = []
            for update_id in updates:
                info = eks_client.describe_update(name=cluster_name, updateId=update_id)
                status = info.get("update", {}).get("status")
                if status in {"InProgress", "Pending"}:
                    in_progress.append(update_id)
            if not in_progress:
                return
            print(f"⏳ Cluster đang có update chạy ({len(in_progress)}). Đợi {poll_seconds}s...")
            time.sleep(poll_seconds)
        except ClientError as exc:
            print(f"⚠️  Không thể kiểm tra update EKS: {exc}")
            time.sleep(poll_seconds)
    raise SystemExit("⛔ Hết thời gian chờ cluster idle. Hãy thử lại sau.")


def set_public_endpoint(cluster_name, region):
    """Bật public endpoint tạm thời để chạy phần 4 từ máy ngoài VPC."""
    eks_client = boto3.client("eks", region_name=region)
    cluster = eks_client.describe_cluster(name=cluster_name)["cluster"]
    vpc_cfg = cluster.get("resourcesVpcConfig", {})

    if vpc_cfg.get("endpointPublicAccess") is True:
        return

    print("🔧 Bật public endpoint để chạy REMEDIATION 4...")
    try:
        eks_client.update_cluster_config(
            name=cluster_name,
            resourcesVpcConfig={
                "endpointPublicAccess": True,
                "endpointPrivateAccess": True,
            },
        )
    except ClientError as exc:
        msg = str(exc)
        if "already at the desired configuration" in msg:
            return
        raise

    wait_for_cluster_idle(cluster_name, region)


def ensure_kube_access(cluster_name, region):
    """Đảm bảo kubeconfig sẵn sàng và endpoint có thể truy cập trước phần 4."""
    # Bật public endpoint tạm để chạy phần 4
    set_public_endpoint(cluster_name, region)

    # Cố gắng cập nhật kubeconfig tự động (nếu có AWS CLI)
    try:
        subprocess.run(
            ["aws", "eks", "update-kubeconfig", "--name", cluster_name, "--region", region],
            check=True,
        )
    except FileNotFoundError:
        print("⚠️  Không tìm thấy AWS CLI (aws). Bỏ qua bước update-kubeconfig tự động.")
    except subprocess.CalledProcessError as exc:
        print(f"⚠️  update-kubeconfig thất bại: {exc}")

    # Kiểm tra kết nối bằng kubectl
    try:
        subprocess.run(["kubectl", "version", "--short"], check=True)
    except FileNotFoundError:
        raise SystemExit("⛔ Không tìm thấy kubectl. Hãy cài đặt kubectl rồi chạy lại.")
    except subprocess.CalledProcessError:
        raise SystemExit(
            "⛔ Không thể kết nối Kubernetes API. Hãy kiểm tra kubeconfig hoặc mạng."
        )


def run_worker_nodes_remediation(instance_id, region):
    import sys
    argv_backup = sys.argv
    sys.argv = ["remediate_worker_nodes", "--instance-id", instance_id]
    if region:
        sys.argv += ["--region", region]
    try:
        remediate_worker_nodes_main()
    finally:
        sys.argv = argv_backup


def run_workloads_remediation(target_namespace):
    import sys
    argv_backup = sys.argv
    sys.argv = ["remediate_workloads", "--target-namespace", target_namespace]
    try:
        remediate_workloads_main()
    finally:
        sys.argv = argv_backup


def main():
    print("=== RUN ALL REMEDIATION ===")

    cluster_name = env_or_prompt("CLUSTER_NAME", default="ctf-eks-arena", required=True)
    repo_name = env_or_prompt("REPO_NAME", default="malicious-repo", required=True)
    node_role = env_or_prompt("NODE_ROLE_NAME", default="vuln-node-role", required=True)
    region = env_or_prompt("AWS_REGION", default="ap-southeast-1", required=True)
    instance_id = env_or_prompt("INSTANCE_ID", required=True)
    target_namespace = env_or_prompt("TARGET_NAMESPACE", default="production", required=True)

    print("\n=== [REMEDIATION 1] Infrastructure & IAM (CIS 5.x) ===")
    wait_for_cluster_idle(cluster_name, region)
    remediate_section_1 = load_remediation_section_1()
    remediate_section_1(cluster_name, repo_name, node_role)

    print("\n=== [REMEDIATION 2] Control Plane & Managed Services ===")
    wait_for_cluster_idle(cluster_name, region)
    remediate_eks_core(cluster_name, region)

    print("\n=== [REMEDIATION 3] Worker Nodes (SSM) ===")
    run_worker_nodes_remediation(instance_id, region)

    print("\n=== [REMEDIATION 4] Workloads & Policies ===")
    ensure_kube_access(cluster_name, region)
    run_workloads_remediation(target_namespace)


if __name__ == "__main__":
    main()
