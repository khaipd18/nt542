#!/usr/bin/env python3
import os
import importlib.util
from pathlib import Path
import subprocess
import sys

from audit.modules.cis_1_eks_infra_iam import audit_section_1_infrastructure
from audit.modules.cis_2_eks_control_plane import audit_cis_eks_benchmark
from audit.modules.cis_3_eks_worker_nodes import main as audit_worker_nodes_main
from audit.modules.cis_4_eks_workloads_policies import main as audit_workloads_main


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


def run_simulation(instance_id, region):
    script_path = Path(__file__).resolve().parent / "simulation" / "cis_3_eks_worker_nodes.py"
    if not script_path.exists():
        raise SystemExit(f"Không tìm thấy file simulation: {script_path}")
    cmd = [sys.executable, str(script_path), "--instance-id", instance_id, "--region", region]
    print("\n=== [SIMULATION] Worker Nodes (CIS 3.x) ===")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(f"Simulation thất bại với mã lỗi {result.returncode}.")


def run_worker_nodes_audit(instance_id, region):
    import sys
    argv_backup = sys.argv
    sys.argv = ["audit_worker_nodes", "--instance-id", instance_id]
    if region:
        sys.argv += ["--region", region]
    try:
        audit_worker_nodes_main()
    finally:
        sys.argv = argv_backup


def run_workloads_audit():
    import sys
    argv_backup = sys.argv
    sys.argv = ["audit_workloads"]
    try:
        audit_workloads_main()
    finally:
        sys.argv = argv_backup


def main():
    print("=== RUN ALL AUDIT ===")

    cluster_name = env_or_prompt("CLUSTER_NAME", default="ctf-eks-arena", required=True)
    repo_name = env_or_prompt("REPO_NAME", default="malicious-repo", required=True)
    node_role = env_or_prompt("NODE_ROLE_NAME", default="vuln-node-role", required=True)
    region = env_or_prompt("AWS_REGION", default="ap-southeast-1", required=True)
    instance_id = env_or_prompt("INSTANCE_ID", required=True)

    print("\n=== [AUDIT 1] Infrastructure & IAM (CIS 5.x) ===")
    audit_section_1_infrastructure(cluster_name, repo_name, node_role)

    print("\n=== [AUDIT 2] Control Plane & Managed Services ===")
    audit_cis_eks_benchmark(cluster_name, region)

    # Thêm bước simulation trước khi audit phần 3 theo README
    run_simulation(instance_id, region)

    print("\n=== [AUDIT 3] Worker Nodes (SSM) ===")
    run_worker_nodes_audit(instance_id, region)

    print("\n=== [AUDIT 4] Workloads & Policies ===")
    run_workloads_audit()


if __name__ == "__main__":
    main()
