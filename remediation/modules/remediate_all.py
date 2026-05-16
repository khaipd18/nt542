#!/usr/bin/env python3
import os
import importlib.util
from pathlib import Path

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
    remediate_section_1 = load_remediation_section_1()
    remediate_section_1(cluster_name, repo_name, node_role)

    print("\n=== [REMEDIATION 2] Control Plane & Managed Services ===")
    remediate_eks_core(cluster_name, region)

    print("\n=== [REMEDIATION 3] Worker Nodes (SSM) ===")
    run_worker_nodes_remediation(instance_id, region)

    print("\n=== [REMEDIATION 4] Workloads & Policies ===")
    run_workloads_remediation(target_namespace)


if __name__ == "__main__":
    main()