from __future__ import annotations

import argparse
import copy
import time
from typing import Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException

SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
SYSTEM_NAME_PREFIXES = ("system:", "eks:")
DEFAULT_TARGET_NAMESPACE = "production"

config.load_kube_config()
core = client.CoreV1Api()
apps = client.AppsV1Api()

def section(title: str, mode: str) -> None:
    print(f"{title} [{mode}]")

def print_manual(msg: str) -> None:
    print(msg.rstrip() + "\n")

def safe_name(value) -> str:
    return value or ""

def is_system_namespace(namespace: Optional[str]) -> bool:
    return namespace in SYSTEM_NAMESPACES

def is_system_name(name: Optional[str]) -> bool:
    return bool(name) and name.startswith(SYSTEM_NAME_PREFIXES)

def remove_runtime_metadata(obj) -> None:
    metadata = getattr(obj, "metadata", None)
    if metadata is None:
        return
    for attr in ("resource_version", "uid", "self_link", "creation_timestamp", "generation", "managed_fields"):
        if hasattr(metadata, attr):
            setattr(metadata, attr, None)
    if hasattr(metadata, "owner_references"):
        metadata.owner_references = None


def wait_for_deployment_rollout(namespace: str, name: str, timeout_seconds: int = 120) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            dep = apps.read_namespaced_deployment(name=name, namespace=namespace)
        except ApiException as exc:
            if exc.status == 404:
                time.sleep(2)
                continue
            raise

        desired = dep.spec.replicas or 1
        status = dep.status
        updated = getattr(status, "updated_replicas", 0) or 0
        available = getattr(status, "available_replicas", 0) or 0
        ready = getattr(status, "ready_replicas", 0) or 0
        if updated >= desired and available >= desired and ready >= desired:
            return True
        time.sleep(3)
    return False

def wait_for_pod_deleted(namespace: str, name: str, timeout_seconds: int = 60) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            core.read_namespaced_pod(name=name, namespace=namespace)
        except ApiException as exc:
            if exc.status == 404:
                return True
            raise
        time.sleep(2)
    return False


def ensure_namespace_exists(namespace_name: str) -> None:
    try:
        core.read_namespace(namespace_name)
        return
    except ApiException as exc:
        if exc.status != 404:
            raise
    ns = client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace_name))
    try:
        core.create_namespace(ns)
        print(f"[FIX] Đã tạo namespace: {namespace_name}")
    except ApiException as exc:
        if exc.status != 409:
            raise

def ensure_secret_copy(secret_name: str, src_ns: str, dst_ns: str) -> bool:
    if secret_name.startswith("default-token-"):
        return False
    try:
        src = core.read_namespaced_secret(secret_name, src_ns)
    except ApiException as exc:
        if exc.status == 404: return False
        raise

    if getattr(src, "type", None) == "kubernetes.io/service-account-token":
        return False

    new_obj = copy.deepcopy(src)
    new_obj.metadata.namespace = dst_ns
    remove_runtime_metadata(new_obj)
    try:
        core.create_namespaced_secret(dst_ns, new_obj)
        print(f"[FIX] Đã sao chép Secret {src_ns}/{secret_name} -> {dst_ns}/{secret_name}")
        return True
    except ApiException as exc:
        if exc.status == 409:
            return True
        raise

def ensure_configmap_copy(cm_name: str, src_ns: str, dst_ns: str) -> bool:
    if cm_name == "kube-root-ca.crt": return False
    try:
        src = core.read_namespaced_config_map(cm_name, src_ns)
    except ApiException as exc:
        if exc.status == 404: return False
        raise

    new_obj = copy.deepcopy(src)
    new_obj.metadata.namespace = dst_ns
    remove_runtime_metadata(new_obj)
    try:
        core.create_namespaced_config_map(dst_ns, new_obj)
        print(f"[FIX] Đã sao chép ConfigMap {src_ns}/{cm_name} -> {dst_ns}/{cm_name}")
        return True
    except ApiException as exc:
        if exc.status == 409:
            return True
        raise

def ensure_serviceaccount_copy(sa_name: str, src_ns: str, dst_ns: str) -> bool:
    if sa_name == "default": return False
    try:
        src = core.read_namespaced_service_account(sa_name, src_ns)
    except ApiException as exc:
        if exc.status == 404: return False
        raise

    new_obj = copy.deepcopy(src)
    new_obj.metadata.namespace = dst_ns
    remove_runtime_metadata(new_obj)
    try:
        core.create_namespaced_service_account(dst_ns, new_obj)
        print(f"[FIX] Đã sao chép ServiceAccount {src_ns}/{sa_name} -> {dst_ns}/{sa_name}")
        return True
    except ApiException as exc:
        if exc.status == 409:
            return True
        raise

def delete_default_namespace_object(kind: str, name: str) -> None:
    try:
        if kind == "secret":
            core.delete_namespaced_secret(name, "default")
        elif kind == "configmap":
            core.delete_namespaced_config_map(name, "default")
        elif kind == "serviceaccount":
            if name != "default":
                core.delete_namespaced_service_account(name, "default")
    except ApiException as exc:
        if exc.status != 404:
            pass

def move_deployment_to_namespace(deploy, target_ns: str) -> None:
    new_deploy = copy.deepcopy(deploy)
    new_deploy.metadata.namespace = target_ns
    remove_runtime_metadata(new_deploy)
    new_deploy.status = None

    sa_name = safe_name(getattr(new_deploy.spec.template.spec, "service_account_name", "") or "default")
    if sa_name != "default":
        ensure_serviceaccount_copy(sa_name, deploy.metadata.namespace, target_ns)

    try:
        apps.create_namespaced_deployment(target_ns, new_deploy)
        print(f"[FIX] Đã tạo deployment trong {target_ns}: {deploy.metadata.name}")
    except ApiException as exc:
        if exc.status == 409:
            apps.patch_namespaced_deployment(name=deploy.metadata.name, namespace=target_ns, body=new_deploy)
            print(f"[FIX] Đã cập nhật (patch) deployment trong {target_ns}: {deploy.metadata.name}")
        else:
            raise

    wait_for_deployment_rollout(target_ns, deploy.metadata.name)

    try:
        apps.delete_namespaced_deployment(name=deploy.metadata.name, namespace=deploy.metadata.namespace, propagation_policy="Foreground")
        print(f"[FIX] Đã xóa deployment gốc từ {deploy.metadata.namespace}: {deploy.metadata.name}")
    except ApiException:
        pass

def move_standalone_pod_to_namespace(pod, target_ns: str) -> None:
    if getattr(pod.metadata, "owner_references", None):
        return

    new_pod = copy.deepcopy(pod)
    new_pod.metadata.namespace = target_ns
    remove_runtime_metadata(new_pod)
    new_pod.status = None

    sa_name = safe_name(getattr(new_pod.spec, "service_account_name", "") or "default")
    if sa_name != "default":
        ensure_serviceaccount_copy(sa_name, pod.metadata.namespace, target_ns)

    try:
        core.create_namespaced_pod(target_ns, new_pod)
        print(f"[FIX] Đã tạo pod trong {target_ns}: {pod.metadata.name}")
    except ApiException as exc:
        if exc.status != 409:
            raise

    try:
        core.delete_namespaced_pod(name=pod.metadata.name, namespace=pod.metadata.namespace, propagation_policy="Foreground")
        print(f"[FIX] Đã xóa pod gốc từ {pod.metadata.namespace}: {pod.metadata.name}")
    except ApiException:
        pass
    wait_for_pod_deleted(pod.metadata.namespace, pod.metadata.name)

def auto_fix_4_5_2(target_ns: str) -> None:
    section("4.5.2 The default namespace should not be used", "AUTOMATED")
    ensure_namespace_exists(target_ns)

    try: secrets = core.list_namespaced_secret("default").items
    except ApiException: secrets = []
    for secret in secrets:
        name = safe_name(secret.metadata.name)
        if name in {"kube-root-ca.crt"} or name.startswith("default-token-") or is_system_name(name): continue
        if ensure_secret_copy(name, "default", target_ns): delete_default_namespace_object("secret", name)

    try: configmaps = core.list_namespaced_config_map("default").items
    except ApiException: configmaps = []
    for cm in configmaps:
        name = safe_name(cm.metadata.name)
        if name == "kube-root-ca.crt" or is_system_name(name): continue
        if ensure_configmap_copy(name, "default", target_ns): delete_default_namespace_object("configmap", name)

    moved = 0
    try: deployments = apps.list_namespaced_deployment("default").items
    except ApiException: deployments = []
    for deploy in deployments:
        name = safe_name(deploy.metadata.name)
        if is_system_name(name): continue
        move_deployment_to_namespace(deploy, target_ns)
        moved += 1

    try: pods = core.list_namespaced_pod("default").items
    except ApiException: pods = []
    for pod in pods:
        name = safe_name(pod.metadata.name)
        if is_system_name(name) or getattr(pod.metadata, "owner_references", None): continue
        move_standalone_pod_to_namespace(pod, target_ns)
        moved += 1

    if moved == 0:
        print("[REVIEW] Không còn user workload nào trong default namespace.")
    else:
        print(f"[FIX] Đã di chuyển {moved} đối tượng user workload khỏi default namespace sang '{target_ns}'.")

def print_manual_remediation_guides() -> None:
    section("\n4.1.3 Minimize wildcard use in Roles and ClusterRoles", "MANUAL")
    print_manual("Hướng dẫn khắc phục:\n"
                 " - Xác định các Roles/ClusterRoles đang sử dụng wildcards (*).\n"
                 " - Thay thế '*' bằng các API groups, resources, và verbs cụ thể mà workload yêu cầu.\n"
                 " - Ví dụ: đổi resources: ['*'] thành resources: ['pods', 'services'].")

    section("4.2.1 & 4.2.4 Pod Security Standards (Privileged & HostNetwork)", "MANUAL")
    print_manual("Hướng dẫn khắc phục:\n"
                 " - Áp dụng các nhãn Pod Security Admission cho các user namespace để hạn chế các pod nguy hiểm.\n"
                 " - Lệnh thực hiện: kubectl label ns <namespace_name> pod-security.kubernetes.io/enforce=restricted --overwrite\n"
                 " - Chỉnh sửa cấu hình pod để xóa 'privileged: true' và 'hostNetwork: true'.")

    section("4.3.2 All namespaces have Network Policies defined", "MANUAL")
    print_manual("Hướng dẫn khắc phục:\n"
                 " - Tạo một NetworkPolicy default-deny trong tất cả user namespace để chặn các luồng traffic không hợp lệ.\n"
                 " - Lệnh để tạo nhanh:\n"
                 "   kubectl create networkpolicy default-deny --namespace <namespace_name> --tcp --dry-run=client -o yaml | kubectl apply -f -")

def main() -> int:
    parser = argparse.ArgumentParser(description="CIS Amazon EKS Benchmark - Targeted Remediation")
    parser.add_argument("--target-namespace", default=DEFAULT_TARGET_NAMESPACE, help="Target namespace for 4.5.2 migration")
    args = parser.parse_args()

    print("CIS AMAZON EKS BENCHMARK - REMEDIATION")

    # 1. Automated Fixes
    auto_fix_4_5_2(args.target_namespace)

    # 2. Manual Remediation Guides
    print_manual_remediation_guides()

    print("HOÀN THÀNH")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())