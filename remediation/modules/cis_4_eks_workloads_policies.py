from __future__ import annotations

import argparse
import copy
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from kubernetes import client, config
from kubernetes.client.rest import ApiException


SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
SYSTEM_NAME_PREFIXES = ("system:", "eks:")
DEFAULT_TARGET_NAMESPACE = "production"


def find_default_terraform_file() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "terraform" / "eks" / "main.tf",
        here.parents[2] / "terraform" / "main.tf",
        here.parents[1] / "terraform" / "eks" / "main.tf",
        here.parents[1] / "terraform" / "main.tf",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


DEFAULT_EKS_TERRAFORM_FILE = find_default_terraform_file()

config.load_kube_config()
core = client.CoreV1Api()
apps = client.AppsV1Api()
rbac = client.RbacAuthorizationV1Api()
networking = client.NetworkingV1Api()
batch = client.BatchV1Api()


def section(title: str, mode: str) -> None:
    print("\n" + "=" * 80)
    print(f"{title} [{mode}]")
    print("=" * 80)


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


def find_first_existing(path_candidates: List[Path]) -> Path:
    for p in path_candidates:
        if p.exists():
            return p
    return path_candidates[0]


def patch_terraform_auth_mode(terraform_file: Path) -> bool:
    if not terraform_file.exists():
        print(f"[WARN] Terraform file not found: {terraform_file}")
        return False

    original = terraform_file.read_text(encoding="utf-8")

    updated, count = re.subn(
        r'authentication_mode\s*=\s*"CONFIG_MAP"',
        'authentication_mode = "API_AND_CONFIG_MAP"',
        original,
    )

    if count == 0:
        if (
            'authentication_mode = "API_AND_CONFIG_MAP"' in original
            or 'authentication_mode = "API"' in original
        ):
            print("[INFO] Terraform already uses API / API_AND_CONFIG_MAP for EKS access mode.")
            return False

        print(f"[WARN] No authentication_mode = \"CONFIG_MAP\" found in {terraform_file}.")
        return False

    backup = terraform_file.with_suffix(terraform_file.suffix + ".bak")

    backup.write_text(original, encoding="utf-8")
    terraform_file.write_text(updated, encoding="utf-8")

    print(f"[FIX] Updated Terraform access mode in {terraform_file.name}")
    print(f"[FIX] Backup saved to {backup.name}")

    return True


def run_terraform_apply(terraform_file: Path) -> None:
    root = terraform_file.resolve().parents[1]

    commands = [
        ["terraform", "init"],
        ["terraform", "apply", "-auto-approve"],
    ]

    for cmd in commands:
        print(f"[RUN] {' '.join(cmd)} (cwd={root})")

        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True
        )

        if proc.stdout:
            print(proc.stdout)

        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip()

            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\n{err}"
            )


def get_template_spec(obj):
    kind = safe_name(getattr(obj, "kind", "")).lower()
    spec = getattr(obj, "spec", None)
    if spec is None:
        return None
    if kind == "pod":
        return spec
    if kind in {"deployment", "daemonset", "statefulset", "job"}:
        return getattr(getattr(spec, "template", None), "spec", None)
    if kind == "cronjob":
        jt = getattr(spec, "job_template", None)
        return getattr(getattr(getattr(jt, "spec", None), "template", None), "spec", None)
    return None


def pod_has_secret_key_ref(podspec) -> bool:
    for container in (getattr(podspec, "containers", []) or []):
        for env in (getattr(container, "env", []) or []):
            value_from = getattr(env, "value_from", None)
            if value_from and getattr(value_from, "secret_key_ref", None):
                return True
        for env_from in (getattr(container, "env_from", []) or []):
            if getattr(env_from, "secret_ref", None):
                return True
    return False


def get_workload_secret_refs(workload_spec) -> Set[str]:
    refs: Set[str] = set()
    for container in (getattr(workload_spec, "containers", []) or []):
        for env in (getattr(container, "env", []) or []):
            value_from = getattr(env, "value_from", None)
            secret_key_ref = getattr(value_from, "secret_key_ref", None) if value_from else None
            if secret_key_ref and getattr(secret_key_ref, "name", None):
                refs.add(secret_key_ref.name)
        for env_from in (getattr(container, "env_from", []) or []):
            secret_ref = getattr(env_from, "secret_ref", None)
            if secret_ref and getattr(secret_ref, "name", None):
                refs.add(secret_ref.name)
    for volume in (getattr(workload_spec, "volumes", []) or []):
        secret_src = getattr(volume, "secret", None)
        if secret_src and getattr(secret_src, "secret_name", None):
            refs.add(secret_src.secret_name)
    return refs


def strip_secret_envs_and_mount_files(pod_spec) -> Set[str]:
    """
    Remove env/envFrom secret references and mount them as files at /etc/secrets/<secret-name>.
    """
    secret_names: Set[str] = set()

    for container in (getattr(pod_spec, "containers", []) or []):
        # env with secretKeyRef
        envs = list(getattr(container, "env", []) or [])
        new_envs = []
        for env in envs:
            value_from = getattr(env, "value_from", None)
            secret_key_ref = getattr(value_from, "secret_key_ref", None) if value_from else None
            if secret_key_ref and getattr(secret_key_ref, "name", None):
                secret_names.add(secret_key_ref.name)
            else:
                new_envs.append(env)
        container.env = new_envs or None

        # envFrom with secretRef
        env_froms = list(getattr(container, "env_from", []) or [])
        new_env_froms = []
        for env_from in env_froms:
            secret_ref = getattr(env_from, "secret_ref", None)
            if secret_ref and getattr(secret_ref, "name", None):
                secret_names.add(secret_ref.name)
            else:
                new_env_froms.append(env_from)
        container.env_from = new_env_froms or None

    if not secret_names:
        return secret_names

    existing_volumes = list(getattr(pod_spec, "volumes", []) or [])
    existing_volume_names = {v.name for v in existing_volumes if getattr(v, "name", None)}

    for secret_name in sorted(secret_names):
        vol_name = "secret-" + re.sub(r"[^a-z0-9-]+", "-", secret_name.lower()).strip("-")
        if vol_name not in existing_volume_names:
            existing_volumes.append(
                client.V1Volume(
                    name=vol_name,
                    secret=client.V1SecretVolumeSource(secret_name=secret_name),
                )
            )
            existing_volume_names.add(vol_name)

        mount_path = f"/etc/secrets/{secret_name}"
        for container in (getattr(pod_spec, "containers", []) or []):
            mounts = list(getattr(container, "volume_mounts", []) or [])
            if not any(getattr(vm, "name", None) == vol_name for vm in mounts):
                mounts.append(
                    client.V1VolumeMount(
                        name=vol_name,
                        mount_path=mount_path,
                        read_only=True,
                    )
                )
            container.volume_mounts = mounts or None

    pod_spec.volumes = existing_volumes or None
    return secret_names


def wait_for_deployment_rollout(namespace: str, name: str, timeout_seconds: int = 180) -> bool:
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

    print(f"[WARN] Timed out waiting for deployment rollout: {namespace}/{name}")
    return False


def wait_for_pod_deleted(namespace: str, name: str, timeout_seconds: int = 120) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            core.read_namespaced_pod(name=name, namespace=namespace)
        except ApiException as exc:
            if exc.status == 404:
                return True
            raise
        time.sleep(2)

    print(f"[WARN] Timed out waiting for pod deletion: {namespace}/{name}")
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
        print(f"[FIX] Created namespace: {namespace_name}")
    except ApiException as exc:
        if exc.status != 409:
            raise


def ensure_secret_copy(secret_name: str, src_ns: str, dst_ns: str) -> bool:
    if secret_name.startswith("default-token-"):
        return False
    try:
        src = core.read_namespaced_secret(secret_name, src_ns)
    except ApiException as exc:
        if exc.status == 404:
            return False
        raise

    if getattr(src, "type", None) == "kubernetes.io/service-account-token":
        return False

    new_obj = copy.deepcopy(src)
    new_obj.metadata.namespace = dst_ns
    remove_runtime_metadata(new_obj)
    try:
        core.create_namespaced_secret(dst_ns, new_obj)
        print(f"[FIX] Copied Secret {src_ns}/{secret_name} -> {dst_ns}/{secret_name}")
        return True
    except ApiException as exc:
        if exc.status == 409:
            try:
                core.patch_namespaced_secret(secret_name, dst_ns, new_obj)
                print(f"[FIX] Patched Secret {dst_ns}/{secret_name}")
                return True
            except ApiException:
                return False
        raise


def ensure_configmap_copy(cm_name: str, src_ns: str, dst_ns: str) -> bool:
    if cm_name == "kube-root-ca.crt":
        return False
    try:
        src = core.read_namespaced_config_map(cm_name, src_ns)
    except ApiException as exc:
        if exc.status == 404:
            return False
        raise

    new_obj = copy.deepcopy(src)
    new_obj.metadata.namespace = dst_ns
    remove_runtime_metadata(new_obj)
    try:
        core.create_namespaced_config_map(dst_ns, new_obj)
        print(f"[FIX] Copied ConfigMap {src_ns}/{cm_name} -> {dst_ns}/{cm_name}")
        return True
    except ApiException as exc:
        if exc.status == 409:
            try:
                core.patch_namespaced_config_map(cm_name, dst_ns, new_obj)
                print(f"[FIX] Patched ConfigMap {dst_ns}/{cm_name}")
                return True
            except ApiException:
                return False
        raise


def ensure_serviceaccount_copy(sa_name: str, src_ns: str, dst_ns: str) -> bool:
    if sa_name == "default":
        return False
    try:
        src = core.read_namespaced_service_account(sa_name, src_ns)
    except ApiException as exc:
        if exc.status == 404:
            return False
        raise

    new_obj = copy.deepcopy(src)
    new_obj.metadata.namespace = dst_ns
    remove_runtime_metadata(new_obj)
    try:
        core.create_namespaced_service_account(dst_ns, new_obj)
        print(f"[FIX] Copied ServiceAccount {src_ns}/{sa_name} -> {dst_ns}/{sa_name}")
        return True
    except ApiException as exc:
        if exc.status == 409:
            try:
                core.patch_namespaced_service_account(sa_name, dst_ns, new_obj)
                print(f"[FIX] Patched ServiceAccount {dst_ns}/{sa_name}")
                return True
            except ApiException:
                return False
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
        elif kind == "service":
            core.delete_namespaced_service(name, "default")
    except ApiException as exc:
        if exc.status != 404:
            print(f"[WARN] Could not delete default/{kind}/{name}: {exc}")


def move_deployment_to_namespace(deploy, target_ns: str) -> None:
    new_deploy = copy.deepcopy(deploy)
    new_deploy.metadata.namespace = target_ns
    remove_runtime_metadata(new_deploy)
    new_deploy.status = None

    secret_refs = get_workload_secret_refs(new_deploy.spec.template.spec)
    for secret_name in secret_refs:
        ensure_secret_copy(secret_name, deploy.metadata.namespace, target_ns)

    strip_secret_envs_and_mount_files(new_deploy.spec.template.spec)

    sa_name = safe_name(getattr(new_deploy.spec.template.spec, "service_account_name", "") or "default")
    if sa_name != "default":
        ensure_serviceaccount_copy(sa_name, deploy.metadata.namespace, target_ns)

    try:
        apps.create_namespaced_deployment(target_ns, new_deploy)
        print(f"[FIX] Created deployment in {target_ns}: {deploy.metadata.name}")
    except ApiException as exc:
        if exc.status == 409:
            apps.patch_namespaced_deployment(name=deploy.metadata.name, namespace=target_ns, body=new_deploy)
            print(f"[FIX] Patched deployment in {target_ns}: {deploy.metadata.name}")
        else:
            raise

    wait_for_deployment_rollout(target_ns, deploy.metadata.name)

    try:
        apps.delete_namespaced_deployment(
            name=deploy.metadata.name,
            namespace=deploy.metadata.namespace,
            propagation_policy="Foreground",
        )
        print(f"[FIX] Deleted original deployment from {deploy.metadata.namespace}: {deploy.metadata.name}")
    except ApiException as exc:
        print(f"[WARN] Could not delete original deployment {deploy.metadata.namespace}/{deploy.metadata.name}: {exc}")


def move_standalone_pod_to_namespace(pod, target_ns: str) -> None:
    if getattr(pod.metadata, "owner_references", None):
        return

    new_pod = copy.deepcopy(pod)
    new_pod.metadata.namespace = target_ns
    remove_runtime_metadata(new_pod)
    new_pod.status = None

    secret_refs = get_workload_secret_refs(new_pod.spec)
    for secret_name in secret_refs:
        ensure_secret_copy(secret_name, pod.metadata.namespace, target_ns)

    strip_secret_envs_and_mount_files(new_pod.spec)

    sa_name = safe_name(getattr(new_pod.spec, "service_account_name", "") or "default")
    if sa_name != "default":
        ensure_serviceaccount_copy(sa_name, pod.metadata.namespace, target_ns)

    try:
        core.create_namespaced_pod(target_ns, new_pod)
        print(f"[FIX] Created pod in {target_ns}: {pod.metadata.name}")
    except ApiException as exc:
        if exc.status == 409:
            print(f"[INFO] Pod already exists in {target_ns}: {pod.metadata.name}")
        else:
            raise

    try:
        core.delete_namespaced_pod(
            name=pod.metadata.name,
            namespace=pod.metadata.namespace,
            propagation_policy="Foreground",
        )
        print(f"[FIX] Deleted original pod from {pod.metadata.namespace}: {pod.metadata.name}")
    except ApiException as exc:
        print(f"[WARN] Could not delete original pod {pod.metadata.namespace}/{pod.metadata.name}: {exc}")

    wait_for_pod_deleted(pod.metadata.namespace, pod.metadata.name)


def auto_fix_4_1_7(terraform_file: Path, apply_terraform: bool) -> None:
    """
    Automated remediation for 4.1.7: Updates Terraform file and calls AWS CLI directly to update the cluster.
    """
    section("4.1.7 Cluster Access Manager API", "AUTOMATED")

    # 1. Patch Terraform file
    changed = patch_terraform_auth_mode(terraform_file)

    # 2. Call AWS CLI directly to ensure cluster is updated (Thorough remediation)
    cluster_name = "ctf-eks-arena"  # Cluster name from your logs
    region = "ap-southeast-1"      # Region from your logs
    
    print(f"[RUN] Executing AWS CLI to update authentication mode for cluster '{cluster_name}'...")
    try:
        cmd = [
            "aws", "eks", "update-cluster-config",
            "--name", cluster_name,
            "--region", region,
            "--access-config", "authenticationMode=API_AND_CONFIG_MAP"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[SUCCESS] update-cluster-config command sent successfully.")
            print("=> Note: The cluster will transition to 'Updating' state for approximately 10-15 minutes.")
        else:
            # Consider success if AWS reports it's already in the desired mode
            if "no changes needed" in result.stderr.lower() or "already" in result.stderr.lower():
                print("[INFO] AWS confirmed the cluster is already in API_AND_CONFIG_MAP mode.")
            else:
                print(f"[WARN] AWS CLI error: {result.stderr.strip()}")
    except Exception as e:
        print(f"[WARN] Could not call AWS CLI: {e}")

    # 3. Run terraform apply if requested
    if changed and apply_terraform:
        print("[RUN] Applying Terraform to keep IaC in sync with the EKS cluster.")
        run_terraform_apply(terraform_file)


def auto_fix_4_4_1() -> None:
    section("4.4.1 Prefer secrets as files over environment variables", "AUTOMATED")

    workload_kinds = [
        ("deployments", apps.list_deployment_for_all_namespaces(), "deployment"),
        ("daemonsets", apps.list_daemon_set_for_all_namespaces(), "daemonset"),
        ("statefulsets", apps.list_stateful_set_for_all_namespaces(), "statefulset"),
        ("jobs", batch.list_job_for_all_namespaces(), "job"),
        ("cronjobs", batch.list_cron_job_for_all_namespaces(), "cronjob"),
    ]

    for plural, resp, kind_name in workload_kinds:
        for obj in resp.items:
            ns = safe_name(getattr(obj.metadata, "namespace", ""))
            name = safe_name(getattr(obj.metadata, "name", ""))
            if is_system_namespace(ns) or is_system_name(name):
                continue

            spec = get_template_spec(obj)
            if not spec:
                continue

            secret_refs = get_workload_secret_refs(spec)
            if not secret_refs and not pod_has_secret_key_ref(spec):
                continue

            strip_secret_envs_and_mount_files(spec)
            for secret_name in secret_refs:
                ensure_secret_copy(secret_name, ns, ns)

            try:
                if kind_name == "deployment":
                    apps.patch_namespaced_deployment(name=name, namespace=ns, body=obj)
                elif kind_name == "daemonset":
                    apps.patch_namespaced_daemon_set(name=name, namespace=ns, body=obj)
                elif kind_name == "statefulset":
                    apps.patch_namespaced_stateful_set(name=name, namespace=ns, body=obj)
                elif kind_name == "job":
                    batch.patch_namespaced_job(name=name, namespace=ns, body=obj)
                elif kind_name == "cronjob":
                    batch.patch_namespaced_cron_job(name=name, namespace=ns, body=obj)

                print(f"[FIX] Patched {plural[:-1].capitalize()} {ns}/{name}: removed secret env refs")
            except Exception as exc:
                print(f"[WARN] Could not patch {plural} {ns}/{name}: {exc}")

    # Standalone pods
    for pod in core.list_pod_for_all_namespaces().items:
        ns = safe_name(pod.metadata.namespace)
        name = safe_name(pod.metadata.name)
        if is_system_namespace(ns) or is_system_name(name) or getattr(pod.metadata, "owner_references", None):
            continue

        podspec = pod.spec
        secret_refs = get_workload_secret_refs(podspec)
        if not secret_refs and not pod_has_secret_key_ref(podspec):
            continue

        for secret_name in secret_refs:
            ensure_secret_copy(secret_name, ns, ns)

        new_pod = copy.deepcopy(pod)
        remove_runtime_metadata(new_pod)
        new_pod.status = None
        strip_secret_envs_and_mount_files(new_pod.spec)

        try:
            core.delete_namespaced_pod(name=name, namespace=ns, propagation_policy="Foreground")
            wait_for_pod_deleted(ns, name)
            core.create_namespaced_pod(ns, new_pod)
            print(f"[FIX] Recreated pod {ns}/{name} without secret env refs")
        except ApiException as exc:
            print(f"[WARN] Could not recreate pod {ns}/{name}: {exc}")

    print(
        "[SUCCESS] 4.4.1 remediation completed.\n"
        "Secret env references that were discoverable have been removed or converted to mounted secret files."
    )


def auto_fix_4_5_2(target_ns: str = DEFAULT_TARGET_NAMESPACE) -> None:
    section("4.5.2 The default namespace should not be used", "AUTOMATED")

    ensure_namespace_exists(target_ns)

    # Copy and remove user-created Secrets from default
    try:
        secrets = core.list_namespaced_secret("default").items
    except ApiException:
        secrets = []
    for secret in secrets:
        name = safe_name(secret.metadata.name)
        if name in {"kube-root-ca.crt"} or name.startswith("default-token-") or is_system_name(name):
            continue
        if ensure_secret_copy(name, "default", target_ns):
            delete_default_namespace_object("secret", name)

    # Copy and remove ConfigMaps from default
    try:
        configmaps = core.list_namespaced_config_map("default").items
    except ApiException:
        configmaps = []
    for cm in configmaps:
        name = safe_name(cm.metadata.name)
        if name == "kube-root-ca.crt" or is_system_name(name):
            continue
        if ensure_configmap_copy(name, "default", target_ns):
            delete_default_namespace_object("configmap", name)

    # Copy and remove user-created ServiceAccounts from default
    try:
        sas = core.list_namespaced_service_account("default").items
    except ApiException:
        sas = []
    for sa in sas:
        name = safe_name(sa.metadata.name)
        if name == "default" or is_system_name(name):
            continue
        if ensure_serviceaccount_copy(name, "default", target_ns):
            delete_default_namespace_object("serviceaccount", name)

    moved = 0

    # Move Deployments out of default
    try:
        deployments = apps.list_namespaced_deployment("default").items
    except ApiException:
        deployments = []
    for deploy in deployments:
        name = safe_name(deploy.metadata.name)
        if is_system_name(name):
            continue
        move_deployment_to_namespace(deploy, target_ns)
        moved += 1

    # Move standalone Pods out of default
    try:
        pods = core.list_namespaced_pod("default").items
    except ApiException:
        pods = []
    for pod in pods:
        name = safe_name(pod.metadata.name)
        if is_system_name(name) or getattr(pod.metadata, "owner_references", None):
            continue
        move_standalone_pod_to_namespace(pod, target_ns)
        moved += 1

    if moved == 0:
        print(
            "[REVIEW] No user workloads remain in the default namespace.\n"
            "System-managed objects such as kube-root-ca.crt, events, and the default ServiceAccount may still exist."
        )
    else:
        print(
            f"[FIX] Moved {moved} user workload object(s) out of default namespace into '{target_ns}'.\n"
            "System-managed default-namespace objects are intentionally retained."
        )


def review_manual_controls() -> None:
    section("4.1.x RBAC & Service Accounts", "MANUAL")
    print_manual(
        "Manual controls are reviewed for evidence only.\n"
        "Remediation for manual controls should be carried out by the operator, not auto-patched by this script."
    )

    section("4.2.x Pod Security Standards", "MANUAL")
    print_manual(
        "Manual controls are reviewed for evidence only.\n"
        "Use Pod Security Admission labels / namespace policies to remediate."
    )

    section("4.3.1 CNI plugin supports network policies", "MANUAL")
    ds_names = [d.metadata.name for d in apps.list_namespaced_daemon_set("kube-system").items]
    print_manual(
        f"REVIEW: detected kube-system daemonsets = {ds_names}\n"
        "Verify the CNI plugin documentation supports NetworkPolicy enforcement."
    )

    section("4.3.2 Network Policies", "MANUAL")
    for ns in core.list_namespace().items:
        ns_name = ns.metadata.name
        if is_system_namespace(ns_name):
            continue
        try:
            policies = networking.list_namespaced_network_policy(ns_name).items
        except ApiException:
            policies = []
        if not policies:
            print_manual(
                f"[FAIL] Namespace '{ns_name}' has no NetworkPolicy.\n"
                f"Remediation: create at least one NetworkPolicy in {ns_name}."
            )
        else:
            print_manual(
                f"[REVIEW] Namespace '{ns_name}' has {len(policies)} NetworkPolicy object(s).\n"
                "Manually validate that the policy set matches least privilege."
            )

    section("4.4.2 External secret storage", "MANUAL")
    print_manual("[REVIEW] Consider AWS Secrets Manager, HashiCorp Vault, or External Secrets Operator.")

    section("4.5.1 Namespace boundaries", "MANUAL")
    ns_names = [n.metadata.name for n in core.list_namespace().items]
    print_manual(
        f"[REVIEW] Cluster namespaces = {ns_names}\n"
        "Verify each namespace has a clear administrative boundary."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="CIS Amazon EKS Benchmark - Section 4 remediation")
    parser.add_argument("--cluster-name", help="The name of the EKS cluster")
    parser.add_argument("--region", default="ap-southeast-1", help="AWS region")
    parser.add_argument(
        "--terraform-file",
        default=str(DEFAULT_EKS_TERRAFORM_FILE),
        help="Path to Terraform EKS main.tf",
    )
    parser.add_argument(
        "--target-namespace",
        default=DEFAULT_TARGET_NAMESPACE,
        help="Target namespace for 4.5.2 user workload migration",
    )
    parser.add_argument(
        "--apply-terraform",
        action="store_true",
        help="Run terraform init/apply after patching 4.1.7 Terraform configuration",
    )
    args = parser.parse_args()

    terraform_file = Path(args.terraform_file)

    print("=" * 80)
    print("CIS AMAZON EKS BENCHMARK - SECTION 4 REMEDIATION (BENCHMARK-PURE)")
    print("=" * 80)

    auto_fix_4_1_7(terraform_file, args.apply_terraform)
    auto_fix_4_4_1()
    auto_fix_4_5_2(args.target_namespace)
    review_manual_controls()

    print("\nDONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
