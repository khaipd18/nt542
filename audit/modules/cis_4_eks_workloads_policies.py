#!/usr/bin/env python3
"""
CIS Amazon EKS Benchmark - Section 4 Auditor

Audits section 4 controls against a live EKS/Kubernetes cluster after Terraform deploy.

This version is aligned more closely with the benchmark:
- Automated controls are reported as PASS / FAIL.
- Manual controls are reported as FAIL when a clear issue is found, and REVIEW when
  only manual verification is possible or the control appears compliant.
- System-managed Kubernetes/EKS objects are not treated as user findings where the
  benchmark intent is to review workload/security posture.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
}

# Environment variable names that commonly hold secrets when hardcoded.
SUSPICIOUS_ENV_NAMES = [
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "KEY",
    "ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
]

# Objects that are acceptable in the default namespace as system-managed items.
SYSTEM_DEFAULT_ALLOWED_PREFIXES = [
    "configmap/kube-root-ca.crt",
    "serviceaccount/default",
    "service/kubernetes",
    "endpoints/kubernetes",
    "endpointslice/kubernetes",
    "event/",
    "lease/",
]


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def run_cmd(cmd: List[str], timeout: int = 90) -> str:
    """Run a command and return stdout; raise with stderr on failure."""
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr}")
    return proc.stdout.strip()


def kubectl_json(args: List[str], timeout: int = 90) -> Dict[str, Any]:
    out = run_cmd(["kubectl", *args, "-o", "json"], timeout=timeout)
    return json.loads(out) if out else {}


def kubectl_text(args: List[str], timeout: int = 90) -> str:
    return run_cmd(["kubectl", *args], timeout=timeout)


def aws_json(args: List[str], timeout: int = 90) -> Dict[str, Any]:
    out = run_cmd(["aws", *args, "--output", "json"], timeout=timeout)
    return json.loads(out) if out else {}


def safe_get(obj: Any, path: Iterable[Any], default: Any = None) -> Any:
    cur = obj
    for key in path:
        try:
            if isinstance(cur, dict):
                cur = cur[key]
            elif isinstance(cur, list) and isinstance(key, int):
                cur = cur[key]
            else:
                return default
        except Exception:
            return default
    return cur


def flatten_subjects(binding: Dict[str, Any]) -> List[str]:
    subjects = []
    for s in binding.get("subjects", []) or []:
        kind = s.get("kind", "Unknown")
        name = s.get("name", "Unknown")
        ns = s.get("namespace")
        if ns:
            subjects.append(f"{kind}/{name} ({ns})")
        else:
            subjects.append(f"{kind}/{name}")
    return subjects or ["<none>"]


def list_api_resources(namespaced_only: bool = True) -> List[str]:
    args = ["api-resources", "--verbs=list"]
    if namespaced_only:
        args.append("--namespaced=true")
    args += ["-o", "name"]
    out = kubectl_text(args)
    return [x.strip() for x in out.splitlines() if x.strip()]


def is_system_namespace(name: str) -> bool:
    return name in SYSTEM_NAMESPACES


def spec_containers(podspec: Dict[str, Any]) -> List[Dict[str, Any]]:
    containers = []
    containers.extend(podspec.get("containers", []) or [])
    containers.extend(podspec.get("initContainers", []) or [])
    return containers


def get_podspec(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = (obj.get("kind") or "").lower()
    spec = obj.get("spec") or {}
    if kind == "pod":
        return spec
    if kind in {"deployment", "replicaset", "daemonset", "statefulset"}:
        return safe_get(obj, ["spec", "template", "spec"], None)
    if kind == "job":
        return safe_get(obj, ["spec", "template", "spec"], None)
    if kind == "cronjob":
        return safe_get(obj, ["spec", "jobTemplate", "spec", "template", "spec"], None)
    return None


def has_secret_key_ref_in_env(podspec: Dict[str, Any]) -> List[str]:
    matches = []
    for c in spec_containers(podspec):
        for env in c.get("env", []) or []:
            vf = env.get("valueFrom") or {}
            if "secretKeyRef" in vf:
                matches.append(f"{c.get('name', '<container>')}:{env.get('name', '<env>')}")
    return matches


def has_hardcoded_secret_env(podspec: Dict[str, Any]) -> List[str]:
    findings = []
    for c in spec_containers(podspec):
        for env in c.get("env", []) or []:
            env_name = env.get("name", "").upper()
            if any(token in env_name for token in SUSPICIOUS_ENV_NAMES):
                if "value" in env:
                    findings.append(f"{c.get('name', '<container>')}:{env.get('name', '<env>')}")
    return findings


def has_privileged_container(podspec: Dict[str, Any]) -> List[str]:
    matches = []
    for c in podspec.get("containers", []) or []:
        if safe_get(c, ["securityContext", "privileged"], False) is True:
            matches.append(c.get("name", "<container>"))
    for c in podspec.get("initContainers", []) or []:
        if safe_get(c, ["securityContext", "privileged"], False) is True:
            matches.append(f"init:{c.get('name', '<container>')}")
    return matches


def has_allow_privilege_escalation(podspec: Dict[str, Any]) -> List[str]:
    matches = []
    for c in spec_containers(podspec):
        if safe_get(c, ["securityContext", "allowPrivilegeEscalation"], False) is True:
            matches.append(c.get("name", "<container>"))
    return matches


def has_default_sa_mount_issue(podspec: Dict[str, Any]) -> bool:
    sa_name = podspec.get("serviceAccountName")
    automount = podspec.get("automountServiceAccountToken", None)
    if sa_name in (None, "", "default"):
        return automount is not False
    return False


def role_rule_violations(rule: Dict[str, Any]) -> List[str]:
    issues = []
    api_groups = rule.get("apiGroups", []) or []
    resources = rule.get("resources", []) or []
    verbs = rule.get("verbs", []) or []

    if "*" in api_groups or "*" in resources or "*" in verbs:
        issues.append("4.1.3")
    if "secrets" in resources and any(v in {"get", "list", "watch", "*"} for v in verbs):
        issues.append("4.1.2")
    if "pods" in resources and "create" in verbs:
        issues.append("4.1.4")
    if "persistentvolumes" in resources and "create" in verbs:
        issues.append("4.1.9")
    if "nodes/proxy" in resources:
        issues.append("4.1.10")
    if any(r in {"validatingwebhookconfigurations", "mutatingwebhookconfigurations"} for r in resources):
        issues.append("4.1.11")
    if "serviceaccounts/token" in resources and "create" in verbs:
        issues.append("4.1.12")
    if any(v in {"bind", "impersonate", "escalate"} for v in verbs):
        issues.append("4.1.8")

    return issues


def is_system_rbac_evidence(binding: Dict[str, Any], role_name: str) -> bool:
    """
    Treat obvious system-managed RBAC as REVIEW rather than FAIL.
    This keeps the auditor aligned with benchmark intent and reduces noise.
    """
    binding_name = binding.get("metadata", {}).get("name", "")
    namespace = binding.get("metadata", {}).get("namespace", "")
    subjects = flatten_subjects(binding)

    if namespace in SYSTEM_NAMESPACES:
        return True
    if binding_name.startswith(("system:", "eks:")):
        return True
    if role_name.startswith(("system:", "eks:")):
        return True

    # Default cluster-admin binding from system:masters is default system-managed state.
    if role_name == "cluster-admin" and binding_name == "cluster-admin":
        if any("system:masters" in s for s in subjects):
            return True

    # EKS default addon binding path.
    if binding_name == "eks:addon-cluster-admin":
        return True

    return False


def is_default_namespace_system_object(kind: str, name: str) -> bool:
    item = f"{kind}/{name}".lower()
    return any(item.startswith(prefix) for prefix in SYSTEM_DEFAULT_ALLOWED_PREFIXES)


# ---------------------------------------------------------------------
# Dataclass for findings
# ---------------------------------------------------------------------

@dataclass
class Finding:
    cis_id: str
    title: str
    benchmark_type: str  # Manual / Automated
    status: str           # PASS / FAIL / REVIEW
    scope: str
    evidence: str
    remediation: str
    details: Dict[str, Any]


# ---------------------------------------------------------------------
# RBAC scanning
# ---------------------------------------------------------------------

def load_rbac_objects() -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    clusterroles = kubectl_json(["get", "clusterroles"])
    roles = kubectl_json(["get", "roles", "--all-namespaces"])
    crbs = kubectl_json(["get", "clusterrolebindings"])
    rbs = kubectl_json(["get", "rolebindings", "--all-namespaces"])
    return clusterroles, roles, crbs.get("items", []), rbs.get("items", [])


def build_role_maps(clusterroles: Dict[str, Any], roles: Dict[str, Any]):
    cr_map = {item["metadata"]["name"]: item for item in clusterroles.get("items", [])}
    r_map = {
        (item["metadata"].get("namespace", ""), item["metadata"]["name"]): item
        for item in roles.get("items", [])
    }
    return cr_map, r_map


def audit_rbac() -> List[Finding]:
    clusterroles, roles, crbs, rbs = load_rbac_objects()
    cr_map, r_map = build_role_maps(clusterroles, roles)

    findings: List[Finding] = []
    seen: set[Tuple[str, str, str, str]] = set()

    manual_controls = {
        "4.1.1": False,
        "4.1.2": False,
        "4.1.3": False,
        "4.1.4": False,
        "4.1.5": False,
        "4.1.6": False,
        "4.1.8": False,
        "4.1.9": False,
        "4.1.10": False,
        "4.1.11": False,
        "4.1.12": False,
    }

    titles = {
        "4.1.1": "cluster-admin role is only used where required",
        "4.1.2": "Minimize access to secrets",
        "4.1.3": "Minimize wildcard use in Roles and ClusterRoles",
        "4.1.4": "Minimize access to create pods",
        "4.1.5": "default service accounts are not actively used",
        "4.1.6": "Service Account Tokens are only mounted where necessary",
        "4.1.8": "Limit use of the Bind, Impersonate and Escalate permissions",
        "4.1.9": "Minimize access to create persistent volumes",
        "4.1.10": "Minimize access to the proxy sub-resource of nodes",
        "4.1.11": "Minimize access to webhook configuration objects",
        "4.1.12": "Minimize access to the service account token creation",
    }

    remediations = {
        "4.1.1": "Identify all ClusterRoleBindings to cluster-admin; bind users to a lower-privileged role first, then delete the cluster-admin binding.",
        "4.1.2": "Remove get/list/watch access to secrets where possible.",
        "4.1.3": "Replace wildcards in Roles/ClusterRoles with specific resources and verbs.",
        "4.1.4": "Remove create access to pods where possible.",
        "4.1.5": "Create explicit service accounts for workloads and set automountServiceAccountToken: false on each default service account.",
        "4.1.6": "Set automountServiceAccountToken: false for pods and accounts that do not explicitly require API server access.",
        "4.1.8": "Remove bind/impersonate/escalate rights from subjects where possible.",
        "4.1.9": "Remove create access to PersistentVolumes where possible.",
        "4.1.10": "Remove access to nodes/proxy where possible.",
        "4.1.11": "Remove access to validatingwebhookconfigurations and mutatingwebhookconfigurations where possible.",
        "4.1.12": "Remove access to create serviceaccounts/token where possible.",
    }

    def add_finding(cis_id: str, status: str, scope: str, evidence: str, details: Dict[str, Any]):
        findings.append(
            Finding(
                cis_id=cis_id,
                title=titles[cis_id],
                benchmark_type="Manual",
                status=status,
                scope=scope,
                evidence=evidence,
                remediation=remediations[cis_id],
                details=details,
            )
        )

    def scan_role_obj(role_obj: Dict[str, Any], binding: Dict[str, Any], scope_label: str):
        role_name = role_obj["metadata"]["name"]
        binding_name = binding["metadata"]["name"]
        subjects = flatten_subjects(binding)
        for rule in role_obj.get("rules", []) or []:
            for cis_id in role_rule_violations(rule):
                key = (cis_id, scope_label, binding_name, role_name)
                if key in seen:
                    continue
                seen.add(key)

                manual_controls[cis_id] = True
                status = "REVIEW" if is_system_rbac_evidence(binding, role_name) else "FAIL"

                if cis_id == "4.1.3" and role_name == "cluster-admin":
                    # The benchmark default cluster-admin role is a known built-in; keep it as REVIEW.
                    status = "REVIEW"

                evidence = f"Binding={binding_name} Role={role_name} Subjects={', '.join(subjects)}"
                if cis_id == "4.1.10":
                    evidence = f"Binding={binding_name} Role={role_name} Subjects={', '.join(subjects)}"
                add_finding(
                    cis_id=cis_id,
                    status=status,
                    scope=scope_label,
                    evidence=evidence,
                    details={
                        "binding": binding_name,
                        "role": role_name,
                        "subjects": subjects,
                        "rule": rule,
                    },
                )

    # ClusterRoleBindings
    for b in crbs:
        role_ref = b.get("roleRef", {})
        role_kind = role_ref.get("kind", "")
        role_name = role_ref.get("name", "")
        if role_kind == "ClusterRole":
            role = cr_map.get(role_name)
            if role:
                scan_role_obj(role, b, "ClusterRoleBinding")

        if role_kind == "ClusterRole" and role_name == "cluster-admin":
            cis_id = "4.1.1"
            key = (cis_id, "ClusterRoleBinding", b["metadata"]["name"], "cluster-admin")
            if key not in seen:
                seen.add(key)
                manual_controls[cis_id] = True
                status = "REVIEW" if is_system_rbac_evidence(b, "cluster-admin") else "FAIL"
                evidence = f"Binding={b['metadata']['name']} Role=cluster-admin Subjects={', '.join(flatten_subjects(b))}"
                add_finding(
                    cis_id=cis_id,
                    status=status,
                    scope="ClusterRoleBinding",
                    evidence=evidence,
                    details={
                        "binding": b["metadata"]["name"],
                        "role": "cluster-admin",
                        "subjects": flatten_subjects(b),
                    },
                )

    # RoleBindings
    for b in rbs:
        role_ref = b.get("roleRef", {})
        role_kind = role_ref.get("kind", "")
        role_name = role_ref.get("name", "")
        ns = b.get("metadata", {}).get("namespace", "")
        if role_kind == "Role":
            role = r_map.get((ns, role_name))
            if role:
                scan_role_obj(role, b, "RoleBinding")
        elif role_kind == "ClusterRole":
            role = cr_map.get(role_name)
            if role:
                scan_role_obj(role, b, "RoleBinding->ClusterRole")

    # 4.1.5 default service accounts
    sa_items = kubectl_json(["get", "serviceaccounts", "--all-namespaces"]).get("items", [])
    sa_issues = False
    seen_sa = set()

    for sa in sa_items:
        name = sa.get("metadata", {}).get("name", "")
        ns = sa.get("metadata", {}).get("namespace", "")
        if name != "default":
            continue

        automount = sa.get("automountServiceAccountToken")
        has_issue = automount is not False
        # For system namespaces, keep the finding as REVIEW to reduce noise.
        status = "REVIEW" if ns in SYSTEM_NAMESPACES else ("FAIL" if has_issue else "REVIEW")
        if has_issue:
            sa_issues = True
            key = (ns, "default", "automount")
            if key not in seen_sa:
                seen_sa.add(key)
                findings.append(
                    Finding(
                        cis_id="4.1.5",
                        title=titles["4.1.5"],
                        benchmark_type="Manual",
                        status=status,
                        scope=f"ServiceAccount/{ns}/default",
                        evidence=f"automountServiceAccountToken={automount!r}",
                        remediation=remediations["4.1.5"],
                        details={"namespace": ns, "automountServiceAccountToken": automount},
                    )
                )

    # default SA bound to extra RoleBindings / ClusterRoleBindings
    for b in crbs + rbs:
        for s in b.get("subjects", []) or []:
            if s.get("kind") == "ServiceAccount" and s.get("name") == "default":
                sa_ns = s.get("namespace") or b.get("metadata", {}).get("namespace")
                if not sa_ns:
                    sa_ns = "default"
                key = (sa_ns, b["metadata"]["name"], "binding")
                if key in seen_sa:
                    continue
                seen_sa.add(key)
                sa_issues = True
                status = "REVIEW" if sa_ns in SYSTEM_NAMESPACES else "FAIL"
                findings.append(
                    Finding(
                        cis_id="4.1.5",
                        title=titles["4.1.5"],
                        benchmark_type="Manual",
                        status=status,
                        scope="ServiceAccount/default",
                        evidence=f"Binding={b['metadata']['name']} SubjectNamespace={sa_ns} RoleRef={b.get('roleRef', {}).get('kind')}/{b.get('roleRef', {}).get('name')}",
                        remediation=remediations["4.1.5"],
                        details={
                            "binding": b["metadata"]["name"],
                            "subject_namespace": sa_ns,
                            "roleRef": b.get("roleRef", {}),
                        },
                    )
                )

    if not sa_issues:
        findings.append(
            Finding(
                cis_id="4.1.5",
                title=titles["4.1.5"],
                benchmark_type="Manual",
                status="REVIEW",
                scope="ServiceAccount/default",
                evidence="No default service account issues detected.",
                remediation=remediations["4.1.5"],
                details={},
            )
        )

    # 4.1.6 service account tokens only mounted where necessary (skip system namespaces)
    pod_items = kubectl_json(["get", "pods", "--all-namespaces"]).get("items", [])
    pod_issues = False
    for pod in pod_items:
        ns = pod.get("metadata", {}).get("namespace", "")
        name = pod.get("metadata", {}).get("name", "")
        if is_system_namespace(ns):
            continue
        podspec = pod.get("spec", {}) or {}
        if has_default_sa_mount_issue(podspec):
            pod_issues = True
            findings.append(
                Finding(
                    cis_id="4.1.6",
                    title=titles["4.1.6"],
                    benchmark_type="Manual",
                    status="FAIL",
                    scope=f"Pod/{ns}/{name}",
                    evidence="automountServiceAccountToken is True or omitted",
                    remediation=remediations["4.1.6"],
                    details={"namespace": ns, "pod": name},
                )
            )
    if not pod_issues:
        findings.append(
            Finding(
                cis_id="4.1.6",
                title=titles["4.1.6"],
                benchmark_type="Manual",
                status="REVIEW",
                scope="Cluster Pods",
                evidence="No unnecessary service account token mounts detected in user namespaces.",
                remediation=remediations["4.1.6"],
                details={},
            )
        )

    # Summary REVIEWs for controls that produced no manual findings at all.
    for cis_id in ["4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.8", "4.1.9", "4.1.10", "4.1.11", "4.1.12"]:
        if manual_controls[cis_id]:
            continue
        findings.append(
            Finding(
                cis_id=cis_id,
                title=titles[cis_id],
                benchmark_type="Manual",
                status="REVIEW",
                scope="Cluster RBAC",
                evidence="No issues detected during audit; manual verification recommended.",
                remediation=remediations[cis_id],
                details={},
            )
        )

    return findings

def audit_eks_authentication_mode() -> Finding:

    args = global_args_cache.get("args")

    if not args or not args.cluster_name:
        return Finding(
            cis_id="4.1.7",
            title="Prefer API-based authentication over ConfigMap",
            benchmark_type="Automated",
            status="FAIL",
            scope="EKS Cluster",
            evidence="No --cluster-name supplied",
            remediation="Run audit with --cluster-name and --region.",
            details={},
        )

    cmd = [
        "eks",
        "describe-cluster",
        "--name",
        args.cluster_name,
    ]

    if args.region:
        cmd += ["--region", args.region]

    try:
        data = aws_json(cmd)

        mode = (
            data.get("cluster", {})
            .get("accessConfig", {})
            .get("authenticationMode", "UNKNOWN")
        )

        if mode in {"API", "API_AND_CONFIG_MAP"}:
            return Finding(
                cis_id="4.1.7",
                title="Prefer API-based authentication over ConfigMap",
                benchmark_type="Automated",
                status="PASS",
                scope=f"EKS/{args.cluster_name}",
                evidence=f"authenticationMode='{mode}'",
                remediation="No action required.",
                details={"authenticationMode": mode},
            )

        return Finding(
            cis_id="4.1.7",
            title="Prefer API-based authentication over ConfigMap",
            benchmark_type="Automated",
            status="FAIL",
            scope=f"EKS/{args.cluster_name}",
            evidence=f"authenticationMode='{mode}'",
            remediation="Use API or API_AND_CONFIG_MAP authentication mode.",
            details={"authenticationMode": mode},
        )

    except Exception as exc:
        return Finding(
            cis_id="4.1.7",
            title="Prefer API-based authentication over ConfigMap",
            benchmark_type="Automated",
            status="FAIL",
            scope="EKS Cluster",
            evidence=f"Unable to query EKS cluster: {exc}",
            remediation="Verify AWS credentials and cluster access.",
            details={},
        )


# ---------------------------------------------------------------------
# Pod security checks (4.2)
# ---------------------------------------------------------------------

def audit_pod_security() -> List[Finding]:
    findings: List[Finding] = []
    pods = kubectl_json(["get", "pods", "--all-namespaces"]).get("items", [])

    control_found = {
        "4.2.1": False,
        "4.2.2": False,
        "4.2.3": False,
        "4.2.4": False,
        "4.2.5": False,
    }

    titles = {
        "4.2.1": "Minimize the admission of privileged containers",
        "4.2.2": "Minimize hostPID admission",
        "4.2.3": "Minimize hostIPC admission",
        "4.2.4": "Minimize hostNetwork admission",
        "4.2.5": "Minimize allowPrivilegeEscalation",
    }
    remediations = {
        "4.2.1": "Add namespace policies / Pod Security Admission labels to restrict privileged containers.",
        "4.2.2": "Add namespace policies to restrict hostPID containers.",
        "4.2.3": "Add namespace policies to restrict hostIPC containers.",
        "4.2.4": "Add namespace policies to restrict hostNetwork containers.",
        "4.2.5": "Add namespace policies to restrict containers with allowPrivilegeEscalation=true.",
    }

    for pod in pods:
        ns = pod.get("metadata", {}).get("namespace", "")
        if is_system_namespace(ns):
            continue

        name = pod.get("metadata", {}).get("name", "")
        scope = f"Pod/{ns}/{name}"
        podspec = pod.get("spec", {}) or {}

        privileged = has_privileged_container(podspec)
        if privileged:
            control_found["4.2.1"] = True
            findings.append(
                Finding(
                    cis_id="4.2.1",
                    title=titles["4.2.1"],
                    benchmark_type="Manual",
                    status="FAIL",
                    scope=scope,
                    evidence=f"privileged containers={privileged}",
                    remediation=remediations["4.2.1"],
                    details={"namespace": ns, "pod": name, "containers": privileged},
                )
            )

        if podspec.get("hostPID") is True:
            control_found["4.2.2"] = True
            findings.append(
                Finding(
                    cis_id="4.2.2",
                    title=titles["4.2.2"],
                    benchmark_type="Manual",
                    status="FAIL",
                    scope=scope,
                    evidence="spec.hostPID=true",
                    remediation=remediations["4.2.2"],
                    details={"namespace": ns, "pod": name},
                )
            )

        if podspec.get("hostIPC") is True:
            control_found["4.2.3"] = True
            findings.append(
                Finding(
                    cis_id="4.2.3",
                    title=titles["4.2.3"],
                    benchmark_type="Manual",
                    status="FAIL",
                    scope=scope,
                    evidence="spec.hostIPC=true",
                    remediation=remediations["4.2.3"],
                    details={"namespace": ns, "pod": name},
                )
            )

        if podspec.get("hostNetwork") is True:
            control_found["4.2.4"] = True
            findings.append(
                Finding(
                    cis_id="4.2.4",
                    title=titles["4.2.4"],
                    benchmark_type="Manual",
                    status="FAIL",
                    scope=scope,
                    evidence="spec.hostNetwork=true",
                    remediation=remediations["4.2.4"],
                    details={"namespace": ns, "pod": name},
                )
            )

        ape = has_allow_privilege_escalation(podspec)
        if ape:
            control_found["4.2.5"] = True
            findings.append(
                Finding(
                    cis_id="4.2.5",
                    title=titles["4.2.5"],
                    benchmark_type="Manual",
                    status="FAIL",
                    scope=scope,
                    evidence=f"allowPrivilegeEscalation={ape}",
                    remediation=remediations["4.2.5"],
                    details={"namespace": ns, "pod": name, "containers": ape},
                )
            )

    # If a control had no issues at all, emit one REVIEW summary instead of PASS.
    for cis_id in ["4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5"]:
        if control_found[cis_id]:
            continue
        findings.append(
            Finding(
                cis_id=cis_id,
                title=titles[cis_id],
                benchmark_type="Manual",
                status="REVIEW",
                scope="Cluster Pods",
                evidence=f"No {titles[cis_id].lower()} detected in user namespaces.",
                remediation=remediations[cis_id],
                details={},
            )
        )

    return findings


# ---------------------------------------------------------------------
# CNI / NetworkPolicy / Secrets / Namespaces
# ---------------------------------------------------------------------

def audit_cni_support() -> Finding:
    ds = kubectl_json(["get", "daemonsets", "-n", "kube-system"]).get("items", [])
    ds_names = [item["metadata"]["name"] for item in ds]
    ds_joined = " ".join(ds_names).lower()

    detected = []
    supports_policy = False

    if "aws-node" in ds_names:
        detected.append("aws-vpc-cni")
        supports_policy = True
    if "calico-node" in ds_names:
        detected.append("calico")
        supports_policy = True
    if "cilium" in ds_joined:
        detected.append("cilium")
        supports_policy = True
    if "flannel" in ds_joined:
        detected.append("flannel")

    # Manual control: always REVIEW with evidence, because benchmark requires documentation review.
    return Finding(
        cis_id="4.3.1",
        title="CNI plugin supports network policies",
        benchmark_type="Manual",
        status="REVIEW",
        scope="CNI plugin",
        evidence=f"detected_plugins={detected or ['<none>']}, supports_network_policy={supports_policy}",
        remediation="Review the CNI documentation and ensure network-policy support exists; for enforcement use a deny-all baseline or a policy-capable CNI like Calico.",
        details={"daemonsets": ds_names, "detected_plugins": detected, "supports_network_policy": supports_policy},
    )


def audit_network_policies() -> List[Finding]:
    findings: List[Finding] = []
    namespaces = kubectl_json(["get", "namespaces"]).get("items", [])
    policies = kubectl_json(["get", "networkpolicy", "--all-namespaces"]).get("items", [])

    policy_count_by_ns = defaultdict(int)
    for p in policies:
        policy_count_by_ns[p["metadata"]["namespace"]] += 1

    any_missing = False
    for ns in namespaces:
        ns_name = ns["metadata"]["name"]
        if is_system_namespace(ns_name):
            continue

        if policy_count_by_ns.get(ns_name, 0) == 0:
            any_missing = True
            findings.append(
                Finding(
                    cis_id="4.3.2",
                    title="All namespaces have Network Policies defined",
                    benchmark_type="Manual",
                    status="FAIL",
                    scope=f"Namespace/{ns_name}",
                    evidence="No NetworkPolicy objects in namespace",
                    remediation="Create at least one NetworkPolicy in each user namespace (for example, a default-deny policy).",
                    details={"namespace": ns_name},
                )
            )

    if not any_missing:
        findings.append(
            Finding(
                cis_id="4.3.2",
                title="All namespaces have Network Policies defined",
                benchmark_type="Manual",
                status="REVIEW",
                scope="User namespaces",
                evidence="NetworkPolicy objects exist in all user namespaces.",
                remediation="Create at least one NetworkPolicy in each user namespace (for example, a default-deny policy).",
                details={},
            )
        )

    return findings


def audit_secret_management() -> List[Finding]:
    findings: List[Finding] = []

    # 4.4.1 automated: secretKeyRef in env vars and hardcoded secret-like envs
    workload_kinds = ["pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"]
    any_secret_env_findings = False

    for kind in workload_kinds:
        try:
            objs = kubectl_json(["get", kind, "--all-namespaces"]).get("items", [])
        except Exception:
            continue

        for obj in objs:
            ns = obj.get("metadata", {}).get("namespace", "")
            if is_system_namespace(ns):
                continue

            name = obj.get("metadata", {}).get("name", "")
            podspec = get_podspec(obj)
            if not podspec:
                continue

            refs = has_secret_key_ref_in_env(podspec)
            hardcoded = has_hardcoded_secret_env(podspec)
            if refs or hardcoded:
                any_secret_env_findings = True
                findings.append(
                    Finding(
                        cis_id="4.4.1",
                        title="Prefer secrets as files over environment variables",
                        benchmark_type="Automated",
                        status="FAIL",
                        scope=f"{obj.get('kind', kind)}/{ns}/{name}",
                        evidence=f"secretKeyRef={refs}, hardcodedSecrets={hardcoded}",
                        remediation="Rewrite application code to read secrets from mounted secret files instead of environment variables.",
                        details={"namespace": ns, "name": name, "kind": obj.get("kind", kind), "secretKeyRef": refs, "hardcodedSecrets": hardcoded},
                    )
                )

    if not any_secret_env_findings:
        findings.append(
            Finding(
                cis_id="4.4.1",
                title="Prefer secrets as files over environment variables",
                benchmark_type="Automated",
                status="PASS",
                scope="User workloads",
                evidence="No secretKeyRef or hardcoded secret-like env vars detected in user workloads.",
                remediation="No action required.",
                details={},
            )
        )

    # 4.4.2 manual
    findings.append(
        Finding(
            cis_id="4.4.2",
            title="Consider external secret storage",
            benchmark_type="Manual",
            status="REVIEW",
            scope="Secrets management",
            evidence="Check for Vault / External Secrets Operator",
            remediation="Prefer cloud-provider secret storage.",
            details={},
        )
    )

    return findings


def audit_namespace_governance() -> List[Finding]:
    findings: List[Finding] = []

    # 4.5.1 manual
    namespaces = kubectl_json(["get", "namespaces"]).get("items", [])
    ns_names = [n["metadata"]["name"] for n in namespaces]

    findings.append(
        Finding(
            cis_id="4.5.1",
            title="Create administrative boundaries between resources using namespaces",
            benchmark_type="Manual",
            status="REVIEW",
            scope="Cluster namespaces",
            evidence=f"namespaces={ns_names}",
            remediation="Create namespaces for objects in your deployment as needed and administer them separately.",
            details={"namespaces": ns_names},
        )
    )

    # 4.5.2 automated
    default_objects: List[str] = []

    try:
        resources = list_api_resources(namespaced_only=True)
        for res in resources:
            try:
                out = kubectl_json(["get", res, "-n", "default"]).get("items", [])
            except Exception:
                continue

            for item in out:
                kind = item.get("kind", res)
                name = item.get("metadata", {}).get("name", "")
                default_objects.append(f"{kind}/{name}")
    except Exception as exc:
        default_objects.append(f"<error collecting default namespace objects: {exc}>")

    non_system = []
    for obj in default_objects:
        lower = obj.lower()
        if any(lower.startswith(prefix) for prefix in SYSTEM_DEFAULT_ALLOWED_PREFIXES):
            continue
        non_system.append(obj)

    if non_system:
        findings.append(
            Finding(
                cis_id="4.5.2",
                title="The default namespace should not be used",
                benchmark_type="Automated",
                status="FAIL",
                scope="Namespace/default",
                evidence=f"objects found: {non_system[:30]}",
                remediation="Create namespaces for resources and ensure all new resources are created in a specific namespace.",
                details={"default_objects": non_system},
            )
        )
    else:
        findings.append(
            Finding(
                cis_id="4.5.2",
                title="The default namespace should not be used",
                benchmark_type="Automated",
                status="PASS",
                scope="Namespace/default",
                evidence="Only system-managed resources detected in default namespace.",
                remediation="No action required.",
                details={"default_objects": default_objects},
            )
        )

    return findings


# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------

def print_findings(findings: List[Finding]) -> None:
    total_fail = sum(1 for f in findings if f.status == "FAIL")
    total_review = sum(1 for f in findings if f.status == "REVIEW")
    total_pass = sum(1 for f in findings if f.status == "PASS")

    print(f"\nSection 4 audit summary: PASS={total_pass} FAIL={total_fail} REVIEW={total_review}\n")

    for f in findings:
        print(f"[{f.status}] CIS {f.cis_id} ({f.benchmark_type}) - {f.title}")
        print(f"  Scope      : {f.scope}")
        print(f"  Evidence   : {f.evidence}")
        print(f"  Remediation: {f.remediation}")
        print()


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

global_args_cache: Dict[str, Any] = {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS Amazon EKS Benchmark Section 4")
    parser.add_argument("--cluster-name", help="EKS cluster name for 4.1.7")
    parser.add_argument("--region", default=None, help="AWS region, for example ap-southeast-1")
    args = parser.parse_args()

    global_args_cache["args"] = args

    findings: List[Finding] = []
    findings.extend(audit_rbac())
    findings.append(audit_eks_authentication_mode())
    findings.extend(audit_pod_security())
    findings.append(audit_cni_support())
    findings.extend(audit_network_policies())
    findings.extend(audit_secret_management())
    findings.extend(audit_namespace_governance())
    findings.append(audit_eks_authentication_mode())

    print_findings(findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
