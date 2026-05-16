#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass

SYSTEM_NAMESPACE_PREFIXES = {"kube-system", "kube-public", "kube-node-lease"}

@dataclass
class Finding:
    cis_id: str
    title: str
    bench_type: str
    status: str
    scope: str
    evidence: str

def run(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

def kubectl_json(args):
    code, out, err = run(["kubectl"] + args)
    if code != 0:
        raise RuntimeError(f"lệnh kubectl {' '.join(args)} thất bại: {err or out}")
    if not out:
        return {}
    return json.loads(out)

def get_namespaced_resources():
    code, out, err = run(["kubectl", "api-resources", "--verbs=list", "--namespaced", "-o", "name"])
    if code != 0:
        raise RuntimeError(f"lệnh kubectl api-resources thất bại: {err or out}")
    resources = [line.strip() for line in out.splitlines() if line.strip()]
    skip = {
        "bindings", "componentstatuses", "events", "localsubjectaccessreviews",
        "tokenreviews", "subjectaccessreviews", "pods/attach", "pods/exec",
        "pods/log", "pods/portforward", "pods/proxy", "services/proxy",
        "nodes/proxy", "persistentvolumeclaims/status", "pods/status",
        "replicationcontrollers/status", "deployments/status", "statefulsets/status",
        "daemonsets/status", "replicasets/status", "horizontalpodautoscalers/status",
        "jobs/status", "cronjobs/status",
    }
    filtered = []
    for r in resources:
        if "/" in r and r not in {"events.k8s.io", "events"}:
            continue
        if r in skip:
            continue
        filtered.append(r)
    return filtered

def audit_cis_4_1_3():
    findings = []
    fail_count = 0

    def scan_role_list(kind, args_prefix):
        nonlocal fail_count
        try:
            data = kubectl_json(args_prefix + ["-o", "json"])
        except Exception as e:
            findings.append(Finding("4.1.3", "Hạn chế sử dụng wildcard trong Roles và ClusterRoles", "Thủ công", "FAIL", "Cluster RBAC", f"Không thể đọc {kind}: {e}"))
            return

        for item in data.get("items", []):
            meta = item.get("metadata", {})
            name = meta.get("name", "<unknown>")
            namespace = meta.get("namespace", "")
            
            for rule in item.get("rules", []) or []:
                api_groups = rule.get("apiGroups", []) or []
                resources = rule.get("resources", []) or []
                verbs = rule.get("verbs", []) or []
                
                if "*" in api_groups or "*" in resources or "*" in verbs:
                    scope_ns = f"{namespace}/" if namespace else ""
                    findings.append(Finding(
                        cis_id="4.1.3",
                        title="Hạn chế sử dụng wildcard trong Roles và ClusterRoles",
                        bench_type="Thủ công",
                        status="FAIL",
                        scope=f"{kind}/{scope_ns}{name}",
                        evidence=f"apiGroups={api_groups}, resources={resources}, verbs={verbs}"
                    ))
                    fail_count += 1

    scan_role_list("Role", ["get", "roles", "--all-namespaces"])
    scan_role_list("ClusterRole", ["get", "clusterroles"])

    if fail_count == 0:
        findings.append(Finding("4.1.3", "Hạn chế sử dụng wildcard trong Roles và ClusterRoles", "Thủ công", "PASS", "Cluster RBAC", "Không tìm thấy quy tắc wildcard nào."))
    return findings

def audit_cis_4_2_1():
    findings = []
    try:
        data = kubectl_json(["get", "pods", "--all-namespaces", "-o", "json"])
    except Exception as e:
        return [Finding("4.2.1", "Hạn chế cấp phép cho privileged containers", "Thủ công", "FAIL", "Cluster Pods", f"Lỗi: {e}")]

    fail_count = 0
    for pod in data.get("items", []):
        meta = pod.get("metadata", {})
        spec = pod.get("spec", {})
        namespace = meta.get("namespace", "")
        pod_name = meta.get("name", "<unknown>")

        if namespace in SYSTEM_NAMESPACE_PREFIXES:
            continue

        privileged_containers = []
        for section_name, containers in [
            ("containers", spec.get("containers", []) or []),
            ("initContainers", spec.get("initContainers", []) or []),
            ("ephemeralContainers", spec.get("ephemeralContainers", []) or []),
        ]:
            for c in containers:
                sec = c.get("securityContext", {}) or {}
                if sec.get("privileged") is True:
                    privileged_containers.append(c.get("name", "<unknown>"))
        
        if privileged_containers:
            findings.append(Finding(
                cis_id="4.2.1",
                title="Hạn chế cấp phép cho privileged containers",
                bench_type="Thủ công",
                status="FAIL",
                scope=f"Pod/{namespace}/{pod_name}",
                evidence=f"privileged containers={privileged_containers}"
            ))
            fail_count += 1
            
    if fail_count == 0:
        findings.append(Finding("4.2.1", "Hạn chế cấp phép cho privileged containers", "Thủ công", "PASS", "Cluster Pods", "Không tìm thấy privileged container nào."))
    return findings

def audit_cis_4_2_4():
    findings = []
    try:
        data = kubectl_json(["get", "pods", "--all-namespaces", "-o", "json"])
    except Exception as e:
        return [Finding("4.2.4", "Hạn chế cấp phép hostNetwork", "Thủ công", "FAIL", "Cluster Pods", f"Lỗi: {e}")]

    fail_count = 0
    for pod in data.get("items", []):
        meta = pod.get("metadata", {})
        spec = pod.get("spec", {})
        namespace = meta.get("namespace", "")
        pod_name = meta.get("name", "<unknown>")

        if namespace in SYSTEM_NAMESPACE_PREFIXES:
            continue

        if spec.get("hostNetwork") is True:
            findings.append(Finding(
                cis_id="4.2.4",
                title="Hạn chế cấp phép hostNetwork",
                bench_type="Thủ công",
                status="FAIL",
                scope=f"Pod/{namespace}/{pod_name}",
                evidence="spec.hostNetwork=true"
            ))
            fail_count += 1
            
    if fail_count == 0:
        findings.append(Finding("4.2.4", "Hạn chế cấp phép hostNetwork", "Thủ công", "PASS", "Cluster Pods", "Không tìm thấy container nào sử dụng hostNetwork."))
    return findings

def audit_cis_4_3_2():
    findings = []
    try:
        namespaces = kubectl_json(["get", "namespaces", "-o", "json"]).get("items", [])
        np_data = kubectl_json(["get", "networkpolicies", "--all-namespaces", "-o", "json"])
    except Exception as e:
        return [Finding("4.3.2", "Tất cả các namespace phải định nghĩa Network Policies", "Thủ công", "FAIL", "Cluster Namespaces", f"Lỗi: {e}")]

    ns_with_np = set()
    for item in np_data.get("items", []):
        ns_with_np.add(item.get("metadata", {}).get("namespace", ""))

    fail_count = 0
    for ns in namespaces:
        ns_name = ns.get("metadata", {}).get("name", "")
        if ns_name in SYSTEM_NAMESPACE_PREFIXES:
            continue
        if ns_name not in ns_with_np:
            findings.append(Finding(
                cis_id="4.3.2",
                title="Tất cả các namespace phải định nghĩa Network Policies",
                bench_type="Thủ công",
                status="FAIL",
                scope=f"Namespace/{ns_name}",
                evidence="Không có đối tượng NetworkPolicy nào trong namespace"
            ))
            fail_count += 1
            
    if fail_count == 0:
        findings.append(Finding("4.3.2", "Tất cả các namespace phải định nghĩa Network Policies", "Thủ công", "PASS", "Cluster Namespaces", "Tất cả user namespace đều đã có Network Policies."))
    return findings

def audit_cis_4_5_2():
    findings = []
    try:
        resources = get_namespaced_resources()
    except Exception as e:
        return [Finding("4.5.2", "Không nên sử dụng default namespace", "Tự động", "FAIL", "Namespace/default", f"Lỗi: {e}")]

    found_objects = []
    for resource in resources:
        code, out, err = run(["kubectl", "get", resource, "-n", "default", "-o", "json", "--ignore-not-found"])
        if code != 0 or not out:
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            continue

        items = data.get("items", [])
        for item in items:
            meta = item.get("metadata", {})
            kind = item.get("kind", resource)
            name = meta.get("name", "<unknown>")
            namespace = meta.get("namespace", "default")

            kind_lower = kind.lower()
            
            # 1. Bỏ qua Service 'kubernetes' và các Endpoints/EndpointSlice đi kèm
            if name == "kubernetes" and kind_lower in {"service", "endpoints", "endpointslice"}:
                continue
            
            # 2. Bỏ qua các thành phần hệ thống mặc định không thể xóa
            if name == "kube-root-ca.crt" and kind_lower == "configmap":
                continue
            if name == "default" and kind_lower == "serviceaccount":
                continue
                
            # 3. Bỏ qua các Event (nhật ký hệ thống tạm thời không phải là workload)
            if kind_lower == "event":
                continue

            found_objects.append(f"{kind}/{name}")

    if found_objects:
        findings.append(Finding(
            cis_id="4.5.2",
            title="Không nên sử dụng default namespace",
            bench_type="Tự động",
            status="FAIL",
            scope="Namespace/default",
            evidence=f"tìm thấy các đối tượng: {found_objects}"
        ))
    else:
        findings.append(Finding("4.5.2", "Không nên sử dụng default namespace", "Tự động", "PASS", "Namespace/default", "Không tìm thấy user workload nào trong default namespace."))
        
    return findings

def main():
    parser = argparse.ArgumentParser(description="Kiểm tra CIS Amazon EKS Benchmark Phần 4.")
    parser.add_argument("--json", action="store_true", help="In kết quả dưới dạng JSON")
    args = parser.parse_args()

    checks = [
        audit_cis_4_1_3,
        audit_cis_4_2_1,
        audit_cis_4_2_4,
        audit_cis_4_3_2,
        audit_cis_4_5_2,
    ]

    all_findings = []
    for fn in checks:
        all_findings.extend(fn())

    if args.json:
        # Hỗ trợ xuất JSON nếu cần thiết (dùng asdict để chuyển đổi đối tượng dataclass)
        import dataclasses
        print(json.dumps([dataclasses.asdict(f) for f in all_findings], indent=2))
        sys.exit(0)

    total_pass = sum(1 for f in all_findings if f.status == "PASS")
    total_fail = sum(1 for f in all_findings if f.status == "FAIL")
    total_review = sum(1 for f in all_findings if f.status == "REVIEW")

    print(f"\nTổng kết đánh giá Phần 4: PASS={total_pass} FAIL={total_fail} REVIEW={total_review}\n")

    for f in all_findings:
        print(f"[{f.status}] CIS {f.cis_id} ({f.bench_type}) - {f.title}")
        print(f"  Phạm vi       : {f.scope}")
        print(f"  Bằng chứng    : {f.evidence}\n")

    sys.exit(0 if total_fail == 0 else 1)

if __name__ == "__main__":
    main()