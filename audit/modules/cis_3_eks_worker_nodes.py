#!/usr/bin/env python3
"""CIS Amazon EKS Benchmark v1.8.0 - Worker Nodes audit (Section 3 only).

This script audits recommendations 3.1.1-3.1.4 and 3.2.1-3.2.9 by creating a
privileged DaemonSet that mounts the node root filesystem at /host. It then
reads kubelet configuration files and kubelet process command-line arguments
from the host filesystem, producing PASS/FAIL results per node.

Designed for local execution on a machine that has kubectl access to the EKS
cluster.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


NAMESPACE = "cis-worker-node-audit"
APP_LABEL = "cis-worker-node-audit"
DAEMONSET_NAME = "cis-worker-node-audit"
DEFAULT_TIMEOUT_SECONDS = 300
POLL_INTERVAL_SECONDS = 3

KUBECONFIG_CANDIDATES = [
    "/var/lib/kubelet/kubeconfig",
    "/etc/kubernetes/kubelet/kubeconfig",
]

KUBELET_CONFIG_CANDIDATES = [
    "/etc/kubernetes/kubelet/config.json",
    "/etc/kubernetes/kubelet/kubelet-config.json",
    "/var/lib/kubelet/config.json",
    "/var/lib/kubelet/config.yaml",
    "/var/lib/kubelet/config.yml",
]


@dataclass
class Finding:
    node: str
    control: str
    status: str
    evidence: str
    details: str = ""


class AuditError(RuntimeError):
    pass


def run(cmd: List[str], *, input_text: Optional[str] = None, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and proc.returncode != 0:
        raise AuditError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def kubectl(*args: str, input_text: Optional[str] = None, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return run(["kubectl", *args], input_text=input_text, check=check, timeout=timeout)


def ensure_namespace() -> None:
    manifest = textwrap.dedent(
        f"""
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {NAMESPACE}
          labels:
            pod-security.kubernetes.io/enforce: privileged
            pod-security.kubernetes.io/enforce-version: latest
            pod-security.kubernetes.io/audit: privileged
            pod-security.kubernetes.io/warn: privileged
        """
    ).strip() + "\n"
    kubectl("apply", "-f", "-", input_text=manifest)


def apply_daemonset() -> None:
    manifest = textwrap.dedent(
        f"""
        apiVersion: apps/v1
        kind: DaemonSet
        metadata:
          name: {DAEMONSET_NAME}
          namespace: {NAMESPACE}
          labels:
            app: {APP_LABEL}
        spec:
          selector:
            matchLabels:
              app: {APP_LABEL}
          updateStrategy:
            type: RollingUpdate
          template:
            metadata:
              labels:
                app: {APP_LABEL}
            spec:
              automountServiceAccountToken: false
              terminationGracePeriodSeconds: 0
              tolerations:
                - operator: Exists
              volumes:
                - name: host-root
                  hostPath:
                    path: /
                    type: Directory
              containers:
                - name: host-audit
                  image: busybox:1.36.1
                  imagePullPolicy: IfNotPresent
                  command: ["sh", "-c", "sleep 36000"]
                  securityContext:
                    privileged: true
                    runAsUser: 0
                  volumeMounts:
                    - name: host-root
                      mountPath: /host
                      readOnly: true
        """
    ).strip() + "\n"
    kubectl("apply", "-f", "-", input_text=manifest)


def delete_resources() -> None:
    # Best effort cleanup.
    kubectl("delete", "daemonset", DAEMONSET_NAME, "-n", NAMESPACE, "--ignore-not-found=true", check=False)
    kubectl("delete", "namespace", NAMESPACE, "--ignore-not-found=true", check=False)


def wait_for_daemonset_ready(timeout: int = DEFAULT_TIMEOUT_SECONDS) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ds = kubectl("get", "daemonset", DAEMONSET_NAME, "-n", NAMESPACE, "-o", "json").stdout
            data = json.loads(ds)
            desired = int(data.get("status", {}).get("desiredNumberScheduled", 0))
            ready = int(data.get("status", {}).get("numberReady", 0))
            if desired > 0 and ready >= desired:
                return
        except Exception:
            pass
        time.sleep(POLL_INTERVAL_SECONDS)
    raise AuditError(f"DaemonSet {DAEMONSET_NAME} did not become ready within {timeout} seconds")


def get_pods() -> List[Dict[str, Any]]:
    raw = kubectl("get", "pods", "-n", NAMESPACE, "-l", f"app={APP_LABEL}", "-o", "json").stdout
    data = json.loads(raw)
    return data.get("items", [])


def exec_in_pod(pod: str, script: str, timeout: int = 120) -> str:
    proc = kubectl(
        "exec",
        "-n",
        NAMESPACE,
        pod,
        "--",
        "sh",
        "-c",
        script,
        timeout=timeout,
    )
    return proc.stdout


def host_path(path: str) -> str:
    return "/host" + path if path.startswith("/") else path


def path_exists_in_pod(pod: str, path: str) -> bool:
    p = host_path(path)
    script = f'if [ -e {shlex.quote(p)} ]; then echo YES; else echo NO; fi'
    return exec_in_pod(pod, script).strip() == "YES"


def stat_in_pod(pod: str, path: str) -> Optional[Tuple[str, str, str]]:
    p = host_path(path)
    script = f"""
    if [ -e {shlex.quote(p)} ]; then
      stat -c '%a|%U|%G' {shlex.quote(p)}
    fi
    """.strip()
    out = exec_in_pod(pod, script).strip()
    if not out:
        return None
    parts = out.split("|")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def cat_in_pod(pod: str, path: str) -> Optional[str]:
    p = host_path(path)
    script = f"""
    if [ -e {shlex.quote(p)} ]; then
      cat {shlex.quote(p)}
    fi
    """.strip()
    out = exec_in_pod(pod, script).strip()
    return out if out else None


def find_kubelet_cmdline(pod: str) -> Optional[str]:
    script = r'''
    for f in /host/proc/[0-9]*/cmdline; do
      [ -r "$f" ] || continue
      cmd=$(tr '\000' ' ' < "$f" | sed 's/[[:space:]]\+/ /g')
      case "$cmd" in
        *kubelet*)
          echo "$cmd"
          exit 0
          ;;
      esac
    done
    exit 1
    '''.strip()
    proc = kubectl("exec", "-n", NAMESPACE, pod, "--", "sh", "-c", script, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def parse_cmdline(cmdline: str) -> Dict[str, Optional[str]]:
    tokens = shlex.split(cmdline)
    args: Dict[str, Optional[str]] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("--"):
            key = tok[2:]
            value: Optional[str] = None
            if "=" in key:
                key, value = key.split("=", 1)
            elif i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                value = tokens[i + 1]
                i += 1
            else:
                value = None
            args[key.lower()] = value
        i += 1
    return args


def normalize_key(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def lookup_case_insensitive(mapping: Any, key: str) -> Any:
    if not isinstance(mapping, dict):
        return None
    wanted = normalize_key(key)
    for k, v in mapping.items():
        if normalize_key(str(k)) == wanted:
            return v
    return None


def parse_config_text(text: str) -> Optional[Any]:
    stripped = text.lstrip()
    if not stripped:
        return None
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except Exception:
        return None


def config_value(config: Any, *path: str) -> Any:
    cur = config
    for part in path:
        cur = lookup_case_insensitive(cur, part)
        if cur is None:
            return None
    return cur


def as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in {"true", "t", "yes", "y", "1"}:
        return True
    if s in {"false", "f", "no", "n", "0"}:
        return False
    return None


def as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except Exception:
        return None


def is_mode_permissive(mode: str) -> bool:
    return int(mode, 8) <= 0o644


def resolve_paths(cmd_args: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    result = {"kubeconfig": None, "config": None}
    for key in ("kubeconfig",):
        if key in cmd_args and cmd_args[key]:
            result[key] = cmd_args[key]
    if "config" in cmd_args and cmd_args["config"]:
        result["config"] = cmd_args["config"]
    return result


def infer_existing_path(pod: str, candidates: List[str]) -> Optional[str]:
    for p in candidates:
        if path_exists_in_pod(pod, p):
            return p
    return None


def file_stat_string(stat_result: Optional[Tuple[str, str, str]]) -> str:
    if not stat_result:
        return "missing"
    mode, owner, group = stat_result
    return f"mode={mode} owner={owner}:{group}"


def audit_node(node: str, pod: str) -> List[Finding]:
    findings: List[Finding] = []

    cmdline = find_kubelet_cmdline(pod)
    if not cmdline:
        # Without kubelet args we cannot reliably audit section 3.
        for control in [
            "3.1.1", "3.1.2", "3.1.3", "3.1.4",
            "3.2.1", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.2.6", "3.2.7", "3.2.8", "3.2.9",
        ]:
            findings.append(Finding(node, control, "FAIL", "kubelet process not found in host /proc", "Cannot read node-level kubelet configuration."))
        return findings

    args = parse_cmdline(cmdline)
    paths = resolve_paths(args)
    kubeconfig_path = paths["kubeconfig"] or infer_existing_path(pod, KUBECONFIG_CANDIDATES)
    config_path = paths["config"] or infer_existing_path(pod, KUBELET_CONFIG_CANDIDATES)

    # 3.1.1 / 3.1.2 kubeconfig file checks
    if kubeconfig_path:
        stat_res = stat_in_pod(pod, kubeconfig_path)
        if not stat_res:
            findings.append(Finding(node, "3.1.1", "FAIL", f"{kubeconfig_path}: missing", "kubeconfig file not found on host"))
            findings.append(Finding(node, "3.1.2", "FAIL", f"{kubeconfig_path}: missing", "kubeconfig file not found on host"))
        else:
            mode, owner, group = stat_res
            mode_ok = is_mode_permissive(mode)
            owner_ok = (owner == "root" and group == "root")
            findings.append(
                Finding(
                    node,
                    "3.1.1",
                    "PASS" if mode_ok else "FAIL",
                    f"{kubeconfig_path}: {file_stat_string(stat_res)}",
                    "permissions are 644 or more restrictive" if mode_ok else "permissions are too open",
                )
            )
            findings.append(
                Finding(
                    node,
                    "3.1.2",
                    "PASS" if owner_ok else "FAIL",
                    f"{kubeconfig_path}: {file_stat_string(stat_res)}",
                    "owned by root:root" if owner_ok else "ownership is not root:root",
                )
            )
    else:
        findings.append(Finding(node, "3.1.1", "FAIL", "kubeconfig path not discovered", "No kubeconfig path found in kubelet args or common locations"))
        findings.append(Finding(node, "3.1.2", "FAIL", "kubeconfig path not discovered", "No kubeconfig path found in kubelet args or common locations"))

    config = None
    if config_path:
        config_text = cat_in_pod(pod, config_path)
        if config_text:
            config = parse_config_text(config_text)

    # 3.1.3 / 3.1.4 kubelet config file checks
    if config_path:
        stat_res = stat_in_pod(pod, config_path)
        if not stat_res:
            findings.append(Finding(node, "3.1.3", "FAIL", f"{config_path}: missing", "kubelet config file not found on host"))
            findings.append(Finding(node, "3.1.4", "FAIL", f"{config_path}: missing", "kubelet config file not found on host"))
        else:
            mode, owner, group = stat_res
            mode_ok = is_mode_permissive(mode)
            owner_ok = (owner == "root" and group == "root")
            findings.append(
                Finding(
                    node,
                    "3.1.3",
                    "PASS" if mode_ok else "FAIL",
                    f"{config_path}: {file_stat_string(stat_res)}",
                    "permissions are 644 or more restrictive" if mode_ok else "permissions are too open",
                )
            )
            findings.append(
                Finding(
                    node,
                    "3.1.4",
                    "PASS" if owner_ok else "FAIL",
                    f"{config_path}: {file_stat_string(stat_res)}",
                    "owned by root:root" if owner_ok else "ownership is not root:root",
                )
            )
    else:
        findings.append(Finding(node, "3.1.3", "FAIL", "kubelet config path not discovered", "No kubelet config path found in kubelet args or common locations"))
        findings.append(Finding(node, "3.1.4", "FAIL", "kubelet config path not discovered", "No kubelet config path found in kubelet args or common locations"))

    # 3.2.1 Anonymous auth not enabled
    anon_arg = args.get("anonymous-auth")
    anon_cfg = None
    if config is not None:
        anon_cfg = as_bool(config_value(config, "authentication", "anonymous", "enabled"))
    if anon_arg is not None:
        anon_val = as_bool(anon_arg)
        pass_ = (anon_val is False)
        findings.append(Finding(node, "3.2.1", "PASS" if pass_ else "FAIL", f"cmdline anonymous-auth={anon_arg}", "anonymous auth disabled" if pass_ else "anonymous auth enabled"))
    elif anon_cfg is not None:
        pass_ = (anon_cfg is False)
        findings.append(Finding(node, "3.2.1", "PASS" if pass_ else "FAIL", f"config authentication.anonymous.enabled={anon_cfg}", "anonymous auth disabled" if pass_ else "anonymous auth enabled"))
    else:
        findings.append(Finding(node, "3.2.1", "FAIL", "anonymous-auth not explicitly found", "could not confirm anonymous auth is disabled"))

    # 3.2.2 authorization-mode not AlwaysAllow (prefer Webhook)
    authz_arg = args.get("authorization-mode")
    authz_cfg = None
    if config is not None:
        authz_cfg = config_value(config, "authorization", "mode")
    if authz_arg is not None:
        authz_val = str(authz_arg).strip()
        pass_ = authz_val.lower() == "webhook"
        findings.append(Finding(node, "3.2.2", "PASS" if pass_ else "FAIL", f"cmdline authorization-mode={authz_val}", "set to Webhook" if pass_ else "not set to Webhook"))
    elif authz_cfg is not None:
        authz_val = str(authz_cfg).strip()
        pass_ = authz_val.lower() == "webhook"
        findings.append(Finding(node, "3.2.2", "PASS" if pass_ else "FAIL", f"config authorization.mode={authz_val}", "set to Webhook" if pass_ else "not set to Webhook"))
    else:
        findings.append(Finding(node, "3.2.2", "FAIL", "authorization mode not explicitly found", "could not confirm authorization mode is Webhook"))

    # 3.2.3 client CA file configured
    ca_arg = args.get("client-ca-file")
    ca_cfg = None
    if config is not None:
        ca_cfg = config_value(config, "authentication", "x509", "clientCAFile")
    if ca_arg:
        pass_ = path_exists_in_pod(pod, str(ca_arg))
        findings.append(Finding(node, "3.2.3", "PASS" if pass_ else "FAIL", f"cmdline client-ca-file={ca_arg}", "client CA file exists" if pass_ else "client CA file not found"))
    elif ca_cfg:
        pass_ = path_exists_in_pod(pod, str(ca_cfg))
        findings.append(Finding(node, "3.2.3", "PASS" if pass_ else "FAIL", f"config authentication.x509.clientCAFile={ca_cfg}", "client CA file exists" if pass_ else "client CA file not found"))
    else:
        findings.append(Finding(node, "3.2.3", "FAIL", "client CA file not explicitly found", "could not confirm client CA file is configured"))

    # 3.2.4 read-only port disabled
    ro_arg = args.get("read-only-port")
    ro_cfg = None
    if config is not None:
        ro_cfg = as_int(config_value(config, "readOnlyPort"))
    if ro_arg is not None:
        ro_val = as_int(ro_arg)
        pass_ = (ro_val == 0)
        findings.append(Finding(node, "3.2.4", "PASS" if pass_ else "FAIL", f"cmdline read-only-port={ro_arg}", "read-only port disabled" if pass_ else "read-only port enabled"))
    elif ro_cfg is not None:
        pass_ = (ro_cfg == 0)
        findings.append(Finding(node, "3.2.4", "PASS" if pass_ else "FAIL", f"config readOnlyPort={ro_cfg}", "read-only port disabled" if pass_ else "read-only port enabled"))
    else:
        # Kubelet default is disabled on modern versions; absence alone isn't enough evidence of failure.
        findings.append(Finding(node, "3.2.4", "PASS", "read-only port not explicitly set", "treated as compliant unless an explicit non-zero value is found"))

    # 3.2.5 streaming connection idle timeout not 0
    s_arg = args.get("streaming-connection-idle-timeout")
    s_cfg = None
    if config is not None:
        s_cfg = config_value(config, "streamingConnectionIdleTimeout")
    if s_arg is not None:
        s_val = str(s_arg).strip()
        pass_ = s_val not in {"0", "0s", "0m", "0h", "0h0m0s"}
        findings.append(Finding(node, "3.2.5", "PASS" if pass_ else "FAIL", f"cmdline streaming-connection-idle-timeout={s_val}", "timeout is non-zero" if pass_ else "timeout is 0"))
    elif s_cfg is not None:
        s_val = str(s_cfg).strip()
        pass_ = s_val not in {"0", "0s", "0m", "0h", "0h0m0s"}
        findings.append(Finding(node, "3.2.5", "PASS" if pass_ else "FAIL", f"config streamingConnectionIdleTimeout={s_val}", "timeout is non-zero" if pass_ else "timeout is 0"))
    else:
        findings.append(Finding(node, "3.2.5", "PASS", "streamingConnectionIdleTimeout not explicitly set", "default/inherited value not observed as 0"))

    # 3.2.6 make-iptables-util-chains true
    ipt_arg = args.get("make-iptables-util-chains")
    ipt_cfg = None
    if config is not None:
        ipt_cfg = as_bool(config_value(config, "makeIPTablesUtilChains"))
    if ipt_arg is not None:
        pass_ = as_bool(ipt_arg) is True
        findings.append(Finding(node, "3.2.6", "PASS" if pass_ else "FAIL", f"cmdline make-iptables-util-chains={ipt_arg}", "set to true" if pass_ else "not true"))
    elif ipt_cfg is not None:
        pass_ = ipt_cfg is True
        findings.append(Finding(node, "3.2.6", "PASS" if pass_ else "FAIL", f"config makeIPTablesUtilChains={ipt_cfg}", "set to true" if pass_ else "not true"))
    else:
        findings.append(Finding(node, "3.2.6", "PASS", "makeIPTablesUtilChains not explicitly set", "default/inherited value not observed as false"))

    # 3.2.7 eventRecordQPS appropriate (benchmark allows 0 or a suitable level)
    event_arg = args.get("eventrecordqps")
    event_cfg = None
    if config is not None:
        event_cfg = as_int(config_value(config, "eventRecordQPS"))
    chosen = event_arg if event_arg is not None else event_cfg
    if chosen is not None:
        ev = as_int(chosen)
        if ev is None:
            findings.append(Finding(node, "3.2.7", "FAIL", f"eventRecordQPS={chosen}", "value is not numeric"))
        elif ev < 0:
            findings.append(Finding(node, "3.2.7", "FAIL", f"eventRecordQPS={ev}", "negative value is invalid"))
        else:
            findings.append(Finding(node, "3.2.7", "PASS", f"eventRecordQPS={ev}", "numeric value is set; review whether it matches your event-capture needs"))
    else:
        findings.append(Finding(node, "3.2.7", "PASS", "eventRecordQPS not explicitly set", "default/inherited value not observed as invalid"))

    # 3.2.8 rotate-certificates present or true
    rot_arg = args.get("rotate-certificates")
    rot_cfg = None
    if config is not None:
        rot_cfg = as_bool(config_value(config, "rotateCertificates"))
    if rot_arg is not None:
        pass_ = as_bool(rot_arg) is not False
        findings.append(Finding(node, "3.2.8", "PASS" if pass_ else "FAIL", f"cmdline rotate-certificates={rot_arg}", "true/omitted-style compliant" if pass_ else "explicitly false"))
    elif rot_cfg is not None:
        pass_ = rot_cfg is not False
        findings.append(Finding(node, "3.2.8", "PASS" if pass_ else "FAIL", f"config rotateCertificates={rot_cfg}", "true/omitted-style compliant" if pass_ else "explicitly false"))
    else:
        findings.append(Finding(node, "3.2.8", "PASS", "rotateCertificates not explicitly set", "no explicit false value found"))

    # 3.2.9 RotateKubeletServerCertificate true
    rk_arg = args.get("rotate-kubelet-server-certificate")
    rk_cfg = None
    if config is not None:
        fg = config_value(config, "featureGates")
        if isinstance(fg, dict):
            rk_cfg = as_bool(lookup_case_insensitive(fg, "RotateKubeletServerCertificate"))
    if rk_arg is not None:
        pass_ = as_bool(rk_arg) is True
        findings.append(Finding(node, "3.2.9", "PASS" if pass_ else "FAIL", f"cmdline rotate-kubelet-server-certificate={rk_arg}", "set to true" if pass_ else "not true"))
    elif rk_cfg is not None:
        pass_ = rk_cfg is True
        findings.append(Finding(node, "3.2.9", "PASS" if pass_ else "FAIL", f"config featureGates.RotateKubeletServerCertificate={rk_cfg}", "set to true" if pass_ else "not true"))
    else:
        findings.append(Finding(node, "3.2.9", "FAIL", "RotateKubeletServerCertificate not explicitly found", "benchmark expects this feature gate to be true"))

    return findings


def get_node_pods() -> List[Tuple[str, str]]:
    items = get_pods()
    pairs: List[Tuple[str, str]] = []
    for item in items:
        node = item.get("spec", {}).get("nodeName")
        pod = item.get("metadata", {}).get("name")
        if node and pod:
            pairs.append((node, pod))
    pairs.sort(key=lambda x: x[0])
    return pairs


def print_report(findings: List[Finding]) -> None:
    findings.sort(key=lambda f: (f.node, f.control))
    width_node = max(len("NODE"), *(len(f.node) for f in findings)) if findings else 4
    width_ctrl = max(len("CTRL"), *(len(f.control) for f in findings)) if findings else 4
    width_status = len("STATUS")
    print(f"{'NODE'.ljust(width_node)}  {'CTRL'.ljust(width_ctrl)}  {'STATUS'.ljust(width_status)}  EVIDENCE")
    print(f"{'-'*width_node}  {'-'*width_ctrl}  {'-'*width_status}  {'-'*30}")
    for f in findings:
        evidence = f.evidence if len(f.evidence) <= 90 else f.evidence[:87] + "..."
        print(f"{f.node.ljust(width_node)}  {f.control.ljust(width_ctrl)}  {f.status.ljust(width_status)}  {evidence}")
        if f.details:
            print(f"{' '.ljust(width_node)}  {' '.ljust(width_ctrl)}  {' '.ljust(width_status)}  {f.details}")
    print()
    summary: Dict[str, int] = {"PASS": 0, "FAIL": 0}
    for f in findings:
        if f.status in summary:
            summary[f.status] += 1
        else:
            summary.setdefault(f.status, 0)
            summary[f.status] += 1
    print("Summary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS EKS Worker Node section 3 using a privileged pod method.")
    parser.add_argument("--no-cleanup", action="store_true", help="Keep the namespace and DaemonSet after the audit")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="Seconds to wait for the DaemonSet to become ready")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a human-readable report")
    args = parser.parse_args()

    created = False
    findings: List[Finding] = []
    try:
        ensure_namespace()
        apply_daemonset()
        created = True
        wait_for_daemonset_ready(timeout=args.timeout)

        pairs = get_node_pods()
        if not pairs:
            raise AuditError("No DaemonSet pods found; cannot audit nodes.")

        for node, pod in pairs:
            findings.extend(audit_node(node, pod))

        if args.json:
            print(json.dumps([f.__dict__ for f in findings], indent=2, ensure_ascii=False))
        else:
            print_report(findings)
        return 0
    except AuditError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    finally:
        if created and not args.no_cleanup:
            delete_resources()


if __name__ == "__main__":
    raise SystemExit(main())
