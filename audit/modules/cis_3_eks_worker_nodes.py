"""
audit.py — CIS Benchmark Audit cho EKS Node (kubelet) qua AWS SSM
Sử dụng: python audit.py --instance-id <EC2_INSTANCE_ID> [--region <AWS_REGION>]
"""

import argparse
import time
import boto3

# ──────────────────────────────────────────────
# Helpers: SSM
# ──────────────────────────────────────────────

def run_command(ssm_client, instance_id, command, timeout=30):
    """
    Gửi 1 shell command tới EC2 qua SSM, đợi kết quả và trả về stdout (str).
    Raise RuntimeError nếu command thất bại hoặc timeout.
    """
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [command]},
        TimeoutSeconds=timeout,
    )
    command_id = response["Command"]["CommandId"]

    # Đợi tối đa timeout giây
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        result = ssm_client.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        status = result["Status"]
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    else:
        raise RuntimeError(f"SSM command timeout sau {timeout}s: {command}")

    if status != "Success":
        stderr = result.get("StandardErrorContent", "").strip()
        raise RuntimeError(f"Command thất bại (status={status}): {stderr}")

    return result.get("StandardOutputContent", "").strip()


# ──────────────────────────────────────────────
# Bước 0: Kiểm tra điều kiện tiên quyết
# ──────────────────────────────────────────────

def check_prerequisites(ssm_client, instance_id):
    """
    Kiểm tra kubelet đang running và config path đúng.
    Trả về True nếu hợp lệ, False nếu không.
    """
    print("=" * 60)
    print("KIỂM TRA ĐIỀU KIỆN TIÊN QUYẾT")
    print("=" * 60)

    # 1. Kubelet có đang running?
    try:
        out = run_command(ssm_client, instance_id, "sudo systemctl status kubelet")
        if "Active: active (running)" in out:
            print("[OK] kubelet đang running.")
        else:
            print("[FAIL] kubelet KHÔNG ở trạng thái active (running).")
            print(f"       Output: {out[:200]}")
            return False
    except RuntimeError as e:
        print(f"[ERROR] Không thể kiểm tra kubelet status: {e}")
        return False

    # 2. kubelet dùng đúng config file?
    try:
        out = run_command(ssm_client, instance_id, "ps -ef | grep kubelet")
        if "--config=/etc/kubernetes/kubelet/config.json" in out:
            print("[OK] kubelet sử dụng --config=/etc/kubernetes/kubelet/config.json.")
        else:
            print("[FAIL] Không tìm thấy --config=/etc/kubernetes/kubelet/config.json trong process kubelet.")
            print(f"       Output: {out[:300]}")
            return False
    except RuntimeError as e:
        print(f"[ERROR] Không thể kiểm tra kubelet process: {e}")
        return False

    print()
    return True


# ──────────────────────────────────────────────
# Hàm output kết quả
# ──────────────────────────────────────────────

def report(cis_id, description, status, detail=""):
    """In kết quả một CIS check ra stdout."""
    icon = {"Pass": "✅", "Fail": "❌", "Error": "⚠️ "}.get(status, "?")
    line = f"{icon} [{status:5s}] {cis_id} — {description}"
    if detail:
        line += f"\n         Detail: {detail}"
    print(line)
    return {"cis_id": cis_id, "description": description, "status": status, "detail": detail}


# ──────────────────────────────────────────────
# Helpers: permission / owner
# ──────────────────────────────────────────────

def is_permission_ok(perm_str):
    """
    Kiểm tra permission có phải 644 hoặc chặt chẽ hơn không.
    Chặt chẽ hơn nghĩa là: owner<=6, group<=4, other<=4
    Ví dụ hợp lệ: 600, 640, 644, 400
    """
    perm = perm_str.strip()
    if len(perm) != 3 or not perm.isdigit():
        return False
    owner, group, other = int(perm[0]), int(perm[1]), int(perm[2])
    return owner <= 6 and group <= 4 and other <= 4


# ──────────────────────────────────────────────
# Các hàm audit CIS
# ──────────────────────────────────────────────

def audit_3_1_1(ssm_client, instance_id):
    """CIS 3.1.1 — Permission của /var/lib/kubelet/kubeconfig phải là 644 hoặc chặt hơn."""
    try:
        out = run_command(ssm_client, instance_id, "stat -c %a /var/lib/kubelet/kubeconfig")
        if is_permission_ok(out):
            return report("CIS 3.1.1", "kubeconfig file permission", "Pass", f"permission={out}")
        else:
            return report("CIS 3.1.1", "kubeconfig file permission", "Fail",
                          f"permission={out} (yêu cầu 644 hoặc chặt hơn)")
    except RuntimeError as e:
        return report("CIS 3.1.1", "kubeconfig file permission", "Error", str(e))


def audit_3_1_2(ssm_client, instance_id):
    """CIS 3.1.2 — Owner của /var/lib/kubelet/kubeconfig phải là root:root."""
    try:
        out = run_command(ssm_client, instance_id, "stat -c %U:%G /var/lib/kubelet/kubeconfig")
        if out.strip() == "root:root":
            return report("CIS 3.1.2", "kubeconfig file owner", "Pass", f"owner={out}")
        else:
            return report("CIS 3.1.2", "kubeconfig file owner", "Fail",
                          f"owner={out} (yêu cầu root:root)")
    except RuntimeError as e:
        return report("CIS 3.1.2", "kubeconfig file owner", "Error", str(e))


def audit_3_1_3(ssm_client, instance_id):
    """CIS 3.1.3 — Permission của /etc/kubernetes/kubelet/config.json phải là 644 hoặc chặt hơn."""
    try:
        out = run_command(ssm_client, instance_id, "stat -c %a /etc/kubernetes/kubelet/config.json")
        if is_permission_ok(out):
            return report("CIS 3.1.3", "kubelet config.json file permission", "Pass", f"permission={out}")
        else:
            return report("CIS 3.1.3", "kubelet config.json file permission", "Fail",
                          f"permission={out} (yêu cầu 644 hoặc chặt hơn)")
    except RuntimeError as e:
        return report("CIS 3.1.3", "kubelet config.json file permission", "Error", str(e))


def audit_3_1_4(ssm_client, instance_id):
    """CIS 3.1.4 — Owner của /etc/kubernetes/kubelet/config.json phải là root:root."""
    try:
        out = run_command(ssm_client, instance_id, "stat -c %U:%G /etc/kubernetes/kubelet/config.json")
        if out.strip() == "root:root":
            return report("CIS 3.1.4", "kubelet config.json file owner", "Pass", f"owner={out}")
        else:
            return report("CIS 3.1.4", "kubelet config.json file owner", "Fail",
                          f"owner={out} (yêu cầu root:root)")
    except RuntimeError as e:
        return report("CIS 3.1.4", "kubelet config.json file owner", "Error", str(e))


def audit_3_2_1(ssm_client, instance_id):
    """CIS 3.2.1 — Anonymous Authentication phải là false."""
    try:
        out = run_command(
            ssm_client, instance_id,
            "sudo jq '.authentication.anonymous.enabled' /etc/kubernetes/kubelet/config.json"
        )
        if out.strip() == "false":
            return report("CIS 3.2.1", "Anonymous Authentication disabled", "Pass", f"value={out}")
        else:
            return report("CIS 3.2.1", "Anonymous Authentication disabled", "Fail",
                          f"value={out} (yêu cầu false)")
    except RuntimeError as e:
        return report("CIS 3.2.1", "Anonymous Authentication disabled", "Error", str(e))


def audit_3_2_2(ssm_client, instance_id):
    """CIS 3.2.2 — Webhook Authentication=true và Authorization Mode=Webhook."""
    try:
        webhook_enabled = run_command(
            ssm_client, instance_id,
            "sudo jq '.authentication.webhook.enabled' /etc/kubernetes/kubelet/config.json"
        ).strip()
        auth_mode = run_command(
            ssm_client, instance_id,
            "sudo jq '.authorization.mode' /etc/kubernetes/kubelet/config.json"
        ).strip()

        if webhook_enabled == "true" and auth_mode == '"Webhook"':
            return report("CIS 3.2.2", "Webhook Auth + Authorization Mode", "Pass",
                          f"webhook.enabled={webhook_enabled}, authorization.mode={auth_mode}")
        else:
            return report("CIS 3.2.2", "Webhook Auth + Authorization Mode", "Fail",
                          f"webhook.enabled={webhook_enabled} (yêu cầu true), "
                          f"authorization.mode={auth_mode} (yêu cầu \"Webhook\")")
    except RuntimeError as e:
        return report("CIS 3.2.2", "Webhook Auth + Authorization Mode", "Error", str(e))


def audit_3_2_4(ssm_client, instance_id):
    """CIS 3.2.4 — readOnlyPort phải là 0."""
    try:
        out = run_command(
            ssm_client, instance_id,
            "sudo jq '.readOnlyPort' /etc/kubernetes/kubelet/config.json"
        )
        if out.strip() == "0":
            return report("CIS 3.2.4", "Read-only port disabled", "Pass", f"readOnlyPort={out}")
        else:
            return report("CIS 3.2.4", "Read-only port disabled", "Fail",
                          f"readOnlyPort={out} (yêu cầu 0)")
    except RuntimeError as e:
        return report("CIS 3.2.4", "Read-only port disabled", "Error", str(e))


def audit_3_2_5(ssm_client, instance_id):
    """CIS 3.2.5 — streamingConnectionIdleTimeout không được là '0'."""
    try:
        out = run_command(
            ssm_client, instance_id,
            "sudo jq '.streamingConnectionIdleTimeout' /etc/kubernetes/kubelet/config.json"
        )
        # jq trả về "0" (có nháy kép) nếu là string "0"
        if out.strip() not in ('"0"', "0", "null"):
            return report("CIS 3.2.5", "streamingConnectionIdleTimeout != 0", "Pass",
                          f"value={out}")
        else:
            return report("CIS 3.2.5", "streamingConnectionIdleTimeout != 0", "Fail",
                          f"value={out} (không được là 0)")
    except RuntimeError as e:
        return report("CIS 3.2.5", "streamingConnectionIdleTimeout != 0", "Error", str(e))


def audit_3_2_6(ssm_client, instance_id):
    """CIS 3.2.6 — makeIPTablesUtilChains phải là true."""
    try:
        out = run_command(
            ssm_client, instance_id,
            "sudo jq '.makeIPTablesUtilChains' /etc/kubernetes/kubelet/config.json"
        )
        if out.strip() == "true":
            return report("CIS 3.2.6", "makeIPTablesUtilChains=true", "Pass", f"value={out}")
        else:
            return report("CIS 3.2.6", "makeIPTablesUtilChains=true", "Fail",
                          f"value={out} (yêu cầu true)")
    except RuntimeError as e:
        return report("CIS 3.2.6", "makeIPTablesUtilChains=true", "Error", str(e))


def audit_3_2_8(ssm_client, instance_id):
    """CIS 3.2.8 — rotateCertificates phải là true hoặc null."""
    try:
        out = run_command(
            ssm_client, instance_id,
            "sudo jq '.rotateCertificates' /etc/kubernetes/kubelet/config.json"
        )
        if out.strip() in ("true", "null"):
            return report("CIS 3.2.8", "rotateCertificates=true or null", "Pass", f"value={out}")
        else:
            return report("CIS 3.2.8", "rotateCertificates=true or null", "Fail",
                          f"value={out} (yêu cầu true hoặc null)")
    except RuntimeError as e:
        return report("CIS 3.2.8", "rotateCertificates=true or null", "Error", str(e))


def audit_3_2_9(ssm_client, instance_id):
    """CIS 3.2.9 — serverTLSBootstrap và RotateKubeletServerCertificate phải là true."""
    try:
        tls_bootstrap = run_command(
            ssm_client, instance_id,
            "sudo jq '.serverTLSBootstrap' /etc/kubernetes/kubelet/config.json"
        ).strip()
        rotate_cert = run_command(
            ssm_client, instance_id,
            "sudo jq '.featureGates.RotateKubeletServerCertificate' /etc/kubernetes/kubelet/config.json"
        ).strip()

        if tls_bootstrap == "true" and rotate_cert == "true":
            return report("CIS 3.2.9", "serverTLSBootstrap + RotateKubeletServerCertificate", "Pass",
                          f"serverTLSBootstrap={tls_bootstrap}, RotateKubeletServerCertificate={rotate_cert}")
        else:
            return report("CIS 3.2.9", "serverTLSBootstrap + RotateKubeletServerCertificate", "Fail",
                          f"serverTLSBootstrap={tls_bootstrap} (yêu cầu true), "
                          f"RotateKubeletServerCertificate={rotate_cert} (yêu cầu true)")
    except RuntimeError as e:
        return report("CIS 3.2.9", "serverTLSBootstrap + RotateKubeletServerCertificate", "Error", str(e))


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CIS Benchmark Audit cho EKS Node qua SSM")
    parser.add_argument("--instance-id", required=True, help="EC2 Instance ID (ví dụ: i-0abc123def456)")
    parser.add_argument("--region", default=None, help="AWS Region (mặc định dùng region trong AWS config)")
    args = parser.parse_args()

    ssm_client = boto3.client("ssm", region_name=args.region)

    # Bước 0: kiểm tra điều kiện tiên quyết
    if not check_prerequisites(ssm_client, args.instance_id):
        print("\n[DỪNG] Điều kiện tiên quyết không thỏa mãn. Không thực hiện audit.")
        return

    # Chạy toàn bộ audit
    print("=" * 60)
    print("KẾT QUẢ AUDIT CIS BENCHMARK")
    print("=" * 60)

    audit_functions = [
        audit_3_1_1,
        audit_3_1_2,
        audit_3_1_3,
        audit_3_1_4,
        audit_3_2_1,
        audit_3_2_2,
        audit_3_2_4,
        audit_3_2_5,
        audit_3_2_6,
        audit_3_2_8,
        audit_3_2_9,
    ]

    results = []
    for fn in audit_functions:
        result = fn(ssm_client, args.instance_id)
        results.append(result)

    # Tổng kết
    total   = len(results)
    passed  = sum(1 for r in results if r["status"] == "Pass")
    failed  = sum(1 for r in results if r["status"] == "Fail")
    errors  = sum(1 for r in results if r["status"] == "Error")

    print()
    print("=" * 60)
    print(f"TỔNG KẾT: {total} checks — Pass: {passed} | Fail: {failed} | Error: {errors}")
    print("=" * 60)


if __name__ == "__main__":
    main()