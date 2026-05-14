"""
remediation.py — CIS Benchmark Remediation cho EKS Node (kubelet) qua AWS SSM
Sử dụng: python remediation.py --instance-id <EC2_INSTANCE_ID> --region <AWS_REGION>
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
# Helpers: chạy 1 lệnh remediation và log kết quả
# ──────────────────────────────────────────────

def remediate(ssm_client, instance_id, cis_id, description, command):
    """
    Chạy lệnh remediation. Chỉ in ra khi có lỗi.
    Trả về True nếu thành công, False nếu lỗi.
    """
    try:
        run_command(ssm_client, instance_id, command)
        return True
    except RuntimeError as e:
        print(f"[ERROR] {cis_id} — {description}")
        print(f"        Command : {command}")
        print(f"        Lý do   : {e}")
        return False


# ──────────────────────────────────────────────
# Các hàm remediation CIS
# ──────────────────────────────────────────────

def remediate_3_1_1(ssm_client, instance_id):
    """CIS 3.1.1 — Đặt permission 644 cho /var/lib/kubelet/kubeconfig."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.1.1", "kubeconfig file permission → 644",
        "sudo chmod 644 /var/lib/kubelet/kubeconfig"
    )


def remediate_3_1_2(ssm_client, instance_id):
    """CIS 3.1.2 — Đặt owner root:root cho /var/lib/kubelet/kubeconfig."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.1.2", "kubeconfig file owner → root:root",
        "sudo chown root:root /var/lib/kubelet/kubeconfig"
    )


def remediate_3_1_3(ssm_client, instance_id):
    """CIS 3.1.3 — Đặt permission 644 cho /etc/kubernetes/kubelet/config.json."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.1.3", "kubelet config.json file permission → 644",
        "sudo chmod 644 /etc/kubernetes/kubelet/config.json"
    )


def remediate_3_1_4(ssm_client, instance_id):
    """CIS 3.1.4 — Đặt owner root:root cho /etc/kubernetes/kubelet/config.json."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.1.4", "kubelet config.json file owner → root:root",
        "sudo chown root:root /etc/kubernetes/kubelet/config.json"
    )


def remediate_3_2_1(ssm_client, instance_id):
    """CIS 3.2.1 — Disable Anonymous Authentication."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.2.1", "Anonymous Authentication → false",
        "sudo jq '.authentication.anonymous.enabled = false' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )


def remediate_3_2_2(ssm_client, instance_id):
    """CIS 3.2.2 — Enable Webhook Authentication và set Authorization Mode = Webhook."""
    ok1 = remediate(
        ssm_client, instance_id,
        "CIS 3.2.2 (webhook.enabled)", "Webhook Authentication → true",
        "sudo jq '.authentication.webhook.enabled = true' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )
    ok2 = remediate(
        ssm_client, instance_id,
        "CIS 3.2.2 (authorization.mode)", "Authorization Mode → Webhook",
        'sudo jq \'.authorization.mode = "Webhook"\' '
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )
    return ok1 and ok2


def remediate_3_2_4(ssm_client, instance_id):
    """CIS 3.2.4 — Disable read-only port (set = 0)."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.2.4", "readOnlyPort → 0",
        "sudo jq '.readOnlyPort = 0' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )


def remediate_3_2_5(ssm_client, instance_id):
    """CIS 3.2.5 — Đặt streamingConnectionIdleTimeout = '4h0m0s'."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.2.5", "streamingConnectionIdleTimeout → 4h0m0s",
        'sudo jq \'.streamingConnectionIdleTimeout = "4h0m0s"\' '
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )


def remediate_3_2_6(ssm_client, instance_id):
    """CIS 3.2.6 — Đặt makeIPTablesUtilChains = true."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.2.6", "makeIPTablesUtilChains → true",
        "sudo jq '.makeIPTablesUtilChains = true' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )


def remediate_3_2_8(ssm_client, instance_id):
    """CIS 3.2.8 — Đặt rotateCertificates = true."""
    return remediate(
        ssm_client, instance_id,
        "CIS 3.2.8", "rotateCertificates → true",
        "sudo jq '.rotateCertificates = true' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )


def remediate_3_2_9(ssm_client, instance_id):
    """CIS 3.2.9 — Đặt serverTLSBootstrap = true và RotateKubeletServerCertificate = true."""
    ok1 = remediate(
        ssm_client, instance_id,
        "CIS 3.2.9 (serverTLSBootstrap)", "serverTLSBootstrap → true",
        "sudo jq '.serverTLSBootstrap = true' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )
    ok2 = remediate(
        ssm_client, instance_id,
        "CIS 3.2.9 (RotateKubeletServerCertificate)", "RotateKubeletServerCertificate → true",
        "sudo jq '.featureGates.RotateKubeletServerCertificate = true' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json"
    )
    return ok1 and ok2


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CIS Benchmark Remediation cho EKS Node qua SSM")
    parser.add_argument("--instance-id", required=True, help="EC2 Instance ID (ví dụ: i-0abc123def456)")
    parser.add_argument("--region", default=None, help="AWS Region (mặc định dùng region trong AWS config)")
    args = parser.parse_args()

    ssm_client = boto3.client("ssm", region_name=args.region)

    # Bước 0: kiểm tra điều kiện tiên quyết
    if not check_prerequisites(ssm_client, args.instance_id):
        print("\n[DỪNG] Điều kiện tiên quyết không thỏa mãn. Không thực hiện remediation.")
        return

    print("=" * 60)
    print("BẮT ĐẦU REMEDIATION CIS BENCHMARK")
    print("(Chỉ in ra khi có lỗi)")
    print("=" * 60)

    remediation_functions = [
        remediate_3_1_1,
        remediate_3_1_2,
        remediate_3_1_3,
        remediate_3_1_4,
        remediate_3_2_1,
        remediate_3_2_2,
        remediate_3_2_4,
        remediate_3_2_5,
        remediate_3_2_6,
        remediate_3_2_8,
        remediate_3_2_9,
    ]

    errors = 0
    for fn in remediation_functions:
        ok = fn(ssm_client, args.instance_id)
        if not ok:
            errors += 1

    print()
    if errors == 0:
        print("[HOÀN THÀNH] Tất cả remediation đã chạy thành công.")
        print("             Hãy chạy audit.py để xác nhận kết quả.")
    else:
        print(f"[CẢNH BÁO] Có {errors} lỗi xảy ra trong quá trình remediation (xem chi tiết ở trên).")


if __name__ == "__main__":
    main()