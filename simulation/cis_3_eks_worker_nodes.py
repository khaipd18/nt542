"""
simulate.py — Mô phỏng lỗ hổng CIS Benchmark trên EKS Node qua AWS SSM
Sử dụng: python simulate.py --instance-id <EC2_INSTANCE_ID> --region <AWS_REGION>
"""

import argparse
import time
import boto3

# ──────────────────────────────────────────────
# Helper: SSM
# ──────────────────────────────────────────────

def run_command(ssm_client, instance_id, command, timeout=60):
    """
    Gửi shell command tới EC2 qua SSM, đợi kết quả và trả về stdout.
    Raise RuntimeError nếu thất bại hoặc timeout.
    """
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [command]},
        TimeoutSeconds=timeout,
    )
    command_id = response["Command"]["CommandId"]

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
        raise RuntimeError(f"SSM command timeout sau {timeout}s")

    if status != "Success":
        stderr = result.get("StandardErrorContent", "").strip()
        raise RuntimeError(f"Command thất bại (status={status}): {stderr}")

    return result.get("StandardOutputContent", "").strip()


# ──────────────────────────────────────────────
# Bước 0: Kiểm tra điều kiện tiên quyết
# ──────────────────────────────────────────────

def check_prerequisites(ssm_client, instance_id):
    """Kiểm tra kubelet đang running và config path đúng trước khi mô phỏng."""
    print("=" * 60)
    print("KIỂM TRA ĐIỀU KIỆN TIÊN QUYẾT")
    print("=" * 60)

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

    try:
        out = run_command(ssm_client, instance_id, "ps -ef | grep kubelet")
        if "--config=/etc/kubernetes/kubelet/config.json" in out:
            print("[OK] kubelet sử dụng --config=/etc/kubernetes/kubelet/config.json.")
        else:
            print("[FAIL] Không tìm thấy --config=/etc/kubernetes/kubelet/config.json.")
            print(f"       Output: {out[:300]}")
            return False
    except RuntimeError as e:
        print(f"[ERROR] Không thể kiểm tra kubelet process: {e}")
        return False

    print()
    return True


# ──────────────────────────────────────────────
# Các bước mô phỏng lỗ hổng
# ──────────────────────────────────────────────

# Mỗi step là: (tên hiển thị, lệnh shell)
SIMULATION_STEPS = [
    (
        "Cài jq (nếu chưa có)",
        "sudo yum install -y jq",
    ),
    (
        "CIS 3.1.1 — Sai quyền kubeconfig (chmod 777)",
        "sudo chmod 777 /var/lib/kubelet/kubeconfig",
    ),
    (
        "CIS 3.1.2 — Sai owner kubeconfig (ec2-user:ec2-user)",
        "sudo chown ec2-user:ec2-user /var/lib/kubelet/kubeconfig",
    ),
    (
        "CIS 3.2.1 — Bật Anonymous Authentication (true)",
        "sudo jq '.authentication.anonymous.enabled = true' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.2 — Tắt Webhook Authentication (false)",
        "sudo jq '.authentication.webhook.enabled = false' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.2 — Authorization Mode = AlwaysAllow",
        'sudo jq \'.authorization.mode = "AlwaysAllow"\' '
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.4 — Mở Read-Only Port 10255",
        "sudo jq '.readOnlyPort = 10255' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.5 — Streaming Connection Idle Timeout = '0'",
        'sudo jq \'.streamingConnectionIdleTimeout = "0"\' '
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.6 — makeIPTablesUtilChains = false",
        "sudo jq '.makeIPTablesUtilChains = false' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.8 — rotateCertificates = false",
        "sudo jq '.rotateCertificates = false' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.9 — serverTLSBootstrap = false",
        "sudo jq '.serverTLSBootstrap = false' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.2.9 — RotateKubeletServerCertificate = false",
        "sudo jq '.featureGates.RotateKubeletServerCertificate = false' "
        "/etc/kubernetes/kubelet/config.json > /tmp/config.json "
        "&& sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.1.3 — Sai quyền config.json (chmod 777)",
        "sudo chmod 777 /etc/kubernetes/kubelet/config.json",
    ),
    (
        "CIS 3.1.4 — Sai owner config.json (ec2-user:ec2-user)",
        "sudo chown ec2-user:ec2-user /etc/kubernetes/kubelet/config.json",
    ),
    (
        "Restart kubelet để áp dụng cấu hình lỗi",
        "sudo systemctl daemon-reload "
        "&& sudo systemctl restart kubelet.service",
    ),
]


def run_simulation(ssm_client, instance_id):
    """Chạy toàn bộ các bước mô phỏng lỗ hổng theo thứ tự."""
    print("=" * 60)
    print("BẮT ĐẦU MÔ PHỎNG LỖ HỔNG CIS BENCHMARK")
    print("=" * 60)

    total   = len(SIMULATION_STEPS)
    success = 0
    errors  = []

    for idx, (name, cmd) in enumerate(SIMULATION_STEPS, start=1):
        print(f"[{idx:02d}/{total}] {name} ... ", end="", flush=True)
        try:
            run_command(ssm_client, instance_id, cmd)
            print("OK")
            success += 1
        except RuntimeError as e:
            print(f"ERROR")
            errors.append((name, str(e)))

    # Tổng kết
    print()
    print("=" * 60)
    print(f"KẾT QUẢ: {success}/{total} bước thành công.")

    if errors:
        print(f"\nCác bước thất bại ({len(errors)}):")
        for name, reason in errors:
            print(f"  ❌ {name}")
            print(f"     Lý do: {reason}")
    else:
        print("✅ Tất cả bước mô phỏng hoàn thành.")
        print("   Hãy chạy audit.py để xác nhận các lỗ hổng đã được tạo ra.")

    print("=" * 60)


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Mô phỏng lỗ hổng CIS Benchmark trên EKS Node qua SSM"
    )
    parser.add_argument(
        "--instance-id", required=True,
        help="EC2 Instance ID (ví dụ: i-0abc123def456)"
    )
    parser.add_argument(
        "--region", default=None,
        help="AWS Region (mặc định dùng region trong AWS config)"
    )
    args = parser.parse_args()

    ssm_client = boto3.client("ssm", region_name=args.region)

    # Bước 0: kiểm tra điều kiện tiên quyết
    if not check_prerequisites(ssm_client, args.instance_id):
        print("\n[DỪNG] Điều kiện tiên quyết không thỏa mãn. Không thực hiện mô phỏng.")
        return

    # Chạy mô phỏng
    run_simulation(ssm_client, args.instance_id)


if __name__ == "__main__":
    main()