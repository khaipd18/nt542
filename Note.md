# Ghi chú

## 0. Lưu ý trước khi thực hiện các CIS Benchmark cho EKS cluster phía dưới

- Kiểm tra kubelet có đang running hay không ("Active: active (running) since.. ") bằng lệnh:

```
sudo systemctl status kubelet
```

- Kết quả của lệnh sau phải trả về nội dung "--config=/etc/kubernetes/kubelet/config.json":

```
ps -ef | grep kubelet
```

## 1. CIS 3.1.1

### Mô phỏng lỗ hỏng

- Cấp quyền **777** cho file `/var/lib/kubelet/kubeconfig`:

```
sudo chmod 777 /var/lib/kubelet/kubeconfig
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Kiểm tra permission của file **kubeconfig**, output của lệnh phải trả về **644** hoặc chặt chẽ hơn:

```
stat -c %a /var/lib/kubelet/kubeconfig
```

### Remediation

- - Cấp quyền **644** cho file `/var/lib/kubelet/kubeconfig`:

```
sudo chmod 644 /var/lib/kubelet/kubeconfig
```

---

## 2. CIS 3.1.2

### Mô phỏng lỗ hỏng

- Đổi owner của file `/var/lib/kubelet/kubeconfig` thành **ec2-user:ec2-user**:

```
sudo chown ec2-user:ec2-user /var/lib/kubelet/kubeconfig
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Kiểm tra owner của file **kubeconfig**, output của lệnh phải trả về **root:root**:

```
stat -c %U:%G /var/lib/kubelet/kubeconfig
```

### Remediation

- Đổi owner của file `/var/lib/kubelet/kubeconfig` thành **root:root**:

```
sudo chown root:root /var/lib/kubelet/kubeconfig
```

---

## 3. CIS 3.1.3 & 3.1.4

CIS 3.1.3 giống CIS 3.1.1 và CIS 3.1.4 giống CIS 3.1.2 nhưng đối với file `/etc/kubernetes/kubelet/config.json`

---

## 4. CIS 3.2.1

### Mô phỏng lỗ hỏng

- **Enable Anonymous Authentication**:

```
sudo jq '.authentication.anonymous.enabled = true' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Đảm bảo disable Anonymous Authentication, output của lệnh phải trả về **false**:

```
sudo jq '.authentication.anonymous.enabled' /etc/kubernetes/kubelet/config.json
```

### Remediation

- **Disable Anonymous Authentication**:

```
sudo jq '.authentication.anonymous.enabled = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

---

## 5. CIS 3.2.2

### Mô phỏng lỗ hỏng

- **Thiết lập Authorization Mode là "AlwaysAllow" và disable Webhook Authentication**:

```
sudo jq '.authentication.webhook.enabled = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
sudo jq '.authorization.mode = "AlwaysAllow"' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Đảm bảo enable Webhook Authentication và Authorization Mode phải là **Webhook**, output của lệnh trả về **true** và **"Webhook"**:

```
sudo jq '.authentication.webhook.enabled' /etc/kubernetes/kubelet/config.json
sudo jq '.authorization.mode' /etc/kubernetes/kubelet/config.json
```

### Remediation

- **Thiết lập Authorization Mode là "Webhook" và enable Webhook Authentication**:

```
sudo jq '.authentication.webhook.enabled = true' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
sudo jq '.authorization.mode = "Webhook"' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

---

## 6. CIS 3.2.4

### Mô phỏng lỗ hỏng

- **Thiết lập --read-only-port là 10255**:

```
sudo jq '.readOnlyPort = 10255' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Đảm bảo disable --read-only-port, output của lệnh trả về **0**:

```
sudo jq '.readOnlyPort' /etc/kubernetes/kubelet/config.json
```

### Remediation

- **Disable --read-only-port**:

```
sudo jq '.readOnlyPort = 0' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

---

## 7. CIS 3.2.5

### Mô phỏng lỗ hỏng

- **Thiết lập --streaming-connection-idle-timeout = "0"**:

```
sudo jq '.streamingConnectionIdleTimeout = "0"' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Đảm bảo tham số streamingConnectionIdleTimeout không được set = 0, output của lệnh trả về khác **"0"** (ví dụ: **"4h0m0s"**):

```
sudo jq '.streamingConnectionIdleTimeout' /etc/kubernetes/kubelet/config.json
```

### Remediation

- **Thiết lập --streaming-connection-idle-timeout khác "0"**:

```
sudo jq '.streamingConnectionIdleTimeout = "4h0m0s"' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

---

## 8. CIS 3.2.6

### Mô phỏng lỗ hỏng

- **Thiết lập --make-iptables-util-chains = false**:

```
sudo jq '.makeIPTablesUtilChains = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Đảm bảo tham số makeIPTablesUtilChains true, output của lệnh trả về **true**:

```
sudo jq '.makeIPTablesUtilChains' /etc/kubernetes/kubelet/config.json
```

### Remediation

- **Thiết lập --make-iptables-util-chains = true**:

```
sudo jq '.makeIPTablesUtilChains = true' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

---

## 9. CIS 3.2.8

### Mô phỏng lỗ hỏng

- **Thiết lập --rotate-certificates = false**:

```
sudo jq '.rotateCertificates = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Đảm bảo tham số RotateCertificate không được thiết lập hoặc có giá trị là true, output của lệnh trả về **true** hoặc **null**:

```
sudo jq '.rotateCertificates' /etc/kubernetes/kubelet/config.json
```

### Remediation

- **Thiết lập --make-iptables-util-chains = true**:

```
sudo jq '.rotateCertificates = true' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

---

## 10. CIS 3.2.9

### Mô phỏng lỗ hỏng

- **Thiết lập serverTLSBootstrap = false và RotateKubeletServerCertificate = false**:

```
sudo jq '.serverTLSBootstrap = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
sudo jq '.featureGates.RotateKubeletServerCertificate = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```

### Audit

- Truy cập EC2 Instance bằng SSM
- Đảm bảo tham số serverTLSBootstrap và RotateKubeletServerCertificate đều là true, output của cả 2 lệnh trả về **true**:

```
sudo jq '.serverTLSBootstrap' /etc/kubernetes/kubelet/config.json
sudo jq '.featureGates.RotateKubeletServerCertificate' /etc/kubernetes/kubelet/config.json
```

### Remediation

- **Thiết lập serverTLSBootstrap = true và RotateKubeletServerCertificate = true**:

```
sudo jq '.serverTLSBootstrap = true' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
sudo jq '.featureGates.RotateKubeletServerCertificate = true' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
```
