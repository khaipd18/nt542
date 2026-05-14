# Hướng dẫn chạy Terraform và file Audit + Remediation

## Apply Terraform

Chạy các lệnh sau theo thứ tự từ trên xuống:

```
cd terraform
```

```
terraform init
```

```
# Chỉ dùng 1 trong 2 lệnh phía dưới

terraform apply -target=module.eks
terraform apply -target=module.eks -auto-approve # Không cần nhập "Yes"
```

- Lưu ý: **Đợi module của eks chạy xong thì mới chạy tiếp module của k8s**

```
# Chỉ dùng 1 trong 2 lệnh phía dưới

terraform apply -target=module.k8s
terraform apply -target=module.k8s -auto-approve # Không cần nhập "Yes"
```

---

## Destroy Terraform

Chạy các lệnh sau theo thứ tự từ trên xuống:

```
# Chỉ dùng 1 trong 2 lệnh phía dưới

terraform destroy -target=module.k8s
terraform destroy -auto-approve # Không cần nhập "Yes"
```

```
# Chỉ dùng 1 trong 2 lệnh phía dưới

terraform destroy -target=module.eks
terraform destroy -auto-approve # Không cần nhập "Yes"
```

---

## Chạy file Audit

### File Audit của Nhóm 3 (Lỗi 10 đến 20)

***Khuyến nghị: nên chạy các lệnh sau trong Terminal của Command Prompt/PowerShell hoặc Ubuntu/WSL2, không nên chạy trong Git Bash***

```
cd audit/modules/
```

```
python -m venv venv
```

```
# Đối với Command Prompt trên Window
.\venv\Scripts\activate

# Đối với PowerShell
.\venv\Scripts\Activate.ps1

# Đối với Ubuntu/WSL2
source ./venv/bin/activate
```

```
pip install boto3
```

```
python cis_3_eks_worker_nodes.py
# hoặc
python3 cis_3_eks_worker_nodes.py
```

---

## Chạy file Remediation

### File Remediation của Nhóm 3 (Lỗi 10 đến 20)

***Khuyến nghị: nên chạy các lệnh sau trong Terminal của Command Prompt/PowerShell hoặc Ubuntu/WSL2, không nên chạy trong Git Bash***

```
cd remediation/modules/
```

```
python -m venv venv
```

```
# Đối với Command Prompt trên Window
.\venv\Scripts\activate

# Đối với PowerShell
.\venv\Scripts\Activate.ps1

# Đối với Ubuntu/WSL2
source ./venv/bin/activate
```

```
pip install boto3
```

```
python cis_3_eks_worker_nodes.py
# hoặc
python3 cis_3_eks_worker_nodes.py
```
