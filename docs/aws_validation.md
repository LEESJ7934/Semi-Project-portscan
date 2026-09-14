# AWS Lab Validation Runbook

This runbook is for a user-owned AWS account and the dedicated Terraform lab only.

## 1. Static checks

```powershell
terraform -chdir=infra/aws/terraform fmt -check -recursive
terraform -chdir=infra/aws/terraform init
terraform -chdir=infra/aws/terraform validate
terraform -chdir=infra/aws/terraform plan
```

Do not use `enable_demo_misconfiguration=true` until the normal architecture is validated.

## 2. Apply and capture outputs

```powershell
terraform -chdir=infra/aws/terraform apply
terraform -chdir=infra/aws/terraform output
```

Record only non-secret resource identifiers needed for the portfolio: VPC ID, instance IDs, private IPs and Security Group ID.

## 3. Database V6

Apply `sql/migration_v6.sql` after V5 and verify with `sql/verify_v6.sql`.

## 4. Read-only AWS inventory

First run without DB writes:

```powershell
python -m scripts.aws_inventory --region ap-northeast-2 --vpc-id <vpc-id>
python -m scripts.aws_security_review --region ap-northeast-2 --vpc-id <vpc-id>
```

Then persist only the dedicated VPC:

```powershell
python -m scripts.aws_inventory --region ap-northeast-2 --vpc-id <vpc-id> --save
python -m scripts.aws_security_review --region ap-northeast-2 --vpc-id <vpc-id> --save
```

## 5. Approved private-IP scan

On the scanner EC2, use `config/scope.aws.example.json` and the Terraform `target_private_ip` output:

```powershell
python -m scripts.run_scan scan --target <target-private-ip> --ports 22,8080 --scope-file config/scope.aws.example.json -sT -sV
```

Expected normal-lab result: TCP/8080 open; TCP/22 is not required to be open merely because a Security Group rule exists.

For a legacy self-owned lab EC2, `AWS-SG-007` (FTP/21) and `AWS-SG-008` (Telnet/23) are also reported when those ports are Internet-wide. These are configuration findings, not proof that an FTP/Telnet daemon is actually listening.

## 6. Optional configuration-finding demonstration

Set `enable_demo_misconfiguration=true`, apply, and rerun `aws_security_review`. Expected finding:

- `AWS-SG-001`: Internet-wide SSH ingress
- target has no public IPv4, so the report must **not** claim proven Internet reachability

Return the variable to `false` and apply again. Rerunning the review should mark the stored rule `RESOLVED`.

## 7. Evidence

Useful screenshots/evidence:

- VPC/subnet diagram or resource map
- Scanner SG with no inbound rules
- Target SG using Scanner SG as source for 8080
- EC2 inventory CLI output
- AWS configuration finding output
- approved private-IP scan result
- VPC Flow Log entry showing scanner-private-IP -> target-private-IP:8080 ACCEPT
- CloudTrail Event History for Terraform-created/updated resources

Do not expose AWS credentials, session tokens, account secrets or unrelated resource data.

## 8. Cleanup

```powershell
terraform -chdir=infra/aws/terraform destroy
```

Confirm that lab EC2 instances, Flow Log, CloudWatch log group, VPC and related IAM lab roles were removed.
