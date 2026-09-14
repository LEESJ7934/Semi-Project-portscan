# AWS Security Lab Architecture

## Purpose

This lab extends the existing approved-scope infrastructure scanner to an AWS VPC without turning AWS discovery into automatic scanning. The AWS layer proves cloud-architecture understanding while preserving the existing scan authorization gate.

## Architecture

```text
AWS VPC 10.20.0.0/16
├─ Scanner subnet 10.20.1.0/24
│  └─ Scanner EC2
│     ├─ no inbound Security Group rules
│     ├─ SSM Session Manager administration
│     ├─ IAM instance profile
│     └─ Python scanner / boto3 read-only inventory
└─ Target subnet 10.20.2.0/24
   └─ Target EC2
      ├─ no public IPv4 address
      └─ TCP/8080 allowed only from Scanner SG

VPC Flow Logs -> CloudWatch Logs
CloudTrail Event History -> management-event evidence (no dedicated trail required by this lab)
```

## Security decisions

- No AWS access key or secret key is stored in the repository or `.env`. Live AWS calls use the EC2 instance role or the operator's standard AWS credential chain.
- Scanner administration uses Systems Manager Session Manager. No inbound SSH rule is created for the scanner.
- The target receives no public IP and has no default Internet route.
- Target TCP/8080 uses a Security Group reference to the scanner Security Group rather than a hard-coded source IP.
- `enable_demo_misconfiguration=false` by default. When explicitly enabled, an Internet-wide TCP/22 rule is added only to demonstrate the configuration analyzer; the target still has no public IP.
- VPC Flow Logs are short-lived lab evidence. `terraform destroy` is part of the validation/cleanup procedure.

## Inventory vs scan authorization

AWS discovery is **not** scan authorization.

```text
DescribeInstances / DescribeSecurityGroups
            ↓
      cloud asset inventory
            ↓
      approved ScopePolicy
            ↓
      private-IP port scan
```

`config/scope.aws.example.json` authorizes only the dedicated target subnet. A newly discovered EC2 instance is not scanned unless the operator explicitly invokes the scanner with an approved target/scope.

## Current limitations

- V6 is intentionally scoped to one AWS account/region/VPC lab at a time when persisting assets. The pre-existing `hosts.host_ip` unique key is IP-centric and cannot safely distinguish overlapping RFC1918 addresses across different VPCs/accounts.
- The Security Group analyzer evaluates ingress configuration and whether an instance has a public IP. It does **not** prove Internet reachability; route tables, IGWs, NACLs and host firewall state are not calculated as a reachability graph.
- Only EC2 and Security Groups are inventoried. RDS, EKS, ELB, IAM posture, GuardDuty/Security Hub findings and organization-level controls are out of scope.
