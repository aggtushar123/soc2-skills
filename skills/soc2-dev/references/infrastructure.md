# Infrastructure and Platform

This domain covers the cloud and platform layer the application runs on: how infrastructure is defined and reviewed, how networks are segmented, how cloud identities are scoped, how data is encrypted at rest, how hosts and managed services are patched, how the system survives zone loss and disasters, and how the public edge is shielded. It serves CC6.6 (boundary protection, network and encryption controls), CC6.1 and CC6.3 (logical access to cloud resources and least privilege), CC7.1 (vulnerability and patch management), CC8.1 (infrastructure changes go through change management), C1.2 (confidentiality via encryption at rest), and A1.1 through A1.3 (capacity, redundancy, and recovery). Auditors ask for IaC repositories, IAM policy exports, security group rules, KMS key policies, patch reports, and DR test records; console-only configuration with no code trail is a finding under CC8.1 even if the setting itself is correct.

## When Claude must load this file

- Creating or editing Terraform, Pulumi, CloudFormation, CDK, Bicep, Ansible, or Helm/Kustomize files
- Adding or modifying a security group, NACL, firewall rule, VPC, subnet, route table, peering, or PrivateLink/Private Service Connect
- Writing or changing an IAM policy, role, trust policy, service account, workload identity binding, SCP, or org policy
- Provisioning any datastore, bucket, queue, topic, disk, snapshot, or backup (RDS, DynamoDB, S3, EBS, SQS, Kafka, GCS, Cloud SQL, Azure Storage)
- Creating or editing KMS keys, key policies, or key rotation settings
- Changing instance AMIs, node pools, managed service engine versions, auto-minor-version-upgrade, or maintenance windows
- Editing autoscaling groups, replica counts, multi-AZ flags, load-balancer configuration, or Route 53 / Cloud DNS failover
- Adding a public endpoint, CloudFront/Cloud CDN distribution, API Gateway, or ALB listener
- Writing or changing DR, backup, or restore runbooks
- Reviewing `terraform plan` output or drift-detection reports

## Requirements

### INFRA-01 — Infrastructure as code with drift detection

**Rule:** All infrastructure is defined in version-controlled code, changed only through the same PR process as application code (CHG-01 through CHG-04), and continuously compared to the live environment so unmanaged changes are detected.

**TSC:** CC8.1, CC6.6

**How to implement:**
- Put every production resource in Terraform, Pulumi, CloudFormation, or CDK under a repo path owned by `@acme/platform` in CODEOWNERS. Store Terraform state remotely with locking and encryption (S3 + DynamoDB lock + KMS, Terraform Cloud, GCS backend).
- Run `terraform plan` on every PR and post the plan as a PR comment (Atlantis, Terraform Cloud run tasks, `terraform-plan` GitHub Action). Apply only from the pipeline on merge (CHG-07); never `apply` from a laptop against production.
- Run IaC security scanning as a required check (`iac-scan`): Checkov, tfsec/Trivy `config`, KICS, or cfn-nag. Fail on high (public S3, `0.0.0.0/0` on non-LB ports, unencrypted storage, wildcard IAM).
- Detect drift on a schedule: `terraform plan -detailed-exitcode` nightly against production (exit code 2 = drift), Terraform Cloud drift detection, AWS Config with `cloudformation-stack-drift-detection-check`, or driftctl. Alert to the platform on-call channel and open a ticket per drift event.
- Deny console writes for humans (CHG-07) so drift is rare and each occurrence is investigated; reconcile by importing into code or reverting, never by ignoring.
- Tag every resource with `managed-by=terraform`, `owner`, `env`, and `data-classification`; a Config rule or Cloud Asset query lists untagged resources, which are by definition unmanaged.

**Code example:**

```yaml
# .github/workflows/drift.yml
name: iac-drift
on: { schedule: [{ cron: "0 2 * * *" }], workflow_dispatch: {} }
permissions: { contents: read, id-token: write, issues: write }
jobs:
  drift:
    runs-on: ubuntu-latest
    environment: production-readonly
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: aws-actions/configure-aws-credentials@v4
        with: { role-to-assume: "arn:aws:iam::123456789012:role/github-plan-readonly", aws-region: ap-south-1 }
      - uses: hashicorp/setup-terraform@v3
      - run: terraform -chdir=infra/prod init -input=false
      - name: Detect drift
        run: |
          # SOC2:INFRA-01 exit code 2 means live infra differs from code
          set +e
          terraform -chdir=infra/prod plan -detailed-exitcode -input=false -lock=false -out=drift.plan
          rc=$?; set -e
          if [ "$rc" = "2" ]; then
            terraform -chdir=infra/prod show -no-color drift.plan > drift.txt
            gh issue create --title "Infra drift detected $(date -u +%F)" --label drift --body-file drift.txt
            exit 1
          fi
        env: { GH_TOKEN: "${{ github.token }}" }
```

**Common violations:**
- The VPC, RDS instance, and IAM roles were click-created years ago and only new resources are in Terraform.
- Terraform state stored in a public or unencrypted bucket; state contains secrets and full resource configs.
- Drift detection runs but nobody reads the output; 40 resources have drifted for a year.
- Engineers "hotfix" a security group in the console and forget to backport, so the next `apply` reopens the hole or silently re-closes something someone relied on.

**Evidence to produce:**
- IaC repo path and the `iac-scan` and `iac-drift` workflow files with recent run links.
- Drift issues opened and closed during the period, each with a reconciliation PR.
- Terraform backend configuration showing encryption and locking.

### INFRA-02 — Network segmentation, deny-by-default

**Rule:** Databases, caches, queues, and internal services live in private subnets with no public IPs. Security groups and firewall rules deny by default and allow only specific source security groups or CIDRs on specific ports. Only load balancers (and bastion or VPN endpoints if used) are internet-facing.

**TSC:** CC6.6

**How to implement:**
- Three-tier subnet layout per AZ: public (ALB/NLB, NAT gateways only), private-app (compute), private-data (RDS, ElastiCache, MSK, OpenSearch). Data subnets have no route to an internet gateway or NAT.
- Security groups reference other security groups as sources, not CIDRs: `db_sg` allows 5432 from `app_sg` only; `app_sg` allows 8080 from `alb_sg` only; `alb_sg` allows 443 from `0.0.0.0/0` and nothing else. Deny everything else implicitly; add explicit NACL denies for known-bad ranges if required.
- Egress: restrict outbound from app and data tiers to what is required (VPC endpoints for S3/Secrets Manager/KMS/STS/ECR, plus specific SaaS CIDRs or an egress proxy). `0.0.0.0/0` egress on the data tier is a finding.
- Use VPC endpoints / Private Service Connect / Private Link for cloud APIs so traffic never traverses the public internet.
- Enable VPC Flow Logs (to the log sink, LOG-04) and use them plus AWS Network Access Analyzer or GCP Firewall Insights to prove no path exists from the internet to data subnets.
- Enforce with policy: Checkov `CKV_AWS_24/25` (0.0.0.0/0 on 22/3389), custom OPA/Sentinel rule blocking any non-ALB security group with a public ingress, AWS Config `rds-instance-public-access-check`, `ec2-instance-no-public-ip`.

**Code example:**

```hcl
# network/security-groups.tf
# SOC2:INFRA-02 deny-by-default; only the ALB is reachable from the internet
resource "aws_security_group" "alb" {
  name   = "prod-alb"
  vpc_id = aws_vpc.main.id
  ingress { from_port = 443; to_port = 443; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
  egress  { from_port = 8080; to_port = 8080; protocol = "tcp"; security_groups = [aws_security_group.app.id] }
}

resource "aws_security_group" "app" {
  name   = "prod-app"
  vpc_id = aws_vpc.main.id
  ingress { from_port = 8080; to_port = 8080; protocol = "tcp"; security_groups = [aws_security_group.alb.id] }
  egress  { from_port = 5432; to_port = 5432; protocol = "tcp"; security_groups = [aws_security_group.db.id] }
  egress  { from_port = 443;  to_port = 443;  protocol = "tcp"; prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id] }
}

resource "aws_security_group" "db" {
  name   = "prod-db"
  vpc_id = aws_vpc.main.id
  ingress { from_port = 5432; to_port = 5432; protocol = "tcp"; security_groups = [aws_security_group.app.id] }
  # no egress block: AWS default allow-all egress is overridden to none below
}
resource "aws_vpc_security_group_egress_rule" "db_none" {
  security_group_id = aws_security_group.db.id
  ip_protocol       = "-1"
  cidr_ipv4         = "127.0.0.1/32"  # effectively no egress
}

resource "aws_db_instance" "main" {
  identifier             = "prod-main"
  publicly_accessible    = false                       # SOC2:INFRA-02
  db_subnet_group_name   = aws_db_subnet_group.private_data.name
  vpc_security_group_ids = [aws_security_group.db.id]
  storage_encrypted      = true                        # SOC2:INFRA-04
  kms_key_id             = aws_kms_key.data.arn        # SOC2:INFRA-04
  multi_az               = true                        # SOC2:INFRA-06
}
```

**Common violations:**
- RDS with `publicly_accessible = true` "protected" by a security group that allows the office IP, and later `0.0.0.0/0` for a contractor.
- Default security group left with allow-all ingress from itself and attached to everything.
- SSH (22) or RDP (3389) open to the internet on app hosts instead of SSM Session Manager or a bastion behind VPN.
- Redis or Elasticsearch with no auth in a subnet that has a NAT route and a permissive security group.

**Evidence to produce:**
- Security group and subnet Terraform paths; `aws ec2 describe-security-groups` export filtered for `0.0.0.0/0` showing only the ALB group.
- AWS Config compliance report for `rds-instance-public-access-check` and `ec2-instance-no-public-ip`.
- Network Access Analyzer finding report showing zero internet-to-data-subnet paths.

### INFRA-03 — Least-privilege cloud IAM, no long-lived keys

**Rule:** Cloud IAM policies grant only the specific actions and resources each workload needs. No `"Action": "*"` or `"Resource": "*"` in production policies (except where the API requires `*` for a read-only list action). Workloads and CI use roles or workload identity; no IAM users with access keys.

**TSC:** CC6.1, CC6.3

**How to implement:**
- One IAM role (or GCP service account / Azure managed identity) per workload, attached via IRSA / EKS Pod Identity, ECS task role, Lambda execution role, GKE Workload Identity, or Azure Workload Identity. Never share a role across services.
- Write policies from the workload's actual calls: enable CloudTrail, run the service in staging, and generate a policy with IAM Access Analyzer policy generation or `iamlive`. Then scope resources to specific ARNs and add conditions (`aws:SourceVpce`, `s3:prefix`, `kms:ViaService`).
- Ban wildcards in CI: Checkov `CKV_AWS_107/108/109/110/111`, `tfsec aws-iam-no-policy-wildcards`, or a Semgrep rule on `"Action": "*"`. Where a `List*`/`Describe*` action legitimately needs `Resource: "*"`, isolate it in its own statement with a justifying comment.
- Delete all IAM user access keys in production accounts; enforce with AWS Config `iam-user-no-policies-check`, `access-keys-rotated` (as a tripwire), and an SCP denying `iam:CreateAccessKey`. Humans use SSO (IAM Identity Center, Okta, Google Workspace) with short sessions and MFA; CI uses OIDC (CHG-07).
- Apply SCPs / org policies as guardrails: deny leaving the org, deny disabling CloudTrail/GuardDuty/Config, deny creating IAM users, restrict regions.
- Review with IAM Access Analyzer unused-access findings quarterly and remove permissions unused for 90 days.

**Code example:**

Anti-pattern (fails review):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:*", "kms:*", "sqs:*"],
    "Resource": "*"
  }]
}
```

Corrected:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadWriteUploadsBucket",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::acme-prod-uploads/tenants/*",
      "Condition": { "StringEquals": { "aws:SourceVpce": "vpce-0a1b2c3d" } }
    },
    {
      "Sid": "ListUploadsBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::acme-prod-uploads",
      "Condition": { "StringLike": { "s3:prefix": ["tenants/*"] } }
    },
    {
      "Sid": "UseDataKeyViaS3Only",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:ap-south-1:123456789012:key/6f1e...",
      "Condition": { "StringEquals": { "kms:ViaService": "s3.ap-south-1.amazonaws.com" } }
    },
    {
      "Sid": "ConsumeJobQueue",
      "Effect": "Allow",
      "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
      "Resource": "arn:aws:sqs:ap-south-1:123456789012:prod-jobs"
    }
  ]
}
```

```hcl
# SOC2:INFRA-03 workload identity for the pod; no access keys anywhere
resource "aws_iam_role" "api" {
  name               = "prod-api"
  assume_role_policy = data.aws_iam_policy_document.eks_pod_identity_trust.json
}
resource "aws_eks_pod_identity_association" "api" {
  cluster_name    = aws_eks_cluster.prod.name
  namespace       = "api"
  service_account = "api"
  role_arn        = aws_iam_role.api.arn
}
```

**Common violations:**
- `AdministratorAccess` attached to the application role "until we figure out what it needs".
- An IAM user `ci-deployer` with an access key created in 2021, stored in three CI systems.
- `"Resource": "*"` on `kms:Decrypt`, letting any compromised workload decrypt every key in the account.
- Developers share a single `admin` SSO permission set with 12-hour sessions and no MFA re-prompt.

**Evidence to produce:**
- IAM policy documents in the IaC repo; `iac-scan` results showing wildcard rules enforced.
- `aws iam list-users` + `list-access-keys` export for production accounts (should be empty) and the SCP denying key creation.
- IAM Access Analyzer unused-access report and the quarterly review ticket.

### INFRA-04 — Encryption at rest with KMS-managed keys

**Rule:** Every datastore, object bucket, queue, topic, volume, snapshot, and backup has encryption at rest enabled using customer-managed KMS keys with restricted key policies and rotation enabled.

**TSC:** CC6.6, C1.2

**How to implement:**
- Create customer-managed keys (AWS KMS CMK, GCP Cloud KMS, Azure Key Vault key) per data domain or classification (`data`, `logs`, `backups`, `secrets`). Enable automatic annual rotation. Do not use the AWS-managed `aws/*` keys for restricted data; their policies cannot be restricted.
- Key policy: administrators (`kms:Create*/Put*/Schedule*`) are a small platform role; users (`kms:Encrypt/Decrypt/GenerateDataKey`) are the specific workload roles; add `kms:ViaService` conditions so a key for RDS cannot be used directly. Deny `kms:ScheduleKeyDeletion` via SCP outside a break-glass path.
- Enable encryption on: RDS/Aurora (`storage_encrypted` + `kms_key_id`), DynamoDB (`server_side_encryption` with CMK), S3 (bucket default encryption `aws:kms` + `bucket_key_enabled`, plus a bucket policy denying unencrypted `PutObject`), EBS (account-level default encryption), EFS, ElastiCache (`at_rest_encryption_enabled`), SQS/SNS (`kms_master_key_id`), MSK, OpenSearch, Secrets Manager, CloudWatch Logs, and every snapshot/AMI/backup vault.
- Turn on account-wide defaults: EBS encryption by default, S3 Block Public Access at the account level, RDS snapshot copy with CMK for cross-region.
- Enforce with AWS Config managed rules (`rds-storage-encrypted`, `s3-default-encryption-kms`, `encrypted-volumes`, `dynamodb-table-encrypted-kms`, `sqs-queue-encrypted`, `cloudwatch-log-group-encrypted`) and Checkov/tfsec checks in `iac-scan`.
- Encryption at rest does not replace field-level encryption for restricted fields (DATA-02); both apply.

**Code example:**

```hcl
# kms/data-key.tf
# SOC2:INFRA-04 customer-managed key, rotated, usable only by app roles via S3/RDS
resource "aws_kms_key" "data" {
  description             = "prod data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.data_key.json
}

data "aws_iam_policy_document" "data_key" {
  statement {
    sid       = "KeyAdmins"
    actions   = ["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:Put*", "kms:Update*", "kms:Get*", "kms:List*", "kms:TagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"]
    resources = ["*"]
    principals { type = "AWS"; identifiers = [aws_iam_role.platform_kms_admin.arn] }
  }
  statement {
    sid       = "WorkloadUseViaServices"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals { type = "AWS"; identifiers = [aws_iam_role.api.arn, aws_iam_role.worker.arn] }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.ap-south-1.amazonaws.com", "rds.ap-south-1.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms"; kms_master_key_id = aws_kms_key.data.arn }
    bucket_key_enabled = true
  }
}
```

**Common violations:**
- Encryption enabled on the RDS instance but manual snapshots copied to another region unencrypted.
- S3 default encryption set, but no bucket policy denying `PutObject` without `x-amz-server-side-encryption`, so a misconfigured client writes plaintext objects.
- Key policy contains `"Principal": {"AWS": "arn:aws:iam::123456789012:root"}` with `kms:*`, which effectively delegates to any IAM policy in the account.
- CloudWatch log groups and SQS queues holding PII use no CMK because "it's just logs".

**Evidence to produce:**
- KMS key policy exports and `enable_key_rotation` state for each CMK.
- AWS Config compliance dashboard export for the encryption rules listed above, showing 100% compliant.
- Bucket policy denying unencrypted uploads.

### INFRA-05 — Patching within SLA, auto-update enabled

**Rule:** Managed services, hosts, node pools, and base images receive security patches within the SEC-03 SLAs (critical 7 days, high 30 days, medium 90 days, low 180 days). Automatic updates are enabled wherever the platform offers them.

**TSC:** CC7.1

**How to implement:**
- Prefer managed and serverless services (RDS, Fargate, Lambda, Cloud Run, GKE Autopilot) where the provider patches the OS; document that reliance in `.soc2/CONTROL_MAP.md` and keep the provider's SOC 2 report on file.
- Managed databases: enable `auto_minor_version_upgrade`, set a maintenance window, and track major-version EOL dates (RDS extended support fees are a signal you are late).
- Kubernetes: enable node auto-upgrade and auto-repair (GKE release channels, EKS managed node groups with `update_config`), rotate nodes at least monthly, and keep the control plane within N-1 of current.
- EC2/VMs: bake AMIs weekly with EC2 Image Builder or Packer from the vendor's latest, and roll instances via ASG instance refresh; use SSM Patch Manager with a baseline that auto-approves critical after 0 days and high after 7 days, with compliance reporting. Do not patch in place on long-lived pets.
- Containers: pin base images by digest and let Renovate bump them (SEC-05); rebuild and redeploy weekly regardless.
- Scan continuously with Amazon Inspector, GCP Security Command Center, or Trivy/Grype in the registry, and feed findings into a tracked queue with SLA due dates. Report monthly on findings past SLA.

**Code example:**

```hcl
# compute/patching.tf
# SOC2:INFRA-05 managed services auto-patch; hosts rolled from fresh AMIs on a schedule
resource "aws_db_instance" "main" {
  # ...
  auto_minor_version_upgrade = true
  maintenance_window         = "sun:19:00-sun:20:00"   # UTC
}

resource "aws_eks_node_group" "app" {
  cluster_name    = aws_eks_cluster.prod.name
  node_group_name = "app"
  release_version = data.aws_ssm_parameter.eks_ami_release.value  # latest EKS-optimized AMI
  update_config { max_unavailable_percentage = 25 }
}

resource "aws_ssm_patch_baseline" "linux" {
  name             = "prod-linux"
  operating_system = "AMAZON_LINUX_2023"
  approval_rule {
    approve_after_days = 0
    compliance_level   = "CRITICAL"
    patch_filter { key = "SEVERITY"; values = ["Critical"] }
    patch_filter { key = "CLASSIFICATION"; values = ["Security"] }
  }
  approval_rule {
    approve_after_days = 7
    compliance_level   = "HIGH"
    patch_filter { key = "SEVERITY"; values = ["Important"] }
  }
}
```

**Common violations:**
- `auto_minor_version_upgrade = false` set years ago to avoid a surprise restart, never revisited; database is three minor versions behind with known CVEs.
- Kubernetes nodes running an AMI from 14 months ago because the node group was never refreshed.
- Inspector findings exist but no one owns them; 200 high findings older than 90 days.
- Patching "policy" is verbal; no report shows time-to-patch against SLA.

**Evidence to produce:**
- Terraform paths showing auto-upgrade settings and patch baselines; SSM Patch Manager compliance report.
- Inspector/SCC findings export with age and status; monthly SLA report.
- Node group AMI release dates and the last instance-refresh timestamps.

### INFRA-06 — Redundancy, capacity, and tested DR

**Rule:** Where Availability is in scope, production runs across multiple availability zones with autoscaling or documented capacity headroom, and a disaster-recovery runbook with defined RPO/RTO exists and is tested on a schedule.

**TSC:** A1.1, A1.2, A1.3

**How to implement:**
- Deploy compute across at least two AZs (three preferred) behind a load balancer; set minimum replica count ≥ 2 with pod anti-affinity or ASG AZ balancing. Databases in Multi-AZ (RDS `multi_az`, Aurora with a reader in another AZ, Cloud SQL HA).
- Autoscale on a leading indicator (request rate, queue depth, CPU) with a max that has been load-tested; if fixed capacity, document headroom (e.g. "peak is 40% of provisioned") and review quarterly.
- Backups: automated daily snapshots plus point-in-time recovery, cross-region copy for tier-1 datastores, AWS Backup vault with vault lock, retention per DATA-04 and DATA-07. Encrypt with the backups CMK (INFRA-04).
- Write `docs/runbooks/dr.md` with the RPO/RTO table, failover steps, roles, communication plan, and rollback to primary. Keep IaC able to stand up the stack in the DR region (`terraform apply -var region=...`).
- Test: quarterly restore-from-backup into an isolated account (verify row counts and checksums), annual full regional failover exercise or game day. Record date, participants, achieved RPO/RTO, and gaps as tickets.
- Alert on backup job failures and on any AZ with zero healthy targets (LOG-05).

**DR runbook skeleton:**

| Service / datastore | Tier | RPO | RTO | Mechanism |
|---------------------|------|-----|-----|-----------|
| Primary PostgreSQL (RDS) | 1 | 5 min | 1 h | Multi-AZ auto failover; cross-region read replica promotion for regional loss |
| Object storage (S3 uploads) | 1 | 15 min | 30 min | Cross-region replication, versioning enabled |
| Redis cache | 3 | n/a (rebuildable) | 15 min | Recreate from IaC; app tolerates cold cache |
| Message queue (SQS) | 2 | 0 (durable) | 30 min | Regional service; producers retry; DR region queues pre-created |
| Kubernetes workloads | 1 | n/a (stateless) | 1 h | IaC + image registry replication; DNS failover |

Failover steps (regional loss):

1. Incident commander declares DR; page platform on-call and comms lead; open the incident channel and start the timeline.
2. Confirm primary region is unrecoverable within RTO (provider status page, health checks failing > 15 min).
3. Promote the cross-region RDS replica; update the `DB_SECRET_ARN` secret in the DR region to the promoted endpoint (SEC-02, no code change).
4. Run `terraform apply` for the DR region workspace via the pipeline (CHG-07) to scale compute from warm-standby to production size.
5. Verify readiness probes and synthetic checks pass in the DR region (LOG-06).
6. Switch Route 53 failover record (or lower TTL and repoint) to the DR ALB; confirm traffic and error rates via dashboards.
7. Announce status; record achieved RPO/RTO; schedule failback and post-incident review.

Test cadence: backup restore test quarterly; AZ-loss simulation (drain one AZ) semi-annually; full regional failover exercise annually; runbook review after every production incident that touched availability.

**Code example:**

```hcl
# compute/asg.tf
# SOC2:INFRA-06 multi-AZ, min 2, scales on request rate
resource "aws_autoscaling_group" "app" {
  name                = "prod-app"
  vpc_zone_identifier = [aws_subnet.private_app_a.id, aws_subnet.private_app_b.id, aws_subnet.private_app_c.id]
  min_size            = 2
  max_size            = 12
  health_check_type   = "ELB"
  target_group_arns   = [aws_lb_target_group.app.arn]
  instance_refresh { strategy = "Rolling"; preferences { min_healthy_percentage = 90 } }
}

resource "aws_autoscaling_policy" "req_per_target" {
  name                   = "alb-requests"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.app.arn_suffix}/${aws_lb_target_group.app.arn_suffix}"
    }
    target_value = 800
  }
}
```

**Common violations:**
- "Multi-AZ" compute behind a single-AZ database; the app survives AZ loss but the data does not.
- Backups exist but a restore has never been attempted; the first real restore reveals the KMS key policy blocks the DR account.
- RTO in the runbook is 1 hour; the actual exercise took 9 hours because DNS TTL was 24 h.
- DR region has no IAM roles, secrets, or KMS keys provisioned, so IaC apply fails during the incident.

**Evidence to produce:**
- `docs/runbooks/dr.md` with the RPO/RTO table; Terraform showing `multi_az`, multi-subnet ASG/node groups, and backup plans.
- Most recent restore test and failover exercise records (date, achieved RPO/RTO, gap tickets).
- AWS Backup job history export for the period with zero unresolved failures.

### INFRA-07 — WAF and DDoS protection on public edges

**Rule:** Every internet-facing endpoint (load balancer, CDN distribution, API gateway) sits behind a web application firewall with managed rule sets and a DDoS protection service.

**TSC:** CC6.6, A1.1

**How to implement:**
- Attach AWS WAFv2 to every ALB, CloudFront distribution, and API Gateway stage; on GCP use Cloud Armor policies on backend services; on Azure use Front Door/Application Gateway WAF; or Cloudflare WAF if edge is fronted by Cloudflare.
- Enable managed rule groups: AWS `AWSManagedRulesCommonRuleSet`, `KnownBadInputsRuleSet`, `SQLiRuleSet`, `AmazonIpReputationList`, `AnonymousIpList`, plus `BotControl` for public web apps. Cloud Armor: preconfigured `sqli-v33-stable`, `xss-v33-stable`, `lfi`, `rfi`, `rce` and Adaptive Protection.
- Add rate-based rules at the edge for login, password reset, and token endpoints (complements AUTH-06 and API-04): e.g. 100 requests per 5 minutes per IP on `/auth/*`.
- DDoS: AWS Shield Standard is automatic; enable Shield Advanced for tier-1 public apps (SRT access, cost protection, health-based detection). GCP Cloud Armor includes DDoS defense; Cloudflare/Fastly equivalents. Route public traffic through CloudFront or Cloud CDN so the origin ALB is not directly reachable (restrict origin security group to the CDN prefix list and require a shared origin header).
- Ship WAF logs to the central sink (LOG-04) and alert on blocked-request spikes and rule-group anomalies (LOG-05). Start new rules in `COUNT` mode for a week, review false positives, then switch to `BLOCK`.
- Enforce via IaC scan and Config rule (`alb-waf-enabled`, `cloudfront-associated-with-waf`, `api-gw-associated-with-waf`) so an ALB without a web ACL fails `iac-scan`.

**Code example:**

```hcl
# edge/waf.tf
# SOC2:INFRA-07 managed rules + rate limit on auth endpoints, attached to the public ALB
resource "aws_wafv2_web_acl" "public" {
  name  = "prod-public"
  scope = "REGIONAL"
  default_action { allow {} }

  rule {
    name     = "aws-common"
    priority = 1
    override_action { none {} }
    statement { managed_rule_group_statement { name = "AWSManagedRulesCommonRuleSet"; vendor_name = "AWS" } }
    visibility_config { cloudwatch_metrics_enabled = true; metric_name = "common"; sampled_requests_enabled = true }
  }
  rule {
    name     = "auth-rate-limit"
    priority = 10
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
        scope_down_statement { byte_match_statement {
          search_string = "/auth/"; positional_constraint = "STARTS_WITH"
          field_to_match { uri_path {} }
          text_transformation { priority = 0; type = "LOWERCASE" }
        } }
      }
    }
    visibility_config { cloudwatch_metrics_enabled = true; metric_name = "auth_rl"; sampled_requests_enabled = true }
  }
  visibility_config { cloudwatch_metrics_enabled = true; metric_name = "prod_public"; sampled_requests_enabled = true }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = aws_wafv2_web_acl.public.arn
}
resource "aws_shield_protection" "alb" { name = "prod-alb"; resource_arn = aws_lb.app.arn }
```

**Common violations:**
- WAF attached to CloudFront but the origin ALB is also directly reachable, so attackers bypass the WAF by hitting the ALB hostname.
- All managed rules left in `COUNT` mode permanently after a false-positive scare.
- A new API Gateway stage created without a web ACL because the WAF association is a separate resource nobody added.
- WAF logging disabled to save cost, so blocked-request evidence is unavailable.

**Evidence to produce:**
- WAF web ACL Terraform path and `aws wafv2 list-resources-for-web-acl` export showing every public ALB/CloudFront/API Gateway attached.
- Shield Advanced subscription or Cloud Armor policy export; WAF log query showing blocked requests in the period.
- AWS Config compliance for `alb-waf-enabled` and `cloudfront-associated-with-waf`.

## Review checklist

- [ ] INFRA-01 — Is every infrastructure change in this PR expressed in IaC with a posted plan, a green `iac-scan`, and no console-only steps described in the PR body?
- [ ] INFRA-02 — Do new or modified security groups reference source security groups (not `0.0.0.0/0`) for anything other than 443 on the load balancer, and are new datastores in private subnets with `publicly_accessible = false`?
- [ ] INFRA-03 — Are new IAM policies free of wildcard actions/resources, attached to a per-workload role via workload identity, with no IAM user access keys introduced?
- [ ] INFRA-04 — Does every new datastore, bucket, queue, volume, log group, or backup set a customer-managed KMS key with rotation and a restricted key policy?
- [ ] INFRA-05 — Do new managed services and node pools enable auto-upgrade with a maintenance window, and are base images/AMIs sourced from a currently patched release?
- [ ] INFRA-06 — If Availability is in scope, is the new component multi-AZ with min replicas ≥ 2 or documented headroom, included in backups, and reflected in the DR runbook's RPO/RTO table?
- [ ] INFRA-07 — Does any new public endpoint (ALB, CloudFront, API Gateway) have a WAF web ACL association with managed rules and DDoS protection, and is the origin locked to the CDN?
