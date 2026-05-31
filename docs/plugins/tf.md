# `exalm tf`

Review Terraform plans for risky changes before you apply them. Parses the
JSON output of `terraform show -json`, classifies each resource change by
blast radius, and returns an LLM-powered risk-ranked review.

---

## Usage

```sh
# 1. Create a plan file
terraform plan -out=plan.tfplan

# 2. Convert to JSON
terraform show -json plan.tfplan > plan.json

# 3. Review
exalm tf review --file plan.json

# Or pipe directly
terraform show -json plan.tfplan | exalm tf review

# JSON output
exalm tf review --file plan.json --output json
```

---

## Subcommands

### `exalm tf review`

Reads a `terraform show -json` plan, groups resource changes by risk level
(CRITICAL / HIGH / MEDIUM / LOW), and returns a prioritised review.

| Flag | Default | Description |
|---|---|---|
| `--file` | — | Read plan JSON from this file instead of stdin |

---

## What it looks for

Changes are classified by resource type and action:

| Risk | Examples |
|---|---|
| CRITICAL | Delete or replace: RDS, DynamoDB, ElastiCache, Aurora, Neptune, DocumentDB |
| HIGH | Delete or replace: IAM roles/policies/users, security groups, S3 buckets, KMS keys, VPCs |
| HIGH | Update: IAM roles/policies |
| MEDIUM | Update or replace: load balancers, ECS services, EKS clusters, Auto Scaling groups, Route 53, CloudFront |
| MEDIUM | Create: IAM or network resources |
| LOW | Everything else |

`no-op` changes are ignored.

---

## Example output

```
# Terraform plan review

Reviewed 12 resource change(s) from plan.json using claude.

## CRITICAL — [DELETE] aws_db_instance.payments_db

Resource type: aws_db_instance. Action: delete.

Verify backup exists and all consumers are updated before applying.
Data loss is permanent.

## HIGH — [UPDATE] aws_iam_role.app_role

Resource type: aws_iam_role. Action: update.

Review the IAM policy diff carefully for privilege escalation paths
or overly broad permissions.

## MEDIUM — [REPLACE] aws_security_group.internal

Resource type: aws_security_group. Action: replace.

Check that no ingress/egress rules were widened to 0.0.0.0/0 unintentionally.
```

---

## Input requirements

- Input must be the output of `terraform show -json`, not `terraform plan`
  human-readable text.
- Input is capped at 200 KB. For very large plans, generate the JSON and
  pre-filter it before piping.
- No Terraform binary is required at analysis time — Exalm only reads JSON.

---

## Notes

- Exalm is read-only: it never runs `terraform apply`. The `--apply` flag
  has no effect on the `tf` plugin.
- Redaction is applied before the plan is sent to the LLM. Connection strings,
  API keys, and tokens embedded in resource definitions are stripped.
