# `exalm aws cost`

Detects cost anomalies in AWS billing data. Reads the JSON output of
`aws ce get-cost-and-usage`, identifies month-over-month spending spikes,
and returns an LLM-powered cost report ranked by impact.

---

## Prerequisites

- AWS credentials configured: `~/.aws/credentials`, instance profile, or
  environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`).
- Cost Explorer enabled in your AWS account (Settings → Cost Explorer).
  There is a small charge per API call ($0.01 per request at time of writing).

---

## Usage

```sh
# 1. Export cost data (two months to enable MoM comparison)
aws ce get-cost-and-usage \
  --time-period Start=2024-03-01,End=2024-05-01 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  > cost.json

# 2. Analyse
exalm aws cost --file cost.json

# Pipe directly
aws ce get-cost-and-usage \
  --time-period Start=2024-03-01,End=2024-05-01 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  | exalm aws cost

# JSON output
exalm aws cost --file cost.json --output json
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--file` | — | Read input from this file instead of stdin |

---

## Required IAM permissions

The `aws ce get-cost-and-usage` call requires the following IAM action:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}
```

Exalm itself makes no AWS API calls. It only reads the JSON you provide.

---

## Example output

```
# AWS cost analysis

Analysed 2 billing period(s) using claude.

## HIGH — EC2 spend up 340% month-over-month

EC2 cost rose from $1 240 to $5 460 between March and April.

**Likely causes:**
- New c5.4xlarge instances launched in us-east-1 on 2024-04-03
- On-demand pricing — no Savings Plan or Reserved Instance coverage

**Suggested next steps:**
1. Identify the instances: `aws ec2 describe-instances --filters "Name=instance-type,Values=c5.4xlarge"`
2. Evaluate Compute Savings Plans for sustained workloads
3. Tag instances with cost centre and owner for accountability

## MEDIUM — NAT Gateway data transfer $312 (new charge)

No NAT Gateway cost in March; $312 in April.
...
```

---

## Notes

- Input is capped at 200 KB. For accounts with hundreds of services, use
  `--group-by` filters to limit the export.
- The anomaly detector flags services where MoM spend increased by more than
  20% and at least $10 absolute.
- Cost data passes through the default redaction layer. AWS account IDs and
  IAM ARNs are not redacted by default (they are not secrets); enable
  `EXALM_OPTIONAL_REDACTIONS=aws-account-id` if needed.
