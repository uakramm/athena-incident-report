# Weekly Security Operations Report

This tool builds the weekly security report from Jira and emails it to the client.

## First-time setup (only once)

Open a terminal in this folder and run these three lines.

**Windows** (open **PowerShell** or **Command Prompt** in this folder):

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

**Mac:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Sending the report

Every time you open a new terminal, first activate the environment:

**Windows:**

```powershell
.venv\Scripts\activate
```

**Mac:**

```bash
source .venv/bin/activate
```

Then send the report (same command on both):

```
python generate_report.py --env-file .env.athena --send-email
```

That's it — this pulls the latest data from Jira and emails the report out.

> On Windows, if `python` isn't recognized, try `py` instead
> (e.g. `py -m venv .venv` and `py generate_report.py --env-file .env.athena --send-email`).

## Check before you send (optional)

If you just want to see **who the email will go to** without actually sending it,
run this instead — it shows the recipients and subject but sends nothing:

```
python generate_report.py --env-file .env.athena --email-dry-run
```

## Changing who it goes to

The recipients live in the **`.env.athena`** file. Open it and edit these lines:

- `REPORT_EMAIL_TO=` — the main recipient(s)
- `REPORT_EMAIL_CC=` — anyone to CC (optional)

Put a comma between addresses if there's more than one, for example:
`REPORT_EMAIL_TO=peter@athenasecuritygrp.com, shelly@athenasecuritygrp.com`

Save the file, then run the send command above.

## Manual AWS Lambda trigger behind VPN

This repo can also run as a Lambda function behind an **internal Application Load
Balancer**. The intended path is:

```
OpenVPN / Client VPN -> internal ALB -> Lambda -> Jira + Microsoft Graph
```

The ALB is internal and its security group allows inbound traffic only from the
Client VPN CIDR you pass at deploy time. The Lambda is not given a public URL.

Local deployment files:

- `lambda_handler.py` - ALB-compatible Lambda entry point.
- `infra/internal-alb-lambda.yaml` - CloudFormation template for new ALB/Lambda resources.
- `infra/deploy-internal-alb-lambda.sh` - guarded zip/layer packaging and deploy script.
- `infra/sync-tenant-secret.sh` - guarded tenant config secret create/update helper.
- `infra/report-config-secret.example.json` - example Secrets Manager JSON.

The deploy script packages the repo files into a small Lambda source zip and puts
third-party dependencies into a Lambda layer. This keeps the source files visible
in the Lambda console without mixing them with installed packages.

The deploy script refuses to continue if the target CloudFormation stack, S3
artifact bucket, or generated Secrets Manager secret already exists, so it does
not update existing resources by default.

Required deploy inputs:

```bash
export AWS_PROFILE=athena
export AWS_REGION=us-east-2
export VPC_ID=vpc-xxxxxxxx
export SUBNET_IDS=subnet-aaa,subnet-bbb
export CLIENT_VPN_CIDR=172.16.0.0/16
```

For AWS Client VPN, `CLIENT_VPN_CIDR` here means the source CIDR the ALB sees.
In this environment that is the VPC/target CIDR (`172.16.0.0/16`), not the
client-assigned VPN pool (`10.100.0.0/22`).

Tenant config secrets are not passed to Lambda through environment variables.
For a call with `tenant=nbs`, the handler reads this fixed secret name:

```text
athena-incident-report/nbs/config
```

The secret can be a JSON object or dotenv-style text using the same keys as the
local `.env` file. `REPORT_EMAIL_TO` and `REPORT_EMAIL_CC` are ignored from the
secret and must be passed on every API call. If the secret contains
`REPORT_TRIGGER_TOKEN`, callers must pass it as `X-Report-Token` or
`Authorization: Bearer ...`; if it is absent, the endpoint relies only on VPN/ALB
network access.

To create or update a tenant config secret from a local env file:

```bash
export TENANT=nbs
export ENV_FILE=.env.nbs
infra/sync-tenant-secret.sh
```

Then deploy the ALB/Lambda stack:

```bash
infra/deploy-internal-alb-lambda.sh
```

To update an existing stack, set `ALLOW_STACK_UPDATE=true` and reuse an existing
artifact bucket with `ALLOW_EXISTING_ARTIFACT_BUCKET=true`. To update an existing
tenant secret from `ENV_FILE`, set `ALLOW_SECRET_UPDATE=true`; the existing
`REPORT_TRIGGER_TOKEN` is preserved unless the env file includes a replacement.

Manual invocation from a VPN-connected machine:

```bash
curl -X POST "http://<internal-alb-dns-name>/run?tenant=nbs&email_to=client-contact%40example.com&email_cc=soc-team%40athenasecuritygrp.com&dry_run=true" \
  -H "X-Report-Token: <REPORT_TRIGGER_TOKEN>"
```

Form fields are also supported:

```bash
curl -X POST "http://<internal-alb-dns-name>/run" \
  -H "X-Report-Token: <REPORT_TRIGGER_TOKEN>" \
  --data-urlencode "tenant=nbs" \
  --data-urlencode "email_to=client-contact@example.com" \
  --data-urlencode "email_cc=soc-team@athenasecuritygrp.com" \
  --data-urlencode "dry_run=true"
```

JSON is still accepted, and is useful when passing nested `supplemental` data:

```bash
curl -X POST "http://<internal-alb-dns-name>/run" \
  -H "Content-Type: application/json" \
  -H "X-Report-Token: <REPORT_TRIGGER_TOKEN>" \
  -d '{
    "tenant": "nbs",
    "email_to": ["client-contact@example.com"],
    "email_cc": ["soc-team@athenasecuritygrp.com"],
    "dry_run": true
  }'
```

Use `"dry_run": false` or omit `dry_run` to send the report email. The handler
requires `tenant`, `email_to`, and `email_cc` on every `/run` call. `email_cc`
can be an empty array when there is no Cc recipient, but the key must be present.
The handler also accepts per-run overrides such as `week_of`, `project_key`,
`client`, `report_tenant`, `tenant_domain`, and `email_subject` as query args,
form fields, or JSON fields.
