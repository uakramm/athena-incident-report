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

The AWS deployment uses a Private REST API Gateway and an asynchronous Lambda
dispatcher:

```
OpenVPN / Client VPN -> execute-api VPC endpoint -> Private REST API
                    -> dispatcher Lambda -> report Lambda -> Jira + Microsoft Graph
```

The private API is restricted to its `execute-api` interface VPC endpoint. The
endpoint security group allows HTTPS only from `172.16.0.0/16`. There is no
public API endpoint, load balancer, scheduler, or recurring health-check Lambda
invocation. The default deployment uses one endpoint subnet in `us-east-2a` to
keep the fixed PrivateLink cost to one endpoint ENI; add a second subnet only if
the manual trigger needs multi-AZ endpoint availability.

API Gateway returns `202 Accepted` after validating the request and queuing the
report. The report Lambda then runs in the background, avoiding API Gateway's
29-second integration timeout.

### Run a report

Connect to the Client VPN, then run:

```bash
REPORT_EMAIL_TO='recipient@example.com' REPORT_EMAIL_CC='' REPORT_TRIGGER_TOKEN='tenant-token' ./run-report.sh athena
```

For NBS:

```bash
REPORT_EMAIL_TO='recipient@example.com' REPORT_EMAIL_CC='soc@example.com' REPORT_TRIGGER_TOKEN='tenant-token' ./run-report.sh nbs
```

Add `--dry-run` after the tenant to validate and generate without sending email:

```bash
REPORT_EMAIL_TO='recipient@example.com' REPORT_EMAIL_CC='' REPORT_TRIGGER_TOKEN='tenant-token' ./run-report.sh athena --dry-run
```

The runner includes the endpoint-specific URL and API ID as non-secret defaults,
so `run-report.sh` can be shared and used as a standalone file. The deploy script
also saves the current values locally for future infrastructure updates. This
endpoint hostname resolves to its private IP without relying on OpenVPN to
replace the macOS DNS resolver.
`REPORT_EMAIL_TO` must have at least one address. `REPORT_EMAIL_CC` must always
be set and may be empty.

### Tenant configuration

Tenant config secrets are not passed to Lambda through environment variables.
For a call with `tenant=nbs`, the handler reads this fixed secret name:

```text
athena-incident-report/nbs/config
```

The secret can be a JSON object or dotenv-style text using the same keys as the
local `.env` file. `REPORT_EMAIL_TO` and `REPORT_EMAIL_CC` are ignored from the
secret and must be passed on every API call. If the secret contains
`REPORT_TRIGGER_TOKEN`, callers must pass it as `X-Report-Token` or
`Authorization: Bearer ...`; if it is absent, the endpoint relies only on the
VPN/private API network boundary.

Set `REPORT_LOG_LEVEL=DEBUG` in a tenant secret only when you need the detailed
Jira API trace in CloudWatch. The default `INFO` level keeps the high-level
report progress logs and hides per-request Jira HTTP/search/count/JQL details.

To create or update a tenant config secret from a local env file:

```bash
export TENANT=nbs
export ENV_FILE=.env.nbs
infra/sync-tenant-secret.sh
```

### Deploy or migrate

Deployment files:

- `lambda_handler.py` - private API dispatcher and report worker handlers.
- `infra/private-api-lambda.yaml` - Private REST API, VPC endpoint, and Lambda resources.
- `infra/deploy-private-api-lambda.sh` - guarded zip/layer packaging and ALB migration.
- `infra/sync-tenant-secret.sh` - guarded tenant secret create/update helper.
- `run-report.sh` - simple manual report command.

The deployment keeps third-party dependencies in a Lambda layer, so source files
remain visible in the Lambda code console. The migration script targets AWS
profile `athena`, region `us-east-2`, the existing VPC/subnets, and the existing
CloudFormation stack by default. It prints the exact change and requires typing
`MIGRATE` before it updates AWS.

```bash
AWS_PROFILE=athena AWS_REGION=us-east-2 infra/deploy-private-api-lambda.sh
```
