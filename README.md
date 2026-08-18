# Weekly Security Operations Report

This tool builds the weekly security report from the tenant's OpenSearch
`pallas-incidents` index and emails it to the client. Jira remains authoritative;
the Pallas sync service mirrors its latest ticket state into this index.

The report includes summary-level incident metrics with Jira drill-down links,
an Agent Status section sourced from the Wazuh Manager API, vulnerability
metrics, and a SOC 2 Compliance Status section based on Wazuh TSC mappings. It
intentionally omits the long open/closed ticket tables; users can open the
filtered Jira result behind each metric when they need ticket detail.

Agent Status follows the existing Agent Summary definition: an agent is active
when it reported within 24 hours, inactive agents are grouped into 24-72 hours,
3-7 days, and 7-14 days, and agents not seen for more than 14 days are excluded.
Configure `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASS`, and `WAZUH_VERIFY_SSL` in
the tenant env file. `WAZUH_PORT` defaults to `55000`. The optional
`REPORT_AGENT_STATUS_URL` controls the report's agent-detail link.

SOC 2 Compliance Status states, criterion by criterion, what the SOC did for the
client this week and what the week's own numbers show. Each row is marked *Met*
when the control operated with no exception in the data, *Attention* when it
operated but the numbers show a gap, and *Not evidenced* when the source was
enabled but had nothing to read — a source that failed is never reported as a
pass. Rows whose section is switched off are omitted rather than guessed at. It
is operational evidence of SOC activity, not an audit opinion, attestation, or
certification status.

| Criterion | Control | Evidence |
| --- | --- | --- |
| CC7.1 | Threat and anomaly detection | TSC-mapped alerts (`rule.tsc` from `wazuh-alerts-*`), controls and agents they cover |
| CC7.1 | Vulnerability identification and remediation | open and remediated counts, remediation SLA attainment |
| CC7.2 | Continuous security monitoring | agents reporting within 24h, from the Wazuh Manager heartbeat |
| CC7.3 | Security event evaluation and ticketing | incidents raised and triaged, MTTD and MTTT |
| CC7.4 | Incident response within SLA | severity SLA attainment for incidents resolved this week |
| CC7.5 | Incident resolution and recovery | closure rate, backlog at the cut-off, MTTC |
| A1.2 | Monitored system availability | uptime against target and outages (needs the availability section) |

Detection stays *Met* when it surfaces critical alerts — finding them is the
control working; the response to them is judged by CC7.3 and CC7.4.

Configure `OPENSEARCH_ALERT_INDEX` when a tenant uses a different Wazuh alert
index. Set `REPORT_ENABLE_SOC2_COMPLIANCE=false` to omit the section, and
optionally set `REPORT_SOC2_COMPLIANCE_URL` to link to the detailed evidence
dashboard. The *Met* thresholds default to 95% for SLA attainment
(`REPORT_SOC2_SLA_TARGET_PCT`, matching the report's own green SLA band), 95%
for monitoring coverage (`REPORT_SOC2_COVERAGE_TARGET_PCT`), and a 90% closure
rate (`REPORT_SOC2_CLOSURE_TARGET_PCT`).

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

That's it — this pulls the latest synced data from OpenSearch and emails the report out.

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
                    -> dispatcher Lambda -> tenant VPC Lambda
                    -> OpenSearch + Microsoft Graph
```

The private API is restricted to its `execute-api` interface VPC endpoint. The
endpoint is managed by the standalone `athena-incident-report-private-api-access`
stack in the shared Client VPN account, so deleting an application/test stack
does not remove production report access. There
is no public API endpoint, load balancer, scheduler, or recurring health-check
Lambda invocation. Production uses separate Athena and NBS workers in their
existing tenant subnets so each worker can reach its tenant's private indexer
without changing the existing indexer endpoint security groups.

The executive summary reports four separate incident lifecycle intervals:

- `MTTD`: event occurrence to Athena Core alert generation.
- `MTTT`: Athena Core alert generation to Jira ticket creation.
- `MTTR`: Jira ticket creation to the analyst's first response or action.
- `MTTC`: endpoint event occurrence to Resolved/Closed.

The report reads `mttd_minutes`, `mttt_minutes`, `mttr_minutes`, and
`mttc_minutes` from `pallas-incidents`. Timestamp fallbacks use the mirrored
event, alert, ticket creation, first-response, and resolution timestamps.

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
secret and must be passed on every API call. `REPORT_EMAIL_FROM` is managed by
the report Lambda environment and is also ignored from tenant secrets. If the secret contains
`REPORT_TRIGGER_TOKEN`, callers must pass it as `X-Report-Token` or
`Authorization: Bearer ...`; if it is absent, the endpoint relies only on the
VPN/private API network boundary.

Set `REPORT_LOG_LEVEL=DEBUG` in a tenant secret only when you need detailed
OpenSearch request and compatibility-query traces in CloudWatch. The default
`INFO` level keeps only high-level report progress logs.

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
- `infra/private-api-access.yaml` - standalone Client VPN execute-api endpoint and security group.
- `infra/deploy-private-api-lambda.sh` - guarded zip/layer packaging and ALB migration.
- `infra/deploy-prod-private-api-lambda.sh` - guarded production deployment using `athena-prod`.
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

Production deployment uses account `556976944260`, profile `athena-prod`, and
region `us-east-2`. It requires typing `DEPLOY` before creating or updating AWS
resources:

```bash
AWS_PROFILE=athena-prod AWS_REGION=us-east-2 infra/deploy-prod-private-api-lambda.sh
```
