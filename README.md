# Weekly Security Operations Report

Generates a client-facing **Weekly Security Operations Report** (HTML → print to PDF) on demand.
It pulls incident and vulnerability data from a client's **SECOPS Jira project** (built by
[`security-operations-jira-project-setup`](../security-operations-jira-project-setup)) and lays it out
in the Athena report style, combining:

- **Incident management** — Security Alert + Security Incident work items: opened / closed / still-open,
  severity (Sev-1…Sev-4), a 6-week trend, **MTTD / MTTR**, a **by-type breakdown**, **response-SLA
  attainment** by severity, and the open + closed queues.
- **Analyst commentary** — a short written read on the week (the SOC team's value narrative), shown under
  the executive summary. **Auto-generated** from the week's metrics by default; set `REPORT_COMMENTARY_AUTO=false`
  to omit, or override the wording via the `commentary` key in `--supplemental` (or `REPORT_COMMENTARY`).
- **Vulnerability status** — Vulnerability work items: open by severity, resolved vs newly-detected, top CVEs.
- **Device / endpoint / availability** — not in Jira; supplied via `--supplemental` (Intune / Defender / monitoring).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Jira site + token, plus per-client config
```

`.env` holds credentials **and** per-client config (`JIRA_PROJECT_KEY`, `REPORT_CLIENT`,
`REPORT_ENVIRONMENT`, `REPORT_TENANT`, `REPORT_SUPPORT_EMAIL`, `REPORT_WEEK_START`,
`REPORT_INCIDENT_SEVERITIES`). Keep one file per client (`.env.neuro`, `.env.athena`, …) so a run is just:

```bash
python generate_report.py --env-file .env.neuro --out reports/neuro-2026-07-05.html
```

Any CLI flag overrides its `.env` value.

## Quick preview (no Jira needed)

```bash
python generate_report.py --sample --open
```

## Generate a client report

With a per-client `.env` (recommended):

```bash
python generate_report.py --env-file .env.neuro --open
```

Or with flags:

```bash
python generate_report.py \
  --project-key NSO \
  --client "Neuro" --environment Production --tenant neuro.athenasecuritygrp.com \
  --week-start monday \
  --supplemental supplemental.json
```

## Output

The report is a **local HTML file** saved inside this repo (default `reports/<client>-<week-end>.html`,
or wherever `REPORT_OUTPUT_DIR` / `--out` points). Nothing is uploaded anywhere.

**For a PDF:** open the HTML and **Print → Save as PDF** (Cmd/Ctrl+P). The stylesheet already handles
page breaks and margins for a clean print.

### Common options

| Flag | Purpose |
| --- | --- |
| `--project-key` | Jira project key for the client (e.g. `NSO`). |
| `--week-start monday\|sunday` | Day the reporting week starts on. |
| `--week-of YYYY-MM-DD` | Any date inside the target week. Default: **last complete week**. |
| `--supplemental FILE.json` | Device / endpoint / availability data — see `supplemental.example.json`. |
| `--env-file .env.neuro` | Use a per-client credentials file. |
| `--out-dir DIR` / `--out PATH` | Where to save (defaults to `reports/`, auto-named). |
| `--open` | Open the report when done. |

### Jira field mapping (override if your names differ)

`--severity-field "Severity"` (Sev-1…4 → Critical/High/Medium/Low) · `--mttr-field "MTTR (Minutes)"` ·
`--mttd-field "MTTD (Minutes)"` · `--incident-time-field "Incident Time"` ·
`--incident-type-field "Type of Incident"` (drives the by-type breakdown) · `--vuln-id-field "Vulnerability ID(s)"` ·
`--source-field components` (`components`, `labels`, or a custom field name).

### Response SLA targets

The **Response SLA attainment** card shows the share of incidents resolved within a per-severity target
time. Targets are set in minutes (defaults: Critical 240, High 480, Medium 1440, Low 4320):

| Env var | Default (minutes) |
| --- | --- |
| `REPORT_SLA_CRITICAL_MINUTES` | `240` |
| `REPORT_SLA_HIGH_MINUTES` | `480` |
| `REPORT_SLA_MEDIUM_MINUTES` | `1440` |
| `REPORT_SLA_LOW_MINUTES` | `4320` |

**MTTD / MTTR** are read from the `MTTD (Minutes)` / `MTTR (Minutes)` number fields (unit `minutes`, the
default). If a value is empty the script falls back to timestamps (`resolved − created` for MTTR,
`created − Incident Time` for MTTD).

### Severity mapping (Sev-1…Sev-4)

The `Severity` field means different things per work type, so the two are mapped separately (override the
`JIRA_SEVERITY_*` / `JIRA_VULN_SEVERITY_*` env vars per tenant — defaults match Athena/SECOPS + Palace):

| Sev value | Incidents / alerts | Vulnerabilities |
| --- | --- | --- |
| Sev-1 | Critical (confirmed compromise) | Critical |
| Sev-2 | **Critical** | High |
| Sev-3 | High | Medium |
| Sev-4 | Medium (also Low) | Low |

Because incident Medium and Low both use Sev-4, incidents show **Critical / High / Medium** (no separate
Low); vulnerabilities show all four. The report logs the resolved mapping on each run.

Set `REPORT_INCIDENT_SEVERITIES=CRITICAL,HIGH` to control which incident severities are included in
incident totals, trends, MTTD / MTTR, and open / closed incident rows. The default is `CRITICAL,HIGH`.

### Section enablement

Use these env vars to include or omit non-core report sections:

| Env var | Default |
| --- | --- |
| `REPORT_ENABLE_DEVICE_MANAGEMENT` | `true` |
| `REPORT_ENABLE_ENDPOINT_MANAGEMENT` | `true` |
| `REPORT_ENABLE_VULNERABILITY_STATUS` | `true` |
| `REPORT_ENABLE_SYSTEM_AVAILABILITY` | `true` |

## Files

- `generate_report.py` — CLI + Jira fetch + orchestration.
- `render.py` — pure HTML/SVG rendering from a data dict (also powers `--sample`).
- `report_style.css` — the report stylesheet (light + dark, print-ready).
- `supplemental.example.json` — shape of the non-Jira data.
