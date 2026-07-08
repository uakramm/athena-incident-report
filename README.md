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
