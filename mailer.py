"""Send the weekly report by email through Microsoft Graph.

Opt-in only: nothing here runs unless the caller explicitly asks for it
(``--send-email`` / ``--email-dry-run`` in generate_report.py). Authentication
uses an Entra app registration with Microsoft Graph Mail.Send application
permission and admin consent.
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import urllib.parse
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Tuple

import requests

import render
import render_email

DEFAULT_SUBJECT = "Weekly Security Operations Report — {client} — {period}"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class MailerError(RuntimeError):
    pass


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def split_addrs(raw: Optional[str]) -> List[str]:
    return [a.strip() for a in re.split(r"[,;]", raw or "") if a.strip()]


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip().strip('"')


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().strip('"').lower() in {"1", "true", "yes", "y", "on"}


def _mailbox(raw: str) -> str:
    return parseaddr(raw)[1] or raw


def resolve_email_config(args: argparse.Namespace, data: Dict[str, Any]) -> Dict[str, Any]:
    """CLI flags override .env; .env provides the per-client defaults."""
    to = split_addrs(getattr(args, "email_to", None)) or split_addrs(os.getenv("REPORT_EMAIL_TO"))
    cc = split_addrs(getattr(args, "email_cc", None)) or split_addrs(os.getenv("REPORT_EMAIL_CC"))
    bcc = split_addrs(getattr(args, "email_bcc", None)) or split_addrs(os.getenv("REPORT_EMAIL_BCC"))
    subject_tmpl = getattr(args, "email_subject", None) or os.getenv("REPORT_EMAIL_SUBJECT") or DEFAULT_SUBJECT
    subject = subject_tmpl.format_map(_SafeDict(
        client=data.get("client", ""), period=data.get("period_label", ""),
        environment=data.get("environment", ""), tenant=data.get("tenant", ""),
    ))
    return {
        "tenant_id": _env("ENTRA_TENANT_ID"),
        "client_id": _env("ENTRA_CLIENT_ID"),
        "client_secret": os.getenv("ENTRA_CLIENT_SECRET") or "",
        "authority_host": _env("ENTRA_AUTHORITY_HOST", "https://login.microsoftonline.com").rstrip("/"),
        "graph_base_url": _env("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0").rstrip("/"),
        "from_addr": _mailbox(_env("REPORT_EMAIL_FROM", "shelly@athenasecuritygrp.com") or data.get("support_email", "")),
        "save_to_sent_items": _env_bool("REPORT_EMAIL_SAVE_TO_SENT_ITEMS", True),
        # Body: "email" = table-based, renders reliably in Outlook/Gmail (default);
        # "full" = the SVG report inline (charts/colours break in Outlook & Gmail).
        "body_mode": (getattr(args, "email_body", None) or _env("REPORT_EMAIL_BODY", "email")).lower(),
        # Attach the full SVG report as an .html file (opens pretty in a browser).
        "attach_report": _env_bool("REPORT_EMAIL_ATTACH_REPORT", False),
        "to": to, "cc": cc, "bcc": bcc, "subject": subject,
    }


def _body(data: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, str]:
    content = render.render_report(data) if cfg.get("body_mode") == "full" else render_email.render_email(data)
    return {"contentType": "HTML", "content": content}


def _attachments(cfg: Dict[str, Any], attachment: Optional[Tuple[str, str]],
                 charts: Optional[Dict[str, bytes]] = None) -> List[Dict[str, Any]]:
    atts: List[Dict[str, Any]] = []
    # Inline chart images, referenced from the body as <img src="cid:{name}">.
    for name, png in (charts or {}).items():
        atts.append({
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": f"{name}.png",
            "contentType": "image/png",
            "contentId": name,
            "isInline": True,
            "contentBytes": base64.b64encode(png).decode("ascii"),
        })
    if attachment and cfg.get("attach_report"):
        name, content = attachment
        atts.append({
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": name,
            "contentType": "text/html",
            "contentBytes": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        })
    return atts


def _recipient(address: str) -> Dict[str, Dict[str, str]]:
    return {"emailAddress": {"address": address}}


def _access_token(cfg: Dict[str, Any], *, timeout: int) -> str:
    url = f"{cfg['authority_host']}/{cfg['tenant_id']}/oauth2/v2.0/token"
    resp = requests.post(url, data={
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "grant_type": "client_credentials",
        "scope": GRAPH_SCOPE,
    }, timeout=timeout)
    if resp.status_code != 200:
        raise MailerError(f"Graph token request failed: HTTP {resp.status_code} {resp.text[:500]}")
    token = resp.json().get("access_token")
    if not token:
        raise MailerError("Graph token response did not include access_token.")
    return token


def send(data: Dict[str, Any], cfg: Dict[str, Any], *, attachment: Optional[Tuple[str, str]] = None,
         charts: Optional[Dict[str, bytes]] = None, timeout: int = 30) -> None:
    missing = [k for k in ("tenant_id", "client_id", "client_secret", "from_addr") if not cfg.get(k)]
    if missing:
        raise MailerError(
            "Missing Entra email config: " + ", ".join(missing) +
            ". Set ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET / REPORT_EMAIL_FROM in .env."
        )
    if not cfg["to"]:
        raise MailerError("No recipients. Set REPORT_EMAIL_TO in .env or pass --email-to.")

    # Point the email-safe body at the inline (cid:) chart images we're attaching.
    if charts and cfg.get("body_mode") != "full":
        data = {**data, "_chart_src": {name: f"cid:{name}" for name in charts}}

    token = _access_token(cfg, timeout=timeout)
    message = {
        "subject": cfg["subject"],
        "body": _body(data, cfg),
        "toRecipients": [_recipient(addr) for addr in cfg["to"]],
        "ccRecipients": [_recipient(addr) for addr in cfg["cc"]],
        "bccRecipients": [_recipient(addr) for addr in cfg["bcc"]],
    }
    atts = _attachments(cfg, attachment, charts if cfg.get("body_mode") != "full" else None)
    if atts:
        message["attachments"] = atts
    resp = requests.post(
        f"{cfg['graph_base_url']}/users/{urllib.parse.quote(cfg['from_addr'], safe='')}/sendMail",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"message": message, "saveToSentItems": cfg["save_to_sent_items"]},
        timeout=timeout,
    )
    if resp.status_code != 202:
        raise MailerError(
            f"Graph sendMail failed for {cfg['from_addr']}: HTTP {resp.status_code} {resp.text[:800]}"
        )


def send_report_email(data: Dict[str, Any], args: argparse.Namespace, log=print,
                      attachment: Optional[Tuple[str, str]] = None,
                      charts: Optional[Dict[str, bytes]] = None) -> None:
    """Entry point used by generate_report.py for --send-email / --email-dry-run.

    ``attachment`` is (filename, html) of the full SVG report, attached as an .html
    file when REPORT_EMAIL_ATTACH_REPORT is on.
    """
    cfg = resolve_email_config(args, data)
    recipients_desc = ", ".join(cfg["to"]) + (f" (cc: {', '.join(cfg['cc'])})" if cfg["cc"] else "")
    log(f"Email subject: {cfg['subject']}")
    log(f"Email from: {cfg['from_addr'] or '(none configured)'}")
    log(f"Email to: {recipients_desc or '(none configured)'}")
    log("Email body: " + ("full SVG report inline (note: charts/colours will not render in Outlook or Gmail)"
                          if cfg.get("body_mode") == "full" else "email-safe HTML (renders in all clients)"))
    if charts and cfg.get("body_mode") != "full":
        log(f"Inline charts: {len(charts)} PNG image(s) embedded in the body ({', '.join(sorted(charts))}).")
    if attachment and cfg.get("attach_report"):
        log(f"Attaching full report: {attachment[0]}")

    if getattr(args, "email_dry_run", False):
        log("Dry run — not sending or connecting to Graph." if cfg["to"] else "Dry run — no recipients configured.")
        return

    send(data, cfg, attachment=attachment, charts=charts)
    log(f"Sent to {len(cfg['to']) + len(cfg['cc']) + len(cfg['bcc'])} recipient(s).")
