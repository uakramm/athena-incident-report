"""AWS Lambda entry point for manual report generation behind an internal ALB."""
from __future__ import annotations

import base64
import contextlib
import hmac
import io
import json
import os
import re
import sys
import tempfile
import time
import traceback
from urllib.parse import parse_qs
from typing import Any, Dict, List, Mapping, Optional

import generate_report

REQUEST_ONLY_ENV_KEYS = ("REPORT_EMAIL_TO", "REPORT_EMAIL_CC")
TENANT_SECRET_TEMPLATE = "athena-incident-report/{tenant}/config"
TENANT_KEY_RE = re.compile(r"^[a-z0-9_.-]+$")
LOADED_SECRET_ENV_KEYS: set[str] = set()


class TenantConfigNotFound(Exception):
    """Raised when a requested tenant does not have a config secret."""


class _Tee(io.TextIOBase):
    def __init__(self, buffer: io.StringIO, target: Any):
        self.buffer = buffer
        self.target = target

    def write(self, text: str) -> int:
        self.buffer.write(text)
        self.target.write(text)
        self.target.flush()
        return len(text)

    def flush(self) -> None:
        self.buffer.flush()
        self.target.flush()


def _log(level: str, message: str, **fields: Any) -> None:
    payload = {"level": level, "message": message, **fields}
    print(json.dumps(payload, separators=(",", ":"), default=str), flush=True)


def _header_names(headers: Optional[Mapping[str, str]]) -> List[str]:
    return sorted(str(key).lower() for key in (headers or {}).keys())


def _csv_items(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value).split(",")
    return [str(item).strip() for item in items if str(item).strip()]


def _email_domains(value: Any) -> List[str]:
    domains = []
    for item in _csv_items(value):
        if "@" in item:
            domains.append(item.rsplit("@", 1)[1].lower())
    return sorted(set(domains))


def _body_len(event: Mapping[str, Any]) -> int:
    body = event.get("body")
    if body is None:
        return 0
    return len(body if isinstance(body, (bytes, bytearray)) else str(body))


def _request_source(event: Mapping[str, Any]) -> Dict[str, Any]:
    headers = event.get("headers") or {}
    return {
        "x_forwarded_for": _header(headers, "x-forwarded-for"),
        "x_forwarded_proto": _header(headers, "x-forwarded-proto"),
        "x_forwarded_port": _header(headers, "x-forwarded-port"),
        "user_agent": _header(headers, "user-agent"),
    }


def _arg_summary(query: Mapping[str, Any], body: Mapping[str, Any]) -> Dict[str, Any]:
    email_to = _coalesce(query, body, "email_to")
    email_cc = _coalesce(query, body, "email_cc")
    return {
        "tenant": _csv(_coalesce(query, body, "tenant")),
        "query_keys": sorted(query.keys()),
        "body_keys": sorted(body.keys()),
        "email_to_count": len(_csv_items(email_to)),
        "email_to_domains": _email_domains(email_to),
        "email_cc_count": len(_csv_items(email_cc)),
        "email_cc_domains": _email_domains(email_cc),
        "dry_run": _coalesce(query, body, "dry_run"),
        "send_email": _coalesce(query, body, "send_email"),
        "write_email_preview": _coalesce(query, body, "write_email_preview"),
        "week_of": _coalesce(query, body, "week_of"),
        "project_key": _coalesce(query, body, "project_key"),
        "client": _coalesce(query, body, "client"),
        "report_tenant": _coalesce(query, body, "report_tenant") or _coalesce(query, body, "tenant_domain"),
    }


def _argv_flags(argv: List[str]) -> List[str]:
    return [item for item in argv if item.startswith("--")]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().strip('"').lower() in {"1", "true", "yes", "y", "on"}


def _clear_request_only_env() -> None:
    for key in REQUEST_ONLY_ENV_KEYS:
        os.environ.pop(key, None)


def _clear_loaded_secret_env() -> None:
    for key in LOADED_SECRET_ENV_KEYS:
        os.environ.pop(key, None)
    LOADED_SECRET_ENV_KEYS.clear()


def _header(headers: Optional[Mapping[str, str]], name: str) -> str:
    if not headers:
        return ""
    want = name.lower()
    for key, value in headers.items():
        if key.lower() == want:
            return value or ""
    return ""


def _json_response(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    reason = {
        200: "OK",
        202: "Accepted",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }.get(status, "OK")
    return {
        "isBase64Encoded": False,
        "statusCode": status,
        "statusDescription": f"{status} {reason}",
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(payload, separators=(",", ":"), default=str),
    }


def _collapse_values(values: Mapping[str, Any]) -> Dict[str, Any]:
    collapsed: Dict[str, Any] = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            present = [item for item in value if item is not None]
            collapsed[str(key)] = present if len(present) != 1 else present[0]
        else:
            collapsed[str(key)] = value
    return collapsed


def _query_params(event: Mapping[str, Any]) -> Dict[str, Any]:
    query = _collapse_values(event.get("queryStringParameters") or {})
    multi = _collapse_values(event.get("multiValueQueryStringParameters") or {})
    query.update(multi)
    return query


def _parse_form_body(body: str) -> Dict[str, Any]:
    parsed = parse_qs(body, keep_blank_values=True)
    return _collapse_values(parsed)


def _parse_dotenv(raw: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            data[key] = value
    return data


def _decode_body(event: Mapping[str, Any]) -> Dict[str, Any]:
    body = event.get("body")
    if not body:
        return {}
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    content_type = _header(event.get("headers") or {}, "content-type").lower()
    text = str(body)
    if "application/x-www-form-urlencoded" in content_type:
        return _parse_form_body(text)
    if "application/json" not in content_type and not text.lstrip().startswith("{"):
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Request body is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Request JSON body must be an object.")
    return parsed


def _coalesce(query: Mapping[str, Any], body: Mapping[str, Any], key: str, default: Any = None) -> Any:
    value = body.get(key)
    if value is None:
        value = query.get(key)
    return default if value is None else value


def _provided(query: Mapping[str, Any], body: Mapping[str, Any], key: str) -> bool:
    return key in body or key in query


def _csv(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _tenant_key(query: Mapping[str, Any], body: Mapping[str, Any]) -> str:
    tenant = _csv(_coalesce(query, body, "tenant")).lower()
    if not tenant:
        raise ValueError(
            "Missing required API field: tenant. Pass tenant as a query string arg, "
            "form field, or JSON body field."
        )
    if not TENANT_KEY_RE.fullmatch(tenant):
        raise ValueError(
            "tenant must contain only letters, numbers, dots, underscores, or hyphens; "
            "slashes are not allowed."
        )
    return tenant


def _tenant_secret_id(tenant: str) -> str:
    return TENANT_SECRET_TEMPLATE.format(tenant=tenant)


def _load_secret_env(secret_id: str) -> List[str]:
    """Load tenant .env-style keys from a Secrets Manager secret.

    The secret value may be a JSON object or dotenv text. Keys should match the
    variables already used by generate_report.py, for example JIRA_CLIENT_ID or
    ENTRA_CLIENT_SECRET.
    """
    _clear_loaded_secret_env()

    import boto3  # Imported only in Lambda so local CLI use does not need boto3.

    client = boto3.client("secretsmanager")
    try:
        value = client.get_secret_value(SecretId=secret_id)
    except client.exceptions.ResourceNotFoundException as exc:
        raise TenantConfigNotFound(f"Tenant config secret not found: {secret_id}") from exc
    raw = value.get("SecretString")
    if raw is None and value.get("SecretBinary"):
        raw = base64.b64decode(value["SecretBinary"]).decode("utf-8")
    if not raw:
        _clear_request_only_env()
        return []
    stripped = raw.lstrip()
    data = json.loads(raw) if stripped.startswith("{") else _parse_dotenv(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Tenant config secret must be a JSON object or dotenv text: {secret_id}")
    for key, val in data.items():
        if val is not None:
            env_key = str(key)
            os.environ[env_key] = str(val)
            LOADED_SECRET_ENV_KEYS.add(env_key)
    _clear_request_only_env()
    return sorted(LOADED_SECRET_ENV_KEYS)


def _authorize(event: Mapping[str, Any]) -> bool:
    expected = os.getenv("REPORT_TRIGGER_TOKEN", "")
    if not expected:
        return True
    headers = event.get("headers") or {}
    supplied = _header(headers, "x-report-token")
    auth = _header(headers, "authorization")
    if not supplied and auth.lower().startswith("bearer "):
        supplied = auth[7:].strip()
    return hmac.compare_digest(supplied, expected)


def _argv(query: Mapping[str, Any], body: Mapping[str, Any], tenant_key: str) -> List[str]:
    missing = [key for key in ("email_to", "email_cc") if not _provided(query, body, key)]
    if missing:
        raise ValueError(
            "Missing required API field(s): " + ", ".join(missing) +
            ". Pass tenant, email_to, and email_cc as query string args, form fields, or JSON body fields."
        )

    email_to = _csv(_coalesce(query, body, "email_to"))
    email_cc = _csv(_coalesce(query, body, "email_cc"))
    if not email_to:
        raise ValueError("email_to must include at least one recipient.")

    argv: List[str] = ["--out-dir", tempfile.gettempdir()]

    flag_map = {
        "project_key": "--project-key",
        "client": "--client",
        "environment": "--environment",
        "support_email": "--support-email",
        "week_start": "--week-start",
        "week_of": "--week-of",
        "email_bcc": "--email-bcc",
        "email_subject": "--email-subject",
        "email_body": "--email-body",
    }
    report_tenant = (
        _csv(_coalesce(query, body, "report_tenant"))
        or _csv(_coalesce(query, body, "tenant_domain"))
        or os.getenv("REPORT_TENANT", "").strip()
        or tenant_key
    )
    argv.extend(["--tenant", report_tenant, "--email-to", email_to, "--email-cc", email_cc])
    for key, flag in flag_map.items():
        value = _coalesce(query, body, key)
        if value not in (None, ""):
            argv.extend([flag, _csv(value)])

    supplemental = _coalesce(query, body, "supplemental")
    if isinstance(supplemental, dict):
        supplemental_path = os.path.join(tempfile.gettempdir(), "report-supplemental.json")
        with open(supplemental_path, "w", encoding="utf-8") as handle:
            json.dump(supplemental, handle)
        argv.extend(["--supplemental", supplemental_path])

    dry_run = _as_bool(_coalesce(query, body, "dry_run"), False)
    send_email = _as_bool(
        _coalesce(query, body, "send_email"),
        _env_bool("REPORT_LAMBDA_SEND_EMAIL", True),
    )
    if dry_run:
        argv.append("--email-dry-run")
    elif send_email:
        argv.append("--send-email")

    if _as_bool(_coalesce(query, body, "write_email_preview"), False):
        argv.append("--email")

    return argv


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    started = time.perf_counter()
    request_id = getattr(context, "aws_request_id", None)
    method = (event.get("httpMethod") or "GET").upper()
    path = event.get("path") or "/"
    headers = event.get("headers") or {}

    _log(
        "INFO",
        "lambda_invoked",
        request_id=request_id,
        method=method,
        path=path,
        header_names=_header_names(headers),
        source=_request_source(event),
        body_length=_body_len(event),
        is_base64_encoded=bool(event.get("isBase64Encoded")),
    )

    if path in {"/", "/health"}:
        _log("INFO", "health_response", request_id=request_id, status=200)
        return _json_response(200, {"ok": True, "service": "athena-incident-report"})
    if path != "/run":
        _log("WARN", "invalid_path", request_id=request_id, path=path)
        return _json_response(404, {"ok": False, "error": "Use POST /run."})

    allow_get = _env_bool("REPORT_ALLOW_GET", False)
    if method != "POST" and not (allow_get and method == "GET"):
        _log("WARN", "invalid_method", request_id=request_id, method=method, allow_get=allow_get)
        return _json_response(405, {"ok": False, "error": "Use POST /run."})

    try:
        _log("INFO", "request_decode_start", request_id=request_id)
        query = _query_params(event)
        body = _decode_body(event)
        tenant_key = _tenant_key(query, body)
        _log(
            "INFO",
            "request_decode_done",
            request_id=request_id,
            tenant=tenant_key,
            content_type=_header(headers, "content-type"),
            args=_arg_summary(query, body),
        )
    except Exception as exc:
        _log("ERROR", "request_decode_failed", request_id=request_id, error=str(exc))
        return _json_response(400, {"ok": False, "error": str(exc)})

    secret_id = _tenant_secret_id(tenant_key)
    try:
        _log("INFO", "tenant_secret_load_start", request_id=request_id, tenant=tenant_key, secret_id=secret_id)
        loaded_keys = _load_secret_env(secret_id)
        _log(
            "INFO",
            "tenant_secret_load_done",
            request_id=request_id,
            tenant=tenant_key,
            secret_id=secret_id,
            loaded_key_count=len(loaded_keys),
            loaded_keys=loaded_keys,
            trigger_token_configured=bool(os.getenv("REPORT_TRIGGER_TOKEN")),
        )
    except TenantConfigNotFound as exc:
        _log("ERROR", "tenant_secret_not_found", request_id=request_id, tenant=tenant_key, secret_id=secret_id, error=str(exc))
        return _json_response(400, {"ok": False, "error": str(exc)})
    except Exception as exc:
        _log("ERROR", "tenant_secret_load_failed", request_id=request_id, tenant=tenant_key, secret_id=secret_id, error=str(exc))
        return _json_response(500, {"ok": False, "error": str(exc)})

    _log("INFO", "authorization_start", request_id=request_id, token_required=bool(os.getenv("REPORT_TRIGGER_TOKEN")))
    if not _authorize(event):
        _log("WARN", "authorization_failed", request_id=request_id, tenant=tenant_key)
        return _json_response(401, {"ok": False, "error": "Unauthorized."})
    _log("INFO", "authorization_passed", request_id=request_id, tenant=tenant_key)

    try:
        _log("INFO", "argv_build_start", request_id=request_id, tenant=tenant_key)
        argv = _argv(query, body, tenant_key)
        _log(
            "INFO",
            "argv_build_done",
            request_id=request_id,
            tenant=tenant_key,
            argv_flags=_argv_flags(argv),
            args=_arg_summary(query, body),
        )
    except Exception as exc:
        _log("ERROR", "argv_build_failed", request_id=request_id, tenant=tenant_key, error=str(exc))
        return _json_response(400, {"ok": False, "error": str(exc)})

    log_buffer = io.StringIO()
    report_started = time.perf_counter()
    try:
        _log("INFO", "report_main_start", request_id=request_id, tenant=tenant_key)
        with contextlib.redirect_stderr(_Tee(log_buffer, sys.stderr)):
            code = generate_report.main(argv)
    except Exception as exc:
        logs = log_buffer.getvalue().strip()
        _log(
            "ERROR",
            "report_main_exception",
            request_id=request_id,
            tenant=tenant_key,
            error=str(exc),
            traceback=traceback.format_exc().splitlines(),
            elapsed_seconds=round(time.perf_counter() - report_started, 3),
            total_elapsed_seconds=round(time.perf_counter() - started, 3),
        )
        return _json_response(
            500,
            {
                "ok": False,
                "exit_code": 1,
                "request_id": request_id,
                "error": str(exc),
                "logs": logs.splitlines()[-60:],
            },
        )

    logs = log_buffer.getvalue().strip()
    log_lines = logs.splitlines()
    _log(
        "INFO" if code == 0 else "ERROR",
        "report_main_done",
        request_id=request_id,
        tenant=tenant_key,
        exit_code=code,
        report_elapsed_seconds=round(time.perf_counter() - report_started, 3),
        total_elapsed_seconds=round(time.perf_counter() - started, 3),
        captured_log_lines=len(log_lines),
    )
    payload = {
        "ok": code == 0,
        "exit_code": code,
        "request_id": request_id,
        "logs": log_lines[-60:],
    }
    _log("INFO", "lambda_response", request_id=request_id, tenant=tenant_key, status=200 if code == 0 else 500)
    return _json_response(200 if code == 0 else 500, payload)
