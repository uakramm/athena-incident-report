#!/usr/bin/env bash
set -euo pipefail

PROFILE="${AWS_PROFILE:-athena}"
REGION="${AWS_REGION:-us-east-2}"
TENANT="${TENANT:-${TENANT_KEY:-}}"
ENV_FILE="${ENV_FILE:-}"
ALLOW_SECRET_UPDATE="${ALLOW_SECRET_UPDATE:-false}"

if [[ "$TENANT" == "" ]]; then
  echo "Set TENANT, for example TENANT=nbs."
  exit 1
fi

TENANT="$(printf '%s' "$TENANT" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$TENANT" =~ ^[a-z0-9_.-]+$ ]]; then
  echo "TENANT must contain only letters, numbers, dots, underscores, or hyphens."
  exit 1
fi

if [[ "$ENV_FILE" == "" || ! -f "$ENV_FILE" ]]; then
  echo "Set ENV_FILE to an existing dotenv file, for example ENV_FILE=.env.nbs."
  exit 1
fi

SECRET_NAME="athena-incident-report/$TENANT/config"
ACCOUNT_ID="$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --query Account --output text)"

SECRET_EXISTS=false
if aws secretsmanager describe-secret \
  --profile "$PROFILE" \
  --region "$REGION" \
  --secret-id "$SECRET_NAME" >/dev/null 2>&1; then
  SECRET_EXISTS=true
fi

if [[ "$SECRET_EXISTS" == "true" && "$ALLOW_SECRET_UPDATE" != "true" ]]; then
  echo "Refusing to continue: Secrets Manager secret already exists: $SECRET_NAME. Set ALLOW_SECRET_UPDATE=true to update it."
  exit 1
fi

cat <<EOF
This will create or update a tenant config secret in account $ACCOUNT_ID, region $REGION, profile $PROFILE.

Tenant:       $TENANT
Env file:     $ENV_FILE
Secret name:  $SECRET_NAME
Exists:       $SECRET_EXISTS
Allow update: $ALLOW_SECRET_UPDATE

REPORT_EMAIL_TO and REPORT_EMAIL_CC are removed from the stored secret because
they must be supplied with each API request. An existing REPORT_TRIGGER_TOKEN is
preserved unless the env file includes a replacement.
EOF

read -r -p "Type APPLY to continue: " CONFIRM
if [[ "$CONFIRM" != "APPLY" ]]; then
  echo "Aborted."
  exit 1
fi

SECRET_FILE="$(mktemp)"
EXISTING_SECRET_FILE="$(mktemp)"
trap 'rm -f "$SECRET_FILE" "$EXISTING_SECRET_FILE"' EXIT

if [[ "$SECRET_EXISTS" == "true" ]]; then
  aws secretsmanager get-secret-value \
    --profile "$PROFILE" \
    --region "$REGION" \
    --secret-id "$SECRET_NAME" \
    --query SecretString \
    --output text > "$EXISTING_SECRET_FILE"
fi

python3 - "$ENV_FILE" "$SECRET_FILE" "$EXISTING_SECRET_FILE" <<'PY'
import json
import secrets
import sys

env_path, out_path, existing_path = sys.argv[1], sys.argv[2], sys.argv[3]

def parse_dotenv(text):
    data = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            data[key] = value
    return data

def parse_secret(text):
    text = (text or "").strip()
    if not text or text == "None":
        return {}
    return json.loads(text) if text.startswith("{") else parse_dotenv(text)

with open(env_path, "r", encoding="utf-8") as handle:
    data = parse_dotenv(handle.read())
try:
    with open(existing_path, "r", encoding="utf-8") as handle:
        existing = parse_secret(handle.read())
except FileNotFoundError:
    existing = {}

if "REPORT_TRIGGER_TOKEN" in existing and "REPORT_TRIGGER_TOKEN" not in data:
    data["REPORT_TRIGGER_TOKEN"] = existing["REPORT_TRIGGER_TOKEN"]
data.setdefault("REPORT_TRIGGER_TOKEN", secrets.token_urlsafe(32))
for request_only in ("REPORT_EMAIL_TO", "REPORT_EMAIL_CC"):
    data.pop(request_only, None)

with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, separators=(",", ":"))
PY

if [[ "$SECRET_EXISTS" == "true" ]]; then
  aws secretsmanager put-secret-value \
    --profile "$PROFILE" \
    --region "$REGION" \
    --secret-id "$SECRET_NAME" \
    --secret-string "file://$SECRET_FILE" >/dev/null
  echo "Updated tenant config secret: $SECRET_NAME"
else
  SECRET_ARN="$(aws secretsmanager create-secret \
    --profile "$PROFILE" \
    --region "$REGION" \
    --name "$SECRET_NAME" \
    --description "Athena incident report Lambda configuration for $TENANT" \
    --secret-string "file://$SECRET_FILE" \
    --query ARN \
    --output text)"
  echo "Created tenant config secret: $SECRET_ARN"
fi
