#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  REPORT_EMAIL_TO='to@example.com' \
  REPORT_EMAIL_CC='cc@example.com' \
  REPORT_TRIGGER_TOKEN='token' \
  ./run-report.sh <tenant> [--dry-run]

Examples:
  REPORT_EMAIL_TO='to@example.com' REPORT_EMAIL_CC='' REPORT_TRIGGER_TOKEN='token' ./run-report.sh athena
  REPORT_EMAIL_TO='to@example.com' REPORT_EMAIL_CC='soc@example.com' REPORT_TRIGGER_TOKEN='token' ./run-report.sh nbs --dry-run
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPORT_API_URL="https://vpce-002df2e6240cd5e10-h8m419sk.execute-api.us-east-2.vpce.amazonaws.com/manual"
DEFAULT_REPORT_API_ID="wpd8b8mmu1"
TENANT="${1:-}"
MODE="${2:-}"

if (( $# > 2 )); then
  echo "Too many arguments."
  usage
  exit 1
fi

if [[ -z "$TENANT" || "$TENANT" == "-h" || "$TENANT" == "--help" ]]; then
  usage
  [[ -n "$TENANT" ]] && exit 0
  exit 1
fi
if [[ ! "$TENANT" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
  echo "tenant must contain only letters, numbers, dots, underscores, or hyphens."
  exit 1
fi
TENANT="$(printf '%s' "$TENANT" | tr '[:upper:]' '[:lower:]')"
if [[ -n "$MODE" && "$MODE" != "--dry-run" ]]; then
  echo "Unknown option: $MODE"
  usage
  exit 1
fi
if [[ -z "${REPORT_EMAIL_TO+x}" || -z "$REPORT_EMAIL_TO" ]]; then
  echo "Set REPORT_EMAIL_TO to at least one recipient."
  exit 1
fi
if [[ -z "${REPORT_EMAIL_CC+x}" ]]; then
  echo "Set REPORT_EMAIL_CC. Use REPORT_EMAIL_CC='' when there is no Cc recipient."
  exit 1
fi
if [[ -z "${REPORT_TRIGGER_TOKEN:-}" ]]; then
  echo "Set REPORT_TRIGGER_TOKEN for the selected tenant."
  exit 1
fi

API_URL="${REPORT_API_URL:-}"
if [[ -z "$API_URL" && -f "$ROOT_DIR/.report-api-url" ]]; then
  API_URL="$(tr -d '\r\n' < "$ROOT_DIR/.report-api-url")"
fi
API_URL="${API_URL:-$DEFAULT_REPORT_API_URL}"
if [[ -z "$API_URL" ]]; then
  echo "Set REPORT_API_URL or deploy once to create .report-api-url."
  exit 1
fi

API_ID="${REPORT_API_ID:-}"
if [[ -z "$API_ID" && -f "$ROOT_DIR/.report-api-id" ]]; then
  API_ID="$(tr -d '\r\n' < "$ROOT_DIR/.report-api-id")"
fi
API_ID="${API_ID:-$DEFAULT_REPORT_API_ID}"

DRY_RUN=false
if [[ "$MODE" == "--dry-run" ]]; then
  DRY_RUN=true
fi

API_URL="${API_URL%/}"
HEADERS=(-H "X-Report-Token: $REPORT_TRIGGER_TOKEN")
if [[ -n "$API_ID" ]]; then
  HEADERS+=(-H "X-Apigw-Api-Id: $API_ID")
fi
curl --silent --show-error --fail-with-body \
  --connect-timeout 10 \
  --max-time 30 \
  -X POST "$API_URL/run" \
  "${HEADERS[@]}" \
  --data-urlencode "tenant=$TENANT" \
  --data-urlencode "email_to=$REPORT_EMAIL_TO" \
  --data-urlencode "email_cc=$REPORT_EMAIL_CC" \
  --data-urlencode "dry_run=$DRY_RUN"
echo
