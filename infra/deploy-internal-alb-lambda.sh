#!/usr/bin/env bash
set -euo pipefail

PROFILE="${AWS_PROFILE:-athena}"
REGION="${AWS_REGION:-us-east-2}"
STACK_NAME="${STACK_NAME:-athena-incident-report-manual-zip}"
APP_NAME="${APP_NAME:-athena-incident-report}"
ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-manual}"
BUILD_ID="${BUILD_ID:-$(date +%Y%m%d%H%M%S)}"
ARTIFACT_BUCKET="${ARTIFACT_BUCKET:-air-${AWS_ACCOUNT_ID:-unknown}-${REGION}-${BUILD_ID}}"
ENV_FILE="${ENV_FILE:-}"
TENANT="${TENANT:-${TENANT_KEY:-}}"
ALLOW_STACK_UPDATE="${ALLOW_STACK_UPDATE:-false}"
ALLOW_EXISTING_ARTIFACT_BUCKET="${ALLOW_EXISTING_ARTIFACT_BUCKET:-$ALLOW_STACK_UPDATE}"
ALLOW_SECRET_UPDATE="${ALLOW_SECRET_UPDATE:-false}"
LAMBDA_RUNTIME="${LAMBDA_RUNTIME:-python3.12}"
PYTHON_VERSION="${LAMBDA_RUNTIME#python}"

: "${VPC_ID:?Set VPC_ID to the existing VPC id.}"
: "${SUBNET_IDS:?Set SUBNET_IDS to comma-separated existing private subnet ids.}"
: "${CLIENT_VPN_CIDR:?Set CLIENT_VPN_CIDR to the source CIDR allowed to invoke the ALB, for example the VPC/target CIDR seen by AWS Client VPN.}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT_DIR/infra/internal-alb-lambda.yaml"
BUILD_DIR="$ROOT_DIR/.aws-build/$BUILD_ID"
SOURCE_ZIP="$BUILD_DIR/source.zip"
LAYER_ZIP="$BUILD_DIR/dependencies-layer.zip"
SOURCE_KEY="lambda/$APP_NAME/$BUILD_ID/source.zip"
LAYER_KEY="lambda/$APP_NAME/$BUILD_ID/dependencies-layer.zip"

ACCOUNT_ID="$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --query Account --output text)"
if [[ "$ARTIFACT_BUCKET" == *unknown* ]]; then
  ARTIFACT_BUCKET="air-$ACCOUNT_ID-$REGION-$BUILD_ID"
fi

if [[ "${CONFIG_SECRET_ARN:-}" != "" || "${CONFIG_SECRET_NAME:-}" != "" ]]; then
  echo "CONFIG_SECRET_ARN/CONFIG_SECRET_NAME are no longer used. Tenant secrets are derived as athena-incident-report/{tenant}/config."
  exit 1
fi

if [[ "$TENANT" != "" ]]; then
  TENANT="$(printf '%s' "$TENANT" | tr '[:upper:]' '[:lower:]')"
  if [[ ! "$TENANT" =~ ^[a-z0-9_.-]+$ ]]; then
    echo "TENANT must contain only letters, numbers, dots, underscores, or hyphens."
    exit 1
  fi
fi

if [[ "$ENV_FILE" != "" && "$TENANT" == "" ]]; then
  echo "Set TENANT when ENV_FILE is set, for example TENANT=nbs ENV_FILE=.env.nbs."
  exit 1
fi

if [[ "$ENV_FILE" != "" && ! -f "$ENV_FILE" ]]; then
  echo "ENV_FILE does not exist: $ENV_FILE"
  exit 1
fi

TENANT_SECRET_NAME=""
if [[ "$TENANT" != "" ]]; then
  TENANT_SECRET_NAME="athena-incident-report/$TENANT/config"
fi

cat <<EOF
This will create or update AWS resources in account $ACCOUNT_ID, region $REGION, profile $PROFILE.

Stack:           $STACK_NAME
Stack update:    $ALLOW_STACK_UPDATE
Artifact bucket: $ARTIFACT_BUCKET
Existing bucket: $ALLOW_EXISTING_ARTIFACT_BUCKET
Tenant secret:   ${TENANT_SECRET_NAME:-not creating/updating}
Secret update:   $ALLOW_SECRET_UPDATE
Runtime:         $LAMBDA_RUNTIME
VPC:             $VPC_ID
Subnets:         $SUBNET_IDS
ALB source CIDR: $CLIENT_VPN_CIDR

Existing VPC/subnets are only referenced. The stack creates its own internal ALB,
security group, Lambda function, dependency layer, target group, listener, IAM
role, and log group. The script creates a new S3 artifact bucket unless an
existing bucket is explicitly allowed. If ENV_FILE and TENANT are set, it writes
the tenant config secret at athena-incident-report/{tenant}/config and adds
REPORT_TRIGGER_TOKEN when absent.
EOF

STACK_EXISTS=false
if aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" >/dev/null 2>&1; then
  STACK_EXISTS=true
fi
if [[ "$STACK_EXISTS" == "true" && "$ALLOW_STACK_UPDATE" != "true" ]]; then
  echo "Refusing to continue: CloudFormation stack already exists: $STACK_NAME. Set ALLOW_STACK_UPDATE=true to update it."
  exit 1
fi

BUCKET_EXISTS=false
if aws s3api head-bucket --profile "$PROFILE" --region "$REGION" --bucket "$ARTIFACT_BUCKET" >/dev/null 2>&1; then
  BUCKET_EXISTS=true
fi
if [[ "$BUCKET_EXISTS" == "true" && "$ALLOW_EXISTING_ARTIFACT_BUCKET" != "true" ]]; then
  echo "Refusing to continue: S3 artifact bucket already exists: $ARTIFACT_BUCKET. Set ALLOW_EXISTING_ARTIFACT_BUCKET=true to reuse it."
  exit 1
fi

SECRET_EXISTS=false
if [[ "$ENV_FILE" != "" ]]; then
  if aws secretsmanager describe-secret \
    --profile "$PROFILE" \
    --region "$REGION" \
    --secret-id "$TENANT_SECRET_NAME" >/dev/null 2>&1; then
    SECRET_EXISTS=true
  fi
  if [[ "$SECRET_EXISTS" == "true" && "$ALLOW_SECRET_UPDATE" != "true" ]]; then
    echo "Refusing to continue: Secrets Manager secret already exists: $TENANT_SECRET_NAME. Set ALLOW_SECRET_UPDATE=true to update it."
    exit 1
  fi
fi

read -r -p "Type CREATE to continue: " CONFIRM
if [[ "$CONFIRM" != "CREATE" ]]; then
  echo "Aborted."
  exit 1
fi

mkdir -p "$BUILD_DIR/source" "$BUILD_DIR/layer/python"

python3 -m pip install \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version "$PYTHON_VERSION" \
  --only-binary=:all: \
  --target "$BUILD_DIR/layer/python" \
  -r "$ROOT_DIR/requirements.txt"

find "$BUILD_DIR/layer" \
  \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' -o -name 'tests' -o -name 'test' \) \
  -prune -exec rm -rf {} +

cp "$ROOT_DIR"/charts.py \
   "$ROOT_DIR"/generate_report.py \
   "$ROOT_DIR"/lambda_handler.py \
   "$ROOT_DIR"/mailer.py \
   "$ROOT_DIR"/render.py \
   "$ROOT_DIR"/render_email.py \
   "$ROOT_DIR"/report_style.css \
   "$BUILD_DIR/source/"

(cd "$BUILD_DIR/source" && zip -rq "$SOURCE_ZIP" .)
(cd "$BUILD_DIR/layer" && zip -rq "$LAYER_ZIP" .)

if [[ "$BUCKET_EXISTS" != "true" ]]; then
  aws s3api create-bucket \
    --profile "$PROFILE" \
    --region "$REGION" \
    --bucket "$ARTIFACT_BUCKET" \
    --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
fi

aws s3 cp "$SOURCE_ZIP" "s3://$ARTIFACT_BUCKET/$SOURCE_KEY" --profile "$PROFILE" --region "$REGION" >/dev/null
aws s3 cp "$LAYER_ZIP" "s3://$ARTIFACT_BUCKET/$LAYER_KEY" --profile "$PROFILE" --region "$REGION" >/dev/null

if [[ "$ENV_FILE" != "" ]]; then
  SECRET_FILE="$(mktemp)"
  EXISTING_SECRET_FILE="$(mktemp)"
  trap 'rm -f "$SECRET_FILE" "$EXISTING_SECRET_FILE"' EXIT
  if [[ "$SECRET_EXISTS" == "true" ]]; then
    aws secretsmanager get-secret-value \
      --profile "$PROFILE" \
      --region "$REGION" \
      --secret-id "$TENANT_SECRET_NAME" \
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
      --secret-id "$TENANT_SECRET_NAME" \
      --secret-string "file://$SECRET_FILE" >/dev/null
    echo "Updated tenant config secret: $TENANT_SECRET_NAME"
  else
    TENANT_SECRET_ARN="$(aws secretsmanager create-secret \
      --profile "$PROFILE" \
      --region "$REGION" \
      --name "$TENANT_SECRET_NAME" \
      --description "Athena incident report Lambda configuration for $TENANT" \
      --secret-string "file://$SECRET_FILE" \
      --query ARN \
      --output text)"
    echo "Created tenant config secret: $TENANT_SECRET_ARN"
  fi
fi

PARAMETERS=(
  "AppName=$APP_NAME"
  "EnvironmentName=$ENVIRONMENT_NAME"
  "SourceCodeS3Bucket=$ARTIFACT_BUCKET"
  "SourceCodeS3Key=$SOURCE_KEY"
  "DependenciesLayerS3Bucket=$ARTIFACT_BUCKET"
  "DependenciesLayerS3Key=$LAYER_KEY"
  "LambdaRuntime=$LAMBDA_RUNTIME"
  "VpcId=$VPC_ID"
  "SubnetIds=$SUBNET_IDS"
  "ClientVpnCidr=$CLIENT_VPN_CIDR"
)

if [[ "${CERTIFICATE_ARN:-}" != "" ]]; then
  PARAMETERS+=("CertificateArn=$CERTIFICATE_ARN")
fi

aws cloudformation deploy \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$TEMPLATE" \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides "${PARAMETERS[@]}"

TARGET_GROUP_ARN="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='TargetGroupArn'].OutputValue | [0]" \
  --output text)"

FUNCTION_ARN="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='LambdaFunctionArn'].OutputValue | [0]" \
  --output text)"

aws elbv2 register-targets \
  --profile "$PROFILE" \
  --region "$REGION" \
  --target-group-arn "$TARGET_GROUP_ARN" \
  --targets "Id=$FUNCTION_ARN"

aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs"
