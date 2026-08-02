#!/usr/bin/env bash
set -euo pipefail

PROFILE="${AWS_PROFILE:-athena-prod}"
REGION="${AWS_REGION:-us-east-2}"
EXPECTED_ACCOUNT_ID="${EXPECTED_ACCOUNT_ID:-556976944260}"
STACK_NAME="${STACK_NAME:-athena-incident-report-prod}"
APP_NAME="${APP_NAME:-athena-incident-report}"
ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-prod}"
API_STAGE_NAME="${API_STAGE_NAME:-manual}"
BUILD_ID="${BUILD_ID:-$(date +%Y%m%d%H%M%S)}"
ARTIFACT_BUCKET="${ARTIFACT_BUCKET:-athena-bootstrap-scripts}"
LAMBDA_RUNTIME="${LAMBDA_RUNTIME:-python3.12}"
PYTHON_VERSION="${LAMBDA_RUNTIME#python}"

: "${VPC_ID:=vpc-08da63f65bb2f7fde}"
: "${VPC_CIDR:=10.0.0.0/16}"
: "${ATHENA_WORKER_SUBNET_IDS:=subnet-067eaeb0d95d1863d,subnet-09e7bd629135490dd}"
: "${NBS_WORKER_SUBNET_IDS:=subnet-09dbc0c83d29faceb,subnet-00964885c28178ee5}"
: "${TRIGGER_VPCE_ID:=vpce-002df2e6240cd5e10}"
: "${TRIGGER_VPCE_DNS:=vpce-002df2e6240cd5e10-h8m419sk.execute-api.us-east-2.vpce.amazonaws.com}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT_DIR/infra/private-api-lambda.yaml"
BUILD_DIR="$ROOT_DIR/.aws-build/$BUILD_ID"
SOURCE_ZIP="$BUILD_DIR/source.zip"
LAYER_ZIP="$BUILD_DIR/dependencies-layer.zip"
SOURCE_KEY="lambda/$APP_NAME/$BUILD_ID/source.zip"
LAYER_KEY="lambda/$APP_NAME/$BUILD_ID/dependencies-layer.zip"

ACCOUNT_ID="$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --query Account --output text)"
if [[ "$ACCOUNT_ID" != "$EXPECTED_ACCOUNT_ID" ]]; then
  echo "Refusing to continue: expected AWS account $EXPECTED_ACCOUNT_ID, got $ACCOUNT_ID."
  exit 1
fi

if ! aws s3api head-bucket --profile "$PROFILE" --region "$REGION" --bucket "$ARTIFACT_BUCKET" >/dev/null 2>&1; then
  echo "Refusing to continue: existing artifact bucket is unavailable: $ARTIFACT_BUCKET"
  exit 1
fi

ACTION="create"
if aws cloudformation describe-stacks --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" >/dev/null 2>&1; then
  ACTION="update"
fi

cat <<EOF
This will $ACTION the production report stack in account $ACCOUNT_ID, region $REGION.

Profile:                 $PROFILE
Stack:                   $STACK_NAME
Artifact bucket:         $ARTIFACT_BUCKET
VPC:                     $VPC_ID ($VPC_CIDR)
Existing API endpoint:   $TRIGGER_VPCE_ID
Athena worker subnets:   $ATHENA_WORKER_SUBNET_IDS
NBS worker subnets:      $NBS_WORKER_SUBNET_IDS
API stage:               $API_STAGE_NAME

The stack contains a private REST API, dispatcher, two tenant-specific VPC
Lambdas, Lambda layer, IAM roles, worker security group, and log groups. It uses
the existing reachable execute-api endpoint and does not create schedules or
modify existing VPC endpoints, routes, firewalls, or indexer security groups.
Two versioned deployment artifacts are uploaded under
s3://$ARTIFACT_BUCKET/lambda/$APP_NAME/.
EOF

read -r -p "Type DEPLOY to continue: " CONFIRM
if [[ "$CONFIRM" != "DEPLOY" ]]; then
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

aws s3 cp "$SOURCE_ZIP" "s3://$ARTIFACT_BUCKET/$SOURCE_KEY" \
  --profile "$PROFILE" --region "$REGION" >/dev/null
aws s3 cp "$LAYER_ZIP" "s3://$ARTIFACT_BUCKET/$LAYER_KEY" \
  --profile "$PROFILE" --region "$REGION" >/dev/null

aws cloudformation deploy \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$TEMPLATE" \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "AppName=$APP_NAME" \
    "EnvironmentName=$ENVIRONMENT_NAME" \
    "SourceCodeS3Bucket=$ARTIFACT_BUCKET" \
    "SourceCodeS3Key=$SOURCE_KEY" \
    "DependenciesLayerS3Bucket=$ARTIFACT_BUCKET" \
    "DependenciesLayerS3Key=$LAYER_KEY" \
    "LambdaRuntime=$LAMBDA_RUNTIME" \
    "VpcId=$VPC_ID" \
    "VpcCidr=$VPC_CIDR" \
    "ExistingExecuteApiVpcEndpointId=$TRIGGER_VPCE_ID" \
    "AthenaWorkerSubnetIds=$ATHENA_WORKER_SUBNET_IDS" \
    "NbsWorkerSubnetIds=$NBS_WORKER_SUBNET_IDS" \
    "ApiStageName=$API_STAGE_NAME"

API_ID="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='RestApiId'].OutputValue | [0]" --output text)"
RUNNER_API_URL="https://$TRIGGER_VPCE_DNS/$API_STAGE_NAME"

printf '%s\n' "$RUNNER_API_URL" > "$ROOT_DIR/.report-api-url"
printf '%s\n' "$API_ID" > "$ROOT_DIR/.report-api-id"

echo
echo "Deployment complete."
echo "Existing private endpoint domain: $TRIGGER_VPCE_DNS"
echo "Runner URL: $RUNNER_API_URL"
echo "The existing run-report.sh command remains unchanged."
