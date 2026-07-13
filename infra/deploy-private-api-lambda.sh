#!/usr/bin/env bash
set -euo pipefail

PROFILE="${AWS_PROFILE:-athena}"
REGION="${AWS_REGION:-us-east-2}"
STACK_NAME="${STACK_NAME:-athena-incident-report-manual-zip2}"
APP_NAME="${APP_NAME:-athena-incident-report}"
ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-manual}"
API_STAGE_NAME="${API_STAGE_NAME:-manual}"
BUILD_ID="${BUILD_ID:-$(date +%Y%m%d%H%M%S)}"
ARTIFACT_BUCKET="${ARTIFACT_BUCKET:-air-883111488482-us-east-2-20260710234738}"
LAMBDA_RUNTIME="${LAMBDA_RUNTIME:-python3.12}"
PYTHON_VERSION="${LAMBDA_RUNTIME#python}"

: "${VPC_ID:=vpc-05b4f0960588d3016}"
: "${SUBNET_IDS:=subnet-085d89c90fd008561}"
: "${CLIENT_VPN_CIDR:=172.16.0.0/16}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT_DIR/infra/private-api-lambda.yaml"
BUILD_DIR="$ROOT_DIR/.aws-build/$BUILD_ID"
SOURCE_ZIP="$BUILD_DIR/source.zip"
LAYER_ZIP="$BUILD_DIR/dependencies-layer.zip"
SOURCE_KEY="lambda/$APP_NAME/$BUILD_ID/source.zip"
LAYER_KEY="lambda/$APP_NAME/$BUILD_ID/dependencies-layer.zip"

ACCOUNT_ID="$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --query Account --output text)"
if [[ "$ACCOUNT_ID" != "883111488482" ]]; then
  echo "Refusing to continue: expected AWS account 883111488482, got $ACCOUNT_ID."
  exit 1
fi

if ! aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" >/dev/null 2>&1; then
  echo "Refusing to continue: migration stack does not exist: $STACK_NAME"
  exit 1
fi

if ! aws s3api head-bucket \
  --profile "$PROFILE" \
  --region "$REGION" \
  --bucket "$ARTIFACT_BUCKET" >/dev/null 2>&1; then
  echo "Refusing to continue: artifact bucket does not exist: $ARTIFACT_BUCKET"
  exit 1
fi

cat <<EOF
This will update AWS resources in account $ACCOUNT_ID, region $REGION.

Profile:          $PROFILE
Stack:            $STACK_NAME
Artifact bucket:  $ARTIFACT_BUCKET
VPC:              $VPC_ID
Subnets:          $SUBNET_IDS
Allowed CIDR:     $CLIENT_VPN_CIDR
API stage:        $API_STAGE_NAME

CloudFormation will preserve the existing report Lambda logical resource and
replace its internal ALB, listener, target group, and ALB security group with:

- one execute-api interface VPC endpoint ENI in the selected existing subnet
- one VPC endpoint security group allowing HTTPS from $CLIENT_VPN_CIDR
- one Private REST API Gateway restricted to that VPC endpoint
- one small dispatcher Lambda, IAM role, and CloudWatch log group
- POST /run (asynchronous dispatch) and GET /health (API Gateway mock)

The existing tenant secrets, VPC, subnets, Client VPN endpoint, artifact bucket,
report Lambda name, report Lambda log group, and report Lambda role are preserved.
There are no scheduled health checks or recurring Lambda invocations.
EOF

read -r -p "Type MIGRATE to update the AWS stack: " CONFIRM
if [[ "$CONFIRM" != "MIGRATE" ]]; then
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
  --parameter-overrides \
    "AppName=$APP_NAME" \
    "EnvironmentName=$ENVIRONMENT_NAME" \
    "SourceCodeS3Bucket=$ARTIFACT_BUCKET" \
    "SourceCodeS3Key=$SOURCE_KEY" \
    "DependenciesLayerS3Bucket=$ARTIFACT_BUCKET" \
    "DependenciesLayerS3Key=$LAYER_KEY" \
    "LambdaRuntime=$LAMBDA_RUNTIME" \
    "VpcId=$VPC_ID" \
    "SubnetIds=$SUBNET_IDS" \
    "ClientVpnCidr=$CLIENT_VPN_CIDR" \
    "ApiStageName=$API_STAGE_NAME"

API_URL="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='PrivateApiUrl'].OutputValue | [0]" \
  --output text)"

API_ID="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='RestApiId'].OutputValue | [0]" \
  --output text)"

VPC_ENDPOINT_ID="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='ExecuteApiVpcEndpointId'].OutputValue | [0]" \
  --output text)"

VPC_ENDPOINT_DNS="$(aws ec2 describe-vpc-endpoints \
  --profile "$PROFILE" \
  --region "$REGION" \
  --vpc-endpoint-ids "$VPC_ENDPOINT_ID" \
  --query 'VpcEndpoints[0].DnsEntries[0].DnsName' \
  --output text)"

RUNNER_API_URL="https://$VPC_ENDPOINT_DNS/$API_STAGE_NAME"

printf '%s\n' "$RUNNER_API_URL" > "$ROOT_DIR/.report-api-url"
printf '%s\n' "$API_ID" > "$ROOT_DIR/.report-api-id"

echo
echo "Migration complete."
echo "Private API URL: $API_URL"
echo "VPN runner URL: $RUNNER_API_URL"
echo "Saved local runner configuration in .report-api-url and .report-api-id."
echo
echo "Run a report with:"
echo "REPORT_EMAIL_TO='recipient@example.com' REPORT_EMAIL_CC='' REPORT_TRIGGER_TOKEN='token' ./run-report.sh athena"
