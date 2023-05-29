#!/bin/bash

TF_SA_FILE=".terraform.sa.json"
TF_SA_STATIC_FILE=".terraform.sa.static.json"
TF_CONFIG_FILE=".terraform.config.json"

ENDPOINT=$(jq -r '.storage_endpoint' "${TF_SA_STATIC_FILE}")
BUCKET=$(jq -r '.bucket' "${TF_SA_STATIC_FILE}")
KEY=$(jq -r '.key' "${TF_CONFIG_FILE}")

export AWS_ACCESS_KEY_ID=$(jq -r '.static_access_key' "${TF_SA_STATIC_FILE}")
export AWS_SECRET_ACCESS_KEY=$(jq -r '.static_secret_key' "${TF_SA_STATIC_FILE}")

echo "🧰 init backend..."
terraform init -backend-config="endpoint=${ENDPOINT}" -backend-config="bucket=${BUCKET}" -backend-config="key=${KEY}" -reconfigure -upgrade || exit 1

echo ""
echo "🔍 validate config..."

terraform validate || exit 1

TARGET="$1"

echo "🚀 auto apply..."
terraform apply \
  -var service_account_key_file="${TF_SA_FILE}" \
  -var service_account_static_key_file="${TF_SA_STATIC_FILE}" \
  -var config_file="${TF_CONFIG_FILE}" \
  -auto-approve "${TARGET}" || exit 1
