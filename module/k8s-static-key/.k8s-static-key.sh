#!/bin/bash

CLOUD_ID="$1"
FOLDER_ID="$2"
SERVICE_ACCOUNT_KEY="$3"
K8S_CLUSTER_ID="$4"
TF_MODULE_FOLDER="$5"

PROFILE_PREFIX="tf-k8s-static-key"
PROFILE_NAME="${PROFILE_PREFIX}-$(date +%s)"

KUBE_CONFIG_FILE=".terraform.kubeconfig"

function clear {
  TF_PROFILES=$(yc config profile list | grep "${PROFILE_PREFIX}")
  for profile in $(echo ${TF_PROFILES}); do
    yc config profile delete "${profile}" &>/dev/null
  done
  rm -rf ${KUBE_CONFIG_FILE}
}
trap clear EXIT

OLD_PROFILE=$(yc config profile list | grep -v "${PROFILE_PREFIX}" | grep ACTIVE | sed 's/ ACTIVE//')

if [ -z "${OLD_PROFILE}" ]; then
  yc config profile create temp &>/dev/null
  OLD_PROFILE="temp"
fi

yc config profile create "${PROFILE_NAME}" &>/dev/null || exit 1

yc config set cloud-id ${CLOUD_ID} &>/dev/null || exit 1
yc config set folder-id ${FOLDER_ID} &>/dev/null || exit 1
yc config set service-account-key ${SERVICE_ACCOUNT_KEY} &>/dev/null || exit 1

K8S_NAMESPACE="kube-system"
K8S_ADMIN_USER="admin-user"

rm -rf ${KUBE_CONFIG_FILE}
yc managed-kubernetes cluster get-credentials ${K8S_CLUSTER_ID} --external --profile ${PROFILE_NAME} --kubeconfig ${KUBE_CONFIG_FILE} &>/dev/null || exit 1

kubectl get serviceAccount ${K8S_ADMIN_USER} --kubeconfig ${KUBE_CONFIG_FILE} --namespace ${K8S_NAMESPACE} &>/dev/null ||
  kubectl create -f "${TF_MODULE_FOLDER}/.k8s-sa.yaml" --kubeconfig ${KUBE_CONFIG_FILE} &>/dev/null || exit 1

TOKEN=$(kubectl -n ${K8S_NAMESPACE} get secret "${K8S_ADMIN_USER}-token-secret" -o json --kubeconfig ${KUBE_CONFIG_FILE} | jq -r .data.token | base64 --decode)

yc config profile activate "${OLD_PROFILE}" &>/dev/null

echo "{\"token\": \"${TOKEN}\"}"
