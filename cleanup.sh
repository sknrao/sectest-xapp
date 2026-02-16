#!/bin/bash

NAMESPACE="ricxapp"
HELM_RELEASE="security-test-xapp"

echo "Cleaning up security testing xApp..."

helm uninstall ${HELM_RELEASE} -n ${NAMESPACE} || true

kubectl delete secret security-xapp-credentials -n ${NAMESPACE} || true
kubectl delete secret security-xapp-certificates -n ${NAMESPACE} || true

echo "Cleanup complete!"