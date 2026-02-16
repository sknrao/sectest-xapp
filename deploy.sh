#!/bin/bash
set -e

echo "================================================"
echo "  Deploying Security Testing xApp"
echo "================================================"

# Variables
NAMESPACE="ricxapp"
HELM_RELEASE="security-test-xapp"

echo ""
echo "Step 1: Creating namespace (if not exists)..."
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "Step 2: Creating xApp credentials secret..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: security-xapp-credentials
  namespace: ${NAMESPACE}
type: Opaque
stringData:
  xapp-id: "$(uuidgen | tr '[:upper:]' '[:lower:]')"
  xapp-secret: "$(openssl rand -base64 32)"
EOF

echo ""
echo "Step 3: Creating certificate secret (placeholder)..."
# In production, these would be real certificates from PKI
kubectl create secret generic security-xapp-certificates \
  --from-file=xapp-cert.pem=./certs/xapp-cert.pem \
  --from-file=xapp-key.pem=./certs/xapp-key.pem \
  --from-file=ca-cert.pem=./certs/ca-cert.pem \
  --namespace=${NAMESPACE} \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "Step 4: Deploying with Helm..."
helm upgrade --install ${HELM_RELEASE} ./helm \
  --namespace ${NAMESPACE} \
  --create-namespace \
  --wait \
  --timeout 10m

echo ""
echo "Step 5: Waiting for pod to be ready..."
kubectl wait --for=condition=ready pod \
  -l app=security-test-xapp \
  -n ${NAMESPACE} \
  --timeout=300s

echo ""
echo "================================================"
echo "  Deployment complete!"
echo "================================================"
echo ""
echo "To view logs:"
echo "  kubectl logs -f -l app=security-test-xapp -n ${NAMESPACE}"
echo ""
echo "To run tests:"
echo "  kubectl exec -it deployment/security-test-xapp -n ${NAMESPACE} -- python -m src.main"
echo ""