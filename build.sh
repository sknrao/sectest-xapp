#!/bin/bash
set -e

echo "================================================"
echo "  Building O-RAN Security Testing xApp"
echo "================================================"

# Variables
IMAGE_NAME="security-test-xapp"
IMAGE_TAG="1.0.0"
REGISTRY="${DOCKER_REGISTRY:-localhost:5000}"
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

echo ""
echo "Step 1: Building Docker image..."
docker build -t ${FULL_IMAGE} .

echo ""
echo "Step 2: Tagging image..."
docker tag ${FULL_IMAGE} ${REGISTRY}/${IMAGE_NAME}:latest

echo ""
echo "Step 3: Pushing to registry..."
docker push ${FULL_IMAGE}
docker push ${REGISTRY}/${IMAGE_NAME}:latest

echo ""
echo "================================================"
echo "  Build complete!"
echo "  Image: ${FULL_IMAGE}"
echo "================================================"