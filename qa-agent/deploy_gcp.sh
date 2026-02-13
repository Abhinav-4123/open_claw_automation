#!/bin/bash
# TestGuard AI - GCP Cloud Run Deployment Script

set -e

# Configuration
PROJECT_ID="testguard-prod"
REGION="us-central1"
SERVICE_NAME="testguard-ai"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "=============================================="
echo "  TestGuard AI - Cloud Run Deployment"
echo "=============================================="

# Check if project exists, create if not
if ! gcloud projects describe $PROJECT_ID &>/dev/null; then
    echo "[*] Creating project: $PROJECT_ID"
    gcloud projects create $PROJECT_ID --name="TestGuard Production"
fi

# Set active project
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "[*] Enabling required APIs..."
gcloud services enable \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    containerregistry.googleapis.com \
    secretmanager.googleapis.com

# Build and push container
echo "[*] Building container image..."
gcloud builds submit --tag $IMAGE_NAME

# Deploy to Cloud Run
echo "[*] Deploying to Cloud Run..."
gcloud run deploy $SERVICE_NAME \
    --image $IMAGE_NAME \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 2 \
    --timeout 300s \
    --set-env-vars "GEMINI_API_KEY=${GEMINI_API_KEY:-}"

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format='value(status.url)')

echo ""
echo "=============================================="
echo "  Deployment Complete!"
echo "=============================================="
echo ""
echo "  Service URL: $SERVICE_URL"
echo "  Dashboard:   ${SERVICE_URL}/dashboard"
echo "  API Docs:    ${SERVICE_URL}/docs"
echo ""
