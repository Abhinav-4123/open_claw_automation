#!/bin/bash
#
# TestGuard AI - One-Command Deployment Script
# Usage: ./deploy.sh
#
# Prerequisites:
# - gcloud CLI installed and authenticated
# - Docker installed
# - Anthropic API key
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════╗"
echo "║       TestGuard AI - Deployment           ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-project-a4673773-3949-4a02}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="qa-agent-api"
LANDING_SERVICE="qa-agent-landing"

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}Error: gcloud CLI not installed${NC}"
    echo "Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker not installed${NC}"
    exit 1
fi

# Check for API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${YELLOW}Enter your Anthropic API key:${NC}"
    read -s ANTHROPIC_API_KEY
    export ANTHROPIC_API_KEY
fi

echo -e "${GREEN}✓ Prerequisites checked${NC}"

# Authenticate with GCP
echo -e "${YELLOW}Setting up GCP...${NC}"
gcloud config set project $PROJECT_ID

# Enable required APIs
echo -e "${YELLOW}Enabling GCP APIs...${NC}"
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    secretmanager.googleapis.com \
    artifactregistry.googleapis.com \
    cloudscheduler.googleapis.com \
    --quiet

# Create Artifact Registry if not exists
echo -e "${YELLOW}Setting up Artifact Registry...${NC}"
gcloud artifacts repositories create qa-agent \
    --repository-format=docker \
    --location=$REGION \
    --quiet 2>/dev/null || true

# Configure Docker for GCR
gcloud auth configure-docker ${REGION}-docker.pkg.dev --quiet

# Store API key in Secret Manager
echo -e "${YELLOW}Storing secrets...${NC}"
echo -n "$ANTHROPIC_API_KEY" | gcloud secrets create anthropic-api-key \
    --data-file=- \
    --quiet 2>/dev/null || \
echo -n "$ANTHROPIC_API_KEY" | gcloud secrets versions add anthropic-api-key \
    --data-file=- \
    --quiet

# Build and push API image
echo -e "${YELLOW}Building API container...${NC}"
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/qa-agent/api:latest .
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/qa-agent/api:latest

# Build and push landing page
echo -e "${YELLOW}Building landing page container...${NC}"
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/qa-agent/landing:latest ./landing
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/qa-agent/landing:latest

# Deploy API to Cloud Run
echo -e "${YELLOW}Deploying API to Cloud Run...${NC}"
gcloud run deploy $SERVICE_NAME \
    --image ${REGION}-docker.pkg.dev/${PROJECT_ID}/qa-agent/api:latest \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 2 \
    --min-instances 0 \
    --max-instances 10 \
    --set-secrets "ANTHROPIC_API_KEY=anthropic-api-key:latest" \
    --quiet

# Deploy landing page
echo -e "${YELLOW}Deploying landing page...${NC}"
gcloud run deploy $LANDING_SERVICE \
    --image ${REGION}-docker.pkg.dev/${PROJECT_ID}/qa-agent/landing:latest \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --memory 256Mi \
    --cpu 1 \
    --quiet

# Get service URLs
API_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)')
LANDING_URL=$(gcloud run services describe $LANDING_SERVICE --region $REGION --format 'value(status.url)')

# Set up daily scheduler
echo -e "${YELLOW}Setting up daily test scheduler...${NC}"
gcloud scheduler jobs create http daily-qa-tests \
    --location $REGION \
    --schedule "0 6 * * *" \
    --uri "${API_URL}/run-scheduled" \
    --http-method POST \
    --time-zone "America/New_York" \
    --quiet 2>/dev/null || \
gcloud scheduler jobs update http daily-qa-tests \
    --location $REGION \
    --schedule "0 6 * * *" \
    --uri "${API_URL}/run-scheduled" \
    --quiet

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗"
echo "║         DEPLOYMENT COMPLETE!              ║"
echo "╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "API URL:      ${GREEN}${API_URL}${NC}"
echo -e "Landing Page: ${GREEN}${LANDING_URL}${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Point your domain to the landing page URL"
echo "2. Test the API: curl ${API_URL}/test -X POST -H 'Content-Type: application/json' -d '{\"url\":\"https://example.com\",\"objective\":\"login\"}'"
echo "3. Configure clients in scheduler.py"
echo "4. Start outreach!"
echo ""
echo -e "${GREEN}Your QA testing business is live!${NC}"
