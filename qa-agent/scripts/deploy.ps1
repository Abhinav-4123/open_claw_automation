# TestGuard AI - Windows Deployment Script
# Usage: .\deploy.ps1
#
# Prerequisites:
# - gcloud CLI installed and authenticated
# - Docker Desktop installed
# - Anthropic API key
#

$ErrorActionPreference = "Stop"

Write-Host @"

╔═══════════════════════════════════════════╗
║       TestGuard AI - Deployment           ║
╚═══════════════════════════════════════════╝

"@ -ForegroundColor Green

# Configuration
$PROJECT_ID = if ($env:GCP_PROJECT_ID) { $env:GCP_PROJECT_ID } else { "project-a4673773-3949-4a02" }
$REGION = if ($env:GCP_REGION) { $env:GCP_REGION } else { "us-central1" }
$SERVICE_NAME = "qa-agent-api"
$LANDING_SERVICE = "qa-agent-landing"

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Host "Error: gcloud CLI not installed" -ForegroundColor Red
    Write-Host "Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Docker not installed" -ForegroundColor Red
    exit 1
}

# Check for API key (Gemini preferred, fallback to others)
$API_KEY = $null
$KEY_NAME = $null

if ($env:GEMINI_API_KEY) {
    $API_KEY = $env:GEMINI_API_KEY
    $KEY_NAME = "gemini-api-key"
    Write-Host "Using Gemini API" -ForegroundColor Cyan
} elseif ($env:OPENAI_API_KEY) {
    $API_KEY = $env:OPENAI_API_KEY
    $KEY_NAME = "openai-api-key"
    Write-Host "Using OpenAI API" -ForegroundColor Cyan
} elseif ($env:ANTHROPIC_API_KEY) {
    $API_KEY = $env:ANTHROPIC_API_KEY
    $KEY_NAME = "anthropic-api-key"
    Write-Host "Using Anthropic API" -ForegroundColor Cyan
} else {
    Write-Host "No API key found. Enter your preferred LLM API key:" -ForegroundColor Yellow
    Write-Host "1. Gemini (cheapest)" -ForegroundColor Green
    Write-Host "2. OpenAI"
    Write-Host "3. Anthropic"
    $choice = Read-Host "Choose provider (1/2/3)"

    $secureKey = Read-Host "Enter API key" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $API_KEY = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    switch ($choice) {
        "1" { $KEY_NAME = "gemini-api-key"; $env:GEMINI_API_KEY = $API_KEY }
        "2" { $KEY_NAME = "openai-api-key"; $env:OPENAI_API_KEY = $API_KEY }
        "3" { $KEY_NAME = "anthropic-api-key"; $env:ANTHROPIC_API_KEY = $API_KEY }
        default { $KEY_NAME = "gemini-api-key"; $env:GEMINI_API_KEY = $API_KEY }
    }
}

Write-Host "✓ Prerequisites checked" -ForegroundColor Green

# Set GCP project
Write-Host "Setting up GCP..." -ForegroundColor Yellow
gcloud config set project $PROJECT_ID

# Enable APIs
Write-Host "Enabling GCP APIs..." -ForegroundColor Yellow
gcloud services enable `
    run.googleapis.com `
    cloudbuild.googleapis.com `
    secretmanager.googleapis.com `
    artifactregistry.googleapis.com `
    cloudscheduler.googleapis.com `
    --quiet

# Create Artifact Registry
Write-Host "Setting up Artifact Registry..." -ForegroundColor Yellow
gcloud artifacts repositories create qa-agent `
    --repository-format=docker `
    --location=$REGION `
    --quiet 2>$null

# Configure Docker
gcloud auth configure-docker "$REGION-docker.pkg.dev" --quiet

# Store API key
Write-Host "Storing secrets..." -ForegroundColor Yellow
$API_KEY | gcloud secrets create $KEY_NAME --data-file=- --quiet 2>$null
if ($LASTEXITCODE -ne 0) {
    $API_KEY | gcloud secrets versions add $KEY_NAME --data-file=- --quiet
}

# Build and push containers
Write-Host "Building API container..." -ForegroundColor Yellow
docker build -t "$REGION-docker.pkg.dev/$PROJECT_ID/qa-agent/api:latest" .
docker push "$REGION-docker.pkg.dev/$PROJECT_ID/qa-agent/api:latest"

Write-Host "Building landing page container..." -ForegroundColor Yellow
docker build -t "$REGION-docker.pkg.dev/$PROJECT_ID/qa-agent/landing:latest" ./landing
docker push "$REGION-docker.pkg.dev/$PROJECT_ID/qa-agent/landing:latest"

# Deploy to Cloud Run
Write-Host "Deploying API to Cloud Run..." -ForegroundColor Yellow
# Determine env var name from key name
$ENV_VAR_NAME = switch ($KEY_NAME) {
    "gemini-api-key" { "GEMINI_API_KEY" }
    "openai-api-key" { "OPENAI_API_KEY" }
    "anthropic-api-key" { "ANTHROPIC_API_KEY" }
}

gcloud run deploy $SERVICE_NAME `
    --image "$REGION-docker.pkg.dev/$PROJECT_ID/qa-agent/api:latest" `
    --platform managed `
    --region $REGION `
    --allow-unauthenticated `
    --memory 2Gi `
    --cpu 2 `
    --set-secrets "${ENV_VAR_NAME}=${KEY_NAME}:latest" `
    --set-env-vars "LLM_PROVIDER=auto" `
    --quiet

Write-Host "Deploying landing page..." -ForegroundColor Yellow
gcloud run deploy $LANDING_SERVICE `
    --image "$REGION-docker.pkg.dev/$PROJECT_ID/qa-agent/landing:latest" `
    --platform managed `
    --region $REGION `
    --allow-unauthenticated `
    --memory 256Mi `
    --quiet

# Get URLs
$API_URL = gcloud run services describe $SERVICE_NAME --region $REGION --format "value(status.url)"
$LANDING_URL = gcloud run services describe $LANDING_SERVICE --region $REGION --format "value(status.url)"

# Set up scheduler
Write-Host "Setting up daily test scheduler..." -ForegroundColor Yellow
gcloud scheduler jobs create http daily-qa-tests `
    --location $REGION `
    --schedule "0 6 * * *" `
    --uri "$API_URL/run-scheduled" `
    --http-method POST `
    --time-zone "America/New_York" `
    --quiet 2>$null

Write-Host @"

╔═══════════════════════════════════════════╗
║         DEPLOYMENT COMPLETE!              ║
╚═══════════════════════════════════════════╝

"@ -ForegroundColor Green

Write-Host "API URL:      $API_URL" -ForegroundColor Cyan
Write-Host "Landing Page: $LANDING_URL" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Point your domain to the landing page URL"
Write-Host "2. Test the API with Postman or curl"
Write-Host "3. Configure clients in scheduler.py"
Write-Host "4. Start outreach!"
Write-Host ""
Write-Host "Your QA testing business is live!" -ForegroundColor Green
