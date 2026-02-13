# TestGuard AI - GCP Cloud Run Deployment Script (PowerShell)

$ErrorActionPreference = "Stop"

# Configuration
$PROJECT_ID = "testguard-prod"
$REGION = "us-central1"
$SERVICE_NAME = "testguard-ai"
$IMAGE_NAME = "gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

Write-Host "=============================================="
Write-Host "  TestGuard AI - Cloud Run Deployment"
Write-Host "=============================================="
Write-Host ""

# Check if GEMINI_API_KEY is set
if (-not $env:GEMINI_API_KEY) {
    Write-Host "[WARNING] GEMINI_API_KEY not set. QA testing features will be disabled."
    $env:GEMINI_API_KEY = ""
}

# Check if project exists
$projectExists = gcloud projects describe $PROJECT_ID 2>$null
if (-not $projectExists) {
    Write-Host "[*] Creating project: $PROJECT_ID"
    gcloud projects create $PROJECT_ID --name="TestGuard Production"
}

# Set active project
Write-Host "[*] Setting project to $PROJECT_ID"
gcloud config set project $PROJECT_ID

# Enable required APIs
Write-Host "[*] Enabling required APIs..."
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Change to the qa-agent directory
Set-Location $PSScriptRoot

# Build and push container
Write-Host "[*] Building container image..."
gcloud builds submit --tag $IMAGE_NAME

# Deploy to Cloud Run
Write-Host "[*] Deploying to Cloud Run..."
gcloud run deploy $SERVICE_NAME `
    --image $IMAGE_NAME `
    --platform managed `
    --region $REGION `
    --allow-unauthenticated `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300s `
    --set-env-vars "GEMINI_API_KEY=$($env:GEMINI_API_KEY)"

# Get the service URL
$SERVICE_URL = gcloud run services describe $SERVICE_NAME --region $REGION --format='value(status.url)'

Write-Host ""
Write-Host "=============================================="
Write-Host "  Deployment Complete!"
Write-Host "=============================================="
Write-Host ""
Write-Host "  Service URL: $SERVICE_URL"
Write-Host "  Dashboard:   ${SERVICE_URL}/dashboard"
Write-Host "  API Docs:    ${SERVICE_URL}/docs"
Write-Host ""
