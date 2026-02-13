# TestGuard AI - Deployment Guide

## Quick Start Options

### Option 1: Local Development
```bash
cd qa-agent
pip install -r requirements.txt
playwright install chromium
python run_demo.py
```
Access at: http://localhost:8000

### Option 2: Google Cloud Run (Recommended for Production)

#### Prerequisites
1. GCP Project with billing enabled
2. Owner/Editor role on the project
3. gcloud CLI installed and authenticated

#### Step 1: Set up project
```bash
# Create a new project (or use existing)
gcloud projects create testguard-ai --name="TestGuard AI"
gcloud config set project testguard-ai

# Link billing account
gcloud billing accounts list
gcloud billing projects link testguard-ai --billing-account=YOUR_BILLING_ACCOUNT_ID
```

#### Step 2: Enable APIs
```bash
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com
```

#### Step 3: Set API Key
```bash
# Set your Gemini API key
export GEMINI_API_KEY="your-gemini-api-key"
```

#### Step 4: Deploy
```bash
cd qa-agent

# Build and submit to Cloud Build
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/testguard-ai

# Deploy to Cloud Run
gcloud run deploy testguard-ai \
    --image gcr.io/YOUR_PROJECT_ID/testguard-ai \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 2 \
    --timeout 300s \
    --set-env-vars "GEMINI_API_KEY=$GEMINI_API_KEY"
```

### Option 3: Docker (Any Cloud Provider)

```bash
# Build the image
docker build -t testguard-ai .

# Run locally
docker run -p 8000:8080 -e GEMINI_API_KEY=your-key testguard-ai

# Push to registry (Docker Hub, ECR, GCR, etc.)
docker tag testguard-ai your-registry/testguard-ai
docker push your-registry/testguard-ai
```

### Option 4: Railway/Fly.io (Simple Deploy)

#### Railway
1. Connect GitHub repo
2. Add environment variable: `GEMINI_API_KEY`
3. Deploy

#### Fly.io
```bash
fly launch
fly secrets set GEMINI_API_KEY=your-key
fly deploy
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| GEMINI_API_KEY | Yes* | Google Gemini API key for AI testing |
| OPENAI_API_KEY | No | Fallback to OpenAI |
| ANTHROPIC_API_KEY | No | Fallback to Anthropic |
| LLM_PROVIDER | No | Force specific provider: gemini/openai/anthropic |
| STRIPE_API_KEY | No | For payment processing |

*Security scanning works without API keys

## Endpoints After Deployment

| Endpoint | Description |
|----------|-------------|
| `/` | Landing page |
| `/dashboard` | Main dashboard |
| `/docs` | API documentation |
| `/health` | Health check |

## Testing the Deployment

```bash
# Health check
curl https://your-service-url/health

# Run a security scan
curl -X POST https://your-service-url/security/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "frameworks": ["owasp_top_10"]}'
```
