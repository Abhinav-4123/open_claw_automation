# OpenClaw - GCP VM Deployment Script (Windows PowerShell)

$ErrorActionPreference = "Stop"

# Configuration
$PROJECT_ID = if ($env:GCP_PROJECT_ID) { $env:GCP_PROJECT_ID } else { "project-a4673773-3949-4a02" }
$ZONE = if ($env:GCP_ZONE) { $env:GCP_ZONE } else { "us-central1-a" }
$INSTANCE_NAME = "openclaw-swarm"
$MACHINE_TYPE = "e2-standard-4"

Write-Host @"

 ____                    ____ _
/ __ \___  ___ ___  ____/ __/(_)__ _    __
/ /_/ / _ \/ -_) _ \/ __/ /__/ / _ \ |/|/ /
\____/ .__/\__/_//_/\__/\___/_/\_,_/__,__/
    /_/

"@ -ForegroundColor Green

Write-Host "GCP VM Deployment" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan
Write-Host "Project: $PROJECT_ID"
Write-Host "Zone: $ZONE"
Write-Host ""

# Check gcloud
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Host "gcloud CLI not found. Install from https://cloud.google.com/sdk" -ForegroundColor Red
    exit 1
}

# Set project
gcloud config set project $PROJECT_ID

# Enable APIs
Write-Host "Enabling APIs..." -ForegroundColor Yellow
gcloud services enable compute.googleapis.com --quiet

# Create VM
Write-Host "Creating VM..." -ForegroundColor Yellow

$startupScript = @"
#!/bin/bash
apt-get update
apt-get install -y docker.io docker-compose git curl

systemctl start docker
systemctl enable docker

# Add current user to docker group
usermod -aG docker `$USER

echo "OpenClaw VM ready"
"@

gcloud compute instances create $INSTANCE_NAME `
    --zone=$ZONE `
    --machine-type=$MACHINE_TYPE `
    --image-family=ubuntu-2204-lts `
    --image-project=ubuntu-os-cloud `
    --boot-disk-size=50GB `
    --tags=http-server,https-server `
    --metadata=startup-script=$startupScript

# Create firewall rule
Write-Host "Configuring firewall..." -ForegroundColor Yellow
gcloud compute firewall-rules create allow-openclaw `
    --allow=tcp:8080 `
    --target-tags=http-server `
    --description="Allow OpenClaw API" `
    --quiet 2>$null

# Get IP
$EXTERNAL_IP = gcloud compute instances describe $INSTANCE_NAME `
    --zone=$ZONE `
    --format="get(networkInterfaces[0].accessConfigs[0].natIP)"

Write-Host ""
Write-Host "VM Created!" -ForegroundColor Green
Write-Host "===========" -ForegroundColor Green
Write-Host "Instance: $INSTANCE_NAME"
Write-Host "External IP: $EXTERNAL_IP"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Wait 2 minutes for VM to initialize"
Write-Host ""
Write-Host "2. Copy code to VM:"
Write-Host "   gcloud compute scp --recurse .\openclaw ${INSTANCE_NAME}:/home/`$USER/ --zone=$ZONE"
Write-Host ""
Write-Host "3. SSH and start:"
Write-Host "   gcloud compute ssh $INSTANCE_NAME --zone=$ZONE"
Write-Host "   cd openclaw && sudo docker-compose up -d"
Write-Host ""
Write-Host "4. Test API:"
Write-Host "   curl http://${EXTERNAL_IP}:8080/"
