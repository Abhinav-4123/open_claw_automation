#!/bin/bash
#
# OpenClaw - GCP VM Deployment Script
# Creates a VM and deploys the agent swarm
#

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-project-a4673773-3949-4a02}"
ZONE="${GCP_ZONE:-us-central1-a}"
INSTANCE_NAME="openclaw-swarm"
MACHINE_TYPE="e2-standard-4"  # 4 vCPU, 16GB RAM

echo "🐝 OpenClaw GCP Deployment"
echo "=========================="
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ gcloud CLI not found. Install from https://cloud.google.com/sdk"
    exit 1
fi

# Set project
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "📦 Enabling APIs..."
gcloud services enable compute.googleapis.com --quiet

# Create the VM
echo "🖥️ Creating VM..."
gcloud compute instances create $INSTANCE_NAME \
    --zone=$ZONE \
    --machine-type=$MACHINE_TYPE \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=50GB \
    --tags=http-server,https-server \
    --metadata=startup-script='#!/bin/bash
# Install Docker
apt-get update
apt-get install -y docker.io docker-compose git

# Start Docker
systemctl start docker
systemctl enable docker

# Clone OpenClaw (you would use your repo URL)
# git clone https://github.com/yourusername/openclaw.git /opt/openclaw
# cd /opt/openclaw
# docker-compose up -d

echo "OpenClaw VM ready for deployment"
'

# Create firewall rule for HTTP
echo "🔥 Configuring firewall..."
gcloud compute firewall-rules create allow-openclaw \
    --allow=tcp:8080 \
    --target-tags=http-server \
    --description="Allow OpenClaw API traffic" \
    --quiet 2>/dev/null || true

# Get external IP
EXTERNAL_IP=$(gcloud compute instances describe $INSTANCE_NAME \
    --zone=$ZONE \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo "✅ VM Created!"
echo "==============="
echo "Instance: $INSTANCE_NAME"
echo "External IP: $EXTERNAL_IP"
echo ""
echo "Next steps:"
echo "1. SSH into the VM:"
echo "   gcloud compute ssh $INSTANCE_NAME --zone=$ZONE"
echo ""
echo "2. Copy your code to the VM:"
echo "   gcloud compute scp --recurse ./openclaw $INSTANCE_NAME:/opt/ --zone=$ZONE"
echo ""
echo "3. Start the swarm:"
echo "   cd /opt/openclaw && docker-compose up -d"
echo ""
echo "4. Access the API:"
echo "   curl http://$EXTERNAL_IP:8080/"
