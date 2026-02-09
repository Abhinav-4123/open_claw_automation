#!/bin/bash
#
# OpenClaw VM Setup Script
# Run this ON the GCP VM after copying files
# Usage: sudo bash setup_vm.sh
#

set -e

echo "=================================="
echo "  OpenClaw VM Setup"
echo "=================================="

# Create log directory
mkdir -p /var/log/openclaw
chmod 777 /var/log/openclaw

# Install dependencies
echo "[1/5] Installing dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv postgresql postgresql-contrib nginx

# Setup Python environment
echo "[2/5] Setting up Python environment..."
cd /home/openclaw
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Install Playwright
pip install playwright
playwright install chromium
playwright install-deps chromium

# Setup PostgreSQL
echo "[3/5] Setting up PostgreSQL..."
sudo -u postgres psql -c "CREATE USER openclaw WITH PASSWORD 'openclaw123';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE openclaw OWNER openclaw;" 2>/dev/null || true

# Create systemd service for OpenClaw API
echo "[4/5] Creating systemd services..."

cat > /etc/systemd/system/openclaw-api.service << 'EOF'
[Unit]
Description=OpenClaw API Server
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/openclaw
Environment="PATH=/home/openclaw/venv/bin"
EnvironmentFile=/home/openclaw/.env
ExecStart=/home/openclaw/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for Autonomous Runner
cat > /etc/systemd/system/openclaw-swarm.service << 'EOF'
[Unit]
Description=OpenClaw Autonomous Swarm
After=network.target openclaw-api.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/openclaw
Environment="PATH=/home/openclaw/venv/bin"
EnvironmentFile=/home/openclaw/.env
ExecStart=/home/openclaw/venv/bin/python autonomous_runner.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for QA Agent
cat > /etc/systemd/system/qa-agent.service << 'EOF'
[Unit]
Description=QA Agent API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/qa-agent
Environment="PATH=/home/qa-agent/venv/bin"
EnvironmentFile=/home/qa-agent/.env
ExecStart=/home/qa-agent/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Setup QA Agent
echo "[5/5] Setting up QA Agent..."
cd /home/qa-agent
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
playwright install chromium

# Enable and start services
systemctl daemon-reload
systemctl enable openclaw-api openclaw-swarm qa-agent
systemctl start openclaw-api
sleep 5
systemctl start openclaw-swarm
systemctl start qa-agent

echo ""
echo "=================================="
echo "  SETUP COMPLETE!"
echo "=================================="
echo ""
echo "Services running:"
systemctl status openclaw-api --no-pager | head -5
systemctl status openclaw-swarm --no-pager | head -5
systemctl status qa-agent --no-pager | head -5
echo ""
echo "API Endpoints:"
echo "  OpenClaw: http://$(curl -s ifconfig.me):8080"
echo "  QA Agent: http://$(curl -s ifconfig.me):8000"
echo ""
echo "Logs:"
echo "  OpenClaw API: journalctl -u openclaw-api -f"
echo "  Swarm: journalctl -u openclaw-swarm -f"
echo "  Autonomous: tail -f /var/log/openclaw/autonomous.log"
