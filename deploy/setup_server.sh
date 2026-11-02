#!/usr/bin/env bash
# Shield server setup for Ubuntu 22.04 / 24.04 (e.g. an Azure VM).
#
# Run it from inside the repo folder on the server:
#     cd ~/shield
#     bash deploy/setup_server.sh
#
# What it does (safe to run again; it skips what's already done):
#   1. installs Python and tools
#   2. adds 2 GB of swap (small servers have 1 GB RAM; training needs about 1 GB)
#   3. creates .venv and installs the Python libraries
#   4. trains the model and downloads the phishing feeds
#   5. installs Shield as a service: starts at boot, restarts if it crashes, live radar on
#   6. refreshes the phishing feeds every night at 03:00 (UAE time)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
USER_NAME="$(whoami)"
cd "$REPO"
echo "== Shield setup in $REPO (user $USER_NAME)"

echo "== 1/6 System packages"
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip git unzip

echo "== 2/6 Swap (extra memory)"
if ! swapon --show | grep -q '/swapfile'; then
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
else
  echo "swap already on"
fi

echo "== 3/6 Python environment"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "== 4/6 Model and feeds"
if [ ! -f ml/domain_model.joblib ]; then
  .venv/bin/python backend/scripts/download_data.py
  .venv/bin/python ml/train_baseline.py
else
  echo "model already trained (delete ml/domain_model.joblib to retrain)"
fi
.venv/bin/python backend/scripts/update_feeds.py || echo "feed download failed; Shield still runs"

if [ ! -f .env ]; then
  echo "NOTE: no .env file. Alert emails will be saved to data/outbox until you create one (see .env.example)."
fi

echo "== 5/6 Shield service"
sudo tee /etc/systemd/system/shield.service > /dev/null <<EOF
[Unit]
Description=Shield (dashboard :8000 + public check :8001 + live radar)
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
WorkingDirectory=$REPO
Environment=SHIELD_RADAR=1
Environment=PYTHONUNBUFFERED=1
ExecStart=$REPO/.venv/bin/python run_shield.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "== 6/6 Nightly feed refresh"
sudo tee /etc/systemd/system/shield-feeds.service > /dev/null <<EOF
[Unit]
Description=Refresh Shield phishing feeds, then restart Shield to load them

[Service]
Type=oneshot
User=$USER_NAME
WorkingDirectory=$REPO
ExecStart=$REPO/.venv/bin/python backend/scripts/update_feeds.py
# '+' = this one step runs with admin rights (only it is allowed to restart the service)
ExecStartPost=+/bin/systemctl restart shield
EOF
sudo tee /etc/systemd/system/shield-feeds.timer > /dev/null <<EOF
[Unit]
Description=Refresh Shield phishing feeds every night

[Timer]
OnCalendar=*-*-* 23:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now shield.service
sudo systemctl enable --now shield-feeds.timer
sleep 8
echo
echo "== Check"
curl -s -o /dev/null -w "dashboard (8000): HTTP %{http_code}\n" http://127.0.0.1:8000/ || true
curl -s -o /dev/null -w "public    (8001): HTTP %{http_code}\n" http://127.0.0.1:8001/ || true
echo
echo "Done. Useful commands:"
echo "  sudo systemctl status shield        is it running?"
echo "  sudo journalctl -u shield -f        live log (Ctrl+C to leave)"
echo "  sudo systemctl restart shield       restart after changes"
echo "Next: install the Cloudflare Tunnel connector on this server (see deploy/DEPLOY.md, step 6)."
