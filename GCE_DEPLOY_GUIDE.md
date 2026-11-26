# SecuraAI — Complete Google Cloud (GCE) Backend Deployment Guide

---

## Prerequisites

- Google Cloud Account (free tier gives \$300 credits for 90 days)
- Git repo: `https://github.com/ashleyalmeida07/SecuraAI-Major-Project.git`
- Vercel frontend URL: `https://secura-ai-major-project.vercel.app`

---

## Stack

| Component | Tool |
|---|---|
| Cloud | Google Compute Engine (GCE) — Ubuntu 22.04 LTS |
| App Server | Uvicorn (FastAPI/ASGI) |
| Process Manager | tmux |
| HTTPS | Let's Encrypt via Certbot |
| Domain | `<YOUR_GCE_IP>.nip.io` (free, no DNS setup needed) |
| Port | 443 (HTTPS) |

---

## PART 1 — Create a GCE VM Instance

### Step 1 — Go to Google Cloud Console

1. Open [https://console.cloud.google.com](https://console.cloud.google.com)
2. Sign in with your Google account
3. If this is your first time, click **Try for free** → you get **\$300 free credits** for 90 days

### Step 2 — Create a new project (if needed)

1. Top bar → Click the project dropdown → **New Project**
2. Name: `securai-backend`
3. Click **Create**
4. Make sure this project is selected in the top bar

### Step 3 — Enable Compute Engine API

1. Go to **Navigation Menu (☰)** → **Compute Engine** → **VM Instances**
2. If prompted, click **Enable** to enable the Compute Engine API
3. Wait ~1 minute for it to activate

### Step 4 — Create the VM Instance

1. Click **Create Instance**
2. Fill in:

```
Name:           securai-backend
Region:         us-central1 (Iowa) — or closest to you
Zone:           us-central1-a
Machine type:   e2-medium (2 vCPU, 4 GB RAM)
                ← minimum; LLM/BaaS audit needs RAM
```

### Step 5 — Configure Boot Disk

1. Click **Change** under Boot disk
2. Settings:

```
Operating System:   Ubuntu
Version:            Ubuntu 22.04 LTS (x86/64)
Boot disk type:     Balanced persistent disk
Size (GB):          20
```

3. Click **Select**

### Step 6 — Configure Firewall

Under **Firewall** section, check BOTH:

```
☑ Allow HTTP traffic      (opens port 80)
☑ Allow HTTPS traffic     (opens port 443)
```

### Step 7 — Launch the Instance

1. Click **Create**
2. Wait ~1 minute for the instance to start
3. Note the **External IP** in the VM instances list

```
Your GCE IP: ___________________   ← write it here
Your domain: ___________________.nip.io
```

---

### Step 8 — Reserve a Static External IP (IMPORTANT — prevents IP change on reboot)

1. Go to **Navigation Menu (☰)** → **VPC Network** → **IP Addresses**
2. Find your instance's IP → Click **Reserve** under the "Type" column
   - OR: Click **Reserve External Static Address** at the top
     - Name: `securai-ip`
     - Region: same as your VM (e.g. `us-central1`)
     - Attached to: your VM instance
3. Click **Reserve**

### Step 9 — Add Firewall Rule for Port 8000 (dev/test fallback)

1. Go to **Navigation Menu (☰)** → **VPC Network** → **Firewall**
2. Click **Create Firewall Rule**

```
Name:                   allow-port-8000
Direction of traffic:   Ingress
Targets:                All instances in the network
Source IP ranges:        0.0.0.0/0
Protocols and ports:    Specified protocols and ports
                        ☑ TCP: 8000
```

3. Click **Create**

---

## PART 2 — Connect to the GCE Instance

### Option A — SSH from Google Cloud Console (easiest)

1. Go to **Compute Engine** → **VM Instances**
2. Click the **SSH** button next to your instance
3. A browser-based terminal opens — you're in!

### Option B — SSH from Windows PowerShell (using gcloud CLI)

First, install Google Cloud SDK:

```powershell
# Download and install from: https://cloud.google.com/sdk/docs/install
# Then run:
gcloud init
gcloud auth login

# SSH into your instance:
gcloud compute ssh securai-backend --zone us-central1-a
```

### Option C — SSH using traditional SSH key

```powershell
# Generate SSH key (if you don't have one)
ssh-keygen -t rsa -b 4096 -C "your-email@gmail.com" -f "$HOME\.ssh\gce-securai"

# Add public key to GCE:
# Go to Compute Engine → Metadata → SSH Keys → Add Item
# Paste contents of: type $HOME\.ssh\gce-securai.pub

# Then SSH in:
ssh -i "$HOME\.ssh\gce-securai" your-username@YOUR_GCE_IP
```

---

## PART 3 — System Setup (run once on fresh instance)

All commands below run **inside the GCE terminal** (after SSH).

### Step 10 — Update system packages

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 11 — Install system dependencies

```bash
sudo apt install -y \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    tmux \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev \
    certbot \
    nodejs \
    npm
```

### Step 12 — Install Playwright OS-level dependencies

(Required for LLM Audit and BaaS Audit browser-based scanning)

```bash
sudo apt install -y \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libx11-6 \
    libxcb1 \
    libxext6
```

---

## PART 4 — Clone the Repo and Install Python Dependencies

### Step 13 — Clone the repository

```bash
cd ~
git clone https://github.com/ashleyalmeida07/SecuraAI-Major-Project.git
cd SecuraAI-Major-Project/backend
```

### Step 14 — Create virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should now see `(.venv)` at the start of your terminal prompt.

### Step 15 — Install Python packages

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 16 — Install Playwright browser (Chromium)

```bash
playwright install chromium
playwright install-deps chromium
```

If `playwright install-deps` fails with permission error:

```bash
sudo $(which playwright) install-deps chromium
```

---

## PART 5 — Create the `.env` File

### Step 17 — Create and edit the .env file

```bash
cd ~/SecuraAI-Major-Project/backend
nano .env
```

Paste the following (edit values marked with `← CHANGE THIS`):

```env
# ─────────────────────────────────────────────
# App / Auth
# ─────────────────────────────────────────────
SECRET_KEY=change-this-to-a-long-random-string-at-least-32-chars   # ← CHANGE THIS
ACCESS_TOKEN_EXPIRE_MINUTES=10080
ALGORITHM=HS256

# ─────────────────────────────────────────────
# Database (SQLite — no setup needed)
# ─────────────────────────────────────────────
DATABASE_URL=sqlite:///./securai.db

# ─────────────────────────────────────────────
# CORS — allow your Vercel frontend
# ─────────────────────────────────────────────
CORS_ORIGINS=https://secura-ai-major-project.vercel.app,http://localhost:3000

# ─────────────────────────────────────────────
# LLM Provider — NVIDIA NIM
# ─────────────────────────────────────────────
LLM_PROVIDER=nvidia
LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b
NVIDIA_API_KEY=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

# ─────────────────────────────────────────────
# Scanner settings
# ─────────────────────────────────────────────
MAX_SCAN_DEPTH=3
REQUEST_TIMEOUT=30
```

**Save and exit nano:**
```
Ctrl+O  →  Enter  →  Ctrl+X
```

---

## PART 6 — Get a Free HTTPS Certificate

We use **nip.io** (free wildcard DNS) + **Let's Encrypt** (free SSL certs).
Your domain is simply your GCE IP with `.nip.io` appended. No registration needed.

### Step 18 — Set your IP as a variable

```bash
# Replace with your actual Static External IP
export GCE_IP="34.xxx.xxx.xxx"
```

### Step 19 — Free up port 80 (Certbot needs it)

```bash
sudo fuser -k 80/tcp 2>/dev/null || true
```

### Step 20 — Get SSL certificate

```bash
sudo certbot certonly --standalone \
    -d ${GCE_IP}.nip.io \
    --non-interactive \
    --agree-tos \
    --email your-email@gmail.com
```

Replace `your-email@gmail.com` with your real email.

**Expected output (success):**
```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/34.xxx.xxx.xxx.nip.io/fullchain.pem
Key is saved at: /etc/letsencrypt/live/34.xxx.xxx.xxx.nip.io/privkey.pem
```

### Step 21 — Verify the certificate files exist

```bash
sudo ls /etc/letsencrypt/live/${GCE_IP}.nip.io/
```

You should see: `cert.pem  chain.pem  fullchain.pem  privkey.pem  README`

---

## PART 7 — Start the Backend Server with tmux

### Step 22 — Start a new tmux session

```bash
tmux new-session -s securai
```

### Step 23 — Start the FastAPI backend

```bash
cd ~/SecuraAI-Major-Project/backend
source .venv/bin/activate

export GCE_IP="34.xxx.xxx.xxx"   # ← your actual IP

sudo .venv/bin/python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile /etc/letsencrypt/live/${GCE_IP}.nip.io/privkey.pem \
    --ssl-certfile /etc/letsencrypt/live/${GCE_IP}.nip.io/fullchain.pem \
    --workers 1 \
    --timeout-keep-alive 75
```

**Expected output:**
```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:443
```

### Step 24 — Detach from tmux (leave server running)

Press: `Ctrl+B`  then  `D`

You'll return to the normal terminal. The server keeps running in the background.

---

## PART 8 — Verify It's Working

### Step 25 — Test from local machine (PowerShell)

```powershell
# Health check — replace with your GCE IP
curl "https://34.xxx.xxx.xxx.nip.io/" -k

# Or open in browser:
# https://34.xxx.xxx.xxx.nip.io/docs   ← FastAPI Swagger UI
```

**Expected response:**
```json
{"message": "Welcome to AuthTrack Security Testing API", "status": "healthy", "version": "0.1.0"}
```

---

## PART 9 — Connect the Vercel Frontend to GCE

### Step 26 — Update environment variable on Vercel

1. Go to [vercel.com](https://vercel.com) → your project `secura-ai-major-project`
2. **Settings → Environment Variables**
3. Find `NEXT_PUBLIC_API_URL` → Edit
4. Set value to: `https://34.xxx.xxx.xxx.nip.io`  ← your GCE IP
5. Click **Save**
6. Go to **Deployments → Redeploy** (pick latest deployment → Redeploy)

### Step 27 — Update CLI default API URL

On your **local machine**, update the CLI to point to GCE:

Edit `cli/src/config.mjs` and `cli/bin/secura-mcp.mjs`:

```javascript
const DEFAULT_API = "https://34.xxx.xxx.xxx.nip.io/api/v1";
```

Or use the env var per-session:

```powershell
$env:SECURA_API = "https://34.xxx.xxx.xxx.nip.io/api/v1"
```

---

## PART 10 — Updating the Backend After Code Changes

Every time you push new code to GitHub and want GCE to use it:

### Step 28 — SSH back in

```bash
# Option A — Browser SSH from Cloud Console
# Just click the SSH button on your VM in Compute Engine

# Option B — gcloud CLI
gcloud compute ssh securai-backend --zone us-central1-a
```

### Step 29 — Reattach to the running tmux session

```bash
tmux attach -t securai
```

### Step 30 — Stop the server

Press `Ctrl+C` inside tmux

### Step 31 — Pull the latest code and restart

```bash
cd ~/SecuraAI-Major-Project
git pull origin main

cd backend
source .venv/bin/activate
pip install -r requirements.txt

export GCE_IP="34.xxx.xxx.xxx"   # ← your actual IP

sudo .venv/bin/python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile /etc/letsencrypt/live/${GCE_IP}.nip.io/privkey.pem \
    --ssl-certfile /etc/letsencrypt/live/${GCE_IP}.nip.io/fullchain.pem \
    --workers 1 \
    --timeout-keep-alive 75
```

### Step 32 — Detach again

`Ctrl+B` then `D`

---

## PART 11 — SSL Certificate Renewal (every 90 days)

```bash
# SSH in first, then:
tmux attach -t securai
# Ctrl+C to stop server

sudo fuser -k 80/tcp 2>/dev/null || true
sudo certbot renew --standalone

# Restart server (Step 31 above)
```

---

## PART 12 — Stopping / Starting the VM (save costs)

GCE charges while the VM is running. Stop it when not in use:

### Stop the VM (saves money)

```bash
# From Cloud Console: VM Instances → select your VM → Stop
# Or via gcloud:
gcloud compute instances stop securai-backend --zone us-central1-a
```

### Start the VM again

```bash
gcloud compute instances start securai-backend --zone us-central1-a
```

> **IMPORTANT:** After starting, you need to re-run the backend (tmux sessions don't survive VM stop/start):
> SSH in → run Steps 22-24 again.

---

## tmux Quick Reference

| Action | Command |
|---|---|
| Start new session | `tmux new-session -s securai` |
| Detach (keep running) | `Ctrl+B` then `D` |
| Reattach | `tmux attach -t securai` |
| List sessions | `tmux ls` |
| Kill session | `tmux kill-session -t securai` |
| Scroll up in tmux | `Ctrl+B` then `[` then arrow keys (q to exit) |

---

## GCE vs AWS EC2 — Key Differences

| Feature | AWS EC2 | Google Cloud GCE |
|---|---|---|
| SSH Access | .pem key file | Browser SSH / gcloud CLI / SSH key |
| Static IP | Elastic IP | Static External IP |
| Firewall | Security Groups | VPC Firewall Rules |
| Free tier | t2.micro (750 hrs/mo) | e2-micro (always free in us-central1) |
| Free credits | None for new users | \$300 for 90 days |
| Console | AWS Console | Google Cloud Console |
| CLI | `aws` | `gcloud` |

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Can't SSH in | Firewall blocking port 22 | Check VPC Firewall rules — allow SSH |
| `Address already in use` on port 443 | Old process running | `sudo fuser -k 443/tcp` |
| `Permission denied` on port 443 | Need sudo for ports < 1024 | Use `sudo .venv/bin/python` |
| SSL cert not found | Certbot failed or wrong IP | Re-run Step 20 with correct IP |
| Server dies when SSH closes | Not using tmux | Always start inside tmux |
| tmux gone after VM stop/start | VM stop kills processes | Re-run Steps 22-24 |
| CORS error from Vercel | Wrong CORS_ORIGINS in .env | Add Vercel URL to `CORS_ORIGINS` |
| `git pull` merge conflict | Local changes on GCE | `git stash && git pull` |
| Playwright fails | Missing OS libs | Re-run Step 12 with sudo |
| Port 443 not reachable from outside | Firewall missing HTTPS | Ensure "Allow HTTPS traffic" checked |
| nip.io DNS not resolving | Rare nip.io outage | Wait a few minutes and retry |

---

## Full One-Block Update Script

```bash
# After SSH in and tmux attach + Ctrl+C to stop server:

cd ~/SecuraAI-Major-Project && \
git pull origin main && \
cd backend && \
source .venv/bin/activate && \
pip install -r requirements.txt && \
export GCE_IP="34.xxx.xxx.xxx" && \
sudo .venv/bin/python -m uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 443 \
  --ssl-keyfile /etc/letsencrypt/live/${GCE_IP}.nip.io/privkey.pem \
  --ssl-certfile /etc/letsencrypt/live/${GCE_IP}.nip.io/fullchain.pem \
  --workers 1 \
  --timeout-keep-alive 75
```

---

## Final Architecture

```
User Browser
     │
     ▼
Vercel (Frontend)
https://secura-ai-major-project.vercel.app
     │  NEXT_PUBLIC_API_URL
     ▼
GCE (Backend)
https://34.xxx.xxx.xxx.nip.io  ← port 443 / HTTPS
     │
     ├── FastAPI + Uvicorn
     ├── LangGraph agents (Static, Recon, Header, Injection, LLM, BaaS)
     ├── Playwright (Chromium headless — LLM + BaaS scan)
     └── SQLite DB (users, scan results)
```
