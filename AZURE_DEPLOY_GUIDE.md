# SecuraAI — Complete Azure VM Backend Deployment Guide

> [!IMPORTANT]
> This guide is for **Azure for Students** subscription (free \$100 credits, no credit card needed).

---

## Prerequisites

- Azure account with **Azure for Students** subscription (you already have this)
- Git repo: `https://github.com/ashleyalmeida07/SecuraAI-Major-Project.git`
- Vercel frontend URL: `https://secura-ai-major-project.vercel.app`

---

## Stack

| Component | Tool |
|---|---|
| Cloud | Azure Virtual Machine (Ubuntu 22.04 LTS) |
| App Server | Uvicorn (FastAPI/ASGI) |
| Process Manager | tmux |
| HTTPS | Let's Encrypt via Certbot |
| Domain | `<YOUR_AZURE_IP>.nip.io` (free, no DNS setup needed) |
| Port | 443 (HTTPS) |

---

## PART 1 — Create an Azure Virtual Machine

### Step 1 — Open the Azure Portal

1. Go to [https://portal.azure.com](https://portal.azure.com)
2. You are already logged in as `ashleyalmeida182006@gmail.com`
3. Subscription: **Azure for Students**

### Step 2 — Click Create Virtual Machine

1. On the **Virtual machines** page, click **+ Create** → **Azure virtual machine**

### Step 3 — Basics Tab

Fill in these fields:

```
Subscription:           Azure for Students
Resource group:         Click "Create new" → Name: securai-rg → OK
Virtual machine name:   securai-backend
Region:                 (Asia Pacific) Central India   ← closest to you
                        OR (US) East US if India is unavailable
Availability options:   No infrastructure redundancy required
Security type:          Standard
Image:                  Ubuntu Server 22.04 LTS - x64 Gen2
VM architecture:        x64
Size:                   Click "See all sizes" →
                        Standard_B2s (2 vCPU, 4 GB RAM) ← RECOMMENDED
                        OR Standard_B1ms (1 vCPU, 2 GB RAM) ← budget option
```

### Step 4 — Administrator Account

```
Authentication type:    Password   ← easier than SSH key
Username:               azureuser
Password:               SecuraAI@2026!   ← CHANGE THIS, must have uppercase+lowercase+number+special
Confirm password:       SecuraAI@2026!
```

> [!TIP]
> Password auth is simpler for students. If you prefer SSH keys, select "SSH public key" and Azure will generate one for you to download.

### Step 5 — Inbound Port Rules

```
Public inbound ports:   Allow selected ports
Select inbound ports:   SSH (22), HTTP (80), HTTPS (443)
```

### Step 6 — Click "Next: Disks"

```
OS disk type:           Standard SSD (locally-redundant storage)
OS disk size:           Default (30 GB) is fine
```

### Step 7 — Click "Next: Networking"

Leave defaults, but verify:

```
Virtual network:        (new) securai-backend-vnet   ← auto-created
Subnet:                 default (10.0.0.0/24)
Public IP:              (new) securai-backend-ip     ← auto-created
NIC network security group:   Basic
Public inbound ports:   Allow selected ports
Select inbound ports:   SSH (22), HTTP (80), HTTPS (443)
Delete public IP and NIC when VM is deleted:   ☑ Check this
```

### Step 8 — Skip remaining tabs

Click **"Review + create"** → review the summary → click **"Create"**

Wait ~2 minutes for deployment to complete.

### Step 9 — Note your Public IP

1. Click **"Go to resource"** when deployment finishes
2. On the VM overview page, find **Public IP address** in the right panel
3. Write it down:

```
Your Azure IP: ___________________   ← write it here
Your domain:   ___________________.nip.io
```

---

### Step 10 — Add Firewall Rule for Port 8000 (dev/test fallback)

1. On your VM page → left sidebar → **Networking** → **Network settings**
2. Click **Create port rule** → **Inbound port rule**

```
Source:                     Any
Source port ranges:         *
Destination:                Any
Service:                    Custom
Destination port ranges:    8000
Protocol:                   TCP
Action:                     Allow
Priority:                   1010
Name:                       allow-port-8000
```

3. Click **Add**

---

### Step 11 — Make the Public IP Static (prevents IP change on restart)

1. On the VM Overview page, click on the **Public IP address** link (the IP number)
2. In the Public IP address resource page → **Configuration** (left sidebar)
3. Change **Assignment** from `Dynamic` to `Static`
4. Click **Save**

---

## PART 2 — Connect to the Azure VM

### Option A — SSH from Azure Portal (easiest — no setup)

1. Go to your VM page → left sidebar → **Connect** → **Connect**
2. Select **SSH using Azure CLI**  → Click **Configure + connect**
3. OR click **Native SSH** and follow the instructions

### Option B — SSH from Windows PowerShell

```powershell
# Replace with your actual Azure VM IP
ssh azureuser@20.xxx.xxx.xxx

# When prompted "Are you sure you want to continue connecting?" → type: yes
# Enter the password you set in Step 4
```

### Option C — SSH via Azure Cloud Shell

1. Click the **Cloud Shell** icon (>_) in the Azure Portal top bar
2. Select **Bash**
3. Run:

```bash
ssh azureuser@20.xxx.xxx.xxx
```

---

## PART 3 — System Setup (run once on fresh instance)

All commands below run **inside the Azure VM terminal** (after SSH).

### Step 12 — Update system packages

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 13 — Install system dependencies

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

### Step 14 — Install Playwright OS-level dependencies

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

### Step 15 — Clone the repository

```bash
cd ~
git clone https://github.com/ashleyalmeida07/SecuraAI-Major-Project.git
cd SecuraAI-Major-Project/backend
```

### Step 16 — Create virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should now see `(.venv)` at the start of your terminal prompt.

### Step 17 — Install Python packages

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 18 — Install Playwright browser (Chromium)

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

### Step 19 — Create and edit the .env file

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
# Database (SQLite — no external DB needed)
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

> [!CAUTION]
> Never commit `.env` to git. It contains real API keys.

---

## PART 6 — Get a Free HTTPS Certificate

### Step 20 — Set your IP as a variable

```bash
# Replace with your actual Azure VM Static IP
export AZURE_IP="20.xxx.xxx.xxx"
```

### Step 21 — Free up port 80 (Certbot needs it)

```bash
sudo fuser -k 80/tcp 2>/dev/null || true
```

### Step 22 — Get SSL certificate

```bash
sudo certbot certonly --standalone \
    -d ${AZURE_IP}.nip.io \
    --non-interactive \
    --agree-tos \
    --email ashleyalmeida182006@gmail.com
```

**Expected output (success):**
```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/20.xxx.xxx.xxx.nip.io/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/20.xxx.xxx.xxx.nip.io/privkey.pem
```

### Step 23 — Verify the certificate files exist

```bash
sudo ls /etc/letsencrypt/live/${AZURE_IP}.nip.io/
```

You should see: `cert.pem  chain.pem  fullchain.pem  privkey.pem  README`

---

## PART 7 — Start the Backend Server with tmux

### Step 24 — Start a new tmux session

```bash
tmux new-session -s securai
```

Your terminal will clear — you're now inside tmux (green bar at bottom).

### Step 25 — Start the FastAPI backend

```bash
cd ~/SecuraAI-Major-Project/backend
source .venv/bin/activate

export AZURE_IP="20.xxx.xxx.xxx"   # ← your actual IP

sudo .venv/bin/python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile /etc/letsencrypt/live/${AZURE_IP}.nip.io/privkey.pem \
    --ssl-certfile /etc/letsencrypt/live/${AZURE_IP}.nip.io/fullchain.pem \
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

### Step 26 — Detach from tmux (leave server running)

Press: `Ctrl+B`  then  `D`

The server keeps running in the background even after you close SSH.

---

## PART 8 — Verify It's Working

### Step 27 — Test from your local machine (PowerShell)

```powershell
# Replace with your Azure IP
curl "https://20.xxx.xxx.xxx.nip.io/" -k

# Or open in browser:
# https://20.xxx.xxx.xxx.nip.io/docs   ← FastAPI Swagger UI
```

**Expected response:**
```json
{"message": "Welcome to AuthTrack Security Testing API", "status": "healthy", "version": "0.1.0"}
```

---

## PART 9 — Connect the Vercel Frontend & CLI to Azure

### Step 28 — Update Vercel environment variable

1. Go to [vercel.com](https://vercel.com) → your project `secura-ai-major-project`
2. **Settings → Environment Variables**
3. Find `NEXT_PUBLIC_API_URL` → Edit
4. Set value to: `https://20.xxx.xxx.xxx.nip.io`  ← your Azure IP
5. Click **Save**
6. **Deployments → Redeploy** latest

### Step 29 — Update CLI default URL (local machine)

Edit these two files and replace the DEFAULT_API:

**`cli/src/config.mjs`** and **`cli/bin/secura-mcp.mjs`**:

```javascript
const DEFAULT_API = "https://20.xxx.xxx.xxx.nip.io/api/v1";
```

Or set per-session:

```powershell
$env:SECURA_API = "https://20.xxx.xxx.xxx.nip.io/api/v1"
```

---

## PART 10 — Updating the Backend After Code Changes

### Step 30 — SSH in and update

```bash
# SSH in (from PowerShell)
ssh azureuser@20.xxx.xxx.xxx

# Reattach to tmux
tmux attach -t securai

# Stop server: Ctrl+C

# Pull latest + restart
cd ~/SecuraAI-Major-Project
git pull origin main

cd backend
source .venv/bin/activate
pip install -r requirements.txt

export AZURE_IP="20.xxx.xxx.xxx"

sudo .venv/bin/python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile /etc/letsencrypt/live/${AZURE_IP}.nip.io/privkey.pem \
    --ssl-certfile /etc/letsencrypt/live/${AZURE_IP}.nip.io/fullchain.pem \
    --workers 1 \
    --timeout-keep-alive 75

# Detach: Ctrl+B then D
```

---

## PART 11 — SSL Certificate Renewal (every 90 days)

```bash
# SSH in, then:
tmux attach -t securai
# Ctrl+C to stop server

sudo fuser -k 80/tcp 2>/dev/null || true
sudo certbot renew --standalone

# Restart server (same command as Part 10)
```

---

## PART 12 — Managing the VM (save Azure credits)

### Stop the VM (saves credits — you are NOT billed while stopped)

**From Azure Portal:**
1. Go to **Virtual machines** → `securai-backend`
2. Click **Stop** at the top
3. Confirm

**From PowerShell (with Azure CLI):**
```powershell
az vm deallocate --resource-group securai-rg --name securai-backend
```

### Start the VM again

**From Portal:** Click **Start**

**From CLI:**
```powershell
az vm start --resource-group securai-rg --name securai-backend
```

> [!WARNING]
> After starting the VM, you must SSH back in and restart the backend (tmux dies on VM stop). Just run the commands from Part 10.

### Check how much credit you have left

1. Go to [https://www.microsoftazuresponsorships.com/Balance](https://www.microsoftazuresponsorships.com/Balance)
2. Shows your remaining Azure for Students credits (\$100 total)

---

## tmux Quick Reference

| Action | Command |
|---|---|
| Start new session | `tmux new-session -s securai` |
| Detach (keep running) | `Ctrl+B` then `D` |
| Reattach | `tmux attach -t securai` |
| List sessions | `tmux ls` |
| Kill session | `tmux kill-session -t securai` |
| Scroll up | `Ctrl+B` then `[` then arrow keys (`q` to exit) |

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Can't SSH in | NSG blocking port 22 | VM page → Networking → Verify SSH rule exists |
| `Address already in use` on 443 | Old process running | `sudo fuser -k 443/tcp` |
| `Permission denied` on port 443 | Need sudo | Use `sudo .venv/bin/python` |
| SSL cert error | Certbot failed | Re-run Step 22 with correct IP |
| Server stops when SSH closes | Not using tmux | Always start inside tmux |
| tmux gone after VM restart | VM restart kills tmux | Re-run Steps 24-26 |
| CORS error from Vercel | Wrong CORS_ORIGINS | Add Vercel URL to `.env` |
| `git pull` fails | Local changes on VM | `git stash && git pull` |
| Playwright fails | Missing OS libs | Re-run Step 14 |
| Port 443 unreachable | NSG missing HTTPS rule | Add HTTPS inbound rule in Networking |
| Running out of credits | VM running 24/7 | Stop VM when not in use (Part 12) |

---

## Full One-Block Update Script

```bash
# After SSH in + tmux attach + Ctrl+C:

cd ~/SecuraAI-Major-Project && \
git pull origin main && \
cd backend && \
source .venv/bin/activate && \
pip install -r requirements.txt && \
export AZURE_IP="20.xxx.xxx.xxx" && \
sudo .venv/bin/python -m uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 443 \
  --ssl-keyfile /etc/letsencrypt/live/${AZURE_IP}.nip.io/privkey.pem \
  --ssl-certfile /etc/letsencrypt/live/${AZURE_IP}.nip.io/fullchain.pem \
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
Azure VM (Backend)
https://20.xxx.xxx.xxx.nip.io  ← port 443 / HTTPS
     │
     ├── FastAPI + Uvicorn
     ├── LangGraph agents (Static, Recon, Header, Injection, LLM, BaaS)
     ├── Playwright (Chromium headless — LLM + BaaS scan)
     └── SQLite DB (users, scan results)
```

---

## Azure for Students — Key Facts

| Feature | Detail |
|---|---|
| Credits | **\$100** free (no credit card needed) |
| Renewal | Renews annually if still a student |
| VM cost (B2s, running 24/7) | ~\$30/month |
| VM cost (B1ms, running 24/7) | ~\$15/month |
| Stopped VM | **\$0** (deallocated VMs don't cost compute) |
| Disk cost (30 GB SSD) | ~\$2.40/month (charged even when VM is stopped) |
| Credit check | [microsoftazuresponsorships.com/Balance](https://www.microsoftazuresponsorships.com/Balance) |

> [!TIP]
> **To maximize your credits:** Always **Stop (deallocate)** the VM from the Azure Portal when you're not using it. A B2s VM costs about \$1/day — leaving it running 24/7 for 3 months would use \$90 of your \$100 credits. Stop it overnight and on weekends to stretch your credits much further.
