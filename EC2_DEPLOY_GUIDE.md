# SecuraAI — Complete EC2 Backend Deployment Guide

---

## Prerequisites

- AWS Account with EC2 access
- A `.pem` key pair file (downloaded during instance creation)
- Git repo: `https://github.com/ashleyalmeida07/SecuraAI-Major-Project.git`
- Vercel frontend URL: `https://secura-ai-major-project.vercel.app`

---

## Stack

| Component | Tool |
|---|---|
| Cloud | AWS EC2 (Ubuntu 22.04 LTS) |
| App Server | Uvicorn (FastAPI/ASGI) |
| Process Manager | tmux |
| HTTPS | Let's Encrypt via Certbot |
| Domain | `<YOUR_EC2_IP>.nip.io` (free, no DNS setup needed) |
| Port | 443 (HTTPS) |

---

## PART 1 — Launch EC2 Instance on AWS

### Step 1 — Create the Instance

1. Log in to [AWS Console](https://console.aws.amazon.com)
2. Go to **EC2 → Instances → Launch Instances**
3. Fill in:

```
Name:           securai-backend
AMI:            Ubuntu Server 22.04 LTS (64-bit x86)
Instance type:  t2.medium   ← minimum; LLM audit needs RAM
Key pair:       Create new key pair
                  Name: securai-key
                  Type: RSA
                  Format: .pem
                  → Download and SAVE it safely (you cannot re-download it)
```

### Step 2 — Configure Security Group (Firewall Rules)

Under **Network Settings → Create Security Group**, add these **Inbound Rules**:

| Type | Protocol | Port | Source | Purpose |
|---|---|---|---|---|
| SSH | TCP | 22 | My IP | SSH access |
| Custom TCP | TCP | 443 | 0.0.0.0/0 | HTTPS backend |
| Custom TCP | TCP | 80 | 0.0.0.0/0 | Certbot SSL verification |
| Custom TCP | TCP | 8000 | 0.0.0.0/0 | Dev/test fallback |

### Step 3 — Storage

```
Storage: 20 GB  gp3
```

### Step 4 — Launch

Click **Launch Instance** → wait ~1 minute → go to **Instances** → note the **Public IPv4 address**

---

### Step 5 — Allocate an Elastic IP (IMPORTANT — prevents IP change on reboot)

1. EC2 → **Elastic IPs** (left sidebar under Network & Security)
2. Click **Allocate Elastic IP address** → **Allocate**
3. Select the new IP → **Actions → Associate Elastic IP address**
4. Select your instance → **Associate**
5. Note down this IP — it will NOT change even after reboots

```
Your EC2 IP: ___________________   ← write it here
Your domain: ___________________.nip.io
```

---

## PART 2 — Connect to EC2 from Windows (PowerShell)

### Step 6 — Fix key permissions (required on Windows)

```powershell
# Replace with your actual path to the .pem file
icacls "C:\Users\Ashley\Downloads\securai-key.pem" /inheritance:r
icacls "C:\Users\Ashley\Downloads\securai-key.pem" /grant:r "$($env:USERNAME):(R)"
```

### Step 7 — SSH into the instance

```powershell
# Replace 52.91.8.40 with your actual Elastic IP
ssh -i "C:\Users\Ashley\Downloads\securai-key.pem" ubuntu@52.91.8.40
```

If prompted `Are you sure you want to continue connecting?` → type `yes` → Enter

---

## PART 3 — System Setup (run once on fresh instance)

All commands below run **inside the EC2 terminal** (after SSH).

### Step 8 — Update system packages

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 9 — Install system dependencies

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

### Step 10 — Install Playwright OS-level dependencies

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

### Step 11 — Clone the repository

```bash
cd ~
git clone https://github.com/ashleyalmeida07/SecuraAI-Major-Project.git
cd SecuraAI-Major-Project/backend
```

### Step 12 — Create virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should now see `(.venv)` at the start of your terminal prompt.

### Step 13 — Install Python packages

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 14 — Install Playwright browser (Chromium)

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

### Step 15 — Create and edit the .env file

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
# LLM Provider — NVIDIA NIM (current working key)
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

We use **nip.io** (a free wildcard DNS service) + **Let's Encrypt** (free SSL certs).  
Your domain is simply your EC2 IP with `.nip.io` appended. No registration needed.

### Step 16 — Set your IP as a variable

```bash
# Replace with your actual Elastic IP
export EC2_IP="52.91.8.40"
```

### Step 17 — Free up port 80 (Certbot needs it)

```bash
sudo fuser -k 80/tcp 2>/dev/null || true
```

### Step 18 — Get SSL certificate

```bash
sudo certbot certonly --standalone \
    -d ${EC2_IP}.nip.io \
    --non-interactive \
    --agree-tos \
    --email your-email@gmail.com
```

Replace `your-email@gmail.com` with your real email (used for expiry reminders).

**Expected output (success):**
```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/52.91.8.40.nip.io/fullchain.pem
Key is saved at: /etc/letsencrypt/live/52.91.8.40.nip.io/privkey.pem
This certificate expires on 2027-02-18.
```

### Step 19 — Verify the certificate files exist

```bash
sudo ls /etc/letsencrypt/live/${EC2_IP}.nip.io/
```

You should see: `cert.pem  chain.pem  fullchain.pem  privkey.pem  README`

---

## PART 7 — Start the Backend Server with tmux

**Why tmux?** When you close SSH, any running process dies. tmux keeps it running in the background permanently.

### Step 20 — Start a new tmux session

```bash
tmux new-session -s securai
```

Your terminal will clear and show a green bar at the bottom — you're now inside tmux.

### Step 21 — Start the FastAPI backend

```bash
cd ~/SecuraAI-Major-Project/backend
source .venv/bin/activate

export EC2_IP="52.91.8.40"   # ← your actual IP

sudo .venv/bin/python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile /etc/letsencrypt/live/${EC2_IP}.nip.io/privkey.pem \
    --ssl-certfile /etc/letsencrypt/live/${EC2_IP}.nip.io/fullchain.pem \
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

### Step 22 — Detach from tmux (leave server running)

Press: `Ctrl+B`  then  `D`

You'll return to the normal terminal. The server keeps running in the background.

---

## PART 8 — Verify It's Working

### Step 23 — Test from local machine (PowerShell)

```powershell
# Health check — replace with your IP
curl "https://52.91.8.40.nip.io/health" -k

# Or test the docs page — open this in browser:
# https://52.91.8.40.nip.io/docs
```

**Expected response:**
```json
{"status": "ok"}
```

### Step 24 — Test login endpoint

```powershell
curl -X POST "https://52.91.8.40.nip.io/auth/login" `
  -H "Content-Type: application/json" `
  -d '{"username":"admin","password":"your-admin-password"}' -k
```

---

## PART 9 — Connect the Vercel Frontend to EC2

### Step 25 — Update environment variable on Vercel

1. Go to [vercel.com](https://vercel.com) → your project `secura-ai-major-project`
2. **Settings → Environment Variables**
3. Find `NEXT_PUBLIC_API_URL` → Edit
4. Set value to: `https://52.91.8.40.nip.io`  ← your EC2 IP
5. Click **Save**
6. Go to **Deployments → Redeploy** (pick latest deployment → Redeploy)

---

## PART 10 — Updating the Backend After Code Changes

Every time you push new code to GitHub and want EC2 to use it:

### Step 26 — SSH back in

```powershell
ssh -i "C:\Users\Ashley\Downloads\securai-key.pem" ubuntu@52.91.8.40
```

### Step 27 — Reattach to the running tmux session

```bash
tmux attach -t securai
```

### Step 28 — Stop the server

Press `Ctrl+C` inside tmux

### Step 29 — Pull the latest code

```bash
cd ~/SecuraAI-Major-Project
git pull origin main
```

If git says there are conflicts (unlikely since .env is gitignored):

```bash
git stash
git pull origin main
# .env is NOT tracked by git, so it's safe
```

### Step 30 — Install any new dependencies

```bash
cd backend
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 31 — Restart the server

```bash
export EC2_IP="52.91.8.40"   # ← your actual IP

sudo .venv/bin/python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile /etc/letsencrypt/live/${EC2_IP}.nip.io/privkey.pem \
    --ssl-certfile /etc/letsencrypt/live/${EC2_IP}.nip.io/fullchain.pem \
    --workers 1 \
    --timeout-keep-alive 75
```

### Step 32 — Detach again

`Ctrl+B` then `D`

---

## PART 11 — Updating the .env File on EC2

If you change API keys or settings:

```bash
ssh -i "C:\Users\Ashley\Downloads\securai-key.pem" ubuntu@52.91.8.40

nano ~/SecuraAI-Major-Project/backend/.env
# Edit what you need
# Ctrl+O → Enter → Ctrl+X to save

# Then restart the server (Steps 27-32 above)
```

---

## PART 12 — SSL Certificate Renewal (every 90 days)

Let's Encrypt certs expire every 90 days. Renew them:

```bash
ssh -i "C:\Users\Ashley\Downloads\securai-key.pem" ubuntu@52.91.8.40

# Stop uvicorn first (it uses port 443, certbot needs port 80 free)
tmux attach -t securai
# Ctrl+C to stop

# Free port 80
sudo fuser -k 80/tcp 2>/dev/null || true

# Renew
sudo certbot renew --standalone

# Restart server (Steps 31-32)
```

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

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `Permission denied (publickey)` on SSH | .pem file permissions too open | Re-run `icacls` commands in Step 6 |
| `Address already in use` on port 443 | Old process still running | `sudo fuser -k 443/tcp` |
| `Permission denied` binding port 443 | Need sudo for ports < 1024 | Use `sudo .venv/bin/python -m uvicorn ...` |
| SSL cert not found | Certbot failed or wrong IP | Re-run Step 18 with correct IP |
| `No such file or directory` for certbot path | Wrong EC2_IP variable | `echo $EC2_IP` to check, re-export |
| Server dies when SSH closes | Not using tmux | Always start inside `tmux new-session` |
| tmux session gone after EC2 reboot | Reboot kills tmux | Re-run Steps 20-22 after reboot |
| `git pull` fails (merge conflict) | Local changes on EC2 | `git stash && git pull` |
| CORS error from Vercel | Wrong CORS_ORIGINS in .env | Add Vercel URL to `CORS_ORIGINS` in .env |
| 502 Bad Gateway from Vercel | uvicorn stopped | `tmux ls` → reattach → restart server |
| Playwright install fails | Missing OS libs | Re-run Step 10 with sudo |
| LLM calls failing | NVIDIA API key expired | Update `NVIDIA_API_KEY` in .env |

---

## Full One-Block Update Script (copy-paste after SSH in)

```bash
# After SSH in and tmux attach + Ctrl+C to stop server:

cd ~/SecuraAI-Major-Project && \
git pull origin main && \
cd backend && \
source .venv/bin/activate && \
pip install -r requirements.txt && \
export EC2_IP="52.91.8.40" && \
sudo .venv/bin/python -m uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 443 \
  --ssl-keyfile /etc/letsencrypt/live/${EC2_IP}.nip.io/privkey.pem \
  --ssl-certfile /etc/letsencrypt/live/${EC2_IP}.nip.io/fullchain.pem \
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
EC2 (Backend)
https://52.91.8.40.nip.io  ← port 443 / HTTPS
     │
     ├── FastAPI + Uvicorn
     ├── LangGraph agents (Static, Recon, Header, Injection, LLM, BaaS)
     ├── Playwright (Chromium headless — LLM + BaaS scan)
     └── SQLite DB (users, scan results)
```
