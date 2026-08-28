# Security Scans Overview

AuthTrack currently supports two primary types of scans in the web scanner. 

## 1. Recon Only (Flow 1)
**Purpose:** Discovery and mapping of the attack surface. 
*Think of this as the reconnaissance phase where an attacker figures out what doors and windows exist in a building, without trying to pick the locks.*

**How it works:**
- **Crawler Node:** Spiders the target website to discover pages, forms, APIs, and static assets. It extracts parameters, input fields, technology fingerprints (like `Server` headers), and flags interesting/sensitive paths (e.g., `.env`, `robots.txt`).
- **Classifier Node:** An AI agent (backed by deterministic fallback rules) analyzes every discovered URL and categorizes it by type (e.g., `API`, `Auth Page`, `Static Asset`, `Dashboard`).
- **Surface Report Node:** Aggregates all this data into a structured **Attack Surface Map**.

**Result:** A comprehensive map of the web application's architecture. No active vulnerability auditing is performed.

---

## 2. Full Scan (Flow 1 + Flow 2)
**Purpose:** Discovery mapping followed immediately by active security auditing.
*Think of this as finding all the doors and windows, and then checking if any of them were left unlocked or lack security cameras.*

**How it works:**
- **Step 1 (Recon):** Executes the entire Recon Only flow described above to build the attack surface map.
- **Step 2 (Handoff):** The list of discovered endpoints is handed over to the auditing agents.
- **Header Fetcher Node:** Visits the discovered endpoints to pull HTTP security headers and cookies.
- **Rule Checker Node:** Evaluates the responses against OWASP security best practices (checking for missing HSTS, weak CSP, missing X-Frame-Options, etc.).
- **Severity Scorer Node:** An AI agent reviews the failed rules, assesses the risk context (e.g., a missing security header on an `Auth Page` is far more critical than on a `Static Asset`), assigns a severity score, and writes an Executive Summary.

**Result:** You receive both the Attack Surface Map **AND** a detailed Security Audit Report highlighting misconfigurations and vulnerabilities.

---

## Key Differences Summary
- **Recon Only** just maps the territory (URLs, parameters, forms). It is faster and completely passive.
- **Full Scan** maps the territory and then actively audits those discovered endpoints for security vulnerabilities (currently focusing on security headers and cookies).
