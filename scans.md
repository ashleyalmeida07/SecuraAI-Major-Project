# Security Scans Overview

AuthTrack currently supports three primary types of scans in the web scanner. All scans are powered by a LangGraph multi-agent orchestration framework.

## 1. Recon Only (Flow 1)
**Purpose:** Discovery and mapping of the attack surface. 
*Think of this as the reconnaissance phase where an attacker figures out what doors and windows exist in a building, without trying to pick the locks.*

**How it works:**
- **Crawler Node:** Spiders the target website using a headless **Playwright** browser to ensure JavaScript and Single Page Applications (SPAs) are fully rendered. It discovers pages, forms, APIs, and static assets. It extracts parameters, input fields, technology fingerprints (like `Server` headers), and flags interesting/sensitive paths (e.g., `.env`, `robots.txt`).
- **Classifier Node:** An AI agent analyzes every discovered URL and categorizes it by type (e.g., `api`, `auth_page`, `static_asset`, `dashboard`, `form`).
- **Surface Report Node:** Aggregates all this data into a structured **Attack Surface Map**.

**Result:** A comprehensive map of the web application's architecture. No active vulnerability auditing is performed.

---

## 2. Full Scan (Flow 1 + Flow 2)
**Purpose:** Discovery mapping followed immediately by active security auditing of configurations.
*Think of this as finding all the doors and windows, and then checking if any of them were left unlocked or lack security cameras.*

**How it works:**
- **Step 1 (Recon):** Executes the entire Recon Only flow described above to build the attack surface map.
- **Step 2 (Handoff):** The list of discovered endpoints is handed over to the auditing agents.
- **Header Fetcher Node:** Visits the discovered endpoints to pull HTTP security headers and cookies.
- **Rule Checker Node:** Evaluates the responses against OWASP security best practices (checking for missing HSTS, weak CSP, missing X-Frame-Options, etc.).
- **Severity Scorer Node:** An AI agent reviews the failed rules, assesses the risk context (e.g., a missing security header on an `auth_page` is far more critical than on a `static_asset`), assigns a severity score, and writes an Executive Summary.

**Result:** You receive both the Attack Surface Map **AND** a detailed Security Audit Report highlighting misconfigurations and vulnerabilities.

---

## 3. Injection Test (Flow 1 + Flow 3)
**Purpose:** Active vulnerability testing targeting data inputs and backend queries.
*Think of this as actively trying to break the locks on the doors and windows you found.*

**How it works:**
- **Step 1 (Recon):** Executes the entire Recon Only flow to build the attack surface map and find injectable inputs (forms, query parameters).
- **Step 2 (Handoff):** The injectable endpoints are handed over to the injection testing agents.
- **Payload Generator Node:** Takes an endpoint and generates specific malicious payloads (SQLi, XSS, Command Injection, Path Traversal).
- **Injector Node:** Sends both a normal "Baseline" request and an "Injected" request, recording the differences (status code changes, response lengths, error reflections).
- **Response Analyzer Node:** An AI agent compares the baseline and injected responses to confirm if the application is actually vulnerable, filtering out false positives.
- **Report Builder Node:** Compiles all AI-confirmed vulnerabilities into a detailed final report with evidence and remediation recommendations.

**Result:** An active testing report showing confirmed injection vulnerabilities like SQL Injection or Cross-Site Scripting.

---

## Key Differences Summary
- **Recon Only:** Maps the territory (URLs, parameters, forms). It is faster and completely passive.
- **Full Scan:** Maps the territory and then audits those endpoints for security misconfigurations (headers, cookies).
- **Injection Test:** Maps the territory and then actively attacks the inputs (forms, parameters) using malicious payloads to find execution flaws (SQLi, XSS).
