

# **Fr. Conceicao Rodrigues College of Engineering** 

Father Agnel Ashram, Bandstand, Bandra –west, Mumbai-50 

## **Department of Computer Engineering** 

|**Group Information:**|||
|---|---|---|
|**Roll No**|**Student Name**|**Div A/ B**|
|**10246 (Group Leader)**|Jason Gonsalves|B|
|**10227**|Ashley Almeida|B|
|**10261**|Nathan Murzello|B|



**TITLE OF THE PROJECT:** AuthTrack – A Multi-Agent AI and MCP-Powered Security Testing Platform for Vibe-Coded Web Applications 

### **BROAD AREA (E.g. IoT, Machine Learning, Computer Vision, System Security etc.):** 

System Security, Multi-Agent Systems, AI Agents, Model Context Protocol (MCP), Application Security, LLM Tool-Use, DevSecOps. 

**Category of the Project (** Product based, Application based, or Research based): Application based, with a Research-oriented multi-agent AI architecture and prototype implementation 

### **ABSTRACT (maximum 300 words):** 

AuthTrack is a multi-agent AI security-testing platform built for the era of "vibe coding," where developers ship complete websites and applications from a single prompt with little security expertise. It addresses the resulting explosion of vulnerable software through a team of specialized AI agents coordinated by a central Orchestrator. A Crawler Agent ingests a deployed application URL and discovers its pages and API endpoints, mapping the attack surface. An Endpoint Tester Agent then runs non-destructive, agentic security testing against each endpoint to identify OWASP Top-10 weaknesses such as missing security headers, broken access control, insecure cookies, and information leakage. A Code Analyzer Agent parses the local codebase (via AST and pattern analysis) to detect injection, SSRF, auth-bypass, and misconfiguration patterns, and streams its findings into the developer's IDE through an MCP (Model Context Protocol) server that integrates with VS Code, Cursor, Antigravity, Claude Code, or any MCP-compatible tool. A Fix Generator Agent converts each finding into a framework-specific, copy-paste-ready remediation diff and recommends the controls required for secure-by-design development. The Orchestrator Agent merges the outputs of all agents into a single explainable, prioritized report - every issue carrying the "why," a severity score, and a concrete fix. The same multi-agent engine is exposed through a developer-first CLI (secura scan), so URL, repository, and IDE scans share one intelligence layer. The system is evaluated through quantitative metrics - vulnerability-detection rate, false-positive rate, mean time to actionable fix, framework-coverage breadth, and MCP round-trip latency - positioning AuthTrack as a rigorously measurable, developer-native security assistant rather than yet another passive scanner. 

### **MOTIVATION (maximum 100 word):** 

The rise of single-prompt "vibe coding" lets anyone ship production web apps, but most developers lack security knowledge, and traditional scanners are too complex or noisy for them. Insecure software is now the primary vector for fraud and data breaches. AuthTrack is motivated by the opportunity to give every developer - novice or expert - a coordinated team 



# **Fr. Conceicao Rodrigues College of Engineering** 

Father Agnel Ashram, Bandstand, Bandra –west, Mumbai-50 

## **Department of Computer Engineering** 

of AI agents that finds, explains, and fixes vulnerabilities directly inside their workflow (URL, CLI, or IDE), making secure software the default rather than the exception. 

### **PROBLEM STATEMENT:** 

Modern developers - especially those using AI-assisted "vibe coding" - routinely deploy complete web applications and APIs without security review, and existing security tooling (manual pentests, enterprise scanners, or raw SAST/DAST) is either too expensive, too noisy, or too expert-dependent for them. There is a need for an intelligent, workflow-native MULTI-AGENT system that can (a) automatically discover an application's pages and API endpoints from a deployed URL and (b) perform safe, agentic security testing of those endpoints; (c) integrate into the developer's IDE via MCP to continuously scan source code; (d) explain each vulnerability in context and propose concrete, framework-specific remediations; and (e) recommend the security controls that must be added so the project is secure by design. 

### **SDGs Mapped:** 

SDG 9 – Industry, Innovation and Infrastructure (primary mapping, via AI-driven multi-agent innovation that hardens the digital software-infrastructure layer); SDG 16 – Peace, Justice and Strong Institutions (secondary mapping, via reducing cybercrime exposure and protecting citizens and institutions from insecure, vulnerability-prone applications). 

### **OBJECTIVES:** 

1. To design a multi-agent architecture (Orchestrator + specialized security agents) capable of testing both deployed web applications (by URL) and local codebases (by repository/IDE). 

2. To implement a Crawler Agent that discovers an application's pages and API endpoints from a supplied deployed URL. 

3. To build an Endpoint Tester Agent that runs strictly non-destructive, agentic OWASP testing (missing headers, broken access control, insecure cookies, information leakage, injection-prone patterns) per endpoint. 

4. To develop a Code Analyzer Agent and an MCP server that integrates with IDEs (VS Code, Cursor, Antigravity, Claude Code) to scan the codebase, suggest framework-specific fixes, and recommend required security additions. 

5. To design a Fix Generator Agent that produces framework-specific, copy-paste-ready remediation diffs from each finding. 

6. To evaluate the system using quantitative metrics: vulnerability-detection rate, false-positive rate, mean time to actionable fix, framework-coverage breadth, and MCP round-trip latency. 

### **METHODOLOGY (TENTATIVE IF ANY):** 



# **Fr. Conceicao Rodrigues College of Engineering** 

Father Agnel Ashram, Bandstand, Bandra –west, Mumbai-50 

## **Department of Computer Engineering** 

1. Data Collection & Preprocessing: Curate a benchmark of intentionally vulnerable sample apps (e.g., OWASP Juice Shop, WebGoat-style targets) and a corpus of framework-specific insecure/safe code patterns (Next.js, Django, FastAPI, Express) for evaluation and fix-suggestion tuning. 

2. Crawler Agent: Given a deployed URL, crawl discovered routes/pages and enumerate API endpoints, building a map of the attack surface for testing. 

3. Endpoint Tester Agent: Run strictly non-destructive checks (security-header analysis, cookie flags, exposure of sensitive paths, error/info leakage, access-control probes); an LLM agent reasons over responses to infer deeper weaknesses and ranks severity. 

4. Code Analyzer Agent + MCP Server: Parse the repository (AST/pattern analysis) and run an LLM agent that detects injection, SSRF, auth-bypass, and misconfiguration patterns; the MCP server streams findings into the IDE with concrete diffs and "controls to add" recommendations. 

5. Fix Generator + Orchestrator: The Fix Generator Agent converts findings into framework-specific diffs; the Orchestrator Agent merges all agent outputs into one explainable, prioritized report (issue, why, severity, fix, required additions), exposed identically through the CLI. 

6. Evaluation: Benchmark the system on vulnerability-detection rate and false-positive rate against a baseline scanner, mean time to actionable fix, framework-coverage breadth, and MCP round-trip latency across IDE integrations. 

### **HARDWARE / SOFTWARE REQUIREMENTS:** 

Hardware: Standard developer machine / cloud instance (CPU sufficient for crawling and static analysis; optional GPU/API-backed LLM for agent reasoning), minimum 8GB RAM, sufficient storage for sample apps and dependency trees. 

Software: Python (FastAPI) for the multi-agent engine; Node.js/TypeScript for the MCP server (official MCP SDK) and the web dashboard (Next.js/React); CLI in Python or Node; LangGraph/LangChain for agent orchestration; LLM API (Claude / LLaMA) for agent reasoning; static-analysis libraries (AST parsers, Semgrep-style matchers); PostgreSQL for storing scan history and benchmarks; Docker for packaging the scanner safely. 

### **INNOVATIVENESS:** 

AuthTrack innovates by coordinating a TEAM of specialized security agents - Crawler, Endpoint Tester, Code Analyzer, Fix Generator - under a single Orchestrator, rather than a single monolithic scanner. Each agent contributes a focused capability (surface mapping, runtime testing, source analysis, remediation), and the Orchestrator resolves conflicts and prioritizes findings into one explainable report. By exposing this multi-agent engine through a deployed-URL scanner, an IDE-integrated MCP server, and a CLI, AuthTrack meets developers exactly where they work - directly answering the security gap created by mass "vibe-coded" software deployment, with explainability that doubles as teaching for non-expert builders. 



# **Fr. Conceicao Rodrigues College of Engineering** 

Father Agnel Ashram, Bandstand, Bandra –west, Mumbai-50 

## **Department of Computer Engineering** 

**SOCIETAL RELEVANCE? (e.g. Health, Agriculture, Environment, Smart Solution Etc…)** AuthTrack addresses a pressing, fast-growing need created by the "vibe coding" movement: a flood of deployed web applications built without security review, exposing citizens and businesses to fraud and data breaches. By giving every developer - from student to startup - a coordinated team of AI agents that finds, explains, and fixes vulnerabilities inside their existing workflow, AuthTrack makes secure software the default, strengthening digital trust and resilience (a Smart Governance / Cyber-Security solution aligned with SDG 9 and SDG 16). 

****************** 

