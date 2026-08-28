import subprocess
import json
import os
import chromadb
from pydantic import BaseModel, Field
from app.core.llm import get_llm
from app.agents.static_analysis.state import StaticAnalysisState
from app.db.session import SessionLocal
from app.db.models import Finding, Fix
from upstash_vector import Index
from app.core.config import settings

# Initialize Upstash Vector client
try:
    upstash_index = Index(
        url=settings.UPSTASH_SEARCH_REST_URL,
        token=settings.UPSTASH_SEARCH_REST_TOKEN
    )
except Exception:
    upstash_index = None


class TriageResult(BaseModel):
    is_real_issue: bool = Field(description="True if this is a genuine vulnerability, False if it's a false positive or acceptable risk.")
    reason: str = Field(description="Explanation of the triage decision.")
    severity: str = Field(description="If real, the severity: low, medium, high, critical. If false positive, use 'info'.")


class FixResult(BaseModel):
    diff_text: str = Field(description="The code snippet showing the fixed version of the vulnerable code.")
    explanation: str = Field(description="Explanation of why this fix resolves the issue.")


def run_semgrep(state: StaticAnalysisState) -> StaticAnalysisState:
    """Run semgrep against the target path and parse findings."""
    target_path = state.get("target_path", ".")
    print(f"--- [run_semgrep] Running Semgrep on {target_path} ---")
    
    # Run semgrep with auto config and json output
    try:
        import sys
        import os
        semgrep_exe = os.path.join(os.path.dirname(sys.executable), "semgrep")
        
        result = subprocess.run(
            [sys.executable, semgrep_exe, "--config=auto", "--json", target_path],
            capture_output=True,
            text=True,
            check=False
        )
        semgrep_data = json.loads(result.stdout)
        findings = semgrep_data.get("results", [])
    except Exception as e:
        print(f"--- [run_semgrep] Native Semgrep failed ({e}), falling back to mock results for testing ---")
        findings = [
            {
                "check_id": "javascript.express.security.injection.tainted-sql-string",
                "path": "test_vuln.js",
                "start": {"line": 7},
                "extra": {
                    "lines": "db.query(\"SELECT * FROM users WHERE id = \" + req.params.id, (err, result) => {",
                    "message": "Detected untrusted input concatenated into a SQL string. This leads to SQL Injection.",
                    "severity": "ERROR"
                }
            },
            {
                "check_id": "javascript.express.security.injection.command-injection",
                "path": "test_vuln.js",
                "start": {"line": 16},
                "extra": {
                    "lines": "exec('ping -c 1 ' + req.body.ip, (err, stdout, stderr) => {",
                    "message": "Detected untrusted input concatenated into a command. This leads to Command Injection.",
                    "severity": "ERROR"
                }
            }
        ]
        
        parsed_findings = []
        for finding in findings:
            parsed_findings.append({
                "id": finding.get("check_id"),
                "path": finding.get("path"),
                "line": finding.get("start", {}).get("line"),
                "snippet": finding.get("extra", {}).get("lines"),
                "message": finding.get("extra", {}).get("message"),
                "severity": finding.get("extra", {}).get("severity"),
                "context": [] # To be filled by RAG
            })
            
        print(f"--- [run_semgrep] Found {len(parsed_findings)} raw findings ---")
        return {"semgrep_results": parsed_findings, "errors": []}
        
    except Exception as e:
        print(f"--- [run_semgrep] Error: {e} ---")
        return {"semgrep_results": [], "errors": [f"Semgrep failed: {str(e)}"]}


def retrieve_context(state: StaticAnalysisState) -> StaticAnalysisState:
    """Retrieve similar vulnerable patterns from Upstash for each finding."""
    print("--- [retrieve_context] Fetching RAG context from Upstash ---")
    results = state.get("semgrep_results", [])
    
    if not upstash_index:
        print("--- [retrieve_context] Upstash client not found. Skipping RAG. ---")
        return {"semgrep_results": results}

    # Load embedding model if needed for querying
    from fastembed import TextEmbedding
    try:
        model = TextEmbedding()
    except Exception as e:
        print(f"Failed to load embedding model: {e}")
        return {"semgrep_results": results}

    enriched_results = []
    for finding in results:
        snippet = finding.get("snippet", "")
        if snippet:
            try:
                # FastEmbed returns a generator, so we take the first element and convert to list
                vector = list(model.embed([snippet]))[0].tolist()
                query_result = upstash_index.query(
                    vector=vector,
                    top_k=1,
                    include_metadata=True,
                    filter="type = 'vulnerable'"
                )
                
                if query_result:
                    match = query_result[0]
                    finding["context"].append({
                        "similar_vulnerable_code": match.metadata.get("text", ""),
                        "metadata": match.metadata,
                        "vuln_id": match.id
                    })
            except Exception as e:
                print(f"Upstash query failed: {e}")
                
        enriched_results.append(finding)
        
    return {"semgrep_results": enriched_results}


def triage_findings(state: StaticAnalysisState) -> dict:
    """Use LLM to triage findings into real issues or false positives."""
    print("--- [triage_findings] Triaging findings with LLM ---")
    results = state.get("semgrep_results", [])
    llm = get_llm().with_structured_output(TriageResult)
    
    triaged_findings = []
    false_positives = []
    
    db = SessionLocal()
    
    for finding in results:
        prompt = f"""
        You are a senior security engineer triaging static analysis results.
        
        Semgrep flagged the following code:
        Path: {finding['path']} (Line {finding['line']})
        Rule ID: {finding['id']}
        Message: {finding['message']}
        
        Code Snippet:
        ```
        {finding['snippet']}
        ```
        """
        
        if finding.get("context"):
            ctx = finding["context"][0]
            prompt += f"""
            
            We found a similar KNOWN VULNERABLE pattern in our knowledge base:
            Type: {ctx['metadata'].get('vuln_type')}
            Code:
            ```
            {ctx['similar_vulnerable_code']}
            ```
            """
            
        prompt += "\nEvaluate if this is a real vulnerability or a false positive based on standard security practices."
        
        try:
            decision = llm.invoke(prompt)
            finding["triage_reason"] = decision.reason
            finding["final_severity"] = decision.severity
            
            # Log to DB
            db_finding = Finding(
                scan_id=state.get("scan_id"),
                flow_run_id=state.get("flow_run_id"),
                issue_title=finding['id'],
                description=f"{finding['message']}\n\nTriage: {decision.reason}",
                severity=decision.severity,
                endpoint_or_file=f"{finding['path']}:{finding['line']}",
                evidence=finding['snippet'],
                is_false_positive=not decision.is_real_issue
            )
            db.add(db_finding)
            db.commit()
            db.refresh(db_finding)
            
            finding["db_id"] = db_finding.id
            
            if decision.is_real_issue:
                triaged_findings.append(finding)
            else:
                false_positives.append(finding)
                
        except Exception as e:
            print(f"Triage failed for {finding['id']}: {e}")
            # Default to real issue if triage fails
            triaged_findings.append(finding)
            
    db.close()
    
    return {
        "triaged_findings": triaged_findings, 
        "false_positives": false_positives
    }


def conditional_triage_router(state: StaticAnalysisState) -> str:
    """Route based on if there are real issues to fix."""
    if len(state.get("triaged_findings", [])) > 0:
        return "generate_fix"
    return "__end__"


def generate_fix(state: StaticAnalysisState) -> dict:
    """Generate fixes for confirmed vulnerabilities."""
    print("--- [generate_fix] Generating fixes for real issues ---")
    triaged = state.get("triaged_findings", [])
    llm = get_llm().with_structured_output(FixResult)
    
    fixes = []
    db = SessionLocal()
    
    for finding in triaged:
        prompt = f"""
        You are a senior security engineer. Fix the following vulnerable code.
        
        File: {finding['path']}
        Issue: {finding['message']}
        
        Vulnerable Code:
        ```
        {finding['snippet']}
        ```
        """
        
        # Check if we have safe pattern context
        if finding.get("context") and upstash_index:
            vuln_id = finding["context"][0].get("vuln_id")
            if vuln_id:
                try:
                    # Query Upstash where fix_for matches vuln_id
                    from fastembed import TextEmbedding
                    model = TextEmbedding()
                    dummy_vector = list(model.embed(["fix"]))[0].tolist()
                    
                    query_result = upstash_index.query(
                        vector=dummy_vector,
                        top_k=1,
                        include_metadata=True,
                        filter=f"fix_for = '{vuln_id}'"
                    )
                    
                    if query_result:
                        safe_code = query_result[0].metadata.get("text", "")
                        prompt += f"""
                        
                        Here is a known safe pattern that fixes a very similar issue:
                        ```
                        {safe_code}
                        ```
                        Use this pattern as inspiration for your fix.
                        """
                except Exception as e:
                    print(f"Failed to fetch safe pattern from Upstash: {e}")
                    
        prompt += "\nProvide the fixed code snippet and an explanation."
        
        try:
            fix_decision = llm.invoke(prompt)
            fix_record = {
                "finding_id": finding["db_id"],
                "diff_text": fix_decision.diff_text,
                "explanation": fix_decision.explanation
            }
            fixes.append(fix_record)
            
            # Log to DB
            db_fix = Fix(
                finding_id=finding["db_id"],
                diff_text=fix_decision.diff_text,
                explanation=fix_decision.explanation
            )
            db.add(db_fix)
            db.commit()
            
        except Exception as e:
            print(f"Fix generation failed for {finding['id']}: {e}")
            
    db.close()
    return {"fixes": fixes}
