"""
Utility functions for querying Upstash Vector patterns.
Used by Code Analyzer and Fix Generator agents.
"""

from typing import List, Dict, Optional
from upstash_vector import Index
from app.core.config import settings


class PatternMatcher:
    """Interface to query vulnerable and safe code patterns."""
    
    def __init__(self):
        """Initialize connection to Upstash Vector."""
        self.index = Index(
            url=settings.UPSTASH_SEARCH_REST_URL,
            token=settings.UPSTASH_SEARCH_REST_TOKEN
        )
    
    def find_vulnerable_patterns(
        self,
        code_snippet: str,
        top_k: int = 5,
        min_score: float = 0.7
    ) -> List[Dict]:
        """
        Search for similar vulnerable patterns.
        
        Used by Code Analyzer to detect known vulnerabilities.
        
        Args:
            code_snippet: Code to analyze
            top_k: Number of results to return
            min_score: Minimum similarity score (0-1)
        
        Returns:
            List of matching patterns with metadata:
            [
                {
                    "id": "uuid",
                    "score": 0.85,
                    "vuln_type": "SQL Injection",
                    "framework": "Express",
                    "severity": "critical",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021-Injection",
                    "code": "db.query('...')",
                    "pair_id": "uuid"
                },
                ...
            ]
        """
        try:
            results = self.index.query(
                data=code_snippet,
                top_k=top_k,
                include_metadata=True,
                filter="type = 'vulnerable'"
            )
            
            # Filter by minimum score and format results
            matches = []
            for result in results:
                score = result.get("score", 0)
                if score >= min_score:
                    metadata = result.get("metadata", {})
                    matches.append({
                        "id": result.get("id"),
                        "score": score,
                        "vuln_type": metadata.get("vuln_type"),
                        "framework": metadata.get("framework"),
                        "severity": metadata.get("severity"),
                        "cwe": metadata.get("cwe"),
                        "owasp": metadata.get("owasp"),
                        "language": metadata.get("language"),
                        "code": metadata.get("text"),
                        "pair_id": metadata.get("pair_id")
                    })
            
            return matches
            
        except Exception as e:
            print(f"Error querying vulnerable patterns: {e}")
            return []
    
    def find_safe_pattern(
        self,
        vulnerable_pattern_id: str
    ) -> Optional[Dict]:
        """
        Get the safe/fixed version of a vulnerable pattern.
        
        Used by Fix Generator to retrieve the secure alternative.
        
        Args:
            vulnerable_pattern_id: ID of the vulnerable pattern
        
        Returns:
            Safe pattern with metadata:
            {
                "id": "uuid",
                "code": "db.query('SELECT * FROM users WHERE id = ?', [id])",
                "fix_description": "Use parameterized queries",
                "vuln_type": "SQL Injection",
                "framework": "Express",
                "cwe": "CWE-89"
            }
        """
        try:
            # Query by metadata filter
            results = self.index.query(
                data="",  # Not used when filtering
                top_k=1,
                include_metadata=True,
                filter=f"fix_for = '{vulnerable_pattern_id}'"
            )
            
            if not results:
                return None
            
            result = results[0]
            metadata = result.get("metadata", {})
            
            return {
                "id": result.get("id"),
                "code": metadata.get("text"),
                "fix_description": metadata.get("fix_description", ""),
                "vuln_type": metadata.get("vuln_type"),
                "framework": metadata.get("framework"),
                "cwe": metadata.get("cwe"),
                "owasp": metadata.get("owasp"),
                "language": metadata.get("language")
            }
            
        except Exception as e:
            print(f"Error querying safe pattern: {e}")
            return None
    
    def search_safe_patterns(
        self,
        code_snippet: str,
        vuln_type: Optional[str] = None,
        framework: Optional[str] = None,
        top_k: int = 3
    ) -> List[Dict]:
        """
        Search for safe code patterns by similarity or metadata.
        
        Used by Fix Generator when no direct match exists.
        
        Args:
            code_snippet: Vulnerable code to fix
            vuln_type: Filter by vulnerability type (optional)
            framework: Filter by framework (optional)
            top_k: Number of results
        
        Returns:
            List of safe patterns
        """
        try:
            # Build filter
            filters = ["type = 'safe'"]
            if vuln_type:
                filters.append(f"vuln_type = '{vuln_type}'")
            if framework:
                filters.append(f"framework = '{framework}'")
            
            filter_str = " AND ".join(filters)
            
            results = self.index.query(
                data=code_snippet,
                top_k=top_k,
                include_metadata=True,
                filter=filter_str
            )
            
            matches = []
            for result in results:
                metadata = result.get("metadata", {})
                matches.append({
                    "id": result.get("id"),
                    "score": result.get("score", 0),
                    "code": metadata.get("text"),
                    "fix_description": metadata.get("fix_description", ""),
                    "vuln_type": metadata.get("vuln_type"),
                    "framework": metadata.get("framework"),
                    "fix_for": metadata.get("fix_for")
                })
            
            return matches
            
        except Exception as e:
            print(f"Error searching safe patterns: {e}")
            return []


# Example usage for agents
def example_code_analyzer_usage():
    """Example: How Code Analyzer uses pattern matching."""
    matcher = PatternMatcher()
    
    # Code snippet from static analysis
    suspicious_code = 'db.query("SELECT * FROM users WHERE email = " + userEmail)'
    
    # Find similar vulnerable patterns
    matches = matcher.find_vulnerable_patterns(
        code_snippet=suspicious_code,
        top_k=3,
        min_score=0.75
    )
    
    if matches:
        best_match = matches[0]
        print(f"⚠️  Potential {best_match['vuln_type']} detected!")
        print(f"   Confidence: {best_match['score']:.2%}")
        print(f"   CWE: {best_match['cwe']}")
        print(f"   Framework: {best_match['framework']}")
        
        # Use this as evidence for triage LLM
        evidence = {
            "suspicious_code": suspicious_code,
            "matched_pattern": best_match['code'],
            "vuln_type": best_match['vuln_type'],
            "confidence": best_match['score']
        }
        
        return evidence
    else:
        print("✅ No known vulnerabilities detected")
        return None


def example_fix_generator_usage():
    """Example: How Fix Generator uses pattern matching."""
    matcher = PatternMatcher()
    
    # After confirming vulnerability, get safe pattern
    vuln_pattern_id = "some-uuid-from-finding"
    
    safe_pattern = matcher.find_safe_pattern(vuln_pattern_id)
    
    if safe_pattern:
        print(f"🔧 Found fix for {safe_pattern['vuln_type']}")
        print(f"   Safe code: {safe_pattern['code']}")
        print(f"   Explanation: {safe_pattern['fix_description']}")
        
        # LLM adapts this to the specific context
        fix_prompt = f"""
        Vulnerability: {safe_pattern['vuln_type']}
        
        Generic vulnerable pattern:
        {safe_pattern['code']}
        
        Fix approach:
        {safe_pattern['fix_description']}
        
        Now adapt this fix to the user's specific code...
        """
        
        return fix_prompt
    else:
        print("⚠️  No direct fix pattern found, using fallback")
        
        # Fallback: search by vulnerability type
        safe_patterns = matcher.search_safe_patterns(
            code_snippet="vulnerable code here",
            vuln_type="SQL Injection",
            top_k=3
        )
        
        return safe_patterns


if __name__ == "__main__":
    print("Example: Code Analyzer")
    print("=" * 60)
    example_code_analyzer_usage()
    
    print("\n\nExample: Fix Generator")
    print("=" * 60)
    example_fix_generator_usage()
