"""
Seed ChromaDB with vulnerable and safe code patterns.
Two collections:
1. vulnerable_patterns - Known vulnerable code snippets with metadata
2. safe_patterns - Fixed/secure versions with links to vulnerable patterns
"""

import chromadb
from chromadb.config import Settings
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings


# Vulnerable code patterns from OWASP, CVEs, and intentionally vulnerable apps
VULNERABLE_PATTERNS = [
    # SQL Injection patterns
    {
        "id": "vuln_001",
        "code": 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
        "metadata": {
            "vuln_type": "SQL Injection",
            "framework": "Express",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "description": "String concatenation in SQL query enables SQL injection"
        }
    },
    {
        "id": "vuln_002",
        "code": 'cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\'")',
        "metadata": {
            "vuln_type": "SQL Injection",
            "framework": "Django",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "description": "F-string formatting in SQL query enables SQL injection"
        }
    },
    {
        "id": "vuln_003",
        "code": 'query := "SELECT * FROM products WHERE category = \'" + category + "\'"',
        "metadata": {
            "vuln_type": "SQL Injection",
            "framework": "Generic",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "Go",
            "description": "String concatenation in SQL query"
        }
    },
    
    # XSS patterns
    {
        "id": "vuln_004",
        "code": 'document.getElementById("output").innerHTML = userInput;',
        "metadata": {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Vanilla JS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "description": "innerHTML with unsanitized user input enables XSS"
        }
    },
    {
        "id": "vuln_005",
        "code": '<div dangerouslySetInnerHTML={{__html: props.userContent}} />',
        "metadata": {
            "vuln_type": "Cross-Site Scripting",
            "framework": "React",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "description": "dangerouslySetInnerHTML with user content"
        }
    },
    {
        "id": "vuln_006",
        "code": 'return render_template_string(f"<h1>Hello {name}</h1>")',
        "metadata": {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Flask",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "description": "Unescaped user input in template string"
        }
    },
    
    # Path Traversal patterns
    {
        "id": "vuln_007",
        "code": 'const filePath = path.join(__dirname, "uploads", req.params.filename);\nres.sendFile(filePath);',
        "metadata": {
            "vuln_type": "Path Traversal",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-22",
            "owasp": "A01:2021-Broken Access Control",
            "language": "JavaScript",
            "description": "Unsanitized filename parameter allows directory traversal"
        }
    },
    {
        "id": "vuln_008",
        "code": 'with open(f"/var/data/{filename}", "r") as f:\n    return f.read()',
        "metadata": {
            "vuln_type": "Path Traversal",
            "framework": "FastAPI",
            "severity": "high",
            "cwe": "CWE-22",
            "owasp": "A01:2021-Broken Access Control",
            "language": "Python",
            "description": "Unsanitized filename in file path"
        }
    },
    
    # Command Injection patterns
    {
        "id": "vuln_009",
        "code": 'exec(`ping -c 4 ${req.body.host}`)',
        "metadata": {
            "vuln_type": "Command Injection",
            "framework": "Node.js",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "description": "User input directly in shell command"
        }
    },
    {
        "id": "vuln_010",
        "code": 'os.system("ping -c 4 " + host)',
        "metadata": {
            "vuln_type": "Command Injection",
            "framework": "Generic",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "description": "String concatenation in system command"
        }
    },
    
    # Insecure Deserialization patterns
    {
        "id": "vuln_011",
        "code": 'const userData = eval(req.cookies.session);',
        "metadata": {
            "vuln_type": "Insecure Deserialization",
            "framework": "Express",
            "severity": "critical",
            "cwe": "CWE-502",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "language": "JavaScript",
            "description": "eval() on user-controlled data"
        }
    },
    {
        "id": "vuln_012",
        "code": 'user_data = pickle.loads(request.get_data())',
        "metadata": {
            "vuln_type": "Insecure Deserialization",
            "framework": "Flask",
            "severity": "critical",
            "cwe": "CWE-502",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "language": "Python",
            "description": "pickle.loads on untrusted data"
        }
    },
    
    # Broken Authentication patterns
    {
        "id": "vuln_013",
        "code": 'const token = jwt.sign({userId: user.id}, "hardcoded-secret");',
        "metadata": {
            "vuln_type": "Broken Authentication",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "JavaScript",
            "description": "Hardcoded JWT secret"
        }
    },
    {
        "id": "vuln_014",
        "code": 'if (password == user.password):\n    login_user(user)',
        "metadata": {
            "vuln_type": "Broken Authentication",
            "framework": "Generic",
            "severity": "critical",
            "cwe": "CWE-256",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "Python",
            "description": "Plain text password comparison"
        }
    },
    
    # SSRF patterns
    {
        "id": "vuln_015",
        "code": 'const response = await axios.get(req.query.url);',
        "metadata": {
            "vuln_type": "Server-Side Request Forgery",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "language": "JavaScript",
            "description": "Unvalidated URL from user input"
        }
    },
    {
        "id": "vuln_016",
        "code": 'response = requests.get(url)',
        "metadata": {
            "vuln_type": "Server-Side Request Forgery",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "language": "Python",
            "description": "Unvalidated URL parameter"
        }
    },
    
    # Insecure Cryptography patterns
    {
        "id": "vuln_017",
        "code": 'const hash = crypto.createHash("md5").update(password).digest("hex");',
        "metadata": {
            "vuln_type": "Weak Cryptography",
            "framework": "Node.js",
            "severity": "high",
            "cwe": "CWE-327",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "JavaScript",
            "description": "MD5 used for password hashing"
        }
    },
    {
        "id": "vuln_018",
        "code": 'password_hash = hashlib.md5(password.encode()).hexdigest()',
        "metadata": {
            "vuln_type": "Weak Cryptography",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-327",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "Python",
            "description": "MD5 used for password hashing"
        }
    },
    
    # Sensitive Data Exposure patterns
    {
        "id": "vuln_019",
        "code": 'console.log("User login:", username, password);',
        "metadata": {
            "vuln_type": "Sensitive Data Exposure",
            "framework": "Generic",
            "severity": "medium",
            "cwe": "CWE-532",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "JavaScript",
            "description": "Logging sensitive credentials"
        }
    },
    {
        "id": "vuln_020",
        "code": 'return JsonResponse({"user": user, "password": user.password})',
        "metadata": {
            "vuln_type": "Sensitive Data Exposure",
            "framework": "Django",
            "severity": "high",
            "cwe": "CWE-200",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "Python",
            "description": "Exposing password in API response"
        }
    },
    
    # CORS Misconfiguration patterns
    {
        "id": "vuln_021",
        "code": 'res.setHeader("Access-Control-Allow-Origin", "*");',
        "metadata": {
            "vuln_type": "CORS Misconfiguration",
            "framework": "Express",
            "severity": "medium",
            "cwe": "CWE-942",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "JavaScript",
            "description": "Wildcard CORS origin"
        }
    },
    {
        "id": "vuln_022",
        "code": 'response["Access-Control-Allow-Origin"] = request.headers.get("Origin")',
        "metadata": {
            "vuln_type": "CORS Misconfiguration",
            "framework": "Django",
            "severity": "medium",
            "cwe": "CWE-942",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "Python",
            "description": "Reflecting origin without validation"
        }
    },
    
    # JWT vulnerabilities
    {
        "id": "vuln_023",
        "code": 'const decoded = jwt.decode(token, {complete: true});',
        "metadata": {
            "vuln_type": "Broken Authentication",
            "framework": "Node.js",
            "severity": "critical",
            "cwe": "CWE-347",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "JavaScript",
            "description": "JWT decoded without signature verification"
        }
    },
    
    # NoSQL Injection patterns
    {
        "id": "vuln_024",
        "code": 'User.findOne({username: req.body.username, password: req.body.password})',
        "metadata": {
            "vuln_type": "NoSQL Injection",
            "framework": "MongoDB",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "description": "Direct user input in MongoDB query"
        }
    },
    
    # XML External Entity (XXE) patterns
    {
        "id": "vuln_025",
        "code": 'const doc = libxmljs.parseXml(userXml);',
        "metadata": {
            "vuln_type": "XML External Entity",
            "framework": "Node.js",
            "severity": "high",
            "cwe": "CWE-611",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "JavaScript",
            "description": "XML parsing without disabling external entities"
        }
    },
    
    # Insecure File Upload patterns
    {
        "id": "vuln_026",
        "code": 'file.mv(`./uploads/${file.name}`, (err) => {});',
        "metadata": {
            "vuln_type": "Unrestricted File Upload",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-434",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript",
            "description": "No file type validation on upload"
        }
    },
    
    # LDAP Injection patterns
    {
        "id": "vuln_027",
        "code": 'const filter = `(uid=${username})`;',
        "metadata": {
            "vuln_type": "LDAP Injection",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-90",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "description": "Unsanitized input in LDAP filter"
        }
    },
    
    # Mass Assignment patterns
    {
        "id": "vuln_028",
        "code": 'user.update(req.body)',
        "metadata": {
            "vuln_type": "Mass Assignment",
            "framework": "Express",
            "severity": "high",
            "cwe": "CWE-915",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript",
            "description": "Unfiltered request body update"
        }
    },
    
    # Server-Side Template Injection patterns
    {
        "id": "vuln_029",
        "code": 'Template(request.args.get("template")).render()',
        "metadata": {
            "vuln_type": "Server-Side Template Injection",
            "framework": "Jinja2",
            "severity": "critical",
            "cwe": "CWE-94",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "description": "User input as template string"
        }
    },
    
    # Race Condition patterns
    {
        "id": "vuln_030",
        "code": 'if (user.balance >= amount) {\n  // delay...\n  user.balance -= amount;\n}',
        "metadata": {
            "vuln_type": "Race Condition",
            "framework": "Generic",
            "severity": "high",
            "cwe": "CWE-362",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript",
            "description": "Time-of-check to time-of-use vulnerability"
        }
    },
]


# Safe/fixed code patterns
SAFE_PATTERNS = [
    # SQL Injection fixes
    {
        "id": "safe_001",
        "code": 'db.query("SELECT * FROM users WHERE id = ?", [req.params.id])',
        "metadata": {
            "vuln_type": "SQL Injection",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "fix_for": "vuln_001",
            "fix_description": "Use parameterized query with placeholders"
        }
    },
    {
        "id": "safe_002",
        "code": 'cursor.execute("SELECT * FROM users WHERE username = %s", [username])',
        "metadata": {
            "vuln_type": "SQL Injection",
            "framework": "Django",
            "severity": "safe",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "fix_for": "vuln_002",
            "fix_description": "Use parameterized query with placeholders"
        }
    },
    {
        "id": "safe_003",
        "code": 'query := "SELECT * FROM products WHERE category = $1"\nrows, err := db.Query(query, category)',
        "metadata": {
            "vuln_type": "SQL Injection",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "Go",
            "fix_for": "vuln_003",
            "fix_description": "Use parameterized query"
        }
    },
    
    # XSS fixes
    {
        "id": "safe_004",
        "code": 'document.getElementById("output").textContent = userInput;',
        "metadata": {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Vanilla JS",
            "severity": "safe",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "fix_for": "vuln_004",
            "fix_description": "Use textContent instead of innerHTML to prevent script execution"
        }
    },
    {
        "id": "safe_005",
        "code": 'import DOMPurify from "dompurify";\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(props.userContent)}} />',
        "metadata": {
            "vuln_type": "Cross-Site Scripting",
            "framework": "React",
            "severity": "safe",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "fix_for": "vuln_005",
            "fix_description": "Sanitize HTML content with DOMPurify before rendering"
        }
    },
    {
        "id": "safe_006",
        "code": 'from markupsafe import escape\nreturn f"<h1>Hello {escape(name)}</h1>"',
        "metadata": {
            "vuln_type": "Cross-Site Scripting",
            "framework": "Flask",
            "severity": "safe",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "fix_for": "vuln_006",
            "fix_description": "Escape user input before rendering"
        }
    },
    
    # Path Traversal fixes
    {
        "id": "safe_007",
        "code": 'const filename = path.basename(req.params.filename);\nconst filePath = path.join(__dirname, "uploads", filename);\nif (!filePath.startsWith(path.join(__dirname, "uploads"))) throw new Error("Invalid path");\nres.sendFile(filePath);',
        "metadata": {
            "vuln_type": "Path Traversal",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-22",
            "owasp": "A01:2021-Broken Access Control",
            "language": "JavaScript",
            "fix_for": "vuln_007",
            "fix_description": "Sanitize filename with path.basename and verify resolved path"
        }
    },
    {
        "id": "safe_008",
        "code": 'import os\nfilename = os.path.basename(filename)\nsafe_path = os.path.join("/var/data", filename)\nif not os.path.realpath(safe_path).startswith("/var/data"):\n    raise ValueError("Invalid path")\nwith open(safe_path, "r") as f:\n    return f.read()',
        "metadata": {
            "vuln_type": "Path Traversal",
            "framework": "FastAPI",
            "severity": "safe",
            "cwe": "CWE-22",
            "owasp": "A01:2021-Broken Access Control",
            "language": "Python",
            "fix_for": "vuln_008",
            "fix_description": "Sanitize filename and validate resolved path"
        }
    },
    
    # Command Injection fixes
    {
        "id": "safe_009",
        "code": 'const { execFile } = require("child_process");\nexecFile("ping", ["-c", "4", req.body.host])',
        "metadata": {
            "vuln_type": "Command Injection",
            "framework": "Node.js",
            "severity": "safe",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "fix_for": "vuln_009",
            "fix_description": "Use execFile with argument array instead of shell interpolation"
        }
    },
    {
        "id": "safe_010",
        "code": 'import subprocess\nsubprocess.run(["ping", "-c", "4", host], check=True)',
        "metadata": {
            "vuln_type": "Command Injection",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "fix_for": "vuln_010",
            "fix_description": "Use subprocess.run with list arguments, not shell=True"
        }
    },
    
    # Insecure Deserialization fixes
    {
        "id": "safe_011",
        "code": 'const userData = JSON.parse(req.cookies.session);',
        "metadata": {
            "vuln_type": "Insecure Deserialization",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-502",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "language": "JavaScript",
            "fix_for": "vuln_011",
            "fix_description": "Use JSON.parse instead of eval for data deserialization"
        }
    },
    {
        "id": "safe_012",
        "code": 'import json\nuser_data = json.loads(request.get_data())',
        "metadata": {
            "vuln_type": "Insecure Deserialization",
            "framework": "Flask",
            "severity": "safe",
            "cwe": "CWE-502",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "language": "Python",
            "fix_for": "vuln_012",
            "fix_description": "Use JSON instead of pickle for untrusted data"
        }
    },
    
    # Broken Authentication fixes
    {
        "id": "safe_013",
        "code": 'const token = jwt.sign({userId: user.id}, process.env.JWT_SECRET);',
        "metadata": {
            "vuln_type": "Broken Authentication",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "JavaScript",
            "fix_for": "vuln_013",
            "fix_description": "Use environment variable for JWT secret"
        }
    },
    {
        "id": "safe_014",
        "code": 'import bcrypt\nif bcrypt.checkpw(password.encode(), user.password_hash):\n    login_user(user)',
        "metadata": {
            "vuln_type": "Broken Authentication",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-256",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "Python",
            "fix_for": "vuln_014",
            "fix_description": "Use bcrypt for password hashing and comparison"
        }
    },
    
    # SSRF fixes
    {
        "id": "safe_015",
        "code": 'const allowedHosts = ["api.example.com", "trusted.com"];\nconst url = new URL(req.query.url);\nif (!allowedHosts.includes(url.hostname)) throw new Error("Invalid host");\nconst response = await axios.get(url.toString());',
        "metadata": {
            "vuln_type": "Server-Side Request Forgery",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "language": "JavaScript",
            "fix_for": "vuln_015",
            "fix_description": "Validate URL against allowlist of trusted hosts"
        }
    },
    {
        "id": "safe_016",
        "code": 'from urllib.parse import urlparse\nallowed_hosts = ["api.example.com", "trusted.com"]\nparsed = urlparse(url)\nif parsed.hostname not in allowed_hosts:\n    raise ValueError("Invalid host")\nresponse = requests.get(url)',
        "metadata": {
            "vuln_type": "Server-Side Request Forgery",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "language": "Python",
            "fix_for": "vuln_016",
            "fix_description": "Validate URL hostname against allowlist"
        }
    },
    
    # Insecure Cryptography fixes
    {
        "id": "safe_017",
        "code": 'const bcrypt = require("bcrypt");\nconst hash = await bcrypt.hash(password, 10);',
        "metadata": {
            "vuln_type": "Weak Cryptography",
            "framework": "Node.js",
            "severity": "safe",
            "cwe": "CWE-327",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "JavaScript",
            "fix_for": "vuln_017",
            "fix_description": "Use bcrypt instead of MD5 for password hashing"
        }
    },
    {
        "id": "safe_018",
        "code": 'import bcrypt\npassword_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
        "metadata": {
            "vuln_type": "Weak Cryptography",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-327",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "Python",
            "fix_for": "vuln_018",
            "fix_description": "Use bcrypt instead of MD5 for password hashing"
        }
    },
    
    # Sensitive Data Exposure fixes
    {
        "id": "safe_019",
        "code": 'console.log("User login:", username);',
        "metadata": {
            "vuln_type": "Sensitive Data Exposure",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-532",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "JavaScript",
            "fix_for": "vuln_019",
            "fix_description": "Never log sensitive credentials like passwords"
        }
    },
    {
        "id": "safe_020",
        "code": 'user_data = {k: v for k, v in user.__dict__.items() if k != "password"}\nreturn JsonResponse({"user": user_data})',
        "metadata": {
            "vuln_type": "Sensitive Data Exposure",
            "framework": "Django",
            "severity": "safe",
            "cwe": "CWE-200",
            "owasp": "A02:2021-Cryptographic Failures",
            "language": "Python",
            "fix_for": "vuln_020",
            "fix_description": "Exclude sensitive fields from API responses"
        }
    },
    
    # CORS Misconfiguration fixes
    {
        "id": "safe_021",
        "code": 'const allowedOrigins = ["https://myapp.com"];\nif (allowedOrigins.includes(req.headers.origin)) {\n  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n}',
        "metadata": {
            "vuln_type": "CORS Misconfiguration",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-942",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "JavaScript",
            "fix_for": "vuln_021",
            "fix_description": "Validate origin against allowlist instead of wildcard"
        }
    },
    {
        "id": "safe_022",
        "code": 'allowed_origins = ["https://myapp.com"]\norigin = request.headers.get("Origin")\nif origin in allowed_origins:\n    response["Access-Control-Allow-Origin"] = origin',
        "metadata": {
            "vuln_type": "CORS Misconfiguration",
            "framework": "Django",
            "severity": "safe",
            "cwe": "CWE-942",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "Python",
            "fix_for": "vuln_022",
            "fix_description": "Validate origin against allowlist before reflecting"
        }
    },
    
    # JWT vulnerability fixes
    {
        "id": "safe_023",
        "code": 'const decoded = jwt.verify(token, process.env.JWT_SECRET);',
        "metadata": {
            "vuln_type": "Broken Authentication",
            "framework": "Node.js",
            "severity": "safe",
            "cwe": "CWE-347",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "language": "JavaScript",
            "fix_for": "vuln_023",
            "fix_description": "Use jwt.verify to validate signature"
        }
    },
    
    # NoSQL Injection fixes
    {
        "id": "safe_024",
        "code": 'User.findOne({\n  username: {$eq: req.body.username},\n  password: {$eq: req.body.password}\n})',
        "metadata": {
            "vuln_type": "NoSQL Injection",
            "framework": "MongoDB",
            "severity": "safe",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "fix_for": "vuln_024",
            "fix_description": "Use explicit query operators to prevent injection"
        }
    },
    
    # XXE fixes
    {
        "id": "safe_025",
        "code": 'const doc = libxmljs.parseXml(userXml, {noent: false, dtdload: false});',
        "metadata": {
            "vuln_type": "XML External Entity",
            "framework": "Node.js",
            "severity": "safe",
            "cwe": "CWE-611",
            "owasp": "A05:2021-Security Misconfiguration",
            "language": "JavaScript",
            "fix_for": "vuln_025",
            "fix_description": "Disable external entities in XML parser"
        }
    },
    
    # Insecure File Upload fixes
    {
        "id": "safe_026",
        "code": 'const allowedTypes = [".jpg", ".png", ".pdf"];\nconst ext = path.extname(file.name).toLowerCase();\nif (!allowedTypes.includes(ext)) throw new Error("Invalid file type");\nfile.mv(`./uploads/${file.name}`, (err) => {});',
        "metadata": {
            "vuln_type": "Unrestricted File Upload",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-434",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript",
            "fix_for": "vuln_026",
            "fix_description": "Validate file extensions against allowlist"
        }
    },
    
    # LDAP Injection fixes
    {
        "id": "safe_027",
        "code": 'const sanitized = username.replace(/[^a-zA-Z0-9]/g, "");\nconst filter = `(uid=${sanitized})`;',
        "metadata": {
            "vuln_type": "LDAP Injection",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-90",
            "owasp": "A03:2021-Injection",
            "language": "JavaScript",
            "fix_for": "vuln_027",
            "fix_description": "Sanitize input before using in LDAP filter"
        }
    },
    
    # Mass Assignment fixes
    {
        "id": "safe_028",
        "code": 'const allowedFields = ["name", "email"];\nconst updates = {};\nallowedFields.forEach(f => {\n  if (req.body[f]) updates[f] = req.body[f];\n});\nuser.update(updates);',
        "metadata": {
            "vuln_type": "Mass Assignment",
            "framework": "Express",
            "severity": "safe",
            "cwe": "CWE-915",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript",
            "fix_for": "vuln_028",
            "fix_description": "Filter request body to allowed fields only"
        }
    },
    
    # SSTI fixes
    {
        "id": "safe_029",
        "code": 'from markupsafe import escape\ntemplate_str = "Hello {{ name }}"\nTemplate(template_str).render(name=escape(request.args.get("name")))',
        "metadata": {
            "vuln_type": "Server-Side Template Injection",
            "framework": "Jinja2",
            "severity": "safe",
            "cwe": "CWE-94",
            "owasp": "A03:2021-Injection",
            "language": "Python",
            "fix_for": "vuln_029",
            "fix_description": "Use predefined templates and escape user input"
        }
    },
    
    # Race Condition fixes
    {
        "id": "safe_030",
        "code": 'await db.transaction(async (trx) => {\n  const user = await trx("users").where({id}).forUpdate().first();\n  if (user.balance >= amount) {\n    await trx("users").where({id}).decrement("balance", amount);\n  }\n});',
        "metadata": {
            "vuln_type": "Race Condition",
            "framework": "Generic",
            "severity": "safe",
            "cwe": "CWE-362",
            "owasp": "A04:2021-Insecure Design",
            "language": "JavaScript",
            "fix_for": "vuln_030",
            "fix_description": "Use database transaction with row-level locking"
        }
    },
]


def seed_collections():
    """Seed ChromaDB with vulnerable and safe code patterns."""
    
    print("🚀 Connecting to ChromaDB...")
    
    # Connect to ChromaDB
    if settings.CHROMADB_HOST == "localhost":
        # Use persistent client for local storage
        client = chromadb.PersistentClient(path="./chroma_db")
    else:
        # Use HTTP client for remote ChromaDB
        client = chromadb.HttpClient(
            host=settings.CHROMADB_HOST,
            port=settings.CHROMADB_PORT
        )
    
    print(f"✅ Connected to ChromaDB at {settings.CHROMADB_HOST}:{settings.CHROMADB_PORT}")
    
    # Delete existing collections if they exist
    try:
        client.delete_collection("vulnerable_patterns")
        print("🗑️  Deleted existing vulnerable_patterns collection")
    except:
        pass
    
    try:
        client.delete_collection("safe_patterns")
        print("🗑️  Deleted existing safe_patterns collection")
    except:
        pass
    
    # Create collections
    print("\n📦 Creating collections...")
    vulnerable_collection = client.create_collection(
        name="vulnerable_patterns",
        metadata={"description": "Known vulnerable code patterns from OWASP and CVEs"}
    )
    
    safe_collection = client.create_collection(
        name="safe_patterns",
        metadata={"description": "Fixed/secure code patterns corresponding to vulnerabilities"}
    )
    
    print("✅ Collections created")
    
    # Seed vulnerable patterns
    print(f"\n🔴 Seeding {len(VULNERABLE_PATTERNS)} vulnerable patterns...")
    vulnerable_ids = [p["id"] for p in VULNERABLE_PATTERNS]
    vulnerable_codes = [p["code"] for p in VULNERABLE_PATTERNS]
    vulnerable_metadata = [p["metadata"] for p in VULNERABLE_PATTERNS]
    
    vulnerable_collection.add(
        ids=vulnerable_ids,
        documents=vulnerable_codes,
        metadatas=vulnerable_metadata
    )
    
    print(f"✅ Seeded {len(VULNERABLE_PATTERNS)} vulnerable patterns")
    
    # Seed safe patterns
    print(f"\n🟢 Seeding {len(SAFE_PATTERNS)} safe patterns...")
    safe_ids = [p["id"] for p in SAFE_PATTERNS]
    safe_codes = [p["code"] for p in SAFE_PATTERNS]
    safe_metadata = [p["metadata"] for p in SAFE_PATTERNS]
    
    safe_collection.add(
        ids=safe_ids,
        documents=safe_codes,
        metadatas=safe_metadata
    )
    
    print(f"✅ Seeded {len(SAFE_PATTERNS)} safe patterns")
    
    # Verify
    print("\n🔍 Verifying collections...")
    vuln_count = vulnerable_collection.count()
    safe_count = safe_collection.count()
    
    print(f"✅ Vulnerable patterns collection: {vuln_count} entries")
    print(f"✅ Safe patterns collection: {safe_count} entries")
    
    # Test a query
    print("\n🧪 Testing similarity search...")
    test_query = 'db.execute("SELECT * FROM users WHERE email = " + email)'
    results = vulnerable_collection.query(
        query_texts=[test_query],
        n_results=3
    )
    
    print(f"\n📊 Top 3 matches for test SQL injection pattern:")
    for i, (doc, metadata, distance) in enumerate(zip(
        results['documents'][0],
        results['metadatas'][0],
        results['distances'][0]
    )):
        print(f"\n{i+1}. {metadata['vuln_type']} ({metadata['framework']})")
        print(f"   Distance: {distance:.4f}")
        print(f"   Code: {doc[:80]}...")
    
    print("\n✨ Seeding complete!")
    print("\n💡 Usage:")
    print("   - Code Analyzer: Query vulnerable_patterns to detect known-bad patterns")
    print("   - Fix Generator: Query safe_patterns to find secure alternatives")


if __name__ == "__main__":
    seed_collections()
