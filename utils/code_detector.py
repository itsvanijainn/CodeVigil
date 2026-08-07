"""
CodeVigil — Code Pattern Detector
=====================================
Detects vulnerability patterns in code snippets and
boosts search queries with relevant keywords.
"""

import re


# Code pattern signatures: (pattern_name, keywords, regex_patterns)
CODE_PATTERNS = {
    "SQL Injection": {
        "boost_keywords": [
            "SQL injection", "database query", "SQL query manipulation",
            "parameterized query", "prepared statement", "UNION SELECT",
            "input validation", "database", "SQL",
        ],
        "regexes": [
            r"(?i)(select\s+.*\s+from\s+)",        # SELECT ... FROM
            r"(?i)(insert\s+into\s+)",               # INSERT INTO
            r"(?i)(update\s+\w+\s+set\s+)",          # UPDATE ... SET
            r"(?i)(delete\s+from\s+)",               # DELETE FROM
            r"(?i)(drop\s+table\s+)",                # DROP TABLE
            r"(?i)(union\s+select\s+)",              # UNION SELECT
            r"(?i)(or\s+1\s*=\s*1)",                 # OR 1=1
            r"(?i)(cursor\.execute\s*\()",           # cursor.execute()
            r"(?i)(\.execute\s*\(.*\+)",             # .execute(... + ...) string concat
            r"(?i)(getparameter\s*\()",              # getParameter()
            r"(?i)(query\s*=\s*[\"'].*select)",      # query = "SELECT..."
            r"(?i)(mysql_query\s*\()",               # mysql_query()
            r"(?i)(mysqli_query\s*\()",              # mysqli_query()
            r"(?i)(sqlite3?\.\w+)",                  # sqlite3 calls
            r"(?i)(jdbc|odbc|dbi)",                  # DB drivers
        ],
    },
    "Command Injection": {
        "boost_keywords": [
            "command injection", "shell injection", "OS command execution",
            "arbitrary command", "shell command", "system call",
        ],
        "regexes": [
            r"(?i)(os\.system\s*\()",
            r"(?i)(os\.popen\s*\()",
            r"(?i)(subprocess\.(call|run|popen|check_output)\s*\()",
            r"(?i)(shell\s*=\s*true)",
            r"(?i)(exec\s*\(.*\$)",                  # PHP exec with variable
            r"(?i)(system\s*\(.*\$)",                # PHP system()
            r"(?i)(passthru\s*\()",
            r"(?i)(runtime\.getruntime\(\)\.exec)",
            r"(?i)(processbuilder)",
            r"(?i)(eval\s*\(.*\+)",                  # eval() with concatenation
        ],
    },
    "Path Traversal": {
        "boost_keywords": [
            "path traversal", "directory traversal", "file read",
            "arbitrary file access", "dot dot slash",
        ],
        "regexes": [
            r"\.\./",                                 # ../
            r"\.\.\\\\",                              # ..\
            r"(?i)(open\s*\(.*\+)",                   # open(... + user_input)
            r"(?i)(file_get_contents\s*\()",
            r"(?i)(readfile\s*\()",
            r"(?i)(fopen\s*\()",
            r"(?i)(include\s*\(\s*\$)",              # PHP include with variable
            r"(?i)(require\s*\(\s*\$)",
            r"(?i)(send_from_dir|send_file)",
            r"(?i)(path\.join\s*\(.*request)",
        ],
    },
    "Cross-Site Scripting (XSS)": {
        "boost_keywords": [
            "cross site scripting", "XSS", "HTML injection",
            "script injection", "output encoding", "reflected XSS",
        ],
        "regexes": [
            r"(?i)(innerHTML\s*=)",
            r"(?i)(document\.write\s*\()",
            r"(?i)(<script[^>]*>)",
            r"(?i)(onerror\s*=)",
            r"(?i)(onload\s*=)",
            r"(?i)(javascript:)",
            r"(?i)(alert\s*\()",
            r"(?i)(\.html\s*\(.*request)",
            r"(?i)(dangerouslySetInnerHTML)",
            r"(?i)(v-html\s*=)",
            r"(?i)(\{\{.*\}\})",                      # template injection
        ],
    },
    "Deserialization": {
        "boost_keywords": [
            "deserialization", "unserialize", "pickle",
            "marshalling", "insecure deserialization", "gadget chain",
        ],
        "regexes": [
            r"(?i)(pickle\.loads?\s*\()",
            r"(?i)(yaml\.load\s*\()",
            r"(?i)(yaml\.unsafe_load)",
            r"(?i)(marshal\.loads?\s*\()",
            r"(?i)(unserialize\s*\()",               # PHP unserialize
            r"(?i)(objectinputstream)",
            r"(?i)(readobject\s*\()",
            r"(?i)(xmldecoder)",
            r"(?i)(json\.loads?.*pickle)",
            r"(?i)(binaryformatter)",
        ],
    },
    "Buffer Overflow": {
        "boost_keywords": [
            "buffer overflow", "heap overflow", "stack overflow",
            "memory corruption", "bounds checking",
        ],
        "regexes": [
            r"(?i)(strcpy\s*\()",
            r"(?i)(strcat\s*\()",
            r"(?i)(gets\s*\()",
            r"(?i)(sprintf\s*\()",
            r"(?i)(scanf\s*\()",
            r"(?i)(memcpy\s*\()",
            r"(?i)(malloc\s*\(.*\))",
            r"(?i)(buffer\[.*\])",
        ],
    },
    "Authentication Bypass": {
        "boost_keywords": [
            "authentication bypass", "login bypass",
            "credential stuffing", "session hijacking",
        ],
        "regexes": [
            r"(?i)(password\s*==\s*[\"'])",           # hardcoded password
            r"(?i)(admin\s*==\s*true)",
            r"(?i)(auth\s*=\s*true\s*#)",
            r"(?i)(if\s*\(.*==.*\)\s*login)",
            r"(?i)(session\[.user.\]\s*=\s*)",
        ],
    },
    "Remote Code Execution": {
        "boost_keywords": [
            "remote code execution", "RCE", "arbitrary code execution",
            "code injection", "eval injection",
        ],
        "regexes": [
            r"(?i)(eval\s*\()",
            r"(?i)(exec\s*\()",
            r"(?i)(compile\s*\(.*request)",
            r"(?i)(new\s+function\s*\()",            # JS Function constructor
            r"(?i)(jndi:ldap)",
            r"(?i)(classloader)",
            r"(?i)(defineclass\s*\()",
            r"(?i)(importlib\.import_module)",
        ],
    },
    "SSRF": {
        "boost_keywords": [
            "SSRF", "server side request forgery",
            "internal network access", "URL validation",
        ],
        "regexes": [
            r"(?i)(requests\.get\s*\(.*request)",
            r"(?i)(urllib\.request\.urlopen\s*\(.*request)",
            r"(?i)(file_get_contents\s*\(.*\$)",
            r"(?i)(httpclient.*request)",
            r"(?i)(fetch\s*\(.*req\.)",
        ],
    },
    "Cryptographic Vulnerability": {
        "boost_keywords": [
            "cryptographic vulnerability", "weak encryption",
            "MD5", "SHA1", "hardcoded key", "weak cipher",
        ],
        "regexes": [
            r"(?i)(md5\s*\()",
            r"(?i)(sha1\s*\()",
            r"(?i)(des\b)",
            r"(?i)(rc4\b)",
            r"(?i)(ecb\s*mode)",
            r"(?i)(hardcoded.*key|key.*=.*[\"'][a-z]+[\"'])",
        ],
    },
}


def detect_code_patterns(text: str) -> dict:
    """
    Analyze text/code for vulnerability patterns.
    
    Args:
        text: User input (code snippet or natural language)
        
    Returns:
        Dict with:
        - detected_types: list of matched vulnerability types
        - boosted_query: original text + boost keywords
        - matches: detailed match info
    """
    detected_types = []
    all_boost_keywords = []
    matches = {}

    for vuln_type, pattern_info in CODE_PATTERNS.items():
        type_matches = []
        
        for regex in pattern_info["regexes"]:
            found = re.findall(regex, text)
            if found:
                type_matches.extend(found)
        
        if type_matches:
            detected_types.append(vuln_type)
            all_boost_keywords.extend(pattern_info["boost_keywords"])
            matches[vuln_type] = type_matches

    # Build boosted query: original text + detected vulnerability keywords
    boosted_query = text
    if all_boost_keywords:
        # Add top keywords to boost search
        unique_keywords = list(dict.fromkeys(all_boost_keywords))[:10]
        boosted_query = text + " " + " ".join(unique_keywords)

    return {
        "detected_types": detected_types,
        "boosted_query": boosted_query,
        "matches": matches,
        "is_code": _looks_like_code(text),
    }


def _looks_like_code(text: str) -> bool:
    """Heuristic: does the input look like code or natural language?"""
    code_indicators = [
        "=" in text,
        "(" in text and ")" in text,
        ";" in text,
        "import " in text,
        "def " in text,
        "function " in text,
        "{" in text,
        text.count("\n") > 1 and any(c in text for c in ["=", "(", "{"]),
    ]
    return sum(code_indicators) >= 2
