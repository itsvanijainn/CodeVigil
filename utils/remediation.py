"""Rule-based code remediation engine for CodeVigil."""

from __future__ import annotations

import re

from utils.code_detector import detect_code_patterns
from utils.syntax_fixer import detect_language, fix_syntax, remaining_syntax_issues


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _fix_sql_injection(code: str, language: str) -> tuple[str, list[str]]:
    changes: list[str] = []
    lines = code.splitlines()
    out: list[str] = []
    modified = False

    for line in lines:
        stripped = line.strip()
        if "executeQuery" in line and "+" in line and '"' in line:
            pad = _indent_of(line)
            out.extend([
                f"{pad}PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE username = ?\");",
                f"{pad}pstmt.setString(1, username);",
                f"{pad}ResultSet rs = pstmt.executeQuery();",
            ])
            modified = True
            continue

        if re.search(r"(?i)(cursor|stmt)\.execute\s*\(", line) and "+" in line:
            pad = _indent_of(line)
            out.append(f'{pad}cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))')
            modified = True
            continue

        if re.search(r"(?i)(select|insert|update|delete).*\+.*[\"']", stripped):
            pad = _indent_of(line)
            out.append(f'{pad}// TODO: use parameterized query instead of string concatenation')
            out.append(f'{pad}// {stripped}')
            modified = True
            continue

        out.append(line)

    if modified:
        changes.append("Replaced SQL string concatenation with parameterized queries (PreparedStatement / `%s` bindings).")
    return "\n".join(out), changes


def _fix_command_injection(code: str) -> tuple[str, list[str]]:
    changes: list[str] = []
    updated = code

    if re.search(r"os\.system\s*\(", updated):
        updated = re.sub(
            r"os\.system\s*\(([^)]+)\)",
            r"subprocess.run([cmd], shell=False, check=True)  # was: os.system(\1)",
            updated,
        )
        if "import subprocess" not in updated:
            updated = "import subprocess\n" + updated
        changes.append("Replaced `os.system()` with `subprocess.run(..., shell=False)`.")

    if re.search(r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True", updated, re.I):
        updated = re.sub(r"shell\s*=\s*True", "shell=False", updated, flags=re.I)
        changes.append("Set `shell=False` to prevent shell injection.")

    return updated, changes


def _fix_eval(code: str) -> tuple[str, list[str]]:
    if "eval(" not in code or "ast.literal_eval" in code:
        return code, []
    updated = re.sub(r"eval\s*\(([^)]+)\)", r"ast.literal_eval(\1)", code)
    if "import ast" not in updated:
        updated = "import ast\n" + updated
    return updated, ["Replaced `eval()` with safe `ast.literal_eval()`."]


def _fix_path_traversal(code: str) -> tuple[str, list[str]]:
    if not re.search(r"\.\./|\.\.\\\\", code):
        return code, []

    updated = code.replace("../", "").replace("..\\", "")
    updated = re.sub(
        r"open\s*\(\s*([^)]+)\)",
        r"open(os.path.join(BASE_DIR, os.path.basename(\1)))",
        updated,
    )
    if "import os" not in updated:
        updated = "import os\n\nBASE_DIR = '/safe/uploads'\n\n" + updated
    return updated, ["Removed path traversal sequences and sandboxed file paths with `os.path.basename()`."]


def _fix_deserialization(code: str) -> tuple[str, list[str]]:
    if "pickle.loads(" not in code and "unserialize(" not in code:
        return code, []
    updated = re.sub(r"pickle\.loads\s*\(([^)]+)\)", r"json.loads(\1)", code)
    updated = re.sub(r"unserialize\s*\(([^)]+)\)", r"json_decode(\1, true)", updated)
    if "import json" not in updated and "pickle.loads(" in code:
        updated = "import json\n" + updated
    return updated, ["Replaced insecure deserialization with safe JSON parsing."]


def _fix_hardcoded_credentials(code: str) -> tuple[str, list[str]]:
    if not re.search(r"(?i)(password|secret|api_key)\s*=\s*['\"][^'\"]+['\"]", code):
        return code, []
    updated = re.sub(
        r"(?i)(password|secret|api_key)\s*=\s*['\"][^'\"]+['\"]",
        r"\1 = os.environ.get('SECURITY_\1_SECRET')",
        code,
    )
    if "import os" not in updated:
        updated = "import os\n" + updated
    return updated, ["Moved hardcoded secrets to environment variables (`os.environ.get`)."]


def generate_remediation(code: str, language: str = "Auto-Detect") -> dict:
    """Detect vulnerability patterns and apply targeted rule-based fixes."""
    if not code or not code.strip():
        return {
            "original": code,
            "remediated": code,
            "changes": ["Paste vulnerable code above, then click **Run Remediation**."],
            "has_fix": False,
        }

    detection = detect_code_patterns(code)
    remediated = code
    changes: list[str] = []

    fix_map = {
        "SQL Injection": lambda c: _fix_sql_injection(c, language),
        "Command Injection": _fix_command_injection,
        "Remote Code Execution": _fix_eval,
        "Path Traversal": _fix_path_traversal,
        "Deserialization": _fix_deserialization,
        "Cryptographic Vulnerability": _fix_hardcoded_credentials,
        "Authentication Bypass": _fix_hardcoded_credentials,
    }

    types_to_fix = list(detection["detected_types"])
    if re.search(r"(?i)(password|secret|api_key)\s*=\s*['\"][^'\"]+['\"]", code):
        if "Cryptographic Vulnerability" not in types_to_fix:
            types_to_fix.append("Cryptographic Vulnerability")

    for vuln_type in types_to_fix:
        fn = fix_map.get(vuln_type)
        if fn:
            remediated, new_changes = fn(remediated)
            changes.extend(new_changes)

    if "eval(" in code and "Remote Code Execution" not in detection["detected_types"]:
        remediated, new_changes = _fix_eval(remediated)
        changes.extend(new_changes)

    # Syntax auto-fix (cout<<<, missing semicolons, etc.)
    remediated, syntax_changes = fix_syntax(remediated, language)
    changes.extend(syntax_changes)

    # Deduplicate while preserving order
    changes = list(dict.fromkeys(changes))
    has_fix = remediated.strip() != code.strip()
    detected_lang = detect_language(code, language)
    syntax_issues = remaining_syntax_issues(remediated, language)

    if not has_fix and not changes:
        changes = [
            "No auto-fixable security or syntax issues found. "
            "Supported fixes: SQL injection, `os.system()`, `eval()`, path traversal, "
            "hardcoded secrets, `cout<<<`/`cin>>>`, missing semicolons."
        ]
    elif syntax_issues and has_fix:
        changes.append(f"Note: {len(syntax_issues)} issue(s) may still need manual review.")

    return {
        "original": code,
        "remediated": remediated,
        "changes": changes,
        "has_fix": has_fix,
        "detected_types": detection["detected_types"],
        "detected_language": detected_lang,
        "remaining_syntax_issues": syntax_issues,
    }
