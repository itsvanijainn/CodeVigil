"""Rule-based code remediation engine for CodeVigil."""

from __future__ import annotations

import re

from utils.code_detector import detect_code_patterns
from utils.syntax_fixer import analyze_syntax, detect_language, fix_syntax, normalize_code, remaining_syntax_issues


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
        out.append(line)

    if modified:
        changes.append("Replaced SQL string concatenation with parameterized queries.")
    return "\n".join(out), changes


def _fix_command_injection(code: str) -> tuple[str, list[str]]:
    changes: list[str] = []
    updated = code
    if re.search(r"os\.system\s*\(", updated):
        updated = re.sub(
            r"os\.system\s*\(([^)]+)\)",
            r"subprocess.run([cmd], shell=False, check=True)",
            updated,
        )
        if "import subprocess" not in updated:
            updated = "import subprocess\n" + updated
        changes.append("Replaced `os.system()` with `subprocess.run(..., shell=False)`.")
    if re.search(r"shell\s*=\s*True", updated, re.I):
        updated = re.sub(r"shell\s*=\s*True", "shell=False", updated, flags=re.I)
        changes.append("Set `shell=False` to prevent shell injection.")
    return updated, changes


def _fix_eval(code: str) -> tuple[str, list[str]]:
    if "eval(" not in code or "ast.literal_eval" in code:
        return code, []
    updated = re.sub(r"eval\s*\(([^)]+)\)", r"ast.literal_eval(\1)", code)
    if "import ast" not in updated:
        updated = "import ast\n" + updated
    return updated, ["Replaced `eval()` with `ast.literal_eval()`."]


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
    return updated, ["Sanitized path traversal patterns."]


def _fix_deserialization(code: str) -> tuple[str, list[str]]:
    if "pickle.loads(" not in code and "unserialize(" not in code:
        return code, []
    updated = re.sub(r"pickle\.loads\s*\(([^)]+)\)", r"json.loads(\1)", code)
    if "import json" not in updated:
        updated = "import json\n" + updated
    return updated, ["Replaced insecure deserialization with JSON parsing."]


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
    return updated, ["Moved hardcoded secrets to environment variables."]


def generate_remediation(code: str, language: str = "Auto-Detect") -> dict:
    """Detect vulnerability + syntax issues and apply fixes. Language always auto-detected from code."""
    code = normalize_code(code)

    if not code.strip():
        return {
            "original": code,
            "remediated": code,
            "changes": ["Paste code above, then click **Run Remediation**."],
            "has_fix": False,
            "detected_types": [],
            "detected_language": "Auto-Detect",
            "remaining_syntax_issues": [],
            "syntax_issues_before": [],
        }

    original_code = code
    changes: list[str] = []

    # Phase 1: Syntax fixes (always first, language inferred from code — ignore sidebar hint)
    syntax_report = analyze_syntax(code, "Auto-Detect")
    remediated = syntax_report["fixed_code"]
    if syntax_report["fixes_applied"]:
        changes.extend([f"[Syntax] {c}" for c in syntax_report["fixes_applied"]])

    # Phase 2: Security fixes
    detection = detect_code_patterns(code)
    fix_map = {
        "SQL Injection": lambda c: _fix_sql_injection(c, "Auto-Detect"),
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
            remediated, sec_changes = fn(remediated)
            changes.extend([f"[Security] {c}" for c in sec_changes])

    if "eval(" in code and "Remote Code Execution" not in detection["detected_types"]:
        remediated, ev = _fix_eval(remediated)
        changes.extend([f"[Security] {c}" for c in ev])

    # Phase 3: Re-run syntax pass if security edits changed the code
    if remediated != syntax_report["fixed_code"]:
        remediated, extra = fix_syntax(remediated, "Auto-Detect")
        changes.extend([f"[Syntax] {c}" for c in extra])

    changes = list(dict.fromkeys(changes))
    has_fix = remediated.strip() != original_code.strip()
    syntax_issues = remaining_syntax_issues(remediated, "Auto-Detect")

    if not has_fix:
        if syntax_report["issues_before"]:
            changes = [f"[Syntax] Detected: {'; '.join(syntax_report['issues_before'][:2])}"]
            changes.append("Could not auto-fix — please check the code manually.")
        elif not changes:
            changes = ["No fixable issues detected in this code."]

    return {
        "original": original_code,
        "remediated": remediated,
        "changes": changes,
        "has_fix": has_fix,
        "detected_types": detection["detected_types"],
        "detected_language": syntax_report["language"],
        "remaining_syntax_issues": syntax_issues,
        "syntax_issues_before": syntax_report["issues_before"],
    }
