"""Language-aware syntax detection and auto-fix for CodeVigil remediation."""

from __future__ import annotations

import ast
import re


def detect_language(code: str, language: str = "Auto-Detect") -> str:
    if language != "Auto-Detect":
        return language
    if "#include" in code or "using namespace" in code or re.search(r"\bcout\s*<", code) or re.search(r"\bcin\s*>"):
        return "C / C++"
    if "public class" in code or "System.out.print" in code or "public static void main" in code:
        return "Java"
    if "def " in code or re.search(r"^\s*import ", code, re.M) or "print(" in code:
        return "Python"
    if "function " in code or "console.log" in code or "const " in code or "let " in code:
        return "JavaScript / TypeScript"
    if "<?php" in code or "$_" in code:
        return "PHP"
    return "Auto-Detect"


def _needs_semicolon(stripped: str, language: str) -> bool:
    if not stripped or stripped.endswith(("{", "}", ";")):
        return False
    if stripped.startswith(("//", "#", "/*", "*", "using ", "package ", "import ", "public ", "private ", "protected ")):
        return False
    if language == "C / C++":
        if stripped.startswith(("int main", "void ", "float ", "double ", "char ", "bool ", "long ", "short ")):
            return "(" in stripped and ")" in stripped and "{" not in stripped
        return stripped.startswith(("cout", "cin", "return")) or (
            "=" in stripped and not stripped.startswith(("if ", "for ", "while ", "switch ", "else"))
        )
    if language == "Java":
        return stripped.startswith(("System.out", "return")) or (
            "=" in stripped and not stripped.startswith(("if ", "for ", "while ", "class ", "public ", "private "))
        )
    return False


def fix_syntax(code: str, language: str = "Auto-Detect") -> tuple[str, list[str]]:
    """Apply rule-based syntax fixes for common mistakes across languages."""
    detected = detect_language(code, language)
    changes: list[str] = []
    lines = code.splitlines()
    out: list[str] = []

    for line in lines:
        fixed = line
        stripped = line.strip()

        if detected == "C / C++":
            if re.search(r"\bcout\s*<{3,}", fixed):
                fixed = re.sub(r"(\bcout\s*)<{3,}", r"\1<<", fixed)
                changes.append("Fixed invalid stream operator: `cout<<<` -> `cout<<`.")
            if re.search(r"\bcin\s*>{3,}", fixed):
                fixed = re.sub(r"(\bcin\s*)>{3,}", r"\1>>", fixed)
                changes.append("Fixed invalid stream operator: `cin>>>` -> `cin>>`.")
            if re.search(r"\bcout\s*>>", fixed):
                fixed = re.sub(r"(\bcout\s*)>>", r"\1<<", fixed)
                changes.append("Fixed reversed stream operator on `cout` (`>>` -> `<<`).")
            if re.search(r"\bcin\s*<<", fixed):
                fixed = re.sub(r"(\bcin\s*)<<", r"\1>>", fixed)
                changes.append("Fixed reversed stream operator on `cin` (`<<` -> `>>`).")

        elif detected == "Java":
            if re.search(r"System\.out\.print\s*<<<", fixed):
                fixed = fixed.replace("<<<", "")
                changes.append("Removed stray `<` characters after `System.out.print`.")

        elif detected == "Python":
            fixed = fixed.replace("print ", "print(")  # skip - too risky

        new_stripped = fixed.strip()
        if _needs_semicolon(new_stripped, detected):
            fixed = fixed.rstrip() + ";"
            changes.append(f"Added missing semicolon: `{new_stripped}` -> `{new_stripped};`")

        out.append(fixed)

    remediated = "\n".join(out)

    if detected == "Python":
        try:
            ast.parse(remediated)
        except SyntaxError as e:
            # Common: missing colon, print as statement
            if "invalid syntax" in (e.msg or "").lower() and "print " in remediated:
                pass  # skip risky auto-fixes

    return remediated, list(dict.fromkeys(changes))


def remaining_syntax_issues(code: str, language: str = "Auto-Detect") -> list[str]:
    """Return human-readable syntax issues still present after auto-fix."""
    detected = detect_language(code, language)
    issues: list[str] = []

    if code.count("{") != code.count("}"):
        issues.append(f"Unmatched curly braces: {code.count('{')} `{{` vs {code.count('}')} `}}`.")
    if code.count("(") != code.count(")"):
        issues.append(f"Unmatched parentheses: {code.count('(')} `(` vs {code.count(')')} `)`.")
    if code.count("[") != code.count("]"):
        issues.append(f"Unmatched square brackets: {code.count('[')} `[` vs {code.count(']')} `]`.")
    if re.search(r"\bcout\s*<{3,}|\bcin\s*>{3,}", code):
        issues.append("Invalid stream operator (`<<<` or `>>>`) still present.")

    if detected == "Python":
        try:
            ast.parse(code)
        except SyntaxError as e:
            issues.append(f"Python syntax error (line {e.lineno}): {e.msg}")

    return issues
