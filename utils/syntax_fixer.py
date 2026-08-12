"""Comprehensive language-aware syntax detection and auto-fix for CodeVigil."""

from __future__ import annotations

import ast
import re

# Words that must NOT be wrapped in quotes after cout/cin/print
_STREAM_KEYWORDS = frozenset({
    "endl", "std", "hex", "dec", "oct", "boolalpha", "noboolalpha",
    "fixed", "scientific", "flush", "ws", "true", "false", "nullptr", "NULL",
})


def normalize_code(code: str) -> str:
    if not code:
        return code
    code = code.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    for src, dst in {
        "\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'",
        "\uff1c": "<", "\uff1e": ">",
    }.items():
        code = code.replace(src, dst)
    return code


def detect_language(code: str, language: str = "Auto-Detect") -> str:
    code = normalize_code(code)
    if (
        "#include" in code or "using namespace" in code
        or re.search(r"\bcout\b|\bcin\b|\bstd::", code)
        or re.search(r"\bint\s+main\w*\s*\(", code)
    ):
        return "C / C++"
    if re.search(r"\bpublic\s+class\b|\bSystem\.out\b|\bpublic\s+static\s+void\s+main", code):
        return "Java"
    if re.search(r"^\s*def\s+\w+|^\s*import\s+\w+|^\s*from\s+\w+\s+import|^\s*print\s*\(|^\s*print\s+\S", code, re.M):
        return "Python"
    if re.search(r"\bfunction\s+\w+|\bconsole\.(log|error|warn)\b|\b(const|let|var)\s+\w+", code):
        return "JavaScript / TypeScript"
    if "<?php" in code or re.search(r"\$\w+\s*=", code):
        return "PHP"
    if re.search(r"\bfunc\s+\w+|\bfmt\.Print", code):
        return "Go"
    if re.search(r"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b", code, re.I):
        return "SQL"
    if language != "Auto-Detect":
        return language
    return "Auto-Detect"


from utils.keyword_fixes import fix_keyword_typos, scan_keyword_typos

def scan_syntax_issues(code: str) -> list[str]:
    """Detect all known fixable syntax issue types in code."""
    code = normalize_code(code)
    issues: list[str] = []
    lang = detect_language(code)

    issues.extend(scan_keyword_typos(code, lang))
    if re.search(r"\bmain(?!\.)\w+\s*\(", code) and not re.search(r"\bmain\s*\(", code):
        issues.append("Misspelled entry point (`mainnn`, etc.) — should be `main`.")
    if re.search(r"\bcout\s*<{3,}|\bcin\s*>{3,}", code):
        issues.append("Invalid stream operator (`<<<` or `>>>`).")
    if re.search(r"\bcout\s*>>|\bcin\s*<<", code):
        issues.append("Reversed stream operator on cout/cin.")
    if re.search(r'\bcout\s*<<\s*[a-zA-Z_]\w*(?=\s*[;,\s]|$)', code) and not re.search(r'\bcout\s*<<\s*["\']', code):
        issues.append("Missing quotes around string literal in cout/print output.")
    if re.search(r'\b(printf|puts|console\.log|System\.out\.print\w*)\s*\(\s*[a-zA-Z_]\w*\s*\)', code):
        issues.append("Missing quotes around string in print/printf call.")
    if code.count("{") != code.count("}"):
        issues.append(f"Unmatched curly braces ({code.count('{')} open, {code.count('}')} close).")
    if code.count("(") != code.count(")"):
        issues.append(f"Unmatched parentheses ({code.count('(')} open, {code.count(')')} close).")
    if code.count("[") != code.count("]"):
        issues.append(f"Unmatched square brackets ({code.count('[')} open, {code.count(']')} close).")
    if re.search(r"#include\s*<", code) and not re.search(r"#include\s+<", code):
        issues.append("Missing space in `#include<...>` directive.")

    for i, line in enumerate(code.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", "//", "/*", "*", "using ", "import ", "package ", "#include")):
            continue
        if s.endswith(("{", "}", ";", ":", "\\")):
            continue
        if re.match(r"^(if|for|while|switch|else|catch|try|def|class|public|private|protected|func)\b", s):
            if lang == "Python" and re.match(r"^(if|for|while|def|class|elif|else|try|except|finally|with)\b", s) and not s.endswith(":"):
                issues.append(f"Line {i}: missing colon `:` at end of `{s[:40]}`.")
            continue
        if lang in ("C / C++", "Java", "JavaScript / TypeScript", "PHP", "Go") and re.match(
            r"^(cout|cin|return|printf|scanf|System\.out|console\.|var |let |const |int |float |double |char |bool |String )", s
        ):
            issues.append(f"Line {i}: possible missing semicolon on `{s[:40]}`.")
        if lang == "Python" and re.match(r"^print\s+\S", s) and not s.startswith("print("):
            issues.append(f"Line {i}: Python 2-style print — needs parentheses.")

    if lang == "Python":
        try:
            ast.parse(code)
        except SyntaxError as e:
            if not any("Python" in x for x in issues):
                issues.append(f"Python syntax error (line {e.lineno}): {e.msg}")

    return list(dict.fromkeys(issues))


# ── Fix helpers ───────────────────────────────────────────────────────────────

def _strip_comments_part(line: str) -> str:
    return line.split("//")[0].split("#")[0] if "#include" not in line else line.split("//")[0]


def _fix_entry_point_names(code: str, changes: list[str]) -> str:
    """Fix mainnn, mian, amin -> main."""
    def repl(m: re.Match) -> str:
        changes.append(f"Fixed entry point `{m.group(2)}` -> `main`.")
        return f"{m.group(1)}main{m.group(3)}"
    return re.sub(
        r"(\b(?:int|void)\s+)(main\w+)(\s*\()",
        repl,
        code,
        flags=re.I,
    )


def _fix_include_directives(code: str, changes: list[str]) -> str:
    updated = re.sub(r"#include\s*<", "#include <", code)
    if updated != code:
        changes.append("Fixed `#include<` -> `#include <`.")
    return updated


def _fix_line_stream_operators(line: str, changes: list[str]) -> str:
    fixed = line
    for bad, good, msg in [
        ("cout<<<", "cout<<", "Fixed `cout<<<` -> `cout<<`."),
        ("cin>>>", "cin>>", "Fixed `cin>>>` -> `cin>>`."),
    ]:
        if bad in fixed:
            fixed = fixed.replace(bad, good)
            changes.append(msg)
    if re.search(r"\bcout\s*<{3,}", fixed):
        fixed = re.sub(r"(\bcout\s*)<{3,}", r"\1<<", fixed)
        changes.append("Fixed extra `<` on cout.")
    if re.search(r"\bcin\s*>{3,}", fixed):
        fixed = re.sub(r"(\bcin\s*)>{3,}", r"\1>>", fixed)
        changes.append("Fixed extra `>` on cin.")
    if re.search(r"\bcout\s*>>", fixed):
        fixed = re.sub(r"(\bcout\s*)>>+", r"\1<<", fixed)
        changes.append("Fixed reversed `cout >>` -> `cout <<`.")
    if re.search(r"\bcin\s*<<", fixed):
        fixed = re.sub(r"(\bcin\s*)<<+", r"\1>>", fixed)
        changes.append("Fixed reversed `cin <<` -> `cin >>`.")
    return fixed


def _fix_unquoted_output_strings(line: str, changes: list[str]) -> str:
    """Add quotes: cout<< hello -> cout<<\"hello\", printf(hello) -> printf(\"hello\")."""
    fixed = line

    # cout << bareword
    def cout_repl(m: re.Match) -> str:
        word = m.group(2)
        if word in _STREAM_KEYWORDS or word.isdigit():
            return m.group(0)
        changes.append(f'Added quotes around `{word}` in cout statement.')
        return f'{m.group(1)}"{word}"{m.group(3)}'

    fixed = re.sub(
        r'(\bcout\s*<<\s*)([a-zA-Z_]\w*)(\s*[;,)\s]|$)',
        cout_repl,
        fixed,
    )

    # printf(hello) / puts(hello)
    def print_repl(m: re.Match) -> str:
        word = m.group(2)
        if word in _STREAM_KEYWORDS or word.isdigit():
            return m.group(0)
        changes.append(f'Added quotes around `{word}` in `{m.group(1)}()` call.')
        return f'{m.group(1)}("{word}")'

    fixed = re.sub(
        r'\b(printf|puts|print)\s*\(\s*([a-zA-Z_]\w*)\s*\)',
        print_repl,
        fixed,
    )

    # console.log(hello)
    fixed = re.sub(
        r'\b(console\.(?:log|error|warn|info))\s*\(\s*([a-zA-Z_]\w*)\s*\)',
        lambda m: (
            changes.append(f'Added quotes around `{m.group(2)}` in `{m.group(1)}()`.') or
            f'{m.group(1)}("{m.group(2)}")'
        ),
        fixed,
    )

    # System.out.println(hello)
    fixed = re.sub(
        r'\b(System\.out\.print\w*)\s*\(\s*([a-zA-Z_]\w*)\s*\)',
        lambda m: (
            changes.append(f'Added quotes around `{m.group(2)}` in Java print call.') or
            f'{m.group(1)}("{m.group(2)}")'
        ),
        fixed,
    )

    return fixed


def _fix_line_semicolons(line: str, changes: list[str]) -> str:
    """Add missing semicolons — heuristic, works across C-family languages."""
    stripped = line.strip()
    if not stripped or stripped.endswith(("{", "}", ";", ":", "\\")):
        return line
    if stripped.startswith((
        "//", "#", "/*", "*", "using ", "package ", "import ", "from ",
        "#include", "public class", "private class", "protected class",
        "if ", "for ", "while ", "switch ", "else", "catch ", "try ",
        "def ", "class ", "func ", "else:", "elif ",
    )):
        return line

    needs = bool(re.match(
        r"^(cout|cin|return|printf|scanf|puts|delete|free|"
        r"System\.out|console\.|var |let |const |"
        r"int |float |double |char |bool |long |short |void |String |"
        r"\w+\s*=)",
        stripped,
    ))
    if needs:
        changes.append(f"Added missing semicolon on `{stripped[:50]}`.")
        return line.rstrip() + ";"
    return line


def _fix_python_lines(code: str, changes: list[str]) -> str:
    out: list[str] = []
    for line in code.splitlines():
        fixed = line
        stripped = line.strip()

        # print hello -> print("hello")
        m = re.match(r"^(\s*)print\s+(.+)$", line)
        if m and not m.group(2).lstrip().startswith("("):
            content = m.group(2).strip()
            if re.match(r"^[a-zA-Z_]\w*$", content):
                fixed = f'{m.group(1)}print("{content}")'
            else:
                fixed = f"{m.group(1)}print({content})"
            changes.append("Fixed Python 2-style `print` -> `print(...)`.")

        # missing colon on block headers
        if re.match(r"^\s*(if|elif|else|for|while|def|class|try|except|finally|with)\b.*[^:]\s*$", stripped):
            if not stripped.endswith(":"):
                fixed = line.rstrip() + ":"
                changes.append(f"Added missing colon on `{stripped[:40]}`.")
        out.append(fixed)
    return "\n".join(out)


def _brace_events(line: str) -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    indent = line[: len(line) - len(line.lstrip())]
    part = _strip_comments_part(line)
    in_str: str | None = None
    i = 0
    while i < len(part):
        ch = part[i]
        if in_str:
            if ch == in_str and (i == 0 or part[i - 1] != "\\"):
                in_str = None
        elif ch in ('"', "'"):
            in_str = ch
        elif ch == "{":
            events.append(("open", indent))
        elif ch == "}":
            events.append(("close", indent))
        i += 1
    return events


def _fix_braces(code: str, changes: list[str]) -> str:
    stack: list[str] = []
    for line in code.splitlines():
        for kind, indent in _brace_events(line):
            if kind == "open":
                stack.append(indent)
            elif kind == "close" and stack:
                stack.pop()
    if not stack:
        return code
    result = code.rstrip()
    for indent in reversed(stack):
        result += f"\n{indent}}}"
    changes.append(f"Added {len(stack)} missing closing brace(s) `}}`.")
    return result


def _count_outside_strings(code: str, open_ch: str, close_ch: str) -> tuple[int, int]:
    opens = closes = 0
    in_str: str | None = None
    for ch in code:
        if in_str:
            if ch == in_str:
                in_str = None
        elif ch in ('"', "'"):
            in_str = ch
        elif ch == open_ch:
            opens += 1
        elif ch == close_ch:
            closes += 1
    return opens, closes


def _fix_delimiter(code: str, open_ch: str, close_ch: str, label: str, changes: list[str]) -> str:
    opens, closes = _count_outside_strings(code, open_ch, close_ch)
    if opens > closes:
        missing = opens - closes
        code = code.rstrip() + close_ch * missing
        changes.append(f"Added {missing} missing closing `{close_ch}` ({label}).")
    return code


def _dedupe_changes(changes: list[str]) -> list[str]:
    return list(dict.fromkeys(changes))


# ── Main fix pipeline ─────────────────────────────────────────────────────────

def fix_syntax(code: str, language: str = "Auto-Detect") -> tuple[str, list[str]]:
    """Multi-pass syntax fixer — runs universal + language-specific rules."""
    code = normalize_code(code)
    changes: list[str] = []
    lang = detect_language(code, "Auto-Detect")

    # Pass 1: keyword & phrase typos (language-aware, also scans all if Auto-Detect)
    code = fix_keyword_typos(code, lang, changes)
    code = _fix_entry_point_names(code, changes)
    code = _fix_include_directives(code, changes)

    # Pass 2: line-by-line universal fixes
    lines: list[str] = []
    for line in code.splitlines():
        line = _fix_line_stream_operators(line, changes)
        line = _fix_unquoted_output_strings(line, changes)
        line = _fix_line_semicolons(line, changes)
        lines.append(line)
    code = "\n".join(lines)

    # Pass 3: language-specific
    if lang == "Python":
        code = _fix_python_lines(code, changes)

    # Pass 4: structural balancing (always, all languages)
    code = _fix_braces(code, changes)
    code = _fix_delimiter(code, "(", ")", "parentheses", changes)
    code = _fix_delimiter(code, "[", "]", "square brackets", changes)

    return code, _dedupe_changes(changes)


def analyze_syntax(code: str, language: str = "Auto-Detect") -> dict:
    code = normalize_code(code)
    lang = detect_language(code, "Auto-Detect")
    issues_before = scan_syntax_issues(code)
    fixed_code, fixes_applied = fix_syntax(code, language)
    remaining = remaining_syntax_issues(fixed_code, language)
    return {
        "language": lang,
        "issues_before": issues_before,
        "fixes_applied": fixes_applied,
        "fixed_code": fixed_code,
        "issues_remaining": remaining,
        "is_valid_after": len(remaining) == 0,
    }


def remaining_syntax_issues(code: str, language: str = "Auto-Detect") -> list[str]:
    return scan_syntax_issues(code)
