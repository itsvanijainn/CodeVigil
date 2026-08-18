"""Comprehensive language-aware syntax detection and auto-fix for CodeVigil."""

from __future__ import annotations

import ast
import re

from utils.fuzzy_keywords import detect_language_robust, fuzzy_fix_keywords
from utils.keyword_fixes import fix_keyword_typos, scan_keyword_typos

# Stream keywords and standard single-letter / common variable names that must NOT be quoted
_STREAM_KEYWORDS = frozenset({
    "endl", "std", "hex", "dec", "oct", "boolalpha", "noboolalpha",
    "fixed", "scientific", "flush", "ws", "true", "false", "nullptr", "NULL",
    "i", "j", "k", "n", "m", "x", "y", "z", "a", "b", "c", "s", "t", "v",
    "argc", "argv", "err", "req", "res", "buf", "str", "val", "num", "idx",
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
    inferred = detect_language_robust(code)
    if inferred != "Auto-Detect":
        return inferred
    if language != "Auto-Detect":
        return language
    return "Auto-Detect"


def _extract_declared_variables(code: str) -> set[str]:
    """Find declared variable names in the code snippet."""
    vars_found = set(_STREAM_KEYWORDS)
    # Type declarations: int x;, float val;, String name;
    matches = re.findall(
        r"\b(?:int|float|double|char|bool|auto|String|var|let|const|long|short)\s+([a-zA-Z_]\w*)",
        code,
    )
    vars_found.update(matches)
    # cin >> var
    cin_matches = re.findall(r"\bcin\s*>>\s*([a-zA-Z_]\w*)", code)
    vars_found.update(cin_matches)

    # Extract params ONLY from function definitions (e.g. def foo(x, y), int main(int argc, char* argv[]), function test(a, b))
    fn_def_params = re.findall(
        r"\b(?:def|function|func|public|private|protected|void|int|float|double|char|bool|String)\s+[a-zA-Z_]\w*\s*\(([^)]+)\)",
        code,
    )
    for p in fn_def_params:
        tokens = re.findall(r"\b[a-zA-Z_]\w*\b", p)
        for t in tokens:
            if t not in {"int", "float", "double", "char", "bool", "String", "void", "const", "static", "struct", "class"}:
                vars_found.add(t)
    return vars_found


def scan_syntax_issues(code: str) -> list[str]:
    """Detect all known fixable syntax issue types in code."""
    code = normalize_code(code)
    issues: list[str] = []
    lang = detect_language(code)

    issues.extend(scan_keyword_typos(code, lang))
    if re.search(r"\bmain(?!\.)\w+\s*\(", code) and not re.search(r"\bmain\s*\(", code):
        issues.append("Misspelled entry point (`mainnn`, `maon`, etc.) — should be `main`.")
    if re.search(r"\b([a-zA-Z_]\w*)\s*--(?:-)*\s*(\d+|[a-zA-Z_]\w*)", code) or re.search(r"\b([a-zA-Z_]\w*)\s*-\s*-\s*(\d+)", code):
        issues.append("Invalid decrement/subtraction operator (e.g. `n -- 1` instead of `n - 1`).")
    if re.search(r"\b([a-zA-Z_]\w*)\s*\+\+(?:\+)*\s*(\d+|[a-zA-Z_]\w*)", code):
        issues.append("Invalid increment/addition operator (e.g. `n ++ 1` instead of `n + 1`).")
    if re.search(r"\bcout\s*<{3,}|\bcin\s*>{3,}", code):
        issues.append("Invalid stream operator (`<<<` or `>>>`).")
    if re.search(r"\bcout\s*>>|\bcin\s*<<", code):
        issues.append("Reversed stream operator on cout/cin.")
    if re.search(r"\b(printf|puts|scanf)\s*<<", code):
        issues.append("Invalid stream operator `<<` on `printf`/`puts`/`scanf` call.")
    if re.search(r"\bcout\s*\(\s*[\"'][^\"']+[\"']\s*\)", code):
        issues.append("Invalid function call syntax on `cout(...)` — use `cout << ...`.")
    if re.search(r'\bcout\s*<<\s*[a-zA-Z_]\w*(?=\s*[;,\s]|$)', code) and not re.search(r'\bcout\s*<<\s*["\']', code):
        declared = _extract_declared_variables(code)
        for m in re.finditer(r'\bcout\s*<<\s*([a-zA-Z_]\w*)', code):
            if m.group(1) not in declared:
                issues.append(f"Missing quotes around string literal `{m.group(1)}` in cout output.")
                break

    # Check unclosed string quotes per line
    for i, line in enumerate(code.splitlines(), 1):
        line_clean = _strip_comments_part(line)
        if line_clean.count('"') % 2 != 0:
            issues.append(f"Line {i}: unclosed double quote `\"`.")
        elif line_clean.count("'") % 2 != 0:
            issues.append(f"Line {i}: unclosed single quote `'`.")

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


def _fix_operator_typos(line: str, changes: list[str]) -> str:
    """Fix invalid operator combinations like n -- 1 -> n - 1, n ++ 1 -> n + 1, etc."""
    fixed = line

    # 1. Double minus before a number or variable (e.g. n -- 1 -> n - 1, n - - 1 -> n - 1)
    def decrement_typo_repl(m: re.Match) -> str:
        var = m.group(1)
        num = m.group(2)
        changes.append(f"Fixed operator typo `{var} -- {num}` -> `{var} - {num}`.")
        return f"{var} - {num}"

    fixed = re.sub(r"\b([a-zA-Z_]\w*)\s*--(?:-)*\s*(\d+|[a-zA-Z_]\w*)", decrement_typo_repl, fixed)
    fixed = re.sub(r"\b([a-zA-Z_]\w*)\s*-\s*-\s*(\d+)", decrement_typo_repl, fixed)

    # 2. Double plus before a number (e.g. n ++ 1 -> n + 1)
    def increment_typo_repl(m: re.Match) -> str:
        var = m.group(1)
        num = m.group(2)
        changes.append(f"Fixed operator typo `{var} ++ {num}` -> `{var} + {num}`.")
        return f"{var} + {num}"

    fixed = re.sub(r"\b([a-zA-Z_]\w*)\s*\+\+(?:\+)*\s*(\d+|[a-zA-Z_]\w*)", increment_typo_repl, fixed)
    fixed = re.sub(r"\b([a-zA-Z_]\w*)\s*\+\s*\+\s*(\d+)", increment_typo_repl, fixed)

    # 3. Spaced comparison operators: = = -> ==, ! = -> !=, > = -> >=, < = -> <=
    for bad_op, good_op in [
        (r"=\s*=", "=="),
        (r"!\s*=", "!="),
        (r">\s*=", ">="),
        (r"<\s*=", "<="),
        (r"=\s*>", ">="),
        (r"=\s*<", "<="),
        (r"&\s*&", "&&"),
        (r"\|\s*\|", "||"),
    ]:
        if re.search(bad_op, fixed) and not re.search(r"==\s*=|!=\s*=", fixed):
            fixed = re.sub(bad_op, good_op, fixed)

    return fixed


def _fix_algorithm_logic_bugs(code: str, changes: list[str]) -> str:
    """Fix common algorithmic logic bugs (e.g. Fibonacci base case bounds, infinite recursion)."""
    updated = code

    # Fibonacci Base Case Fix: if (n < 1) with Fibonacci function name or comment -> if (n <= 1)
    if "fibonacci" in updated.lower() or "fib(" in updated.lower() or "f(n)" in updated.lower():
        def fib_base_repl(m: re.Match) -> str:
            changes.append("Fixed Fibonacci base case logic bug: `n < 1` -> `n <= 1` to prevent infinite recursion on `n = 1`.")
            return f"{m.group(1)}n <= 1{m.group(2)}"

        updated = re.sub(r"(\bif\s*\(\s*)n\s*<\s*1(\s*\))", fib_base_repl, updated)

    return updated


def _fix_entry_point_names(code: str, changes: list[str]) -> str:
    """Fix mainnn, maon, mian, amin -> main."""
    def repl(m: re.Match) -> str:
        changes.append(f"Fixed entry point `{m.group(2)}` -> `main`.")
        return f"{m.group(1)}main{m.group(3)}"
    return re.sub(
        r"(\b(?:int|void)\s+)(main\w+|maon)(\s*\()",
        repl,
        code,
        flags=re.I,
    )


def _is_include_line(line: str) -> bool:
    return bool(re.match(r"\s*#include\b", line))


def _fix_include_directives(code: str, changes: list[str]) -> str:
    """Normalize #include lines without breaking header names like iostream."""
    out: list[str] = []
    for line in code.splitlines():
        m = re.match(r"^(\s*)#include\s*<(.+)$", line)
        if not m:
            out.append(line)
            continue
        indent, rest = m.group(1), m.group(2)
        header = rest.strip().rstrip(">").strip().replace(">", "")
        fixed = f"{indent}#include <{header}>"
        if fixed != line:
            changes.append("Fixed `#include` directive formatting.")
        out.append(fixed)
    return "\n".join(out)


def _polish_spacing(line: str, changes: list[str]) -> str:
    """Clean spacing around stream operators and quotes."""
    fixed = line
    if re.search(r"\bcout\s*<<\s+\"", fixed):
        fixed = re.sub(r"(\bcout\s*<<)\s+\"", r'\1"', fixed)
        changes.append("Fixed spacing in cout statement.")
    if re.search(r"\bcin\s*>>\s+\w", fixed):
        fixed = re.sub(r"(\bcin\s*>>)\s+", r"\1", fixed)
    return fixed


def _fix_printf_stream_op(line: str, changes: list[str]) -> str:
    """Fix C/C++ printf/puts/scanf using << stream operator or missing function parens: printf<< "Hi" -> printf("Hi")."""
    fixed = line
    if re.search(r"\b(printf|puts|scanf)\s*<<\s*", fixed):
        def printf_repl(m: re.Match) -> str:
            func = m.group(1)
            raw_arg = m.group(2).strip()
            changes.append(f"Fixed `{func}<<` stream operator -> `{func}(...)` function call.")

            arg = raw_arg.rstrip(";").strip()

            # If string quote is unclosed
            if arg.startswith('"') and arg.count('"') % 2 != 0:
                arg = arg + '"'
            elif arg.startswith("'") and arg.count("'") % 2 != 0:
                arg = arg + "'"
            elif not arg.startswith('"') and not arg.startswith("'") and re.match(r"^[a-zA-Z_]\w*$", arg):
                arg = f'"{arg}"'

            return f"{func}({arg});"

        fixed = re.sub(r"\b(printf|puts|scanf)\s*<<\s*(.+?)\s*(?:;|$)", printf_repl, fixed)
    return fixed


def _fix_unclosed_string_quotes(line: str, changes: list[str]) -> str:
    """Fix unclosed string quotes cleanly before function call closures and semicolons."""
    fixed = line
    stripped = fixed.strip()
    if not stripped or stripped.startswith(("//", "#", "/*", "*")):
        return line

    # Case: Function call with unclosed quote e.g. printf("Hello world ; or console.log("Hello ;
    fn_match = re.match(r'^(\s*(?:printf|puts|scanf|console\.(?:log|error|warn|info)|System\.out\.print\w*|print)\s*\(\s*")([^"\n]*?)\s*(;|\);\s*)?$', fixed)
    if fn_match:
        prefix = fn_match.group(1)
        content = fn_match.group(2)
        changes.append('Fixed unclosed double quote `"` and closing parenthesis `)`.')
        return f'{prefix}{content}");'

    # Case: cout << "Hello ;
    cout_match = re.match(r'^(\s*cout\s*<<\s*")([^"\n]*?)\s*(;|\);\s*)?$', fixed)
    if cout_match:
        prefix = cout_match.group(1)
        content = cout_match.group(2)
        changes.append('Fixed unclosed double quote `"` in cout output.')
        return f'{prefix}{content}";'

    # General line-level unclosed double quote check
    if fixed.count('"') % 2 != 0:
        if fixed.endswith(";"):
            fixed = fixed[:-1].rstrip() + '";'
        elif fixed.endswith(")"):
            fixed = fixed[:-1].rstrip() + '");'
        else:
            fixed = fixed + '"'
        changes.append('Fixed unclosed double quote `"`.')

    # General line-level unclosed single quote check
    elif fixed.count("'") % 2 != 0:
        if fixed.endswith(";"):
            fixed = fixed[:-1].rstrip() + "';"
        elif fixed.endswith(")"):
            fixed = fixed[:-1].rstrip() + "');"
        else:
            fixed = fixed + "'"
        changes.append("Fixed unclosed single quote `'`.")

    return fixed


def _fix_line_stream_operators(line: str, changes: list[str]) -> str:
    fixed = line
    # Fix cout("Hello") -> cout << "Hello"
    if re.search(r"\bcout\s*\(\s*(.+?)\s*\)", fixed):
        def cout_fn_repl(m: re.Match) -> str:
            changes.append("Fixed `cout(...)` function call syntax -> `cout << ...`.")
            return f"cout << {m.group(1)}"
        fixed = re.sub(r"\bcout\s*\(\s*(.+?)\s*\)", cout_fn_repl, fixed)

    # Fix cin(var) -> cin >> var
    if re.search(r"\bcin\s*\(\s*([a-zA-Z_]\w*)\s*\)", fixed):
        fixed = re.sub(r"\bcin\s*\(\s*([a-zA-Z_]\w*)\s*\)", r"cin >> \1", fixed)
        changes.append("Fixed `cin(...)` syntax -> `cin >> ...`.")

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


def _fix_unquoted_output_strings(code_full: str, line: str, changes: list[str]) -> str:
    """Add quotes only for bareword string literals, preserving declared variables."""
    fixed = line
    declared_vars = _extract_declared_variables(code_full)

    # cout << bareword
    def cout_repl(m: re.Match) -> str:
        word = m.group(2)
        if word in declared_vars or word in _STREAM_KEYWORDS or word.isdigit():
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
        if word in declared_vars or word in _STREAM_KEYWORDS or word.isdigit():
            return m.group(0)
        changes.append(f'Added quotes around `{word}` in `{m.group(1)}()` call.')
        return f'{m.group(1)}("{word}")'

    fixed = re.sub(
        r'\b(printf|puts|print)\s*\(\s*([a-zA-Z_]\w*)\s*\)',
        print_repl,
        fixed,
    )

    # console.log(hello)
    def console_repl(m: re.Match) -> str:
        word = m.group(2)
        if word in declared_vars or word in _STREAM_KEYWORDS or word.isdigit():
            return m.group(0)
        changes.append(f'Added quotes around `{word}` in `{m.group(1)}()`.')
        return f'{m.group(1)}("{word}")'

    fixed = re.sub(
        r'\b(console\.(?:log|error|warn|info))\s*\(\s*([a-zA-Z_]\w*)\s*\)',
        console_repl,
        fixed,
    )

    # System.out.println(hello)
    def java_repl(m: re.Match) -> str:
        word = m.group(2)
        if word in declared_vars or word in _STREAM_KEYWORDS or word.isdigit():
            return m.group(0)
        changes.append(f'Added quotes around `{word}` in Java print call.')
        return f'{m.group(1)}("{word}")'

    fixed = re.sub(
        r'\b(System\.out\.print\w*)\s*\(\s*([a-zA-Z_]\w*)\s*\)',
        java_repl,
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

def _single_pass(code: str, lang: str, changes: list[str]) -> str:
    """One full remediation pass."""
    code_full = code
    code = fix_keyword_typos(code, lang, changes)
    code = fuzzy_fix_keywords(code, lang, changes)
    code = _fix_entry_point_names(code, changes)
    code = _fix_include_directives(code, changes)

    lines: list[str] = []
    for line in code.splitlines():
        if _is_include_line(line):
            lines.append(line)
            continue
        line = _fix_operator_typos(line, changes)
        line = _fix_printf_stream_op(line, changes)
        line = _fix_line_stream_operators(line, changes)
        line = _fix_unquoted_output_strings(code_full, line, changes)
        line = _fix_unclosed_string_quotes(line, changes)
        line = _polish_spacing(line, changes)
        line = _fix_line_semicolons(line, changes)
        lines.append(line)
    code = "\n".join(lines)

    if lang == "Python":
        code = _fix_python_lines(code, changes)

    code = _fix_algorithm_logic_bugs(code, changes)
    code = _fix_braces(code, changes)
    code = _fix_delimiter(code, "(", ")", "parentheses", changes)
    code = _fix_delimiter(code, "[", "]", "square brackets", changes)
    return code


def fix_syntax(code: str, language: str = "Auto-Detect") -> tuple[str, list[str]]:
    """Multi-pass syntax fixer — repeats until code stabilizes (max 4 passes)."""
    code = normalize_code(code)
    all_changes: list[str] = []
    lang = detect_language(code, "Auto-Detect")

    for _ in range(4):
        pass_changes: list[str] = []
        new_code = _single_pass(code, lang, pass_changes)
        all_changes.extend(pass_changes)
        if new_code.strip() == code.strip():
            break
        code = new_code
        lang = detect_language(code, "Auto-Detect")

    return code, _dedupe_changes(all_changes)


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
