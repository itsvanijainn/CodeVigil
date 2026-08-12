"""Fuzzy keyword correction using language keyword dictionaries."""

from __future__ import annotations

import difflib
import re

# Canonical keywords per language (lowercase)
LANGUAGE_KEYWORDS: dict[str, list[str]] = {
    "C / C++": [
        "auto", "bool", "break", "case", "catch", "char", "class", "const", "continue",
        "cout", "cin", "default", "delete", "do", "double", "else", "enum", "extern",
        "false", "float", "for", "goto", "if", "include", "int", "long", "main",
        "namespace", "new", "nullptr", "operator", "private", "protected", "public",
        "return", "short", "signed", "sizeof", "static", "std", "string", "struct",
        "switch", "template", "this", "throw", "true", "try", "typedef", "typename",
        "using", "unsigned", "void", "volatile", "while",
    ],
    "Java": [
        "abstract", "boolean", "break", "byte", "case", "catch", "char", "class",
        "continue", "default", "do", "double", "else", "enum", "extends", "final",
        "finally", "float", "for", "if", "implements", "import", "instanceof", "int",
        "interface", "long", "main", "new", "null", "package", "private", "protected",
        "public", "return", "short", "static", "strictfp", "String", "super", "switch",
        "synchronized", "System", "this", "throw", "throws", "transient", "try", "void",
        "volatile", "while", "println", "print",
    ],
    "Python": [
        "and", "as", "assert", "async", "await", "break", "class", "continue", "def",
        "del", "elif", "else", "except", "False", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "None", "nonlocal", "not", "or", "pass",
        "print", "raise", "return", "True", "try", "while", "with", "yield",
    ],
    "JavaScript / TypeScript": [
        "async", "await", "break", "case", "catch", "class", "const", "continue",
        "debugger", "default", "delete", "do", "else", "export", "extends", "false",
        "finally", "for", "function", "if", "import", "in", "instanceof", "let",
        "new", "null", "return", "super", "switch", "this", "throw", "true", "try",
        "typeof", "var", "void", "while", "console", "log",
    ],
    "PHP": [
        "abstract", "and", "array", "as", "break", "case", "catch", "class", "const",
        "continue", "declare", "default", "do", "echo", "else", "elseif", "enddeclare",
        "endfor", "endforeach", "endif", "endswitch", "endwhile", "extends", "false",
        "final", "finally", "for", "foreach", "function", "global", "if", "implements",
        "include", "instanceof", "insteadof", "interface", "isset", "list", "namespace",
        "new", "null", "or", "print", "private", "protected", "public", "require",
        "return", "static", "switch", "throw", "trait", "true", "try", "unset",
        "use", "var", "while", "xor",
    ],
    "Go": [
        "break", "case", "chan", "const", "continue", "default", "defer", "else",
        "fallthrough", "for", "func", "go", "goto", "if", "import", "interface",
        "map", "package", "range", "return", "select", "struct", "switch", "type",
        "var",
    ],
    "SQL": [
        "SELECT", "FROM", "WHERE", "INSERT", "INTO", "UPDATE", "DELETE", "JOIN",
        "LEFT", "RIGHT", "INNER", "OUTER", "ON", "AND", "OR", "NOT", "NULL",
        "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET", "CREATE", "TABLE",
        "DROP", "ALTER", "INDEX", "VALUES", "SET", "AS", "DISTINCT", "COUNT",
    ],
}

# Typo signals for language detection (even wrong spellings)
LANG_SIGNALS: dict[str, list[str]] = {
    "C / C++": [
        "#include", "#incl", "iostream", "using namespace", "namepsace", "namespace",
        "cout", "coutt", "cin", "cinn", "std", "::", "printf", "scanf", "nullptr",
        "main(", "mainn", "mainnn", "int main", "void main",
    ],
    "Java": [
        "public class", "System.out", "Sytem", "static void main", "println",
        "String[]", "package ", "import java",
    ],
    "Python": [
        "def ", "deff ", "import ", "impport", "print(", "print ", "prinnt",
        "elif ", "lambda", "self", "__init__", "from ", "True", "False", "None",
    ],
    "JavaScript / TypeScript": [
        "function ", "fucntion", "console.", "const ", "let ", "var ", "=>",
        "document.", "window.", "async ", "await ",
    ],
    "PHP": ["<?php", "$_", "echo ", "ecoh", "function ", "$"],
    "Go": ["func ", "package ", "fmt.", ":=", "go "],
    "SQL": ["SELECT", "sellect", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"],
}

# Never fuzzy-replace these identifiers (user variables, common words)
SKIP_FUZZY: frozenset[str] = frozenset({
    "hello", "world", "test", "foo", "bar", "baz", "temp", "tmp", "data", "result",
    "value", "name", "user", "item", "count", "index", "key", "args", "argv",
    "i", "j", "k", "n", "x", "y", "z", "a", "b", "c",
})


def detect_language_robust(code: str) -> str:
    """Detect language using signals — works even when keywords are misspelled."""
    code_lower = code.lower()
    scores: dict[str, int] = {}
    for lang, signals in LANG_SIGNALS.items():
        score = sum(1 for s in signals if s.lower() in code_lower)
        if score:
            scores[lang] = score
    if scores:
        return max(scores, key=scores.get)
    return "Auto-Detect"


def fuzzy_fix_keywords(code: str, language: str, changes: list[str]) -> str:
    """Fix misspelled keywords via fuzzy matching against canonical keyword lists."""
    if language not in LANGUAGE_KEYWORDS:
        return code

    keywords = LANGUAGE_KEYWORDS[language]
    kw_lower = [k.lower() for k in keywords]
    # Map lowercase -> canonical casing
    canonical = {k.lower(): k for k in keywords}

    def replace_word(m: re.Match) -> str:
        word = m.group(0)
        wl = word.lower()
        if wl in kw_lower or wl in SKIP_FUZZY or word.isupper() or len(word) < 3:
            return word
        if wl.isdigit():
            return word
        matches = difflib.get_close_matches(wl, kw_lower, n=1, cutoff=0.72)
        if not matches:
            return word
        best = matches[0]
        if best == wl:
            return word
        # Don't replace if already a valid substring match
        fixed = canonical.get(best, best)
        changes.append(f"Corrected `{word}` -> `{fixed}` (fuzzy keyword match).")
        return fixed

    # Only replace bare identifiers outside strings (line-by-line safe approach)
    lines = []
    for line in code.splitlines():
        # Never fuzzy-correct inside #include or // comment lines
        if re.match(r"\s*#include", line) or line.strip().startswith("//"):
            lines.append(line)
            continue
        if line.strip().startswith("#") and "include" not in line:
            lines.append(line)
            continue
        fixed_line = re.sub(r"\b[a-zA-Z_]\w*\b", replace_word, line)
        lines.append(fixed_line)
    return "\n".join(lines)
