"""Common misspelled programming keywords and symbols — per language."""

from __future__ import annotations

import re

# wrong -> correct (lowercase keys; applied case-insensitively where safe)
TYPO_MAP: dict[str, dict[str, str]] = {
    "C / C++": {
        "incldue": "include", "inlcude": "include", "incluude": "include",
        "iostreamm": "iostream", "iosteam": "iostream", "iostreame": "iostream",
        "namespase": "namespace", "namespcae": "namespace", "namepsace": "namespace",
        "namesace": "namespace", "namsespace": "namespace",
        "stdd": "std", "sttd": "std",
        "usingg": "using", "usng": "using",
        "retun": "return", "retrun": "return", "reutrn": "return", "retrn": "return",
        "vooid": "void", "viod": "void", "voiid": "void",
        "innt": "int", "nit": "int", "itn": "int",
        "flaot": "float", "flot": "float",
        "coutt": "cout", "cou": "cout", "ctu": "cout",
        "cinn": "cin", "icn": "cin",
        "priintf": "printf", "prinf": "printf", "printff": "printf",
        "scannf": "scanf",
        "charr": "char", "carh": "char",
        "mainn": "main", "mainnn": "main", "mian": "main", "amin": "main", "mnai": "main",
        "douuble": "double", "booL": "bool",
        "publiic": "public", "privatte": "private",
        "elsse": "else", "eles": "else",
        "whille": "while", "whiel": "while",
        "forr": "for",
        "nulllptr": "nullptr", "nullpt": "nullptr",
    },
    "Java": {
        "publlic": "public", "publiic": "public", "publicc": "public",
        "privatte": "private", "prvate": "private",
        "sttaic": "static", "statc": "static", "statiic": "static",
        "voiid": "void", "voiod": "void",
        "classs": "class", "calss": "class", "clss": "class",
        "Sttring": "String", "Strng": "String", "Strin": "String",
        "Sytem": "System", "Sysetm": "System", "Sstem": "System",
        "prinln": "println", "printl": "println", "printLn": "println",
        "imprt": "import", "impor": "import",
        "retrun": "return", "retun": "return",
        "mainn": "main", "mian": "main",
        "Intteger": "Integer", "integr": "Integer",
        "nwe": "new", "enw": "new",
        "exttends": "extends", "implemennts": "implements",
    },
    "Python": {
        "deff": "def", "dfe": "def",
        "impport": "import", "improt": "import", "imprt": "import",
        "retrun": "return", "retun": "return", "reutrn": "return",
        "prinnt": "print", "prnt": "print", "pirnt": "print",
        "eliff": "elif", "eelif": "elif",
        "whille": "while", "whiel": "while",
        "foor": "for", "fro": "for",
        "clss": "class", "calss": "class",
        "flase": "False", "Flase": "False", "fasle": "False",
        "Treu": "True", "ture": "True", "tru": "True",
        "nane": "None", "non": "None",
        "exept": "except", "excpet": "except",
        "finallly": "finally",
        "lamda": "lambda",
        "yiled": "yield",
    },
    "JavaScript / TypeScript": {
        "fucntion": "function", "funciton": "function", "funtion": "function",
        "functon": "function", "funtion": "function",
        "cosnole": "console", "consol": "console", "consoel": "console",
        "lgo": "log", "logg": "log",
        "retrun": "return", "retun": "return",
        "cosnt": "const", "cnost": "const",
        "llet": "let", "varr": "var",
        "documnet": "document", "windwo": "window",
        "asyncc": "async", "awiat": "await",
        "calss": "class", "exttends": "extends",
    },
    "PHP": {
        "fucntion": "function", "funciton": "function",
        "ecoh": "echo", "ehco": "echo",
        "retrun": "return", "retun": "return",
        "includde": "include", "requirre": "require",
    },
    "Go": {
        "fucntion": "func", "funciton": "func",
        "fomr": "for", "form": "for",
        "retrun": "return", "retun": "return",
        "packge": "package", "packag": "package",
        "improt": "import", "imprt": "import",
        "fmt.Prnt": "fmt.Print", "fmt.Pirntln": "fmt.Println",
    },
    "SQL": {
        "sellect": "SELECT", "selec": "SELECT", "SELECET": "SELECT",
        "form": "FROM", "frm": "FROM",
        "wher": "WHERE", "whee": "WHERE",
        "insrt": "INSERT", "instert": "INSERT",
        "updat": "UPDATE", "upddate": "UPDATE",
        "delet": "DELETE", "deltete": "DELETE",
        "jion": "JOIN", "jooin": "JOIN",
        "gropu": "GROUP", "ordr": "ORDER",
    },
}

# Phrase-level fixes (multi-word typos)
PHRASE_FIXES: list[tuple[str, str, str]] = [
    (r"\busing\s+namepsace\s+std\b", "using namespace std", "C / C++"),
    (r"\busing\s+namespase\s+std\b", "using namespace std", "C / C++"),
    (r"\busing\s+namespace\s+stdd\b", "using namespace std", "C / C++"),
    (r"\busing\s+namespace\s+std\s*;", "using namespace std", "C / C++"),
    (r"#includ\s*<", "#include <", "C / C++"),
    (r"#incluude\s*<", "#include <", "C / C++"),
    (r"#include\s*iostream\s*>", "#include <iostream>", "C / C++"),
    (r"\bSystem\.out\.prinln\b", "System.out.println", "Java"),
    (r"\bSystem\.out\.printIn\b", "System.out.println", "Java"),
    (r"\bconsole\.lgo\b", "console.log", "JavaScript / TypeScript"),
    (r"\bconsole\.logg\b", "console.log", "JavaScript / TypeScript"),
    (r"\bpublic\s+static\s+voiid\s+main\b", "public static void main", "Java"),
    (r"\bpublic\s+sttaic\s+void\s+main\b", "public static void main", "Java"),
]


def fix_keyword_typos(code: str, language: str, changes: list[str]) -> str:
    """Fix misspelled language keywords and common symbol-adjacent typos."""
    lang = language if language in TYPO_MAP else "Auto-Detect"

    # Apply phrase fixes for detected/all languages
    for pattern, replacement, phrase_lang in PHRASE_FIXES:
        if lang == "Auto-Detect" or lang == phrase_lang:
            if re.search(pattern, code, re.I):
                code = re.sub(pattern, replacement, code, flags=re.I)
                changes.append(f"Fixed phrase typo -> `{replacement}`.")

    # Apply word-level typo maps for detected language + universal C-family overlap
    langs_to_apply = [lang] if lang in TYPO_MAP else list(TYPO_MAP.keys())
    if lang == "Auto-Detect":
        langs_to_apply = list(TYPO_MAP.keys())

    applied: set[str] = set()
    for apply_lang in langs_to_apply:
        for wrong, right in TYPO_MAP.get(apply_lang, {}).items():
            if wrong in applied:
                continue
            pattern = rf"\b{re.escape(wrong)}\b"
            if re.search(pattern, code, re.I):
                # Preserve case for SQL keywords
                if right.isupper():
                    code = re.sub(pattern, right, code)
                else:
                    code = re.sub(pattern, right, code, flags=re.I)
                changes.append(f"Fixed keyword `{wrong}` -> `{right}`.")
                applied.add(wrong)

    return code


def scan_keyword_typos(code: str, language: str) -> list[str]:
    """Detect likely keyword typos still present."""
    issues: list[str] = []
    for apply_lang, typo_map in TYPO_MAP.items():
        if language != "Auto-Detect" and apply_lang != language:
            continue
        for wrong in typo_map:
            if re.search(rf"\b{re.escape(wrong)}\b", code, re.I):
                issues.append(f"Misspelled keyword `{wrong}` (should be `{typo_map[wrong]}`).")
    return issues
