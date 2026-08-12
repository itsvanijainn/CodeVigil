"""
CodeVigil — Cyber Security Vulnerability Intelligence & Radar System
====================================================================
A state-of-the-art SOC dashboard for scanning code, analyzing CVEs,
detecting language-aware syntax bugs, and generating instant AI code remediations.
"""

import streamlit as st
import json
import time
import sys
import re
import ast
import pandas as pd
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from ir_engine.tfidf_retriever import TFIDFRetriever
from ir_engine.bm25_retriever import BM25Retriever
from ir_engine.hybrid_retriever import HybridRetriever
from ml_engine.classifier import VulnTypeClassifier
from ml_engine.severity_predictor import SeverityPredictor
from ml_engine.fix_recommender import FixRecommender
from utils.metrics import precision_at_k, recall_at_k, f1_at_k, mean_reciprocal_rank
from utils.code_detector import detect_code_patterns
from utils.remediation import generate_remediation

LANGUAGE_OPTIONS = [
    "Auto-Detect", "C / C++", "Java", "Python", "JavaScript / TypeScript", "PHP",
]


# ─────────────────────────────────────────────
# Page Configuration
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="CodeVigil — Cyber Radar & Security Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Shared Session State Management
if "active_view" not in st.session_state:
    st.session_state.active_view = "main"
if "selected_cve" not in st.session_state:
    st.session_state.selected_cve = None
if "code_query" not in st.session_state:
    st.session_state.code_query = "public User getUserByUsername(String username) {\n    Connection conn = null;\n    try {\n        rs = stmt.executeQuery(\"SELECT * FROM users WHERE username = '\" + username + \"'\");\n        // ..."
if "selected_language" not in st.session_state:
    st.session_state.selected_language = "Auto-Detect"
if "scanning_anim" not in st.session_state:
    st.session_state.scanning_anim = False


# ─────────────────────────────────────────────
# Global Custom Theme (Matrix Cyberpunk + Laser Scan Effects)
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;600;700;800&family=Outfit:wght@400;500;600;700&display=swap');

:root {
    --bg-main: #060907;
    --bg-panel: #0d150e;
    --bg-panel2: #09100a;
    --border-green: #1b2e1c;
    --border-bright: #22c55e;
    --green-glow: #4ade80;
    --green-dim: #16a34a;
    --amber: #facc15;
    --red: #f87171;
    --orange: #fb923c;
    --cyan: #38bdf8;
    --purple: #c084fc;
    --text-main: #e2e8f0;
    --text-dim: #849385;
    --font-mono: 'JetBrains Mono', monospace;
    --font-sans: 'Outfit', sans-serif;
    --font-disp: 'Space Grotesk', sans-serif;
}

/* Global Background & Matrix Grid */
.stApp {
    background-color: var(--bg-main) !important;
    color: var(--text-main) !important;
    font-family: var(--font-sans) !important;
    background-image:
        linear-gradient(rgba(74,222,128,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(74,222,128,0.03) 1px, transparent 1px) !important;
    background-size: 30px 30px !important;
}

/* Laser Scan Animation Overlay */
@keyframes laserSweep {
    0% { top: 0%; opacity: 0.8; }
    50% { opacity: 1; }
    100% { top: 100%; opacity: 0.2; }
}

.laser-scanner {
    position: relative;
    overflow: hidden;
}

.laser-line {
    position: absolute;
    left: 0;
    width: 100%;
    height: 3px;
    background: linear-gradient(90deg, transparent, #4ade80, transparent);
    box-shadow: 0 0 15px #4ade80, 0 0 30px #4ade80;
    animation: laserSweep 3s infinite linear;
    z-index: 5;
    pointer-events: none;
}

/* Sidebar Styling */
[data-testid="stSidebar"] {
    background-color: var(--bg-panel2) !important;
    border-right: 1px solid var(--border-green) !important;
}

/* Terminal Shell Container */
.terminal-shell {
    background: #080d08;
    border: 1px solid var(--border-green);
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 0 25px rgba(74, 222, 128, 0.05), 0 20px 50px rgba(0,0,0,0.7);
    margin-bottom: 20px;
}

.term-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border-green);
    background: #0b120c;
}

.dot {
    width: 11px;
    height: 11px;
    border-radius: 50%;
}
.dot-red { background: #f87171; }
.dot-yellow { background: #facc15; }
.dot-green { background: #4ade80; }

.term-bar .path {
    margin-left: 12px;
    font-family: var(--font-mono);
    font-size: 12.5px;
    color: var(--text-dim);
}

/* Interactive Feature Cards */
.feature-card-staggered {
    background: var(--bg-panel);
    border: 1px solid var(--border-green);
    border-radius: 12px;
    padding: 18px;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    position: relative;
    overflow: hidden;
}

.feature-card-staggered:hover {
    border-color: var(--green-glow);
    transform: translateY(-4px) scale(1.01);
    box-shadow: 0 0 25px rgba(74, 222, 128, 0.25);
}

/* Terminal Result Rows */
.rline {
    display: flex;
    align-items: center;
    gap: 16px;
    font-family: var(--font-mono);
    font-size: 13px;
    border-bottom: 1px solid var(--border-green);
    padding: 12px 10px;
    transition: background 0.2s ease;
}

.rline:hover {
    background: rgba(74, 222, 128, 0.05);
}

.rline .id {
    color: var(--green-glow);
    font-weight: 700;
    width: 150px;
}

/* Badges */
.sev {
    font-size: 11px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 5px;
    text-transform: uppercase;
    font-family: var(--font-mono);
}

.sev.crit { background: rgba(248,113,113,0.15); color: var(--red); border: 1px solid rgba(248,113,113,0.3); }
.sev.high { background: rgba(251,146,60,0.15); color: var(--orange); border: 1px solid rgba(251,146,60,0.3); }
.sev.med { background: rgba(250,204,21,0.15); color: var(--amber); border: 1px solid rgba(250,204,21,0.3); }
.sev.low { background: rgba(74,222,128,0.15); color: var(--green-glow); border: 1px solid rgba(74,222,128,0.3); }

/* Stat Cards */
.stat-card-term {
    background: var(--bg-panel);
    border: 1px solid var(--border-green);
    border-radius: 12px;
    padding: 16px 18px;
}

.stat-card-term .lbl {
    font-size: 11.5px;
    color: var(--text-dim);
    font-family: var(--font-mono);
    margin-bottom: 4px;
}

.stat-card-term .val {
    font-family: var(--font-mono);
    font-size: 26px;
    font-weight: 700;
    color: var(--green-glow);
}

/* Controls */
div[data-baseweb="select"] > div {
    background-color: #0b120c !important;
    border-color: var(--border-green) !important;
    color: var(--text-main) !important;
    border-radius: 8px !important;
    font-family: var(--font-mono) !important;
}

textarea, input {
    background-color: #080d08 !important;
    color: #cdeecd !important;
    font-family: var(--font-mono) !important;
    border: 1px solid var(--border-green) !important;
    border-radius: 8px !important;
    line-height: 1.6 !important;
}

textarea:focus, input:focus {
    border-color: var(--green-glow) !important;
    box-shadow: 0 0 15px rgba(74,222,128,0.25) !important;
}

/* Terminal Buttons */
.stButton > button {
    background: var(--green-glow) !important;
    color: #04150a !important;
    font-family: var(--font-mono) !important;
    font-weight: 800 !important;
    font-size: 14px !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 12px 24px !important;
    transition: all 0.25s ease !important;
}

.stButton > button:hover {
    background: #22c55e !important;
    box-shadow: 0 0 25px rgba(74,222,128,0.6) !important;
    transform: translateY(-2px) !important;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Load Data & Models
# ─────────────────────────────────────────────
@st.cache_resource
def load_models():
    """Load expanded CVE database and initialize IR and ML engines."""
    db_path = Path("data/cve_database.json")
    if not db_path.exists():
        st.error(f"CVE database not found at {db_path}")
        st.stop()
    
    with open(db_path, "r", encoding="utf-8") as f:
        cves = json.load(f)
    
    tfidf = TFIDFRetriever(cves)
    bm25 = BM25Retriever(cves)
    hybrid = HybridRetriever(cves)
    
    type_clf = VulnTypeClassifier()
    type_clf.train(cves)
    
    sev_pred = SeverityPredictor()
    sev_pred.train(cves)
    
    fix_rec = FixRecommender(cves)
    
    return {
        "cves": cves,
        "tfidf": tfidf,
        "bm25": bm25,
        "hybrid": hybrid,
        "type_classifier": type_clf,
        "severity_predictor": sev_pred,
        "fix_recommender": fix_rec,
    }


with st.spinner("⚡ Initializing CodeVigil Intelligence Matrix..."):
    models = load_models()


# ─────────────────────────────────────────────
# LANGUAGE-AWARE AST & SYNTAX BUG CHECKER
# ─────────────────────────────────────────────
def check_code_syntax(code: str, language: str = "Auto-Detect") -> dict:
    """Performs language-aware AST & static syntax analysis without misapplying Python parser to C++/Java."""
    # Detect language if set to Auto-Detect
    detected_lang = language
    if language == "Auto-Detect":
        if "#include" in code or "using namespace" in code or re.search(r"\bcout\s*<", code) or re.search(r"\bcin\s*>"):
            detected_lang = "C / C++"
        elif "public class" in code or "System.out.print" in code or "public static void main" in code:
            detected_lang = "Java"
        elif "def " in code or "import " in code or "print(" in code:
            detected_lang = "Python"
        elif "function " in code or "console.log" in code or "const " in code or "let " in code:
            detected_lang = "JavaScript / TypeScript"
        elif "<?php" in code or "$_" in code:
            detected_lang = "PHP"

    syntax_errors = []
    logic_warnings = []

    # Bracket matching (All languages)
    if code.count("{") != code.count("}"):
        syntax_errors.append(f"❌ **Syntax Error:** Unmatched curly braces `{{}}` (Found {code.count('{')} `{{` and {code.count('}')} `}}`).")
    if code.count("(") != code.count(")"):
        syntax_errors.append(f"❌ **Syntax Error:** Unmatched parentheses `()` (Found {code.count('(')} `(` and {code.count(')')} `)`).")
    if code.count("[") != code.count("]"):
        syntax_errors.append(f"❌ **Syntax Error:** Unmatched square brackets `[]` (Found {code.count('[')} `[` and {code.count(']')} `]`).")

    # 1. PYTHON
    if detected_lang == "Python":
        try:
            ast.parse(code)
        except SyntaxError as e:
            syntax_errors.append(f"❌ **Python Syntax Error (Line {e.lineno}, Col {e.offset}):** `{e.msg}` in line: `{e.text.strip() if e.text else ''}`")

        if re.search(r"==\s*None|!=\s*None", code):
            logic_warnings.append("⚠️ **Python Idiom Warning:** Use `is None` or `is not None` instead of `== None` comparison.")
        if "open(" in code and "with open(" not in code and ".close()" not in code:
            logic_warnings.append("⚠️ **Resource Leak Warning:** File `open()` without `with` context manager or `.close()` call.")

    # 2. C / C++
    elif detected_lang == "C / C++":
        if "int main" in code and "return" not in code:
            logic_warnings.append("⚠️ **C/C++ Standard Warning:** `main()` function missing explicit `return` statement.")
        if re.search(r"\bgets\s*\(", code):
            syntax_errors.append("❌ **Dangerous Function Error:** `gets()` is obsolete and buffer overflow prone. Use `fgets()`.")
        if re.search(r"\bstrcpy\s*\(", code):
            logic_warnings.append("⚠️ **Buffer Safety Warning:** `strcpy()` is unsafe. Consider using `strncpy()` or `std::string`.")

        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            l = line.strip()
            if l and not l.startswith("#") and not l.startswith("//") and not l.endswith(";") and not l.endswith("{") and not l.endswith("}"):
                if (l.startswith("cout") or l.startswith("cin") or l.startswith("return") or "=" in l) and not l.startswith("using") and not l.startswith("int main"):
                    syntax_errors.append(f"❌ **Syntax Error (Line {i}):** Missing trailing semicolon `;` in `{l}`")

    # 3. JAVA
    elif detected_lang == "Java":
        if "class" in code and "public static void main" not in code:
            logic_warnings.append("⚠️ **Java Structure Warning:** Class missing `public static void main(String[] args)` entry point.")
        if re.search(r"System\.out\.print.*?\+.*?\"", code):
            logic_warnings.append("⚠️ **Performance Warning:** String concatenation inside loop or print; consider `StringBuilder`.")
        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            l = line.strip()
            if l and not l.startswith("//") and not l.startswith("package") and not l.startswith("import") and not l.endswith(";") and not l.endswith("{") and not l.endswith("}"):
                if ("=" in l or l.startswith("System.out") or l.startswith("return")) and not l.startswith("public") and not l.startswith("private"):
                    syntax_errors.append(f"❌ **Syntax Error (Line {i}):** Missing trailing semicolon `;` in `{l}`")

    # 4. JAVASCRIPT / TYPESCRIPT
    elif detected_lang == "JavaScript / TypeScript":
        if "eval(" in code:
            logic_warnings.append("⚠️ **Security Warning:** `eval()` executes arbitrary strings. Use safer parsers.")
        if re.search(r"\bvar\b", code):
            logic_warnings.append("⚠️ **Modern JS Warning:** Prefer `let` or `const` over `var` block-scoping.")

    return {
        "language": detected_lang,
        "syntax_errors": syntax_errors,
        "logic_warnings": logic_warnings,
        "is_valid": len(syntax_errors) == 0
    }


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="display:flex; align-items:center; gap:10px; padding: 4px 0 16px 0;">
        <span style="font-family: 'JetBrains Mono', monospace; font-weight:800; font-size:20px; color:#e2e8f0;">
            <span style="color:#4ade80;">[</span>CodeVigil<span style="color:#4ade80;">]</span>
        </span>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Workspace Navigation
    st.markdown("<div style='font-size:11px; text-transform:uppercase; letter-spacing:0.1em; color:#849385; margin-bottom:8px;'>Workspace Navigation</div>", unsafe_allow_html=True)
    
    if st.button("◧ Main Terminal Radar", use_container_width=True):
        st.session_state.active_view = "main"
        st.session_state.selected_cve = None
        st.rerun()

    if st.button("🐛 Syntax Bug Detector", use_container_width=True):
        st.session_state.active_view = "bug_detection"
        st.rerun()

    if st.button("🤖 AI Code Remediation", use_container_width=True):
        st.session_state.active_view = "security_audit"
        st.rerun()

    if st.button("📈 Compare Algorithms", use_container_width=True):
        st.session_state.active_view = "compare_algos"
        st.rerun()

    if st.button("📚 About Vulnerabilities", use_container_width=True):
        st.session_state.active_view = "about_vulns"
        st.rerun()

    if st.button("📄 Export Reports", use_container_width=True):
        st.session_state.active_view = "export_report"
        st.rerun()
        
    st.markdown("---")
    
    # IR Engine Config
    st.markdown("<div style='font-size:11px; text-transform:uppercase; letter-spacing:0.1em; color:#849385; margin-bottom:8px;'>IR Engine Config</div>", unsafe_allow_html=True)
    
    algorithm = st.selectbox(
        "Search Algorithm:",
        ["TF-IDF + Cosine Similarity", "BM25 (Okapi)", "Hybrid (TF-IDF + BM25)"],
        index=0
    )
    
    top_k = 10
    
    st.markdown("---")
    
    # Search Filters
    st.markdown("<div style='font-size:11px; text-transform:uppercase; letter-spacing:0.1em; color:#849385; margin-bottom:8px;'>Search Filters</div>", unsafe_allow_html=True)
    
    severity_filter = st.multiselect(
        "Severity Level:",
        ["Critical", "High", "Medium", "Low"],
        default=[]
    )
    
    type_filter = st.multiselect(
        "Vulnerability Category:",
        models["type_classifier"].classes_.tolist(),
        default=[]
    )
    
    st.markdown("---")
    
    # Quick Stats
    st.markdown(f"""
    <div style="font-family: 'JetBrains Mono', monospace; font-size:11.5px; color:#849385;">
        <b>Engine Intelligence Stats:</b><br>
        • Indexed CVEs: <span style="color:#4ade80;">{len(models['cves'])}</span><br>
        • TF-IDF Features: <span style="color:#4ade80;">{len(models['tfidf'].get_vocabulary()):,}</span><br>
        • ML Vuln Classes: <span style="color:#4ade80;">{len(models['type_classifier'].classes_)}</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.caption("CodeVigil v3.3 · Automated Threat Radar")


# ─────────────────────────────────────────────
# VIEW 1: DEDICATED CVE DETAIL PAGE
# ─────────────────────────────────────────────
if st.session_state.active_view == "cve_detail" and st.session_state.selected_cve:
    cve_id = st.session_state.selected_cve
    cve_item = next((c for c in models["cves"] if c["cve_id"] == cve_id), None)
    
    if cve_item:
        if st.button("← Return to Terminal Radar"):
            st.session_state.active_view = "main"
            st.session_state.selected_cve = None
            st.rerun()
            
        st.markdown(f"""
        <div style="font-family: 'JetBrains Mono', monospace; margin: 10px 0 20px 0;">
            <div style="font-size:12px; color:#4ade80;">codevigil@inspector:~$ cat {cve_item['cve_id']}.log</div>
            <h1 style="font-size:32px; font-weight:800; margin:4px 0;">Vulnerability Detail: <span style="color:#4ade80;">{cve_item['cve_id']}</span></h1>
        </div>
        """, unsafe_allow_html=True)
        
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"<div class='stat-card-term'><div class='lbl'>CVE ID</div><div class='val' style='font-size:19px;'>{cve_item['cve_id']}</div></div>", unsafe_allow_html=True)
        with c2:
            sev_c = "#f87171" if cve_item['severity']=="Critical" else ("#fb923c" if cve_item['severity']=="High" else "#facc15")
            st.markdown(f"<div class='stat-card-term'><div class='lbl'>SEVERITY</div><div class='val' style='font-size:19px; color:{sev_c};'>{cve_item['severity']}</div></div>", unsafe_allow_html=True)
        with c3:
            st.markdown(f"<div class='stat-card-term'><div class='lbl'>CATEGORY</div><div class='val' style='font-size:15px; color:#38bdf8;'>{cve_item['type']}</div></div>", unsafe_allow_html=True)
        with c4:
            st.markdown(f"<div class='stat-card-term'><div class='lbl'>PATCH SLA</div><div class='val' style='font-size:15px; color:#4ade80;'>{'24 HOURS' if cve_item['severity']=='Critical' else '72 HOURS'}</div></div>", unsafe_allow_html=True)
            
        st.markdown("<br>", unsafe_allow_html=True)
        
        col_desc, col_remed = st.columns([1.2, 1])
        
        with col_desc:
            st.markdown("<div class='feature-card-staggered'>", unsafe_allow_html=True)
            st.markdown("### 📝 Vulnerability Description")
            st.write(cve_item['description'])
            
            if cve_item.get('affected_software'):
                st.markdown(f"**📦 Affected Software / Package:** `{cve_item['affected_software']}`")
                
            if cve_item.get('affected_code'):
                st.markdown("**🔍 Vulnerable Code Signature Pattern:**")
                st.code(cve_item['affected_code'], language="text")
            st.markdown("</div>", unsafe_allow_html=True)
            
        with col_remed:
            st.markdown("<div class='feature-card-staggered'>", unsafe_allow_html=True)
            st.markdown("### 🛠️ Patch & Remediation Guidance")
            fix = models["fix_recommender"].get_fix(cve_id=cve_item['cve_id'])
            
            if fix['specific_fix']:
                st.success(f"**Specific Fix:** {fix['specific_fix']}")
                
            st.markdown(f"**Priority:** `{fix['priority']}`")
            
            if fix['immediate_actions']:
                st.markdown("**⚡ Immediate Mitigation Actions:**")
                for act in fix['immediate_actions']:
                    st.markdown(f"- {act}")
                    
            if fix['generic_fixes']:
                with st.expander("📌 General Defense Guidelines", expanded=True):
                    for gf in fix['generic_fixes']:
                        st.markdown(f"- {gf}")
            st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# VIEW 2: SYNTAX BUG DETECTOR (Language-Aware AST & Static Analysis)
# ─────────────────────────────────────────────
elif st.session_state.active_view == "bug_detection":
    if st.button("← Back to Main Dashboard"):
        st.session_state.active_view = "main"
        st.rerun()
        
    st.markdown("""
    <div style="font-family: 'JetBrains Mono', monospace; margin: 10px 0 20px 0;">
        <div style="font-size:12px; color:#4ade80;">codevigil@bugs:~$ ast_parser --check</div>
        <h1 style="font-size:32px; font-weight:800; margin:4px 0;">🐛 Interactive Syntax & Logic Bug Detector</h1>
        <p style="color:#849385;">Performs language-aware AST and static syntax analysis (Python, C/C++, Java, JS, PHP) on your code.</p>
    </div>
    """, unsafe_allow_html=True)
    
    col_lang_b, col_b_space = st.columns([1, 2])
    with col_lang_b:
        selected_lang_bug = st.selectbox(
            "🌐 Programming Language:",
            LANGUAGE_OPTIONS,
            index=LANGUAGE_OPTIONS.index(st.session_state.selected_language) if st.session_state.selected_language in LANGUAGE_OPTIONS else 0,
        )
        st.session_state.selected_language = selected_lang_bug
        
    code_to_check = st.text_area(
        "Code to analyze for syntax bugs (Auto-Synced from Main Terminal):",
        height=180,
        value=st.session_state.code_query
    )
    st.session_state.code_query = code_to_check

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 📊 Language-Aware AST & Syntax Inspection Results")
    
    # Execute Language-Aware Syntax Analysis
    syntax_result = check_code_syntax(code_to_check, selected_lang_bug)
    
    st.markdown(f"**Detected Engine Target:** `{syntax_result['language']}`")
    
    if syntax_result["syntax_errors"]:
        st.markdown("#### ❌ Syntax Errors Detected:")
        for err in syntax_result["syntax_errors"]:
            st.error(err)
            
    if syntax_result["logic_warnings"]:
        st.markdown("#### ⚠️ Code Quality & Logic Warnings:")
        for warn in syntax_result["logic_warnings"]:
            st.warning(warn)

    if syntax_result["is_valid"] and not syntax_result["logic_warnings"]:
        st.success(f"✅ **{syntax_result['language']} AST & Syntax Check:** Code compiles cleanly with valid syntax!")


# ─────────────────────────────────────────────
# VIEW 3: AI CODE REMEDIATION ENGINE (100% Automatic, Zero Key Required)
# ─────────────────────────────────────────────
elif st.session_state.active_view == "security_audit":
    if st.button("← Back to Main Dashboard"):
        st.session_state.active_view = "main"
        st.rerun()
        
    st.markdown("""
    <div style="font-family: 'JetBrains Mono', monospace; margin: 10px 0 20px 0;">
        <div style="font-size:12px; color:#4ade80;">codevigil@ai-remediation:~$ engine --auto-fix</div>
        <h1 style="font-size:32px; font-weight:800; margin:4px 0;">🤖 AI Code Auto-Remediation & Fixation Engine</h1>
        <p style="color:#849385;">Automatically carries over code from the main screen and generates instant secure rewrites with zero key requirements.</p>
    </div>
    """, unsafe_allow_html=True)
    
    input_vuln_code = st.text_area(
        "Vulnerable Code Input (Auto-Synced from Main Terminal):",
        height=160,
        value=st.session_state.code_query
    )
    st.session_state.code_query = input_vuln_code

    run_fix = st.button("▶ Run Remediation", use_container_width=True, type="primary")
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 🛠️ AI Remediation Results")
    
    if run_fix:
        st.session_state.remediation_result = generate_remediation(
            input_vuln_code, st.session_state.selected_language
        )

    fix_result = st.session_state.get("remediation_result")
    if not fix_result:
        st.info("Paste vulnerable code above and click **Run Remediation**.")
    else:
        if fix_result.get("detected_types"):
            st.markdown(f"**Detected vulnerability patterns:** {', '.join(fix_result['detected_types'])}")
        if fix_result.get("detected_language") and fix_result["detected_language"] != "Auto-Detect":
            st.markdown(f"**Detected language:** `{fix_result['detected_language']}`")
        if fix_result.get("has_fix"):
            st.success("Remediation applied — review the fixed code below.")
        elif fix_result.get("changes"):
            st.warning("No code changes were applied. See summary for details.")
    
    if fix_result:
        col_orig, col_fix = st.columns(2)
        with col_orig:
            st.markdown("<div class='feature-card-staggered' style='border-top:3px solid #f87171;'>", unsafe_allow_html=True)
            st.markdown("❌ **Original Code:**")
            st.code(fix_result["original"], language="text")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_fix:
            st.markdown("<div class='feature-card-staggered' style='border-top:3px solid #4ade80;'>", unsafe_allow_html=True)
            st.markdown("✅ **AI Remediated Safe Code:**")
            st.code(fix_result["remediated"], language="text")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("#### 📝 AI Security Refactoring Summary:")
        for chg in fix_result["changes"]:
            st.markdown(f"- {chg}")
        if fix_result.get("remaining_syntax_issues"):
            st.markdown("#### ⚠️ Remaining syntax issues:")
            for issue in fix_result["remaining_syntax_issues"]:
                st.markdown(f"- {issue}")


# ─────────────────────────────────────────────
# VIEW 4: ALGORITHM COMPARISON PAGE
# ─────────────────────────────────────────────
elif st.session_state.active_view == "compare_algos":
    if st.button("← Back to Main Dashboard"):
        st.session_state.active_view = "main"
        st.rerun()
        
    st.markdown("""
    <div style="font-family: 'JetBrains Mono', monospace; margin: 10px 0 20px 0;">
        <div style="font-size:12px; color:#4ade80;">codevigil@analytics:~$ run --benchmark</div>
        <h1 style="font-size:32px; font-weight:800; margin:4px 0;">📈 Information Retrieval Algorithm Benchmark</h1>
        <p style="color:#849385;">Side-by-side performance evaluation comparing TF-IDF, BM25 (Okapi), and Hybrid RRF Fusion.</p>
    </div>
    """, unsafe_allow_html=True)
    
    comp_q = st.text_input("Benchmark Query (Auto-Synced from Main Terminal):", value=st.session_state.code_query if st.session_state.code_query else "log4j remote code execution")
    
    tfidf_res = models["tfidf"].search(comp_q, top_k=top_k)
    bm25_res = models["bm25"].search(comp_q, top_k=top_k)
    hybrid_res = models["hybrid"].search(comp_q, top_k=top_k)
    
    comparison_data = {
        "Algorithm": ["TF-IDF + Cosine Similarity", "BM25 (Okapi)", "Hybrid (TF-IDF + BM25)"],
        "Top Result CVE": [
            tfidf_res[0]["cve_id"] if tfidf_res else "N/A",
            bm25_res[0]["cve_id"] if bm25_res else "N/A",
            hybrid_res[0]["cve_id"] if hybrid_res else "N/A",
        ],
        "Top Match Score": [
            f"{tfidf_res[0]['relevance_score']:.4f}" if tfidf_res else "N/A",
            f"{bm25_res[0]['relevance_score']:.4f}" if bm25_res else "N/A",
            f"{hybrid_res[0]['relevance_score']:.6f}" if hybrid_res else "N/A",
        ],
        "Results Count": [len(tfidf_res), len(bm25_res), len(hybrid_res)]
    }
    
    st.table(pd.DataFrame(comparison_data))

    detection = detect_code_patterns(comp_q)
    if detection["detected_types"]:
        relevant_ids = [c["cve_id"] for c in models["cves"] if c["type"] in detection["detected_types"]]
    else:
        pred_type, _ = models["type_classifier"].predict(comp_q)
        relevant_ids = [c["cve_id"] for c in models["cves"] if c["type"] == pred_type]

    if relevant_ids:
        eval_k = min(top_k, 5)
        tfidf_ids = [r["cve_id"] for r in tfidf_res]
        bm25_ids = [r["cve_id"] for r in bm25_res]
        hybrid_ids = [r["cve_id"] for r in hybrid_res]
        metrics_data = {
            "Algorithm": ["TF-IDF + Cosine Similarity", "BM25 (Okapi)", "Hybrid (TF-IDF + BM25)"],
            f"P@{eval_k}": [
                f"{precision_at_k(tfidf_ids, relevant_ids, eval_k):.4f}",
                f"{precision_at_k(bm25_ids, relevant_ids, eval_k):.4f}",
                f"{precision_at_k(hybrid_ids, relevant_ids, eval_k):.4f}",
            ],
            f"R@{eval_k}": [
                f"{recall_at_k(tfidf_ids, relevant_ids, eval_k):.4f}",
                f"{recall_at_k(bm25_ids, relevant_ids, eval_k):.4f}",
                f"{recall_at_k(hybrid_ids, relevant_ids, eval_k):.4f}",
            ],
            f"F1@{eval_k}": [
                f"{f1_at_k(tfidf_ids, relevant_ids, eval_k):.4f}",
                f"{f1_at_k(bm25_ids, relevant_ids, eval_k):.4f}",
                f"{f1_at_k(hybrid_ids, relevant_ids, eval_k):.4f}",
            ],
            "MRR": [
                f"{mean_reciprocal_rank([(tfidf_ids, relevant_ids)]):.4f}",
                f"{mean_reciprocal_rank([(bm25_ids, relevant_ids)]):.4f}",
                f"{mean_reciprocal_rank([(hybrid_ids, relevant_ids)]):.4f}",
            ],
        }
        st.markdown("#### IR Evaluation Metrics")
        st.caption(f"Relevance set: {len(relevant_ids)} CVE(s) matching detected/predicted type(s).")
        st.table(pd.DataFrame(metrics_data))
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("<div class='feature-card-staggered'>", unsafe_allow_html=True)
        st.markdown("**TF-IDF Top 3 Matches:**")
        for r in tfidf_res[:3]:
            st.markdown(f"- **{r['cve_id']}** (`{r['relevance_score']:.4f}`)<br><span style='font-size:12px; color:#849385;'>{r['type']}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
    with col2:
        st.markdown("<div class='feature-card-staggered'>", unsafe_allow_html=True)
        st.markdown("**BM25 Top 3 Matches:**")
        for r in bm25_res[:3]:
            st.markdown(f"- **{r['cve_id']}** (`{r['relevance_score']:.4f}`)<br><span style='font-size:12px; color:#849385;'>{r['type']}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
    with col3:
        st.markdown("<div class='feature-card-staggered'>", unsafe_allow_html=True)
        st.markdown("**Hybrid Top 3 Matches:**")
        for r in hybrid_res[:3]:
            st.markdown(f"- **{r['cve_id']}** (`{r['relevance_score']:.6f}`)<br><span style='font-size:12px; color:#849385;'>TF-IDF Rank: {r.get('tfidf_rank', 'N/A')}, BM25 Rank: {r.get('bm25_rank', 'N/A')}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# VIEW 5: ABOUT VULNERABILITIES KNOWLEDGE HUB
# ─────────────────────────────────────────────
elif st.session_state.active_view == "about_vulns":
    if st.button("← Back to Main Dashboard"):
        st.session_state.active_view = "main"
        st.rerun()
        
    st.markdown("""
    <div style="font-family: 'JetBrains Mono', monospace; margin: 10px 0 20px 0;">
        <div style="font-size:12px; color:#4ade80;">codevigil@docs:~$ cat vulnerabilities_handbook.md</div>
        <h1 style="font-size:32px; font-weight:800; margin:4px 0;">📚 Software Vulnerabilities Knowledge Hub</h1>
        <p style="color:#849385;">Comprehensive guide to CVEs, OWASP Top 10, CVSS scoring, and security mitigations.</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🔥 OWASP Top 10", "🎯 CVSS Severity Matrix", "📜 Famous CVE Case Studies"])
    
    with tab1:
        st.markdown("""
        ### OWASP Top 10 Web Application Security Risks
        1. **A01:2021 – Broken Access Control:** Unauthorized elevation of privilege and access to user accounts.
        2. **A02:2021 – Cryptographic Failures:** Sensitive data exposure due to weak encryption algorithms (e.g. MD5, SSLv3).
        3. **A03:2021 – Injection:** SQL, Command, and LDAP injection from untrusted input concatenation.
        4. **A04:2021 – Insecure Design:** Flaws in architectural design and lack of threat modeling.
        5. **A05:2021 – Security Misconfiguration:** Default admin credentials, debug modes enabled in production.
        6. **A06:2021 – Vulnerable and Outdated Components:** Using libraries with known CVEs (e.g. Log4j 2.14.1).
        """)
        
    with tab2:
        st.markdown("""
        ### CVSS v3.1 Severity Rating Scale
        - **CRITICAL (9.0 – 10.0):** Exploit allows unauthenticated remote code execution or full system takeovers.
        - **HIGH (7.0 – 8.9):** Allows elevated privilege escalation or significant confidential data leakage.
        - **MEDIUM (4.0 – 6.9):** Requires specific user interaction or complex conditions to trigger.
        - **LOW (0.1 – 3.9):** Minor information disclosure without system compromise.
        """)
        
    with tab3:
        st.markdown("""
        ### Notable Cybersecurity Vulnerabilities
        - **CVE-2021-44228 (Log4Shell):** JNDI LDAP injection in Apache Log4j allowing unauthenticated RCE.
        - **CVE-2014-0160 (Heartbleed):** OpenSSL memory leak exposing secret keys and credentials.
        - **CVE-2017-0144 (EternalBlue):** SMBv1 buffer overflow exploited by WannaCry ransomware.
        """)


# ─────────────────────────────────────────────
# VIEW 6: EXPORT REPORTS (Multi-Format Export)
# ─────────────────────────────────────────────
elif st.session_state.active_view == "export_report":
    if st.button("← Back to Main Dashboard"):
        st.session_state.active_view = "main"
        st.rerun()
        
    st.markdown("""
    <div style="font-family: 'JetBrains Mono', monospace; margin: 10px 0 20px 0;">
        <div style="font-size:12px; color:#4ade80;">codevigil@export:~$ generate_report --all-formats</div>
        <h1 style="font-size:32px; font-weight:800; margin:4px 0;">📄 Export Vulnerability Analysis Reports</h1>
        <p style="color:#849385;">Convert and download your security radar data into JSON, CSV, HTML, and Markdown formats.</p>
    </div>
    """, unsafe_allow_html=True)
    
    df_export = pd.DataFrame(models["cves"])
    
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        json_data = json.dumps(models["cves"], indent=2)
        st.download_button("📥 Download JSON Report", data=json_data, file_name="codevigil_report.json", mime="application/json", use_container_width=True)
        
    with c2:
        csv_data = df_export.to_csv(index=False)
        st.download_button("📥 Download CSV Report", data=csv_data, file_name="codevigil_report.csv", mime="text/csv", use_container_width=True)
        
    with c3:
        html_report = f"""
        <html>
        <head><title>CodeVigil Security Report</title><style>body{{font-family:sans-serif; background:#080d08; color:#e2e8f0; padding:20px;}} table{{width:100%; border-collapse:collapse;}} th,td{{border:1px solid #1b2e1c; padding:8px; text-align:left;}} th{{background:#0d150e; color:#4ade80;}}</style></head>
        <body>
            <h1>🛡️ CodeVigil Security Audit Report</h1>
            <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Indexed CVEs: {len(models['cves'])}</p>
            {df_export[['cve_id', 'type', 'severity', 'affected_software']].to_html(index=False)}
        </body>
        </html>
        """
        st.download_button("📥 Download HTML Report", data=html_report, file_name="codevigil_report.html", mime="text/html", use_container_width=True)

    with c4:
        md_report = f"# CodeVigil Security Audit Report\n\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        for c in models["cves"]:
            md_report += f"### {c['cve_id']} - {c['type']} ({c['severity']})\n{c['description']}\n\n"
        st.download_button("📥 Download Markdown Report", data=md_report, file_name="codevigil_report.md", mime="text/markdown", use_container_width=True)


# ─────────────────────────────────────────────
# VIEW 7: MAIN TERMINAL RADAR DASHBOARD
# ─────────────────────────────────────────────
else:
    # HERO & TAGLINE
    st.markdown("""
    <div style="text-align: center; max-width: 850px; margin: 15px auto 10px auto;">
        <div style="display:inline-flex; align-items:center; gap:8px; background:#0d150e; border:1px solid #1b2e1c; border-radius:100px; padding:6px 18px; margin-bottom:16px; font-family:'JetBrains Mono', monospace; font-size:13px; color:#22c55e;">
            codevigil@scan:~$ ready <span style="width:7px; height:14px; background:#4ade80; display:inline-block; margin-left:4px;"></span>
        </div>
        <h1 style="font-family: 'Space Grotesk', sans-serif; font-size:42px; font-weight:800; line-height:1.15; margin:0 0 12px 0; letter-spacing:-0.02em; color:#e2e8f0;">
            Find the vuln <span style="color:#4ade80;">before it finds you.</span>
        </h1>
        <p style="color:#849385; font-size:15.5px; max-width:640px; margin:0 auto; line-height:1.6; font-family: 'Outfit', sans-serif;">
            Paste code or describe a weakness. CodeVigil scans against <b>""" + str(len(models['cves'])) + """</b> indexed NVD CVEs using TF-IDF + cosine similarity and classifies threats with ML.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # TERMINAL CONTAINER
    st.markdown("""
    <div class="terminal-shell laser-scanner">
        <div class="laser-line"></div>
        <div class="term-bar">
            <span class="dot dot-red"></span>
            <span class="dot dot-yellow"></span>
            <span class="dot dot-green"></span>
            <span class="path">~/codevigil/radar-scanner</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Language Selector Dropdown
    col_lang_sel, col_empty = st.columns([1, 2])
    with col_lang_sel:
        language = st.selectbox(
            "🌐 Select Programming Language:",
            LANGUAGE_OPTIONS,
            index=LANGUAGE_OPTIONS.index(st.session_state.selected_language) if st.session_state.selected_language in LANGUAGE_OPTIONS else 0,
        )
        st.session_state.selected_language = language
        
    # Main Code Input Box (Auto-synced with session state)
    code_input = st.text_area(
        "Code / Description Editor:",
        value=st.session_state.code_query,
        placeholder="Paste code snippet (e.g. print('Hello World') or query = 'SELECT * FROM users WHERE id=' + id)...",
        height=140
    )
    st.session_state.code_query = code_input
    
    col_r1, col_r2, col_r3 = st.columns([1, 2, 1])
    with col_r2:
        run_scan = st.button("▶ RUN SECURITY RADAR SCAN", use_container_width=True)
        
    if run_scan:
        st.session_state.scanning_anim = True

    st.markdown("<br>", unsafe_allow_html=True)
    
    # ── 5 STAGGERED RESPONSIVE FEATURE CARDS ──
    st.markdown("<div style='font-family: \"JetBrains Mono\", monospace; font-size:12px; color:#4ade80; text-transform:uppercase; letter-spacing:0.12em; margin-bottom:6px;'>system capabilities</div>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:24px; margin:0 0 16px 0;'>Interactive Security Modules</h2>", unsafe_allow_html=True)
    
    fb1, fb2, fb3, fb4, fb5 = st.columns(5)
    
    with fb1:
        st.markdown("""
        <div class="feature-card-staggered" style="min-height: 140px; border-top: 3px solid #38bdf8;">
            <div style="font-family:'JetBrains Mono'; font-size:14px; font-weight:700; color:#38bdf8; margin-bottom:6px;">01. Bug Detection</div>
            <p style="font-size:12px; color:#849385; margin:0; line-height:1.4;">Language-aware AST syntax & logic error inspection.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Inspect Bugs", key="btn_b1", use_container_width=True):
            st.session_state.active_view = "bug_detection"
            st.rerun()

    with fb2:
        st.markdown("""
        <div class="feature-card-staggered" style="min-height: 165px; border-top: 3px solid #4ade80;">
            <div style="font-family:'JetBrains Mono'; font-size:14px; font-weight:700; color:#4ade80; margin-bottom:6px;">02. About Vulns</div>
            <p style="font-size:12px; color:#849385; margin:0; line-height:1.4;">OWASP Top 10 & CVSS scoring matrix.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Learn Vulns", key="btn_b2", use_container_width=True):
            st.session_state.active_view = "about_vulns"
            st.rerun()

    with fb3:
        st.markdown("""
        <div class="feature-card-staggered" style="min-height: 190px; border-top: 3px solid #facc15;">
            <div style="font-family:'JetBrains Mono'; font-size:14px; font-weight:700; color:#facc15; margin-bottom:6px;">03. Compare Algos</div>
            <p style="font-size:12px; color:#849385; margin:0; line-height:1.4;">Compare TF-IDF, BM25 & Hybrid metrics.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Compare Algos", key="btn_b3", use_container_width=True):
            st.session_state.active_view = "compare_algos"
            st.rerun()

    with fb4:
        st.markdown("""
        <div class="feature-card-staggered" style="min-height: 165px; border-top: 3px solid #c084fc;">
            <div style="font-family:'JetBrains Mono'; font-size:14px; font-weight:700; color:#c084fc; margin-bottom:6px;">04. AI Auto-Remediation</div>
            <p style="font-size:12px; color:#849385; margin:0; line-height:1.4;">Automated code rewrites & patch diffs.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("AI Remediation", key="btn_b4", use_container_width=True):
            st.session_state.active_view = "security_audit"
            st.rerun()

    with fb5:
        st.markdown("""
        <div class="feature-card-staggered" style="min-height: 140px; border-top: 3px solid #f87171;">
            <div style="font-family:'JetBrains Mono'; font-size:14px; font-weight:700; color:#f87171; margin-bottom:6px;">05. Export Reports</div>
            <p style="font-size:12px; color:#849385; margin:0; line-height:1.4;">Download JSON, CSV, HTML & Markdown.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Export Reports", key="btn_b5", use_container_width=True):
            st.session_state.active_view = "export_report"
            st.rerun()

    st.markdown("<br><hr style='border-color: var(--border-green);'><br>", unsafe_allow_html=True)
    
    # STAT CARDS
    cves_data = models["cves"]
    crit_cnt = sum(1 for c in cves_data if c["severity"] == "Critical")
    high_cnt = sum(1 for c in cves_data if c["severity"] == "High")
    med_cnt = sum(1 for c in cves_data if c["severity"] == "Medium")
    low_cnt = sum(1 for c in cves_data if c["severity"] == "Low")
    
    s1, s2, s3, s4, s5 = st.columns(5)
    with s1:
        st.markdown(f"<div class='stat-card-term'><div class='lbl'>Total CVEs</div><div class='val'>{len(cves_data)}</div></div>", unsafe_allow_html=True)
    with s2:
        st.markdown(f"<div class='stat-card-term'><div class='lbl'>Critical</div><div class='val' style='color:#f87171;'>{crit_cnt}</div></div>", unsafe_allow_html=True)
    with s3:
        st.markdown(f"<div class='stat-card-term'><div class='lbl'>High</div><div class='val' style='color:#fb923c;'>{high_cnt}</div></div>", unsafe_allow_html=True)
    with s4:
        st.markdown(f"<div class='stat-card-term'><div class='lbl'>Medium</div><div class='val' style='color:#facc15;'>{med_cnt}</div></div>", unsafe_allow_html=True)
    with s5:
        st.markdown(f"<div class='stat-card-term'><div class='lbl'>Low</div><div class='val' style='color:#4ade80;'>{low_cnt}</div></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    # SCAN RESULTS
    active_q = code_input.strip()
    detection = detect_code_patterns(active_q) if active_q else {"detected_types": [], "boosted_query": "", "is_code": False}
    boosted_q = detection["boosted_query"] if detection["boosted_query"] else active_q
    
    st.markdown("""
    <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:14px; font-family:'JetBrains Mono', monospace;">
        <h3 style="font-size:16px; margin:0; color:#e2e8f0;">&gt; scan_results.log</h3>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.scanning_anim:
        with st.spinner("⚡ Running Deep Cyber Radar & Vector Cosine Inspection..."):
            time.sleep(0.3)
            st.session_state.scanning_anim = False

    results = []
    if active_q:
        if algorithm == "TF-IDF + Cosine Similarity":
            raw_results = models["tfidf"].search(boosted_q, top_k=top_k)
        elif algorithm == "BM25 (Okapi)":
            raw_results = models["bm25"].search(boosted_q, top_k=top_k)
        else:
            raw_results = models["hybrid"].search(boosted_q, top_k=top_k)

        for r in raw_results:
            if r["relevance_score"] >= 0.12 or detection["detected_types"]:
                results.append(r)

    if severity_filter and results:
        results = [r for r in results if r["severity"] in severity_filter]
    if type_filter and results:
        results = [r for r in results if r["type"] in type_filter]

    if active_q and not detection["detected_types"] and not results:
        st.warning("No matching CVEs found above the relevance threshold. This does **not** confirm your code is safe — review manually or use Bug Detector / AI Remediation.")
    elif results:
        pred_type, type_conf = models["type_classifier"].predict(boosted_q)
        pred_sev, sev_conf = models["severity_predictor"].predict(boosted_q)
        
        st.markdown(f"""
        <div class="feature-card-staggered" style="margin-bottom:16px;">
            <b style="color:#4ade80;">🤖 Machine Learning Threat Assessment:</b> 
            Predicted Type: <b style="color:#38bdf8;">{pred_type}</b> ({type_conf:.1%} confidence) &nbsp;|&nbsp; 
            Predicted Severity: <b style="color:#f87171;">{pred_sev}</b> ({sev_conf:.1%} confidence)
        </div>
        """, unsafe_allow_html=True)
        
        for idx, item in enumerate(results, 1):
            sev_class = "crit" if item['severity'] == "Critical" else ("high" if item['severity'] == "High" else ("med" if item['severity'] == "Medium" else "low"))
            
            c_cve, c_info, c_sev, c_act = st.columns([1.5, 4, 1, 1.2])
            
            with c_cve:
                st.markdown(f"<span style='font-family: JetBrains Mono; color: #4ade80; font-weight: 700;'>{item['cve_id']}</span>", unsafe_allow_html=True)
            with c_info:
                st.markdown(f"<span style='color: #e2e8f0;'><b>{item['type']}</b> — {item['description'][:95]}...</span>", unsafe_allow_html=True)
            with c_sev:
                st.markdown(f"<span class='sev {sev_class}'>{item['severity'].lower()}</span> <span style='color:#849385; font-size:11px;'>{item['relevance_score']:.2f}</span>", unsafe_allow_html=True)
            with c_act:
                if st.button(f"Inspect", key=f"btn_insp_{item['cve_id']}_{idx}"):
                    st.session_state.selected_cve = item['cve_id']
                    st.session_state.active_view = "cve_detail"
                    st.rerun()
            st.markdown("<hr style='border-color: rgba(255,255,255,0.05); margin: 4px 0;'>", unsafe_allow_html=True)
    elif not active_q:
        st.info("💡 Enter code or a vulnerability description in the editor above and click 'RUN SECURITY RADAR SCAN'.")

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown("""
    <div style='text-align: center; color: #849385; font-family: "JetBrains Mono", monospace; font-size: 11px;'>
        [CodeVigil Terminal Core v3.3] · Real-Time Threat Intelligence & Remediation Radar
    </div>
    """, unsafe_allow_html=True)
