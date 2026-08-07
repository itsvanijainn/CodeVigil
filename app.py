"""
CodeVigil — Vulnerability Search & Classification System
===========================================================
A web-based application for searching, classifying, and remediating
software vulnerabilities using Information Retrieval and Machine Learning.

Built with: Python, Scikit-Learn, Streamlit
Author: [Your Name]
"""

import streamlit as st
import json
import time
import sys
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


# ─────────────────────────────────────────────
# Page Configuration
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="CodeVigil — Vulnerability Search",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ─────────────────────────────────────────────
# Load Data & Initialize Models (Cached)
# ─────────────────────────────────────────────
@st.cache_resource
def load_models():
    """Load CVE database and initialize all models."""
    # Load CVE database
    db_path = Path("data/cve_database.json")
    if not db_path.exists():
        st.error(f"CVE database not found at {db_path}")
        st.stop()
    
    with open(db_path, "r") as f:
        cves = json.load(f)
    
    # Initialize retrievers
    tfidf = TFIDFRetriever(cves)
    bm25 = BM25Retriever(cves)
    hybrid = HybridRetriever(cves)
    
    # Initialize classifiers
    type_clf = VulnTypeClassifier()
    type_clf.train(cves)
    
    sev_pred = SeverityPredictor()
    sev_pred.train(cves)
    
    # Initialize fix recommender
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


# Load models
with st.spinner("🔄 Loading models..."):
    models = load_models()


# ─────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ CodeVigil")
    st.markdown("---")
    
    # Algorithm selection
    st.subheader("🔍 Search Algorithm")
    algorithm = st.selectbox(
        "Select retrieval method:",
        ["TF-IDF + Cosine Similarity", "BM25 (Okapi)", "Hybrid (TF-IDF + BM25)"],
        index=0
    )
    
    st.markdown("---")
    
    # Filters
    st.subheader("🎛️ Filters")
    
    severity_filter = st.multiselect(
        "Severity Level:",
        ["Critical", "High", "Medium", "Low"],
        default=[]
    )
    
    type_filter = st.multiselect(
        "Vulnerability Type:",
        models["type_classifier"].classes_.tolist(),
        default=[]
    )
    
    top_k = st.slider("Number of results:", 1, 20, 5)
    
    st.markdown("---")
    
    # Info
    st.subheader("ℹ️ About")
    st.markdown(f"""
    **Database Stats:**
    - CVEs: {len(models['cves'])}
    - TF-IDF Features: {len(models['tfidf'].get_vocabulary())}
    - Vuln Types: {len(models['type_classifier'].classes_)}
    """)
    
    st.markdown("---")
    
    # Algorithm info
    if algorithm == "TF-IDF + Cosine Similarity":
        st.info("TF-IDF converts text to vectors. Cosine similarity measures angle between vectors.")
    elif algorithm == "BM25 (Okapi)":
        st.info("BM25 ranks documents based on term frequency and inverse document frequency.")
    else:
        st.info("Hybrid combines TF-IDF and BM25 using Reciprocal Rank Fusion (RRF).")


# ─────────────────────────────────────────────
# Main Content
# ─────────────────────────────────────────────
st.title("🛡️ CodeVigil")
st.markdown("### Vulnerability Search, Classification & Remediation System")
st.markdown("---")

# Search input
query = st.text_input(
    "🔎 Search vulnerabilities (describe the vulnerability or paste code):",
    placeholder="e.g., 'log4j remote code execution' or paste a code snippet..."
)

# Search button
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    search_clicked = st.button("🔍 Search", type="primary", use_container_width=True)


# ─────────────────────────────────────────────
# Search & Display Results
# ─────────────────────────────────────────────
if search_clicked and query:
    st.markdown("---")
    
    # Show loading spinner
    with st.spinner("🔍 Searching vulnerabilities..."):
        time.sleep(0.5)  # Simulate processing time
        
        # Detect code patterns and boost query
        detection = detect_code_patterns(query)
        search_query = detection["boosted_query"]
        
        # Show detected patterns if code was detected
        if detection["is_code"] and detection["detected_types"]:
            st.info(f"""
            **🔍 Code Pattern Detected:**
            - Detected vulnerability types: **{', '.join(detection['detected_types'])}**
            - Search query boosted with relevant keywords
            """)
        
        # Perform search based on selected algorithm
        if algorithm == "TF-IDF + Cosine Similarity":
            results = models["tfidf"].search(search_query, top_k=top_k)
        elif algorithm == "BM25 (Okapi)":
            results = models["bm25"].search(search_query, top_k=top_k)
        else:  # Hybrid
            results = models["hybrid"].search(search_query, top_k=top_k)
        
        # Apply filters
        if severity_filter:
            results = [r for r in results if r["severity"] in severity_filter]
        
        if type_filter:
            results = [r for r in results if r["type"] in type_filter]
        
        # ML Classification
        pred_type, type_conf = models["type_classifier"].predict(search_query)
        pred_sev, sev_conf = models["severity_predictor"].predict(search_query)
    
    # Display results
    st.subheader(f"📊 Found {len(results)} matching vulnerabilities")
    
    if results:
        # ML Classification summary
        st.info(f"""
        **🤖 ML Classification:**
        - Predicted Type: **{pred_type}** (confidence: {type_conf:.2%})
        - Predicted Severity: **{pred_sev}** (confidence: {sev_conf:.2%})
        """)
        
        # Results table
        for i, result in enumerate(results, 1):
            with st.expander(f"**{i}. {result['cve_id']}** — {result['type']} ({result['severity']})", expanded=(i == 1)):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Relevance Score", f"{result['relevance_score']:.4f}")
                
                with col2:
                    severity_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
                    st.metric("Severity", f"{severity_emoji.get(result['severity'], '⚪')} {result['severity']}")
                
                with col3:
                    st.metric("Type", result['type'])
                
                st.markdown(f"**Description:**")
                st.write(result['description'])
                
                if result.get('affected_software'):
                    st.markdown(f"**Affected Software:** {result['affected_software']}")
                
                if result.get('affected_code'):
                    st.markdown(f"**Affected Code Pattern:**")
                    st.code(result['affected_code'], language="text")
                
                # Fix recommendation
                st.markdown("---")
                st.markdown("**🔧 Remediation:**")
                fix = models["fix_recommender"].get_fix(cve_id=result['cve_id'])
                
                if fix['specific_fix']:
                    st.success(fix['specific_fix'])
                
                st.markdown(f"**Priority:** {fix['priority']}")
                
                if fix['immediate_actions']:
                    st.markdown("**Immediate Actions:**")
                    for action in fix['immediate_actions']:
                        st.markdown(f"- {action}")
                
                if fix['generic_fixes']:
                    with st.expander("View Generic Fixes"):
                        for gf in fix['generic_fixes']:
                            st.markdown(f"- {gf}")
    
    else:
        st.warning("No results found. Try a different query or adjust filters.")
    
    # Algorithm comparison (optional)
    st.markdown("---")
    st.subheader("📈 Algorithm Comparison")
    
    with st.expander("Compare all algorithms for this query"):
        tfidf_res = models["tfidf"].search(search_query, top_k=top_k)
        bm25_res = models["bm25"].search(search_query, top_k=top_k)
        hybrid_res = models["hybrid"].search(search_query, top_k=top_k)
        
        # Create comparison table
        comparison_data = {
            "Algorithm": ["TF-IDF", "BM25", "Hybrid"],
            "Top Result": [
                tfidf_res[0]["cve_id"] if tfidf_res else "N/A",
                bm25_res[0]["cve_id"] if bm25_res else "N/A",
                hybrid_res[0]["cve_id"] if hybrid_res else "N/A",
            ],
            "Score": [
                f"{tfidf_res[0]['relevance_score']:.4f}" if tfidf_res else "N/A",
                f"{bm25_res[0]['relevance_score']:.4f}" if bm25_res else "N/A",
                f"{hybrid_res[0]['relevance_score']:.6f}" if hybrid_res else "N/A",
            ],
            "Results Count": [len(tfidf_res), len(bm25_res), len(hybrid_res)]
        }
        
        st.table(comparison_data)
        
        # Show top 3 from each
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**TF-IDF Top 3:**")
            for r in tfidf_res[:3]:
                st.markdown(f"- {r['cve_id']} ({r['relevance_score']:.4f})")
        
        with col2:
            st.markdown("**BM25 Top 3:**")
            for r in bm25_res[:3]:
                st.markdown(f"- {r['cve_id']} ({r['relevance_score']:.4f})")
        
        with col3:
            st.markdown("**Hybrid Top 3:**")
            for r in hybrid_res[:3]:
                st.markdown(f"- {r['cve_id']} ({r['relevance_score']:.6f})")


elif search_clicked and not query:
    st.warning("⚠️ Please enter a search query.")


# ─────────────────────────────────────────────
# Example Queries
# ─────────────────────────────────────────────
if not query:
    st.markdown("---")
    st.subheader("💡 Try These Example Queries")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Vulnerability Searches:**
        - `log4j remote code execution`
        - `path traversal file read`
        - `SQL injection database`
        - `buffer overflow privilege escalation`
        - `deserialization arbitrary code`
        """)
    
    with col2:
        st.markdown("""
        **Code Snippets:**
        - `user_input = request.getParameter("id"); query = "SELECT * FROM users WHERE id=" + user_input;`
        - `eval(user_controlled_string)`
        - `subprocess.call("ls " + user_input, shell=True)`
        """)


# ─────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: gray;'>
    <p>Built with ❤️ using Python, Scikit-Learn & Streamlit</p>
    <p>CodeVigil — Vulnerability Search, Classification & Remediation System</p>
</div>
""", unsafe_allow_html=True)
