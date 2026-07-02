import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
from dotenv import load_dotenv
import pandas as pd

load_dotenv()

from app.backend.document_parser import parse_document
from app.backend.detector import detect_pii, compute_risk_score
from app.backend.ai_engine import generate_compliance_summary, answer_question
from app.backend.rag import build_index, rag_answer, is_index_built
from app.utils.masking import mask_text, full_redact
from app.utils.audit_logger import log_scan, read_log

# ─── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Proteccio — Sensitive Data Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.main-header {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    padding: 2rem 2.5rem; border-radius: 14px;
    margin-bottom: 1.5rem; text-align: center; color: white;
}
.main-header h1 { font-size: 2rem; font-weight: 700; margin: 0; letter-spacing: -0.5px; }
.main-header p  { color: #9fb8c8; margin: 0.4rem 0 0; font-size: 0.95rem; }

.badge-HIGH   { background:#ff4757; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:700; }
.badge-MEDIUM { background:#ffa502; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:700; }
.badge-LOW    { background:#2ed573; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:700; }

.risk-HIGH   { background:linear-gradient(135deg,#ff4757,#c0392b); color:#fff; padding:14px 20px; border-radius:12px; font-size:1.25rem; font-weight:700; text-align:center; }
.risk-MEDIUM { background:linear-gradient(135deg,#ffa502,#e67e22); color:#fff; padding:14px 20px; border-radius:12px; font-size:1.25rem; font-weight:700; text-align:center; }
.risk-LOW    { background:linear-gradient(135deg,#2ed573,#27ae60); color:#fff; padding:14px 20px; border-radius:12px; font-size:1.25rem; font-weight:700; text-align:center; }

.msg-user {
    background: #1e3a5f;
    border-left: 4px solid #3b82f6;
    border-radius: 0 12px 12px 0;
    padding: 12px 16px;
    margin: 8px 0;
    color: #e8f4fd !important;
    font-size: 0.95rem;
}
.msg-user strong { color: #60a5fa !important; }

.msg-ai {
    background: #2d1b4e;
    border-left: 4px solid #8b5cf6;
    border-radius: 0 12px 12px 0;
    padding: 12px 16px;
    margin: 8px 0;
    color: #f0e8ff !important;
    font-size: 0.95rem;
    line-height: 1.6;
}
.msg-ai strong { color: #a78bfa !important; }
</style>
""", unsafe_allow_html=True)

# ─── Header ──────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
  <h1>🛡️ Proteccio — Sensitive Data Detection & Compliance Assistant</h1>
  <p>Upload documents · Detect PII · Classify Risk · Generate Compliance Reports · Ask Questions</p>
</div>
""", unsafe_allow_html=True)

# ─── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("⚙️ Settings")
    raw_key = os.getenv("GROQ_API_KEY", "")
    api_key_input = st.text_input("Groq API Key", value=raw_key, type="password",
                                  help="Free key at console.groq.com")
    if api_key_input:
        os.environ["GROQ_API_KEY"] = api_key_input

    groq_ok = bool(os.getenv("GROQ_API_KEY", "").strip())
    if groq_ok:
        st.success("✅ Groq API connected")
    else:
        st.warning("⚠️ Enter Groq key for AI features")

    st.divider()
    use_rag = st.toggle("Use RAG for Q&A", value=True,
                        help="TF-IDF retrieval grounds answers in document chunks")
    st.divider()
    st.caption("**LLM:** llama-3.3-70b-versatile (Groq)")
    st.caption("**Detects:** 12+ PII types")
    st.caption("**Frameworks:** DPDP 2023 · GDPR · PCI-DSS · IT Act")

# ─── Session state init ───────────────────────────────────────────────────────
DEFAULTS = {
    "doc": None, "detections": [], "risk": {},
    "summary": "", "chat_history": [], "rag_built": False,
    "pending_question": "",
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ─── Upload ───────────────────────────────────────────────────────────────────
st.subheader("📤 Upload Document")
col_up, col_inf = st.columns([2, 1])
with col_up:
    uploaded_file = st.file_uploader("Drag & drop or click to upload", type=["pdf", "txt", "csv"])
with col_inf:
    st.markdown("""
**Formats:** PDF · TXT · CSV

**Detects:** Aadhaar · PAN · Credit Card · API Keys
JWT Tokens · IFSC · Email · Phone · Employee ID · DOB · IP
""")

if uploaded_file:
    try:
        doc = parse_document(uploaded_file)
    except Exception as e:
        st.error(f"❌ Failed to parse: {e}")
        st.stop()

    is_new = (
        st.session_state.doc is None
        or st.session_state.doc.get("filename") != doc["filename"]
    )
    if is_new:
        with st.spinner("Scanning for sensitive data..."):
            detections = detect_pii(doc["text"])
            risk = compute_risk_score(detections)

        st.session_state.doc = doc
        st.session_state.detections = detections
        st.session_state.risk = risk
        st.session_state.chat_history = []
        st.session_state.rag_built = False
        st.session_state.summary = ""
        st.session_state.pending_question = ""

        if use_rag:
            with st.spinner("Building retrieval index..."):
                try:
                    build_index(doc["text"])
                    st.session_state.rag_built = True
                except Exception as e:
                    st.warning(f"RAG index failed (will use full-context QA instead): {e}")

        log_scan(doc["filename"], doc["type"], st.session_state.risk)

    st.success(
        f"✅ **{doc['filename']}** ({doc['type']}) — "
        f"{doc['word_count']:,} words · "
        f"{st.session_state.risk.get('total_types', 0)} PII types detected"
    )

# ─── Main content (only if a doc is loaded) ──────────────────────────────────
if not st.session_state.doc:
    st.divider()
    c1, c2, c3 = st.columns(3)
    c1.info("**🔍 Smart Detection**\n\n12+ PII types — Aadhaar, PAN, credit cards, API keys, JWTs and more")
    c2.warning("**⚖️ Risk Classification**\n\nWeighted scoring → Low / Medium / High with per-type breakdown")
    c3.success("**🤖 AI Reports & Q&A**\n\nLlama 3.3-70b generates compliance reports and answers your questions")
    st.stop()

# ── pull from session ─────────────────────────────────────────────────────────
doc        = st.session_state.doc
detections = st.session_state.detections
risk       = st.session_state.risk
level      = risk.get("level", "LOW")
score      = risk.get("score", 0)

# ── Risk banner ───────────────────────────────────────────────────────────────
st.divider()
emoji = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(level, "⚪")
rc1, rc2, rc3, rc4 = st.columns(4)
with rc1:
    st.markdown(
        f'<div class="risk-{level}">{emoji} {level} RISK'
        f'<br><span style="font-size:0.85rem;font-weight:400">Score: {score}/100</span></div>',
        unsafe_allow_html=True,
    )
rc2.metric("Total PII Instances", risk.get("total_instances", 0))
rc3.metric("PII Types Found",      risk.get("total_types", 0))
rc4.metric("High Severity Items",  f"🔴 {risk.get('high_count', 0)}")
st.divider()

# ─── Tabs ─────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔍 Detection Results",
    "📋 Compliance Summary",
    "💬 Ask Questions",
    "🔒 Redacted Preview",
    "📊 Audit Log",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Detection Results
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("Sensitive Data Detection Results")

    if not detections:
        st.success("✅ No sensitive data detected in this document.")
    else:
        sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for d in detections:
            sev[d.severity] += d.count
        m1, m2, m3 = st.columns(3)
        m1.metric("🔴 High Severity",   sev["HIGH"])
        m2.metric("🟠 Medium Severity", sev["MEDIUM"])
        m3.metric("🟢 Low Severity",    sev["LOW"])
        st.divider()

        for d in detections:
            sev_emoji = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(d.severity, "⚪")
            sev_color = {"HIGH": "red",  "MEDIUM": "orange", "LOW": "green"}.get(d.severity, "blue")
            with st.expander(
                f"{sev_emoji} **{d.pii_type}** — {d.count} instance(s) [{d.severity}]",
                expanded=(d.severity == "HIGH"),
            ):
                st.caption(d.description)
                ea, eb = st.columns([1, 2])
                with ea:
                    st.metric("Instances Found", d.count)
                    st.badge(d.severity, color=sev_color)
                with eb:
                    st.markdown("**Sample matches (partially masked):**")
                    for raw in d.matches[:5]:
                        m = raw.strip()
                        masked = (m[:2] + "•" * min(len(m) - 4, 8) + m[-2:]) if len(m) > 4 else "•" * len(m)
                        st.code(masked, language=None)

        st.divider()
        st.subheader("Summary Table")

        def _sev_color(val):
            return {
                "HIGH":   "background-color:#ffd7d7;color:#c0392b;font-weight:700",
                "MEDIUM": "background-color:#fff3cd;color:#856404;font-weight:700",
                "LOW":    "background-color:#d4edda;color:#155724;font-weight:700",
            }.get(val, "")

        df_det = pd.DataFrame([
            {"PII Type": d.pii_type, "Severity": d.severity,
             "Instances": d.count, "Description": d.description}
            for d in detections
        ])
        st.dataframe(
            df_det.style.map(_sev_color, subset=["Severity"]),
            use_container_width=True, hide_index=True,
        )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Compliance Summary
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("AI-Generated Compliance & Security Report")

    if not groq_ok:
        st.error("❌ Enter your Groq API key in the sidebar to generate compliance reports.")
    else:
        # ── Generate button (only when no summary exists yet) ──────────────
        if not st.session_state.summary:
            st.info(
                "Click below to generate a structured compliance report using "
                "**Llama 3.3-70b** — covers **DPDP Act 2023**, **PCI-DSS**, **GDPR**, and **IT Act 2000**."
            )
            det_lines = "\n".join(
                f"• {d.pii_type} [{d.severity}]: {d.count}" for d in detections
            ) or "None"
            st.markdown(f"**Detections that will be analysed:**\n\n{det_lines}")
            st.divider()

            if st.button("🤖 Generate Compliance Report", type="primary",
                         use_container_width=True, key="gen_btn"):
                with st.spinner("Analysing with Llama 3.3-70b — this takes ~10 s…"):
                    try:
                        result = generate_compliance_summary(
                            doc["text"], detections, risk, doc["filename"]
                        )
                        st.session_state.summary = result
                        # No st.rerun() — fall through to the block below
                        # in the SAME render cycle so the tab stays active
                    except Exception as e:
                        st.error(f"Generation failed: {e}")

        # ── Display report — immediately after generation OR on revisit ────
        if st.session_state.summary:
            hdr_col, dl_col, regen_col = st.columns([3, 1, 1])
            hdr_col.success("✅ Compliance report ready")
            dl_col.download_button(
                "📥 Download (.md)",
                data=st.session_state.summary,
                file_name=f"compliance_{doc['filename']}.md",
                mime="text/markdown",
                key="dl_compliance",
            )
            # Regenerate: clear summary — the button-click rerun (which Streamlit
            # triggers automatically) will re-render the Generate button with tab preserved
            if regen_col.button("🔄 Regenerate", key="regen_btn"):
                st.session_state.summary = ""
            st.divider()
            if st.session_state.summary:  # guard: may have just been cleared above
                st.markdown(st.session_state.summary)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — Ask Questions
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("Ask Questions About the Document")

    if not groq_ok:
        st.error("❌ Enter your Groq API key in the sidebar to use Q&A.")
    else:
        def _get_answer(question: str) -> str:
            """Call RAG or direct QA, auto-rebuild index if stale."""
            det_summary = "\n".join(
                f"- {d.pii_type}: {d.count} instance(s)" for d in detections
            ) or "No PII detected."
            if use_rag:
                if not is_index_built():
                    try:
                        build_index(doc["text"])
                        st.session_state.rag_built = True
                    except Exception:
                        st.session_state.rag_built = False
                if st.session_state.rag_built:
                    ans = rag_answer(question, det_summary)
                    if ans:  # empty string means index not ready — fall through
                        return ans
            return answer_question(question, doc["text"], detections)

        # ── Quick-question buttons ─────────────────────────────────────────
        st.markdown("**Quick questions — click to ask instantly:**")
        quick_qs = [
            "What sensitive data exists in this document?",
            "How many email addresses are present?",
            "What are the main compliance risks?",
            "Summarize this document.",
            "What remediation steps are recommended?",
            "Which regulations apply to this document?",
        ]
        qc = st.columns(3)
        clicked_q = None
        for i, q in enumerate(quick_qs):
            if qc[i % 3].button(q, key=f"qq_{i}", use_container_width=True):
                clicked_q = q

        st.divider()

        # ── Chat history ───────────────────────────────────────────────────
        for turn in st.session_state.chat_history:
            with st.chat_message("user"):
                st.write(turn["question"])
            with st.chat_message("assistant"):
                st.write(turn["answer"])

        # ── Typed question form ────────────────────────────────────────────
        with st.form("chat_form", clear_on_submit=True):
            typed = st.text_input(
                "Or type your own question:",
                placeholder="e.g. How many Aadhaar numbers are in this document?",
            )
            ask_btn = st.form_submit_button("Ask ➤", type="primary")

        # ── Process question inline (no st.rerun → tab stays active) ──────
        question_to_ask = clicked_q or (typed.strip() if ask_btn and typed.strip() else None)

        if question_to_ask:
            with st.chat_message("user"):
                st.write(question_to_ask)
            with st.chat_message("assistant"):
                with st.spinner("Thinking…"):
                    try:
                        ans = _get_answer(question_to_ask)
                    except Exception as e:
                        ans = f"⚠️ Error: {e}"
                st.write(ans)
            st.session_state.chat_history.append({"question": question_to_ask, "answer": ans})

        # ── Clear chat ─────────────────────────────────────────────────────
        if st.session_state.chat_history:
            if st.button("🗑️ Clear Chat", key="clear_chat"):
                st.session_state.chat_history = []

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — Redacted Preview
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("Document Redaction Preview")

    preview_src = doc["text"][:2000]

    mode = st.radio(
        "Redaction mode:",
        ["Original only", "Masked (partial)", "Fully Redacted"],
        horizontal=True,
        key="redact_mode_radio",
    )

    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("**📄 Original Document**")
        st.text_area("orig_preview", value=preview_src, height=360,
                     label_visibility="collapsed", key="orig_ta", disabled=True)

    with col_r:
        if mode == "Original only":
            st.markdown("**← Select a redaction mode to compare**")
            st.info("Choose **Masked** or **Fully Redacted** above to see the side-by-side comparison.")
        elif mode == "Masked (partial)":
            st.markdown("**🔏 Masked Preview** *(first 2 + last 2 chars visible)*")
            masked_preview = mask_text(preview_src)
            st.text_area("masked_preview", value=masked_preview, height=360,
                         label_visibility="collapsed", key="masked_ta", disabled=True)
        else:
            st.markdown("**🚫 Fully Redacted** *([REDACTED_TYPE] tags)*")
            redacted_preview = full_redact(preview_src)
            st.text_area("redacted_preview", value=redacted_preview, height=360,
                         label_visibility="collapsed", key="redacted_ta", disabled=True)

    st.divider()

    # Download buttons
    dl1, dl2 = st.columns(2)
    with dl1:
        st.download_button(
            "📥 Download Masked Document",
            data=mask_text(doc["text"]),
            file_name=f"masked_{doc['filename']}.txt",
            mime="text/plain",
            key="dl_masked",
        )
    with dl2:
        st.download_button(
            "📥 Download Fully Redacted Document",
            data=full_redact(doc["text"]),
            file_name=f"redacted_{doc['filename']}.txt",
            mime="text/plain",
            key="dl_redacted",
        )

    # CSV raw view
    if doc["type"] == "CSV" and "dataframe" in doc:
        st.divider()
        st.subheader("📊 CSV Raw Preview")
        st.dataframe(doc["dataframe"].head(20), use_container_width=True)

    # What was redacted?
    if detections:
        st.divider()
        st.subheader("What gets redacted in this document?")
        st.dataframe(
            pd.DataFrame([
                {"PII Type": d.pii_type, "Instances": d.count, "Severity": d.severity}
                for d in detections
            ]).style.map(
                lambda v: {
                    "HIGH":   "color:#c0392b;font-weight:700",
                    "MEDIUM": "color:#856404;font-weight:700",
                    "LOW":    "color:#155724;font-weight:700",
                }.get(v, ""),
                subset=["Severity"],
            ),
            use_container_width=True, hide_index=True,
        )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — Audit Log
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("Scan Audit Log")
    entries = read_log()

    if not entries:
        st.info("No scans yet. Upload a document to start the audit trail.")
    else:
        df_log = pd.DataFrame(entries)
        a1, a2, a3 = st.columns(3)
        a1.metric("Total Scans", len(df_log))
        if "risk_level" in df_log.columns:
            a2.metric("High Risk Docs",   int((df_log["risk_level"] == "HIGH").sum()))
            a3.metric("Medium Risk Docs", int((df_log["risk_level"] == "MEDIUM").sum()))
        st.divider()
        st.dataframe(df_log, use_container_width=True, hide_index=True)
        st.divider()
        dl_col, chart_col = st.columns([1, 2])
        with dl_col:
            with open("audit_log.csv", "rb") as f:
                st.download_button("📥 Download Audit Log", f, "audit_log.csv", "text/csv")
        with chart_col:
            if "risk_level" in df_log.columns:
                st.markdown("**Risk distribution across all scans:**")
                st.bar_chart(df_log["risk_level"].value_counts())
