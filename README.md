# 🛡️ Proteccio — Sensitive Data Detection & Compliance Assistant

> An AI-powered application that detects sensitive/confidential information in documents, classifies risk levels, generates compliance reports, and answers questions about uploaded documents.

---

## 🚀 Live Demo

**[https://sensitive-data-detection.streamlit.app](https://sensitive-data-detection.streamlit.app)**

---

## 📸 Features

| Feature | Description |
|---|---|
| 📤 Document Upload | PDF, TXT, CSV support |
| 🔍 PII Detection | 13 sensitive data types via regex patterns |
| ⚖️ Risk Classification | Low / Medium / High scoring with weighted algorithm |
| 🤖 AI Compliance Report | Groq Llama-3.3-70b generates structured reports |
| 💬 Document Q&A | TF-IDF RAG-powered Q&A — no API needed for retrieval |
| 🔒 Data Redaction | Partial masking + full redaction with download |
| 📊 Audit Logging | CSV audit trail of all scans |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Streamlit Frontend                     │
│  Upload → Detection → Compliance → Q&A → Redact → Audit │
└──────────────────────┬──────────────────────────────────┘
                       │
         ┌─────────────▼──────────────┐
         │      Document Parser        │
         │  PyMuPDF (PDF) │ pandas (CSV)│
         │        plain text (TXT)     │
         └─────────────┬──────────────┘
                       │
         ┌─────────────▼──────────────┐
         │      Detection Engine       │
         │  13 Regex Patterns          │
         │  (Indian + international)   │
         └──────┬──────────────┬───────┘
                │              │
    ┌───────────▼──┐    ┌──────▼──────────────┐
    │ Risk Scorer  │    │   RAG Pipeline       │
    │ Weighted algo│    │ sklearn TF-IDF       │
    │ LOW/MED/HIGH │    │ → Cosine Similarity  │
    └───────────┬──┘    │ → Groq LLM Answer   │
                │       └──────────────────────┘
    ┌───────────▼──────────────────────┐
    │         Groq AI Engine           │
    │   llama-3.3-70b-versatile        │
    │  Compliance Summary + Q&A        │
    └──────────────────────────────────┘
```

---

## 🔍 PII Detection Types (13 Types)

| Type | Severity | Description |
|---|---|---|
| Aadhaar Number | 🔴 HIGH | 12-digit format starting 2–9 |
| PAN Number | 🔴 HIGH | ABCDE1234F format |
| Credit Card Number | 🔴 HIGH | Visa / MasterCard / Amex / Discover |
| JWT Token | 🔴 HIGH | eyJ… three-part base64 format |
| API Key / Password | 🔴 HIGH | key/secret/token followed by long string |
| IFSC Code | 🔴 HIGH | 11-char bank branch code |
| Bank Account Number | 🔴 HIGH | 9–18 digits with keyword context |
| Email Address | 🟠 MEDIUM | Standard email format |
| Phone Number | 🟠 MEDIUM | Indian mobile and landline numbers |
| Employee ID | 🟠 MEDIUM | EMP/STAFF prefix patterns |
| Date of Birth | 🟠 MEDIUM | DOB keyword + date value |
| IP Address | 🟢 LOW | IPv4 format |
| Confidential Keywords | 🟢 LOW | "confidential", "restricted", etc. |

---

## 🤖 AI/ML Approach

### 1. Rule-Based Detection (Primary)
Regex patterns tuned for Indian PII formats (Aadhaar, PAN, IFSC) alongside international formats (credit cards, JWT tokens). Fast, deterministic, zero API dependency. Patterns use `re.IGNORECASE` per-pattern (Python 3.11+ compatible) to avoid global flag conflicts.

### 2. LLM-Powered Analysis (Groq / Llama 3.3-70b)
Structured prompting with document context + detection results → generates compliance reports aligned with:
- **DPDP Act 2023** (India's Digital Personal Data Protection Act)
- **IT Act 2000**
- **PCI-DSS** (when card data detected)
- **GDPR** (when applicable)

### 3. RAG for Q&A (sklearn TF-IDF)
Documents are chunked by paragraph then 120-word windows. Chunks are vectorised with `TfidfVectorizer` (sklearn) and retrieved per question using cosine similarity. The retrieved context grounds the Groq LLM answer, reducing hallucination. No external embedding API or model download required.

### 4. Risk Scoring Algorithm
Weighted scoring: HIGH PII = 10 pts/instance, MEDIUM = 4 pts, LOW = 1 pt. Capped at 100.  
Level thresholds: ≥ 2 HIGH types or score ≥ 30 → **HIGH**; 1 HIGH or ≥ 2 MEDIUM or score ≥ 10 → **MEDIUM**; else **LOW**.

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.10+
- [Groq API Key](https://console.groq.com) (free tier available)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/pranay9981/Sensitive-Data-Detection-Compliance-Assistant.git
cd Sensitive-Data-Detection-Compliance-Assistant

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# 5. Run the application
streamlit run app/main.py
```

The app will open at `http://localhost:8501`

### Docker

```bash
docker build -t proteccio-assistant .
docker run -p 8501:8501 -e GROQ_API_KEY=your_key_here proteccio-assistant
```

---

## 🧪 Testing

Try uploading the included sample files in `sample_docs/`:
- `sample_employee.txt` — Contains Aadhaar, PAN, API keys, credit card, JWT → **HIGH** risk
- `sample_data.csv` — Employee data CSV with 5 rows of PII → **HIGH** risk

---

## 🚧 Challenges Faced

1. **Bank Account False Positives** — A bare `\d{9-18}` regex matched phone numbers, Aadhaar, and salary figures. Fixed by requiring keyword context (e.g. "account no:", "acc no:") before the digit sequence.

2. **Python 3.11 Regex Incompatibility** — `(?i)` inline flags inside alternations raise `PatternError` in Python 3.11+. Fixed by passing `re.IGNORECASE` as a per-pattern `flags` argument to `re.findall`.

3. **CSV Double-Counting** — Concatenating `df.to_string()` and a flat value join caused each cell to appear twice. Fixed by building one `"col: value | col: value"` line per row.

4. **Streamlit Tab Reset on `st.rerun()`** — Calling `st.rerun()` inside a tab always resets the active tab to tab 1. Fixed by processing all state changes (compliance generation, Q&A) inline in the same render cycle so no explicit rerun is needed.

5. **RAG Index Lost on Server Restart** — Module-level TF-IDF globals reset when Streamlit's file watcher reloaded the server, while `rag_built=True` remained in session state. Fixed with an `is_index_built()` guard that auto-rebuilds the index transparently.

6. **Groq Rate Limits** — Free tier has per-minute token limits. Mitigated by capping document text sent to the LLM and using RAG retrieval (top-4 chunks) rather than sending the full document.

---

## 🔮 Future Improvements

- [ ] **OCR Support** — Tesseract integration for scanned PDFs and images
- [ ] **Multi-document analysis** — Compare PII exposure across document sets
- [ ] **Named Entity Recognition** — spaCy NER for PERSON, ORG, LOCATION detection
- [ ] **DOCX support** — Microsoft Word document parsing
- [ ] **Custom regex rules** — Allow organisations to define their own PII patterns
- [ ] **Compliance framework selector** — HIPAA, SOC 2, ISO 27001 templates
- [ ] **Webhook alerts** — Notify security teams when HIGH risk documents are uploaded
- [ ] **Database integration** — Store scan history in PostgreSQL

---

## 📁 Project Structure

```
Sensitive-Data-Detection-Compliance-Assistant/
├── app/
│   ├── main.py                  # Streamlit UI (5 tabs)
│   ├── backend/
│   │   ├── document_parser.py   # PDF / TXT / CSV text extraction
│   │   ├── detector.py          # Regex PII detection + risk scoring
│   │   ├── ai_engine.py         # Groq LLM — compliance summary + Q&A
│   │   └── rag.py               # TF-IDF RAG pipeline (sklearn)
│   └── utils/
│       ├── masking.py           # Partial masking + full redaction
│       └── audit_logger.py      # CSV audit trail
├── sample_docs/
│   ├── sample_employee.txt      # Test file — HIGH risk
│   └── sample_data.csv          # Test file — HIGH risk
├── .streamlit/
│   └── config.toml              # Disables file watcher (prevents torch conflicts)
├── requirements.txt
├── Dockerfile
├── .env.example
└── README.md
```

---

## 📄 License

MIT License — built for the Proteccio Data AI Innovation Internship assignment.
