# 🛡️ Proteccio — Sensitive Data Detection & Compliance Assistant

> An AI-powered application that detects sensitive/confidential information in documents, classifies risk levels, generates compliance reports, and answers questions about uploaded documents.

---

## 🚀 Live Demo

**Deployed App:** [https://proteccio-data-assistant.streamlit.app](https://proteccio-data-assistant.streamlit.app)

---

## 📸 Features

| Feature | Description |
|---|---|
| 📤 Document Upload | PDF, TXT, CSV support |
| 🔍 PII Detection | 12+ sensitive data types via regex + spaCy |
| ⚖️ Risk Classification | Low / Medium / High scoring with weighted algorithm |
| 🤖 AI Compliance Report | Groq Llama-3.3-70b generates structured reports |
| 💬 Document Q&A | RAG-powered Q&A using FAISS + LangChain |
| 🔒 Data Redaction | Partial masking + full redaction download |
| 📊 Audit Logging | CSV audit trail of all scans |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Streamlit Frontend                     │
│   Upload → Detection Tab → Summary Tab → QA Tab         │
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
         │  Regex Patterns (12 types)  │
         │  + spaCy NER (supporting)   │
         └──────┬──────────────┬───────┘
                │              │
    ┌───────────▼──┐    ┌──────▼──────────────┐
    │ Risk Scorer  │    │   RAG Pipeline       │
    │ Weighted algo│    │ LangChain Splitter   │
    │ LOW/MED/HIGH │    │ → FAISS Index        │
    └───────────┬──┘    │ → Groq LLM Answer   │
                │       └──────────────────────┘
    ┌───────────▼──────────────────────┐
    │         Groq AI Engine           │
    │   llama-3.3-70b-versatile        │
    │  Compliance Summary + QA         │
    └──────────────────────────────────┘
```

---

## 🔍 PII Detection Types

| Type | Severity | Pattern |
|---|---|---|
| Aadhaar Number | 🔴 HIGH | 12-digit format starting 2-9 |
| PAN Number | 🔴 HIGH | ABCDE1234F format |
| Credit Card | 🔴 HIGH | Visa/MC/Amex/Discover |
| API Key / Password | 🔴 HIGH | key/secret/token followed by long string |
| JWT Token | 🔴 HIGH | eyJ... format |
| Bank Account / IFSC | 🔴 HIGH | IFSC code + 9-18 digit accounts |
| Email Address | 🟠 MEDIUM | Standard email regex |
| Phone Number | 🟠 MEDIUM | Indian mobile/landline |
| Employee ID | 🟠 MEDIUM | EMP/STAFF prefix patterns |
| Date of Birth | 🟠 MEDIUM | DOB keyword + date |
| IP Address | 🟢 LOW | IPv4 format |
| Confidential Keywords | 🟢 LOW | "confidential", "restricted", etc. |

---

## 🤖 AI/ML Approach

### 1. Rule-Based Detection (Primary)
Regex patterns tuned for Indian PII formats (Aadhaar, PAN, IFSC) alongside international formats (credit cards, JWT tokens). Fast, deterministic, zero API dependency.

### 2. LLM-Powered Analysis (Groq / Llama 3.3-70b)
Structured prompting with document context + detection results → generates compliance reports aligned with:
- **DPDP Act 2023** (India's Digital Personal Data Protection Act)
- **IT Act 2000**
- **PCI-DSS** (when card data detected)
- **GDPR** (when applicable)

### 3. RAG for Q&A
Documents are chunked (500-token chunks, 100-token overlap) using LangChain's `RecursiveCharacterTextSplitter`, embedded via `sentence-transformers/all-MiniLM-L6-v2`, indexed in FAISS, and retrieved for each question. The retrieved context grounds the LLM answer, reducing hallucination.

### 4. Risk Scoring Algorithm
Weighted scoring: HIGH PII = 10 pts/instance, MEDIUM = 4 pts, LOW = 1 pt. Capped at 100. Level thresholds: ≥2 HIGH types or score≥30 → HIGH risk; 1 HIGH or ≥2 MEDIUM or score≥10 → MEDIUM; else LOW.

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.10+
- [Groq API Key](https://console.groq.com) (free tier available)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/proteccio-data-assistant.git
cd proteccio-data-assistant

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download spaCy model
python -m spacy download en_core_web_sm

# 5. Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# 6. Run the application
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
- `sample_employee.txt` — Contains Aadhaar, PAN, API keys, credit card → HIGH risk
- `sample_data.csv` — Employee data CSV with PII → HIGH risk

---

## 🚧 Challenges Faced

1. **False Positives in Bank Account Detection** — The broad regex for 9-18 digit numbers matches many non-financial numbers. Mitigated by requiring keyword context proximity.

2. **PDF Text Extraction Quality** — Scanned PDFs with no text layer return empty content. Addressed with a warning; full OCR (Tesseract) is a planned improvement.

3. **RAG Embedding Speed** — First-time model download for `all-MiniLM-L6-v2` is slow. Cached after first use via HuggingFace cache.

4. **Groq Rate Limits** — Free tier has per-minute token limits. Handled by capping document preview sent to LLM at 2000 characters.

5. **Indian PII Specificity** — Aadhaar regex needed to exclude numbers starting with 0 or 1 (invalid Aadhaar). PAN required exact 10-character format validation.

---

## 🔮 Future Improvements

- [ ] **OCR Support** — Tesseract integration for scanned PDFs and images
- [ ] **Multi-document analysis** — Compare PII exposure across document sets
- [ ] **Named Entity Recognition** — spaCy NER for PERSON, ORG, LOCATION detection
- [ ] **Database integration** — Store scan history in PostgreSQL
- [ ] **Role-based access** — Admin/analyst roles with different redaction permissions
- [ ] **CI/CD pipeline** — GitHub Actions for automated testing and deployment
- [ ] **Webhook alerts** — Notify security teams when HIGH risk documents are uploaded
- [ ] **DOCX support** — Microsoft Word document parsing
- [ ] **Custom regex rules** — Allow organizations to define their own PII patterns
- [ ] **Compliance framework selector** — HIPAA, SOC 2, ISO 27001 templates

---

## 📁 Project Structure

```
proteccio-data-assistant/
├── app/
│   ├── main.py                  # Streamlit UI (all 5 tabs)
│   ├── backend/
│   │   ├── document_parser.py   # PDF/TXT/CSV text extraction
│   │   ├── detector.py          # Regex PII detection + risk scoring
│   │   ├── ai_engine.py         # Groq LLM — compliance summary + QA
│   │   └── rag.py               # FAISS RAG pipeline
│   └── utils/
│       ├── masking.py           # Partial masking + full redaction
│       └── audit_logger.py      # CSV audit trail
├── sample_docs/
│   ├── sample_employee.txt      # Test file — HIGH risk
│   └── sample_data.csv          # Test file — HIGH risk
├── requirements.txt
├── Dockerfile
├── .env.example
└── README.md
```

---

## 📄 License

MIT License — built for the Proteccio Data AI Innovation Internship assignment.
