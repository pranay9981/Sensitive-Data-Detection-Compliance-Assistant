import os
from groq import Groq
from typing import List
from app.backend.detector import Detection


def _get_client() -> Groq:
    key = os.getenv("GROQ_API_KEY", "")
    if not key:
        raise ValueError("GROQ_API_KEY not set. Add it to your .env file.")
    return Groq(api_key=key)


def generate_compliance_summary(
    doc_text: str,
    detections: List[Detection],
    risk: dict,
    filename: str,
) -> str:
    """Generate a structured compliance and security summary via Groq LLM."""
    client = _get_client()

    detection_summary = "\n".join(
        f"- {d.pii_type} [{d.severity}]: {d.count} instance(s) found"
        for d in detections
    ) or "No sensitive data detected."

    prompt = f"""You are a Data Privacy and Compliance Officer AI assistant.

Analyze the following document and PII detection results, then generate a structured compliance report.

**Document:** {filename}
**Risk Level:** {risk.get('level', 'UNKNOWN')} (Score: {risk.get('score', 0)}/100)
**Total PII Instances Found:** {risk.get('total_instances', 0)}

**Detected Sensitive Data:**
{detection_summary}

**Document Preview (first 2000 chars):**
{doc_text[:2000]}

Generate a compliance report with exactly these sections:

## 1. Executive Summary
Brief 2-3 sentence overview of the document's compliance posture.

## 2. Compliance Observations
List specific compliance concerns under relevant frameworks (DPDP Act 2023, GDPR if applicable, PCI-DSS if cards detected, IT Act 2000).

## 3. Security Risks Identified
Enumerate specific risks with their potential impact.

## 4. Regulatory Exposure
Which regulations this document may be in violation of and why.

## 5. Remediation Steps
Prioritized action items (numbered list) the organization should take immediately.

## 6. Data Handling Recommendations
Best practices for handling this type of document going forward.

Be specific, actionable, and professional. Do not be generic."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=1500,
    )
    return response.choices[0].message.content


def answer_question(question: str, context: str, detections: List[Detection]) -> str:
    """Answer a user question about the document using context."""
    client = _get_client()

    detection_info = "\n".join(
        f"- {d.pii_type}: {d.count} instance(s), samples: {', '.join(d.matches[:3])}"
        for d in detections
    ) or "No PII detected."

    system_prompt = """You are a document analysis assistant specialized in data privacy and compliance.
Answer questions about the document accurately and concisely.
If the answer involves sensitive data, describe it without revealing the actual values.
If you cannot find the answer in the provided context, say so clearly."""

    user_prompt = f"""**Document Context:**
{context[:3000]}

**PII Detection Results:**
{detection_info}

**User Question:** {question}

Provide a clear, accurate answer based on the document and detection results above."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        max_tokens=800,
    )
    return response.choices[0].message.content
