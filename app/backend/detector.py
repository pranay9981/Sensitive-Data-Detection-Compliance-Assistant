import re
from dataclasses import dataclass
from typing import List


@dataclass
class Detection:
    pii_type: str
    matches: List[str]
    count: int
    severity: str  # HIGH / MEDIUM / LOW
    description: str


# ── Regex patterns ────────────────────────────────────────────────────────────
# Each entry: regex, optional flags (default 0), severity, description

PATTERNS = {
    "Aadhaar Number": {
        "regex": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
        "severity": "HIGH",
        "description": "Indian government-issued 12-digit unique identity number",
    },
    "PAN Number": {
        "regex": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "severity": "HIGH",
        "description": "Indian Permanent Account Number issued by Income Tax Dept",
    },
    "Credit Card Number": {
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "HIGH",
        "description": "Credit/debit card number (Visa, MasterCard, Amex, Discover)",
    },
    "JWT Token": {
        "regex": r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
        "severity": "HIGH",
        "description": "JSON Web Tokens — may contain auth credentials",
    },
    "API Key / Password": {
        "regex": r'(?:api[_\-\s]?key|apikey|secret[_\-\s]?key|password|passwd|bearer)["\s:=]+([A-Za-z0-9_\-\.]{16,})',
        "flags": re.IGNORECASE,
        "severity": "HIGH",
        "description": "Hardcoded API keys, secrets, passwords, or bearer tokens",
    },
    "IFSC Code": {
        "regex": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "severity": "HIGH",
        "description": "Indian Financial System Code identifying a bank branch",
    },
    "Bank Account Number": {
        "regex": r"(?:account\s*(?:no\.?|number|#)?|acc\.?\s*no\.?|a/c\s*no\.?|bank\s*a/c)[:\s]*(\d{9,18})",
        "flags": re.IGNORECASE,
        "severity": "HIGH",
        "description": "Bank account numbers detected via keyword context",
    },
    "Email Address": {
        "regex": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "MEDIUM",
        "description": "Email addresses that may identify individuals",
    },
    "Phone Number": {
        "regex": r"(?:\+91[\s\-]?)?(?:\(0\d{2,4}\)[\s\-]?)?\b[6-9]\d{9}\b|\b0\d{2,4}[\s\-]?\d{6,8}\b",
        "severity": "MEDIUM",
        "description": "Indian mobile and landline phone numbers",
    },
    "Employee ID": {
        "regex": r"(?:emp(?:loyee)?[_\-\s]?(?:id|no|num|code)|staff[_\-\s]?(?:id|no))[:\s#]*([A-Z0-9\-]{4,15})",
        "flags": re.IGNORECASE,
        "severity": "MEDIUM",
        "description": "Employee identification numbers",
    },
    "Date of Birth": {
        "regex": r"(?:dob|date\s+of\s+birth|birth\s+date)[:\s]+(\d{1,2}[\-/]\d{1,2}[\-/]\d{2,4})",
        "flags": re.IGNORECASE,
        "severity": "MEDIUM",
        "description": "Date of birth — personally identifiable",
    },
    "IP Address": {
        "regex": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "LOW",
        "description": "IP addresses that may expose infrastructure details",
    },
    "Confidential Keywords": {
        "regex": r"\b(?:confidential|top\s+secret|internal\s+only|restricted|classified|do\s+not\s+distribute|proprietary|not\s+for\s+distribution)\b",
        "flags": re.IGNORECASE,
        "severity": "LOW",
        "description": "Documents marked as confidential or restricted",
    },
}

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def detect_pii(text: str) -> List[Detection]:
    """Run all regex patterns against text and return Detection objects."""
    results = []
    for pii_type, config in PATTERNS.items():
        flags = config.get("flags", 0)
        raw_matches = re.findall(config["regex"], text, flags)

        # Flatten tuple matches from capture groups; drop empty strings
        flat = []
        for m in raw_matches:
            if isinstance(m, tuple):
                flat.extend(x for x in m if x)
            elif m:  # skip empty strings from non-participating capture groups
                flat.append(m)

        unique = list(dict.fromkeys(flat))  # deduplicated, order-preserved
        if unique:
            results.append(Detection(
                pii_type=pii_type,
                matches=unique[:10],
                count=len(flat),
                severity=config["severity"],
                description=config["description"],
            ))

    results.sort(key=lambda d: SEVERITY_ORDER.get(d.severity, 0), reverse=True)
    return results


def compute_risk_score(detections: List[Detection]) -> dict:
    """Compute overall risk level and numeric score."""
    if not detections:
        return {"level": "LOW", "score": 0, "total_types": 0,
                "total_instances": 0, "high_count": 0, "medium_count": 0, "low_count": 0}

    weights = {"HIGH": 10, "MEDIUM": 4, "LOW": 1}
    score = sum(weights[d.severity] * d.count for d in detections)

    high_count   = sum(1 for d in detections if d.severity == "HIGH")
    medium_count = sum(1 for d in detections if d.severity == "MEDIUM")

    if high_count >= 2 or score >= 30:
        level = "HIGH"
    elif high_count == 1 or medium_count >= 2 or score >= 10:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "level": level,
        "score": min(score, 100),
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": sum(1 for d in detections if d.severity == "LOW"),
        "total_types": len(detections),
        "total_instances": sum(d.count for d in detections),
    }
