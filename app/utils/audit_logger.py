import csv
import os
from datetime import datetime


LOG_FILE = "audit_log.csv"
HEADERS = ["timestamp", "filename", "file_type", "risk_level", "risk_score",
           "total_pii_types", "total_instances", "high_severity", "medium_severity", "low_severity"]


def log_scan(filename: str, file_type: str, risk: dict) -> None:
    """Append a scan record to the audit log CSV."""
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        if not file_exists:
            writer.writeheader()
        writer.writerow({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": filename,
            "file_type": file_type,
            "risk_level": risk.get("level", ""),
            "risk_score": risk.get("score", 0),
            "total_pii_types": risk.get("total_types", 0),
            "total_instances": risk.get("total_instances", 0),
            "high_severity": risk.get("high_count", 0),
            "medium_severity": risk.get("medium_count", 0),
            "low_severity": risk.get("low_count", 0),
        })


def read_log() -> list:
    """Read all audit log entries."""
    if not os.path.isfile(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))
