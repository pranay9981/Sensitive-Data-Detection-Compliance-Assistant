import re
from app.backend.detector import PATTERNS


def mask_text(text: str, mask_char: str = "*") -> str:
    """Replace all detected PII in text with masked placeholders."""
    masked = text
    for pii_type, config in PATTERNS.items():
        label = pii_type.upper().replace(" ", "_")

        def replace_match(m, label=label, mask_char=mask_char):
            full = m.group(0)
            # Keep first 2 and last 2 chars visible for context, mask the rest
            if len(full) <= 4:
                return f"[{label}]"
            visible_start = full[:2]
            visible_end = full[-2:]
            masked_middle = mask_char * (len(full) - 4)
            return f"{visible_start}{masked_middle}{visible_end}"

        masked = re.sub(config["regex"], replace_match, masked)
    return masked


def full_redact(text: str) -> str:
    """Fully redact all PII — replace with [REDACTED_TYPE] tags."""
    redacted = text
    for pii_type, config in PATTERNS.items():
        label = pii_type.upper().replace(" ", "_")
        redacted = re.sub(config["regex"], f"[REDACTED_{label}]", redacted)
    return redacted
