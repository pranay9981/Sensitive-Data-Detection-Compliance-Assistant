import fitz  # PyMuPDF
import pandas as pd
import io


def parse_document(uploaded_file) -> dict:
    """Parse uploaded file and return text content + metadata."""
    filename = uploaded_file.name
    ext = filename.rsplit(".", 1)[-1].lower()
    file_bytes = uploaded_file.read()

    if ext == "pdf":
        return _parse_pdf(file_bytes, filename)
    elif ext == "txt":
        return _parse_txt(file_bytes, filename)
    elif ext == "csv":
        return _parse_csv(file_bytes, filename)
    else:
        raise ValueError(f"Unsupported file type: {ext}")


def _parse_pdf(file_bytes: bytes, filename: str) -> dict:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    pages = []
    full_text = ""
    for i, page in enumerate(doc):
        text = page.get_text()
        pages.append({"page": i + 1, "text": text})
        full_text += text + "\n"
    doc.close()
    return {
        "filename": filename,
        "type": "PDF",
        "text": full_text.strip(),
        "pages": pages,
        "word_count": len(full_text.split()),
        "char_count": len(full_text),
    }


def _parse_txt(file_bytes: bytes, filename: str) -> dict:
    text = file_bytes.decode("utf-8", errors="ignore")
    return {
        "filename": filename,
        "type": "TXT",
        "text": text.strip(),
        "pages": [{"page": 1, "text": text}],
        "word_count": len(text.split()),
        "char_count": len(text),
    }


def _parse_csv(file_bytes: bytes, filename: str) -> dict:
    df = pd.read_csv(io.BytesIO(file_bytes))
    # Build one clean text: each row as "col: value  col: value" lines
    # This avoids duplication while still exposing all cell values to the detector
    lines = []
    for _, row in df.iterrows():
        parts = [f"{col}: {val}" for col, val in row.items()]
        lines.append("  |  ".join(str(p) for p in parts))
    text = "\n".join(lines)
    return {
        "filename": filename,
        "type": "CSV",
        "text": text.strip(),
        "pages": [{"page": 1, "text": text}],
        "word_count": len(text.split()),
        "char_count": len(text),
        "dataframe": df,
        "shape": df.shape,
    }
