import os
from typing import List, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from groq import Groq

_chunks: List[str] = []
_vectorizer: Optional[TfidfVectorizer] = None
_tfidf_matrix = None


def is_index_built() -> bool:
    """Return True only if the in-memory TF-IDF index is ready."""
    return _vectorizer is not None and len(_chunks) > 0


def build_index(text: str) -> None:
    """Chunk document text and build a TF-IDF index for retrieval."""
    global _chunks, _vectorizer, _tfidf_matrix

    # Simple chunking by paragraphs then fixed-size windows
    raw_chunks = [p.strip() for p in text.split("\n\n") if p.strip()]
    # If paragraphs are too large, split further
    final_chunks = []
    for chunk in raw_chunks:
        if len(chunk) > 600:
            words = chunk.split()
            for i in range(0, len(words), 100):
                piece = " ".join(words[i:i + 120])
                if piece.strip():
                    final_chunks.append(piece.strip())
        else:
            final_chunks.append(chunk)

    if not final_chunks:
        final_chunks = [text[:500]] if text else ["empty document"]

    _chunks = final_chunks
    _vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
    _tfidf_matrix = _vectorizer.fit_transform(_chunks)


def retrieve_context(question: str, k: int = 4) -> str:
    """Retrieve top-k relevant chunks for a question using TF-IDF cosine similarity."""
    global _chunks, _vectorizer, _tfidf_matrix
    if _vectorizer is None or not _chunks:
        return ""
    q_vec = _vectorizer.transform([question])
    scores = cosine_similarity(q_vec, _tfidf_matrix).flatten()
    top_indices = scores.argsort()[-k:][::-1]
    # Return top-k chunks regardless of score — TF-IDF gives 0 for short/conversational
    # questions with no exact term match, but chunks are still the best available context
    return "\n\n---\n\n".join(_chunks[i] for i in top_indices)


def rag_answer(question: str, detections_summary: str) -> str:
    """RAG pipeline: retrieve relevant chunks → answer with Groq LLM."""
    context = retrieve_context(question)
    if not context:
        # Index not built yet — fall back signal to caller
        return ""

    client = Groq(api_key=os.getenv("GROQ_API_KEY", ""))

    prompt = f"""You are a document analysis assistant specializing in data privacy and compliance.
Answer the question using the provided document context and PII detection results.

**Retrieved Document Context:**
{context}

**PII Detection Summary:**
{detections_summary}

**Question:** {question}

Answer concisely and accurately. If the context lacks enough detail, say so clearly."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=600,
    )
    return response.choices[0].message.content
