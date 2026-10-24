"""
AgentShield Document Ingestion & Chunking Pipeline
Handles PDF (selectable & hidden text) and TXT files:
- Magic byte validation
- Size & page bounding
- Local text extraction (pypdf with native stream fallback)
- Image-only PDF detection (422 response)
- Overlapping chunk generation with page provenance
- Adversarial de-obfuscation via normalizer
- Bounded chunk selection for Groq LLM contextual review
"""
from __future__ import annotations

import io
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import get_settings
from app.schemas.models import DocumentChunk, DocumentMetadata, PolicyDecision
from app.services.normalizer import normalize_text
from app.services.scanner import scan

# Sanitizer for uploaded filenames
FILENAME_SAFE = re.compile(r'[^a-zA-Z0-9_\-\.]')


def sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename).strip()
    clean = FILENAME_SAFE.sub('_', base)
    return clean[:100] or "unnamed_document"


def _extract_text_from_pdf(content: bytes, max_pages: int) -> Tuple[List[Tuple[int, str]], int]:
    """
    Extracts text per page from PDF bytes.
    Returns: (list of (page_num, page_text), total_pages)
    Extracts selectable text including white-on-white / 1pt font hidden text.
    """
    pages_text: List[Tuple[int, str]] = []

    # Attempt extraction via pypdf
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(content))
        total_pages = len(reader.pages)
        pages_to_read = min(total_pages, max_pages)

        for p_idx in range(pages_to_read):
            page = reader.pages[p_idx]
            text = page.extract_text() or ""
            pages_text.append((p_idx + 1, text))
        return pages_text, total_pages
    except ImportError:
        pass
    except Exception as exc:
        pass

    # Native fallback PDF stream extractor (handles standard Text objects: BT ... ET)
    try:
        stream_str = content.decode('latin-1', errors='ignore')
        # Simple regex for PDF text chunks within (text) Tj or TJ
        text_blocks = []
        for match in re.finditer(r'BT\s*(.*?)\s*ET', stream_str, re.DOTALL):
            bt_content = match.group(1)
            # Find literal strings (string)
            strings = re.findall(r'\((.*?)\)\s*T[jd]', bt_content)
            if strings:
                text_blocks.append(" ".join(strings))
        extracted = "\n".join(text_blocks)
        return [(1, extracted)], 1
    except Exception:
        return [], 0


def validate_and_extract_document(
    filename: str, content: bytes
) -> Tuple[DocumentMetadata, List[Tuple[int, str]]]:
    """
    Validates document header, size, pages, and extracts page-wise text.
    Raises ValueError with client-actionable error messages.
    """
    settings = get_settings()

    # 1. Empty and size check
    if not content or len(content.strip()) == 0:
        raise ValueError("The uploaded document is empty.")

    if len(content) > settings.max_upload_bytes:
        raise ValueError(
            f"File exceeds maximum upload size of {settings.max_upload_bytes // (1024 * 1024)}MB."
        )

    clean_name = sanitize_filename(filename)
    lower_name = clean_name.lower()

    # 2. Magic byte inspection & extension spoofing check
    if lower_name.endswith('.pdf') and not content.startswith(b'%PDF-'):
        raise ValueError(
            "Unsupported media type: file claims .pdf extension but lacks %PDF- header (magic-byte spoofing)."
        )

    if not (lower_name.endswith('.pdf') or lower_name.endswith('.txt')) and not content.startswith(b'%PDF-'):
        raise ValueError("Unsupported media type: only text-based PDF and TXT files are accepted.")

    if content.startswith(b'%PDF-'):
        file_type = "pdf"
        pages_data, total_pages = _extract_text_from_pdf(content, settings.max_pdf_pages)
        if total_pages > settings.max_pdf_pages:
            limitation = f"Document truncated to first {settings.max_pdf_pages} of {total_pages} pages."
        else:
            limitation = None

        total_extracted_chars = sum(len(text.strip()) for _, text in pages_data)
        # Check for image-only PDF
        if total_extracted_chars == 0:
            raise ValueError(
                "Image-only PDF detected. OCR is not available. Please provide a text-based PDF or TXT file."
            )
    else:
        # Check for TXT
        try:
            # Try UTF-8
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                # Try latin-1 fallback
                text = content.decode('latin-1')
            except Exception:
                raise ValueError("Unsupported media type: only text-based PDF and TXT files are accepted.")

        file_type = "txt"
        total_pages = 1
        pages_data = [(1, text)]
        limitation = None
        total_extracted_chars = len(text.strip())

        if total_extracted_chars == 0:
            raise ValueError("The uploaded text document is empty.")

    meta = DocumentMetadata(
        filename=clean_name,
        file_type=file_type,
        file_size_bytes=len(content),
        pages=total_pages,
        extracted_chars=total_extracted_chars,
        chunks_total=0,
        chunks_scanned=0,
        chunks_sent_to_llm=0,
        llm_review_status="pending",
        limitation_note=limitation,
        suspicious_regions=[],
    )

    return meta, pages_data


def chunk_and_scan_document(
    meta: DocumentMetadata,
    pages_data: List[Tuple[int, str]],
    chunk_size: int = 800,
    chunk_overlap: int = 150,
) -> List[DocumentChunk]:
    """
    Splits document into overlapping chunks, normalizes each chunk,
    and runs deterministic security scanning across ALL chunks.
    """
    chunks: List[DocumentChunk] = []
    chunk_index = 0

    for page_num, page_text in pages_data:
        text_len = len(page_text)
        if text_len == 0:
            continue

        start = 0
        while start < text_len:
            end = min(start + chunk_size, text_len)
            raw_chunk = page_text[start:end]

            # Normalize chunk & flag obfuscation
            normalized_chunk, flags = normalize_text(raw_chunk)

            # Fast deterministic scan
            findings = scan(normalized_chunk)

            preview = raw_chunk[:140].replace('\n', ' ').strip()
            if len(raw_chunk) > 140:
                preview += "..."

            chunk = DocumentChunk(
                page=page_num,
                chunk_index=chunk_index,
                char_start=start,
                char_end=end,
                text_preview=preview,
                obfuscation_flags=flags,
                scanner_score=findings.raw_score,
                scanner_patterns=findings.patterns_matched,
                sent_to_llm=False,
                decision=PolicyDecision.BLOCK if findings.raw_score >= 70 else (
                    PolicyDecision.QUARANTINE if findings.raw_score >= 35 else PolicyDecision.ALLOW
                ),
                judge_finding=None,
            )
            chunks.append(chunk)

            if findings.raw_score >= 20 or flags:
                meta.suspicious_regions.append(
                    f"Page {page_num} Chunk #{chunk_index} (score {findings.raw_score:.0f}): "
                    f"{', '.join(findings.patterns_matched or flags)}"
                )

            chunk_index += 1
            if end == text_len:
                break
            start += chunk_size - chunk_overlap

    meta.chunks_total = len(chunks)
    meta.chunks_scanned = len(chunks)
    return chunks


def select_chunks_for_judge(
    chunks: List[DocumentChunk],
    max_llm_calls: int = 6,
    score_threshold: float = 15.0,
) -> List[DocumentChunk]:
    """
    Selects prioritized chunks for Groq contextual judge evaluation:
    1. All chunks with scanner score >= threshold or obfuscation flags.
    2. Small representative sample of remaining chunks up to max_llm_calls budget.
    """
    suspicious = [
        c for c in chunks
        if c.scanner_score >= score_threshold or len(c.obfuscation_flags) > 0
    ]

    # Sort suspicious by highest score first
    suspicious.sort(key=lambda x: x.scanner_score, reverse=True)

    if len(suspicious) >= max_llm_calls:
        selected = suspicious[:max_llm_calls]
    else:
        selected = list(suspicious)
        remaining = [c for c in chunks if c not in suspicious]
        needed = max_llm_calls - len(selected)
        selected.extend(remaining[:needed])

    for c in selected:
        c.sent_to_llm = True

    return selected
