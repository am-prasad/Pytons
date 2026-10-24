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
import zlib
import zipfile
import xml.etree.ElementTree as ET
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


def _decode_pdf_hex(hex_str: str) -> str:
    """Helper to decode PDF hex strings <...> into unicode text."""
    cleaned = re.sub(r'[^0-9a-fA-F]', '', hex_str)
    if len(cleaned) % 2 != 0:
        cleaned += '0'
    if not cleaned:
        return ""
    try:
        raw_b = bytes.fromhex(cleaned)
        # Word PDFs frequently use UTF-16BE for CID/Identity-H fonts
        if len(raw_b) >= 2 and (raw_b[0] == 0 or raw_b[1] == 0):
            t = raw_b.decode('utf-16be', errors='ignore')
            if any(c.isprintable() for c in t):
                return t
        t_utf8 = raw_b.decode('utf-8', errors='ignore')
        if any(c.isprintable() for c in t_utf8):
            return t_utf8
        return raw_b.decode('latin-1', errors='ignore')
    except Exception:
        return ""


def _extract_text_from_docx(content: bytes) -> Tuple[List[Tuple[int, str]], int]:
    """
    Extracts text from Microsoft Word (.docx) documents with multi-tier resilience:
    1. python-docx (if available)
    2. zipfile + XML ElementTree over word/document.xml, headers, footers, footnotes
    3. Regex fallback across all XML text tags (<w:t>, <m:t>, etc.) with entity unescaping
    """
    # Engine 1: python-docx if installed
    try:
        import docx
        doc = docx.Document(io.BytesIO(content))
        p_texts = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
        for tbl in doc.tables:
            for row in tbl.rows:
                for cell in row.cells:
                    c_txt = cell.text.strip()
                    if c_txt and c_txt not in p_texts:
                        p_texts.append(c_txt)
        full_text = "\n\n".join(p_texts).strip()
        if full_text:
            est_pages = max(1, (len(full_text) // 3000) + 1)
            return [(1, full_text)], est_pages
    except Exception:
        pass

    # Engine 2: zipfile standard library extraction
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            # Target all document XML parts
            xml_targets = []
            for name in z.namelist():
                lower_name = name.lower()
                if (
                    lower_name.startswith("word/document")
                    or lower_name.startswith("word/header")
                    or lower_name.startswith("word/footer")
                    or lower_name.startswith("word/footnotes")
                    or lower_name.startswith("word/endnotes")
                ) and lower_name.endswith(".xml"):
                    xml_targets.append(name)

            paragraphs: List[str] = []
            for target in xml_targets:
                try:
                    xml_data = z.read(target)
                except Exception:
                    continue

                # Sub-strategy A: ElementTree parsing
                et_success = False
                try:
                    root = ET.fromstring(xml_data)
                    for elem in root.iter():
                        tag = elem.tag.lower()
                        if tag.endswith("p") or tag.endswith("tr"):
                            p_texts = [
                                t_node.text
                                for t_node in elem.iter()
                                if t_node.tag.lower().endswith("t") and t_node.text
                            ]
                            if p_texts:
                                p_clean = "".join(p_texts).strip()
                                if p_clean:
                                    paragraphs.append(p_clean)
                    if paragraphs:
                        et_success = True
                except Exception:
                    et_success = False

                # Sub-strategy B: Regex fallback over raw XML tags if ElementTree returned nothing
                if not et_success or not paragraphs:
                    import html
                    xml_str = xml_data.decode('utf-8', errors='ignore')
                    # Match any <*:t ...>text</*:t>
                    raw_tags = re.findall(r'<[^:>]*:?t\b[^>]*>(.*?)</[^:>]*:?t>', xml_str, re.DOTALL)
                    for raw in raw_tags:
                        clean_item = html.unescape(raw).strip()
                        if clean_item and any(c.isalnum() for c in clean_item):
                            paragraphs.append(clean_item)

            full_text = "\n\n".join(paragraphs).strip()
            if full_text:
                est_pages = max(1, (len(full_text) // 3000) + 1)
                return [(1, full_text)], est_pages
    except Exception:
        pass

    return [], 0


def _extract_text_from_doc(content: bytes) -> Tuple[List[Tuple[int, str]], int]:
    """
    Extracts readable text runs from legacy binary Word (.doc) and RTF files:
    1. RTF parser for {\\rtf...} documents
    2. UTF-16LE binary sequence scanner (standard Word OLE2 text stream)
    3. ASCII/Latin-1 printable block scanner
    """
    try:
        # Check if RTF
        if content.startswith(b'{\\rtf'):
            rtf_text = content.decode('latin-1', errors='ignore')
            clean_rtf = re.sub(r'\\[a-z0-9\-]+ ?', ' ', rtf_text)
            clean_rtf = re.sub(r'[{}]', '', clean_rtf)
            clean_rtf = re.sub(r'\s+', ' ', clean_rtf).strip()
            if len(clean_rtf) > 10:
                est_pages = max(1, (len(clean_rtf) // 3000) + 1)
                return [(1, clean_rtf)], est_pages

        # Check for UTF-16LE strings (standard in Word .doc files)
        utf16_runs = []
        for m in re.finditer(b'(?:[\x20-\x7E]\x00){4,}', content):
            try:
                decoded = m.group(0).decode('utf-16le', errors='ignore').strip()
                if len(decoded) >= 4 and any(c.isalpha() for c in decoded):
                    utf16_runs.append(decoded)
            except Exception:
                continue

        # Extract ASCII / Latin-1 printable characters
        raw_str = content.decode('latin-1', errors='ignore')
        runs = re.findall(r'[\x20-\x7E\r\n\t]{6,}', raw_str)
        meaningful = [
            r.strip() for r in runs
            if any(c.isalpha() for c in r) and not r.startswith(('Font', 'CompObj', 'WordDocument', 'SummaryInformation'))
        ]

        all_runs = utf16_runs if len(" ".join(utf16_runs)) > len(" ".join(meaningful)) else meaningful
        text = "\n".join(all_runs).strip()
        if text:
            est_pages = max(1, (len(text) // 3000) + 1)
            return [(1, text)], est_pages
    except Exception:
        pass
    return [], 0


def _extract_text_from_pdf(content: bytes, max_pages: int) -> Tuple[List[Tuple[int, str]], int]:
    """
    Extracts text per page from PDF bytes using multi-engine resilience:
    1. pypdf extraction
    2. pdfplumber extraction
    3. zlib /FlateDecode decompression of PDF content streams (Word / Google Docs exports)
    4. Hex string and literal string decoder for Word-exported PDFs
    5. Uncompressed literal string extraction
    """
    pages_text: List[Tuple[int, str]] = []

    # Engine 1: pypdf
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(content))
        total_pages = len(reader.pages)
        pages_to_read = min(total_pages, max_pages)

        for p_idx in range(pages_to_read):
            page = reader.pages[p_idx]
            text = page.extract_text() or ""
            pages_text.append((p_idx + 1, text))
        extracted_chars = sum(len(t.strip()) for _, t in pages_text)
        if extracted_chars > 0:
            return pages_text, total_pages
    except Exception:
        pass

    # Engine 2: pdfplumber (if available)
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            total_pages = len(pdf.pages)
            pages_to_read = min(total_pages, max_pages)
            plumber_pages = []
            for p_idx in range(pages_to_read):
                p_text = pdf.pages[p_idx].extract_text() or ""
                plumber_pages.append((p_idx + 1, p_text))
            extracted_chars = sum(len(t.strip()) for _, t in plumber_pages)
            if extracted_chars > 0:
                return plumber_pages, total_pages
    except Exception:
        pass

    # Engine 3: Decompress /FlateDecode zlib streams (Word exports and compressed streams)
    try:
        stream_matches = list(re.finditer(b'stream[\r\n]+(.*?)[\r\n]+endstream', content, re.DOTALL))
        decompressed_texts: List[str] = []

        for m in stream_matches:
            raw_stream = m.group(1).strip(b'\r\n')
            decomp = None
            # Try standard decompression
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 15, -15, 47):
                try:
                    decomp = zlib.decompress(raw_stream, wbits)
                    break
                except Exception:
                    continue

            # Fallback to streaming decompression object for trailing noise
            if not decomp:
                try:
                    dobj = zlib.decompressobj()
                    decomp = dobj.decompress(raw_stream)
                except Exception:
                    pass

            stream_to_search = decomp if decomp else raw_stream
            stream_str = stream_to_search.decode('latin-1', errors='ignore')

            # Extract from (text) Tj
            for match in re.finditer(r'\((.*?)\)\s*Tj', stream_str):
                s = match.group(1).replace(r'\\', '\\').replace(r'\(', '(').replace(r'\)', ')')
                if s.strip():
                    decompressed_texts.append(s)

            # Extract from <hex> Tj (Word PDF export format)
            for match in re.finditer(r'<([0-9a-fA-F\s]{4,})>\s*Tj', stream_str):
                h_text = _decode_pdf_hex(match.group(1))
                if h_text.strip():
                    decompressed_texts.append(h_text)

            # Extract from [(a) 10 (b)] TJ or [<hex> 10 <hex>] TJ
            for match in re.finditer(r'\[(.*?)\]\s*TJ', stream_str):
                array_content = match.group(1)
                sub_strings = re.findall(r'\((.*?)\)', array_content)
                combined = "".join(sub_strings).replace(r'\\', '\\').replace(r'\(', '(').replace(r'\)', ')')
                if combined.strip():
                    decompressed_texts.append(combined)
                # Hex segments inside TJ
                for h_match in re.findall(r'<([0-9a-fA-F\s]{4,})>', array_content):
                    h_text = _decode_pdf_hex(h_match)
                    if h_text.strip():
                        decompressed_texts.append(h_text)

            # Extract from BT ... ET blocks
            for match in re.finditer(r'BT\s*(.*?)\s*ET', stream_str, re.DOTALL):
                bt_content = match.group(1)
                raw_strings = re.findall(r'\((.*?)\)', bt_content)
                for s in raw_strings:
                    s_clean = s.replace(r'\\', '\\').replace(r'\(', '(').replace(r'\)', ')')
                    if s_clean.strip() and s_clean not in decompressed_texts:
                        decompressed_texts.append(s_clean)
                for h in re.findall(r'<([0-9a-fA-F\s]{4,})>', bt_content):
                    h_text = _decode_pdf_hex(h)
                    if h_text.strip() and h_text not in decompressed_texts:
                        decompressed_texts.append(h_text)

        extracted = "\n".join(decompressed_texts).strip()
        if extracted:
            return [(1, extracted)], 1
    except Exception:
        pass

    # Engine 4: Raw text literal scanner across entire file
    try:
        content_str = content.decode('latin-1', errors='ignore')
        literals = []
        for match in re.finditer(r'\(([^()]{3,})\)', content_str):
            txt = match.group(1).strip()
            if any(c.isalpha() for c in txt) and not txt.startswith(('/Font', '/Type', '/Subtype', '/Filter')):
                literals.append(txt)
        if len(literals) >= 2:
            extracted = "\n".join(literals)
            return [(1, extracted)], 1
    except Exception:
        pass

    return [], 0


def validate_and_extract_document(
    filename: str, content: bytes
) -> Tuple[DocumentMetadata, List[Tuple[int, str]]]:
    """
    Validates document header, size, pages, and extracts page-wise text.
    Supports PDF (standard, hidden text, and compressed), Word (.docx, .doc, .docm),
    RTF, and plain text (.txt, .md) documents.
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

    # 2. Document Format Routing & Text Extraction
    pages_data: List[Tuple[int, str]] = []
    total_pages = 1
    limitation = None
    file_type = "txt"

    # PDF Format
    if content.startswith(b'%PDF-') or lower_name.endswith('.pdf'):
        file_type = "pdf"
        pages_data, total_pages = _extract_text_from_pdf(content, settings.max_pdf_pages)
        if total_pages > settings.max_pdf_pages:
            limitation = f"Document truncated to first {settings.max_pdf_pages} of {total_pages} pages."

        total_extracted_chars = sum(len(text.strip()) for _, text in pages_data)
        if total_extracted_chars == 0:
            raise ValueError(
                "Image-only PDF detected. OCR is not available. Please provide a text-based PDF, Word (.docx), or TXT file."
            )

    # Word .docx Format (Zip archive with word/document.xml)
    elif content.startswith(b'PK\x03\x04') or lower_name.endswith(('.docx', '.docm', '.dotx')):
        file_type = "docx"
        pages_data, total_pages = _extract_text_from_docx(content)
        total_extracted_chars = sum(len(text.strip()) for _, text in pages_data)
        if total_extracted_chars == 0:
            # Fallback to doc binary extractor if zip was modified or corrupt
            pages_data, total_pages = _extract_text_from_doc(content)
            total_extracted_chars = sum(len(text.strip()) for _, text in pages_data)
        if total_extracted_chars == 0:
            raise ValueError("Empty or unreadable Word document (.docx).")

    # Word .doc Format (Legacy binary) or RTF
    elif content.startswith((b'\xd0\xcf\x11\xe0', b'{\\rtf')) or lower_name.endswith(('.doc', '.rtf')):
        file_type = "doc"
        pages_data, total_pages = _extract_text_from_doc(content)
        total_extracted_chars = sum(len(text.strip()) for _, text in pages_data)
        if total_extracted_chars == 0:
            raise ValueError("Empty or unreadable Word document (.doc).")

    # Plain text / Markdown format
    else:
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                text = content.decode('latin-1')
            except Exception:
                raise ValueError("Unsupported media type: only text-based PDF, Word (.docx), and TXT files are accepted.")

        file_type = "txt"
        total_pages = 1
        pages_data = [(1, text)]
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
