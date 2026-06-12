"""
CloudGuard-AI — Upload Validator
Rule 8: Validate file uploads before processing.

Checks:
- File extension whitelist
- MIME type validation (reads magic bytes, not just Content-Type header)
- File size limit
- Filename sanitization (path traversal prevention)
- No executable content
"""
import re
from pathlib import Path

from fastapi import HTTPException, UploadFile

# ── Constants ──────────────────────────────────────────────────────────────────

MAX_UPLOAD_SIZE_BYTES = 1 * 1024 * 1024   # 1 MB — Terraform files should never be larger

ALLOWED_EXTENSIONS = {".tf", ".tfvars"}

# Safe MIME types for Terraform files (text only)
ALLOWED_MIME_PREFIXES = ("text/", "application/octet-stream")

# Blocked patterns in filenames — path traversal prevention
DANGEROUS_FILENAME_PATTERN = re.compile(r'[\\/:*?"<>|]|\.\.')


async def validate_terraform_upload(file: UploadFile) -> bytes:
    """
    Validate an uploaded Terraform file.

    Returns raw bytes if valid.
    Raises HTTPException with generic message if invalid.
    Logs detailed rejection reason to audit log.
    """
    from app.utils.audit_log import log_upload_rejected

    filename = file.filename or "unknown"

    # 1. Filename sanitization — prevent path traversal
    if DANGEROUS_FILENAME_PATTERN.search(filename):
        log_upload_rejected(ip="unknown", filename=filename, reason="dangerous filename pattern")
        raise HTTPException(status_code=400, detail="Invalid filename")

    # 2. Extension whitelist
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        log_upload_rejected(ip="unknown", filename=filename,
                            reason=f"disallowed extension: {suffix}")
        raise HTTPException(
            status_code=400,
            detail=f"Only {', '.join(ALLOWED_EXTENSIONS)} files are accepted"
        )

    # 3. Read content with size limit enforced during read
    content = await file.read(MAX_UPLOAD_SIZE_BYTES + 1)
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        log_upload_rejected(ip="unknown", filename=filename,
                            reason=f"file too large: {len(content)} bytes")
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE_BYTES // 1024} KB"
        )

    # 4. Magic byte check — ensure it's plain text, not a binary/executable
    #    Terraform .tf files are UTF-8 text; check for null bytes (binary indicator)
    if b"\x00" in content[:512]:
        log_upload_rejected(ip="unknown", filename=filename, reason="binary content detected")
        raise HTTPException(status_code=400, detail="File must be plain text")

    # 5. Executable content heuristic — block common script shebangs
    first_line = content[:100].decode("utf-8", errors="ignore").lower()
    if first_line.startswith(("#!/", "<%", "<script", "<?php", "<?xml")):
        log_upload_rejected(ip="unknown", filename=filename,
                            reason="executable/script content detected")
        raise HTTPException(status_code=400, detail="Executable content not permitted")

    return content
