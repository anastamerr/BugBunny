from __future__ import annotations

import logging
from typing import Optional

from supabase import create_client, Client

from ..config import get_settings

logger = logging.getLogger(__name__)

BUCKET_NAME = "pdf_reports"


def _get_supabase_client() -> Optional[Client]:
    """Get Supabase client if configured."""
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        logger.warning("Supabase storage not configured (missing URL or service key)")
        return None
    return create_client(settings.supabase_url, settings.supabase_service_key)


def upload_pdf(
    scan_id: str,
    pdf_bytes: bytes,
    *,
    upsert: bool = False,
) -> Optional[str]:
    """Upload PDF to Supabase storage and return public URL."""
    client = _get_supabase_client()
    if not client:
        return None

    file_path = f"{scan_id}.pdf"
    try:
        # Upload with upsert to overwrite if exists
        client.storage.from_(BUCKET_NAME).upload(
            file_path,
            pdf_bytes,
            file_options={
                "content-type": "application/pdf",
                "upsert": "true" if upsert else "false",
            },
        )
        # Get public URL
        public_url = client.storage.from_(BUCKET_NAME).get_public_url(file_path)
        logger.info(f"Uploaded PDF report for scan {scan_id}")
        return public_url
    except Exception as e:
        if not upsert:
            existing = get_pdf_url(scan_id)
            if existing:
                return existing
        logger.error(f"Failed to upload PDF for scan {scan_id}: {e}")
        return None


def get_pdf_url(scan_id: str) -> Optional[str]:
    """Get public URL for existing PDF if it exists."""
    client = _get_supabase_client()
    if not client:
        return None

    file_path = f"{scan_id}.pdf"
    try:
        # Check if file exists by listing
        files = client.storage.from_(BUCKET_NAME).list()
        if any(f.get("name") == file_path for f in files):
            return client.storage.from_(BUCKET_NAME).get_public_url(file_path)
        return None
    except Exception as e:
        logger.error(f"Failed to check PDF for scan {scan_id}: {e}")
        return None


def download_pdf(scan_id: str) -> Optional[bytes]:
    """Download PDF bytes from Supabase storage."""
    client = _get_supabase_client()
    if not client:
        return None

    file_path = f"{scan_id}.pdf"
    try:
        data = client.storage.from_(BUCKET_NAME).download(file_path)
    except Exception as e:
        logger.error(f"Failed to download PDF for scan {scan_id}: {e}")
        return None

    if isinstance(data, bytes):
        return data
    if hasattr(data, "read"):
        try:
            return data.read()
        except Exception:
            return None
    return None


def delete_pdf(scan_id: str) -> bool:
    """Delete PDF from storage."""
    client = _get_supabase_client()
    if not client:
        return False

    file_path = f"{scan_id}.pdf"
    try:
        client.storage.from_(BUCKET_NAME).remove([file_path])
        logger.info(f"Deleted PDF report for scan {scan_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete PDF for scan {scan_id}: {e}")
        return False
