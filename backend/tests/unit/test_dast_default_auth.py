"""Unit tests for DAST default auth header parsing."""

from __future__ import annotations

from src.services.scanner.dast_runner import _parse_default_auth_header


def test_parse_default_auth_header_valid():
    """Test parsing valid auth header."""
    result = _parse_default_auth_header("Authorization: Bearer token123")
    assert result == {"Authorization": "Bearer token123"}


def test_parse_default_auth_header_with_spaces():
    """Test parsing with extra spaces."""
    result = _parse_default_auth_header("  Authorization:   Bearer token123  ")
    assert result == {"Authorization": "Bearer token123"}


def test_parse_default_auth_header_custom_header():
    """Test parsing custom header."""
    result = _parse_default_auth_header("X-API-Key: secret-key-123")
    assert result == {"X-API-Key": "secret-key-123"}


def test_parse_default_auth_header_value_with_colon():
    """Test parsing when value contains colons."""
    # JWT tokens often have colons
    result = _parse_default_auth_header("Authorization: Bearer eyJhbGc:iOiJIUzI1NiIs:InR5cCI6IkpXVCJ9")
    assert result == {"Authorization": "Bearer eyJhbGc:iOiJIUzI1NiIs:InR5cCI6IkpXVCJ9"}


def test_parse_default_auth_header_empty():
    """Test parsing empty string."""
    result = _parse_default_auth_header("")
    assert result is None


def test_parse_default_auth_header_none():
    """Test parsing None."""
    result = _parse_default_auth_header(None)
    assert result is None


def test_parse_default_auth_header_no_colon():
    """Test parsing invalid format without colon."""
    result = _parse_default_auth_header("InvalidHeader")
    assert result is None


def test_parse_default_auth_header_empty_name():
    """Test parsing with empty header name."""
    result = _parse_default_auth_header(": value")
    assert result is None


def test_parse_default_auth_header_empty_value():
    """Test parsing with empty value (should still work)."""
    result = _parse_default_auth_header("X-Custom-Header:")
    assert result == {"X-Custom-Header": ""}


def test_parse_default_auth_header_whitespace_only():
    """Test parsing whitespace-only string."""
    result = _parse_default_auth_header("   ")
    assert result is None
