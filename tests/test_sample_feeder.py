"""Unit tests for sample_feeder parsing and validation logic."""
import pytest


def parse_sample_entry(entry: dict) -> dict:
    """Extract fields we need from a MalwareBazaar API response entry."""
    sha256 = entry.get("sha256_hash", "")
    if not sha256 or len(sha256) != 64:
        raise ValueError(f"Invalid sha256: {sha256!r}")

    return {
        "sha256": sha256.lower(),
        "filename": entry.get("file_name", "unknown"),
        "file_type": entry.get("file_type", "unknown"),
        "file_size": entry.get("file_size", 0),
        "signature": entry.get("signature") or "unknown",
        "tags": [t for t in (entry.get("tags") or []) if isinstance(t, str)],
    }


def should_skip(entry: dict, seen_hashes: set, max_size_bytes: int) -> str | None:
    """Return a reason string if this sample should be skipped, else None."""
    sha256 = entry.get("sha256_hash", "").lower()
    if sha256 in seen_hashes:
        return "already_submitted"
    file_size = entry.get("file_size", 0)
    if file_size > max_size_bytes:
        return f"too_large ({file_size} > {max_size_bytes})"
    return None


def format_preview_line(parsed: dict) -> str:
    """Format a single sample entry for the preview table."""
    tags = ",".join(parsed["tags"][:3]) or "-"
    size_kb = parsed["file_size"] / 1024
    return (
        f"  {parsed['sha256'][:16]}...  "
        f"{parsed['filename']:<30s}  "
        f"{parsed['signature']:<20s}  "
        f"{size_kb:>8.1f} KB  "
        f"{tags}"
    )


class TestParseSampleEntry:
    def test_valid_entry(self):
        entry = {
            "sha256_hash": "a" * 64,
            "file_name": "evil.exe",
            "file_type": "exe",
            "file_size": 45056,
            "signature": "AgentTesla",
            "tags": ["stealer", "exe"],
        }
        result = parse_sample_entry(entry)
        assert result["sha256"] == "a" * 64
        assert result["filename"] == "evil.exe"
        assert result["file_size"] == 45056
        assert result["signature"] == "AgentTesla"
        assert result["tags"] == ["stealer", "exe"]

    def test_missing_sha256_raises(self):
        with pytest.raises(ValueError, match="Invalid sha256"):
            parse_sample_entry({"file_name": "test.exe"})

    def test_short_sha256_raises(self):
        with pytest.raises(ValueError, match="Invalid sha256"):
            parse_sample_entry({"sha256_hash": "abc123"})

    def test_null_signature_becomes_unknown(self):
        entry = {"sha256_hash": "b" * 64, "signature": None}
        result = parse_sample_entry(entry)
        assert result["signature"] == "unknown"

    def test_null_tags_becomes_empty_list(self):
        entry = {"sha256_hash": "c" * 64, "tags": None}
        result = parse_sample_entry(entry)
        assert result["tags"] == []


class TestShouldSkip:
    def test_already_seen(self):
        entry = {"sha256_hash": "a" * 64, "file_size": 100}
        assert should_skip(entry, {"a" * 64}, 1000000) == "already_submitted"

    def test_too_large(self):
        entry = {"sha256_hash": "b" * 64, "file_size": 500_000_000}
        assert "too_large" in should_skip(entry, set(), 256_000_000)

    def test_acceptable(self):
        entry = {"sha256_hash": "d" * 64, "file_size": 1024}
        assert should_skip(entry, set(), 256_000_000) is None


class TestFormatPreviewLine:
    def test_basic_format(self):
        parsed = {
            "sha256": "a" * 64,
            "filename": "evil.exe",
            "file_size": 45056,
            "signature": "AgentTesla",
            "tags": ["stealer"],
        }
        line = format_preview_line(parsed)
        assert "aaaaaaaaaaaaaaaa..." in line
        assert "evil.exe" in line
        assert "AgentTesla" in line
        assert "44.0 KB" in line
        assert "stealer" in line

    def test_no_tags_shows_dash(self):
        parsed = {
            "sha256": "b" * 64,
            "filename": "test.dll",
            "file_size": 1024,
            "signature": "unknown",
            "tags": [],
        }
        line = format_preview_line(parsed)
        assert "  -" in line
