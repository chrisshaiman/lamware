"""Encoding/decoding helpers for malware analysis."""

import base64
import codecs


def b64_decode(data: str) -> bytes:
    """Standard base64 decode with padding fix."""
    data = data.strip()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def b64_variants(data: str) -> dict[str, bytes]:
    """Try standard, URL-safe base64 variants. Returns dict of variant name -> decoded bytes."""
    results = {}
    data = data.strip()
    padded = data + "=" * (4 - len(data) % 4) if len(data) % 4 else data

    try:
        results["standard"] = base64.b64decode(padded)
    except Exception:
        pass
    try:
        results["urlsafe"] = base64.urlsafe_b64decode(padded)
    except Exception:
        pass
    return results


def hex_to_bytes(data: str) -> bytes:
    """Convert hex string to bytes, stripping 0x prefix and whitespace."""
    data = data.strip().replace(" ", "").replace("\n", "")
    if data.startswith(("0x", "0X")):
        data = data[2:]
    return bytes.fromhex(data)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def rot13(data: str) -> str:
    """ROT13 decode/encode."""
    return codecs.decode(data, "rot_13")
