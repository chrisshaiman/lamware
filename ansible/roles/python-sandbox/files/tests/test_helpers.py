"""Tests for sandbox helper library — run locally with pytest, not in the container."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "helpers"))

from crypto import xor_decrypt, rc4_decrypt, single_byte_xor_scan
from encoding import b64_decode, b64_variants, hex_to_bytes, bytes_to_hex, rot13
from parsing import read_dword_le, read_dword_be, read_qword_le, extract_strings, pe_overlay_offset, struct_unpack_at


def test_xor_decrypt_single_byte():
    key = b"\x41"
    data = bytes(b ^ 0x41 for b in b"hello")
    assert xor_decrypt(data, key) == b"hello"


def test_xor_decrypt_multi_byte_key():
    key = b"\xaa\xbb\xcc"
    plaintext = b"the quick brown fox"
    encrypted = bytes(b ^ key[i % 3] for i, b in enumerate(plaintext))
    assert xor_decrypt(encrypted, key) == plaintext


def test_rc4_roundtrip():
    key = b"secret"
    plaintext = b"hello world"
    encrypted = rc4_decrypt(plaintext, key)
    assert encrypted != plaintext
    assert rc4_decrypt(encrypted, key) == plaintext


def test_single_byte_xor_scan_finds_key():
    plaintext = b"http://evil.example.com/gate.php"
    key = 0x55
    encrypted = bytes(b ^ key for b in plaintext)
    results = single_byte_xor_scan(encrypted, b"http://")
    assert any(k == key for k, _ in results)
    found = [d for k, d in results if k == key][0]
    assert found == plaintext


def test_b64_decode_with_and_without_padding():
    assert b64_decode("aGVsbG8=") == b"hello"
    assert b64_decode("aGVsbG8") == b"hello"


def test_b64_variants():
    variants = b64_variants("aGVsbG8=")
    assert variants["standard"] == b"hello"


def test_hex_to_bytes():
    assert hex_to_bytes("48656c6c6f") == b"Hello"
    assert hex_to_bytes("0x4141") == b"AA"
    assert hex_to_bytes("48 65 6c") == b"Hel"


def test_bytes_to_hex_roundtrip():
    assert hex_to_bytes(bytes_to_hex(b"\x00\xff\x41")) == b"\x00\xff\x41"


def test_rot13():
    assert rot13("Uryyb") == "Hello"


def test_read_dword_le():
    assert read_dword_le(b"\x01\x00\x00\x00", 0) == 1
    assert read_dword_le(b"\xff\xff\x78\x56\x34\x12", 2) == 0x12345678


def test_read_dword_be():
    assert read_dword_be(b"\x12\x34\x56\x78", 0) == 0x12345678


def test_read_qword_le():
    assert read_qword_le(b"\x01\x00\x00\x00\x00\x00\x00\x00", 0) == 1


def test_extract_strings_ascii():
    data = b"\x00\x00http://evil.com\x00\x00ab\x00test\x00"
    strings = extract_strings(data, min_length=4)
    assert "http://evil.com" in strings
    assert "test" in strings
    assert "ab" not in strings


def test_extract_strings_utf16():
    data = "C2SERVER".encode("utf-16-le")
    strings = extract_strings(data, min_length=4)
    assert "C2SERVER" in strings


def test_pe_overlay_offset_not_pe():
    assert pe_overlay_offset(b"\x7fELF" + b"\x00" * 100) is None


def test_struct_unpack_at():
    assert struct_unpack_at("<HH", b"\x01\x00\x02\x00", 0) == (1, 2)


def test_xor_decrypt_empty_key_raises():
    with pytest.raises(ValueError):
        xor_decrypt(b"data", b"")


def test_rc4_decrypt_empty_key_raises():
    with pytest.raises(ValueError):
        rc4_decrypt(b"data", b"")


def test_xor_decrypt_empty_data():
    assert xor_decrypt(b"", b"\x41") == b""
