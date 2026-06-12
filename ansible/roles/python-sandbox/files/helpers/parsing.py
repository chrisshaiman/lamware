"""Binary parsing helpers for malware analysis."""

import struct


def read_dword_le(data: bytes, offset: int) -> int:
    """Read a 32-bit little-endian unsigned integer."""
    return struct.unpack_from("<I", data, offset)[0]


def read_dword_be(data: bytes, offset: int) -> int:
    """Read a 32-bit big-endian unsigned integer."""
    return struct.unpack_from(">I", data, offset)[0]


def read_qword_le(data: bytes, offset: int) -> int:
    """Read a 64-bit little-endian unsigned integer."""
    return struct.unpack_from("<Q", data, offset)[0]


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract ASCII and UTF-16LE strings from binary data."""
    strings = []

    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))

    try:
        decoded = data.decode("utf-16-le", errors="ignore")
        current = []
        for ch in decoded:
            if 32 <= ord(ch) < 127:
                current.append(ch)
            else:
                if len(current) >= min_length:
                    s = "".join(current)
                    if s not in strings:
                        strings.append(s)
                current = []
        if len(current) >= min_length:
            s = "".join(current)
            if s not in strings:
                strings.append(s)
    except Exception:
        pass

    return strings


def pe_overlay_offset(data: bytes) -> int | None:
    """Find the file offset where PE overlay data begins (after all sections). None if no overlay or not a PE."""
    if data[:2] != b"MZ":
        return None
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from("<H", data, pe_offset + 0x14)[0]
        section_table = pe_offset + 0x18 + opt_header_size
        max_end = 0
        for i in range(num_sections):
            offset = section_table + i * 40
            raw_size = struct.unpack_from("<I", data, offset + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, offset + 20)[0]
            section_end = raw_ptr + raw_size
            if section_end > max_end:
                max_end = section_end
        if 0 < max_end < len(data):
            return max_end
    except (struct.error, IndexError):
        pass
    return None


def struct_unpack_at(fmt: str, data: bytes, offset: int) -> tuple:
    """Unpack a struct format at a given offset."""
    return struct.unpack_from(fmt, data, offset)
