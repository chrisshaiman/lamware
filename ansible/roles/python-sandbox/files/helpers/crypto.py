"""Cryptographic helpers for malware payload decryption."""


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR decrypt data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """RC4 (ARC4) decrypt/encrypt — symmetric, same function for both."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


rc4_encrypt = rc4_decrypt  # RC4 is symmetric


def single_byte_xor_scan(data: bytes, known_plaintext: bytes) -> list[tuple[int, bytes]]:
    """Try all 256 single-byte XOR keys, return (key, full_decryption) for those producing known_plaintext."""
    results = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in data)
        if known_plaintext in decrypted:
            results.append((key, decrypted))
    return results
