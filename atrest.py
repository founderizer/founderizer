"""Encryption at rest of the hub's own files (UI-API.md, "The file on the hub machine" of Google, version 1.202).

The cipher is AEAD_CHACHA20_POLY1305 as RFC 8439 defines it, written here with the Python standard library alone:
the standard library has no cipher, and the hub has no dependency outside it. test_atrest.py holds this code to the
RFC's own test vectors, and, where the `cryptography` package is installed, to that package's implementation of the
same cipher.

A text is sealed with a key of 32 random bytes and a nonce of 12 random bytes, which each sealing draws again. The
caller's file is written seldom (a Connect, a Disconnect, a new secret of Founderizer's Google app), so random nonces
stay far below the limit of RFC 8439 section 4 for one key. The tag is checked before any byte is decrypted, and with
a comparison in constant time.

Python's integers are not constant time, so this code does not hide its timing from a process on the same machine.
Such a process can read the file and the key anyway, when it runs as the hub's user, and cannot read either when it
does not.
"""
import hashlib
import hmac
import secrets
import struct

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_TEXT = 64 * 1024 * 1024     # bytes: far more than a file of the hub needs, far less than the cipher's limit
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)    # "expand 32-byte k"
_M = 0xFFFFFFFF
_P = (1 << 130) - 5
_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


class Unopened(ValueError):
    """A sealed text that this key and these associated bytes do not open: another key, or bytes that changed."""


def _block(key_words, counter, nonce_words):
    """ChaCha20's block function (RFC 8439, 2.3): 64 bytes of key stream."""
    state = [*_SIGMA, *key_words, counter, *nonce_words]
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = state
    for _ in range(10):
        # the column rounds (2.2): quarter rounds on (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)
        x0 = (x0 + x4) & _M; x12 ^= x0; x12 = ((x12 << 16) & _M) | (x12 >> 16)
        x8 = (x8 + x12) & _M; x4 ^= x8; x4 = ((x4 << 12) & _M) | (x4 >> 20)
        x0 = (x0 + x4) & _M; x12 ^= x0; x12 = ((x12 << 8) & _M) | (x12 >> 24)
        x8 = (x8 + x12) & _M; x4 ^= x8; x4 = ((x4 << 7) & _M) | (x4 >> 25)
        x1 = (x1 + x5) & _M; x13 ^= x1; x13 = ((x13 << 16) & _M) | (x13 >> 16)
        x9 = (x9 + x13) & _M; x5 ^= x9; x5 = ((x5 << 12) & _M) | (x5 >> 20)
        x1 = (x1 + x5) & _M; x13 ^= x1; x13 = ((x13 << 8) & _M) | (x13 >> 24)
        x9 = (x9 + x13) & _M; x5 ^= x9; x5 = ((x5 << 7) & _M) | (x5 >> 25)
        x2 = (x2 + x6) & _M; x14 ^= x2; x14 = ((x14 << 16) & _M) | (x14 >> 16)
        x10 = (x10 + x14) & _M; x6 ^= x10; x6 = ((x6 << 12) & _M) | (x6 >> 20)
        x2 = (x2 + x6) & _M; x14 ^= x2; x14 = ((x14 << 8) & _M) | (x14 >> 24)
        x10 = (x10 + x14) & _M; x6 ^= x10; x6 = ((x6 << 7) & _M) | (x6 >> 25)
        x3 = (x3 + x7) & _M; x15 ^= x3; x15 = ((x15 << 16) & _M) | (x15 >> 16)
        x11 = (x11 + x15) & _M; x7 ^= x11; x7 = ((x7 << 12) & _M) | (x7 >> 20)
        x3 = (x3 + x7) & _M; x15 ^= x3; x15 = ((x15 << 8) & _M) | (x15 >> 24)
        x11 = (x11 + x15) & _M; x7 ^= x11; x7 = ((x7 << 7) & _M) | (x7 >> 25)
        # the diagonal rounds: (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)
        x0 = (x0 + x5) & _M; x15 ^= x0; x15 = ((x15 << 16) & _M) | (x15 >> 16)
        x10 = (x10 + x15) & _M; x5 ^= x10; x5 = ((x5 << 12) & _M) | (x5 >> 20)
        x0 = (x0 + x5) & _M; x15 ^= x0; x15 = ((x15 << 8) & _M) | (x15 >> 24)
        x10 = (x10 + x15) & _M; x5 ^= x10; x5 = ((x5 << 7) & _M) | (x5 >> 25)
        x1 = (x1 + x6) & _M; x12 ^= x1; x12 = ((x12 << 16) & _M) | (x12 >> 16)
        x11 = (x11 + x12) & _M; x6 ^= x11; x6 = ((x6 << 12) & _M) | (x6 >> 20)
        x1 = (x1 + x6) & _M; x12 ^= x1; x12 = ((x12 << 8) & _M) | (x12 >> 24)
        x11 = (x11 + x12) & _M; x6 ^= x11; x6 = ((x6 << 7) & _M) | (x6 >> 25)
        x2 = (x2 + x7) & _M; x13 ^= x2; x13 = ((x13 << 16) & _M) | (x13 >> 16)
        x8 = (x8 + x13) & _M; x7 ^= x8; x7 = ((x7 << 12) & _M) | (x7 >> 20)
        x2 = (x2 + x7) & _M; x13 ^= x2; x13 = ((x13 << 8) & _M) | (x13 >> 24)
        x8 = (x8 + x13) & _M; x7 ^= x8; x7 = ((x7 << 7) & _M) | (x7 >> 25)
        x3 = (x3 + x4) & _M; x14 ^= x3; x14 = ((x14 << 16) & _M) | (x14 >> 16)
        x9 = (x9 + x14) & _M; x4 ^= x9; x4 = ((x4 << 12) & _M) | (x4 >> 20)
        x3 = (x3 + x4) & _M; x14 ^= x3; x14 = ((x14 << 8) & _M) | (x14 >> 24)
        x9 = (x9 + x14) & _M; x4 ^= x9; x4 = ((x4 << 7) & _M) | (x4 >> 25)
    mixed = (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)
    return struct.pack("<16I", *((a + b) & _M for a, b in zip(mixed, state)))


def _words(key, nonce):
    if not (isinstance(key, (bytes, bytearray)) and len(key) == KEY_BYTES):
        raise ValueError(f"a key has {KEY_BYTES} bytes")
    if not (isinstance(nonce, (bytes, bytearray)) and len(nonce) == NONCE_BYTES):
        raise ValueError(f"a nonce has {NONCE_BYTES} bytes")
    return struct.unpack("<8I", key), struct.unpack("<3I", nonce)


def chacha20(key, counter, nonce, data):
    """ChaCha20 (RFC 8439, 2.4): `data` with the key stream from block `counter` on, XORed; the same call decrypts."""
    key_words, nonce_words = _words(key, nonce)
    if len(data) > MAX_TEXT:
        raise ValueError(f"at most {MAX_TEXT} bytes")
    out = bytearray()
    for start in range(0, len(data), 64):
        chunk = data[start:start + 64]
        stream = _block(key_words, (counter + start // 64) & _M, nonce_words)[:len(chunk)]
        out += (int.from_bytes(chunk, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(chunk), "little")
    return bytes(out)


def poly1305(key, message):
    """Poly1305 (RFC 8439, 2.5): the 16-byte tag of `message` under a one-time key of 32 bytes."""
    if len(key) != 32:
        raise ValueError("a Poly1305 key has 32 bytes")
    r = int.from_bytes(key[:16], "little") & _CLAMP
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for start in range(0, len(message), 16):
        acc = (acc + int.from_bytes(message[start:start + 16] + b"\x01", "little")) * r % _P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(n):
    return b"\x00" * (-n % 16)


def _tag(key, nonce, aad, ciphertext):
    """The AEAD's tag (RFC 8439, 2.8): Poly1305 under the one-time key of block 0 (2.6), over the associated bytes,
    the ciphertext, each padded to 16 bytes, and their two lengths."""
    key_words, nonce_words = _words(key, nonce)
    one_time = _block(key_words, 0, nonce_words)[:32]
    return poly1305(one_time, aad + _pad16(len(aad)) + ciphertext + _pad16(len(ciphertext)) +
                    struct.pack("<QQ", len(aad), len(ciphertext)))


def encrypt(key, plain, aad=b"", nonce=None):
    """AEAD_CHACHA20_POLY1305 (RFC 8439, 2.8): nonce, ciphertext and tag in one bytes object. The nonce is 12 random
    bytes unless a test gives one."""
    nonce = secrets.token_bytes(NONCE_BYTES) if nonce is None else bytes(nonce)
    ciphertext = chacha20(key, 1, nonce, bytes(plain))
    return nonce + ciphertext + _tag(key, nonce, bytes(aad), ciphertext)


def decrypt(key, sealed, aad=b""):
    """The plain bytes of `encrypt`'s output, or Unopened when the tag does not match: the text, the nonce or the
    associated bytes changed, or the key is another one. Nothing is decrypted before the tag is checked."""
    sealed = bytes(sealed)
    if len(sealed) < NONCE_BYTES + TAG_BYTES:
        raise Unopened("the sealed text is too short")
    nonce, ciphertext, tag = sealed[:NONCE_BYTES], sealed[NONCE_BYTES:-TAG_BYTES], sealed[-TAG_BYTES:]
    if not hmac.compare_digest(_tag(key, nonce, bytes(aad), ciphertext), tag):
        raise Unopened("this key does not open the sealed text, or the text changed")
    return chacha20(key, 1, nonce, ciphertext)


def new_key():
    """A new key: 32 random bytes from the system's source."""
    return secrets.token_bytes(KEY_BYTES)


def key_id(key):
    """A short name of a key, for a file that says which key sealed it: 16 hex characters of a SHA-256 that is used
    for nothing else. It tells two keys apart, and it opens nothing."""
    return hashlib.sha256(b"founderizer key id\x00" + bytes(key)).hexdigest()[:16]
