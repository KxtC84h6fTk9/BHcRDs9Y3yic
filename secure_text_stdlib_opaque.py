#!/usr/bin/env python3
"""
secure_text_stdlib.py

Small text encryption helper using only Python's standard library. Implements
ChaCha20-Poly1305 directly in pure Python. Default output is an opaque
Google-Docs-safe data block with no JSON metadata.

Examples:
  python secure_text_stdlib.py selftest
  python secure_text_stdlib.py benchmark
  python secure_text_stdlib.py encrypt input.txt output.txt
  python secure_text_stdlib.py encrypt input.txt output.txt --label "IMAGE DATA"
  python secure_text_stdlib.py encrypt input.txt output.txt --no-wrapper
  python secure_text_stdlib.py decrypt output.txt roundtrip.txt

In Chat, use:
  encrypted = encrypt_text(plaintext, passphrase)
  plaintext = decrypt_text(encrypted, passphrase)
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import struct
import time

VERSION = 2
DEFAULT_ITERATIONS = 600_000
SALT_BYTES = 32
NONCE_BYTES = 12
KEY_BYTES = 32
HEADER_BYTES = 1 + 4 + SALT_BYTES + NONCE_BYTES
ENCODING = "utf-8"
DEFAULT_LABEL = "DATA BLOCK"


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(text: str) -> bytes:
    clean = "".join(text.split())
    return base64.urlsafe_b64decode(clean + "=" * (-len(clean) % 4))


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("passphrase must be a non-empty string")
    if iterations < 100_000:
        raise ValueError("iterations must be at least 100,000")
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(ENCODING), salt, iterations, dklen=KEY_BYTES
    )


def _rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += [counter & 0xFFFFFFFF]
    state += list(struct.unpack("<3I", nonce))
    working = state.copy()
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack("<16I", *((working[i] + state[i]) & 0xFFFFFFFF for i in range(16)))


def _chacha20_xor(data: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    out = bytearray()
    counter = initial_counter
    for offset in range(0, len(data), 64):
        block = data[offset:offset + 64]
        stream = _chacha20_block(key, counter, nonce)
        out.extend(b ^ s for b, s in zip(block, stream))
        counter = (counter + 1) & 0xFFFFFFFF
        if counter == 0:
            raise ValueError("ChaCha20 counter exhausted")
    return bytes(out)


def _poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    r = int.from_bytes(one_time_key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for offset in range(0, len(message), 16):
        acc = ((acc + int.from_bytes(message[offset:offset + 16] + b"\x01", "little")) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"" if len(data) % 16 == 0 else b"\x00" * (16 - len(data) % 16)


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return aad + _pad16(aad) + ciphertext + _pad16(ciphertext) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))


def _seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    otk = _chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_xor(plaintext, key, nonce)
    return ciphertext + _poly1305_mac(_mac_data(aad, ciphertext), otk)


def _open(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    if len(data) < 16:
        raise ValueError("ciphertext is too short")
    ciphertext, tag = data[:-16], data[-16:]
    expected = _poly1305_mac(_mac_data(aad, ciphertext), _chacha20_block(key, 0, nonce)[:32])
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")
    return _chacha20_xor(ciphertext, key, nonce)


def _wrap(payload: bytes, *, label: str = DEFAULT_LABEL, wrapper: bool = True) -> str:
    blob = _b64u_encode(payload)
    if not wrapper:
        return blob + "\n"
    label = " ".join(label.strip().upper().split()) or DEFAULT_LABEL
    return f"-----BEGIN {label}-----\n{blob}\n-----END {label}-----\n"


def _extract_payload(text: str) -> bytes:
    stripped = text.strip()
    if stripped.startswith("-----BEGIN "):
        lines = stripped.splitlines()
        if len(lines) < 3 or not lines[-1].startswith("-----END "):
            raise ValueError("bad wrapped data block")
        stripped = "".join(lines[1:-1])
    return _b64u_decode(stripped)


def encrypt_text(
    plaintext: str,
    passphrase: str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    label: str = DEFAULT_LABEL,
    wrapper: bool = True,
) -> str:
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    header = bytes([VERSION]) + iterations.to_bytes(4, "big") + salt + nonce
    key = _derive_key(passphrase, salt, iterations)
    ciphertext = _seal(key, nonce, plaintext.encode(ENCODING), header)
    return _wrap(header + ciphertext, label=label, wrapper=wrapper)


def decrypt_text(data_text: str, passphrase: str) -> str:
    payload = _extract_payload(data_text)
    if len(payload) <= HEADER_BYTES or payload[0] != VERSION:
        raise ValueError("unsupported or corrupted data block")
    header = payload[:HEADER_BYTES]
    iterations = int.from_bytes(payload[1:5], "big")
    salt = payload[5:5 + SALT_BYTES]
    nonce = payload[5 + SALT_BYTES:HEADER_BYTES]
    key = _derive_key(passphrase, salt, iterations)
    return _open(key, nonce, payload[HEADER_BYTES:], header).decode(ENCODING)


def reencrypt_text(data_text: str, old_passphrase: str, new_passphrase: str, *, iterations: int = DEFAULT_ITERATIONS) -> str:
    return encrypt_text(decrypt_text(data_text, old_passphrase), new_passphrase, iterations=iterations)


def _read_text(path: str) -> str:
    with open(path, "r", encoding=ENCODING, newline="") as handle:
        return handle.read()


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding=ENCODING, newline="\n") as handle:
        handle.write(text)


def _get_passphrase(confirm: bool = False) -> str:
    env_value = os.environ.get("SECURE_TEXT_PASSPHRASE")
    if env_value:
        return env_value
    first = getpass.getpass("Passphrase: ")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise SystemExit("Passphrases did not match.")
    return first


def _rfc8439_quick_check() -> None:
    block = _chacha20_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000"))
    if block[:16] != bytes.fromhex("10f1e7e4d13b5915500fdd1fa32071c4"):
        raise SystemExit("RFC8439 ChaCha20 block check failed")


def selftest() -> None:
    _rfc8439_quick_check()
    passphrase = "correct horse battery staple"
    plaintext = "This is a harmless test.\nCANARY: blue-horse-742\nUnicode: café — αβγ — 😊\n"
    encrypted = encrypt_text(plaintext, passphrase, iterations=100_000, label="IMAGE DATA")
    if decrypt_text(encrypted, passphrase) != plaintext:
        raise SystemExit("selftest failed: plaintext mismatch")
    payload = bytearray(_extract_payload(encrypted))
    payload[-1] ^= 1
    try:
        decrypt_text(_wrap(bytes(payload), label="IMAGE DATA"), passphrase)
    except Exception:
        pass
    else:
        raise SystemExit("selftest failed: tampering was not detected")
    print("selftest ok")


def benchmark(size_kb: int = 64, rounds: int = 3, iterations: int = 100_000) -> None:
    passphrase = "benchmark passphrase"
    plaintext = ("0123456789abcdef café — αβγ — 😊\n" * 2048)
    plaintext = (plaintext * (((size_kb * 1024) // len(plaintext)) + 1))[:size_kb * 1024]
    enc_times = []
    dec_times = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        encrypted = encrypt_text(plaintext, passphrase, iterations=iterations)
        t1 = time.perf_counter()
        decrypted = decrypt_text(encrypted, passphrase)
        t2 = time.perf_counter()
        if decrypted != plaintext:
            raise SystemExit("benchmark failed: plaintext mismatch")
        enc_times.append(t1 - t0)
        dec_times.append(t2 - t1)
    print(json.dumps({
        "backend": "stdlib",
        "cipher": "CHACHA20-POLY1305-PUREPY",
        "size_kb": size_kb,
        "rounds": rounds,
        "iterations": iterations,
        "encrypt_seconds_avg": sum(enc_times) / len(enc_times),
        "decrypt_seconds_avg": sum(dec_times) / len(dec_times),
    }, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Encrypt/decrypt opaque text data blocks using pure-Python ChaCha20-Poly1305.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encrypt", help="encrypt a UTF-8 text file")
    p_enc.add_argument("input")
    p_enc.add_argument("output")
    p_enc.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    p_enc.add_argument("--label", default=DEFAULT_LABEL)
    p_enc.add_argument("--no-wrapper", action="store_true")

    p_dec = sub.add_parser("decrypt", help="decrypt an opaque data block file")
    p_dec.add_argument("input")
    p_dec.add_argument("output")

    sub.add_parser("selftest", help="run a quick round-trip and tamper test")

    p_bench = sub.add_parser("benchmark", help="run a small benchmark")
    p_bench.add_argument("--size-kb", type=int, default=64)
    p_bench.add_argument("--rounds", type=int, default=3)
    p_bench.add_argument("--iterations", type=int, default=100_000)

    args = parser.parse_args(argv)
    if args.command == "encrypt":
        passphrase = _get_passphrase(confirm=True)
        _write_text(args.output, encrypt_text(_read_text(args.input), passphrase, iterations=args.iterations, label=args.label, wrapper=not args.no_wrapper))
        return 0
    if args.command == "decrypt":
        passphrase = _get_passphrase(confirm=False)
        _write_text(args.output, decrypt_text(_read_text(args.input), passphrase))
        return 0
    if args.command == "selftest":
        selftest()
        return 0
    if args.command == "benchmark":
        benchmark(size_kb=args.size_kb, rounds=args.rounds, iterations=args.iterations)
        return 0
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
