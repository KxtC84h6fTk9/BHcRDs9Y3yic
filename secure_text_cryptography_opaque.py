#!/usr/bin/env python3
"""
secure_text_cryptography.py

Small text encryption helper using the third-party `cryptography` package.
Default output is an opaque Google-Docs-safe data block with no JSON metadata.

Examples:
  python secure_text_cryptography.py selftest
  python secure_text_cryptography.py benchmark
  python secure_text_cryptography.py encrypt input.txt output.txt
  python secure_text_cryptography.py encrypt input.txt output.txt --label "IMAGE DATA"
  python secure_text_cryptography.py encrypt input.txt output.txt --no-wrapper
  python secure_text_cryptography.py decrypt output.txt roundtrip.txt

In Chat, use:
  encrypted = encrypt_text(plaintext, passphrase)
  plaintext = decrypt_text(encrypted, passphrase)
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "The 'cryptography' package is required.\n"
        "Install locally with: python -m pip install cryptography\n"
        f"Original import error: {exc}"
    )

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
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(ENCODING), header)
    return _wrap(header + ciphertext, label=label, wrapper=wrapper)


def decrypt_text(data_text: str, passphrase: str) -> str:
    payload = _extract_payload(data_text)
    if len(payload) <= HEADER_BYTES or payload[0] != VERSION:
        raise ValueError("unsupported or corrupted data block")
    header = payload[:HEADER_BYTES]
    iterations = int.from_bytes(payload[1:5], "big")
    salt = payload[5:5 + SALT_BYTES]
    nonce = payload[5 + SALT_BYTES:HEADER_BYTES]
    ciphertext = payload[HEADER_BYTES:]
    key = _derive_key(passphrase, salt, iterations)
    return AESGCM(key).decrypt(nonce, ciphertext, header).decode(ENCODING)


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


def selftest() -> None:
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
        "backend": "cryptography",
        "cipher": "AES-256-GCM",
        "size_kb": size_kb,
        "rounds": rounds,
        "iterations": iterations,
        "encrypt_seconds_avg": sum(enc_times) / len(enc_times),
        "decrypt_seconds_avg": sum(dec_times) / len(dec_times),
    }, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Encrypt/decrypt opaque text data blocks using cryptography AES-GCM.")
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
