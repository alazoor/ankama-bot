import os
import json
import base64
import hashlib
import binascii

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = bytes.fromhex(
    "6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98"
)


def encode(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"))
    crc = binascii.crc32(raw.encode()) & 0xFFFFFFFF
    return f"{crc:08X}#{raw}"


def encrypt(plaintext: str) -> str:
    iv  = os.urandom(12)
    ct  = AESGCM(KEY).encrypt(iv, plaintext.encode(), None)
    tag = ct[-16:]                                              # GCM auth tag
    enc = ct[:-16]
    return f"{base64.b64encode(iv).decode()}::{tag.hex()}::{enc.hex()}"


def decrypt(encrypted: str) -> bytes:
    iv_b64, tag_hex, ct_hex = encrypted.split("::")
    iv  = base64.b64decode(iv_b64)
    tag = bytes.fromhex(tag_hex)
    ct  = bytes.fromhex(ct_hex)
    return AESGCM(KEY).decrypt(iv, ct + tag, None)


def solve_sha2(challenge_input: str, checksum: str, difficulty: int) -> str:
    base  = (challenge_input + checksum).encode()
    bits  = difficulty // 4 + 1                                 # hex chars to check
    shift = bits * 4 - difficulty                               # right-shift to test leading zeros
    nonce = 0
    while True:
        h = hashlib.sha256(base + str(nonce).encode()).hexdigest()
        if int(h[:bits], 16) >> shift == 0:
            return str(nonce)
        nonce += 1
