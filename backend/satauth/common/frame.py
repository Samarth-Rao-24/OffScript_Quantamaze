"""Command frame format (PRD section 5).

Wire layout (big-endian)::

    version  1 B   frame format version (FRAME_VERSION)
    sat_id   1 B   target spacecraft
    key_id   1 B   which ground key signed this frame (maps to a role)
    cmd_len  1 B   length of command body
    counter  8 B   monotonic counter
    expiry   4 B   unix timestamp (seconds) after which the frame is invalid
    command  cmd_len B   opcode (1 B) + arguments
    signature 666 B  Falcon-512 *padded* signature

The signature covers DOMAIN_TAG || header || command || pass_nonce. The pass
nonce is held onboard and is never transmitted inside command frames.

Command bodies are limited to 32 B (PRD). The single exception is PASS_OPEN,
whose body is the 1-byte opcode plus the new 32-byte pass nonce (33 B); the
PRD's 32-byte limit cannot hold opcode + nonce, so it is widened for that one
opcode only (documented deviation).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

FRAME_VERSION = 1
HEADER_FMT = ">BBBBQI"
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 16
SIG_LEN = 666  # Falcon-padded-512 fixed signature length (verified at import in crypto.py)
MAX_BODY_LEN = 32
PASS_OPEN_BODY_LEN = 33
NONCE_LEN = 32
DOMAIN_TAG = b"Q-UPLINK/FRAME/v1"

assert HEADER_LEN == 16


class MalformedFrame(ValueError):
    """Raised when bytes cannot be parsed as a frame."""


@dataclass(frozen=True)
class Frame:
    version: int
    sat_id: int
    key_id: int
    counter: int
    expiry: int
    command: bytes
    signature: bytes

    @property
    def cmd_len(self) -> int:
        return len(self.command)

    @property
    def opcode(self) -> int | None:
        return self.command[0] if self.command else None

    def header_bytes(self) -> bytes:
        return pack_header(self.version, self.sat_id, self.key_id, len(self.command), self.counter, self.expiry)

    def to_bytes(self) -> bytes:
        return self.header_bytes() + self.command + self.signature

    def signed_message(self, pass_nonce: bytes) -> bytes:
        return signed_message(self.header_bytes(), self.command, pass_nonce)

    def __len__(self) -> int:
        return HEADER_LEN + len(self.command) + len(self.signature)

    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


def pack_header(version: int, sat_id: int, key_id: int, cmd_len: int, counter: int, expiry: int) -> bytes:
    return struct.pack(HEADER_FMT, version, sat_id, key_id, cmd_len, counter, expiry)


def signed_message(header: bytes, command: bytes, pass_nonce: bytes) -> bytes:
    if len(pass_nonce) != NONCE_LEN:
        raise ValueError("pass nonce must be 32 bytes")
    return DOMAIN_TAG + header + command + pass_nonce


def max_body_for(opcode: int | None) -> int:
    from .roles import Opcode

    return PASS_OPEN_BODY_LEN if opcode == Opcode.PASS_OPEN else MAX_BODY_LEN


def parse_frame(data: bytes) -> Frame:
    """Parse wire bytes. Cheap and constant-time-ish; never touches crypto."""
    if len(data) < HEADER_LEN + 1 + SIG_LEN:
        raise MalformedFrame(f"frame too short ({len(data)} B)")
    version, sat_id, key_id, cmd_len, counter, expiry = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    if version != FRAME_VERSION:
        raise MalformedFrame(f"unsupported frame version {version}")
    if cmd_len < 1:
        raise MalformedFrame("empty command body")
    expected = HEADER_LEN + cmd_len + SIG_LEN
    if len(data) != expected:
        raise MalformedFrame(f"length mismatch: got {len(data)} B, header implies {expected} B")
    command = data[HEADER_LEN : HEADER_LEN + cmd_len]
    if cmd_len > max_body_for(command[0]):
        raise MalformedFrame(f"command body {cmd_len} B exceeds limit for opcode 0x{command[0]:02x}")
    signature = data[HEADER_LEN + cmd_len :]
    return Frame(version, sat_id, key_id, counter, expiry, command, signature)


def frame_size(body_len: int) -> int:
    return HEADER_LEN + body_len + SIG_LEN
