"""Roles, key IDs, opcodes and the onboard role-to-command table (FR-02, FR-09)."""

from __future__ import annotations

from enum import IntEnum


class Role(str):
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


ROLES = (Role.OPERATOR, Role.ADMIN)

# key_id carried in the frame header -> role. 1 and 2 are the primary keys; the
# rest of the key ring (rotation spares and migration suites) is pre-loaded at
# provisioning: odd ids are OPERATOR keys, even ids ADMIN keys.
KEY_RING_SPEC: list[tuple[int, str, str, str]] = [
    (1, Role.OPERATOR, "falcon512", "active"),
    (2, Role.ADMIN, "falcon512", "active"),
    (3, Role.OPERATOR, "falcon512", "standby"),
    (4, Role.ADMIN, "falcon512", "standby"),
    (5, Role.OPERATOR, "mldsa44", "standby"),
    (6, Role.ADMIN, "mldsa44", "standby"),
    (7, Role.OPERATOR, "hybrid", "standby"),
    (8, Role.ADMIN, "hybrid", "standby"),
]
KEY_IDS: dict[int, str] = {kid: role for kid, role, _, _ in KEY_RING_SPEC}
ROLE_KEY_ID: dict[str, int] = {Role.OPERATOR: 1, Role.ADMIN: 2}  # primary keys


class Opcode(IntEnum):
    PASS_OPEN = 0x01
    NOOP_PING = 0x10
    SET_ATTITUDE_MODE = 0x11
    CAPTURE_IMAGE = 0x12
    DOWNLINK_DATA = 0x13
    SET_HEATER = 0x14
    ORBIT_BURN = 0x20
    SET_SAFE_MODE = 0x21
    REBOOT_SUBSYSTEM = 0x22
    PATCH_FIRMWARE = 0x23
    KEY_ACTIVATE = 0x30
    KEY_REVOKE = 0x31


OPCODE_INFO: dict[int, dict] = {
    Opcode.PASS_OPEN: {"name": "PASS_OPEN", "desc": "Open contact window, install QRNG pass nonce", "admin_only": True},
    Opcode.NOOP_PING: {"name": "NOOP_PING", "desc": "Health ping", "admin_only": False},
    Opcode.SET_ATTITUDE_MODE: {"name": "SET_ATTITUDE_MODE", "desc": "Change ADCS pointing mode", "admin_only": False},
    Opcode.CAPTURE_IMAGE: {"name": "CAPTURE_IMAGE", "desc": "Schedule payload image capture", "admin_only": False},
    Opcode.DOWNLINK_DATA: {"name": "DOWNLINK_DATA", "desc": "Queue stored data for downlink", "admin_only": False},
    Opcode.SET_HEATER: {"name": "SET_HEATER", "desc": "Battery heater set-point", "admin_only": False},
    Opcode.ORBIT_BURN: {"name": "ORBIT_BURN", "desc": "Thruster burn (delta-v)", "admin_only": True},
    Opcode.SET_SAFE_MODE: {"name": "SET_SAFE_MODE", "desc": "Enter/leave safe mode", "admin_only": True},
    Opcode.REBOOT_SUBSYSTEM: {"name": "REBOOT_SUBSYSTEM", "desc": "Power-cycle a subsystem", "admin_only": True},
    Opcode.PATCH_FIRMWARE: {"name": "PATCH_FIRMWARE", "desc": "Apply firmware patch chunk", "admin_only": True},
    Opcode.KEY_ACTIVATE: {"name": "KEY_ACTIVATE", "desc": "Activate a pre-loaded standby key (args: key_id)", "admin_only": True},
    Opcode.KEY_REVOKE: {"name": "KEY_REVOKE", "desc": "Revoke a key permanently (args: key_id)", "admin_only": True},
}

ADMIN_ONLY = frozenset(op for op, info in OPCODE_INFO.items() if info["admin_only"])
OPERATOR_ALLOWED = frozenset(op for op, info in OPCODE_INFO.items() if not info["admin_only"])


def default_role_table() -> dict[str, list[int]]:
    """Role -> allowed opcodes. Preloaded onboard; JSON-serialisable."""
    return {
        Role.OPERATOR: sorted(int(o) for o in OPERATOR_ALLOWED),
        Role.ADMIN: sorted(int(o) for o in OPCODE_INFO),
    }


def opcode_name(op: int | None) -> str:
    if op is None:
        return "?"
    info = OPCODE_INFO.get(op)
    return info["name"] if info else f"0x{op:02x}"


def required_role(op: int) -> str:
    return Role.ADMIN if op in ADMIN_ONLY else Role.OPERATOR
