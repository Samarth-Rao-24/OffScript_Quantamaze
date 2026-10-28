"""Command queue and pass definitions shared by every scheduler and validator."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..common.frame import MAX_BODY_LEN, PASS_OPEN_BODY_LEN, frame_size
from ..common.roles import OPCODE_INFO, Opcode, Role, required_role

PASS_OPEN_FRAME_BYTES = frame_size(PASS_OPEN_BODY_LEN)  # 715 B, sent at the start of every pass


@dataclass
class Command:
    id: str
    name: str
    opcode: int
    args_hex: str
    role: str
    priority: int
    deadline_pass: int
    depends_on: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def body(self) -> bytes:
        return bytes([self.opcode]) + bytes.fromhex(self.args_hex)

    @property
    def frame_bytes(self) -> int:
        return frame_size(len(self.body))

    def validate(self) -> None:
        if self.opcode not in OPCODE_INFO or self.opcode == Opcode.PASS_OPEN:
            raise ValueError(f"{self.id}: unsupported opcode 0x{self.opcode:02x}")
        if len(self.body) > MAX_BODY_LEN:
            raise ValueError(f"{self.id}: body {len(self.body)} B exceeds {MAX_BODY_LEN} B")
        if self.role not in (Role.OPERATOR, Role.ADMIN):
            raise ValueError(f"{self.id}: unknown role {self.role}")
        if not (1 <= self.priority <= 100):
            raise ValueError(f"{self.id}: priority must be 1..100")
        if self.deadline_pass < 1:
            raise ValueError(f"{self.id}: deadline must be >= 1")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["frame_bytes"] = self.frame_bytes
        d["body_len"] = len(self.body)
        d["opcode_name"] = OPCODE_INFO[self.opcode]["name"]
        d["required_role"] = required_role(self.opcode)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Command":
        keys = {"id", "name", "opcode", "args_hex", "role", "priority", "deadline_pass", "depends_on", "note"}
        c = cls(**{k: v for k, v in d.items() if k in keys})
        c.opcode = int(c.opcode)
        c.priority = int(c.priority)
        c.deadline_pass = int(c.deadline_pass)
        c.depends_on = list(c.depends_on or [])
        return c


@dataclass
class PassWindow:
    index: int  # 1-based
    budget_bytes: int
    label: str = ""

    @property
    def command_budget(self) -> int:
        """Bytes left for commands after the mandatory PASS_OPEN frame."""
        return self.budget_bytes - PASS_OPEN_FRAME_BYTES

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "budget_bytes": self.budget_bytes,
            "command_budget": self.command_budget,
            "pass_open_bytes": PASS_OPEN_FRAME_BYTES,
            "label": self.label,
        }


@dataclass
class Instance:
    commands: list[Command]
    passes: list[PassWindow]

    @property
    def T(self) -> int:
        return len(self.passes)

    @staticmethod
    def weight(t: int) -> float:
        """Earlier passes weigh more (PRD 11.1): w_t = 1 - 0.1 (t - 1)."""
        return round(1.0 - 0.1 * (t - 1), 6)

    def by_id(self) -> dict[str, Command]:
        return {c.id: c for c in self.commands}

    def validate(self) -> None:
        ids = [c.id for c in self.commands]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate command ids")
        known = set(ids)
        for c in self.commands:
            c.validate()
            for dep in c.depends_on:
                if dep not in known:
                    raise ValueError(f"{c.id} depends on unknown command {dep}")
                if dep == c.id:
                    raise ValueError(f"{c.id} depends on itself")
        # reject dependency cycles
        state: dict[str, int] = {}
        bymap = self.by_id()

        def visit(cid: str) -> None:
            if state.get(cid) == 1:
                raise ValueError(f"dependency cycle through {cid}")
            if state.get(cid) == 2:
                return
            state[cid] = 1
            for d in bymap[cid].depends_on:
                visit(d)
            state[cid] = 2

        for cid in ids:
            visit(cid)
        if not self.passes:
            raise ValueError("at least one pass required")
        for i, p in enumerate(self.passes, start=1):
            if p.index != i:
                raise ValueError("passes must be numbered 1..T")
            if p.command_budget < 0:
                raise ValueError(f"pass {p.index} budget smaller than the PASS_OPEN frame ({PASS_OPEN_FRAME_BYTES} B)")

    def to_dict(self) -> dict:
        return {
            "commands": [c.to_dict() for c in self.commands],
            "passes": [p.to_dict() for p in self.passes],
            "weights": {p.index: self.weight(p.index) for p in self.passes},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Instance":
        return cls(
            commands=[Command.from_dict(c) for c in d["commands"]],
            passes=[PassWindow(int(p["index"]), int(p["budget_bytes"]), p.get("label", "")) for p in d["passes"]],
        )


def default_queue() -> list[Command]:
    O, A = Role.OPERATOR, Role.ADMIN
    return [
        Command("C01", "Exit safe mode", Opcode.SET_SAFE_MODE, "00", A, 9, 1, [], "Must happen before payload ops"),
        Command("C02", "Point nadir", Opcode.SET_ATTITUDE_MODE, "0201", O, 7, 2, ["C01"]),
        Command("C03", "Image target A (flood zone)", Opcode.CAPTURE_IMAGE, "0a1b2c3d00f00012001e0004", O, 8, 2, ["C02"]),
        Command("C04", "Downlink image A", Opcode.DOWNLINK_DATA, "0a1b2c3d00000001", O, 6, 4, ["C03"]),
        Command("C05", "Collision-avoidance burn", Opcode.ORBIT_BURN, "00000a3c000000640000001e000000c8", A, 10, 2, []),
        Command("C06", "Battery heater set-point", Opcode.SET_HEATER, "0112", O, 5, 3, []),
        Command("C07", "Firmware patch chunk 1/2", Opcode.PATCH_FIRMWARE, "01" + "a5" * 30, A, 4, 4, []),
        Command("C08", "Firmware patch chunk 2/2", Opcode.PATCH_FIRMWARE, "02" + "5a" * 30, A, 4, 4, ["C07"]),
        Command("C09", "Reboot ADCS after patch", Opcode.REBOOT_SUBSYSTEM, "03", A, 3, 4, ["C08"]),
        Command("C10", "Health ping", Opcode.NOOP_PING, "", O, 1, 4, []),
        Command("C11", "Image target B (wildfire)", Opcode.CAPTURE_IMAGE, "0b2c3d4e00f00012001e0004", O, 6, 1, []),
        Command("C12", "Housekeeping downlink", Opcode.DOWNLINK_DATA, "000000ff0001", O, 2, 3, []),
        Command("C13", "Image target C (glacier)", Opcode.CAPTURE_IMAGE, "0c3d4e5f00f00012001e0004", O, 5, 3, []),
        Command("C14", "Sun-pointing for charge", Opcode.SET_ATTITUDE_MODE, "0300", O, 3, 4, []),
    ]


def default_passes(budgets: list[int]) -> list[PassWindow]:
    return [PassWindow(i, b, f"Pass {i}") for i, b in enumerate(budgets, start=1)]
