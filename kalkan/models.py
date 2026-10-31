"""Cekirdek veri modelleri. Bilincli olarak stdlib-only (dataclass) tutuldu."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Risk(enum.IntEnum):
    """Bir aksiyonun hedef uzerindeki etki seviyesi.

    PASSIVE    : hedefe paket gitmez (Shodan, STIX sorgusu, yerel analiz)
    ACTIVE     : hedefe dokunur ama zarar vermez (port tarama, HTTP probe)
    INTRUSIVE  : kimlik dogrulama denemesi, exploit check, payload
    DESTRUCTIVE: veri degistirme/silme, kalici erisim
    """

    PASSIVE = 0
    ACTIVE = 1
    INTRUSIVE = 2
    DESTRUCTIVE = 3

    @classmethod
    def parse(cls, value: "Risk | str | int") -> "Risk":
        if isinstance(value, Risk):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().lower()
        for member in cls:
            if member.name.lower() == key:
                return member
        raise ValueError(f"bilinmeyen risk seviyesi: {value!r}")

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Action:
    """Tek bir arac cagrisi. Planlayici uretir, Executor uygular."""

    tool: str
    capability: str
    target: str
    args: dict[str, Any] = field(default_factory=dict)
    risk: Risk = Risk.PASSIVE
    technique: str = ""
    rationale: str = ""

    def key(self) -> str:
        return f"{self.tool}:{self.capability}:{self.target}"

    def describe(self) -> str:
        return f"[{self.risk.label}] {self.tool}.{self.capability} -> {self.target}"


@dataclass
class ActionResult:
    action: Action
    status: str
    command: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0
    detail: str = ""

    def summary(self) -> str:
        return f"{self.action.describe()} => {self.status} ({self.duration_s:.1f}s)"


@dataclass
class Plan:
    """Bir hedefe yonelik sirali aksiyon listesi."""

    objective: str
    target: str
    actions: list[Action] = field(default_factory=list)
    created: datetime = field(default_factory=utcnow)
    notes: list[str] = field(default_factory=list)

    def sorted_by_risk(self) -> list[Action]:
        return sorted(self.actions, key=lambda a: (int(a.risk), a.tool))

    def max_risk(self) -> Risk:
        if not self.actions:
            return Risk.PASSIVE
        return max(a.risk for a in self.actions)


@dataclass(frozen=True)
class Intent:
    """LLM router'in urettigi niyet nesnesi. Sadece bu alanlar kabul edilir."""

    objective: str
    targets: tuple[str, ...]
    techniques: tuple[str, ...]
    rationale: str = ""
    source: str = "llm"
    notes: tuple[str, ...] = ()
