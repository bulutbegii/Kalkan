"""Arac kayit defteri (registry).

Her adaptor bir ToolSpec ilan eder: hangi yetenekleri (capability)
sagladigi, hangi risk seviyesinde calistigi, hangi binary'ye ihtiyac
duydugu. Planlayici yetenek adiyla arac secer; isimle degil.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Risk


@dataclass(frozen=True)
class ToolSpec:
    name: str
    capabilities: tuple[str, ...]
    risk: Risk
    binary: str | None
    description: str

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities


class Registry:
    def __init__(self) -> None:
        self._adapters: dict[str, object] = {}

    def register(self, adapter: object) -> None:
        spec: ToolSpec = adapter.spec  # type: ignore[attr-defined]
        if spec.name in self._adapters:
            raise ValueError(f"araç zaten kayıtlı: {spec.name}")
        self._adapters[spec.name] = adapter

    def get(self, name: str):
        if name not in self._adapters:
            raise KeyError(f"bilinmeyen araç: {name}")
        return self._adapters[name]

    def names(self) -> list[str]:
        return sorted(self._adapters)

    def all(self) -> list[object]:
        return [self._adapters[n] for n in self.names()]

    def by_capability(self, capability: str) -> list[object]:
        return [a for a in self.all() if a.spec.supports(capability)]  # type: ignore[attr-defined]

    def capabilities(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for adapter in self.all():
            for cap in adapter.spec.capabilities:  # type: ignore[attr-defined]
                out.setdefault(cap, []).append(adapter.spec.name)  # type: ignore[attr-defined]
        return dict(sorted(out.items()))

    def availability(self) -> dict[str, bool]:
        return {a.spec.name: a.available() for a in self.all()}  # type: ignore[attr-defined]
