"""Canli beslemeden plan onerisi (router/planner zenginlestirme).

Router modelin niyetini (hedef + teknik) cikarir. Bu modul o niyeti
CANLI besleme ile zenginlestirir: hedef uruna dair trend KEV/kritik
CVE'leri bulur, CWE->ATT&CK koprUsuyle tekniklere cevirir ve bunlari
*oneri* olarak dondurur.

Onemli: bunlar yalnizca ONERIdir. Hicbir sey otomatik calismaz; plan
yine Scope+Policy+Audit kapilarindan gecer. Amac operatore "su an sahada
somurulen ve bu hedefle ilgili olabilecek sunlar var" demek.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..knowledge import bridge
from ..knowledge.vuln import VulnStore


@dataclass
class Suggestion:
    cve: str
    priority: float
    tier: str
    kev: bool
    techniques: list[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "priority": self.priority,
            "tier": self.tier,
            "kev": self.kev,
            "techniques": self.techniques,
            "rationale": self.rationale,
        }


def _keywords(text: str) -> list[str]:
    """Metinden urun/teknoloji adi adaylarini cikar (kaba ama aciklanabilir)."""
    out = []
    for tok in text.replace("/", " ").replace(":", " ").split():
        tok = tok.strip().lower()
        if len(tok) >= 4 and not tok.startswith(("http", "www", "t10", "t15", "aml")):
            out.append(tok)
    return list(dict.fromkeys(out))[:8]


def suggest_for_text(
    text: str,
    targets: tuple[str, ...] | list[str] = (),
    store: VulnStore | None = None,
    limit: int = 5,
    min_score: float = 40.0,
) -> list[Suggestion]:
    """Serbest metin + hedeflerden canli CVE onerileri uret.

    Depoda veri yoksa ([] boş donerse) sessizce bos liste doner -- oneri
    yoklugu akisi bozmamali.
    """
    store = store if store is not None else VulnStore()
    if not store.cves:
        return []

    needles = _keywords(text)
    for t in targets:
        for part in str(t).replace("://", " ").replace(".", " ").replace("/", " ").split():
            if len(part) >= 4:
                needles.append(part.lower())
    needles = list(dict.fromkeys(needles))

    scored: list[Suggestion] = []
    seen: set[str] = set()
    for needle in needles:
        for record in store.match(product=needle, limit=limit):
            if record.id in seen or record.score() < min_score:
                continue
            seen.add(record.id)
            link = bridge.enrich(record, min_confidence=0.5)
            scored.append(Suggestion(
                cve=record.id,
                priority=record.score(),
                tier=record.tier(),
                kev=record.kev,
                techniques=link["runnable"],
                rationale=f"'{needle}' ile eslesti" + (" · KEV" if record.kev else ""),
            ))

    scored.sort(key=lambda s: (s.kev, s.priority), reverse=True)
    return scored[:limit]


def techniques_from_suggestions(suggestions: list[Suggestion]) -> list[str]:
    """Onerilerden playbook'u olan benzersiz teknik kimliklerini topla."""
    out: list[str] = []
    for s in suggestions:
        for tid in s.techniques:
            if tid not in out:
                out.append(tid)
    return out
