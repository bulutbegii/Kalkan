"""MITRE ATT&CK Navigator layer uretici.

https://github.com/mitre-attack/attack-navigator 'den destek alir:
Kalkan'in OTOMASYON kapsamini (hangi teknik icin calistirilabilir playbook
var) tum ATT&CK matrisi uzerine boyayan, Navigator uygulamasina dogrudan
yuklenebilir bir layer JSON uretir.

- Kapsanan teknikler (mapping._PLAYBOOKS, framework=="attack") en yuksek
  adim riskine gore renklenir (passive->destructive).
- Tam veri seti indirilmisse (kalkan knowledge fetch), kapsanmayan TUM
  teknikler de gri (skor 0) olarak eklenir; boylece layer tum matrisi gosterir
  ve "neyi otomatiklestirebiliyoruz / neyi elle yapmali" tek bakista gorunur.
- Veri seti yoksa yalnizca kapsanan teknikler yazilir (ag gerekmez).

Layer formati Navigator v4.5 ile uyumludur.
"""

from __future__ import annotations

from typing import Any

from ..models import Risk
from . import mapping

_DOMAIN_ATTACK = {
    "enterprise": "enterprise-attack",
    "mobile": "mobile-attack",
    "ics": "ics-attack",
}

_RISK_META: dict[Risk, tuple[int, str, str]] = {
    Risk.PASSIVE: (25, "#8ec843", "passive"),
    Risk.ACTIVE: (50, "#ffe766", "active"),
    Risk.INTRUSIVE: (75, "#ff9f40", "intrusive"),
    Risk.DESTRUCTIVE: (100, "#e4584f", "destructive"),
}
_UNCOVERED_COLOR = "#eeeeee"

_LEGEND = [
    {"label": "otomasyon: passive", "color": "#8ec843"},
    {"label": "otomasyon: active", "color": "#ffe766"},
    {"label": "otomasyon: intrusive", "color": "#ff9f40"},
    {"label": "otomasyon: destructive", "color": "#e4584f"},
    {"label": "otomasyon yok (manuel/kapsam dışı)", "color": _UNCOVERED_COLOR},
]


def _covered_entries() -> dict[str, dict[str, Any]]:
    """Kalkan ATT&CK playbook'larindan teknik -> Navigator girdi sozlugu."""
    entries: dict[str, dict[str, Any]] = {}
    for pb in mapping.all_playbooks():
        if pb.framework != "attack":
            continue
        max_risk = max((s.risk for s in pb.steps), default=Risk.PASSIVE)
        score, color, lbl = _RISK_META[max_risk]
        tools = sorted({s.tool for s in pb.steps})
        comment = (f"{pb.name} — {len(pb.steps)} adım ({lbl}); "
                   f"araçlar: {', '.join(tools)}")
        if pb.rules:
            comment += f"; tespit kuralları: {', '.join(pb.rules)}"
        entries[pb.technique] = {
            "techniqueID": pb.technique,
            "enabled": True,
            "score": score,
            "color": color,
            "comment": comment,
            "metadata": [
                {"name": "kalkan", "value": "otomatik (playbook)"},
                {"name": "tactic", "value": pb.tactic},
                {"name": "max_risk", "value": lbl},
                {"name": "steps", "value": str(len(pb.steps))},
            ],
        }
    return entries


def build_layer(
    domain: str = "enterprise",
    include_all: bool = True,
    name: str = "Kalkan Coverage",
    cache_dir: str | None = None,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Navigator layer sozlugu ve istatistik dondur.

    include_all=True ve veri seti mevcutsa kapsanmayan teknikler de gri eklenir.
    Doner: (layer, {"covered": n, "all": m}) — m veri seti yoksa 0.
    """
    covered = _covered_entries()
    techniques: list[dict[str, Any]] = list(covered.values())
    all_count = 0

    if include_all:
        try:
            from .attack import AttackKnowledge
            ak = AttackKnowledge(domain=domain, cache_dir=cache_dir)
            if ak.available:
                for info in ak.all():
                    all_count += 1
                    tid = info["id"]
                    if tid in covered:
                        continue
                    techniques.append({
                        "techniqueID": tid,
                        "enabled": True,
                        "score": 0,
                        "color": _UNCOVERED_COLOR,
                        "comment": "Kalkan otomasyonu yok (manuel/kapsam dışı)",
                    })
        except Exception:  # noqa: BLE001 - veri seti yoksa yalnizca kapsanan yazilir
            all_count = 0

    layer = {
        "name": name,
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": _DOMAIN_ATTACK.get(domain, "enterprise-attack"),
        "description": (
            "Kalkan otomasyon kapsamı: renkli teknikler için çalıştırılabilir "
            "playbook vardır (renk = en yüksek adım riski); gri teknikler elle "
            "yapılır. https://github.com/mitre-attack/attack-navigator"
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff9f40", "#e4584f"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": _LEGEND,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "sorting": 3,
        "hideDisabled": False,
    }
    return layer, {"covered": len(covered), "all": all_count}
