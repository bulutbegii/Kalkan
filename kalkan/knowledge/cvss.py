"""CVSS vector ayristirma ve temel skor hesabi (stdlib-only).

Desteklenen:
  * CVSS v3.0 / v3.1 base score (tam formul)
  * CVSS v4.0 vector ayristirma (skor NVD'den alinir; burada hesaplanmaz)
  * CVSS v2 vector ayristirma (skor NVD'den alinir)

NVD kayitlarinda bazen skor alani eksik olur; bu modul vector string'den
skoru yeniden uretebilir. Amac seffaflik: hangi metrik skoru nasil
sisirdigini gosterebilmek.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

SEVERITY_BANDS = (
    (0.0, "none"),
    (4.0, "low"),
    (7.0, "medium"),
    (9.0, "high"),
    (10.01, "critical"),
)

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

LABELS = {
    "AV": {"N": "ag", "A": "komsu ag", "L": "yerel", "P": "fiziksel"},
    "AC": {"L": "dusuk", "H": "yuksek"},
    "PR": {"N": "yok", "L": "dusuk", "H": "yuksek"},
    "UI": {"N": "gerekmiyor", "R": "gerekli"},
    "S": {"U": "degismemis", "C": "degismis"},
    "C": {"H": "yuksek", "L": "dusuk", "N": "yok"},
    "I": {"H": "yuksek", "L": "dusuk", "N": "yok"},
    "A": {"H": "yuksek", "L": "dusuk", "N": "yok"},
}


class CvssError(ValueError):
    pass


def _roundup(value: float) -> float:
    """CVSS 3.1 spec: en yakin 0.1'e yukari yuvarla (float hatasina dayanikli)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """'CVSS:3.1/AV:N/AC:L/...' -> {'version': '3.1', 'AV': 'N', ...}."""
    if not vector:
        raise CvssError("bos vector")
    text = vector.strip()
    version = ""
    parts = text.split("/")
    if parts[0].upper().startswith("CVSS:"):
        version = parts[0].split(":", 1)[1]
        parts = parts[1:]
    metrics: dict[str, str] = {"version": version}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    return metrics


def severity(score: float) -> str:
    for limit, label in SEVERITY_BANDS:
        if score < limit:
            return label
    return "critical"


def base_score(vector: str) -> float:
    """CVSS v3.0/3.1 base score. Desteklenmeyen vector'de CvssError atar."""
    m = parse_vector(vector)
    version = m.get("version", "")
    if version and not version.startswith("3"):
        raise CvssError(f"desteklenmeyen CVSS surumu: {version}")
    try:
        av = AV[m["AV"]]
        ac = AC[m["AC"]]
        ui = UI[m["UI"]]
        scope_changed = m["S"] == "C"
        pr = (PR_CHANGED if scope_changed else PR_UNCHANGED)[m["PR"]]
        c, i, a = CIA[m["C"]], CIA[m["I"]], CIA[m["A"]]
    except KeyError as exc:
        raise CvssError(f"eksik/gecersiz metrik: {exc}") from exc

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min((impact + exploitability) * (1.08 if scope_changed else 1.0), 10.0)
    return _roundup(raw)


@dataclass(frozen=True)
class CvssAssessment:
    vector: str
    version: str
    base: float
    severity: str
    scope_changed: bool
    metrics: dict[str, str] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def explain(self) -> list[str]:
        m = self.metrics
        lines = [
            f"vector     : {self.vector}",
            f"surum      : {self.version or 'bilinmiyor'}",
            f"base skor  : {self.base:.1f} ({self.severity})",
        ]
        for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
            if key in m:
                label = LABELS.get(key, {}).get(m[key], m[key])
                lines.append(f"  {key} = {m[key]}  ({label})")
        lines.extend(f"not: {n}" for n in self.notes)
        return lines


def assess(vector: str, fallback_score: float | None = None, fallback_severity: str = "") -> CvssAssessment:
    """Vector'den degerlendirme uret; hesaplanamazsa NVD skoruna dus."""
    metrics: dict[str, str] = {}
    version = ""
    try:
        metrics = parse_vector(vector)
        version = metrics.get("version", "")
        if version.startswith("3"):
            score = base_score(vector)
            sev = severity(score)
            return CvssAssessment(
                vector=vector,
                version=version,
                base=score,
                severity=sev,
                scope_changed=metrics.get("S") == "C",
                metrics=metrics,
            )
        notes = ("v4.x/v2 vector ayristirildi; skor NVD'den alinmali",)
    except CvssError as exc:
        notes = (f"vector hesaplanamadi: {exc}",)
        metrics = {}

    if fallback_score is None:
        raise CvssError(notes[0])
    return CvssAssessment(
        vector=vector,
        version=version,
        base=float(fallback_score),
        severity=(fallback_severity or severity(float(fallback_score))).lower(),
        scope_changed=metrics.get("S") == "C",
        metrics=metrics,
        notes=notes,
    )
