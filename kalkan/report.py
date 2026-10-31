"""Tarama raporu üretimi (Markdown).

Her çalıştırmadan sonra: plan adımları + sonuçlar + keşifler + (varsa) model
özeti tek bir .md dosyasına yazılır. Dosya hedefe ve tarihe göre adlandırılır,
böylece geçmişe dönük arşiv oluşur:  reports/<hedef>_<YYYYAAGG-SSDDSS>.md
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .models import Action, ActionResult, Plan

DEFAULT_DIR = "reports"


def _slug(target: str) -> str:
    """Hedefi dosya adına uygun hale getir (şema/port/eğik çizgi temizlenir)."""
    t = re.sub(r"^\w+://", "", (target or "hedef").strip()).strip("/")
    t = re.sub(r"[^A-Za-z0-9._-]+", "_", t).strip("_.")
    return (t or "hedef")[:80]


_HIGHLIGHT = (
    ("open_ports", "Açık portlar"),
    ("ports", "Portlar"),
    ("detected", "WAF/CDN"),
    ("technologies", "Teknolojiler"),
    ("ip", "IP"),
    ("resolved_ip", "Çözülen IP"),
    ("org", "Organizasyon"),
    ("count", "Bulgu sayısı"),
    ("by_severity", "Önem dağılımı"),
    ("known_vulns", "Bilinen zafiyetler"),
)


def _fmt(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "-"
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items()) if value else "-"
    return str(value)


def _discoveries(results: Iterable[ActionResult]) -> list[str]:
    """Sonuçlardan insana okunur keşif satırları çıkar."""
    lines: list[str] = []
    for r in results:
        p = r.parsed or {}
        bits = []
        for key, label in _HIGHLIGHT:
            if key in p and p[key] not in (None, "", [], {}):
                bits.append(f"{label}: {_fmt(p[key])}")
        findings = p.get("findings")
        if isinstance(findings, list) and findings:
            for f in findings[:10]:
                if isinstance(f, dict):
                    sev = f.get("severity", "")
                    name = f.get("name") or f.get("check") or f.get("template") or ""
                    detail = f.get("detail", "")
                    lines.append(f"- `{r.action.tool}.{r.action.capability}` "
                                 f"**{sev}** {name} {('— ' + detail) if detail else ''}".rstrip())
        if bits:
            lines.append(f"- `{r.action.tool}.{r.action.capability}`: " + " · ".join(bits))
    return lines


def render(target: str, objective: str, actions: list[Action],
           results: list[ActionResult], notes: list[str] | None = None,
           summary: str = "", scope: str = "", when: datetime | None = None) -> str:
    when = when or datetime.now()
    lines = [
        "# Kalkan Tarama Raporu",
        "",
        f"- **Hedef:** {target or '-'}",
        f"- **Tarih:** {when.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Amaç:** {objective or '-'}",
    ]
    if scope:
        lines.append(f"- **Kapsam:** {scope}")
    max_risk = max((a.risk for a in actions), default=None)
    lines.append(f"- **Aksiyon:** {len(actions)}"
                 + (f" (tavan risk: {max_risk.label})" if max_risk is not None else ""))
    lines.append("")

    lines += ["## Plan Adımları", "", "| # | Risk | Araç.Yetenek | Teknik | Argüman |",
              "|---|------|--------------|--------|---------|"]
    for i, a in enumerate(actions, 1):
        args = ", ".join(f"{k}={v}" for k, v in a.args.items() if v not in (None, "")) or "-"
        lines.append(f"| {i} | {a.risk.label} | {a.tool}.{a.capability} | {a.technique or '-'} | {args} |")
    lines.append("")

    lines += ["## Sonuçlar", ""]
    for r in results:
        lines.append(f"### {r.action.tool}.{r.action.capability} → {r.status} ({r.duration_s:.1f}s)")
        if r.detail:
            lines.append(f"- {r.detail}")
        p = r.parsed or {}
        for key, label in _HIGHLIGHT:
            if key in p and p[key] not in (None, "", [], {}):
                lines.append(f"- {label}: {_fmt(p[key])}")
        lines.append("")

    disc = _discoveries(results)
    if disc:
        lines += ["## Keşifler", "", *disc, ""]

    if summary:
        lines += ["## Özet", "", summary, ""]

    if notes:
        lines += ["## Notlar", "", *[f"- {n}" for n in notes], ""]

    lines += ["---", "_Kalkan — yalnızca yetkili/izinli testler içindir._"]
    return "\n".join(lines)


def write_report(plan: Plan, results: list[ActionResult], *, summary: str = "",
                 scope: str = "", out_dir: str | Path = DEFAULT_DIR,
                 when: datetime | None = None) -> Path:
    """Raporu reports/<hedef>_<zaman>.md olarak yaz ve yolunu döndür."""
    when = when or datetime.now()
    md = render(
        target=plan.target, objective=plan.objective, actions=plan.actions,
        results=results, notes=plan.notes, summary=summary, scope=scope, when=when,
    )
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    fname = f"{_slug(plan.target)}_{when.strftime('%Y%m%d-%H%M%S')}.md"
    path = directory / fname
    path.write_text(md, encoding="utf-8")
    return path
