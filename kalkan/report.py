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


def _md_cell(text: Any, limit: int = 160) -> str:
    """Bir degeri Markdown tablo hucresine guvenli hale getir (| ve newline)."""
    s = str(text or "").replace("|", "\\|").replace("\n", " ").strip()
    return (s[:limit] + "…") if len(s) > limit else (s or "-")


def _decision_log(decisions: list[dict[str, Any]]) -> list[str]:
    """Ajan karar logunu Markdown tablosu olarak uret.

    Plan tablosundan farki: modelin/kuralin HER adimda NE SECTIGINI ve NEDEN
    (gerekce + kaynak + sonuc) gosterir -> oturumun denetlenebilir anlatimi."""
    lines = ["## Ajan Karar Logu", "",
             "| # | Kaynak | Yetenek.Araç | Risk | Teknik | Durum | Süre | Gerekçe |",
             "|---|--------|--------------|------|--------|-------|------|---------|"]
    for d in decisions:
        src = "model" if d.get("source") == "llm" else "kural"
        dur = f"{d.get('duration_s', 0):.1f}s"
        lines.append(
            f"| {d.get('step', '')} | {src} "
            f"| {_md_cell(d.get('capability'))}.{_md_cell(d.get('tool'))} "
            f"| {d.get('risk', '-')} | {d.get('technique') or '-'} "
            f"| {d.get('status', '-')} | {dur} | {_md_cell(d.get('thought'), 200)} |"
        )
    lines.append("")
    return lines


def render(target: str, objective: str, actions: list[Action],
           results: list[ActionResult], notes: list[str] | None = None,
           summary: str = "", scope: str = "", when: datetime | None = None,
           loot: list[dict[str, Any]] | None = None,
           correlation: list[dict[str, Any]] | None = None,
           decisions: list[dict[str, Any]] | None = None) -> str:
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

    if decisions:
        lines += _decision_log(decisions)

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

    if correlation:
        lines += ["## Sürüm→CVE Korelasyonu", "",
                  "| CVE | Skor | Derece | KEV | Ürün/Sürüm | MSF modülü |",
                  "|-----|------|--------|-----|------------|------------|"]
        for c in correlation:
            pv = f"{c.get('product', '')} {c.get('version', '')}".strip() or "-"
            kev = "✓" if c.get("kev") else ""
            lines.append(f"| {c['cve']} | {c['score']} | {c['tier']} | {kev} | "
                         f"{pv} | {c.get('msf_module') or '-'} |")
        lines.append("")

    if loot:
        lines += ["## Loot / Elde Edilen Veri", ""]
        for item in loot:
            lines.append(f"### {item['label']}")
            lines.append(f"- **Dosya:** `{item['path']}`")
            snippet = (item.get("snippet") or "").strip()
            if snippet:
                lines += ["", "```", snippet, "```", ""]
            else:
                lines.append("")

    if summary:
        lines += ["## Özet", "", summary, ""]

    if notes:
        lines += ["## Notlar", "", *[f"- {n}" for n in notes], ""]

    lines += ["---", "_Kalkan — yalnızca yetkili/izinli testler içindir._"]
    return "\n".join(lines)


def _persist_loot(results: list[ActionResult], target: str, out_dir: Path,
                  stamp: str) -> list[dict[str, Any]]:
    """Adaptorlerin dondurdugu ham loot'u (sqlmap dump, msf oturum ciktisi)
    reports/loot/<hedef>_<zaman>/ altina yaz; rapora eklenecek ozeti dondur."""
    loot: list[dict[str, Any]] = []
    loot_dir: Path | None = None
    for r in results:
        p = r.parsed or {}
        text = p.get("loot_text")
        if not text or not str(text).strip():
            continue
        if loot_dir is None:
            loot_dir = out_dir / "loot" / f"{_slug(target)}_{stamp}"
            loot_dir.mkdir(parents=True, exist_ok=True)
        name = p.get("loot_name") or f"{r.action.tool}_{r.action.capability}"
        fpath = loot_dir / f"{_slug(name)}.txt"
        try:
            fpath.write_text(str(text), encoding="utf-8")
        except OSError:
            continue
        loot.append({
            "label": f"{r.action.tool}.{r.action.capability}",
            "path": str(fpath),
            "snippet": str(text)[:1500],
        })
    return loot


def write_report(plan: Plan, results: list[ActionResult], *, summary: str = "",
                 scope: str = "", out_dir: str | Path = DEFAULT_DIR,
                 when: datetime | None = None,
                 correlation: list[dict[str, Any]] | None = None,
                 decisions: list[dict[str, Any]] | None = None) -> Path:
    """Raporu reports/<hedef>_<zaman>.md olarak yaz ve yolunu döndür.
    Gercek istismar ciktilari (loot) ayrica reports/loot/ altina kaydedilir."""
    when = when or datetime.now()
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = when.strftime("%Y%m%d-%H%M%S")
    loot = _persist_loot(results, plan.target, directory, stamp)
    md = render(
        target=plan.target, objective=plan.objective, actions=plan.actions,
        results=results, notes=plan.notes, summary=summary, scope=scope, when=when,
        loot=loot, correlation=correlation, decisions=decisions,
    )
    fname = f"{_slug(plan.target)}_{stamp}.md"
    path = directory / fname
    path.write_text(md, encoding="utf-8")
    return path
