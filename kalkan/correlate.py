"""Surum -> CVE korelasyonu.

Tarama sonuclarindan (nmap service_version, httpx tech_detect, shodan)
tespit edilen urun/surumleri alir, yerel CVE deposuyla (NVD) eslestirir,
CVSS/EPSS/KEV onceligine gore siralar ve her CVE icin 'sonraki adim'
koprusunu (msf modulu / sqlmap / nuclei -id) uretir.

Bu katman yalnizca BULGU ve ONERI uretir; hicbir sey calistirmaz. Gercek
istismar yine scope + --allow-destructive + onay + acik silahlama ister.
"""

from __future__ import annotations

from typing import Any, Iterable

from .knowledge import bridge
from .knowledge.vuln import VulnStore
from .models import ActionResult


def _detect_products(results: Iterable[ActionResult]) -> tuple[list[tuple[str, str]], set[str]]:
    """Sonuclardan (urun, surum) ciftlerini ve dogrudan CVE'leri topla."""
    pairs: list[tuple[str, str]] = []
    direct_cves: set[str] = set()
    seen: set[tuple[str, str]] = set()

    def add(product: str, version: str = "") -> None:
        product = (product or "").strip()
        version = (version or "").strip()
        if len(product) < 2:
            return
        key = (product.lower(), version.lower())
        if key in seen:
            return
        seen.add(key)
        pairs.append((product, version))

    for r in results:
        p = r.parsed or {}
        for host in p.get("hosts", []) or []:
            for port in host.get("ports", []) or []:
                prod = port.get("product") or ""
                ver = port.get("version") or ""
                if prod:
                    add(prod, ver)
        techs = p.get("technologies")
        if isinstance(techs, dict):
            for name in techs:
                add(str(name))
        elif isinstance(techs, (list, tuple)):
            for name in techs:
                add(str(name))
        for f in p.get("findings", []) or []:
            if isinstance(f, dict):
                if f.get("server"):
                    add(str(f["server"]))
                for t in f.get("tech", []) or []:
                    add(str(t))
        for svc in p.get("services", []) or []:
            if isinstance(svc, dict) and svc.get("product"):
                add(str(svc["product"]), str(svc.get("version") or ""))
        for cve in p.get("known_vulns", []) or []:
            direct_cves.add(str(cve).strip().upper())
    return pairs, direct_cves


def _entry(record: Any, product: str = "", version: str = "") -> dict[str, Any]:
    cid = record.id
    module = bridge.msf_module(cid)
    sqli = bridge.is_sqli(getattr(record, "cwe", None), getattr(record, "description", "") or "")
    return {
        "cve": cid,
        "score": round(record.score(), 1),
        "tier": record.tier(),
        "kev": bool(getattr(record, "kev", False)),
        "epss": getattr(record, "epss", 0.0),
        "product": product,
        "version": version,
        "msf_module": module[0] if module else "",
        "sqli": sqli,
        "nuclei_id": cid,
    }


def correlate(results: list[ActionResult], store: VulnStore | None = None,
              limit: int = 12, min_score: float = 0.0) -> list[dict[str, Any]]:
    """Tespit edilen urun/surumlerden onceliklendirilmis CVE bulgulari uret."""
    store = store or VulnStore()
    pairs, direct_cves = _detect_products(results)
    if not pairs and not direct_cves:
        return []

    found: dict[str, dict[str, Any]] = {}

    for cid in direct_cves:
        rec = store.get(cid)
        if rec:
            found[cid] = _entry(rec)

    for product, version in pairs:
        try:
            records = store.match(product, version or None, limit=15)
        except Exception:  # noqa: BLE001 - depo bos/erisilemezse atla
            continue
        for rec in records:
            cid = rec.id
            if cid in found:
                continue
            found[cid] = _entry(rec, product, version)

    rows = [e for e in found.values() if e["score"] >= min_score]
    rows.sort(key=lambda e: (e["kev"], e["score"]), reverse=True)
    return rows[:limit]


def next_steps(rows: list[dict[str, Any]]) -> list[str]:
    """Korelasyon satirlarindan operatore 'nasil silahlanir' ipuclari."""
    tips: list[str] = []
    cve_ids = [r["cve"] for r in rows[:8]]
    if cve_ids:
        tips.append(f"nuclei ile dogrula: --arg cve_id={','.join(cve_ids[:5])}")
    msf = [r for r in rows if r["msf_module"]]
    if msf:
        top = msf[0]
        tips.append(f"msf modulu: --arg module={top['msf_module']} "
                    f"(exploit_run, --allow-destructive + scope destructive)")
    if any(r["sqli"] for r in rows):
        tips.append("SQLi sinifi CVE: sqlmap icin --arg verify=1 (tespit) / dump=1 (cekme)")
    return tips
