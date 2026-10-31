"""CVE / CVSS / EPSS / KEV istihbarat katmani.

Neden var: zafiyet tarayicisinin urettigi CVE kimligi tek basina karar
vermeye yetmez. Bu modul dort kaynagi birlestirir:

  * NVD 2.0        -> CVSS v3.1/v4.0 vektoru, CWE, referanslar
  * CISA KEV       -> sahada somuruldugu dogrulanmis zafiyetler
  * FIRST EPSS     -> 30 gun icinde somurulme olasiligi
  * yerel oncelik  -> yukaridakileri tek 0-100 skora indirger

Hepsi stdlib. Veri `~/.kalkan/vuln/` altinda onbelleklenir; boylece
ag kesildiginde de son bilinen durumla degerlendirme yapilabilir.

Surekli izleme: `VulnStore.watch()` yeni kayitlari dondurur; CLI
`kalkan vuln watch` bunu dongude calistirir.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from . import cvss

DEFAULT_HOME = Path.home() / ".kalkan" / "vuln"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API = "https://api.first.org/data/v1/epss"
USER_AGENT = "kalkan-vuln-intel/1.0 (+local defensive tooling)"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def http_json(url: str, timeout: int = 60, retries: int = 3) -> Any:
    """Kucuk, bagimliliksiz HTTP JSON istemcisi (geri cekilmeli)."""
    delay = 2.0
    last: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code in (403, 429, 503) and attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError(f"istek basarisiz: {url} ({last})")


@dataclass
class CveRecord:
    id: str
    published: str = ""
    modified: str = ""
    status: str = ""
    description: str = ""
    cvss_version: str = ""
    base_score: float = 0.0
    severity: str = ""
    vector: str = ""
    cwe: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    exploit_refs: int = 0
    kev: bool = False
    kev_added: str = ""
    kev_due: str = ""
    ransomware: str = ""
    vendor: str = ""
    product: str = ""
    epss: float = 0.0
    epss_percentile: float = 0.0
    epss_date: str = ""

    def age_days(self, reference: datetime | None = None) -> int:
        published = _parse_dt(self.published)
        if not published:
            return 3650
        ref = _now() if reference is None else reference
        if published.tzinfo is None and ref.tzinfo is not None:
            published = published.replace(tzinfo=timezone.utc)
        elif published.tzinfo is not None and ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        return max(0, (ref - published).days)

    def score(self) -> float:
        """0-100 oncelik skoru.

        Agirliklar bilincli: somuru kaniti (KEV) ve EPSS, ham CVSS'ten
        daha onemli. Cok yeni ama hic somurulmemis bir CVE, eski ama
        KEV'de olan bir CVE'nin onune gecmemeli.
        """
        value = 0.0
        value += min(self.base_score, 10.0) * 5.0
        value += 25.0 if self.kev else 0.0
        value += min(self.epss, 1.0) * 15.0
        value += min(self.exploit_refs, 3) * 1.5
        value += max(0.0, 10.0 - self.age_days() / 4.0)
        return round(min(value, 100.0), 1)

    def tier(self) -> str:
        s = self.score()
        if s >= 80:
            return "critical"
        if s >= 60:
            return "high"
        if s >= 40:
            return "medium"
        if s >= 20:
            return "low"
        return "info"

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "base_score": self.base_score,
            "severity": self.severity,
            "vector": self.vector,
            "kev": self.kev,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "priority": self.score(),
            "tier": self.tier(),
            "published": self.published,
            "vendor": self.vendor,
            "product": self.product,
            "description": self.description[:300],
        }


def _pick_metric(metrics: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = next((i for i in items if i.get("type") == "Primary"), items[0])
        data = primary.get("cvssData") or {}
        if data.get("baseScore") is not None:
            return key, data
    return "", {}


def parse_nvd_item(item: dict[str, Any]) -> CveRecord | None:
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = ""
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            description = entry.get("value", "")
            break
    if not description and cve.get("descriptions"):
        description = cve["descriptions"][0].get("value", "")

    metric_key, data = _pick_metric(cve.get("metrics") or {})
    version = str(data.get("version") or "")
    if not version:
        version = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV40": "4.0", "cvssMetricV2": "2.0"}.get(metric_key, "")
    base = float(data.get("baseScore") or 0.0)
    vector = str(data.get("vectorString") or "")
    severity_label = str(data.get("baseSeverity") or "").lower()

    if vector and not base:
        try:
            base = cvss.base_score(vector)
            severity_label = cvss.severity(base)
        except cvss.CvssError:
            pass
    if not severity_label and base:
        severity_label = cvss.severity(base)

    cwe: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwe.append(value)

    refs = [r.get("url", "") for r in cve.get("references") or [] if r.get("url")]
    exploit_refs = sum(
        1
        for r in cve.get("references") or []
        if any(str(t).lower() in ("exploit", "third party advisory") for t in r.get("tags") or [])
    )

    vendor, product = "", ""
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    break
            if product:
                break
        if product:
            break

    return CveRecord(
        id=cve_id,
        published=str(cve.get("published") or ""),
        modified=str(cve.get("lastModified") or ""),
        status=str(cve.get("vulnStatus") or ""),
        description=description,
        cvss_version=version,
        base_score=base,
        severity=severity_label,
        vector=vector,
        cwe=tuple(dict.fromkeys(cwe)),
        references=tuple(refs),
        exploit_refs=exploit_refs,
        vendor=vendor,
        product=product,
    )


def parse_kev(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in payload.get("vulnerabilities") or []:
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        out[cve_id] = {
            "kev_added": item.get("dateAdded", ""),
            "kev_due": item.get("dueDate", ""),
            "ransomware": item.get("knownRansomwareCampaignUse", ""),
            "vendor": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "name": item.get("vulnerabilityName", ""),
        }
    return out


def parse_epss(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in payload.get("data") or []:
        cve_id = item.get("cve")
        if not cve_id:
            continue
        out[cve_id] = {
            "epss": float(item.get("epss") or 0.0),
            "epss_percentile": float(item.get("percentile") or 0.0),
            "epss_date": item.get("date", ""),
        }
    return out


class VulnStore:
    def __init__(self, home: str | Path | None = None):
        self.home = Path(home) if home else DEFAULT_HOME
        self.home.mkdir(parents=True, exist_ok=True)
        self.cves: dict[str, CveRecord] = {}
        self.kev: dict[str, dict[str, Any]] = {}
        self.epss: dict[str, dict[str, Any]] = {}
        self.meta: dict[str, Any] = {}
        self.load()

    @property
    def _cves_path(self) -> Path:
        return self.home / "cves.json"

    @property
    def _kev_path(self) -> Path:
        return self.home / "kev.json"

    @property
    def _epss_path(self) -> Path:
        return self.home / "epss.json"

    @property
    def _meta_path(self) -> Path:
        return self.home / "meta.json"

    def load(self) -> None:
        if self._cves_path.exists():
            raw = json.loads(self._cves_path.read_text(encoding="utf-8"))
            for cve_id, data in raw.items():
                try:
                    self.cves[cve_id] = CveRecord(**data)
                except TypeError:
                    continue
        if self._kev_path.exists():
            self.kev = json.loads(self._kev_path.read_text(encoding="utf-8"))
        if self._epss_path.exists():
            self.epss = json.loads(self._epss_path.read_text(encoding="utf-8"))
        if self._meta_path.exists():
            self.meta = json.loads(self._meta_path.read_text(encoding="utf-8"))

    def save(self) -> None:
        self._cves_path.write_text(
            json.dumps({k: asdict(v) for k, v in self.cves.items()}, ensure_ascii=False),
            encoding="utf-8",
        )
        self._kev_path.write_text(json.dumps(self.kev, ensure_ascii=False), encoding="utf-8")
        self._epss_path.write_text(json.dumps(self.epss, ensure_ascii=False), encoding="utf-8")
        self._meta_path.write_text(json.dumps(self.meta, ensure_ascii=False, indent=2), encoding="utf-8")

    def sync(
        self,
        days: int = 30,
        keyword: str | None = None,
        max_pages: int = 5,
        with_kev: bool = True,
        with_epss: bool = True,
        progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """NVD'den son `days` gunun CVE'lerini cek, KEV/EPSS ile birlestir."""
        say = progress or (lambda _msg: None)
        end = _now()
        start = end - timedelta(days=max(1, days))

        params: dict[str, str] = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "resultsPerPage": "2000",
        }
        if keyword:
            params["keywordSearch"] = keyword

        seen_before = set(self.cves)
        added = 0
        fetched = 0
        for page in range(max_pages):
            params["startIndex"] = str(page * 2000)
            url = NVD_API + "?" + urllib.parse.urlencode(params)
            say(f"NVD sayfa {page + 1}: {url}")
            payload = http_json(url, timeout=90)
            items = payload.get("vulnerabilities") or []
            if not items:
                break
            for item in items:
                record = parse_nvd_item(item)
                if record is None:
                    continue
                fetched += 1
                if record.id not in self.cves:
                    added += 1
                self.cves[record.id] = record
            total = int(payload.get("totalResults") or 0)
            if (page + 1) * 2000 >= total:
                break
            time.sleep(0.7 if os.environ.get("NVD_API_KEY") else 6.0)

        if with_kev:
            say("CISA KEV indiriliyor")
            self.kev = parse_kev(http_json(KEV_URL, timeout=90))
            self.meta["kev_synced"] = _iso(_now())
            self.meta["kev_count"] = len(self.kev)

        if with_epss:
            ids = list(self.cves)[:4000]
            say(f"EPSS sorgusu: {len(ids)} CVE")
            merged = 0
            for i in range(0, len(ids), 100):
                chunk = ids[i : i + 100]
                url = EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
                try:
                    merged += len(parse_epss(http_json(url, timeout=60)))
                except Exception as exc:
                    say(f"EPSS atlandi: {exc}")
                    break
            if merged:
                self.meta["epss_synced"] = _iso(_now())

        for cve_id, record in self.cves.items():
            kev = self.kev.get(cve_id)
            if kev:
                record.kev = True
                record.kev_added = kev.get("kev_added", "")
                record.kev_due = kev.get("kev_due", "")
                record.ransomware = kev.get("ransomware", "")
                if not record.vendor:
                    record.vendor = kev.get("vendor", "")
                if not record.product:
                    record.product = kev.get("product", "")
            epss = self.epss.get(cve_id)
            if epss:
                record.epss = epss.get("epss", 0.0)
                record.epss_percentile = epss.get("epss_percentile", 0.0)
                record.epss_date = epss.get("epss_date", "")

        self.meta["cves_synced"] = _iso(_now())
        self.meta["cve_count"] = len(self.cves)
        self.meta["window_days"] = days
        self.save()

        new_ids = [c for c in self.cves if c not in seen_before]
        return {
            "fetched": fetched,
            "added": added,
            "new": new_ids,
            "total": len(self.cves),
            "kev": len(self.kev),
            "synced_at": self.meta["cves_synced"],
        }

    def refresh_kev(self) -> int:
        self.kev = parse_kev(http_json(KEV_URL, timeout=90))
        for cve_id, record in self.cves.items():
            kev = self.kev.get(cve_id)
            if kev:
                record.kev = True
                record.kev_added = kev.get("kev_added", "")
                record.kev_due = kev.get("kev_due", "")
                record.ransomware = kev.get("ransomware", "")
        self.meta["kev_synced"] = _iso(_now())
        self.meta["kev_count"] = len(self.kev)
        self.save()
        return len(self.kev)

    def get(self, cve_id: str) -> CveRecord | None:
        return self.cves.get(cve_id.strip().upper())

    def records(self) -> list[CveRecord]:
        return sorted(self.cves.values(), key=lambda r: r.score(), reverse=True)

    def top(self, limit: int = 20, min_score: float = 0.0) -> list[CveRecord]:
        return [r for r in self.records() if r.score() >= min_score][:limit]

    def search(self, query: str, limit: int = 50) -> list[CveRecord]:
        q = query.strip().lower()
        if not q:
            return self.top(limit)
        hits = [
            r
            for r in self.records()
            if q in r.id.lower()
            or q in r.description.lower()
            or q in r.vendor.lower()
            or q in r.product.lower()
        ]
        return hits[:limit]

    def match(self, product: str, version: str | None = None, limit: int = 30) -> list[CveRecord]:
        """Urun/versiyon eslesmesi. Kaba ama aciklanabilir bir eslesme."""
        p = product.strip().lower()
        hits = []
        for r in self.records():
            haystack = f"{r.vendor} {r.product} {r.description}".lower()
            if p and p not in haystack:
                continue
            if version and version.lower() not in r.description.lower():
                continue
            hits.append(r)
            if len(hits) >= limit:
                break
        return hits

    def stats(self) -> dict[str, Any]:
        records = list(self.cves.values())
        by_sev: dict[str, int] = {}
        for r in records:
            by_sev[r.severity or "unknown"] = by_sev.get(r.severity or "unknown", 0) + 1
        return {
            "home": str(self.home),
            "cve_count": len(records),
            "kev_count": len(self.kev),
            "epss_count": len(self.epss),
            "by_severity": dict(sorted(by_sev.items())),
            "cves_synced": self.meta.get("cves_synced", ""),
            "kev_synced": self.meta.get("kev_synced", ""),
            "epss_synced": self.meta.get("epss_synced", ""),
            "critical": sum(1 for r in records if r.tier() == "critical"),
            "high": sum(1 for r in records if r.tier() == "high"),
            "kev_in_store": sum(1 for r in records if r.kev),
        }

    def enrich(self, cve_id: str) -> dict[str, Any] | None:
        record = self.get(cve_id)
        if record is None:
            return None
        out = record.summary()
        out["cwe"] = list(record.cwe)
        out["references"] = list(record.references[:5])
        out["ransomware"] = record.ransomware
        out["kev_due"] = record.kev_due
        out["epss_date"] = record.epss_date
        try:
            assessment = cvss.assess(
                record.vector, fallback_score=record.base_score, fallback_severity=record.severity
            )
            out["cvss_explain"] = assessment.explain()
        except cvss.CvssError:
            out["cvss_explain"] = [f"vector yok/gecersiz: {record.vector!r}"]
        return out

    def enrich_findings(self, findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Tarayici bulgularindaki CVE'leri yerel istihbaratla zenginlestir."""
        enriched = []
        for finding in findings:
            item = dict(finding)
            cve_id = item.get("cve")
            if isinstance(cve_id, list):
                cve_id = cve_id[0] if cve_id else None
            if cve_id:
                intel = self.enrich(str(cve_id))
                if intel:
                    item["cve_intel"] = intel
            enriched.append(item)
        return enriched

    def watch(
        self,
        interval_s: int = 3600,
        days: int = 1,
        once: bool = False,
        max_cycles: int | None = None,
        on_cycle: Callable[[dict[str, Any]], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Periyodik senkron. `once=True` tek tur calisir (test/CI icin)."""
        cycle = 0
        while True:
            cycle += 1
            result = self.sync(days=days, max_pages=2)
            if on_cycle:
                on_cycle(result)
            if once or (max_cycles is not None and cycle >= max_cycles):
                return
            sleep(max(30, interval_s))
