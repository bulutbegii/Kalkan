"""Besleme zamanlayicisi (daemon).

Tek bir dongu, uc beslemeyi BAGIMSIZ periyotlarda tazeler:
  * vuln   (NVD + CISA KEV + FIRST EPSS)  -> varsayilan saatte bir
  * attack (MITRE ATT&CK STIX)            -> varsayilan haftada bir
  * atlas  (MITRE ATLAS STIX)             -> varsayilan haftada bir

Her tur icinde "vadesi gelen" beslemeler calistirilir; sonra bir sonraki
vadeye kadar uyunur. Mevcut bloklayan `VulnStore.watch()`'in aksine bu
daemon olay YAYINLAR: yeni/KEV/kritik CVE'ler `events.jsonl`'e dusier ve
her CVE icin CWE->ATT&CK koprUsu (bridge) eklenir. Boylece akistan dusen
bir CVE dogrudan bir teknik/playbook'a baglanir.

Durum `~/.kalkan/feeds/state.json`'a yazilir (son senkronlar, sayimlar,
pid). `kalkan feed status` bunu okur.

Stdlib-only. Tasima/arka plan ayrintilarini CLI yonetir; burasi saf
mantik ve test edilebilir (`run(max_cycles=...)`, enjekte edilebilir
`sleep` ve `clock`).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..knowledge import bridge
from ..knowledge.attack import AttackKnowledge
from ..knowledge.atlas import AtlasKnowledge
from ..knowledge.vuln import VulnStore
from .events import DEFAULT_HOME, FanOut, FeedEvent, JsonlSink, Sink


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass
class FeedConfig:
    """Besleme periyotlari ve esikler (saniye)."""

    vuln_interval: int = 3600
    attack_interval: int = 7 * 86400
    atlas_interval: int = 7 * 86400
    vuln_days: int = 1
    vuln_max_pages: int = 2
    with_kev: bool = True
    with_epss: bool = True
    critical_score: float = 60.0
    max_events_per_cycle: int = 200

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_interval": self.vuln_interval,
            "attack_interval": self.attack_interval,
            "atlas_interval": self.atlas_interval,
            "vuln_days": self.vuln_days,
            "with_kev": self.with_kev,
            "with_epss": self.with_epss,
            "critical_score": self.critical_score,
        }


class FeedDaemon:
    def __init__(
        self,
        config: FeedConfig | None = None,
        home: str | Path | None = None,
        sink: Sink | None = None,
        store: VulnStore | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config or FeedConfig()
        self.home = Path(home) if home else DEFAULT_HOME
        self.home.mkdir(parents=True, exist_ok=True)
        self.sink = sink or JsonlSink(self.home / "events.jsonl")
        self.store = store if store is not None else VulnStore()
        self.clock = clock
        self.sleep = sleep
        self._last_run: dict[str, float] = {}

    @property
    def state_path(self) -> Path:
        return self.home / "state.json"

    @property
    def pid_path(self) -> Path:
        return self.home / "daemon.pid"

    def _read_state(self) -> dict[str, Any]:
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                return {}
        return {}

    def _write_state(self, **updates: Any) -> None:
        state = self._read_state()
        state.update(updates)
        state["updated_at"] = _iso(_now())
        try:
            self.state_path.write_text(
                json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass

    def status(self) -> dict[str, Any]:
        state = self._read_state()
        state["store"] = self.store.stats()
        state["config"] = self.config.to_dict()
        state["pid"] = self._running_pid()
        return state

    def _running_pid(self) -> int | None:
        if not self.pid_path.exists():
            return None
        try:
            pid = int(self.pid_path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return None
        return pid if _pid_alive(pid) else None

    def sync_vuln(self) -> list[FeedEvent]:
        """vuln beslemesini tazele, farkları olaya cevir."""
        events: list[FeedEvent] = []
        try:
            before = set(self.store.cves)
            result = self.store.sync(
                days=self.config.vuln_days,
                max_pages=self.config.vuln_max_pages,
                with_kev=self.config.with_kev,
                with_epss=self.config.with_epss,
            )
        except Exception as exc:  # noqa: BLE001 - ag/parse hatasi daemon'u dusurmesin
            ev = FeedEvent(kind="feed.error", source="nvd", title=str(exc)[:200])
            self._emit(ev)
            return [ev]

        new_ids = [c for c in result.get("new", []) if c not in before] or result.get("new", [])
        count = 0
        for cve_id in new_ids:
            if count >= self.config.max_events_per_cycle:
                break
            record = self.store.get(cve_id)
            if record is None:
                continue
            count += 1
            link = bridge.enrich(record, min_confidence=0.0)
            base = dict(
                id=record.id,
                source="nvd",
                title=record.description[:140],
                priority=record.score(),
                tier=record.tier(),
                data={
                    "cvss": record.base_score,
                    "severity": record.severity,
                    "vector": record.vector,
                    "cwe": list(record.cwe),
                    "kev": record.kev,
                    "epss": record.epss,
                    "product": record.product,
                    "vendor": record.vendor,
                    "attack": link,
                },
            )
            if record.kev:
                events.append(self._emit(FeedEvent(kind="cve.kev", **base)))
            elif record.score() >= self.config.critical_score:
                events.append(self._emit(FeedEvent(kind="cve.critical", **base)))
            else:
                events.append(self._emit(FeedEvent(kind="cve.new", **base)))

        summary = self._emit(FeedEvent(
            kind="feed.sync", source="nvd",
            title=f"vuln senkron: +{result.get('added', 0)} yeni / {result.get('total', 0)} toplam",
            data={k: result.get(k) for k in ("fetched", "added", "total", "kev", "synced_at")},
        ))
        events.append(summary)
        self._write_state(vuln_synced=_iso(_now()), vuln_last=result)
        return events

    def sync_knowledge(self, domain: str) -> list[FeedEvent]:
        """ATT&CK veya ATLAS STIX'ini tazele; degisiklik varsa olay yayinla."""
        try:
            if domain == "atlas":
                kb = AtlasKnowledge()
                before = kb.statistics() if kb.available else {}
                kb.fetch(force=True)
                after = kb.statistics()
                source = "atlas"
            else:
                kb = AttackKnowledge(domain=domain)
                before = {"count": len(kb)} if kb.available else {"count": 0}
                kb.fetch(force=True)
                kb._loaded = False
                after = {"count": len(kb)}
                source = "attack"
        except Exception as exc:  # noqa: BLE001
            ev = FeedEvent(kind="feed.error", source=domain, title=str(exc)[:200])
            self._emit(ev)
            return [ev]

        changed = before != after
        ev = self._emit(FeedEvent(
            kind="knowledge.updated" if changed else "feed.sync",
            source=source, id=domain,
            title=f"{domain} {'guncellendi' if changed else 'tazelendi (degisiklik yok)'}",
            data={"before": before, "after": after, "changed": changed},
        ))
        self._write_state(**{f"{domain}_synced": _iso(_now())})
        return [ev]

    def _due(self, source: str, interval: int, now: float) -> bool:
        last = self._last_run.get(source)
        return last is None or (now - last) >= interval

    def run(
        self,
        once: bool = False,
        max_cycles: int | None = None,
        write_pid: bool = True,
    ) -> dict[str, Any]:
        """Daemon dongusu. Her tur vadesi gelen beslemeleri calistirir.

        `once=True` tek tur (vuln dahil hepsini zorlar, test/CI icin).
        `max_cycles` tur sayisini sinirlar. Ikisi de yoksa sonsuz doner.
        """
        if write_pid:
            self._write_pid()
        self._write_state(started_at=_iso(_now()), config=self.config.to_dict())
        cycle = 0
        try:
            while True:
                cycle += 1
                now = self.clock()
                if once or self._due("vuln", self.config.vuln_interval, now):
                    self.sync_vuln()
                    self._last_run["vuln"] = now
                if once or self._due("attack", self.config.attack_interval, now):
                    self.sync_knowledge("enterprise")
                    self._last_run["attack"] = now
                if once or self._due("atlas", self.config.atlas_interval, now):
                    self.sync_knowledge("atlas")
                    self._last_run["atlas"] = now

                if once or (max_cycles is not None and cycle >= max_cycles):
                    break
                self.sleep(self._next_sleep(self.clock()))
        finally:
            if write_pid:
                self._clear_pid()
        return {"cycles": cycle, "last_run": dict(self._last_run)}

    def _next_sleep(self, now: float) -> float:
        """Bir sonraki vadeye kadar kac saniye uyunacagini hesapla."""
        waits = []
        for source, interval in (
            ("vuln", self.config.vuln_interval),
            ("attack", self.config.attack_interval),
            ("atlas", self.config.atlas_interval),
        ):
            last = self._last_run.get(source, now)
            waits.append(max(0.0, interval - (now - last)))
        return max(1.0, min(waits)) if waits else 60.0

    def _emit(self, event: FeedEvent) -> FeedEvent:
        self.sink.emit(event)
        return event

    def _write_pid(self) -> None:
        try:
            self.pid_path.write_text(str(os.getpid()), encoding="utf-8")
        except OSError:
            pass

    def _clear_pid(self) -> None:
        try:
            self.pid_path.unlink()
        except OSError:
            pass


def _pid_alive(pid: int) -> bool:
    """Surec yasiyor mu? (Windows + POSIX, stdlib-only, en iyi caba)."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import subprocess
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=5,
            )
            return str(pid) in out.stdout
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
