"""Besleme olaylari ve akis (stream) altyapisi.

Canli akisin omurgasi: beslemeler yeni bir sey gorunce buraya bir
`FeedEvent` yazar. Olaylar `~/.kalkan/feeds/events.jsonl` dosyasina
append edilir (NDJSON, her satir bir olay). `kalkan feed stream`
bu dosyayi `tail -f` gibi takip edip stdout'a basar; baska surecler
de ayni dosyayi okuyabilir.

Neden JSONL + dosya: en dusuk bagimlilik, surecler-arasi, Windows'ta
sorunsuz, dayanikli (ag kesilse de olay kaybolmaz). Daha sofistike
tasima (SSE/webhook) `Sink` arayuzuyle ustune eklenebilir.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

DEFAULT_HOME = Path.home() / ".kalkan" / "feeds"



def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class FeedEvent:
    kind: str
    source: str
    ts: str = field(default_factory=lambda: _now().isoformat(timespec="seconds"))
    id: str = ""
    title: str = ""
    priority: float = 0.0
    tier: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, line: str) -> "FeedEvent":
        obj = json.loads(line)
        return cls(
            kind=obj.get("kind", ""),
            source=obj.get("source", ""),
            ts=obj.get("ts", ""),
            id=obj.get("id", ""),
            title=obj.get("title", ""),
            priority=float(obj.get("priority", 0.0)),
            tier=obj.get("tier", ""),
            data=obj.get("data", {}) or {},
        )


class Sink:
    """Bir olay hedefinin arayuzu."""

    def emit(self, event: FeedEvent) -> None:  # pragma: no cover - arayuz
        raise NotImplementedError


class JsonlSink(Sink):
    """Olaylari NDJSON olarak dosyaya append eder (varsayilan akis kaynagi).

    Dosya `max_bytes`'i asinca basit bir dondurme (rotate) yapar:
    events.jsonl -> events.1.jsonl. Boylece disk sinirsiz buyumez.
    """

    def __init__(self, path: str | Path | None = None, max_bytes: int = 5_000_000):
        self.path = Path(path) if path else DEFAULT_HOME / "events.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes

    def emit(self, event: FeedEvent) -> None:
        self._rotate_if_needed()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(event.to_json() + "\n")

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                backup = self.path.with_suffix(".1.jsonl")
                if backup.exists():
                    backup.unlink()
                self.path.rename(backup)
        except OSError:
            pass

    def tail(self, limit: int = 20) -> list[FeedEvent]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out: list[FeedEvent] = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(FeedEvent.from_json(line))
            except (ValueError, json.JSONDecodeError):
                continue
        return out

    def follow(
        self,
        from_start: bool = False,
        poll_s: float = 1.0,
        stop: Callable[[], bool] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Iterator[FeedEvent]:
        """`tail -f` benzeri: dosyaya eklenen her yeni olayi uretir.

        Dondurme (rotate) olursa ofseti sifirlar. `stop()` True donunce
        durur; verilmezse sonsuza dek takip eder (KeyboardInterrupt ile
        kesilir).
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        offset = 0 if from_start else self.path.stat().st_size
        while True:
            if stop is not None and stop():
                return
            try:
                size = self.path.stat().st_size
            except OSError:
                size = 0
            if size < offset:
                offset = 0
            if size > offset:
                with self.path.open("r", encoding="utf-8") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
                    offset = fh.tell()
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield FeedEvent.from_json(line)
                    except (ValueError, json.JSONDecodeError):
                        continue
            else:
                sleep(poll_s)


class StdoutSink(Sink):
    """Olaylari dogrudan stdout'a NDJSON olarak basar."""

    def __init__(self, stream: Any = None):
        import sys
        self.stream = stream or sys.stdout

    def emit(self, event: FeedEvent) -> None:
        self.stream.write(event.to_json() + "\n")
        self.stream.flush()


class WebhookSink(Sink):
    """Olaylari yapilandirilmis bir URL'ye POST eder (Slack/Discord/kendi).

    Yalnizca `min_tier` ve ustu olaylari gonderir (gurultuyu kesmek icin).
    Ag hatasi olayi dusurur ama daemon'u cokertmez.
    """

    _TIER_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, url: str, min_tier: str = "high", timeout: int = 15):
        self.url = url
        self.min_tier = min_tier
        self.timeout = timeout

    def emit(self, event: FeedEvent) -> None:
        if self._TIER_RANK.get(event.tier, 0) < self._TIER_RANK.get(self.min_tier, 0):
            if event.kind not in ("cve.kev",):
                return
        payload = json.dumps(asdict(event), ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "kalkan-feeds/1.0"},
        )
        try:
            urllib.request.urlopen(req, timeout=self.timeout).close()
        except (urllib.error.URLError, OSError, TimeoutError):
            pass


class FanOut(Sink):
    """Birden cok sinke ayni anda yayinlar."""

    def __init__(self, *sinks: Sink):
        self.sinks = [s for s in sinks if s is not None]

    def emit(self, event: FeedEvent) -> None:
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception:  # noqa: BLE001 - bir sink digerlerini dusurmesin
                continue
