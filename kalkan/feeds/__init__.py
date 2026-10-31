"""Canli besleme katmani: ATT&CK/ATLAS + CVE/CVSS/KEV/EPSS.

Bilesenler:
  * events    -> FeedEvent + sinkler (JSONL/stdout/webhook) + `tail -f`
  * scheduler -> FeedDaemon: beslemeleri bagimsiz periyotlarda tazeler,
                 olay yayinlar, CWE->ATT&CK koprUsunu uygular
  * suggest   -> canli CVE'lerden router/planner icin teknik onerisi

CLI: `kalkan feed {run,start,stop,status,stream,tail}`.
"""

from .events import (
    DEFAULT_HOME,
    FanOut,
    FeedEvent,
    JsonlSink,
    Sink,
    StdoutSink,
    WebhookSink,
)
from .scheduler import FeedConfig, FeedDaemon
from .suggest import Suggestion, suggest_for_text, techniques_from_suggestions

__all__ = [
    "DEFAULT_HOME",
    "FeedEvent",
    "Sink",
    "JsonlSink",
    "StdoutSink",
    "WebhookSink",
    "FanOut",
    "FeedConfig",
    "FeedDaemon",
    "Suggestion",
    "suggest_for_text",
    "techniques_from_suggestions",
]
