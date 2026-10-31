"""Adaptor kayit defteri.

Her adaptor kendi ToolSpec'ini ilan eder. Binary gerektirenler
kurulu degilse `unavailable` doner; yerlesik olanlar (webprobe,
llmprobe) her zaman calisir.
"""

from __future__ import annotations

from ..registry import Registry
from .arjun import ArjunAdapter
from .browser import BrowserAdapter
from .dalfox import DalfoxAdapter
from .ffuf import FfufAdapter
from .httpx import HttpxAdapter
from .llmprobe import LlmProbeAdapter
from .msf import MetasploitAdapter
from .nikto import NiktoAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .shodan import ShodanAdapter
from .sqlmap import SqlmapAdapter
from .wafw00f import Wafw00fAdapter
from .webprobe import WebProbeAdapter

__all__ = [
    "NmapAdapter",
    "NucleiAdapter",
    "ShodanAdapter",
    "MetasploitAdapter",
    "LlmProbeAdapter",
    "WebProbeAdapter",
    "FfufAdapter",
    "HttpxAdapter",
    "NiktoAdapter",
    "SqlmapAdapter",
    "DalfoxAdapter",
    "ArjunAdapter",
    "Wafw00fAdapter",
    "BrowserAdapter",
    "load_default_registry",
]

_ADAPTERS = (
    NmapAdapter,
    NucleiAdapter,
    ShodanAdapter,
    MetasploitAdapter,
    LlmProbeAdapter,
    WebProbeAdapter,
    FfufAdapter,
    HttpxAdapter,
    NiktoAdapter,
    SqlmapAdapter,
    DalfoxAdapter,
    ArjunAdapter,
    Wafw00fAdapter,
    BrowserAdapter,
)


def load_default_registry() -> Registry:
    registry = Registry()
    for cls in _ADAPTERS:
        registry.register(cls())
    return registry
