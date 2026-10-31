"""wafw00f adaptoru - WAF/CDN tespiti.

Neden onemli: WAF varsa payload secimi ve istek hizi degismeli.
Yoksa dogrudan uygulama katmanina gidiliyor demektir. Pasif sayilir
(tek parmak izi istegi).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from ._common import temp_file
from .base import Adapter

_DETECTED_RE = re.compile(r"is behind (?P<waf>[A-Za-z0-9 ._+-]+?)(?: WAF)?\.?$", re.IGNORECASE)


class Wafw00fAdapter(Adapter):
    spec = ToolSpec(
        name="wafw00f",
        capabilities=("waf_detect",),
        risk=Risk.PASSIVE,
        binary="wafw00f",
        description="WAF/CDN parmak izi tespiti",
    )

    def __init__(self) -> None:
        self._out: Path | None = None

    def _outfile(self, action: Action) -> Path:
        if action.args.get("output"):
            return Path(str(action.args["output"]))
        if self._out is None:
            self._out = temp_file("wafw00f-", ".json")
        return self._out

    def prepare(self, action: Action) -> None:
        self._outfile(action)

    def cleanup(self) -> None:
        if self._out and self._out.exists():
            try:
                self._out.unlink()
            except OSError:
                pass
        self._out = None

    def command(self, action: Action) -> list[str]:
        cmd = [
            "wafw00f",
            str(action.target),
            "-o",
            str(self._outfile(action)),
            "-f",
            "json",
        ]
        if action.args.get("no_group"):
            cmd += ["-a"]
        return cmd

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        out = self._outfile(action)
        raw: Any = None
        if out.exists():
            try:
                raw = json.loads(out.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                raw = None
        findings: list[dict[str, Any]] = []
        detected: list[str] = []
        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue
                if item.get("detected"):
                    name = item.get("firewall", "") or item.get("manufacturer", "")
                    if name:
                        detected.append(name)
                    findings.append(
                        {
                            "check": "waf_detected",
                            "severity": "info",
                            "detail": f"WAF/CDN: {name or 'bilinmiyor'}",
                            "url": item.get("url", ""),
                            "manufacturer": item.get("manufacturer", ""),
                        }
                    )
        if not findings:
            for match in _DETECTED_RE.finditer(stdout or ""):
                name = match.group("waf").strip()
                if name:
                    detected.append(name)
                    findings.append(
                        {"check": "waf_detected", "severity": "info", "detail": f"WAF/CDN: {name}"}
                    )
        return {
            "findings": findings,
            "count": len(findings),
            "detected": sorted(set(detected)),
            "protected": bool(detected),
        }
