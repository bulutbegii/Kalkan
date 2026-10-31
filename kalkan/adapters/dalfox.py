"""dalfox adaptoru - XSS dogrulama (T1059.007 destegi).

Yalnizca parametre/URL uzerinde *kanit* arar (reflected/stored XSS).
Tarayici otomasyonu (`--deep-domxss`) varsayilan kapali; yavas ve
gurultulu. Bulgular `--format json` ciktisindan okunur.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from ._common import temp_file
from .base import Adapter


class DalfoxAdapter(Adapter):
    spec = ToolSpec(
        name="dalfox",
        capabilities=("xss_scan",),
        risk=Risk.INTRUSIVE,
        binary="dalfox",
        description="XSS tarayicisi/dogrulayicisi (reflected, stored)",
    )

    def __init__(self) -> None:
        self._out: Path | None = None

    def _outfile(self, action: Action) -> Path:
        if action.args.get("output"):
            return Path(str(action.args["output"]))
        if self._out is None:
            self._out = temp_file("dalfox-", ".json")
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
        args = action.args
        cmd = [
            "dalfox",
            "url",
            str(action.target),
            "--silence",
            "--no-color",
            "--format",
            "json",
            "--output",
            str(self._outfile(action)),
        ]
        if args.get("method"):
            cmd += ["--method", str(args["method"]).upper()]
        if args.get("data"):
            cmd += ["--data", str(args["data"])]
        if args.get("cookie"):
            cmd += ["--cookie", str(args["cookie"])]
        if args.get("deep_domxss"):
            cmd += ["--deep-domxss"]
        if args.get("workers"):
            cmd += ["--workers", str(args["workers"])]
        if args.get("blind"):
            cmd += ["--blind", str(args["blind"])]
        return cmd

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        out = self._outfile(action)
        text = ""
        if out.exists():
            try:
                text = out.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
        findings: list[dict[str, Any]] = []
        if text.strip():
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                payload = [payload]
            if isinstance(payload, list):
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    findings.append(
                        {
                            "type": item.get("type", "XSS"),
                            "method": item.get("method", ""),
                            "url": item.get("data", "") or item.get("url", ""),
                            "parameter": item.get("param", ""),
                            "payload": item.get("payload", ""),
                            "evidence": item.get("evidence", ""),
                            "severity": "high",
                            "detail": f"{item.get('type', 'XSS')} @ {item.get('param', '?')}",
                        }
                    )
        return {
            "findings": findings,
            "count": len(findings),
            "by_severity": {"high": len(findings)} if findings else {},
            "vulnerable": bool(findings),
        }
