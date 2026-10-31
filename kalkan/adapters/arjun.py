"""arjun adaptoru - gizli HTTP parametre kesfi.

Gorunmeyen parametreler (`?debug=1`, `?admin=true` gibi) cogu zaman
yetki atlatmanin kapisidir. arjun bunlari sozluk + sezgisel ile bulur.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from ._common import temp_file, wordlist
from .base import Adapter


class ArjunAdapter(Adapter):
    spec = ToolSpec(
        name="arjun",
        capabilities=("param_discovery",),
        risk=Risk.ACTIVE,
        binary="arjun",
        description="Gizli HTTP parametre kesfi (yetki atlatma yuzeyi)",
    )

    def __init__(self) -> None:
        self._out: Path | None = None

    def _outfile(self, action: Action) -> Path:
        if action.args.get("output"):
            return Path(str(action.args["output"]))
        if self._out is None:
            self._out = temp_file("arjun-", ".json")
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
            "arjun",
            "-u",
            str(action.target),
            "-oJ",
            str(self._outfile(action)),
            "-q",
        ]
        if args.get("wordlist"):
            cmd += ["-w", str(args["wordlist"])]
        else:
            cmd += ["-w", wordlist("params.txt")]
        if args.get("method"):
            cmd += ["-m", str(args["method"]).upper()]
        if args.get("headers"):
            cmd += ["--headers", str(args["headers"])]
        if args.get("stable"):
            cmd += ["--stable"]
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
        if isinstance(raw, dict):
            for url, params in raw.items():
                if not isinstance(params, list):
                    continue
                for param in params:
                    findings.append(
                        {
                            "url": url,
                            "parameter": param,
                            "severity": "medium",
                            "detail": f"Gizli parametre kabul ediliyor: {param}",
                        }
                    )
        return {
            "findings": findings,
            "count": len(findings),
            "parameters": [f["parameter"] for f in findings],
        }
