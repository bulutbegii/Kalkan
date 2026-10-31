"""nikto adaptoru - web sunucu yanlis yapilandirma taramasi.

Yerlesik webprobe baslik/CORS gibi *kanitlanabilir* kontroller yapar;
nikto ise bilinen dosya/surum/CGI imzalarini dener. Ikisi bilincli
olarak ayri tutuldu: biri kesin, digeri genis ama gurultulu.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from ._common import temp_file
from .base import Adapter


class NiktoAdapter(Adapter):
    spec = ToolSpec(
        name="nikto",
        capabilities=("web_misconfig",),
        risk=Risk.ACTIVE,
        binary="nikto",
        description="Web sunucu yanlis yapilandirma/versiyon tarayicisi",
    )

    def __init__(self) -> None:
        self._out: Path | None = None

    def _outfile(self, action: Action) -> Path:
        if action.args.get("output"):
            return Path(str(action.args["output"]))
        if self._out is None:
            self._out = temp_file("nikto-", ".json")
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
            "nikto",
            "-h",
            str(action.target),
            "-Format",
            "json",
            "-output",
            str(self._outfile(action)),
            "-nointeractive",
        ]
        if args.get("tuning"):
            cmd += ["-Tuning", str(args["tuning"])]
        if args.get("maxtime"):
            cmd += ["-maxtime", f"{args['maxtime']}s"]
        if args.get("ssl"):
            cmd += ["-ssl"]
        return cmd

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        out = self._outfile(action)
        findings: list[dict[str, Any]] = []
        raw: Any = None
        if out.exists():
            try:
                raw = json.loads(out.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                raw = None
        if isinstance(raw, dict):
            for host in raw.get("host") or []:
                hostname = host.get("host", "")
                for item in host.get("vulnerabilities") or []:
                    findings.append(
                        {
                            "host": hostname,
                            "id": item.get("id", ""),
                            "method": item.get("method", "GET"),
                            "url": item.get("url", ""),
                            "msg": item.get("msg", ""),
                            "severity": _guess_severity(item.get("msg", "")),
                            "references": item.get("references", ""),
                        }
                    )
        by_sev: dict[str, int] = {}
        for finding in findings:
            by_sev[finding["severity"]] = by_sev.get(finding["severity"], 0) + 1
        return {"findings": findings, "count": len(findings), "by_severity": by_sev}


def _guess_severity(message: str) -> str:
    """nikto seviye vermez; metinden kaba bir onem cikar."""
    text = (message or "").lower()
    if any(k in text for k in ("remote code", "rce", "sql injection", "authentication bypass", "default password")):
        return "high"
    if any(k in text for k in ("xss", "cross site", "traversal", "file inclusion", "disclosure", "outdated")):
        return "medium"
    if any(k in text for k in ("header", "cookie", "information", "allowed http methods")):
        return "low"
    return "info"
