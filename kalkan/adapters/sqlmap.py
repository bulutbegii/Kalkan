"""sqlmap adaptoru - SQL enjeksiyonu dogrulama (T1190).

Varsayilan mod *tespit*: `--batch --smart --level 1 --risk 1`.
Veri cekme (`--dump`) veya isletim sistemi komutu (`--os-shell`)
bilincli olarak yok; bunlar ayri ve yikici sayilir. Amac "var mi"
sorusunu kanitlamak, veriyi almak degil.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from ._common import temp_file
from .base import Adapter

_INJECTION_RE = re.compile(
    r"Parameter:\s*(?P<param>[^\s(]+).*?(?:\n|$).*?Type:\s*(?P<type>[^\n]+)",
    re.IGNORECASE | re.DOTALL,
)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>[^\n]+)", re.IGNORECASE)
_TECH_RE = re.compile(r"Type:\s*(?P<type>[^\n]+)", re.IGNORECASE)


class SqlmapAdapter(Adapter):
    spec = ToolSpec(
        name="sqlmap",
        capabilities=("sqli_check",),
        risk=Risk.INTRUSIVE,
        binary="sqlmap",
        description="SQL enjeksiyonu tespiti (varsayilan: yalnizca dogrulama, veri cekmez)",
    )

    def __init__(self) -> None:
        self._out: Any = None

    def prepare(self, action: Action) -> None:
        if self._out is None:
            self._out = temp_file("sqlmap-", ".log")

    def cleanup(self) -> None:
        if self._out is not None and getattr(self._out, "exists", lambda: False)():
            try:
                self._out.unlink()
            except OSError:
                pass
        self._out = None

    def command(self, action: Action) -> list[str]:
        args = action.args
        cmd = [
            "sqlmap",
            "-u",
            str(action.target),
            "--batch",
            "--smart",
            "--level",
            str(args.get("level", 1)),
            "--risk",
            str(args.get("risk", 1)),
            "--threads",
            "1",
            "--timeout",
            str(args.get("timeout", 10)),
            "--retries",
            "0",
            "--disable-coloring",
        ]
        if args.get("data"):
            cmd += ["--data", str(args["data"])]
        if args.get("cookie"):
            cmd += ["--cookie", str(args["cookie"])]
        if args.get("param"):
            cmd += ["-p", str(args["param"])]
        if args.get("forms", True):
            cmd += ["--forms"]
        if args.get("crawl"):
            cmd += ["--crawl", str(args["crawl"])]
        if args.get("random_agent", True):
            cmd += ["--random-agent"]
        return cmd

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        text = stdout or ""
        vulnerable = bool(re.search(r"is vulnerable|injectable", text, re.IGNORECASE))
        parameters: list[dict[str, Any]] = []
        for match in _INJECTION_RE.finditer(text):
            parameters.append(
                {
                    "parameter": match.group("param").strip(),
                    "type": " ".join(match.group("type").split()),
                }
            )
        seen: set[tuple[str, str]] = set()
        unique: list[dict[str, Any]] = []
        for item in parameters:
            key = (item["parameter"], item["type"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        dbms_match = _DBMS_RE.search(text)
        findings = [
            {
                "parameter": item["parameter"],
                "type": item["type"],
                "severity": "critical" if "stacked" in item["type"].lower() else "high",
                "detail": f"SQL enjeksiyonu: {item['type']}",
            }
            for item in unique
        ]
        return {
            "vulnerable": vulnerable,
            "dbms": dbms_match.group("dbms").strip() if dbms_match else "",
            "parameters": unique,
            "findings": findings,
            "count": len(findings),
            "note": "veri cekme kapali; yalnizca dogrulama yapildi",
        }
