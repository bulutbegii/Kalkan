"""ffuf adaptoru - icerik/parametre kesfi (T1595.003, T1083 destegi).

ffuf hizli bir web fuzzer. Burada iki kullanim var:
  content_discovery  -> gizli dizin/dosya kesfi (FUZZ = yol)
  parameter_fuzzing  -> parametre adi kesfi (FUZZ = ?param=deger)

Cikti JSON'a yazdirilir; stdout karisik olabildigi icin dosyadan
okunur. Boylece Turkce/ANSI bozulmalarindan etkilenmeyiz.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from ._common import temp_file, wordlist
from .base import Adapter

MATCH_CODES = "200,204,301,302,307,308,401,403,405"


class FfufAdapter(Adapter):
    spec = ToolSpec(
        name="ffuf",
        capabilities=("content_discovery", "parameter_fuzzing"),
        risk=Risk.ACTIVE,
        binary="ffuf",
        description="Hizli web icerik/parametre fuzzer (gizli yol ve parametre kesfi)",
    )

    def __init__(self) -> None:
        self._out: Path | None = None

    def _outfile(self, action: Action) -> Path:
        if action.args.get("output"):
            return Path(str(action.args["output"]))
        if self._out is None:
            self._out = temp_file("ffuf-", ".json")
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
        out = self._outfile(action)
        if action.capability == "parameter_fuzzing":
            base = str(action.target).rstrip("/")
            url = f"{base}?FUZZ={args.get('value', 'kalkan')}"
            word = args.get("wordlist") or wordlist("params.txt")
            cmd = ["ffuf", "-u", url, "-w", word, "-mc", MATCH_CODES, "-s"]
        else:
            base = str(action.target).rstrip("/")
            url = f"{base}/FUZZ"
            word = args.get("wordlist") or wordlist("common.txt")
            cmd = ["ffuf", "-u", url, "-w", word, "-mc", MATCH_CODES, "-s"]
            if args.get("extensions"):
                cmd += ["-e", str(args["extensions"])]
        if args.get("method"):
            cmd += ["-X", str(args["method"]).upper()]
        if args.get("headers"):
            for header in str(args["headers"]).split(","):
                if header.strip():
                    cmd += ["-H", header.strip()]
        if args.get("rate"):
            cmd += ["-rate", str(args["rate"])]
        if args.get("timeout"):
            cmd += ["-timeout", str(args["timeout"])]
        cmd += ["-of", "json", "-o", str(out), "-noninteractive"]
        return cmd

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        out = self._outfile(action)
        text = ""
        if out.exists():
            try:
                text = out.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
        payload: Any = None
        if text.strip():
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = None
        findings: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            for item in payload.get("results") or []:
                findings.append(
                    {
                        "url": item.get("url", ""),
                        "status": item.get("status", 0),
                        "length": item.get("length", 0),
                        "words": item.get("words", 0),
                        "lines": item.get("lines", 0),
                        "content_type": item.get("content-type", ""),
                        "redirect": item.get("redirectlocation", ""),
                        "input": item.get("input", {}),
                    }
                )
        by_status: dict[str, int] = {}
        for finding in findings:
            key = str(finding["status"])
            by_status[key] = by_status.get(key, 0) + 1
        interesting = [
            f
            for f in findings
            if f["status"] in (200, 204, 301, 302, 307, 308, 401, 403)
        ]
        return {
            "findings": findings,
            "interesting": interesting,
            "count": len(findings),
            "interesting_count": len(interesting),
            "by_status": by_status,
            "wordlist": str(action.args.get("wordlist") or ""),
        }
