"""nuclei adaptoru - sablon tabanli zafiyet tarama (T1595.002, T1190 dogrulama)."""

from __future__ import annotations

import json
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from .base import Adapter


class NucleiAdapter(Adapter):
    spec = ToolSpec(
        name="nuclei",
        capabilities=("vuln_scan", "web_template", "misconfig_scan"),
        risk=Risk.ACTIVE,
        binary="nuclei",
        description="Sablon tabanli zafiyet/yanlis yapilandirma tarayici",
    )

    def command(self, action: Action) -> list[str]:
        args = action.args
        cmd = ["nuclei", "-u", action.target, "-jsonl", "-silent", "-no-color"]
        if action.capability == "misconfig_scan":
            cmd += ["-tags", args.get("tags", "misconfig,exposure")]
        elif action.capability == "web_template":
            cmd += ["-tags", args.get("tags", "cve,exposure")]
        else:
            cmd += ["-severity", args.get("severity", "low,medium,high,critical")]
        if args.get("templates"):
            cmd += ["-t", str(args["templates"])]
        if args.get("rate_limit"):
            cmd += ["-rl", str(args["rate_limit"])]
        if args.get("exclude_intrusive", True):
            cmd += ["-exclude-tags", "intrusive,dos,fuzz"]
        return cmd

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            findings.append(
                {
                    "template": item.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": info.get("severity", "unknown"),
                    "matched_at": item.get("matched-at", ""),
                    "tags": info.get("tags", []),
                    "cve": (info.get("classification") or {}).get("cve-id"),
                }
            )
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {"findings": findings, "count": len(findings), "by_severity": by_sev}
