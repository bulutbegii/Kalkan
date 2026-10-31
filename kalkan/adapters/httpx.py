"""httpx adaptoru (ProjectDiscovery) - HTTP parmak izi.

nmap'in HTTP tarafi degil: canli URL dogrulama, baslik, teknoloji,
TLS bilgisi ve CDN/WAF izlerini tek gecisde toplar. T1592/T1590
playbook'larinda nmap'e alternatif olarak kullanilir.
"""

from __future__ import annotations

from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from ._common import json_lines
from .base import Adapter


class HttpxAdapter(Adapter):
    spec = ToolSpec(
        name="httpx",
        capabilities=("http_probe", "tech_detect"),
        risk=Risk.ACTIVE,
        binary="httpx",
        description="ProjectDiscovery httpx: canli URL, baslik, teknoloji ve TLS parmak izi",
    )

    def command(self, action: Action) -> list[str]:
        args = action.args
        cmd = ["httpx", "-u", str(action.target), "-json", "-silent", "-no-color"]
        if action.capability == "tech_detect":
            cmd += ["-tech-detect", "-web-server", "-title"]
        else:
            cmd += ["-status-code", "-title", "-web-server"]
        cmd += ["-tls-grab"]
        if args.get("ports"):
            cmd += ["-ports", str(args["ports"])]
        if args.get("rate_limit"):
            cmd += ["-rate-limit", str(args["rate_limit"])]
        if args.get("timeout"):
            cmd += ["-timeout", str(args["timeout"])]
        if args.get("follow_redirects", True):
            cmd += ["-follow-redirects"]
        return cmd

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for item in json_lines(stdout):
            tls = item.get("tls") or {}
            findings.append(
                {
                    "url": item.get("url", ""),
                    "status": item.get("status_code", 0),
                    "title": item.get("title", ""),
                    "server": item.get("webserver", ""),
                    "tech": item.get("tech") or [],
                    "content_type": item.get("content_type", ""),
                    "host": item.get("host", ""),
                    "ip": item.get("host_ip", ""),
                    "cdn": item.get("cdn_name", ""),
                    "tls_version": tls.get("tls_version", ""),
                    "tls_cn": tls.get("subject_cn", ""),
                    "tls_issuer": tls.get("issuer_cn", ""),
                    "tls_expiry": tls.get("expire_date", ""),
                }
            )
        techs: dict[str, int] = {}
        for finding in findings:
            for tech in finding["tech"]:
                techs[tech] = techs.get(tech, 0) + 1
        return {
            "findings": findings,
            "count": len(findings),
            "live": len([f for f in findings if f["status"]]),
            "technologies": dict(sorted(techs.items())),
        }
