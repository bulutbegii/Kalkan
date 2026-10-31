"""Shodan adaptoru - pasif kesif (T1590, T1596).

Hedefe paket gitmez; ucuncu taraf veritabani sorgulanir. Bu yuzden
PASSIVE risk sinifindadir ve kapsam disi hedeflerde bile "kim ne
goruyor" sorusunu cevaplar.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any

from ..models import Action, ActionResult, Risk
from ..registry import ToolSpec
from ..scope import parse_target
from .base import Adapter

API = "https://api.shodan.io"


def resolve_ip(target: str) -> str:
    """Shodan host endpoint IP ister; domain/URL verilirse IP'ye çöz.

    'http://a.b:443/x' veya 'a.b' -> gethostbyname; '1.2.3.4' -> aynen.
    """
    kind, host, _ = parse_target(target)
    if kind == "ip":
        return host
    return socket.gethostbyname(host)


class ShodanAdapter(Adapter):
    spec = ToolSpec(
        name="shodan",
        capabilities=("passive_osint", "host_lookup", "exposure_lookup"),
        risk=Risk.PASSIVE,
        binary=None,
        description="Shodan pasif servis/parmak izi sorgusu (API anahtarı gerekir)",
    )

    def available(self) -> bool:
        return bool(os.environ.get("SHODAN_API_KEY"))

    def unavailable_reason(self) -> str:
        if not os.environ.get("SHODAN_API_KEY"):
            return "SHODAN_API_KEY tanımlı değil"
        return ""

    def command(self, action: Action) -> list[str]:
        return ["GET", f"{API}/shodan/host/{action.target}", "?key=$SHODAN_API_KEY"]

    def dry_run(self, action: Action) -> str:
        reason = self.unavailable_reason()
        prefix = f"[dry-run:{reason}] " if reason else "[dry-run] "
        return prefix + f"GET {API}/shodan/host/{action.target}?key=***"

    def run(self, action: Action, timeout: int = 60) -> ActionResult:
        key = os.environ.get("SHODAN_API_KEY")
        if not key:
            return ActionResult(action=action, status="unavailable", detail="SHODAN_API_KEY yok")
        try:
            ip = resolve_ip(action.target)
        except (socket.gaierror, OSError, ValueError) as exc:
            return ActionResult(action=action, status="error", detail=f"hedef IP'ye çözülemedi: {exc}")
        url = f"{API}/shodan/host/{ip}?key={key}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            hint = " (ücretsiz 'oss' planı veya kredi/endpoint kısıtı olabilir)" if exc.code in (401, 403) else ""
            return ActionResult(action=action, status="error", detail=f"HTTP {exc.code}{hint}")
        except (urllib.error.URLError, TimeoutError) as exc:
            return ActionResult(action=action, status="error", detail=str(exc))
        parsed = self.parse(json.dumps(payload), action)
        parsed["resolved_ip"] = ip
        return ActionResult(
            action=action,
            status="ok",
            command=["GET", f"{API}/shodan/host/{ip}"],
            parsed=parsed,
        )

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {}
        if "error" in data:
            return {"error": data["error"]}
        services = [
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner_snippet": (item.get("data") or "")[:200],
            }
            for item in data.get("data", [])
        ]
        return {
            "ip": data.get("ip_str"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "os": data.get("os"),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "ports": sorted({s["port"] for s in services if s["port"]}),
            "services": services,
            "known_vulns": sorted((data.get("vulns") or {}).keys()),
            "tags": data.get("tags", []),
        }
