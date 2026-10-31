"""nmap adaptoru - ag kesfi ve servis parmak izi (T1046, T1595.001)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..models import Action, Risk
from ..registry import ToolSpec
from .base import Adapter


class NmapAdapter(Adapter):
    spec = ToolSpec(
        name="nmap",
        capabilities=("port_scan", "service_version", "vuln_script", "host_discovery"),
        risk=Risk.ACTIVE,
        binary="nmap",
        description="Port tarama ve servis/versiyon tespiti",
    )

    def command(self, action: Action) -> list[str]:
        args = action.args
        cmd = ["nmap", "-Pn", "-oX", "-", "--reason"]
        if action.capability in ("service_version", "vuln_script"):
            cmd += ["-sV", "--version-light"]
        if action.capability == "vuln_script":
            scripts = args.get("scripts", "vuln")
            cmd += ["--script", scripts]
        if action.capability == "host_discovery":
            cmd += ["-sn"]

        ports = args.get("ports")
        top = args.get("top_ports")
        if ports:
            cmd += ["-p", str(ports)]
        elif top:
            cmd += ["--top-ports", str(top)]
        else:
            cmd += ["--top-ports", "100"]

        if args.get("timing"):
            cmd.append(f"-T{args['timing']}")
        cmd.append(action.target)
        return cmd

    def dry_run(self, action: Action) -> str:
        return super().dry_run(action) + "   # XML çıktısı stdout'a"

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        if not stdout.strip().startswith("<"):
            return {}
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return {"parse_error": "nmap XML ayrıştırılamadı"}

        hosts: list[dict[str, Any]] = []
        for host in root.findall("host"):
            if host.find("status") is not None and host.find("status").get("state") != "up":
                continue
            addr_el = host.find("address")
            entry: dict[str, Any] = {
                "address": addr_el.get("addr") if addr_el is not None else action.target,
                "ports": [],
                "hostnames": [
                    h.get("name") for h in host.findall("./hostnames/hostname") if h.get("name")
                ],
            }
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                entry["ports"].append(
                    {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "service": service.get("name") if service is not None else "",
                        "product": (service.get("product") or "") if service is not None else "",
                        "version": (service.get("version") or "") if service is not None else "",
                    }
                )
            hosts.append(entry)

        open_ports = [p["port"] for h in hosts for p in h["ports"]]
        return {
            "hosts": hosts,
            "host_count": len(hosts),
            "open_port_count": len(open_ports),
            "open_ports": sorted(open_ports),
        }
