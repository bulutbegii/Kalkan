"""Kapsam (scope) zorlamasi.

Bu modul projenin en onemli parcasidir: bir hedefe paket gitmeden once
buradan gecmek zorundadir. Yetki belgesi yoksa, kapsam disiysa veya
suresi dolmussa hicbir sey calismaz.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .models import Risk


class ScopeViolation(Exception):
    """Hedef yetkilendirilmis kapsamin disinda."""


def _parse_dt(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_target(raw: str) -> tuple[str, str, int | None]:
    """'https://a.b:8443/x', '10.0.0.5', '10.0.0.0/24', 'a.b:443' -> (kind, host, port)."""
    raw = raw.strip()
    port: int | None = None
    if "://" in raw:
        parts = urlsplit(raw)
        host = (parts.hostname or "").strip("[]")
        port = parts.port
    else:
        host = raw
        if raw.count(":") == 1:
            candidate_host, candidate_port = raw.rsplit(":", 1)
            if candidate_port.isdigit():
                host, port = candidate_host, int(candidate_port)
    host = host.strip("[]").rstrip(".").lower()
    if not host:
        raise ScopeViolation(f"hedef ayrıştırılamadı: {raw!r}")
    try:
        ipaddress.ip_network(host, strict=False)
        kind = "cidr" if "/" in host else "ip"
    except ValueError:
        kind = "domain"
    return kind, host, port


def add_to_scope_file(path: str | Path, raw: str) -> dict:
    """Bir hedefi kapsam dosyasina ekle (domain/ip/cidr otomatik ayrilir).

    Dosyadaki diger alanlari korur. Donen sozluk: kind/host/port/changed.
    DIKKAT: buraya ekleme, o hedefi test etmeye YETKILI oldugunu beyan
    etmen demektir; Kalkan bu beyana guvenir.
    """
    p = Path(path)
    if not p.exists():
        raise ScopeViolation(
            f"kapsam dosyası yok: {p}\n  önce örneği kopyala: examples/scope.json"
        )
    data = json.loads(p.read_text(encoding="utf-8"))
    kind, host, port = parse_target(raw)

    changed = False
    if kind == "domain":
        lst = [d.lower() for d in data.get("allow_domains", [])]
        if host not in lst:
            lst.append(host)
            data["allow_domains"] = lst
            changed = True
    else:
        entry = host if kind == "cidr" else (
            f"{host}/32" if ":" not in host else f"{host}/128"
        )
        lst = list(data.get("allow_cidrs", []))
        if entry not in lst:
            lst.append(entry)
            data["allow_cidrs"] = lst
            changed = True
        host = entry

    port_added = False
    if port is not None and data.get("allow_ports"):
        ports = [int(x) for x in data["allow_ports"]]
        if port not in ports:
            ports.append(port)
            data["allow_ports"] = sorted(ports)
            port_added = True

    if changed or port_added:
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"kind": kind, "host": host, "port": port,
            "changed": changed, "port_added": port_added}


@dataclass(frozen=True)
class Scope:
    name: str
    authorized_by: str
    ticket: str
    expires: datetime
    allow_cidrs: tuple[str, ...] = ()
    allow_domains: tuple[str, ...] = ()
    allow_ports: tuple[int, ...] = ()
    deny_cidrs: tuple[str, ...] = ()
    max_risk: str = "active"

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            name=str(data.get("name", "")),
            authorized_by=str(data.get("authorized_by", "")),
            ticket=str(data.get("ticket", "")),
            expires=_parse_dt(data["expires"]),
            allow_cidrs=tuple(data.get("allow_cidrs", [])),
            allow_domains=tuple(d.lower() for d in data.get("allow_domains", [])),
            allow_ports=tuple(int(p) for p in data.get("allow_ports", [])),
            deny_cidrs=tuple(data.get("deny_cidrs", [])),
            max_risk=str(data.get("max_risk", "active")),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires

    def is_empty(self) -> bool:
        return not self.allow_cidrs and not self.allow_domains


class ScopeGuard:
    """Scope'u derlenmis halde tutar ve her hedefi denetler."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self._allow_nets = [ipaddress.ip_network(c, strict=False) for c in scope.allow_cidrs]
        self._deny_nets = [ipaddress.ip_network(c, strict=False) for c in scope.deny_cidrs]
        self._ports = set(scope.allow_ports)
        self._max_risk = Risk.parse(scope.max_risk)

    def check(self, target: str, risk: Risk = Risk.PASSIVE, port: int | None = None) -> str:
        """Gecerliyse normalize edilmis hedefi dondurur, degilse ScopeViolation atar."""
        scope = self.scope
        if scope.expired():
            raise ScopeViolation(
                f"kapsam süresi dolmuş ({scope.expires.isoformat()}); yeni yetki belgesi gerekli"
            )
        if scope.is_empty():
            raise ScopeViolation("kapsam boş: allow_cidrs/allow_domains tanımlı değil")
        if risk > self._max_risk:
            raise ScopeViolation(
                f"risk {risk.label} > kapsam tavanı {self._max_risk.label}"
            )

        kind, host, parsed_port = parse_target(target)
        port = port if port is not None else parsed_port

        if port is not None and self._ports and port not in self._ports:
            raise ScopeViolation(
                f"port {port} kapsamda izinli değil ({sorted(self._ports)}); "
                "kapsam dosyasındaki allow_ports listesine ekleyin"
            )

        if kind in ("ip", "cidr"):
            self._check_ip(host, kind)
        else:
            self._check_domain(host)
        return host if port is None else f"{host}:{port}"

    def _check_ip(self, host: str, kind: str) -> None:
        if kind == "cidr":
            net = ipaddress.ip_network(host, strict=False)
            for deny in self._deny_nets:
                if net.overlaps(deny):
                    raise ScopeViolation(f"{host} deny listesiyle çakışıyor ({deny})")
            if not any(net.subnet_of(a) for a in self._allow_nets):
                raise ScopeViolation(f"{host} izinli ağların içinde değil")
            return

        ip = ipaddress.ip_address(host)
        if any(ip in deny for deny in self._deny_nets):
            raise ScopeViolation(f"{host} deny listesinde")
        if not any(ip in allow for allow in self._allow_nets):
            raise ScopeViolation(f"{host} izinli ağların içinde değil")

    def _check_domain(self, host: str) -> None:
        for deny in self.scope.deny_cidrs:
            _ = deny
        for allowed in self.scope.allow_domains:
            if host == allowed or host.endswith("." + allowed):
                return
        raise ScopeViolation(f"{host} izinli alan adlarının altında değil")

    def describe(self) -> str:
        s = self.scope
        lines = [
            f"kapsam      : {s.name}",
            f"yetki veren : {s.authorized_by}",
            f"bilet       : {s.ticket}",
            f"bitiş       : {s.expires.isoformat()}",
            f"risk tavanı : {self._max_risk.label}",
            f"ağlar       : {', '.join(s.allow_cidrs) or '-'}",
            f"alan adları : {', '.join(s.allow_domains) or '-'}",
            f"portlar     : {', '.join(str(p) for p in s.allow_ports) or 'hepsi'}",
            f"hariç       : {', '.join(s.deny_cidrs) or '-'}",
        ]
        return "\n".join(lines)
