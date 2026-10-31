"""Yerlesik web denetimleri (harici arac gerektirmez).

Amac: hedefe *gercek* HTTP istekleri atarak yanlis yapilandirmayi
kanitla gostermek. Harici binary yoksa bile calisir; bu yuzden
`coverage` tablosunda her zaman "hazir" gorunur.

Yetkinlikler:
  security_headers  -> eksik guvenlik basliklari
  cookie_flags      -> Secure/HttpOnly/SameSite
  cors_check        -> yansitilan Origin + credentials
  http_methods      -> OPTIONS Allow, TRACE acigi
  tls_inspect       -> sertifika/surum/sona erme
  redirect_check    -> acik yonlendirme
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Action, ActionResult, Risk
from ..registry import ToolSpec
from ._common import base_url, host_of, severity_counts
from .base import Adapter

SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "HSTS yok; HTTPS downgrade ve cookie hirsizligi kolaylasir"),
    "content-security-policy": ("medium", "CSP yok; XSS bulgusu dogrudan somurulebilir"),
    "x-content-type-options": ("low", "MIME sniffing acik; icerik tipi karisikligi"),
    "referrer-policy": ("low", "Referrer sizintisi; URL'deki tokenlar ucuncu taraflara gidebilir"),
    "permissions-policy": ("info", "Tarayici ozellikleri kisitlanmamis"),
    "cross-origin-opener-policy": ("low", "Cross-origin izolasyon yok"),
}

PROBE_ORIGIN = "https://kalkan.invalid"
REDIRECT_PAYLOADS = (
    "https://kalkan.invalid/redirect",
    "//kalkan.invalid/redirect",
    "/\\kalkan.invalid/redirect",
    "https://kalkan.invalid/%2f..%2f",
)


@dataclass
class HttpResponse:
    url: str
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    error: str = ""

    def header(self, name: str) -> str:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return ""

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def as_dict(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.headers}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class WebProbeAdapter(Adapter):
    spec = ToolSpec(
        name="webprobe",
        capabilities=(
            "security_headers",
            "cookie_flags",
            "cors_check",
            "http_methods",
            "tls_inspect",
            "redirect_check",
        ),
        risk=Risk.ACTIVE,
        binary=None,
        description="Yerleşik HTTP/TLS denetimleri (başlık, CORS, çerez, yöntem, sertifika)",
    )

    def command(self, action: Action) -> list[str]:
        verb = {
            "security_headers": "GET",
            "cookie_flags": "GET",
            "cors_check": "GET+OPTIONS",
            "http_methods": "OPTIONS+TRACE",
            "tls_inspect": "TLS",
            "redirect_check": "GET",
        }.get(action.capability, "GET")
        return [verb, action.target]

    def dry_run(self, action: Action) -> str:
        return f"[dry-run] {self.command(action)[0]} {action.target}  # yerleşik denetim"

    def _request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        follow: bool = False,
        insecure: bool = False,
        timeout: int = 10,
    ) -> HttpResponse:
        handlers: list[Any] = []
        if not follow:
            handlers.append(_NoRedirect())
        if insecure:
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", "kalkan-webprobe/1.0")
        req.add_header("Accept", "*/*")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with opener.open(req, timeout=timeout) as resp:
                return HttpResponse(
                    url=url,
                    status=getattr(resp, "status", 0) or resp.getcode(),
                    headers=list(resp.headers.items()),
                    body=resp.read(65536).decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                url=url,
                status=exc.code,
                headers=list(exc.headers.items()) if exc.headers else [],
                body=exc.read(65536).decode("utf-8", errors="replace") if exc.fp else "",
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return HttpResponse(url=url, error=str(reason))
        except ssl.SSLError as exc:
            return HttpResponse(url=url, error=f"TLS: {exc}")

    def run(self, action: Action, timeout: int = 120) -> ActionResult:
        started = time.monotonic()
        handler = {
            "security_headers": self._security_headers,
            "cookie_flags": self._cookie_flags,
            "cors_check": self._cors,
            "http_methods": self._methods,
            "tls_inspect": self._tls,
            "redirect_check": self._redirect,
        }.get(action.capability)
        if handler is None:
            return ActionResult(action=action, status="error", detail="bilinmeyen yetenek")
        try:
            parsed = handler(action)
        except Exception as exc:
            return ActionResult(action=action, status="error", detail=f"denetim hatası: {exc}")

        findings = parsed.get("findings", [])
        parsed["count"] = len(findings)
        parsed["by_severity"] = severity_counts(findings)
        return ActionResult(
            action=action,
            status="ok" if not parsed.get("error") else "error",
            command=self.command(action),
            parsed=parsed,
            duration_s=time.monotonic() - started,
            detail=parsed.get("error", ""),
        )

    def _security_headers(self, action: Action) -> dict[str, Any]:
        resp = self._request(base_url(action.target), insecure=bool(action.args.get("insecure")))
        if resp.error:
            return {"error": resp.error, "findings": []}
        headers = resp.as_dict()
        findings: list[dict[str, Any]] = []
        for name, (severity, why) in SECURITY_HEADERS.items():
            if name not in headers:
                findings.append(
                    {
                        "check": "missing_header",
                        "header": name,
                        "severity": severity,
                        "detail": why,
                    }
                )
        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                findings.append(
                    {
                        "check": "weak_csp",
                        "header": "content-security-policy",
                        "severity": "medium",
                        "detail": "CSP 'unsafe-inline' içeriyor; inline XSS engellenmiyor",
                    }
                )
            if "unsafe-eval" in csp:
                findings.append(
                    {
                        "check": "weak_csp",
                        "header": "content-security-policy",
                        "severity": "medium",
                        "detail": "CSP 'unsafe-eval' içeriyor",
                    }
                )
            if "frame-ancestors" not in csp and "x-frame-options" not in headers:
                findings.append(
                    {
                        "check": "clickjacking",
                        "header": "content-security-policy",
                        "severity": "medium",
                        "detail": "frame-ancestors yok ve X-Frame-Options yok; clickjacking mümkün",
                    }
                )
        server = headers.get("server", "")
        if any(ch.isdigit() for ch in server):
            findings.append(
                {
                    "check": "version_disclosure",
                    "header": "server",
                    "severity": "info",
                    "detail": f"Sunucu sürümü açık: {server}",
                }
            )
        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append(
                {
                    "check": "version_disclosure",
                    "header": "x-powered-by",
                    "severity": "low",
                    "detail": f"Teknoloji/sürüm açık: {powered}",
                }
            )
        return {
            "url": resp.url,
            "status": resp.status,
            "present": {k: v for k, v in headers.items() if k in SECURITY_HEADERS},
            "findings": findings,
        }

    def _cookie_flags(self, action: Action) -> dict[str, Any]:
        resp = self._request(base_url(action.target), insecure=bool(action.args.get("insecure")))
        if resp.error:
            return {"error": resp.error, "findings": []}
        findings: list[dict[str, Any]] = []
        cookies: list[dict[str, Any]] = []
        for raw in resp.header_all("set-cookie"):
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=", 1)[0] if parts else "?"
            lower = raw.lower()
            flags = {
                "name": name,
                "secure": "secure" in lower,
                "httponly": "httponly" in lower,
                "samesite": "",
            }
            for part in parts[1:]:
                if part.lower().startswith("samesite="):
                    flags["samesite"] = part.split("=", 1)[1].lower()
            cookies.append(flags)
            if not flags["secure"]:
                findings.append(
                    {
                        "check": "cookie_secure",
                        "cookie": name,
                        "severity": "medium",
                        "detail": "Secure bayrağı yok; HTTP üzerinden gönderilebilir",
                    }
                )
            if not flags["httponly"]:
                findings.append(
                    {
                        "check": "cookie_httponly",
                        "cookie": name,
                        "severity": "medium",
                        "detail": "HttpOnly yok; XSS ile çalınabilir",
                    }
                )
            if flags["samesite"] == "none" and not flags["secure"]:
                findings.append(
                    {
                        "check": "cookie_samesite",
                        "cookie": name,
                        "severity": "high",
                        "detail": "SameSite=None ama Secure yok; tarayıcı reddeder veya CSRF'e açık",
                    }
                )
            elif not flags["samesite"]:
                findings.append(
                    {
                        "check": "cookie_samesite",
                        "cookie": name,
                        "severity": "low",
                        "detail": "SameSite belirtilmemiş",
                    }
                )
        return {"url": resp.url, "cookies": cookies, "findings": findings}

    def _cors(self, action: Action) -> dict[str, Any]:
        url = base_url(action.target)
        get = self._request(
            url,
            headers={"Origin": PROBE_ORIGIN},
            insecure=bool(action.args.get("insecure")),
        )
        preflight = self._request(
            url,
            method="OPTIONS",
            headers={
                "Origin": PROBE_ORIGIN,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
            insecure=bool(action.args.get("insecure")),
        )
        findings: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        for label, resp in (("simple", get), ("preflight", preflight)):
            if resp.error:
                continue
            acao = resp.header("access-control-allow-origin")
            acac = resp.header("access-control-allow-credentials").lower()
            acam = resp.header("access-control-allow-methods")
            results.append(
                {
                    "request": label,
                    "status": resp.status,
                    "allow_origin": acao,
                    "allow_credentials": acac,
                    "allow_methods": acam,
                }
            )
            if acao == PROBE_ORIGIN:
                severity = "high" if acac == "true" else "medium"
                findings.append(
                    {
                        "check": "cors_origin_reflected",
                        "severity": severity,
                        "detail": (
                            f"{label}: Origin yansıtılıyor"
                            + (" + credentials=true (oturum çalınabilir)" if acac == "true" else "")
                        ),
                    }
                )
            elif acao == "*" and acac == "true":
                findings.append(
                    {
                        "check": "cors_wildcard_credentials",
                        "severity": "high",
                        "detail": f"{label}: ACAO=* ile credentials=true birlikte",
                    }
                )
            elif acao == "*":
                findings.append(
                    {
                        "check": "cors_wildcard",
                        "severity": "info",
                        "detail": f"{label}: ACAO=* (kimlik doğrulamasız okuma)",
                    }
                )
            if acam and any(m in acam.upper() for m in ("PUT", "DELETE", "PATCH")):
                findings.append(
                    {
                        "check": "cors_methods",
                        "severity": "low",
                        "detail": f"{label}: yazma yöntemleri CORS'ta açık ({acam})",
                    }
                )
        if get.error and preflight.error:
            return {"error": get.error, "findings": []}
        return {"url": url, "probe_origin": PROBE_ORIGIN, "results": results, "findings": findings}

    def _methods(self, action: Action) -> dict[str, Any]:
        url = base_url(action.target)
        options = self._request(url, method="OPTIONS", insecure=bool(action.args.get("insecure")))
        trace = self._request(url, method="TRACE", insecure=bool(action.args.get("insecure")))
        findings: list[dict[str, Any]] = []
        allow = options.header("allow")
        if allow:
            upper = allow.upper()
            risky = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT") if m in upper]
            if risky:
                findings.append(
                    {
                        "check": "dangerous_methods",
                        "severity": "medium",
                        "detail": f"Allow başlığı riskli yöntemler içeriyor: {', '.join(risky)}",
                    }
                )
        if trace.status == 200 and ("TRACE" in trace.body.upper() or trace.body):
            findings.append(
                {
                    "check": "trace_enabled",
                    "severity": "medium",
                    "detail": "TRACE etkin; istek yansıtma (XST) mümkün olabilir",
                }
            )
        return {
            "url": url,
            "options_status": options.status,
            "allow": allow,
            "trace_status": trace.status,
            "findings": findings,
        }

    def _tls(self, action: Action) -> dict[str, Any]:
        parts = urlsplit(action.target if "://" in action.target else "https://" + action.target)
        host = parts.hostname or host_of(action.target)
        port = parts.port or int(action.args.get("port", 443))
        insecure = bool(action.args.get("insecure"))
        notes: list[str] = []
        context = ssl.create_default_context()
        try:
            cert, version, cipher = self._tls_handshake(host, port, context, insecure)
        except (ssl.SSLError, socket.error, OSError) as exc:
            return {"error": f"TLS bağlantısı kurulamadı: {exc}", "findings": []}

        findings: list[dict[str, Any]] = []
        subject = _flatten(cert.get("subject", ()))
        issuer = _flatten(cert.get("issuer", ()))
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        not_after = cert.get("notAfter", "")
        days_left = None
        if not_after:
            try:
                days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400)
            except ValueError:
                days_left = None
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(
                {
                    "check": "tls_version",
                    "severity": "high",
                    "detail": f"Eski TLS sürümü: {version}",
                }
            )
        if days_left is not None:
            if days_left < 0:
                findings.append(
                    {"check": "cert_expired", "severity": "high", "detail": f"Sertifika süresi dolmuş ({not_after})"}
                )
            elif days_left < 30:
                findings.append(
                    {
                        "check": "cert_expiring",
                        "severity": "medium",
                        "detail": f"Sertifika {days_left} gün içinde bitiyor ({not_after})",
                    }
                )
        if not sans:
            findings.append(
                {"check": "cert_no_san", "severity": "low", "detail": "subjectAltName yok (modern tarayıcılar reddeder)"}
            )
        if insecure:
            notes.append("sertifika doğrulaması kapatıldı (insecure=True)")
        return {
            "host": host,
            "port": port,
            "tls_version": version,
            "cipher": cipher,
            "subject": subject,
            "issuer": issuer,
            "sans": sans,
            "not_after": not_after,
            "days_left": days_left,
            "notes": notes,
            "findings": findings,
        }

    def _tls_handshake(self, host: str, port: int, context: ssl.SSLContext, insecure: bool):
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert() or {}, ssock.version(), ssock.cipher()
        except ssl.SSLCertVerificationError:
            if not insecure:
                raise
            fallback = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with fallback.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert() or {}, ssock.version(), ssock.cipher()

    def _redirect(self, action: Action) -> dict[str, Any]:
        param = str(action.args.get("param", "next"))
        target = base_url(action.target)
        parts = urlsplit(target)
        existing = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
        tested: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        target_host = (parts.hostname or "").lower()
        for payload in REDIRECT_PAYLOADS:
            query = urlencode(existing + [(param, payload)])
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
            resp = self._request(url, insecure=bool(action.args.get("insecure")))
            location = resp.header("location")
            entry = {
                "payload": payload,
                "status": resp.status,
                "location": location,
                "error": resp.error,
            }
            tested.append(entry)
            if not location:
                continue
            lowered = location.lower()
            if lowered.startswith("javascript:"):
                findings.append(
                    {
                        "check": "redirect_javascript",
                        "severity": "high",
                        "detail": f"Location javascript: şeması kullanıyor ({payload})",
                    }
                )
            elif "kalkan.invalid" in lowered:
                findings.append(
                    {
                        "check": "open_redirect",
                        "severity": "high",
                        "detail": f"Dış alana yönlendirme: {location}",
                    }
                )
            elif location.startswith("//") and "kalkan.invalid" not in lowered:
                findings.append(
                    {
                        "check": "open_redirect_protocol_relative",
                        "severity": "medium",
                        "detail": f"Protokol-göreli yönlendirme: {location}",
                    }
                )
        return {
            "url": target,
            "param": param,
            "target_host": target_host,
            "tested": tested,
            "findings": findings,
        }


def _flatten(items: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for group in items or ():
        for key, value in group:
            out[key] = value
    return out
