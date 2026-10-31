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
  idor_probe        -> nesne kimligi numaralandirma (IDOR/BOLA, kirik erisim kontrolu)
  source_recon      -> DevTools "Sources" karsiligi: JS/asset agaci, source map ile
                       orijinal kaynak agacini geri kurma, secret/endpoint tarama
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..models import Action, ActionResult, Risk
from ..registry import ToolSpec
from ._common import base_url, host_of, origin, severity_counts
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
_IDOR_NOAUTH = "__noauth__"
REDIRECT_PAYLOADS = (
    "https://kalkan.invalid/redirect",
    "//kalkan.invalid/redirect",
    "/\\kalkan.invalid/redirect",
    "https://kalkan.invalid/%2f..%2f",
)

_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
_SRCMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_ENDPOINT_RE = re.compile(r"""['"](/[A-Za-z0-9_][A-Za-z0-9_\-./]{2,}(?:\?[^'"]{0,80})?)['"]""")
_STATIC_EXT = (".js", ".css", ".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".mp4", ".json")
_SECRET_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("github_token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.=]{20,}")),
    ("generic_secret", re.compile(
        r"(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
        r"[\"'\s]{0,3}[:=][\"'\s]{0,3}([A-Za-z0-9\-_./+]{16,})")),
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
            "idor_probe",
            "source_recon",
        ),
        risk=Risk.ACTIVE,
        binary=None,
        description="Yerleşik HTTP/TLS denetimleri (başlık, CORS, çerez, yöntem, sertifika, IDOR, kaynak keşfi)",
    )

    def command(self, action: Action) -> list[str]:
        verb = {
            "security_headers": "GET",
            "cookie_flags": "GET",
            "cors_check": "GET+OPTIONS",
            "http_methods": "OPTIONS+TRACE",
            "tls_inspect": "TLS",
            "redirect_check": "GET",
            "idor_probe": "GET(enum)",
            "source_recon": "GET(sources)",
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
        read_bytes: int = 65536,
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
                    body=resp.read(read_bytes).decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                url=url,
                status=exc.code,
                headers=list(exc.headers.items()) if exc.headers else [],
                body=exc.read(read_bytes).decode("utf-8", errors="replace") if exc.fp else "",
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
            "idor_probe": self._idor,
            "source_recon": self._source_recon,
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

    def _idor(self, action: Action) -> dict[str, Any]:
        """Nesne referansi (id) numaralandirarak yetkisiz erisimi dener.

        Uc sinyal uretir:
          * idor_enumeration  : komsu kimlikler (id±N) oturumumuza 200 donuyor
                                -> baska kullanicinin nesnesine erisim (yatay IDOR)
          * missing_authentication : cerezsiz istek de ayni nesneyi 200 donuyor
                                -> kimlik dogrulama zorlanmiyor
          * bola_horizontal   : ikinci oturum (cookie_b) A kullanicisinin nesnesini
                                okuyor -> dogrulanmis BOLA (en guvenilir kanit)

        Hedef URL sayisal bir kimlik icermeli (yol parcasi veya sorgu degeri);
        param=<ad> ile hangi sorgu parametresinin kimlik oldugu verilebilir.
        """
        args = action.args
        insecure = bool(args.get("insecure"))
        cookie = str(args.get("cookie") or "")
        cookie_b = str(args.get("cookie_b") or args.get("cookie2") or "")
        param = str(args.get("param") or "").strip()
        url = action.target if "://" in action.target else "http://" + action.target
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)

        loc: tuple[str, Any] | None = None
        cur_id = str(args.get("id") or "")
        if param:
            for k, v in query:
                if k == param:
                    loc, cur_id = ("query", param), (cur_id or v)
                    break
        if loc is None:
            for k, v in query:
                if v.isdigit():
                    loc, cur_id, param = ("query", k), (cur_id or v), k
                    break
        if loc is None:
            segs = parts.path.split("/")
            for i in range(len(segs) - 1, -1, -1):
                if segs[i].isdigit():
                    loc, cur_id = ("path", i), (cur_id or segs[i])
                    break
        if loc is None:
            return {"url": url, "findings": [],
                    "note": "nesne kimliği bulunamadı; --arg param=<ad> ver "
                            "ya da sayısal kimlikli bir URL kullan (örn. /users/1001)"}

        explicit = [s.strip() for s in str(args.get("ids") or "").split(",") if s.strip()]
        if explicit:
            candidates = explicit
        else:
            rng = int(args.get("range", 3) or 3)
            cand: list[str] = []
            try:
                base = int(cur_id)
            except ValueError:
                base = None
            if base is not None:
                for d in range(1, rng + 1):
                    cand += [str(base + d), str(base - d)]
                cand += ["1", str(base + 100)]
            candidates = [
                c for c in dict.fromkeys(cand)
                if c and c != str(cur_id) and not (c.lstrip("-").isdigit() and int(c) < 0)
            ]
        candidates = candidates[:8]

        def build(idv: str) -> str:
            if loc[0] == "query":
                newq = [(k, (idv if k == loc[1] else v)) for k, v in query]
                return urlunsplit((parts.scheme, parts.netloc, parts.path,
                                   urlencode(newq), parts.fragment))
            segs = parts.path.split("/")
            segs[loc[1]] = idv
            return urlunsplit((parts.scheme, parts.netloc, "/".join(segs),
                               parts.query, parts.fragment))

        def fetch(idv: str, use_cookie: str) -> HttpResponse:
            hdrs = {"Cookie": use_cookie} if (use_cookie and use_cookie != _IDOR_NOAUTH) else {}
            return self._request(build(idv), headers=hdrs, insecure=insecure)

        def similar(a: int, b: int) -> bool:
            hi = max(a, b)
            return hi == 0 or abs(a - b) / hi < 0.3

        baseline = fetch(str(cur_id), cookie)
        base_len = len(baseline.body)
        findings: list[dict[str, Any]] = []
        tested: list[dict[str, Any]] = [
            {"id": str(cur_id), "role": "baseline", "status": baseline.status, "len": base_len}
        ]
        param_label = param if loc[0] == "query" else f"path[{loc[1]}]"

        for idv in candidates:
            r = fetch(idv, cookie)
            tested.append({"id": idv, "role": "enum", "status": r.status, "len": len(r.body),
                           "error": r.error})
            if r.error or r.status != 200 or not r.body:
                continue
            distinct = (not similar(len(r.body), base_len)) or (r.body != baseline.body)
            findings.append({
                "check": "idor_enumeration",
                "parameter": param_label,
                "severity": "high" if distinct else "medium",
                "detail": f"kimlik {idv} HTTP 200 döndü — başka nesneye erişim "
                          + ("(farklı içerik)" if distinct else "(aynı içerik)"),
                "id": idv,
            })

        if cookie:
            r = fetch(str(cur_id), _IDOR_NOAUTH)
            tested.append({"id": f"{cur_id} (noauth)", "role": "unauth",
                           "status": r.status, "len": len(r.body)})
            if not r.error and r.status == 200 and similar(len(r.body), base_len):
                findings.append({
                    "check": "missing_authentication",
                    "parameter": param_label,
                    "severity": "high",
                    "detail": "çerezsiz (kimlik doğrulamasız) istek de aynı nesneyi 200 döndürdü",
                    "id": str(cur_id),
                })

        if cookie_b:
            r = fetch(str(cur_id), cookie_b)
            tested.append({"id": f"{cur_id} (userB)", "role": "bola",
                           "status": r.status, "len": len(r.body)})
            if not r.error and r.status == 200 and similar(len(r.body), base_len):
                findings.append({
                    "check": "bola_horizontal",
                    "parameter": param_label,
                    "severity": "critical",
                    "detail": "ikinci oturum (B) birinci kullanıcının (A) nesnesini okudu "
                              "— doğrulanmış BOLA/IDOR",
                    "id": str(cur_id),
                })

        return {
            "url": url,
            "param": param_label,
            "object_id": cur_id,
            "baseline_status": baseline.status,
            "vulnerable": any(f["severity"] in ("high", "critical") for f in findings),
            "tested": tested,
            "findings": findings,
        }

    def _source_recon(self, action: Action) -> dict[str, Any]:
        """Sayfanin yukledigi JS/asset agacini cikarir, source map'lerden
        orijinal kaynak agacini (ve icerigini) geri kurar ve toplanan tum
        kaynakta gomulu sir / endpoint / acikta kalan kaynak deposu arar.

        Tarayicisiz calisir (yalnizca HTTP GET). JS ile DINAMIK enjekte edilen
        script'ler icin browser adaptoru gerekir."""
        args = action.args
        insecure = bool(args.get("insecure"))
        max_js = int(args.get("max_js", 25) or 25)
        big = int(args.get("max_bytes", 2_000_000) or 2_000_000)
        base = base_url(action.target)
        root = origin(action.target)
        host = host_of(action.target)

        home = self._request(base, insecure=insecure, read_bytes=big)
        if home.error:
            return {"error": home.error, "findings": []}
        html = home.body
        inline = _INLINE_SCRIPT_RE.findall(html)
        js_urls: list[str] = []
        for s in _SCRIPT_SRC_RE.findall(html):
            u = urljoin(base + "/", s)
            if host_of(u) == host and u not in js_urls:
                js_urls.append(u)

        findings: list[dict[str, Any]] = []
        corpus: list[tuple[str, str]] = [("<inline>", t) for t in inline]
        sources_tree: list[str] = []

        for u in js_urls[:max_js]:
            r = self._request(u, insecure=insecure, read_bytes=big)
            if r.error or not r.body:
                continue
            corpus.append((u, r.body))
            m = _SRCMAP_RE.search(r.body)
            map_url = urljoin(u, m.group(1)) if m else (u.split("?", 1)[0] + ".map")
            if not map_url or map_url.startswith("data:"):
                continue
            rm = self._request(map_url, insecure=insecure, read_bytes=big)
            if rm.error or not rm.body.strip().startswith("{"):
                continue
            try:
                data = json.loads(rm.body)
            except ValueError:
                continue
            srcs_list = data.get("sources") or []
            contents = data.get("sourcesContent") or []
            if not srcs_list:
                continue
            for i, sp in enumerate(srcs_list):
                sources_tree.append(str(sp))
                if i < len(contents) and contents[i]:
                    corpus.append((str(sp), contents[i]))
            findings.append({
                "check": "source_map_exposed", "severity": "medium",
                "detail": f"source map açık ({map_url.rsplit('/', 1)[-1]}); "
                          f"{len(srcs_list)} orijinal kaynak dosyası geri kuruldu",
            })

        for art, sev, why in ((".git/HEAD", "high", ".git deposu açık"),
                              (".env", "high", ".env dosyası açık"),
                              (".svn/entries", "medium", ".svn dizini açık")):
            r = self._request(f"{root}/{art}", insecure=insecure)
            if r.error or r.status != 200 or not r.body:
                continue
            if art == ".git/HEAD" and not r.body.strip().startswith("ref:"):
                continue
            findings.append({"check": "exposed_source", "severity": sev,
                             "detail": f"{why}: /{art}"})

        endpoints: set[str] = set()
        seen_secret: set[str] = set()
        for name, text in corpus:
            for label, pat in _SECRET_PATTERNS:
                for mm in pat.finditer(text):
                    snippet = mm.group(0)[:64]
                    key = f"{label}:{snippet}"
                    if key in seen_secret:
                        continue
                    seen_secret.add(key)
                    findings.append({
                        "check": "secret_in_source", "severity": "high",
                        "detail": f"{label} kaynakta: {snippet}", "location": name,
                    })
            for mm in _ENDPOINT_RE.finditer(text):
                p = mm.group(1)
                if len(p) < 80 and not p.lower().endswith(_STATIC_EXT):
                    endpoints.add(p)

        return {
            "url": base,
            "scripts": len([c for c in corpus if c[0] not in ("<inline>",) and "://" in c[0]]),
            "inline_scripts": len(inline),
            "sources_recovered": len(sources_tree),
            "sources_tree": sorted(set(sources_tree))[:300],
            "endpoints": sorted(endpoints)[:80],
            "vulnerable": any(f["severity"] == "high" for f in findings),
            "findings": findings,
        }


def _flatten(items: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for group in items or ():
        for key, value in group:
            out[key] = value
    return out
