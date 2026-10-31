"""Gercek tarayici (Chrome/Edge) adaptoru — Chrome DevTools Protocol (CDP).

Kurulu Chrome/Edge'i `--headless=new --remote-debugging-port` ile baslatir ve
CDP'yi minimal, STDLIB-ONLY bir WebSocket istemcisiyle konusur. Ek pip
bagimliligi YOKTUR; tarayici yoksa adaptor `unavailable`'a duser.

DevTools karsiliklari (yetenekler):
  dom_render  -> sayfayi JS calistirarak render eder; final DOM, script/form/
                 link agaci, KONSOL loglari, NETWORK istekleri ve XHR/FETCH
                 cagrilari (dinamik API uclari) toplanir.
  net_capture -> yalnizca Network + XHR/Fetch dokumu (hafif).
  js_eval     -> DevTools 'Snippets' karsiligi: sayfa baglaminda verilen JS'i
                 calistirir, sonucu doner (--arg script="..." ya da snippet=).
  dom_xss     -> parametrelere JS yurutme payload'lari enjekte eder; konsolda
                 isaretci calisirsa yansiyan/DOM XSS dogrulanir (INTRUSIVE).
  screenshot  -> sayfanin PNG goruntusunu loot olarak kaydeder (kanit).

Guvenlik: tum yetenekler Executor'un scope+policy+onay kapilarindan gecer.
Hicbir hata Executor'u dusurmez; sorun olursa status=error/unavailable doner.
"""

from __future__ import annotations

import base64
import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Action, ActionResult, Risk
from ..registry import ToolSpec
from ._common import host_of
from .base import Adapter

_WIN_CANDIDATES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
)
_NIX_CANDIDATES = (
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)
_XSS_MARKER = "KALKANXSS"
_XSS_PAYLOADS = (
    '"><img src=x onerror=console.log(\'{m}\')>',
    "'><img src=x onerror=console.log('{m}')>",
    "<img src=x onerror=console.log('{m}')>",
    "\"><svg onload=console.log('{m}')>",
    "javascript:console.log('{m}')",
)


def _find_browser() -> str:
    for name in ("chrome", "chromium", "chromium-browser", "google-chrome", "msedge",
                 "microsoft-edge", "msedge.exe", "chrome.exe"):
        p = shutil.which(name)
        if p:
            return p
    if os.name == "nt":
        for p in _WIN_CANDIDATES:
            if os.path.exists(p):
                return p
    for p in _NIX_CANDIDATES:
        if os.path.exists(p):
            return p
    return ""


_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*:", re.I)


def _norm_url(target: str) -> str:
    """Scheme'i olan (http/https/data/file/about/blob...) URL'i oldugu gibi birak;
    yoksa http:// ekle."""
    t = (target or "").strip()
    if "://" in t or _SCHEME_RE.match(t):
        return t
    return "http://" + t


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _WS:
    def __init__(self, host: str, port: int, path: str, timeout: float = 30.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        head = self._read_until(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise OSError("websocket handshake başarısız: " + head[:120].decode("latin1"))

    def _read_until(self, sep: bytes) -> bytes:
        while sep not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise OSError("bağlantı el sıkışma sırasında kapandı")
            self._buf += chunk
        head, _, rest = self._buf.partition(sep)
        self._buf = rest
        return head + sep

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("bağlantı kapandı")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x81])
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv(self) -> str:
        chunks: list[bytes] = []
        while True:
            b0, b1 = self._recv_exact(2)
            fin = b0 & 0x80
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._recv_exact(8))[0]
            mask = self._recv_exact(4) if masked else b""
            data = self._recv_exact(length) if length else b""
            if masked:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:
                raise OSError("websocket karşı tarafça kapatıldı")
            if opcode == 0x9:
                self._pong(data)
                continue
            if opcode == 0xA:
                continue
            chunks.append(data)
            if fin:
                return b"".join(chunks).decode("utf-8", "replace")

    def _pong(self, data: bytes) -> None:
        header = bytearray([0x8A])
        mask = os.urandom(4)
        header.append(0x80 | len(data))
        header += mask
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def readable(self, timeout: float) -> bool:
        if self._buf:
            return True
        r, _, _ = select.select([self.sock], [], [], timeout)
        return bool(r)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class _CDP:
    """CDP mesajlasmasi: komut yanitlarini id ile eslestirir, olaylari biriktirir."""

    def __init__(self, ws: _WS):
        self.ws = ws
        self._id = 0
        self.events: list[dict[str, Any]] = []

    def cmd(self, method: str, params: dict | None = None,
            session: str | None = None) -> dict[str, Any]:
        self._id += 1
        mid = self._id
        msg: dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.ws.send(json.dumps(msg))
        while True:
            data = json.loads(self.ws.recv())
            if data.get("id") == mid:
                if "error" in data:
                    raise OSError(f"CDP {method}: {data['error'].get('message', data['error'])}")
                return data.get("result", {})
            self.events.append(data)

    def pump(self, seconds: float) -> None:
        """Belirtilen sure boyunca olaylari topla (mesaj sinirinda bekler)."""
        end = time.monotonic() + seconds
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            if not self.ws.readable(min(remaining, 0.4)):
                continue
            try:
                self.events.append(json.loads(self.ws.recv()))
            except (OSError, ValueError):
                break


class _Browser:
    """Headless Chrome/Edge baslatir, CDP oturumu acar; context manager."""

    def __init__(self, binary: str, timeout: float = 30.0):
        self.binary = binary
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self.tmp = ""
        self.ws: _WS | None = None
        self.cdp: _CDP | None = None
        self.session = ""
        self.target = ""

    def __enter__(self) -> "_Browser":
        port = _free_port()
        self.tmp = tempfile.mkdtemp(prefix="kalkan-br-")
        args = [
            self.binary, "--headless=new", "--disable-gpu", "--no-first-run",
            "--no-default-browser-check", "--disable-extensions", "--mute-audio",
            "--disable-background-networking", "--remote-allow-origins=*",
            f"--remote-debugging-port={port}", f"--user-data-dir={self.tmp}",
            "about:blank",
        ]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        ws_url = ""
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version",
                                            timeout=1) as r:
                    ws_url = json.loads(r.read().decode("utf-8")).get("webSocketDebuggerUrl", "")
                if ws_url:
                    break
            except (OSError, ValueError):
                time.sleep(0.2)
        if not ws_url:
            self.__exit__(None, None, None)
            raise OSError("DevTools uç noktası açılmadı (tarayıcı başlatılamadı)")
        parts = urlsplit(ws_url)
        self.ws = _WS(parts.hostname or "127.0.0.1", parts.port or port,
                      parts.path, timeout=self.timeout)
        self.cdp = _CDP(self.ws)
        self.target = self.cdp.cmd("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = self.cdp.cmd("Target.attachToTarget",
                                    {"targetId": self.target, "flatten": True})["sessionId"]
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.cdp and self.target:
                self.cdp.cmd("Target.closeTarget", {"targetId": self.target})
        except OSError:
            pass
        if self.ws:
            self.ws.close()
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                try:
                    self.proc.kill()
                except OSError:
                    pass
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)


class BrowserAdapter(Adapter):
    spec = ToolSpec(
        name="browser",
        capabilities=("dom_render", "net_capture", "js_eval", "dom_xss", "screenshot"),
        risk=Risk.ACTIVE,
        binary=None,
        description="Gerçek tarayıcı (Chrome/Edge, CDP): render, Network/XHR, konsol, snippet, DOM-XSS",
    )

    def __init__(self) -> None:
        self._bin_cache: str | None = None

    def _binary(self) -> str:
        if self._bin_cache is None:
            self._bin_cache = _find_browser()
        return self._bin_cache

    def available(self) -> bool:
        return bool(self._binary())

    def unavailable_reason(self) -> str:
        if self.available():
            return ""
        return "Chrome/Edge bulunamadı (headless tarayıcı gerekli)"

    def command(self, action: Action) -> list[str]:
        return ["BROWSER", action.capability, action.target]

    def dry_run(self, action: Action) -> str:
        reason = self.unavailable_reason()
        head = f"[dry-run:{reason}] " if reason else "[dry-run] "
        return head + f"{self._binary() or 'chrome'} --headless=new --remote-debugging-port=… " \
                      f"→ CDP {action.capability} → {action.target}"

    def run(self, action: Action, timeout: int = 60) -> ActionResult:
        reason = self.unavailable_reason()
        if reason:
            return ActionResult(action=action, status="unavailable", detail=reason)
        url = _norm_url(action.target)
        started = time.monotonic()
        try:
            with _Browser(self._binary(), timeout=min(timeout, 60)) as br:
                parsed = self._dispatch(br, action, url)
        except Exception as exc:  # noqa: BLE001 - tarayici hatasi plani bozmasin
            return ActionResult(action=action, status="error",
                                command=self.command(action),
                                detail=f"tarayıcı hatası: {exc}",
                                duration_s=time.monotonic() - started)
        return ActionResult(
            action=action,
            status="ok" if not parsed.get("error") else "error",
            command=self.command(action),
            parsed=parsed,
            duration_s=time.monotonic() - started,
            detail=parsed.get("error", ""),
        )

    def _dispatch(self, br: _Browser, action: Action, url: str) -> dict[str, Any]:
        cap = action.capability
        if cap == "js_eval":
            return self._js_eval(br, action)
        if cap == "dom_xss":
            return self._dom_xss(br, action, url)
        if cap == "screenshot":
            return self._screenshot(br, action, url)
        return self._render(br, action, url, net_only=(cap == "net_capture"))

    def _eval(self, br: _Browser, expr: str, by_value: bool = True) -> Any:
        res = br.cdp.cmd("Runtime.evaluate",
                         {"expression": expr, "returnByValue": by_value,
                          "awaitPromise": False, "timeout": 5000},
                         session=br.session)
        return res.get("result", {}).get("value")

    def _collect_network(self, events: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
        reqs: dict[str, dict[str, Any]] = {}
        console: list[dict[str, Any]] = []
        for ev in events:
            m = ev.get("method", "")
            p = ev.get("params", {})
            if m == "Network.requestWillBeSent":
                rid = p.get("requestId", "")
                req = p.get("request", {})
                reqs.setdefault(rid, {})
                reqs[rid].update({
                    "url": req.get("url", ""), "method": req.get("method", ""),
                    "type": p.get("type", ""),
                })
            elif m == "Network.responseReceived":
                rid = p.get("requestId", "")
                resp = p.get("response", {})
                reqs.setdefault(rid, {})
                reqs[rid].update({
                    "status": resp.get("status", 0),
                    "mime": resp.get("mimeType", ""),
                })
            elif m == "Runtime.consoleAPICalled":
                vals = [a.get("value") for a in p.get("args", []) if "value" in a]
                console.append({"type": p.get("type", ""),
                                "text": " ".join(str(v) for v in vals)[:300]})
        network = [r for r in reqs.values() if r.get("url")]
        xhr = [r for r in network if str(r.get("type", "")).lower() in ("xhr", "fetch")]
        return network, xhr, console

    def _render(self, br: _Browser, action: Action, url: str, net_only: bool) -> dict[str, Any]:
        wait = float(action.args.get("wait", 3) or 3)
        br.cdp.cmd("Page.enable", session=br.session)
        br.cdp.cmd("Runtime.enable", session=br.session)
        br.cdp.cmd("Network.enable", session=br.session)
        br.cdp.cmd("Page.navigate", {"url": url}, session=br.session)
        br.cdp.pump(wait)
        network, xhr, console = self._collect_network(br.cdp.events)
        findings: list[dict[str, Any]] = []
        for c in console:
            if c["type"] == "error":
                findings.append({"check": "console_error", "severity": "info",
                                 "detail": c["text"][:160]})
        out: dict[str, Any] = {
            "url": url,
            "network_count": len(network),
            "network": network[:120],
            "xhr_fetch": xhr[:80],
            "xhr_fetch_count": len(xhr),
            "console": console[:60],
            "findings": findings,
        }
        if net_only:
            return out
        dom = self._eval(br, "document.documentElement.outerHTML") or ""
        tree = self._eval(br, _PAGE_TREE_JS) or {}
        out["title"] = (tree or {}).get("title", "") if isinstance(tree, dict) else ""
        out["dom_length"] = len(dom)
        out["forms"] = (tree or {}).get("forms", []) if isinstance(tree, dict) else []
        out["links"] = (tree or {}).get("links", []) if isinstance(tree, dict) else []
        out["scripts"] = (tree or {}).get("scripts", []) if isinstance(tree, dict) else []
        out["inputs"] = (tree or {}).get("inputs", []) if isinstance(tree, dict) else []
        return out

    def _js_eval(self, br: _Browser, action: Action) -> dict[str, Any]:
        script = action.args.get("script") or action.args.get("snippet") or ""
        if not script:
            return {"error": "script/snippet argümanı gerekli (--arg script=\"...\")",
                    "findings": []}
        url = _norm_url(action.args.get("url") or action.target)
        br.cdp.cmd("Page.enable", session=br.session)
        br.cdp.cmd("Runtime.enable", session=br.session)
        br.cdp.cmd("Page.navigate", {"url": url}, session=br.session)
        br.cdp.pump(float(action.args.get("wait", 2) or 2))
        res = br.cdp.cmd("Runtime.evaluate",
                         {"expression": script, "returnByValue": True,
                          "awaitPromise": True, "timeout": 8000},
                         session=br.session)
        result = res.get("result", {})
        exc = res.get("exceptionDetails")
        return {
            "url": url,
            "snippet": script[:200],
            "result": result.get("value") if "value" in result else result.get("description", ""),
            "type": result.get("type", ""),
            "exception": (exc.get("text") if exc else ""),
            "findings": [],
        }

    def _dom_xss(self, br: _Browser, action: Action, url: str) -> dict[str, Any]:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        params = [k for k, _ in query] or [str(action.args.get("param", "q"))]
        if not parts.query and "param" not in action.args:
            query = [("q", "1")]
        br.cdp.cmd("Page.enable", session=br.session)
        br.cdp.cmd("Runtime.enable", session=br.session)
        tested: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        max_tests = int(action.args.get("max_tests", 12) or 12)
        count = 0
        for param in dict.fromkeys(params):
            for tmpl in _XSS_PAYLOADS:
                if count >= max_tests:
                    break
                count += 1
                marker = f"{_XSS_MARKER}{count}"
                payload = tmpl.format(m=marker)
                newq = [(k, (payload if k == param else v)) for k, v in query]
                if param not in dict(newq):
                    newq.append((param, payload))
                test_url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                       urlencode(newq), parts.fragment))
                before = len(br.cdp.events)
                br.cdp.cmd("Page.navigate", {"url": test_url}, session=br.session)
                br.cdp.pump(float(action.args.get("wait", 1.5) or 1.5))
                _, _, console = self._collect_network(br.cdp.events[before:])
                hit = any(marker in c["text"] for c in console)
                tested.append({"param": param, "payload": payload[:60], "executed": hit})
                if hit:
                    findings.append({
                        "check": "dom_xss", "parameter": param, "severity": "high",
                        "detail": f"JS yürütme doğrulandı (konsol işareti): {param} ← {payload[:50]}",
                    })
        return {
            "url": url,
            "vulnerable": bool(findings),
            "tested": tested,
            "findings": findings,
        }

    def _screenshot(self, br: _Browser, action: Action, url: str) -> dict[str, Any]:
        br.cdp.cmd("Page.enable", session=br.session)
        br.cdp.cmd("Page.navigate", {"url": url}, session=br.session)
        br.cdp.pump(float(action.args.get("wait", 3) or 3))
        res = br.cdp.cmd("Page.captureScreenshot", {"format": "png"}, session=br.session)
        data = res.get("data", "")
        if not data:
            return {"error": "ekran görüntüsü alınamadı", "findings": []}
        out_dir = Path.home() / ".kalkan" / "loot"
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = f"screenshot_{host_of(url)}_{int(time.time())}.png"
        path = out_dir / fname
        try:
            path.write_bytes(base64.b64decode(data))
        except (OSError, ValueError) as exc:
            return {"error": f"ekran görüntüsü yazılamadı: {exc}", "findings": []}
        return {"url": url, "screenshot_path": str(path),
                "size_bytes": path.stat().st_size, "findings": []}


_PAGE_TREE_JS = """
(function(){
  const q=(s)=>Array.from(document.querySelectorAll(s));
  const uniq=(a)=>Array.from(new Set(a));
  return {
    title: document.title || "",
    forms: q('form').slice(0,30).map(f=>({
      action: f.action||"", method: (f.method||"get"),
      inputs: q('input,select,textarea').filter(i=>f.contains(i))
               .map(i=>i.name||i.id).filter(Boolean).slice(0,30)
    })),
    links: uniq(q('a[href]').map(a=>a.href)).slice(0,100),
    scripts: uniq(q('script[src]').map(s=>s.src)).slice(0,100),
    inputs: q('input,select,textarea').map(i=>i.name||i.id).filter(Boolean).slice(0,60)
  };
})()
"""
