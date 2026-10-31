"""Metasploit adaptoru - modul dogrulama (check) ve kontrollu calistirma.

Guvenlik tasarimi:
  * varsayilan mod `check`  -> modul hedefte uygulanabilir mi, dogrular
  * `run` modu sadece acikca istenirse ve onaydan gecerse calisir
  * oturum (session) acilmasi istenmez; `exploit -z` ile arka planda birakilir
  * her calistirma bir .rc dosyasina yazilir; bu dosya denetim icin saklanabilir
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from ..models import Action, ActionResult, Risk
from ..registry import ToolSpec
from .base import Adapter


class MetasploitAdapter(Adapter):
    spec = ToolSpec(
        name="msf",
        capabilities=("exploit_check", "auxiliary_scan", "exploit_run"),
        risk=Risk.INTRUSIVE,
        binary="msfconsole",
        description="Metasploit modul dogrulama ve kontrollu exploit",
    )

    def __init__(self) -> None:
        self._dir: Path | None = None
        self._rc: Path | None = None
        self._rc_body = ""

    def _build_rc(self, action: Action) -> str:
        args = action.args
        module = args.get("module")
        if not module:
            raise ValueError("msf aksiyonu 'module' argümanı gerektirir")
        lines = [f"use {module}", f"set RHOSTS {action.target}"]
        if args.get("rport"):
            lines.append(f"set RPORT {args['rport']}")
        if args.get("payload"):
            lines.append(f"set PAYLOAD {args['payload']}")
        for key, value in (args.get("options") or {}).items():
            lines.append(f"set {key} {value}")
        lines += [
            "set VERBOSE false",
            "set ExitOnSession false",
            "set THREADS 1",
        ]
        mode = args.get("mode", "check")
        if mode == "run":
            if args.get("payload"):
                lines.append("exploit -z -j")
            else:
                lines.append("exploit -z")
        else:
            lines.append("check")
        lines.append("exit -y")
        return "\n".join(lines) + "\n"

    def prepare(self, action: Action) -> None:
        self._rc_body = self._build_rc(action)
        self._dir = Path(tempfile.mkdtemp(prefix="kalkan-msf-"))
        self._rc = self._dir / "job.rc"
        self._rc.write_text(self._rc_body, encoding="utf-8")

    def command(self, action: Action) -> list[str]:
        if self._rc is None:
            raise RuntimeError("prepare() çağrılmadan command() kullanılamaz")
        return ["msfconsole", "-q", "-n", "-r", str(self._rc)]

    def cleanup(self) -> None:
        if self._rc and self._rc.exists():
            try:
                self._rc.unlink()
            except OSError:
                pass
        if self._dir and self._dir.exists():
            try:
                self._dir.rmdir()
            except OSError:
                pass

    def dry_run(self, action: Action) -> str:
        body = self._build_rc(action)
        reason = self.unavailable_reason()
        head = f"[dry-run:{reason}] " if reason else "[dry-run] "
        return head + "msfconsole -q -r <job.rc>\n" + body

    def run(self, action: Action, timeout: int = 600) -> ActionResult:
        result = super().run(action, timeout=timeout)
        result.parsed.setdefault("rc_script", self._rc_body)
        result.parsed.update(self.parse(result.stdout, action))
        return result

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        text = stdout.lower()
        vulnerable = any(
            marker in text
            for marker in (
                "the target is vulnerable",
                "appears to be vulnerable",
                "the target appears to be vulnerable",
            )
        )
        sessions = [
            line.strip()
            for line in stdout.splitlines()
            if line.strip().lower().startswith(("meterpreter session", "command shell session"))
        ]
        return {
            "module": action.args.get("module", ""),
            "mode": action.args.get("mode", "check"),
            "vulnerable": vulnerable,
            "sessions": sessions,
            "session_count": len(sessions),
            "completed": "auxiliary module execution completed" in text
            or "exploit completed" in text
            or "check completed" in text,
        }
