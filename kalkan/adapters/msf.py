"""Metasploit adaptoru - modul dogrulama (check), kontrollu exploit (run)
ve oturum sonrasi (post) kesif.

Guvenlik tasarimi:
  * MOD YETENEGE BAGLIDIR, argumana degil:
      - exploit_check  -> her zaman `check` (INTRUSIVE). mode=run ile
        kandirilamaz; gercek exploit ayri yetenektir.
      - exploit_run    -> `exploit` (DESTRUCTIVE); yalnizca --allow-destructive
        + onaydan gecerse calisir.
      - auxiliary_scan -> yardimci modul calistirir (INTRUSIVE).
  * Oturum arka planda birakilir (`-z`); payload varsa handler job olarak (`-j`).
  * `post` argumani verilirse acilan oturumlarda SADECE kesif komutlari
    (sysinfo/getuid vb.) calisir; varsayilan zararsizdir.
  * Tum konsol ciktisi bir spool dosyasina yazilir ve loot olarak dondurulur
    (rapor katmani bunu reports/loot altina kaydeder).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from ..models import Action, ActionResult, Risk
from ..registry import ToolSpec
from ._common import read_text
from .base import Adapter

_DEFAULT_POST = "sysinfo; getuid; getpid"


class MetasploitAdapter(Adapter):
    spec = ToolSpec(
        name="msf",
        capabilities=("exploit_check", "exploit_run", "auxiliary_scan"),
        risk=Risk.INTRUSIVE,
        binary="msfconsole",
        description="Metasploit: modul dogrulama (check) ve kontrollu exploit (run)",
    )

    def __init__(self) -> None:
        self._dir: Path | None = None
        self._rc: Path | None = None
        self._spool: Path | None = None
        self._rc_body = ""

    @staticmethod
    def _mode_for(capability: str, args: dict) -> str:
        if capability == "exploit_run":
            return "run"
        if capability == "auxiliary_scan":
            return "run"
        return "check"

    def _build_rc(self, action: Action, spool: str | None = None) -> str:
        args = action.args
        module = args.get("module")
        if not module:
            raise ValueError("msf aksiyonu 'module' argümanı gerektirir")
        mode = self._mode_for(action.capability, args)
        lines: list[str] = []
        if spool:
            lines.append(f"spool {spool}")
        lines += [f"use {module}", f"set RHOSTS {action.target}"]
        if args.get("rport"):
            lines.append(f"set RPORT {args['rport']}")
        if args.get("payload"):
            lines.append(f"set PAYLOAD {args['payload']}")
        if args.get("lhost"):
            lines.append(f"set LHOST {args['lhost']}")
        if args.get("lport"):
            lines.append(f"set LPORT {args['lport']}")
        for key, value in (args.get("options") or {}).items():
            lines.append(f"set {key} {value}")
        lines += ["set VERBOSE false", "set ExitOnSession false", "set THREADS 1"]
        if mode == "run":
            lines.append("exploit -z -j" if args.get("payload") else "exploit -z")
            lines.append("sleep 3")
            lines.append("sessions -l")
            post = args.get("post")
            if post:
                cmds = _DEFAULT_POST if str(post) in ("1", "true", "yes") else str(post)
                for cmd in (c.strip() for c in cmds.split(";") if c.strip()):
                    lines.append(f"sessions -C {cmd}")
        else:
            lines.append("check")
        if spool:
            lines.append("spool off")
        lines.append("exit -y")
        return "\n".join(lines) + "\n"

    def prepare(self, action: Action) -> None:
        self._dir = Path(tempfile.mkdtemp(prefix="kalkan-msf-"))
        self._spool = self._dir / "console.log"
        self._rc_body = self._build_rc(action, spool=str(self._spool))
        self._rc = self._dir / "job.rc"
        self._rc.write_text(self._rc_body, encoding="utf-8")

    def command(self, action: Action) -> list[str]:
        if self._rc is None:
            raise RuntimeError("prepare() çağrılmadan command() kullanılamaz")
        return ["msfconsole", "-q", "-n", "-r", str(self._rc)]

    def cleanup(self) -> None:
        for p in (self._rc,):
            if p and p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

    def dry_run(self, action: Action) -> str:
        body = self._build_rc(action, spool="<spool>")
        reason = self.unavailable_reason()
        head = f"[dry-run:{reason}] " if reason else "[dry-run] "
        return head + "msfconsole -q -n -r <job.rc>\n" + body

    def run(self, action: Action, timeout: int = 600) -> ActionResult:
        result = super().run(action, timeout=timeout)
        result.parsed.setdefault("rc_script", self._rc_body)
        loot = ""
        if self._spool and self._spool.exists():
            loot = read_text(self._spool)
        result.parsed.update(self.parse(loot or result.stdout, action))
        return result

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        text = (stdout or "").lower()
        mode = self._mode_for(action.capability, action.args)
        vulnerable = any(
            m in text
            for m in (
                "the target is vulnerable",
                "appears to be vulnerable",
                "the target appears to be vulnerable",
            )
        )
        sessions = [
            line.strip()
            for line in (stdout or "").splitlines()
            if line.strip().lower().startswith(("meterpreter session", "command shell session"))
        ]
        out: dict[str, Any] = {
            "module": action.args.get("module", ""),
            "mode": mode,
            "vulnerable": vulnerable,
            "sessions": sessions,
            "session_count": len(sessions),
            "completed": any(
                m in text for m in (
                    "auxiliary module execution completed",
                    "exploit completed",
                    "check completed",
                )
            ),
        }
        if mode == "run" and stdout and stdout.strip():
            out["loot_text"] = stdout
            out["loot_name"] = f"msf_{action.args.get('module', 'module').replace('/', '_')}"
            if sessions:
                findings = [{
                    "severity": "critical",
                    "check": "session_opened",
                    "detail": f"OTURUM ACILDI: {s}",
                } for s in sessions]
                out["findings"] = findings
        return out
