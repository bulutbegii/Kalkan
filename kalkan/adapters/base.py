"""Adaptor tabani.

Kural: bir adaptor komutu *uretir* ve ciktisi *ayristirir*. Komutu
calistirma karari burada verilmez; Executor kapsam + politika
kontrollerinden sonra cagirir.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _stderr_hint(stderr: str) -> str:
    """stderr'den son anlamlı satırı (ANSI'siz) kısa ipucu olarak çıkar."""
    for line in reversed((stderr or "").splitlines()):
        clean = _ANSI.sub("", line).strip()
        if clean:
            return clean[:160]
    return ""

from ..models import Action, ActionResult
from ..registry import ToolSpec


class Adapter:
    spec: ToolSpec

    def available(self) -> bool:
        if not self.spec.binary:
            return True
        return shutil.which(self.spec.binary) is not None

    def unavailable_reason(self) -> str:
        if self.spec.binary and not self.available():
            return f"'{self.spec.binary}' PATH'te bulunamadı"
        return ""

    def prepare(self, action: Action) -> None:
        """Calistirma oncesi gecici dosya vb. hazirligi (msf .rc gibi)."""

    def command(self, action: Action) -> list[str]:
        raise NotImplementedError

    def cleanup(self) -> None:
        """prepare() ile olusturulan gecici kaynaklari sil."""

    def parse(self, stdout: str, action: Action) -> dict[str, Any]:
        return {}

    def dry_run(self, action: Action) -> str:
        reason = self.unavailable_reason()
        prefix = f"[dry-run:{reason}] " if reason else "[dry-run] "
        return prefix + " ".join(shlex.quote(part) for part in self.command(action))

    def run(self, action: Action, timeout: int = 300) -> ActionResult:
        reason = self.unavailable_reason()
        if reason:
            return ActionResult(action=action, status="unavailable", detail=reason)

        self.prepare(action)
        try:
            cmd = self.command(action)
            started = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    stdin=subprocess.DEVNULL,
                )
            except subprocess.TimeoutExpired:
                return ActionResult(
                    action=action,
                    status="error",
                    command=cmd,
                    duration_s=time.monotonic() - started,
                    detail=f"zaman aşımı ({timeout}s)",
                )
            except FileNotFoundError as exc:
                return ActionResult(action=action, status="unavailable", detail=str(exc))
            duration = time.monotonic() - started
            parsed = self.parse(proc.stdout, action)
            return ActionResult(
                action=action,
                status="ok" if proc.returncode == 0 else "error",
                command=cmd,
                stdout=proc.stdout[-200_000:],
                stderr=proc.stderr[-20_000:],
                parsed=parsed,
                duration_s=duration,
                detail="" if proc.returncode == 0
                else f"çıkış kodu {proc.returncode}" + (
                    f": {_stderr_hint(proc.stderr)}" if _stderr_hint(proc.stderr) else ""
                ),
            )
        finally:
            self.cleanup()


def write_temp(directory: Path, name: str, content: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path
