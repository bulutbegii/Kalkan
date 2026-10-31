"""Degistirilemez (hash zincirli) denetim kaydi.

Her kayit bir oncekinin hash'ini tasir. Tek bir satiri degistirirsen
zincir kirilir ve `verify()` bunu yakalar. Adli inceleme icin yeterli
bir taban; imzalama (GPG/HSM) sonradan eklenebilir.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last_seq, last_hash = 0, GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                last_seq, last_hash = record["seq"], record["hash"]
        return last_seq, last_hash

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        seq, prev = self._last()
        body = {
            "seq": seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": fields,
            "prev": prev,
        }
        body["hash"] = _hash(body)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical(body) + "\n")
        return body

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "kayıt dosyası yok (boş zincir)"
        expected_prev = GENESIS
        expected_seq = 1
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                stored = record.pop("hash", None)
                if record.get("seq") != expected_seq:
                    return False, f"satır {lineno}: seq {record.get('seq')} beklenen {expected_seq}"
                if record.get("prev") != expected_prev:
                    return False, f"satır {lineno}: prev hash kopuk"
                if _hash(record) != stored:
                    return False, f"satır {lineno}: içerik hash'i tutmuyor (kayıt değiştirilmiş)"
                expected_prev = stored
                expected_seq += 1
        return True, f"zincir sağlam, {expected_seq - 1} kayıt doğrulandı"

    def tail(self, n: int = 10) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return [json.loads(ln) for ln in lines[-n:]]
