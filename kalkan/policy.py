"""Aksiyon onay kapisi.

Scope "nereye" sorusunu, Policy "ne" sorusunu cevaplar. Ikisi de
gecilmeden Executor hicbir sey calistirmaz.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import Action, Risk


class PolicyDenied(Exception):
    """Aksiyon politika tarafindan reddedildi."""


Approver = Callable[[Action], bool]


@dataclass
class Policy:
    """Varsayilan olarak muhafazakar: intrusive ve ustu onay ister."""

    require_approval_at: Risk = Risk.INTRUSIVE
    allow_destructive: bool = False
    allow_intrusive: bool = True

    def check(self, action: Action, approve: Approver | None = None) -> None:
        if action.risk >= Risk.DESTRUCTIVE and not self.allow_destructive:
            raise PolicyDenied(
                f"{action.tool}.{action.capability} yıkıcı seviyede; --allow-destructive verilmedi"
            )
        if action.risk >= Risk.INTRUSIVE and not self.allow_intrusive:
            raise PolicyDenied(
                f"{action.tool}.{action.capability} intrusive; --allow-intrusive verilmedi"
            )
        if action.risk >= self.require_approval_at:
            if approve is None:
                raise PolicyDenied(
                    f"{action.tool}.{action.capability} onay gerektiriyor ama onay mekanizması yok"
                )
            if not approve(action):
                raise PolicyDenied(f"kullanıcı reddetti: {action.describe()}")

    def describe(self) -> str:
        return (
            f"onay eşiği={self.require_approval_at.label} "
            f"intrusive={self.allow_intrusive} destructive={self.allow_destructive}"
        )
