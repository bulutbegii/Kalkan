"""Kalkan - guvenlik orkestrasyon cekirdegi.

Tasarim ilkesi: model karar verir, kod uygular, kapsam denetler.
Model ciktisi asla dogrudan calistirilmaz; her aksiyon once
ScopeGuard ve Policy kapilarindan gecer, sonra AuditLog'a yazilir.
"""

__version__ = "0.1.0"
