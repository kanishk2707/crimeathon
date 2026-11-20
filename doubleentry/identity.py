"""Identity resolution: the same actor carries different names in different systems.

key-tb-07 (LedgerOne), tb-sync-svc (HelpDeskr), key-tb-03 (legacy) and the E15
host label 'tb-sync-worker-01' all resolve to one entity, using the E04
register's vendor field plus configurable alias tokens.
"""
from __future__ import annotations

import re

import pandas as pd

from .util import bare


def _sys(s: str) -> str:
    s = (s or "").lower()
    if "ledger" in s:
        return "LedgerOne"
    if "help" in s or "desk" in s:
        return "HelpDeskr"
    if "vault" in s or "blue" in s:
        return "BlueVault"
    return s


class Identity:
    def __init__(self, ev, cfg):
        self.cfg = cfg
        self.internal_re = re.compile(cfg["internal_vendor_regex"], re.I)
        self.aliases = {ent: [t.lower() for t in toks] for ent, toks in cfg.get("entity_aliases", {}).items()}
        self.meta = {}
        self._ent = {}
        self.external_entities = set(self.aliases)
        for e in ev.register:
            cid = str(e.get("credential_id") or e.get("key") or e.get("id") or "").strip()
            if not cid:
                continue
            vendor = str(e.get("vendor") or "").strip()
            integ = str(e.get("integration") or "").strip()
            ent = self._alias_for(f"{cid} {vendor} {integ}")
            if ent is None:
                if vendor and not self.internal_re.search(vendor):
                    ent = vendor
                    self.external_entities.add(vendor)
                else:
                    ent = cid
            self._ent[cid.lower()] = ent
            self.meta[cid] = {**e, "system_norm": _sys(str(e.get("system", ""))), "entity": ent}
        self.humans = set(ev.roster["username"]) if len(ev.roster) else set()

    def _alias_for(self, text: str):
        t = text.lower()
        for ent, toks in self.aliases.items():
            if any(tok and tok in t for tok in toks):
                return ent
        return None

    def entity(self, raw: str) -> str:
        if not isinstance(raw, str) or not raw:
            return ""
        hit = self._ent.get(raw.strip().lower()) or self._ent.get(bare(raw))
        if hit:
            return hit
        a = self._alias_for(raw)
        return a if a else raw.strip()

    def is_external(self, ent: str) -> bool:
        return ent in self.external_entities

    def is_credential(self, raw: str) -> bool:
        return isinstance(raw, str) and (raw.strip().lower() in self._ent or bare(raw) in self._ent)

    def is_human(self, raw: str) -> bool:
        return isinstance(raw, str) and bare(raw) in self.humans

    def creds_of(self, ent: str):
        return [c for c, m in self.meta.items() if m["entity"] == ent]

    def entity_series(self, s: pd.Series) -> pd.Series:
        cache = {}
        return s.map(lambda v: cache.setdefault(v, self.entity(v)))
