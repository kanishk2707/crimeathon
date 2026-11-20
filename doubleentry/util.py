"""Small shared helpers: IP sets, time parsing, endpoint normalisation."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

import numpy as np
import pandas as pd

IST_MIN = 330


@lru_cache(maxsize=500_000)
def ip_obj(s):
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


class NetSet:
    """Membership test for a list of CIDRs, cached per address."""

    def __init__(self, cidrs):
        self.nets = []
        for c in cidrs or []:
            try:
                self.nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
            except ValueError:
                pass
        self._cache = {}

    def __contains__(self, ip):
        hit = self._cache.get(ip)
        if hit is None:
            o = ip_obj(ip)
            hit = bool(o) and any(o.version == n.version and o in n for n in self.nets)
            self._cache[ip] = hit
        return hit

    def __bool__(self):
        return bool(self.nets)


def net24(ip) -> str:
    o = ip_obj(ip)
    if o is None:
        return ""
    plen = 24 if o.version == 4 else 64
    return str(ipaddress.ip_network(f"{o}/{plen}", strict=False))


_TZ_SUFFIX = re.compile(r"(?:Z|[+-]\d{2}:?\d{2})$")


_SLASH = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})")


def _dayfirst(s: pd.Series) -> bool | None:
    """For dd/mm vs mm/dd strings: decide from the data (a field > 12 settles it).
    Ambiguous data defaults to day-first (Indian tenant convention)."""
    m = s.str.extract(_SLASH)
    if m[0].isna().all():
        return None
    a = pd.to_numeric(m[0], errors="coerce")
    b = pd.to_numeric(m[1], errors="coerce")
    if (b > 12).any() and not (a > 12).any():
        return False
    return True


def to_utc_naive(series: pd.Series, offset_minutes: int = 0) -> pd.Series:
    """Parse timestamps to naive UTC. Strings without a zone are taken as
    local time `offset_minutes` ahead of UTC. dd/mm/yyyy is detected, never guessed as mm/dd."""
    s = series.astype(str).str.strip()
    has_tz = s.str.contains(_TZ_SUFFIX)
    df = _dayfirst(s) if len(s) else None
    if df is None:
        out = pd.to_datetime(s, errors="coerce", utc=True, format="mixed")
    else:
        out = pd.to_datetime(s, errors="coerce", utc=True, dayfirst=df, format="mixed")
    out = out.dt.tz_localize(None)
    if offset_minutes:
        out = out.where(has_tz, out - pd.Timedelta(minutes=offset_minutes))
    return out


_PREFIX = re.compile(r"^(?:user|key|svc|sa|cred|principal|api)[:/]", re.I)


def bare(name) -> str:
    """'user:a.desai' -> 'a.desai' ; 'key:bvk-7f3a' -> 'bvk-7f3a'"""
    if not isinstance(name, str):
        return ""
    return _PREFIX.sub("", name.strip()).lower()


def truthy(v) -> bool | None:
    """E04 fields may be booleans, 'true'/'false', CIDR lists, or blank."""
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "yes", "y", "1", "restricted"):
        return True
    if s in ("", "false", "no", "n", "0", "none", "null", "nan", "-", "n/a", "unlimited", "never"):
        return False
    return None  # something else, e.g. a CIDR list


def epoch_to_naive(series: pd.Series) -> pd.Series:
    v = pd.to_numeric(series, errors="coerce")
    # milliseconds if clearly too large for seconds
    if v.dropna().gt(1e12).mean() > 0.5:
        v = v / 1000.0
    return pd.to_datetime(v, unit="s", errors="coerce")


def col(df: pd.DataFrame, *names, default="") -> pd.Series:
    lower = {c.lower().strip(): c for c in df.columns}
    for n in names:
        if n.lower() in lower:
            return df[lower[n.lower()]].fillna(default).astype(str)
    return pd.Series([default] * len(df), index=df.index, dtype=object)


def num(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series.astype(str).str.replace(",", ""), errors="coerce").fillna(0)


_SEG_ID = re.compile(r"^(?=.*\d)[A-Za-z0-9_\-.:~]+$")
_VERSION_SEG = re.compile(r"^v\d+(\.\d+)?$", re.I)


def norm_ep(ep: str) -> str:
    """'/api/v2/vendors/V0123/bank-details?x=1' -> '/api/v2/vendors/{id}/bank-details'"""
    if not isinstance(ep, str):
        return ""
    p = ep.split("?")[0].split("#")[0].strip()
    out = []
    for seg in p.split("/"):
        if seg and _SEG_ID.match(seg) and not _VERSION_SEG.match(seg):
            out.append("{id}")
        else:
            out.append(seg.lower())
    return "/".join(out)


def status_ok(s) -> bool:
    s = str(s).strip().lower()
    if s.isdigit():
        return 200 <= int(s) < 400
    return s in {"ok", "success", "succeeded", "true", "allowed", "accept", "accepted", "allow"}


_VER = re.compile(r"(\d+(?:\.\d+)+)")


def ua_parts(ua: str):
    """'TallyBridge-Sync 3.5.0' -> ('tallybridge-sync', (3,5,0))"""
    if not isinstance(ua, str) or not ua.strip():
        return ("", ())
    m = _VER.search(ua)
    if not m:
        return (ua.strip().lower(), ())
    prod = ua[: m.start()].strip(" /;(").lower()
    ver = tuple(int(x) for x in m.group(1).split("."))
    return (prod, ver)


def circ_minutes(ts: pd.Series) -> np.ndarray:
    return (ts.dt.hour * 60 + ts.dt.minute).to_numpy(dtype=float)


def circ_mean_std(mins: np.ndarray):
    if len(mins) == 0:
        return 0.0, 1440.0
    ang = mins / 1440.0 * 2 * np.pi
    c, s = np.cos(ang).mean(), np.sin(ang).mean()
    mean = (np.arctan2(s, c) % (2 * np.pi)) / (2 * np.pi) * 1440.0
    r = min(max(np.hypot(c, s), 1e-9), 1.0)
    std = np.sqrt(-2 * np.log(r)) / (2 * np.pi) * 1440.0
    return float(mean), float(std)


def circ_diff(a: float, b: float) -> float:
    d = abs(a - b) % 1440.0
    return min(d, 1440.0 - d)


def fmt_ts(t) -> str:
    if t is None or (isinstance(t, float) and np.isnan(t)) or pd.isna(t):
        return ""
    return pd.Timestamp(t).strftime("%Y-%m-%d %H:%M:%S")


def fmt_ist(t) -> str:
    if t is None or pd.isna(t):
        return ""
    return (pd.Timestamp(t) + pd.Timedelta(minutes=IST_MIN)).strftime("%d %b %H:%M IST")
