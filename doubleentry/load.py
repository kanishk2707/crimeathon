"""Load the evidence folder into normalised frames.

Files are discovered by their evidence code prefix (E01*.csv, E04*.json ...), so
'E01_ledgerone_api.csv' and 'e01.csv' both work. Missing files are tolerated:
every module degrades to 'not enough evidence' instead of crashing.

All timestamps become naive UTC.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from .util import col, epoch_to_naive, norm_ep, num, status_ok, to_utc_naive


@dataclass
class Evidence:
    folder: Path
    cfg: dict
    api: pd.DataFrame = None
    hd: pd.DataFrame = None
    sso: pd.DataFrame = None
    bv: pd.DataFrame = None
    flows: pd.DataFrame = None
    changes: pd.DataFrame = None
    roster: pd.DataFrame = None
    iocs: pd.DataFrame = None
    register: list = field(default_factory=list)
    context: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def _find(folder: Path, code: str, exts=(".csv", ".json", ".xlsx")):
    pat = re.compile(rf"^{code}(?!\d)", re.I)
    for p in sorted(folder.iterdir()):
        if p.is_file() and pat.match(p.name) and p.suffix.lower() in exts:
            return p
    return None


def _read_table(p: Path) -> pd.DataFrame:
    if p.suffix.lower() == ".xlsx":
        return pd.read_excel(p, dtype=str).fillna("")
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [data])
        return pd.DataFrame(data).astype(str)
    return pd.read_csv(p, dtype=str, keep_default_na=False, encoding_errors="replace")


def _ids(series: pd.Series, code: str) -> pd.Series:
    s = series.astype(str).str.strip()
    fallback = pd.Series([f"row{i}" for i in range(len(s))], index=s.index)
    return s.where(s != "", fallback)


def _api(df: pd.DataFrame, code: str) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["ts"] = to_utc_naive(col(df, "ts_utc", "timestamp", "ts", "time"))
    out["src"] = code
    out["rid"] = _ids(col(df, "request_id", "id"), code)
    out["cred"] = col(df, "api_key_id", "key_id", "api_key", "credential_id").str.strip()
    out["ip"] = col(df, "caller_ip", "source_ip", "ip", "src_ip").str.strip()
    out["ua"] = col(df, "user_agent", "ua").str.strip()
    out["endpoint"] = col(df, "endpoint", "path", "url")
    out["method"] = col(df, "method", "http_method").str.upper().str.strip()
    out["records"] = num(col(df, "records_returned", "records", "count", default="0"))
    out["status"] = col(df, "status", "status_code", "result")
    out["ep"] = out["endpoint"].map(norm_ep)
    out["ok"] = out["status"].map(status_ok)
    rd = out["method"].isin(["GET", "HEAD", "OPTIONS"]) | (
        out["method"].isin(["POST", ""]) & out["ep"].str.contains(r"search|query|export|download|report|list", regex=True)
    )
    out["op"] = rd.map({True: "read", False: "write"})
    out["token"] = out["method"].where(out["method"] != "", "?") + " " + out["ep"]
    out["system"] = "LedgerOne"
    out["ref"] = code + ":" + out["rid"]
    return out


def _hd(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    off = int(cfg["local_tz_offset_minutes"].get("E02", 330))
    out = pd.DataFrame(index=df.index)
    out["ts"] = to_utc_naive(col(df, "ts_local", "ts", "timestamp", "time"), off)
    out["src"] = "E02"
    out["rid"] = _ids(col(df, "event_id", "id"), "E02")
    out["cred"] = col(df, "actor", "user", "principal").str.strip()
    out["actor_type"] = col(df, "actor_type", "type").str.lower()
    out["action"] = col(df, "action", "event", "operation").str.strip().str.lower()
    out["object_id"] = col(df, "object_id", "object", "target")
    out["ip"] = col(df, "source_ip", "ip", "caller_ip").str.strip()
    out["result"] = col(df, "result", "status")
    out["details"] = col(df, "details", "detail", "message")
    rec = out["details"].str.extract(r"(?:records|count|rows|items|n)\s*[=:]\s*(\d+)", flags=re.I)[0]
    out["records"] = pd.to_numeric(rec, errors="coerce").fillna(1)
    a = out["action"]
    exp = a.str.contains(cfg["export_action_regex"], regex=True)
    dl = a.str.contains(cfg["download_action_regex"], regex=True)
    de = a.str.contains(cfg["delete_action_regex"], regex=True)
    rd = a.str.contains(cfg["read_action_regex"], regex=True)
    wr = a.str.contains(cfg["write_action_regex"], regex=True)
    op = pd.Series("other", index=df.index)
    op = op.mask(rd, "read").mask(wr & ~rd, "write")
    op = op.mask(exp, "export_other").mask(exp & wr, "export_create").mask(exp & dl, "export_download").mask(exp & de, "export_delete")
    out["op"] = op
    out["ok"] = out["result"].map(lambda s: status_ok(s) or str(s).strip() == "")
    out["ua"] = ""
    out["ep"] = out["action"]
    out["token"] = out["action"]
    out["system"] = "HelpDeskr"
    out["ref"] = "E02:" + out["rid"]
    return out


def _sso(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["ts"] = to_utc_naive(col(df, "ts_utc", "ts", "timestamp"))
    out["rid"] = _ids(col(df, "event_id", "id"), "E03")
    out["user"] = col(df, "user", "username").str.strip().str.lower()
    out["ip"] = col(df, "source_ip", "ip").str.strip()
    out["city"] = col(df, "city", "location")
    out["auth"] = col(df, "auth_method")
    out["mfa"] = col(df, "mfa_result", "mfa")
    out["device"] = col(df, "device_id", "device")
    out["result"] = col(df, "result", "status").str.lower()
    out["ok"] = out["result"].map(status_ok)
    out["ref"] = "E03:" + out["rid"]
    return out


def _bv(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    ep = col(df, "epoch_s", "epoch", "ts")
    out["ts_raw"] = epoch_to_naive(ep) if ep.str.match(r"^\d+(\.\d+)?$").mean() > 0.5 else to_utc_naive(ep)
    out["ts"] = out["ts_raw"]
    out["rid"] = _ids(col(df, "event_id", "id"), "E05")
    out["principal"] = col(df, "principal", "user", "actor").str.strip()
    out["ip"] = col(df, "source_ip", "ip").str.strip()
    out["action"] = col(df, "action", "operation").str.upper().str.strip()
    out["path"] = col(df, "path", "object", "key")
    out["bytes"] = num(col(df, "bytes", "size", default="0"))
    out["result"] = col(df, "result", "status")
    out["ref"] = "E05:" + out["rid"]
    return out


def _sysname(s: str) -> str:
    raw = (s or "").strip()
    s = raw.lower()
    if re.search(r"sandbox|staging|test|dev\b|uat", s):
        return raw  # a non-production target must never witness production traffic
    if "ledger" in s:
        return "LedgerOne"
    if "help" in s or "desk" in s:
        return "HelpDeskr"
    if "vault" in s or "blue" in s:
        return "BlueVault"
    return s


def _flows(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["ts"] = to_utc_naive(col(df, "ts_utc", "ts", "timestamp"))
    out["rid"] = _ids(col(df, "flow_id", "id"), "E15")
    out["src_ip"] = col(df, "src_ip", "source_ip").str.strip()
    out["label"] = col(df, "src_label", "label")
    out["system"] = col(df, "dst_system", "dst", "destination").map(_sysname)
    out["port"] = col(df, "dst_port", "port")
    out["bytes_out"] = num(col(df, "bytes_out", default="0"))
    out["bytes_in"] = num(col(df, "bytes_in", default="0"))
    out["tunnel"] = col(df, "tunnel_id", "tunnel")
    out["result"] = col(df, "result", "action")
    out["ref"] = "E15:" + out["rid"]
    return out


def _changes(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["ts"] = to_utc_naive(col(df, "ts_utc", "ts", "timestamp"))
    out["rid"] = _ids(col(df, "change_id", "id"), "E19")
    out["vendor_id"] = col(df, "vendor_id").str.strip()
    out["vendor_name"] = col(df, "vendor_name", "vendor")
    out["field"] = col(df, "field", "attribute").str.strip()
    out["old"] = col(df, "old_value", "old")
    out["new"] = col(df, "new_value", "new")
    out["changed_by"] = col(df, "changed_by", "actor", "user").str.strip()
    out["channel"] = col(df, "channel", "via").str.strip()
    out["approval"] = col(df, "approval_ref", "approval").str.strip()
    out["ip"] = col(df, "source_ip", "ip").str.strip()
    out["request_id"] = col(df, "request_id").str.strip()
    out["ref"] = "E19:" + out["rid"]
    return out


def _roster(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["employee_id"] = col(df, "employee_id", "id")
    out["username"] = col(df, "username", "user").str.strip().str.lower()
    out["full_name"] = col(df, "full_name", "name")
    out["department"] = col(df, "department")
    out["role"] = col(df, "role", "title")
    out["status"] = col(df, "status").str.strip()
    out["manager"] = col(df, "manager")
    out["termination_date"] = pd.to_datetime(col(df, "termination_date", "leave_date"), errors="coerce", format="mixed")
    out["notes"] = col(df, "notes")
    return out


def _iocs(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["indicator"] = col(df, "indicator", "value").str.strip()
    out["type"] = col(df, "type").str.lower()
    out["first_seen"] = to_utc_naive(col(df, "first_seen"))
    out["last_seen"] = to_utc_naive(col(df, "last_seen"))
    out["confidence"] = col(df, "confidence")
    out["vendor_note"] = col(df, "vendor_note", "note", "notes")
    return out


def _register(p: Path) -> list:
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [data])
    else:
        data = _read_table(p).to_dict("records")
    out = []
    for e in data:
        out.append({str(k).lower().strip(): ("" if v is None else v) for k, v in e.items()})
    return out


def load_evidence(folder: str | Path, cfg: dict) -> Evidence:
    folder = Path(folder)
    ev = Evidence(folder=folder, cfg=cfg)
    empty = pd.DataFrame()

    def note_src(code, p, n, clock):
        ev.sources[code] = {"file": p.name if p else None, "rows": n, "clock": clock}

    frames = []
    for code in ("E01", "E18"):
        p = _find(folder, code)
        if p:
            d = _api(_read_table(p), code)
            frames.append(d)
            note_src(code, p, len(d), "UTC")
        else:
            note_src(code, None, 0, "UTC")
    ev.api = pd.concat(frames, ignore_index=True) if frames else _api(pd.DataFrame(columns=["ts_utc"]), "E01")
    # E18 continues E01: drop duplicated request ids if both exports overlap
    ev.api = ev.api.drop_duplicates(subset=["rid", "ts"], keep="first").sort_values("ts").reset_index(drop=True)

    loaders = {
        "E02": (lambda d: _hd(d, cfg), "hd", "tenant local (IST) -> UTC"),
        "E03": (_sso, "sso", "UTC"),
        "E05": (_bv, "bv", "epoch, unsynchronised"),
        "E14": (_roster, "roster", "n/a"),
        "E15": (_flows, "flows", "UTC"),
        "E17": (_iocs, "iocs", "UTC (vendor supplied)"),
        "E19": (_changes, "changes", "UTC"),
    }
    for code, (fn, attr, clock) in loaders.items():
        p = _find(folder, code)
        if p:
            d = fn(_read_table(p))
            if "ts" in d.columns:
                d = d.sort_values("ts").reset_index(drop=True)
            setattr(ev, attr, d)
            note_src(code, p, len(d), clock)
        else:
            setattr(ev, attr, fn(pd.DataFrame()) if code != "E14" else _roster(pd.DataFrame()))
            note_src(code, None, 0, clock)
            ev.notes.append(f"{code} not found - modules depending on it run in reduced mode.")

    p = _find(folder, "E04", (".json", ".csv", ".xlsx"))
    ev.register = _register(p) if p else []
    note_src("E04", p, len(ev.register), "current state, no history")
    ctx = folder / "context.json"
    if ctx.exists():
        ev.context = json.loads(ctx.read_text(encoding="utf-8"))
    return ev
