"""Call-back guard.

The standard defence against payee fraud is to phone the vendor before paying a
changed account. That only works if the phone number is trustworthy. If software
(an integration key) rewrote a vendor's contact details, a call-back to the number
on file may reach the attacker. This lists those vendors and marks which of them are
on the hold/verify list, so Finance calls the number in the contract instead.
"""
from __future__ import annotations

import re

import pandas as pd


def run(ev, ident, vendors: pd.DataFrame, analysis_end, cfg) -> dict:
    ch = ev.changes
    if ch.empty:
        return {"rows": pd.DataFrame(), "findings": [], "by_vendor": {}}
    contact = ch[ch["field"].str.contains(r"contact|email|phone|mobile", flags=re.I, regex=True)]
    soft = contact[contact["changed_by"].map(lambda a: ident.is_credential(a) or ident.is_external(ident.entity(a)))]
    since = analysis_end - pd.Timedelta(days=30)
    recent = soft[soft["ts"] >= since]
    listed = set(vendors["vendor_id"]) if len(vendors) else set()
    rows = []
    for (vid, name), g in recent.groupby(["vendor_id", "vendor_name"]):
        rows.append(dict(vendor_id=vid, vendor_name=name, changes=len(g), fields=", ".join(sorted(set(g["field"]))),
                         last=g["ts"].max(), by=", ".join(sorted(set(g["changed_by"]))), on_payment_list=vid in listed,
                         refs=list(g["ref"])))
    df = pd.DataFrame(rows)
    by_vendor = {r["vendor_id"]: r for r in rows}
    findings = []
    if len(df):
        on_list = df[df["on_payment_list"]]
        findings.append(dict(
            module="callback", category="change-control", severity=58,
            title="Call-back numbers on file cannot be trusted",
            ts_first=recent["ts"].min(), ts_last=recent["ts"].max(), entity=", ".join(sorted(set(recent["changed_by"]))),
            cred=", ".join(sorted(set(recent["changed_by"]))), ip="", refs=list(recent["ref"]),
            summary=f"Software rewrote contact details for {len(df)} vendor(s) in the 30 days before the next run "
                    f"({len(recent)} changes, no approval reference). A call-back to the number on file proves nothing for them"
                    + (f"; {len(on_list)} are on the hold/verify list: {', '.join(on_list['vendor_id'])}" if len(on_list) else "") + ".",
            details={},
        ))
    return {"rows": df, "findings": findings, "by_vendor": by_vendor}
