"""Analyst labels for the REAL evidence, written down from the manual investigation.

These are our own conclusions (not organiser-supplied ground truth). Each rule is a
plain statement that can be argued with. Run:  python analysis/make_labels.py evidence analysis/analyst_labels.json
"""
import json, sys
import pandas as pd

ev = sys.argv[1]; out = sys.argv[2]
r = lambda f: pd.read_csv(f"{ev}/{f}", dtype=str, keep_default_na=False)
e01, e18 = r("E01_ledgerone_api_access.csv"), r("E18_ledgerone_api_access_1_to_7_sep.csv")
e02, e03, e05, e19 = r("E02_helpdeskr_audit_log.csv"), r("E03_sso_signin_log.csv"), r("E05_bluevault_access_log.csv"), r("E19_vendor_master_change_log.csv")
ATT = {"198.18.7.41", "198.18.7.58", "10.20.4.77"}
mal, stages = [], {}

def add(stage, refs):
    stages.setdefault(stage, []).extend(refs); mal.extend(refs)

for code, d in (("E01", e01), ("E18", e18)):
    x = d[d.api_key_id.str.startswith("key-tb") & d.caller_ip.isin(ATT)]
    for _, row in x.iterrows():
        ts = row.ts_utc
        st = ("probe_9aug" if ts.startswith("2026-08-09") else "ledger_export_12aug" if ts.startswith("2026-08-12")
              else "build_host_recon_17_19aug" if ts[:10] in ("2026-08-17", "2026-08-18", "2026-08-19") else "bank_tamper_sep")
        add(st, [f"{code}:{row.request_id}"])
x = e02[(e02.actor == "tb-sync-svc") & e02.source_ip.isin(ATT)]
for _, row in x.iterrows():
    st = "ticket_secret_search" if row.action in ("ticket.search", "ticket.read") else "helpdeskr_export_delete"
    if row.source_ip == "10.20.4.77": st = "build_host_ticket_search"
    add(st, [f"E02:{row.event_id}"])
x = e05[(e05.principal == "key:bvk-7f3a") & ~e05.path.str.startswith("/customer-docs")]
add("bluevault_pivot", [f"E05:{i}" for i in x.event_id])
add("bank_tamper_sep", [f"E19:{i}" for i in e19[e19.change_id == "chg-8b9888c39b"].change_id])
x = e03[(e03.user == "a.kapoor") & (e03.source_ip == "198.18.7.77")]
add("admin_password_attempt", [f"E03:{i}" for i in x.event_id])
gov = [f"E03:{i}" for i in e03[(e03.user == "r.menon") & (e03.ts_utc >= "2026-07-01")].event_id]
truth = {"variant": "REAL evidence - analyst labels", "malicious": mal, "governance": gov, "traps": {},
         "stages": {k: {"refs": v, "first": None} for k, v in stages.items()},
         "money": [{"run": "2026-09-08", "vendors": ["V-0412"], "kind": "at risk"}]}
# benign look-alikes named in the case file, to count false alarms on them
truth["traps"]["contractor_travel(c.lawson)"] = [f"E03:{i}" for i in e03[e03.user == "c.lawson"].event_id]
truth["traps"]["weekly_export(s.iyer)"] = [f"E02:{i}" for i in e02[(e02.actor == "s.iyer") & e02.action.str.startswith("export")].event_id]
truth["traps"]["vendor_audit_export(f.dsouza)"] = [f"E01:{i}" for i in e01[(e01.api_key_id == "user:f.dsouza") & e01.endpoint.str.contains("export")].request_id]
truth["traps"]["month_end_bulk_import"] = [f"E19:{i}" for i in e19[e19.approval_ref == "BULK-0731"].change_id]
truth["traps"]["announced_contact_sync(3.6.0)"] = [f"E19:{i}" for i in e19[e19.field.str.startswith("contact") & (e19.channel == "API")].change_id] + \
    [f"E18:{i}" for i in e18[e18.endpoint.str.endswith("/contact")].request_id]
truth["traps"]["nightly_sync(.11-.16)"] = [f"{c}:{i}" for c, d in (("E01", e01), ("E18", e18)) for i in d[d.caller_ip.str.match(r"10\.20\.4\.1[1-6]$")].request_id]
truth["traps"]["staff_on_198.18.7.x"] = [f"E03:{i}" for i in e03[e03.source_ip.str.startswith("198.18.7.") & (e03.user != "a.kapoor")].event_id]
truth["traps"]["approved_human_bank_changes"] = [f"E19:{i}" for i in e19[(e19.field == "bank_account") & (e19.channel == "UI") & (e19.approval_ref != "")].change_id]
json.dump(truth, open(out, "w"), indent=1)
print({k: len(v["refs"]) for k, v in truth["stages"].items()}, "malicious", len(mal))
