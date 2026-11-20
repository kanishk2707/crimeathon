"""Synthetic Harbor & Finch evidence (entirely fictional) with ground truth.

Matches the column layout of Appendix D so the same engine runs on the real
E01-E19 files. Ordinary-but-odd-looking behaviour from section 4 is planted as
labelled 'traps' so false alarms can be measured:

  sync drift and retry storms, the Tuesday support export, month-end bulk vendor
  clean-up (approved), the senior accountant's audit, an approved bank change two
  days before a run, a contractor signing in from many cities, blank BlueVault
  addresses, overnight backup/report jobs.

Attack variants (the 'hidden variation' rehearsal):

  reference        stolen TallyBridge keys used off-link: ticket secret search, export-and-delete,
                   legacy-key probe, BlueVault pivot with a leaked portal key, bank recon,
                   bank tamper before 23 Aug, change-back, second tamper before 8 Sep
  on_link          same campaign from a host INSIDE the private link with flows present and a
                   current client version (vendor infrastructure compromised)
  mimic            off-link but current client version, inside the sync window, no exports:
                   low-and-slow ticket pulls through the normal sync action, single tamper before 8 Sep
  insider          no integration abuse: a leaver's still-active account edits bank details by UI
  forged_approval  daytime API tamper carrying a well-formed approval reference, current client
  inside_worker    the vendor's real sync host is compromised: small skims through real sync endpoints
                   inside the real session (designed to be MISSED), then two bank edits from the same host
"""
from __future__ import annotations

import csv
import json
import random
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path

IST = timedelta(minutes=330)
D0, D_END = date(2026, 6, 3), date(2026, 9, 7)
SSO_START = date(2026, 6, 1)
HD_END = datetime(2026, 8, 31, 18, 29, 59)      # 31 Aug 23:59 IST
LOG_END = datetime(2026, 8, 31, 23, 59, 59)      # E03/E05/E15 end
LINK = {"ledger": "10.20.4.11", "help": "10.20.4.12"}
LINK_LABEL = {"10.20.4.11": "tb-sync-worker-01", "10.20.4.12": "tb-sync-worker-02", "10.20.4.13": "tb-sync-worker-03"}
ATT1, ATT2, ATT_LINK = "203.0.113.45", "198.51.100.23", "10.20.4.13"
UA_OLD, UA_NEW = "TallyBridge-Sync 3.4.1", "TallyBridge-Sync 3.5.0"
UPGRADE = date(2026, 7, 15)
EPOCH = datetime(1970, 1, 1)

VARIANTS = ["reference", "on_link", "mimic", "insider", "forged_approval", "inside_worker"]

FIRST = ["Arun", "Priya", "Karthik", "Divya", "Suresh", "Lakshmi", "Vijay", "Meena", "Rahul", "Anitha", "Ganesh", "Revathi",
         "Senthil", "Kavya", "Arjun", "Deepa", "Manoj", "Nisha", "Ravi", "Shalini", "Bala", "Gayathri", "Hari", "Janani",
         "Kumar", "Lavanya", "Mohan", "Nandini", "Prakash", "Ramya", "Sathish", "Swathi", "Venkat", "Yamini", "Ashok", "Bhavani"]
LAST = ["Raman", "Pillai", "Krishnan", "Natarajan", "Subramanian", "Iyer", "Reddy", "Nair", "Rao", "Venkatesan", "Murthy",
        "Balaji", "Chandran", "Gopal", "Hegde", "Joseph", "Kannan", "Mani", "Prasad", "Selvam"]
VEND_A = ["Coastal", "Southern", "Deccan", "Kaveri", "Marina", "Nilgiri", "Pallava", "Chola", "Vaigai", "Konkan", "Sahyadri", "Palar"]
VEND_B = ["Haulage", "Fuels", "Packaging", "Transport", "Carriers", "Logistics", "Movers", "Freightways", "Pack Co", "Roadlines"]
CITIES = ["Chennai", "Bengaluru", "Hyderabad", "Kochi", "Mumbai", "Pune"]


class World:
    def __init__(self, seed: int = 7, variant: str = "reference", bv_skew: int = 247):
        assert variant in VARIANTS, variant
        self.r = random.Random(seed)
        self.variant = variant
        self.skew = bv_skew
        self.api, self.hd, self.sso, self.bv, self.flows, self.chg = [], [], [], [], [], []
        self.n = defaultdict(int)
        self.truth = {"variant": variant, "malicious": [], "stages": {}, "traps": defaultdict(list),
                      "governance": [], "money": []}
        self.vendors = self._vendors()
        self.staff = self._staff()

    # ------------------------------------------------------------------ records
    def _id(self, p):
        self.n[p] += 1
        return f"{p}-{self.n[p]:06d}"

    def _label(self, ref, ts, stage=None, trap=None, gov=False):
        if stage:
            self.truth["malicious"].append(ref)
            st = self.truth["stages"].setdefault(stage, {"refs": [], "first": None})
            st["refs"].append(ref)
            if st["first"] is None or ts.isoformat() < st["first"]:
                st["first"] = ts.isoformat()
        if trap:
            self.truth["traps"][trap].append(ref)
        if gov:
            self.truth["governance"].append(ref)

    def secs(self, a, b):
        return timedelta(seconds=self.r.uniform(a, b))

    def flow(self, ts, ip, system, records):
        if ts > LOG_END:
            return
        fid = self._id("FL")
        self.flows.append(dict(ts_utc=ts + self.secs(-1.5, 1.5), flow_id=fid, src_ip=ip, src_label=LINK_LABEL.get(ip, "unknown"),
                               dst_system=system, dst_port=443, bytes_out=int(600 + self.r.random() * 900),
                               bytes_in=int(records * 850 + self.r.random() * 4000), tunnel_id="tun-hf-01", result="ACCEPT"))

    def api_call(self, ts, cred, ip, ua, endpoint, method, records, status=200, stage=None, trap=None, flow=None):
        rid = self._id("REQ")
        code = "E18" if ts.date() >= date(2026, 9, 1) else "E01"
        self.api.append(dict(ts_utc=ts, request_id=rid, api_key_id=cred, caller_ip=ip, user_agent=ua, endpoint=endpoint,
                             method=method, records_returned=records, status=status, _code=code))
        self._label(f"{code}:{rid}", ts, stage, trap)
        if flow is None:
            flow = ip.startswith("10.20.4.")
        if flow:
            self.flow(ts, ip, "LedgerOne", records)
        return rid

    def hd_event(self, ts, actor, actor_type, action, obj, ip, details="", result="success", stage=None, trap=None, flow=None):
        if ts > HD_END:
            return None
        eid = self._id("EVT")
        self.hd.append(dict(ts_local=ts + IST, event_id=eid, actor=actor, actor_type=actor_type, action=action, object_id=obj,
                            source_ip=ip, result=result, details=details))
        self._label(f"E02:{eid}", ts, stage, trap)
        if flow is None:
            flow = ip.startswith("10.20.4.")
        if flow:
            self.flow(ts, ip, "HelpDeskr", 1)
        return eid

    def bv_event(self, ts, principal, ip, action, path, nbytes, stage=None, trap=None):
        if ts > LOG_END:
            return
        eid = self._id("BV")
        self.bv.append(dict(epoch_s=int((ts - EPOCH).total_seconds()) + self.skew, event_id=eid, principal=principal,
                            source_ip=ip, action=action, path=path, bytes=int(nbytes), result="success"))
        self._label(f"E05:{eid}", ts, stage, trap)

    def sso_event(self, ts, user, ip, city, auth, mfa, device, result="success", failure="", stage=None, trap=None, gov=False):
        if ts > LOG_END:
            return
        eid = self._id("SSO")
        self.sso.append(dict(ts_utc=ts, event_id=eid, user=user, source_ip=ip, city=city, auth_method=auth, mfa_result=mfa,
                             device_id=device if ts.date() >= date(2026, 6, 20) else "", result=result, failure_reason=failure))
        self._label(f"E03:{eid}", ts, stage, trap, gov)

    def change(self, ts, vid, fld, new, by, channel, approval, ip, request_id="", stage=None, trap=None):
        cid = self._id("CHG")
        v = self.vendors[vid]
        old = v[fld]
        v[fld] = new
        self.chg.append(dict(ts_utc=ts, change_id=cid, vendor_id=vid, vendor_name=v["name"], field=fld, old_value=old,
                             new_value=new, changed_by=by, channel=channel, approval_ref=approval, source_ip=ip,
                             request_id=request_id))
        self._label(f"E19:{cid}", ts, stage, trap)
        return old

    # ------------------------------------------------------------------ people / vendors
    def _vendors(self):
        out = {}
        for i in range(1, 301):
            vid = f"V{i:04d}"
            out[vid] = dict(name=f"{self.r.choice(VEND_A)} {self.r.choice(VEND_B)}",
                            bank_account=f"{self.r.randint(10**13, 10**14 - 1)}",
                            ifsc=f"{self.r.choice(['HDFC', 'ICIC', 'SBIN', 'UTIB', 'KKBK'])}0{self.r.randint(100000, 999999)}",
                            phone=f"+91-44-{self.r.randint(20000000, 29999999)}", email=f"accounts@vendor{i:04d}.example",
                            address=f"{self.r.randint(1, 200)}, Industrial Estate", contact_name=self.r.choice(FIRST),
                            payment_terms="NET30", status="active")
        return out

    def _staff(self):
        named = [
            ("E1001", "dev.raghavan", "Dev Raghavan", "Management", "General Manager", "Active", "", "2012-04-01", ""),
            ("E1002", "madhavi.sundar", "Madhavi Sundar", "Finance", "Finance Manager", "Active", "dev.raghavan", "2014-07-14", ""),
            ("E1003", "farah.dsouza", "Farah Dsouza", "Finance", "Senior Accountant", "Active", "madhavi.sundar", "2017-01-09", ""),
            ("E1004", "sunita.iyer", "Sunita Iyer", "Support", "Support Team Lead", "Active", "dev.raghavan", "2016-03-21", ""),
            ("E1005", "aditi.kapoor", "Aditi Kapoor", "IT", "IT Security Administrator", "Active", "dev.raghavan", "2018-02-05", ""),
            ("E1006", "pradeep.shah", "Pradeep Shah", "IT", "IT Officer", "Active", "aditi.kapoor", "2019-08-12", ""),
            ("E1007", "prakash.menon", "Prakash Menon", "IT", "Helpdesk Technician", "Active", "aditi.kapoor", "2021-05-03", ""),
            ("E1008", "colin.lawson", "Colin Lawson", "IT", "Network Contractor", "Active", "aditi.kapoor", "2023-10-02", "contractor; travels"),
            ("E1009", "rohan.menon", "Rohan Menon", "Finance", "Accounts Payable Clerk", "Terminated", "madhavi.sundar", "2020-11-16", "2026-06-30"),
            ("E1010", "kavya.raman", "Kavya Raman", "Finance", "Accountant", "Active", "madhavi.sundar", "2022-02-14", ""),
            ("E1011", "arjun.pillai", "Arjun Pillai", "Finance", "AP Executive", "Active", "madhavi.sundar", "2023-06-19", ""),
            ("E1012", "suresh.krishnan", "Suresh Krishnan", "Operations", "Dispatcher", "Active", "dev.raghavan", "2019-03-11", "2026-07-15"),
        ]
        rows = [dict(employee_id=a, username=b, full_name=c, department=d, role=e, status=f, manager=g, hire_date=h,
                     termination_date=i, notes=("HR list not updated" if b == "suresh.krishnan" else ("" if b != "colin.lawson" else "contractor; travels")))
                for a, b, c, d, e, f, g, h, i in named]
        used = {r["username"] for r in rows}
        depts = [("Support", "Support Agent", 45), ("Operations", "Dispatcher", 30), ("Finance", "Accounts Executive", 6),
                 ("Warehouse", "Warehouse Associate", 12), ("Sales", "Account Manager", 10), ("IT", "Systems Engineer", 6)]
        k = 2000
        for dept, role, n in depts:
            for _ in range(n):
                while True:
                    fn, ln = self.r.choice(FIRST), self.r.choice(LAST)
                    u = f"{fn}.{ln}".lower()
                    if u not in used:
                        break
                used.add(u)
                rows.append(dict(employee_id=f"E{k}", username=u, full_name=f"{fn} {ln}", department=dept, role=role,
                                 status="Active", manager="", hire_date="2021-01-04", termination_date="", notes=""))
                k += 1
        return rows

    # ------------------------------------------------------------------ routine behaviour
    def sync_night(self, d):
        r = self.r
        start = datetime(d.year, d.month, d.day, 20, 45) + timedelta(minutes=r.gauss(0, 10))
        trap = None
        if r.random() < 0.10:
            start += timedelta(minutes=r.randint(55, 95)); trap = "sync_drift"
        retry = r.random() < 0.06
        fail = r.random() < 0.03
        ua = UA_OLD if d < UPGRADE else UA_NEW
        t = start
        for obj, pages in [("invoices", r.randint(3, 8)), ("customers", r.randint(1, 3)), ("shipments", r.randint(2, 6)),
                           ("payment-status", r.randint(1, 2))]:
            for p in range(pages):
                n = 200 if p < pages - 1 else r.randint(20, 199)
                reps = 2 if (retry and r.random() < 0.5) else 1
                for rep in range(reps):
                    tt = trap or ("sync_retry" if rep else None)
                    status, n_eff = 200, n
                    if fail and obj == "shipments" and p == pages - 1:
                        status, n_eff = 503, 0
                    self.api_call(t, "key-tb-07", LINK["ledger"], ua, f"/api/v2/{obj}?page={p + 1}&updated_since={d.isoformat()}",
                                  "GET", n_eff, status, trap=tt)
                    if n_eff:
                        self.hd_event(t + self.secs(5, 30), "tb-sync-svc", "integration", "record.upsert", f"SYNC-{obj}",
                                      LINK["help"], f"records={n_eff} source=ledgerone object={obj}", trap=tt)
                    t += self.secs(2, 6)
        for _ in range(r.randint(1, 3)):
            n = r.randint(5, 60)
            self.hd_event(t, "tb-sync-svc", "integration", "ticket.read", "SYNC-tickets", LINK["help"],
                          f"records={n} target=ledgerone", trap=trap)
            t += self.secs(3, 10)
            self.api_call(t, "key-tb-07", LINK["ledger"], ua, "/api/v2/case-links", "POST", n, 201, trap=trap)
            t += self.secs(2, 5)

    def backup_and_reports(self, d):
        r = self.r
        t = datetime(d.year, d.month, d.day, 19, 30) + timedelta(minutes=r.gauss(0, 6))
        for obj in ["invoices", "vendors", "payments", "customers", "shipments"]:
            n = r.randint(500, 3000)
            self.api_call(t, "key-bkp-01", "172.16.10.5", "backup-agent 2.1", f"/api/v2/{obj}/bulk?since={d.isoformat()}", "GET", n,
                          trap="backup_overnight")
            self.bv_event(t + self.secs(2, 8), "bv-backup", "172.16.10.5", "PUT", f"/backups/ledgerone/{d.isoformat()}/{obj}.bak",
                          n * 900, trap="backup_overnight")
            t += self.secs(20, 60)
        t = datetime(d.year, d.month, d.day, 0, 30) + timedelta(minutes=r.gauss(0, 12))
        for obj in ["invoices", "shipments", "payment-status"]:
            self.api_call(t, "key-rpt-02", "172.16.10.8", "HF-Reports 1.8", f"/api/v2/{obj}/summary", "GET", r.randint(50, 400),
                          trap="reports_overnight")
            t += self.secs(5, 20)

    def portal(self, d):
        r = self.r
        n = 40 if d.weekday() == 6 else 110
        for _ in range(n):
            t = datetime(d.year, d.month, d.day, 3, 0) + timedelta(seconds=r.uniform(0, 11 * 3600))
            if r.random() < 0.6:
                self.api_call(t, "key-portal-01", "172.16.20.4", "HF-Portal 5.2", f"/api/v2/invoices/INV-{r.randint(10000, 99999)}", "GET", 1)
            else:
                self.api_call(t, "key-portal-01", "172.16.20.4", "HF-Portal 5.2", f"/api/v2/shipments/SHP-{r.randint(10000, 99999)}", "GET", 1)
        for _ in range(n // 3):
            t = datetime(d.year, d.month, d.day, 3, 0) + timedelta(seconds=r.uniform(0, 11 * 3600))
            blank = r.random() < 0.05
            self.bv_event(t, "bv-portal-docs", "" if blank else "172.16.20.4", "GET",
                          f"/customers/C{r.randint(1, 1400):04d}/docs/POD-{r.randint(10000, 99999)}.pdf", r.randint(40_000, 900_000),
                          trap="blank_address" if blank else None)

    def helpdesk(self, d, agents):
        r = self.r
        n = 50 if d.weekday() >= 5 else 160
        for _ in range(n):
            u, ip = r.choice(agents)
            t = datetime(d.year, d.month, d.day, 3, 0) + timedelta(seconds=r.uniform(0, 10.5 * 3600))
            act = r.choices(["ticket.create", "ticket.comment", "ticket.view", "ticket.assign", "ticket.close", "ticket.search"],
                            [15, 30, 35, 8, 10, 2])[0]
            det = ""
            if act == "ticket.search":
                det = 'query="' + r.choice(["delivery delay", "POD missing", "password reset", "invoice copy", "API key not working"]) + '"'
            self.hd_event(t, u, "user", act, f"TCK-{r.randint(100000, 199999)}", ip, det,
                          trap="agent_search" if act == "ticket.search" else None)
        if d.weekday() == 1:  # Tuesday weekly service review
            t = datetime(d.year, d.month, d.day, 5, 0) + timedelta(minutes=r.gauss(0, 15))
            job = self._id("EXP")
            self.hd_event(t, "sunita.iyer", "user", "export.create", job, "172.16.30.5",
                          "scope=tickets_last_7d purpose=weekly-service-review", trap="weekly_export")
            self.hd_event(t + self.secs(180, 360), "sunita.iyer", "user", "export.download", job, "172.16.30.5", "", trap="weekly_export")
            self.hd_event(t + timedelta(days=2, minutes=r.randint(0, 90)), "sunita.iyer", "user", "export.delete", job, "172.16.30.5", "",
                          trap="weekly_export")
            self.bv_event(t + timedelta(minutes=12), "sunita.iyer", "172.16.30.5", "PUT", f"/support/weekly-review/{d.isoformat()}.xlsx",
                          r.randint(200_000, 900_000), trap="weekly_export")

    def sso_day(self, d, users):
        r = self.r
        if d.weekday() < 6:
            for u in users:
                if r.random() < 0.08:
                    continue
                t = datetime(d.year, d.month, d.day, 2, 30) + timedelta(seconds=r.uniform(0, 2 * 3600))
                ok = r.random() > 0.02
                self.sso_event(t, u["username"], u["ip"], u["city"], "password+mfa", "success" if ok else "not_attempted",
                               u["device"], "success" if ok else "failure", "" if ok else "bad_password")
        # contractor on the road
        if r.random() < 0.85:
            city = CITIES[(d.toordinal() // 2) % len(CITIES)]
            t = datetime(d.year, d.month, d.day, 3, 15) + timedelta(minutes=r.randint(0, 120))
            self.sso_event(t, "colin.lawson", f"100.80.{CITIES.index(city) * 10 + r.randint(1, 9)}.{r.randint(2, 250)}", city,
                           "password+mfa", "success", "LT-CL-01", trap="contractor_travel")
            if r.random() < 0.25:
                c2 = r.choice([c for c in CITIES if c != city])
                self.sso_event(t + timedelta(minutes=r.randint(90, 170)), "colin.lawson",
                               f"100.80.{CITIES.index(c2) * 10 + 1}.{r.randint(2, 250)}", c2, "password+mfa", "success", "LT-CL-01",
                               trap="contractor_travel")
        if d <= date(2026, 6, 30) and d.weekday() < 5:
            self.sso_event(datetime(d.year, d.month, d.day, 3, 5), "rohan.menon", "172.16.12.31", "Chennai", "password+mfa", "success", "LT-0931")

    def finance(self, d):
        r = self.r
        fin = ["farah.dsouza", "kavya.raman", "arjun.pillai"]
        if d.weekday() < 5:
            for _ in range(r.randint(0, 4)):
                t = datetime(d.year, d.month, d.day, 4, 0) + timedelta(seconds=r.uniform(0, 8 * 3600))
                vid = f"V{r.randint(1, 300):04d}"
                fld = r.choice(["phone", "email", "address", "contact_name", "payment_terms"])
                newv = {"phone": f"+91-44-{r.randint(20000000, 29999999)}", "email": f"ap{r.randint(1, 99)}@{vid.lower()}.example",
                        "address": f"{r.randint(1, 200)}, SIDCO Estate", "contact_name": r.choice(FIRST),
                        "payment_terms": r.choice(["NET15", "NET30", "NET45"])}[fld]
                appr = f"FIN-APR-2026-{r.randint(100, 999):04d}" if r.random() < 0.3 else ""
                self.change(t, vid, fld, newv, r.choice(fin), "UI", appr, f"172.16.12.{r.randint(10, 40)}")
        # payment-run preparation
        for run_day in (8, 23):
            if d.day == run_day - 1:
                self.bv_event(datetime(d.year, d.month, d.day, 6, 30), "madhavi.sundar", "172.16.12.3", "GET",
                              f"/finance/payment-runs/{d.year}-{d.month:02d}-{run_day:02d}/run-sheet.xlsx", 380_000)
        # month end: approved bulk clean-up + accountant's reads
        last = (d + timedelta(days=1)).month != d.month
        if last:
            appr = f"FIN-APR-2026-{r.randint(500, 899):04d}"
            t = datetime(d.year, d.month, d.day, 10, 40)
            for vid in r.sample(sorted(self.vendors), r.randint(28, 40)):
                fld = r.choice(["status", "address"])
                self.change(t, vid, fld, "inactive" if fld == "status" else f"{r.randint(1, 200)}, New Industrial Area",
                            "farah.dsouza", "BULK", appr, "172.16.12.14", trap="month_end_cleanup")
                t += self.secs(1, 3)
            if d.month == 8:
                for vid in ("V0090", "V0091"):
                    self.change(t, vid, "ifsc", f"KKBK0{r.randint(100000, 999999)}", "farah.dsouza", "BULK", appr, "172.16.12.14",
                                trap="month_end_cleanup")
            for p in ["/finance/statements", "/finance/vendor-master", "/finance/bank-instructions"]:
                self.bv_event(datetime(d.year, d.month, d.day, 9, 0) + self.secs(0, 3000), "farah.dsouza", "172.16.12.14", "GET",
                              f"{p}/{d.year}-{d.month:02d}.xlsx", r.randint(300_000, 2_000_000))
        if d in (date(2026, 7, 28), date(2026, 8, 27)):  # vendor-record audit
            for _ in range(40):
                p = r.choice(["/finance/statements", "/finance/vendor-master", "/finance/bank-instructions"])
                self.bv_event(datetime(d.year, d.month, d.day, 5, 0) + self.secs(0, 6 * 3600), "farah.dsouza", "172.16.12.14", "GET",
                              f"{p}/archive-{r.randint(1, 60):02d}.xlsx", r.randint(1_000_000, 9_000_000), trap="finance_audit")
        approved_bank = {date(2026, 6, 18): ("V0042", "FIN-APR-2026-0311"), date(2026, 7, 6): ("V0150", "FIN-APR-2026-0358"),
                         date(2026, 8, 21): ("V0107", "FIN-APR-2026-0402")}
        if d in approved_bank:
            vid, appr = approved_bank[d]
            t = datetime(d.year, d.month, d.day, 5, 30)
            trap = "approved_near_run" if d == date(2026, 8, 21) else None
            self.change(t, vid, "bank_account", f"{r.randint(10**13, 10**14 - 1)}", "kavya.raman", "UI", appr, "172.16.12.22", trap=trap)
            self.change(t + timedelta(seconds=20), vid, "ifsc", f"SBIN0{r.randint(100000, 999999)}", "kavya.raman", "UI", appr,
                        "172.16.12.22", trap=trap)

    # ------------------------------------------------------------------ the incident
    def _mule(self):
        return f"{self.r.randint(10**13, 10**14 - 1)}", f"{self.r.choice(['YESB', 'IDFB', 'RATN'])}0{self.r.randint(100000, 999999)}"

    def _tamper(self, t, vid, cred, ip, ua, stage, approval=""):
        acct, ifsc = self._mule()
        rid = self.api_call(t, cred, ip, ua, f"/api/v2/vendors/{vid}/bank-details", "PATCH", 1, stage=stage,
                            flow=ip.startswith("10.20.4."))
        self.change(t + timedelta(seconds=1), vid, "bank_account", acct, cred, "API", approval, ip, rid, stage=stage)
        self.change(t + timedelta(seconds=1), vid, "ifsc", ifsc, cred, "API", approval, ip, rid, stage=stage)

    def _restore(self, t, vid, old, cred, ip, ua, stage):
        rid = self.api_call(t, cred, ip, ua, f"/api/v2/vendors/{vid}/bank-details", "PATCH", 1, stage=stage,
                            flow=ip.startswith("10.20.4."))
        self.change(t + timedelta(seconds=1), vid, "bank_account", old["bank_account"], cred, "API", "", ip, rid, stage=stage)
        self.change(t + timedelta(seconds=1), vid, "ifsc", old["ifsc"], cred, "API", "", ip, rid, stage=stage)

    def _recon(self, days, hour, minute, cred, ip, ua, vendors, stage):
        for day in days:
            t = datetime(2026, day[0], day[1], hour, minute) + self.secs(0, 300)
            self.api_call(t, cred, ip, ua, "/api/v2/vendors?page=1", "GET", 300, stage=stage, flow=ip.startswith("10.20.4."))
            for v in vendors:
                t += self.secs(4, 15)
                self.api_call(t, cred, ip, ua, f"/api/v2/vendors/{v}/bank-details", "GET", 1, stage=stage, flow=ip.startswith("10.20.4."))
            t += self.secs(4, 15)
            self.api_call(t, cred, ip, ua, "/api/v2/payments/search", "POST", 120, stage=stage, flow=ip.startswith("10.20.4."))

    def _pivot(self, ip_fn, stage="bluevault_pivot"):
        paths = ["/finance/bank-instructions/vendor-bank-master.xlsx", "/finance/statements/2026-07.pdf",
                 "/finance/payment-runs/2026-08-23/run-sheet-draft.xlsx", "/finance/statements/2026-06.pdf",
                 "/finance/bank-instructions/change-requests.xlsx", "/finance/payment-runs/2026-08-08/run-sheet.xlsx"]
        k = 0
        for day in range(12, 20):
            for _ in range(2 if day % 2 else 1):
                t = datetime(2026, 8, day, 22, 0) + self.secs(0, 3000)
                self.bv_event(t, "bv-portal-docs", ip_fn(k), "GET", paths[k % len(paths)], self.r.randint(200_000, 4_000_000), stage=stage)
                k += 1

    def attack(self):
        v = self.variant
        aug_targets, sep_targets = ["V0219", "V0033", "V0187"], ["V0251", "V0078", "V0140", "V0012"]
        recon_extra = ["V0219", "V0033", "V0187", "V0251", "V0078", "V0140", "V0012", "V0164"]
        if v == "insider":
            self._insider()
            return
        if v == "inside_worker":
            self._inside_worker()
            return
        if v == "reference":
            ip_h, ip_l, ua, bv_ip = ATT1, ATT2, UA_OLD, (lambda k: ATT2 if k % 3 else "")
        elif v == "on_link":
            ip_h, ip_l, ua, bv_ip = ATT_LINK, ATT_LINK, UA_NEW, (lambda k: "")
        elif v == "mimic":
            ip_h, ip_l, ua, bv_ip = ATT1, ATT2, UA_NEW, (lambda k: ATT2)
        else:  # forged_approval
            ip_h, ip_l, ua, bv_ip = ATT1, ATT2, UA_NEW, None

        # stage A - support data
        if v in ("reference", "on_link"):
            for k, (mo, dy, hh, mi) in enumerate([(7, 29, 22, 10), (8, 5, 21, 40), (8, 10, 23, 5), (8, 14, 22, 20), (8, 18, 21, 55)]):
                t = datetime(2026, mo, dy, hh, mi)
                if k < 2:
                    self.hd_event(t - timedelta(minutes=2), "tb-sync-svc", "integration", "ticket.search", "SEARCH", ip_h,
                                  'query="access key" OR password OR token OR "connection string"', stage="helpdeskr_secret_search")
                job = f"EXP-9{k:03d}"
                self.hd_event(t, "tb-sync-svc", "integration", "export.create", job, ip_h,
                              "scope=all_tickets include=attachments,custom_fields", stage="helpdeskr_export")
                self.hd_event(t + timedelta(minutes=6), "tb-sync-svc", "integration", "export.download", job, ip_h,
                              f"size={self.r.randint(180, 420)}MB", stage="helpdeskr_export")
                self.hd_event(t + timedelta(minutes=9), "tb-sync-svc", "integration", "export.delete", job, ip_h, "", stage="helpdeskr_export")
        elif v == "mimic":
            d = date(2026, 7, 29)
            while d <= date(2026, 8, 18):
                t = datetime(d.year, d.month, d.day, 21, 0) + self.secs(0, 900)
                for _ in range(self.r.randint(2, 4)):
                    self.hd_event(t, "tb-sync-svc", "integration", "ticket.read", "SYNC-tickets", ip_h,
                                  f"records={self.r.randint(40, 80)} target=ledgerone", stage="helpdeskr_slow_pull")
                    t += self.secs(20, 90)
                d += timedelta(days=2)

        # stage B - legacy key
        if v in ("reference", "on_link"):
            t = datetime(2026, 8, 9, 1, 12)
            pua = "python-requests/2.31.0" if v == "reference" else UA_NEW
            self.api_call(t, "key-tb-03", ip_h, pua, "/api/v2/vendors?page=1", "GET", 300, stage="legacy_key_probe", flow=ip_h.startswith("10.20.4."))
            self.api_call(t + timedelta(seconds=40), "key-tb-03", ip_h, pua, "/api/v2/payments/search", "POST", 0,
                          stage="legacy_key_probe", flow=ip_h.startswith("10.20.4."))

        # stage C - storage pivot with a portal key leaked in a ticket
        if bv_ip is not None:
            self._pivot(bv_ip)

        # stage D/E - recon + tamper
        if v in ("reference", "on_link"):
            self._recon([(8, 17), (8, 18), (8, 19)], 21, 5, "key-tb-07", ip_l, ua, recon_extra[:6], "bank_recon")
            olds = {}
            t = datetime(2026, 8, 20, 21, 20)
            for vid in aug_targets:
                olds[vid] = dict(self.vendors[vid])
                self._tamper(t, vid, "key-tb-07", ip_l, ua, "bank_tamper_aug")
                t += self.secs(20, 60)
            self.truth["money"].append({"run": "2026-08-23", "vendors": aug_targets, "kind": "paid to attacker account"})
            self._restore(datetime(2026, 8, 25, 21, 15), "V0219", olds["V0219"], "key-tb-07", ip_l, ua, "bank_revert")
            self._recon([(9, 3), (9, 4)], 21, 10, "key-tb-07", ip_l, ua, sep_targets, "bank_recon")
            t = datetime(2026, 9, 5, 21, 10)
            for vid in sep_targets:
                self._tamper(t, vid, "key-tb-07", ip_l, ua, "bank_tamper_sep")
                t += self.secs(20, 60)
            self.truth["money"].append({"run": "2026-09-08", "vendors": ["V0033", "V0187"] + sep_targets, "kind": "at risk"})
        elif v == "mimic":
            self._recon([(9, 2), (9, 3), (9, 4)], 21, 0, "key-tb-07", ip_l, ua, sep_targets, "bank_recon")
            t = datetime(2026, 9, 5, 21, 5)
            for vid in sep_targets:
                self._tamper(t, vid, "key-tb-07", ip_l, ua, "bank_tamper_sep")
                t += self.secs(40, 120)
            self.truth["money"].append({"run": "2026-09-08", "vendors": sep_targets, "kind": "at risk"})
        else:  # forged_approval
            self._recon([(8, 18), (8, 19)], 7, 0, "key-tb-07", ip_l, ua, aug_targets, "bank_recon")
            t = datetime(2026, 8, 20, 7, 30)
            for vid in aug_targets:
                self._tamper(t, vid, "key-tb-07", ip_l, ua, "bank_tamper_aug", approval="FIN-APR-2026-0417")
                t += self.secs(30, 90)
            self.truth["money"].append({"run": "2026-08-23", "vendors": aug_targets, "kind": "paid to attacker account"})

    def _insider(self):
        kiosk = "172.16.40.21"
        for (mo, dy, hh, mi) in [(8, 20, 7, 50), (8, 21, 8, 5)]:
            self.sso_event(datetime(2026, mo, dy, hh, mi), "rohan.menon", kiosk, "Madurai", "password", "not_enrolled", "KIOSK-WH-02",
                           stage="insider_access")
        self.bv_event(datetime(2026, 8, 20, 8, 2), "rohan.menon", kiosk, "GET", "/finance/payment-runs/2026-08-23/run-sheet-draft.xlsx",
                      410_000, stage="insider_recon")
        t = datetime(2026, 8, 21, 8, 20)
        for vid in ["V0219", "V0033", "V0187"]:
            acct, ifsc = self._mule()
            self.change(t, vid, "bank_account", acct, "rohan.menon", "UI", "", kiosk, stage="bank_tamper_aug")
            self.change(t + timedelta(seconds=15), vid, "ifsc", ifsc, "rohan.menon", "UI", "", kiosk, stage="bank_tamper_aug")
            t += timedelta(minutes=2)
        self.truth["money"].append({"run": "2026-08-23", "vendors": ["V0219", "V0033", "V0187"], "kind": "paid to attacker account"})
        t = datetime(2026, 9, 4, 7, 50)
        for vid in ["V0251", "V0078"]:
            acct, ifsc = self._mule()
            self.change(t, vid, "bank_account", acct, "rohan.menon", "UI", "", kiosk, stage="bank_tamper_sep")
            self.change(t + timedelta(seconds=15), vid, "ifsc", ifsc, "rohan.menon", "UI", "", kiosk, stage="bank_tamper_sep")
            t += timedelta(minutes=2)
        self.truth["money"].append({"run": "2026-09-08", "vendors": ["V0219", "V0033", "V0187", "V0251", "V0078"], "kind": "at risk"})

    def _inside_worker(self):
        """The vendor's own sync worker is compromised. It skims small pages through endpoints the
        sync really uses, inside the real session, from the real address, with flows present.
        Expected outcome: the skim is NOT caught (balance stays within tolerance); the bank edit is."""
        ip = LINK["ledger"]
        d = date(2026, 8, 1)
        while d <= date(2026, 8, 20):
            t = datetime(d.year, d.month, d.day, 20, 47) + self.secs(0, 60)
            self.api_call(t, "key-tb-07", ip, UA_NEW, f"/api/v2/customers?page={self.r.randint(40, 90)}&updated_since=2025-01-01",
                          "GET", self.r.randint(60, 140), stage="covert_skim")
            d += timedelta(days=2)
        t = datetime(2026, 9, 5, 20, 52)
        for vid in ["V0251", "V0078"]:
            self._tamper(t, vid, "key-tb-07", ip, UA_NEW, "bank_tamper_sep")
            t += self.secs(20, 40)
        self.truth["money"].append({"run": "2026-09-08", "vendors": ["V0251", "V0078"], "kind": "at risk"})

    # ------------------------------------------------------------------ build + write
    def build(self):
        r = self.r
        agents = []
        support = [s for s in self.staff if s["department"] == "Support" and s["role"] == "Support Agent"]
        for i, s in enumerate(support):
            ip = f"172.16.30.{20 + i}" if r.random() < 0.85 else f"100.72.{r.randint(1, 250)}.{r.randint(2, 250)}"
            agents.append((s["username"], ip))
        users = []
        for i, s in enumerate(self.staff):
            if s["status"] != "Active" or s["username"] in ("colin.lawson",) or s["termination_date"]:
                continue
            if r.random() < 0.55:
                remote = r.random() < 0.1
                users.append(dict(username=s["username"], ip=f"100.72.{r.randint(1, 250)}.{r.randint(2, 250)}" if remote else f"172.16.{12 + i % 30}.{20 + i % 200}",
                                  city=r.choice(["Chennai", "Chennai", "Coimbatore", "Madurai"]), device=f"LT-{1000 + i}"))
        d = SSO_START
        while d <= D_END:
            if d >= D0:
                self.sync_night(d)
                self.backup_and_reports(d)
                self.portal(d)
                if d <= date(2026, 8, 31):
                    self.helpdesk(d, agents)
                self.finance(d)
            self.sso_day(d, users)
            d += timedelta(days=1)
        # leaver still active on the warehouse kiosk (governance finding in every variant)
        for (mo, dy, hh, mi) in [(7, 22, 3, 40), (8, 13, 4, 5)]:
            self.sso_event(datetime(2026, mo, dy, hh, mi), "rohan.menon", "172.16.40.21", "Madurai", "password", "not_enrolled",
                           "KIOSK-WH-02", gov=True)
        self.attack()
        return self

    def write(self, out: Path):
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)

        def wcsv(name, rows, cols, tsf=None):
            with open(out / name, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
                w.writeheader()
                for row in sorted(rows, key=lambda x: x[tsf] if tsf else 0):
                    row = dict(row)
                    for k, val in row.items():
                        if isinstance(val, datetime):
                            row[k] = val.strftime("%Y-%m-%d %H:%M:%S")
                    w.writerow(row)

        api_cols = ["ts_utc", "request_id", "api_key_id", "caller_ip", "user_agent", "endpoint", "method", "records_returned", "status"]
        wcsv("E01_ledgerone_api.csv", [a for a in self.api if a["_code"] == "E01"], api_cols, "ts_utc")
        wcsv("E18_ledgerone_api_sep.csv", [a for a in self.api if a["_code"] == "E18"], api_cols, "ts_utc")
        wcsv("E02_helpdeskr_audit.csv", self.hd, ["ts_local", "event_id", "actor", "actor_type", "action", "object_id", "source_ip", "result", "details"], "ts_local")
        wcsv("E03_sso.csv", self.sso, ["ts_utc", "event_id", "user", "source_ip", "city", "auth_method", "mfa_result", "device_id", "result", "failure_reason"], "ts_utc")
        wcsv("E05_bluevault.csv", self.bv, ["epoch_s", "event_id", "principal", "source_ip", "action", "path", "bytes", "result"], "epoch_s")
        wcsv("E14_roster.csv", self.staff, ["employee_id", "username", "full_name", "department", "role", "status", "manager", "hire_date", "termination_date", "notes"])
        wcsv("E15_link_flows.csv", self.flows, ["ts_utc", "flow_id", "src_ip", "src_label", "dst_system", "dst_port", "bytes_out", "bytes_in", "tunnel_id", "result"], "ts_utc")
        wcsv("E19_vendor_changes.csv", self.chg, ["ts_utc", "change_id", "vendor_id", "vendor_name", "field", "old_value", "new_value", "changed_by", "channel", "approval_ref", "source_ip", "request_id"], "ts_utc")
        reg = [
            dict(integration="TallyBridge Connect - LedgerOne", credential_id="key-tb-07", system="LedgerOne", vendor="TallyBridge Technologies",
                 scope="ledgerone:all-modules:read-write", owner="Finance IT", created="2024-06-12", last_review="2024-06-05",
                 ip_restriction="", token_lifetime_days="", last_used="2026-09-07", status="active"),
            dict(integration="TallyBridge Connect - HelpDeskr", credential_id="tb-sync-svc", system="HelpDeskr", vendor="TallyBridge Technologies",
                 scope="helpdeskr:admin", owner="Support Ops", created="2024-06-12", last_review="2024-06-05",
                 ip_restriction="", token_lifetime_days="", last_used="2026-08-31", status="active"),
            dict(integration="TallyBridge Connect v1 (legacy)", credential_id="key-tb-03", system="LedgerOne", vendor="TallyBridge Technologies",
                 scope="ledgerone:read", owner="", created="2024-06-12", last_review="", ip_restriction="", token_lifetime_days="",
                 last_used="2024-11-02", status="active"),
            dict(integration="Nightly backup", credential_id="key-bkp-01", system="LedgerOne", vendor="Harbor & Finch (internal)",
                 scope="ledgerone:read", owner="IT", created="2023-03-01", last_review="2026-02-10", ip_restriction="172.16.10.0/24",
                 token_lifetime_days="365", last_used="2026-09-07", status="active"),
            dict(integration="Management reporting", credential_id="key-rpt-02", system="LedgerOne", vendor="Harbor & Finch (internal)",
                 scope="ledgerone:read", owner="Operations IT", created="2023-09-15", last_review="2026-02-10", ip_restriction="172.16.10.0/24",
                 token_lifetime_days="365", last_used="2026-09-07", status="active"),
            dict(integration="Customer portal", credential_id="key-portal-01", system="LedgerOne", vendor="Harbor & Finch (internal)",
                 scope="ledgerone:invoices,shipments:read", owner="Operations IT", created="2025-02-03", last_review="2026-02-10",
                 ip_restriction="172.16.20.0/24", token_lifetime_days="365", last_used="2026-09-07", status="active"),
            dict(integration="Customer document portal", credential_id="bv-portal-docs", system="BlueVault", vendor="Harbor & Finch (internal)",
                 scope="bluevault:read:/customers/*", owner="Support Ops", created="2025-02-03", last_review="2025-02-03",
                 ip_restriction="", token_lifetime_days="", last_used="2026-08-31", status="active"),
            dict(integration="Backup to BlueVault", credential_id="bv-backup", system="BlueVault", vendor="Harbor & Finch (internal)",
                 scope="bluevault:write:/backups/*", owner="IT", created="2023-03-01", last_review="2026-02-10", ip_restriction="172.16.10.0/24",
                 token_lifetime_days="365", last_used="2026-08-31", status="active"),
        ]
        (out / "E04_connected_software.json").write_text(json.dumps({"integrations": reg}, indent=1), encoding="utf-8")
        iocs = [dict(indicator="192.0.2.77", type="ip", first_seen="2026-08-11", last_seen="2026-08-16", confidence="low",
                     vendor_note="Scanning against shared sync edge; blocked."),
                dict(indicator="tallybridge-update.net", type="domain", first_seen="2026-08-12", last_seen="2026-08-15", confidence="medium",
                     vendor_note="Look-alike domain; no customer impact confirmed."),
                dict(indicator="e3b0c44298fc1c149afbf4c8996fb924", type="md5", first_seen="2026-08-12", last_seen="2026-08-12", confidence="low",
                     vendor_note="Dropper hash seen on one build agent.")]
        if self.variant in ("reference", "mimic", "forged_approval"):
            iocs.insert(0, dict(indicator=ATT1, type="ip", first_seen="2026-08-10", last_seen="2026-08-18", confidence="medium",
                                vendor_note="Observed authenticating to shared sync infrastructure. No evidence of customer data access."))
        wcsv("E17_vendor_indicators.csv", iocs, ["indicator", "type", "first_seen", "last_seen", "confidence", "vendor_note"])
        billed = defaultdict(int)
        for h in self.hd:
            if h["action"] == "export.create":
                billed[(h["ts_local"] - IST).strftime("%Y-%m")] += 1
        (out / "context.json").write_text(json.dumps({
            "_comment": "Facts transcribed by hand from document evidence (E06 invoice). Optional.",
            "billed_exports": dict(billed)}, indent=1), encoding="utf-8")
        t = dict(self.truth)
        t["traps"] = dict(t["traps"])
        (out / "ground_truth.json").write_text(json.dumps(t, indent=1), encoding="utf-8")
        return out


def generate(out, variant="reference", seed=7, bv_skew=247):
    return World(seed=seed, variant=variant, bv_skew=bv_skew).build().write(out)
