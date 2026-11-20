"""Governance and outside-intelligence checks.

* Integration passport (E04 vs policy): scope, IP restriction, lifetime, review age,
  dormant/legacy keys, owners that are business teams rather than IT security.
* Leavers: HR roster (E14) x sign-ins (E03) x application actors. Flags same-surname
  pairs so a 'Menon' report is not pinned on the wrong Menon.
* IOC gap: what the vendor's indicator list (E17) says vs what our own logs show,
  and which addresses the vendor did not list at all.
"""
from __future__ import annotations

import re

import pandas as pd

from .util import NetSet, bare


def _blank(v) -> bool:
    if isinstance(v, bool):
        return not v
    return v is None or str(v).strip().lower() in ("", "none", "null", "nan", "no", "false", "-", "0", "n/a", "unlimited", "never")


def passport(ev, ident, act, cfg, analysis_end):
    rows, findings = [], []
    for cred, m in ident.meta.items():
        issues = []
        scope = str(m.get("scope", ""))
        if re.search(r"admin|\*|all|full|read.?write|rw", scope, re.I):
            issues.append(f"broad scope '{scope}'")
        if _blank(m.get("ip_restriction", "")):
            issues.append("no IP restriction")
        if _blank(m.get("token_lifetime_days", "")):
            issues.append("never expires")
        lr = pd.to_datetime(m.get("last_review", ""), errors="coerce")
        if pd.isna(lr):
            issues.append("never reviewed")
        elif (analysis_end - lr).days > cfg["review_max_age_days"]:
            issues.append(f"last review {lr:%d %b %Y} ({(analysis_end - lr).days} days ago)")
        used = act[act["cred"].map(bare) == cred.lower()]
        granted_used = sorted(set(used["token"]))
        if len(ev.bv):
            bvu = ev.bv[ev.bv["principal"].map(bare) == cred.lower()]
            if len(bvu):
                used = pd.concat([used[["ts", "ref"]], bvu[["ts", "ref"]]])
                granted_used += sorted(set(bvu["path"].map(lambda p: "/".join(str(p).split("/")[:2]) or "/")))
        text = f"{m.get('status', '')} {m.get('notes', '')} {m.get('integration', '')}".lower()
        if "legacy" in text or "deprecat" in text:
            issues.append("legacy key still active")
        rows.append(dict(credential=cred, entity=m["entity"], system=m.get("system", ""), owner=m.get("owner", ""),
                         scope=scope, ip_restriction=m.get("ip_restriction", ""), lifetime=m.get("token_lifetime_days", ""),
                         last_review=m.get("last_review", ""), last_used_register=m.get("last_used", ""),
                         seen_in_logs=len(used), distinct_actions_used=len(granted_used),
                         issues="; ".join(issues)))
        if ident.is_external(m["entity"]) and issues:
            findings.append(dict(
                module="passport", category="governance", severity=55,
                title=f"Third-party credential {cred} breaks the integration controls",
                ts_first=analysis_end, ts_last=analysis_end, entity=m["entity"], cred=cred, ip="", refs=[f"E04:{cred}"],
                summary="; ".join(issues) + f". Used {len(granted_used)} distinct action(s) in the logs.",
                details={},
            ))
    return pd.DataFrame(rows), findings


def leavers(ev, ident, act, cfg):
    term_re = re.compile(cfg["terminated_status_regex"], re.I)
    ro = ev.roster
    findings, notes = [], []
    if ro.empty:
        return findings, notes
    gone = ro[ro["status"].str.contains(term_re) | ro["termination_date"].notna()]
    for _, p in gone.iterrows():
        u = p["username"]
        td = p["termination_date"]
        if pd.isna(td):
            continue
        cutoff = td + pd.Timedelta(days=1)
        hits = []
        if len(ev.sso):
            s = ev.sso[(ev.sso["user"] == u) & (ev.sso["ts"] >= cutoff)]
            hits.append(("E03 sign-ins", s[s["ok"]]))
        a = act[(act["cred"].map(bare) == u) & (act["ts"] >= cutoff)]
        hits.append(("application actions", a))
        if len(ev.bv):
            b = ev.bv[(ev.bv["principal"].map(bare) == u) & (ev.bv["ts"] >= cutoff)]
            hits.append(("BlueVault actions", b))
        if len(ev.changes):
            c = ev.changes[(ev.changes["changed_by"].map(bare) == u) & (ev.changes["ts"] >= cutoff)]
            hits.append(("vendor record changes", c))
        refs, parts, first, last = [], [], None, None
        for label, df in hits:
            if len(df):
                refs += list(df["ref"])
                parts.append(f"{len(df)} {label}")
                first = df["ts"].min() if first is None else min(first, df["ts"].min())
                last = df["ts"].max() if last is None else max(last, df["ts"].max())
        if refs:
            extra = ""
            if len(ev.sso):
                s = ev.sso[(ev.sso["user"] == u) & (ev.sso["ts"] >= cutoff) & ev.sso["ok"]]
                if len(s):
                    extra = f" Devices: {', '.join(sorted(set(s['device']) - {''}))[:60] or 'blank'}; addresses: {', '.join(sorted(set(s['ip'])))[:60]}."
            findings.append(dict(
                module="leavers", category="governance", severity=65,
                title="Account of a former employee still in use",
                ts_first=first, ts_last=last, entity=u, cred=u, ip="", refs=refs,
                summary=f"{p['full_name']} ({u}, {p['role']}) left on {td:%d %b %Y}; after that: {', '.join(parts)}.{extra}",
                details={},
            ))
        # same-surname staff who could be confused with the leaver
        sur = str(p["full_name"]).split()[-1].lower() if str(p["full_name"]).split() else ""
        if sur:
            twins = ro[(ro["full_name"].str.lower().str.endswith(" " + sur)) & (ro["username"] != u)]
            for _, t in twins.iterrows():
                notes.append(f"Name collision: leaver {p['full_name']} ({u}) and active {t['full_name']} ({t['username']}, "
                             f"{t['role']}) share a surname - confirm which account any report refers to.")
    return findings, notes


def ioc_gap(ev, ident, act, findings_so_far):
    io = ev.iocs
    if io.empty:
        return pd.DataFrame(), []
    seen = pd.concat([
        act[["ts", "ip", "ref"]],
        ev.bv[["ts", "ip", "ref"]] if len(ev.bv) else pd.DataFrame(columns=["ts", "ip", "ref"]),
        ev.sso[["ts", "ip", "ref"]] if len(ev.sso) else pd.DataFrame(columns=["ts", "ip", "ref"]),
        ev.flows.rename(columns={"src_ip": "ip"})[["ts", "ip", "ref"]] if len(ev.flows) else pd.DataFrame(columns=["ts", "ip", "ref"]),
    ], ignore_index=True)
    # Only sightings made WITH the vendor's credentials (or inside our own alerts) count: residential
    # addresses are reassigned between customers (E20-G), so a staff sign-in from the same address is not a sighting.
    vend_refs = set(act.loc[act["entity"].map(ident.is_external) | act["link_expected"], "ref"])
    for f in findings_so_far:
        if f["category"] == "detection" and f["severity"] >= 60:
            vend_refs |= set(f["refs"])
    shared = seen[~seen["ref"].isin(vend_refs)]
    seen = seen[seen["ref"].isin(vend_refs)]
    rows = []
    for _, r in io.iterrows():
        ind = r["indicator"]
        hit = seen[seen["ip"] == ind] if ind else seen.iloc[0:0]
        n_shared = int((shared["ip"] == ind).sum()) if ind else 0
        if hit.empty and ind:
            ua_hit = act[act["ua"].str.contains(re.escape(ind), case=False, na=False)]
            hit = ua_hit[["ts", "ip", "ref"]]
        ours_first, ours_last = (hit["ts"].min(), hit["ts"].max()) if len(hit) else (pd.NaT, pd.NaT)
        gap = []
        if len(hit) and pd.notna(r["first_seen"]) and ours_first < r["first_seen"]:
            gap.append(f"we saw it {(r['first_seen'] - ours_first).days} day(s) before the vendor's first_seen")
        if len(hit) and pd.notna(r["last_seen"]) and ours_last > r["last_seen"]:
            gap.append(f"still active {(ours_last - r['last_seen']).days} day(s) after the vendor's last_seen")
        rows.append(dict(indicator=ind, type=r["type"], vendor_first=r["first_seen"], vendor_last=r["last_seen"],
                         our_first=ours_first, our_last=ours_last, our_events=len(hit), confidence=r["confidence"],
                         gap="; ".join(gap) or ("not seen with the vendor's credentials" if hit.empty else "consistent"),
                         shared_use=n_shared))
    listed = set(io["indicator"])
    unlisted = {}
    for f in findings_so_far:
        if f["category"] != "detection" or f["severity"] < 60 or not ident.is_external(f.get("entity", "")):
            continue
        for ip in str(f.get("ip", "")).split(","):
            ip = ip.strip()
            if ip and ip not in listed and ip != "(blank)":
                unlisted.setdefault(ip, 0)
                unlisted[ip] += 1
    link = NetSet(ev.cfg["link_cidrs"])
    for ip, n in unlisted.items():
        hit = seen[seen["ip"] == ip]
        rows.append(dict(indicator=ip, type="ip (NOT in vendor list)", vendor_first=pd.NaT, vendor_last=pd.NaT,
                         our_first=hit["ts"].min(), our_last=hit["ts"].max(), our_events=len(hit), confidence="ours",
                         gap="used with the vendor's credentials but absent from the vendor's indicator list"
                             + (" (inside the private link - vendor-side host?)" if ip in link else "")))
    return pd.DataFrame(rows), []


def sso_checks(ev, cfg):
    """Identity signals that need no threshold:
    * password accepted, MFA failed, from a city the person has never signed in from
      => someone else knows the password (rotate it, whatever MFA did)
    * accounts that sign in with a password and no second factor at all."""
    s = ev.sso
    findings, gov = [], []
    if s.empty:
        return findings, gov
    ok = s[s["ok"]]
    home_cities = ok.groupby("user")["city"].agg(lambda x: set(x)).to_dict()
    home_ips = ok.groupby("user")["ip"].agg(lambda x: set(x)).to_dict()
    mfa_fail = s[~s["ok"] & s["mfa"].str.contains("fail", case=False) & ~s["mfa"].str.contains("not", case=False)]
    for (user, day), g in mfa_fail.groupby(["user", mfa_fail["ts"].dt.date]):
        new_city = [c for c in g["city"] if c and c not in home_cities.get(user, set())]
        new_ip = [i for i in g["ip"] if i not in home_ips.get(user, set())]
        if not (new_city and new_ip):
            continue
        burst = s[(s["user"] == user) & (s["ts"] >= g["ts"].min() - pd.Timedelta(minutes=30)) & (s["ts"] <= g["ts"].max()) & ~s["ok"]]
        findings.append(dict(
            module="identity", category="detection", severity=75,
            title="Password accepted, MFA refused, from a city never used",
            ts_first=burst["ts"].min(), ts_last=burst["ts"].max(), entity=user, cred=user, ip=", ".join(sorted(set(burst["ip"]))),
            refs=list(burst["ref"]),
            summary=f"{user}: {len(burst)} failed sign-in(s) from {', '.join(sorted(set(burst['ip'])))} ({', '.join(sorted(set(new_city)))}); "
                    f"the last one passed the password and failed only at MFA. Treat the password as known to someone else.",
            details={},
        ))
    pw_only = ok[ok["auth"].str.strip().str.lower().eq("password")]
    for user, g in pw_only.groupby("user"):
        gov.append(dict(user=user, sign_ins=len(g), first=g["ts"].min(), last=g["ts"].max(),
                        devices=", ".join(sorted(set(g["device"]) - {""}))[:60], ips=", ".join(sorted(set(g["ip"])))[:60]))
    return findings, gov


def exposure_chain(ev, act, cfg):
    """Credentials known to be written in a ticket (context.json 'credential_exposures', e.g. from the
    support chat E13). If a suspicious identity reads that ticket and the credential is later used from
    an address it never used before, the two halves join into one chain."""
    out = []
    for x in ev.context.get("credential_exposures", []):
        cred, ticket = bare(x.get("credential", "")), x.get("ticket", "")
        if not cred:
            continue
        reads = ev.hd[ev.hd["object_id"] == ticket] if ticket and len(ev.hd) else ev.hd.iloc[0:0]
        reads = reads.merge(act[["ref", "witness", "external_ip"]], on="ref", how="left")
        odd_reads = reads[reads["witness"].isin(["OFF_LINK", "NEW_LINK_HOST", "UNWITNESSED"])]
        uses = []
        if len(ev.bv):
            u = ev.bv[ev.bv["principal"].map(bare) == cred]
            uses.append(u[["ts", "ip", "ref"]])
        u = act[act["cred"].map(bare) == cred]
        uses.append(u[["ts", "ip", "ref"]])
        uses = pd.concat(uses)
        if uses.empty:
            continue
        nets = uses[uses["ip"] != ""]["ip"].str.rsplit(".", n=1).str[0]
        share = nets.value_counts(normalize=True)
        homes = set(share[share >= cfg["home_net_min_share"]].index)
        after = uses[uses["ts"] > (odd_reads["ts"].min() if len(odd_reads) else pd.Timestamp.min)]
        foreign = after[(after["ip"] != "") & ~after["ip"].str.rsplit(".", n=1).str[0].isin(homes)]
        if len(odd_reads) and len(foreign):
            out.append(dict(
                module="chain", category="detection", severity=90,
                title="Credential lifted from a ticket, then used from new addresses",
                ts_first=odd_reads["ts"].min(), ts_last=foreign["ts"].max(), entity=cred, cred=cred,
                ip=", ".join(sorted(set(odd_reads["ip"]) | set(foreign["ip"]))),
                refs=list(odd_reads["ref"]) + list(foreign["ref"]),
                summary=f"{ticket} holds {cred} ({x.get('source', 'context')}). It was read by "
                        f"{', '.join(sorted(set(odd_reads['cred'])))} from {', '.join(sorted(set(odd_reads['ip'])))} on "
                        f"{odd_reads['ts'].min():%d %b %H:%M} UTC; {cred} was then used {len(foreign)} time(s) from "
                        f"{', '.join(sorted(set(foreign['ip'])))}, starting {foreign['ts'].min():%d %b %H:%M} UTC.",
                details={},
            ))
    return out


def roster_inconsistencies(ev, cfg):
    ro = ev.roster
    if ro.empty:
        return []
    term_re = re.compile(cfg["terminated_status_regex"], re.I)
    bad = ro[ro["termination_date"].notna() & ~ro["status"].str.contains(term_re)]
    return [f"{r['full_name']} ({r['username']}) has termination date {r['termination_date']:%d %b %Y} but status '{r['status']}'"
            for _, r in bad.iterrows()]
