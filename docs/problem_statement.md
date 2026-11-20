# Problem Statement: Case CR-26-047 · Approach: DEFENSE

**What we believe happened.** TallyBridge Connect's long-lived LedgerOne and HelpDeskr keys were used by a second actor alongside the real nightly sync:
- first from home-broadband addresses (9–12 Aug),
- then from a TallyBridge **build server inside the private link**, 10.20.4.77 `tb-build-02` (17 Aug – 6 Sep).

The actor searched support tickets for secrets. It took a customer storage key that had been pasted into a ticket and used it to read our vendor bank-details and payment files in BlueVault. It exported the vendor and payment lists, deleting the export jobs afterwards. On **3 Sep it changed vendor V-0412's bank account through the API with no approval, five days before the 8 Sep payment run.** The vendor's own account of the incident (E16) is contradicted by our logs on every point.

**Evidence** (all times UTC)
- **Off-link probing, forged client name.** E01 `req-c28d87e49d` (`/v2/me`, 9 Aug 03:12, 198.18.7.41, `TallyBridge-Sync/3.4.1`). E20-C says 3.4.x was retired on 10 Jul. The real sync (E01, .11–.16) ran 3.5.0 from 10 Jul.
- **Secret hunt and stolen storage key.** E02 `evt-43137d98e2`…`evt-908faff869`: 16 searches ("password", "api_key", "bvk-", "credentials"). E02 `evt-20d941e9bc` then reads **TKT-48213**, which holds `bvk-7f3a` per E13 (25 Jun 11:31).
- **Export and delete.** E02 EXP-5410…5419: 10 jobs created, downloaded and deleted in 75 min. `evt-3fe76f60c4` is the failed delete. E06 shows 14 jobs billed in Aug against 4 that are routine. E01 `req-c35c2ccaff` and `req-51b30fba51` are vendor exports (9,840 and 9,835 records). Export 9932 was never deleted.
- **BlueVault pivot.** E05 `bv-80ffa5124a` and `bv-edb0081dad`: `bvk-7f3a` lists `/finance` and reads `vendor-bank-details-2026.xlsx` from 198.18.7.23 on 14 Aug. In total there are 44 out-of-territory events from 198.18.7.23, .24 and .77. E04 gives the key `read:all-folders` with no IP limit.
- **Admin password attempt.** E03 `sso-74805f5dd1`, `sso-5e1305b0b4`, `sso-562f41d2b5`: a.kapoor, from 198.18.7.77 (Mumbai), 15 Aug. The third attempt passed the password and failed only at MFA.
- **The build host.** E15 `flw-67f0a99b5c`: 10.20.4.77 `tb-build-02` reaches **production** LedgerOne on 17 Aug. Before that it had only reached LedgerOne-sandbox (9 Jul). E20-B shows it was "re-provisioned" on 16 Aug. E01 `req-fe4bd4fe93` is a payments export (4,210 records), then `req-ab03db20b8` deletes export 9955.
- **The fraud.** E18 `req-5f61b0de8` is a PATCH to `/v2/vendors/V-0412/bank-details` from 10.20.4.77. It joins to E19 `chg-8b9888c39b`: V-0412 "Coastal Packaging Ltd", ****4417 → ****9083, channel API, **approval_ref blank**. E18 `req-bb819dfe0c` reads the scheduled payments on 6 Sep.
- **Governance.**
  - E04: `key-tb-07` has read/write on all modules, no IP limit, no expiry, last reviewed Jun 2024.
  - E10 §2, §4.1 and §5.1 were breached, and the §7.1 deadline (1 Jan 2026) has passed.
  - E11 findings 2–7 are all open and match the exploited gaps.
  - E09 R-031 rates TallyBridge **Low / accepted**, with the review overdue since Jun 2025.
  - E07: the vendor's SOC 2 excludes its source code and credential vault.
  - E12 went to the billing contact only. E17 omits 10.20.4.77.

**What we are unsure about, and what would settle it**
1. **Whether V-0412 or any earlier run was paid to a changed account.** The bank's payment file for the 23 Aug and 8 Sep runs would settle it.
2. **Whether `tb-build-02` was an outside attacker or a vendor insider.** TallyBridge's build and VaultWorks logs would settle it, and E08 §9.1 gives us no audit right to them.
3. **Whether the "rotated" key (E16 §5) is already in the attacker's hands.** `key-tb-07` was still accepted from .77 on 3 Sep. Re-issuing it ourselves with an IP restriction and checking for use would settle it.
4. **Whether any of the 70 announced contact-detail changes (Sep, E19) were tampered with.** They would defeat call-back checks. The vendors' own contacts in their contracts would settle it.
5. **The BlueVault clock skew could not be measured** (there are no co-occurring events). The timeline is precise only to within minutes. That doesn't change the order of events, which are days apart.

**Other explanations we weighed**
- **An insider, Rohan Menon** (left 30 Jun). He made one kiosk sign-in, E03 `sso-bb8ab61e08` on 13 Aug, and there is no other activity by him anywhere afterwards. That makes it a leaver-access failure (E11 finding 3), not the actor.
- **Farah Dsouza and V-0233.** The change carries APR-1182, which is out of sequence (numbers had already reached APR-1237), three days before a run. Everything else about it is normal: same device, same office address. Verdict: VERIFY the approval record, not proven fraud.
- **A legitimate TallyBridge change.** Contact sync is announced (E16 §7, 3.6.0), but payments export, bank-details reads and bank PATCHes are not. A build host has no reason to touch production.
- **"The address belongs to a staff member."** 198.18.7.0/24 is dynamic residential (E20-G), and staff used .24 and .41 on other days. We attribute by credential and behaviour, not by IP.
- **Ordinary events, set aside.** Colin's travel, Sunita's Tuesday exports (her 28 Jul delete is explained in E13), Farah's 22 Jul audit export (announced in E13), the 31 Jul bulk import (BULK-0731), and the 429 retries.

**The problem we chose.** A third-party integration can change where we send money, and nothing checks that change against anything else. No other system confirms which host acted, no approval is enforced, and nobody watches. We chose it because it is the only failure here where money leaves irreversibly, and the next run is on 8 Sep.

**The obvious approach, and why we did not take it.** The obvious approach is per-log SIEM rules: new IP, impossible travel, off-hours, volume. **On this evidence it raises 29,961 false alarms**, mostly staff on dynamic home addresses, and still misses the BlueVault theft and the admin password attempt. It would also never fire on the bank change, which came from inside the private link, inside the sync window, with the real client name.

We check invariants instead:
1. A link identity's actions are witnessed by a known host.
2. The sync only does what the sync does (a ledger of normal actions plus a grammar of how they follow each other).
3. A credential stolen from a ticket can't be used from new addresses without the two events being joined.
4. Payment instructions change only with a person's approval.

On the real evidence, scored against our own labels, this flags **181 of 181 attacker events with 0 false alarms**, in one incident thread.

**What would change our mind.**
- An approval record exists for the V-0412 change.
- TallyBridge's logs show 10.20.4.77 was operated by its staff for an authorised purpose.
- A payment-run file shows V-0412's new account belongs to the vendor.

**Approach: DEFENSE** (locked).
