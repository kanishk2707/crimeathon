# One incident, four briefs

## General Manager

- A second actor used the TallyBridge integration keys from 09 Aug to 06 Sep: 67 requests from home-broadband addresses and 66 from 10.20.4.77 (tb-build-02) inside our private link.
- Money at risk: 1 vendor payment(s) to hold before the 08 Sep run (V-0412); 4 more to verify.
- The vendor's incident statement: 6 of 6 claims are contradicted by our own logs.
- Decision needed today: approve the payment holds and the revocation of the vendor's keys.

## Finance

- HOLD V-0412 Coastal Packaging Ltd: restore bank_account=****4417 (record now shows bank_account=****9083).
- VERIFY V-0162 Nila Logistics Supply 162: no approval reference. Call the contract number: the record's contact was rewritten by software.
- VERIFY V-0128 Orion Logistics Supply 128: no approval reference.
- VERIFY V-0233 Southern Fuel Services: approval APR-1182 is out of sequence: numbers issued in the previous 30 days reached APR-1237.
- VERIFY V-0298 Gemini Logistics Supply 298: no approval reference.
- Call-back warning: software rewrote contact details for 66 vendors since 01 Sep. Call the number in the contract, not the record — including V-0162 on your list.
- Past runs paid to a tampered account: none found in the records.

## Legal

- Support tickets: 10 bulk export jobs of HelpDeskr data on 11 Aug, downloaded and then deleted.
- 21 ticket searches for credentials and bank terms; at least one customer key was taken from a ticket.
- Finance system: 1 × /v2/payments/export (4,210 records).
- Finance system: 2 × /v2/vendors/export (19,675 records).
- Stored files: 44 reads/listings under /finance, /hr (85 MB) using a customer partner's storage key.
- Earliest incident record: 09 Aug 2026 03:12 UTC; latest: 06 Sep 2026 01:36 UTC. Contract and regulator notification periods should be checked from the earliest date.

## IT security

- Revoke and re-issue: bvk-7f3a, key-tb-07, tb-sync-svc.
- Block on the link: 10.20.4.77 — not one of the hosts that carry the sync.
- Block at the edge (temporary — dynamic home addresses): 198.18.7.23, 198.18.7.24, 198.18.7.41, 198.18.7.58, 198.18.7.77.
- Reset the password of a.kapoor: it was accepted from 198.18.7.77; only MFA stopped the sign-in.
- Disable r.menon: former employee whose account still signs in.
- Re-issue key-tb-07 limited to 4 action(s), hosts 10.20.4.11, 10.20.4.12, 10.20.4.13, 10.20.4.14, 10.20.4.15, 10.20.4.16, 01:00–02:45 UTC (granted today: 'read:write all-modules').
- Re-issue tb-sync-svc limited to 1 action(s), hosts 10.20.4.11, 10.20.4.12, 10.20.4.13, 10.20.4.14, 10.20.4.15, 10.20.4.16, 00:59–02:43 UTC (granted today: 'admin').
