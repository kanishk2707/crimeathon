# Demo video: script and shot list

`Vortex_CR-26-047_Demo.mp4`, 1920×1080, 3 min 38 s. Built by `docs/tier3/build/make_demo_video.py` from a real run of the engine on the supplied evidence (the terminal scene shows that run's actual console output; omitted lines are marked `…`). Every report scene is a screenshot of the generated `out/real/report.html`.

The narration is Windows' built-in text-to-speech voice. To re-record it in your own voice, read the narration column below; each row starts at the time shown.

| # | Starts | Scene | On-screen caption | Narration |
|---|---|---|---|---|
| 1 | 0:00 | Title | Live run on the supplied evidence (E01–E20) | Double-Entry Defense, by Team Vortex. Case C R 26, zero 47, Defense track. This is a live run of our engine on the supplied evidence. |
| 2 | 0:12 | The problem | A trusted vendor key changed where we pay V-0412, with no approval, 5 days before a payment run | A trusted vendor integration, TallyBridge Connect, had its keys used by a second actor. It searched support tickets for secrets, stole a storage key, exported our vendor and payment lists, and on the third of September changed vendor V 0 4 1 2's bank account with no approval, five days before a payment run. |
| 3 | 0:31 | Architecture | Every action by the integration must match an independent record | Our engine checks the integration the way an accountant checks books: every action must match an independent record. It loads the evidence, aligns the clocks, joins each actor's names across systems, runs four checks, and ranks findings by how soon money could leave. |
| 4 | 0:48 | Run it | pip install -r requirements.txt   ·   python -m doubleentry analyze evidence | Setup is one pip install. One command analyses the evidence and scores it against our labels: 181 of 181 attacker records, zero false alarms, all nine stages. The obvious per-log rules raise almost 30 thousand false alarms. |
| 5 | 1:06 | The report | The decision comes first: hold one vendor before the 8 Sep payment run | The report opens with the decision: hold one vendor before the eighth of September payment run. Fifty alerts, joined into one incident. |
| 6 | 1:15 | Four briefs | One analysis, four readers: General Manager, Finance, Legal, IT security | The same findings are written four ways: for the General Manager, Finance, Legal, and IT security. Every line is generated from the analysis; nothing is typed by hand. |
| 7 | 1:28 | Payment-run firewall | HOLD V-0412: changed by a software key, no approval, unknown host  ·  call-back guard: 66 vendors | The payment-run firewall holds V 0 4 1 2. Its bank account was changed by a software key, with no approval, from a host that never carried the sync, and the report gives the last known good account to restore. The call-back guard warns that software rewrote the contact details of 66 vendors, so Finance must call the number in the contract, not the one on file. |
| 8 | 1:50 | Incident threads | All alerts join into one incident, 9 Aug to 6 Sep | Every alert joins into one incident thread, linked by shared keys and addresses, from the ninth of August to the sixth of September. |
| 9 | 1:59 | Double-entry ledger | Reads with no matching write go to the suspense account | The double-entry ledger pairs every read of our data with the write it serves. Reads with no matching write land in the suspense account. |
| 10 | 2:08 | Witness check | API log × network log: off-link use, and the unlisted link host 10.20.4.77 | The witness check compares every API call with the private link's network log. It catches the stolen keys used from home broadband, and the vendor build host, 10.20.4.77, which never carried the sync. |
| 11 | 2:23 | Sync grammar | Learned from witnessed sessions only: searches, exports and a retired client break it | The sync grammar is learned only from witnessed sessions, with no hand labels. Ticket searches, exports and a retired client version break it. |
| 12 | 2:33 | Exports and storage | Deleted exports still appear on the invoice; a stolen storage key read /finance | Ten export jobs were deleted, but the vendor's invoice still counts them. And a storage key stolen from a support ticket read our finance folders. |
| 13 | 2:42 | Vendor-claim checker | The vendor's statement, tested against our logs: 6 of 6 claims contradicted | We tested the vendor's own incident statement against our logs. All six claims are contradicted, and each verdict cites the records. |
| 14 | 2:51 | Least-privilege replay | Learned before 21 Jul, replayed after: 133 of 133 attacker requests refused | The least-privilege policy learns what each key really needs. Replayed on the rest of the evidence, it would have refused all 133 attacker requests. Among genuine requests, it refuses only the unreviewed contact sync. |
| 15 | 3:07 | Evidence IDs | Every alert cites the exact evidence records it relies on | Every alert lists the exact evidence records it relies on, so anyone can open the file and check. |
| 16 | 3:14 | Testing | 6 attack variants × 3 seeds: precision 1.00 everywhere; the hardest variant is half caught | To test variations we have not seen, we generate six attack variants with three seeds each. Precision is 1 point 0 everywhere. The hardest variant, an attacker hiding inside the sync's own session, is only half caught, and we say so. |
| 17 | 3:29 | Close | github.com/kanishk2707/crimeathon | Double-Entry Defense. The code, the proof pack and the technical report are on GitHub. Thank you. |

## Recording it live instead

1. `pip install -r requirements.txt`
2. `.\run_demo.ps1` (prints the score and the four briefs, opens the report)
3. Scroll the report in the order of the scenes above, then open `eval/evaluation.html` (run `.\run_demo.ps1 -Full` first to regenerate it).
