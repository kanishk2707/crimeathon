# Double-Entry Defense

**Team Vortex · CRIMEATHON'26 · Case CR-26-047 (Harbor & Finch Freight) · Defense track**

A trusted integration (TallyBridge Connect) had its keys used by a second actor. That actor stole data and, on 3 Sep, changed where Harbor & Finch pays vendor V-0412, five days before a payment run. Every log recorded it, but nothing cross-checked the logs.

Double-Entry Defense checks a trusted integration the way an accountant checks books: **every action it takes must be matched by an independent record**, and anything that doesn't match is held for review instead of trusted.

On the supplied evidence, scored against our own labels:
- **181 of 181 attacker records**, all 9 stages, flagged with **0 false alarms**;
- everything joined into **1 incident**, and **V-0412 held** before the 8 Sep run;
- about 8 seconds per run on a laptop (up to ~30 s on battery power).

The obvious per-log approach, measured on the same evidence, raises 29,961 false alarms and still misses two stages.

---

## Tier 3 submission materials

| # | Item | Where |
|---|---|---|
| 1 | One-page final project PPT | [`docs/tier3/Vortex_CR-26-047_Final_OnePager.pptx`](docs/tier3/) (+ `.pdf`) |
| 2 | Working solution | this repository: `python -m doubleentry ...` (see [Run it](#run-it-step-by-step)) |
| 3 | Source and README | this file |
| 4 | Demo video | [`docs/tier3/demo/`](docs/tier3/demo/) (video and narration script) |
| 5 | Proof pack | [`docs/tier3/PROOF_PACK.md`](docs/tier3/PROOF_PACK.md) (+ `.pdf`, `evidence_index.csv`, `input_manifest.csv`) |
| 6 | Final technical report | [`docs/tier3/Vortex_CR-26-047_Technical_Report.pdf`](docs/tier3/) |

Earlier rounds: [Tier 1 case analysis](docs/Vortex_CR-26-047_Tier1_Case_Analysis.pdf) · [Tier 2 concept deck](docs/tier2/Vortex_CR-26-047_Tier2_Concept.pdf)

---

## What it does

| Check | Module | Catches |
|---|---|---|
| **Witness check**: every integration API call must also appear in the private-link network log, from a known sync host | `witness.py` | Stolen keys used from home broadband, and an unlisted machine **inside** the private link |
| **Double-entry ledger**: every read of our data must be paired with the sync write it serves; unpaired reads go to a *suspense* list | `ledger.py` | Data taken with no business reason |
| **Sync grammar**: the sync's normal requests are learned from witnessed sessions only, with no hand labels | `grammar.py` | Searches, exports and client versions the sync never uses |
| **Payment-run firewall**: every bank-detail change is checked for approval, who made it, leavers, source address, timing and approval-reference order | `firewall.py` | Unapproved payee changes; HOLD or VERIFY per vendor before the run |

**Supporting checks:**
- **Clock solver** (`clocks.py`): measures each system's clock offset from events that must happen together, and refuses to guess when there is no signal.
- **Identity resolution** (`identity.py`): joins one actor's different names across systems.
- **Exports and secret searches** (`exfil.py`): treats the vendor's invoice as a record the attacker can't delete.
- **Storage territory** (`territory.py`): flags keys reading folders they have never touched.
- **Governance and outside information** (`intel.py`):
  - integration passport against policy;
  - leavers;
  - SSO;
  - ticket-to-key exposure chain;
  - the vendor's indicator gap.
- **Triage** (`triage.py`): weights findings by time to the next payment run, joins them into incident threads, and caps paged alerts per day.

**Features that act, not just detect:**
- **Vendor-claim checker** (`claims.py`): each statement in the vendor's notice is tested against our logs. **6/6 are contradicted.**
- **Least-privilege replay** (`shrinkwrap.py`): learns what each key really needs, then replays the rest of the evidence. It would have refused **133/133** attacker requests and 70 genuine ones (the unreviewed contact sync).
- **Call-back guard** (`callback.py`): lists vendors whose phone or email was rewritten by software, so Finance calls the number in the contract. There are 66, including V-0162 on the verify list.
- **Four briefs** (`briefs.py`): one-screen briefs for the General Manager, Finance, Legal and IT, generated from the same findings.

---

## Setup

**Requirements:**
- Python 3.10 or newer (tested on 3.13.7, Windows 11);
- `pandas>=2.0` and `numpy>=1.24`;
- no network access, GPU, database or API keys.

```powershell
git clone https://github.com/kanishk2707/crimeathon.git
cd crimeathon
python -m venv .venv
.venv\Scripts\activate              # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

The supplied evidence (E01–E20, all synthetic and fictional) and `evidence/context.json` are already in `evidence/`.

## Run it, step by step

**One command (Windows):** `.\run_demo.ps1` analyses the evidence, prints the score and opens the report. Add `-Full` to also run the synthetic suite. On Linux or macOS use `./run_demo.sh` (`./run_demo.sh --full`).

Or step by step:

```powershell
# 1. Analyse the supplied evidence (about 8 s on a laptop, ~30 s on battery). Writes out/real/
python -m doubleentry analyze evidence --out out/real

# 2. Same, plus a score against our labels and against the obvious approach
python -m doubleentry analyze evidence --out out/real --truth analysis/analyst_labels.json

# 3. Open the report
start out/real/report.html            # macOS: open … · Linux: xdg-open …

# 4. Synthetic rehearsal with ground truth (fictional data, same file layout)
python -m doubleentry generate --out synthetic/reference --variant reference --seed 7
python -m doubleentry analyze synthetic/reference --out out/reference --truth synthetic/reference/ground_truth.json

# 5. Hidden-variation suite: 6 attack variants x 3 seeds vs the obvious approach (about 1 minute)
python -m doubleentry evaluate --out eval --variants all --seeds 7,11,23

# 6. Regenerate our labels from their written rules, and rebuild the proof pack
python analysis/make_labels.py evidence analysis/analyst_labels.json
python analysis/build_proof_pack.py evidence docs/tier3
```

Expected output of step 2 ends with:

```text
50 alerts in 1 thread(s); 1 vendor(s) to hold. Report: out\real\report.html
```

and the score block shows `"tp": 181, "fp": 0, "fn": 0, "stages_detected": "9/9"` for us, and `"tp": 134, "fp": 29961` for the baseline.

## Configuration

**`--config my.json`** overrides any value in [`doubleentry/config.py`](doubleentry/config.py). The defaults are facts from the case file, not tuned thresholds:

| Key | Default | Meaning |
|---|---|---|
| `link_cidrs` | `["10.20.4.0/24"]` | Private link to the vendor |
| `internal_cidrs` | `["172.16.0.0/16"]` | Office and server networks |
| `payment_run_days` | `[8, 23]` | Vendor payment-run days |
| `local_tz_offset_minutes` | `{"E02": 330, "E13": 330}` | HelpDeskr logs in IST |
| `bluevault_skew_seconds` | `null` | `null` = estimate automatically; set it when the solver can't measure it |
| `alert_budget_per_day` | `10` | Paged alerts per day; the rest stay in the report |
| `policy_train_until` | `null` | Least-privilege learning cut-off (default: midpoint of the evidence) |

Behavioural baselines (normal hosts, hours, request types, folders, export routines) are learned from the data at run time.

**`evidence/context.json`** holds facts typed in from PDF and chat evidence. Each entry cites its source. The file is optional; without it, the matching checks switch off.

| Key | Source | Switches on |
|---|---|---|
| `billed_exports` | E06 invoice | Invoice vs audit-log export count |
| `announced_changes` | E16 item 7, E20-C | Announced behaviour goes to change control, not to the incident queue |
| `credential_exposures` | E13 chat | Ticket-to-key exposure chain |
| `vendor_claims` | E16 items 1–5, E20-A | Vendor-claim checker |
| `approval_refs` (optional) | an approval register | The firewall checks that a reference exists, not just its form |

## Inputs

Evidence files are found by their code prefix (`E01*.csv`, `E04*.json`, …), so renamed files still load. Column names are matched loosely. A missing file switches off only the modules that need it.

Formats, row counts, columns, clocks and SHA-256 hashes for every file are in [proof pack §2](docs/tier3/PROOF_PACK.md#2-required-input-files-and-formats) and `docs/tier3/input_manifest.csv`.

## Outputs (`out/real/`, included in the repo)

| File | Contents |
|---|---|
| `report.html` | The full report; opens offline |
| `briefs.md` | Four one-screen briefs: GM, Finance, Legal, IT security |
| `hold_list.csv` | HOLD / VERIFY per vendor, last-known-good bank value, call-back advice |
| `payment_changes_scored.csv` | Every bank-detail change with its score and reasons |
| `timeline.csv` | All alerts in time order |
| `findings.json` | Every finding with the exact evidence records it relies on (`E01:req-…`, `E19:chg-…`) |
| `vendor_claims_checked.csv` | Each vendor claim, verdict and contradicting records |
| `least_privilege_policy.json` | Learned policy per credential and what it would have refused |

**What the report shows.** At the top, a banner names the vendors to hold before the next run, with six headline numbers. Then:

0. The four briefs
1. The payment hold list and call-back guard
2. Incident threads
3. The suspense list
4. Witness check
5. Sync grammar
6. Exports and storage
7. The vendor's statement against our logs
8. Governance and the least-privilege policy
9. Clock offsets and sources
10. Every alert, with its evidence record IDs

## Results

**Supplied evidence** (scored against `analysis/analyst_labels.json`, which holds *our* conclusions, not organiser ground truth):

| | Double-Entry Defense | Obvious per-log rules (`baseline.py`) |
|---|---|---|
| Attacker records flagged | **181 / 181**, 9/9 stages | 134 / 181; misses the BlueVault pivot and the admin password attempt |
| False alarms | **0** of 99,456 benign records | **29,961** |
| Incident threads | 1 | n/a |
| Before the 8 Sep run | **HOLD V-0412** (****9083 → restore ****4417); VERIFY V-0162, V-0128, V-0233, V-0298 | nothing |

**Tuning disclosure.** The first run on the real evidence raised about 24 false alarms. We changed three rules, each based on a documented fact:
1. Blank BlueVault addresses don't count against people (E05 drops addresses).
2. Announced behaviour goes to change control (E16 §7, E20-C).
3. A person viewing a ticket doesn't count as the ticket-to-key chain.

The synthetic suite was re-run afterwards with no regressions.

**Synthetic hidden-variation suite** (6 variants × 3 seeds, a different BlueVault clock skew each time, the engine never told which variant it is analysing):

| Variant | What changes | Precision | Recall | False alarms | Baseline false alarms / world |
|---|---|---|---|---|---|
| reference | off-link keys, export-and-delete, legacy-key probe, storage pivot, tamper → revert → tamper | 1.00 | 1.00 | 0 | ~490 |
| on_link | same campaign from a host **inside** the private link | 1.00 | 1.00 | 0 | ~490 |
| mimic | current client version, inside the sync window, low and slow | 1.00 | 1.00 | 0 | ~490 |
| insider | a leaver's still-active account edits bank details | 1.00 | 1.00 | 0 | ~490 |
| forged_approval | daytime tamper with a **well-formed approval reference** | 1.00 | 1.00 | 0 | ~490 |
| **inside_worker** | the vendor's real sync host skims inside the real session | 1.00 | **0.44–0.56** | 0 | ~490 |

The clock solver recovered every planted skew to within 6 s (199 → 204, 311 → 317, 347 → 352).

## Limitations (full list in [proof pack §6](docs/tier3/PROOF_PACK.md#6-known-limitations))

- **The real-evidence score uses our own labels, after one calibration pass.** It shows the engine reproduces our investigation, not an independent accuracy figure.
- **A compromised vendor host that stays inside the sync's own pattern** is only half caught. Its bank edits are still caught.
- **BlueVault's clock offset can't be measured on the real data,** so its times are shown uncorrected.
- **Approval references are checked for form and order,** not existence, unless an approval register is supplied.
- **It runs as a batch over exported logs,** not live.

## Repository layout

```text
doubleentry/        the engine (Python package, 25 modules)
  __main__.py         CLI: generate | analyze | evaluate
  engine.py           pipeline: load → clocks → identity → witness → ledger → grammar → firewall
                      → exports → territory → governance → triage → claims/policy/briefs
  load.py config.py util.py
  clocks.py identity.py witness.py ledger.py grammar.py firewall.py
  exfil.py territory.py intel.py triage.py
  claims.py shrinkwrap.py callback.py briefs.py report.py
  synth.py baseline.py evaluate.py   synthetic worlds, obvious-approach baseline, scoring
analysis/           make_labels.py (our labels as written rules), build_proof_pack.py
evidence/           supplied E01–E20 + context.json
out/real/           outputs of the run on the supplied evidence
eval/               evaluation.html / .json from the synthetic suite
docs/               Tier 1 PDF, Tier 2 deck, Tier 3 materials
run_demo.ps1 / run_demo.sh
```

## Data and safety

All data is synthetic: the supplied CRIMEATHON evidence is fictional, and our generated worlds are fictional. The engine only reads files from the evidence folder and writes reports. It doesn't connect to, scan or change any system.
