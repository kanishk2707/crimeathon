"""Default configuration. Everything here can be overridden with --config file.json.

Values are deliberately *facts from the case file*, not tuned thresholds:
network ranges (section 3), payment-run days (section 2), tenant time zone (E02).
Behavioural baselines are learned from the data at run time.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

DEFAULT = {
    # --- facts from the case file -------------------------------------------------
    "link_cidrs": ["10.20.4.0/24"],          # private link to TallyBridge (section 3)
    "internal_cidrs": ["172.16.0.0/16"],      # office + server networks
    "payment_run_days": [8, 23],              # vendor payment runs (section 2)
    "payment_run_time_ist": "10:00",
    "local_tz_offset_minutes": {"E02": 330, "E13": 330},  # HelpDeskr tenant time = IST
    "bluevault_skew_seconds": None,           # None = estimate automatically
    "internal_vendor_regex": r"harbor|finch|internal|in-house|inhouse|h&f|self",
    "entity_aliases": {"TallyBridge Connect": ["tallybridge", "key-tb-", "tb-sync"]},
    # --- vocabulary ------------------------------------------------------------------
    "bank_field_regex": r"bank|account|acct|ifsc|iban|swift|bic|beneficiary|routing|upi|payee|sort.?code",
    "approval_ref_regex": r"[A-Za-z]{2,}.*\d{2,}",
    "approval_placeholders": ["", "na", "n/a", "none", "-", "null", "tbd", "pending", "nan", "0"],
    "sensitive_token_regex": r"bank|payment|vendor|export|search|secret|password|credential|finance|statement|payee",
    "secret_query_regex": r"password|passwd|secret|api[ _-]?key|access[ _-]?key|token|credential|private[ _-]?key|connection string",
    "export_action_regex": r"export",
    "download_action_regex": r"download|retriev|fetch",
    "delete_action_regex": r"delete|remove|purge|destroy|cancel",
    "write_action_regex": r"creat|updat|upsert|writ|sync|import|insert|put|patch|post|comment|link|assign|close|merge",
    "read_action_regex": r"read|view|get|list|search|query|fetch|open",
    "terminated_status_regex": r"terminat|left|leaver|inactive|exit|resign|former|disabled",
    # --- learned-model knobs (relative, not absolute thresholds) ---------------------
    "session_gap_minutes": 20,
    "credit_lag_minutes": 45,
    "witness_tolerances_s": [15, 30, 60, 120, 300, 600, 1800],
    "witness_target_rate": 0.95,
    "home_net_min_share": 0.05,
    "territory_min_weeks": 3,
    "routine_min_weeks_fraction": 0.5,
    "vocab_min_session_share": 0.2,
    "bigram_min_sessions": 2,
    "antiforensic_window_minutes": 60,
    "review_max_age_days": 365,
    "dormant_days": 90,
    "alert_threshold": 60,
    "alert_budget_per_day": 10,
    "analysis_end": None,
    "policy_train_until": None,  # least-privilege policy: learn before this, replay after (default: midpoint)
}


def _merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULT)
    if path:
        cfg = _merge(cfg, json.loads(Path(path).read_text(encoding="utf-8")))
    return cfg
