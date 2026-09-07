"""Pure, deterministic project triage policy; this does not verify a CVE."""
from __future__ import annotations

import hashlib
import json
import math

METHODOLOGY = {
    "id": "day6-priority-v1",
    "description": "Project triage policy; not an industry standard risk formula or vulnerability verdict.",
    "thresholds": {"epss_very_high": 0.95, "epss_high": 0.80, "cvss_critical": 9.0, "cvss_high": 7.0},
    "actions": {"CANDIDATE": "VERIFY", "POTENTIAL": "VERIFY", "ERROR": "VERIFY",
                "CONFIRMED": "REMEDIATE", "RETEST_REQUIRED": "RETEST"},
    "precedence": ["P1", "P2", "P3", "P4"],
    "rules": [
        {"id": "P1_KEV_EXPOSED", "priority": "P1", "when": {"all": [["kev", "eq", "KNOWN_EXPLOITED"], ["exposed", "eq", True]]},
         "reason": "KEV-listed CVE on an internet-exposed asset; local vulnerability status is unchanged."},
        {"id": "P1_CONFIRMED_CRITICAL_EXPOSED", "priority": "P1", "when": {"all": [["status", "eq", "CONFIRMED"], ["criticality", "eq", "CRITICAL"], ["exposed", "eq", True]]},
         "reason": "Confirmed finding on a critical, internet-exposed asset."},
        {"id": "P2_KEV", "priority": "P2", "when": ["kev", "eq", "KNOWN_EXPLOITED"],
         "reason": "CISA lists this CVE as known exploited."},
        {"id": "P2_EPSS_VERY_HIGH_EXPOSED", "priority": "P2", "when": {"all": [["percentile", "gte", {"threshold": "epss_very_high"}], ["exposed", "eq", True]]},
         "reason": "Very high EPSS percentile and internet exposure."},
        {"id": "P2_CONFIRMED_IMPORTANT_ASSET", "priority": "P2", "when": {"all": [["status", "eq", "CONFIRMED"], ["criticality", "in", ["HIGH", "CRITICAL"]]]},
         "reason": "Confirmed finding on a high or critical asset."},
        {"id": "P2_CVSS_CRITICAL_IMPORTANT_ASSET", "priority": "P2", "when": {"all": [["cvss", "gte", {"threshold": "cvss_critical"}], ["criticality", "in", ["HIGH", "CRITICAL"]]]},
         "reason": "Critical CVSS score and high or critical asset importance."},
        {"id": "P3_EPSS_HIGH", "priority": "P3", "when": ["percentile", "gte", {"threshold": "epss_high"}],
         "reason": "High EPSS percentile."},
        {"id": "P3_CVSS_HIGH", "priority": "P3", "when": ["cvss", "gte", {"threshold": "cvss_high"}],
         "reason": "High CVSS score."},
        {"id": "P3_IMPORTANT_ASSET", "priority": "P3", "when": ["criticality", "in", ["HIGH", "CRITICAL"]],
         "reason": "High or critical asset importance."},
        {"id": "P3_EXPOSED", "priority": "P3", "when": ["exposed", "eq", True],
         "reason": "The asset is internet exposed."},
        {"id": "P4_AVAILABLE_DATA", "priority": "P4", "when": {"all": [{"any": [["cvss", "present", None], ["epss", "present", None]]}, ["criticality", "in", ["LOW", "MEDIUM", "HIGH", "CRITICAL"]]]},
         "reason": "Score data and assigned asset importance are available; no higher rule matched."},
    ],
    "personal_data_modifier": {"id": "PII_ONE_LEVEL", "promotions": {"P4": "P3", "P3": "P2"},
                               "reason": "Personal-data handling raises business-impact priority by one level, capped at P2."},
    "unknown_policy": "Missing scores are not zero; KEV UNKNOWN is not negative evidence. No matching rule means UNASSESSED.",
}
METHODOLOGY_ID = METHODOLOGY["id"]


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_json(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _score(result, field, maximum):
    if result.get("state") != "OK" or result.get(field) is None:
        return None
    value = result[field]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError(f"Invalid normalized {field}")
    return value


def _matches(condition, context, thresholds):
    if isinstance(condition, dict):
        if "all" in condition:
            return all(_matches(item, context, thresholds) for item in condition["all"])
        return any(_matches(item, context, thresholds) for item in condition["any"])
    field, operator, expected = condition
    value = context[field]
    if isinstance(expected, dict):
        expected = thresholds[expected["threshold"]]
    if operator == "present":
        return value is not None
    if value is None:
        return False
    if operator == "eq":
        return value == expected
    if operator == "in":
        return value in expected
    if operator == "gte":
        return value >= expected
    raise ValueError("Unsupported methodology operator")


def assess_priority(status, asset, cvss, epss, kev, *, methodology=None):
    """Return an action and explainable priority without DB, network or mutation."""
    policy = METHODOLOGY if methodology is None else methodology
    if status not in policy["actions"]:
        raise ValueError("Status is not eligible for assessment")
    criticality = asset.get("criticality")
    if criticality not in {None, "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNASSIGNED"}:
        raise ValueError("Invalid asset criticality")
    for field in ("internet_exposed", "handles_personal_data"):
        if asset.get(field) is not None and not isinstance(asset[field], bool):
            raise ValueError("Asset context flags must be boolean or unknown")
    kev_status = kev.get("status", "UNKNOWN")
    if kev_status not in {"KNOWN_EXPLOITED", "NOT_LISTED", "UNKNOWN"}:
        raise ValueError("Invalid KEV state")
    context = {"status": status, "criticality": criticality, "exposed": asset.get("internet_exposed"),
               "cvss": _score(cvss, "score", 10), "epss": _score(epss, "score", 1),
               "percentile": _score(epss, "percentile", 1), "kev": kev_status}
    missing = []
    for key, name in (("cvss", "cvss.score"), ("epss", "epss.score"), ("percentile", "epss.percentile")):
        if context[key] is None:
            missing.append(name)
    if epss.get("date") is None:
        missing.append("epss.date")
    if kev_status == "UNKNOWN":
        missing.append("kev.status")
    if criticality in (None, "UNASSIGNED"):
        missing.append("asset.criticality")
    for field in ("internet_exposed", "handles_personal_data"):
        if asset.get(field) is None:
            missing.append("asset." + field)
    priority, rules, reasons = "UNASSESSED", [], []
    for level in policy["precedence"]:
        winners = [rule for rule in policy["rules"] if rule["priority"] == level
                   and _matches(rule["when"], context, policy["thresholds"])]
        if winners:
            priority = level
            rules = [rule["id"] for rule in winners]
            reasons = [rule["reason"] for rule in winners]
            break
    base_priority = priority
    modifier = policy["personal_data_modifier"]
    if asset.get("handles_personal_data") is True and priority in modifier["promotions"]:
        priority = modifier["promotions"][priority]
        rules.append(modifier["id"])
        reasons.append(modifier["reason"])
    if not reasons:
        reasons.append("Insufficient available inputs to match a triage rule.")
    return {"methodology_id": policy["id"], "methodology_sha256": sha256_json(policy),
            "action": policy["actions"][status], "priority": priority, "base_priority": base_priority,
            "matched_rules": rules, "missing_inputs": missing, "reason": " ".join(reasons)}
