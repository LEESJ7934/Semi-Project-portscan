"""Build one read-only, current-state V5 report snapshot and export it locally."""
from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

from analysis.vuln_mapper import load_catalog
from db.db_client import get_connection
from db.statuses import VulnStatus

PRIORITIES = ("P1", "P2", "P3", "P4", "UNASSESSED")
FRESHNESS = ("CURRENT", "STALE", "MISSING")
SELECTION_NOTE = "Current-state port observations only; this is not historical replay."
COVERAGE_NOTE = "No stored reviewed findings does not establish security. Unobserved services and unsupported CVEs are outside this report."
FRESHNESS_NOTE = "CURRENT means stored assessment context matches this snapshot; external threat feeds were not refreshed."
ASSET_FIELDS = ("id", "asset_uid", "host_ip", "host_name", "asset_name", "asset_type", "environment",
                "criticality", "owner", "business_unit", "data_classification", "handles_personal_data",
                "internet_exposed", "lifecycle_status", "first_seen", "last_seen", "last_scan_id")
PORT_FIELDS = ("port_id", "host_id", "port", "protocol", "service", "product", "version", "state", "last_scan_id")
FINDING_FIELDS = ("vuln_id", "port_id", "cve_id", "title", "source", "status", "severity",
                  "first_detected_at", "last_detected_at", "verified_at", "closed_at")
ASSESSMENT_FIELDS = ("assessment_id", "vuln_id", "methodology_id", "methodology_sha256", "vuln_status",
                     "action", "priority", "cvss_score", "cvss_version", "cvss_vector", "cvss_source",
                     "epss_score", "epss_percentile", "epss_date", "kev_status", "kev_date_added",
                     "asset_criticality", "internet_exposed", "handles_personal_data", "input_sha256",
                     "first_assessed_at", "last_assessed_at", "observations")
FINGERPRINT_FIELDS = ("service", "product", "version", "source", "confidence", "parser_version", "error")


class ReportSelectionError(ValueError):
    pass


class ReportDatabaseError(RuntimeError):
    pass


class ReportDataError(ValueError):
    pass


def validate_selection(*, asset_uid=None, scan_id=None):
    if (asset_uid is None) == (scan_id is None):
        raise ReportSelectionError("Exactly one asset UUID or positive scan ID is required")
    if scan_id is not None:
        if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
            raise ReportSelectionError("scan-id must be a positive integer")
        return {"type": "scan", "scan_id": scan_id, "selection_note": SELECTION_NOTE}
    try:
        canonical = str(UUID(asset_uid))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReportSelectionError("asset-id must be an asset UUID, not an IP address") from exc
    return {"type": "asset", "asset_uid": canonical, "selection_note": SELECTION_NOTE}


def json_value(value):
    """Preserve absent values and make MySQL Decimal/date results JSON compatible."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z") if value.tzinfo is None else value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value) if value.is_finite() else None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _boolean(value):
    return bool(value) if isinstance(value, (bool, int)) and value in (0, 1) else None


def _object(value):
    if value is None or value == "":
        return {}, "MISSING"
    try:
        if isinstance(value, (str, bytes)):
            value = json.loads(value, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
        if not isinstance(value, dict):
            raise ValueError("Expected JSON object")
        return json_value(value), "PARSED"
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return {}, "PARSE_ERROR"


def _pick(row, fields):
    return {key: json_value(row.get(key)) for key in fields}


def _select(cursor, sql, params=()):
    cursor.execute(sql, tuple(params))
    return cursor.fetchall()


def _related(cursor, sql, identifiers, suffix=""):
    results = []
    ids = sorted(set(identifiers))
    for start in range(0, len(ids), 500):
        batch = ids[start:start + 500]
        results.extend(_select(cursor, sql + "(" + ",".join(["%s"] * len(batch)) + ") " + suffix, batch))
    return results


def _read_rows(conn, selection):
    with conn.cursor(dictionary=True) as cursor:
        asset_sql = "SELECT " + ", ".join("h." + key for key in ASSET_FIELDS) + " FROM hosts AS h WHERE "
        scan_sql = """
            SELECT s.id AS scan_id, s.scan_uid, s.status, s.scan_type, s.target,
                   s.requested_targets, s.port_range, s.started_at, s.finished_at,
                   sc.scope_uid, sc.authorization_ref, sc.approved_by, sc.valid_from,
                   sc.valid_until, sc.policy_sha256
            FROM scans AS s LEFT JOIN scan_scopes AS sc ON sc.id = s.scope_id
            WHERE s.id IN
        """
        if selection["type"] == "asset":
            assets = _select(cursor, asset_sql + "h.asset_uid = %s ORDER BY h.id", [selection["asset_uid"]])
            if not assets:
                raise ReportSelectionError("Asset was not found")
            port_condition = "h.asset_uid = %s AND p.last_scan_id = h.last_scan_id"
            port_params = [selection["asset_uid"]]
            scans = _related(cursor, scan_sql, [row["last_scan_id"] for row in assets if row.get("last_scan_id") is not None])
        else:
            scan_id = selection["scan_id"]
            scans = _related(cursor, scan_sql, [scan_id])
            if not scans:
                raise ReportSelectionError("Scan was not found")
            assets = _select(cursor, asset_sql + """
                EXISTS (SELECT 1 FROM scan_assets AS sa WHERE sa.host_id = h.id AND sa.scan_id = %s)
                OR EXISTS (SELECT 1 FROM ports AS p WHERE p.host_id = h.id AND p.last_scan_id = %s)
                ORDER BY h.id
            """, [scan_id, scan_id])
            port_condition = "p.last_scan_id = %s"
            port_params = [scan_id]
        ports = _select(cursor, """
            SELECT p.id AS port_id, p.host_id, p.port, p.protocol, p.service, p.product,
                   p.version, p.state, p.last_scan_id, p.fingerprint
            FROM ports AS p JOIN hosts AS h ON h.id = p.host_id WHERE
        """ + port_condition + " ORDER BY p.host_id, p.port, p.protocol, p.id", port_params)
        findings = _related(cursor, """
            SELECT v.id AS vuln_id, v.port_id, v.cve_id, v.title, v.source, v.status, v.severity,
                   v.first_detected_at, v.last_detected_at, v.verified_at, v.closed_at
            FROM vulns AS v WHERE v.port_id IN
        """, [row["port_id"] for row in ports], "AND v.source LIKE 'day4:%' ORDER BY v.id")
        return cursor_rows(cursor, assets, scans, ports, findings)


def cursor_rows(cursor, assets, scans, ports, findings):
    try:
        reviewed = {rule["id"]: rule["cve"] for rule in load_catalog()[0]["rules"]}
    except (OSError, ValueError, KeyError) as exc:
        raise ReportDataError("Reviewed Day 4 catalog could not be read") from exc
    findings = [row for row in findings if reviewed.get(row["source"]) == row["cve_id"]]
    ids = [row["vuln_id"] for row in findings]
    assessments = _related(cursor, """
        SELECT r.id AS assessment_id, r.vuln_id, r.methodology_id, r.methodology_sha256,
               r.vuln_status, r.action, r.priority, r.cvss_score, r.cvss_version, r.cvss_vector,
               r.cvss_source, r.epss_score, r.epss_percentile, r.epss_date, r.kev_status,
               r.kev_date_added, r.asset_criticality, r.internet_exposed, r.handles_personal_data,
               r.details, r.input_sha256, r.first_assessed_at, r.last_assessed_at, r.observations
        FROM vuln_risk_assessments AS r WHERE r.vuln_id IN
    """, ids, """AND NOT EXISTS (
        SELECT 1 FROM vuln_risk_assessments AS newer WHERE newer.vuln_id = r.vuln_id
        AND (newer.last_assessed_at > r.last_assessed_at
             OR (newer.last_assessed_at = r.last_assessed_at AND newer.id > r.id))
    ) ORDER BY r.vuln_id""")
    evidence = _related(cursor, """
        SELECT e.id AS evidence_id, e.vuln_id, e.checker, e.evidence_type, e.sha256, e.collected_at, e.details
        FROM vuln_evidence AS e WHERE e.vuln_id IN
    """, ids, "ORDER BY e.collected_at, e.id")
    history = _related(cursor, """
        SELECT rh.id AS history_id, rh.vuln_id, rh.from_status, rh.to_status,
               rh.action_type, rh.reason, rh.changed_by, rh.changed_at
        FROM remediation_history AS rh WHERE rh.vuln_id IN
    """, ids, "ORDER BY rh.changed_at, rh.id")
    return assets, scans, ports, findings, assessments, evidence, history


def parse_evidence(row):
    result = _pick(row, ("evidence_id", "checker", "evidence_type", "sha256", "collected_at"))
    document, state = _object(row.get("details"))
    result["details_status"] = state
    if state != "PARSED":
        result["parse_error"] = "Invalid or legacy JSON details" if state == "PARSE_ERROR" else None
        result["details"] = {}
        return result
    content = document.get("content", document)
    if not isinstance(content, dict):
        result.update(details_status="PARSE_ERROR", parse_error="Invalid evidence content", details={})
        return result
    parsed = _pick(content, ("result", "reason", "error_code", "additional_checks"))
    if row.get("checker") == "day4_mapper":
        parsed.update(result=content.get("status"), reason=content.get("match_reason"),
                      additional_checks=content.get("conditions_to_verify"),
                      references=content.get("references"), affected=content.get("affected"),
                      catalog_sha256=content.get("catalog_sha256"))
    parsed.update(_pick(document, ("first_checked_at", "last_checked_at", "observations")))
    checks = content.get("details")
    if isinstance(checks, dict):
        parsed["safe_checks"] = checks.get("safe_checks")
        parsed["condition"] = checks.get("condition")
    result["details"] = parsed
    return result


def _assessment(row, finding, asset, endpoint):
    if row is None:
        return None, "MISSING", ["assessment_missing"]
    assessment = _pick(row, ASSESSMENT_FIELDS)
    document, state = _object(row.get("details"))
    assessment["details_status"] = state
    assessment["details"] = _pick(document, ("matched_rules", "missing_inputs", "reason", "source_errors", "incomplete"))
    # Only normalized provider fields are retained; never render arbitrary response bodies.
    provenance = {}
    for provider, fields in {
        "cvss": ("state", "score", "version", "vector", "severity", "source", "metric_type", "endpoint", "error_code"),
        "epss": ("state", "score", "percentile", "date", "source", "error_code"),
        "kev": ("state", "status", "source", "catalog_version", "date_released", "date_added", "due_date",
                "known_ransomware_campaign_use", "required_action", "vendor_project", "product", "error_code", "errors"),
    }.items():
        value = document.get(provider)
        provenance[provider] = _pick(value, fields) if isinstance(value, dict) else None
    assessment["provenance"] = provenance
    for key in ("internet_exposed", "handles_personal_data"):
        assessment[key] = _boolean(assessment[key])
    reasons = []
    for field, current in (("vuln_status", finding["status"]), ("asset_criticality", asset["criticality"]),
                           ("internet_exposed", asset["internet_exposed"]),
                           ("handles_personal_data", asset["handles_personal_data"])):
        if assessment[field] is None or current is None or assessment[field] != current:
            reasons.append(field + "_mismatch_or_missing")
    for key in ("cve_id", "source"):
        if key in document and document[key] != finding[key]:
            reasons.append(key + "_mismatch")
    old_asset = document.get("asset_context")
    if isinstance(old_asset, dict):
        for key in ("asset_uid", "host_ip", "asset_name", "asset_type", "environment", "owner", "business_unit",
                    "data_classification", "lifecycle_status"):
            if key in old_asset and old_asset[key] != asset.get(key):
                reasons.append("asset." + key + "_mismatch")
    old_endpoint = document.get("endpoint")
    if isinstance(old_endpoint, dict):
        for key in ("port_id", "port", "protocol", "scan_id"):
            current = endpoint.get("last_scan_id") if key == "scan_id" else endpoint.get(key)
            if key in old_endpoint and old_endpoint[key] != current:
                reasons.append("endpoint." + key + "_mismatch")
    if assessment["priority"] not in PRIORITIES:
        reasons.append("invalid_stored_priority")
    return assessment, "STALE" if reasons else "CURRENT", reasons


def snapshot_sha256(snapshot):
    content = {key: value for key, value in snapshot.items() if key != "generated_at"}
    content["integrity"] = {key: value for key, value in snapshot.get("integrity", {}).items() if key != "snapshot_sha256"}
    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _assemble(selection, rows):
    assets, scans, ports, findings, assessments, evidence, history = rows
    by_asset = {}
    for row in sorted(assets, key=lambda row: row["id"]):
        item = _pick(row, ASSET_FIELDS)
        for key in ("internet_exposed", "handles_personal_data"):
            item[key] = _boolean(row.get(key))
        by_asset[row["id"]] = {**item, "ports": [], "findings": []}
    by_port = {}
    for row in sorted(ports, key=lambda row: (row["host_id"], row["port"], row["protocol"], row["port_id"])):
        item = _pick(row, PORT_FIELDS)
        fp, fp_state = _object(row.get("fingerprint"))
        item.update(fingerprint=_pick(fp, FINGERPRINT_FIELDS), fingerprint_status=fp_state)
        by_port[item["port_id"]] = item
        by_asset[item["host_id"]]["ports"].append(item)
    latest = {row["vuln_id"]: row for row in assessments}
    evidence_by, history_by = {}, {}
    for row in sorted(evidence, key=lambda row: (str(json_value(row.get("collected_at")) or ""), row["evidence_id"])):
        evidence_by.setdefault(row["vuln_id"], []).append(parse_evidence(row))
    for row in sorted(history, key=lambda row: (str(json_value(row.get("changed_at")) or ""), row["history_id"])):
        history_by.setdefault(row["vuln_id"], []).append(_pick(row, ("history_id", "from_status", "to_status",
                                                        "action_type", "reason", "changed_by", "changed_at")))
    summary = {"asset_count": len(by_asset), "open_port_count": sum(p["state"] == "open" for p in ports),
               "finding_count": len(findings), "status_counts": {status.value: 0 for status in VulnStatus},
               "priority_counts": dict.fromkeys(PRIORITIES, 0), "assessment_freshness_counts": dict.fromkeys(FRESHNESS, 0),
               "highest_priority": "UNASSESSED", "coverage_note": COVERAGE_NOTE, "freshness_note": FRESHNESS_NOTE}
    for row in findings:
        item = _pick(row, FINDING_FIELDS)
        port = by_port[item["port_id"]]
        asset = by_asset[port["host_id"]]
        endpoint = {**_pick(port, PORT_FIELDS), "host_ip": asset["host_ip"], "asset_uid": asset["asset_uid"]}
        assessment, freshness, reasons = _assessment(latest.get(item["vuln_id"]), item, asset, endpoint)
        priority = assessment["priority"] if freshness == "CURRENT" else "UNASSESSED"
        item.update(endpoint=endpoint, assessment=assessment, assessment_freshness=freshness,
                    freshness_reasons=reasons, effective_priority=priority,
                    effective_action=assessment["action"] if freshness == "CURRENT" else None,
                    evidence=evidence_by.get(item["vuln_id"], []), history=history_by.get(item["vuln_id"], []))
        asset["findings"].append(item)
        summary["status_counts"][item["status"]] = summary["status_counts"].get(item["status"], 0) + 1
        summary["priority_counts"][priority] += 1
        summary["assessment_freshness_counts"][freshness] += 1
    summary["highest_priority"] = next((level for level in PRIORITIES if summary["priority_counts"][level]), "UNASSESSED")
    for asset in by_asset.values():
        asset["findings"].sort(key=lambda finding: (PRIORITIES.index(finding["effective_priority"]), finding["vuln_id"]))
    scan_documents = []
    for row in sorted(scans, key=lambda row: row["scan_id"]):
        item = _pick(row, ("scan_id", "scan_uid", "status", "scan_type", "target", "port_range", "started_at", "finished_at"))
        targets = row.get("requested_targets")
        try:
            targets = json.loads(targets) if isinstance(targets, (str, bytes)) else targets
            if targets is not None and not isinstance(targets, list):
                raise ValueError("Invalid requested targets")
            item["requested_targets"] = json_value(targets)
            item["requested_targets_status"] = "PARSED" if targets is not None else "MISSING"
        except (ValueError, TypeError):
            item.update(requested_targets=None, requested_targets_status="PARSE_ERROR")
        item["scope"] = _pick(row, ("scope_uid", "authorization_ref", "approved_by", "valid_from", "valid_until", "policy_sha256"))
        scan_documents.append(item)
    snapshot = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "selection": selection, "summary": summary, "scans": scan_documents, "assets": list(by_asset.values()),
                "integrity": {"algorithm": "SHA-256", "digest_excludes": ["generated_at", "integrity.snapshot_sha256"]}}
    snapshot["integrity"]["snapshot_sha256"] = snapshot_sha256(snapshot)
    return snapshot


def build_report_snapshot(*, asset_uid=None, scan_id=None):
    selection = validate_selection(asset_uid=asset_uid, scan_id=scan_id)
    conn = None
    try:
        conn = get_connection()
        # Fail closed if the connector/server cannot establish these semantics.
        conn.start_transaction(isolation_level="REPEATABLE READ", consistent_snapshot=True, readonly=True)
        rows = _read_rows(conn, selection)
    except (ReportSelectionError, ReportDataError):
        raise
    except Exception as exc:
        raise ReportDatabaseError("Read-only report query failed (" + type(exc).__name__ + ")") from exc
    finally:
        if conn is not None:
            try:
                conn.rollback()  # End read-only transaction. Never commit in a report.
            finally:
                conn.close()
    return _assemble(selection, rows)


def generate_report(*, asset_uid=None, scan_id=None, output_dir="reports", format="both"):
    if format not in {"json", "pdf", "both"}:
        raise ReportSelectionError("format must be json, pdf or both")
    snapshot = build_report_snapshot(asset_uid=asset_uid, scan_id=scan_id)
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    selection = snapshot["selection"]
    identifier = selection.get("asset_uid", selection.get("scan_id"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    stem = f"report_{selection['type']}_{identifier}_{stamp}"
    output = {"selection": selection, "snapshot_sha256": snapshot["integrity"]["snapshot_sha256"],
              "json_path": None, "pdf_path": None}
    # Finish both formats before publishing either. Temporary partial files are cleaned up on failure.
    with TemporaryDirectory(prefix=".report-", dir=directory) as temporary:
        created = []
        if format in {"json", "both"}:
            temp = Path(temporary) / (stem + ".json")
            temp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
            created.append(("json_path", temp, directory / temp.name))
        if format in {"pdf", "both"}:
            from api.report_pdf import render_report_pdf
            temp = Path(temporary) / (stem + ".pdf")
            render_report_pdf(snapshot, temp)
            created.append(("pdf_path", temp, directory / temp.name))
        for key, temp, destination in created:
            os.replace(temp, destination)
            output[key] = str(destination)
    return output
