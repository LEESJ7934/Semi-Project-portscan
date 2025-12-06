# analysis/vuln_mapper.py
import json
import re
from typing import List, Dict, Any

def load_rules(rule_path="analysis/vuln_rules.json"):
    with open(rule_path, "r", encoding="utf-8") as f:
        return json.load(f)

def match_rule(port_record: Dict[str, Any], rule: Dict[str, Any]):
    """
    단일 port_record가 rule에 매칭되면 True 반환
    """
    service = port_record.get("service", "")
    version = port_record.get("version", "")

    # 서비스 타입 불일치 시 제외
    if rule.get("service") != service:
        return False

    # version regex 체크
    ver_rgx = rule.get("version_regex")
    if ver_rgx:
        if not re.search(ver_rgx, str(version), re.IGNORECASE):
            return False

    return True

def map_vulns(port_records, rule_path="analysis/vuln_rules.json"):
    rules = load_rules(rule_path)
    results = []

    for p in port_records:
        for r in rules:
            if match_rule(p, r):
                results.append({
                    "port_id": p["id"],
                    "cve_id": r.get("cve", "NONE"),
                    "title": r.get("title", "Unknown Vulnerability"),
                    "severity": r.get("severity", "LOW"),
                    "status": r.get("status", "POTENTIAL"),       # 기본값 자동
                    "source": r.get("id", "rule_unknown"),        # ★ id를 source로 사용
                    "rule_id": r.get("id"),
                })
    return results
