USE port_scan;
SHOW COLUMNS FROM ports LIKE 'product';
SHOW COLUMNS FROM ports LIKE 'fingerprint';
SELECT
    (SELECT COUNT(*) FROM scans) AS scan_count,
    (SELECT COUNT(*) FROM hosts) AS asset_count,
    (SELECT COUNT(*) FROM ports) AS port_count,
    (SELECT COUNT(*) FROM vulns) AS vuln_count,
    (SELECT COUNT(*) FROM asset_change_history) AS asset_change_count;
SELECT h.host_ip, p.port, p.protocol, p.service, p.product, p.version,
       p.last_scan_id, p.fingerprint->>'$.source' AS identification_source
FROM ports p JOIN hosts h ON h.id = p.host_id
WHERE p.product IS NOT NULL ORDER BY h.id, p.port;
SELECT v.id, v.cve_id, v.status, v.source, v.cvss, v.epss, v.risk,
       COUNT(e.id) AS matching_evidence_count
FROM vulns v LEFT JOIN vuln_evidence e
    ON e.vuln_id = v.id AND e.checker = 'day4_mapper'
WHERE v.source LIKE 'day4:%'
GROUP BY v.id ORDER BY v.id;
-- Expected: no rows. Re-saving the same candidate must not create duplicate rows/evidence.
SELECT port_id, cve_id, source, COUNT(*) AS duplicate_count
FROM vulns GROUP BY port_id, cve_id, source HAVING COUNT(*) > 1;
SELECT vuln_id, sha256, COUNT(*) AS duplicate_evidence_count
FROM vuln_evidence WHERE checker = 'day4_mapper'
GROUP BY vuln_id, sha256 HAVING COUNT(*) > 1;
-- Preserved legacy findings need review. Their old rules are no longer executed.
SELECT id, cve_id, source, status, 'REVIEW_RETIRED_RULE' AS review_note
FROM vulns WHERE source IN (
    'rule_ftp_vsftpd_3_0_5', 'rule_ssh_openssh_8_9', 'rule_telnet_default',
    'rule_dvwa_sqli', 'rule_dvwa_fileupload'
) ORDER BY id;
