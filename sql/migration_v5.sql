USE port_scan;

-- V4 prerequisite. Back up the DB outside the repository first.
-- MySQL DDL commits implicitly: this is not an atomic/reversible transaction.
-- Reruns allow an interrupted ALTER/CREATE to finish. No finding/review data is rewritten.
DELIMITER $$
DROP PROCEDURE IF EXISTS portscan_migrate_v5$$
CREATE PROCEDURE portscan_migrate_v5()
BEGIN
    DECLARE before_scans BIGINT UNSIGNED;
    DECLARE before_hosts BIGINT UNSIGNED;
    DECLARE before_ports BIGINT UNSIGNED;
    DECLARE before_vulns BIGINT UNSIGNED;
    DECLARE before_evidence BIGINT UNSIGNED;
    DECLARE before_history BIGINT UNSIGNED;
    DECLARE before_asset_history BIGINT UNSIGNED;

    IF (SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'
          AND engine = 'InnoDB'
          AND table_name IN ('scans', 'hosts', 'ports', 'vulns', 'vuln_evidence',
                             'remediation_history', 'asset_change_history', 'scan_assets')) <> 8
       OR (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE()
           AND ((table_name = 'ports' AND column_name IN ('product', 'fingerprint', 'last_scan_id'))
                OR (table_name = 'hosts' AND column_name IN
                    ('asset_uid', 'criticality', 'internet_exposed', 'handles_personal_data'))
                OR (table_name = 'vulns' AND column_name IN
                    ('epss', 'cvss', 'status', 'source', 'verified_at', 'closed_at')))) <> 13
    THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'V4 InnoDB schema is required before V5';
    END IF;
    IF EXISTS (SELECT 1 FROM vulns WHERE epss < 0 OR epss > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Existing EPSS values are outside 0..1; review before V5';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'vulns' AND column_name = 'epss'
          AND data_type = 'decimal' AND is_nullable = 'YES'
          AND ((numeric_precision = 6 AND numeric_scale = 5)
               OR (numeric_precision = 10 AND numeric_scale = 9))
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Unexpected EPSS definition; expected V4 or V5 decimal';
    END IF;

    SELECT COUNT(*) INTO before_scans FROM scans;
    SELECT COUNT(*) INTO before_hosts FROM hosts;
    SELECT COUNT(*) INTO before_ports FROM ports;
    SELECT COUNT(*) INTO before_vulns FROM vulns;
    SELECT COUNT(*) INTO before_evidence FROM vuln_evidence;
    SELECT COUNT(*) INTO before_history FROM remediation_history;
    SELECT COUNT(*) INTO before_asset_history FROM asset_change_history;
    SELECT 'BEFORE_V5' AS phase, before_scans AS scan_count, before_hosts AS asset_count,
           before_ports AS port_count, before_vulns AS vuln_count, before_evidence AS evidence_count,
           before_history AS remediation_history_count, before_asset_history AS asset_change_count;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'vulns' AND column_name = 'epss'
          AND numeric_precision = 10 AND numeric_scale = 9
    ) THEN
        ALTER TABLE vulns MODIFY COLUMN epss DECIMAL(10,9) NULL;
    END IF;

    CREATE TABLE IF NOT EXISTS vuln_risk_assessments (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        vuln_id BIGINT UNSIGNED NOT NULL,
        methodology_id VARCHAR(64) NOT NULL,
        methodology_sha256 CHAR(64) NOT NULL,
        vuln_status ENUM(
            'CANDIDATE', 'POTENTIAL', 'CONFIRMED', 'NOT_APPLICABLE',
            'FALSE_POSITIVE', 'RETEST_REQUIRED', 'CLOSED', 'ERROR'
        ) NOT NULL,
        action ENUM('VERIFY', 'REMEDIATE', 'RETEST') NOT NULL,
        priority ENUM('P1', 'P2', 'P3', 'P4', 'UNASSESSED') NOT NULL,
        cvss_score DECIMAL(4,2) NULL,
        cvss_version VARCHAR(16) NULL,
        cvss_vector VARCHAR(255) NULL,
        cvss_source VARCHAR(255) NULL,
        epss_score DECIMAL(10,9) NULL,
        epss_percentile DECIMAL(10,9) NULL,
        epss_date DATE NULL,
        kev_status ENUM('KNOWN_EXPLOITED', 'NOT_LISTED', 'UNKNOWN') NOT NULL,
        kev_date_added DATE NULL,
        asset_criticality ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNASSIGNED') NOT NULL,
        internet_exposed BOOLEAN NOT NULL,
        handles_personal_data BOOLEAN NOT NULL,
        details JSON NOT NULL,
        input_sha256 CHAR(64) NOT NULL,
        first_assessed_at DATETIME NOT NULL,
        last_assessed_at DATETIME NOT NULL,
        observations INT UNSIGNED NOT NULL DEFAULT 1,

        PRIMARY KEY (id),
        UNIQUE KEY uq_risk_vuln_method_input (vuln_id, methodology_id, input_sha256),
        INDEX idx_risk_priority (priority),
        INDEX idx_risk_last_assessed (last_assessed_at),
        CONSTRAINT fk_risk_vuln FOREIGN KEY (vuln_id) REFERENCES vulns(id) ON DELETE CASCADE,
        CONSTRAINT chk_risk_cvss CHECK (cvss_score BETWEEN 0 AND 10),
        CONSTRAINT chk_risk_epss CHECK (epss_score BETWEEN 0 AND 1),
        CONSTRAINT chk_risk_percentile CHECK (epss_percentile BETWEEN 0 AND 1),
        CONSTRAINT chk_risk_flags CHECK (internet_exposed IN (0, 1) AND handles_personal_data IN (0, 1)),
        CONSTRAINT chk_risk_observations CHECK (observations >= 1),
        CONSTRAINT chk_risk_times CHECK (last_assessed_at >= first_assessed_at),
        CONSTRAINT chk_risk_action CHECK (
            (vuln_status IN ('CANDIDATE', 'POTENTIAL', 'ERROR') AND action = 'VERIFY') OR
            (vuln_status = 'CONFIRMED' AND action = 'REMEDIATE') OR
            (vuln_status = 'RETEST_REQUIRED' AND action = 'RETEST')
        )
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    SELECT 'AFTER_V5' AS phase,
        (SELECT COUNT(*) FROM scans) AS scan_count,
        (SELECT COUNT(*) FROM hosts) AS asset_count,
        (SELECT COUNT(*) FROM ports) AS port_count,
        (SELECT COUNT(*) FROM vulns) AS vuln_count,
        (SELECT COUNT(*) FROM vuln_evidence) AS evidence_count,
        (SELECT COUNT(*) FROM remediation_history) AS remediation_history_count,
        (SELECT COUNT(*) FROM asset_change_history) AS asset_change_count,
        (SELECT COUNT(*) FROM vuln_risk_assessments) AS risk_assessment_count;
    SELECT (before_scans = (SELECT COUNT(*) FROM scans)
        AND before_hosts = (SELECT COUNT(*) FROM hosts)
        AND before_ports = (SELECT COUNT(*) FROM ports)
        AND before_vulns = (SELECT COUNT(*) FROM vulns)
        AND before_evidence = (SELECT COUNT(*) FROM vuln_evidence)
        AND before_history = (SELECT COUNT(*) FROM remediation_history)
        AND before_asset_history = (SELECT COUNT(*) FROM asset_change_history)) AS existing_counts_preserved;
END$$
CALL portscan_migrate_v5()$$
DROP PROCEDURE portscan_migrate_v5$$
DELIMITER ;
