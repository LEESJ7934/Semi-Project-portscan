USE port_scan;

-- Prerequisite: V3/V3.1. Back up port_scan outside the project before running.
-- DDL commits implicitly in MySQL. Each column check allows a safe rerun after interruption.
-- Existing ports, vulnerabilities, asset metadata and review statuses are preserved.
DELIMITER $$
DROP PROCEDURE IF EXISTS portscan_migrate_v4$$
CREATE PROCEDURE portscan_migrate_v4()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'hosts' AND column_name = 'asset_uid'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'vuln_evidence'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'V3 schema is required before V4';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'ports' AND column_name = 'product'
    ) THEN
        ALTER TABLE ports ADD COLUMN product VARCHAR(100) NULL AFTER service;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'ports' AND column_name = 'fingerprint'
    ) THEN
        ALTER TABLE ports ADD COLUMN fingerprint JSON NULL AFTER banner;
    END IF;
END$$
CALL portscan_migrate_v4()$$
DROP PROCEDURE portscan_migrate_v4$$
DELIMITER ;

SHOW COLUMNS FROM ports LIKE 'product';
SHOW COLUMNS FROM ports LIKE 'fingerprint';
SELECT
    (SELECT COUNT(*) FROM scans) AS scan_count,
    (SELECT COUNT(*) FROM hosts) AS asset_count,
    (SELECT COUNT(*) FROM ports) AS port_count,
    (SELECT COUNT(*) FROM vulns) AS vuln_count,
    (SELECT COUNT(*) FROM asset_change_history) AS asset_change_count;
