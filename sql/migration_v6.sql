USE port_scan;

-- V6: AWS cloud asset context and configuration findings.
-- Prerequisite: V5 schema. Back up the database before applying.
DELIMITER $$
DROP PROCEDURE IF EXISTS portscan_migrate_v6$$
CREATE PROCEDURE portscan_migrate_v6()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'vuln_risk_assessments'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'V5 schema is required before V6';
    END IF;

    CREATE TABLE IF NOT EXISTS cloud_resources (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        host_id BIGINT UNSIGNED NOT NULL,
        provider VARCHAR(32) NOT NULL,
        account_id VARCHAR(32) NOT NULL,
        region VARCHAR(64) NOT NULL,
        resource_type VARCHAR(64) NOT NULL,
        resource_id VARCHAR(128) NOT NULL,
        vpc_id VARCHAR(64) NOT NULL,
        subnet_id VARCHAR(64) NULL,
        private_ip VARCHAR(45) NOT NULL,
        public_ip VARCHAR(45) NULL,
        instance_state VARCHAR(32) NULL,
        security_groups JSON NOT NULL,
        tags JSON NOT NULL,
        first_discovered_at DATETIME NOT NULL,
        last_discovered_at DATETIME NOT NULL,

        PRIMARY KEY (id),
        UNIQUE KEY uq_cloud_host (host_id),
        UNIQUE KEY uq_cloud_identity (provider, account_id, region, resource_id),
        INDEX idx_cloud_vpc (vpc_id),
        INDEX idx_cloud_private_ip (private_ip),
        INDEX idx_cloud_last_discovered (last_discovered_at),
        CONSTRAINT fk_cloud_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
        CONSTRAINT chk_cloud_provider CHECK (provider = 'AWS'),
        CONSTRAINT chk_cloud_resource_type CHECK (resource_type = 'EC2'),
        CONSTRAINT chk_cloud_times CHECK (last_discovered_at >= first_discovered_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS cloud_configuration_findings (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        cloud_resource_id BIGINT UNSIGNED NOT NULL,
        rule_id VARCHAR(64) NOT NULL,
        category VARCHAR(64) NOT NULL,
        title VARCHAR(255) NOT NULL,
        severity ENUM('INFO','LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
        priority ENUM('P1','P2','P3','P4','UNASSESSED') NOT NULL,
        status ENUM('OPEN','RESOLVED') NOT NULL DEFAULT 'OPEN',
        public_address_present BOOLEAN NOT NULL,
        evidence JSON NOT NULL,
        remediation VARCHAR(1000) NOT NULL,
        input_sha256 CHAR(64) NOT NULL,
        first_detected_at DATETIME NOT NULL,
        last_detected_at DATETIME NOT NULL,
        resolved_at DATETIME NULL,
        observations INT UNSIGNED NOT NULL DEFAULT 1,

        PRIMARY KEY (id),
        UNIQUE KEY uq_cloud_finding_rule (cloud_resource_id, rule_id),
        INDEX idx_cloud_finding_status (status),
        INDEX idx_cloud_finding_priority (priority),
        INDEX idx_cloud_finding_last_detected (last_detected_at),
        CONSTRAINT fk_cloud_finding_resource FOREIGN KEY (cloud_resource_id)
            REFERENCES cloud_resources(id) ON DELETE CASCADE,
        CONSTRAINT chk_cloud_finding_public CHECK (public_address_present IN (0,1)),
        CONSTRAINT chk_cloud_finding_observations CHECK (observations >= 1),
        CONSTRAINT chk_cloud_finding_times CHECK (last_detected_at >= first_detected_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
END$$
CALL portscan_migrate_v6()$$
DROP PROCEDURE portscan_migrate_v6$$
DELIMITER ;
