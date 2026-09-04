CREATE DATABASE IF NOT EXISTS port_scan
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE port_scan;

CREATE TABLE IF NOT EXISTS scans (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_uid VARCHAR(64) NOT NULL,
    target VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    port_range VARCHAR(100) NOT NULL,
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    status ENUM(
        'QUEUED',
        'RUNNING',
        'COMPLETED',
        'PARTIAL',
        'FAILED'
    ) NOT NULL DEFAULT 'QUEUED',
    config_snapshot JSON NULL,
    created_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_scans_uid (scan_uid),
    INDEX idx_scans_status (status),
    INDEX idx_scans_started_at (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS hosts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_ip VARCHAR(45) NOT NULL,
    host_name VARCHAR(255) NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    last_scan_id BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_hosts_ip (host_ip),
    INDEX idx_hosts_last_seen (last_seen),
    INDEX idx_hosts_last_scan (last_scan_id),

    CONSTRAINT fk_hosts_last_scan
        FOREIGN KEY (last_scan_id)
        REFERENCES scans(id)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    port INT UNSIGNED NOT NULL,
    protocol ENUM('tcp', 'udp') NOT NULL,
    service VARCHAR(100) NULL,
    version VARCHAR(255) NULL,
    banner TEXT NULL,
    state ENUM(
        'open',
        'closed',
        'filtered'
    ) NOT NULL DEFAULT 'closed',
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    last_scan_id BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_ports_host_port_proto (
        host_id,
        port,
        protocol
    ),
    INDEX idx_ports_host (host_id),
    INDEX idx_ports_service (service),
    INDEX idx_ports_last_seen (last_seen),
    INDEX idx_ports_last_scan (last_scan_id),

    CONSTRAINT fk_ports_host
        FOREIGN KEY (host_id)
        REFERENCES hosts(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ports_last_scan
        FOREIGN KEY (last_scan_id)
        REFERENCES scans(id)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vulns (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    port_id BIGINT UNSIGNED NOT NULL,
    cve_id VARCHAR(50) NOT NULL
        DEFAULT 'NONE',
    title VARCHAR(255) NOT NULL,
    severity ENUM(
        'INFO',
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL'
    ) NOT NULL DEFAULT 'INFO',
    epss DECIMAL(6,5) NULL,
    cvss DECIMAL(4,2) NULL,
    risk DECIMAL(6,5) NULL,
    status ENUM(
        'CANDIDATE',
        'POTENTIAL',
        'CONFIRMED',
        'NOT_APPLICABLE',
        'FALSE_POSITIVE',
        'RETEST_REQUIRED',
        'CLOSED',
        'ERROR'
    ) NOT NULL DEFAULT 'CANDIDATE',
    source VARCHAR(100) NOT NULL
        DEFAULT 'unknown',
    first_detected_at DATETIME NOT NULL,
    last_detected_at DATETIME NOT NULL,
    verified_at DATETIME NULL,
    closed_at DATETIME NULL,
    created_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_vulns_port_cve_source (
        port_id,
        cve_id,
        source
    ),
    INDEX idx_vulns_port (port_id),
    INDEX idx_vulns_cve (cve_id),
    INDEX idx_vulns_severity (severity),
    INDEX idx_vulns_status (status),
    INDEX idx_vulns_last_detected (
        last_detected_at
    ),

    CONSTRAINT fk_vulns_port
        FOREIGN KEY (port_id)
        REFERENCES ports(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vuln_evidence (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    vuln_id BIGINT UNSIGNED NOT NULL,
    checker VARCHAR(100) NOT NULL,
    evidence_type ENUM(
        'HTTP_RESPONSE',
        'SCREENSHOT',
        'NUCLEI',
        'BANNER',
        'MANUAL',
        'ERROR_LOG'
    ) NOT NULL,
    details TEXT NULL,
    evidence_path VARCHAR(500) NULL,
    sha256 CHAR(64) NULL,
    collected_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_evidence_vuln (vuln_id),
    INDEX idx_evidence_collected_at (
        collected_at
    ),

    CONSTRAINT fk_evidence_vuln
        FOREIGN KEY (vuln_id)
        REFERENCES vulns(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS remediation_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    vuln_id BIGINT UNSIGNED NOT NULL,
    from_status ENUM(
        'CANDIDATE',
        'POTENTIAL',
        'CONFIRMED',
        'NOT_APPLICABLE',
        'FALSE_POSITIVE',
        'RETEST_REQUIRED',
        'CLOSED',
        'ERROR'
    ) NULL,
    to_status ENUM(
        'CANDIDATE',
        'POTENTIAL',
        'CONFIRMED',
        'NOT_APPLICABLE',
        'FALSE_POSITIVE',
        'RETEST_REQUIRED',
        'CLOSED',
        'ERROR'
    ) NOT NULL,
    action_type ENUM(
        'STATUS_CHANGE',
        'RETEST_REQUEST',
        'REMEDIATION',
        'CLOSURE',
        'REOPEN'
    ) NOT NULL DEFAULT 'STATUS_CHANGE',
    reason VARCHAR(500) NULL,
    changed_by VARCHAR(100) NOT NULL
        DEFAULT 'system',
    changed_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_remediation_vuln (vuln_id),
    INDEX idx_remediation_changed_at (
        changed_at
    ),

    CONSTRAINT fk_remediation_vuln
        FOREIGN KEY (vuln_id)
        REFERENCES vulns(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;