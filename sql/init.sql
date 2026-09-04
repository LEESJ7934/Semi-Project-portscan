CREATE DATABASE IF NOT EXISTS port_scan
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE port_scan;

CREATE TABLE IF NOT EXISTS scan_scopes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scope_uid VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    authorization_ref VARCHAR(255) NOT NULL,
    approved_by VARCHAR(255) NOT NULL,
    valid_from DATETIME NOT NULL,
    valid_until DATETIME NOT NULL,
    allowed_targets JSON NOT NULL,
    max_targets INT UNSIGNED NOT NULL,
    max_workers INT UNSIGNED NOT NULL,
    max_ports_per_target INT UNSIGNED NOT NULL,
    policy_sha256 CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_scopes_uid (scope_uid),
    INDEX idx_scan_scopes_valid_until (valid_until),
    CONSTRAINT chk_scan_scopes_validity
        CHECK (valid_until > valid_from),
    CONSTRAINT chk_scan_scopes_max_targets
        CHECK (max_targets BETWEEN 1 AND 4096),
    CONSTRAINT chk_scan_scopes_max_workers
        CHECK (max_workers BETWEEN 1 AND 512),
    CONSTRAINT chk_scan_scopes_max_ports
        CHECK (max_ports_per_target BETWEEN 1 AND 65535)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scans (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_uid VARCHAR(64) NOT NULL,
    scope_id BIGINT UNSIGNED NULL,
    target MEDIUMTEXT NOT NULL,
    requested_targets JSON NULL,
    scan_type VARCHAR(50) NOT NULL,
    port_range MEDIUMTEXT NOT NULL,
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
    INDEX idx_scans_scope (scope_id),
    INDEX idx_scans_status (status),
    INDEX idx_scans_started_at (started_at),

    CONSTRAINT fk_scans_scope
        FOREIGN KEY (scope_id)
        REFERENCES scan_scopes(id)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS hosts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_uid CHAR(36) NOT NULL,
    host_ip VARCHAR(45) NOT NULL,
    host_name VARCHAR(255) NULL,
    asset_name VARCHAR(255) NULL,
    asset_type ENUM(
        'SERVER',
        'WORKSTATION',
        'NETWORK_DEVICE',
        'CLOUD_RESOURCE',
        'CONTAINER',
        'UNKNOWN'
    ) NOT NULL DEFAULT 'UNKNOWN',
    environment ENUM(
        'PRODUCTION',
        'STAGING',
        'DEVELOPMENT',
        'TEST',
        'UNKNOWN'
    ) NOT NULL DEFAULT 'UNKNOWN',
    criticality ENUM(
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL',
        'UNASSIGNED'
    ) NOT NULL DEFAULT 'UNASSIGNED',
    owner VARCHAR(255) NULL,
    business_unit VARCHAR(255) NULL,
    data_classification ENUM(
        'PUBLIC',
        'INTERNAL',
        'CONFIDENTIAL',
        'RESTRICTED',
        'UNKNOWN'
    ) NOT NULL DEFAULT 'UNKNOWN',
    handles_personal_data BOOLEAN NOT NULL
        DEFAULT FALSE,
    internet_exposed BOOLEAN NOT NULL
        DEFAULT FALSE,
    lifecycle_status ENUM(
        'ACTIVE',
        'INACTIVE',
        'RETIRED'
    ) NOT NULL DEFAULT 'ACTIVE',
    source ENUM(
        'DISCOVERED',
        'MANUAL',
        'IMPORTED'
    ) NOT NULL DEFAULT 'DISCOVERED',
    notes TEXT NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    last_scan_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_hosts_asset_uid (asset_uid),
    UNIQUE KEY uq_hosts_ip (host_ip),
    INDEX idx_hosts_lifecycle (lifecycle_status),
    INDEX idx_hosts_criticality (criticality),
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
        'filtered',
        'open_or_filtered'
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

CREATE TABLE IF NOT EXISTS scan_assets (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id BIGINT UNSIGNED NOT NULL,
    host_id BIGINT UNSIGNED NOT NULL,
    input_target VARCHAR(255) NOT NULL,
    resolution_type ENUM(
        'IP',
        'CIDR',
        'HOSTNAME'
    ) NOT NULL,
    result_status ENUM(
        'SCANNED',
        'ERROR'
    ) NOT NULL,
    open_port_count INT UNSIGNED NOT NULL
        DEFAULT 0,
    error_code VARCHAR(100) NULL,
    observed_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_assets_scan_host (
        scan_id,
        host_id
    ),
    INDEX idx_scan_assets_host (host_id),
    INDEX idx_scan_assets_result (result_status),

    CONSTRAINT fk_scan_assets_scan
        FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_scan_assets_host
        FOREIGN KEY (host_id)
        REFERENCES hosts(id)
        ON DELETE CASCADE,

    CONSTRAINT chk_scan_assets_open_ports
        CHECK (open_port_count >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS asset_change_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    field_name VARCHAR(64) NOT NULL,
    old_value TEXT NULL,
    new_value TEXT NULL,
    reason VARCHAR(500) NOT NULL,
    changed_by VARCHAR(100) NOT NULL,
    changed_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_asset_history_host (host_id),
    INDEX idx_asset_history_changed_at (changed_at),

    CONSTRAINT fk_asset_history_host
        FOREIGN KEY (host_id)
        REFERENCES hosts(id)
        ON DELETE CASCADE
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
