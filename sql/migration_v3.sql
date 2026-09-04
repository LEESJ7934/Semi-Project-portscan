USE port_scan;

-- V2 DB에서 한 번만 실행합니다.
-- 변경 전 핵심 테이블을 별도 이름으로 보존합니다.

CREATE TABLE IF NOT EXISTS migration_backup_scans_v2
AS SELECT * FROM scans;

CREATE TABLE IF NOT EXISTS migration_backup_hosts_v2
AS SELECT * FROM hosts;

CREATE TABLE IF NOT EXISTS migration_backup_ports_v2
AS SELECT * FROM ports;

-- 1. 승인된 스캔 범위

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

ALTER TABLE scans
    ADD COLUMN scope_id BIGINT UNSIGNED NULL
        AFTER scan_uid,
    ADD COLUMN requested_targets JSON NULL
        AFTER target,
    MODIFY COLUMN target MEDIUMTEXT NOT NULL,
    ADD INDEX idx_scans_scope (scope_id),
    ADD CONSTRAINT fk_scans_scope
        FOREIGN KEY (scope_id)
        REFERENCES scan_scopes(id)
        ON DELETE SET NULL;

-- 2. hosts를 자산대장으로 확장

ALTER TABLE hosts
    ADD COLUMN asset_uid CHAR(36) NULL
        AFTER id,
    ADD COLUMN asset_name VARCHAR(255) NULL
        AFTER host_name,
    ADD COLUMN asset_type ENUM(
        'SERVER',
        'WORKSTATION',
        'NETWORK_DEVICE',
        'CLOUD_RESOURCE',
        'CONTAINER',
        'UNKNOWN'
    ) NOT NULL DEFAULT 'UNKNOWN'
        AFTER asset_name,
    ADD COLUMN environment ENUM(
        'PRODUCTION',
        'STAGING',
        'DEVELOPMENT',
        'TEST',
        'UNKNOWN'
    ) NOT NULL DEFAULT 'UNKNOWN'
        AFTER asset_type,
    ADD COLUMN criticality ENUM(
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL',
        'UNASSIGNED'
    ) NOT NULL DEFAULT 'UNASSIGNED'
        AFTER environment,
    ADD COLUMN owner VARCHAR(255) NULL
        AFTER criticality,
    ADD COLUMN business_unit VARCHAR(255) NULL
        AFTER owner,
    ADD COLUMN data_classification ENUM(
        'PUBLIC',
        'INTERNAL',
        'CONFIDENTIAL',
        'RESTRICTED',
        'UNKNOWN'
    ) NOT NULL DEFAULT 'UNKNOWN'
        AFTER business_unit,
    ADD COLUMN handles_personal_data BOOLEAN NOT NULL
        DEFAULT FALSE
        AFTER data_classification,
    ADD COLUMN internet_exposed BOOLEAN NOT NULL
        DEFAULT FALSE
        AFTER handles_personal_data,
    ADD COLUMN lifecycle_status ENUM(
        'ACTIVE',
        'INACTIVE',
        'RETIRED'
    ) NOT NULL DEFAULT 'ACTIVE'
        AFTER internet_exposed,
    ADD COLUMN source ENUM(
        'DISCOVERED',
        'MANUAL',
        'IMPORTED'
    ) NOT NULL DEFAULT 'DISCOVERED'
        AFTER lifecycle_status,
    ADD COLUMN notes TEXT NULL
        AFTER source,
    ADD COLUMN created_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        AFTER last_scan_id,
    ADD COLUMN updated_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
        AFTER created_at;

UPDATE hosts
SET asset_uid = UUID()
WHERE asset_uid IS NULL OR asset_uid = '';

ALTER TABLE hosts
    MODIFY COLUMN asset_uid CHAR(36) NOT NULL,
    ADD UNIQUE KEY uq_hosts_asset_uid (asset_uid),
    ADD INDEX idx_hosts_lifecycle (lifecycle_status),
    ADD INDEX idx_hosts_criticality (criticality);

-- 3. UDP 스캔 결과와 DB 상태값 일치

ALTER TABLE ports
    MODIFY COLUMN state ENUM(
        'open',
        'closed',
        'filtered',
        'open|filtered',
        'open_or_filtered'
    ) NOT NULL DEFAULT 'closed';

UPDATE ports
SET state = 'open_or_filtered'
WHERE state = 'open|filtered';

ALTER TABLE ports
    MODIFY COLUMN state ENUM(
        'open',
        'closed',
        'filtered',
        'open_or_filtered'
    ) NOT NULL DEFAULT 'closed';

-- 4. 스캔과 자산의 다대다 관찰 이력

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

-- 5. 자산 메타데이터 변경 감사이력

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

-- 6. 마이그레이션 결과 확인

SELECT
    (SELECT COUNT(*) FROM scans)
        AS scan_count,
    (SELECT COUNT(*) FROM hosts)
        AS asset_count,
    (SELECT COUNT(*) FROM ports)
        AS port_count,
    (
        SELECT COUNT(*)
        FROM hosts
        WHERE asset_uid IS NULL
            OR asset_uid = ''
    ) AS missing_asset_uid_count,
    (
        SELECT COUNT(*)
        FROM scan_scopes
    ) AS scope_count,
    (
        SELECT COUNT(*)
        FROM scan_assets
    ) AS scan_asset_count;
