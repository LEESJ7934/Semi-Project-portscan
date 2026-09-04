USE port_scan;

-- 기존 V1 DB에서 한 번만 실행합니다.
-- 구조를 변경하기 전에 기존 데이터를 복사합니다.

CREATE TABLE IF NOT EXISTS migration_backup_scans_v1
AS SELECT * FROM scans;

CREATE TABLE IF NOT EXISTS migration_backup_hosts_v1
AS SELECT * FROM hosts;

CREATE TABLE IF NOT EXISTS migration_backup_ports_v1
AS SELECT * FROM ports;

CREATE TABLE IF NOT EXISTS migration_backup_vulns_v1
AS SELECT * FROM vulns;

-- 1. 스캔 식별자와 상태값 정리

ALTER TABLE scans
    ADD COLUMN scan_uid VARCHAR(64) NULL
        AFTER id,
    ADD COLUMN created_at DATETIME NULL
        DEFAULT CURRENT_TIMESTAMP
        AFTER config_snapshot;

UPDATE scans
SET scan_uid = CONCAT('legacy-', id)
WHERE scan_uid IS NULL OR scan_uid = '';

ALTER TABLE scans
    MODIFY COLUMN status ENUM(
        'DONE',
        'QUEUED',
        'RUNNING',
        'COMPLETED',
        'PARTIAL',
        'FAILED'
    ) NOT NULL DEFAULT 'QUEUED';

UPDATE scans
SET status = 'COMPLETED'
WHERE status = 'DONE';

ALTER TABLE scans
    MODIFY COLUMN scan_uid VARCHAR(64)
        NOT NULL,
    MODIFY COLUMN status ENUM(
        'QUEUED',
        'RUNNING',
        'COMPLETED',
        'PARTIAL',
        'FAILED'
    ) NOT NULL DEFAULT 'QUEUED',
    ADD UNIQUE KEY uq_scans_uid (
        scan_uid
    );

-- 2. 기존 문자열 스캔 ID를 보존하고
-- 정규화된 외래키 열 추가

ALTER TABLE hosts
    CHANGE COLUMN last_scan_id
        legacy_last_scan_uid VARCHAR(64) NULL,
    ADD COLUMN last_scan_id BIGINT UNSIGNED NULL
        AFTER legacy_last_scan_uid,
    ADD INDEX idx_hosts_last_scan (
        last_scan_id
    ),
    ADD CONSTRAINT fk_hosts_last_scan
        FOREIGN KEY (last_scan_id)
        REFERENCES scans(id)
        ON DELETE SET NULL;

ALTER TABLE ports
    CHANGE COLUMN last_scan_id
        legacy_last_scan_uid VARCHAR(64) NULL,
    ADD COLUMN last_scan_id BIGINT UNSIGNED NULL
        AFTER legacy_last_scan_uid,
    MODIFY COLUMN version VARCHAR(255) NULL,
    MODIFY COLUMN state ENUM(
        'open',
        'closed',
        'filtered'
    ) NOT NULL DEFAULT 'closed',
    ADD INDEX idx_ports_last_scan (
        last_scan_id
    ),
    ADD CONSTRAINT fk_ports_last_scan
        FOREIGN KEY (last_scan_id)
        REFERENCES scans(id)
        ON DELETE SET NULL;

-- 3. 취약점 상태값과 탐지 시각 열 확장

ALTER TABLE vulns
    MODIFY COLUMN status ENUM(
        'POTENTIAL',
        'CONFIRMED',
        'REJECTED',
        'CANDIDATE',
        'NOT_APPLICABLE',
        'FALSE_POSITIVE',
        'RETEST_REQUIRED',
        'CLOSED',
        'ERROR'
    ) NOT NULL DEFAULT 'CANDIDATE';

UPDATE vulns
SET status = 'FALSE_POSITIVE'
WHERE status = 'REJECTED';

UPDATE vulns
SET source = 'unknown'
WHERE source IS NULL OR TRIM(source) = '';

ALTER TABLE vulns
    MODIFY COLUMN severity ENUM(
        'INFO',
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL'
    ) NOT NULL DEFAULT 'INFO',
    MODIFY COLUMN epss DECIMAL(6,5) NULL,
    MODIFY COLUMN cvss DECIMAL(4,2) NULL,
    MODIFY COLUMN risk DECIMAL(6,5) NULL,
    MODIFY COLUMN source VARCHAR(100)
        NOT NULL DEFAULT 'unknown',
    ADD COLUMN first_detected_at DATETIME NULL
        AFTER source,
    ADD COLUMN last_detected_at DATETIME NULL
        AFTER first_detected_at,
    ADD COLUMN verified_at DATETIME NULL
        AFTER last_detected_at,
    ADD COLUMN closed_at DATETIME NULL
        AFTER verified_at;

UPDATE vulns
SET
    first_detected_at = created_at,
    last_detected_at = updated_at,
    verified_at = CASE
        WHEN status IN (
            'CONFIRMED',
            'FALSE_POSITIVE',
            'NOT_APPLICABLE'
        )
        THEN updated_at
        ELSE NULL
    END,
    closed_at = CASE
        WHEN status = 'CLOSED'
        THEN updated_at
        ELSE NULL
    END;

ALTER TABLE vulns
    MODIFY COLUMN first_detected_at
        DATETIME NOT NULL,
    MODIFY COLUMN last_detected_at
        DATETIME NOT NULL,
    MODIFY COLUMN status ENUM(
        'CANDIDATE',
        'POTENTIAL',
        'CONFIRMED',
        'NOT_APPLICABLE',
        'FALSE_POSITIVE',
        'RETEST_REQUIRED',
        'CLOSED',
        'ERROR'
    ) NOT NULL DEFAULT 'CANDIDATE';

-- 4. 중복 취약점 중 최신 레코드만 유지

DELETE older
FROM vulns AS older
JOIN vulns AS newer
    ON older.port_id = newer.port_id
    AND older.cve_id = newer.cve_id
    AND older.source = newer.source
    AND (
        older.updated_at < newer.updated_at
        OR (
            older.updated_at = newer.updated_at
            AND older.id < newer.id
        )
    );

ALTER TABLE vulns
    ADD UNIQUE KEY uq_vulns_port_cve_source (
        port_id,
        cve_id,
        source
    ),
    ADD INDEX idx_vulns_status (
        status
    ),
    ADD INDEX idx_vulns_last_detected (
        last_detected_at
    );

-- 5. 취약점 검증 증적 테이블

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
    INDEX idx_evidence_vuln (
        vuln_id
    ),
    INDEX idx_evidence_collected_at (
        collected_at
    ),

    CONSTRAINT fk_evidence_vuln
        FOREIGN KEY (vuln_id)
        REFERENCES vulns(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. 상태 변경 및 조치 이력 테이블

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
    INDEX idx_remediation_vuln (
        vuln_id
    ),
    INDEX idx_remediation_changed_at (
        changed_at
    ),

    CONSTRAINT fk_remediation_vuln
        FOREIGN KEY (vuln_id)
        REFERENCES vulns(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO remediation_history (
    vuln_id,
    from_status,
    to_status,
    action_type,
    reason,
    changed_by
)
SELECT
    v.id,
    NULL,
    v.status,
    'STATUS_CHANGE',
    'V2 마이그레이션 시점의 초기 상태',
    'migration-v2'
FROM vulns AS v
WHERE NOT EXISTS (
    SELECT 1
    FROM remediation_history AS history
    WHERE history.vuln_id = v.id
);

SELECT
    (SELECT COUNT(*) FROM scans)
        AS scan_count,
    (SELECT COUNT(*) FROM hosts)
        AS host_count,
    (SELECT COUNT(*) FROM ports)
        AS port_count,
    (SELECT COUNT(*) FROM vulns)
        AS vuln_count,
    (SELECT COUNT(*) FROM vuln_evidence)
        AS evidence_count,
    (
        SELECT COUNT(*)
        FROM remediation_history
    ) AS remediation_history_count;