USE port_scan;

-- V3 적용 후 실행하는 포트 범위 저장 용량 보완입니다.
-- 먼저 현재 DB를 외부 파일로 백업합니다.
-- 기존 스캔과 자산, 감사이력의 값은 변경하지 않습니다.
-- 이미 MEDIUMTEXT인 경우에도 실행할 수 있습니다.

ALTER TABLE scans
    MODIFY COLUMN port_range MEDIUMTEXT NOT NULL;

SHOW COLUMNS FROM scans LIKE 'port_range';

SELECT
    (SELECT COUNT(*) FROM scans) AS scan_count,
    (SELECT COUNT(*) FROM hosts) AS asset_count,
    (SELECT COUNT(*) FROM ports) AS port_count,
    (SELECT COUNT(*) FROM vulns) AS vuln_count,
    (SELECT COUNT(*) FROM asset_change_history) AS asset_change_count;
