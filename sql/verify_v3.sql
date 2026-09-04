USE port_scan;

SHOW TABLES;

SHOW COLUMNS FROM scan_scopes;
SHOW COLUMNS FROM scans;
SHOW COLUMNS FROM hosts;
SHOW COLUMNS FROM scan_assets;
SHOW COLUMNS FROM asset_change_history;

SELECT
    (SELECT COUNT(*) FROM scans) AS scan_count,
    (SELECT COUNT(*) FROM hosts) AS asset_count,
    (SELECT COUNT(*) FROM ports) AS port_count,
    (SELECT COUNT(*) FROM scan_scopes) AS scope_count,
    (SELECT COUNT(*) FROM scan_assets) AS scan_asset_count,
    (
        SELECT COUNT(*)
        FROM asset_change_history
    ) AS asset_change_count;

SELECT COUNT(*) AS missing_asset_uid_count
FROM hosts
WHERE asset_uid IS NULL OR asset_uid = '';

SELECT asset_uid, COUNT(*) AS duplicate_count
FROM hosts
GROUP BY asset_uid
HAVING COUNT(*) > 1;

SELECT host_ip, COUNT(*) AS duplicate_count
FROM hosts
GROUP BY host_ip
HAVING COUNT(*) > 1;

SELECT scan_asset.id AS orphan_scan_asset_id
FROM scan_assets AS scan_asset
LEFT JOIN scans AS scan
    ON scan_asset.scan_id = scan.id
LEFT JOIN hosts AS host
    ON scan_asset.host_id = host.id
WHERE scan.id IS NULL OR host.id IS NULL;

SELECT history.id AS orphan_asset_history_id
FROM asset_change_history AS history
LEFT JOIN hosts AS host
    ON history.host_id = host.id
WHERE host.id IS NULL;
