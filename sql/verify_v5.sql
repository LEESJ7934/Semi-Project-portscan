USE port_scan;

-- READ ONLY: run this file before AND after migration, while other writers are stopped.
-- Keep both outputs outside the repo and compare the seven existing-data counts.
-- Before migration risk_table_exists=0, risk_assessment_count=NULL and epss is decimal(6,5).
-- After migration risk_table_exists=1, epss is decimal(10,9), existing counts must match.
SELECT COUNT(*) AS risk_table_exists FROM information_schema.tables
WHERE table_schema = DATABASE() AND table_name = 'vuln_risk_assessments';
SELECT column_name, column_type, numeric_precision, numeric_scale, is_nullable
FROM information_schema.columns
WHERE table_schema = DATABASE() AND table_name = 'vulns' AND column_name = 'epss';
SELECT
    (SELECT COUNT(*) FROM scans) AS scan_count,
    (SELECT COUNT(*) FROM hosts) AS asset_count,
    (SELECT COUNT(*) FROM ports) AS port_count,
    (SELECT COUNT(*) FROM vulns) AS vuln_count,
    (SELECT COUNT(*) FROM vuln_evidence) AS vuln_evidence_count,
    (SELECT COUNT(*) FROM remediation_history) AS remediation_history_count,
    (SELECT COUNT(*) FROM asset_change_history) AS asset_change_count;

-- Metadata queries also work before the table exists.
SELECT column_name, column_type, is_nullable
FROM information_schema.columns
WHERE table_schema = DATABASE() AND table_name = 'vuln_risk_assessments'
ORDER BY ordinal_position;
SELECT index_name, non_unique, seq_in_index, column_name
FROM information_schema.statistics
WHERE table_schema = DATABASE() AND table_name = 'vuln_risk_assessments'
ORDER BY index_name, seq_in_index;
SELECT constraint_name, referenced_table_name, delete_rule
FROM information_schema.referential_constraints
WHERE constraint_schema = DATABASE() AND table_name = 'vuln_risk_assessments';

SET @risk_exists = (SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = 'vuln_risk_assessments');
SET @risk_count_sql = IF(@risk_exists = 1,
    'SELECT COUNT(*) AS risk_assessment_count FROM vuln_risk_assessments',
    'SELECT NULL AS risk_assessment_count');
PREPARE risk_count_check FROM @risk_count_sql;
EXECUTE risk_count_check;
DEALLOCATE PREPARE risk_count_check;

-- Expected after V5: no duplicate rows.
SET @risk_duplicate_sql = IF(@risk_exists = 1,
    'SELECT vuln_id, methodology_id, input_sha256, COUNT(*) AS duplicate_count FROM vuln_risk_assessments GROUP BY vuln_id, methodology_id, input_sha256 HAVING COUNT(*) > 1',
    'SELECT ''V5_NOT_APPLIED'' AS risk_duplicate_check');
PREPARE risk_duplicate_check FROM @risk_duplicate_sql;
EXECUTE risk_duplicate_check;
DEALLOCATE PREPARE risk_duplicate_check;
