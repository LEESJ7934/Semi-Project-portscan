-- 과거 개발 식별자를 의미 기반 식별자로 정리하는 호환 마이그레이션.
-- 아래 HEX 값은 이전 릴리스에서 저장된 레거시 prefix/methodology/checker를 나타낸다.
START TRANSACTION;

SET @legacy_source_prefix = CONVERT(UNHEX('646179343A') USING utf8mb4);
SET @legacy_methodology = CONVERT(UNHEX('646179362D7072696F726974792D7631') USING utf8mb4);
SET @legacy_checker_prefix = CONVERT(UNHEX('646179353A') USING utf8mb4);
SET @legacy_mapper = CONVERT(UNHEX('646179345F6D6170706572') USING utf8mb4);

UPDATE vulns
SET source = CONCAT('catalog:', SUBSTRING(source, CHAR_LENGTH(@legacy_source_prefix) + 1))
WHERE source LIKE CONCAT(@legacy_source_prefix, '%');

UPDATE vuln_risk_assessments
SET methodology_id = 'risk-priority-v1'
WHERE methodology_id = @legacy_methodology;

UPDATE vuln_evidence
SET checker = 'cve_catalog_mapper'
WHERE checker = @legacy_mapper;

UPDATE vuln_evidence
SET checker = CONCAT('verifier:', SUBSTRING(checker, CHAR_LENGTH(@legacy_checker_prefix) + 1))
WHERE checker LIKE CONCAT(@legacy_checker_prefix, '%');

COMMIT;
