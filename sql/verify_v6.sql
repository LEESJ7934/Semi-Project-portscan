USE port_scan;

SELECT table_name
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name IN ('cloud_resources', 'cloud_configuration_findings')
ORDER BY table_name;

SELECT
    cr.id,
    h.asset_uid,
    h.host_ip,
    h.asset_type,
    cr.provider,
    cr.region,
    cr.resource_id,
    cr.vpc_id,
    cr.subnet_id,
    cr.private_ip,
    cr.public_ip,
    cr.instance_state,
    cr.last_discovered_at
FROM cloud_resources AS cr
JOIN hosts AS h ON h.id = cr.host_id
ORDER BY cr.id DESC
LIMIT 20;

SELECT
    cf.rule_id,
    cf.severity,
    cf.priority,
    cf.status,
    cf.public_address_present,
    cr.resource_id,
    cr.private_ip,
    cf.observations,
    cf.last_detected_at
FROM cloud_configuration_findings AS cf
JOIN cloud_resources AS cr ON cr.id = cf.cloud_resource_id
ORDER BY FIELD(cf.priority, 'P1','P2','P3','P4','UNASSESSED'), cf.rule_id;
