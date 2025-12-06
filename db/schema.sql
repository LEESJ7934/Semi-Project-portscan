CREATE DATABASE IF NOT EXISTS port_scan
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE port_scan;

-- 1) 스캔 실행 기록 테이블
CREATE TABLE IF NOT EXISTS scans (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    target          VARCHAR(255)    NOT NULL,   
    scan_type       VARCHAR(50)     NOT NULL,   
    port_range      VARCHAR(100)    NOT NULL,   
    started_at      DATETIME        NOT NULL,
    finished_at     DATETIME        NULL,
    status          VARCHAR(20)     NOT NULL,   
    config_snapshot JSON            NULL,       

    PRIMARY KEY (id),
    INDEX idx_scans_status (status),
    INDEX idx_scans_started_at (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2) 호스트 테이블
CREATE TABLE IF NOT EXISTS hosts (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_ip         VARCHAR(45)     NOT NULL,  
    host_name       VARCHAR(255)    NULL,      
    first_seen      DATETIME        NOT NULL,
    last_seen       DATETIME        NOT NULL,
    last_scan_id    VARCHAR(64)     NULL,     

    PRIMARY KEY (id),
    UNIQUE KEY uq_hosts_ip (host_ip),
    INDEX idx_hosts_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3) 포트 테이블
CREATE TABLE IF NOT EXISTS ports (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id         BIGINT UNSIGNED NOT NULL,
    port            INT UNSIGNED    NOT NULL,
    protocol        ENUM('tcp','udp') NOT NULL,
    service         VARCHAR(100)    NULL,
    version         VARCHAR(100)    NULL,
    banner          TEXT            NULL,
    state           ENUM('open', 'closed') NOT NULL DEFAULT 'closed',
    first_seen      DATETIME        NOT NULL,
    last_seen       DATETIME        NOT NULL,
    last_scan_id    VARCHAR(64)     NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_ports_host_port_proto (host_id, port, protocol),
    INDEX idx_ports_host (host_id),
    INDEX idx_ports_service (service),
    INDEX idx_ports_last_seen (last_seen),

    CONSTRAINT fk_ports_host
        FOREIGN KEY (host_id) REFERENCES hosts(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- 4) 취약점 테이블
CREATE TABLE IF NOT EXISTS vulns (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    port_id         BIGINT UNSIGNED NOT NULL,
    cve_id          VARCHAR(50)     NOT NULL,   
    title           VARCHAR(255)    NOT NULL,
    severity        ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    epss            DECIMAL(5,4)    NULL,       
    status          ENUM('POTENTIAL','CONFIRMED','REJECTED') 
    NOT NULL DEFAULT 'POTENTIAL',
    source          VARCHAR(100)    NULL,       
    created_at      DATETIME        NOT NULL,
    updated_at      DATETIME        NOT NULL,

    PRIMARY KEY (id),
    INDEX idx_vulns_port (port_id),
    INDEX idx_vulns_cve (cve_id),
    INDEX idx_vulns_severity (severity),
    CONSTRAINT fk_vulns_port
        FOREIGN KEY (port_id) REFERENCES ports(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE vulns 
ADD COLUMN cvss DECIMAL(4,2) DEFAULT 0.0 AFTER epss;

ALTER TABLE vulns 
ADD COLUMN risk DECIMAL(4,3) DEFAULT 0.0 AFTER cvss;