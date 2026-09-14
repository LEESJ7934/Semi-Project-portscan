-- MySQL dump 10.13  Distrib 8.0.44, for Linux (x86_64)
--
-- Host: localhost    Database: port_scan
-- ------------------------------------------------------
-- Server version	8.0.44

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `asset_change_history`
--

DROP TABLE IF EXISTS `asset_change_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `asset_change_history` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `host_id` bigint unsigned NOT NULL,
  `field_name` varchar(64) NOT NULL,
  `old_value` text,
  `new_value` text,
  `reason` varchar(500) NOT NULL,
  `changed_by` varchar(100) NOT NULL,
  `changed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_asset_history_host` (`host_id`),
  KEY `idx_asset_history_changed_at` (`changed_at`),
  CONSTRAINT `fk_asset_history_host` FOREIGN KEY (`host_id`) REFERENCES `hosts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `asset_change_history`
--

LOCK TABLES `asset_change_history` WRITE;
/*!40000 ALTER TABLE `asset_change_history` DISABLE KEYS */;
INSERT INTO `asset_change_history` VALUES (1,2,'asset_name',NULL,'day3-local-lab','3일차 로컬 실습 자산 등록','portfolio-owner','2026-09-04 22:53:22'),(2,2,'asset_type','UNKNOWN','SERVER','3일차 로컬 실습 자산 등록','portfolio-owner','2026-09-04 22:53:22'),(3,2,'environment','UNKNOWN','TEST','3일차 로컬 실습 자산 등록','portfolio-owner','2026-09-04 22:53:22'),(4,2,'criticality','UNASSIGNED','LOW','3일차 로컬 실습 자산 등록','portfolio-owner','2026-09-04 22:53:22'),(5,2,'owner',NULL,'portfolio-owner','3일차 로컬 실습 자산 등록','portfolio-owner','2026-09-04 22:53:22'),(6,2,'data_classification','UNKNOWN','INTERNAL','3일차 로컬 실습 자산 등록','portfolio-owner','2026-09-04 22:53:22'),(7,2,'source','DISCOVERED','MANUAL','3일차 로컬 실습 자산 등록','portfolio-owner','2026-09-04 22:53:22'),(8,2,'criticality','LOW','HIGH','3일차 중요도 및 담당자 변경 기능 검증','portfolio-owner','2026-09-04 22:53:44'),(9,2,'owner','portfolio-owner','security-team','3일차 중요도 및 담당자 변경 기능 검증','portfolio-owner','2026-09-04 22:53:44');
/*!40000 ALTER TABLE `asset_change_history` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `hosts`
--

DROP TABLE IF EXISTS `hosts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hosts` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_uid` char(36) NOT NULL,
  `host_ip` varchar(45) NOT NULL,
  `host_name` varchar(255) DEFAULT NULL,
  `asset_name` varchar(255) DEFAULT NULL,
  `asset_type` enum('SERVER','WORKSTATION','NETWORK_DEVICE','CLOUD_RESOURCE','CONTAINER','UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
  `environment` enum('PRODUCTION','STAGING','DEVELOPMENT','TEST','UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
  `criticality` enum('LOW','MEDIUM','HIGH','CRITICAL','UNASSIGNED') NOT NULL DEFAULT 'UNASSIGNED',
  `owner` varchar(255) DEFAULT NULL,
  `business_unit` varchar(255) DEFAULT NULL,
  `data_classification` enum('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
  `handles_personal_data` tinyint(1) NOT NULL DEFAULT '0',
  `internet_exposed` tinyint(1) NOT NULL DEFAULT '0',
  `lifecycle_status` enum('ACTIVE','INACTIVE','RETIRED') NOT NULL DEFAULT 'ACTIVE',
  `source` enum('DISCOVERED','MANUAL','IMPORTED') NOT NULL DEFAULT 'DISCOVERED',
  `notes` text,
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `legacy_last_scan_uid` varchar(64) DEFAULT NULL,
  `last_scan_id` bigint unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_hosts_ip` (`host_ip`),
  UNIQUE KEY `uq_hosts_asset_uid` (`asset_uid`),
  KEY `idx_hosts_last_seen` (`last_seen`),
  KEY `fk_hosts_last_scan` (`legacy_last_scan_uid`),
  KEY `idx_hosts_last_scan` (`last_scan_id`),
  KEY `idx_hosts_lifecycle` (`lifecycle_status`),
  KEY `idx_hosts_criticality` (`criticality`),
  CONSTRAINT `fk_hosts_last_scan` FOREIGN KEY (`last_scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `hosts`
--

LOCK TABLES `hosts` WRITE;
/*!40000 ALTER TABLE `hosts` DISABLE KEYS */;
INSERT INTO `hosts` VALUES (1,'0561e307-a8b3-11f1-bb09-9a1fea705640','43.200.247.45','ec2-43-200-247-45.ap-northeast-2.compute.amazonaws.com',NULL,'UNKNOWN','UNKNOWN','UNASSIGNED',NULL,NULL,'UNKNOWN',0,0,'ACTIVE','DISCOVERED',NULL,'2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL,'2026-09-04 22:50:26','2026-09-04 22:50:26'),(2,'9cd48a9c-bc17-4bbb-81ce-419f2bef8306','127.0.0.1','kubernetes.docker.internal','day3-local-lab','SERVER','TEST','HIGH','security-team',NULL,'INTERNAL',0,0,'ACTIVE','MANUAL',NULL,'2026-09-04 22:53:22','2026-09-11 14:09:25',NULL,6,'2026-09-04 22:53:22','2026-09-11 14:09:25');
/*!40000 ALTER TABLE `hosts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migration_backup_hosts_v1`
--

DROP TABLE IF EXISTS `migration_backup_hosts_v1`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migration_backup_hosts_v1` (
  `id` bigint unsigned NOT NULL DEFAULT '0',
  `host_ip` varchar(45) NOT NULL,
  `host_name` varchar(255) DEFAULT NULL,
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `last_scan_id` varchar(64) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migration_backup_hosts_v1`
--

LOCK TABLES `migration_backup_hosts_v1` WRITE;
/*!40000 ALTER TABLE `migration_backup_hosts_v1` DISABLE KEYS */;
INSERT INTO `migration_backup_hosts_v1` VALUES (1,'43.200.247.45','ec2-43-200-247-45.ap-northeast-2.compute.amazonaws.com','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833');
/*!40000 ALTER TABLE `migration_backup_hosts_v1` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migration_backup_hosts_v2`
--

DROP TABLE IF EXISTS `migration_backup_hosts_v2`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migration_backup_hosts_v2` (
  `id` bigint unsigned NOT NULL DEFAULT '0',
  `host_ip` varchar(45) NOT NULL,
  `host_name` varchar(255) DEFAULT NULL,
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `legacy_last_scan_uid` varchar(64) DEFAULT NULL,
  `last_scan_id` bigint unsigned DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migration_backup_hosts_v2`
--

LOCK TABLES `migration_backup_hosts_v2` WRITE;
/*!40000 ALTER TABLE `migration_backup_hosts_v2` DISABLE KEYS */;
INSERT INTO `migration_backup_hosts_v2` VALUES (1,'43.200.247.45','ec2-43-200-247-45.ap-northeast-2.compute.amazonaws.com','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL);
/*!40000 ALTER TABLE `migration_backup_hosts_v2` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migration_backup_ports_v1`
--

DROP TABLE IF EXISTS `migration_backup_ports_v1`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migration_backup_ports_v1` (
  `id` bigint unsigned NOT NULL DEFAULT '0',
  `host_id` bigint unsigned NOT NULL,
  `port` int unsigned NOT NULL,
  `protocol` enum('tcp','udp') NOT NULL,
  `service` varchar(100) DEFAULT NULL,
  `version` varchar(512) DEFAULT NULL,
  `banner` text,
  `state` enum('open','closed','open|filtered') NOT NULL,
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `last_scan_id` varchar(64) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migration_backup_ports_v1`
--

LOCK TABLES `migration_backup_ports_v1` WRITE;
/*!40000 ALTER TABLE `migration_backup_ports_v1` DISABLE KEYS */;
INSERT INTO `migration_backup_ports_v1` VALUES (1,1,21,'tcp','ftp','3.0.5','220 (vsFTPd 3.0.5)\r\n','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833'),(2,1,22,'tcp','ssh','8.9p1','SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13\r\n','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833'),(3,1,23,'tcp','telnet',' #\'',' #\'','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833'),(4,1,80,'tcp','http','2.4.25','HTTP/1.1 302 Found\r\nDate: Wed, 11 Mar 2026 06:52:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=fu7nb97lam84oqu41ocgkev9g1; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nSet-Cookie: PHPSESSID=fu7nb97lam84oqu41ocgkev9g1; path=/\r\nSet-Cookie: security=low\r\nLocation: login.php\r\nContent-Length: 0\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833');
/*!40000 ALTER TABLE `migration_backup_ports_v1` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migration_backup_ports_v2`
--

DROP TABLE IF EXISTS `migration_backup_ports_v2`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migration_backup_ports_v2` (
  `id` bigint unsigned NOT NULL DEFAULT '0',
  `host_id` bigint unsigned NOT NULL,
  `port` int unsigned NOT NULL,
  `protocol` enum('tcp','udp') NOT NULL,
  `service` varchar(100) DEFAULT NULL,
  `version` varchar(255) DEFAULT NULL,
  `banner` text,
  `state` enum('open','closed','filtered') NOT NULL DEFAULT 'closed',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `legacy_last_scan_uid` varchar(64) DEFAULT NULL,
  `last_scan_id` bigint unsigned DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migration_backup_ports_v2`
--

LOCK TABLES `migration_backup_ports_v2` WRITE;
/*!40000 ALTER TABLE `migration_backup_ports_v2` DISABLE KEYS */;
INSERT INTO `migration_backup_ports_v2` VALUES (1,1,21,'tcp','ftp','3.0.5','220 (vsFTPd 3.0.5)\r\n','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL),(2,1,22,'tcp','ssh','8.9p1','SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13\r\n','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL),(3,1,23,'tcp','telnet',' #\'',' #\'','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL),(4,1,80,'tcp','http','2.4.25','HTTP/1.1 302 Found\r\nDate: Wed, 11 Mar 2026 06:52:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=fu7nb97lam84oqu41ocgkev9g1; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nSet-Cookie: PHPSESSID=fu7nb97lam84oqu41ocgkev9g1; path=/\r\nSet-Cookie: security=low\r\nLocation: login.php\r\nContent-Length: 0\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n','open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL);
/*!40000 ALTER TABLE `migration_backup_ports_v2` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migration_backup_scans_v1`
--

DROP TABLE IF EXISTS `migration_backup_scans_v1`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migration_backup_scans_v1` (
  `id` bigint unsigned NOT NULL DEFAULT '0',
  `target` varchar(255) NOT NULL,
  `scan_type` varchar(50) NOT NULL,
  `port_range` varchar(100) NOT NULL,
  `started_at` datetime NOT NULL,
  `finished_at` datetime DEFAULT NULL,
  `status` varchar(20) NOT NULL,
  `config_snapshot` json DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migration_backup_scans_v1`
--

LOCK TABLES `migration_backup_scans_v1` WRITE;
/*!40000 ALTER TABLE `migration_backup_scans_v1` DISABLE KEYS */;
INSERT INTO `migration_backup_scans_v1` VALUES (1,'43.200.247.45','tcp','1-100','2026-03-11 15:52:53','2026-03-11 15:52:54','DONE',NULL);
/*!40000 ALTER TABLE `migration_backup_scans_v1` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migration_backup_scans_v2`
--

DROP TABLE IF EXISTS `migration_backup_scans_v2`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migration_backup_scans_v2` (
  `id` bigint unsigned NOT NULL DEFAULT '0',
  `scan_uid` varchar(64) NOT NULL,
  `target` varchar(255) NOT NULL,
  `scan_type` varchar(50) NOT NULL,
  `port_range` varchar(100) NOT NULL,
  `started_at` datetime NOT NULL,
  `finished_at` datetime DEFAULT NULL,
  `status` enum('QUEUED','RUNNING','COMPLETED','PARTIAL','FAILED') NOT NULL DEFAULT 'QUEUED',
  `config_snapshot` json DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migration_backup_scans_v2`
--

LOCK TABLES `migration_backup_scans_v2` WRITE;
/*!40000 ALTER TABLE `migration_backup_scans_v2` DISABLE KEYS */;
INSERT INTO `migration_backup_scans_v2` VALUES (1,'legacy-1','43.200.247.45','tcp','1-100','2026-03-11 15:52:53','2026-03-11 15:52:54','COMPLETED',NULL,'2026-09-04 04:03:35');
/*!40000 ALTER TABLE `migration_backup_scans_v2` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migration_backup_vulns_v1`
--

DROP TABLE IF EXISTS `migration_backup_vulns_v1`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migration_backup_vulns_v1` (
  `id` bigint unsigned NOT NULL DEFAULT '0',
  `port_id` bigint unsigned NOT NULL,
  `cve_id` varchar(50) NOT NULL,
  `title` varchar(255) NOT NULL,
  `severity` enum('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
  `epss` decimal(5,4) DEFAULT NULL,
  `cvss` decimal(4,2) DEFAULT '0.00',
  `risk` decimal(4,3) DEFAULT '0.000',
  `status` enum('POTENTIAL','CONFIRMED','INVALID') NOT NULL,
  `source` varchar(100) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migration_backup_vulns_v1`
--

LOCK TABLES `migration_backup_vulns_v1` WRITE;
/*!40000 ALTER TABLE `migration_backup_vulns_v1` DISABLE KEYS */;
INSERT INTO `migration_backup_vulns_v1` VALUES (1,1,'CVE-1999-0497','Anonymous FTP writable','LOW',0.0061,0.00,0.002,'POTENTIAL','rule_ftp_vsftpd_3_0_5','2026-03-11 06:53:14','2026-03-11 06:53:14'),(2,2,'CVE-2023-25136','OpenSSH 8.x Vulnerability','MEDIUM',0.9048,6.50,0.726,'POTENTIAL','rule_ssh_openssh_8_9','2026-03-11 06:53:14','2026-03-11 06:53:14'),(3,3,'CVE-1999-0613','Telnet Service Exposure','HIGH',0.0061,0.00,0.002,'POTENTIAL','rule_telnet_default','2026-03-11 06:53:14','2026-03-11 06:53:14'),(4,4,'CVE-2012-1823','DVWA SQL Injection (mapped to PHP CGI RCE CVE-2012-1823)','HIGH',0.9439,9.80,0.969,'POTENTIAL','rule_dvwa_sqli','2026-03-11 06:53:14','2026-03-11 06:53:14'),(5,4,'CVE-2020-2551','DVWA File Upload Vulnerability (mapped to WebLogic CVE-2020-2551)','CRITICAL',0.9441,9.80,0.969,'POTENTIAL','rule_dvwa_fileupload','2026-03-11 06:53:14','2026-03-11 06:53:14');
/*!40000 ALTER TABLE `migration_backup_vulns_v1` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ports`
--

DROP TABLE IF EXISTS `ports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ports` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `host_id` bigint unsigned NOT NULL,
  `port` int unsigned NOT NULL,
  `protocol` enum('tcp','udp') NOT NULL,
  `service` varchar(100) DEFAULT NULL,
  `product` varchar(100) DEFAULT NULL,
  `version` varchar(255) DEFAULT NULL,
  `banner` text,
  `fingerprint` json DEFAULT NULL,
  `state` enum('open','closed','filtered','open_or_filtered') NOT NULL DEFAULT 'closed',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `legacy_last_scan_uid` varchar(64) DEFAULT NULL,
  `last_scan_id` bigint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ports_host_port_proto` (`host_id`,`port`,`protocol`),
  KEY `idx_ports_host` (`host_id`),
  KEY `idx_ports_service` (`service`),
  KEY `idx_ports_last_seen` (`last_seen`),
  KEY `fk_ports_last_scan` (`legacy_last_scan_uid`),
  KEY `idx_ports_last_scan` (`last_scan_id`),
  CONSTRAINT `fk_ports_host` FOREIGN KEY (`host_id`) REFERENCES `hosts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ports_last_scan` FOREIGN KEY (`last_scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ports`
--

LOCK TABLES `ports` WRITE;
/*!40000 ALTER TABLE `ports` DISABLE KEYS */;
INSERT INTO `ports` VALUES (1,1,21,'tcp','ftp',NULL,'3.0.5','220 (vsFTPd 3.0.5)\r\n',NULL,'open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL),(2,1,22,'tcp','ssh',NULL,'8.9p1','SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13\r\n',NULL,'open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL),(3,1,23,'tcp','telnet',NULL,' #\'',' #\'',NULL,'open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL),(4,1,80,'tcp','http',NULL,'2.4.25','HTTP/1.1 302 Found\r\nDate: Wed, 11 Mar 2026 06:52:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=fu7nb97lam84oqu41ocgkev9g1; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nSet-Cookie: PHPSESSID=fu7nb97lam84oqu41ocgkev9g1; path=/\r\nSet-Cookie: security=low\r\nLocation: login.php\r\nContent-Length: 0\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n',NULL,'open','2026-03-11 06:52:59','2026-03-11 06:52:59','scan-20260311065253-a3fc3833',NULL),(5,2,80,'tcp','http','microsoft_iis','10.0','HTTP/1.1 200 OK\r\nContent-Length: 696\r\nContent-Type: text/html\r\nLast-Modified: Mon, 28 Jul 2025 06:36:16 GMT\r\nAccept-Ranges: bytes\r\nETag: \"db48feb89ffdb1:0\"\r\nServer: Microsoft-IIS/10.0\r\nDate: Fri, 11 Sep 2026 14:09:24 GMT\r\nConnection: close\r\n\r\n','{\"tls\": \"not_used\", \"source\": \"http_server\", \"product\": \"microsoft_iis\", \"service\": \"http\", \"version\": \"10.0\", \"evidence\": \"Server: Microsoft-IIS/10.0\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-04 23:08:58','2026-09-11 14:09:25',NULL,6),(6,2,135,'tcp','msrpc',NULL,NULL,NULL,NULL,'open','2026-09-04 23:08:58','2026-09-04 23:08:58',NULL,2),(7,2,445,'tcp','microsoft-ds',NULL,NULL,NULL,NULL,'open','2026-09-04 23:08:58','2026-09-04 23:08:58',NULL,2),(8,2,945,'tcp','unknown',NULL,NULL,NULL,NULL,'open','2026-09-04 23:08:58','2026-09-04 23:08:58',NULL,2),(10,2,3306,'tcp','mysql','mysql','8.0.39','J\0\0\0\n8.0.39\04\0\0\0ygBkZ.jG\0ÿÿÿ\0ÿß\0\0\0\0\0\0\0\0\0\0r\r>Ed]e6@j\0caching_sha2_password\0','{\"tls\": \"not_used\", \"source\": \"mysql_greeting\", \"product\": \"mysql\", \"service\": \"mysql\", \"version\": \"8.0.39\", \"evidence\": \"8.0.39\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-04 23:09:07','2026-09-11 14:09:25',NULL,6),(11,2,18080,'tcp','http','apache_http_server','2.4.50','HTTP/1.0 200 OK\r\nServer: Apache/2.4.50\r\nDate: Sat, 05 Sep 2026 11:50:05 GMT\r\nContent-Type: text/plain; charset=utf-8\r\nX-Portscanner-Demo: simulated-banner-only\r\nContent-Length: 0\r\n\r\n','{\"tls\": \"not_used\", \"source\": \"http_server\", \"product\": \"apache_http_server\", \"service\": \"http\", \"version\": \"2.4.50\", \"evidence\": \"Server: Apache/2.4.50\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-05 11:50:06','2026-09-05 11:50:06',NULL,4),(12,2,8081,'tcp','http','apache_http_server','2.4.50','HTTP/1.0 200 OK\r\nServer: Apache/2.4.50\r\nDate: Fri, 11 Sep 2026 13:01:54 GMT\r\nContent-Type: text/plain; charset=utf-8\r\nX-Portscanner-Demo: simulated-banner-only\r\nContent-Length: 0\r\n\r\n','{\"tls\": \"not_used\", \"source\": \"http_server\", \"product\": \"apache_http_server\", \"service\": \"http\", \"version\": \"2.4.50\", \"evidence\": \"Server: Apache/2.4.50\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-11 13:01:55','2026-09-11 13:01:55',NULL,5),(15,2,3307,'tcp','mysql','mysql','8.0.44','J\0\0\0\n8.0.44\0\0\0A{U\\{up\0ÿÿà\0ÿß\0\0\0\0\0\0\0\0\0\0,Ty4ehd\0mysql_native_password\0','{\"tls\": \"not_used\", \"source\": \"mysql_greeting\", \"product\": \"mysql\", \"service\": \"mysql\", \"version\": \"8.0.44\", \"evidence\": \"8.0.44\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-11 14:09:25','2026-09-11 14:09:25',NULL,6),(16,2,5601,'tcp','http',NULL,NULL,'HTTP/1.1 302 Found\r\nlocation: /spaces/enter\r\nx-content-type-options: nosniff\r\nreferrer-policy: strict-origin-when-cross-origin\r\npermissions-policy: camera=(), display-capture=(), fullscreen=(self), geolocation=(), microphone=(), web-share=()\r\ncross-origin-opener-policy: same-origin\r\ncontent-security-policy: script-src \'report-sample\' \'self\'; worker-src \'report-sample\' \'self\' blob:; style-src \'report-sample\' \'self\' \'unsafe-inline\'\r\ncontent-security-policy-report-only: form-action \'report-sample\' \'self\'\r\nkbn-name: 579ddac31fdd\r\nkbn-license-sig: 78fd83517c188138a878743c3d2abb7e52b8a75de507b3d13a3cefb0d5b2dc4c\r\ncache-control: private, no-cache, no-store, must-revalidate\r\ncontent-length: 0\r\nDate: Fri, 11 Sep 2026 14:09:24 GMT\r\nConnection: close\r\n\r\n','{\"tls\": \"not_used\", \"source\": \"http_response\", \"product\": null, \"service\": \"http\", \"version\": null, \"evidence\": \"HTTP/1.1 302 Found\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-11 14:09:25','2026-09-11 14:09:25',NULL,6),(17,2,9150,'tcp','http',NULL,NULL,'HTTP/1.0 501 Tor is not an HTTP Proxy\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<html>\n<head>\n<title>This is a SOCKS Proxy, Not An HTTP Proxy</title>\n</head>\n<body>\n<h1>This is a SOCKS proxy, not an HTTP proxy.</h1>\n<p>\nIt appears you have configured your web browser to use this Tor port as\nan HTTP proxy.\n</p>\n<p>\nThis is not correct: This port is configured as a SOCKS proxy, not\nan HTTP proxy. If you need an HTTP proxy tunnel, use the HTTPTunnelPort\nconfiguration option in place of, or in addition to, SOCKSPort.\nPlease configure your client accordingly.\n</p>\n<p>\nSee <a href=\"https://www.torproject.org/documentation.html\">https://www.torproject.org/documentation.html</a> for more information.\n</p>\n</body>\n</html>\n\0','{\"tls\": \"not_used\", \"source\": \"http_response\", \"product\": null, \"service\": \"http\", \"version\": null, \"evidence\": \"HTTP/1.0 501 Tor is not an HTTP Proxy\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-11 14:09:25','2026-09-11 14:09:25',NULL,6),(18,2,9151,'tcp','unknown',NULL,NULL,'514 Authentication required.\r\n','{\"tls\": \"not_used\", \"source\": \"port_hint\", \"product\": null, \"service\": \"unknown\", \"version\": null, \"evidence\": null, \"confidence\": \"unknown\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-11 14:09:25','2026-09-11 14:09:25',NULL,6),(19,2,9200,'tcp','http',NULL,NULL,'HTTP/1.1 200 OK\r\nX-elastic-product: Elasticsearch\r\ncontent-type: application/json\r\ncontent-length: 541\r\n\r\n','{\"tls\": \"not_used\", \"source\": \"http_response\", \"product\": null, \"service\": \"http\", \"version\": null, \"evidence\": \"HTTP/1.1 200 OK\", \"confidence\": \"reported\", \"probe_error\": null, \"parser_version\": \"day4.1\"}','open','2026-09-11 14:09:25','2026-09-11 14:09:25',NULL,6);
/*!40000 ALTER TABLE `ports` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `remediation_history`
--

DROP TABLE IF EXISTS `remediation_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `remediation_history` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `vuln_id` bigint unsigned NOT NULL,
  `from_status` enum('CANDIDATE','POTENTIAL','CONFIRMED','NOT_APPLICABLE','FALSE_POSITIVE','RETEST_REQUIRED','CLOSED','ERROR') DEFAULT NULL,
  `to_status` enum('CANDIDATE','POTENTIAL','CONFIRMED','NOT_APPLICABLE','FALSE_POSITIVE','RETEST_REQUIRED','CLOSED','ERROR') NOT NULL,
  `action_type` enum('STATUS_CHANGE','RETEST_REQUEST','REMEDIATION','CLOSURE','REOPEN') NOT NULL DEFAULT 'STATUS_CHANGE',
  `reason` varchar(500) DEFAULT NULL,
  `changed_by` varchar(100) NOT NULL DEFAULT 'system',
  `changed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_remediation_vuln` (`vuln_id`),
  KEY `idx_remediation_changed_at` (`changed_at`),
  CONSTRAINT `fk_remediation_vuln` FOREIGN KEY (`vuln_id`) REFERENCES `vulns` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `remediation_history`
--

LOCK TABLES `remediation_history` WRITE;
/*!40000 ALTER TABLE `remediation_history` DISABLE KEYS */;
INSERT INTO `remediation_history` VALUES (1,1,NULL,'POTENTIAL','STATUS_CHANGE','V2 ????????? ???????? ???','migration-v2','2026-09-04 04:03:36'),(2,2,NULL,'POTENTIAL','STATUS_CHANGE','V2 ????????? ???????? ???','migration-v2','2026-09-04 04:03:36'),(3,3,NULL,'POTENTIAL','STATUS_CHANGE','V2 ????????? ???????? ???','migration-v2','2026-09-04 04:03:36'),(4,4,NULL,'POTENTIAL','STATUS_CHANGE','V2 ????????? ???????? ???','migration-v2','2026-09-04 04:03:36'),(5,5,NULL,'POTENTIAL','STATUS_CHANGE','V2 ????????? ???????? ???','migration-v2','2026-09-04 04:03:36'),(6,6,NULL,'CANDIDATE','STATUS_CHANGE','최초 탐지','analysis','2026-09-05 11:54:25'),(7,6,'CANDIDATE','POTENTIAL','STATUS_CHANGE','Read-only observation completed; installed package, patches and CVE-specific conditions need verification.','verification','2026-09-06 02:50:27'),(8,6,'POTENTIAL','ERROR','STATUS_CHANGE','The read-only probe failed; no non-vulnerable conclusion can be drawn.','verification','2026-09-06 02:52:44'),(9,6,'ERROR','POTENTIAL','STATUS_CHANGE','Read-only observation completed; installed package, patches and CVE-specific conditions need verification.','verification','2026-09-06 02:53:48'),(10,6,'POTENTIAL','ERROR','STATUS_CHANGE','The read-only probe failed; no non-vulnerable conclusion can be drawn.','verification','2026-09-06 02:57:26'),(11,6,'ERROR','POTENTIAL','STATUS_CHANGE','Read-only observation completed; installed package, patches and CVE-specific conditions need verification.','verification','2026-09-06 02:58:27'),(12,8,NULL,'CANDIDATE','STATUS_CHANGE','최초 탐지','analysis','2026-09-11 13:04:05'),(13,8,'CANDIDATE','POTENTIAL','STATUS_CHANGE','Read-only observation completed; installed package, patches and CVE-specific conditions need verification.','verification','2026-09-11 13:04:50');
/*!40000 ALTER TABLE `remediation_history` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `scan_assets`
--

DROP TABLE IF EXISTS `scan_assets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scan_assets` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `scan_id` bigint unsigned NOT NULL,
  `host_id` bigint unsigned NOT NULL,
  `input_target` varchar(255) NOT NULL,
  `resolution_type` enum('IP','CIDR','HOSTNAME') NOT NULL,
  `result_status` enum('SCANNED','ERROR') NOT NULL,
  `open_port_count` int unsigned NOT NULL DEFAULT '0',
  `error_code` varchar(100) DEFAULT NULL,
  `observed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_scan_assets_scan_host` (`scan_id`,`host_id`),
  KEY `idx_scan_assets_host` (`host_id`),
  KEY `idx_scan_assets_result` (`result_status`),
  CONSTRAINT `fk_scan_assets_host` FOREIGN KEY (`host_id`) REFERENCES `hosts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_scan_assets_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `chk_scan_assets_open_ports` CHECK ((`open_port_count` >= 0))
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `scan_assets`
--

LOCK TABLES `scan_assets` WRITE;
/*!40000 ALTER TABLE `scan_assets` DISABLE KEYS */;
INSERT INTO `scan_assets` VALUES (1,2,2,'127.0.0.1','IP','SCANNED',4,NULL,'2026-09-04 23:08:58'),(2,3,2,'127.0.0.1','IP','SCANNED',2,NULL,'2026-09-04 23:09:06'),(3,4,2,'127.0.0.1','IP','SCANNED',1,NULL,'2026-09-05 11:50:05'),(4,5,2,'127.0.0.1','IP','SCANNED',1,NULL,'2026-09-11 13:01:55'),(5,6,2,'127.0.0.1','IP','SCANNED',7,NULL,'2026-09-11 14:09:25');
/*!40000 ALTER TABLE `scan_assets` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `scan_scopes`
--

DROP TABLE IF EXISTS `scan_scopes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scan_scopes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `scope_uid` varchar(64) NOT NULL,
  `name` varchar(255) NOT NULL,
  `authorization_ref` varchar(255) NOT NULL,
  `approved_by` varchar(255) NOT NULL,
  `valid_from` datetime NOT NULL,
  `valid_until` datetime NOT NULL,
  `allowed_targets` json NOT NULL,
  `max_targets` int unsigned NOT NULL,
  `max_workers` int unsigned NOT NULL,
  `max_ports_per_target` int unsigned NOT NULL,
  `policy_sha256` char(64) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_scan_scopes_uid` (`scope_uid`),
  KEY `idx_scan_scopes_valid_until` (`valid_until`),
  CONSTRAINT `chk_scan_scopes_max_ports` CHECK ((`max_ports_per_target` between 1 and 65535)),
  CONSTRAINT `chk_scan_scopes_max_targets` CHECK ((`max_targets` between 1 and 4096)),
  CONSTRAINT `chk_scan_scopes_max_workers` CHECK ((`max_workers` between 1 and 512)),
  CONSTRAINT `chk_scan_scopes_validity` CHECK ((`valid_until` > `valid_from`))
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `scan_scopes`
--

LOCK TABLES `scan_scopes` WRITE;
/*!40000 ALTER TABLE `scan_scopes` DISABLE KEYS */;
INSERT INTO `scan_scopes` VALUES (1,'local-lab-v1','Local loopback lab','SELF-OWNED-LAB','project-owner','2019-12-31 15:00:00','2099-12-31 14:59:59','[\"127.0.0.1\", \"::1\", \"localhost\"]',16,100,1024,'97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe','2026-09-04 23:08:58','2026-09-04 23:08:58');
/*!40000 ALTER TABLE `scan_scopes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `scans`
--

DROP TABLE IF EXISTS `scans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scans` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `scan_uid` varchar(64) NOT NULL,
  `scope_id` bigint unsigned DEFAULT NULL,
  `target` mediumtext NOT NULL,
  `requested_targets` json DEFAULT NULL,
  `scan_type` varchar(50) NOT NULL,
  `port_range` mediumtext NOT NULL,
  `started_at` datetime NOT NULL,
  `finished_at` datetime DEFAULT NULL,
  `status` enum('QUEUED','RUNNING','COMPLETED','PARTIAL','FAILED') NOT NULL DEFAULT 'QUEUED',
  `config_snapshot` json DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_scans_uid` (`scan_uid`),
  KEY `idx_scans_status` (`status`),
  KEY `idx_scans_started_at` (`started_at`),
  KEY `idx_scans_scope` (`scope_id`),
  CONSTRAINT `fk_scans_scope` FOREIGN KEY (`scope_id`) REFERENCES `scan_scopes` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `scans`
--

LOCK TABLES `scans` WRITE;
/*!40000 ALTER TABLE `scans` DISABLE KEYS */;
INSERT INTO `scans` VALUES (1,'legacy-1',NULL,'43.200.247.45',NULL,'tcp','1-100','2026-03-11 15:52:53','2026-03-11 15:52:54','COMPLETED',NULL,'2026-09-04 04:03:35'),(2,'scan-20260904230831-3c63cbbf',1,'127.0.0.1','[\"127.0.0.1\"]','tcp','1-1024','2026-09-05 08:08:31','2026-09-05 08:08:57','COMPLETED','{\"ports\": \"1-1024\", \"scope\": {\"name\": \"Local loopback lab\", \"scope_uid\": \"local-lab-v1\", \"valid_from\": \"2019-12-31T15:00:00+00:00\", \"approved_by\": \"project-owner\", \"max_targets\": 16, \"max_workers\": 100, \"valid_until\": \"2099-12-31T14:59:59+00:00\", \"policy_sha256\": \"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\", \"allowed_targets\": [\"127.0.0.1\", \"::1\", \"localhost\"], \"authorization_ref\": \"SELF-OWNED-LAB\", \"max_ports_per_target\": 1024}, \"timeout\": 0.5, \"max_workers\": 20, \"service_version_requested\": false}','2026-09-04 23:08:58'),(3,'scan-20260904230905-7a9e3dac',1,'127.0.0.1','[\"127.0.0.1\"]','tcp','22,80,443,3306','2026-09-05 08:09:05','2026-09-05 08:09:06','COMPLETED','{\"ports\": \"22,80,443,3306\", \"scope\": {\"name\": \"Local loopback lab\", \"scope_uid\": \"local-lab-v1\", \"valid_from\": \"2019-12-31T15:00:00+00:00\", \"approved_by\": \"project-owner\", \"max_targets\": 16, \"max_workers\": 100, \"valid_until\": \"2099-12-31T14:59:59+00:00\", \"policy_sha256\": \"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\", \"allowed_targets\": [\"127.0.0.1\", \"::1\", \"localhost\"], \"authorization_ref\": \"SELF-OWNED-LAB\", \"max_ports_per_target\": 1024}, \"timeout\": 0.5, \"max_workers\": 4, \"service_version_requested\": false}','2026-09-04 23:09:06'),(4,'scan-20260905115004-7e7a40e7',1,'127.0.0.1','[\"127.0.0.1\"]','tcp','18080','2026-09-05 20:50:04','2026-09-05 20:50:05','COMPLETED','{\"ports\": \"18080\", \"scope\": {\"name\": \"Local loopback lab\", \"scope_uid\": \"local-lab-v1\", \"valid_from\": \"2019-12-31T15:00:00+00:00\", \"approved_by\": \"project-owner\", \"max_targets\": 16, \"max_workers\": 100, \"valid_until\": \"2099-12-31T14:59:59+00:00\", \"policy_sha256\": \"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\", \"allowed_targets\": [\"127.0.0.1\", \"::1\", \"localhost\"], \"authorization_ref\": \"SELF-OWNED-LAB\", \"max_ports_per_target\": 1024}, \"timeout\": 1.0, \"max_workers\": 100, \"service_version_requested\": true}','2026-09-05 11:50:05'),(5,'scan-20260911130154-af756dfd',1,'127.0.0.1','[\"127.0.0.1\"]','tcp','8081','2026-09-11 22:01:54','2026-09-11 22:01:54','COMPLETED','{\"ports\": \"8081\", \"scope\": {\"name\": \"Local loopback lab\", \"scope_uid\": \"local-lab-v1\", \"valid_from\": \"2019-12-31T15:00:00+00:00\", \"approved_by\": \"project-owner\", \"max_targets\": 16, \"max_workers\": 100, \"valid_until\": \"2099-12-31T14:59:59+00:00\", \"policy_sha256\": \"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\", \"allowed_targets\": [\"127.0.0.1\", \"::1\", \"localhost\"], \"authorization_ref\": \"SELF-OWNED-LAB\", \"max_ports_per_target\": 1024}, \"timeout\": 2.0, \"max_workers\": 2, \"service_version_requested\": true}','2026-09-11 13:01:55'),(6,'scan-20260911140924-607fda54',1,'127.0.0.1','[\"127.0.0.1\"]','tcp','80,3306-3307,5601,9150-9151,9200','2026-09-11 23:09:24','2026-09-11 23:09:24','COMPLETED','{\"ports\": \"80,3306,3307,5601,9150,9151,9200\", \"scope\": {\"name\": \"Local loopback lab\", \"scope_uid\": \"local-lab-v1\", \"valid_from\": \"2019-12-31T15:00:00+00:00\", \"approved_by\": \"project-owner\", \"max_targets\": 16, \"max_workers\": 100, \"valid_until\": \"2099-12-31T14:59:59+00:00\", \"policy_sha256\": \"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\", \"allowed_targets\": [\"127.0.0.1\", \"::1\", \"localhost\"], \"authorization_ref\": \"SELF-OWNED-LAB\", \"max_ports_per_target\": 1024}, \"timeout\": 1.0, \"max_workers\": 100, \"service_version_requested\": true}','2026-09-11 14:09:25');
/*!40000 ALTER TABLE `scans` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vuln_evidence`
--

DROP TABLE IF EXISTS `vuln_evidence`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vuln_evidence` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `vuln_id` bigint unsigned NOT NULL,
  `checker` varchar(100) NOT NULL,
  `evidence_type` enum('HTTP_RESPONSE','SCREENSHOT','NUCLEI','BANNER','MANUAL','ERROR_LOG') NOT NULL,
  `details` text,
  `evidence_path` varchar(500) DEFAULT NULL,
  `sha256` char(64) DEFAULT NULL,
  `collected_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_evidence_vuln` (`vuln_id`),
  KEY `idx_evidence_collected_at` (`collected_at`),
  CONSTRAINT `fk_evidence_vuln` FOREIGN KEY (`vuln_id`) REFERENCES `vulns` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vuln_evidence`
--

LOCK TABLES `vuln_evidence` WRITE;
/*!40000 ALTER TABLE `vuln_evidence` DISABLE KEYS */;
INSERT INTO `vuln_evidence` VALUES (1,6,'day4_mapper','BANNER','{\"affected\":{\"fixed\":\"2.4.51\",\"introduced\":\"2.4.49\"},\"catalog_reviewed_on\":\"2026-09-05\",\"catalog_sha256\":\"e0f73c4ca29c42089cc8978ef00321098c846866b79647e948a360ea31d3ed6a\",\"conditions_to_verify\":[\"Confirm installed package and vendor backports.\",\"Review Alias-like mappings, directory access restrictions and CGI configuration.\"],\"cve_id\":\"CVE-2021-42013\",\"cvss\":null,\"epss\":null,\"fingerprint\":{\"confidence\":\"reported\",\"evidence\":\"Server: Apache/2.4.50\",\"parser_version\":\"day4.1\",\"product\":\"apache_http_server\",\"service\":\"http\",\"source\":\"http_server\",\"version\":\"2.4.50\"},\"host_ip\":\"127.0.0.1\",\"match_reason\":\"apache_http_server 2.4.50: >= 2.4.49 and < 2.4.51\",\"port\":18080,\"port_id\":11,\"product\":\"apache_http_server\",\"protocol\":\"tcp\",\"references\":[\"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013\"],\"risk\":null,\"rule_id\":\"day4:apache:cve-2021-42013\",\"scan_id\":4,\"severity\":\"CRITICAL\",\"severity_basis\":\"Apache vendor advisory rating; not measured host risk\",\"source\":\"day4:apache:cve-2021-42013\",\"status\":\"CANDIDATE\",\"title\":\"Apache HTTP Server incomplete path normalization fix (candidate)\",\"version\":\"2.4.50\"}',NULL,'a1093da4883935daf475145aa05bfbe9655af61db5046e992b726739685259e9','2026-09-05 11:54:25'),(2,6,'Apache42013Verifier','HTTP_RESPONSE','{\"content\":{\"additional_checks\":[\"Confirm installed package and vendor backports.\",\"Review Alias-like mappings, directory access restrictions and CGI configuration.\"],\"checker\":\"Apache42013Verifier\",\"cve_id\":\"CVE-2021-42013\",\"details\":{\"affected\":{\"fixed\":\"2.4.51\",\"introduced\":\"2.4.49\"},\"catalog_sha256\":\"e0f73c4ca29c42089cc8978ef00321098c846866b79647e948a360ea31d3ed6a\",\"condition\":\"advertised_version_in_affected_range\",\"cve_id\":\"CVE-2021-42013\",\"expected_product\":\"apache_http_server\",\"http_status\":200,\"observed_fingerprint\":{\"confidence\":\"reported\",\"evidence\":\"Server: Apache/2.4.50\",\"parser_version\":\"day4.1\",\"product\":\"apache_http_server\",\"service\":\"http\",\"source\":\"http_server\",\"version\":\"2.4.50\"},\"references\":[\"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013\"],\"safe_checks\":[\"tcp_connect\",\"http_head_root_no_redirects\"],\"tls\":\"not_used\",\"verifier_version\":\"day5.1\"},\"error_code\":null,\"evidence_type\":\"HTTP_RESPONSE\",\"reason\":\"Read-only observation completed; installed package, patches and CVE-specific conditions need verification.\",\"result\":\"POTENTIAL\",\"scope\":{\"policy_sha256\":\"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\",\"scope_uid\":\"local-lab-v1\"},\"source\":\"day4:apache:cve-2021-42013\",\"target\":{\"host_ip\":\"127.0.0.1\",\"id\":11,\"input_target\":\"127.0.0.1\",\"port\":18080,\"protocol\":\"tcp\",\"scan_id\":4,\"scan_uid\":\"scan-20260905115004-7e7a40e7\"}},\"first_checked_at\":\"2026-09-06T02:50:27.388910+00:00\",\"last_checked_at\":\"2026-09-06T02:58:27.789445+00:00\",\"observations\":4,\"schema_version\":1}',NULL,'b9fab9cd9834b5311b0ed63864b7c554bf49c5752e15632240d117d8ddf56cda','2026-09-06 02:50:27'),(3,6,'Apache42013Verifier','ERROR_LOG','{\"content\":{\"additional_checks\":[],\"checker\":\"Apache42013Verifier\",\"cve_id\":\"CVE-2021-42013\",\"details\":{\"affected\":{\"fixed\":\"2.4.51\",\"introduced\":\"2.4.49\"},\"catalog_sha256\":\"e0f73c4ca29c42089cc8978ef00321098c846866b79647e948a360ea31d3ed6a\",\"cve_id\":\"CVE-2021-42013\",\"expected_product\":\"apache_http_server\",\"probe_error\":\"ConnectionRefusedError\",\"references\":[\"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013\"],\"safe_checks\":[\"tcp_connect\",\"http_head_root_no_redirects\"],\"tls\":\"not_used\",\"verifier_version\":\"day5.1\"},\"error_code\":\"CONNECTION_ERROR\",\"evidence_type\":\"ERROR_LOG\",\"reason\":\"The read-only probe failed; no non-vulnerable conclusion can be drawn.\",\"result\":\"ERROR\",\"scope\":{\"policy_sha256\":\"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\",\"scope_uid\":\"local-lab-v1\"},\"source\":\"day4:apache:cve-2021-42013\",\"target\":{\"host_ip\":\"127.0.0.1\",\"id\":11,\"input_target\":\"127.0.0.1\",\"port\":18080,\"protocol\":\"tcp\",\"scan_id\":4,\"scan_uid\":\"scan-20260905115004-7e7a40e7\"}},\"first_checked_at\":\"2026-09-06T02:52:44.406615+00:00\",\"last_checked_at\":\"2026-09-06T02:57:40.306150+00:00\",\"observations\":3,\"schema_version\":1}',NULL,'2cc4d6816e6e595551912f85373ee5e1173caf31fbaabf8c85856e4922e8b053','2026-09-06 02:52:44'),(4,8,'day4_mapper','BANNER','{\"affected\":{\"fixed\":\"2.4.51\",\"introduced\":\"2.4.49\"},\"catalog_reviewed_on\":\"2026-09-05\",\"catalog_sha256\":\"e0f73c4ca29c42089cc8978ef00321098c846866b79647e948a360ea31d3ed6a\",\"conditions_to_verify\":[\"Confirm installed package and vendor backports.\",\"Review Alias-like mappings, directory access restrictions and CGI configuration.\"],\"cve_id\":\"CVE-2021-42013\",\"cvss\":null,\"epss\":null,\"fingerprint\":{\"confidence\":\"reported\",\"evidence\":\"Server: Apache/2.4.50\",\"parser_version\":\"day4.1\",\"product\":\"apache_http_server\",\"service\":\"http\",\"source\":\"http_server\",\"version\":\"2.4.50\"},\"host_ip\":\"127.0.0.1\",\"match_reason\":\"apache_http_server 2.4.50: >= 2.4.49 and < 2.4.51\",\"port\":8081,\"port_id\":12,\"product\":\"apache_http_server\",\"protocol\":\"tcp\",\"references\":[\"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013\"],\"risk\":null,\"rule_id\":\"day4:apache:cve-2021-42013\",\"scan_id\":5,\"severity\":\"CRITICAL\",\"severity_basis\":\"Apache vendor advisory rating; not measured host risk\",\"source\":\"day4:apache:cve-2021-42013\",\"status\":\"CANDIDATE\",\"title\":\"Apache HTTP Server incomplete path normalization fix (candidate)\",\"version\":\"2.4.50\"}',NULL,'ea8a2b54cdbcda1ad2fd9262833b7230f4bc16d3d74f14fd4a2b792d6ac5f58d','2026-09-11 13:04:05'),(5,8,'Apache42013Verifier','HTTP_RESPONSE','{\"content\":{\"additional_checks\":[\"Confirm installed package and vendor backports.\",\"Review Alias-like mappings, directory access restrictions and CGI configuration.\"],\"checker\":\"Apache42013Verifier\",\"cve_id\":\"CVE-2021-42013\",\"details\":{\"affected\":{\"fixed\":\"2.4.51\",\"introduced\":\"2.4.49\"},\"catalog_sha256\":\"e0f73c4ca29c42089cc8978ef00321098c846866b79647e948a360ea31d3ed6a\",\"condition\":\"advertised_version_in_affected_range\",\"cve_id\":\"CVE-2021-42013\",\"expected_product\":\"apache_http_server\",\"http_status\":200,\"observed_fingerprint\":{\"confidence\":\"reported\",\"evidence\":\"Server: Apache/2.4.50\",\"parser_version\":\"day4.1\",\"product\":\"apache_http_server\",\"service\":\"http\",\"source\":\"http_server\",\"version\":\"2.4.50\"},\"references\":[\"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013\"],\"safe_checks\":[\"tcp_connect\",\"http_head_root_no_redirects\"],\"tls\":\"not_used\",\"verifier_version\":\"day5.1\"},\"error_code\":null,\"evidence_type\":\"HTTP_RESPONSE\",\"reason\":\"Read-only observation completed; installed package, patches and CVE-specific conditions need verification.\",\"result\":\"POTENTIAL\",\"scope\":{\"policy_sha256\":\"97352069dfd1b26ebc0533e8e4acfa85ac3ed8a427b6c9f1bd3ff75218271bbe\",\"scope_uid\":\"local-lab-v1\"},\"source\":\"day4:apache:cve-2021-42013\",\"target\":{\"host_ip\":\"127.0.0.1\",\"id\":12,\"input_target\":\"127.0.0.1\",\"port\":8081,\"protocol\":\"tcp\",\"scan_id\":5,\"scan_uid\":\"scan-20260911130154-af756dfd\"}},\"first_checked_at\":\"2026-09-11T13:04:50.872408+00:00\",\"last_checked_at\":\"2026-09-11T13:05:41.441696+00:00\",\"observations\":2,\"schema_version\":1}',NULL,'263a983007360043ae9a0992e87e12ea35dd0401d3a0d68f850e2d65b558a04f','2026-09-11 13:04:50');
/*!40000 ALTER TABLE `vuln_evidence` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vuln_risk_assessments`
--

DROP TABLE IF EXISTS `vuln_risk_assessments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vuln_risk_assessments` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `vuln_id` bigint unsigned NOT NULL,
  `methodology_id` varchar(64) NOT NULL,
  `methodology_sha256` char(64) NOT NULL,
  `vuln_status` enum('CANDIDATE','POTENTIAL','CONFIRMED','NOT_APPLICABLE','FALSE_POSITIVE','RETEST_REQUIRED','CLOSED','ERROR') NOT NULL,
  `action` enum('VERIFY','REMEDIATE','RETEST') NOT NULL,
  `priority` enum('P1','P2','P3','P4','UNASSESSED') NOT NULL,
  `cvss_score` decimal(4,2) DEFAULT NULL,
  `cvss_version` varchar(16) DEFAULT NULL,
  `cvss_vector` varchar(255) DEFAULT NULL,
  `cvss_source` varchar(255) DEFAULT NULL,
  `epss_score` decimal(10,9) DEFAULT NULL,
  `epss_percentile` decimal(10,9) DEFAULT NULL,
  `epss_date` date DEFAULT NULL,
  `kev_status` enum('KNOWN_EXPLOITED','NOT_LISTED','UNKNOWN') NOT NULL,
  `kev_date_added` date DEFAULT NULL,
  `asset_criticality` enum('LOW','MEDIUM','HIGH','CRITICAL','UNASSIGNED') NOT NULL,
  `internet_exposed` tinyint(1) NOT NULL,
  `handles_personal_data` tinyint(1) NOT NULL,
  `details` json NOT NULL,
  `input_sha256` char(64) NOT NULL,
  `first_assessed_at` datetime NOT NULL,
  `last_assessed_at` datetime NOT NULL,
  `observations` int unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_risk_vuln_method_input` (`vuln_id`,`methodology_id`,`input_sha256`),
  KEY `idx_risk_priority` (`priority`),
  KEY `idx_risk_last_assessed` (`last_assessed_at`),
  CONSTRAINT `fk_risk_vuln` FOREIGN KEY (`vuln_id`) REFERENCES `vulns` (`id`) ON DELETE CASCADE,
  CONSTRAINT `chk_risk_action` CHECK ((((`vuln_status` in (_utf8mb4'CANDIDATE',_utf8mb4'POTENTIAL',_utf8mb4'ERROR')) and (`action` = _utf8mb4'VERIFY')) or ((`vuln_status` = _utf8mb4'CONFIRMED') and (`action` = _utf8mb4'REMEDIATE')) or ((`vuln_status` = _utf8mb4'RETEST_REQUIRED') and (`action` = _utf8mb4'RETEST')))),
  CONSTRAINT `chk_risk_cvss` CHECK ((`cvss_score` between 0 and 10)),
  CONSTRAINT `chk_risk_epss` CHECK ((`epss_score` between 0 and 1)),
  CONSTRAINT `chk_risk_flags` CHECK (((`internet_exposed` in (0,1)) and (`handles_personal_data` in (0,1)))),
  CONSTRAINT `chk_risk_observations` CHECK ((`observations` >= 1)),
  CONSTRAINT `chk_risk_percentile` CHECK ((`epss_percentile` between 0 and 1)),
  CONSTRAINT `chk_risk_times` CHECK ((`last_assessed_at` >= `first_assessed_at`))
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vuln_risk_assessments`
--

LOCK TABLES `vuln_risk_assessments` WRITE;
/*!40000 ALTER TABLE `vuln_risk_assessments` DISABLE KEYS */;
INSERT INTO `vuln_risk_assessments` VALUES (1,6,'day6-priority-v1','65b537f7371244fe8c750c1ae1f567607546eb2dea56c61e1d471932bb654a26','POTENTIAL','VERIFY','P2',9.80,'3.1','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','nvd@nist.gov',0.999640000,0.999750000,'2026-09-06','KNOWN_EXPLOITED','2021-11-03','HIGH',0,0,'{\"kev\": {\"state\": \"OK\", \"errors\": [], \"source\": \"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\", \"status\": \"KNOWN_EXPLOITED\", \"product\": \"HTTP Server\", \"due_date\": \"2021-11-17\", \"date_added\": \"2021-11-03\", \"error_code\": null, \"date_released\": \"2026-09-04T16:47:03.5197Z\", \"vendor_project\": \"Apache\", \"catalog_version\": \"2026.09.04\", \"required_action\": \"Apply updates per vendor instructions.\", \"known_ransomware_campaign_use\": \"Known\"}, \"cvss\": {\"score\": 9.8, \"state\": \"OK\", \"source\": \"nvd@nist.gov\", \"vector\": \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\", \"version\": \"3.1\", \"endpoint\": \"https://services.nvd.nist.gov/rest/json/cves/2.0\", \"severity\": \"CRITICAL\", \"error_code\": null, \"metric_type\": \"Primary\"}, \"epss\": {\"date\": \"2026-09-06\", \"epss\": 0.99964, \"score\": 0.99964, \"state\": \"OK\", \"source\": \"https://api.first.org/data/v1/epss\", \"error_code\": null, \"percentile\": 0.99975}, \"action\": \"VERIFY\", \"cve_id\": \"CVE-2021-42013\", \"reason\": \"CISA lists this CVE as known exploited. Critical CVSS score and high or critical asset importance.\", \"source\": \"day4:apache:cve-2021-42013\", \"endpoint\": {\"port\": 18080, \"port_id\": 11, \"scan_id\": 4, \"protocol\": \"tcp\"}, \"priority\": \"P2\", \"incomplete\": false, \"asset_context\": {\"owner\": \"security-team\", \"host_id\": 2, \"host_ip\": \"127.0.0.1\", \"asset_uid\": \"9cd48a9c-bc17-4bbb-81ce-419f2bef8306\", \"asset_name\": \"day3-local-lab\", \"asset_type\": \"SERVER\", \"criticality\": \"HIGH\", \"environment\": \"TEST\", \"business_unit\": null, \"internet_exposed\": false, \"lifecycle_status\": \"ACTIVE\", \"data_classification\": \"INTERNAL\", \"handles_personal_data\": false}, \"base_priority\": \"P2\", \"matched_rules\": [\"P2_KEV\", \"P2_CVSS_CRITICAL_IMPORTANT_ASSET\"], \"source_errors\": [], \"current_status\": \"POTENTIAL\", \"methodology_id\": \"day6-priority-v1\", \"missing_inputs\": [], \"schema_version\": 1, \"methodology_sha256\": \"65b537f7371244fe8c750c1ae1f567607546eb2dea56c61e1d471932bb654a26\"}','11b57161700a6838215f8491d0721f1ea2a118a95276705d9aabe2f80e7eaf5a','2026-09-07 02:00:02','2026-09-07 02:00:17',2),(2,8,'day6-priority-v1','65b537f7371244fe8c750c1ae1f567607546eb2dea56c61e1d471932bb654a26','POTENTIAL','VERIFY','P2',9.80,'3.1','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','nvd@nist.gov',0.999640000,0.999750000,'2026-09-10','KNOWN_EXPLOITED','2021-11-03','HIGH',0,0,'{\"kev\": {\"state\": \"OK\", \"errors\": [], \"source\": \"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\", \"status\": \"KNOWN_EXPLOITED\", \"product\": \"HTTP Server\", \"due_date\": \"2021-11-17\", \"date_added\": \"2021-11-03\", \"error_code\": null, \"date_released\": \"2026-09-10T19:00:05.1949Z\", \"vendor_project\": \"Apache\", \"catalog_version\": \"2026.09.10\", \"required_action\": \"Apply updates per vendor instructions.\", \"known_ransomware_campaign_use\": \"Known\"}, \"cvss\": {\"score\": 9.8, \"state\": \"OK\", \"source\": \"nvd@nist.gov\", \"vector\": \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\", \"version\": \"3.1\", \"endpoint\": \"https://services.nvd.nist.gov/rest/json/cves/2.0\", \"severity\": \"CRITICAL\", \"error_code\": null, \"metric_type\": \"Primary\"}, \"epss\": {\"date\": \"2026-09-10\", \"epss\": 0.99964, \"score\": 0.99964, \"state\": \"OK\", \"source\": \"https://api.first.org/data/v1/epss\", \"error_code\": null, \"percentile\": 0.99975}, \"action\": \"VERIFY\", \"cve_id\": \"CVE-2021-42013\", \"reason\": \"CISA lists this CVE as known exploited. Critical CVSS score and high or critical asset importance.\", \"source\": \"day4:apache:cve-2021-42013\", \"endpoint\": {\"port\": 8081, \"port_id\": 12, \"scan_id\": 5, \"protocol\": \"tcp\"}, \"priority\": \"P2\", \"incomplete\": false, \"asset_context\": {\"owner\": \"security-team\", \"host_id\": 2, \"host_ip\": \"127.0.0.1\", \"asset_uid\": \"9cd48a9c-bc17-4bbb-81ce-419f2bef8306\", \"asset_name\": \"day3-local-lab\", \"asset_type\": \"SERVER\", \"criticality\": \"HIGH\", \"environment\": \"TEST\", \"business_unit\": null, \"internet_exposed\": false, \"lifecycle_status\": \"ACTIVE\", \"data_classification\": \"INTERNAL\", \"handles_personal_data\": false}, \"base_priority\": \"P2\", \"matched_rules\": [\"P2_KEV\", \"P2_CVSS_CRITICAL_IMPORTANT_ASSET\"], \"source_errors\": [], \"current_status\": \"POTENTIAL\", \"methodology_id\": \"day6-priority-v1\", \"missing_inputs\": [], \"schema_version\": 1, \"methodology_sha256\": \"65b537f7371244fe8c750c1ae1f567607546eb2dea56c61e1d471932bb654a26\"}','b317a3fc24b24a92a0c3e10260011e547fb1082c1ea9605a6047ed4c6fee8d98','2026-09-11 13:07:32','2026-09-11 13:08:16',2);
/*!40000 ALTER TABLE `vuln_risk_assessments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vulns`
--

DROP TABLE IF EXISTS `vulns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulns` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `port_id` bigint unsigned NOT NULL,
  `cve_id` varchar(50) NOT NULL,
  `title` varchar(255) NOT NULL,
  `severity` enum('INFO','LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'INFO',
  `epss` decimal(10,9) DEFAULT NULL,
  `cvss` decimal(4,2) DEFAULT NULL,
  `risk` decimal(6,5) DEFAULT NULL,
  `status` enum('CANDIDATE','POTENTIAL','CONFIRMED','NOT_APPLICABLE','FALSE_POSITIVE','RETEST_REQUIRED','CLOSED','ERROR') NOT NULL DEFAULT 'CANDIDATE',
  `source` varchar(100) NOT NULL DEFAULT 'unknown',
  `first_detected_at` datetime NOT NULL,
  `last_detected_at` datetime NOT NULL,
  `verified_at` datetime DEFAULT NULL,
  `closed_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_vulns_port_cve_source` (`port_id`,`cve_id`,`source`),
  KEY `idx_vulns_port` (`port_id`),
  KEY `idx_vulns_cve` (`cve_id`),
  KEY `idx_vulns_severity` (`severity`),
  KEY `idx_vulns_status` (`status`),
  KEY `idx_vulns_last_detected` (`last_detected_at`),
  CONSTRAINT `fk_vulns_port` FOREIGN KEY (`port_id`) REFERENCES `ports` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vulns`
--

LOCK TABLES `vulns` WRITE;
/*!40000 ALTER TABLE `vulns` DISABLE KEYS */;
INSERT INTO `vulns` VALUES (1,1,'CVE-1999-0497','Anonymous FTP writable','LOW',0.006100000,0.00,0.00200,'POTENTIAL','rule_ftp_vsftpd_3_0_5','2026-03-11 06:53:14','2026-03-11 06:53:14',NULL,NULL,'2026-03-11 06:53:14','2026-03-11 06:53:14'),(2,2,'CVE-2023-25136','OpenSSH 8.x Vulnerability','MEDIUM',0.904800000,6.50,0.72600,'POTENTIAL','rule_ssh_openssh_8_9','2026-03-11 06:53:14','2026-03-11 06:53:14',NULL,NULL,'2026-03-11 06:53:14','2026-03-11 06:53:14'),(3,3,'CVE-1999-0613','Telnet Service Exposure','HIGH',0.006100000,0.00,0.00200,'POTENTIAL','rule_telnet_default','2026-03-11 06:53:14','2026-03-11 06:53:14',NULL,NULL,'2026-03-11 06:53:14','2026-03-11 06:53:14'),(4,4,'CVE-2012-1823','DVWA SQL Injection (mapped to PHP CGI RCE CVE-2012-1823)','HIGH',0.943900000,9.80,0.96900,'POTENTIAL','rule_dvwa_sqli','2026-03-11 06:53:14','2026-03-11 06:53:14',NULL,NULL,'2026-03-11 06:53:14','2026-03-11 06:53:14'),(5,4,'CVE-2020-2551','DVWA File Upload Vulnerability (mapped to WebLogic CVE-2020-2551)','CRITICAL',0.944100000,9.80,0.96900,'POTENTIAL','rule_dvwa_fileupload','2026-03-11 06:53:14','2026-03-11 06:53:14',NULL,NULL,'2026-03-11 06:53:14','2026-03-11 06:53:14'),(6,11,'CVE-2021-42013','Apache HTTP Server incomplete path normalization fix (candidate)','CRITICAL',0.999640000,9.80,NULL,'POTENTIAL','day4:apache:cve-2021-42013','2026-09-05 11:54:25','2026-09-05 11:55:33',NULL,NULL,'2026-09-05 11:54:25','2026-09-06 02:58:28'),(8,12,'CVE-2021-42013','Apache HTTP Server incomplete path normalization fix (candidate)','CRITICAL',0.999640000,9.80,NULL,'POTENTIAL','day4:apache:cve-2021-42013','2026-09-11 13:04:05','2026-09-11 13:04:05',NULL,NULL,'2026-09-11 13:04:05','2026-09-11 13:04:51');
/*!40000 ALTER TABLE `vulns` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping routines for database 'port_scan'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-09-14  6:29:50
