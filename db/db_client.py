# db/db_client.py

import os
from pathlib import Path

from dotenv import load_dotenv
import mysql.connector
from mysql.connector import MySQLConnection


# 프로젝트 루트 기준으로 docker/env/db.env 불러오기
BASE_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = BASE_DIR / "docker" / "env" / "db.env"
if ENV_PATH.exists():
    load_dotenv(ENV_PATH)


def get_connection() -> MySQLConnection:
    """
    MySQL 커넥션을 반환.
    VSCode에서 실행하든, 나중에 Docker 컨테이너에서 실행하든
    환경변수(DB_HOST, DB_PORT, DB_USER, ...)만 맞으면 동작하도록 고정.
    """
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER", "portuser")
    password = os.getenv("DB_PASSWORD", "portpass")
    db_name = os.getenv("DB_NAME", "port_scan")

    conn = mysql.connector.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        autocommit=False,  # 트랜잭션은 코드에서 관리
    )
    return conn
