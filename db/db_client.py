import os
from pathlib import Path

import mysql.connector
from dotenv import load_dotenv
from mysql.connector import MySQLConnection


# 프로젝트 루트의 .env를 불러옵니다.
# .env는 .gitignore에 등록되어 GitHub에 올라가지 않습니다.
BASE_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = BASE_DIR / ".env"

if ENV_PATH.exists():
    load_dotenv(ENV_PATH)


def get_connection() -> MySQLConnection:
    """환경변수에 저장된 설정으로 MySQL에 연결합니다."""

    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME", "port_scan")

    required_values = {
        "DB_USER": user,
        "DB_PASSWORD": password,
    }

    missing_values = [
        name for name, value in required_values.items() if not value
    ]

    if missing_values:
        missing_names = ", ".join(missing_values)
        raise RuntimeError(
            f"필수 환경변수가 없습니다: {missing_names}. "
            f"프로젝트 루트의 .env 파일을 확인하세요."
        )

    return mysql.connector.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        autocommit=False,
    )


class DBClient:
    def __init__(self):
        self.conn = get_connection()
        self.cursor = self.conn.cursor(dictionary=True)

    def fetch_all(self, query, params=None):
        self.cursor.execute(query, params or ())
        return self.cursor.fetchall()

    def execute(self, query, params=None):
        self.cursor.execute(query, params or ())
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()