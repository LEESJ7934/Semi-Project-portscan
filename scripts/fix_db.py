# scripts/fix_severity.py
from db.db_client import get_connection


def fix_enum():
    conn = get_connection()
    cursor = conn.cursor()
    try:
        print("[*] Updating 'severity' column in 'vulns' table to include 'INFO'...")

        # severity 컬럼의 ENUM 정의를 수정하여 'INFO'를 추가합니다.
        sql = "ALTER TABLE vulns MODIFY COLUMN severity ENUM('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL;"

        cursor.execute(sql)
        conn.commit()
        print("[+] Severity ENUM Updated Successfully! Now accepting 'INFO'.")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    fix_enum()
