from db.db_client import get_connection

def clear_tables():
    tables = ["vulns", "ports", "hosts", "scans"]

    with get_connection() as conn:
        with conn.cursor() as cur:
            # 외래키 체크 OFF
            cur.execute("SET FOREIGN_KEY_CHECKS = 0;")

            for t in tables:
                print(f"[!] Truncating {t} ...")
                cur.execute(f"TRUNCATE TABLE {t};")

            # 외래키 체크 ON
            cur.execute("SET FOREIGN_KEY_CHECKS = 1;")

        conn.commit()

    print("[+] All tables cleared (with FK disabled safely).")


if __name__ == "__main__":
    clear_tables()