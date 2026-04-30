import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), '../logs/sentinel.db')

def clean_old_logs():
    print("[*] Janitor: Cleaning logs older than 24 hours...")
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # 24 hours se purana data delete karo
        c.execute("DELETE FROM traffic WHERE timestamp < datetime('now', '-1 day')")
        conn.commit()
        conn.close()
        print("[*] Janitor: Cleanup complete.")
    except Exception as e:
        print(f"[-] Janitor Error: {e}")

if __name__ == "__main__":
    while True:
        clean_old_logs()
        time.sleep(3600) # Har ghante check karega