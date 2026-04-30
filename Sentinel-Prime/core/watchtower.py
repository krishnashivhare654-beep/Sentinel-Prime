import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '../logs/sentinel.db')

def analyze_threats():
    if not os.path.exists(DB_PATH):
        return []
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    alerts = []

    try:
        # DOS DETECTION: Kisi IP ne pichle 30 seconds mein 100 se zyada packets bheje?
        query = '''SELECT src_ip, COUNT(*) as packet_count 
                   FROM traffic 
                   WHERE timestamp >= datetime('now', '-30 seconds')
                   GROUP BY src_ip 
                   HAVING packet_count > 100'''
        suspicious_ips = c.execute(query).fetchall()
        
        for row in suspicious_ips:
            alerts.append({
                "type": "POTENTIAL_DOS",
                "ip": row['src_ip'],
                "msg": f"High Traffic: {row['packet_count']} pkts/30s from {row['src_ip']}"
            })
    except Exception as e:
        print(f"Watchtower Error: {e}")

    conn.close()
    return alerts