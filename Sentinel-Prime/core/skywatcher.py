from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import datetime
import os

# Database initialization
DB_PATH = os.path.join(os.path.dirname(__file__), '../logs/sentinel.db')

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS traffic 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, 
                  src_ip TEXT, dst_ip TEXT, protocol TEXT, length INTEGER, risk_level TEXT)''')
    conn.commit()
    conn.close()

def analyze_risk(packet):
    # Basic Threat Logic: Agar koi unusual packet size ya specific flags hain
    # (Hum yahan baad mein advanced AI logic integrate karenge)
    if packet.haslayer(TCP) and packet[TCP].flags == 0x02: # SYN Scan detect
        return "MEDIUM"
    return "LOW"

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP"
        length = len(packet)
        risk = analyze_risk(packet)
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Save to SQLite
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO traffic (timestamp, src_ip, dst_ip, protocol, length, risk_level) VALUES (?,?,?,?,?,?)",
                      (ts, src, dst, proto, length, risk))
            conn.commit()
            conn.close()
            print(f"[*] {ts} | Captured {proto} from {src} -> Risk: {risk}")
        except Exception as e:
            print(f"Error logging packet: {e}")

def run_skywatcher():
    init_db()
    print("[*] SkyWatcher Sentinel Active... Deep Packet Inspection Started.")
    # store=0 means we don't keep packets in RAM, saving memory
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    run_skywatcher()