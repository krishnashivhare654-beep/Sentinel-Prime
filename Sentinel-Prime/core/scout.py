import nmap
import sqlite3
import os
import datetime

# Database Path
DB_PATH = os.path.join(os.path.dirname(__file__), '../logs/sentinel.db')
# Nmap Path (Fixed for your system)
NMAP_EXE_PATH = r'C:\Program Files (x86)\Nmap\nmap.exe'

def init_scout_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # IP ko UNIQUE rakha hai taaki duplicates na aayein
    c.execute('''CREATE TABLE IF NOT EXISTS devices 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  ip TEXT UNIQUE, 
                  hostname TEXT, 
                  status TEXT, 
                  ports TEXT, 
                  last_seen TEXT)''')
    conn.commit()
    conn.close()

def scan_network(network_range):
    init_scout_db()
    try:
        nm = nmap.PortScanner(nmap_search_path=(NMAP_EXE_PATH,))
        print(f"[*] Scout Engine: Scanning {network_range}...")
        nm.scan(hosts=network_range, arguments='-F')
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        for host in nm.all_hosts():
            ip = host
            hostname = nm[host].hostname()
            status = nm[host].state()
            ports = ",".join([str(p) for p in nm[host].all_tcp()])
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # INSERT OR REPLACE duplicates ko handle karega
            c.execute("INSERT OR REPLACE INTO devices (ip, hostname, status, ports, last_seen) VALUES (?,?,?,?,?)",
                      (ip, hostname, status, ports, ts))
            print(f"[+] Discovered: {ip} | Status: {status}")

        conn.commit()
        conn.close()
        print("[*] Scan Complete.")
    except Exception as e:
        print(f"[-] Scout Error: {e}")

if __name__ == "__main__":
    scan_network("10.106.204.0/24")