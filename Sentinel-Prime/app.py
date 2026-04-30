from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import sqlite3
import os
import threading

# Import core modules
from core.scout import scan_network
from core.vault import encrypt_file, decrypt_file
from core.watchtower import analyze_threats

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
socketio = SocketIO(app)

# Database path configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'logs/sentinel.db')

# --- RISK INTELLIGENCE DATABASE ---
# Port numbers se potential vulnerabilities identify karne ke liye
RISK_MAP = {
    "445": {"level": "CRITICAL", "info": "SMB Vulnerability (EternalBlue Risk)"},
    "135": {"level": "MEDIUM", "info": "RPC Endpoint Mapper"},
    "3000": {"level": "LOW", "info": "Development Server Node.js"},
    "53": {"level": "LOW", "info": "Standard DNS Service"},
    "80": {"level": "MEDIUM", "info": "Unsecured HTTP Protocol"},
    "3389": {"level": "HIGH", "info": "Remote Desktop Protocol (RDP) Exposed"}
}

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/traffic')
def get_traffic():
    conn = get_db_connection()
    try:
        # Latest 20 packets filter
        traffic = conn.execute('SELECT * FROM traffic ORDER BY id DESC LIMIT 20').fetchall()
    except:
        traffic = []
    conn.close()
    return jsonify([dict(row) for row in traffic])

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    try:
        # Protocol distribution analytics ke liye
        stats = conn.execute('SELECT protocol, COUNT(*) as count FROM traffic GROUP BY protocol').fetchall()
    except:
        stats = []
    conn.close()
    return jsonify({row['protocol']: row['count'] for row in stats})

@app.route('/api/devices')
def get_devices():
    conn = get_db_connection()
    try:
        devices = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    except:
        devices = []
    conn.close()
    return jsonify([dict(row) for row in devices])

@app.route('/api/alerts')
def get_alerts():
    # Watchtower module se live threats fetch karta hai
    alerts = analyze_threats()
    return jsonify(alerts)

@app.route('/api/risk_assessment')
def risk_assessment():
    conn = get_db_connection()
    try:
        devices = conn.execute('SELECT ip, ports FROM devices').fetchall()
        assessment = []
        for dev in devices:
            ports = dev['ports'].split(',')
            threats = [RISK_MAP[p] for p in ports if p in RISK_MAP]
            assessment.append({"ip": dev['ip'], "threats": threats})
    except:
        assessment = []
    conn.close()
    return jsonify(assessment)

@app.route('/api/scan')
def trigger_scan():
    # Background thread mein network scan start karta hai (VIT Bhopal subnet)
    threading.Thread(target=scan_network, args=("10.106.204.0/24",), daemon=True).start()
    return jsonify({"status": "Scout Engine Engaged: Scanning Subnet..."})

# --- VAULT-X CRYPTO ROUTES ---

@app.route('/api/vault/encrypt', methods=['POST'])
def vault_encrypt():
    data = request.json
    success, msg = encrypt_file(data['path'], data['password'])
    return jsonify({"success": success, "message": msg})

@app.route('/api/vault/decrypt', methods=['POST'])
def vault_decrypt():
    data = request.json
    success, msg = decrypt_file(data['path'], data['password'])
    return jsonify({"success": success, "message": msg})

if __name__ == '__main__':
    # Flask application launch
    print("[*] Sentinel Prime Core: Online")
    socketio.run(app, debug=True, port=5000)