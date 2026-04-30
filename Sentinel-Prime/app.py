from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO
import sqlite3
import os
import threading
import time
from fpdf import FPDF

# Core Module Imports
from core.scout import scan_network
from core.vault import encrypt_file, decrypt_file
from core.watchtower import analyze_threats

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
socketio = SocketIO(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'logs/sentinel.db')
REPORT_PATH = os.path.join(os.path.dirname(__file__), 'logs/security_report.pdf')

RISK_MAP = {
    "445": {"level": "CRITICAL", "info": "SMB Vulnerability (EternalBlue Risk)"},
    "135": {"level": "MEDIUM", "info": "RPC Endpoint Mapper"},
    "3000": {"level": "LOW", "info": "Development Server Node.js"},
    "53": {"level": "LOW", "info": "Standard DNS Service"},
    "80": {"level": "MEDIUM", "info": "Unsecured HTTP Protocol"},
    "3389": {"level": "HIGH", "info": "RDP Exposed"}
}

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- PDF GENERATOR LOGIC ---
def create_pdf_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL PRIME // SECURITY EXECUTIVE REPORT", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", size=12)
    conn = get_db_connection()
    
    # Section 1: Network Summary
    devices = conn.execute('SELECT COUNT(*) as count FROM devices').fetchone()
    pdf.cell(200, 10, txt=f"Total Devices Discovered: {devices['count']}", ln=True)
    
    # Section 2: Recent Threats
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Detected Threats (Last 24h):", ln=True)
    pdf.set_font("Arial", size=10)
    alerts = analyze_threats()
    if not alerts:
        pdf.cell(200, 10, txt="No immediate threats detected.", ln=True)
    for alert in alerts:
        pdf.cell(200, 10, txt=f"- {alert['msg']}", ln=True)
        
    conn.close()
    pdf.output(REPORT_PATH)
    return REPORT_PATH

# --- ROUTES ---

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/traffic')
def get_traffic():
    conn = get_db_connection()
    try: traffic = conn.execute('SELECT * FROM traffic ORDER BY id DESC LIMIT 20').fetchall()
    except: traffic = []
    conn.close()
    return jsonify([dict(row) for row in traffic])

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    try: stats = conn.execute('SELECT protocol, COUNT(*) as count FROM traffic GROUP BY protocol').fetchall()
    except: stats = []
    conn.close()
    return jsonify({row['protocol']: row['count'] for row in stats})

@app.route('/api/devices')
def get_devices():
    conn = get_db_connection()
    try: devices = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    except: devices = []
    conn.close()
    return jsonify([dict(row) for row in devices])

@app.route('/api/download_report')
def download_report():
    path = create_pdf_report()
    return send_file(path, as_attachment=True)

@app.route('/api/risk_assessment')
def risk_assessment():
    conn = get_db_connection()
    try:
        devices = conn.execute('SELECT ip, ports FROM devices').fetchall()
        assessment = []
        for dev in devices:
            ports = str(dev['ports']).split(',')
            threats = [RISK_MAP[p] for p in ports if p in RISK_MAP]
            assessment.append({"ip": dev['ip'], "threats": threats})
    except: assessment = []
    conn.close()
    return jsonify(assessment)

@app.route('/api/scan')
def trigger_scan():
    threading.Thread(target=scan_network, args=("10.106.204.0/24",), daemon=True).start()
    return jsonify({"status": "Manual Scan Started"})

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
    # Start background threads
    threading.Thread(target=scan_network, args=("10.106.204.0/24",), daemon=True).start()
    print("[*] Sentinel Prime Core: Online & Monitoring")
    socketio.run(app, debug=True, port=5000)