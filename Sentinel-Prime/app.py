from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO
import sqlite3
import os
import threading
import time
from fpdf import FPDF

# Vercel Compatibility Layer
try:
    from core.scout import scan_network
    from core.watchtower import analyze_threats
    PLATFORM_SUPPORT = True
except ImportError:
    PLATFORM_SUPPORT = False

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
socketio = SocketIO(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'logs/sentinel.db')
REPORT_PATH = os.path.join(os.path.dirname(__file__), 'logs/security_report.pdf')

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- PDF GENERATOR ---
def create_pdf_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL PRIME // SECURITY REPORT", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    try:
        conn = get_db_connection()
        devices = conn.execute('SELECT COUNT(*) as count FROM devices').fetchone()
        pdf.cell(200, 10, txt=f"Total Devices Discovered: {devices['count']}", ln=True)
        conn.close()
    except:
        pdf.cell(200, 10, txt="Database empty or in Demo Mode.", ln=True)
    pdf.output(REPORT_PATH)
    return REPORT_PATH

# --- ROUTES ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/traffic')
def get_traffic():
    try:
        conn = get_db_connection()
        traffic = conn.execute('SELECT * FROM traffic ORDER BY id DESC LIMIT 20').fetchall()
        data = [dict(row) for row in traffic]
        conn.close()
        return jsonify(data)
    except: return jsonify([])

@app.route('/api/devices')
def get_devices():
    try:
        conn = get_db_connection()
        devices = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
        data = [dict(row) for row in devices]
        conn.close()
        return jsonify(data)
    except: return jsonify([])

@app.route('/api/stats')
def get_stats():
    return jsonify({"TCP": 65, "UDP": 20, "ICMP": 15}) # Demo Stats for UI

@app.route('/api/download_report')
def download_report():
    path = create_pdf_report()
    return send_file(path, as_attachment=True)

@app.route('/api/alerts')
def get_alerts():
    if PLATFORM_SUPPORT: return jsonify(analyze_threats())
    return jsonify([])

if __name__ == '__main__':
    if PLATFORM_SUPPORT:
        threading.Thread(target=scan_network, args=("10.106.204.0/24",), daemon=True).start()
    
    print(f"[*] Sentinel Prime Core: Online (Support: {PLATFORM_SUPPORT})")
    socketio.run(app, debug=True, port=5000)