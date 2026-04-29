from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import sqlite3
import os
import threading
from core.scout import scan_network
from core.vault import encrypt_file, decrypt_file

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
socketio = SocketIO(app)
DB_PATH = os.path.join(os.path.dirname(__file__), 'logs/sentinel.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/traffic')
def get_traffic():
    conn = get_db_connection()
    try: traffic = conn.execute('SELECT * FROM traffic ORDER BY id DESC LIMIT 20').fetchall()
    except: traffic = []
    conn.close()
    return jsonify([dict(row) for row in traffic])

@app.route('/api/devices')
def get_devices():
    conn = get_db_connection()
    try: devices = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    except: devices = []
    conn.close()
    return jsonify([dict(row) for row in devices])

@app.route('/api/scan')
def trigger_scan():
    threading.Thread(target=scan_network, args=("10.106.204.0/24",), daemon=True).start()
    return jsonify({"status": "Scan started"})

# --- VAULT ROUTES ---
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
    socketio.run(app, debug=True, port=5000)