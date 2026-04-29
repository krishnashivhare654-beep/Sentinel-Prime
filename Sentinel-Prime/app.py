from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import sqlite3
import os
import threading
from core.scout import scan_network

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
socketio = SocketIO(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'logs/sentinel.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/traffic')
def get_traffic():
    conn = get_db_connection()
    traffic = conn.execute('SELECT * FROM traffic ORDER BY id DESC LIMIT 20').fetchall()
    conn.close()
    return jsonify([dict(row) for row in traffic])

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    stats = conn.execute('SELECT protocol, COUNT(*) as count FROM traffic GROUP BY protocol').fetchall()
    conn.close()
    return jsonify({row['protocol']: row['count'] for row in stats})

@app.route('/api/devices')
def get_devices():
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    conn.close()
    return jsonify([dict(row) for row in devices])

@app.route('/api/scan')
def trigger_scan():
    thread = threading.Thread(target=scan_network, args=("10.106.204.0/24",))
    thread.daemon = True
    thread.start()
    return jsonify({"status": "Scan initiated in background"})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)