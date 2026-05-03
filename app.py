from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
import os
import time
import random

app = Flask(__name__, 
            template_folder='web/templates', 
            static_folder='web/static')

app.secret_key = 'sentinel_prime_key_2026' #

# --- LOGIN LOGIC (Feature #3) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Admin credentials for your portfolio
        if username == "admin" and password == "sentinel@2026":
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# --- DASHBOARD ROUTES ---
@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')

# --- APIS FOR DASHBOARD (Feature #2) ---
@app.route('/api/traffic')
def get_traffic():
    return jsonify([
        {"time": time.strftime("%H:%M:%S"), "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "protocol": "TCP"},
        {"time": time.strftime("%H:%M:%S"), "src_ip": "192.168.1.12", "dst_ip": "104.21.43.11", "protocol": "UDP"}
    ])

@app.route('/api/stats')
def get_stats():
    return jsonify({"TCP": 65, "UDP": 25, "ICMP": 10})

@app.route('/api/devices')
def get_devices():
    return jsonify([
        {"ip": "10.106.204.1", "status": "ONLINE", "ports": "80, 443"},
        {"ip": "10.106.204.45", "status": "ONLINE", "ports": "8080"}
    ])

# Dark Web Monitor Simulation
@app.route('/api/darkweb/monitor')
def darkweb_monitor():
    leaks = [
        {"source": "Pastebin", "status": "Leak Detected", "severity": "High"},
        {"source": "RaidForums", "status": "No Match", "severity": "Low"},
        {"source": "DeepDump", "status": "Credentials Found", "severity": "Critical"}
    ]
    return jsonify(random.choice(leaks))

# --- VAULT-X & SCAN ---
@app.route('/api/vault/encrypt', methods=['POST'])
def encrypt():
    return jsonify({"success": True, "message": "AES-256 Encryption successful."})

@app.route('/api/initiate_scan', methods=['POST'])
def start_scan():
    return jsonify({"status": "Scan initiated on 10.106.204.0/24"})

if __name__ == '__main__':
    app.run(debug=True)