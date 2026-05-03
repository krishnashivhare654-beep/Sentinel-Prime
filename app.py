from flask import Flask, render_template, jsonify, request
import os
import time
import random

# Explicit path setting for Vercel
app = Flask(__name__, 
            template_folder='web/templates', 
            static_folder='web/static')

@app.route('/')
def index():
    # Direct access to dashboard to prevent 500 error
    return render_template('index.html')

@app.route('/api/traffic')
def get_traffic():
    return jsonify([
        {"time": time.strftime("%H:%M:%S"), "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "protocol": "TCP"},
        {"time": time.strftime("%H:%M:%S"), "src_ip": "192.168.1.12", "dst_ip": "104.21.43.11", "protocol": "UDP"}
    ])

@app.route('/api/stats')
def get_stats():
    return jsonify({"TCP": 65, "UDP": 25, "ICMP": 10})

@app.route('/api/darkweb/monitor')
def darkweb_monitor():
    leaks = [
        {"source": "Pastebin", "status": "Leak Detected", "severity": "High"},
        {"source": "RaidForums", "status": "No Match", "severity": "Low"},
        {"source": "DeepDump", "status": "Credentials Found", "severity": "Critical"}
    ]
    return jsonify(random.choice(leaks))

if __name__ == '__main__':
    app.run(debug=True)