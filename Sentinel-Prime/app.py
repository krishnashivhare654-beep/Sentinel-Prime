from flask import Flask, render_template, jsonify, request, send_file
import os

# Explicit folder paths taaki Vercel ko index.html mil jaye
app = Flask(__name__, 
            template_folder='web/templates', 
            static_folder='web/static')

# Root Route (Isse dashboard khulega)
@app.route('/')
def index():
    return render_template('index.html')

# Demo APIs for Dashboard
@app.route('/api/traffic')
def get_traffic():
    return jsonify([
        {"timestamp": "2026-05-03 17:15:01", "src_ip": "10.16.71.2", "dst_ip": "192.168.1.5", "protocol": "TCP"},
        {"timestamp": "2026-05-03 17:15:15", "src_ip": "10.16.71.5", "dst_ip": "172.16.0.1", "protocol": "UDP"}
    ])

@app.route('/api/stats')
def get_stats():
    return jsonify({"TCP": 70, "UDP": 20, "ICMP": 10})

@app.route('/api/devices')
def get_devices():
    return jsonify([
        {"ip": "10.106.204.1", "status": "UP", "ports": "80, 443"},
        {"ip": "10.106.204.10", "status": "UP", "ports": "22, 3389"}
    ])

if __name__ == '__main__':
    app.run(debug=True)