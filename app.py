from flask import Flask, render_template, jsonify, request, send_file
import os

app = Flask(__name__, 
            template_folder='web/templates', 
            static_folder='web/static')

# Root Route
@app.route('/')
def index():
    return render_template('index.html')

# Dashboard APIs
@app.route('/api/traffic')
def get_traffic():
    return jsonify([{"timestamp": "Live", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "protocol": "TCP"}])

@app.route('/api/stats')
def get_stats():
    return jsonify({"TCP": 70, "UDP": 20, "ICMP": 10, "status": "Sentinel Prime Online"})

@app.route('/api/devices')
def get_devices():
    return jsonify([{"ip": "10.106.204.1", "status": "UP", "ports": "80, 443"}])

if __name__ == '__main__':
    app.run(debug=True)