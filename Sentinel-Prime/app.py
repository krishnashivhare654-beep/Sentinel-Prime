# --- ROUTES (Add after @app.route('/') ) ---

@app.route('/api/traffic')
def get_traffic():
    try:
        conn = get_db_connection()
        traffic = conn.execute('SELECT * FROM traffic ORDER BY id DESC LIMIT 20').fetchall()
        data = [dict(row) for row in traffic]
        conn.close()
        return jsonify(data)
    except:
        return jsonify([])

@app.route('/api/devices')
def get_devices():
    try:
        conn = get_db_connection()
        devices = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
        data = [dict(row) for row in devices]
        conn.close()
        return jsonify(data)
    except:
        return jsonify([])

@app.route('/api/stats')
def get_stats():
    # LinkedIn portfolio ke liye visual stats
    return jsonify({"TCP": 65, "UDP": 20, "ICMP": 15})

@app.route('/api/download_report')
def download_report():
    path = create_pdf_report()
    return send_file(path, as_attachment=True)

@app.route('/api/scan')
def trigger_scan():
    if PLATFORM_SUPPORT:
        threading.Thread(target=scan_network, args=("10.106.204.0/24",), daemon=True).start()
        return jsonify({"status": "Scanning Started"})
    return jsonify({"status": "Scan not supported on this platform"})

# --- START SERVER ---
if __name__ == '__main__':
    # Auto-start scan only if on local machine
    if PLATFORM_SUPPORT:
        threading.Thread(target=scan_network, args=("10.106.204.0/24",), daemon=True).start()
    
    print(f"[*] Sentinel Prime Core: Online (Support: {PLATFORM_SUPPORT})")
    socketio.run(app, debug=True, port=5000)