from flask import Flask, render_template, jsonify, request, send_file
import os
import time
from fpdf import FPDF

app = Flask(__name__, 
            template_folder='web/templates', 
            static_folder='web/static')

# --- PDF GENERATOR LOGIC ---
def generate_security_report():
    report_name = "Sentinel_Prime_Report.pdf"
    report_path = os.path.join("/tmp", report_name) 
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL PRIME // SECURITY AUDIT REPORT", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Report Generated On: {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, txt="System Status: ONLINE", ln=True)
    pdf.ln(10)
    
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Discovered Devices:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="- 10.106.204.1 (Online, Ports: 80, 443) - Risk: LOW", ln=True)
    pdf.cell(200, 10, txt="- 10.106.204.45 (Online, Ports: 8080) - Risk: MEDIUM", ln=True)
    
    pdf.output(report_path)
    return report_path

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    data = request.json
    file_path = data.get('path')
    password = data.get('password')
    
    if not file_path or not password:
        return jsonify({"status": "error", "message": "Missing Path or Key!"}), 400
    
    # Simulation logic for frontend feedback
    return jsonify({
        "status": "success", 
        "message": f"SUCCESS: {os.path.basename(file_path)} has been secured."
    })

@app.route('/api/download_report')
def download_report():
    try:
        path = generate_security_report()
        return send_file(path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic')
def get_traffic():
    return jsonify([
        {"time": time.strftime("%H:%M:%S"), "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "protocol": "TCP"}
    ])

if __name__ == '__main__':
    app.run(debug=True)