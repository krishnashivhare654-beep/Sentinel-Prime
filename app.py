from flask import Flask, render_template, jsonify, request, send_file
import os
import time
from fpdf import FPDF # PDF generate karne ke liye

app = Flask(__name__, 
            template_folder='web/templates', 
            static_folder='web/static')

# --- PDF GENERATOR LOGIC ---
def generate_security_report():
    report_name = "Sentinel_Prime_Report.pdf"
    report_path = os.path.join("/tmp", report_name) # Vercel par /tmp folder hi writable hota hai
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL PRIME // SECURITY AUDIT REPORT", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Report Generated On: {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, txt="System Status: ONLINE (Operational)", ln=True)
    pdf.cell(200, 10, txt="Security Mode: AES-256 GCM (Vault-X Core)", ln=True)
    pdf.ln(10)
    
    # Fake Scan Data for the report
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Discovered Devices:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="- 10.106.204.1 (Online, Ports: 80, 443)", ln=True)
    pdf.cell(200, 10, txt="- 10.106.204.45 (Online, Ports: 8080)", ln=True)
    
    pdf.output(report_path)
    return report_path

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/download_report')
def download_report():
    try:
        path = generate_security_report()
        return send_file(path, as_attachment=True) # Ye user ko file prompt dega
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic')
def get_traffic():
    return jsonify([
        {"time": time.strftime("%H:%M:%S"), "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "protocol": "TCP"},
        {"time": time.strftime("%H:%M:%S"), "src_ip": "192.168.1.12", "dst_ip": "104.21.43.11", "protocol": "UDP"}
    ])

if __name__ == '__main__':
    app.run(debug=True)