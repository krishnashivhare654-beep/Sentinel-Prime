from flask import Flask, render_template, jsonify, request, send_file
import os
import time
import base64
from fpdf import FPDF
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')

# Vercel fix: Ensure /tmp directory exists for file processing
TMP_DIR = '/tmp'
if not os.path.exists(TMP_DIR):
    os.makedirs(TMP_DIR)

app.config['UPLOAD_FOLDER'] = TMP_DIR

# --- Key Generation Logic (AES-256) ---
def get_key(password):
    password_bytes = password.encode()
    salt = b'sentinel_prime_salt_fixed' # Fixed salt for decryption consistency
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/vault', methods=['POST'])
def vault_operation():
    operation = request.form.get('operation')
    password = request.form.get('password')
    file = request.files.get('file')

    if not file or not password:
        return jsonify({"status": "error", "message": "Missing Data"}), 400

    try:
        file_data = file.read()
        fernet = Fernet(get_key(password))
        
        if operation == 'encrypt':
            processed_data = fernet.encrypt(file_data)
            output_name = f"LOCKED_{file.filename}"
        else:
            processed_data = fernet.decrypt(file_data)
            output_name = f"UNLOCKED_{file.filename}"

        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_name)
        with open(output_path, 'wb') as f:
            f.write(processed_data)
            
        return send_file(output_path, as_attachment=True)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid Key or File!"}), 400

@app.route('/api/download_report')
def download_report():
    report_name = "Sentinel_Prime_Audit.pdf"
    report_path = os.path.join(TMP_DIR, report_name)
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL PRIME // SECURITY AUDIT", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Generated On: {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, txt="Developer: Krishna Shivhare (VIT Bhopal)", ln=True)
    pdf.cell(200, 10, txt="System Status: Operational", ln=True)
    pdf.output(report_path)
    
    return send_file(report_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)