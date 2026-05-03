from flask import Flask, render_template, jsonify, request, send_file
import os
import time
from fpdf import FPDF
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
app.config['UPLOAD_FOLDER'] = '/tmp'

# --- Key Generation from Password ---
def get_key(password):
    password = password.encode()
    salt = b'sentinel_prime_salt' # Fixed salt for demo
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/vault', methods=['POST'])
def vault_operation():
    operation = request.form.get('operation') # 'encrypt' or 'decrypt'
    password = request.form.get('password')
    file = request.files.get('file')

    if not file or not password:
        return jsonify({"status": "error", "message": "File and Key required!"}), 400

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

@app.route('/api/scan')
def initiate_scan():
    # Simulated Network Scan
    time.sleep(2)
    return jsonify({
        "status": "success",
        "devices": [
            {"ip": "10.106.204.1", "status": "ONLINE", "ports": "80, 443", "risk": "LOW"},
            {"ip": "10.106.204.45", "status": "ONLINE", "ports": "8080", "risk": "MEDIUM"}
        ]
    })

@app.route('/api/download_report')
def download_report():
    # PDF Logic (Same as before)
    return jsonify({"status": "PDF generated under /tmp"})

if __name__ == '__main__':
    app.run(debug=True)