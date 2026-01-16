# analyzer/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
from phishing_analyzer import analyze_single_email, analyze_csv_batch
from malware_analyzer import analyze_malware_in_email_content, analyze_attachment_file, extract_attachments_info
import email # Import library email bawaan Python untuk parsing .eml/.msg

app = Flask(__name__)
CORS(app)

@app.route('/analyze/phishing', methods=['POST'])
def analyze_phishing():
    """Endpoint untuk analisis phishing email tunggal atau batch CSV."""
    try:
        if 'file' in request.files:
            # Upload file (CSV, EML, MSG)
            file = request.files['file']
            filename = file.filename.lower()

            if filename.endswith('.csv'):
                # Analisis Batch CSV
                content = file.read().decode('utf-8')
                result = analyze_csv_batch(content)
                return jsonify(result)

            elif filename.endswith(('.eml', '.msg')):
                # Analisis Email Tunggal dari File
                content = file.read().decode('utf-8')
                # Parse email untuk mendapatkan subject, body
                msg = email.message_from_string(content)
                subject = msg.get('Subject', '')
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                else:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

                email_text = subject + " " + body
                result = analyze_single_email(email_text, email_id=filename)
                return jsonify(result)

        else:
            # JSON payload (untuk kompatibilitas lama atau API langsung)
            data = request.get_json()
            email_content = data.get('email_content', '')
            email_id = data.get('email_id', 'json_request')
            result = analyze_single_email(email_content, email_id)
            return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze/malware', methods=['POST'])
def analyze_malware():
    """Endpoint untuk analisis malware dalam email atau attachment."""
    try:
        if 'file' in request.files:
            file = request.files['file']
            filename = file.filename.lower()

            # Simpan file sementara
            temp_path = os.path.join(tempfile.gettempdir(), file.filename)
            file.save(temp_path)

            if filename.endswith(('.eml', '.msg')):
                # Analisis malware dalam konten email
                with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
                    email_content = f.read()
                # Ekstrak info attachment jika bisa
                attachments_info = extract_attachments_info(email_content)
                result = analyze_malware_in_email_content(email_content, attachments_info)
            else:
                # Analisis file attachment langsung
                result = analyze_attachment_file(temp_path)

            # Hapus file sementara
            os.remove(temp_path)
            return jsonify(result)

        else:
            # JSON payload untuk konten email mentah
            data = request.get_json()
            email_content = data.get('email_content', '')
            attachments_info = data.get('attachments_info', [])
            result = analyze_malware_in_email_content(email_content, attachments_info)
            return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "analyzer"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
