# analyzer/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import logging
import io
import hashlib
from datetime import datetime, timezone
from phishing_analyzer import analyze_single_email, analyze_csv_batch
from malware_analyzer import analyze_malware_in_email_content, analyze_attachment_file, extract_attachments_info
import email
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

def generate_pdf_report(combined_results, filename_prefix="ePhish_Forensic_Report"):
    """
    Generate a PDF report from combined phishing/malware analysis results.
    Includes Top-N URLs section.
    Saves to the shared /app/reports directory.
    """
    # Create a filename with timestamp
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}.pdf"
    # Create a file path in the shared reports directory
    temp_pdf_path = os.path.join("/app/reports", filename)

    doc = SimpleDocTemplate(temp_pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        alignment=1, # Center alignment
    )
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=20,
    )
    normal_style = styles['Normal']

    # Title
    title = Paragraph("ePhish - Digital Forensic Analysis Report", title_style)
    elements.append(title)
    elements.append(Spacer(1, 20))

    # Summary Section
    elements.append(Paragraph("Executive Summary", subtitle_style))
    total_emails = 0
    total_phishing = 0
    total_malware = 0
    all_urls = []
    all_social_eng = []

    if 'csv_analysis' in combined_results:
        # Batch analysis
        summary_data = combined_results['csv_analysis']
        total_emails = summary_data.get('total_rows', 0)
        total_phishing = summary_data.get('phishing_count', 0)
        # For malware, we might need to iterate through rows if malware was checked per email
        for row in summary_data.get('rows', []):
            if row.get('malware_analysis', {}).get('is_malware'):
                total_malware += 1
            all_urls.extend(row.get('urls', []))
            all_social_eng.extend(row.get('social_engineering', []))
    else:
        # Single analysis
        total_emails = 1
        if combined_results.get('phishing'):
            total_phishing = 1
        if combined_results.get('malware_analysis', {}).get('is_malware'):
            total_malware = 1
        all_urls = combined_results.get('urls', [])
        all_social_eng = combined_results.get('social_engineering', [])

    summary_text = f"""
    Total Emails Analyzed: {total_emails}<br/>
    Phishing Detected: {total_phishing}<br/>
    Malware Detected: {total_malware}<br/>
    """
    elements.append(Paragraph(summary_text, normal_style))
    elements.append(Spacer(1, 20))

    # Top-N URLs Section
    elements.append(Paragraph("Top Suspicious URLs", subtitle_style))
    from collections import Counter
    url_counts = Counter(all_urls)
    top_urls = url_counts.most_common(10) # Get top 10

    if top_urls:
        table_data = [["Rank", "URL", "Count"]]
        for i, (url, count) in enumerate(top_urls, 1):
             # Truncate very long URLs for readability
            truncated_url = url if len(url) <= 60 else url[:57] + "..."
            table_data.append([str(i), truncated_url, str(count)])

        url_table = Table(table_data, colWidths=[0.5*inch, 4*inch, 0.8*inch])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(url_table)
    else:
        elements.append(Paragraph("No URLs found in the analyzed content.", normal_style))
    elements.append(Spacer(1, 20))

    # Detailed Results Section (only if single email or small batch)
    if 'csv_analysis' not in combined_results:
        # Single Email Analysis
        elements.append(Paragraph("Detailed Analysis Result", subtitle_style))
        detail_parts = [
            f"<b>Email ID:</b> {combined_results.get('email_id', 'unknown')}",
            f"<b>Phishing:</b> {combined_results.get('phishing', False)}",
            f"<b>Confidence (Phishing):</b> {combined_results.get('confidence', 0):.4f}",
            f"<b>Severity:</b> {combined_results.get('severity', 'N/A')}",
            f"<b>Explanation:</b> {combined_results.get('explanation', 'N/A')}",
        ]
        if combined_results.get('malware_analysis'):
            ma = combined_results['malware_analysis']
            detail_parts.extend([
                f"<b>Malware (Email Content):</b> {ma.get('is_malware', False)}",
                f"<b>Malware Confidence:</b> {ma.get('malware_confidence', 0):.4f}",
                f"<b>Malware Family:</b> {ma.get('malware_family', 'N/A')}",
                f"<b>Analysis Method:</b> {ma.get('analysis_method', 'N/A')}",
            ])
        detail_text = "<br/>".join(detail_parts)
        elements.append(Paragraph(detail_text, normal_style))

    elif combined_results['csv_analysis'].get('total_rows', 0) <= 20: # Only show detailed rows if batch is small
        elements.append(Paragraph("Detailed Batch Results (First 20)", subtitle_style))
        rows = combined_results['csv_analysis'].get('rows', [])
        for i, row in enumerate(rows[:20]): # Show first 20
            elements.append(Paragraph(f"--- Email {i+1}: {row.get('email_id', 'unknown')} ---", styles['Heading3']))
            detail_parts = [
                f"<b>Phishing:</b> {row.get('phishing', False)}",
                f"<b>Confidence:</b> {row.get('confidence', 0):.4f}",
                f"<b>Severity:</b> {row.get('severity', 'N/A')}",
                f"<b>Social Eng.:</b> {', '.join(row.get('social_engineering', []))}",
            ]
            if row.get('malware_analysis'):
                ma = row['malware_analysis']
                detail_parts.extend([
                    f"<b>Malware:</b> {ma.get('is_malware', False)}",
                    f"<b>Malware Conf.:</b> {ma.get('malware_confidence', 0):.4f}",
                ])
            detail_text = "<br/>".join(detail_parts)
            elements.append(Paragraph(detail_text, normal_style))
            elements.append(Spacer(1, 10))

    doc.build(elements)
    # Return just the filename, not the full path
    return filename


def analyze_combined(email_content, email_id=None):
    """
    Perform both phishing and malware analysis on a single email content.
    Returns a combined result dictionary.
    """
    # 1. Phishing Analysis
    phishing_result = analyze_single_email(email_content, email_id)

    # 2. Malware Analysis (on email content itself)
    # Extract attachment info if possible (this is basic, improve if needed)
    attachments_info = extract_attachments_info(email_content)
    malware_result = analyze_malware_in_email_content(email_content, attachments_info)

    # Combine results
    combined_result = phishing_result.copy() # Start with phishing results
    combined_result['malware_analysis'] = malware_result # Add malware analysis under a sub-key

    return combined_result

@app.route('/analyze/phishing', methods=['POST'])
def analyze_phishing():
    """Endpoint for combined phishing and malware analysis."""
    try:
        logger.info("Received combined analysis request")
        
        if 'file' in request.files:
            file = request.files['file']
            filename = file.filename.lower()
            logger.info(f"Processing file: {filename}")

            if filename.endswith('.csv'):
                # Analisis Batch CSV
                content = file.read().decode('utf-8')
                batch_result = analyze_csv_batch(content)

                # Proses batch untuk tambahkan malware analysis ke setiap row (opsional, bisa di-skip untuk performansi)
                # Kita hanya buat laporan PDF untuk batch
                pdf_filename = generate_pdf_report(batch_result, f"ePhish_Batch_Report_{filename.replace('.csv', '')}")
                # Store the relative path from the shared directory perspective for the backend
                batch_result['report_pdf_path'] = pdf_filename # Store only the filename

                return jsonify(batch_result)

            elif filename.endswith(('.eml', '.msg')):
                # Analisis Email Tunggal dari File
                content = file.read().decode('utf-8')
                # Parse email untuk mendapatkan subject, body
                try:
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
                    result = analyze_combined(email_text, email_id=filename)
                    
                    # Generate PDF for single email
                    pdf_filename = generate_pdf_report(result, f"ePhish_Analysis_Report_{filename.replace('.eml', '').replace('.msg', '')}")
                    # Store the relative path from the shared directory perspective for the backend
                    result['report_pdf_path'] = pdf_filename # Store only the filename
                    
                    logger.info(f"Combined analysis completed: phishing={result.get('phishing')}, malware={result.get('malware_analysis', {}).get('is_malware')}")
                    return jsonify(result)
                except Exception as e:
                    logger.error(f"Error parsing email file: {e}")
                    return jsonify({"error": f"Failed to parse email file: {str(e)}"}), 400

        else:
            # JSON payload (for compatibility or direct API call)
            data = request.get_json()
            email_content = data.get('email_content', '')
            email_id = data.get('email_id', 'json_request')
            result = analyze_combined(email_content, email_id)
            
            # Generate PDF for JSON input
            pdf_filename = generate_pdf_report(result, f"ePhish_JSON_Analysis_Report")
            # Store the relative path from the shared directory perspective for the backend
            result['report_pdf_path'] = pdf_filename # Store only the filename
            
            logger.info(f"Combined JSON analysis completed: phishing={result.get('phishing')}, malware={result.get('malware_analysis', {}).get('is_malware')}")
            return jsonify(result)

    except Exception as e:
        logger.error(f"Error in analyze_phishing: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/analyze/malware', methods=['POST']) # Tetap ada untuk kompatibilitas jika diperlukan
def analyze_malware_endpoint():
    """Endpoint for standalone malware analysis (e.g., attachment file)."""
    try:
        logger.info("Received standalone malware analysis request")
        
        if 'file' in request.files:
            file = request.files['file']
            filename = file.filename.lower()
            logger.info(f"Processing malware file: {filename}")

            # Simpan file sementara
            temp_path = os.path.join(tempfile.gettempdir(), file.filename)
            file.save(temp_path)

            # Analisis file attachment langsung
            result = analyze_attachment_file(temp_path)

            # Hapus file sementara
            try:
                os.remove(temp_path)
            except:
                pass # Jika gagal hapus, lanjutkan saja
            return jsonify(result)

        else:
            # JSON payload untuk konten email mentah
            data = request.get_json()
            email_content = data.get('email_content', '')
            attachments_info = data.get('attachments_info', [])
            result = analyze_malware_in_email_content(email_content, attachments_info)
            return jsonify(result)

    except Exception as e:
        logger.error(f"Error in analyze_malware_endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "analyzer"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
