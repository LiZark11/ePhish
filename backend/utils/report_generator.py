from weasyprint import HTML, CSS
import tempfile
import os
from datetime import datetime

def generate_forensic_report(report_type, analysis_data):
    """Generate professional forensic PDF report"""
    
    if report_type == "email":
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }}
                .section {{ margin: 20px 0; }}
                .highlight {{ background-color: #f0f0f0; padding: 10px; border-left: 4px solid #007acc; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>FORENSIC EMAIL ANALYSIS REPORT</h1>
                <p>Case ID: EPH-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}</p>
                <p>Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Analysis Summary</h2>
                <table>
                    <tr><td>Filename</td><td>{getattr(analysis_data, 'filename', 'N/A')}</td></tr>
                    <tr><td>Phishing Score</td><td>{getattr(analysis_data, 'phishing_score', 'N/A')}</td></tr>
                    <tr><td>Is Phishing</td><td>{'YES' if getattr(analysis_data, 'is_phishing', False) else 'NO'}</td></tr>
                    <tr><td>Confidence</td><td>{getattr(analysis_data, 'confidence', 'N/A')}%</td></tr>
                    <tr><td>Verdict</td><td>{getattr(analysis_data, 'verdict', 'N/A').upper()}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Suspicious Indicators</h2>
                <ul>
                    {''.join([f'<li>{url}</li>' for url in getattr(analysis_data, 'suspicious_urls', [])])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Social Engineering Patterns</h2>
                <ul>
                    {''.join([f'<li>{indicator}</li>' for indicator in getattr(analysis_data, 'social_engineering_indicators', [])])}
                </ul>
            </div>
            
            <div class="section highlight">
                <h3>Recommendations</h3>
                <p>Based on analysis, appropriate incident response actions should be taken.</p>
            </div>
        </body>
        </html>
        """
    
    elif report_type == "malware":
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }}
                .section {{ margin: 20px 0; }}
                .highlight {{ background-color: #f0f0f0; padding: 10px; border-left: 4px solid #cc0000; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>FORENSIC MALWARE ANALYSIS REPORT</h1>
                <p>Case ID: EPM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}</p>
                <p>Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Analysis Summary</h2>
                <table>
                    <tr><td>Filename</td><td>{getattr(analysis_data, 'filename', 'N/A')}</td></tr>
                    <tr><td>File Hash</td><td>{getattr(analysis_data, 'file_hash', 'N/A')}</td></tr>
                    <tr><td>Is Malware</td><td>{'YES' if getattr(analysis_data, 'is_malware', False) else 'NO'}</td></tr>
                    <tr><td>Malware Family</td><td>{getattr(analysis_data, 'malware_family', 'N/A')}</td></tr>
                    <tr><td>Confidence</td><td>{getattr(analysis_data, 'malware_confidence', 'N/A')}%</td></tr>
                    <tr><td>Entropy</td><td>{getattr(analysis_data, 'entropy', 'N/A')}</td></tr>
                    <tr><td>Verdict</td><td>{getattr(analysis_data, 'verdict', 'N/A').upper()}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>YARA Rule Matches</h2>
                <ul>
                    {''.join([f'<li>{match}</li>' for match in getattr(analysis_data, 'yara_matches', [])])}
                </ul>
            </div>
            
            <div class="section highlight">
                <h3>Recommendations</h3>
                <p>Immediate isolation required. Conduct advanced malware analysis and threat hunting.</p>
            </div>
        </body>
        </html>
        """
    
    # Generate PDF
    pdf_path = f"/tmp/forensic_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    try:
        HTML(string=html_content).write_pdf(pdf_path)
        return pdf_path
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None