# backend/main.py
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import os
from typing import Optional
import requests
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, JSON, Float, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
import time
import logging
import pandas as pd
import uuid
import html

# --- Import untuk PDF ---
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic Model
class AIExplainRequest(BaseModel):
    query: str
    analysis_data: Optional[dict] = {}

# Database setup with retry logic
def create_db_engine():
    max_retries = 10
    for attempt in range(max_retries):
        try:
            DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@mysql-db:3306/ephish_db")
            engine = create_engine(DATABASE_URL, pool_pre_ping=True)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Database connection successful")
            return engine
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                raise e
            time.sleep(5)

engine = None
SessionLocal = None
Base = declarative_base()

def init_db():
    global engine, SessionLocal
    engine = create_db_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

# Database Models
class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255))
    content = Column(Text)
    phishing_score = Column(Float)
    is_phishing = Column(Boolean, default=False)
    confidence = Column(Float)
    suspicious_urls = Column(JSON)
    social_engineering_indicators = Column(JSON)
    verdict = Column(String(50))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class MalwareAnalysis(Base):
    __tablename__ = "malware_analyses"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255))
    file_hash = Column(String(64))
    is_malware = Column(Boolean, default=False)
    malware_family = Column(String(100))
    malware_confidence = Column(Float)
    entropy = Column(Float)
    yara_matches = Column(JSON)
    verdict = Column(String(50))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class CsvAnalysis(Base):
    __tablename__ = "csv_analyses"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255))
    total_rows = Column(Integer)
    phishing_count = Column(Integer)
    clean_count = Column(Integer)
    analysis_results = Column(JSON)
    verdict = Column(String(50))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

app = FastAPI(title="ePhish Backend API", version="1.0.0")

# Mount the shared reports directory as static files
app.mount("/reports", StaticFiles(directory="/app/reports"), name="reports")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

# =========================================================
# PDF GENERATION FUNCTIONS (FORMAT PERSIS COLAB / REQUEST)
# =========================================================
def clean_text(text, max_length=200):
    # Cegah nilai NaN dari Pandas muncul sebagai teks "nan"
    if text is None or str(text).lower() == 'nan':
        text = "-"
    text = str(text)
    text = html.escape(text)
    text = text[:max_length]
    text = text.replace("\n", "<br/>")
    return text

def generate_forensic_pdf_from_analysis_results(df_results, filename_prefix="ePhish_Forensic_Report"):
    reports_dir = "/app/reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    unique_filename = f"{filename_prefix}_{timestamp}_{uuid.uuid4().hex[:8]}.pdf"
    full_path = os.path.join(reports_dir, unique_filename)
    
    doc = SimpleDocTemplate(full_path, pagesize=A4, rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    title = Paragraph("<b>ePhish – Digital Forensic Email Analysis Report</b>", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 20))
    
    # Iterate Emails
    for idx, row in df_results.iterrows():
        email_id = clean_text(row.get("email_id", "-"))
        phishing = "YES" if row.get("phishing", False) else "NO"
        severity = clean_text(row.get("severity", "-"))
        confidence = clean_text(row.get("confidence", "-"))
        se = clean_text(row.get("social_engineering", "-"))
        urls = clean_text(row.get("urls", "-"), 150) # Diperbesar max_length-nya untuk URL panjang
        explanation = clean_text(row.get("explanation", "-"))
        
        # Header per Email
        header = Paragraph(f"<b>Email Evidence #{email_id}</b>", styles["Heading2"])
        elements.append(header)
        elements.append(Spacer(1, 8))
        
        # Table Content (Key-Value)
        table_data = [
            [Paragraph("<b>Email ID</b>", styles["BodyText"]), Paragraph(email_id, styles["BodyText"])],
            [Paragraph("<b>Phishing</b>", styles["BodyText"]), Paragraph(phishing, styles["BodyText"])],
            [Paragraph("<b>Severity</b>", styles["BodyText"]), Paragraph(severity, styles["BodyText"])],
            [Paragraph("<b>Confidence</b>", styles["BodyText"]), Paragraph(confidence, styles["BodyText"])],
            [Paragraph("<b>Social Engineering</b>", styles["BodyText"]), Paragraph(se, styles["BodyText"])],
            [Paragraph("<b>URL</b>", styles["BodyText"]), Paragraph(urls, styles["BodyText"])],
            [Paragraph("<b>Explanation</b>", styles["BodyText"]), Paragraph(explanation, styles["BodyText"])]
        ]
        
        table = Table(table_data, colWidths=[140, 380]) # Disesuaikan lebarnya agar pas di A4
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke), # Kolom kiri abu-abu
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),   # Kolom kiri Bold
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),        # Kolom kanan Regular
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),             # Wrap text otomatis
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 15))
        
        # PAGE BREAK EVERY 5 EMAILS (Sesuai request format Colab)
        if (idx + 1) % 5 == 0:
            elements.append(PageBreak())
            
    doc.build(elements)
    return unique_filename

# =========================================================
# ENDPOINTS
# =========================================================
@app.post("/api/email/analyze")
async def analyze_email(file: UploadFile = File(...)):
    try:
        logger.info(f"Received combined analysis request for file: {file.filename}")
        filename = file.filename.lower()
        content = await file.read()

        analyzer_url = os.getenv("ANALYZER_URL", "http://analyzer:5000")

        if filename.endswith('.csv'):
            files = {"file": (file.filename, content, file.content_type)}
            response = requests.post(f"{analyzer_url}/analyze/phishing", files=files, timeout=43200)
        elif filename.endswith(('.eml', '.msg')):
            files = {"file": (file.filename, content, file.content_type)}
            response = requests.post(f"{analyzer_url}/analyze/phishing", files=files, timeout=300)
        else:
            email_content = content.decode('utf-8')
            response = requests.post(f"{analyzer_url}/analyze/phishing", json={"email_content": email_content}, timeout=300)

        if response.status_code != 200:
            error_detail = response.text if response.text else "Unknown error"
            raise HTTPException(status_code=500, detail=f"Analyzer service error: {error_detail}")

        analysis_result = response.json()
        logger.info(f"Analyzer response received, verdict: {analysis_result.get('verdict', 'unknown')}")

        # --- GENERATE PDF REPORT (DENGAN BATASAN 100 BARIS) ---
        try:
            # Cek apakah ada key 'rows' dan itu adalah list (Ciri khas data batch CSV)
            if 'rows' in analysis_result and isinstance(analysis_result['rows'], list):
                total_rows = len(analysis_result['rows'])
                logger.info(f"✅ Mode BATCH CSV terdeteksi. Jumlah baris: {total_rows}")
                
                # 🔥 BATASAN: Maksimal 100 baris untuk PDF agar file tidak meledak
                MAX_PDF_ROWS = 100
                rows_for_pdf = analysis_result['rows'][:MAX_PDF_ROWS]
                df_for_pdf = pd.DataFrame(rows_for_pdf)
                
                if total_rows > MAX_PDF_ROWS:
                    logger.info(f"⚠️ Data terlalu banyak ({total_rows} baris). PDF dibatasi hanya {MAX_PDF_ROWS} baris pertama.")
            else:
                logger.info(f"⚠️ Mode SINGLE EMAIL terdeteksi.")
                df_for_pdf = pd.DataFrame([analysis_result])
                
            pdf_filename = generate_forensic_pdf_from_analysis_results(df_for_pdf, f"ePhish_Forensic_Report_{file.filename.replace('.', '_')}")
            logger.info(f"✅ PDF berhasil dibuat: {pdf_filename}")
            analysis_result['report_pdf_path'] = pdf_filename
            
        except Exception as e:
            logger.error(f"❌ Error generating PDF report: {e}")
            analysis_result['report_pdf_error'] = str(e)

        # Simpan ke database (SEMUA DATA DISIMPAN, TIDAK DIBATASI)
        db = SessionLocal()
        try:
            if 'rows' in analysis_result and isinstance(analysis_result['rows'], list):
                csv_analysis = CsvAnalysis(
                    filename=file.filename,
                    total_rows=analysis_result.get('total_rows', 0),
                    phishing_count=analysis_result.get('phishing_count', 0),
                    clean_count=analysis_result.get('clean_count', 0),
                    analysis_results=analysis_result['rows'], # Simpan SEMUA baris ke database
                    verdict=analysis_result.get('verdict', 'completed'),
                    timestamp=datetime.now(timezone.utc)
                )
                db.add(csv_analysis)
            else:
                # Single Email
                raw_urls = analysis_result.get('urls', [])
                if isinstance(raw_urls, str):
                    urls_list = [u.strip() for u in raw_urls.split('\n') if u.strip() and u.strip() != '-']
                else:
                    urls_list = raw_urls if isinstance(raw_urls, list) else []

                raw_se = analysis_result.get('social_engineering', [])
                if isinstance(raw_se, str):
                    se_list = [s.strip() for s in raw_se.split(',') if s.strip() and s.strip() != '-']
                else:
                    se_list = raw_se if isinstance(raw_se, list) else []

                email_analysis = EmailAnalysis(
                    filename=file.filename,
                    content=content.decode('utf-8')[:10000],
                    phishing_score=analysis_result.get('confidence', 0),
                    is_phishing=analysis_result.get('phishing', False),
                    confidence=analysis_result.get('confidence', 0),
                    suspicious_urls=urls_list,
                    social_engineering_indicators=se_list,
                    verdict=analysis_result.get('verdict', 'unknown'),
                    timestamp=datetime.now(timezone.utc)
                )
                db.add(email_analysis)
            db.commit()
        finally:
            db.close()

        return analysis_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in backend analyze_email: {e}")
        raise HTTPException(status_code=500, detail=f"Backend error: {str(e)}")

@app.post("/api/malware/analyze")
async def analyze_malware_endpoint(file: UploadFile = File(...)):
    try:
        logger.info(f"Received standalone malware analysis request for file: {file.filename}")
        temp_path = f"/tmp/{file.filename}"
        with open(temp_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        analyzer_url = os.getenv("ANALYZER_URL", "http://analyzer:5000")
        with requests.Session() as session:
            response = session.post(f"{analyzer_url}/analyze/malware", files={"file": (file.filename, open(temp_path, 'rb'), file.content_type)}, timeout=3600)

        if response.status_code != 200:
            error_detail = response.text if response.text else "Unknown error"
            raise HTTPException(status_code=500, detail=f"Analyzer service error: {error_detail}")

        analysis_result = response.json()
        
        try: os.remove(temp_path)
        except: pass

        db = SessionLocal()
        try:
            malware_analysis = MalwareAnalysis(
                filename=file.filename,
                file_hash=analysis_result.get('file_hash', ''),
                is_malware=analysis_result.get('is_malware', False),
                malware_family=analysis_result.get('malware_family', 'unknown'),
                malware_confidence=analysis_result.get('malware_confidence', 0),
                entropy=analysis_result.get('entropy', 0),
                yara_matches=analysis_result.get('yara_matches', []),
                verdict=analysis_result.get('verdict', 'unknown'),
                timestamp=datetime.now(timezone.utc)
            )
            db.add(malware_analysis)
            db.commit()
        finally:
            db.close()

        return analysis_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in backend analyze_malware_endpoint: {e}")
        raise HTTPException(status_code=500, detail=f"Backend error: {str(e)}")

@app.post("/api/ai/explain")
async def explain_analysis_endpoint(request_data: AIExplainRequest):
    try:
        query = request_data.query
        analysis_data = request_data.analysis_data

        explanations = []
        if 'phishing' in query.lower() or 'email' in query.lower():
            phishing_data = analysis_data
            if 'malware_analysis' in analysis_data:
                phishing_data = {k: v for k, v in analysis_data.items() if k != 'malware_analysis'}
            if phishing_data.get('phishing'):
                explanations.append(phishing_data.get('explanation', 'Phishing detected based on NLP and text analysis.'))
            else:
                explanations.append("Email appears legitimate with no significant phishing indicators detected.")

        if 'malware' in query.lower() or 'attachment' in query.lower() or 'email' in query.lower():
            malware_data = analysis_data.get('malware_analysis', {})
            if malware_data.get('is_malware'):
                explanations.append(f"Malware detected in email content using {malware_data.get('analysis_method', 'unknown method')}. Confidence: {malware_data.get('malware_confidence', 0):.2f}")
            elif analysis_data.get('is_malware'):
                 explanations.append(f"Malware detected. Confidence: {analysis_data.get('malware_confidence', 0):.2f}")
            else:
                explanations.append("No malware signatures detected in the email content or attachment.")

        if not explanations:
             explanations.append("I can help explain phishing analysis results, malware detection findings, and provide forensic recommendations.")

        return {"explanation": " ".join(explanations)}

    except Exception as e:
        logger.error(f"Error in backend explain_analysis_endpoint: {e}")
        raise HTTPException(status_code=500, detail=f"Backend AI error: {str(e)}")

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    db = SessionLocal()
    try:
        total_emails = db.query(EmailAnalysis).count()
        phishing_count = db.query(EmailAnalysis).filter(EmailAnalysis.is_phishing == True).count()
        malware_count = db.query(MalwareAnalysis).filter(MalwareAnalysis.is_malware == True).count()
        csv_count = db.query(CsvAnalysis).count()

        return {
            "total_analyses": total_emails + csv_count,
            "phishing_detected": phishing_count,
            "malware_found": malware_count,
            "csv_analyzed": csv_count,
            "avg_response_time": "2.3s"
        }
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)