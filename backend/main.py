# backend/main.py
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn
import os
from typing import Optional
import requests
import json
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
import time
import logging
import pandas as pd
import io
from sqlalchemy import text

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Tambahkan Pydantic Model di sini ---
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
            # Test connection using SQLAlchemy 2.0 syntax
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Database connection successful")
            return engine
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                raise e
            time.sleep(5)

# Inisialisasi engine di luar blok if __name__ == "__main__"
# Kita buat fungsi untuk inisialisasi nanti
engine = None
SessionLocal = None
Base = declarative_base()

def init_db():
    global engine, SessionLocal
    engine = create_db_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
def startup_event():
    init_db() # Panggil inisialisasi database saat startup

@app.get("/")
async def root():
    return {"message": "ePhish Backend API - Digital Forensic Platform"}

@app.post("/api/email/analyze")
async def analyze_email(file: UploadFile = File(...)):
    """
    Endpoint untuk analisis gabungan phishing dan malware.
    Mendukung file .eml, .msg, .csv
    """
    try:
        logger.info(f"Received combined analysis request for file: {file.filename}")
        filename = file.filename.lower()
        content = await file.read()

        analyzer_url = os.getenv("ANALYZER_URL", "http://analyzer:5000")
        logger.info(f"Sending request to analyzer at: {analyzer_url}")

        # Gunakan Session untuk konfigurasi timeout
        with requests.Session() as session:
            # Atur timeout besar (12 jam) untuk batch besar, atau lebih kecil untuk single
            timeout_seconds = 300 # 5 menit untuk single
            if filename.endswith('.csv'):
                 # Bisa disesuaikan, misalnya 12 jam (43200 detik) untuk batch besar
                timeout_seconds = 43200 

            files = {"file": (file.filename, content, file.content_type)}
            response = session.post(f"{analyzer_url}/analyze/phishing", files=files, timeout=timeout_seconds)

        logger.info(f"Analyzer response status: {response.status_code}")
        if response.status_code != 200:
            error_detail = response.text if response.text else "Unknown error"
            logger.error(f"Analyzer service error: {error_detail}")
            raise HTTPException(status_code=500, detail=f"Analyzer service error: {error_detail}")

        analysis_result = response.json()
        logger.info(f"Analyzer response received, verdict: {analysis_result.get('verdict', 'unknown')}")

        # Simpan ke database berdasarkan jenis analisis
        db = SessionLocal()
        try:
            if 'csv_analysis' in analysis_result: # Batch CSV
                csv_analysis = CsvAnalysis(
                    filename=file.filename,
                    total_rows=analysis_result['csv_analysis']['total_rows'],
                    phishing_count=analysis_result['csv_analysis']['phishing_count'],
                    clean_count=analysis_result['csv_analysis']['clean_count'],
                    analysis_results=analysis_result['csv_analysis']['rows'], # Simpan semua hasil row
                    verdict=analysis_result['verdict'],
                    timestamp=datetime.now(timezone.utc)
                )
                db.add(csv_analysis)
            else: # Single Email (hasil gabungan)
                email_analysis = EmailAnalysis(
                    filename=file.filename,
                    content=content.decode('utf-8')[:10000], # Batasi ukuran simpan
                    phishing_score=analysis_result.get('confidence', 0),
                    is_phishing=analysis_result.get('phishing', False),
                    confidence=analysis_result.get('confidence', 0),
                    suspicious_urls=analysis_result.get('urls', []),
                    social_engineering_indicators=analysis_result.get('social_engineering', []),
                    verdict=analysis_result.get('verdict', 'unknown'),
                    timestamp=datetime.now(timezone.utc)
                )
                db.add(email_analysis)
                # Juga simpan malware analysis jika ada
                malware_data = analysis_result.get('malware_analysis')
                if malware_data:
                    malware_analysis = MalwareAnalysis(
                        filename=file.filename,
                        file_hash=malware_data.get('file_hash', ''),
                        is_malware=malware_data.get('is_malware', False),
                        malware_family=malware_data.get('malware_family', 'unknown'),
                        malware_confidence=malware_data.get('malware_confidence', 0),
                        entropy=malware_data.get('entropy', 0),
                        yara_matches=malware_data.get('yara_matches', []),
                        verdict=malware_data.get('verdict', 'unknown'),
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
        logger.error(f"Error in backend analyze_email: {e}")
        raise HTTPException(status_code=500, detail=f"Backend error: {str(e)}")

@app.post("/api/malware/analyze")
async def analyze_malware(file: UploadFile = File(...)):
    """
    Endpoint untuk analisis malware standalone (e.g., attachment).
    """
    try:
        logger.info(f"Received standalone malware analysis request for file: {file.filename}")
        temp_path = f"/tmp/{file.filename}"
        with open(temp_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        analyzer_url = os.getenv("ANALYZER_URL", "http://analyzer:5000")
        logger.info(f"Sending request to analyzer at: {analyzer_url}")

        with requests.Session() as session:
            # Timeout sedang untuk file attachment
            response = session.post(f"{analyzer_url}/analyze/malware", files={"file": (file.filename, open(temp_path, 'rb'), file.content_type)}, timeout=3600) # 1 jam

        logger.info(f"Analyzer response status: {response.status_code}")
        if response.status_code != 200:
            error_detail = response.text if response.text else "Unknown error"
            logger.error(f"Analyzer service error: {error_detail}")
            raise HTTPException(status_code=500, detail=f"Analyzer service error: {error_detail}")

        analysis_result = response.json()
        logger.info(f"Analyzer response received, verdict: {analysis_result.get('verdict', 'unknown')}")

        # Hapus file sementara
        try:
            os.remove(temp_path)
        except:
            pass # Jika gagal hapus, lanjutkan saja

        # Simpan ke database
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
        logger.error(f"Error in backend analyze_malware: {e}")
        raise HTTPException(status_code=500, detail=f"Backend error: {str(e)}")

# Endpoint baru untuk mengunduh laporan PDF
@app.get("/api/report/{report_filename}")
async def get_report(report_filename: str):
    """Download the generated PDF report."""
    report_path = os.path.join("/tmp", report_filename) # Asumsi disimpan di /tmp analyzer
    if os.path.exists(report_path):
        return FileResponse(path=report_path, filename=report_filename, media_type='application/pdf')
    else:
        raise HTTPException(status_code=404, detail="Report file not found")

@app.post("/api/ai/explain")
async def explain_analysis(request_data: AIExplainRequest):
    """AI-powered explanation of analysis results"""
    try:
        query = request_data.query
        analysis_data = request_data.analysis_data

        # Gabungkan logika penjelasan untuk phishing dan malware
        explanations = []
        if 'phishing' in query.lower() or 'email' in query.lower():
            phishing_data = analysis_data
            if 'malware_analysis' in analysis_data: # Jika hasil gabungan
                phishing_data = {k: v for k, v in analysis_data.items() if k != 'malware_analysis'}
            if phishing_data.get('phishing'):
                explanations.append(phishing_data.get('explanation', 'Phishing detected based on NLP and text analysis.'))
            else:
                explanations.append("Email appears legitimate with no significant phishing indicators detected.")

        if 'malware' in query.lower() or 'attachment' in query.lower() or 'email' in query.lower(): # Cek juga 'email' untuk hasil gabungan
            malware_data = analysis_data.get('malware_analysis', {})
            if malware_data.get('is_malware'):
                explanations.append(f"Malware detected in email content using {malware_data.get('analysis_method', 'unknown method')}. Confidence: {malware_data.get('malware_confidence', 0):.2f}")
            elif analysis_data.get('is_malware'): # Jika hasil standalone malware
                 explanations.append(f"Malware detected. Confidence: {analysis_data.get('malware_confidence', 0):.2f}")
            else:
                explanations.append("No malware signatures detected in the email content or attachment.")

        if not explanations:
             explanations.append("I can help explain phishing analysis results, malware detection findings, and provide forensic recommendations. Please ask specific questions about your analysis results.")

        final_explanation = " ".join(explanations)
        return {"explanation": final_explanation}

    except Exception as e:
        logger.error(f"Error in backend explain_analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Backend AI error: {str(e)}")

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
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
    # Jangan inisialisasi engine di sini
    # init_db() # Ini akan dihandle oleh startup event
    uvicorn.run(app, host="0.0.0.0", port=8000)
