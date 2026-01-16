# backend/main.py
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
from typing import Optional
import requests
import json
from datetime import datetime
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

# Konstanta Timeout dan Ukuran Maksimal
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 500  # 500 MB
REQUEST_TIMEOUT_SECONDS = 3 * 60 * 60  # 3 Jam dalam detik

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
    timestamp = Column(DateTime, default=datetime.utcnow)

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
    timestamp = Column(DateTime, default=datetime.utcnow)

class CsvAnalysis(Base):
    __tablename__ = "csv_analyses"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255))
    total_rows = Column(Integer)
    phishing_count = Column(Integer)
    clean_count = Column(Integer)
    analysis_results = Column(JSON)
    verdict = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)

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
    init_db()

@app.get("/")
async def root():
    return {"message": "ePhish Backend API - Digital Forensic Platform"}

@app.post("/api/email/analyze")
async def analyze_email(file: UploadFile = File(...)):
    """
    Endpoint untuk analisis phishing.
    Mendukung file .eml, .msg, .csv
    """
    try:
        # Validasi ukuran file
        if file.size and file.size > MAX_FILE_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed size is {MAX_FILE_SIZE_BYTES / (1024*1024):.2f} MB")

        logger.info(f"Received email analysis request for file: {file.filename}, size: {file.size / (1024*1024):.2f} MB")
        filename = file.filename.lower()
        content = await file.read()

        analyzer_url = os.getenv("ANALYZER_URL", "http://analyzer:5000")
        logger.info(f"Sending request to analyzer at: {analyzer_url}")

        if filename.endswith('.csv'):
            # Kirim ke analyzer untuk batch analysis
            files = {"file": (file.filename, content, file.content_type)}
            response = requests.post(f"{analyzer_url}/analyze/phishing", files=files, timeout=REQUEST_TIMEOUT_SECONDS)

        elif filename.endswith(('.eml', '.msg')):
            # Kirim ke analyzer untuk single email analysis
            files = {"file": (file.filename, content, file.content_type)}
            response = requests.post(f"{analyzer_url}/analyze/phishing", files=files, timeout=REQUEST_TIMEOUT_SECONDS)

        else:
            # Untuk file teks biasa atau format lain, baca sebagai teks
            email_content = content.decode('utf-8')
            response = requests.post(f"{analyzer_url}/analyze/phishing", json={"email_content": email_content}, timeout=REQUEST_TIMEOUT_SECONDS)

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
                    analysis_results=analysis_result['csv_analysis']['rows'],
                    verdict=analysis_result['verdict'],
                    timestamp=datetime.utcnow()
                )
                db.add(csv_analysis)
            else: # Single Email
                email_analysis = EmailAnalysis(
                    filename=file.filename,
                    content=content.decode('utf-8')[:10000], # Batasi ukuran simpan
                    phishing_score=analysis_result.get('confidence', 0),
                    is_phishing=analysis_result.get('phishing', False),
                    confidence=analysis_result.get('confidence', 0),
                    suspicious_urls=analysis_result.get('urls', []),
                    social_engineering_indicators=analysis_result.get('social_engineering', []),
                    verdict=analysis_result.get('verdict', 'unknown'),
                    timestamp=datetime.utcnow()
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
async def analyze_malware(file: UploadFile = File(...)):
    """
    Endpoint untuk analisis malware dalam email atau attachment.
    """
    try:
        # Validasi ukuran file
        if file.size and file.size > MAX_FILE_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed size is {MAX_FILE_SIZE_BYTES / (1024*1024):.2f} MB")

        logger.info(f"Received malware analysis request for file: {file.filename}, size: {file.size / (1024*1024):.2f} MB")
        temp_path = f"/tmp/{file.filename}"
        with open(temp_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        analyzer_url = os.getenv("ANALYZER_URL", "http://analyzer:5000")
        logger.info(f"Sending request to analyzer at: {analyzer_url}")

        with open(temp_path, "rb") as f:
            files = {"file": (file.filename, f, file.content_type)}
            response = requests.post(f"{analyzer_url}/analyze/malware", files=files, timeout=REQUEST_TIMEOUT_SECONDS)

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
                timestamp=datetime.utcnow()
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

@app.post("/api/ai/explain")
async def explain_analysis(request_data: AIExplainRequest):
    """AI-powered explanation of analysis results"""
    try:
        query = request_data.query
        analysis_data = request_data.analysis_data

        if 'phishing' in query.lower() or 'email' in query.lower():
            if analysis_data.get('phishing'):
                explanation = analysis_data.get('explanation', 'Phishing detected based on NLP and text analysis.')
            else:
                explanation = "Email appears legitimate with no significant phishing indicators detected."
        elif 'malware' in query.lower() or 'attachment' in query.lower():
            if analysis_data.get('is_malware'):
                explanation = f"""
                Malware detected in {analysis_data.get('analysis_method', 'unknown method')}.
                Confidence: {analysis_data.get('malware_confidence', 0):.2f}
                """
            else:
                explanation = "File appears clean with no malware signatures detected."
        else:
            explanation = "I can help explain phishing analysis results, malware detection findings, and provide forensic recommendations. Please ask specific questions about your analysis results."

        return {"explanation": explanation}

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