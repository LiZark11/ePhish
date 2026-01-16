from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

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