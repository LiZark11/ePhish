# backend/schemas.py
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class EmailAnalysisCreate(BaseModel):
    filename: str
    phishing_score: float
    is_phishing: bool
    confidence: float
    suspicious_urls: List[str]
    social_engineering_indicators: List[str]
    verdict: str

class MalwareAnalysisCreate(BaseModel):
    filename: str
    file_hash: str
    is_malware: bool
    malware_family: str
    malware_confidence: float
    entropy: float
    yara_matches: List[str]
    verdict: str