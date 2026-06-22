# analyzer/phishing_analyzer.py
import re
import tldextract
import pandas as pd
import io
import logging
from transformers import pipeline
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# =========================================================
# LOAD NLP MODEL (DISTILBERT SST-2)
# =========================================================
logger.info("Loading NLP Model (DistilBERT)...")
phishing_model = pipeline(
    "text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english",
    truncation=True
)
logger.info("Model Loaded Successfully")

# =========================================================
# HELPER FUNCTIONS
# =========================================================
def phishing_nlp(text):
    """Analyze text using DistilBERT model."""
    # Fallback jika teks kosong agar tidak error
    if not text or not text.strip():
        return 0.5, "POSITIVE" 
    result = phishing_model(text[:512])[0]
    return result["score"], result["label"]

def extract_urls(text):
    """Extract up to 3 URLs, truncated to 80 chars each."""
    if not text: return []
    urls = re.findall(r'https?://[^\s]+', text)
    return [url[:80] for url in urls[:3]]

def extract_domains(urls):
    """Extract up to 3 unique domains from URLs using tldextract."""
    domains = []
    for url in urls[:3]:
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            if domain and domain not in domains:
                domains.append(domain)
        except Exception:
            continue
    return domains[:3]

def social_engineering(text):
    """Detect up to 3 social engineering keywords."""
    if not text: return []
    keywords = [
        "urgent", "verify", "suspend", "immediately", "click here",
        "confirm", "password", "bank", "login", "security"
    ]
    text_lower = text.lower()
    return [kw for kw in keywords if kw in text_lower][:3]

def severity_classification(is_phishing, confidence):
    """Classify severity based on phishing status and confidence score."""
    if is_phishing and confidence >= 0.90:
        return "CRITICAL"
    elif is_phishing:
        return "HIGH"
    return "LOW"

def ai_explanation(is_phishing):
    """Generate a human-readable explanation for the analysis result."""
    if is_phishing:
        return "Email diklasifikasikan sebagai phishing karena mengandung pola social engineering, urgensi tinggi, dan konteks manipulatif."
    return "Email tidak menunjukkan indikator phishing signifikan."

# =========================================================
# SINGLE EMAIL ANALYSIS
# =========================================================
def analyze_single_email(text, email_id):
    """Analyze a single email text and return a detailed dictionary."""
    score, label = phishing_nlp(text)
    urls = extract_urls(text)
    domains = extract_domains(urls)
    se = social_engineering(text)
    
    # LOGIKA KEPUTUSAN (HYBRID OR)
    sentiment_risk = (label == "NEGATIVE" and score >= 0.65)
    is_phishing = (len(urls) >= 1 or len(se) >= 1 or sentiment_risk)
    
    return {
        "email_id": email_id,
        "phishing": is_phishing,
        "confidence": round(score, 4),
        "social_engineering": ", ".join(se) if se else "-",
        "domains": ", ".join(domains) if domains else "-",
        "urls": "\n".join(urls) if urls else "-",
        "sentiment": label,
        "severity": severity_classification(is_phishing, score),
        "explanation": ai_explanation(is_phishing),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# =========================================================
# BATCH CSV ANALYSIS (OPTIMIZED WITH BATCH INFERENCE)
# =========================================================
def analyze_csv_batch(csv_content):
    """
    Analyze a batch of emails from CSV content.
    Uses optimized batch inference for the NLP model to process thousands of rows quickly.
    Returns a flat dictionary structure expected by the backend.
    """
    csv_df = pd.read_csv(io.StringIO(csv_content))
    
    # Detect text column (fallback ke kolom pertama jika tidak ada yang cocok)
    possible_columns = ["text", "email", "body", "message", "content"]
    selected_column = next((col for col in possible_columns if col in csv_df.columns), csv_df.columns[0])
        
    # PERBAIKAN: Ekstrak semua teks, tangani nilai NaN/None dengan aman agar tidak jadi string "nan"
    texts = [str(row[selected_column]) if pd.notna(row[selected_column]) else "" for _, row in csv_df.iterrows()]
    truncated_texts = [t[:512] for t in texts]
    
    logger.info(f"Running optimized batch NLP inference on {len(truncated_texts)} texts...")
    
    # BATCH INFERENCE: Proses semua teks sekaligus dengan batch_size untuk kecepatan maksimal
    nlp_results = phishing_model(truncated_texts, batch_size=32, truncation=True)
    logger.info("Batch NLP inference completed successfully.")
    
    results = []
    phishing_count = 0
    clean_count = 0
    
    for idx, row in csv_df.iterrows():
        body = texts[idx]
        email_id = idx + 1
        
        # Ambil hasil NLP untuk baris ini dari output batch
        score = nlp_results[idx]['score']
        label = nlp_results[idx]['label']
        
        urls = extract_urls(body)
        domains = extract_domains(urls)
        se = social_engineering(body)
        
        # LOGIKA KEPUTUSAN (HYBRID OR)
        sentiment_risk = (label == "NEGATIVE" and score >= 0.65)
        is_phishing = (len(urls) >= 1 or len(se) >= 1 or sentiment_risk)
        
        severity = severity_classification(is_phishing, score)
        explanation = ai_explanation(is_phishing)
        
        analysis = {
            "email_id": email_id,
            "phishing": is_phishing,
            "confidence": round(score, 4),
            "social_engineering": ", ".join(se) if se else "-",
            "domains": ", ".join(domains) if domains else "-",
            "urls": "\n".join(urls) if urls else "-",
            "sentiment": label,
            "severity": severity,
            "explanation": explanation,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        results.append(analysis)
        if is_phishing:
            phishing_count += 1
        else:
            clean_count += 1
            
    # RETURN STRUKTUR FLAT (SUDAH SESUAI 100% DENGAN BACKEND BARU)
    return {
        "total_rows": len(results),
        "phishing_count": phishing_count,
        "clean_count": clean_count,
        "rows": results,
        "verdict": "completed"
    }