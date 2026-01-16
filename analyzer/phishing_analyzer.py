# analyzer/phishing_analyzer.py
import pandas as pd
import numpy as np
import re
import hashlib
from datetime import datetime, timezone
from transformers import pipeline
import logging
import io

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Inisialisasi model hanya sekali
phishing_model = None

def initialize_model():
    global phishing_model
    if phishing_model is None:
        logger.info("Initializing DistilBERT model...")
        try:
            phishing_model = pipeline(
                "text-classification",
                model="distilbert-base-uncased-finetuned-sst-2-english",
                return_all_scores=False,
                truncation=True,
                max_length=512
            )
            logger.info("Model initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize model: {e}")
            phishing_model = "ERROR"

def phishing_nlp(text):
    initialize_model()
    if phishing_model == "ERROR":
        logger.warning("Using rule-based fallback due to model error.")
        return rule_based_phishing_score(text)

    try:
        if not text or not isinstance(text, str):
            logger.warning("Empty or non-string text provided to phishing_nlp.")
            return {
                "phishing_score": 0.0,
                "is_phishing": False,
                "label": "NO_CONTENT"
            }

        clean_text = text.strip()[:512]
        if not clean_text:
            logger.warning("Text became empty after cleaning.")
            return {
                "phishing_score": 0.0,
                "is_phishing": False,
                "label": "EMPTY_AFTER_CLEAN"
            }

        result = phishing_model(clean_text)[0]
        score = result["score"]
        label = result["label"]
        is_phishing = True if label == "NEGATIVE" and score > 0.85 else False

        return {
            "phishing_score": float(score),
            "is_phishing": is_phishing,
            "label": label
        }
    except Exception as e:
        logger.error(f"Error dalam phishing_nlp: {e}")
        return rule_based_phishing_score(text)

def rule_based_phishing_score(text):
    if not text:
        return {
            "phishing_score": 0.0,
            "is_phishing": False,
            "label": "RULE_BASED_EMPTY"
        }

    score = 0.0
    found_keywords = []
    keywords = [
        ("urgent", 0.1), ("verify", 0.1), ("suspend", 0.2),
        ("click here", 0.15), ("password", 0.1), ("act now", 0.1),
        ("limited time", 0.1), ("account", 0.05), ("security", 0.05),
        ("locked", 0.1)
    ]

    text_lower = text.lower()
    for keyword, weight in keywords:
        if keyword in text_lower:
            score += weight
            found_keywords.append(keyword)

    score = min(score, 1.0)
    is_phishing = score > 0.5
    label = f"RULE_BASED_{len(found_keywords)}_MATCHES"

    return {
        "phishing_score": score,
        "is_phishing": is_phishing,
        "label": label,
        "matched_keywords": found_keywords
    }

def extract_urls(text):
    if not text:
        return []
    pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?'
    urls = re.findall(pattern, text)
    return [url for url in urls if len(url) < 500]

def social_engineering(text):
    if not text:
        return []
    keywords = [
        "urgent", "verify", "suspend", "immediately",
        "click here", "confirm", "password", "act now",
        "limited time", "account", "security", "locked",
        "dear customer", "your account", "click immediately"
    ]
    return [k for k in keywords if k in text.lower()]

def severity(confidence, is_phishing):
    if is_phishing and confidence > 0.9:
        return "CRITICAL"
    elif is_phishing:
        return "HIGH"
    else:
        return "LOW"

def ai_explain(phishing_result, urls, social_eng_terms):
    is_phishing = phishing_result["is_phishing"]
    confidence = phishing_result["phishing_score"]
    label = phishing_result["label"]

    if is_phishing:
        explanation_parts = [
            f"Email diklasifikasikan sebagai phishing karena "
            f"mengandung pola social engineering ({', '.join(social_eng_terms) if social_eng_terms else 'tidak ada'}), "
            f"dan konteks analisis NLP menunjukkan indikator phishing (score: {confidence:.2f}, label: {label})."
        ]
        if urls:
            explanation_parts.append(f" Terdapat {len(urls)} URL yang ditemukan.")
        return " ".join(explanation_parts)
    else:
        explanation_parts = [
            "Email tidak menunjukkan indikator phishing signifikan berdasarkan analisis NLP (score: {:.2f}, label: {})".format(confidence, label)
        ]
        if social_eng_terms:
            explanation_parts.append(f", meskipun terdapat beberapa istilah social engineering: {', '.join(social_eng_terms)}.")
        else:
            explanation_parts.append(".")
        return "".join(explanation_parts)

def analyze_single_email(email_text, email_id=None):
    nlp_result = phishing_nlp(email_text)
    urls = extract_urls(email_text)
    social_eng_terms = social_engineering(email_text)
    current_severity = severity(nlp_result["phishing_score"], nlp_result["is_phishing"])
    explanation = ai_explain(nlp_result, urls, social_eng_terms)

    result = {
        "email_id": email_id or "unknown",
        "phishing": nlp_result["is_phishing"],
        "confidence": nlp_result["phishing_score"],
        "urls": urls,
        "social_engineering": social_eng_terms,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": current_severity,
        "explanation": explanation,
        "nlp_label": nlp_result["label"]
    }

    return result

# --- Fungsi untuk Analisis Batch (CSV) ---
def analyze_csv_batch(csv_content):
    """
    Analisis batch email dari konten CSV.
    Menerima string CSV, kembalikan list hasil analisis.
    """
    try:
        df = pd.read_csv(io.StringIO(csv_content))

        text_column = None
        if 'subject' in df.columns and 'body' in df.columns:
            df["email_text"] = df.apply(lambda row: str(row.get("subject", "")) + " " + str(row.get("body", "")), axis=1)
            text_column = "email_text"
        elif 'content' in df.columns:
            text_column = "content"
        elif 'text' in df.columns:
            text_column = "text"
        elif 'message' in df.columns:
            text_column = "message"
        else:
            first_col = df.columns[0]
            df["email_text"] = df[first_col].astype(str)
            text_column = "email_text"

        if text_column not in df.columns:
            raise ValueError(f"Could not determine text column from CSV. Columns found: {list(df.columns)}")

        results = []
        total_rows = len(df)
        logger.info(f"Starting batch analysis for {total_rows} rows.")

        # Inisialisasi model di awal batch untuk menghindari inisialisasi ulang
        initialize_model()

        # Log setiap 1% atau setiap N baris (gunakan yang lebih besar)
        progress_interval = max(1, total_rows // 100) # Log setiap 1% atau minimal 1 baris
        last_logged_percentage = -1

        for index, row in df.iterrows():
            email_text = str(row.get(text_column, ""))
            email_id = str(row.get("email_id", row.get("id", f"csv_row_{index}")))

            analysis_result = analyze_single_email(email_text, email_id)
            results.append(analysis_result)

            # Log progress
            current_percentage = (index + 1) * 100 // total_rows
            if current_percentage > last_logged_percentage and current_percentage % 10 == 0: # Log setiap 10%
                 logger.info(f"Progress: {current_percentage}% ({index + 1}/{total_rows})")
                 last_logged_percentage = current_percentage


        phishing_count = sum(1 for r in results if r["phishing"])
        clean_count = total_rows - phishing_count

        batch_result = {
            "csv_analysis": {
                "total_rows": total_rows,
                "phishing_count": phishing_count,
                "clean_count": clean_count,
                "rows": results
            },
            "verdict": "completed",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        logger.info(f"Batch analysis completed. {phishing_count} phishing, {clean_count} clean.")
        return batch_result

    except Exception as e:
        logger.error(f"Error dalam analyze_csv_batch: {e}")
        return {"error": str(e), "verdict": "failed", "timestamp": datetime.now(timezone.utc).isoformat()}
