import joblib
import pandas as pd
from flask import Flask, request, jsonify
from utils import extract_features
import logging
import os
import requests

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)

# ─────────────────────────────────────────────
# API Keys — loaded from environment variables
# ─────────────────────────────────────────────
VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
GOOGLE_SB_KEY  = os.environ.get('GOOGLE_SB_KEY', '')

# ─────────────────────────────────────────────
# Load ML model at startup
# ─────────────────────────────────────────────
logging.info("Loading model...")
model = joblib.load('models/model_improved.pkl')
logging.info("Model loaded successfully.")

# ─────────────────────────────────────────────
# VirusTotal Check
# ─────────────────────────────────────────────
def check_virustotal(url: str):
    if not VIRUSTOTAL_KEY:
        app.logger.warning("VirusTotal key not set — skipping.")
        return None
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if response.status_code != 200:
            return None
        analysis_id = response.json()["data"]["id"]
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )
        if result.status_code != 200:
            return None
        stats = result.json()["data"]["attributes"]["stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious >= 2 or suspicious >= 3:
            return 'DANGER'
        return 'SAFE'
    except Exception as e:
        app.logger.error(f"VirusTotal error: {e}")
        return None

# ─────────────────────────────────────────────
# Google Safe Browsing Check
# ─────────────────────────────────────────────
def check_google_safe_browsing(url: str):
    if not GOOGLE_SB_KEY:
        app.logger.warning("Google Safe Browsing key not set — skipping.")
        return None
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}"
        payload = {
            "client": {"clientId": "linkguard", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=payload, timeout=10)
        if response.status_code != 200:
            return None
        data = response.json()
        if data.get("matches"):
            return 'DANGER'
        return 'SAFE'
    except Exception as e:
        app.logger.error(f"Google Safe Browsing error: {e}")
        return None

# ─────────────────────────────────────────────
# ML Model Check (fixed to use phishing probability)
# ─────────────────────────────────────────────
def check_ml_model(url: str, threshold: float):
    features = extract_features(url)
    feat_df  = pd.DataFrame([features])
    probs = model.predict_proba(feat_df)[0]

    # Log both probabilities for debugging
    app.logger.info(f"Probabilities → phishing={probs[0]}, safe={probs[1]}")

    # Use phishing probability (class 0)
    probability = probs[0]
    verdict = 'DANGER' if probability >= threshold else 'SAFE'
    app.logger.info(f"ML model → phishing_prob={round(probability * 100, 1)}, verdict={verdict}")
    return verdict, probability

# ─────────────────────────────────────────────
# Verdict Combination
# ─────────────────────────────────────────────
def combine_verdicts(vt_result, gsb_result, ml_verdict):
    if vt_result == 'DANGER':
        return 'DANGER'
    if gsb_result == 'DANGER':
        return 'DANGER'
    if ml_verdict == 'DANGER':
        return 'DANGER'
    return 'SAFE'

# ─────────────────────────────────────────────
# Health endpoint
# ─────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "model": "loaded"})

# ─────────────────────────────────────────────
# Main check endpoint
# ─────────────────────────────────────────────
@app.route('/check', methods=['POST'])
def check():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "No url provided"}), 400

    url       = data['url']
    threshold = 0.30

    vt_result, gsb_result = check_virustotal(url), check_google_safe_browsing(url)
    ml_verdict, probability = check_ml_model(url, threshold)

    final_verdict = combine_verdicts(vt_result, gsb_result, ml_verdict)
    score = round(float(probability) * 100, 1)

    if final_verdict == 'SAFE':
        message_en, message_ar = "This link appears to be safe.", "يبدو هذا الرابط آمناً."
    else:
        message_en, message_ar = "This link is dangerous...", "هذا الرابط خطير..."

    response = {
        "url": url,
        "verdict": final_verdict,
        "score": score,
        "message_en": message_en,
        "message_ar": message_ar,
        "details": {
            "virustotal": vt_result or "unavailable",
            "google_safe_browsing": gsb_result or "unavailable",
            "ml_model": ml_verdict
        }
    }
    return jsonify(response)

# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
