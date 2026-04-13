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
# Set these on Railway as environment variables:
#   VIRUSTOTAL_KEY   = your VirusTotal API key
#   GOOGLE_SB_KEY    = your Google Safe Browsing API key
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
# Returns: 'DANGER', 'SAFE', or None (if unavailable)
# ─────────────────────────────────────────────
def check_virustotal(url: str):
    if not VIRUSTOTAL_KEY:
        app.logger.warning("VirusTotal key not set — skipping.")
        return None
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}

        # Submit URL for analysis
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if response.status_code != 200:
            app.logger.warning(f"VirusTotal submission failed: {response.status_code}")
            return None

        analysis_id = response.json()["data"]["id"]

        # Fetch analysis result
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )
        if result.status_code != 200:
            app.logger.warning(f"VirusTotal result fetch failed: {result.status_code}")
            return None

        stats = result.json()["data"]["attributes"]["stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        app.logger.info(f"VirusTotal → malicious={malicious}, suspicious={suspicious}")

        # If 2 or more engines flag it, treat as DANGER
        if malicious >= 2 or suspicious >= 3:
            return 'DANGER'
        return 'SAFE'

    except Exception as e:
        app.logger.error(f"VirusTotal error: {e}")
        return None  # Fallback — do not crash


# ─────────────────────────────────────────────
# Google Safe Browsing Check
# Returns: 'DANGER', 'SAFE', or None (if unavailable)
# ─────────────────────────────────────────────
def check_google_safe_browsing(url: str):
    if not GOOGLE_SB_KEY:
        app.logger.warning("Google Safe Browsing key not set — skipping.")
        return None
    try:
        endpoint = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={GOOGLE_SB_KEY}"
        )
        payload = {
            "client": {
                "clientId":      "linkguard",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=payload, timeout=10)

        if response.status_code != 200:
            app.logger.warning(f"Google Safe Browsing failed: {response.status_code}")
            return None

        data = response.json()
        app.logger.info(f"Google Safe Browsing → {data}")

        # If any matches found, it is dangerous
        if data.get("matches"):
            return 'DANGER'
        return 'SAFE'

    except Exception as e:
        app.logger.error(f"Google Safe Browsing error: {e}")
        return None  # Fallback — do not crash


# ─────────────────────────────────────────────
# ML Model Check
# Returns: 'DANGER' or 'SAFE' with a probability score
# ─────────────────────────────────────────────
def check_ml_model(url: str, threshold: float):
    features = extract_features(url)
    feat_df  = pd.DataFrame([features])
    probability = model.predict_proba(feat_df)[0][1]
    verdict = 'DANGER' if probability >= threshold else 'SAFE'
    app.logger.info(f"ML model → score={round(probability * 100, 1)}, verdict={verdict}")
    return verdict, probability


# ─────────────────────────────────────────────
# Combined Verdict Logic
#
# Rules:
#   - If VirusTotal says DANGER → DANGER (strong external signal)
#   - If Google Safe Browsing says DANGER → DANGER (strong external signal)
#   - If both external APIs are unavailable → rely on ML only
#   - If ML says DANGER and at least one external API says SAFE → DANGER
#     (ML is conservative — we trust it)
#   - Otherwise → SAFE
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
        app.logger.warning("Prediction aborted: No URL in request.")
        return jsonify({"error": "No url provided"}), 400

    url  = data['url']
    mode = data.get('mode', 'balanced').lower()  # 'balanced' or 'protective'

    app.logger.info(f"Check request → URL: {url} | Mode: {mode}")

    # Set ML threshold based on mode
    threshold = 0.30 if mode == 'protective' else 0.50

    # ── Run all three checks ──────────────────
    vt_result  = check_virustotal(url)          # 'DANGER', 'SAFE', or None
    gsb_result = check_google_safe_browsing(url) # 'DANGER', 'SAFE', or None
    ml_verdict, probability = check_ml_model(url, threshold)

    app.logger.info(
        f"Results → VT: {vt_result} | GSB: {gsb_result} | ML: {ml_verdict}"
    )

    # ── Combine into final verdict ────────────
    final_verdict = combine_verdicts(vt_result, gsb_result, ml_verdict)
    score = round(float(probability) * 100, 1)

    # ── Build bilingual messages ──────────────
    if final_verdict == 'SAFE':
        message_en = "This link appears to be safe."
        message_ar = "يبدو هذا الرابط آمناً."
    else:
        message_en = "This link is dangerous..."
        message_ar = "هذا الرابط خطير..."

    response = {
        "url":        url,
        "verdict":    final_verdict,
        "score":      score,
        "message_en": message_en,
        "message_ar": message_ar,
        "details": {
            "virustotal":          vt_result  or "unavailable",
            "google_safe_browsing": gsb_result or "unavailable",
            "ml_model":            ml_verdict
        }
    }

    app.logger.info(
        f"Final → URL: {url} | Verdict: {final_verdict} | Score: {score}"
    )

    return jsonify(response)


# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
