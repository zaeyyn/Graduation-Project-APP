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
# API Keys
# ─────────────────────────────────────────────
VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
GOOGLE_SB_KEY  = os.environ.get('GOOGLE_SB_KEY', '')

# ─────────────────────────────────────────────
# Load ML model
# ─────────────────────────────────────────────
logging.info("Loading model...")
model = joblib.load('models/model_improved.pkl')
logging.info(f"Model loaded. Classes: {list(model.classes_)}")

# ─────────────────────────────────────────────
# 1st CHECK: VirusTotal
# ─────────────────────────────────────────────
def check_virustotal(url: str):
    if not VIRUSTOTAL_KEY:
        app.logger.warning("ae4dd714acee2f5f32abc2740c6ff87a397bc1798ec7a9d7ea78aefbc7cd35f9")
        return None
    try:
        headers  = {"x-apikey": VIRUSTOTAL_KEY}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if response.status_code != 200:
            app.logger.warning(f"VirusTotal submit failed: {response.status_code}")
            return None

        analysis_id = response.json()["data"]["id"]
        result      = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )
        if result.status_code != 200:
            return None

        stats      = result.json()["data"]["attributes"]["stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        app.logger.info(f"VirusTotal → malicious={malicious}, suspicious={suspicious}")

        return 'DANGER' if (malicious >= 2 or suspicious >= 3) else 'SAFE'

    except Exception as e:
        app.logger.error(f"VirusTotal error: {e}")
        return None

# ─────────────────────────────────────────────
# 2nd CHECK: Google Safe Browsing
# ─────────────────────────────────────────────
def check_google_safe_browsing(url: str):
    if not GOOGLE_SB_KEY:
        app.logger.warning("AIzaSyA8xgJY8evTJIiqoM_LL7_YO-7EQ5MEeHE")
        return None
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}"
        payload  = {
            "client": {"clientId": "linkguard", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=payload, timeout=10)
        if response.status_code != 200:
            app.logger.warning(f"GSB failed: {response.status_code}")
            return None

        data = response.json()
        app.logger.info(f"Google Safe Browsing → matches={bool(data.get('matches'))}")
        return 'DANGER' if data.get("matches") else 'SAFE'

    except Exception as e:
        app.logger.error(f"Google Safe Browsing error: {e}")
        return None

# ─────────────────────────────────────────────
# 3rd CHECK: ML Model (fallback only)
# ─────────────────────────────────────────────
def check_ml_model(url: str, threshold: float = 0.55):
    try:
        features = extract_features(url)
        feat_df  = pd.DataFrame([features])
        probs    = model.predict_proba(feat_df)[0]
        classes  = list(model.classes_)

        app.logger.info(f"ML classes: {classes}")
        app.logger.info(f"ML probs:   {dict(zip(classes, probs))}")

        # class 1 = dangerous, class 0 = safe
        if 1 in classes:
            danger_prob = probs[classes.index(1)]
        elif 'phishing' in classes:
            danger_prob = probs[classes.index('phishing')]
        elif 'malicious' in classes:
            danger_prob = probs[classes.index('malicious')]
        else:
            danger_prob = probs[-1]

        verdict = 'DANGER' if danger_prob >= threshold else 'SAFE'
        app.logger.info(f"ML → danger_prob={round(danger_prob * 100, 1)}%, verdict={verdict}")
        return verdict, danger_prob

    except Exception as e:
        app.logger.error(f"ML model error: {e}")
        return 'SAFE', 0.0  # fail safe

# ─────────────────────────────────────────────
# Verdict Combination Logic:
#
#  VT=DANGER or GSB=DANGER  → DANGER (hard block)
#  VT=SAFE  or GSB=SAFE     → SAFE   (trusted APIs override ML)
#  Both unavailable          → use ML verdict
# ─────────────────────────────────────────────
def combine_verdicts(vt_result, gsb_result, ml_verdict):
    # If either trusted API confirms DANGER → block it
    if vt_result == 'DANGER' or gsb_result == 'DANGER':
        return 'DANGER'

    # If BOTH trusted APIs say SAFE → trust them
    if vt_result == 'SAFE' and gsb_result == 'SAFE':
        return 'SAFE'

    # One API unavailable, one says SAFE → use ML as tiebreaker
    if vt_result == 'SAFE' or gsb_result == 'SAFE':
        return ml_verdict

    # Both unavailable → fall back to ML only
    app.logger.info("VT and GSB both unavailable — using ML verdict.")
    return ml_verdict

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
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({"error": "No url provided"}), 400

    url = data['url'].strip()
    app.logger.info(f"Checking URL: {url}")

    vt_result            = check_virustotal(url)
    gsb_result           = check_google_safe_browsing(url)
    ml_verdict, danger_prob = check_ml_model(url)

    final_verdict = combine_verdicts(vt_result, gsb_result, ml_verdict)
    score         = round(float(danger_prob) * 100, 1)

    if final_verdict == 'SAFE':
        message_en = "This link appears to be safe."
        message_ar = "يبدو هذا الرابط آمناً."
    else:
        message_en = "This link is dangerous."
        message_ar = "هذا الرابط خطير."

    return jsonify({
        "url":        url,
        "verdict":    final_verdict,
        "score":      score,
        "message_en": message_en,
        "message_ar": message_ar,
        "details": {
            "virustotal":           vt_result  or "unavailable",
            "google_safe_browsing": gsb_result or "unavailable",
            "ml_model":             ml_verdict
        }
    })

# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)