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
# Known safe domains — bypass ML for these
# ─────────────────────────────────────────────
KNOWN_SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com',
    'twitter.com', 'instagram.com', 'linkedin.com', 'github.com',
    'wikipedia.org', 'reddit.com', 'yahoo.com', 'bing.com',
    'live.com', 'outlook.com', 'office.com', 'windows.com',
    'whatsapp.com', 'tiktok.com', 'snapchat.com', 'pinterest.com',
    'twitch.tv', 'spotify.com', 'adobe.com', 'dropbox.com',
    'icloud.com', 'amazonaws.com', 'cloudflare.com',
}

def is_known_safe_url(url: str) -> bool:
    try:
        host = url.split('//')[-1].split('/')[0].lower()
        host = host.replace('www.', '')
        # Check exact match
        if host in KNOWN_SAFE_DOMAINS:
            return True
        # Check root domain (e.g. docs.google.com → google.com)
        parts = host.split('.')
        if len(parts) >= 2:
            root = f"{parts[-2]}.{parts[-1]}"
            if root in KNOWN_SAFE_DOMAINS:
                return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────
# 1st CHECK: VirusTotal
# ─────────────────────────────────────────────
def check_virustotal(url: str):
    if not VIRUSTOTAL_KEY:
        app.logger.warning("VirusTotal API key not configured — skipping.")
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
        app.logger.warning("Google Safe Browsing API key not configured — skipping.")
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
# 3rd CHECK: ML Model
# ─────────────────────────────────────────────
def check_ml_model(url: str):
    try:
        features = extract_features(url)
        feat_df  = pd.DataFrame([features])
        probs    = model.predict_proba(feat_df)[0]
        classes  = list(model.classes_)

        app.logger.info(f"ML classes: {classes}")
        app.logger.info(f"ML probs:   {dict(zip(classes, probs))}")

        if 0 in classes:
            safe_prob   = probs[classes.index(0)]
            danger_prob = 1.0 - safe_prob
        else:
            danger_prob = probs[-1]
            safe_prob   = 1.0 - danger_prob

        verdict = 'DANGER' if safe_prob < 0.50 else 'SAFE'
        app.logger.info(f"ML → safe_prob={round(safe_prob*100,1)}%, danger_prob={round(danger_prob*100,1)}%, verdict={verdict}")
        return verdict, danger_prob

    except Exception as e:
        app.logger.error(f"ML model error: {e}")
        return 'SAFE', 0.0

# ─────────────────────────────────────────────
# Verdict Combination Logic
# ─────────────────────────────────────────────
def combine_verdicts(vt_result, gsb_result, ml_verdict, danger_prob):
    if vt_result == 'DANGER' or gsb_result == 'DANGER':
        app.logger.info("Final verdict: DANGER (flagged by VT or GSB)")
        return 'DANGER'

    if ml_verdict == 'DANGER':
        app.logger.info(f"Final verdict: DANGER (ML flagged with {round(danger_prob*100,1)}% danger score)")
        return 'DANGER'

    app.logger.info("Final verdict: SAFE (all checks passed)")
    return 'SAFE'

# ─────────────────────────────────────────────
# Health endpoint
# ─────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "model":  "loaded",
        "virustotal_configured":           bool(VIRUSTOTAL_KEY),
        "google_safe_browsing_configured": bool(GOOGLE_SB_KEY)
    })

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

    # Fast path: known safe domains skip ML entirely
    if is_known_safe_url(url):
        app.logger.info(f"Known safe domain — skipping ML: {url}")
        return jsonify({
            "url":        url,
            "verdict":    "SAFE",
            "score":      0.0,
            "message_en": "This link appears to be safe.",
            "message_ar": "يبدو هذا الرابط آمناً.",
            "details": {
                "virustotal":           "skipped",
                "google_safe_browsing": "skipped",
                "ml_model":             "skipped (known safe domain)"
            }
        })

    vt_result               = check_virustotal(url)
    gsb_result              = check_google_safe_browsing(url)
    ml_verdict, danger_prob = check_ml_model(url)

    final_verdict = combine_verdicts(vt_result, gsb_result, ml_verdict, danger_prob)
    score         = round(float(danger_prob) * 100, 1)

    if final_verdict == 'SAFE':
        message_en = "This link appears to be safe."
        message_ar = "يبدو هذا الرابط آمناً."
    else:
        message_en = "This link is dangerous. Do not proceed."
        message_ar = "هذا الرابط خطير. لا تكمل."

    app.logger.info(f"URL={url} | VT={vt_result} | GSB={gsb_result} | ML={ml_verdict}({round(danger_prob*100,1)}%) | FINAL={final_verdict}")

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