import joblib
import pandas as pd
import re
from flask import Flask, request, jsonify
from utils import extract_features
import logging
import os
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)

VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
GOOGLE_SB_KEY  = os.environ.get('GOOGLE_SB_KEY', '')

logging.info("Loading model...")
model = joblib.load('models/model_improved.pkl')
logging.info(f"Model loaded. Classes: {list(model.classes_)}")

# ─────────────────────────────────────────────
# Known safe domains — bypass ML entirely
# ─────────────────────────────────────────────
KNOWN_SAFE_DOMAINS = {
    'google.com', 'gmail.com', 'youtube.com', 'googleapis.com',
    'gstatic.com', 'googleusercontent.com', 'googlevideo.com',
    'dns.google', 'facebook.com', 'instagram.com', 'twitter.com',
    'x.com', 'linkedin.com', 'tiktok.com', 'snapchat.com',
    'pinterest.com', 'reddit.com', 'discord.com', 'telegram.org',
    'whatsapp.com', 'signal.org', 'fbcdn.net', 'whatsapp.net',
    'facebook.net', 'cdninstagram.com', 'microsoft.com', 'live.com',
    'outlook.com', 'office.com', 'windows.com', 'bing.com',
    'microsoftonline.com', 'msftconnecttest.com', 'apple.com',
    'icloud.com', 'mzstatic.com', 'amazon.com', 'amazonaws.com',
    'cloudfront.net', 'samsung.com', 'samsungcloud.com',
    'pool.ntp.org', 'connectivitycheck.gstatic.com',
    'akamaized.net', 'akamai.net', 'cloudflare.com', 'fastly.net',
    'netflix.com', 'spotify.com', 'github.com', 'gitlab.com',
    'stackoverflow.com', 'bbc.com', 'bbc.co.uk', 'cnn.com',
    'reuters.com', 'paypal.com', 'stripe.com', 'ebay.com',
    'wikipedia.org', 'canva.com', 'figma.com', 'adobe.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'notion.so',
    'yahoo.com', 'medium.com', 'wordpress.com', 'shopify.com',
    'bbc-reporting-api.app', 'reporting-api.app',
}

# Known safe TLDs/patterns that ML often false-flags
SAFE_TLDS = {'.app', '.dev', '.io', '.co', '.ai', '.fm', '.pm', '.me'}

# Suspicious TLDs commonly used for phishing
PHISHING_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                 '.click', '.download', '.loan', '.win', '.bid',
                 '.stream', '.science', '.racing', '.site', '.online'}

# Suspicious words in domains — strong phishing signal
PHISHING_WORDS = {
    'verify', 'secure', 'login', 'update', 'confirm', 'account',
    'billing', 'payment', 'alert', 'suspended', 'locked',
    'unusual', 'activity', 'validate', 'recover', 'signin',
    'webscr', 'ebayisapi', 'support', 'helpdesk', 'customer'
}

# Known brand names — if combined with phishing words = very suspicious
KNOWN_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
    'facebook', 'instagram', 'twitter', 'bank', 'chase', 'wells',
    'ebay', 'dropbox', 'linkedin', 'spotify', 'steam', 'adobe'
]


def get_host(url: str) -> str:
    try:
        host = url.split('//')[-1].split('/')[0].lower().split(':')[0]
        return host.replace('www.', '')
    except Exception:
        return url


def is_known_safe_url(url: str) -> bool:
    host = get_host(url)
    if host in KNOWN_SAFE_DOMAINS:
        return True
    parts = host.split('.')
    if len(parts) >= 2:
        root = f"{parts[-2]}.{parts[-1]}"
        if root in KNOWN_SAFE_DOMAINS:
            return True
    if len(parts) >= 3:
        root = f"{parts[-2]}.{parts[-1]}"
        if root in KNOWN_SAFE_DOMAINS:
            return True
    return False


def is_system_domain(url: str) -> bool:
    SYSTEM_SUFFIXES = (
        '.googleapis.com', '.gstatic.com', '.google.com',
        '.android.com', '.samsung.com', '.samsungcloud.com',
        '.pool.ntp.org', '.akamaized.net', '.cloudfront.net',
        '.whatsapp.net', '.facebook.com', '.fbcdn.net',
        '.instagram.com', '.cdninstagram.com',
        '.microsoft.com', '.msftconnecttest.com',
        '.apple.com', '.icloud.com',
    )
    host = get_host(url)
    for suffix in SYSTEM_SUFFIXES:
        if host.endswith(suffix) or host == suffix.lstrip('.'):
            return True
    return False


def looks_suspicious(url: str) -> bool:
    """
    Determine if a domain has genuinely suspicious characteristics.
    Only trust ML DANGER verdict when this returns True.
    """
    host = get_host(url)
    main_label = host.split('.')[0] if '.' in host else host

    # Number substitutions: paypa1, g00gle, faceb00k
    if re.search(r'[a-z]+[0-9]+[a-z]+', main_label):
        return True

    # Suspicious TLD
    for tld in PHISHING_TLDS:
        if host.endswith(tld):
            return True

    # Suspicious words in domain
    for word in PHISHING_WORDS:
        if word in host:
            return True

    # Brand name + hyphen = impersonation (paypal-secure.com, apple-id-verify.com)
    for brand in KNOWN_BRANDS:
        if brand in host and '-' in host:
            return True

    # Very long main label (>25 chars) = likely random/generated
    if len(main_label) > 25:
        return True

    # Multiple hyphens = suspicious
    if host.count('-') >= 3:
        return True

    return False


# ─────────────────────────────────────────────
# API Checks
# ─────────────────────────────────────────────
def check_virustotal(url: str):
    if not VIRUSTOTAL_KEY:
        return None
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}, timeout=10
        )
        if response.status_code != 200:
            return None
        analysis_id = response.json()["data"]["id"]
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers, timeout=10
        )
        if result.status_code != 200:
            return None
        stats = result.json()["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return 'DANGER' if (malicious >= 2 or suspicious >= 3) else 'SAFE'
    except Exception as e:
        app.logger.error(f"VirusTotal error: {e}")
        return None


def check_google_safe_browsing(url: str):
    if not GOOGLE_SB_KEY:
        return None
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}"
        payload = {
            "client": {"clientId": "linkguard", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=payload, timeout=10)
        if response.status_code != 200:
            return None
        return 'DANGER' if response.json().get("matches") else 'SAFE'
    except Exception as e:
        app.logger.error(f"GSB error: {e}")
        return None


def check_ml_model(url: str):
    try:
        features = extract_features(url)
        feat_df = pd.DataFrame([features])
        probs = model.predict_proba(feat_df)[0]
        classes = list(model.classes_)

        if 0 in classes:
            safe_prob = probs[classes.index(0)]
            danger_prob = 1.0 - safe_prob
        else:
            danger_prob = probs[-1]
            safe_prob = 1.0 - danger_prob

        verdict = 'DANGER' if safe_prob < 0.50 else 'SAFE'
        return verdict, danger_prob
    except Exception as e:
        app.logger.error(f"ML model error: {e}")
        return 'SAFE', 0.0


def combine_verdicts(url, vt_result, gsb_result, ml_verdict, danger_prob):
    # VT or GSB flagged it — always trust these external sources
    if vt_result == 'DANGER' or gsb_result == 'DANGER':
        app.logger.info("Final: DANGER (VT or GSB)")
        return 'DANGER'

    # ML flagged it — only trust if domain actually looks suspicious
    if ml_verdict == 'DANGER':
        if looks_suspicious(url):
            app.logger.info(f"Final: DANGER (ML + suspicious domain)")
            return 'DANGER'
        else:
            app.logger.info(f"Final: SAFE (ML said DANGER but domain not suspicious)")
            return 'SAFE'

    return 'SAFE'


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok", "model": "loaded",
        "virustotal_configured": bool(VIRUSTOTAL_KEY),
        "google_safe_browsing_configured": bool(GOOGLE_SB_KEY)
    })


@app.route('/check', methods=['POST'])
def check():
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({"error": "No url provided"}), 400

    url = data['url'].strip()
    app.logger.info(f"Checking URL: {url}")

    # Fast path 1: system infrastructure
    if is_system_domain(url):
        return jsonify({
            "url": url, "verdict": "SAFE", "score": 0.0,
            "message_en": "This link appears to be safe.",
            "message_ar": "يبدو هذا الرابط آمناً.",
            "details": {"virustotal": "skipped",
                        "google_safe_browsing": "skipped",
                        "ml_model": "skipped (system domain)"}
        })

    # Fast path 2: known safe domains
    if is_known_safe_url(url):
        return jsonify({
            "url": url, "verdict": "SAFE", "score": 0.0,
            "message_en": "This link appears to be safe.",
            "message_ar": "يبدو هذا الرابط آمناً.",
            "details": {"virustotal": "skipped",
                        "google_safe_browsing": "skipped",
                        "ml_model": "skipped (known safe domain)"}
        })

    vt_result = check_virustotal(url)
    gsb_result = check_google_safe_browsing(url)
    ml_verdict, danger_prob = check_ml_model(url)
    final_verdict = combine_verdicts(url, vt_result, gsb_result, ml_verdict, danger_prob)
    score = round(float(danger_prob) * 100, 1)

    if final_verdict == 'SAFE':
        message_en = "This link appears to be safe."
        message_ar = "يبدو هذا الرابط آمناً."
    else:
        message_en = "This link is dangerous. Do not proceed."
        message_ar = "هذا الرابط خطير. لا تكمل."

    app.logger.info(
        f"URL={url} | VT={vt_result} | GSB={gsb_result} | "
        f"ML={ml_verdict}({round(danger_prob*100,1)}%) | "
        f"suspicious={looks_suspicious(url)} | FINAL={final_verdict}"
    )

    return jsonify({
        "url": url, "verdict": final_verdict, "score": score,
        "message_en": message_en, "message_ar": message_ar,
        "details": {
            "virustotal": vt_result or "unavailable",
            "google_safe_browsing": gsb_result or "unavailable",
            "ml_model": ml_verdict
        }
    })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)