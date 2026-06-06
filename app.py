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
    # Search & Google
    'google.com', 'gmail.com', 'youtube.com', 'docs.google.com',
    'drive.google.com', 'maps.google.com', 'play.google.com',
    'accounts.google.com', 'mail.google.com', 'google.co.uk',
    'google.com.au', 'google.ca', 'google.de', 'google.fr',
    'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    'googlevideo.com', 'googletagmanager.com', 'googleadservices.com',
    'google-analytics.com', 'dns.google', 'clients.google.com',

    # Social Media
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'tiktok.com', 'snapchat.com', 'pinterest.com',
    'reddit.com', 'tumblr.com', 'quora.com', 'discord.com',
    'telegram.org', 'whatsapp.com', 'signal.org',
    'fbcdn.net', 'whatsapp.net', 'facebook.net',
    'cdninstagram.com', 'fbsbx.com',

    # Microsoft
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    'windows.com', 'xbox.com', 'azure.com', 'bing.com',
    'office365.com', 'sharepoint.com', 'teams.microsoft.com',
    'microsoftonline.com', 'msftconnecttest.com', 'msedge.net',

    # Apple
    'apple.com', 'icloud.com', 'itunes.com', 'appstore.com',
    'mzstatic.com', 'apple-dns.net',

    # Amazon
    'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
    'amazonaws.com', 'aws.amazon.com', 'prime.amazon.com',
    'cloudfront.net',

    # Samsung & Android device
    'samsung.com', 'samsungcloud.com', 'samsungdive.com',
    'samsungknox.com', 'samsungelectronics.com',
    'android.com', 'android.clients.google.com',

    # System & Network infrastructure
    'pool.ntp.org', 'time.android.com', 'time.google.com',
    'connectivitycheck.gstatic.com', 'connectivitycheck.android.com',
    'clients3.google.com', 'clients4.google.com',
    'mtalk.google.com', 'alt1-mtalk.google.com',
    'fcm.googleapis.com', 'fcmconnection.googleapis.com',
    'safebrowsing.google.com', 'safebrowsing.googleapis.com',
    'update.googleapis.com', 'play.googleapis.com',
    'optimizationguide-pa.googleapis.com',
    'firebaseinstallations.googleapis.com',
    'firebaselogging-pa.googleapis.com',
    'crashlyticsreports-pa.googleapis.com',
    'app-measurement.com',

    # CDN & Infrastructure
    'akamaized.net', 'akamai.net', 'akamaitechnologies.com',
    'cloudflare.com', 'cloudflare-dns.com', '1.1.1.1',
    'fastly.net', 'edgesuite.net', 'edgekey.net',

    # Entertainment
    'netflix.com', 'spotify.com', 'twitch.tv', 'hulu.com',
    'disneyplus.com', 'hbomax.com', 'primevideo.com',
    'soundcloud.com', 'vimeo.com', 'dailymotion.com',

    # Tech & Dev
    'github.com', 'gitlab.com', 'stackoverflow.com', 'stackexchange.com',
    'digitalocean.com', 'heroku.com', 'vercel.com',
    'netlify.com', 'firebase.google.com', 'developer.apple.com',
    'developer.android.com', 'npmjs.com', 'pypi.org', 'docker.com',

    # News & Media
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
    'reuters.com', 'apnews.com', 'washingtonpost.com', 'forbes.com',
    'bloomberg.com', 'techcrunch.com', 'theverge.com', 'wired.com',
    'arstechnica.com', 'engadget.com', 'zdnet.com',

    # Finance
    'paypal.com', 'stripe.com', 'wise.com', 'revolut.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',

    # Shopping
    'ebay.com', 'etsy.com', 'shopify.com', 'aliexpress.com',
    'walmart.com', 'target.com', 'bestbuy.com',

    # Education
    'wikipedia.org', 'khanacademy.org', 'coursera.org', 'udemy.com',
    'edx.org', 'mit.edu', 'harvard.edu', 'stanford.edu', 'duolingo.com',

    # Hosting & Domains
    'godaddy.com', 'namecheap.com', 'hostinger.com', 'bluehost.com',
    'siteground.com', 'hostgator.com', 'domain.com', 'hover.com',

    # Tools & Productivity
    'dropbox.com', 'box.com', 'notion.so', 'trello.com', 'slack.com',
    'zoom.us', 'canva.com', 'figma.com', 'adobe.com', 'atlassian.com',

    # Other popular
    'yahoo.com', 'ymail.com', 'medium.com', 'wordpress.com', 'wix.com',
}

def is_known_safe_url(url: str) -> bool:
    try:
        host = url.split('//')[-1].split('/')[0].lower()
        host = host.replace('www.', '')
        # Remove port if present
        host = host.split(':')[0]

        # Check exact match
        if host in KNOWN_SAFE_DOMAINS:
            return True
        # Check root domain (e.g. docs.google.com → google.com)
        parts = host.split('.')
        if len(parts) >= 2:
            root = f"{parts[-2]}.{parts[-1]}"
            if root in KNOWN_SAFE_DOMAINS:
                return True
        # Check one level up (e.g. edge-mqtt.facebook.com → facebook.com)
        if len(parts) >= 3:
            root = f"{parts[-2]}.{parts[-1]}"
            if root in KNOWN_SAFE_DOMAINS:
                return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────
# System/infrastructure domains to ALWAYS skip
# These are Android internal domains — never malicious
# ─────────────────────────────────────────────
SYSTEM_DOMAIN_SUFFIXES = (
    '.gstatic.com', '.googleapis.com', '.google.com',
    '.android.com', '.samsung.com', '.samsungcloud.com',
    '.pool.ntp.org', '.akamaized.net', '.cloudfront.net',
    '.whatsapp.net', '.facebook.com', '.fbcdn.net',
    '.instagram.com', '.cdninstagram.com',
    '.microsoft.com', '.msftconnecttest.com',
    '.apple.com', '.icloud.com',
)

def is_system_domain(url: str) -> bool:
    try:
        host = url.split('//')[-1].split('/')[0].lower().split(':')[0]
        for suffix in SYSTEM_DOMAIN_SUFFIXES:
            if host.endswith(suffix) or host == suffix.lstrip('.'):
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
        return 'DANGER' if (malicious >= 2 or suspicious >= 3) else 'SAFE'

    except Exception as e:
        app.logger.error(f"VirusTotal error: {e}")
        return None

# ─────────────────────────────────────────────
# 2nd CHECK: Google Safe Browsing
# ─────────────────────────────────────────────
def check_google_safe_browsing(url: str):
    if not GOOGLE_SB_KEY:
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
            return None

        data = response.json()
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

        if 0 in classes:
            safe_prob   = probs[classes.index(0)]
            danger_prob = 1.0 - safe_prob
        else:
            danger_prob = probs[-1]
            safe_prob   = 1.0 - danger_prob

        verdict = 'DANGER' if safe_prob < 0.50 else 'SAFE'
        return verdict, danger_prob

    except Exception as e:
        app.logger.error(f"ML model error: {e}")
        return 'SAFE', 0.0

# ─────────────────────────────────────────────
# Verdict Combination Logic
# ─────────────────────────────────────────────
def combine_verdicts(vt_result, gsb_result, ml_verdict, danger_prob):
    if vt_result == 'DANGER' or gsb_result == 'DANGER':
        return 'DANGER'
    if ml_verdict == 'DANGER':
        return 'DANGER'
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

    # Fast path 1: system/infrastructure domains — always safe
    if is_system_domain(url):
        app.logger.info(f"System domain — skipping: {url}")
        return jsonify({
            "url":        url,
            "verdict":    "SAFE",
            "score":      0.0,
            "message_en": "This link appears to be safe.",
            "message_ar": "يبدو هذا الرابط آمناً.",
            "details": {
                "virustotal":           "skipped",
                "google_safe_browsing": "skipped",
                "ml_model":             "skipped (system domain)"
            }
        })

    # Fast path 2: known safe domains — skip ML
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