import joblib
import pandas as pd
from flask import Flask, request, jsonify
from utils import extract_features
import logging
import os

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)

# Load the saved model
logging.info("Loading model...")
model = joblib.load('models/model_improved.pkl')
logging.info("Model loaded successfully.")


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "model": "loaded"})


@app.route('/check', methods=['POST'])
def check():
    data = request.json
    if not data or 'url' not in data:
        app.logger.warning("Prediction aborted: No URL provided in request payload.")
        return jsonify({"error": "No url provided"}), 400

    url = data['url']
    mode = data.get('mode', 'balanced').lower()  # Default to balanced

    app.logger.info(f"Received check request -> URL: {url} | Mode: {mode}")

    # Extract features for prediction
    features = extract_features(url)
    feat_df = pd.DataFrame([features])

    # Predict probability
    probability = model.predict_proba(feat_df)[0][1]

    # Apply thresholds based on requested mode
    threshold = 0.30 if mode == 'protective' else 0.50
    active_result = "DANGER" if probability >= threshold else "SAFE"
    score = round(float(probability) * 100, 1)

    # Prepare localized messages
    if active_result == "SAFE":
        message_en = "This link appears to be safe."
        message_ar = "يبدو هذا الرابط آمناً."
    else:
        message_en = "This link is dangerous..."
        message_ar = "هذا الرابط خطير..."

    # Build response payload
    response = {
        "url": url,
        "verdict": active_result,
        "score": score,
        "message_en": message_en,
        "message_ar": message_ar
    }

    app.logger.info(f"Check successful -> URL: {url} | Verdict: {active_result} (Score: {score})")

    return jsonify(response)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
