# Phishing URL Classifier API

This project contains a machine learning pipeline that trains an XGBoost classifier to detect malicious or phishing URLs based on string characteristics, domain features, and simulated brand impersonations. It includes an automated training script, a feature extraction utility suite, and a localized Python Flask API to service real-time inference.

## 🚀 Project Overview
**1. Model Details:**
- Uses **XGBoost** adjusted with `scale_pos_weight` to address class imbalances.
- Features include string length, character entropy calculations (`calc_entropy`), and brand sequence matchers (`difflib` brand similarity metric).
- Decision thresholds:
  - **Balanced Mode (0.50 threshold):** Optimized fora equal distribution of safe inferences over sensitive inputs.
  - **Extra Protective (0.35 threshold):** Flags suspicious activity more aggressively, yielding higher recall rates for malicious link interception.

## ⚙️ How to Train the Model
If you've updated the dataset (`malicious_phish.csv`) and want to retrain:

1. Ensure the dataset exists in the root folder with the name `malicious_phish.csv`.
2. Ensure you have installed the requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the training script:
   ```bash
   python model_training.py
   ```
   *Note: This unpacks the dataset, applies mapping transformations to extract features across all URLs, runs training iterations, outputs performance metrics, and successfully saves `models/model_improved.pkl`.*

## 🌐 How to Run the API
To launch the localized server which loads the trained `.pkl` inference model:

1. Run the Flask wrapper script:
   ```bash
   python app.py
   ```
2. The server spins up at `http://localhost:5000` or `http://127.0.0.1:5000`.

## 📡 Example Request / Response
You can ping the application natively using curl from your terminal:

**Request:**
```bash
curl -X POST http://127.0.0.1:5000/predict \
     -H "Content-Type: application/json" \
     -d '{"url":"paypa1-verify-account.com/login", "mode":"balanced"}'
```

**Response (JSON):**
```json
{
  "active_verdict": "DANGEROUS",
  "probability": 0.8872,
  "url": "paypa1-verify-account.com/login",
  "verdict_balanced": "DANGEROUS",
  "verdict_protective": "DANGEROUS"
}
```

## 📱 Integrating with Flutter (Frontend)
To implement this inside a Dart & Flutter environment, you can refer to the `flutter_integration_sample.dart` provided in the codebase for making basic `http.post` network calls!
