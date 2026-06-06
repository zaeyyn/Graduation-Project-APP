import joblib
import pandas as pd
from utils import extract_features

model = joblib.load('models/model_improved.pkl')

urls = [
    ('https://www.google.com', 'SAFE'),
    ('https://www.bbc.com', 'SAFE'),
    ('https://www.stackoverflow.com', 'SAFE'),
    ('https://www.godaddy.com', 'SAFE'),
    ('http://paypa1-verify.net/secure/login', 'DANGER'),
    ('http://amazon-security-alert.tk/verify', 'DANGER'),
    ('http://apple-id-locked.ml/unlock', 'DANGER'),
]

classes = list(model.classes_)
print(f"Model classes: {classes}")
print()

for url, expected in urls:
    f = extract_features(url)
    df = pd.DataFrame([f])
    probs = model.predict_proba(df)[0]
    safe_prob = probs[classes.index(0)] * 100
    danger_prob = probs[classes.index(1)] * 100
    verdict = 'DANGER' if safe_prob < 50 else 'SAFE'
    match = '✅' if verdict == expected else '❌'
    print(f"{match} {verdict} (safe:{safe_prob:.1f}% danger:{danger_prob:.1f}%) — {url}")