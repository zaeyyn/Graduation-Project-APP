import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import xgboost as xgb
import joblib
from utils import extract_features

def main():
    print("Loading dataset...")
    df = pd.read_csv('malicious_phish.csv')

    # benign = 0 (safe), everything else = 1 (dangerous)
    df['label'] = df['type'].apply(lambda x: 0 if x == 'benign' else 1)

    print("Extracting features... this might take a few minutes...")
    features = df['url'].apply(extract_features)
    X = pd.DataFrame(features.tolist())
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Calculate class imbalance weight
    scale_weight = float((y_train == 0).sum() / (y_train == 1).sum())
    print(f"Assigning scale_pos_weight: {scale_weight:.2f}")

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=5,
        scale_pos_weight=scale_weight,
        eval_metric='logloss',
        random_state=42
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50
    )

    print("Training complete.")

    y_prob = model.predict_proba(X_test)[:, 1]

    # Mode 1: Balanced Mode (Threshold = 0.50)
    y_pred_balanced = (y_prob >= 0.50).astype(int)

    # Mode 2: Extra Protective Mode (Threshold = 0.35)
    y_pred_protective = (y_prob >= 0.35).astype(int)

    def print_metrics(y_true, y_pred, mode_name):
        accuracy  = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred)
        recall    = recall_score(y_true, y_pred)
        f1        = f1_score(y_true, y_pred)

        cm = confusion_matrix(y_true, y_pred)
        TN = cm[0][0]
        FP = cm[0][1]
        fpr = FP / (FP + TN)

        print(f"=== {mode_name} PERFORMANCE ===")
        print(f"Accuracy:            {accuracy:.4f}  ({accuracy*100:.2f}%)")
        print(f"Precision:           {precision:.4f}")
        print(f"Recall:              {recall:.4f}")
        print(f"F1 Score:            {f1:.4f}")
        print(f"False Positive Rate: {fpr:.4f}  ({fpr*100:.2f}%)\n")

    print_metrics(y_test, y_pred_balanced, "BALANCED MODE (Threshold 0.50)")
    print_metrics(y_test, y_pred_protective, "EXTRA PROTECTIVE MODE (Threshold 0.35)")

    import os
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/model_improved.pkl')
    print("Model saved as models/model_improved.pkl")

if __name__ == "__main__":
    main()
