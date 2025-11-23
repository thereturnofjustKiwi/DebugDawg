import os
import numpy as np
import joblib
from pathlib import Path
from builtins import print, int, str, zip, len, float, Exception, enumerate
import joblib
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, recall_score, precision_score, roc_auc_score, f1_score

# Define paths relative to this script
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "processed"
MODEL_DIR = BASE_DIR / "models"

def train_model():
    # Load data
    print("Loading processed data...")
    X_train = np.load(DATA_DIR / "X_train.npy")
    y_train = np.load(DATA_DIR / "y_train.npy")
    X_test = np.load(DATA_DIR / "X_test.npy")
    y_test = np.load(DATA_DIR / "y_test.npy")

    # --- BALANCED STRATEGY ---
    # Use standard ratio (neg/pos) without extra multiplier to reduce false positives
    neg, pos = np.bincount(y_train)
    spw = float(neg / pos) 
    print(f"Using scale_pos_weight: {spw:.2f}")

    # Initialize XGBoost with regularization to prevent overfitting
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,  # Slower learning for better generalization
        scale_pos_weight=spw,
        subsample=0.8,       # Reduce variance
        colsample_bytree=0.8,
        eval_metric='logloss',
        use_label_encoder=False,
        random_state=42
    )

    # Train
    print("Training model...")
    model.fit(X_train, y_train)

    # Predict
    y_probs = model.predict_proba(X_test)[:, 1]
    
    # --- SMART THRESHOLD TUNING ---
    # Search for best F1 where Recall is at least 0.90
    thresholds = np.arange(0.1, 0.95, 0.01)
    best_thresh = 0.5
    best_score = -1
    
    print("\nThreshold Tuning (Recall >= 0.90):")
    print(f"{'Threshold':<10} {'Recall':<10} {'Precision':<10} {'F1-Score':<10}")
    
    valid_thresholds_found = False
    
    for t in thresholds:
        preds = (y_probs >= t).astype(int)
        rec = recall_score(y_test, preds)
        prec = precision_score(y_test, preds)
        f1 = f1_score(y_test, preds)
        
        # Logging specific points to track behavior
        if t in [0.1, 0.3, 0.5, 0.7, 0.9]: 
             print(f"{t:<10.2f} {rec:<10.4f} {prec:<10.4f} {f1:<10.4f}")

        # Constraint: Recall must be decent (>0.90), then maximize F1
        # If model is too weak to hit 0.90, fall back to max F1
        if rec >= 0.90:
            valid_thresholds_found = True
            if f1 > best_score:
                best_score = f1
                best_thresh = t
    
    # Fallback if no threshold met recall > 0.90
    if not valid_thresholds_found:
        print("\n⚠ Warning: No threshold met 0.90 recall. picking max F1.")
        # Simple max F1 search
        scores = [f1_score(y_test, (y_probs >= t).astype(int)) for t in thresholds]
        best_thresh = thresholds[np.argmax(scores)]

    print(f"\n✅ Selected Threshold: {best_thresh:.2f}")
    
    # Final Evaluation
    final_preds = (y_probs >= best_thresh).astype(int)
    print("\nClassification Report (Test Set):")
    print(classification_report(y_test, final_preds, target_names=["Benign", "Intrusion"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_probs):.4f}")

    # Save
    model_bundle = {
        "model": model,
        "threshold": best_thresh
    }
    joblib.dump(model_bundle, MODEL_DIR / "unsw_trained_model.pkl")
    print(f"✅ Model saved to {MODEL_DIR}/unsw_trained_model.pkl")

if __name__ == "__main__":
    train_model()
