import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    recall_score, precision_score, f1_score, accuracy_score, roc_auc_score
)

def evaluate(y_true, y_pred, y_proba, name):
    acc = accuracy_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    pre = precision_score(y_true, y_pred)
    f1  = f1_score(y_true, y_pred)
    auc = roc_auc_score(y_true, y_proba)
    cm  = confusion_matrix(y_true, y_pred)
    print(f"\n==== {name} ====")
    print(f"Accuracy:  {acc:.4f}  Precision: {pre:.4f}  Recall: {rec:.4f}  F1: {f1:.4f}  ROC-AUC: {auc:.4f}")
    print("Confusion matrix:\n", cm)
    print(classification_report(y_true, y_pred, target_names=["Benign","Attack"]))

def recall_first_threshold(y_true, y_proba, recall_floor=0.97):
    chosen = 0.05
    for t in np.arange(0.05, 0.91, 0.01):
        pred = (y_proba >= t).astype(int)
        rec = recall_score(y_true, pred)
        if rec >= recall_floor:
            chosen = t
            break
    print(f"\nSelected recall‑first threshold: {chosen:.2f} (validation recall ≥ {recall_floor})")
    return chosen

if __name__ == "__main__":
    # Load sparse matrices with joblib
    X_tr = joblib.load("data/processed_unsw/X_train.pkl")
    X_val = joblib.load("data/processed_unsw/X_val.pkl")
    X_tst = joblib.load("data/processed_unsw/X_test.pkl")
    y_tr = np.load("data/processed_unsw/y_train.npy")
    y_val = np.load("data/processed_unsw/y_val.npy")
    y_tst = np.load("data/processed_unsw/y_test.npy")

    print(f"Train: {X_tr.shape}  Val: {X_val.shape}  Test: {X_tst.shape}")

    # Class weight amplification for recall
    neg, pos = (y_tr==0).sum(), (y_tr==1).sum()
    spw = max(1.0, neg/pos) * 5.0

    model = XGBClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.08,
        subsample=0.85, colsample_bytree=0.85, min_child_weight=4,
        reg_lambda=1.0, scale_pos_weight=spw, eval_metric="logloss",
        n_jobs=-1, random_state=42
    )
    model.fit(X_tr, y_tr)
    print(f"✅ Trained XGBoost with scale_pos_weight={spw:.2f}")

    # Validation tuning (recall-first)
    val_proba = model.predict_proba(X_val)[:,1]
    thr = recall_first_threshold(y_val, val_proba, recall_floor=0.97)

    # Evaluate on val and test
    val_pred = (val_proba >= thr).astype(int)
    evaluate(y_val, val_pred, val_proba, "VAL")

    tst_proba = model.predict_proba(X_tst)[:,1]
    tst_pred  = (tst_proba >= thr).astype(int)
    evaluate(y_tst, tst_pred, tst_proba, "TEST")

    # Persist model + threshold + preprocessor
    joblib.dump({"model": model, "threshold": thr}, "models/unsw_trained_model.pkl")
    print("💾 Saved to models/unsw_trained_model.pkl")