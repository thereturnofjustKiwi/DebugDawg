import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    recall_score, precision_score, f1_score, accuracy_score, roc_auc_score
)
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, recall_score, accuracy_score
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
    y_tr_attack = np.load("data/processed_unsw/y_train_attack.npy")
    y_val_attack = np.load("data/processed_unsw/y_val_attack.npy")
    y_tst_attack = np.load("data/processed_unsw/y_test_attack.npy")
    le = joblib.load("models/unsw_attack_cat_le.pkl")

    # Train multiclass XGBoost
    model_attack = XGBClassifier(
        n_estimators=250, max_depth=6, learning_rate=0.10,
        subsample=0.85, colsample_bytree=0.85, min_child_weight=4,
        reg_lambda=1.0, objective='multi:softprob',
        num_class=len(le.classes_),
        n_jobs=-1, random_state=42
    )
    model_attack.fit(X_tr, y_tr_attack)
    print("✅ Multiclass attack_cat XGBoost trained.")

    # Evaluate
    val_pred_attack = np.argmax(model_attack.predict_proba(X_val), axis=1)
    print("\nVAL:")
    print(classification_report(y_val_attack, val_pred_attack, target_names=le.classes_))

    tst_pred_attack = np.argmax(model_attack.predict_proba(X_tst), axis=1)
    print("\nTEST:")
    print(classification_report(y_tst_attack, tst_pred_attack, target_names=le.classes_))

    joblib.dump(model_attack, "models/unsw_attack_cat_xgb.pkl")