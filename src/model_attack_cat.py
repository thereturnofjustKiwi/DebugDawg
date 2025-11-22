import joblib, numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import recall_score, classification_report
from collections import Counter

# Load attack-only features/labels
X_tr = joblib.load("data/processed_unsw/X_train_attack.pkl")
X_val = joblib.load("data/processed_unsw/X_val_attack.pkl")
X_tst = joblib.load("data/processed_unsw/X_test_attack.pkl")
y_tr  = np.load("data/processed_unsw/y_train_attack.npy")
y_val = np.load("data/processed_unsw/y_val_attack.npy")
y_tst = np.load("data/processed_unsw/y_test_attack.npy")
le    = joblib.load("models/unsw_attack_cat_le.pkl")
classes = list(range(len(le.classes_)))

# Class weights to offset imbalance inside each binary classifier
cnt = Counter(y_tr)
maxc = max(cnt.values())
cls_wt = {c: maxc / cnt[c] for c in cnt}

def train_one_vs_rest(c):
    y_tr_bin  = (y_tr == c).astype(int)
    y_val_bin = (y_val == c).astype(int)

    w_tr = np.where(y_tr_bin == 1, cls_wt[c], 1.0)

    clf = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.10,
        subsample=0.85, colsample_bytree=0.85, min_child_weight=4,
        reg_lambda=1.0, objective='binary:logistic',
        n_jobs=-1, random_state=42
    )
    clf.fit(X_tr, y_tr_bin, sample_weight=w_tr)
    # Find lowest threshold with recall >= floor
    val_proba = clf.predict_proba(X_val)[:,1]
    thr = 0.05
    for t in np.arange(0.05, 0.91, 0.01):
        pred = (val_proba >= t).astype(int)
        rec = recall_score(y_val_bin, pred, zero_division=0)
        if rec >= 0.80:  # per-class recall floor; adjust per class if needed
            thr = t
            break
    return clf, thr

# Train all OvR heads
heads = {}
for c in classes:
    print("Training OvR for:", le.classes_[c])
    clf, thr = train_one_vs_rest(c)
    heads[c] = {"clf": clf, "thr": thr}

joblib.dump({"heads": heads, "classes": le.classes_}, "models/unsw_attack_cat_ovr.pkl")

# Evaluate on test: choose class with highest margin (proba - thr) among those exceeding threshold
def predict_ovr(X):
    best_c, best_margin = None, -1e9
    for c, h in heads.items():
        p = h["clf"].predict_proba(X)[:,1]
        margin = p - h["thr"]
        # candidate: margin > 0
        if margin[0] > best_margin:
            best_margin = margin[0]
            best_c = c
    return best_c

y_pred = []
for i in range(X_tst.shape[0]):
    y_pred.append(predict_ovr(X_tst[i]))
y_pred = np.array(y_pred, dtype=int)

print("\nTEST (OvR, attacks only):")
print(classification_report(y_tst, y_pred, target_names=le.classes_))
