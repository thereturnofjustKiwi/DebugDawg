import os
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder

CATEGORICAL = ["proto", "service", "state"]
DROP_COLS = ["id", "attack_cat"]
LABEL_COL = "label"

def load_unsw(train_csv, test_csv):
    train = pd.read_csv(train_csv, low_memory=False)
    test  = pd.read_csv(test_csv, low_memory=False)
    return train, test

def clean_df(df):
    return df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()

def build_transformer(df_train):
    all_cols = [c for c in df_train.columns if c not in DROP_COLS + [LABEL_COL, "attack_cat"]]
    numeric = [c for c in all_cols if c not in CATEGORICAL]
    pre = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse=True), CATEGORICAL),
            ("num", StandardScaler(), numeric),
        ],
        remainder="drop",
        sparse_threshold=1.0
    )
    return pre, all_cols

def main(train_csv="data/raw/UNSW_NB15_training-set.csv",
         test_csv="data/raw/UNSW_NB15_testing-set.csv",
         out_dir="data/processed_unsw"):
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs("models", exist_ok=True)

    train, test = load_unsw(train_csv, test_csv)
    train = clean_df(train)
    test = clean_df(test)

    # Binary labels
    y_binary_train = train[LABEL_COL].astype(int).values
    y_binary_test  = test[LABEL_COL].astype(int).values

    # Attack-only subsets for multi-class
    train_attack = train[train[LABEL_COL] == 1].copy()
    test_attack  = test[test[LABEL_COL] == 1].copy()

    # Encode attack_cat on attack-only rows
    le = LabelEncoder()
    y_attack_train = le.fit_transform(train_attack["attack_cat"].astype(str))
    y_attack_test  = le.transform(test_attack["attack_cat"].astype(str))
    joblib.dump(le, "models/unsw_attack_cat_le.pkl")

    # Feature frames for both tasks (same columns)
    X_train_df = train.drop(columns=[LABEL_COL, "attack_cat"] + [c for c in DROP_COLS if c != "attack_cat"], errors="ignore")
    X_test_df  = test.drop(columns=[LABEL_COL, "attack_cat"] + [c for c in DROP_COLS if c != "attack_cat"], errors="ignore")

    # One aligned split for binary: split X, y_binary, AND capture indexes to use for attack-only alignment
    X_tr_df, X_val_df, y_tr_bin, y_val_bin, idx_tr, idx_val = train_test_split(
        X_train_df, y_binary_train, np.arange(len(X_train_df)),
        test_size=0.2, random_state=42, stratify=y_binary_train
    )

    # Fit transformer on full training (to learn all categories), then transform splits
    pre, all_cols = build_transformer(X_tr_df)
    X_tr  = pre.fit_transform(X_tr_df)
    X_val = pre.transform(X_val_df)
    X_tst = pre.transform(X_test_df)

    # Save binary task arrays
    joblib.dump(pre, "models/unsw_preprocessor.pkl")
    joblib.dump(X_tr, os.path.join(out_dir, "X_train.pkl"))
    joblib.dump(X_val, os.path.join(out_dir, "X_val.pkl"))
    joblib.dump(X_tst, os.path.join(out_dir, "X_test.pkl"))
    np.save(os.path.join(out_dir, "y_train_bin.npy"), y_tr_bin)
    np.save(os.path.join(out_dir, "y_val_bin.npy"),   y_val_bin)
    np.save(os.path.join(out_dir, "y_test_bin.npy"),  y_binary_test)

    # Build attack-only matrices using the same transformer and ALIGNED indices
    # Map original indices to attack-only rows
    train_attack_idx_map = train_attack.index.to_numpy()
    # Select those training indices (idx_tr/idx_val) that are attacks
    tr_attack_mask = np.isin(idx_tr, train_attack_idx_map)
    val_attack_mask = np.isin(idx_val, train_attack_idx_map)

    # Build attack-only design matrices from the original DataFrame rows
    X_tr_attack_df = X_train_df.iloc[idx_tr[tr_attack_mask]]
    X_val_attack_df = X_train_df.iloc[idx_val[val_attack_mask]]

    # Targets for attack-only (aligned using index intersection)
    # Create a lookup from global index -> attack class id
    idx_to_attack = dict(zip(train_attack.index.to_numpy(), y_attack_train))
    y_tr_attack = np.array([idx_to_attack[i] for i in idx_tr[tr_attack_mask]])
    y_val_attack = np.array([idx_to_attack[i] for i in idx_val[val_attack_mask]])

    # Transform
    X_tr_attack  = pre.transform(X_tr_attack_df)
    X_val_attack = pre.transform(X_val_attack_df)
    X_tst_attack = pre.transform(test_attack.drop(columns=[LABEL_COL, "attack_cat"], errors="ignore"))

    # Save multiclass arrays
    joblib.dump(X_tr_attack,  os.path.join(out_dir, "X_train_attack.pkl"))
    joblib.dump(X_val_attack, os.path.join(out_dir, "X_val_attack.pkl"))
    joblib.dump(X_tst_attack, os.path.join(out_dir, "X_test_attack.pkl"))
    np.save(os.path.join(out_dir, "y_train_attack.npy"), y_tr_attack)
    np.save(os.path.join(out_dir, "y_val_attack.npy"),   y_val_attack)
    np.save(os.path.join(out_dir, "y_test_attack.npy"),  y_attack_test)

    print("✅ Binary + Attack-only multiclass preprocessing saved with aligned indices.")

if __name__ == "__main__":
    main()
