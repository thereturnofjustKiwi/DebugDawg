import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
import joblib

CATEGORICAL = ["proto", "service", "state"]
DROP_COLS = ["id", "attack_cat"]
LABEL_COL = "label"

def load_unsw(train_csv, test_csv):
    train = pd.read_csv(train_csv, low_memory=False)
    test  = pd.read_csv(test_csv, low_memory=False)
    return train, test

def clean_df(df):
    df = df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()
    return df

def build_transformer(df_train):
    all_cols = [c for c in df_train.columns if c not in DROP_COLS + [LABEL_COL]]
    numeric = [c for c in all_cols if c not in CATEGORICAL]
    pre = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse=True), CATEGORICAL),
            ("num", StandardScaler(), numeric),
        ],
        remainder="drop",
        sparse_threshold=1.0
    )
    return pre, numeric

def main(train_csv="data/raw/UNSW_NB15_training-set.csv",
         test_csv="data/raw/UNSW_NB15_testing-set.csv",
         out_dir="data/processed_unsw"):
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs("models", exist_ok=True)

    train, test = load_unsw(train_csv, test_csv)
    train = clean_df(train)
    test = clean_df(test)

    X_train_df = train.drop(columns=DROP_COLS + [LABEL_COL], errors="ignore")
    y_train = train[LABEL_COL].astype(int).values

    X_test_df  = test.drop(columns=DROP_COLS + [LABEL_COL], errors="ignore")
    y_test = test[LABEL_COL].astype(int).values

    # Internal validation split from official train set
    X_tr_df, X_val_df, y_tr, y_val = train_test_split(
        X_train_df, y_train, test_size=0.2, random_state=42, stratify=y_train
    )

    pre, numeric = build_transformer(X_tr_df)
    X_tr  = pre.fit_transform(X_tr_df)
    X_val = pre.transform(X_val_df)
    X_tst = pre.transform(X_test_df)

    joblib.dump(pre, "models/unsw_preprocessor.pkl")
    joblib.dump(X_tr, os.path.join(out_dir, "X_train.pkl"))
    joblib.dump(X_val, os.path.join(out_dir, "X_val.pkl"))
    joblib.dump(X_tst, os.path.join(out_dir, "X_test.pkl"))
    np.save(os.path.join(out_dir, "y_train.npy"), y_tr)
    np.save(os.path.join(out_dir, "y_val.npy"), y_val)
    np.save(os.path.join(out_dir, "y_test.npy"), y_test)
    print("✅ UNSW-NB15 preprocessing complete and saved.")

if __name__ == "__main__":
    main()
