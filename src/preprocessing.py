import os
import numpy as np
import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.model_selection import train_test_split

# UNSW-NB15 Constants
CATEGORICAL_COLS = ["proto", "service", "state"]
DROP_COLS = ["id", "attack_cat"]  # Dropping attack_cat for binary focus
LABEL_COL = "label"

def load_data(train_path, test_path):

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    return train_df, test_df

def clean_data(df):
    # Basic cleanup
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df

def build_preprocessor(df_sample):
    # Identify numeric columns automatically (excluding cat and label/drops)
    all_cols = [c for c in df_sample.columns if c not in DROP_COLS + [LABEL_COL]]
    numeric_cols = [c for c in all_cols if c not in CATEGORICAL_COLS]
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL_COLS),
            ('num', StandardScaler(), numeric_cols)
        ],
        remainder='drop'  # Drop columns not in transformers
    )
    return preprocessor, numeric_cols

def preprocess_and_save(
    train_csv="data/raw/UNSW_NB15_training-set.csv",
    test_csv="data/raw/UNSW_NB15_testing-set.csv",
    output_dir="data/processed",
    model_dir="models"
):
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(model_dir, exist_ok=True)

    # Load
    train_df, test_df = load_data(train_csv, test_csv)
    train_df = clean_data(train_df)
    test_df = clean_data(test_df)

    # Split Features/Target
    X_train_raw = train_df.drop(columns=[LABEL_COL] + [c for c in DROP_COLS if c in train_df.columns], errors='ignore')
    y_train = train_df[LABEL_COL].values
    
    X_test_raw = test_df.drop(columns=[LABEL_COL] + [c for c in DROP_COLS if c in test_df.columns], errors='ignore')
    y_test = test_df[LABEL_COL].values

    # Build and Fit Preprocessor on Train
    preprocessor, _ = build_preprocessor(X_train_raw)
    X_train_processed = preprocessor.fit_transform(X_train_raw)
    
    # Transform Test
    X_test_processed = preprocessor.transform(X_test_raw)

    # Save
    np.save(os.path.join(output_dir, "X_train.npy"), X_train_processed)
    np.save(os.path.join(output_dir, "y_train.npy"), y_train)
    np.save(os.path.join(output_dir, "X_test.npy"), X_test_processed)
    np.save(os.path.join(output_dir, "y_test.npy"), y_test)
    
    joblib.dump(preprocessor, os.path.join(model_dir, "unsw_preprocessor.pkl"))


if __name__ == "__main__":
    preprocess_and_save()
