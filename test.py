import pandas as pd
import pickle
import os

# Define file paths
CSV_PATH = 'Extraction layer/sample.csv'
MODEL_PATH = 'model/trained_model.pkl'

def inspect_pickle_file(model_path):
    """Inspect what's inside the pickle file"""
    with open(model_path, 'rb') as f:
        obj = pickle.load(f)
    
    print(f"Type of loaded object: {type(obj)}")
    
    if isinstance(obj, dict):
        print("Dictionary keys:", obj.keys())
        for key, value in obj.items():
            print(f"  {key}: {type(value)}")
        return obj
    else:
        return obj

def load_model(model_path):
    """Load the trained model from pickle"""
    with open(model_path, 'rb') as f:
        obj = pickle.load(f)
    
    # If it's a dictionary, extract the model
    if isinstance(obj, dict):
        # Common keys: 'model', 'classifier', 'regressor', 'xgb_model'
        if 'model' in obj:
            model = obj['model']
        elif 'classifier' in obj:
            model = obj['classifier']
        elif 'regressor' in obj:
            model = obj['regressor']
        else:
            # Print all keys and raise error
            print("Available keys in pickle:", obj.keys())
            raise KeyError("Cannot find model in dictionary. Check keys above.")
        
        print(f"Extracted model type: {type(model)}")
        return model, obj  # Return both model and full dict (for scaler, etc.)
    else:
        return obj, None

def load_csv_data(csv_path):
    """Load CSV data - handles files with/without headers"""
    # First, try to detect if file has headers
    df_test = pd.read_csv(csv_path, nrows=5)
    
    # If first column name is a number, likely no header
    if df_test.columns[0].isdigit():
        print("No headers detected. Loading with header=None")
        df = pd.read_csv(csv_path, header=None)
    else:
        df = pd.read_csv(csv_path)
    
    print(f"Data loaded. Shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    print(f"\nFirst few rows:\n{df.head()}")
    
    return df

def main():
    # First, inspect what's in the pickle file
    print("="*60)
    print("INSPECTING PICKLE FILE")
    print("="*60)
    obj = inspect_pickle_file(MODEL_PATH)
    
    print("\n" + "="*60)
    print("LOADING MODEL")
    print("="*60)
    model, full_obj = load_model(MODEL_PATH)
    print("✓ Model loaded successfully!")
    
    print("\n" + "="*60)
    print("LOADING CSV DATA")
    print("="*60)
    data = load_csv_data(CSV_PATH)
    
    # If pickle contains scaler, apply it
    if full_obj and 'scaler' in full_obj:
        print("\n✓ Scaler found in pickle file. Applying...")
        scaler = full_obj['scaler']
        data_scaled = scaler.transform(data)
        data = pd.DataFrame(data_scaled, columns=data.columns)
    
    print("\n" + "="*60)
    print("MAKING PREDICTIONS")
    print("="*60)
    predictions = model.predict(data)
    
    # Add predictions to dataframe
    data['predictions'] = predictions
    
    print(f"✓ Predictions completed for {len(predictions)} samples")
    print(f"\nFirst few predictions:\n{data[['predictions']].head()}")
    
    # Save results
    output_path = 'Extraction layer/predictions_output.csv'
    data.to_csv(output_path, index=False)
    print(f"\n✓ Full results saved to {output_path}")

if __name__ == "__main__":
    main()
