import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))
from feature_extractor import get_feature_array

def train():
    print("Loading dataset...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_dir, '..', 'datasets', 'phishing_urls.csv')
    
    df = pd.read_csv(csv_path)
    df['label'] = df['Type'].apply(lambda x: 1 if str(x).strip().lower() == 'phishing' else 0)
    
    # Train ONLY on Phishing URLs to create a "Phishing Profile"
    phishing_df = df[df['label'] == 1]
    if len(phishing_df) == 0:
        phishing_df = df # Fallback if labels are missing
        
    print("Extracting features...")
    features_list = []
    for url in phishing_df['url']:
        try:
            features = get_feature_array(str(url))
            features_list.append(features)
        except Exception:
            pass
            
    X = np.array(features_list)
    
    print("Training Isolation Forest Model...")
    # contamination=0.05 implies we expect a tight cluster of phishing features
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    
    model_path = os.path.join(base_dir, 'phishing_model.pkl')
    joblib.dump(model, model_path)
    print(f"Model saved successfully at: {model_path}")

if __name__ == "__main__":
    train()
