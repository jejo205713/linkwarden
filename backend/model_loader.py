import joblib
import os

model = None

def get_model():
    global model
    if model is None:
        model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model.pkl')
        try:
            model = joblib.load(model_path)
        except Exception as e:
            print(f"Error loading model (Did you run train_model.py?): {e}")
    return model
