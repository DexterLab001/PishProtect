from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import joblib
import numpy as np
import re
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Cyber Threat Detection API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Feature Extractor for URLs --- #
def extract_url_features(url: str):
    parsed = urlparse(url)
    return [
        len(url),
        url.count('.'),
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        url.count('-'),
        url.count('/'),
        1 if parsed.scheme == 'https' else 0
    ]

# --- Load Models --- #
try:
    intrusion_model = joblib.load("intrusion_model.pkl")
    phishing_email_model = joblib.load("phishing_email_model.pkl")
    email_vectorizer = joblib.load("email_vectorizer.pkl")
    phishing_url_model = joblib.load("phishing_url_model.pkl")
    try:
        intrusion_label_encoder = joblib.load("intrusion_label_encoder.pkl")
    except FileNotFoundError:
        intrusion_label_encoder = None
except Exception as e:
    raise RuntimeError(f"Model loading failed: {e}")

# --- Input Schemas --- #
class IntrusionInput(BaseModel):
    features: List[float]

class EmailInput(BaseModel):
    email_text: str

class RawURLInput(BaseModel):
    url: str

@app.post("/predict_intrusion")
def predict_intrusion(data: IntrusionInput):
    try:
        if len(data.features) != 41:
            raise ValueError("Model requires exactly 41 features.")

        X = np.array(data.features).reshape(1, -1)
        pred_raw = intrusion_model.predict(X)[0]

        # Skip encoder and map directly
        label = "Threat" if pred_raw == -1 else "Safe"
        return {"prediction": label}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Intrusion prediction failed: {str(e)}")


@app.post("/predict_phishing_email")
def predict_email(data: EmailInput):
    try:
        pred_raw = phishing_email_model.predict([data.email_text])[0]
        if isinstance(pred_raw, str):
            label = "Phishing" if "phishing" in pred_raw.lower() else "Safe"
        else:
            label = "Phishing" if int(pred_raw) == 1 else "Safe"
        return {"prediction": label}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Email prediction failed: {str(e)}")

WHITELIST = ["google.com", "github.com", "microsoft.com", "wikipedia.org"]

@app.post("/predict_phishing_url")
def predict_phishing_url(data: RawURLInput):
    try:
        domain = urlparse(data.url).netloc.lower().replace("www.", "")
        if domain in WHITELIST:
            return {"prediction": "Safe"}

        features = extract_url_features(data.url)
        X = np.array(features).reshape(1, -1)
        pred = phishing_url_model.predict(X)
        label = "Phishing" if int(pred[0]) == 1 else "Safe"
        return {"prediction": label}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"URL prediction failed: {str(e)}")

