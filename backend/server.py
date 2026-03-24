# ============================================================
# server.py — PhishGuard Flask API
# Run: python server.py
# ============================================================

import os
import pickle
import numpy as np
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

from feature_extraction import extract_features, get_feature_names

app = Flask(__name__)

# ── CORS: allow ALL origins (Chrome extensions, localhost, any site) ──
CORS(app,
     resources={r"/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"],
     supports_credentials=False)

# ── Add CORS headers to EVERY response (belt-and-suspenders) ─────────
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# ── Handle OPTIONS preflight for ALL routes ───────────────────────────
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        resp.headers["Access-Control-Allow-Origin"]  = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return resp

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing.pkl")

try:
    with open(MODEL_PATH, "rb") as _f:
        model = pickle.load(_f)
    print(f"[PhishGuard] ✅ Model loaded: {MODEL_PATH}")
except FileNotFoundError:
    print(f"[PhishGuard] ❌ Model NOT found at {MODEL_PATH}")
    model = None


@app.route("/", methods=["GET"])
def index():
    """Health check."""
    return jsonify({"status": "running", "model_loaded": model is not None})


@app.route("/predict", methods=["POST"])
def predict():
    """
    POST JSON: { "url": "https://example.com" }
    Returns:   { "prediction": "phishing"|"safe", "confidence": 0.0-1.0, "features": {...} }
    """
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Request must be JSON with a 'url' key."}), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "URL cannot be empty."}), 400

    if model is None:
        return jsonify({"error": "ML model not loaded. Add phishing.pkl to /backend/"}), 503

    try:
        features = extract_features(url)
    except Exception as e:
        return jsonify({"error": f"Feature extraction failed: {e}"}), 500

    feature_names = get_feature_names()
    features_dict = dict(zip(feature_names, features))

    print(f"[PhishGuard] Checking: {url}")
    print(f"[PhishGuard] Features: {features_dict}")

    try:
        feature_array  = np.array(features).reshape(1, -1)
        raw_prediction = model.predict(feature_array)[0]
        confidence     = None
        if hasattr(model, "predict_proba"):
            proba      = model.predict_proba(feature_array)[0]
            confidence = float(max(proba))
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {e}"}), 500

    # Map model output to label
    # Adjust if your dataset uses different conventions (e.g., -1/1 or "phishing"/"legitimate")
    if raw_prediction == 1 or str(raw_prediction).lower() in ("phishing", "1", "true"):
        label = "phishing"
    else:
        label = "safe"

    print(f"[PhishGuard] Result  : {label} (raw={raw_prediction})")

    response = {"prediction": label, "url": url, "features": features_dict}
    if confidence is not None:
        response["confidence"] = round(confidence, 4)

    return jsonify(response)


@app.route("/features", methods=["POST"])
def features_only():
    """Debug: return extracted features without prediction."""
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url'."}), 400
    url   = str(data["url"]).strip()
    feats = extract_features(url)
    names = get_feature_names()
    return jsonify({"url": url, "features": dict(zip(names, feats))})


if __name__ == "__main__":
    print("=" * 55)
    print("  PhishGuard — Flask API Server")
    print(f"  Listening on http://127.0.0.1:5000")
    print("=" * 55)
    app.run(host="127.0.0.1", port=5000, debug=True)
