# 🛡️ PhishGuard — Real-Time Phishing Detection System

A machine-learning-powered phishing URL detector consisting of:
- **Chrome Extension** (Manifest V3) — detects URLs in real time
- **Python Flask API** — serves ML predictions
- **Scikit-learn model** — `phishing.pkl` classifies URLs

---

## 📁 Folder Structure

```
phishing-detector/
│
├── extension/                  ← Chrome Extension files
│   ├── manifest.json           ← MV3 config
│   ├── background.js           ← Service worker (badge, caching)
│   ├── content.js              ← Injected into pages (URL checks, banner)
│   ├── popup.html              ← Extension popup UI
│   ├── popup.js                ← Popup logic
│   ├── style.css               ← Warning banner styles
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
└── backend/                    ← Python Flask API
    ├── server.py               ← Main Flask app
    ├── feature_extraction.py   ← URL → feature vector
    ├── phishing.pkl            ← ⬅ YOUR TRAINED MODEL (place here)
    └── requirements.txt        ← Python dependencies
```

---

## ⚙️ Backend Setup (Flask API)

### Step 1 — Place your model
Copy your trained model file into the backend folder:
```
phishing-detector/backend/phishing.pkl
```

> **Model format requirements:**
> - Must be a scikit-learn compatible model saved with `pickle`
> - `model.predict([[...15 features...]])` must return `1` (phishing) or `0` (safe)
> - Optionally supports `model.predict_proba()` for confidence scores
> - The feature vector has **15 features** (see feature_extraction.py for details)

### Step 2 — Create a virtual environment (recommended)
```bash
cd phishing-detector/backend

# Create virtual environment
python3 -m venv venv

# Activate it
# On macOS / Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Start the Flask server
```bash
python server.py
```

You should see:
```
=======================================================
  PhishGuard ML API Server
=======================================================
✅  Model loaded successfully from .../phishing.pkl
    Model type: RandomForestClassifier
Starting Flask server on http://127.0.0.1:5000
```

### Step 5 — Test the API (optional)
```bash
curl -X POST http://127.0.0.1:5000/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "https://paypal-secure.phishing-example.com/login"}'
```

Expected response:
```json
{"prediction": "phishing", "confidence": 94.3}
```

---

## 🧩 Chrome Extension Setup

### Step 1 — Open Chrome Extensions page
Go to:
```
chrome://extensions/
```

### Step 2 — Enable Developer Mode
Toggle **"Developer mode"** ON (top-right corner of the page).

### Step 3 — Load the extension
1. Click **"Load unpacked"**
2. Navigate to the `phishing-detector/extension/` folder
3. Click **"Select Folder"**

The PhishGuard shield icon (🛡️) will appear in your Chrome toolbar.

### Step 4 — Pin the extension (optional)
Click the puzzle-piece icon → click the pin next to PhishGuard.

---

## 🔍 How It Works

| Trigger | What happens |
|---|---|
| Page loads | `content.js` sends the URL to Flask → if phishing, shows red banner |
| User clicks a link | `content.js` intercepts, checks URL → if phishing, confirms before navigating |
| Extension popup opens | Shows current tab status (safe / phishing / checking) |
| Manual URL scan | Type any URL in the popup → click Scan |

### Warning Banner
When phishing is detected:
- 🚨 A **red banner** slides in at the top of the page
- All **password/credential input fields** are disabled and highlighted
- The **extension badge** turns red with a ⚠ symbol
- A browser **confirm dialog** blocks clicked phishing links

---

## 🔬 Feature Vector (15 features)

| # | Feature | Description |
|---|---|---|
| 0 | `url_length` | Total character count |
| 1 | `num_dots` | Number of `.` characters |
| 2 | `has_at_symbol` | 1 if `@` present |
| 3 | `has_hyphen` | 1 if `-` in domain |
| 4 | `num_subdomains` | Subdomain depth |
| 5 | `uses_https` | 1 if HTTPS scheme |
| 6 | `num_digits` | Digit character count |
| 7 | `url_depth` | Path depth (slash count) |
| 8 | `has_ip_address` | 1 if hostname is an IP |
| 9 | `suspicious_words` | Count of phishing keywords |
| 10 | `domain_length` | Hostname character count |
| 11 | `has_port` | 1 if non-standard port used |
| 12 | `query_length` | Length of query string |
| 13 | `has_double_slash` | 1 if `//` in path |
| 14 | `num_special_chars` | Count of `%`, `=`, `&`, `#`, `!` |

---

## 🐛 Troubleshooting

| Issue | Fix |
|---|---|
| "API Unreachable" in popup | Make sure `python server.py` is running |
| Model not loading | Check `phishing.pkl` is in `backend/` folder |
| Extension not detecting URLs | Reload extension in `chrome://extensions/` |
| CORS errors in console | Flask-CORS is included; restart the server |
| Feature mismatch error | Your model expects a different number of features — edit `feature_extraction.py` |

### Feature count mismatch?
If your model was trained with a different number of features, open `feature_extraction.py`
and add/remove features to match your training set. The feature order must exactly match
what was used during model training.

---

## 📄 License
MIT — free to use, modify, and distribute.
