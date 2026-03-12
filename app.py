from flask import Flask, render_template, request
import pickle
import re

app = Flask(__name__)

# Load trained ML model
model = pickle.load(open("phishing_model.pkl", "rb"))

# Analyze URL and generate reasons
def analyze_url(url):

    reasons = []

    # IP address check
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url):
        reasons.append("URL contains an IP address")

    # URL length
    if len(url) > 75:
        reasons.append("URL is unusually long")

    # Suspicious symbols
    if "@" in url:
        reasons.append("URL contains '@' symbol")

    # HTTPS check
    if not url.startswith("https"):
        reasons.append("Website not using HTTPS")

    # Suspicious keywords
    keywords = ["login","verify","update","secure","bank","account"]
    if any(k in url.lower() for k in keywords):
        reasons.append("URL contains suspicious keywords")

    return reasons


# Feature extraction for ML model
def extract_features(url):

    features = []

    # Using IP
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features.append(-1 if re.search(ip_pattern, url) else 1)

    # URL length
    features.append(-1 if len(url) > 75 else 1)

    # Short URL services
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly"]
    features.append(-1 if any(s in url for s in shorteners) else 1)

    # @ symbol
    features.append(-1 if "@" in url else 1)

    # Redirecting using //
    features.append(-1 if url.count("//") > 1 else 1)

    # Prefix-suffix (-)
    features.append(-1 if "-" in url else 1)

    # Subdomains
    features.append(-1 if url.count(".") > 3 else 1)

    # HTTPS usage
    features.append(1 if url.startswith("https") else -1)

    # Fill remaining features (dataset requires 30)
    while len(features) < 30:
        features.append(1)

    return [features]


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    risk = None
    reasons = []

    if request.method == "POST":

        url = request.form["url"]

        # Extract features
        features = extract_features(url)

        # ML Prediction
        prediction = model.predict(features)[0]

        # Risk score
        prob = model.predict_proba(features)[0]
        risk = round(max(prob) * 100, 2)

        # Reasons for detection
        reasons = analyze_url(url)

        if prediction == -1:
            result = "⚠️ Phishing Website Detected"
        else:
            result = "✅ Legitimate Website"

    return render_template("index.html", result=result, risk=risk, reasons=reasons)


if __name__ == "__main__":
    app.run(debug=True)