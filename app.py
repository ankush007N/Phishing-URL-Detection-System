from flask import Flask, render_template, request
import pickle
import re
import dns.resolver
import whois
import ssl
import socket
import difflib
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

model = pickle.load(open("phishing_model.pkl", "rb"))


def domain_exists(domain):
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except:
        return False


def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
        return True
    except:
        return False


def domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days
        return age_days
    except:
        return None


def detect_brand_impersonation(domain):

    trusted_domains = [
        "google.com","google.co.in",
        "amazon.com","amazon.in",
        "paypal.com",
        "facebook.com",
        "instagram.com",
        "apple.com",
        "microsoft.com",
        "netflix.com",
        "whatsapp.com",
        "reddit.com"
    ]

    if domain in trusted_domains:
        return None

    brands = [
        "google","paypal","amazon","facebook","instagram",
        "icloud","apple","microsoft","netflix","whatsapp","reddit"
    ]

    for brand in brands:
        if brand in domain:
            return f"Possible {brand} impersonation"

    return None


# 🔹 Typosquatting detection
def detect_typosquatting(domain):

    popular_domains = [
        "google.com","paypal.com","amazon.com",
        "facebook.com","apple.com","instagram.com",
        "microsoft.com","reddit.com"
    ]

    for real_domain in popular_domains:
        similarity = difflib.SequenceMatcher(None, domain, real_domain).ratio()

        if similarity > 0.85 and domain != real_domain:
            return f"Domain similar to {real_domain} (possible typosquatting)"

    return None


def analyze_url(url):

    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")

    if not domain_exists(domain):
        reasons.append("Domain does not exist")

    if not check_ssl(domain):
        reasons.append("No valid SSL certificate")

    age = domain_age(domain)
    if age is not None and age < 30:
        reasons.append("Domain is very new")

    if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain):
        reasons.append("URL contains IP address")

    keywords = ["login","verify","secure","bank","update"]
    if any(k in url.lower() for k in keywords):
        reasons.append("Suspicious keywords detected")

    suspicious_tlds = [".xyz",".tk",".ml",".ga",".cf",".top"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        reasons.append("Suspicious domain extension")

    # 🔹 URL shortener detection
    shorteners = ["bit.ly","tinyurl.com","goo.gl","ow.ly","t.co","is.gd","buff.ly"]
    if domain in shorteners:
        reasons.append("URL shortener detected (can hide phishing links)")

    brand_check = detect_brand_impersonation(domain)
    if brand_check:
        reasons.append(brand_check)

    typo_check = detect_typosquatting(domain)
    if typo_check:
        reasons.append(typo_check)

    return reasons


def extract_features(url):

    features = []

    features.append(-1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 1)
    features.append(-1 if len(url) > 75 else 1)
    features.append(-1 if "@" in url else 1)
    features.append(-1 if "-" in url else 1)
    features.append(-1 if url.count(".") > 3 else 1)
    features.append(1 if url.startswith("https") else -1)

    while len(features) < 49:
        features.append(1)

    return [features]


@app.route("/", methods=["GET","POST"])
def home():

    result = None
    reasons = []
    risk = 0
    url = ""

    if request.method == "POST":

        url = request.form["url"].strip()

        if not url.startswith("http"):
            url = "https://" + url

        if not re.match(r'https?://[^\s]+\.[^\s]+', url):
            result = "❌ Invalid URL"
            return render_template("index.html", result=result)

        reasons = analyze_url(url)

        # 🔹 Risk score calculation
        risk = min(len(reasons) * 20, 100)

        features = extract_features(url)
        prediction = model.predict(features)[0]

        if prediction == -1 or risk >= 60:
            result = "🚨 Phishing Website Detected"

        elif risk >= 20:
            result = "⚠️ Suspicious Website"

        else:
            result = "✅ Legitimate Website"

    return render_template("index.html", result=result, reasons=reasons, risk=risk, url=url)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/help", methods=["GET","POST"])
def help():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        subject = request.form["subject"]
        category = request.form["category"]
        message = request.form["message"]

        with open("message.txt", "a") as f:
            f.write(f"\nName: {name}\n")
            f.write(f"Email: {email}\n")
            f.write(f"Subject: {subject}\n")
            f.write(f"Category: {category}\n")
            f.write(f"Message: {message}\n")
            f.write("---------------------\n")

        return render_template("help.html", success="Message sent successfully")

    return render_template("help.html")

@app.route("/usecases")
def usecases():
    return render_template("usecases.html")

if __name__ == "__main__":
    app.run(debug=True)
