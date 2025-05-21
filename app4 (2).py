from flask import Flask, render_template, request
import re
import logging
import requests
from urllib.parse import urlparse
import idna
import base64

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Replace with your actual API keys
GOOGLE_API_KEY = 
VIRUSTOTAL_API_KEY = 

def is_online():
    """Check if the system is connected to the internet by pinging Google."""
    try:
        requests.get("https://www.google.com", timeout=3)
        return True
    except requests.RequestException:
        return False

def expand_short_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        if url != response.url:
            return response.url, True
        else:
            return url, False
    except:
        return url, False

def is_valid_url(url):
    """Check if the URL format is valid and if the URL exists."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # Assume HTTP if not provided

    regex = re.compile(
        r'^(http|https)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', re.IGNORECASE
    )
    
    if not re.match(regex, url):
        return False, url, False  # Invalid URL format

    # Check if the URL exists
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True, url, True  # URL exists
        else:
            return True, url, False  # URL does not exist (error response)
    except requests.RequestException:
        return True, url, False  # URL does not exist (server unreachable)

def detect_homograph_attack(url):
    domain = urlparse(url).netloc
    try:
        ascii_domain = idna.encode(domain).decode()
        return domain != ascii_domain
    except:
        return False

def detect_phishing_url(url):
    """Check for suspicious patterns in the URL."""
    patterns = [
        r'login|verify|secure',
        r'-{2,}',
        r'[0-9]{4,}',
        r'@[a-zA-Z0-9.-]+',
        r'\b\d{1,3}(\.\d{1,3}){3}\b'
    ]
    for pattern in patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API."""
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "deon-tech", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(api_url, json=payload, timeout=5)
        data = response.json()
        if "matches" in data:
            return True
        else:
            return False
    except Exception as e:
        logging.error(f"Google API Error: {e}")
        return False

def check_virustotal_url(url):
    """Check URL against VirusTotal API."""
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(vt_url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                return True
        return False
    except Exception as e:
        logging.error(f"VirusTotal API error: {e}")
        return False

@app.route("/", methods=["GET", "POST"])
def home():
    result, details = None, []

    if request.method == "POST":
        # Check internet connectivity
        if not is_online():
            result = "❌ System is offline. Please check your internet connection."
            details.append("The application requires an internet connection for API calls and URL expansion.")
            return render_template("index2.html", result=result, details=details)

        url = request.form.get("url")
        is_valid, normalized_url, url_exists = is_valid_url(url)

        if not is_valid:
            return render_template("index2.html", result="❌ Invalid URL", details=["The URL format is incorrect."])
        if not url_exists:
            return render_template("index2.html", result="⚠️ URL Does Not Exist", details=["The entered URL does not seem to exist."])

        expanded_url, is_shortened = expand_short_url(normalized_url)
        if is_shortened:
            details.append(f"🔍 Shortened URL expanded to: {expanded_url}")

        # Run phishing/homograph/pattern checks
        if detect_homograph_attack(expanded_url):
            details.append("⚠️ The domain uses unusual characters that may indicate a homograph attack.")
            return render_template("index2.html", result="⚠️ Possible Homograph Attack Detected", details=details)

        if detect_phishing_url(expanded_url):
            details.append("🚨 Suspicious patterns detected (e.g., 'login', '@', long numbers, etc).")
            return render_template("index2.html", result="🚨 Suspicious URL Detected", details=details)

        # External checks (Google/VirusTotal)
        if check_google_safe_browsing(expanded_url):
            details.append("🚫 Flagged by Google Safe Browsing.")
        if check_virustotal_url(expanded_url):
            details.append("🚫 Flagged by VirusTotal.")

        if any("🚫" in msg for msg in details):
            return render_template("index2.html", result="🚫 Unsafe URL Detected", details=details)

        details.append("✅ No suspicious patterns or external flags found.")
        result = f"✅ URL appears safe: {expanded_url}"
        return render_template("index2.html", result=result, details=details)

    return render_template("index2.html")

if __name__ == "__main__":
    app.run(debug=True, port=5001)
