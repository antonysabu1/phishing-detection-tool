from flask import Flask, render_template, request
import re
import logging

app = Flask(__name__)

# Enable logging
logging.basicConfig(level=logging.INFO)

# Function to check if a URL is valid
def is_valid_url(url):
    url = url.strip()  # Remove leading/trailing spaces
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # Add protocol if missing
    regex = re.compile(
        r'^(http|https)://'                  # Requires http or https
        r'([a-zA-Z0-9.-]+)'                  # Domain name
        r'(\.[a-zA-Z]{2,})'                 # Top-level domain
        r'(:[0-9]{1,5})?'                   # Optional port
        r'(\/.*)?$',                        # Optional path
        re.IGNORECASE
    )
    return re.match(regex, url) is not None, url

# Basic phishing URL pattern detection
def detect_phishing_url(url):
    suspicious_patterns = [
        r'login|verify|secure',             # Contains suspicious words
        r'-{2,}',                          # Double dashes in domain
        r'[0-9]{4,}',                      # Long numeric strings
        r'@[a-zA-Z0-9.-]+',                # Contains '@' in the URL
        r'\b\d{1,3}(\.\d{1,3}){3}\b'       # Contains IP address
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form.get("url")
        is_valid, normalized_url = is_valid_url(url)

        if not is_valid:
            return render_template("index.html", result="Invalid URL. Please enter a valid URL.")

        if detect_phishing_url(normalized_url):
            result = f"Warning: The URL '{normalized_url}' contains phishing patterns."
        else:
            result = f"The URL '{normalized_url}' appears safe based on pattern checks."

        # Log the result for debugging or tracking
        logging.info(f"Checked URL: {normalized_url}, Result: {result}")
        return render_template("index.html", result=result)

    return render_template("index.html", result=None)

if __name__ == "__main__":
    app.run(debug=True)
