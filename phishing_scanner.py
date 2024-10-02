import requests
import re
from urllib.parse import urlparse

BLACKLISTED_DOMAINS = [
    "malicious.com",
    "phishing.com",
    "fakebank.com",
]

def is_blacklisted(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain in BLACKLISTED_DOMAINS

def contains_phishing_keywords(url):
    phishing_keywords = ["login", "secure", "update", "account", "verify", "confirm"]
    return any(keyword in url.lower() for keyword in phishing_keywords)

def check_http_status(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except requests.exceptions.RequestException:
        return None

def analyze_url(url):
    print(f"Analyzing URL: {url}")
    
    if is_blacklisted(url):
        print("Warning: This URL is blacklisted!")
        return True

    if contains_phishing_keywords(url):
        print("Warning: This URL contains phishing keywords!")
        return True

    status_code = check_http_status(url)
    if status_code is None:
        print("Error: Unable to access the URL.")
        return True
    elif status_code != 200:
        print(f"Warning: Received HTTP status code {status_code}. This could indicate a problem.")
        return True

    print("This URL appears to be safe.")
    return False

def main():
    print("Welcome to the Phishing Link Scanner")
    while True:
        url = input("Enter a URL to check (or type 'exit' to quit): ")
        if url.lower() == 'exit':
            break
        analyze_url(url)

if __name__ == "__main__":
    main()
