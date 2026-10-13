import re
from urllib.parse import urlparse

def extract_features(url):
    features = []

    # URL Length
    features.append(len(url))

    # IP Address in URL
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)

    # Dot Count
    features.append(url.count('.'))

    # @ Symbol
    features.append(1 if '@' in url else 0)

    # HTTPS
    features.append(1 if url.startswith("https://") else 0)

    # Suspicious Keywords
    suspicious = ['login', 'secure', 'bank', 'verify', 'update', 'account']
    features.append(1 if any(word in url.lower() for word in suspicious) else 0)

    # Hyphen in Domain
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    features.append(1 if '-' in domain else 0)

    # Number Count
    digits = sum(c.isdigit() for c in url)
    features.append(digits)

    return features


def analyze_url(url):
    vulnerabilities = []
    risk_score = 0

    suspicious = ['login', 'secure', 'bank', 'verify', 'update', 'account']

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # 1. No HTTPS
    if not url.startswith("https://"):
        risk_score += 10
        vulnerabilities.append("No HTTPS")

    # 2. IP Address Used
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        risk_score += 20
        vulnerabilities.append("Uses IP address")

    # 3. @ Symbol
    if '@' in url:
        risk_score += 15
        vulnerabilities.append("Contains @ symbol")

    # 4. Too Many Dots
    if domain.count('.') >= 3:
        risk_score += 10
        vulnerabilities.append("Too many subdomains")

    # 5. Suspicious Keywords
    found_words = [word for word in suspicious if word in url.lower()]
    if found_words:
        risk_score += min(len(found_words) * 5, 15)
        vulnerabilities.append("Suspicious keywords")

    # 6. Long URL
    length = len(url)
    if length > 50:
        extra = min((length - 50) // 5, 15)
        risk_score += extra
        vulnerabilities.append("Long URL")

    # 7. Hyphen in Domain
    if '-' in domain:
        risk_score += 10
        vulnerabilities.append("Hyphen in domain")

    # 8. Too Many Numbers
    digits = sum(c.isdigit() for c in url)
    if digits >= 5:
        risk_score += 10
        vulnerabilities.append("Too many numbers")

    # 9. Very Short Domain
    clean_domain = domain.replace("www.", "").split('.')[0]
    if len(clean_domain) <= 3:
        risk_score += 5
        vulnerabilities.append("Suspicious short domain")

    # Limit score to 100
    risk_score = min(risk_score, 100)

    return vulnerabilities, risk_score
