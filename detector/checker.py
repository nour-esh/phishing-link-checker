import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse

import requests
import tldextract

# Use the suffix list bundled with the package (no network call, works on Vercel)
extract = tldextract.TLDExtract(suffix_list_urls=())

KEYWORDS = ["login", "verify", "secure", "update", "account", "bank", "confirm", "password"]
BRANDS = ["paypal", "google", "facebook", "microsoft", "apple", "amazon", "netflix", "instagram"]

_age_cache = {}


def normalize(url):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def is_valid_url(url):                              
    """True only if the input has a real domain (name + suffix) or an IP address."""
    url = normalize(url)
    if " " in url:
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        return True
    ext = extract(host)
    return bool(ext.domain and ext.suffix)          


def domain_age_days(domain):
    """Ask RDAP (the modern, HTTP-based WHOIS) when the domain was registered."""
    if domain in _age_cache:
        return _age_cache[domain]
    age = None
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=4)
        if r.ok:
            for event in r.json().get("events", []):
                if event.get("eventAction") == "registration":
                    created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - created).days
                    break
    except Exception:
        pass
    _age_cache[domain] = age
    return age


def lookalike(ext):
    """Return a reason if the domain imitates a known brand, else None."""
    # undo common character swaps: paypa1 -> paypal, g00gle -> google
    cleaned = ext.domain.translate(str.maketrans("01", "ol"))
    for brand in BRANDS:
        if ext.domain != brand and SequenceMatcher(None, cleaned, brand).ratio() > 0.8:
            return f"Domain looks like '{brand}'"
        if brand in ext.subdomain.lower().split(".") and ext.domain != brand:
            return f"'{brand}' used as a subdomain of {ext.top_domain_under_public_suffix}"
    return None


def check_url(url, use_age=True):
    url = normalize(url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    ext = extract(host)

    score, reasons = 0, []

    def flag(points, reason):
        nonlocal score
        score += points
        reasons.append(f"{reason} (+{points})")

    if parsed.scheme != "https":
        flag(1, "No HTTPS")
    if re.fullmatch(r"[\d.]+", host):
        flag(3, "IP address instead of a domain")
    if "@" in url:
        flag(2, "Contains @ symbol")
    if len(url) > 75:
        flag(1, "Very long URL")
    if host.count(".") > 3:
        flag(2, "Too many subdomains")
    if "-" in ext.domain:
        flag(1, "Hyphen in domain")
    if any(k in url.lower() for k in KEYWORDS):
        flag(1, "Suspicious keyword")
    if "xn--" in host:
        flag(2, "Punycode (possible lookalike characters)")

    match = lookalike(ext)
    if match:
        flag(3, match)

    if use_age and ext.top_domain_under_public_suffix:
        age = domain_age_days(ext.top_domain_under_public_suffix)
        if age is None:
            reasons.append("Domain age unknown (lookup failed)")
        elif age < 30:
            flag(3, f"Domain only {age} days old")
        elif age < 180:
            flag(1, f"Fairly new domain ({age} days)")

    verdict = "SAFE" if score <= 1 else "SUSPICIOUS" if score <= 3 else "PHISHING"
    return {"url": url, "verdict": verdict, "score": score, "reasons": reasons}


if __name__ == "__main__":
    result = check_url(input("Enter URL: "))
    print(result["verdict"], result["score"])
    for r in result["reasons"]:
        print("-", r)
