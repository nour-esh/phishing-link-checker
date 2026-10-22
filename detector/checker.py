import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse

import requests
import tldextract

# Use the suffix list bundled with the package (no network call, works on Vercel)
extract = tldextract.TLDExtract(suffix_list_urls=())

KEYWORDS = ["login", "verify", "secure", "update", "account", "bank", "confirm",
            "password", "auth", "webmail", "track", "signin", "wallet"]
BRANDS = ["paypal", "google", "facebook", "microsoft", "apple", "amazon", "netflix",
          "instagram", "roblox", "dhl", "fedex", "dpd"]
FREE_HOSTS = [
    "pages.dev", "vercel.app", "netlify.app", "webflow.io", "framer.website",
    "github.io", "web.app", "firebaseapp.com", "weebly.com", "wixsite.com",
    "blogspot.com", "glitch.me", "workers.dev", "herokuapp.com", "carrd.co",
    "gitlab.io", "craftum.io", "4everland.app",
]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rb.gy", "ow.ly", "g5.lu"]
SUSPICIOUS_TLDS = ["xyz", "shop", "cc", "top", "click", "qpon", "icu", "buzz", "cfd", "sbs"]

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

    for h in FREE_HOSTS:
        if host == h or host.endswith("." + h):
            flag(2, f"Hosted on a free platform ({h})")
            break
    if host in SHORTENERS:
        flag(2, "URL shortener hides the real destination")
    if host.count("-") >= 3:
        flag(2, "Many hyphens (looks auto-generated)")
    if ext.suffix in SUSPICIOUS_TLDS:
        flag(1, f"Suspicious TLD (.{ext.suffix})")
    if ext.domain and sum(c.isdigit() for c in ext.domain) / len(ext.domain) > 0.5:
        flag(1, "Domain is mostly digits")

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

    verdict = "SAFE" if score <= 1 else "SUSPICIOUS" if score <= 4 else "PHISHING"
    return {"url": url, "verdict": verdict, "score": score, "reasons": reasons}


if __name__ == "__main__":
    result = check_url(input("Enter URL: "))
    print(result["verdict"], result["score"])
    for r in result["reasons"]:
        print("-", r)
