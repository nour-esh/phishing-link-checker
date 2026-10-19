"""
Measure how well the checker works.

Usage:
    python -m scripts.evaluate      # fast, URL-only rules
    python -m scripts.evaluate --age  # also uses domain age (slow, one lookup per domain)

Files needed (one URL per line), run from the project root:
    data/phishing.txt   e.g. from PhishTank / OpenPhish
    data/legit.txt e.g. top domains from the Tranco list
"""
import sys

from detector.checker import check_url

use_age = "--age" in sys.argv


def load(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def run(urls):
    flagged, missed = 0, []
    for u in urls:
        result = check_url(u, use_age=use_age)
        if result["verdict"] != "SAFE":
            flagged += 1
        else:
            missed.append(u)
    return flagged, missed


phishing = load("data/phishing.txt")
legit = load("data/legit.txt")

caught, missed = run(phishing)
false_pos, _ = run(legit)

print(f"Mode: {'with domain age' if use_age else 'URL rules only'}")
print(f"Phishing URLs tested: {len(phishing)}")
print(f"Detection rate: {caught / len(phishing):.1%}")
print(f"Legit URLs tested: {len(legit)}")
print(f"False-positive rate: {false_pos / len(legit):.1%}")

print("\nFirst 10 phishing URLs it missed (study these, then add a check):")
for u in missed[:10]:
    print(" -", u)
