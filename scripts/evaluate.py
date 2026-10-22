import sys

from detector.checker import check_url

use_age = "--age" in sys.argv


def load(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def run(urls):
    flagged, safe = [], []
    for u in urls:
        result = check_url(u, use_age=use_age)
        if result["verdict"] == "SAFE":
            safe.append(u)
        else:
            flagged.append((u, result["reasons"]))
    return flagged, safe


phishing = load("data/phishing.txt")
legit = load("data/legit.txt")

caught, missed = run(phishing)
false_pos, _ = run(legit)

print(f"Mode: {'with domain age' if use_age else 'URL rules only'}")
print(f"Phishing URLs tested: {len(phishing)}")
print(f"Detection rate: {len(caught) / len(phishing):.1%}")
print(f"Legit URLs tested: {len(legit)}")
print(f"False-positive rate: {len(false_pos) / len(legit):.1%}")

print("\nLegit URLs wrongly flagged:")
for u, reasons in false_pos:
    print(" -", u, reasons)

print("\nFirst 10 phishing URLs it missed:")
for u in missed[:10]:
    print(" -", u)