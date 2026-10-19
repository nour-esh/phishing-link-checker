# Phishing Link Checker

A simple rule-based tool that scores a URL on common phishing red flags and explains why.

## Structure
- `app.py` - Flask app (web page + `/api/check` endpoint)
- `detector/checker.py` - the detection rules and scoring
- `templates/index.html` - the web page
- `scripts/evaluate.py` - measures detection and false-positive rates
- `data/` - URL lists for evaluation (replace with PhishTank/OpenPhish and Tranco samples)

## Run
    pip install -r requirements.txt
    python app.py

## Evaluate
    python -m scripts.evaluate
    python -m scripts.evaluate --age

## Deploy
Push to GitHub and import the repo in Vercel, or run `vercel` in this folder.
