from flask import Flask, jsonify, render_template, request

from detector.checker import check_url

app = Flask(__name__)



@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url or len(url) > 2000:
        return jsonify({"error": "Provide a URL"}), 400
    return jsonify(check_url(url))


if __name__ == "__main__":
    app.run(debug=True)
