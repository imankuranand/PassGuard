# Flask entrypoint for Vercel - Vercel looks for a top-level `app` variable.
from flask import Flask, render_template, request, jsonify

from analyzer import analyze_password, validate_password_input

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    is_valid, error_message = validate_password_input(password)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    try:
        result = analyze_password(password)
    except Exception:
        # Generic message - never echo the password back
        return jsonify({"error": "Analysis failed. Please try again."}), 500

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
