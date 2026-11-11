# Flask entrypoint for Vercel - Vercel looks for a top-level `app` variable.
import logging
from pathlib import Path

from flask import Flask, render_template, request, jsonify

from analyzer import analyze_password, validate_password_input

BASE_DIR = Path(__file__).resolve().parent

# Absolute path so the templates folder is found no matter where Vercel runs the code
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))


@app.errorhandler(Exception)
def handle_error(exc):
    # Shows the real error in Vercel -> Logs (never logs the password itself)
    logging.exception("Unhandled error: %s", type(exc).__name__)
    return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.route("/health")
def health():
    # Open /health on your site: if this works, Flask itself is fine
    return jsonify({"status": "ok", "templates_exist": (BASE_DIR / "templates" / "index.html").exists()})


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
