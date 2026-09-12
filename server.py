"""
server.py
Minimal Flask API server for the IPsec VPN Security Assessment Dashboard.
Wraps the existing SecurityAssessmentEngine — no backend logic changed.
"""
import json
import sys
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.security_engine import SecurityAssessmentEngine
from app.output_formatter import format_assessment

app = Flask(__name__, static_folder="frontend", static_url_path="")
engine = SecurityAssessmentEngine()

EXAMPLES_DIR = PROJECT_ROOT / "examples"


@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")


@app.route("/api/assess", methods=["POST"])
def assess():
    """Run the existing SecurityAssessmentEngine on submitted features."""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON body provided."}), 400

        result = engine.assess(data)
        return jsonify(format_assessment(result))

    except TypeError as e:
        return jsonify({"error": str(e)}), 400
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        return jsonify({"error": f"Internal error: {str(e)}"}), 500


@app.route("/api/example/<name>", methods=["GET"])
def get_example(name):
    """Return one of the three built-in example traffic scenarios."""
    allowed = {"normal", "suspicious", "anomalous"}
    if name not in allowed:
        return jsonify({"error": "Unknown example name."}), 404

    file_path = EXAMPLES_DIR / f"{name}_traffic.json"
    with open(file_path, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    print("=" * 55)
    print("IPsec VPN Security Assessment Dashboard")
    print("Open http://127.0.0.1:5000 in your browser")
    print("=" * 55)
    app.run(debug=True, port=5000)
