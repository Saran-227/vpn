import json
import sys
from pathlib import Path


# Add the project root to Python's import path.
# This allows the script to import the app package
# when executed as:
# python examples/run_example.py

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from app.security_engine import SecurityAssessmentEngine
from app.output_formatter import assessment_to_json


EXAMPLES_DIR = Path(__file__).resolve().parent


def load_example(filename):
    """
    Load an example traffic feature file.
    """

    file_path = EXAMPLES_DIR / filename

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def run_example(filename, title):
    """
    Run one traffic example through the
    Security Assessment Engine.
    """

    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    features = load_example(filename)

    engine = SecurityAssessmentEngine()

    assessment = engine.assess(features)

    formatted_result = assessment_to_json(
        assessment
    )

    print(formatted_result)


def main():
    """
    Run all example traffic scenarios.
    """

    run_example(
        "normal_traffic.json",
        "NORMAL TRAFFIC"
    )

    run_example(
        "suspicious_traffic.json",
        "SUSPICIOUS TRAFFIC"
    )

    run_example(
        "anomalous_traffic.json",
        "ANOMALOUS TRAFFIC"
    )


if __name__ == "__main__":
    main()