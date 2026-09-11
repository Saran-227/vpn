import csv
from dataclasses import fields
from pathlib import Path

from analyzer.feature_extractor.features import FlowFeatures


def export_features_to_csv(
    features: list[FlowFeatures],
    output_path: str | Path,
) -> None:
    path = Path(output_path)

    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [field.name for field in fields(FlowFeatures)]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()

        for feature in features:
            writer.writerow(
                {
                    field_name: getattr(feature, field_name)
                    for field_name in fieldnames
                }
            )
