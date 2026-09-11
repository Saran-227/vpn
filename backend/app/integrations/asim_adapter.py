"""Adapter boundary for Asim's feature extractor.

PLACEHOLDER: Do not guess Asim's final schema. Replace `adapt` once the
feature extractor contract is finalized. The frontend only consumes the
standardized schemas under app.schemas.dashboard.
"""
from typing import Any

class AsimAdapter:
    def adapt(self, raw_feature_data: Any) -> dict:
        raise NotImplementedError('Replace with Asim final-output mapping when the schema is provided.')
