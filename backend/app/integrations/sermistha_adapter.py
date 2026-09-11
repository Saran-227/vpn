"""Adapter boundary for Sermistha's Security Assessment Engine.

PLACEHOLDER: Accept the engine's final result and map it to the standardized
SecurityState / Finding contract without exposing engine internals to React.
"""
from typing import Any

class SermisthaAdapter:
    def adapt(self, raw_security_result: Any) -> dict:
        raise NotImplementedError('Replace with Sermistha final-output mapping when the schema is provided.')
