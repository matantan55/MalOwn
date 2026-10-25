"""Serializes analysis results to JSON format."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum

from fileanalysis.analyzers.base import AnalysisResult


class JsonReporter:
    """Exports analysis results to standard JSON structure."""

    def render(self, result: AnalysisResult) -> str:
        """Serialize AnalysisResult dataclass to JSON string."""
        data = asdict(result)

        # Convert enum types to their string values in the JSON output
        data["risk_level"] = result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level)
        data["nn_risk_level"] = result.nn_risk_level.value if hasattr(result.nn_risk_level, "value") else str(result.nn_risk_level)
        data["nn_score"] = result.nn_score
        data["nn_confidence"] = result.nn_confidence
        data["ml_risk_level"] = result.ml_risk_level.value if hasattr(result.ml_risk_level, "value") else str(result.ml_risk_level)
        data["ml_score"] = result.ml_score
        data["ml_confidence"] = result.ml_confidence
        data["ensemble_risk_level"] = result.ensemble_risk_level.value if hasattr(result.ensemble_risk_level, "value") else str(result.ensemble_risk_level)
        data["ensemble_score"] = result.ensemble_score
        data["scoring_method"] = result.scoring_method
        data["mode"] = result.mode

        def _clean_enums(obj):
            if isinstance(obj, dict):
                return {k: _clean_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_clean_enums(x) for x in obj]
            elif isinstance(obj, Enum):
                return obj.value
            elif hasattr(obj, "value"):
                return obj.value
            return obj

        cleaned = _clean_enums(data)
        return json.dumps(cleaned, indent=2, default=str)
