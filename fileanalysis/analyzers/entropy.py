"""Shannon entropy analysis for detecting packed/encrypted content."""

from __future__ import annotations
import math
from collections import Counter
from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    EntropyResult,
    Indicator,
    ThreatCategory,
)


# Entropy thresholds
HIGH_ENTROPY_THRESHOLD = 7.0   # Strongly suggests packing/encryption
MEDIUM_ENTROPY_THRESHOLD = 6.5  # Possibly suspicious


class EntropyAnalyzer(BaseAnalyzer):
    """Analyzes Shannon entropy to detect packed/encrypted content."""

    @property
    def name(self) -> str:
        return "Entropy Analyzer"

    DEFAULT_BLOCK_SIZE = 256

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Compute overall, per-block profile, and per-section entropy."""
        overall = self._calculate_entropy(file_bytes)
        is_packed = overall >= HIGH_ENTROPY_THRESHOLD

        # Choose appropriate block size: 256 bytes default, 1024 for files > 512 KB to keep profile responsive
        block_size = 1024 if len(file_bytes) > 512 * 1024 else self.DEFAULT_BLOCK_SIZE
        profile: list[float] = []
        if file_bytes and block_size > 0:
            for offset in range(0, len(file_bytes), block_size):
                chunk = file_bytes[offset:offset + block_size]
                profile.append(round(self._calculate_entropy(chunk), 4))

        result.entropy = EntropyResult(
            overall=round(overall, 4),
            is_packed=is_packed,
            block_size=block_size,
            profile=profile,
        )

        file_len = len(file_bytes)
        if is_packed:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="High Entropy Detected",
                description=(
                    f"Overall file entropy is {overall:.2f}/8.0, strongly suggesting "
                    "the file is packed, encrypted, or compressed to evade analysis."
                ),
                evidence=[f"Entropy: {overall:.4f}"],
                severity=0.7,
                offset=0,
                length=file_len,
            ))
        elif overall >= MEDIUM_ENTROPY_THRESHOLD:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Elevated Entropy",
                description=(
                    f"Overall file entropy is {overall:.2f}/8.0, which may indicate "
                    "partial packing or embedded encrypted payloads."
                ),
                evidence=[f"Entropy: {overall:.4f}"],
                severity=0.4,
                offset=0,
                length=file_len,
            ))

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence.

        Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly random).
        """
        if not data:
            return 0.0

        counts = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def calculate_section_entropy(data: bytes) -> float:
        """Public method to calculate entropy for a section of bytes."""
        return EntropyAnalyzer._calculate_entropy(data)
