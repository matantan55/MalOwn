"""Cryptographic hash computation for file analysis."""

from __future__ import annotations
import hashlib
import pefile
import ppdeep
from fileanalysis.analyzers.base import AnalysisResult, BaseAnalyzer, HashResult


class HashAnalyzer(BaseAnalyzer):
    """Computes MD5, SHA-1, SHA-256, and ssdeep/imphash."""

    @property
    def name(self) -> str:
        return "Hash Calculator"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Compute all hashes for the file."""
        md5_val = hashlib.md5(file_bytes).hexdigest()
        sha1_val = hashlib.sha1(file_bytes).hexdigest()
        sha256_val = hashlib.sha256(file_bytes).hexdigest()
        ssdeep_val = self._compute_ssdeep(file_bytes)
        imphash_val = self._compute_imphash(file_path)

        result.hashes = HashResult(
            md5=md5_val,
            sha1=sha1_val,
            sha256=sha256_val,
            ssdeep=ssdeep_val,
            imphash=imphash_val,
        )

        # Add typed IOCs for hashes
        file_len = len(file_bytes)
        from fileanalysis.analyzers.base import IOC
        result.iocs.extend([
            IOC(type="hash", value=md5_val, offset=0, length=file_len),
            IOC(type="hash", value=sha1_val, offset=0, length=file_len),
            IOC(type="hash", value=sha256_val, offset=0, length=file_len),
        ])

    def _compute_ssdeep(self, file_bytes: bytes) -> str:
        """Compute ssdeep fuzzy hash using ppdeep."""
        try:
            return ppdeep.hash(file_bytes)
        except Exception:
            return "N/A"

    def _compute_imphash(self, file_path: str) -> str:
        """Compute import hash for PE files."""
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            imphash = pe.get_imphash()
            pe.close()
            return imphash if imphash else "N/A"
        except Exception:
            return "N/A"
