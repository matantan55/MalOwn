"""In-memory UPX unpacking and payload analysis."""

from __future__ import annotations
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from fileanalysis.analyzers.base import AnalysisResult

logger = logging.getLogger("malown.upx")

UPX_MAGIC = b"UPX!"


def is_upx_packed(file_bytes: bytes, result: Optional[AnalysisResult] = None) -> bool:
    """Determine if a file is packed with UPX."""
    # 1. Check if format_info already noted UPX packer or sections
    if result and "packers" in result.format_info:
        if any("UPX" in p.upper() for p in result.format_info["packers"]):
            return True

    if result and result.sections:
        if any("UPX" in s.name.upper() for s in result.sections):
            return True

    # 2. Check for UPX signature magic bytes
    if UPX_MAGIC in file_bytes:
        return True

    # 3. Check for UPX section header names in raw bytes
    if b"UPX0" in file_bytes or b"UPX1" in file_bytes or b"UPX2" in file_bytes:
        return True

    return False


def unpack_upx_bytes(file_bytes: bytes) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """Unpack UPX-compressed file bytes in memory.

    Returns:
        Tuple of (is_packed, unpacked_bytes, error_message).
    """
    if not is_upx_packed(file_bytes):
        return False, None, None

    upx_bin = shutil.which("upx")
    if not upx_bin:
        # Common locations on macOS/Linux
        for candidate in ("/opt/homebrew/bin/upx", "/usr/local/bin/upx", "/usr/bin/upx"):
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                upx_bin = candidate
                break

    if not upx_bin:
        return True, None, "UPX packing detected, but 'upx' executable is not installed on PATH"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        packed_file = tmp_path / "packed.bin"
        unpacked_file = tmp_path / "unpacked.bin"

        try:
            packed_file.write_bytes(file_bytes)
            # Run UPX decompressor in a safe sandbox process
            proc = subprocess.run(
                [upx_bin, "-d", "-q", "-f", "-o", str(unpacked_file), str(packed_file)],
                capture_output=True,
                timeout=20,
            )

            if proc.returncode == 0 and unpacked_file.exists():
                unpacked_bytes = unpacked_file.read_bytes()
                logger.info(
                    "Successfully unpacked UPX binary in memory: %d -> %d bytes",
                    len(file_bytes),
                    len(unpacked_bytes),
                )
                return True, unpacked_bytes, None
            else:
                err = proc.stderr.decode("utf-8", errors="replace").strip()
                logger.warning("UPX decompression failed (code %d): %s", proc.returncode, err)
                return True, None, f"UPX unpack failed: {err or 'non-zero exit code'}"

        except subprocess.TimeoutExpired:
            return True, None, "UPX unpacking timed out"
        except Exception as exc:
            return True, None, f"UPX unpack error: {exc}"
