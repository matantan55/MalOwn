"""In-memory ZIP archive inspection with password support and zip bomb defenses."""

from __future__ import annotations
import io
import logging
import zipfile
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, Callable, List, Optional

from fileanalysis.analyzers.base import (
    AnalysisResult,
    ArchiveMemberResult,
    Indicator,
    ThreatCategory,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger("malown.archive")

DEFAULT_ARCHIVE_PASSWORDS = ["infected", "malware", "infected!", "password", "1234", ""]

# Zip bomb defenses
MAX_MEMBERS = 100
MAX_DEPTH = 3
MAX_TOTAL_UNPACKED_BYTES = 100 * 1024 * 1024   # 100 MB
MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024       # 50 MB
MAX_COMPRESSION_RATIO = 100.0


def is_zip_archive(file_bytes: bytes, file_name: str = "") -> bool:
    """Check if bytes represent a ZIP archive (excluding standard Office docs)."""
    if len(file_bytes) < 4 or file_bytes[:4] != b"PK\x03\x04":
        return False

    # Skip office documents if named .docx/.xlsx/.pptx
    lower = file_name.lower()
    if lower.endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")):
        return False

    return True


def inspect_archive(
    file_bytes: bytes,
    pipeline_fn: Callable[[str | None, bytes, str, str, str | None], AnalysisResult],
    passwords: Optional[List[str]] = None,
    mode: str = "full",
    yara_rules: Optional[str] = None,
    current_depth: int = 1,
) -> tuple[List[ArchiveMemberResult], List[Indicator]]:
    """Analyze all members of a ZIP archive in memory safely.

    Args:
        file_bytes: Raw bytes of the ZIP archive.
        pipeline_fn: Analysis pipeline function to run on each member.
        passwords: List of password strings to attempt for encrypted members.
        mode: Analysis mode ('full' or 'quick').
        yara_rules: Custom YARA rules directory or None.
        current_depth: Recursion depth.

    Returns:
        Tuple of (member_results, indicators).
    """
    if current_depth > MAX_DEPTH:
        logger.warning("Reached maximum archive recursion depth (%d)", MAX_DEPTH)
        return [], []

    pwd_candidates = (passwords or []) + DEFAULT_ARCHIVE_PASSWORDS
    # Ensure bytes versions of passwords without duplicates
    raw_passwords: list[bytes] = []
    for p in pwd_candidates:
        b = p.encode("utf-8") if isinstance(p, str) else p
        if b not in raw_passwords:
            raw_passwords.append(b)

    member_results: list[ArchiveMemberResult] = []
    indicators: list[Indicator] = []
    total_unpacked = 0

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            namelist = [n for n in z.infolist() if not n.is_dir()]

            # Guard against member count zip bomb
            if len(namelist) > MAX_MEMBERS:
                indicators.append(Indicator(
                    category=ThreatCategory.DEFENSE_EVASION,
                    name="Archive Bomb: Excessive Member Count",
                    description=(
                        f"Archive contains {len(namelist)} members (max allowed: {MAX_MEMBERS}). "
                        "Truncating analysis to avoid denial of service."
                    ),
                    evidence=[f"Member count: {len(namelist)}"],
                    severity=0.8,
                    offset=0,
                    length=len(file_bytes),
                ))
                namelist = namelist[:MAX_MEMBERS]

            for zinfo in namelist:
                filename = zinfo.filename
                file_size = zinfo.file_size
                compress_size = max(zinfo.compress_size, 1)

                # Check compression ratio
                ratio = file_size / compress_size
                if ratio > MAX_COMPRESSION_RATIO and file_size > 10 * 1024 * 1024:
                    member_results.append(ArchiveMemberResult(
                        filename=filename,
                        size=file_size,
                        compressed_size=zinfo.compress_size,
                        is_encrypted=bool(zinfo.flag_bits & 0x1),
                        error=f"Compression ratio ({ratio:.1f}:1) exceeds safety threshold",
                    ))
                    indicators.append(Indicator(
                        category=ThreatCategory.DEFENSE_EVASION,
                        name="Archive Bomb: Anomalous Compression Ratio",
                        description=f"Member '{filename}' has an anomalous compression ratio of {ratio:.1f}:1.",
                        evidence=[f"File: {filename}", f"Ratio: {ratio:.1f}:1"],
                        severity=0.85,
                        offset=0,
                        length=len(file_bytes),
                    ))
                    continue

                # Guard against total size limits
                if total_unpacked + file_size > MAX_TOTAL_UNPACKED_BYTES:
                    member_results.append(ArchiveMemberResult(
                        filename=filename,
                        size=file_size,
                        compressed_size=zinfo.compress_size,
                        is_encrypted=bool(zinfo.flag_bits & 0x1),
                        error="Total unpacked archive size limit exceeded",
                    ))
                    indicators.append(Indicator(
                        category=ThreatCategory.DEFENSE_EVASION,
                        name="Archive Bomb: Total Size Limit Exceeded",
                        description="Archive contents exceed maximum total unpacked size.",
                        evidence=[f"Total unpacked: {total_unpacked} bytes"],
                        severity=0.8,
                        offset=0,
                        length=len(file_bytes),
                    ))
                    break

                if file_size > MAX_SINGLE_FILE_BYTES:
                    member_results.append(ArchiveMemberResult(
                        filename=filename,
                        size=file_size,
                        compressed_size=zinfo.compress_size,
                        is_encrypted=bool(zinfo.flag_bits & 0x1),
                        error=f"Single member exceeds maximum size ({MAX_SINGLE_FILE_BYTES} bytes)",
                    ))
                    continue

                # Unpack member in memory
                is_encrypted = bool(zinfo.flag_bits & 0x1)
                data: bytes | None = None
                pwd_used: str | None = None
                read_err: str | None = None

                if is_encrypted:
                    for candidate_pwd in raw_passwords:
                        try:
                            data = z.read(zinfo, pwd=candidate_pwd if candidate_pwd else None)
                            pwd_used = candidate_pwd.decode("utf-8", errors="replace")
                            break
                        except (RuntimeError, zipfile.BadZipFile):
                            continue
                    if data is None:
                        read_err = "Encrypted member: none of the passwords matched"
                else:
                    try:
                        data = z.read(zinfo)
                    except Exception as e:
                        read_err = f"Failed to extract member: {e}"

                if data is None:
                    member_results.append(ArchiveMemberResult(
                        filename=filename,
                        size=file_size,
                        compressed_size=zinfo.compress_size,
                        is_encrypted=is_encrypted,
                        error=read_err,
                    ))
                    continue

                total_unpacked += len(data)

                # Run analysis pipeline on the unpacked member bytes
                try:
                    member_res = pipeline_fn(
                        None,             # file_path
                        data,             # file_bytes
                        filename,         # file_name
                        mode,             # mode
                        yara_rules,       # yara_rules
                    )
                    from fileanalysis.reporting.json_report import JsonReporter
                    member_dict = asdict(member_res)
                    # Convert enums for consistency
                    member_dict["risk_level"] = member_res.risk_level.value
                    member_dict["ensemble_risk_level"] = member_res.ensemble_risk_level.value
                    for ind in member_dict.get("indicators", []):
                        if isinstance(ind.get("category"), ThreatCategory):
                            ind["category"] = ind["category"].value

                    member_results.append(ArchiveMemberResult(
                        filename=filename,
                        size=file_size,
                        compressed_size=zinfo.compress_size,
                        is_encrypted=is_encrypted,
                        password_used=pwd_used,
                        result=member_dict,
                    ))
                except Exception as exc:
                    logger.exception("Error analyzing archive member %s", filename)
                    member_results.append(ArchiveMemberResult(
                        filename=filename,
                        size=file_size,
                        compressed_size=zinfo.compress_size,
                        is_encrypted=is_encrypted,
                        password_used=pwd_used,
                        error=f"Analysis failed: {exc}",
                    ))

    except Exception as exc:
        logger.warning("Error reading ZIP archive: %s", exc)

    return member_results, indicators
