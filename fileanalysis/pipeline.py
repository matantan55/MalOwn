"""Shared analysis pipeline used by CLI, MCP server, and the Python library API."""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

# Prevent OpenMP segmentation fault on macOS when LightGBM and PyTorch coexist
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
os.environ["OMP_NUM_THREADS"] = "1"

from fileanalysis.loader import load_file, load_bytes
from fileanalysis.analyzers.base import AnalysisResult, RiskLevel, ThreatCategory
from fileanalysis.analyzers.dll_analyzer import DLLAnalyzer
from fileanalysis.analyzers.document_analyzer import DocumentAnalyzer
from fileanalysis.analyzers.elf_analyzer import ELFAnalyzer
from fileanalysis.analyzers.entropy import EntropyAnalyzer
from fileanalysis.analyzers.hashing import HashAnalyzer
from fileanalysis.analyzers.macho_analyzer import MachOAnalyzer
from fileanalysis.analyzers.pe_analyzer import PEAnalyzer
from fileanalysis.analyzers.script_analyzer import ScriptAnalyzer
from fileanalysis.analyzers.strings import StringAnalyzer
from fileanalysis.analyzers.upx import is_upx_packed, unpack_upx_bytes
from fileanalysis.analyzers.archive import is_zip_archive, inspect_archive
from fileanalysis.intelligence.capability_mapper import CapabilityMapper
from fileanalysis.intelligence.yara_scanner import YaraScanner
from fileanalysis.scoring.scorer import ThreatScorer
from fileanalysis.scoring.nn_model import NNThreatScorer
from fileanalysis.scoring.ml_model import LightGBMThreatScorer
from fileanalysis.intelligence.ai_insights import AIInsightsGenerator

logger = logging.getLogger("malown.pipeline")

# ── Ensemble scoring weights ────────────────────────────────────────
_W_HEURISTIC_TRIPLE = 0.4
_W_ML_TRIPLE = 0.4
_W_NN_TRIPLE = 0.2

_W_HEURISTIC_DUAL = 0.6
_W_NN_DUAL = 0.4

_W_HEURISTIC_DUAL_ML = 0.6
_W_ML_DUAL_ML = 0.4


def _classify_risk_level(score: float) -> RiskLevel:
    """Map a numeric score to a RiskLevel enum."""
    if score <= 20.0:
        return RiskLevel.CLEAN
    elif score <= 40.0:
        return RiskLevel.LOW
    elif score <= 60.0:
        return RiskLevel.MODERATE
    elif score <= 80.0:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _compute_ensemble(result: AnalysisResult) -> None:
    """Compute the ensemble score and risk level from individual scorers."""
    method = getattr(result, "scoring_method", "heuristic")

    if method == "triple":
        base_score = (
            _W_HEURISTIC_TRIPLE * result.risk_score
            + _W_ML_TRIPLE * result.ml_score
            + _W_NN_TRIPLE * getattr(result, "nn_score", result.risk_score)
        )
    elif method == "dual":
        base_score = (
            _W_HEURISTIC_DUAL * result.risk_score
            + _W_NN_DUAL * getattr(result, "nn_score", result.risk_score)
        )
    elif method == "dual_ml":
        base_score = (
            _W_HEURISTIC_DUAL_ML * result.risk_score
            + _W_ML_DUAL_ML * getattr(result, "ml_score", result.risk_score)
        )
    else:
        base_score = result.risk_score

    # Anti-False-Positive Filter
    if result.metadata.file_type not in ["pe", "elf", "macho"]:
        if result.risk_score < 20.0:
            base_score = min(base_score, 20.0)  # Cap at CLEAN
    else:
        if result.risk_score < 10.0:
            base_score = min(base_score, 40.0)  # Cap at LOW

    result.ensemble_score = round(base_score, 1)
    result.ensemble_risk_level = _classify_risk_level(result.ensemble_score)


def run_pipeline(
    file_path: str | None = None,
    file_bytes: bytes | None = None,
    file_name: str | None = None,
    mode: str = "full",
    yara_rules: str | None = None,
    passwords: Optional[List[str]] = None,
    is_subanalysis: bool = False,
) -> AnalysisResult:
    """Execute analysis pipeline and return a populated AnalysisResult.

    Args:
        file_path: Optional path to the file on disk.
        file_bytes: Optional raw byte content (if analyzing in memory).
        file_name: Optional file name for in-memory files.
        mode: "full" (all ML + neural net + SHAP) or "quick" (heuristics, hashes, entropy, strings, headers, YARA).
        yara_rules: Optional path to custom YARA rules directory or file.
        passwords: Optional list of passwords for encrypted archive members.
        is_subanalysis: Set to True for nested unpacked/archive members to avoid recursion.
    """
    logger.info("Starting analysis pipeline (mode=%s) for: %s", mode, file_path or file_name)

    # 1. Load file bytes & initial AnalysisResult
    created_temp_file = False
    temp_path: Path | None = None

    if file_path and os.path.exists(file_path):
        resolved_path = str(Path(file_path).resolve())
        loaded_bytes, result = load_file(resolved_path)
    elif file_bytes is not None:
        loaded_bytes = file_bytes
        name = file_name or "in_memory_file"
        _, result = load_bytes(file_bytes, file_name=name)
        # Create a temporary file on disk so tools expecting a filepath can access it
        clean_suffix = f"_{os.path.basename(name)}"
        with tempfile.NamedTemporaryFile(delete=False, suffix=clean_suffix) as tf:
            tf.write(file_bytes)
            tf.flush()
            resolved_path = tf.name
            created_temp_file = True
            temp_path = Path(resolved_path)
    else:
        raise ValueError("Either file_path or file_bytes must be provided to run_pipeline")

    result.mode = mode

    try:
        # 2. Common analyzers
        HashAnalyzer().analyze(resolved_path, loaded_bytes, result)
        EntropyAnalyzer().analyze(resolved_path, loaded_bytes, result)
        StringAnalyzer().analyze(resolved_path, loaded_bytes, result)

        # 3. Format-specific analyzers
        file_type = result.metadata.file_type
        if file_type == "pe":
            PEAnalyzer().analyze(resolved_path, loaded_bytes, result)
            if result.format_info.get("is_dll"):
                DLLAnalyzer().analyze(resolved_path, loaded_bytes, result)
        elif file_type == "elf":
            ELFAnalyzer().analyze(resolved_path, loaded_bytes, result)
        elif file_type == "macho":
            MachOAnalyzer().analyze(resolved_path, loaded_bytes, result)
        elif file_type == "script":
            ScriptAnalyzer().analyze(resolved_path, loaded_bytes, result)
        elif file_type == "document":
            DocumentAnalyzer().analyze(resolved_path, loaded_bytes, result)

        # 4. YARA scanning (merges custom rules with 11 built-in rule sets)
        scanner = YaraScanner(custom_rules_dir=yara_rules)
        scanner.scan(resolved_path, result)

        # 5. MITRE ATT&CK capability mapping (sets byte offset/length on each hit)
        mapper = CapabilityMapper()
        mapper.map_capabilities(result)

        # 6. Heuristic scoring
        heuristic_scorer = ThreatScorer()
        heuristic_scorer.calculate_score(result)

        # 7 & 8: Machine Learning and Neural Net Scoring (Skipped in Quick Mode)
        if mode == "quick":
            result.scoring_method = "heuristic"
            result.ensemble_score = round(result.risk_score, 1)
            result.ensemble_risk_level = _classify_risk_level(result.ensemble_score)
        else:
            # Neural network scoring (MalConv)
            try:
                nn_scorer = NNThreatScorer()
                nn_scorer.calculate_score(result, file_bytes=loaded_bytes)
                result.scoring_method = "dual"
            except (FileNotFoundError, ImportError, Exception) as exc:
                logger.debug("NN scoring skipped/failed: %s", exc)

            # LightGBM scoring
            try:
                ml_scorer = LightGBMThreatScorer()
                ml_scorer.calculate_score(result)
                if result.scoring_method == "dual":
                    result.scoring_method = "triple"
                else:
                    result.scoring_method = "dual_ml"
            except (FileNotFoundError, ImportError, Exception) as exc:
                logger.debug("LightGBM scoring skipped/failed: %s", exc)
                if result.scoring_method != "dual":
                    result.scoring_method = "heuristic"

            # Compute ensemble score
            _compute_ensemble(result)

            # SHAP AI Insights
            try:
                ai_gen = AIInsightsGenerator()
                result.ai_summary = ai_gen.generate(result)
            except Exception as exc:
                logger.debug("AI insights generation skipped: %s", exc)

        # 9. UPX In-memory Unpacking (only for top-level binaries)
        if not is_subanalysis and is_upx_packed(loaded_bytes, result):
            result.is_upx_packed = True
            is_packed, unpacked_bytes, unpack_err = unpack_upx_bytes(loaded_bytes)
            if is_packed and unpacked_bytes:
                result.upx_unpacked = True
                try:
                    unpacked_res = run_pipeline(
                        file_bytes=unpacked_bytes,
                        file_name=f"unpacked_{result.metadata.name or 'payload'}",
                        mode=mode,
                        yara_rules=yara_rules,
                        is_subanalysis=True,
                    )
                    unpacked_dict = asdict(unpacked_res)
                    unpacked_dict["risk_level"] = unpacked_res.risk_level.value
                    unpacked_dict["ensemble_risk_level"] = unpacked_res.ensemble_risk_level.value
                    for ind in unpacked_dict.get("indicators", []):
                        if isinstance(ind.get("category"), ThreatCategory):
                            ind["category"] = ind["category"].value
                    result.unpacked_result = unpacked_dict
                except Exception as exc:
                    logger.warning("Failed analyzing UPX unpacked image: %s", exc)
            elif unpack_err:
                result.errors.append(unpack_err)

        # 10. In-memory ZIP archive member inspection
        if not is_subanalysis and is_zip_archive(loaded_bytes, result.metadata.name):
            member_results, arch_indicators = inspect_archive(
                loaded_bytes,
                pipeline_fn=run_pipeline,
                passwords=passwords,
                mode=mode,
                yara_rules=yara_rules,
            )
            result.archive_members = member_results
            result.indicators.extend(arch_indicators)

            # Elevate ensemble score if any member has high threat score
            if member_results:
                max_member_score = max(
                    (m.result.get("ensemble_score", 0.0) for m in member_results if m.result),
                    default=0.0,
                )
                if max_member_score > result.ensemble_score:
                    result.ensemble_score = round(max_member_score, 1)
                    result.ensemble_risk_level = _classify_risk_level(result.ensemble_score)

    finally:
        if created_temp_file and temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass

    logger.info(
        "Pipeline complete for %s — mode=%s, ensemble_score=%.1f (%s)",
        result.metadata.name or file_path,
        mode,
        result.ensemble_score,
        result.ensemble_risk_level.value,
    )
    return result


def analyze(
    path: str | Path | None = None,
    mode: str = "full",
    yara_rules: str | None = None,
    file_bytes: bytes | None = None,
    filename: str | None = None,
    passwords: Optional[List[str]] = None,
) -> AnalysisResult:
    """Stable, thread-safe library entry point for MalOwn analysis.

    Models and YARA rules are loaded once and reused across subsequent calls.

    Args:
        path: Path to the target file.
        mode: 'full' (all models + AI insights) or 'quick' (static heuristics, YARA, strings, headers).
        yara_rules: Optional path to a directory of custom YARA rules (.yar/.yara).
        file_bytes: Optional bytes if analyzing directly from memory.
        filename: Optional filename for in-memory bytes.
        passwords: Optional list of passwords to try for encrypted archive members.

    Returns:
        AnalysisResult: Populated analysis result with threat scores, typed IOCs, and findings.
    """
    return run_pipeline(
        file_path=str(path) if path else None,
        file_bytes=file_bytes,
        file_name=filename,
        mode=mode,
        yara_rules=yara_rules,
        passwords=passwords,
    )
