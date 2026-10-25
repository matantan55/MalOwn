"""YARA signature matching engine."""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Any
import yara
from fileanalysis.analyzers.base import AnalysisResult, YaraMatch

logger = logging.getLogger("malown.yara")

# Cache compiled rules to avoid recompilation on every file analysis
_RULE_CACHE: dict[str, yara.Rules] = {}


class YaraScanner:
    """Compiles and scans files using YARA rules, merging built-in and custom rules."""

    def __init__(self, custom_rules_dir: str | None = None):
        self.custom_rules_dir = custom_rules_dir
        self.rules = self._get_or_compile_rules(custom_rules_dir)

    def _get_or_compile_rules(self, custom_rules_dir: str | None) -> yara.Rules | None:
        """Fetch cached rules or compile merged built-in + custom rules."""
        cache_key = str(Path(custom_rules_dir).resolve()) if custom_rules_dir else "__builtin__"
        if cache_key in _RULE_CACHE:
            return _RULE_CACHE[cache_key]

        rule_files = {}

        # 1. Built-in rules
        builtin_dir = Path(__file__).resolve().parent.parent.parent / "rules"
        if builtin_dir.exists() and builtin_dir.is_dir():
            for p in builtin_dir.glob("**/*"):
                if p.suffix.lower() in (".yar", ".yara"):
                    rule_files[f"builtin_{p.stem}"] = str(p)

        # 2. Merge custom rules (without replacing built-in ones)
        if custom_rules_dir:
            custom_dir = Path(custom_rules_dir)
            if custom_dir.exists() and custom_dir.is_dir():
                for p in custom_dir.glob("**/*"):
                    if p.suffix.lower() in (".yar", ".yara"):
                        rule_files[f"custom_{p.stem}"] = str(p)
            elif custom_dir.is_file() and custom_dir.suffix.lower() in (".yar", ".yara"):
                rule_files[f"custom_{custom_dir.stem}"] = str(custom_dir)

        if not rule_files:
            return None

        try:
            compiled = yara.compile(filepaths=rule_files)
            _RULE_CACHE[cache_key] = compiled
            return compiled
        except Exception as e:
            logger.warning("Failed to compile merged YARA rules: %s", e)
            # Fallback: try compiling built-in rules alone if custom failed
            if custom_rules_dir and "__builtin__" in _RULE_CACHE:
                return _RULE_CACHE["__builtin__"]
            try:
                builtin_files = {k: v for k, v in rule_files.items() if k.startswith("builtin_")}
                if builtin_files:
                    compiled = yara.compile(filepaths=builtin_files)
                    _RULE_CACHE["__builtin__"] = compiled
                    return compiled
            except Exception:
                pass
            return None

    def scan(
        self,
        file_path: str | None = None,
        result: AnalysisResult | None = None,
        file_bytes: bytes | None = None,
    ) -> None:
        """Scan a file or in-memory bytes using compiled rules, extracting offsets and lengths."""
        if not self.rules or result is None:
            return

        try:
            if file_bytes is not None:
                matches = self.rules.match(data=file_bytes)
            elif file_path:
                matches = self.rules.match(filepath=file_path)
            else:
                return

            for m in matches:
                desc = m.meta.get("description", "No description provided")
                severity = m.meta.get("severity", "medium")

                matched_strings: list[str] = []
                detailed_matches: list[dict[str, Any]] = []
                first_offset = 0
                first_length = 0

                for s_match in m.strings:
                    if hasattr(s_match, "instances"):
                        identifier = getattr(s_match, "identifier", "$?")
                        for inst in getattr(s_match, "instances", []):
                            offset = getattr(inst, "offset", 0)
                            data = getattr(inst, "matched_data", b"")
                            length = getattr(inst, "matched_length", len(data))
                            try:
                                printable = data.decode("utf-8", errors="replace")
                            except Exception:
                                printable = data.hex()

                            if not detailed_matches:
                                first_offset = offset
                                first_length = length

                            matched_strings.append(f"{identifier} at 0x{offset:X}: {printable[:60]}")
                            detailed_matches.append({
                                "identifier": identifier,
                                "offset": offset,
                                "length": length,
                                "data": printable[:100],
                            })
                    else:
                        try:
                            offset, identifier, data = s_match
                            length = len(data) if isinstance(data, (bytes, str)) else 0
                            try:
                                printable = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
                            except Exception:
                                printable = data.hex() if isinstance(data, bytes) else str(data)

                            if not detailed_matches:
                                first_offset = offset
                                first_length = length

                            matched_strings.append(f"{identifier} at 0x{offset:X}: {printable[:60]}")
                            detailed_matches.append({
                                "identifier": identifier,
                                "offset": offset,
                                "length": length,
                                "data": printable[:100],
                            })
                        except Exception:
                            pass

                result.yara_matches.append(YaraMatch(
                    rule_name=m.rule,
                    description=desc,
                    tags=list(m.tags),
                    severity=severity,
                    matched_strings=matched_strings[:10],
                    offset=first_offset,
                    length=first_length,
                    string_matches=detailed_matches[:20],
                ))
        except Exception as e:
            result.errors.append(f"YARA scan error: {e}")

    def scan_bytes(self, file_bytes: bytes, result: AnalysisResult) -> None:
        """Convenience method to scan raw in-memory bytes."""
        self.scan(result=result, file_bytes=file_bytes)
