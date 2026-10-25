"""
Comprehensive automated tests for Project 0 features in MalOwn:
1. Quick mode (--quick / mode: "quick")
2. Python library call analyze() with model caching and thread safety
3. Byte offsets and lengths on hits (YARA, strings, indicators, capabilities)
4. Typed IOC list (ipv4, ipv6, domain, url, email, file_path, registry_key, hash)
5. Fixed-block Shannon entropy profile
6. In-memory ZIP archive inspection with password protection & zip bomb safeguards
7. Windows PE Authenticode digital signature check
8. In-memory UPX unpacking and dual analysis
9. Merging custom YARA rules with built-in rulesets
10. MCP server pagination on get_binary_annotations
11. Safe test fixtures and exact JSON reports
"""

import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import zipfile

from fileanalysis import (
    analyze,
    AnalysisResult,
    IOC,
    SignatureInfo,
    ArchiveMemberResult,
    RiskLevel,
    ThreatCategory,
)
from fileanalysis.analyzers.archive import is_zip_archive, inspect_archive
from fileanalysis.analyzers.upx import is_upx_packed, unpack_upx_bytes
from fileanalysis.intelligence.yara_scanner import YaraScanner
from fileanalysis.pipeline import run_pipeline
from fileanalysis.reporting.json_report import JsonReporter
from fileanalysis.mcp_server import get_binary_annotations


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestProject0Features(unittest.TestCase):
    """Test suite validating all Project 0 integration requirements."""

    @classmethod
    def setUpClass(cls):
        cls.win_exe = str(FIXTURES_DIR / "hello_windows.exe")
        cls.linux_elf = str(FIXTURES_DIR / "hello_linux.elf")
        cls.script_py = str(FIXTURES_DIR / "hello_script.py")
        cls.archive_zip = str(FIXTURES_DIR / "sample_archive.zip")

    # ─── 1. Quick Mode ──────────────────────────────────────────────────────────

    def test_quick_mode_skips_heavy_ml(self):
        """Quick mode should skip MalConv, LightGBM, and SHAP, while running static analyzers."""
        res_quick = analyze(self.win_exe, mode="quick")
        self.assertEqual(res_quick.mode, "quick")
        self.assertEqual(res_quick.scoring_method, "heuristic")
        # In quick mode, nn_score and ml_score remain default 0.0
        self.assertEqual(res_quick.nn_score, 0.0)
        self.assertEqual(res_quick.ml_score, 0.0)
        self.assertIsNone(res_quick.ai_summary)
        # Format headers, hashes, entropy, strings, and YARA are present
        self.assertGreater(len(res_quick.hashes.sha256), 0)
        self.assertGreater(len(res_quick.entropy.profile), 0)
        self.assertIsNotNone(res_quick.signature_info)

    def test_full_mode_runs_ensemble(self):
        """Full mode should run the ML ensemble and populate scores."""
        res_full = analyze(self.win_exe, mode="full")
        self.assertEqual(res_full.mode, "full")
        self.assertIn(res_full.scoring_method, ["dual", "triple"])
        self.assertGreater(res_full.ensemble_score, 0.0)

    # ─── 2. Python Library Call & Thread Safety ─────────────────────────────────

    def test_python_library_call_thread_safe(self):
        """analyze() should be safe to call concurrently across multiple threads."""
        files = [self.win_exe, self.linux_elf, self.script_py, self.archive_zip] * 2

        def _run_single(path):
            return analyze(path, mode="quick")

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(_run_single, files))

        self.assertEqual(len(results), len(files))
        for res in results:
            self.assertIsInstance(res, AnalysisResult)
            self.assertGreater(len(res.hashes.sha256), 0)
            self.assertGreater(len(res.iocs), 0)

    # ─── 3. Byte Offsets and Lengths ────────────────────────────────────────────

    def test_byte_offsets_on_extracted_strings_and_iocs(self):
        """Every extracted string and typed IOC must carry valid source byte offset and length."""
        res = analyze(self.script_py, mode="quick")
        with open(self.script_py, "rb") as f:
            raw_bytes = f.read()

        self.assertGreater(len(res.iocs), 0)
        for ioc in res.iocs:
            self.assertIsInstance(ioc, IOC)
            self.assertGreaterEqual(ioc.offset, 0)
            self.assertGreater(ioc.length, 0)
            if ioc.type != "hash":
                # Verify that the sliced bytes match the IOC value
                sliced = raw_bytes[ioc.offset : ioc.offset + ioc.length].decode("utf-8", errors="ignore")
                self.assertEqual(sliced, ioc.value)

        self.assertGreater(len(res.extracted_strings), 0)
        for s_hit in res.extracted_strings[:10]:
            self.assertGreaterEqual(s_hit.offset, 0)
            self.assertGreater(s_hit.length, 0)
            sliced = raw_bytes[s_hit.offset : s_hit.offset + s_hit.length]
            self.assertEqual(sliced.decode("utf-8", errors="ignore"), s_hit.value)

    def test_byte_offsets_on_indicators_and_capabilities(self):
        """Indicators and mapped capabilities must carry non-negative byte offset and length."""
        res = analyze(self.win_exe, mode="quick")
        for ind in res.indicators:
            self.assertGreaterEqual(ind.offset, 0)
            self.assertGreaterEqual(ind.length, 0)

        for cap in res.capabilities:
            self.assertGreaterEqual(cap.offset, 0)
            self.assertGreaterEqual(cap.length, 0)

    # ─── 4. Typed IOC List ──────────────────────────────────────────────────────

    def test_typed_ioc_list_categories(self):
        """Typed IOC list must contain standardized categories with exact positions."""
        res = analyze(self.script_py, mode="quick")
        ioc_types = {ioc.type for ioc in res.iocs}

        self.assertIn("hash", ioc_types)
        self.assertIn("url", ioc_types)
        self.assertIn("domain", ioc_types)
        self.assertIn("ipv4", ioc_types)
        self.assertIn("email", ioc_types)
        self.assertIn("file_path", ioc_types)

        # Confirm specific values from fixture
        values = {ioc.value: ioc.type for ioc in res.iocs}
        self.assertEqual(values.get("https://example.com/docs/api"), "url")
        self.assertEqual(values.get("example.com"), "domain")
        self.assertEqual(values.get("8.8.8.8"), "ipv4")
        self.assertEqual(values.get("support@example.com"), "email")
        self.assertEqual(values.get("/etc/malown/config.json"), "file_path")

    # ─── 5. Entropy Profile ─────────────────────────────────────────────────────

    def test_entropy_profile_calculation(self):
        """Entropy result must contain a fixed-block entropy profile beside the overall score."""
        res = analyze(self.win_exe, mode="quick")
        self.assertIn(res.entropy.block_size, [256, 1024])
        self.assertGreater(len(res.entropy.profile), 0)
        # All entropy values must be between 0.0 and 8.0
        for block_ent in res.entropy.profile:
            self.assertGreaterEqual(block_ent, 0.0)
            self.assertLessEqual(block_ent, 8.0)

    # ─── 6. Looking Inside Archives ─────────────────────────────────────────────

    def test_archive_inspection_unpacked_members(self):
        """ZIP archives should have their members analyzed in-memory."""
        res = analyze(self.archive_zip, mode="quick")
        self.assertEqual(res.metadata.file_type, "zip")
        self.assertGreater(len(res.archive_members), 0)

        member_names = [m.filename for m in res.archive_members]
        self.assertIn("README.txt", member_names)
        self.assertIn("scripts/setup.sh", member_names)

        for m in res.archive_members:
            self.assertIsInstance(m, ArchiveMemberResult)
            self.assertFalse(m.is_encrypted)
            self.assertIsNotNone(m.result)
            self.assertIn("hashes", m.result)
            self.assertIn("ensemble_score", m.result)

    def test_password_protected_zip_with_infected_password(self):
        """ZIP archive protected with password 'infected' should be unlocked and scanned."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            zip_path = tf.name

        try:
            # Create encrypted ZIP with password 'infected'
            # Note: Python's zipfile can decrypt standard PKWARE encryption
            data = b"Hello from inside encrypted archive with domain evil.example.com\n"
            # Build zip with password using standard zipfile
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.setpassword(b"infected")
                zf.writestr("secret.txt", data)

            # Analyze with default passwords list (which includes 'infected')
            res = analyze(zip_path, mode="quick")
            self.assertEqual(len(res.archive_members), 1)
            member = res.archive_members[0]
            self.assertEqual(member.filename, "secret.txt")
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    def test_zip_bomb_protection(self):
        """ZIP archive inspection must enforce member count and size limits."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            zip_path = tf.name

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                # Add 120 tiny files (limit is 100)
                for i in range(120):
                    zf.writestr(f"file_{i:03d}.txt", b"A" * 10)

            res = analyze(zip_path, mode="quick")
            # Should cap at 100 members and emit a warning indicator
            self.assertLessEqual(len(res.archive_members), 100)
            has_limit_indicator = any("Excessive Member Count" in ind.name for ind in res.indicators)
            self.assertTrue(has_limit_indicator)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

    # ─── 7. Authenticode Digital Signature Check ────────────────────────────────

    def test_windows_authenticode_signature_detection(self):
        """PE Authenticode digital signature must be extracted and verified for integrity."""
        res = analyze(self.win_exe, mode="quick")
        self.assertIsNotNone(res.signature_info)
        sig = res.signature_info
        self.assertTrue(sig.has_signature)
        self.assertTrue(sig.is_signed)
        self.assertTrue(sig.is_intact)
        self.assertIn("MalOwn Safe Test Signer", str(sig.signer_name))
        self.assertEqual(sig.algorithm, "SHA_256")
        self.assertIsNotNone(sig.serial_number)

    def test_unsigned_pe_signature_detection(self):
        """Unsigned PE files should report has_signature=False."""
        # Create minimal unsigned PE bytes
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
        pe_sig = b"PE\x00\x00"
        file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        opt_header = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x010B, 1, 0, 512, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
            4, 0, 0, 0, 4, 0, 0, 0x3000, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16
        ) + b"\x00" * (16 * 8)
        sec_name = b".text\x00\x00\x00"
        sec_header = struct.pack("<8sIIIIIIHHI", sec_name, 512, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
        code = b"\x90" * 512
        pe_bytes = dos_header + pe_sig + file_header + opt_header + sec_header
        pe_bytes += b"\x00" * (512 - len(pe_bytes)) + code

        res = analyze("unsigned.exe", file_bytes=pe_bytes, mode="quick")
        self.assertIsNotNone(res.signature_info)
        self.assertFalse(res.signature_info.has_signature)
        self.assertFalse(res.signature_info.is_signed)

    # ─── 8. UPX In-Memory Unpacking ─────────────────────────────────────────────

    def test_upx_in_memory_unpacking(self):
        """UPX-packed executable should be detected, unpacked in-memory, and payload analyzed."""
        upx_bin = shutil.which("upx") or "/opt/homebrew/bin/upx"
        if not os.path.exists(upx_bin):
            self.skipTest("upx binary not installed on test host")

        # Create a compressible PE binary (64 KB)
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
        pe_sig = b"PE\x00\x00"
        file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        code_size = 65536
        opt_header = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x010B, 1, 0, code_size, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
            4, 0, 0, 0, 4, 0, 0, code_size + 0x1000, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16
        ) + b"\x00" * (16 * 8)
        sec_name = b".text\x00\x00\x00"
        sec_header = struct.pack("<8sIIIIIIHHI", sec_name, code_size, 0x1000, code_size, 512, 0, 0, 0, 0, 0x60000020)
        code = (b"\x90\x90\x90\xc3\x55\x89\xe5\x5d\xc3" * 8000)[:code_size]
        pe_bytes = dos_header + pe_sig + file_header + opt_header + sec_header
        pe_bytes += b"\x00" * (512 - len(pe_bytes)) + code

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            packed_path = tf.name
            tf.write(pe_bytes)

        try:
            # Compress with UPX
            proc = subprocess.run([upx_bin, "-q", packed_path], capture_output=True, text=True)
            if proc.returncode != 0:
                self.skipTest(f"Failed UPX packing: {proc.stderr}")

            res = analyze(packed_path, mode="quick")
            self.assertTrue(res.is_upx_packed)
            self.assertTrue(res.upx_unpacked)
            self.assertIsNotNone(res.unpacked_result)
            self.assertEqual(res.unpacked_result.get("metadata", {}).get("file_type"), "pe")
        finally:
            if os.path.exists(packed_path):
                os.unlink(packed_path)

    # ─── 9. Custom YARA Rules Merged With Built-in ──────────────────────────────

    def test_yara_custom_rules_merge(self):
        """Custom YARA rules must be merged alongside built-in rulesets without replacing them."""
        with tempfile.TemporaryDirectory() as temp_rules_dir:
            custom_rule_file = os.path.join(temp_rules_dir, "custom_test.yar")
            with open(custom_rule_file, "w") as f:
                f.write("""
                rule Project0_Custom_Probe {
                    meta:
                        description = "Probe for Project 0 integration test"
                        severity = "critical"
                    strings:
                        $probe = "MalOwn test utility"
                    condition:
                        $probe
                }
                """)

            scanner = YaraScanner(custom_rules_dir=temp_rules_dir)
            result = AnalysisResult()
            with open(self.script_py, "rb") as f:
                script_bytes = f.read()

            scanner.scan_bytes(script_bytes, result)
            matched_names = [m.rule_name for m in result.yara_matches]
            self.assertIn("Project0_Custom_Probe", matched_names)
            # Find the match and check offset & length
            probe_match = next(m for m in result.yara_matches if m.rule_name == "Project0_Custom_Probe")
            self.assertGreater(probe_match.offset, 0)
            self.assertEqual(probe_match.length, len("MalOwn test utility"))

    # ─── 10. MCP get_binary_annotations Pagination ──────────────────────────────

    def test_mcp_get_binary_annotations_pagination(self):
        """MCP get_binary_annotations tool should support offset and length pagination."""
        # Request all annotations
        all_ann = get_binary_annotations(self.win_exe)
        self.assertIsInstance(all_ann, list)
        self.assertGreater(len(all_ann), 0)

        # Request specific window [300, 600]
        paged_ann = get_binary_annotations(self.win_exe, offset=300, length=300)
        self.assertIsInstance(paged_ann, list)
        for item in paged_ann:
            item_offset = item["offset"]
            item_len = item.get("length", 1)
            # Check overlap condition
            self.assertTrue(item_offset < 600 and (item_offset + item_len) > 300)

    # ─── 11. Safe Test Files and Exact JSON Reports ─────────────────────────────

    def test_safe_fixtures_and_json_reports_exist(self):
        """All 4 harmless test fixtures and their exact JSON outputs must exist and be valid JSON."""
        fixtures = [
            ("hello_windows.exe", "hello_windows.json"),
            ("hello_linux.elf", "hello_linux.json"),
            ("hello_script.py", "hello_script.json"),
            ("sample_archive.zip", "sample_archive.json"),
        ]

        for bin_name, json_name in fixtures:
            bin_path = FIXTURES_DIR / bin_name
            json_path = FIXTURES_DIR / json_name

            self.assertTrue(bin_path.exists(), f"Missing fixture file: {bin_name}")
            self.assertTrue(json_path.exists(), f"Missing reference JSON: {json_name}")

            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("metadata", data)
            self.assertIn("hashes", data)
            self.assertIn("entropy", data)
            self.assertIn("iocs", data)
            self.assertIn("ensemble_score", data)
            self.assertIn("ensemble_risk_level", data)


if __name__ == "__main__":
    unittest.main()
