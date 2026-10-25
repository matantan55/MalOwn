"""Intelligent string extraction, classification, and typed IOC generation for malware analysis."""

from __future__ import annotations
import base64
import re
from urllib.parse import urlparse
from dataclasses import dataclass

from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    StringCategory,
    ThreatCategory,
    ExtractedStringHit,
    IOC,
)


# Minimum string length to extract
MIN_STRING_LEN = 4
MAX_STRINGS_PER_CATEGORY = 50

# Regex patterns for categorizing strings
PATTERNS = {
    "urls": re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{4,}',
        re.ASCII
    ),
    "ips": re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b|'
        r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
    ),
    "domains": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|io|ru|cn|cc|info|biz|xyz|top|online|site|club|vip|pro|dev|me|live|cloud)\b',
        re.IGNORECASE
    ),
    "email_addresses": re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ),
    "file_paths_win": re.compile(
        r'[A-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'
    ),
    "file_paths_unix": re.compile(
        r'(?:/(?:usr|etc|var|tmp|home|opt|bin|sbin|dev|proc|sys|root|mnt|boot|lib)'
        r'(?:/[a-zA-Z0-9._-]+)+)'
    ),
    "registry_keys": re.compile(
        r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)'
        r'(?:\\[a-zA-Z0-9 _.-]+)+'
    ),
    "crypto_wallets": re.compile(
        r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|'
        r'0x[a-fA-F0-9]{40})\b'
    ),
    "base64_blobs": re.compile(
        r'(?:[A-Za-z0-9+/]{40,}={0,2})'
    ),
    "cve_references": re.compile(
        r'CVE-\d{4}-\d{4,7}',
        re.IGNORECASE
    ),
}

# Suspicious shell commands and indicators
SUSPICIOUS_COMMANDS = [
    "cmd.exe", "cmd /c", "cmd /k",
    "powershell", "pwsh", "Invoke-Expression", "iex(",
    "Invoke-WebRequest", "Invoke-RestMethod",
    "System.Net.WebClient", "DownloadString", "DownloadFile",
    "Start-Process", "New-Object",
    "/bin/sh", "/bin/bash", "bash -c", "sh -c",
    "wget ", "curl ", "nc ", "ncat ",
    "chmod +x", "chmod 777",
    "/etc/shadow", "/etc/passwd",
    "eval(", "exec(",
    "base64 --decode", "base64 -d",
    "certutil -decode", "certutil -urlcache",
    "bitsadmin",
    "reg add", "reg delete", "reg query", "reg import", "reg export",
    "schtasks", "at ",
    "net user", "net localgroup",
    "wmic ", "wscript", "cscript",
    "mshta ", "rundll32",
    "regsvr32", "InstallUtil",
    "crontab", "launchctl",
    "iptables", "ufw ",
    "rm -rf", "del /f",
    "mkfifo", "mknod",
    "nohup ", "disown",
]

# Suspicious API function names (Windows)
SUSPICIOUS_APIS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "NtUnmapViewOfSection", "NtCreateSection",
    "CreateProcess", "ShellExecute", "WinExec",
    "OpenProcess", "ReadProcessMemory",
    "VirtualProtect", "VirtualAlloc",
    "LoadLibrary", "GetProcAddress",
    "CreateFile", "WriteFile", "DeleteFile",
    "RegSetValue", "RegCreateKey", "RegDeleteKey", "RegDeleteValue", "RegOpenKey",
    "InternetOpen", "HttpSendRequest", "URLDownloadToFile",
    "WSAStartup", "connect", "send", "recv",
    "socket", "bind", "listen", "accept",
    "CreateService", "StartService",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "MiniDumpWriteDump",
    "LsaRetrievePrivateData",
    "CredEnumerate",
    "FindFirstFile", "FindNextFile",
    "GetSystemInfo", "GetComputerName", "GetUserName",
    "EnumProcesses", "EnumProcessModules",
    "CreateToolhelp32Snapshot", "Process32First",
]


@dataclass
class _RawString:
    text: str
    offset: int
    length: int
    is_unicode: bool = False


class StringAnalyzer(BaseAnalyzer):
    """Extracts strings, records byte offsets, generates typed IOCs, and flags threats."""

    @property
    def name(self) -> str:
        return "String Extractor"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Extract strings and record source locations, typed IOCs, and indicators."""
        # Extract ASCII and Unicode raw strings with exact offsets
        raw_ascii = self._extract_ascii_strings(file_bytes)
        raw_unicode = self._extract_unicode_strings(file_bytes)
        all_raw = raw_ascii + raw_unicode

        # Classify strings and collect detailed hits
        categorized, hits, iocs, first_hits = self._classify_and_locate(all_raw)
        result.strings = categorized
        result.extracted_strings.extend(hits)
        result.iocs.extend(iocs)

        # Generate threat indicators with source byte offsets
        self._generate_indicators(result, first_hits)

    def _extract_ascii_strings(self, data: bytes) -> list[_RawString]:
        """Extract printable ASCII strings with their byte offset and length."""
        pattern = rb'[\x20-\x7E]{' + str(MIN_STRING_LEN).encode() + rb',}'
        results: list[_RawString] = []
        for m in re.finditer(pattern, data):
            if len(results) >= 5000:
                break
            raw = m.group()
            results.append(_RawString(
                text=raw.decode("ascii", errors="replace"),
                offset=m.start(),
                length=len(raw),
                is_unicode=False,
            ))
        return results

    def _extract_unicode_strings(self, data: bytes) -> list[_RawString]:
        """Extract UTF-16LE encoded strings with their byte offset and length."""
        pattern = rb'(?:[\x20-\x7E]\x00){' + str(MIN_STRING_LEN).encode() + rb',}'
        results: list[_RawString] = []
        for m in re.finditer(pattern, data):
            if len(results) >= 2000:
                break
            raw = m.group()
            try:
                decoded = raw.decode("utf-16-le").strip("\x00")
                if len(decoded) >= MIN_STRING_LEN:
                    results.append(_RawString(
                        text=decoded,
                        offset=m.start(),
                        length=len(raw),
                        is_unicode=True,
                    ))
            except Exception:
                pass
        return results

    def _match_pattern(
        self,
        raw_strings: list[_RawString],
        pattern: re.Pattern,
        category: str,
    ) -> list[tuple[str, int, int]]:
        """Find regex pattern matches inside raw strings, calculating byte offsets."""
        matches: list[tuple[str, int, int]] = []
        seen = set()
        for s in raw_strings:
            for m in pattern.finditer(s.text):
                val = m.group()
                char_start = m.start()
                char_len = len(val)
                if s.is_unicode:
                    byte_off = s.offset + char_start * 2
                    byte_len = char_len * 2
                else:
                    byte_off = s.offset + char_start
                    byte_len = char_len

                key = (val, byte_off)
                if key not in seen:
                    seen.add(key)
                    matches.append((val, byte_off, byte_len))
        return matches

    def _classify_and_locate(
        self,
        raw_strings: list[_RawString],
    ) -> tuple[StringCategory, list[ExtractedStringHit], list[IOC], dict[str, tuple[int, int]]]:
        """Classify strings, build detailed string hits, typed IOCs, and first hit locations."""
        cat = StringCategory()
        hits: list[ExtractedStringHit] = []
        iocs: list[IOC] = []
        first_hits: dict[str, tuple[int, int]] = {}

        # 1. URLs & Domains
        url_matches = self._match_pattern(raw_strings, PATTERNS["urls"], "url")
        url_values = []
        for val, off, length in url_matches:
            url_values.append(val)
            hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="url"))
            iocs.append(IOC(type="url", value=val, offset=off, length=length))
            if "urls" not in first_hits:
                first_hits["urls"] = (off, length)

            # Extract domain from URL
            try:
                parsed = urlparse(val)
                hostname = parsed.hostname
                if hostname and not hostname.replace(".", "").isdigit():
                    host_idx = val.find(hostname)
                    dom_off = off + host_idx if host_idx != -1 else off
                    dom_len = len(hostname)
                    iocs.append(IOC(type="domain", value=hostname, offset=dom_off, length=dom_len))
            except Exception:
                pass
        cat.urls = list(dict.fromkeys(url_values))[:MAX_STRINGS_PER_CATEGORY]

        # 2. Standalone Domains
        domain_matches = self._match_pattern(raw_strings, PATTERNS["domains"], "domain")
        for val, off, length in domain_matches:
            # Avoid duplicate if already covered by URL
            if not any(val in u for u in cat.urls):
                hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="domain"))
                iocs.append(IOC(type="domain", value=val, offset=off, length=length))

        # 3. IPv4 Addresses
        ip_matches = self._match_pattern(raw_strings, PATTERNS["ips"], "ipv4")
        ip_values = []
        benign_prefixes = ("0.", "127.", "255.", "224.", "239.")
        for val, off, length in ip_matches:
            ip_clean = val.split(":")[0]
            if not ip_clean.startswith(benign_prefixes):
                try:
                    parts = ip_clean.split(".")
                    if len(parts) == 4 and all(0 <= int(o) <= 255 for o in parts):
                        ip_values.append(val)
                        hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="ipv4"))
                        iocs.append(IOC(type="ipv4", value=val, offset=off, length=length))
                        if "ips" not in first_hits:
                            first_hits["ips"] = (off, length)
                except ValueError:
                    pass
        cat.ips = list(dict.fromkeys(ip_values))[:MAX_STRINGS_PER_CATEGORY]

        # 4. IPv6 Addresses
        ipv6_matches = self._match_pattern(raw_strings, PATTERNS["ipv6"], "ipv6")
        for val, off, length in ipv6_matches:
            if ":" in val and len(val) >= 4:
                hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="ipv6"))
                iocs.append(IOC(type="ipv6", value=val, offset=off, length=length))
                if "ips" not in first_hits:
                    first_hits["ips"] = (off, length)

        # 5. Email Addresses
        email_matches = self._match_pattern(raw_strings, PATTERNS["email_addresses"], "email")
        email_values = []
        for val, off, length in email_matches:
            email_values.append(val)
            hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="email"))
            iocs.append(IOC(type="email", value=val, offset=off, length=length))
            if "emails" not in first_hits:
                first_hits["emails"] = (off, length)
        cat.email_addresses = list(dict.fromkeys(email_values))[:MAX_STRINGS_PER_CATEGORY]

        # 6. File Paths (Windows & Unix)
        win_matches = self._match_pattern(raw_strings, PATTERNS["file_paths_win"], "file_path")
        unix_matches = self._match_pattern(raw_strings, PATTERNS["file_paths_unix"], "file_path")
        path_values = []
        for val, off, length in win_matches + unix_matches:
            path_values.append(val)
            hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="file_path"))
            iocs.append(IOC(type="file_path", value=val, offset=off, length=length))
            if "file_paths" not in first_hits:
                first_hits["file_paths"] = (off, length)
        cat.file_paths = list(dict.fromkeys(path_values))[:MAX_STRINGS_PER_CATEGORY]

        # 7. Registry Keys
        reg_matches = self._match_pattern(raw_strings, PATTERNS["registry_keys"], "registry_key")
        reg_values = []
        for val, off, length in reg_matches:
            reg_values.append(val)
            hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="registry_key"))
            iocs.append(IOC(type="registry_key", value=val, offset=off, length=length))
            if "registry_keys" not in first_hits:
                first_hits["registry_keys"] = (off, length)
        cat.registry_keys = list(dict.fromkeys(reg_values))[:MAX_STRINGS_PER_CATEGORY]

        # 8. Crypto Wallets
        wallet_matches = self._match_pattern(raw_strings, PATTERNS["crypto_wallets"], "crypto_wallet")
        wallet_values = []
        for val, off, length in wallet_matches:
            wallet_values.append(val)
            hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="crypto_wallet"))
            if "crypto_wallets" not in first_hits:
                first_hits["crypto_wallets"] = (off, length)
        cat.crypto_wallets = list(dict.fromkeys(wallet_values))[:MAX_STRINGS_PER_CATEGORY]

        # 9. Base64 Blobs
        b64_matches = self._match_pattern(raw_strings, PATTERNS["base64_blobs"], "base64")
        b64_values = []
        for val, off, length in b64_matches[:100]:
            try:
                decoded = base64.b64decode(val)
                printable_ratio = sum(1 for c in decoded if 32 <= c <= 126) / max(len(decoded), 1)
                if printable_ratio > 0.4:
                    trunc = val[:80] + ("..." if len(val) > 80 else "")
                    b64_values.append(trunc)
                    hits.append(ExtractedStringHit(value=trunc, offset=off, length=length, category="base64"))
                    if "base64" not in first_hits:
                        first_hits["base64"] = (off, length)
            except Exception:
                pass
        cat.base64_blobs = list(dict.fromkeys(b64_values))[:MAX_STRINGS_PER_CATEGORY]

        # 10. CVE References
        cve_matches = self._match_pattern(raw_strings, PATTERNS["cve_references"], "cve")
        cve_values = []
        for val, off, length in cve_matches:
            cve_values.append(val)
            hits.append(ExtractedStringHit(value=val, offset=off, length=length, category="cve"))
            if "cve" not in first_hits:
                first_hits["cve"] = (off, length)
        cat.cve_references = list(dict.fromkeys(cve_values))[:MAX_STRINGS_PER_CATEGORY]

        # 11. Suspicious Shell Commands
        cmd_values = []
        for s in raw_strings:
            s_lower = s.text.lower()
            for cmd in SUSPICIOUS_COMMANDS:
                idx = s_lower.find(cmd.lower())
                if idx != -1:
                    byte_off = s.offset + (idx * 2 if s.is_unicode else idx)
                    byte_len = len(cmd) * (2 if s.is_unicode else 1)
                    val = s.text.strip()[:200]
                    cmd_values.append(val)
                    hits.append(ExtractedStringHit(value=val, offset=byte_off, length=byte_len, category="shell_command"))
                    if "shell_commands" not in first_hits:
                        first_hits["shell_commands"] = (byte_off, byte_len)
                    break
        cat.shell_commands = list(dict.fromkeys(cmd_values))[:MAX_STRINGS_PER_CATEGORY]

        # 12. Suspicious API Calls
        api_values = []
        for s in raw_strings:
            for api in SUSPICIOUS_APIS:
                idx = s.text.find(api)
                if idx != -1:
                    byte_off = s.offset + (idx * 2 if s.is_unicode else idx)
                    byte_len = len(api) * (2 if s.is_unicode else 1)
                    api_values.append(api)
                    hits.append(ExtractedStringHit(value=api, offset=byte_off, length=byte_len, category="api_call"))
                    if "api_calls" not in first_hits:
                        first_hits["api_calls"] = (byte_off, byte_len)
                    break
        cat.api_calls = list(dict.fromkeys(api_values))[:MAX_STRINGS_PER_CATEGORY]

        # Deduplicate IOCs
        dedup_iocs: list[IOC] = []
        seen_iocs = set()
        for ioc in iocs:
            key = (ioc.type, ioc.value, ioc.offset)
            if key not in seen_iocs:
                seen_iocs.add(key)
                dedup_iocs.append(ioc)

        return cat, hits, dedup_iocs, first_hits

    def _generate_indicators(
        self,
        result: AnalysisResult,
        first_hits: dict[str, tuple[int, int]],
    ) -> None:
        """Generate threat indicators from string findings with exact source byte offsets."""
        s = result.strings

        if s.urls:
            off, length = first_hits.get("urls", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.COMMAND_AND_CONTROL,
                name="URLs Detected",
                description=f"Found {len(s.urls)} URL(s) embedded in the file.",
                evidence=s.urls[:5],
                severity=0.4,
                offset=off,
                length=length,
            ))

        if s.ips:
            off, length = first_hits.get("ips", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.COMMAND_AND_CONTROL,
                name="IP Addresses Detected",
                description=f"Found {len(s.ips)} IP address(es) embedded in the file.",
                evidence=s.ips[:5],
                severity=0.5,
                offset=off,
                length=length,
            ))

        if s.registry_keys:
            off, length = first_hits.get("registry_keys", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.PERSISTENCE,
                name="Registry Key References",
                description=f"Found {len(s.registry_keys)} registry key reference(s).",
                evidence=s.registry_keys[:5],
                severity=0.5,
                offset=off,
                length=length,
            ))

        if s.crypto_wallets:
            off, length = first_hits.get("crypto_wallets", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.IMPACT,
                name="Cryptocurrency Wallet Addresses",
                description=(
                    f"Found {len(s.crypto_wallets)} cryptocurrency wallet address(es). "
                    "This may indicate ransomware or crypto-miner activity."
                ),
                evidence=s.crypto_wallets[:3],
                severity=0.8,
                offset=off,
                length=length,
            ))

        if s.shell_commands:
            off, length = first_hits.get("shell_commands", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Suspicious Shell Commands",
                description=f"Found {len(s.shell_commands)} suspicious command reference(s).",
                evidence=s.shell_commands[:5],
                severity=0.6,
                offset=off,
                length=length,
            ))

        if s.api_calls:
            off, length = first_hits.get("api_calls", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Suspicious API Calls",
                description=f"Found {len(s.api_calls)} suspicious API function reference(s).",
                evidence=s.api_calls[:10],
                severity=0.5,
                offset=off,
                length=length,
            ))

        if s.base64_blobs:
            off, length = first_hits.get("base64", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Base64 Encoded Data",
                description=(
                    f"Found {len(s.base64_blobs)} base64-encoded blob(s) that decode "
                    "to meaningful content. May hide malicious payloads."
                ),
                evidence=s.base64_blobs[:3],
                severity=0.4,
                offset=off,
                length=length,
            ))

        if s.cve_references:
            off, length = first_hits.get("cve", (0, 0))
            result.indicators.append(Indicator(
                category=ThreatCategory.EXPLOIT,
                name="Vulnerability/CVE References Detected",
                description=f"Found {len(s.cve_references)} reference(s) to known vulnerabilities (CVEs), highly indicative of an exploit payload.",
                evidence=s.cve_references[:5],
                severity=0.9,
                offset=off,
                length=length,
            ))
