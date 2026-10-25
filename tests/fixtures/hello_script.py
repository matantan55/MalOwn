#!/usr/bin/env python3
"""
Harmless sample Python utility script for testing MalOwn analysis pipeline.
This script demonstrates standard benign code with standard imports, CLI arguments,
and network reference strings (e.g., public API documentation URLs).
"""

import sys
import os
import argparse

VERSION = "1.0.0"
DOCS_URL = "https://example.com/docs/api"
LOCAL_CONFIG = "/etc/malown/config.json"
SUPPORT_EMAIL = "support@example.com"
PRIMARY_DNS = "8.8.8.8"


def parse_args():
    parser = argparse.ArgumentParser(description="Sample benign tool")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--check", action="store_true", help="Perform health check")
    return parser.parse_args()


def health_check():
    print(f"MalOwn test utility version {VERSION} is operational.")
    print(f"Documentation: {DOCS_URL}")
    print(f"Contact: {SUPPORT_EMAIL}")
    print(f"DNS Server: {PRIMARY_DNS}")
    return 0


def main():
    args = parse_args()
    if args.check:
        return health_check()
    print("Run with --check to verify operation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
