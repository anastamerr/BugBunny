#!/usr/bin/env python3
"""CLI command to evaluate scan policy for CI/CD integration.

Usage:
    python -m src.cli.scan_policy --scan-id <uuid> [--fail-on high] [--include-fps]

Exit codes:
    0 - Policy passed (no violations)
    1 - Policy failed (violations found)
    2 - Error (invalid arguments, scan not found, etc.)
"""

from __future__ import annotations

import argparse
import json
import sys

from ..db.session import SessionLocal
from ..services.scanner.scan_policy import evaluate_scan_policy


def main() -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Evaluate scan findings against policy threshold"
    )
    parser.add_argument(
        "--scan-id",
        required=True,
        help="Scan UUID to evaluate",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=["info", "low", "medium", "high", "critical"],
        help="Minimum severity to fail on (default: high)",
    )
    parser.add_argument(
        "--include-fps",
        action="store_true",
        help="Include findings marked as false positives",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON result instead of summary",
    )

    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = evaluate_scan_policy(
            db=db,
            scan_id=args.scan_id,
            fail_on=args.fail_on,
            include_false_positives=args.include_fps,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()

    if args.json:
        # Full JSON output
        output = {
            "passed": result.passed,
            "exit_code": result.exit_code,
            "fail_on": result.fail_on,
            "violations_count": result.violations_count,
            "violations": [
                {
                    "finding_id": v.finding_id,
                    "severity": v.severity,
                    "rule_id": v.rule_id,
                    "rule_message": v.rule_message,
                    "file_path": v.file_path,
                    "line_start": v.line_start,
                }
                for v in result.violations
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        # Compact summary
        status = "PASS" if result.passed else "FAIL"
        print(
            f"Policy: {status} (fail_on={result.fail_on}, violations={result.violations_count})"
        )
        if not result.passed:
            print("\nViolations:")
            for v in result.violations[:10]:  # Show first 10
                print(f"  [{v.severity.upper()}] {v.rule_message} ({v.file_path}:{v.line_start})")
            if result.violations_count > 10:
                print(f"  ... and {result.violations_count - 10} more")

    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
