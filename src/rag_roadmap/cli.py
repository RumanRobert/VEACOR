import argparse
from rag_roadmap.roadmap_builder import run


def main():
    example_text = """
Examples:

  CVE      → gvrm CVE-2023-4412
  CWE      → gvrm CWE-78
  CAPEC    → gvrm CAPEC-100
  ATT&CK   → gvrm T1059
  D3FEND   → gvrm D3-DAE
  CPE      → gvrm cpe:2.3:a:apache:http_server:2.4.49
  Product  → gvrm Microsoft IIS 3.0


Modes:
  gvrm CVE-2023-4412 --mode agg   --- changes the limit of nodes to 20 (DEFAULT is 5)
  gvrm CWE-78 --mode xtrm         --- removes limit set to the number of nodes
"""

    parser = argparse.ArgumentParser(
        description="Automatic cyber roadmap builder (CPE/CVE/CWE/CAPEC/ATT&CK/D3FEND).",
        epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "identifier",
        help="Input identifier (CVE, CWE, CAPEC, ATT&CK, D3FEND, or CPE)"
    )

    parser.add_argument(
        "--mode",
        choices=["default", "agg", "xtrm"],
        default="default",
        help="Execution mode (default=5 CVEs, agg=20 CVEs, xtrm=unlimited)"
    )

    args = parser.parse_args()

    run(args.identifier, mode=args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
