import argparse
from veacor.roadmap_builder import run


def main():
    example_text = """
Examples:

  CVE      → veacorg CVE-2023-4412
  CWE      → veacorg CWE-78
  CAPEC    → veacorg CAPEC-100
  ATT&CK   → veacorg T1059
  D3FEND   → veacorg D3-DAE
  CPE      → veacorg cpe:2.3:a:apache:http_server:2.4.49
  Product  → veacorg -p Microsoft IIS 3.0


Modes:
  veacorg CVE-2023-4412 --mode agg   --- changes the limit of nodes to 20 (DEFAULT is 5)
  veacorg CWE-78 --mode xtrm         --- removes limit set to the number of nodes
"""

    parser = argparse.ArgumentParser(
        description="Automatic cyber roadmap builder (CPE/CVE/CWE/CAPEC/ATT&CK/D3FEND).",
        epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "identifier",
        nargs="?",
        help="Input identifier (CVE, CWE, CAPEC, ATT&CK, D3FEND, or CPE)"
    )
    parser.add_argument(
        "--mode",
        choices=["default", "agg", "xtrm"],
        default="default",
        help="Execution mode (default=5 CVEs, agg=20 CVEs, xtrm=unlimited)"
    )

    parser.add_argument(
        "-desc",
        "--description",
        metavar="TYPE",
        help="Resolve free-text description to an entity type (CWE, CAPEC, ATTACK, DEFEND, CVE)"
    )

    args = parser.parse_args()

    if args.description:

        # Normalize CLI input
        target_type_cli = args.description.strip().upper()

        valid_types = {"CVE", "CWE", "CAPEC", "ATTACK", "D3FEND"}

        type_map = {
            "CVE": "CVE",
            "CWE": "CWE",
            "CAPEC": "CAPEC",
            "ATTACK": "ATTACK",
            "D3FEND": "DEFEND"  # internal naming
        }

        if target_type_cli not in valid_types:
            print(f"❌ Invalid TYPE '{target_type_cli}'. Must be one of: {', '.join(sorted(valid_types))}")
            raise SystemExit(1)

        # Map CLI label to internal label
        target_type = type_map[target_type_cli]

        # Prompt user interactively
        try:
            user_text = input("Enter description:\n> ").strip()
        except KeyboardInterrupt:
            print("\n❌ Cancelled.")
            raise SystemExit(1)

        if not user_text:
            print("❌ Description cannot be empty.")
            raise SystemExit(1)

        run(user_text, forced_target_type=target_type)
        return
    elif not args.identifier:
        parser.error("identifier is required unless using -desc")
    else:
        run(args.identifier, mode=args.mode)

    run(args.identifier, mode=args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
