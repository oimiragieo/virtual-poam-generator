#!/usr/bin/env python3
"""
Virtual POAM Generator - DoD eMASS Compliance Tool
Command-line interface for processing Nessus vulnerability reports
and generating DoD-compliant POAMs and compliance documentation
"""

import argparse
import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from parser.nessus_parser import parse_nessus_file  # noqa: E402
from processor.vulnerability_processor import process_nessus_report  # noqa: E402
from exporters.html_exporter import export_html_report  # noqa: E402
from exporters.pdf_exporter import export_pdf_report  # noqa: E402
from exporters.csv_exporter import (  # noqa: E402
    export_csv_report,
    export_csv_summary,
)
from exporters.excel_exporter import (  # noqa: E402
    export_excel_vulnerability_report,
    export_excel_ivv_test_plan,
    export_excel_cnet_report,
    export_excel_hw_sw_inventory,
    export_excel_emass_inventory,
    export_excel_poam,
)
from exporters.stig_exporter import export_stig_checklist  # noqa: E402


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Virtual POAM Generator - DoD eMASS Compliance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py report.nessus -o poam.xlsx -f xlsx -r poam
  python cli.py report.nessus -o report.xlsx -f xlsx -r vulnerability
  python cli.py report.nessus -o test_plan.xlsx -f xlsx -r ivv-test-plan
  python cli.py report.nessus -o inventory.xlsx -f xlsx -r hw-sw-inventory
  python cli.py report.nessus -o emass.xlsm -f xlsx -r emass-inventory
  python cli.py report.nessus -o report.html -f html
  python cli.py report.nessus --summary -o summary.csv
        """,
    )

    # Required arguments
    parser.add_argument("input_file", help="Input .nessus file to process")

    parser.add_argument("-o", "--output", help="Output file path")

    parser.add_argument(
        "-f",
        "--format",
        choices=["html", "pdf", "csv", "xlsx"],
        default="xlsx",
        help="Output format (default: xlsx)",
    )

    parser.add_argument(
        "-r",
        "--report-type",
        choices=[
            "vulnerability",
            "poam",
            "ivv-test-plan",
            "cnet",
            "hw-sw-inventory",
            "emass-inventory",
            "stig-checklist",
        ],
        default="vulnerability",
        help="Report type to generate (default: vulnerability)",
    )

    # Optional arguments
    parser.add_argument(
        "--summary", action="store_true", help="Export summary only (CSV format)"
    )

    parser.add_argument("--template-dir", help="Custom template directory")

    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument(
        "--version", action="version", version="Virtual POAM Generator v1.0.0"
    )

    args = parser.parse_args()

    try:
        # Validate input file
        if not os.path.exists(args.input_file):
            print(f"Error: Input file '{args.input_file}' not found")
            sys.exit(1)

        if not args.input_file.lower().endswith(".nessus"):
            print("Warning: Input file doesn't have .nessus extension")

        # Set default output file if not provided
        if not args.output:
            base_name = Path(args.input_file).stem
            if args.summary:
                args.output = f"{base_name}_summary.csv"
            else:
                args.output = f"{base_name}_report.{args.format}"

        if args.verbose:
            print(f"Processing Nessus file: {args.input_file}")
            print(f"Output format: {args.format}")
            print(f"Output file: {args.output}")

        # Parse the Nessus file
        if args.verbose:
            print("Parsing Nessus file...")

        report = parse_nessus_file(args.input_file)

        if args.verbose:
            print(
                f"Found {report.total_hosts} hosts with {report.total_vulnerabilities} vulnerabilities"
            )

        # Process the data
        if args.verbose:
            print("Processing vulnerability data...")

        analysis_data = process_nessus_report(report)
        analysis_data["report"] = report

        # Add report type to analysis data
        analysis_data["report_type"] = args.report_type

        # Export based on format and report type
        if args.summary:
            if args.verbose:
                print(f"Exporting {args.report_type} summary to CSV...")
            output_path = export_csv_summary(analysis_data, args.output)
        elif args.format == "xlsx":
            if args.verbose:
                print(f"Exporting {args.report_type} Excel report...")
            # Route to appropriate Excel exporter based on report type
            if args.report_type == "vulnerability":
                output_path = export_excel_vulnerability_report(
                    analysis_data, args.output
                )
            elif args.report_type == "poam":
                output_path = export_excel_poam(analysis_data, args.output)
            elif args.report_type == "ivv-test-plan":
                output_path = export_excel_ivv_test_plan(analysis_data, args.output)
            elif args.report_type == "cnet":
                output_path = export_excel_cnet_report(analysis_data, args.output)
            elif args.report_type == "hw-sw-inventory":
                output_path = export_excel_hw_sw_inventory(analysis_data, args.output)
            elif args.report_type == "emass-inventory":
                output_path = export_excel_emass_inventory(analysis_data, args.output)
            elif args.report_type == "stig-checklist":
                output_path = export_stig_checklist(analysis_data, args.output)
            else:
                print(
                    f"Error: Unsupported report type '{args.report_type}' for Excel format"
                )
                sys.exit(1)
        elif args.format == "html":
            if args.verbose:
                print(f"Exporting {args.report_type} HTML report...")
            output_path = export_html_report(
                analysis_data, args.output, args.template_dir
            )
        elif args.format == "pdf":
            if args.verbose:
                print(f"Exporting {args.report_type} PDF report...")
            output_path = export_pdf_report(
                analysis_data, args.output, args.template_dir
            )
        elif args.format == "csv":
            if args.verbose:
                print(f"Exporting {args.report_type} CSV report...")
            output_path = export_csv_report(analysis_data, args.output)
        else:
            print(f"Error: Unsupported format '{args.format}'")
            sys.exit(1)

        # Print results
        print(f"Report exported successfully to: {output_path}")

        # Print summary statistics
        summary = analysis_data["summary"]
        print("\nSummary:")
        print(f"  Total hosts: {len(analysis_data['host_summaries'])}")
        print(f"  Total vulnerabilities: {summary.total_vulnerabilities}")
        print(f"  Critical: {summary.critical_count}")
        print(f"  High: {summary.high_count}")
        print(f"  Medium: {summary.medium_count}")
        print(f"  Low: {summary.low_count}")
        print(f"  Info: {summary.info_count}")

        # Print recommendations
        if analysis_data.get("recommendations"):
            print("\nKey Recommendations:")
            for i, rec in enumerate(analysis_data["recommendations"][:3], 1):
                print(f"  {i}. {rec}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
