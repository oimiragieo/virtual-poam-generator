"""
HTML Exporter for vISSM
Exports vulnerability reports to HTML format
"""

import os
from typing import Dict, Any
from src.templates.template_engine import render_html_report


class HTMLExporter:
    """Exports vulnerability reports to HTML format"""

    def __init__(self, template_dir: str = None):
        self.template_dir = template_dir

    def export(self, analysis_data: Dict[str, Any], output_path: str) -> str:
        """Export analysis data to HTML file"""
        try:
            # Render the HTML report
            html_content = render_html_report(analysis_data, self.template_dir)

            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            return output_path

        except Exception as e:
            raise ValueError(f"Error exporting HTML report: {e}")

    def export_to_string(self, analysis_data: Dict[str, Any]) -> str:
        """Export analysis data to HTML string"""
        try:
            return render_html_report(analysis_data, self.template_dir)
        except Exception as e:
            raise ValueError(f"Error generating HTML string: {e}")


def export_html_report(
    analysis_data: Dict[str, Any], output_path: str, template_dir: str = None
) -> str:
    """Convenience function to export HTML report"""
    exporter = HTMLExporter(template_dir)
    return exporter.export(analysis_data, output_path)


if __name__ == "__main__":
    # Test the HTML exporter
    import sys
    from src.parser.nessus_parser import parse_nessus_file
    from src.processor.vulnerability_processor import process_nessus_report

    if len(sys.argv) != 3:
        print("Usage: python html_exporter.py <nessus_file> <output_file>")
        sys.exit(1)

    try:
        # Parse and process the file
        report = parse_nessus_file(sys.argv[1])
        analysis_data = process_nessus_report(report)
        analysis_data["report"] = report

        # Export to HTML
        output_path = export_html_report(analysis_data, sys.argv[2])
        print(f"HTML report exported to: {output_path}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
