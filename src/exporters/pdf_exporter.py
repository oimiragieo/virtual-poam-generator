"""
PDF Exporter for vISSM
Exports vulnerability reports to PDF format using WeasyPrint
"""

import os
from typing import Dict, Any
from src.templates.template_engine import render_pdf_report


class PDFExporter:
    """Exports vulnerability reports to PDF format"""

    def __init__(self, template_dir: str = None):
        self.template_dir = template_dir

    def export(self, analysis_data: Dict[str, Any], output_path: str) -> str:
        """Export analysis data to PDF file"""
        try:
            # Render the PDF report (HTML that can be converted to PDF)
            html_content = render_pdf_report(analysis_data, self.template_dir)

            # Try to use WeasyPrint if available
            try:
                from weasyprint import HTML
                from weasyprint.text.fonts import FontConfiguration

                # Ensure output directory exists
                output_dir = os.path.dirname(output_path)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)

                # Convert HTML to PDF
                font_config = FontConfiguration()
                html_doc = HTML(string=html_content)
                html_doc.write_pdf(output_path, font_config=font_config)

            except ImportError:
                # Fallback: save as HTML that can be printed to PDF
                html_path = output_path.replace(".pdf", ".html")
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                print(f"WeasyPrint not available. HTML saved to: {html_path}")
                print("You can open this file in a browser and print to PDF.")
                return html_path

            return output_path

        except Exception as e:
            raise ValueError(f"Error exporting PDF report: {e}")

    def export_to_string(self, analysis_data: Dict[str, Any]) -> str:
        """Export analysis data to HTML string (for PDF conversion)"""
        try:
            return render_pdf_report(analysis_data, self.template_dir)
        except Exception as e:
            raise ValueError(f"Error generating PDF HTML: {e}")


def export_pdf_report(
    analysis_data: Dict[str, Any], output_path: str, template_dir: str = None
) -> str:
    """Convenience function to export PDF report"""
    exporter = PDFExporter(template_dir)
    return exporter.export(analysis_data, output_path)


if __name__ == "__main__":
    # Test the PDF exporter
    import sys
    from src.parser.nessus_parser import parse_nessus_file
    from src.processor.vulnerability_processor import process_nessus_report

    if len(sys.argv) != 3:
        print("Usage: python pdf_exporter.py <nessus_file> <output_file>")
        sys.exit(1)

    try:
        # Parse and process the file
        report = parse_nessus_file(sys.argv[1])
        analysis_data = process_nessus_report(report)
        analysis_data["report"] = report

        # Export to PDF
        output_path = export_pdf_report(analysis_data, sys.argv[2])
        print(f"PDF report exported to: {output_path}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
