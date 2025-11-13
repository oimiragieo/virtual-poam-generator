"""
Template Engine for vISSM
Handles template rendering for various output formats
"""

import os
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, Template
from datetime import datetime


class TemplateEngine:
    """Template engine for rendering vulnerability reports"""

    def __init__(self, template_dir: str = None):
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "templates")

        self.template_dir = template_dir
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Add custom filters
        self.env.filters["severity_name"] = self._severity_name_filter
        self.env.filters["risk_level"] = self._risk_level_filter
        self.env.filters["format_date"] = self._format_date_filter

    def render_template(self, template_name: str, data: Dict[str, Any]) -> str:
        """Render a template with the provided data"""
        try:
            template = self.env.get_template(template_name)
            return template.render(**data)
        except Exception as e:
            raise ValueError(f"Error rendering template {template_name}: {e}")

    def render_string(self, template_string: str, data: Dict[str, Any]) -> str:
        """Render a template string with the provided data"""
        try:
            template = Template(template_string)
            return template.render(**data)
        except Exception as e:
            raise ValueError(f"Error rendering template string: {e}")

    def _severity_name_filter(self, severity: int) -> str:
        """Convert severity number to name"""
        severity_names = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        return severity_names.get(severity, "Unknown")

    def _risk_level_filter(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"

    def _format_date_filter(self, date_string: str) -> str:
        """Format date string for display"""
        if not date_string:
            return "Unknown"

        try:
            # Try to parse common date formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"]:
                try:
                    dt = datetime.strptime(date_string, fmt)
                    return dt.strftime("%B %d, %Y")
                except ValueError:
                    continue
            return date_string
        except Exception:
            return date_string


class ReportTemplate:
    """Base class for report templates"""

    def __init__(self, template_engine: TemplateEngine):
        self.template_engine = template_engine

    def prepare_data(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for template rendering"""
        # Add common template variables
        data = analysis_data.copy()
        data["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["generated_by"] = "vISSM v1.0"

        # Add summary statistics
        if "summary" in data:
            summary = data["summary"]
            data["total_hosts"] = len(data.get("host_summaries", []))
            data["total_vulnerabilities"] = summary.total_vulnerabilities
            data["critical_count"] = summary.critical_count
            data["high_count"] = summary.high_count
            data["medium_count"] = summary.medium_count
            data["low_count"] = summary.low_count
            data["info_count"] = summary.info_count

        return data


class HTMLReportTemplate(ReportTemplate):
    """HTML report template"""

    def render(self, analysis_data: Dict[str, Any]) -> str:
        """Render HTML report"""
        data = self.prepare_data(analysis_data)

        # Add HTML-specific data
        data["css_styles"] = self._get_css_styles()
        data["javascript"] = self._get_javascript()

        # Use inline template as fallback if template files don't exist
        return self._render_inline_html(data)

    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML report"""
        return """
        <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .summary-item { text-align: center; padding: 10px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; font-weight: bold; }
        .low { color: #388e3c; font-weight: bold; }
        .info { color: #1976d2; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .host-row { background-color: #f9f9f9; }
        .vuln-row { background-color: #fff; }
        .severity-critical { background-color: #ffebee; }
        .severity-high { background-color: #fff3e0; }
        .severity-medium { background-color: #fffde7; }
        .severity-low { background-color: #e8f5e8; }
        .severity-info { background-color: #e3f2fd; }
        </style>
        """

    def _get_javascript(self) -> str:
        """Get JavaScript for HTML report"""
        return """
        <script>
        function toggleVulnerabilities(hostId) {
            var vulns = document.getElementById('vulns-' + hostId);
            if (vulns.style.display === 'none') {
                vulns.style.display = 'block';
            } else {
                vulns.style.display = 'none';
            }
        }
        </script>
        """

    def _render_inline_html(self, data: Dict[str, Any]) -> str:
        """Render HTML report using inline template"""
        host_summaries = data.get("host_summaries", [])
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Assessment Report</title>
    {data.get('css_styles', '')}
</head>
<body>
    <div class="header">
        <h1>Vulnerability Assessment Report</h1>
        <p>Generated: {data.get('generated_at', 'N/A')}</p>
        <p>Generated by: {data.get('generated_by', 'N/A')}</p>
    </div>

    <div class="summary">
        <div class="summary-item">
            <h3>Total Hosts</h3>
            <p>{data.get('total_hosts', 0)}</p>
        </div>
        <div class="summary-item">
            <h3>Total Vulnerabilities</h3>
            <p>{data.get('total_vulnerabilities', 0)}</p>
        </div>
        <div class="summary-item critical">
            <h3>Critical</h3>
            <p>{data.get('critical_count', 0)}</p>
        </div>
        <div class="summary-item high">
            <h3>High</h3>
            <p>{data.get('high_count', 0)}</p>
        </div>
        <div class="summary-item medium">
            <h3>Medium</h3>
            <p>{data.get('medium_count', 0)}</p>
        </div>
        <div class="summary-item low">
            <h3>Low</h3>
            <p>{data.get('low_count', 0)}</p>
        </div>
        <div class="summary-item info">
            <h3>Info</h3>
            <p>{data.get('info_count', 0)}</p>
        </div>
    </div>

    <h2>Host Summaries</h2>
    <table>
        <tr>
            <th>Hostname</th>
            <th>IP</th>
            <th>OS</th>
            <th>Total</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Info</th>
            <th>Risk Score</th>
        </tr>
"""

        for host in host_summaries:
            html += f"""
        <tr class="host-row">
            <td>{host.hostname or 'N/A'}</td>
            <td>{host.ip}</td>
            <td>{host.os or 'Unknown'}</td>
            <td>{host.total_vulnerabilities}</td>
            <td class="critical">{host.critical_vulnerabilities}</td>
            <td class="high">{host.high_vulnerabilities}</td>
            <td class="medium">{host.medium_vulnerabilities}</td>
            <td class="low">{host.low_vulnerabilities}</td>
            <td class="info">{host.info_vulnerabilities}</td>
            <td>{host.risk_score:.1f}</td>
        </tr>
"""

        html += """
    </table>

    <h2>Recommendations</h2>
    <ul>
"""

        for rec in data.get("recommendations", []):
            html += f"        <li>{rec}</li>\n"

        html += """
    </ul>
</body>
</html>
"""
        return html


class PDFReportTemplate(ReportTemplate):
    """PDF report template"""

    def render(self, analysis_data: Dict[str, Any]) -> str:
        """Render PDF report (HTML that can be converted to PDF)"""
        data = self.prepare_data(analysis_data)

        # Add PDF-specific styling
        data["pdf_styles"] = self._get_pdf_styles()

        # Select template based on report type
        report_type = analysis_data.get("report_type", "vulnerability")
        template_map = {
            "vulnerability": "pdf_report.html",
            "ivv-test-plan": "ivv_test_plan.html",
            "cnet": "cnet_report.html",
            "hw-sw-inventory": "hw_sw_inventory.html",
            "emass-inventory": "emass_inventory.html",
        }

        template_name = template_map.get(report_type, "pdf_report.html")
        return self.template_engine.render_template(template_name, data)

    def _get_pdf_styles(self) -> str:
        """Get styles optimized for PDF generation"""
        return """
        <style>
        @page { size: A4; margin: 2cm; }
        body { font-family: 'Times New Roman', serif; font-size: 12px; line-height: 1.4; }
        .header { text-align: center; margin-bottom: 30px; }
        .summary { display: table; width: 100%; margin: 20px 0; }
        .summary-item { display: table-cell; text-align: center; padding: 10px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; font-weight: bold; }
        .low { color: #388e3c; font-weight: bold; }
        .info { color: #1976d2; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; page-break-inside: avoid; }
        th, td { border: 1px solid #000; padding: 5px; font-size: 10px; }
        th { background-color: #f0f0f0; font-weight: bold; }
        .page-break { page-break-before: always; }
        </style>
        """


class CSVReportTemplate(ReportTemplate):
    """CSV report template"""

    def render(self, analysis_data: Dict[str, Any]) -> str:
        """Render CSV report"""
        import csv
        import io

        data = self.prepare_data(analysis_data)

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "Host",
                "IP",
                "OS",
                "Plugin ID",
                "Plugin Name",
                "Severity",
                "Family",
                "Port",
                "Service",
                "Description",
                "Solution",
            ]
        )

        # Write vulnerability data
        for host_summary in data.get("host_summaries", []):
            # Find the corresponding host data
            host_data = None
            for host in data.get("report", {}).get("hosts", []):
                if (
                    host.name == host_summary.ip
                    or host.properties.hostname == host_summary.hostname
                ):
                    host_data = host
                    break

            if host_data:
                for vuln in host_data.vulnerabilities:
                    writer.writerow(
                        [
                            host_summary.hostname,
                            host_summary.ip,
                            host_summary.os,
                            vuln.plugin_id,
                            vuln.plugin_name,
                            vuln.severity,
                            vuln.plugin_family,
                            vuln.port,
                            vuln.service_name,
                            (
                                vuln.description[:200] + "..."
                                if len(vuln.description) > 200
                                else vuln.description
                            ),
                            (
                                vuln.solution[:100] + "..."
                                if len(vuln.solution) > 100
                                else vuln.solution
                            ),
                        ]
                    )

        return output.getvalue()


def create_template_engine(template_dir: str = None) -> TemplateEngine:
    """Create a template engine instance"""
    return TemplateEngine(template_dir)


def render_html_report(analysis_data: Dict[str, Any], template_dir: str = None) -> str:
    """Render HTML vulnerability report"""
    engine = create_template_engine(template_dir)
    template = HTMLReportTemplate(engine)
    return template.render(analysis_data)


def render_pdf_report(analysis_data: Dict[str, Any], template_dir: str = None) -> str:
    """Render PDF vulnerability report"""
    engine = create_template_engine(template_dir)
    template = PDFReportTemplate(engine)
    return template.render(analysis_data)


def render_csv_report(analysis_data: Dict[str, Any]) -> str:
    """Render CSV vulnerability report"""
    engine = create_template_engine()
    template = CSVReportTemplate(engine)
    return template.render(analysis_data)


if __name__ == "__main__":
    # Test the template engine
    import sys
    from src.parser.nessus_parser import parse_nessus_file
    from src.processor.vulnerability_processor import process_nessus_report

    if len(sys.argv) != 2:
        print("Usage: python template_engine.py <nessus_file>")
        sys.exit(1)

    try:
        # Parse and process the file
        report = parse_nessus_file(sys.argv[1])
        analysis_data = process_nessus_report(report)
        analysis_data["report"] = report

        # Test HTML rendering
        html_output = render_html_report(analysis_data)
        print("HTML Report generated successfully")

        # Test CSV rendering
        csv_output = render_csv_report(analysis_data)
        print("CSV Report generated successfully")

        print(f"HTML length: {len(html_output)} characters")
        print(f"CSV length: {len(csv_output)} characters")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
