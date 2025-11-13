"""
CSV Exporter for vISSM
Exports vulnerability reports to CSV format
"""

import os
import csv
from typing import Dict, Any, List
from src.templates.template_engine import render_csv_report


class CSVExporter:
    """Exports vulnerability reports to CSV format"""

    def __init__(self):
        pass

    def export(self, analysis_data: Dict[str, Any], output_path: str) -> str:
        """Export analysis data to CSV file"""
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            # Get the report data
            report = analysis_data.get('report')
            host_summaries = analysis_data.get('host_summaries', [])

            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                writer.writerow([
                    'Host', 'IP', 'OS', 'Plugin ID', 'Plugin Name', 'Severity',
                    'Family', 'Port', 'Service', 'Description', 'Solution', 'CVE'
                ])

                # Write vulnerability data
                for host_summary in host_summaries:
                    # Find the corresponding host data
                    host_data = None
                    if report and hasattr(report, 'hosts'):
                        for host in report.hosts:
                            if host.name == host_summary.ip or host.properties.hostname == host_summary.hostname:
                                host_data = host
                                break

                    if host_data:
                        for vuln in host_data.vulnerabilities:
                            writer.writerow([
                                host_summary.hostname,
                                host_summary.ip,
                                host_summary.os,
                                vuln.plugin_id,
                                vuln.plugin_name,
                                vuln.severity,
                                vuln.plugin_family,
                                vuln.port,
                                vuln.service_name,
                                vuln.description[:500] + '...' if len(vuln.description) > 500 else vuln.description,
                                vuln.solution[:200] + '...' if len(vuln.solution) > 200 else vuln.solution,
                                vuln.cve
                            ])

            return output_path

        except Exception as e:
            raise ValueError(f"Error exporting CSV report: {e}")

    def export_summary(self, analysis_data: Dict[str, Any], output_path: str) -> str:
        """Export summary data to CSV file"""
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            host_summaries = analysis_data.get('host_summaries', [])

            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                writer.writerow([
                    'Host', 'IP', 'OS', 'Total Vulns', 'Critical', 'High',
                    'Medium', 'Low', 'Info', 'Risk Score'
                ])

                # Write host summary data
                for host in host_summaries:
                    writer.writerow([
                        host.hostname,
                        host.ip,
                        host.os,
                        host.total_vulnerabilities,
                        host.critical_vulnerabilities,
                        host.high_vulnerabilities,
                        host.medium_vulnerabilities,
                        host.low_vulnerabilities,
                        host.info_vulnerabilities,
                        f"{host.risk_score:.1f}"
                    ])

            return output_path

        except Exception as e:
            raise ValueError(f"Error exporting CSV summary: {e}")

    def export_to_string(self, analysis_data: Dict[str, Any]) -> str:
        """Export analysis data to CSV string"""
        try:
            return render_csv_report(analysis_data)
        except Exception as e:
            raise ValueError(f"Error generating CSV string: {e}")


def export_csv_report(analysis_data: Dict[str, Any], output_path: str) -> str:
    """Convenience function to export CSV report"""
    exporter = CSVExporter()
    return exporter.export(analysis_data, output_path)


def export_csv_summary(analysis_data: Dict[str, Any], output_path: str) -> str:
    """Convenience function to export CSV summary"""
    exporter = CSVExporter()
    return exporter.export_summary(analysis_data, output_path)


if __name__ == "__main__":
    # Test the CSV exporter
    import sys
    from src.parser.nessus_parser import parse_nessus_file
    from src.processor.vulnerability_processor import process_nessus_report

    if len(sys.argv) != 3:
        print("Usage: python csv_exporter.py <nessus_file> <output_file>")
        sys.exit(1)

    try:
        # Parse and process the file
        report = parse_nessus_file(sys.argv[1])
        analysis_data = process_nessus_report(report)
        analysis_data['report'] = report

        # Export to CSV
        output_path = export_csv_report(analysis_data, sys.argv[2])
        print(f"CSV report exported to: {output_path}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
