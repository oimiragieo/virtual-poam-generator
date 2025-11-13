"""
Test suite for vISSM
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from parser.nessus_parser import parse_nessus_file, NessusParser
from processor.vulnerability_processor import (
    process_nessus_report,
    VulnerabilityProcessor,
)
from exporters.html_exporter import export_html_report
from exporters.csv_exporter import export_csv_report, export_csv_summary


class TestVISSM(unittest.TestCase):
    """Test cases for vISSM functionality"""

    def setUp(self):
        """Set up test environment"""
        self.test_data_dir = Path(__file__).parent / "fixtures"
        self.test_output_dir = Path(tempfile.mkdtemp())

        # Create test fixtures directory if it doesn't exist
        self.test_data_dir.mkdir(exist_ok=True)

    def test_nessus_parser_import(self):
        """Test that Nessus parser can be imported"""
        from parser.nessus_parser import NessusParser, parse_nessus_file

        self.assertTrue(True)

    def test_vulnerability_processor_import(self):
        """Test that vulnerability processor can be imported"""
        from processor.vulnerability_processor import (
            VulnerabilityProcessor,
            process_nessus_report,
        )

        self.assertTrue(True)

    def test_exporters_import(self):
        """Test that exporters can be imported"""
        from exporters.html_exporter import export_html_report
        from exporters.csv_exporter import export_csv_report, export_csv_summary

        self.assertTrue(True)

    def test_cli_help(self):
        """Test that CLI shows help"""
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), "..", "cli.py"),
                "--help",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("vISSM", result.stdout)

    def test_cli_version(self):
        """Test that CLI shows version"""
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), "..", "cli.py"),
                "--version",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("vISSM v1.0", result.stdout)

    def test_nessus_parser_structure(self):
        """Test Nessus parser data structures"""
        from parser.nessus_parser import (
            NessusReport,
            ReportHost,
            Vulnerability,
            HostProperties,
        )

        # Test data structure creation
        props = HostProperties(
            hostname="test-host",
            ip="192.168.1.1",
            os="Windows 10",
            mac_address="",
            netbios_name="",
            fqdn="",
            scan_start="",
            scan_end="",
        )

        vuln = Vulnerability(
            plugin_id="12345",
            plugin_name="Test Vulnerability",
            plugin_family="Test Family",
            severity=3,
            description="Test description",
            solution="Test solution",
            see_also="",
            cve="CVE-2023-1234",
            cvss_base_score="7.5",
            cvss_vector="",
            port="80",
            protocol="tcp",
            service_name="http",
            plugin_output="",
        )

        host = ReportHost(name="192.168.1.1", properties=props, vulnerabilities=[vuln])

        report = NessusReport(
            policy_name="Test Policy",
            scan_name="Test Scan",
            scan_start="2023-01-01",
            scan_end="2023-01-01",
            hosts=[host],
            total_hosts=1,
            total_vulnerabilities=1,
        )

        self.assertEqual(report.total_hosts, 1)
        self.assertEqual(report.total_vulnerabilities, 1)
        self.assertEqual(host.vulnerabilities[0].severity, 3)

    def test_vulnerability_processor_analysis(self):
        """Test vulnerability processor analysis"""
        from parser.nessus_parser import (
            NessusReport,
            ReportHost,
            Vulnerability,
            HostProperties,
        )

        # Create test data
        props = HostProperties(
            hostname="test-host",
            ip="192.168.1.1",
            os="Windows 10",
            mac_address="",
            netbios_name="",
            fqdn="",
            scan_start="",
            scan_end="",
        )

        vuln1 = Vulnerability(
            plugin_id="12345",
            plugin_name="Critical Vulnerability",
            plugin_family="Critical Family",
            severity=4,  # Critical
            description="Critical test description",
            solution="Critical test solution",
            see_also="",
            cve="CVE-2023-1234",
            cvss_base_score="9.5",
            cvss_vector="",
            port="80",
            protocol="tcp",
            service_name="http",
            plugin_output="",
        )

        vuln2 = Vulnerability(
            plugin_id="12346",
            plugin_name="High Vulnerability",
            plugin_family="High Family",
            severity=3,  # High
            description="High test description",
            solution="High test solution",
            see_also="",
            cve="CVE-2023-1235",
            cvss_base_score="7.5",
            cvss_vector="",
            port="443",
            protocol="tcp",
            service_name="https",
            plugin_output="",
        )

        host = ReportHost(
            name="192.168.1.1", properties=props, vulnerabilities=[vuln1, vuln2]
        )

        report = NessusReport(
            policy_name="Test Policy",
            scan_name="Test Scan",
            scan_start="2023-01-01",
            scan_end="2023-01-01",
            hosts=[host],
            total_hosts=1,
            total_vulnerabilities=2,
        )

        # Process the data
        processor = VulnerabilityProcessor(report)
        results = processor.process()

        # Verify analysis results
        self.assertEqual(results["summary"].total_vulnerabilities, 2)
        self.assertEqual(results["summary"].critical_count, 1)
        self.assertEqual(results["summary"].high_count, 1)
        self.assertEqual(len(results["host_summaries"]), 1)
        self.assertGreater(results["host_summaries"][0].risk_score, 0)

    def test_html_export(self):
        """Test HTML export functionality"""
        from parser.nessus_parser import (
            NessusReport,
            ReportHost,
            Vulnerability,
            HostProperties,
        )

        # Create minimal test data
        props = HostProperties(
            hostname="test-host",
            ip="192.168.1.1",
            os="Windows 10",
            mac_address="",
            netbios_name="",
            fqdn="",
            scan_start="",
            scan_end="",
        )

        vuln = Vulnerability(
            plugin_id="12345",
            plugin_name="Test Vulnerability",
            plugin_family="Test Family",
            severity=2,
            description="Test description",
            solution="Test solution",
            see_also="",
            cve="CVE-2023-1234",
            cvss_base_score="5.0",
            cvss_vector="",
            port="80",
            protocol="tcp",
            service_name="http",
            plugin_output="",
        )

        host = ReportHost(name="192.168.1.1", properties=props, vulnerabilities=[vuln])

        report = NessusReport(
            policy_name="Test Policy",
            scan_name="Test Scan",
            scan_start="2023-01-01",
            scan_end="2023-01-01",
            hosts=[host],
            total_hosts=1,
            total_vulnerabilities=1,
        )

        # Process and export
        analysis_data = process_nessus_report(report)
        analysis_data["report"] = report

        output_file = self.test_output_dir / "test_report.html"
        result_path = export_html_report(analysis_data, str(output_file))

        # Verify file was created
        self.assertTrue(os.path.exists(result_path))
        self.assertGreater(os.path.getsize(result_path), 0)

        # Verify HTML content
        with open(result_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("Vulnerability Assessment Report", content)
            self.assertIn("test-host", content)
            self.assertIn("Test Vulnerability", content)

    def test_csv_export(self):
        """Test CSV export functionality"""
        from parser.nessus_parser import (
            NessusReport,
            ReportHost,
            Vulnerability,
            HostProperties,
        )

        # Create minimal test data
        props = HostProperties(
            hostname="test-host",
            ip="192.168.1.1",
            os="Windows 10",
            mac_address="",
            netbios_name="",
            fqdn="",
            scan_start="",
            scan_end="",
        )

        vuln = Vulnerability(
            plugin_id="12345",
            plugin_name="Test Vulnerability",
            plugin_family="Test Family",
            severity=2,
            description="Test description",
            solution="Test solution",
            see_also="",
            cve="CVE-2023-1234",
            cvss_base_score="5.0",
            cvss_vector="",
            port="80",
            protocol="tcp",
            service_name="http",
            plugin_output="",
        )

        host = ReportHost(name="192.168.1.1", properties=props, vulnerabilities=[vuln])

        report = NessusReport(
            policy_name="Test Policy",
            scan_name="Test Scan",
            scan_start="2023-01-01",
            scan_end="2023-01-01",
            hosts=[host],
            total_hosts=1,
            total_vulnerabilities=1,
        )

        # Process and export
        analysis_data = process_nessus_report(report)
        analysis_data["report"] = report

        output_file = self.test_output_dir / "test_report.csv"
        result_path = export_csv_report(analysis_data, str(output_file))

        # Verify file was created
        self.assertTrue(os.path.exists(result_path))
        self.assertGreater(os.path.getsize(result_path), 0)

        # Verify CSV content
        with open(result_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("Host,IP,OS,Plugin ID", content)
            self.assertIn("test-host", content)
            self.assertIn("12345", content)

    def tearDown(self):
        """Clean up test environment"""
        import shutil

        if self.test_output_dir.exists():
            shutil.rmtree(self.test_output_dir)


if __name__ == "__main__":
    unittest.main()
