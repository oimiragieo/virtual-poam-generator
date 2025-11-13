"""
Nessus XML Parser for KARP Clone
Parses .nessus files and extracts vulnerability data
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class HostProperties:
    """Host properties from Nessus scan"""
    hostname: str
    ip: str
    os: str
    mac_address: str
    netbios_name: str
    fqdn: str
    scan_start: str
    scan_end: str


@dataclass
class Vulnerability:
    """Individual vulnerability finding"""
    plugin_id: str
    plugin_name: str
    plugin_family: str
    severity: int
    description: str
    solution: str
    see_also: str
    cve: str
    cvss_base_score: str
    cvss_vector: str
    port: str
    protocol: str
    service_name: str
    plugin_output: str


@dataclass
class ReportHost:
    """Host with vulnerabilities"""
    name: str
    properties: HostProperties
    vulnerabilities: List[Vulnerability]


@dataclass
class NessusReport:
    """Complete Nessus scan report"""
    policy_name: str
    scan_name: str
    scan_start: str
    scan_end: str
    hosts: List[ReportHost]
    total_hosts: int
    total_vulnerabilities: int


class NessusParser:
    """Parser for Nessus XML files"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tree = None
        self.root = None

    def parse(self) -> NessusReport:
        """Parse the Nessus file and return structured data"""
        try:
            self.tree = ET.parse(self.file_path)
            self.root = self.tree.getroot()

            # Extract policy information
            policy_name = self._extract_policy_name()
            scan_info = self._extract_scan_info()

            # Parse all hosts
            hosts = self._parse_hosts()

            # Calculate totals
            total_vulnerabilities = sum(len(host.vulnerabilities) for host in hosts)

            return NessusReport(
                policy_name=policy_name,
                scan_name=scan_info.get('name', 'Unknown Scan'),
                scan_start=scan_info.get('start', ''),
                scan_end=scan_info.get('end', ''),
                hosts=hosts,
                total_hosts=len(hosts),
                total_vulnerabilities=total_vulnerabilities
            )

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML file: {e}")
        except Exception as e:
            raise ValueError(f"Error parsing Nessus file: {e}")

    def _extract_policy_name(self) -> str:
        """Extract policy name from the file"""
        policy_elem = self.root.find('.//Policy/policyName')
        if policy_elem is not None:
            return policy_elem.text or 'Unknown Policy'
        return 'Unknown Policy'

    def _extract_scan_info(self) -> Dict[str, str]:
        """Extract scan information"""
        info = {}

        # Look for scan start/end times
        start_elem = self.root.find('.//preference[@name="TARGET"]')
        if start_elem is not None:
            info['name'] = start_elem.find('value').text if start_elem.find('value') is not None else 'Unknown'

        return info

    def _parse_hosts(self) -> List[ReportHost]:
        """Parse all ReportHost elements"""
        hosts = []

        for host_elem in self.root.findall('.//ReportHost'):
            host_name = host_elem.get('name', 'Unknown')

            # Parse host properties
            properties = self._parse_host_properties(host_elem)

            # Parse vulnerabilities for this host
            vulnerabilities = self._parse_host_vulnerabilities(host_elem)

            hosts.append(ReportHost(
                name=host_name,
                properties=properties,
                vulnerabilities=vulnerabilities
            ))

        return hosts

    def _parse_host_properties(self, host_elem) -> HostProperties:
        """Parse host properties from ReportHost"""
        # Get IP from host element name attribute first
        host_ip = host_elem.get('name', '')

        props = HostProperties(
            hostname='',
            ip=host_ip,  # Set IP from host element name
            os='',
            mac_address='',
            netbios_name='',
            fqdn='',
            scan_start='',
            scan_end=''
        )

        host_props = host_elem.find('HostProperties')
        if host_props is not None:
            for tag in host_props.findall('tag'):
                name = tag.get('name', '')
                value = tag.text or ''

                if name == 'host-ip':
                    props.ip = value  # Prefer host-ip tag if available
                elif name == 'hostname':
                    props.hostname = value
                elif name == 'operating-system':
                    props.os = value
                elif name == 'mac-address':
                    props.mac_address = value
                elif name == 'netbios-name':
                    props.netbios_name = value
                elif name == 'fqdn':
                    props.fqdn = value
                elif name == 'HOST_START':
                    props.scan_start = value
                elif name == 'HOST_END':
                    props.scan_end = value

        return props

    def _parse_host_vulnerabilities(self, host_elem) -> List[Vulnerability]:
        """Parse vulnerabilities for a specific host"""
        vulnerabilities = []

        for item in host_elem.findall('.//ReportItem'):
            vuln = Vulnerability(
                plugin_id=item.get('pluginID', ''),
                plugin_name=item.get('pluginName', ''),
                plugin_family=item.get('pluginFamily', ''),
                severity=int(item.get('severity', '0')),
                description=self._get_text(item, 'description'),
                solution=self._get_text(item, 'solution'),
                see_also=self._get_text(item, 'see_also'),
                cve=self._get_text(item, 'cve'),
                cvss_base_score=self._get_text(item, 'cvss_base_score'),
                cvss_vector=self._get_text(item, 'cvss_vector'),
                port=item.get('port', ''),
                protocol=item.get('protocol', ''),
                service_name=item.get('svc_name', ''),
                plugin_output=self._get_text(item, 'plugin_output')
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_text(self, element, tag_name: str) -> str:
        """Safely get text content from XML element"""
        elem = element.find(tag_name)
        return elem.text if elem is not None else ''


def parse_nessus_file(file_path: str) -> NessusReport:
    """Convenience function to parse a Nessus file"""
    parser = NessusParser(file_path)
    return parser.parse()


if __name__ == "__main__":
    # Test the parser
    import sys

    if len(sys.argv) != 2:
        print("Usage: python nessus_parser.py <nessus_file>")
        sys.exit(1)

    try:
        report = parse_nessus_file(sys.argv[1])
        print(f"Parsed Nessus report:")
        print(f"  Policy: {report.policy_name}")
        print(f"  Hosts: {report.total_hosts}")
        print(f"  Vulnerabilities: {report.total_vulnerabilities}")

        for host in report.hosts[:3]:  # Show first 3 hosts
            print(f"  Host {host.name}: {len(host.vulnerabilities)} vulnerabilities")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
