"""
STIG (Security Technical Implementation Guide) Mapper
Maps Nessus plugin IDs and CVEs to STIG identifiers and rules
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class STIGFinding:
    """STIG finding information"""

    stig_id: str
    vulnerability_id: str
    rule_id: str
    severity: str  # CAT I, CAT II, CAT III
    group_title: str
    rule_title: str
    discussion: str
    check_text: str
    fix_text: str
    cci_refs: List[str]  # Control Correlation Identifiers
    nist_controls: List[str]


class STIGMapper:
    """Maps vulnerabilities to STIG requirements"""

    def __init__(self):
        self._initialize_mappings()

    def _initialize_mappings(self):
        """Initialize STIG mappings for common Nessus plugins"""
        # Plugin ID to STIG mapping
        self.plugin_to_stig = {
            # Windows STIG mappings
            "10863": {
                "stig_id": "V-1112",
                "rule_id": "SV-52844r1_rule",
                "severity": "CAT II",
                "group_title": "Undeletable Scheduled Tasks",
                "rule_title": "Only administrators responsible for system can have the "
                "Debug programs user right",
                "cci_refs": ["CCI-002235"],
                "nist_controls": ["AC-6(10)"],
            },
            "21643": {
                "stig_id": "V-1114",
                "rule_id": "SV-52847r2_rule",
                "severity": "CAT II",
                "group_title": "SMBv1 Protocol",
                "rule_title": "The Windows SMB client must be configured to always perform "
                "SMB packet signing",
                "cci_refs": ["CCI-000366"],
                "nist_controls": ["CM-6"],
            },
            # SSL/TLS STIG mappings
            "20007": {
                "stig_id": "V-68897",
                "rule_id": "SV-83493r1_rule",
                "severity": "CAT I",
                "group_title": "SSL Version 2 and 3 Protocol Detection",
                "rule_title": "SSL 2.0 and 3.0 must be disabled",
                "cci_refs": ["CCI-001453"],
                "nist_controls": ["AC-17(2)"],
            },
            "42873": {
                "stig_id": "V-68903",
                "rule_id": "SV-83499r2_rule",
                "severity": "CAT II",
                "group_title": "SSL Medium Strength Cipher Suites Supported",
                "rule_title": "SSL/TLS must use FIPS 140-2 approved ciphers",
                "cci_refs": ["CCI-001453"],
                "nist_controls": ["AC-17(2)", "SC-13"],
            },
            # Apache STIG mappings
            "11422": {
                "stig_id": "V-2230",
                "rule_id": "SV-32755r2_rule",
                "severity": "CAT II",
                "group_title": "Apache Version Detection",
                "rule_title": "Apache server version must be hidden",
                "cci_refs": ["CCI-000366"],
                "nist_controls": ["CM-6"],
            },
            # Microsoft Patch Mappings
            "66334": {
                "stig_id": "V-92485",
                "rule_id": "SV-102573r1_rule",
                "severity": "CAT I",
                "group_title": "MS15-034 Remote Code Execution",
                "rule_title": "Security patches must be installed",
                "cci_refs": ["CCI-000366"],
                "nist_controls": ["SI-2"],
            },
            # Weak Password/Authentication
            "10394": {
                "stig_id": "V-1098",
                "rule_id": "SV-52843r2_rule",
                "severity": "CAT II",
                "group_title": "Password Complexity Requirements",
                "rule_title": "Passwords must meet complexity requirements",
                "cci_refs": ["CCI-000192", "CCI-000193", "CCI-000194"],
                "nist_controls": ["IA-5(1)"],
            },
            # Default Credentials
            "11219": {
                "stig_id": "V-15823",
                "rule_id": "SV-16720r1_rule",
                "severity": "CAT I",
                "group_title": "Default Credentials",
                "rule_title": "Default vendor passwords must be changed",
                "cci_refs": ["CCI-000366"],
                "nist_controls": ["IA-5(1)"],
            },
        }

        # CVE to STIG mapping (sample mappings)
        self.cve_to_stig = {
            "CVE-2014-0160": {  # Heartbleed
                "stig_id": "V-68897",
                "severity": "CAT I",
                "nist_controls": ["SC-8", "SC-8(1)"],
            },
            "CVE-2017-0144": {  # EternalBlue
                "stig_id": "V-92485",
                "severity": "CAT I",
                "nist_controls": ["SI-2"],
            },
            "CVE-2021-44228": {  # Log4Shell
                "stig_id": "V-252847",
                "severity": "CAT I",
                "nist_controls": ["SI-2", "SI-10"],
            },
        }

    def get_stig_for_plugin(self, plugin_id: str) -> Optional[STIGFinding]:
        """Get STIG finding for a Nessus plugin ID"""
        mapping = self.plugin_to_stig.get(plugin_id)
        if not mapping:
            return None

        return STIGFinding(
            stig_id=mapping["stig_id"],
            vulnerability_id=mapping["stig_id"],
            rule_id=mapping["rule_id"],
            severity=mapping["severity"],
            group_title=mapping["group_title"],
            rule_title=mapping["rule_title"],
            discussion="",  # Would be populated from STIG XCCDF
            check_text="",  # Would be populated from STIG XCCDF
            fix_text="",  # Would be populated from STIG XCCDF
            cci_refs=mapping["cci_refs"],
            nist_controls=mapping["nist_controls"],
        )

    def get_stig_for_cve(self, cve: str) -> Optional[Dict]:
        """Get STIG information for a CVE"""
        return self.cve_to_stig.get(cve)

    def get_severity_category(self, severity: int) -> str:
        """Convert Nessus severity to STIG CAT level"""
        if severity == 4:  # Critical
            return "CAT I"
        elif severity == 3:  # High
            return "CAT I"
        elif severity == 2:  # Medium
            return "CAT II"
        elif severity == 1:  # Low
            return "CAT III"
        else:  # Info
            return "CAT III"

    def get_all_applicable_stigs(
        self, plugin_ids: List[str], cves: List[str]
    ) -> Dict[str, STIGFinding]:
        """Get all applicable STIG findings for a list of plugins and CVEs"""
        findings = {}

        for plugin_id in plugin_ids:
            stig = self.get_stig_for_plugin(plugin_id)
            if stig:
                findings[plugin_id] = stig

        return findings

    def export_stig_checklist(self, findings: List[STIGFinding]) -> str:
        """Export STIG findings as CKL (checklist) format XML"""
        # This would generate DISA STIG Viewer compatible .ckl file
        # For now, return a simple representation
        output = []
        output.append('<?xml version="1.0" encoding="UTF-8"?>')
        output.append("<CHECKLIST>")
        output.append("  <ASSET>")
        output.append("    <ROLE>None</ROLE>")
        output.append("    <ASSET_TYPE>Computing</ASSET_TYPE>")
        output.append("  </ASSET>")
        output.append("  <STIGS>")
        output.append("    <iSTIG>")
        output.append("      <STIG_INFO>")
        output.append("        <SI_DATA>")
        output.append("          <SID_NAME>version</SID_NAME>")
        output.append("          <SID_DATA>1</SID_DATA>")
        output.append("        </SI_DATA>")
        output.append("      </STIG_INFO>")

        for finding in findings:
            output.append("      <VULN>")
            output.append("        <STIG_DATA>")
            output.append("          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>")
            output.append(
                f"          <ATTRIBUTE_DATA>{finding.stig_id}</ATTRIBUTE_DATA>"
            )
            output.append("        </STIG_DATA>")
            output.append("        <STIG_DATA>")
            output.append("          <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>")
            output.append(
                f"          <ATTRIBUTE_DATA>{finding.severity}</ATTRIBUTE_DATA>"
            )
            output.append("        </STIG_DATA>")
            output.append("        <STIG_DATA>")
            output.append("          <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>")
            output.append(
                f"          <ATTRIBUTE_DATA>{finding.rule_id}</ATTRIBUTE_DATA>"
            )
            output.append("        </STIG_DATA>")
            output.append("        <STATUS>Open</STATUS>")
            output.append("        <FINDING_DETAILS>")
            output.append("Identified via automated Nessus scan")
            output.append("        </FINDING_DETAILS>")
            output.append("      </VULN>")

        output.append("    </iSTIG>")
        output.append("  </STIGS>")
        output.append("</CHECKLIST>")

        return "\n".join(output)


def get_stig_id_for_plugin(plugin_id: str) -> Optional[str]:
    """Convenience function to get STIG ID for a plugin"""
    mapper = STIGMapper()
    stig = mapper.get_stig_for_plugin(plugin_id)
    return stig.stig_id if stig else None
