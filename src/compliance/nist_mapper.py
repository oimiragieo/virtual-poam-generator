"""
NIST 800-53 Control Mapper
Maps CVEs and vulnerabilities to NIST 800-53 security controls
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class NISTControl:
    """NIST 800-53 Control information"""

    control_id: str
    control_name: str
    family: str
    priority: str  # P1, P2, P3
    baseline: List[str]  # LOW, MODERATE, HIGH
    description: str


class NISTMapper:
    """Maps vulnerabilities to NIST 800-53 Rev 5 controls"""

    def __init__(self):
        self._initialize_mappings()

    def _initialize_mappings(self):
        """Initialize NIST 800-53 control mappings"""

        # Control definitions
        self.controls = {
            "AC-2": NISTControl(
                control_id="AC-2",
                control_name="Account Management",
                family="Access Control",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage system accounts",
            ),
            "AC-6": NISTControl(
                control_id="AC-6",
                control_name="Least Privilege",
                family="Access Control",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Employ least privilege principle",
            ),
            "AC-17": NISTControl(
                control_id="AC-17",
                control_name="Remote Access",
                family="Access Control",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Control remote access to the system",
            ),
            "CM-6": NISTControl(
                control_id="CM-6",
                control_name="Configuration Settings",
                family="Configuration Management",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish and document configuration settings",
            ),
            "CM-7": NISTControl(
                control_id="CM-7",
                control_name="Least Functionality",
                family="Configuration Management",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Configure systems to provide only essential capabilities",
            ),
            "IA-5": NISTControl(
                control_id="IA-5",
                control_name="Authenticator Management",
                family="Identification and Authentication",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage system authenticators",
            ),
            "SC-8": NISTControl(
                control_id="SC-8",
                control_name="Transmission Confidentiality and Integrity",
                family="System and Communications Protection",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Protect confidentiality and integrity of transmitted information",
            ),
            "SC-13": NISTControl(
                control_id="SC-13",
                control_name="Cryptographic Protection",
                family="System and Communications Protection",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Use FIPS-validated or NSA-approved cryptography",
            ),
            "SI-2": NISTControl(
                control_id="SI-2",
                control_name="Flaw Remediation",
                family="System and Information Integrity",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Identify, report, and correct system flaws",
            ),
            "SI-10": NISTControl(
                control_id="SI-10",
                control_name="Information Input Validation",
                family="System and Information Integrity",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Check the validity of information inputs",
            ),
        }

        # CVE to NIST control mapping
        self.cve_to_controls = {
            "CVE-2014-0160": ["SC-8", "SC-8(1)", "SC-13"],  # Heartbleed
            "CVE-2017-0144": ["SI-2", "CM-7"],  # EternalBlue/SMBv1
            "CVE-2021-44228": ["SI-2", "SI-10", "CM-7"],  # Log4Shell
            "CVE-2014-6271": ["SI-2", "AC-6"],  # Shellshock
            "CVE-2017-5638": ["SI-2", "SI-10"],  # Apache Struts
        }

        # Vulnerability category to NIST control mapping
        self.category_to_controls = {
            "Missing Patches": ["SI-2"],
            "Weak Encryption": ["SC-8", "SC-13"],
            "Weak Authentication": ["IA-5", "IA-5(1)"],
            "Default Credentials": ["IA-5", "IA-5(1)", "CM-6"],
            "Unnecessary Services": ["CM-7"],
            "Configuration Issues": ["CM-6"],
            "Access Control": ["AC-2", "AC-6"],
            "Remote Access": ["AC-17"],
            "Input Validation": ["SI-10"],
        }

    def get_controls_for_cve(self, cve: str) -> List[str]:
        """Get NIST controls for a specific CVE"""
        return self.cve_to_controls.get(cve, [])

    def get_controls_for_category(self, category: str) -> List[str]:
        """Get NIST controls for a vulnerability category"""
        return self.category_to_controls.get(category, [])

    def get_control_details(self, control_id: str) -> Optional[NISTControl]:
        """Get detailed information about a NIST control"""
        return self.controls.get(control_id)

    def categorize_vulnerability(self, plugin_name: str, description: str) -> str:
        """Categorize vulnerability based on plugin name and description"""
        plugin_lower = plugin_name.lower()
        desc_lower = description.lower()

        if any(
            word in plugin_lower or word in desc_lower
            for word in ["patch", "update", "security update", "kb"]
        ):
            return "Missing Patches"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["ssl", "tls", "cipher", "encryption", "weak"]
        ):
            return "Weak Encryption"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["password", "authentication", "credential"]
        ):
            return "Weak Authentication"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["default password", "default credential"]
        ):
            return "Default Credentials"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["service detection", "unnecessary", "unused"]
        ):
            return "Unnecessary Services"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["configuration", "misconfiguration"]
        ):
            return "Configuration Issues"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["access control", "permission", "privilege"]
        ):
            return "Access Control"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["remote", "rdp", "ssh"]
        ):
            return "Remote Access"
        elif any(
            word in plugin_lower or word in desc_lower
            for word in ["injection", "input", "validation"]
        ):
            return "Input Validation"
        else:
            return "Configuration Issues"  # Default category

    def get_rmf_package_controls(
        self, baseline: str = "MODERATE"
    ) -> Dict[str, NISTControl]:
        """Get all controls for an RMF package baseline"""
        return {
            cid: control
            for cid, control in self.controls.items()
            if baseline in control.baseline
        }

    def map_vulnerability_to_controls(
        self, plugin_name: str, description: str, cves: List[str]
    ) -> List[str]:
        """Map a vulnerability to applicable NIST controls"""
        controls = set()

        # Check CVE mappings
        for cve in cves:
            if cve in self.cve_to_controls:
                controls.update(self.cve_to_controls[cve])

        # Check category mapping
        category = self.categorize_vulnerability(plugin_name, description)
        controls.update(self.category_to_controls.get(category, []))

        # If no specific mapping found, default to SI-2 (Flaw Remediation)
        if not controls:
            controls.add("SI-2")

        return sorted(list(controls))


def get_nist_controls_for_cve(cve: str) -> List[str]:
    """Convenience function to get NIST controls for a CVE"""
    mapper = NISTMapper()
    return mapper.get_controls_for_cve(cve)
