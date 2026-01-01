"""
NIST 800-53 Rev 5 Control Mapper
Maps CVEs and vulnerabilities to NIST 800-53 Rev 5 security controls

Enterprise-ready implementation with all 20 control families:
- AC: Access Control
- AT: Awareness and Training
- AU: Audit and Accountability
- CA: Assessment, Authorization, and Monitoring
- CM: Configuration Management
- CP: Contingency Planning
- IA: Identification and Authentication
- IR: Incident Response
- MA: Maintenance
- MP: Media Protection
- PE: Physical and Environmental Protection
- PL: Planning
- PM: Program Management
- PS: Personnel Security
- PT: PII Processing and Transparency
- RA: Risk Assessment
- SA: System and Services Acquisition
- SC: System and Communications Protection
- SI: System and Information Integrity
- SR: Supply Chain Risk Management

Reference: NIST SP 800-53 Rev 5 (September 2020)
https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class NISTControl:
    """NIST 800-53 Rev 5 Control information"""

    control_id: str
    control_name: str
    family: str
    family_id: str
    priority: str  # P1, P2, P3
    baseline: List[str] = field(default_factory=list)  # LOW, MODERATE, HIGH
    description: str = ""
    related_controls: List[str] = field(default_factory=list)


@dataclass
class ControlFamily:
    """NIST 800-53 Rev 5 Control Family"""

    family_id: str
    family_name: str
    description: str
    control_count: int = 0


class NISTMapper:
    """
    Maps vulnerabilities to NIST 800-53 Rev 5 controls.

    Enterprise-ready implementation supporting:
    - All 20 NIST 800-53 Rev 5 control families
    - Comprehensive CVE-to-control mappings
    - Vulnerability category-to-control mappings
    - RMF baseline support (LOW, MODERATE, HIGH)
    """

    def __init__(self):
        self._initialize_control_families()
        self._initialize_controls()
        self._initialize_cve_mappings()
        self._initialize_category_mappings()

    def _initialize_control_families(self):
        """Initialize all 20 NIST 800-53 Rev 5 control families"""
        self.control_families = {
            "AC": ControlFamily(
                family_id="AC",
                family_name="Access Control",
                description="Controls for managing access to system resources",
            ),
            "AT": ControlFamily(
                family_id="AT",
                family_name="Awareness and Training",
                description="Controls for security awareness and training programs",
            ),
            "AU": ControlFamily(
                family_id="AU",
                family_name="Audit and Accountability",
                description="Controls for audit logging and accountability",
            ),
            "CA": ControlFamily(
                family_id="CA",
                family_name="Assessment, Authorization, and Monitoring",
                description="Controls for security assessment and continuous monitoring",
            ),
            "CM": ControlFamily(
                family_id="CM",
                family_name="Configuration Management",
                description="Controls for system configuration management",
            ),
            "CP": ControlFamily(
                family_id="CP",
                family_name="Contingency Planning",
                description="Controls for business continuity and disaster recovery",
            ),
            "IA": ControlFamily(
                family_id="IA",
                family_name="Identification and Authentication",
                description="Controls for user and device identification and authentication",
            ),
            "IR": ControlFamily(
                family_id="IR",
                family_name="Incident Response",
                description="Controls for security incident handling and response",
            ),
            "MA": ControlFamily(
                family_id="MA",
                family_name="Maintenance",
                description="Controls for system maintenance activities",
            ),
            "MP": ControlFamily(
                family_id="MP",
                family_name="Media Protection",
                description="Controls for protecting system media",
            ),
            "PE": ControlFamily(
                family_id="PE",
                family_name="Physical and Environmental Protection",
                description="Controls for physical security and environmental protection",
            ),
            "PL": ControlFamily(
                family_id="PL",
                family_name="Planning",
                description="Controls for security planning activities",
            ),
            "PM": ControlFamily(
                family_id="PM",
                family_name="Program Management",
                description="Controls for information security program management",
            ),
            "PS": ControlFamily(
                family_id="PS",
                family_name="Personnel Security",
                description="Controls for personnel security requirements",
            ),
            "PT": ControlFamily(
                family_id="PT",
                family_name="PII Processing and Transparency",
                description="Controls for personally identifiable information processing",
            ),
            "RA": ControlFamily(
                family_id="RA",
                family_name="Risk Assessment",
                description="Controls for risk assessment and vulnerability management",
            ),
            "SA": ControlFamily(
                family_id="SA",
                family_name="System and Services Acquisition",
                description="Controls for secure system development and acquisition",
            ),
            "SC": ControlFamily(
                family_id="SC",
                family_name="System and Communications Protection",
                description="Controls for system and network security",
            ),
            "SI": ControlFamily(
                family_id="SI",
                family_name="System and Information Integrity",
                description="Controls for system integrity and flaw remediation",
            ),
            "SR": ControlFamily(
                family_id="SR",
                family_name="Supply Chain Risk Management",
                description="Controls for supply chain security",
            ),
        }

    def _initialize_controls(self):
        """Initialize comprehensive NIST 800-53 Rev 5 control definitions"""
        self.controls = {}

        # =====================================================================
        # AC - Access Control Family
        # =====================================================================
        self.controls.update({
            "AC-1": NISTControl(
                control_id="AC-1",
                control_name="Policy and Procedures",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop, document, and disseminate access control policy",
            ),
            "AC-2": NISTControl(
                control_id="AC-2",
                control_name="Account Management",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage system accounts including creation, activation, modification, review, and termination",
                related_controls=["AC-3", "AC-5", "AC-6", "AU-9", "IA-2", "IA-4", "MA-3", "MA-5", "PE-2", "PS-4", "PS-5"],
            ),
            "AC-3": NISTControl(
                control_id="AC-3",
                control_name="Access Enforcement",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Enforce approved authorizations for logical access to information and system resources",
                related_controls=["AC-2", "AC-4", "AC-5", "AC-6", "AC-16", "AC-17", "AC-18", "AC-19", "AC-24", "AU-9", "CM-5", "CM-11", "IA-2", "MA-3", "MA-4", "PE-3", "SC-4"],
            ),
            "AC-4": NISTControl(
                control_id="AC-4",
                control_name="Information Flow Enforcement",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Enforce approved authorizations for controlling information flows within and between systems",
            ),
            "AC-5": NISTControl(
                control_id="AC-5",
                control_name="Separation of Duties",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Separate duties of individuals to prevent malicious activity",
            ),
            "AC-6": NISTControl(
                control_id="AC-6",
                control_name="Least Privilege",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Employ least privilege principle allowing only authorized accesses necessary for assigned tasks",
                related_controls=["AC-2", "AC-3", "AC-5", "CM-5", "CM-11", "PL-2", "PM-12", "SA-8", "SC-38"],
            ),
            "AC-7": NISTControl(
                control_id="AC-7",
                control_name="Unsuccessful Logon Attempts",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Enforce limit on consecutive invalid logon attempts and take protective action",
            ),
            "AC-8": NISTControl(
                control_id="AC-8",
                control_name="System Use Notification",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Display system use notification message before granting access",
            ),
            "AC-10": NISTControl(
                control_id="AC-10",
                control_name="Concurrent Session Control",
                family="Access Control",
                family_id="AC",
                priority="P2",
                baseline=["HIGH"],
                description="Limit the number of concurrent sessions for each account",
            ),
            "AC-11": NISTControl(
                control_id="AC-11",
                control_name="Device Lock",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Prevent further access by initiating device lock after period of inactivity",
            ),
            "AC-12": NISTControl(
                control_id="AC-12",
                control_name="Session Termination",
                family="Access Control",
                family_id="AC",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Automatically terminate user session after conditions or time period",
            ),
            "AC-14": NISTControl(
                control_id="AC-14",
                control_name="Permitted Actions Without Identification or Authentication",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Identify actions permitted without identification or authentication",
            ),
            "AC-17": NISTControl(
                control_id="AC-17",
                control_name="Remote Access",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish usage restrictions and configuration requirements for remote access",
                related_controls=["AC-2", "AC-3", "AC-4", "AC-18", "AC-19", "AC-20", "CA-3", "CM-10", "IA-2", "IA-3", "IA-8", "MA-4", "PE-17", "PL-2", "SC-10", "SC-12", "SC-13", "SI-4"],
            ),
            "AC-18": NISTControl(
                control_id="AC-18",
                control_name="Wireless Access",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish usage restrictions and configuration requirements for wireless access",
            ),
            "AC-19": NISTControl(
                control_id="AC-19",
                control_name="Access Control for Mobile Devices",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish usage restrictions and configuration requirements for mobile devices",
            ),
            "AC-20": NISTControl(
                control_id="AC-20",
                control_name="Use of External Systems",
                family="Access Control",
                family_id="AC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish terms and conditions for use of external systems",
            ),
            "AC-21": NISTControl(
                control_id="AC-21",
                control_name="Information Sharing",
                family="Access Control",
                family_id="AC",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Facilitate information sharing by enabling authorized users to determine access",
            ),
            "AC-22": NISTControl(
                control_id="AC-22",
                control_name="Publicly Accessible Content",
                family="Access Control",
                family_id="AC",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Designate individuals authorized to post publicly accessible content",
            ),
        })

        # =====================================================================
        # AT - Awareness and Training Family
        # =====================================================================
        self.controls.update({
            "AT-1": NISTControl(
                control_id="AT-1",
                control_name="Policy and Procedures",
                family="Awareness and Training",
                family_id="AT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop security awareness and training policy",
            ),
            "AT-2": NISTControl(
                control_id="AT-2",
                control_name="Literacy Training and Awareness",
                family="Awareness and Training",
                family_id="AT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide security and privacy literacy training to users",
            ),
            "AT-3": NISTControl(
                control_id="AT-3",
                control_name="Role-Based Training",
                family="Awareness and Training",
                family_id="AT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide role-based security and privacy training",
            ),
            "AT-4": NISTControl(
                control_id="AT-4",
                control_name="Training Records",
                family="Awareness and Training",
                family_id="AT",
                priority="P3",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Document and monitor individual training activities",
            ),
        })

        # =====================================================================
        # AU - Audit and Accountability Family
        # =====================================================================
        self.controls.update({
            "AU-1": NISTControl(
                control_id="AU-1",
                control_name="Policy and Procedures",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop audit and accountability policy",
            ),
            "AU-2": NISTControl(
                control_id="AU-2",
                control_name="Event Logging",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Identify event types for logging within the system",
                related_controls=["AC-2", "AC-3", "AC-6", "AC-7", "AC-8", "AC-16", "AU-3", "AU-4", "AU-5", "AU-6", "AU-7", "AU-11", "AU-12", "CM-3", "CM-5", "MA-4", "MP-4", "PE-3", "PM-21", "PT-2", "RA-8", "SA-8", "SC-7", "SC-18", "SI-3", "SI-4", "SI-7", "SI-10"],
            ),
            "AU-3": NISTControl(
                control_id="AU-3",
                control_name="Content of Audit Records",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Ensure audit records contain information to establish what, when, where, source, outcome, and identity",
            ),
            "AU-4": NISTControl(
                control_id="AU-4",
                control_name="Audit Log Storage Capacity",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Allocate audit log storage capacity to accommodate log requirements",
            ),
            "AU-5": NISTControl(
                control_id="AU-5",
                control_name="Response to Audit Logging Process Failures",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Alert personnel on audit logging process failures",
            ),
            "AU-6": NISTControl(
                control_id="AU-6",
                control_name="Audit Record Review, Analysis, and Reporting",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Review and analyze system audit records for indications of inappropriate activity",
                related_controls=["AC-2", "AC-3", "AC-5", "AC-6", "AC-7", "AC-17", "AU-7", "AU-16", "CA-2", "CA-7", "IA-3", "IR-5", "IR-6", "MA-4", "PE-3", "PE-6", "RA-5", "SA-8", "SC-7", "SI-3", "SI-4", "SI-7"],
            ),
            "AU-7": NISTControl(
                control_id="AU-7",
                control_name="Audit Record Reduction and Report Generation",
                family="Audit and Accountability",
                family_id="AU",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Provide audit record reduction and report generation capability",
            ),
            "AU-8": NISTControl(
                control_id="AU-8",
                control_name="Time Stamps",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Use internal system clocks to generate time stamps for audit records",
            ),
            "AU-9": NISTControl(
                control_id="AU-9",
                control_name="Protection of Audit Information",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Protect audit information and tools from unauthorized access and modification",
                related_controls=["AC-3", "AC-6", "AU-6", "AU-11", "AU-14", "AU-15", "MP-2", "MP-4", "PE-2", "PE-3", "PE-6", "SA-8", "SC-8", "SI-4"],
            ),
            "AU-10": NISTControl(
                control_id="AU-10",
                control_name="Non-repudiation",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["HIGH"],
                description="Provide irrefutable evidence that an individual performed specific actions",
            ),
            "AU-11": NISTControl(
                control_id="AU-11",
                control_name="Audit Record Retention",
                family="Audit and Accountability",
                family_id="AU",
                priority="P3",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Retain audit records for defined time period to support investigations",
            ),
            "AU-12": NISTControl(
                control_id="AU-12",
                control_name="Audit Record Generation",
                family="Audit and Accountability",
                family_id="AU",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide audit record generation capability for defined event types",
            ),
        })

        # =====================================================================
        # CA - Assessment, Authorization, and Monitoring Family
        # =====================================================================
        self.controls.update({
            "CA-1": NISTControl(
                control_id="CA-1",
                control_name="Policy and Procedures",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop assessment, authorization, and monitoring policy",
            ),
            "CA-2": NISTControl(
                control_id="CA-2",
                control_name="Control Assessments",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop control assessment plan and assess controls in the system",
                related_controls=["CA-5", "CA-6", "CA-7", "PM-9", "RA-5", "SA-11", "SI-4"],
            ),
            "CA-3": NISTControl(
                control_id="CA-3",
                control_name="Information Exchange",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Approve and manage exchange of information between systems",
            ),
            "CA-5": NISTControl(
                control_id="CA-5",
                control_name="Plan of Action and Milestones",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P3",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop plan of action and milestones for planned remedial actions",
                related_controls=["CA-2", "CA-7", "PM-4", "PM-9", "RA-7", "SI-2", "SI-12"],
            ),
            "CA-6": NISTControl(
                control_id="CA-6",
                control_name="Authorization",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Assign authorizing official and ensure system authorization before operations",
            ),
            "CA-7": NISTControl(
                control_id="CA-7",
                control_name="Continuous Monitoring",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop continuous monitoring strategy and implement continuous monitoring program",
                related_controls=["AC-2", "AC-6", "AC-17", "AT-4", "AU-6", "AU-13", "CA-2", "CA-5", "CA-6", "CM-3", "CM-4", "IA-5", "PE-3", "PE-6", "PE-14", "PE-16", "PL-2", "PM-4", "PM-6", "PM-9", "PM-10", "PM-12", "PM-14", "PM-23", "PM-28", "PM-31", "RA-3", "RA-5", "RA-7", "SA-8", "SA-9", "SA-11", "SC-5", "SC-7", "SC-18", "SC-38", "SC-43", "SI-3", "SI-4", "SI-12", "SR-2", "SR-4"],
            ),
            "CA-8": NISTControl(
                control_id="CA-8",
                control_name="Penetration Testing",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P2",
                baseline=["HIGH"],
                description="Conduct penetration testing at organization-defined frequency",
            ),
            "CA-9": NISTControl(
                control_id="CA-9",
                control_name="Internal System Connections",
                family="Assessment, Authorization, and Monitoring",
                family_id="CA",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Authorize internal connections of system components",
            ),
        })

        # =====================================================================
        # CM - Configuration Management Family
        # =====================================================================
        self.controls.update({
            "CM-1": NISTControl(
                control_id="CM-1",
                control_name="Policy and Procedures",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop configuration management policy",
            ),
            "CM-2": NISTControl(
                control_id="CM-2",
                control_name="Baseline Configuration",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop and maintain current baseline configuration under configuration control",
                related_controls=["AC-19", "AU-6", "CA-9", "CM-1", "CM-3", "CM-5", "CM-6", "CM-8", "CM-9", "CP-9", "CP-10", "CP-12", "MA-4", "PL-8", "PM-5", "SA-8", "SA-10", "SA-15", "SC-18"],
            ),
            "CM-3": NISTControl(
                control_id="CM-3",
                control_name="Configuration Change Control",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Determine and approve configuration-controlled changes with reviews",
                related_controls=["CA-7", "CM-2", "CM-4", "CM-5", "CM-6", "CM-9", "CM-11", "IA-3", "MA-2", "PE-16", "PT-6", "RA-8", "SA-8", "SA-10", "SC-28", "SC-34", "SC-37", "SI-2", "SI-3", "SI-4", "SI-7", "SI-10", "SR-11"],
            ),
            "CM-4": NISTControl(
                control_id="CM-4",
                control_name="Impact Analyses",
                family="Configuration Management",
                family_id="CM",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Analyze changes to determine potential security and privacy impacts",
            ),
            "CM-5": NISTControl(
                control_id="CM-5",
                control_name="Access Restrictions for Change",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Define and enforce access restrictions for changes to the system",
            ),
            "CM-6": NISTControl(
                control_id="CM-6",
                control_name="Configuration Settings",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish and document configuration settings using secure configurations",
                related_controls=["AC-3", "AC-19", "AU-2", "AU-6", "CA-7", "CA-9", "CM-2", "CM-3", "CM-5", "CM-7", "CM-11", "CP-7", "CP-9", "CP-10", "IA-3", "IA-5", "PL-8", "PL-9", "RA-5", "SA-4", "SA-5", "SA-8", "SA-9", "SC-18", "SC-28", "SC-43", "SI-2", "SI-4", "SI-6"],
            ),
            "CM-7": NISTControl(
                control_id="CM-7",
                control_name="Least Functionality",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Configure systems to provide only essential capabilities and restrict functions, ports, protocols, and services",
                related_controls=["AC-3", "AC-4", "CM-2", "CM-5", "CM-6", "CM-11", "RA-5", "SA-4", "SA-5", "SA-8", "SA-9", "SA-15", "SC-7", "SC-37", "SI-4"],
            ),
            "CM-8": NISTControl(
                control_id="CM-8",
                control_name="System Component Inventory",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop and document inventory of system components",
                related_controls=["CM-2", "CM-7", "CM-9", "CM-10", "CM-11", "CM-13", "CP-2", "CP-9", "MA-2", "MA-6", "PE-20", "PL-9", "PM-5", "RA-9", "SA-4", "SA-5", "SI-2", "SR-4"],
            ),
            "CM-9": NISTControl(
                control_id="CM-9",
                control_name="Configuration Management Plan",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Develop and implement configuration management plan",
            ),
            "CM-10": NISTControl(
                control_id="CM-10",
                control_name="Software Usage Restrictions",
                family="Configuration Management",
                family_id="CM",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Use software in accordance with contract agreements and copyright laws",
            ),
            "CM-11": NISTControl(
                control_id="CM-11",
                control_name="User-Installed Software",
                family="Configuration Management",
                family_id="CM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish policies governing installation of software by users",
            ),
        })

        # =====================================================================
        # CP - Contingency Planning Family
        # =====================================================================
        self.controls.update({
            "CP-1": NISTControl(
                control_id="CP-1",
                control_name="Policy and Procedures",
                family="Contingency Planning",
                family_id="CP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop contingency planning policy",
            ),
            "CP-2": NISTControl(
                control_id="CP-2",
                control_name="Contingency Plan",
                family="Contingency Planning",
                family_id="CP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop contingency plan addressing roles, responsibilities, and recovery objectives",
            ),
            "CP-3": NISTControl(
                control_id="CP-3",
                control_name="Contingency Training",
                family="Contingency Planning",
                family_id="CP",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide contingency training to system users",
            ),
            "CP-4": NISTControl(
                control_id="CP-4",
                control_name="Contingency Plan Testing",
                family="Contingency Planning",
                family_id="CP",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Test contingency plan to determine effectiveness",
            ),
            "CP-6": NISTControl(
                control_id="CP-6",
                control_name="Alternate Storage Site",
                family="Contingency Planning",
                family_id="CP",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Establish alternate storage site for backup information",
            ),
            "CP-7": NISTControl(
                control_id="CP-7",
                control_name="Alternate Processing Site",
                family="Contingency Planning",
                family_id="CP",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Establish alternate processing site for operations transfer",
            ),
            "CP-8": NISTControl(
                control_id="CP-8",
                control_name="Telecommunications Services",
                family="Contingency Planning",
                family_id="CP",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Establish alternate telecommunications services",
            ),
            "CP-9": NISTControl(
                control_id="CP-9",
                control_name="System Backup",
                family="Contingency Planning",
                family_id="CP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Conduct backups of user-level and system-level information",
            ),
            "CP-10": NISTControl(
                control_id="CP-10",
                control_name="System Recovery and Reconstitution",
                family="Contingency Planning",
                family_id="CP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide for recovery and reconstitution of system to known state",
            ),
        })

        # =====================================================================
        # IA - Identification and Authentication Family
        # =====================================================================
        self.controls.update({
            "IA-1": NISTControl(
                control_id="IA-1",
                control_name="Policy and Procedures",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop identification and authentication policy",
            ),
            "IA-2": NISTControl(
                control_id="IA-2",
                control_name="Identification and Authentication (Organizational Users)",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Uniquely identify and authenticate organizational users",
                related_controls=["AC-2", "AC-3", "AC-4", "AC-14", "AC-17", "AC-18", "AU-1", "AU-6", "IA-4", "IA-5", "IA-8", "MA-4", "MA-5", "PE-2", "PL-4", "SA-4", "SA-8"],
            ),
            "IA-3": NISTControl(
                control_id="IA-3",
                control_name="Device Identification and Authentication",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Uniquely identify and authenticate devices before connection",
            ),
            "IA-4": NISTControl(
                control_id="IA-4",
                control_name="Identifier Management",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage system identifiers by receiving authorization and ensuring uniqueness",
            ),
            "IA-5": NISTControl(
                control_id="IA-5",
                control_name="Authenticator Management",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage system authenticators by verifying identity and ensuring sufficient strength",
                related_controls=["AC-3", "AC-6", "CM-6", "IA-2", "IA-4", "IA-7", "IA-8", "IA-9", "MA-4", "PE-2", "PL-4", "SC-12", "SC-13"],
            ),
            "IA-6": NISTControl(
                control_id="IA-6",
                control_name="Authentication Feedback",
                family="Identification and Authentication",
                family_id="IA",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Obscure feedback of authentication information during authentication",
            ),
            "IA-7": NISTControl(
                control_id="IA-7",
                control_name="Cryptographic Module Authentication",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Implement mechanisms for authentication to cryptographic modules",
            ),
            "IA-8": NISTControl(
                control_id="IA-8",
                control_name="Identification and Authentication (Non-Organizational Users)",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Uniquely identify and authenticate non-organizational users",
            ),
            "IA-11": NISTControl(
                control_id="IA-11",
                control_name="Re-Authentication",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Require users to re-authenticate when defined circumstances occur",
            ),
            "IA-12": NISTControl(
                control_id="IA-12",
                control_name="Identity Proofing",
                family="Identification and Authentication",
                family_id="IA",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Identity proof users before issuing credentials or accounts",
            ),
        })

        # =====================================================================
        # IR - Incident Response Family
        # =====================================================================
        self.controls.update({
            "IR-1": NISTControl(
                control_id="IR-1",
                control_name="Policy and Procedures",
                family="Incident Response",
                family_id="IR",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop incident response policy",
            ),
            "IR-2": NISTControl(
                control_id="IR-2",
                control_name="Incident Response Training",
                family="Incident Response",
                family_id="IR",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide incident response training to system users",
            ),
            "IR-3": NISTControl(
                control_id="IR-3",
                control_name="Incident Response Testing",
                family="Incident Response",
                family_id="IR",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Test incident response capability to determine effectiveness",
            ),
            "IR-4": NISTControl(
                control_id="IR-4",
                control_name="Incident Handling",
                family="Incident Response",
                family_id="IR",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Implement incident handling capability for security incidents",
                related_controls=["AC-19", "AU-6", "AU-7", "CM-6", "CP-2", "CP-4", "IR-2", "IR-3", "IR-5", "IR-6", "IR-8", "PE-6", "PL-2", "PM-12", "SA-8", "SC-5", "SC-7", "SI-3", "SI-4", "SI-7"],
            ),
            "IR-5": NISTControl(
                control_id="IR-5",
                control_name="Incident Monitoring",
                family="Incident Response",
                family_id="IR",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Track and document system security incidents",
            ),
            "IR-6": NISTControl(
                control_id="IR-6",
                control_name="Incident Reporting",
                family="Incident Response",
                family_id="IR",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Require personnel to report suspected security incidents",
            ),
            "IR-7": NISTControl(
                control_id="IR-7",
                control_name="Incident Response Assistance",
                family="Incident Response",
                family_id="IR",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide incident response support resource to system users",
            ),
            "IR-8": NISTControl(
                control_id="IR-8",
                control_name="Incident Response Plan",
                family="Incident Response",
                family_id="IR",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop incident response plan providing roadmap for implementation",
            ),
        })

        # =====================================================================
        # MA - Maintenance Family
        # =====================================================================
        self.controls.update({
            "MA-1": NISTControl(
                control_id="MA-1",
                control_name="Policy and Procedures",
                family="Maintenance",
                family_id="MA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop maintenance policy",
            ),
            "MA-2": NISTControl(
                control_id="MA-2",
                control_name="Controlled Maintenance",
                family="Maintenance",
                family_id="MA",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Schedule, document, and review records of maintenance and repair",
            ),
            "MA-3": NISTControl(
                control_id="MA-3",
                control_name="Maintenance Tools",
                family="Maintenance",
                family_id="MA",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Approve, control, and monitor maintenance tools",
            ),
            "MA-4": NISTControl(
                control_id="MA-4",
                control_name="Nonlocal Maintenance",
                family="Maintenance",
                family_id="MA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Approve and monitor nonlocal maintenance and diagnostic activities",
            ),
            "MA-5": NISTControl(
                control_id="MA-5",
                control_name="Maintenance Personnel",
                family="Maintenance",
                family_id="MA",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish process for maintenance personnel authorization",
            ),
            "MA-6": NISTControl(
                control_id="MA-6",
                control_name="Timely Maintenance",
                family="Maintenance",
                family_id="MA",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Obtain maintenance support within defined time period of failure",
            ),
        })

        # =====================================================================
        # MP - Media Protection Family
        # =====================================================================
        self.controls.update({
            "MP-1": NISTControl(
                control_id="MP-1",
                control_name="Policy and Procedures",
                family="Media Protection",
                family_id="MP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop media protection policy",
            ),
            "MP-2": NISTControl(
                control_id="MP-2",
                control_name="Media Access",
                family="Media Protection",
                family_id="MP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Restrict access to digital and non-digital media",
            ),
            "MP-3": NISTControl(
                control_id="MP-3",
                control_name="Media Marking",
                family="Media Protection",
                family_id="MP",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Mark system media indicating distribution limitations",
            ),
            "MP-4": NISTControl(
                control_id="MP-4",
                control_name="Media Storage",
                family="Media Protection",
                family_id="MP",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Physically control and securely store system media",
            ),
            "MP-5": NISTControl(
                control_id="MP-5",
                control_name="Media Transport",
                family="Media Protection",
                family_id="MP",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Protect and control system media during transport",
            ),
            "MP-6": NISTControl(
                control_id="MP-6",
                control_name="Media Sanitization",
                family="Media Protection",
                family_id="MP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Sanitize system media prior to disposal, release, or reuse",
            ),
            "MP-7": NISTControl(
                control_id="MP-7",
                control_name="Media Use",
                family="Media Protection",
                family_id="MP",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Restrict or prohibit use of defined types of system media",
            ),
        })

        # =====================================================================
        # PE - Physical and Environmental Protection Family
        # =====================================================================
        self.controls.update({
            "PE-1": NISTControl(
                control_id="PE-1",
                control_name="Policy and Procedures",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop physical and environmental protection policy",
            ),
            "PE-2": NISTControl(
                control_id="PE-2",
                control_name="Physical Access Authorizations",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop and maintain list of individuals with authorized facility access",
            ),
            "PE-3": NISTControl(
                control_id="PE-3",
                control_name="Physical Access Control",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Enforce physical access authorizations at entry and exit points",
            ),
            "PE-4": NISTControl(
                control_id="PE-4",
                control_name="Access Control for Transmission",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Control physical access to system transmission lines",
            ),
            "PE-5": NISTControl(
                control_id="PE-5",
                control_name="Access Control for Output Devices",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Control physical access to output devices",
            ),
            "PE-6": NISTControl(
                control_id="PE-6",
                control_name="Monitoring Physical Access",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Monitor physical access to detect and respond to incidents",
            ),
            "PE-8": NISTControl(
                control_id="PE-8",
                control_name="Visitor Access Records",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P3",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Maintain visitor access records to the facility",
            ),
            "PE-9": NISTControl(
                control_id="PE-9",
                control_name="Power Equipment and Cabling",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Protect power equipment and cabling from damage",
            ),
            "PE-10": NISTControl(
                control_id="PE-10",
                control_name="Emergency Shutoff",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Provide capability to shut off power to system in emergencies",
            ),
            "PE-11": NISTControl(
                control_id="PE-11",
                control_name="Emergency Power",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Provide uninterruptible power supply for orderly shutdown",
            ),
            "PE-12": NISTControl(
                control_id="PE-12",
                control_name="Emergency Lighting",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Employ and maintain automatic emergency lighting",
            ),
            "PE-13": NISTControl(
                control_id="PE-13",
                control_name="Fire Protection",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Employ and maintain fire detection and suppression systems",
            ),
            "PE-14": NISTControl(
                control_id="PE-14",
                control_name="Environmental Controls",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Maintain temperature and humidity levels within facility",
            ),
            "PE-15": NISTControl(
                control_id="PE-15",
                control_name="Water Damage Protection",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Protect system from damage from water leakage",
            ),
            "PE-16": NISTControl(
                control_id="PE-16",
                control_name="Delivery and Removal",
                family="Physical and Environmental Protection",
                family_id="PE",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Authorize, monitor, and control entry and exit of system components",
            ),
        })

        # =====================================================================
        # PL - Planning Family
        # =====================================================================
        self.controls.update({
            "PL-1": NISTControl(
                control_id="PL-1",
                control_name="Policy and Procedures",
                family="Planning",
                family_id="PL",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop planning policy",
            ),
            "PL-2": NISTControl(
                control_id="PL-2",
                control_name="System Security and Privacy Plans",
                family="Planning",
                family_id="PL",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop security and privacy plans for the system",
            ),
            "PL-4": NISTControl(
                control_id="PL-4",
                control_name="Rules of Behavior",
                family="Planning",
                family_id="PL",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish rules describing responsibilities and expected behavior",
            ),
            "PL-8": NISTControl(
                control_id="PL-8",
                control_name="Security and Privacy Architectures",
                family="Planning",
                family_id="PL",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Develop security and privacy architectures for the system",
            ),
            "PL-10": NISTControl(
                control_id="PL-10",
                control_name="Baseline Selection",
                family="Planning",
                family_id="PL",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Select control baseline for the system",
            ),
            "PL-11": NISTControl(
                control_id="PL-11",
                control_name="Baseline Tailoring",
                family="Planning",
                family_id="PL",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Tailor control baseline for the system",
            ),
        })

        # =====================================================================
        # PM - Program Management Family
        # =====================================================================
        self.controls.update({
            "PM-1": NISTControl(
                control_id="PM-1",
                control_name="Information Security Program Plan",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop organization-wide information security program plan",
            ),
            "PM-2": NISTControl(
                control_id="PM-2",
                control_name="Information Security Program Leadership Role",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Appoint senior information security officer",
            ),
            "PM-3": NISTControl(
                control_id="PM-3",
                control_name="Information Security and Privacy Resources",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Include resources for security and privacy in capital planning",
            ),
            "PM-4": NISTControl(
                control_id="PM-4",
                control_name="Plan of Action and Milestones Process",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Implement process for plan of action and milestones",
            ),
            "PM-5": NISTControl(
                control_id="PM-5",
                control_name="System Inventory",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop and maintain inventory of organizational systems",
            ),
            "PM-6": NISTControl(
                control_id="PM-6",
                control_name="Measures of Performance",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop, monitor, and report on security and privacy measures",
            ),
            "PM-9": NISTControl(
                control_id="PM-9",
                control_name="Risk Management Strategy",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop comprehensive strategy to manage risk",
            ),
            "PM-10": NISTControl(
                control_id="PM-10",
                control_name="Authorization Process",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage authorization process for organizational systems",
            ),
            "PM-11": NISTControl(
                control_id="PM-11",
                control_name="Mission and Business Process Definition",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Define mission and business processes with security considerations",
            ),
            "PM-12": NISTControl(
                control_id="PM-12",
                control_name="Insider Threat Program",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Implement insider threat program",
            ),
            "PM-14": NISTControl(
                control_id="PM-14",
                control_name="Testing, Training, and Monitoring",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Implement testing, training, and monitoring process",
            ),
            "PM-16": NISTControl(
                control_id="PM-16",
                control_name="Threat Awareness Program",
                family="Program Management",
                family_id="PM",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Implement threat awareness program",
            ),
        })

        # =====================================================================
        # PS - Personnel Security Family
        # =====================================================================
        self.controls.update({
            "PS-1": NISTControl(
                control_id="PS-1",
                control_name="Policy and Procedures",
                family="Personnel Security",
                family_id="PS",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop personnel security policy",
            ),
            "PS-2": NISTControl(
                control_id="PS-2",
                control_name="Position Risk Designation",
                family="Personnel Security",
                family_id="PS",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Assign risk designation to all organizational positions",
            ),
            "PS-3": NISTControl(
                control_id="PS-3",
                control_name="Personnel Screening",
                family="Personnel Security",
                family_id="PS",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Screen individuals prior to authorizing access",
            ),
            "PS-4": NISTControl(
                control_id="PS-4",
                control_name="Personnel Termination",
                family="Personnel Security",
                family_id="PS",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Upon termination, terminate access and retrieve property",
            ),
            "PS-5": NISTControl(
                control_id="PS-5",
                control_name="Personnel Transfer",
                family="Personnel Security",
                family_id="PS",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Review access authorizations when individuals are transferred",
            ),
            "PS-6": NISTControl(
                control_id="PS-6",
                control_name="Access Agreements",
                family="Personnel Security",
                family_id="PS",
                priority="P3",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop and document access agreements for systems",
            ),
            "PS-7": NISTControl(
                control_id="PS-7",
                control_name="External Personnel Security",
                family="Personnel Security",
                family_id="PS",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish personnel security requirements for external providers",
            ),
            "PS-8": NISTControl(
                control_id="PS-8",
                control_name="Personnel Sanctions",
                family="Personnel Security",
                family_id="PS",
                priority="P3",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Employ formal sanctions process for personnel violations",
            ),
        })

        # =====================================================================
        # PT - PII Processing and Transparency Family
        # =====================================================================
        self.controls.update({
            "PT-1": NISTControl(
                control_id="PT-1",
                control_name="Policy and Procedures",
                family="PII Processing and Transparency",
                family_id="PT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop PII processing and transparency policy",
            ),
            "PT-2": NISTControl(
                control_id="PT-2",
                control_name="Authority to Process PII",
                family="PII Processing and Transparency",
                family_id="PT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Determine and document legal authority for PII processing",
            ),
            "PT-3": NISTControl(
                control_id="PT-3",
                control_name="PII Processing Purposes",
                family="PII Processing and Transparency",
                family_id="PT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Identify and document purpose for processing PII",
            ),
            "PT-4": NISTControl(
                control_id="PT-4",
                control_name="Consent",
                family="PII Processing and Transparency",
                family_id="PT",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Implement mechanisms for individuals to authorize PII processing",
            ),
            "PT-5": NISTControl(
                control_id="PT-5",
                control_name="Privacy Notice",
                family="PII Processing and Transparency",
                family_id="PT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide notice to individuals about PII processing",
            ),
            "PT-6": NISTControl(
                control_id="PT-6",
                control_name="System of Records Notice",
                family="PII Processing and Transparency",
                family_id="PT",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Publish System of Records Notice for Privacy Act requirements",
            ),
            "PT-7": NISTControl(
                control_id="PT-7",
                control_name="Specific Categories of PII",
                family="PII Processing and Transparency",
                family_id="PT",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Apply controls for specific categories of PII",
            ),
        })

        # =====================================================================
        # RA - Risk Assessment Family
        # =====================================================================
        self.controls.update({
            "RA-1": NISTControl(
                control_id="RA-1",
                control_name="Policy and Procedures",
                family="Risk Assessment",
                family_id="RA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop risk assessment policy",
            ),
            "RA-2": NISTControl(
                control_id="RA-2",
                control_name="Security Categorization",
                family="Risk Assessment",
                family_id="RA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Categorize system and information per FIPS 199",
            ),
            "RA-3": NISTControl(
                control_id="RA-3",
                control_name="Risk Assessment",
                family="Risk Assessment",
                family_id="RA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Conduct risk assessment including likelihood and magnitude of harm",
                related_controls=["CA-3", "CA-6", "PM-9", "PM-28", "RA-2", "SA-9", "SC-38", "SI-12"],
            ),
            "RA-5": NISTControl(
                control_id="RA-5",
                control_name="Vulnerability Monitoring and Scanning",
                family="Risk Assessment",
                family_id="RA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Monitor and scan for vulnerabilities in the system and applications",
                related_controls=["CA-2", "CA-7", "CA-8", "CM-4", "CM-6", "CM-8", "RA-3", "SA-11", "SA-15", "SC-38", "SI-2", "SI-3", "SI-4", "SI-7", "SR-6"],
            ),
            "RA-7": NISTControl(
                control_id="RA-7",
                control_name="Risk Response",
                family="Risk Assessment",
                family_id="RA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Respond to findings from assessments, monitoring, and audits",
            ),
            "RA-9": NISTControl(
                control_id="RA-9",
                control_name="Criticality Analysis",
                family="Risk Assessment",
                family_id="RA",
                priority="P1",
                baseline=["HIGH"],
                description="Identify critical system components and functions",
            ),
            "RA-10": NISTControl(
                control_id="RA-10",
                control_name="Threat Hunting",
                family="Risk Assessment",
                family_id="RA",
                priority="P2",
                baseline=["HIGH"],
                description="Establish threat hunting capability for indicators of compromise",
            ),
        })

        # =====================================================================
        # SA - System and Services Acquisition Family
        # =====================================================================
        self.controls.update({
            "SA-1": NISTControl(
                control_id="SA-1",
                control_name="Policy and Procedures",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop system and services acquisition policy",
            ),
            "SA-2": NISTControl(
                control_id="SA-2",
                control_name="Allocation of Resources",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Determine security requirements and allocate resources",
            ),
            "SA-3": NISTControl(
                control_id="SA-3",
                control_name="System Development Life Cycle",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage system using SDLC incorporating security",
            ),
            "SA-4": NISTControl(
                control_id="SA-4",
                control_name="Acquisition Process",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Include security requirements in acquisition contracts",
            ),
            "SA-5": NISTControl(
                control_id="SA-5",
                control_name="System Documentation",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Obtain and maintain system documentation",
            ),
            "SA-8": NISTControl(
                control_id="SA-8",
                control_name="Security and Privacy Engineering Principles",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Apply security and privacy engineering principles",
            ),
            "SA-9": NISTControl(
                control_id="SA-9",
                control_name="External System Services",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Require external service providers comply with security requirements",
            ),
            "SA-10": NISTControl(
                control_id="SA-10",
                control_name="Developer Configuration Management",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Require developer configuration management during development",
            ),
            "SA-11": NISTControl(
                control_id="SA-11",
                control_name="Developer Testing and Evaluation",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Require developer testing and evaluation plan",
            ),
            "SA-15": NISTControl(
                control_id="SA-15",
                control_name="Development Process, Standards, and Tools",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Require documented development process addressing security",
            ),
            "SA-22": NISTControl(
                control_id="SA-22",
                control_name="Unsupported System Components",
                family="System and Services Acquisition",
                family_id="SA",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Replace components when support is no longer available",
            ),
        })

        # =====================================================================
        # SC - System and Communications Protection Family
        # =====================================================================
        self.controls.update({
            "SC-1": NISTControl(
                control_id="SC-1",
                control_name="Policy and Procedures",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop system and communications protection policy",
            ),
            "SC-2": NISTControl(
                control_id="SC-2",
                control_name="Separation of System and User Functionality",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Separate user functionality from system management functionality",
            ),
            "SC-4": NISTControl(
                control_id="SC-4",
                control_name="Information in Shared System Resources",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Prevent unauthorized transfer via shared system resources",
            ),
            "SC-5": NISTControl(
                control_id="SC-5",
                control_name="Denial-of-Service Protection",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Protect against or limit effects of denial-of-service attacks",
            ),
            "SC-7": NISTControl(
                control_id="SC-7",
                control_name="Boundary Protection",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Monitor and control communications at external and internal boundaries",
                related_controls=["AC-4", "AC-17", "AC-18", "AC-19", "AC-20", "AU-13", "CA-3", "CM-6", "CM-7", "CP-7", "CP-8", "IR-4", "MA-4", "PE-4", "PL-8", "PM-12", "SA-8", "SA-17", "SC-5", "SC-26", "SC-32", "SC-35", "SC-43", "SI-3", "SI-4"],
            ),
            "SC-8": NISTControl(
                control_id="SC-8",
                control_name="Transmission Confidentiality and Integrity",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Protect confidentiality and integrity of transmitted information",
                related_controls=["AC-17", "AC-18", "AU-10", "IA-3", "IA-5", "MA-4", "PE-4", "SA-4", "SA-8", "SC-7", "SC-12", "SC-13", "SC-16", "SC-20", "SC-23", "SC-28"],
            ),
            "SC-10": NISTControl(
                control_id="SC-10",
                control_name="Network Disconnect",
                family="System and Communications Protection",
                family_id="SC",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Terminate network connection at end of session or after inactivity period",
            ),
            "SC-12": NISTControl(
                control_id="SC-12",
                control_name="Cryptographic Key Establishment and Management",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Establish and manage cryptographic keys",
            ),
            "SC-13": NISTControl(
                control_id="SC-13",
                control_name="Cryptographic Protection",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Implement cryptography using FIPS-validated modules",
                related_controls=["AC-2", "AC-3", "AC-7", "AC-17", "AC-18", "AC-19", "AU-9", "AU-10", "CM-11", "CP-9", "IA-3", "IA-5", "IA-7", "MA-4", "MP-2", "MP-4", "MP-5", "PE-3", "SA-4", "SA-8", "SA-9", "SC-8", "SC-12", "SC-23", "SC-28", "SC-43", "SI-3", "SI-7"],
            ),
            "SC-15": NISTControl(
                control_id="SC-15",
                control_name="Collaborative Computing Devices and Applications",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Prohibit remote activation of collaborative computing devices",
            ),
            "SC-17": NISTControl(
                control_id="SC-17",
                control_name="Public Key Infrastructure Certificates",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Issue public key certificates under organization policy or from approved provider",
            ),
            "SC-18": NISTControl(
                control_id="SC-18",
                control_name="Mobile Code",
                family="System and Communications Protection",
                family_id="SC",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Define acceptable and unacceptable mobile code and technologies",
            ),
            "SC-20": NISTControl(
                control_id="SC-20",
                control_name="Secure Name/Address Resolution Service (Authoritative Source)",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Provide origin and integrity verification for authoritative DNS",
            ),
            "SC-21": NISTControl(
                control_id="SC-21",
                control_name="Secure Name/Address Resolution Service (Recursive or Caching Resolver)",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Request and perform data origin and integrity verification for DNS responses",
            ),
            "SC-22": NISTControl(
                control_id="SC-22",
                control_name="Architecture and Provisioning for Name/Address Resolution Service",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Ensure fault-tolerant and role-separated DNS systems",
            ),
            "SC-23": NISTControl(
                control_id="SC-23",
                control_name="Session Authenticity",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Protect authenticity of communications sessions",
            ),
            "SC-28": NISTControl(
                control_id="SC-28",
                control_name="Protection of Information at Rest",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Protect confidentiality and integrity of information at rest",
            ),
            "SC-39": NISTControl(
                control_id="SC-39",
                control_name="Process Isolation",
                family="System and Communications Protection",
                family_id="SC",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Maintain separate execution domain for each executing process",
            ),
        })

        # =====================================================================
        # SI - System and Information Integrity Family
        # =====================================================================
        self.controls.update({
            "SI-1": NISTControl(
                control_id="SI-1",
                control_name="Policy and Procedures",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop system and information integrity policy",
            ),
            "SI-2": NISTControl(
                control_id="SI-2",
                control_name="Flaw Remediation",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Identify, report, and correct system flaws; test updates before installation",
                related_controls=["CA-5", "CM-3", "CM-4", "CM-5", "CM-6", "CM-8", "IR-4", "MA-2", "RA-5", "RA-7", "SA-8", "SA-10", "SA-11", "SI-3", "SI-5", "SI-7", "SI-11"],
            ),
            "SI-3": NISTControl(
                control_id="SI-3",
                control_name="Malicious Code Protection",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Implement malicious code protection at system entry and exit points",
                related_controls=["AC-4", "AC-19", "CM-3", "CM-8", "IR-4", "MA-3", "MA-4", "PL-9", "RA-5", "SC-7", "SC-23", "SC-26", "SC-28", "SC-44", "SI-2", "SI-4", "SI-7", "SI-8", "SI-15"],
            ),
            "SI-4": NISTControl(
                control_id="SI-4",
                control_name="System Monitoring",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Monitor system to detect attacks, indicators of potential attacks, and unauthorized connections",
                related_controls=["AC-2", "AC-3", "AC-4", "AC-8", "AC-17", "AU-2", "AU-6", "AU-7", "AU-9", "AU-12", "AU-13", "AU-14", "CA-7", "CM-3", "CM-8", "IA-10", "IR-4", "PE-3", "PE-6", "PM-12", "RA-5", "RA-10", "SC-5", "SC-7", "SC-18", "SC-26", "SC-35", "SC-36", "SC-37", "SI-3", "SI-7", "SR-10"],
            ),
            "SI-5": NISTControl(
                control_id="SI-5",
                control_name="Security Alerts, Advisories, and Directives",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Receive and generate security alerts, advisories, and directives",
            ),
            "SI-6": NISTControl(
                control_id="SI-6",
                control_name="Security and Privacy Function Verification",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["HIGH"],
                description="Verify correct operation of security and privacy functions",
            ),
            "SI-7": NISTControl(
                control_id="SI-7",
                control_name="Software, Firmware, and Information Integrity",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Employ integrity verification tools to detect unauthorized changes",
            ),
            "SI-8": NISTControl(
                control_id="SI-8",
                control_name="Spam Protection",
                family="System and Information Integrity",
                family_id="SI",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Employ spam protection mechanisms at system entry and exit points",
            ),
            "SI-10": NISTControl(
                control_id="SI-10",
                control_name="Information Input Validation",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Check validity of information inputs",
                related_controls=["AC-3", "SI-11"],
            ),
            "SI-11": NISTControl(
                control_id="SI-11",
                control_name="Error Handling",
                family="System and Information Integrity",
                family_id="SI",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Generate error messages without revealing sensitive information",
            ),
            "SI-12": NISTControl(
                control_id="SI-12",
                control_name="Information Management and Retention",
                family="System and Information Integrity",
                family_id="SI",
                priority="P2",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Manage and retain information per applicable requirements",
            ),
            "SI-16": NISTControl(
                control_id="SI-16",
                control_name="Memory Protection",
                family="System and Information Integrity",
                family_id="SI",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Implement safeguards to protect memory from unauthorized code execution",
            ),
        })

        # =====================================================================
        # SR - Supply Chain Risk Management Family
        # =====================================================================
        self.controls.update({
            "SR-1": NISTControl(
                control_id="SR-1",
                control_name="Policy and Procedures",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["LOW", "MODERATE", "HIGH"],
                description="Develop supply chain risk management policy",
            ),
            "SR-2": NISTControl(
                control_id="SR-2",
                control_name="Supply Chain Risk Management Plan",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Develop plan for managing supply chain risks",
            ),
            "SR-3": NISTControl(
                control_id="SR-3",
                control_name="Supply Chain Controls and Processes",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Establish processes to identify and address supply chain weaknesses",
            ),
            "SR-4": NISTControl(
                control_id="SR-4",
                control_name="Provenance",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["HIGH"],
                description="Document, monitor, and maintain provenance of systems and components",
            ),
            "SR-5": NISTControl(
                control_id="SR-5",
                control_name="Acquisition Strategies, Tools, and Methods",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Employ acquisition strategies to protect against supply chain risks",
            ),
            "SR-6": NISTControl(
                control_id="SR-6",
                control_name="Supplier Assessments and Reviews",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Assess and review supply chain-related risks from suppliers",
            ),
            "SR-8": NISTControl(
                control_id="SR-8",
                control_name="Notification Agreements",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P2",
                baseline=["MODERATE", "HIGH"],
                description="Establish notification agreements for supply chain compromises",
            ),
            "SR-10": NISTControl(
                control_id="SR-10",
                control_name="Inspection of Systems or Components",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["HIGH"],
                description="Inspect systems or components to detect tampering",
            ),
            "SR-11": NISTControl(
                control_id="SR-11",
                control_name="Component Authenticity",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Develop anti-counterfeit policy and procedures",
            ),
            "SR-12": NISTControl(
                control_id="SR-12",
                control_name="Component Disposal",
                family="Supply Chain Risk Management",
                family_id="SR",
                priority="P1",
                baseline=["MODERATE", "HIGH"],
                description="Dispose of components per organizational techniques",
            ),
        })

    def _initialize_cve_mappings(self):
        """Initialize comprehensive CVE to NIST control mappings"""
        self.cve_to_controls = {
            # Cryptographic/SSL/TLS Vulnerabilities
            "CVE-2014-0160": ["SC-8", "SC-12", "SC-13", "RA-5"],  # Heartbleed
            "CVE-2014-3566": ["SC-8", "SC-13"],  # POODLE
            "CVE-2015-0204": ["SC-8", "SC-13"],  # FREAK
            "CVE-2015-4000": ["SC-8", "SC-13"],  # Logjam
            "CVE-2016-0800": ["SC-8", "SC-13"],  # DROWN
            "CVE-2016-2183": ["SC-8", "SC-13"],  # SWEET32
            "CVE-2020-1472": ["IA-2", "IA-5", "SC-8", "SC-23"],  # Zerologon

            # Remote Code Execution
            "CVE-2017-0144": ["SI-2", "CM-7", "SC-7", "RA-5"],  # EternalBlue
            "CVE-2017-0145": ["SI-2", "CM-7", "SC-7"],  # EternalRomance
            "CVE-2019-0708": ["SI-2", "AC-17", "CM-7"],  # BlueKeep
            "CVE-2021-44228": ["SI-2", "SI-10", "CM-7", "RA-5"],  # Log4Shell
            "CVE-2021-45046": ["SI-2", "SI-10", "CM-7"],  # Log4j additional
            "CVE-2021-45105": ["SI-2", "SI-10", "CM-7"],  # Log4j DoS
            "CVE-2022-22965": ["SI-2", "SI-10", "CM-6"],  # Spring4Shell
            "CVE-2022-26134": ["SI-2", "SI-10", "AC-6"],  # Confluence RCE
            "CVE-2023-44487": ["SC-5", "SI-2"],  # HTTP/2 Rapid Reset

            # Command/Code Injection
            "CVE-2014-6271": ["SI-2", "SI-10", "AC-6"],  # Shellshock
            "CVE-2014-7169": ["SI-2", "SI-10", "AC-6"],  # Shellshock variant
            "CVE-2017-5638": ["SI-2", "SI-10", "AC-3"],  # Apache Struts
            "CVE-2021-41773": ["SI-2", "AC-3", "CM-6"],  # Apache path traversal
            "CVE-2021-42013": ["SI-2", "AC-3", "CM-6"],  # Apache path traversal

            # Authentication/Access Control
            "CVE-2018-11776": ["SI-2", "AC-3", "SI-10"],  # Apache Struts RCE
            "CVE-2019-11510": ["SI-2", "AC-17", "IA-5"],  # Pulse Secure
            "CVE-2020-0796": ["SI-2", "SC-7", "CM-7"],  # SMBGhost
            "CVE-2020-5902": ["SI-2", "AC-3", "CM-6"],  # F5 BIG-IP
            "CVE-2021-22986": ["SI-2", "AC-3", "CM-6"],  # F5 BIG-IP iControl

            # Privilege Escalation
            "CVE-2021-1675": ["SI-2", "AC-6", "CM-6"],  # PrintNightmare
            "CVE-2021-34527": ["SI-2", "AC-6", "CM-6"],  # PrintNightmare
            "CVE-2021-4034": ["SI-2", "AC-6"],  # PwnKit/Polkit
            "CVE-2022-0847": ["SI-2", "AC-6"],  # Dirty Pipe

            # Web Application Vulnerabilities
            "CVE-2019-11581": ["SI-2", "SI-10", "AC-3"],  # Jira template injection
            "CVE-2019-18935": ["SI-2", "AC-3", "AU-9"],  # Telerik UI deserialization
            "CVE-2020-0688": ["SI-2", "IA-5", "CM-6"],  # Exchange Server
            "CVE-2021-26855": ["SI-2", "AC-17", "CM-6"],  # ProxyLogon
            "CVE-2021-27065": ["SI-2", "AC-6", "CM-6"],  # ProxyLogon (write)
            "CVE-2021-34473": ["SI-2", "AC-17", "CM-6"],  # ProxyShell
            "CVE-2023-23397": ["SI-2", "IA-5", "SC-8"],  # Outlook elevation

            # Database Vulnerabilities
            "CVE-2012-2122": ["IA-5", "IA-2", "AU-2"],  # MySQL auth bypass
            "CVE-2020-1938": ["SI-2", "SC-7", "CM-7"],  # Ghostcat/Tomcat AJP

            # Supply Chain
            "CVE-2020-14882": ["SI-2", "AC-3", "CM-6"],  # Oracle WebLogic
            "CVE-2020-14883": ["SI-2", "AC-3", "CM-6"],  # Oracle WebLogic
            "CVE-2020-25213": ["SI-2", "CM-6", "AC-3"],  # WordPress file manager
            "CVE-2021-22205": ["SI-2", "SI-10", "CM-6"],  # GitLab RCE
        }

    def _initialize_category_mappings(self):
        """Initialize comprehensive vulnerability category to NIST control mappings"""
        self.category_to_controls = {
            # Patching and Updates
            "Missing Patches": ["SI-2", "CM-3", "CM-6", "RA-5"],
            "Outdated Software": ["SI-2", "SA-22", "CM-8"],
            "End of Life Software": ["SA-22", "SI-2", "PM-5"],
            "Unsupported Software": ["SA-22", "SI-2", "CM-8"],

            # Encryption and Cryptography
            "Weak Encryption": ["SC-8", "SC-12", "SC-13", "SC-28"],
            "Weak SSL/TLS": ["SC-8", "SC-13", "CM-6"],
            "Expired Certificates": ["SC-17", "SC-12", "IA-5"],
            "Self-Signed Certificates": ["SC-17", "SC-12"],
            "Missing Encryption": ["SC-8", "SC-28", "MP-5"],

            # Authentication
            "Weak Authentication": ["IA-2", "IA-5", "IA-11"],
            "Default Credentials": ["IA-5", "CM-6", "CM-2"],
            "Weak Passwords": ["IA-5", "AC-7"],
            "Missing MFA": ["IA-2", "AC-17"],
            "Password Policy": ["IA-5", "AC-7", "CM-6"],
            "Session Management": ["SC-23", "AC-12", "IA-11"],

            # Access Control
            "Access Control": ["AC-2", "AC-3", "AC-6"],
            "Excessive Privileges": ["AC-6", "AC-2", "CM-5"],
            "Least Privilege": ["AC-6", "CM-5"],
            "Account Management": ["AC-2", "PS-4", "PS-5"],
            "Orphaned Accounts": ["AC-2", "PS-4"],

            # Configuration
            "Configuration Issues": ["CM-6", "CM-2", "CM-7"],
            "Misconfiguration": ["CM-6", "CM-2"],
            "Insecure Defaults": ["CM-6", "CM-2", "SA-4"],
            "Unnecessary Services": ["CM-7", "CM-2"],
            "Open Ports": ["CM-7", "SC-7"],
            "Unnecessary Features": ["CM-7"],

            # Network Security
            "Network Security": ["SC-7", "AC-4", "SI-4"],
            "Remote Access": ["AC-17", "IA-2", "SC-8"],
            "Wireless Security": ["AC-18", "SC-8"],
            "Boundary Protection": ["SC-7", "AC-4"],
            "Network Segmentation": ["SC-7", "AC-4"],

            # Input Validation
            "Input Validation": ["SI-10", "SC-18"],
            "SQL Injection": ["SI-10", "SA-11"],
            "Cross-Site Scripting": ["SI-10", "SA-11"],
            "Command Injection": ["SI-10", "AC-6"],
            "Path Traversal": ["SI-10", "AC-3"],

            # Logging and Monitoring
            "Logging Issues": ["AU-2", "AU-3", "AU-12"],
            "Insufficient Logging": ["AU-2", "AU-12"],
            "Missing Audit": ["AU-2", "AU-6"],
            "Log Protection": ["AU-9", "AU-11"],

            # Malware Protection
            "Malware Protection": ["SI-3", "SI-4"],
            "Antivirus": ["SI-3", "CM-6"],
            "Missing EDR": ["SI-3", "SI-4"],

            # Data Protection
            "Data Protection": ["SC-28", "MP-2", "MP-4"],
            "Data at Rest": ["SC-28", "MP-4"],
            "Media Protection": ["MP-2", "MP-4", "MP-6"],
            "Data Leakage": ["AC-4", "SC-7", "SI-4"],

            # Incident Response
            "Incident Response": ["IR-4", "IR-5", "IR-6"],
            "Security Monitoring": ["SI-4", "AU-6", "IR-5"],

            # Vulnerability Management
            "Vulnerability Scanning": ["RA-5", "CA-2", "CA-7"],
            "Vulnerability Management": ["RA-5", "SI-2", "CA-5"],
            "Risk Assessment": ["RA-3", "RA-5"],

            # Backup and Recovery
            "Backup Issues": ["CP-9", "CP-10"],
            "Disaster Recovery": ["CP-2", "CP-7", "CP-10"],
            "Business Continuity": ["CP-2", "CP-4"],

            # Physical Security
            "Physical Security": ["PE-2", "PE-3", "PE-6"],

            # Personnel Security
            "Personnel Security": ["PS-2", "PS-3", "PS-4"],
            "Security Awareness": ["AT-2", "AT-3"],

            # Supply Chain
            "Supply Chain": ["SR-2", "SR-3", "SR-6"],
            "Third Party Risk": ["SA-9", "SR-6", "SA-4"],
            "Vendor Management": ["SA-9", "SR-6"],

            # Privacy
            "PII Protection": ["PT-2", "PT-3", "PT-5"],
            "Privacy": ["PT-1", "PT-2", "PT-4"],

            # General/Default
            "General Security": ["SI-2", "CM-6"],
            "Unknown": ["SI-2"],
        }

    def get_control_family(self, family_id: str) -> Optional[ControlFamily]:
        """Get control family information by ID"""
        return self.control_families.get(family_id)

    def get_all_control_families(self) -> Dict[str, ControlFamily]:
        """Get all control families"""
        return self.control_families

    def get_controls_for_cve(self, cve: str) -> List[str]:
        """Get NIST controls for a specific CVE"""
        return self.cve_to_controls.get(cve, [])

    def get_controls_for_category(self, category: str) -> List[str]:
        """Get NIST controls for a vulnerability category"""
        return self.category_to_controls.get(category, [])

    def get_control_details(self, control_id: str) -> Optional[NISTControl]:
        """Get detailed information about a NIST control"""
        # Handle base control ID (strip enhancement notation)
        base_id = control_id.split("(")[0] if "(" in control_id else control_id
        return self.controls.get(base_id)

    def get_controls_by_family(self, family_id: str) -> Dict[str, NISTControl]:
        """Get all controls for a specific control family"""
        return {
            cid: control
            for cid, control in self.controls.items()
            if control.family_id == family_id
        }

    def categorize_vulnerability(self, plugin_name: str, description: str) -> str:
        """Categorize vulnerability based on plugin name and description"""
        plugin_lower = plugin_name.lower()
        desc_lower = description.lower()

        # Check for specific vulnerability patterns
        patterns = {
            "Missing Patches": ["patch", "update", "security update", "kb", "hotfix", "cumulative update"],
            "Weak SSL/TLS": ["ssl", "tls", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "weak cipher", "cipher suite"],
            "Weak Encryption": ["weak encryption", "des", "rc4", "md5", "sha1", "3des", "sweet32"],
            "Default Credentials": ["default password", "default credential", "default account", "factory default"],
            "Weak Passwords": ["weak password", "password policy", "password complexity", "blank password"],
            "Missing MFA": ["multi-factor", "mfa", "two-factor", "2fa"],
            "Outdated Software": ["outdated", "unsupported", "end of life", "eol", "obsolete", "deprecated"],
            "Unnecessary Services": ["service detection", "unnecessary service", "unused service", "unneeded"],
            "Open Ports": ["open port", "exposed port", "listening port"],
            "Configuration Issues": ["configuration", "misconfiguration", "misconfigured", "hardening"],
            "SQL Injection": ["sql injection", "sqli", "blind sql"],
            "Cross-Site Scripting": ["cross-site scripting", "xss", "script injection"],
            "Command Injection": ["command injection", "os command", "shell injection", "code injection"],
            "Path Traversal": ["path traversal", "directory traversal", "../ ", "file inclusion"],
            "Remote Access": ["remote access", "rdp", "ssh", "vnc", "telnet"],
            "Wireless Security": ["wireless", "wifi", "wpa", "wep", "802.11"],
            "Logging Issues": ["logging", "audit", "event log"],
            "Malware Protection": ["antivirus", "anti-malware", "malware", "virus"],
            "Backup Issues": ["backup", "recovery", "restore"],
            "Access Control": ["access control", "permission", "privilege", "authorization"],
            "Session Management": ["session", "cookie", "timeout"],
            "Input Validation": ["input validation", "validation", "sanitization"],
            "Expired Certificates": ["expired certificate", "certificate expir"],
            "Self-Signed Certificates": ["self-signed", "untrusted certificate"],
            "Vulnerability Scanning": ["vulnerability scan", "vulnerability assessment"],
        }

        for category, keywords in patterns.items():
            if any(keyword in plugin_lower or keyword in desc_lower for keyword in keywords):
                return category

        return "General Security"  # Default category

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
            cve_upper = cve.upper().strip()
            if cve_upper in self.cve_to_controls:
                controls.update(self.cve_to_controls[cve_upper])

        # Check category mapping
        category = self.categorize_vulnerability(plugin_name, description)
        controls.update(self.category_to_controls.get(category, []))

        # If no specific mapping found, default to SI-2 (Flaw Remediation)
        if not controls:
            controls.add("SI-2")

        return sorted(list(controls))

    def get_control_priority(self, control_id: str) -> str:
        """Get the priority level of a control (P1, P2, P3)"""
        control = self.get_control_details(control_id)
        return control.priority if control else "P3"

    def get_controls_by_priority(self, priority: str) -> Dict[str, NISTControl]:
        """Get all controls with a specific priority level"""
        return {
            cid: control
            for cid, control in self.controls.items()
            if control.priority == priority
        }

    def get_vulnerability_controls_with_details(
        self, plugin_name: str, description: str, cves: List[str]
    ) -> List[NISTControl]:
        """Get full control details for a vulnerability mapping"""
        control_ids = self.map_vulnerability_to_controls(plugin_name, description, cves)
        controls = []
        for cid in control_ids:
            control = self.get_control_details(cid)
            if control:
                controls.append(control)
        return controls


def get_nist_controls_for_cve(cve: str) -> List[str]:
    """Convenience function to get NIST controls for a CVE"""
    mapper = NISTMapper()
    return mapper.get_controls_for_cve(cve)


def get_nist_control_families() -> Dict[str, ControlFamily]:
    """Convenience function to get all NIST 800-53 Rev 5 control families"""
    mapper = NISTMapper()
    return mapper.get_all_control_families()


def map_vulnerability_to_nist(
    plugin_name: str, description: str, cves: List[str] = None
) -> List[str]:
    """Convenience function to map a vulnerability to NIST controls"""
    mapper = NISTMapper()
    return mapper.map_vulnerability_to_controls(
        plugin_name, description, cves or []
    )
