"""
CVE Database Integration
Provides enhanced CVE information lookup
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class CVEInfo:
    """CVE information"""

    cve_id: str
    description: str
    cvss_v3_score: float
    cvss_v3_vector: str
    cvss_v2_score: float
    cvss_v2_vector: str
    published_date: str
    last_modified: str
    cwe_ids: List[str]  # Common Weakness Enumeration
    references: List[str]
    exploitability_score: float
    impact_score: float


class CVEDatabase:
    """Simple CVE database for enhanced vulnerability information"""

    def __init__(self):
        self._initialize_database()

    def _initialize_database(self):
        """Initialize CVE database with common critical CVEs"""
        self.cve_data = {
            "CVE-2014-0160": CVEInfo(
                cve_id="CVE-2014-0160",
                description="Heartbleed - OpenSSL TLS heartbeat read overrun",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_v2_score=5.0,
                cvss_v2_vector="AV:N/AC:L/Au:N/C:P/I:N/A:N",
                published_date="2014-04-07",
                last_modified="2020-10-15",
                cwe_ids=["CWE-125"],
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
                    "http://heartbleed.com/",
                ],
                exploitability_score=10.0,
                impact_score=2.9,
            ),
            "CVE-2017-0144": CVEInfo(
                cve_id="CVE-2017-0144",
                description="EternalBlue - Microsoft SMBv1 Remote Code Execution",
                cvss_v3_score=8.1,
                cvss_v3_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_v2_score=9.3,
                cvss_v2_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C",
                published_date="2017-03-17",
                last_modified="2020-09-28",
                cwe_ids=["CWE-119"],
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                    "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
                ],
                exploitability_score=2.8,
                impact_score=5.9,
            ),
            "CVE-2021-44228": CVEInfo(
                cve_id="CVE-2021-44228",
                description="Log4Shell - Apache Log4j2 Remote Code Execution",
                cvss_v3_score=10.0,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cvss_v2_score=9.3,
                cvss_v2_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C",
                published_date="2021-12-10",
                last_modified="2023-12-10",
                cwe_ids=["CWE-917", "CWE-502"],
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://logging.apache.org/log4j/2.x/security.html",
                ],
                exploitability_score=3.9,
                impact_score=6.0,
            ),
            "CVE-2014-6271": CVEInfo(
                cve_id="CVE-2014-6271",
                description="Shellshock - GNU Bash Remote Code Execution",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_v2_score=10.0,
                cvss_v2_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
                published_date="2014-09-24",
                last_modified="2021-02-01",
                cwe_ids=["CWE-78"],
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
                    "https://shellshocker.net/",
                ],
                exploitability_score=10.0,
                impact_score=10.0,
            ),
        }

    def get_cve_info(self, cve_id: str) -> Optional[CVEInfo]:
        """Get information about a specific CVE"""
        return self.cve_data.get(cve_id)

    def get_multiple_cves(self, cve_ids: List[str]) -> Dict[str, CVEInfo]:
        """Get information for multiple CVEs"""
        return {
            cve_id: self.cve_data[cve_id]
            for cve_id in cve_ids
            if cve_id in self.cve_data
        }

    def get_high_severity_cves(self, min_cvss: float = 7.0) -> List[CVEInfo]:
        """Get all CVEs with CVSS score above threshold"""
        return [cve for cve in self.cve_data.values() if cve.cvss_v3_score >= min_cvss]
