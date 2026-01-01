# Compliance Module Documentation

## Overview

The `compliance` module is **Stage 3** of the vISSM pipeline. It maps vulnerabilities to DoD compliance frameworks including DISA STIGs, NIST 800-53 controls, and CVE databases.

**Primary Responsibility**: Provide compliance context and regulatory mappings for vulnerability findings.

## Module Structure

```
src/compliance/
├── __init__.py           # Module exports
├── stig_mapper.py       # DISA STIG mapping (245 lines)
├── nist_mapper.py       # NIST 800-53 Rev 5 mapping (~2,500 lines) - Enterprise-ready
└── cve_database.py      # CVE enrichment database (121 lines)
```

## Sub-Modules

### 1. STIG Mapper (`stig_mapper.py`)

Maps Nessus vulnerabilities to **DISA Security Technical Implementation Guides (STIGs)**.

#### Data Classes

##### `STIGFinding`
Represents a STIG compliance finding.

**Fields:**
```python
stig_id: str              # STIG identifier (e.g., "V-220706")
rule_id: str              # Rule ID (e.g., "SV-220706r569187_rule")
severity: str             # "CAT I", "CAT II", or "CAT III"
group_title: str          # Group description
rule_title: str           # Specific rule title
check_content: str        # How to verify compliance
fix_text: str            # Remediation instructions
cci_references: List[str] # Control Correlation Identifiers
nist_controls: List[str]  # Related NIST controls
```

**Example:**
```python
finding = STIGFinding(
    stig_id="V-220706",
    rule_id="SV-220706r569187_rule",
    severity="CAT II",
    group_title="SRG-OS-000480-GPOS-00227",
    rule_title="SMBv1 must be disabled",
    check_content="Verify SMBv1 is disabled...",
    fix_text="Disable SMBv1 using...",
    cci_references=["CCI-000366"],
    nist_controls=["CM-6"]
)
```

#### Classes

##### `STIGMapper`
Main STIG mapping class with hardcoded plugin-to-STIG and CVE-to-STIG mappings.

**Attributes:**

###### `plugin_to_stig: Dict[str, STIGFinding]`
Maps Nessus plugin IDs to STIG findings.

**Coverage:**
- Windows STIGs (User rights, SMB configuration, account policies)
- SSL/TLS STIGs (Protocol versions, cipher suites)
- Apache Web Server STIGs (Configuration standards)
- Default account STIGs (Weak credentials)

**Example Mappings:**
```python
"10863": STIGFinding(
    stig_id="V-220706",
    severity="CAT II",
    rule_title="SMBv1 must be disabled",
    # ...
),
"21643": STIGFinding(
    stig_id="V-220965",
    severity="CAT I",
    rule_title="Windows must require strong passwords",
    # ...
)
```

###### `cve_to_stig: Dict[str, STIGFinding]`
Maps CVE identifiers to STIG findings.

**Example Mappings:**
```python
"CVE-2017-0144": STIGFinding(  # EternalBlue
    stig_id="V-220857",
    severity="CAT I",
    rule_title="SMBv1 remote code execution vulnerability",
    # ...
)
```

**Methods:**

###### `get_stig_for_plugin(plugin_id: str) -> Optional[STIGFinding]`
Lookup STIG finding by Nessus plugin ID.

**Parameters:**
- `plugin_id`: Nessus plugin ID (e.g., "10863")

**Returns:**
- `STIGFinding` if mapping exists, `None` otherwise

**Example:**
```python
mapper = STIGMapper()
finding = mapper.get_stig_for_plugin("10863")
if finding:
    print(f"STIG ID: {finding.stig_id}, Severity: {finding.severity}")
```

###### `get_stig_for_cve(cve: str) -> Optional[STIGFinding]`
Lookup STIG finding by CVE identifier.

**Parameters:**
- `cve`: CVE identifier (e.g., "CVE-2017-0144")

**Returns:**
- `STIGFinding` if mapping exists, `None` otherwise

**Example:**
```python
finding = mapper.get_stig_for_cve("CVE-2017-0144")
if finding:
    print(f"EternalBlue: {finding.rule_title}")
```

#### Severity Levels (CAT I/II/III)

| CAT Level | DoD Definition | Remediation Timeline | Nessus Severity |
|-----------|----------------|---------------------|-----------------|
| **CAT I** | Critical/high risk | 15 days | 4 (Critical) |
| **CAT II** | Medium/moderate risk | 30 days | 3 (High) |
| **CAT III** | Low risk | 90 days | 2 (Medium) |

**Mapping Logic:**
```python
severity_map = {
    4: "CAT I",   # Critical
    3: "CAT II",  # High
    2: "CAT III"  # Medium
}
```

---

### 2. NIST Mapper (`nist_mapper.py`) - Enterprise-Ready

Maps vulnerabilities to **NIST SP 800-53 Rev 5 security controls** with complete coverage of all 20 control families.

**Version 1.1.0 Features:**
- ~150+ control definitions across all 20 families
- ~50 CVE-to-control mappings for major vulnerabilities
- ~50 vulnerability category-to-control mappings
- Control priorities (P1, P2, P3) and baselines (LOW, MODERATE, HIGH)
- Related control cross-references

#### Data Classes

##### `NISTControl`
Represents a NIST 800-53 security control.

**Fields:**
```python
control_id: str                      # Control identifier (e.g., "AC-2")
control_name: str                    # Full name (e.g., "Account Management")
family: str                          # Control family name (e.g., "Access Control")
family_id: str                       # Control family ID (e.g., "AC")
priority: str                        # "P1", "P2", or "P3"
baseline: List[str]                  # ["LOW", "MODERATE", "HIGH"]
description: str                     # Control description
related_controls: List[str]          # Related control IDs
```

**Example:**
```python
control = NISTControl(
    control_id="AC-2",
    control_name="Account Management",
    family="Access Control",
    family_id="AC",
    priority="P1",
    baseline=["LOW", "MODERATE", "HIGH"],
    description="Manage system accounts including creating, enabling, modifying...",
    related_controls=["AC-3", "AC-5", "AU-9"]
)
```

##### `ControlFamily`
Represents a NIST 800-53 control family (NEW in v1.1.0).

**Fields:**
```python
family_id: str              # Family identifier (e.g., "AC")
family_name: str            # Full name (e.g., "Access Control")
description: str            # Family description
control_count: int          # Number of controls in family
```

#### Classes

##### `NISTMapper`
Main NIST control mapping class with enterprise-grade coverage.

**Attributes:**

###### `controls: Dict[str, NISTControl]`
Comprehensive dictionary of ~150+ NIST controls.

###### `control_families: Dict[str, ControlFamily]`
Metadata for all 20 NIST 800-53 Rev 5 control families.

###### `cve_to_controls: Dict[str, List[str]]`
Maps ~50 CVE identifiers to NIST control IDs.

**Example Mappings:**
```python
"CVE-2014-0160": ["SC-8", "SC-13", "SC-17"],   # Heartbleed
"CVE-2017-0144": ["SC-7", "SI-2", "SI-3"],     # EternalBlue
"CVE-2021-44228": ["SI-2", "SI-10", "CM-7"],   # Log4Shell
"CVE-2023-44487": ["SC-5", "SC-7", "SI-4"],    # HTTP/2 Rapid Reset
"CVE-2024-3094": ["SA-12", "SR-3", "SR-4"]     # XZ Utils Backdoor
```

###### `category_to_controls: Dict[str, List[str]]`
Maps ~50 vulnerability categories to relevant NIST controls.

**Example Mappings:**
```python
"authentication_bypass": ["IA-2", "IA-5", "IA-8"],
"sql_injection": ["SI-10", "SI-16", "SA-11"],
"buffer_overflow": ["SI-16", "SA-11", "SI-17"],
"weak_cryptography": ["SC-8", "SC-12", "SC-13"]
```

**Methods:**

###### `get_controls_for_cve(cve: str) -> List[NISTControl]`
Get NIST controls for a CVE.

###### `get_controls_for_category(category: str) -> List[NISTControl]`
Get NIST controls for a vulnerability category.

###### `get_control_family(family_id: str) -> Optional[ControlFamily]`
Get control family metadata by ID (NEW in v1.1.0).

###### `get_all_control_families() -> List[ControlFamily]`
Get all 20 control families (NEW in v1.1.0).

###### `get_controls_by_family(family_id: str) -> List[NISTControl]`
Get all controls for a specific family (NEW in v1.1.0).

###### `get_control_priority(control_id: str) -> str`
Get priority (P1/P2/P3) for a control (NEW in v1.1.0).

###### `get_controls_by_priority(priority: str) -> List[NISTControl]`
Filter controls by priority level (NEW in v1.1.0).

###### `get_vulnerability_controls_with_details(cve: str, category: str) -> List[NISTControl]`
Enhanced control lookup with full metadata (NEW in v1.1.0).

#### Convenience Functions

```python
# Get all 20 control family names
families = get_nist_control_families()

# Map vulnerability to NIST controls
controls = map_vulnerability_to_nist(cve="CVE-2021-44228")
```

#### NIST 800-53 Rev 5 Control Families (All 20)

| Family Code | Family Name | Example Controls |
|-------------|-------------|------------------|
| **AC** | Access Control | AC-2 (Account Management), AC-3 (Access Enforcement) |
| **AT** | Awareness and Training | AT-2 (Literacy Training), AT-3 (Role-Based Training) |
| **AU** | Audit and Accountability | AU-2 (Event Logging), AU-6 (Audit Record Review) |
| **CA** | Assessment, Authorization and Monitoring | CA-2 (Assessments), CA-7 (Continuous Monitoring) |
| **CM** | Configuration Management | CM-2 (Baseline Configuration), CM-6 (Configuration Settings) |
| **CP** | Contingency Planning | CP-2 (Contingency Plan), CP-9 (System Backup) |
| **IA** | Identification and Authentication | IA-2 (Multi-Factor Auth), IA-5 (Authenticator Management) |
| **IR** | Incident Response | IR-4 (Incident Handling), IR-6 (Incident Reporting) |
| **MA** | Maintenance | MA-2 (Controlled Maintenance), MA-4 (Nonlocal Maintenance) |
| **MP** | Media Protection | MP-2 (Media Access), MP-4 (Media Storage) |
| **PE** | Physical and Environmental Protection | PE-2 (Physical Access), PE-6 (Monitoring Physical Access) |
| **PL** | Planning | PL-2 (Security Plans), PL-8 (Security Architecture) |
| **PM** | Program Management | PM-1 (Information Security Program), PM-9 (Risk Management) |
| **PS** | Personnel Security | PS-2 (Position Risk), PS-3 (Personnel Screening) |
| **PT** | PII Processing and Transparency | PT-1 (Policy), PT-2 (Authority to Process) |
| **RA** | Risk Assessment | RA-3 (Risk Assessment), RA-5 (Vulnerability Monitoring) |
| **SA** | System and Services Acquisition | SA-4 (Acquisition Process), SA-11 (Developer Testing) |
| **SC** | System and Communications Protection | SC-7 (Boundary Protection), SC-8 (Transmission Confidentiality) |
| **SI** | System and Information Integrity | SI-2 (Flaw Remediation), SI-4 (System Monitoring) |
| **SR** | Supply Chain Risk Management | SR-3 (Supply Chain Controls), SR-6 (Supplier Assessments) |

#### Control Priorities

| Priority | Description | Selection |
|----------|-------------|-----------|
| **P1** | Highest priority, address first | Selected for all baselines |
| **P2** | Moderate priority | Selected for MODERATE and HIGH |
| **P3** | Lower priority | Selected for HIGH only |

#### RMF Baselines

**Impact Levels:**
- **LOW**: Minimal impact on operations, assets, or individuals
- **MODERATE**: Serious impact (most DoD systems)
- **HIGH**: Severe or catastrophic impact (critical DoD systems)

**Control Selection Example:**
```python
mapper = NISTMapper()

# Get all P1 (highest priority) controls
p1_controls = mapper.get_controls_by_priority("P1")

# Get all controls in the Incident Response family
ir_controls = mapper.get_controls_by_family("IR")

# Get controls for a specific vulnerability
log4shell_controls = mapper.get_vulnerability_controls_with_details(
    cve="CVE-2021-44228",
    category="remote_code_execution"
)
```

---

### 3. CVE Database (`cve_database.py`)

Enriches CVE identifiers with CVSS scores, CWE mappings, and exploitability data.

#### Data Classes

##### `CVEInfo`
Comprehensive CVE information.

**Fields:**
```python
cve_id: str                  # CVE identifier
description: str             # Vulnerability description
cvss_v2_score: float        # CVSS v2 base score (0.0-10.0)
cvss_v2_vector: str         # CVSS v2 vector string
cvss_v3_score: float        # CVSS v3 base score (0.0-10.0)
cvss_v3_vector: str         # CVSS v3 vector string
cwe_ids: List[str]          # Common Weakness Enumeration IDs
published_date: str         # Publication date
last_modified_date: str     # Last modification date
exploitability_score: float # Ease of exploitation (0.0-10.0)
impact_score: float         # Potential impact (0.0-10.0)
```

**Example:**
```python
cve = CVEInfo(
    cve_id="CVE-2017-0144",
    description="EternalBlue SMBv1 Remote Code Execution",
    cvss_v2_score=9.3,
    cvss_v2_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C",
    cvss_v3_score=8.1,
    cvss_v3_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe_ids=["CWE-119"],
    published_date="2017-03-14",
    last_modified_date="2020-09-28",
    exploitability_score=8.6,
    impact_score=10.0
)
```

#### Classes

##### `CVEDatabase`
Hardcoded database of critical CVEs.

**Attributes:**

###### `cve_data: Dict[str, CVEInfo]`
Maps CVE IDs to enriched information.

**Coverage (Notable CVEs):**
- **CVE-2014-0160**: Heartbleed (OpenSSL)
- **CVE-2017-0144**: EternalBlue (SMBv1)
- **CVE-2021-44228**: Log4Shell (Apache Log4j)
- Many more critical CVEs

**Methods:**

###### `get_cve_info(cve_id: str) -> Optional[CVEInfo]`
Lookup CVE information.

**Parameters:**
- `cve_id`: CVE identifier

**Returns:**
- `CVEInfo` if available, `None` otherwise

**Example:**
```python
db = CVEDatabase()
cve_info = db.get_cve_info("CVE-2017-0144")
if cve_info:
    print(f"CVSS v3: {cve_info.cvss_v3_score}")
    print(f"Exploitability: {cve_info.exploitability_score}")
```

---

## Integration with Pipeline

### Upstream (Input)
- **analysis_data dict** from `processor.vulnerability_processor`
- **NessusReport object** (for raw vulnerability data)

### Downstream (Output)
- **Enhanced analysis data** → exporters
- Specifically used by:
  - `exporters.stig_exporter` (primary user)
  - `exporters.excel_exporter` (for compliance columns)

### Usage in Exporters

```python
# From exporters/stig_exporter.py
from compliance.stig_mapper import STIGMapper
from compliance.nist_mapper import NISTMapper

stig_mapper = STIGMapper()
nist_mapper = NISTMapper()

for vuln in vulnerabilities:
    # Try plugin ID mapping
    stig_finding = stig_mapper.get_stig_for_plugin(vuln.plugin_id)

    # Fallback to CVE mapping
    if not stig_finding and vuln.cve:
        stig_finding = stig_mapper.get_stig_for_cve(vuln.cve)

    # Get NIST controls
    if vuln.cve:
        nist_controls = nist_mapper.get_controls_for_cve(vuln.cve)
    else:
        nist_controls = nist_mapper.get_controls_for_family(vuln.family)
```

## Design Decisions

### Why Hardcoded Mappings?

**Rationale:**
1. **Offline operation**: DoD environments often air-gapped
2. **Reliability**: No external API dependencies
3. **Auditability**: Mappings are version-controlled
4. **Consistency**: Same mappings across all users

**Trade-offs:**
- Mappings require manual updates
- May not include latest STIGs/CVEs
- Increases code size

### Why Not External Database?

**Considered alternatives:**
- SQLite database
- JSON/YAML configuration files
- External API calls (NVD, DISA STIG API)

**Rejected because:**
- Adds complexity for minimal benefit
- Users can't easily audit external databases
- API calls fail in air-gapped environments

**Future consideration:** Add optional external database sync for connected environments

### Control Correlation Identifiers (CCIs)

CCIs map STIG findings to NIST controls:

```python
# Example from stig_mapper.py
STIGFinding(
    cci_references=["CCI-000366"],  # Generic CCI
    nist_controls=["CM-6"]           # Configuration Management
)
```

**CCI Purpose:**
- Bridge between STIGs and NIST controls
- Required for eMASS system authorization
- Enables automated compliance mapping

## Testing

### Test Coverage
Located in `tests/test_vissm.py`:

Currently **no dedicated compliance mapper tests**.

**Recommended additions:**
```python
def test_stig_mapper_plugin_lookup(self):
    """Test STIG mapper can find known plugins"""
    mapper = STIGMapper()
    finding = mapper.get_stig_for_plugin("10863")
    self.assertIsNotNone(finding)
    self.assertEqual(finding.severity, "CAT II")

def test_nist_mapper_cve_lookup(self):
    """Test NIST mapper can find controls for CVEs"""
    mapper = NISTMapper()
    controls = mapper.get_controls_for_cve("CVE-2017-0144")
    self.assertGreater(len(controls), 0)
    self.assertIn("SC-7", [c.control_id for c in controls])

def test_cve_database_lookup(self):
    """Test CVE database has expected entries"""
    db = CVEDatabase()
    cve = db.get_cve_info("CVE-2014-0160")
    self.assertIsNotNone(cve)
    self.assertEqual(cve.cve_id, "CVE-2014-0160")
    self.assertGreater(cve.cvss_v2_score, 5.0)
```

## Maintenance Guide

### Adding New STIG Mappings

1. **Identify the plugin ID or CVE**
2. **Find the corresponding STIG**
   - Reference: https://public.cyber.mil/stigs/
   - Search STIG Library for relevant guideline
3. **Extract STIG details**
   - STIG ID (V-######)
   - Rule ID (SV-######r######_rule)
   - Severity (CAT I/II/III)
   - Rule title, check content, fix text
   - CCIs and NIST controls
4. **Add to `stig_mapper.py`:**
   ```python
   self.plugin_to_stig["PLUGIN_ID"] = STIGFinding(
       stig_id="V-######",
       rule_id="SV-######r######_rule",
       severity="CAT II",
       group_title="...",
       rule_title="...",
       check_content="...",
       fix_text="...",
       cci_references=["CCI-######"],
       nist_controls=["CM-6"]
   )
   ```
5. **Add unit test** to verify mapping

### Adding New NIST Mappings

1. **Identify the CVE or plugin family**
2. **Determine relevant NIST controls**
   - Reference: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
   - Review control catalog
3. **Add to `nist_mapper.py`:**
   ```python
   # For CVE mapping
   self.cve_to_controls["CVE-YYYY-####"] = ["AC-2", "IA-5"]

   # For family mapping
   self.family_to_controls["New Family"] = ["SI-2", "CM-6"]
   ```
4. **Add unit test** to verify mapping

### Adding New CVEs to Database

1. **Retrieve CVE details from NVD**
   - URL: https://nvd.nist.gov/vuln/detail/CVE-YYYY-####
2. **Extract CVSS scores and vectors**
3. **Add to `cve_database.py`:**
   ```python
   self.cve_data["CVE-YYYY-####"] = CVEInfo(
       cve_id="CVE-YYYY-####",
       description="...",
       cvss_v3_score=7.5,
       cvss_v3_vector="CVSS:3.1/...",
       cwe_ids=["CWE-###"],
       published_date="YYYY-MM-DD",
       # ... other fields
   )
   ```
4. **Add unit test** to verify presence

## Common Pitfalls

### 1. Assuming All Plugins Have STIG Mappings

**Problem:** Only a subset of Nessus plugins map to STIGs

**Solution:** Always check for `None` return values:
```python
finding = stig_mapper.get_stig_for_plugin(plugin_id)
if finding:
    # Use STIG data
else:
    # Fall back to generic categorization
```

### 2. Using Outdated STIG References

**Problem:** STIGs are updated quarterly

**Solution:** Document STIG version in comments:
```python
# Based on: Windows 10 STIG Version 2 Release 8 (2024-01-24)
self.plugin_to_stig["10863"] = STIGFinding(...)
```

### 3. Not Mapping Both Plugin ID and CVE

**Problem:** Missing mappings when CVE is available but plugin_id isn't mapped

**Solution:** Always provide both mappings when possible:
```python
# Map by plugin ID
self.plugin_to_stig["10863"] = stig_finding

# Also map by CVE if applicable
self.cve_to_stig["CVE-2017-0143"] = stig_finding
```

## Extending the Module

### External Configuration Support

**Proposed:** Load mappings from JSON/YAML files

```python
# config/stig_mappings.yaml
mappings:
  - plugin_id: "10863"
    stig_id: "V-220706"
    severity: "CAT II"
    # ... more fields

# Load in stig_mapper.py
def load_external_mappings(config_file: str):
    with open(config_file) as f:
        data = yaml.safe_load(f)
    for mapping in data["mappings"]:
        self.plugin_to_stig[mapping["plugin_id"]] = STIGFinding(**mapping)
```

### API Integration

**Proposed:** Sync with external databases (when online)

```python
def sync_with_nvd(self, api_key: str):
    """Sync CVE database with NVD API"""
    # Fetch latest CVE data
    # Update cve_data dictionary
    pass
```

## Related Modules

- **parser.nessus_parser** - Provides vulnerability data with plugin_id and CVE
- **processor.vulnerability_processor** - Provides analyzed vulnerability data
- **exporters.stig_exporter** - Primary consumer of STIG mappings
- **exporters.excel_exporter** - Uses compliance data for POAM columns

## Additional Resources

- **DISA STIG Library**: https://public.cyber.mil/stigs/
- **NIST SP 800-53 Rev 5**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **National Vulnerability Database**: https://nvd.nist.gov/
- **CCI List**: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
- **RMF Knowledge Service**: https://rmfks.osd.mil/

---

**Module Maintainer Notes:**
- Update STIG mappings quarterly (aligned with DISA releases)
- Verify NIST control accuracy against SP 800-53 Rev 5
- Document mapping sources and versions
- Maintain backward compatibility when adding new mappings
- Consider externalizing mappings in future releases
