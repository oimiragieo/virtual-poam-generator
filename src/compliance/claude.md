# Compliance Module Documentation

## Overview

The `compliance` module is **Stage 3** of the vISSM pipeline. It maps vulnerabilities to DoD compliance frameworks including DISA STIGs, NIST 800-53 controls, and CVE databases.

**Primary Responsibility**: Provide compliance context and regulatory mappings for vulnerability findings.

## Module Structure

```
src/compliance/
├── __init__.py           # Module exports
├── stig_mapper.py       # DISA STIG mapping (245 lines)
├── nist_mapper.py       # NIST 800-53 Rev 5 mapping (237 lines)
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

### 2. NIST Mapper (`nist_mapper.py`)

Maps vulnerabilities to **NIST SP 800-53 Rev 5 security controls**.

#### Data Classes

##### `NISTControl`
Represents a NIST 800-53 security control.

**Fields:**
```python
control_id: str           # Control identifier (e.g., "AC-2")
control_name: str         # Full name (e.g., "Account Management")
family: str              # Control family (e.g., "Access Control")
priority: str            # "P1", "P2", or "P3"
baselines: List[str]     # ["LOW", "MODERATE", "HIGH"]
description: str         # Control description
related_controls: List[str]  # Related control IDs
```

**Example:**
```python
control = NISTControl(
    control_id="AC-2",
    control_name="Account Management",
    family="Access Control",
    priority="P1",
    baselines=["LOW", "MODERATE", "HIGH"],
    description="The organization manages information system accounts...",
    related_controls=["AC-3", "AC-5", "AU-9"]
)
```

#### Classes

##### `NISTMapper`
Main NIST control mapping class.

**Attributes:**

###### `cve_to_controls: Dict[str, List[str]]`
Maps CVE identifiers to NIST control IDs.

**Example Mappings:**
```python
"CVE-2014-0160": ["SC-13", "SC-23"],  # Heartbleed: Cryptographic Protection
"CVE-2017-0144": ["SC-7", "SC-8"],    # EternalBlue: Boundary Protection
"CVE-2021-44228": ["SI-2", "SI-10"]   # Log4Shell: Flaw Remediation
```

###### `family_to_controls: Dict[str, List[str]]`
Maps Nessus plugin families to relevant NIST controls.

**Example Mappings:**
```python
"Windows": ["CM-6", "SI-2", "IA-5"],
"Web Servers": ["SC-5", "SC-7", "SI-10"],
"Databases": ["SC-8", "SI-2", "AU-9"]
```

**Methods:**

###### `get_controls_for_cve(cve: str) -> List[NISTControl]`
Get NIST controls for a CVE.

**Parameters:**
- `cve`: CVE identifier

**Returns:**
- List of `NISTControl` objects

###### `get_controls_for_family(family: str) -> List[NISTControl]`
Get NIST controls for a plugin family.

**Parameters:**
- `family`: Nessus plugin family name

**Returns:**
- List of `NISTControl` objects

#### NIST Control Families

| Family Code | Family Name | Example Controls |
|-------------|-------------|------------------|
| **AC** | Access Control | AC-2 (Account Management) |
| **AU** | Audit and Accountability | AU-2 (Auditable Events) |
| **CM** | Configuration Management | CM-6 (Configuration Settings) |
| **IA** | Identification and Authentication | IA-5 (Authenticator Management) |
| **SC** | System and Communications Protection | SC-7 (Boundary Protection) |
| **SI** | System and Information Integrity | SI-2 (Flaw Remediation) |

#### RMF Baselines

**Impact Levels:**
- **LOW**: Minimal impact on operations, assets, or individuals
- **MODERATE**: Serious impact (most DoD systems)
- **HIGH**: Severe or catastrophic impact (critical DoD systems)

**Control Selection:**
```python
# All baselines include these controls
baseline_low = ["AC-2", "AC-3", "AU-2", "CM-6", "IA-2", "SI-2"]

# MODERATE adds more controls
baseline_moderate = baseline_low + ["AC-4", "AU-6", "CM-7", "SC-7"]

# HIGH adds comprehensive coverage
baseline_high = baseline_moderate + ["AC-6", "AU-9", "SC-8", "SI-4"]
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
