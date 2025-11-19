# Parser Module Documentation

## Overview

The `parser` module is **Stage 1** of the vISSM pipeline. It converts Tenable Nessus XML files (`.nessus` format) into Python dataclass objects for downstream processing.

**Primary Responsibility**: Extract vulnerability data from XML without analysis or transformation.

## Module Structure

```
src/parser/
├── __init__.py          # Empty module marker
└── nessus_parser.py     # Main parsing logic (249 lines)
```

## Key Components

### Data Classes

All data structures use Python dataclasses for type safety and clarity:

#### 1. `Vulnerability`
Represents a single vulnerability finding on a host.

**Fields:**
```python
plugin_id: str          # Nessus plugin ID (e.g., "10863")
plugin_name: str        # Human-readable name
family: str             # Plugin family (e.g., "Windows", "Web Servers")
severity: int           # 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
description: str        # Detailed vulnerability description
solution: str           # Remediation guidance
port: str              # Port number (e.g., "445")
protocol: str          # Protocol (e.g., "tcp")
service_name: str      # Service name (e.g., "smb")
cve: str              # CVE identifier if available
cvss_base_score: str  # CVSS score (e.g., "9.8")
cvss_vector: str      # CVSS vector string
plugin_output: str    # Raw output from the plugin
```

**Usage:**
```python
vuln = Vulnerability(
    plugin_id="10863",
    plugin_name="SMBv1 Enabled",
    severity=3,
    # ... other fields
)
```

#### 2. `HostProperties`
Metadata about a scanned host.

**Fields:**
```python
hostname: str          # Hostname (e.g., "server01.example.mil")
ip: str               # IP address (e.g., "192.168.1.10")
os: str = ""          # Operating system (e.g., "Windows Server 2019")
mac_address: str = "" # MAC address
fqdn: str = ""        # Fully qualified domain name
scan_start: str = ""  # Scan start timestamp
scan_end: str = ""    # Scan end timestamp
```

**Usage:**
```python
properties = HostProperties(
    hostname="server01",
    ip="192.168.1.10",
    os="Windows Server 2019"
)
```

#### 3. `ReportHost`
A host with all its vulnerability findings.

**Fields:**
```python
name: str                      # Host identifier (IP or hostname)
properties: HostProperties     # Host metadata
vulnerabilities: List[Vulnerability]  # All findings for this host
```

**Usage:**
```python
host = ReportHost(
    name="192.168.1.10",
    properties=properties,
    vulnerabilities=[vuln1, vuln2, ...]
)
```

#### 4. `NessusReport`
Complete scan report with all hosts and metadata.

**Fields:**
```python
policy_name: str           # Nessus scan policy name
scan_name: str             # Scan name
scan_start: str            # Scan start time
scan_end: str              # Scan end time
hosts: List[ReportHost]    # All scanned hosts
total_hosts: int           # Count of hosts
total_vulnerabilities: int # Total vulnerability count
```

**Usage:**
```python
report = NessusReport(
    policy_name="Internal Network Scan",
    scan_name="Weekly Vulnerability Scan",
    hosts=[host1, host2, ...],
    total_hosts=50,
    total_vulnerabilities=234
)
```

### Classes

#### `NessusParser`
Main parsing class that converts XML to dataclasses.

**Key Methods:**

##### `__init__(self, xml_file: str)`
Initialize parser with path to .nessus file.

**Parameters:**
- `xml_file`: Path to .nessus XML file

**Raises:**
- `FileNotFoundError`: If file doesn't exist
- `lxml.etree.XMLSyntaxError`: If XML is malformed

##### `parse(self) -> NessusReport`
Parse the Nessus file and return a complete report.

**Returns:**
- `NessusReport`: Fully populated report object

**Processing Steps:**
1. Parse XML file with lxml.etree
2. Extract policy and scan metadata
3. Iterate through `<ReportHost>` elements
4. For each host:
   - Parse `<HostProperties>` → `HostProperties` dataclass
   - Parse `<ReportItem>` elements → `Vulnerability` dataclasses
   - Create `ReportHost` object
5. Calculate totals
6. Return `NessusReport`

**Example:**
```python
parser = NessusParser("/path/to/scan.nessus")
report = parser.parse()
print(f"Found {report.total_vulnerabilities} vulnerabilities on {report.total_hosts} hosts")
```

### Functions

#### `parse_nessus_file(file_path: str) -> NessusReport`
Convenience function for one-step parsing.

**Parameters:**
- `file_path`: Path to .nessus file

**Returns:**
- `NessusReport`: Parsed report

**Example:**
```python
from parser.nessus_parser import parse_nessus_file

report = parse_nessus_file("scan.nessus")
```

**This is the recommended way to use the parser.**

## XML Structure Reference

### Nessus XML Format
```xml
<NessusClientData_v2>
  <Policy>
    <policyName>...</policyName>
    <!-- Policy details -->
  </Policy>

  <Report name="scan_name">
    <ReportHost name="192.168.1.10">
      <HostProperties>
        <tag name="host-ip">192.168.1.10</tag>
        <tag name="hostname">server01</tag>
        <tag name="operating-system">Windows Server 2019</tag>
        <!-- More tags -->
      </HostProperties>

      <ReportItem pluginID="10863" pluginName="SMBv1 Enabled" ...>
        <description>...</description>
        <solution>...</solution>
        <plugin_output>...</plugin_output>
        <cvss_base_score>9.8</cvss_base_score>
        <!-- More fields -->
      </ReportItem>

      <!-- More ReportItems -->
    </ReportHost>

    <!-- More ReportHosts -->
  </Report>
</NessusClientData_v2>
```

### Key XML Mappings

| XML Element | Dataclass Field | Notes |
|-------------|----------------|-------|
| `<ReportHost name="...">` | `ReportHost.name` | Host identifier |
| `<tag name="host-ip">` | `HostProperties.ip` | IP address |
| `<tag name="hostname">` | `HostProperties.hostname` | DNS hostname |
| `<tag name="operating-system">` | `HostProperties.os` | OS fingerprint |
| `<ReportItem pluginID="...">` | `Vulnerability.plugin_id` | Plugin identifier |
| `<ReportItem severity="...">` | `Vulnerability.severity` | 0-4 severity |
| `<description>` | `Vulnerability.description` | Full description |
| `<solution>` | `Vulnerability.solution` | Remediation steps |

## Severity Scale

The parser preserves Nessus severity levels as integers:

| Value | Nessus Level | Maps to CAT | Timeline |
|-------|--------------|-------------|----------|
| 0 | Info | N/A | N/A |
| 1 | Low | N/A | N/A |
| 2 | Medium | CAT III | 90 days |
| 3 | High | CAT II | 30 days |
| 4 | Critical | CAT I | 15 days |

**Note:** The mapping to CAT levels happens in the **compliance** module, not here.

## Error Handling

### Common Errors

1. **File Not Found**
   ```python
   parser = NessusParser("nonexistent.nessus")
   # Raises: FileNotFoundError
   ```

2. **Malformed XML**
   ```python
   parser = NessusParser("corrupted.nessus")
   report = parser.parse()
   # Raises: lxml.etree.XMLSyntaxError
   ```

3. **Empty Report**
   ```python
   report = parse_nessus_file("empty_scan.nessus")
   # Returns: NessusReport with hosts=[], total_vulnerabilities=0
   ```

### Best Practices

1. **Validate file exists before parsing:**
   ```python
   if not os.path.exists(file_path):
       raise FileNotFoundError(f"File not found: {file_path}")
   report = parse_nessus_file(file_path)
   ```

2. **Use try-except for robust error handling:**
   ```python
   try:
       report = parse_nessus_file(file_path)
   except FileNotFoundError:
       print(f"Error: File '{file_path}' not found")
   except Exception as e:
       print(f"Error parsing Nessus file: {e}")
   ```

3. **Check for empty reports:**
   ```python
   report = parse_nessus_file(file_path)
   if report.total_vulnerabilities == 0:
       print("Warning: No vulnerabilities found in scan")
   ```

## Performance Characteristics

### Speed
- Small scans (1-10 hosts): < 0.1 seconds
- Medium scans (10-100 hosts): 0.1-0.5 seconds
- Large scans (100-1000 hosts): 0.5-2 seconds
- Very large scans (1000+ hosts): 2-10 seconds

### Memory Usage
- Approximately 1-2 MB per 1000 vulnerabilities
- Entire report is loaded into memory (not streamed)
- For scans with >100,000 findings, consider splitting the .nessus file

## Integration with Pipeline

### Upstream (Input)
- **.nessus files** from Tenable Nessus scanner
- Exported via: Nessus Web UI → Scans → Export → .nessus format

### Downstream (Output)
- **NessusReport object** → `processor.vulnerability_processor.process_nessus_report()`

### Usage in CLI
```python
# From cli.py
report = parse_nessus_file(args.input_file)
analysis_data = process_nessus_report(report)
# ... export to various formats
```

## Testing

### Test Coverage
Located in `tests/test_vissm.py`:

1. **`test_nessus_parser_import()`** - Verify module imports correctly
2. **`test_nessus_parser_structure()`** - Verify dataclass creation

### Example Test
```python
def test_nessus_parser_structure(self):
    """Test that NessusReport can be created with expected structure"""
    # Create in-memory report
    properties = HostProperties(
        hostname="test-host",
        ip="192.168.1.1",
        os="Windows 10"
    )

    vuln = Vulnerability(
        plugin_id="12345",
        plugin_name="Test Vulnerability",
        family="Test Family",
        severity=3,
        description="Test description",
        solution="Test solution",
        port="80",
        protocol="tcp",
        service_name="http",
        cve="CVE-2020-1234",
        cvss_base_score="7.5",
        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        plugin_output="Test output"
    )

    host = ReportHost(
        name="192.168.1.1",
        properties=properties,
        vulnerabilities=[vuln]
    )

    report = NessusReport(
        policy_name="Test Policy",
        scan_name="Test Scan",
        scan_start="2024-01-01 00:00:00",
        scan_end="2024-01-01 01:00:00",
        hosts=[host],
        total_hosts=1,
        total_vulnerabilities=1
    )

    # Assertions
    self.assertEqual(report.total_hosts, 1)
    self.assertEqual(report.total_vulnerabilities, 1)
    self.assertEqual(len(report.hosts), 1)
```

## Design Decisions

### Why Dataclasses?
- **Type safety**: Catches errors at development time
- **Clarity**: Clear data contracts
- **Automatic methods**: `__init__`, `__repr__`, `__eq__` generated automatically
- **Immutability option**: Can freeze dataclasses if needed
- **Documentation**: Self-documenting data structures

### Why lxml over xml.etree.ElementTree?
- **Faster parsing** for large XML files
- **XPath support** for complex queries
- **Better error messages**
- **Namespace handling**

### Why Not Stream Parsing?
- **Simplicity**: Entire report fits in memory for typical scans
- **Random access**: Easier to reference hosts and vulnerabilities
- **Performance**: Not a bottleneck for target use cases

**Future consideration:** Add streaming parser for very large scans (>10,000 hosts).

## Common Pitfalls

### 1. Assuming All Fields Are Present
**Problem:** Not all Nessus plugins populate all fields.

**Solution:** Use default values in dataclasses:
```python
@dataclass
class Vulnerability:
    plugin_id: str
    plugin_name: str
    cve: str = ""  # May be empty
    cvss_base_score: str = ""  # May be empty
```

### 2. Confusing name vs hostname
**Problem:** `ReportHost.name` might be IP or hostname.

**Solution:** Always use `HostProperties.ip` for IP address, `HostProperties.hostname` for DNS name.

### 3. Not Validating Empty Scans
**Problem:** Scans with no vulnerabilities produce valid but empty reports.

**Solution:** Check `total_vulnerabilities` after parsing:
```python
if report.total_vulnerabilities == 0:
    print("Warning: No vulnerabilities found")
```

## Extending the Parser

### Adding New Fields

1. **Add field to dataclass:**
   ```python
   @dataclass
   class Vulnerability:
       # ... existing fields
       risk_factor: str = ""  # New field
   ```

2. **Extract from XML:**
   ```python
   # In NessusParser.parse()
   risk_factor = item.get("risk_factor", "")
   ```

3. **Update tests:**
   ```python
   vuln = Vulnerability(
       # ... existing fields
       risk_factor="High"
   )
   ```

### Adding New Data Classes

Example: Add `ScanStatistics` dataclass:

```python
@dataclass
class ScanStatistics:
    duration_seconds: int
    hosts_scanned: int
    plugins_used: int

@dataclass
class NessusReport:
    # ... existing fields
    statistics: ScanStatistics
```

## Troubleshooting

### Issue: "XMLSyntaxError: error parsing attribute name"
**Cause:** Corrupted .nessus file

**Solution:** Re-export from Nessus scanner

### Issue: "FileNotFoundError"
**Cause:** Incorrect path or file doesn't exist

**Solution:** Verify path with `os.path.exists()`

### Issue: Parser is slow
**Cause:** Very large .nessus file (>100MB)

**Solution:** Consider splitting scan or using chunked processing

### Issue: Missing vulnerability data
**Cause:** Nessus plugin didn't populate certain fields

**Solution:** This is expected; use default values in dataclasses

## Related Modules

- **processor.vulnerability_processor** - Consumes `NessusReport` objects
- **compliance.stig_mapper** - Uses `plugin_id` and `cve` fields
- **compliance.nist_mapper** - Uses `cve` and `family` fields
- **exporters.*** - All exporters consume processed data from `NessusReport`

## Additional Resources

- **Nessus XML Format**: Tenable documentation (proprietary)
- **lxml documentation**: https://lxml.de/
- **Python dataclasses**: https://docs.python.org/3/library/dataclasses.html

---

**Module Maintainer Notes:**
- Keep parser pure (no analysis logic)
- Preserve all Nessus data (even if not currently used)
- Maintain backward compatibility with .nessus format changes
- Document any Nessus version-specific quirks
