# Processor Module Documentation

## Overview

The `processor` module is **Stage 2** of the vISSM pipeline. It analyzes parsed Nessus data to calculate risk scores, generate statistics, identify trends, and produce actionable recommendations.

**Primary Responsibility**: Transform raw vulnerability data into analyzed risk assessment intelligence.

## Module Structure

```
src/processor/
├── __init__.py                        # Empty module marker
└── vulnerability_processor.py         # Analysis engine (373 lines)
```

## Key Components

### Data Classes

#### 1. `VulnerabilitySummary`
High-level statistics about all vulnerabilities across all hosts.

**Fields:**
```python
total_vulnerabilities: int      # Total count of all findings
critical_count: int            # Severity 4 vulnerabilities
high_count: int               # Severity 3 vulnerabilities
medium_count: int             # Severity 2 vulnerabilities
low_count: int                # Severity 1 vulnerabilities
info_count: int               # Severity 0 vulnerabilities
severity_counts: Dict[int, int]     # {0: N, 1: N, 2: N, 3: N, 4: N}
family_counts: Dict[str, int]       # {"Windows": N, "Web Servers": N}
host_counts: Dict[str, int]         # {"192.168.1.10": N, ...}
```

**Usage:**
```python
summary = VulnerabilitySummary(
    total_vulnerabilities=234,
    critical_count=12,
    high_count=45,
    medium_count=89,
    low_count=67,
    info_count=21,
    severity_counts={0: 21, 1: 67, 2: 89, 3: 45, 4: 12},
    family_counts={"Windows": 120, "Web Servers": 45, ...},
    host_counts={"192.168.1.10": 23, "192.168.1.11": 19, ...}
)
```

#### 2. `HostSummary`
Per-host statistics and risk assessment.

**Fields:**
```python
hostname: str                  # Host identifier
ip: str                       # IP address
os: str                       # Operating system
critical_count: int           # CAT I vulnerabilities
high_count: int              # CAT II vulnerabilities
medium_count: int            # CAT III vulnerabilities
low_count: int               # Low severity
info_count: int              # Informational
total_vulnerabilities: int    # Total for this host
risk_score: float            # Calculated 0-100 risk score
```

**Usage:**
```python
host = HostSummary(
    hostname="server01.example.mil",
    ip="192.168.1.10",
    os="Windows Server 2019",
    critical_count=3,
    high_count=12,
    medium_count=18,
    low_count=8,
    info_count=2,
    total_vulnerabilities=43,
    risk_score=75.5
)
```

### Classes

#### `VulnerabilityProcessor`
Main analysis engine that processes `NessusReport` objects.

**Key Methods:**

##### `__init__(self, report: NessusReport)`
Initialize processor with parsed Nessus report.

**Parameters:**
- `report`: `NessusReport` object from parser module

##### `process(self) -> Dict[str, Any]`
Perform complete analysis and return comprehensive results.

**Returns:**
Dictionary with:
```python
{
    "summary": VulnerabilitySummary,
    "host_summaries": List[HostSummary],
    "top_vulnerabilities": List[Dict],
    "vulnerability_trends": Dict,
    "recommendations": List[str]
}
```

**Processing Pipeline:**
1. Calculate overall summary (`_calculate_summary()`)
2. Calculate per-host summaries (`_calculate_host_summaries()`)
3. Calculate risk scores (`_calculate_risk_scores()`)
4. Identify top vulnerabilities (`_get_top_vulnerabilities()`)
5. Analyze trends (`_analyze_trends()`)
6. Generate recommendations (`_generate_recommendations()`)

**Example:**
```python
processor = VulnerabilityProcessor(report)
analysis_data = processor.process()

print(f"Critical: {analysis_data['summary'].critical_count}")
print(f"High Risk Hosts: {[h.hostname for h in analysis_data['host_summaries'] if h.risk_score > 70]}")
```

##### `_calculate_summary(self) -> VulnerabilitySummary`
Calculate overall vulnerability statistics.

**Returns:**
- `VulnerabilitySummary` with aggregated counts

**Internal Logic:**
1. Initialize counters
2. Iterate through all hosts and vulnerabilities
3. Count by severity level
4. Count by plugin family
5. Count by host
6. Return summary object

##### `_calculate_host_summaries(self) -> List[HostSummary]`
Calculate per-host statistics.

**Returns:**
- List of `HostSummary` objects (one per host)

**Internal Logic:**
1. For each host in report:
   - Extract hostname, IP, OS
   - Count vulnerabilities by severity
   - Calculate total
   - Create `HostSummary` (risk_score = 0.0 initially)
2. Return list of summaries

##### `_calculate_risk_scores(self, host_summaries: List[HostSummary]) -> None`
Calculate and assign risk scores to hosts (modifies in place).

**Parameters:**
- `host_summaries`: List of `HostSummary` objects to update

**Risk Score Formula:**
```python
raw_score = (
    critical_count * 10 +  # CAT I: 10 points each
    high_count * 7 +       # CAT II: 7 points each
    medium_count * 4 +     # CAT III: 4 points each
    low_count * 2 +        # Low: 2 points each
    info_count * 1         # Info: 1 point each
)

# Normalize to 0-100 scale
max_possible = max(raw_score for all hosts)
risk_score = (raw_score / max_possible) * 100 if max_possible > 0 else 0
```

**Risk Levels:**
- **Critical** (80-100): Immediate action required
- **High** (60-79): Prompt remediation needed
- **Medium** (40-59): Schedule remediation
- **Low** (20-39): Routine maintenance
- **Minimal** (0-19): Low priority

##### `_get_top_vulnerabilities(self, limit: int = 10) -> List[Dict]`
Identify most common vulnerabilities across all hosts.

**Parameters:**
- `limit`: Number of top vulnerabilities to return (default: 10)

**Returns:**
List of dictionaries:
```python
[
    {
        "plugin_id": "10863",
        "plugin_name": "SMBv1 Enabled",
        "severity": 3,
        "count": 45,  # Number of hosts affected
        "family": "Windows"
    },
    # ... more
]
```

**Sorting:** By count (most common first), then by severity (highest first)

##### `_analyze_trends(self) -> Dict`
Analyze vulnerability distribution by plugin family.

**Returns:**
Dictionary of family-level statistics:
```python
{
    "Windows": {
        "count": 120,
        "critical": 8,
        "high": 35,
        "medium": 50,
        "low": 22,
        "info": 5
    },
    "Web Servers": {...},
    # ... more families
}
```

##### `_generate_recommendations(self) -> List[str]`
Generate actionable recommendations based on analysis.

**Returns:**
List of recommendation strings

**Recommendation Logic:**
1. **High critical count** (>10): "Address X critical vulnerabilities immediately"
2. **High high count** (>20): "Prioritize remediation of X high-severity vulnerabilities"
3. **Specific families**: "Focus on Windows/Web Server/etc. vulnerabilities"
4. **High-risk hosts**: "Isolate or prioritize hosts with risk scores >80"
5. **Patch management**: "Implement patch management for consistent updates"

**Example Output:**
```python
[
    "Address 12 critical vulnerabilities immediately (CAT I, 15-day timeline)",
    "Focus on Windows vulnerabilities (120 findings across 45 hosts)",
    "Implement regular patch management cycle for consistent updates",
    "Consider isolating hosts with risk scores above 80 until remediated"
]
```

### Functions

#### `process_nessus_report(report: NessusReport) -> Dict[str, Any]`
Convenience function for one-step processing.

**Parameters:**
- `report`: `NessusReport` object from parser

**Returns:**
- Analysis data dictionary (same as `VulnerabilityProcessor.process()`)

**Example:**
```python
from processor.vulnerability_processor import process_nessus_report

report = parse_nessus_file("scan.nessus")
analysis_data = process_nessus_report(report)
```

**This is the recommended way to use the processor.**

## Analysis Data Structure

### Complete Output Format

```python
analysis_data = {
    # Overall summary
    "summary": VulnerabilitySummary(
        total_vulnerabilities=234,
        critical_count=12,
        high_count=45,
        medium_count=89,
        low_count=67,
        info_count=21,
        severity_counts={...},
        family_counts={...},
        host_counts={...}
    ),

    # Per-host summaries
    "host_summaries": [
        HostSummary(...),  # Host 1
        HostSummary(...),  # Host 2
        # ...
    ],

    # Most common vulnerabilities
    "top_vulnerabilities": [
        {
            "plugin_id": "10863",
            "plugin_name": "SMBv1 Enabled",
            "severity": 3,
            "count": 45,
            "family": "Windows"
        },
        # ... top 10
    ],

    # Family-based trends
    "vulnerability_trends": {
        "Windows": {
            "count": 120,
            "critical": 8,
            "high": 35,
            "medium": 50,
            "low": 22,
            "info": 5
        },
        # ... other families
    },

    # Actionable recommendations
    "recommendations": [
        "Address 12 critical vulnerabilities immediately",
        "Focus on Windows vulnerabilities",
        # ... more recommendations
    ]
}
```

## Performance Characteristics

### Speed
- Small reports (1-10 hosts, 100-1000 vulns): < 0.1 seconds
- Medium reports (10-100 hosts, 1000-10000 vulns): 0.1-0.5 seconds
- Large reports (100-1000 hosts, 10000-100000 vulns): 0.5-2 seconds

### Memory Usage
- Negligible beyond the `NessusReport` object (already in memory from parser)
- Analysis data typically adds <1 MB

## Integration with Pipeline

### Upstream (Input)
- **NessusReport object** from `parser.nessus_parser`

### Downstream (Output)
- **analysis_data dict** → Used by all exporters:
  - `exporters.excel_exporter` (POAM, inventories, reports)
  - `exporters.stig_exporter` (STIG checklists)
  - `exporters.csv_exporter` (CSV summaries)
  - `exporters.html_exporter` (HTML reports)
  - `exporters.pdf_exporter` (PDF reports)

### Usage in CLI
```python
# From cli.py
report = parse_nessus_file(args.input_file)
analysis_data = process_nessus_report(report)

# Add the report back for exporters that need raw data
analysis_data["report"] = report

# Export to various formats
export_excel_poam(analysis_data, output_file)
```

## Testing

### Test Coverage
Located in `tests/test_vissm.py`:

1. **`test_vulnerability_processor_import()`** - Verify module imports
2. **`test_vulnerability_processor_analysis()`** - Verify analysis logic

### Example Test
```python
def test_vulnerability_processor_analysis(self):
    """Test vulnerability processor generates correct analysis"""
    # Create test report
    properties = HostProperties(
        hostname="test-host",
        ip="192.168.1.1",
        os="Windows 10"
    )

    vulns = [
        Vulnerability(
            plugin_id="10863",
            plugin_name="SMBv1 Enabled",
            family="Windows",
            severity=3,
            # ... other fields
        ),
        # ... more vulnerabilities
    ]

    host = ReportHost(
        name="192.168.1.1",
        properties=properties,
        vulnerabilities=vulns
    )

    report = NessusReport(
        policy_name="Test",
        scan_name="Test",
        scan_start="",
        scan_end="",
        hosts=[host],
        total_hosts=1,
        total_vulnerabilities=len(vulns)
    )

    # Process
    analysis_data = process_nessus_report(report)

    # Verify
    self.assertIn("summary", analysis_data)
    self.assertIn("host_summaries", analysis_data)
    self.assertEqual(len(analysis_data["host_summaries"]), 1)
```

## Risk Scoring Algorithm

### Formula Breakdown

The risk scoring system weighs vulnerabilities by severity:

```python
# Step 1: Calculate raw score
raw_score = (
    critical_count * 10 +  # CAT I vulnerabilities
    high_count * 7 +       # CAT II vulnerabilities
    medium_count * 4 +     # CAT III vulnerabilities
    low_count * 2 +        # Low severity
    info_count * 1         # Informational
)

# Step 2: Find maximum possible score across all hosts
max_score = max(raw_score for all hosts)

# Step 3: Normalize to 0-100 scale
if max_score > 0:
    risk_score = (raw_score / max_score) * 100
else:
    risk_score = 0  # No vulnerabilities
```

### Example Calculation

**Host A:**
- 3 critical
- 12 high
- 18 medium
- 8 low
- 2 info

```python
raw_score_A = (3*10) + (12*7) + (18*4) + (8*2) + (2*1)
            = 30 + 84 + 72 + 16 + 2
            = 204
```

**Host B:**
- 1 critical
- 5 high
- 10 medium
- 3 low
- 1 info

```python
raw_score_B = (1*10) + (5*7) + (10*4) + (3*2) + (1*1)
            = 10 + 35 + 40 + 6 + 1
            = 92
```

**Normalization:**
```python
max_score = max(204, 92) = 204

risk_score_A = (204 / 204) * 100 = 100.0  # Highest risk
risk_score_B = (92 / 204) * 100 = 45.1    # Medium risk
```

### Severity Weights Rationale

| Severity | Weight | Rationale |
|----------|--------|-----------|
| Critical (4) | 10 | CAT I, 15-day timeline, high impact |
| High (3) | 7 | CAT II, 30-day timeline, significant impact |
| Medium (2) | 4 | CAT III, 90-day timeline, moderate impact |
| Low (1) | 2 | Non-critical, low impact |
| Info (0) | 1 | Informational only, no security impact |

**Why not linear (4, 3, 2, 1, 0)?**
- Critical vulnerabilities are disproportionately important in DoD environments
- Weight distribution reflects DoD remediation timelines (15/30/90 days)
- Emphasizes CAT I/II findings in risk scoring

## Recommendation Generation Logic

### Trigger Thresholds

```python
# Critical vulnerabilities
if critical_count > 0:
    recommendations.append(
        f"Address {critical_count} critical vulnerabilities immediately "
        "(CAT I, 15-day timeline)"
    )

# High vulnerabilities
if high_count > 20:
    recommendations.append(
        f"Prioritize remediation of {high_count} high-severity vulnerabilities "
        "(CAT II, 30-day timeline)"
    )

# Family-specific
if family_count > 30:  # High concentration in one family
    recommendations.append(
        f"Focus on {family_name} vulnerabilities "
        f"({family_count} findings across multiple hosts)"
    )

# High-risk hosts
high_risk_hosts = [h for h in host_summaries if h.risk_score > 80]
if high_risk_hosts:
    recommendations.append(
        f"Consider isolating {len(high_risk_hosts)} hosts with risk scores above 80"
    )

# Always include patch management
recommendations.append(
    "Implement regular patch management cycle for consistent updates"
)
```

### Prioritization Order

1. **Critical vulnerabilities** - Always first if present
2. **High vulnerabilities** - If count >20
3. **Specific families** - If concentrated in one area
4. **High-risk hosts** - If any host has risk_score >80
5. **Patch management** - Always included as general guidance

## Design Decisions

### Why Separate Summary and Host Summaries?

**Summary** provides:
- Quick overview for executive reporting
- Aggregate statistics for reporting
- Family and severity distributions

**Host Summaries** provide:
- Per-asset risk assessment
- Targeted remediation planning
- Infrastructure segmentation insights

### Why Normalize Risk Scores?

**Benefits:**
- Consistent 0-100 scale across all scans
- Easy to interpret (percentage-like)
- Comparable across different scan sizes
- Aligns with common risk scoring systems

**Trade-off:**
- Relative scoring (dependent on worst host in scan)
- Not absolute (can't compare across different scans)

**Alternative considered:** Absolute scoring with fixed thresholds
- **Rejected because:** Would require defining arbitrary "maximum" vulnerability count

### Why Top 10 Vulnerabilities?

**Rationale:**
- Most common POAMs focus on top findings
- Pareto principle: 80% of risk often from 20% of issues
- Manageable list for prioritization

**Configurable via `limit` parameter** in `_get_top_vulnerabilities()`

## Common Pitfalls

### 1. Assuming All Hosts Have Same Risk

**Problem:** Risk scores are normalized; 100.0 means "highest in this scan", not "worst possible"

**Solution:** Use absolute counts alongside risk scores:
```python
print(f"Host risk: {host.risk_score:.1f}")
print(f"Critical: {host.critical_count}, High: {host.high_count}")
```

### 2. Comparing Risk Scores Across Scans

**Problem:** Risk scores are scan-relative

**Solution:** Don't compare scores from different scans; compare absolute counts instead

### 3. Not Using Recommendations

**Problem:** Recommendations are generated but often ignored

**Solution:** Display prominently in CLI output and reports

## Extending the Processor

### Adding New Metrics

Example: Add "average CVSS score" metric:

```python
@dataclass
class VulnerabilitySummary:
    # ... existing fields
    average_cvss: float = 0.0

# In _calculate_summary():
cvss_scores = []
for host in self.report.hosts:
    for vuln in host.vulnerabilities:
        if vuln.cvss_base_score:
            cvss_scores.append(float(vuln.cvss_base_score))

summary.average_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
```

### Adding New Recommendations

Example: Add recommendation for outdated OS:

```python
# In _generate_recommendations():
outdated_os = [
    h for h in self.host_summaries
    if "2012" in h.os or "2008" in h.os  # Outdated Windows versions
]

if outdated_os:
    recommendations.append(
        f"Upgrade {len(outdated_os)} hosts running outdated operating systems"
    )
```

### Custom Risk Scoring

Example: Add compliance-focused scoring:

```python
def _calculate_compliance_score(self, host_summary: HostSummary) -> float:
    """Calculate compliance score (0-100) based on CAT levels only"""
    # Only count CAT I/II/III
    cat_i = host_summary.critical_count
    cat_ii = host_summary.high_count
    cat_iii = host_summary.medium_count

    # Compliance: 100% - percentage of findings
    total_cat_findings = cat_i + cat_ii + cat_iii
    if total_cat_findings == 0:
        return 100.0  # Fully compliant

    # Deduct points based on CAT level
    deductions = (cat_i * 10) + (cat_ii * 5) + (cat_iii * 2)
    compliance_score = max(0, 100 - deductions)

    return compliance_score
```

## Troubleshooting

### Issue: All risk scores are 0.0

**Cause:** No vulnerabilities in scan

**Solution:** Check `total_vulnerabilities` in report

### Issue: Risk scores don't match expected values

**Cause:** Risk scores are scan-relative (normalized)

**Solution:** Review normalization logic; ensure understanding of relative scoring

### Issue: Recommendations seem generic

**Cause:** Thresholds not tuned for your environment

**Solution:** Adjust recommendation thresholds in `_generate_recommendations()`

### Issue: Processing is slow

**Cause:** Very large scan (>100,000 vulnerabilities)

**Solution:** Profile code with `cProfile`; consider optimizing loops

## Related Modules

- **parser.nessus_parser** - Provides `NessusReport` input
- **compliance.stig_mapper** - Uses vulnerability data for STIG mapping
- **compliance.nist_mapper** - Uses vulnerability data for NIST mapping
- **exporters.*** - All exporters consume processed analysis data

## Additional Resources

- **NIST SP 800-30**: Risk assessment guidance
- **CVSS v3.1**: Common Vulnerability Scoring System
- **DoD RMF**: Risk Management Framework process

---

**Module Maintainer Notes:**
- Risk scoring algorithm should remain stable across versions
- Changes to weighting should be documented in CHANGELOG
- Recommendation logic should be tunable without code changes (future: config file)
- Performance optimization should focus on large scan processing
