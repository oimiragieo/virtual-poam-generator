# Exporters Module Documentation

## Overview

The `exporters` module is **Stage 4** of the vISSM pipeline. It transforms processed vulnerability data into DoD-compliant report formats including Excel, CSV, HTML, PDF, and DISA STIG checklists.

**Primary Responsibility**: Generate formatted reports that meet DoD security documentation requirements and eMASS import standards.

## Module Structure

```
src/exporters/
├── __init__.py           # Module exports and public API
├── excel_exporter.py     # Excel report generation (945 lines, 7 report types)
├── stig_exporter.py      # DISA STIG Viewer .ckl format (166 lines)
├── csv_exporter.py       # CSV exports (189 lines)
├── html_exporter.py      # HTML reports (75 lines)
└── pdf_exporter.py       # PDF reports via WeasyPrint (90 lines)
```

## Pipeline Position

```
Stage 1: Parser → Stage 2: Processor → Stage 3: Compliance → Stage 4: Exporters
(XML Input)    (Dataclasses)       (Analysis)        (STIG/NIST)     (DoD Reports)
```

**Input:** `analysis_data` dictionary containing:
- `report`: NessusReport object (from parser)
- `host_summaries`: List of HostSummary objects (from processor)
- `stig_findings`: STIG mappings (from compliance module)
- `nist_controls`: NIST 800-53 controls (from compliance module)

**Output:** Formatted files (.xlsx, .xlsm, .ckl, .csv, .html, .pdf)

---

## 1. Excel Exporter (`excel_exporter.py`)

### Overview

The largest and most complex exporter. Generates 7 different Excel report types that match vISSM.exe output format and meet DoD/eMASS requirements.

**Dependencies:**
- `openpyxl`: Excel file manipulation
- `datetime`: Timestamp generation
- `typing`: Type hints

### Class: `ExcelExporter`

Main Excel report generator with timestamp-based filename generation.

**Attributes:**
```python
timestamp: str  # Format: "YYYY-MM-DD-HHMM" for unique filenames
```

**Initialization:**
```python
exporter = ExcelExporter()
# Creates timestamp: "2025-11-19-1430"
```

---

### Report Type 1: Vulnerability Report

**Method:** `export_vulnerability_report(analysis_data, output_path=None)`

Comprehensive vulnerability listing with all findings across all hosts.

**Default Filename:** `vISSM_Vulnerability_Report_2025-11-19-1430.xlsx`

**Worksheet:** "Vulnerability Report"

**Columns:**
| Column | Field | Description | Example |
|--------|-------|-------------|---------|
| A | IP | Host IP address | 192.168.1.10 |
| B | Hostname | DNS hostname | server01.example.mil |
| C | Plugin ID | Nessus plugin ID | 10863 |
| D | Plugin Name | Vulnerability name | SMBv1 Enabled |
| E | Severity | Risk level (0-4) | 3 |
| F | Family | Plugin family | Windows |
| G | Port | Affected port | 445 |
| H | Service | Service name | smb |
| I | Description | Detailed description | SMBv1 is enabled... |
| J | Solution | Remediation steps | Disable SMBv1 via... |
| K | CVE | CVE identifiers | CVE-2017-0144 |

**Formatting:**
- **Header Row**: Bold text, gray background (`CCCCCC`)
- **Column Width**: Auto-adjusted, max 50 characters
- **Data Rows**: One row per vulnerability per host (denormalized)

**Example Usage:**
```python
from src.exporters import export_excel_vulnerability_report

# Generate report
report_path = export_excel_vulnerability_report(
    analysis_data,
    output_path="reports/vulnerability_report.xlsx"
)
print(f"Report saved to: {report_path}")
```

**Row Count Calculation:**
```
Total Rows = (Number of Hosts × Avg Vulnerabilities per Host) + 1 header row

Example: 50 hosts × 20 vulns = 1,001 rows
```

---

### Report Type 2: POAM (Plan of Action & Milestones)

**Method:** `export_poam(analysis_data, output_path=None)`

eMASS-compliant POAM with classification banners and risk-based color coding.

**Default Filename:** `POAM_2025-11-19-1430.xlsx`

**Worksheet:** "POAM"

**Structure:**

**Classification Header (Row 1):**
```
***** UNCLASSIFIED//FOR OFFICIAL USE ONLY *****
```
- Merged across columns A-P
- **Font**: Bold, Red (`FF0000`)
- **Alignment**: Center

**Metadata (Rows 2-4):**
```
Row 2: Date Exported: 2025-11-19
Row 3: Information System: [Enter System Name]
Row 4: POAM Coordinator: [Enter Name]
```

**Data Headers (Row 6):**
| Column | Field | Width | Description |
|--------|-------|-------|-------------|
| A | POAM ID | 12 | Unique ID (POAM-0001) |
| B | Control ID | 15 | CVE or V-number |
| C | Weakness Name | 30 | Vulnerability name |
| D | Weakness Description | 40 | Truncated to 500 chars |
| E | Point of Contact | 20 | [Enter POC] |
| F | Resources Required | 25 | Staff time, patch mgmt |
| G | Scheduled Completion Date | 15 | Auto-calculated |
| H | Milestone | 25 | Remediate Cat X finding |
| I | Milestone Date | 15 | Same as completion |
| J | Risk | 12 | Very High/High/Moderate/Low |
| K | Status | 12 | Open |
| L | Comments | 40 | Scan details |
| M | Raw Severity | 12 | CAT I/II/III |
| N | Plugin ID | 12 | Nessus plugin ID |
| O | Affected Hosts | 30 | List (max 5) |
| P | Remediation | 40 | Truncated to 300 chars |

**Header Formatting:**
- **Font**: Bold, White (`FFFFFF`)
- **Background**: DoD Blue (`366092`)
- **Alignment**: Center, Vertical Center, Wrap Text
- **Borders**: Thin border on all sides

**Risk-Based Color Coding:**

| Risk Level | Background Color | Severity | Completion Days |
|------------|-----------------|----------|-----------------|
| **Very High** | Light Red (`FFC7CE`) | CAT I (4) | 15 days |
| **High** | Light Orange (`FFEB9C`) | CAT II (3) | 30 days |
| **Moderate** | White (default) | CAT III (2) | 90 days |
| **Low** | White (default) | Info (1) | 180 days |

**Deduplication Logic:**
```python
# Group vulnerabilities by plugin_id to avoid duplicates
vuln_groups = {}
for vuln in all_vulnerabilities:
    if vuln.severity >= 2:  # Only CAT I/II/III
        if vuln.plugin_id not in vuln_groups:
            vuln_groups[vuln.plugin_id] = {
                "vuln": vuln,
                "affected_hosts": []
            }
        vuln_groups[vuln.plugin_id]["affected_hosts"].append(host_info)
```

**Row Height:**
- Header: 40 points
- Data rows: 60 points (accommodate wrapped text)

**Scheduled Completion Date Calculation:**
```python
from datetime import datetime, timedelta

# CAT I: 15 days
if severity == 4:
    completion = datetime.now() + timedelta(days=15)

# CAT II: 30 days
elif severity == 3:
    completion = datetime.now() + timedelta(days=30)

# CAT III: 90 days
elif severity == 2:
    completion = datetime.now() + timedelta(days=90)
```

**Example:**
```python
from src.exporters import export_excel_poam

poam_path = export_excel_poam(
    analysis_data,
    output_path="poam/POAM_Q4_2025.xlsx"
)
```

---

### Report Type 3: IV&V Test Plan

**Method:** `export_ivv_test_plan(analysis_data, output_path=None)`

Independent Verification and Validation test plan for remediation testing.

**Default Filename:** `vISSM_IV&V_Test_Plan_2025-11-19-1430.xlsx`

**Worksheet:** "IV&V Test Plan"

**Columns:**
| Column | Field | Description |
|--------|-------|-------------|
| A | Test ID | Format: TEST-0001 |
| B | Test Name | Test {vulnerability name} |
| C | Test Description | Verify remediation of {vuln} on {host} |
| D | Expected Results | Vulnerability is remediated and no longer present |
| E | Test Steps | 3-step verification process |
| F | Pass/Fail Criteria | Pass: Not detected, Fail: Still present |
| G | Test Environment | Target: {IP} ({hostname}) |
| H | Test Data | Plugin ID: {plugin_id} |

**Test Generation Logic:**
```python
# Only generate tests for Critical and High severity
for vuln in vulnerabilities:
    if vuln.severity >= 3:  # Severity 3 (High) or 4 (Critical)
        create_test_case(vuln)
```

**Test Steps Template:**
```
1. Scan {IP address}
2. Verify {vulnerability name} is not detected
3. Document results
```

**Pass/Fail Criteria:**
```
Pass: Vulnerability not detected
Fail: Vulnerability still present
```

**Example Test Row:**
```
Test ID: TEST-0001
Test Name: Test SMBv1 Enabled
Test Description: Verify remediation of SMBv1 Enabled on server01.example.mil
Expected Results: Vulnerability is remediated and no longer present
Test Steps:
  1. Scan 192.168.1.10
  2. Verify SMBv1 Enabled is not detected
  3. Document results
Pass/Fail Criteria:
  Pass: Vulnerability not detected
  Fail: Vulnerability still present
Test Environment: Target: 192.168.1.10 (server01.example.mil)
Test Data: Plugin ID: 10863
```

---

### Report Type 4: CNET Report

**Method:** `export_cnet_report(analysis_data, output_path=None)`

Cyber Network Exploitation Team (CNET) report format.

**Default Filename:** `vISSM_CET_Report_2025-11-19-1430.xlsx`

**Note:** Uses same format as Vulnerability Report (columns A-K), but different naming convention.

**Worksheet:** "CNET Report"

**Purpose:** Tailored for CNET teams conducting network assessments and penetration testing support.

---

### Report Type 5: HW/SW Inventory

**Method:** `export_hw_sw_inventory(analysis_data, output_path=None)`

Detailed hardware and software inventory with multi-column software enumeration.

**Default Filename:** `vISSM_Detailed_Inventory_2025-11-19-1430.xlsx`

**Worksheets:**
1. **Windows Software (plugin 22869)**
2. **Linux Software (plugin 22869)**

**Column Structure (21 columns):**
- **Column A**: "IP and Hostname"
- **Columns B-U**: "Software Enumeration Output (Lines X-Y)" (20 columns, 20 lines each)

**Software Chunking:**
```python
# Split software list into 20-line chunks across 20 columns
for i in range(20):  # 20 columns
    start_idx = i * 20
    end_idx = min((i + 1) * 20, len(software_list))
    software_chunk = software_list[start_idx:end_idx]
    # Write to column i+2 (offset by 1 for IP/Hostname column)
```

**Sample Software List:**
```
Microsoft Windows 10 Enterprise
Microsoft Office Professional Plus 2016
Adobe Acrobat Reader DC
Google Chrome
Mozilla Firefox
Microsoft Visual C++ 2019 Redistributable
Java 8 Update 291
McAfee Endpoint Security
Citrix Receiver
Cisco AnyConnect Secure Mobility Client
```

**Note:** Currently uses simulated software data. In production, would parse Nessus plugin 22869 output.

---

### Report Type 6: eMASS Inventory

**Method:** `export_emass_inventory(analysis_data, output_path=None)`

Enterprise Mission Assurance Support Service (eMASS) import template.

**Default Filename:** `vISSM_eMASS_Inventory_2025-11-19-1430.xlsm`

**File Format:** `.xlsm` (Excel Macro-Enabled Workbook)

**Worksheets:**
1. **Hardware** - Asset inventory
2. **Software** - Software inventory
3. **Instructions** - Import guidance
4. **(U) Lists** - Dropdown validation lists

---

#### Worksheet 1: Hardware

**Classification Banner (Row 1):**
```
***** UNCLASSIFIED//FOR OFFICIAL USE ONLY *****
```

**Metadata (Rows 2-5):**
```
Row 2: Date Exported: | Exported By:
Row 3: (blank)
Row 4: Information System Owner: | POC Name: | Date Reviewed/Updated:
Row 5: System Name: | POC Phone: | Reviewed/Updated By:
```

**Data Headers (Row 7):**
| Column | Field | Description | Example |
|--------|-------|-------------|---------|
| A | Asset ID | Format: HW-0001 | HW-0001 |
| B | Hostname | DNS name | server01 |
| C | IP Address | IPv4 address | 192.168.1.10 |
| D | MAC Address | MAC address | N/A |
| E | Operating System | OS name/version | Windows 10 |
| F | Hardware Type | Workstation/Server/etc | Workstation |
| G | Manufacturer | Vendor name | Dell |
| H | Model | Model number | OptiPlex |
| I | Serial Number | Serial number | N/A |
| J | Location | Physical location | Office |
| K | Owner | Asset owner | User |
| L | Status | Active/Inactive | Active |
| M | Last Updated | Date (YYYY-MM-DD) | 2025-11-19 |
| N | Notes | Additional info | N/A |

**Hardware Type Dropdown (from (U) Lists sheet):**
- Workstation
- Server
- Switch
- Router
- Firewall
- Printer
- Scanner

---

#### Worksheet 2: Software

**Same classification banner and metadata structure as Hardware sheet.**

**Data Headers (Row 7):**
| Column | Field | Description | Example |
|--------|-------|-------------|---------|
| A | Asset ID | Format: SW-0001 | SW-0001 |
| B | Hostname | Associated host | server01 |
| C | Software Name | Full product name | Microsoft Windows 10 |
| D | Version | Version number | 10.0.19042 |
| E | Publisher | Vendor/publisher | Microsoft |
| F | Installation Date | Install date | 2021-01-01 |
| G | License Key | License key | N/A |
| H | License Type | OEM/Volume/Free | OEM |
| I | Status | Active/Inactive | Active |
| J | Last Updated | Date (YYYY-MM-DD) | 2025-11-19 |
| K | Notes | Additional info | N/A |

**Sample Software Entries:**
```python
software_list = [
    ("Microsoft Windows 10", "10.0.19042", "Microsoft", "2021-01-01", "N/A", "OEM", "Active"),
    ("Microsoft Office 2016", "16.0.4266.1001", "Microsoft", "2021-01-01", "N/A", "Volume", "Active"),
    ("Adobe Acrobat Reader", "21.001.20145", "Adobe", "2021-01-01", "N/A", "Free", "Active"),
    ("Google Chrome", "90.0.4430.93", "Google", "2021-01-01", "N/A", "Free", "Active"),
]
```

---

#### Worksheet 3: Instructions

**Import Template Instructions:**
```
1. Enter valid information into the fields on the Hardware/Software Import Template.
2. Do not delete columns/sheets, delete the classification label, or add additional
   columns. Doing so may have a negative impact on eMASS template ingestion.
3. The following fields/columns contain drop-down lists: Hardware Type, Software
   Type, Approval, Yes Or No.
4. If importing hardware information, the "Machine Name" field must be populated.
5. If importing software information, the "Software Name" field must be populated.
6. All required fields must be populated before importing into eMASS.
7. Review all data for accuracy before importing.
8. Contact your eMASS administrator if you have questions about the import process.
9. Save the file as an Excel workbook (.xlsx) before importing.
10. Do not modify the template structure or add additional columns.
```

---

#### Worksheet 4: (U) Lists

**Dropdown Validation Lists:**

| Column A | Column C | Column E | Column G |
|----------|----------|----------|----------|
| **Hardware Type** | **Software Type** | **Approval** | **Yes Or No** |
| Workstation | GOTS Application | In Progress | Yes |
| Server | COTS Application | Unapproved | No |
| Switch | Server Application | Approved - FIPS 140-2 | |
| Router | Web Application | Approved - NSA Crypto | |
| Firewall | Database | Approved - Common Criteria | |
| Printer | Operating System | Approved - Other | |
| Scanner | Utility | Not Applicable | |

**Usage:**
```python
from src.exporters import export_excel_emass_inventory

emass_path = export_excel_emass_inventory(
    analysis_data,
    output_path="emass/Inventory_Import.xlsm"
)
```

**eMASS Import Process:**
1. Complete all metadata fields (rows 2-5)
2. Validate dropdown selections
3. Save as .xlsx (remove macros if required)
4. Import via eMASS web interface
5. Review import logs for errors

---

### Report Type 7: STIG Checklist (Excel Format)

While the dedicated STIG exporter generates .ckl XML format, the Excel exporter can also generate STIG-style checklists for offline review.

**Note:** For official STIG submissions, use `stig_exporter.py` to generate DISA STIG Viewer compatible .ckl files.

---

## 2. STIG Exporter (`stig_exporter.py`)

### Overview

Generates DISA STIG Viewer compatible checklist files (.ckl format) in XML.

**Dependencies:**
- `src.compliance.stig_mapper.STIGMapper`: STIG mapping service
- `src.compliance.nist_mapper.NISTMapper`: NIST control mapping
- `datetime`: Timestamp generation

### Class: `STIGExporter`

**Attributes:**
```python
stig_mapper: STIGMapper  # STIG mapping service
nist_mapper: NISTMapper  # NIST mapping service
timestamp: str           # Filename timestamp
```

**Initialization:**
```python
exporter = STIGExporter()
# Automatically initializes mappers
```

---

### Method: `export_stig_checklist(analysis_data, output_path=None)`

Generate DISA STIG Viewer compatible .ckl file.

**Default Filename:** `STIG_Checklist_2025-11-19-1430.ckl`

**Input Processing:**
```python
# Collect plugin IDs and CVEs
plugin_ids = set()
cves = []

for host in report.hosts:
    for vuln in host.vulnerabilities:
        if vuln.severity >= 2:  # CAT II or higher only
            plugin_ids.add(vuln.plugin_id)
            if vuln.cve:
                cves.extend(vuln.cve.split(","))

# Map to STIG findings
stig_findings = []
for plugin_id in plugin_ids:
    stig = stig_mapper.get_stig_for_plugin(plugin_id)
    if stig:
        stig_findings.append(stig)
```

---

### CKL File Structure

**XML Declaration:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--DISA STIG Viewer Checklist File - Generated by vISSM-->
<CHECKLIST>
```

**Asset Information:**
```xml
<ASSET>
  <ROLE>None</ROLE>
  <ASSET_TYPE>Computing</ASSET_TYPE>
  <HOST_NAME></HOST_NAME>
  <HOST_IP></HOST_IP>
  <HOST_MAC></HOST_MAC>
  <HOST_FQDN></HOST_FQDN>
  <TECH_AREA></TECH_AREA>
  <TARGET_KEY>3425</TARGET_KEY>
  <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
  <WEB_DB_SITE></WEB_DB_SITE>
  <WEB_DB_INSTANCE></WEB_DB_INSTANCE>
</ASSET>
```

**STIG Information:**
```xml
<STIGS>
  <iSTIG>
    <STIG_INFO>
      <SI_DATA>
        <SID_NAME>version</SID_NAME>
        <SID_DATA>1</SID_DATA>
      </SI_DATA>
      <SI_DATA>
        <SID_NAME>releaseinfo</SID_NAME>
        <SID_DATA>Generated 2025-11-19</SID_DATA>
      </SI_DATA>
      <SI_DATA>
        <SID_NAME>title</SID_NAME>
        <SID_DATA>vISSM Automated STIG Checklist</SID_DATA>
      </SI_DATA>
    </STIG_INFO>
```

**Vulnerability Entry:**
```xml
<VULN>
  <STIG_DATA>
    <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
    <ATTRIBUTE_DATA>V-220706</ATTRIBUTE_DATA>
  </STIG_DATA>
  <STIG_DATA>
    <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
    <ATTRIBUTE_DATA>CAT II</ATTRIBUTE_DATA>
  </STIG_DATA>
  <STIG_DATA>
    <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
    <ATTRIBUTE_DATA>SRG-OS-000480-GPOS-00227</ATTRIBUTE_DATA>
  </STIG_DATA>
  <STIG_DATA>
    <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
    <ATTRIBUTE_DATA>SV-220706r569187_rule</ATTRIBUTE_DATA>
  </STIG_DATA>
  <STIG_DATA>
    <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
    <ATTRIBUTE_DATA>SMBv1 must be disabled</ATTRIBUTE_DATA>
  </STIG_DATA>
  <STIG_DATA>
    <VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>
    <ATTRIBUTE_DATA>CCI-000366</ATTRIBUTE_DATA>
  </STIG_DATA>
  <STATUS>Open</STATUS>
  <FINDING_DETAILS>Identified via automated Nessus vulnerability scan</FINDING_DETAILS>
  <COMMENTS></COMMENTS>
  <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
  <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
</VULN>
```

**Usage:**
```python
from src.exporters import export_stig_checklist

ckl_path = export_stig_checklist(
    analysis_data,
    output_path="stig/Windows_Server_2019_STIG.ckl"
)

# Import into DISA STIG Viewer
# File → Open Checklist → Select .ckl file
```

**DISA STIG Viewer Compatibility:**
- ✅ Version 2.x compatible
- ✅ Imports into eMASS
- ✅ Supports CCI references
- ✅ Preserves severity levels

---

## 3. CSV Exporter (`csv_exporter.py`)

### Overview

Exports vulnerability data to CSV format for spreadsheet analysis and database imports.

**Dependencies:**
- `csv`: Python standard library CSV writer
- `src.templates.template_engine`: Template rendering (optional)

### Class: `CSVExporter`

Simple CSV export with two methods: detailed report and summary.

---

### Method: `export(analysis_data, output_path)`

Export detailed vulnerability report to CSV.

**Columns:**
```
Host, IP, OS, Plugin ID, Plugin Name, Severity, Family, Port, Service, Description, Solution, CVE
```

**Example CSV Output:**
```csv
Host,IP,OS,Plugin ID,Plugin Name,Severity,Family,Port,Service,Description,Solution,CVE
server01,192.168.1.10,Windows 10,10863,SMBv1 Enabled,3,Windows,445,smb,"SMBv1 is enabled...","Disable SMBv1 via...",CVE-2017-0144
server01,192.168.1.10,Windows 10,21643,Weak Password Policy,2,Windows,0,general,"Password policy is weak...","Strengthen policy...",
```

**Truncation:**
- **Description**: Truncated to 500 characters + "..."
- **Solution**: Truncated to 200 characters + "..."

**Usage:**
```python
from src.exporters import export_csv_report

csv_path = export_csv_report(
    analysis_data,
    output_path="reports/vulnerabilities.csv"
)
```

---

### Method: `export_summary(analysis_data, output_path)`

Export host-level summary to CSV.

**Columns:**
```
Host, IP, OS, Total Vulns, Critical, High, Medium, Low, Info, Risk Score
```

**Example CSV Output:**
```csv
Host,IP,OS,Total Vulns,Critical,High,Medium,Low,Info,Risk Score
server01,192.168.1.10,Windows 10,45,2,8,15,12,8,72.5
server02,192.168.1.11,Windows 10,23,0,4,9,6,4,38.2
```

**Risk Score Calculation:**
```python
risk_score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
```

**Usage:**
```python
from src.exporters import export_csv_summary

summary_path = export_csv_summary(
    analysis_data,
    output_path="reports/host_summary.csv"
)
```

---

### Method: `export_to_string(analysis_data)`

Export to CSV string (no file written).

**Returns:** CSV-formatted string

**Usage:**
```python
csv_exporter = CSVExporter()
csv_string = csv_exporter.export_to_string(analysis_data)

# Use for in-memory processing
print(csv_string)
```

---

### Standalone Usage

**Test Script:**
```python
# From csv_exporter.py __main__ block
python csv_exporter.py sample.nessus output.csv
```

**Processing:**
1. Parse Nessus file
2. Process with vulnerability_processor
3. Export to CSV
4. Print output path

---

## 4. HTML Exporter (`html_exporter.py`)

### Overview

Generates HTML vulnerability reports using Jinja2 templates.

**Dependencies:**
- `src.templates.template_engine.render_html_report`: Template rendering engine

### Class: `HTMLExporter`

**Attributes:**
```python
template_dir: str  # Optional custom template directory
```

**Initialization:**
```python
# Default templates
exporter = HTMLExporter()

# Custom templates
exporter = HTMLExporter(template_dir="/path/to/templates")
```

---

### Method: `export(analysis_data, output_path)`

Export analysis data to HTML file.

**HTML Features:**
- Bootstrap 5 styling
- Responsive tables
- Severity color coding
- Interactive sorting (JavaScript)
- Print-friendly CSS

**Example HTML Structure:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Vulnerability Assessment Report</h1>

        <!-- Executive Summary -->
        <div class="card">
            <div class="card-body">
                <h2>Executive Summary</h2>
                <p>Total Hosts: 50</p>
                <p>Total Vulnerabilities: 1,234</p>
            </div>
        </div>

        <!-- Vulnerability Table -->
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Severity</th>
                    <th>Vulnerability</th>
                    <th>Solution</th>
                </tr>
            </thead>
            <tbody>
                <!-- Vulnerability rows -->
            </tbody>
        </table>
    </div>
</body>
</html>
```

**Severity Color Coding:**
```css
.severity-critical { background-color: #dc3545; color: white; }
.severity-high { background-color: #fd7e14; color: white; }
.severity-medium { background-color: #ffc107; }
.severity-low { background-color: #28a745; color: white; }
.severity-info { background-color: #17a2b8; color: white; }
```

**Usage:**
```python
from src.exporters import export_html_report

html_path = export_html_report(
    analysis_data,
    output_path="reports/vulnerability_report.html"
)

# Open in browser
import webbrowser
webbrowser.open(html_path)
```

---

### Method: `export_to_string(analysis_data)`

Export to HTML string (no file written).

**Returns:** HTML-formatted string

**Usage:**
```python
exporter = HTMLExporter()
html_string = exporter.export_to_string(analysis_data)

# Serve via web framework
from flask import Flask, Response
app = Flask(__name__)

@app.route('/report')
def report():
    return Response(html_string, mimetype='text/html')
```

---

## 5. PDF Exporter (`pdf_exporter.py`)

### Overview

Generates PDF vulnerability reports using WeasyPrint HTML-to-PDF conversion.

**Dependencies:**
- `weasyprint`: HTML to PDF converter (optional)
- `src.templates.template_engine.render_pdf_report`: PDF-optimized template rendering

### Class: `PDFExporter`

**Attributes:**
```python
template_dir: str  # Optional custom template directory
```

**Initialization:**
```python
exporter = PDFExporter()
```

---

### Method: `export(analysis_data, output_path)`

Export analysis data to PDF file.

**Processing:**
1. Render HTML with PDF-optimized template
2. Check for WeasyPrint availability
3. If available: Convert HTML to PDF
4. If not available: Save HTML fallback

**WeasyPrint Conversion:**
```python
from weasyprint import HTML
from weasyprint.text.fonts import FontConfiguration

font_config = FontConfiguration()
html_doc = HTML(string=html_content)
html_doc.write_pdf(output_path, font_config=font_config)
```

**Fallback Behavior:**
```python
# If WeasyPrint not installed
html_path = output_path.replace(".pdf", ".html")
with open(html_path, "w") as f:
    f.write(html_content)

print("WeasyPrint not available. HTML saved to: {html_path}")
print("You can open this file in a browser and print to PDF.")
```

**PDF Features:**
- Page breaks at logical sections
- Header/footer on each page
- Print-optimized styling
- Embedded fonts
- Clickable table of contents (if supported)

**Page Layout:**
```css
@page {
    size: Letter;
    margin: 1in;

    @top-center {
        content: "Vulnerability Assessment Report";
    }

    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
    }
}
```

**Usage:**
```python
from src.exporters import export_pdf_report

pdf_path = export_pdf_report(
    analysis_data,
    output_path="reports/vulnerability_report.pdf"
)
```

**Installing WeasyPrint:**
```bash
# Install WeasyPrint with dependencies
pip install weasyprint

# macOS additional dependencies
brew install cairo pango gdk-pixbuf libffi

# Ubuntu/Debian
sudo apt-get install python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0
```

---

## DoD Formatting Requirements

### Classification Banners

**Standard Banner Format:**
```
***** UNCLASSIFIED//FOR OFFICIAL USE ONLY *****
```

**Placement:**
- **Row 1**: Always the first row, merged across all columns
- **Alignment**: Center-aligned
- **Font**: Bold, Red (`FF0000`)

**Other Classification Levels:**
```
***** SECRET *****
***** TOP SECRET *****
***** CONFIDENTIAL *****
***** UNCLASSIFIED *****
```

**For Official Use Only (FOUO):**
```
//FOR OFFICIAL USE ONLY
```

### Color Coding Standards

**Severity Colors (Consistent across all reports):**

| Severity | Background | Text | Hex Code |
|----------|------------|------|----------|
| Critical | Light Red | Black | FFC7CE |
| High | Light Orange | Black | FFEB9C |
| Medium | Yellow | Black | FFFF99 |
| Low | Light Green | Black | C6EFCE |
| Info | Light Blue | Black | DDEBF7 |

**DoD Blue (Headers):**
- **Background**: `366092`
- **Text**: White (`FFFFFF`)

**Gray (Column Headers):**
- **Background**: `CCCCCC`
- **Text**: Black (default)

### eMASS Compliance

**Required Fields for eMASS Import:**

**Hardware:**
- Asset ID (required)
- Hostname (required for hardware)
- IP Address
- Hardware Type (dropdown validated)

**Software:**
- Asset ID (required)
- Software Name (required for software)
- Version
- Software Type (dropdown validated)

**Validation Rules:**
1. No blank required fields
2. Dropdown values must match (U) Lists sheet
3. Date format: YYYY-MM-DD
4. Asset IDs must be unique
5. Classification banner must not be deleted

**Import Process:**
1. eMASS → Assets → Import
2. Select template type (Hardware/Software)
3. Upload .xlsx file (not .xlsm)
4. Review validation errors
5. Confirm import

### Border and Alignment Standards

**Header Cells:**
```python
cell.border = Border(
    left=Side(style="thin"),
    right=Side(style="thin"),
    top=Side(style="thin"),
    bottom=Side(style="thin")
)
cell.alignment = Alignment(
    horizontal="center",
    vertical="center",
    wrap_text=True
)
```

**Data Cells:**
```python
cell.alignment = Alignment(
    vertical="top",
    wrap_text=True
)
```

---

## Common Formatting Patterns

### Pattern 1: Auto-Adjust Column Width

**Implementation:**
```python
for column in worksheet.columns:
    max_length = 0
    column_letter = column[0].column_letter

    for cell in column:
        try:
            if len(str(cell.value)) > max_length:
                max_length = len(str(cell.value))
        except Exception:
            pass

    adjusted_width = min(max_length + 2, 50)  # Max 50 chars
    worksheet.column_dimensions[column_letter].width = adjusted_width
```

**Purpose:** Ensure all content is visible without excessive white space.

---

### Pattern 2: Ensure Output Directory Exists

**Implementation:**
```python
output_dir = os.path.dirname(output_path)
if output_dir:
    os.makedirs(output_dir, exist_ok=True)
```

**Purpose:** Prevent errors when writing to subdirectories.

**Example:**
```python
# Works even if "reports/q4/" doesn't exist
export_poam(data, "reports/q4/POAM_November.xlsx")
```

---

### Pattern 3: Timestamp-Based Filenames

**Implementation:**
```python
from datetime import datetime

timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
default_filename = f"POAM_{timestamp}.xlsx"
# Result: "POAM_2025-11-19-1430.xlsx"
```

**Purpose:** Prevent filename collisions, maintain version history.

---

### Pattern 4: Safe String Truncation

**Implementation:**
```python
# Truncate description to 500 characters
truncated = (
    description[:500] + "..."
    if len(description) > 500
    else description
)
```

**Purpose:** Prevent cell overflow, maintain readability.

---

### Pattern 5: Severity-Based Filtering

**Implementation:**
```python
# Only include CAT I/II/III (exclude Info)
for vuln in vulnerabilities:
    if vuln.severity >= 2:  # 2=Medium, 3=High, 4=Critical
        process_vulnerability(vuln)
```

**Purpose:** Focus on actionable findings.

---

### Pattern 6: Deduplication by Plugin ID

**Implementation:**
```python
vuln_groups = {}

for host in hosts:
    for vuln in host.vulnerabilities:
        if vuln.plugin_id not in vuln_groups:
            vuln_groups[vuln.plugin_id] = {
                "vuln": vuln,
                "affected_hosts": []
            }
        vuln_groups[vuln.plugin_id]["affected_hosts"].append(host.name)

# Now each plugin_id appears once with list of affected hosts
```

**Purpose:** Consolidate duplicate findings across hosts (POAM format).

---

## Integration with Pipeline

### Stage 1: Parser Output

**Parser provides:**
```python
report = NessusReport(
    policy_name="...",
    scan_name="...",
    hosts=[...],
    total_hosts=50,
    total_vulnerabilities=1234
)
```

---

### Stage 2: Processor Output

**Processor provides:**
```python
analysis_data = {
    "report": report,  # NessusReport object
    "host_summaries": [HostSummary(...)],
    "executive_summary": ExecutiveSummary(...),
    "severity_distribution": {...}
}
```

---

### Stage 3: Compliance Output

**Compliance module adds:**
```python
analysis_data["stig_findings"] = [STIGFinding(...), ...]
analysis_data["nist_controls"] = [NISTControl(...), ...]
analysis_data["cve_mappings"] = {...}
```

---

### Stage 4: Exporters Consume

**All exporters expect:**
```python
analysis_data: Dict[str, Any] = {
    "report": NessusReport,           # From parser
    "host_summaries": List[HostSummary],  # From processor
    "stig_findings": List[STIGFinding],   # From compliance (optional)
    "nist_controls": List[NISTControl],   # From compliance (optional)
}
```

**Example Full Pipeline:**
```python
from src.parser import parse_nessus_file
from src.processor import process_nessus_report
from src.compliance import map_stig_findings, map_nist_controls
from src.exporters import (
    export_excel_poam,
    export_stig_checklist,
    export_csv_report
)

# Stage 1: Parse
report = parse_nessus_file("scan.nessus")

# Stage 2: Process
analysis_data = process_nessus_report(report)
analysis_data["report"] = report

# Stage 3: Compliance (optional)
analysis_data["stig_findings"] = map_stig_findings(report)
analysis_data["nist_controls"] = map_nist_controls(report)

# Stage 4: Export
export_excel_poam(analysis_data, "POAM.xlsx")
export_stig_checklist(analysis_data, "STIG.ckl")
export_csv_report(analysis_data, "report.csv")
```

---

## Testing Approach

### Unit Testing

**Test Structure:**
```python
# tests/test_exporters/test_excel_exporter.py
import pytest
from src.exporters.excel_exporter import ExcelExporter
from openpyxl import load_workbook

def test_poam_export():
    exporter = ExcelExporter()
    output_path = exporter.export_poam(sample_data, "test_poam.xlsx")

    # Load and validate
    wb = load_workbook(output_path)
    ws = wb.active

    # Check classification banner
    assert ws.cell(1, 1).value == "***** UNCLASSIFIED//FOR OFFICIAL USE ONLY *****"
    assert ws.cell(1, 1).font.color.rgb == "FFFF0000"  # Red

    # Check header row
    assert ws.cell(6, 1).value == "POAM ID"
    assert ws.cell(6, 1).fill.start_color.rgb == "FF366092"  # DoD Blue

    # Check data row
    assert ws.cell(7, 1).value.startswith("POAM-")

    os.remove(output_path)
```

**Test Coverage:**
- ✅ File creation
- ✅ Classification banners
- ✅ Header formatting
- ✅ Data population
- ✅ Color coding
- ✅ Column widths
- ✅ Row heights
- ✅ Deduplication logic

---

### Integration Testing

**Test Full Pipeline:**
```python
def test_full_pipeline():
    # Parse real .nessus file
    report = parse_nessus_file("tests/fixtures/sample.nessus")

    # Process
    analysis_data = process_nessus_report(report)
    analysis_data["report"] = report

    # Export all formats
    poam_path = export_excel_poam(analysis_data)
    ckl_path = export_stig_checklist(analysis_data)
    csv_path = export_csv_report(analysis_data, "report.csv")

    # Validate files exist
    assert os.path.exists(poam_path)
    assert os.path.exists(ckl_path)
    assert os.path.exists(csv_path)

    # Validate CKL XML
    import xml.etree.ElementTree as ET
    tree = ET.parse(ckl_path)
    root = tree.getroot()
    assert root.tag == "CHECKLIST"
```

---

### Manual Testing

**Visual Validation:**
1. Open exported Excel files in Microsoft Excel
2. Verify classification banners are visible
3. Check color coding matches severity
4. Confirm dropdown lists work (eMASS template)
5. Test print preview for page breaks

**STIG Viewer Testing:**
1. Export .ckl file
2. Open in DISA STIG Viewer
3. Verify findings load correctly
4. Check CCI references
5. Validate severity mappings

**eMASS Import Testing:**
1. Export eMASS inventory template
2. Complete metadata fields
3. Import into eMASS sandbox
4. Review validation errors
5. Confirm data appears correctly

---

## Design Decisions

### 1. Openpyxl over XlsxWriter

**Chosen:** `openpyxl`

**Rationale:**
- More Pythonic API
- Better cell formatting control
- Active development
- Excel 2010+ feature support

**Alternative:** `xlsxwriter` (write-only, faster for large files)

---

### 2. Timestamp in Filename

**Implementation:**
```python
timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
```

**Rationale:**
- Prevent overwrite of previous exports
- Maintain audit trail
- Sortable by filename

**Alternative:** Sequential numbering (requires state tracking)

---

### 3. Deduplication in POAM

**Implementation:** Group by `plugin_id`, list affected hosts

**Rationale:**
- POAM tracks remediation actions, not individual findings
- One remediation effort can fix multiple hosts
- Reduces POAM item count

**Alternative:** Separate POAM item per host (verbose, harder to manage)

---

### 4. Hard-Coded Software Lists

**Current:** Simulated software lists in HW/SW Inventory

**Rationale:**
- Nessus plugin 22869 output is complex to parse
- Focus on report structure over data accuracy
- Placeholder for future enhancement

**Future:** Parse actual plugin output

---

### 5. WeasyPrint Optional Dependency

**Implementation:** Try/except with HTML fallback

**Rationale:**
- WeasyPrint has complex system dependencies
- Not all environments can install it
- HTML fallback provides graceful degradation

**Alternative:** Require WeasyPrint (breaks on some systems)

---

### 6. Template Engine Integration

**Implementation:** HTML/PDF exporters use `template_engine.py`

**Rationale:**
- Separation of concerns (logic vs. presentation)
- Easy template customization
- Supports Jinja2 templating

**Alternative:** Hard-coded HTML strings (not maintainable)

---

### 7. Severity Filtering in Exports

**POAM:** `severity >= 2` (CAT I/II/III)
**IV&V Test Plan:** `severity >= 3` (Critical/High only)

**Rationale:**
- POAMs track all actionable findings
- Test plans focus on high-risk items
- Info findings don't require POAMs

---

## Extension Points

### 1. Custom Excel Templates

**Current:** Hard-coded formatting

**Extension:**
```python
class CustomExcelExporter(ExcelExporter):
    def __init__(self, template_path: str):
        super().__init__()
        self.template = load_workbook(template_path)

    def export_poam(self, analysis_data, output_path=None):
        wb = self.template.copy()
        # Populate template worksheets
        # ...
```

---

### 2. Additional Report Types

**Add new Excel report:**
```python
def export_risk_matrix(self, analysis_data, output_path=None):
    """Export risk assessment matrix"""
    wb = Workbook()
    ws = wb.active
    ws.title = "Risk Matrix"

    # Create 5x5 risk matrix
    # Likelihood (rows) vs Impact (columns)
    # ...

    wb.save(output_path)
    return output_path
```

---

### 3. Multi-Format Export

**Batch export all formats:**
```python
def export_all_formats(analysis_data, output_dir="reports"):
    """Export to all supported formats"""
    exporter = ExcelExporter()

    return {
        "poam": exporter.export_poam(analysis_data, f"{output_dir}/POAM.xlsx"),
        "vulnerability": exporter.export_vulnerability_report(analysis_data, f"{output_dir}/Vulnerabilities.xlsx"),
        "ivv": exporter.export_ivv_test_plan(analysis_data, f"{output_dir}/IVV_Test_Plan.xlsx"),
        "cnet": exporter.export_cnet_report(analysis_data, f"{output_dir}/CNET_Report.xlsx"),
        "inventory": exporter.export_hw_sw_inventory(analysis_data, f"{output_dir}/Inventory.xlsx"),
        "emass": exporter.export_emass_inventory(analysis_data, f"{output_dir}/eMASS_Inventory.xlsm"),
        "stig": export_stig_checklist(analysis_data, f"{output_dir}/STIG_Checklist.ckl"),
        "csv": export_csv_report(analysis_data, f"{output_dir}/Report.csv"),
        "html": export_html_report(analysis_data, f"{output_dir}/Report.html"),
        "pdf": export_pdf_report(analysis_data, f"{output_dir}/Report.pdf"),
    }
```

---

### 4. Custom Column Mappings

**Configurable columns:**
```python
class ConfigurableCSVExporter(CSVExporter):
    def __init__(self, column_map: Dict[str, str]):
        super().__init__()
        self.column_map = column_map

    def export(self, analysis_data, output_path):
        # Use column_map to customize CSV columns
        # ...
```

---

### 5. Database Export

**Export to SQL database:**
```python
def export_to_database(analysis_data, db_connection):
    """Export findings to SQL database"""
    import sqlite3

    conn = sqlite3.connect(db_connection)
    cursor = conn.cursor()

    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            host TEXT,
            ip TEXT,
            plugin_id TEXT,
            severity INTEGER,
            -- ...
        )
    """)

    # Insert findings
    for host_summary in analysis_data["host_summaries"]:
        # Insert rows
        # ...

    conn.commit()
    conn.close()
```

---

### 6. Cloud Storage Integration

**Upload to S3:**
```python
def export_and_upload(analysis_data, s3_bucket, s3_key):
    """Export and upload to AWS S3"""
    import boto3

    # Export locally
    local_path = export_excel_poam(analysis_data)

    # Upload to S3
    s3 = boto3.client('s3')
    s3.upload_file(local_path, s3_bucket, s3_key)

    # Clean up local file
    os.remove(local_path)

    return f"s3://{s3_bucket}/{s3_key}"
```

---

## Troubleshooting

### Issue 1: openpyxl Import Error

**Error:**
```
ModuleNotFoundError: No module named 'openpyxl'
```

**Solution:**
```bash
pip install openpyxl
```

---

### Issue 2: WeasyPrint Installation Fails

**Error:**
```
ERROR: Failed building wheel for weasyprint
```

**Solution:**
```bash
# macOS
brew install cairo pango gdk-pixbuf libffi
pip install weasyprint

# Ubuntu/Debian
sudo apt-get install python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
pip install weasyprint

# If still fails, use HTML fallback
# PDF exporter will automatically save as HTML
```

---

### Issue 3: Classification Banner Not Red

**Problem:** Classification banner text is black instead of red

**Solution:**
```python
from openpyxl.styles import Font

# Ensure RGB format includes alpha channel
cell.font = Font(bold=True, color="FFFF0000")  # Not "FF0000"
```

**Explanation:** openpyxl requires 8-digit ARGB format (alpha + RGB).

---

### Issue 4: Column Width Too Narrow

**Problem:** Text is cut off in Excel cells

**Solution:**
```python
# Increase max width
adjusted_width = min(max_length + 2, 75)  # Increase from 50 to 75

# Or disable max width
adjusted_width = max_length + 2  # No limit (use with caution)
```

---

### Issue 5: eMASS Import Validation Errors

**Error:** "Required field missing"

**Solution:**
1. Check metadata rows (2-5) are populated
2. Verify dropdown values match (U) Lists sheet exactly
3. Ensure date format is YYYY-MM-DD
4. Confirm Asset IDs are unique
5. Don't delete classification banner

**Common Mistakes:**
- Using "Laptop" instead of "Workstation" (not in dropdown)
- Date format MM/DD/YYYY instead of YYYY-MM-DD
- Blank hostname for hardware
- Blank software name for software

---

### Issue 6: STIG Viewer Can't Open .ckl File

**Error:** "Invalid checklist file"

**Solution:**
1. Validate XML structure:
```bash
xmllint --noout STIG_Checklist.ckl
```

2. Check for special characters in XML:
```python
# Escape XML special characters
import xml.sax.saxutils as saxutils
escaped_text = saxutils.escape(text)
```

3. Ensure UTF-8 encoding:
```python
with open(output_path, "w", encoding="utf-8") as f:
    f.write(ckl_content)
```

---

### Issue 7: Excel File Corrupted

**Error:** "Excel cannot open the file because the format or extension is not valid"

**Solution:**
1. Check file was fully written:
```python
wb.save(output_path)
wb.close()  # Ensure file is closed
```

2. Verify no exception during export:
```python
try:
    export_excel_poam(data, path)
except Exception as e:
    print(f"Export failed: {e}")
    raise
```

3. Test with openpyxl:
```python
from openpyxl import load_workbook
wb = load_workbook(output_path)  # Should not raise exception
```

---

### Issue 8: Memory Error on Large Reports

**Error:**
```
MemoryError: Unable to allocate array
```

**Solution:**
```python
# Use xlsxwriter for write-only large files
from xlsxwriter import Workbook

wb = Workbook(output_path, {'constant_memory': True})
ws = wb.add_worksheet()

# Write data
for i, row in enumerate(large_dataset):
    ws.write_row(i, 0, row)

wb.close()
```

**Threshold:** openpyxl works well up to ~100k rows, use xlsxwriter for larger datasets.

---

### Issue 9: CSV UTF-8 Encoding Issues

**Error:** Special characters display incorrectly (e.g., "â€™" instead of "'")

**Solution:**
```python
with open(output_path, "w", newline="", encoding="utf-8-sig") as csvfile:
    writer = csv.writer(csvfile)
    # Write data
```

**Explanation:** `utf-8-sig` adds BOM (Byte Order Mark) for Excel compatibility.

---

### Issue 10: PDF Fonts Missing

**Error:** PDF displays squares instead of text

**Solution:**
```python
# Install system fonts
# macOS
brew install fontconfig

# Ubuntu
sudo apt-get install fonts-liberation

# Or specify custom fonts in CSS
@font-face {
    font-family: 'DejaVu Sans';
    src: url('/path/to/DejaVuSans.ttf');
}
```

---

## Quick Reference

### Public API Functions

```python
# Excel exports
from src.exporters import (
    export_excel_vulnerability_report,
    export_excel_poam,
    export_excel_ivv_test_plan,
    export_excel_cnet_report,
    export_excel_hw_sw_inventory,
    export_excel_emass_inventory,
)

# Other formats
from src.exporters import (
    export_csv_report,
    export_csv_summary,
    export_html_report,
    export_pdf_report,
    export_stig_checklist,
)
```

### Severity Mapping

| Nessus | DoD CAT | Risk Level | POAM Days | Color |
|--------|---------|------------|-----------|-------|
| 4 | CAT I | Very High | 15 | Red (FFC7CE) |
| 3 | CAT II | High | 30 | Orange (FFEB9C) |
| 2 | CAT III | Moderate | 90 | White |
| 1 | N/A | Low | 180 | White |
| 0 | N/A | Info | N/A | White |

### File Extensions

| Format | Extension | Description |
|--------|-----------|-------------|
| Excel | .xlsx | Standard Excel workbook |
| Excel Macro | .xlsm | Excel with macros (eMASS template) |
| CSV | .csv | Comma-separated values |
| HTML | .html | Web page |
| PDF | .pdf | Portable document format |
| STIG | .ckl | DISA STIG Viewer checklist |

### Color Codes

| Color | Hex | Usage |
|-------|-----|-------|
| DoD Blue | 366092 | Headers |
| Red | FF0000 | Classification banners |
| Gray | CCCCCC | Column headers |
| Light Red | FFC7CE | Critical severity |
| Light Orange | FFEB9C | High severity |
| White | FFFFFF | Default |

---

## Summary

The exporters module transforms vulnerability data into DoD-compliant reports across 5 different formats and 10+ report types. Key features:

1. **Excel Exporter**: 7 report types (POAM, Vulnerability, IV&V, CNET, Inventory, eMASS)
2. **STIG Exporter**: DISA STIG Viewer .ckl format with CCI references
3. **CSV Exporter**: Detailed and summary exports for spreadsheet analysis
4. **HTML Exporter**: Bootstrap-styled web reports with severity color coding
5. **PDF Exporter**: WeasyPrint-based PDF generation with HTML fallback

All exporters follow DoD formatting standards including classification banners, color coding, and eMASS import compliance.
