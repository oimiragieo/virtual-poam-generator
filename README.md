# Virtual POAM Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Virtual POAM Generator** is an open-source tool designed specifically for DoD GRC (Governance, Risk, and Compliance) teams working with eMASS (Enterprise Mission Assurance Support Service). It processes Tenable Nessus vulnerability scan reports and generates standardized compliance documentation required for DoD cybersecurity workflows.

## 🎯 Purpose

This tool bridges the gap between vulnerability scanning and compliance documentation by automatically converting Nessus .nessus files into DoD-compliant Excel templates, including:

- **POAM (Plan of Action & Milestones)** - Critical for eMASS workflows
- **Vulnerability Reports** - Detailed findings with risk categorization
- **IV&V Test Plans** - Independent Verification & Validation documentation
- **Hardware/Software Inventory** - Asset tracking for ATO packages
- **eMASS Import Templates** - Ready-to-import hardware and software inventories

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/virtual-poam-generator.git
cd virtual-poam-generator

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Generate a POAM from Nessus scan (most common use case)
python cli.py scan.nessus -o poam.xlsx -r poam

# Generate a detailed vulnerability report
python cli.py scan.nessus -o vulnerabilities.xlsx -r vulnerability

# Generate eMASS hardware/software inventory
python cli.py scan.nessus -o emass_inventory.xlsm -r emass-inventory

# Generate IV&V test plan
python cli.py scan.nessus -o test_plan.xlsx -r ivv-test-plan
```

## 📋 Key Features

### 1. POAM Generation
Automatically creates Plan of Action & Milestones documents with:
- CAT I/II/III severity categorization
- Risk-based completion timelines (15/30/90 days)
- Grouped findings by vulnerability type
- Affected host tracking
- Remediation guidance
- DoD-compliant formatting with classification banners

### 2. Vulnerability Reports
- Complete vulnerability details with descriptions
- CVSS scoring and CVE references
- Port, protocol, and service information
- Severity-based color coding
- Host-by-host breakdowns

### 3. IV&V Test Plans
- Test cases for critical and high severity findings
- Pass/fail criteria
- Test environment specifications
- Verification procedures

### 4. eMASS Integration
- Hardware and software inventory sheets
- Classification markings
- Import-ready format for eMASS
- Dropdown lists for standard fields

### 5. Additional Exports
- CSV summaries for executive reporting
- HTML reports (basic)
- Multiple output formats

## 📊 Report Types

| Report Type | CLI Flag | Description | Use Case |
|------------|----------|-------------|----------|
| **POAM** | `-r poam` | Plan of Action & Milestones | Required for eMASS, tracks remediation |
| **Vulnerability** | `-r vulnerability` | Detailed vulnerability listing | Technical analysis, patch prioritization |
| **IV&V Test Plan** | `-r ivv-test-plan` | Verification test procedures | Testing after remediation |
| **HW/SW Inventory** | `-r hw-sw-inventory` | Detailed asset inventory | ATO packages, asset management |
| **eMASS Inventory** | `-r emass-inventory` | eMASS-ready import template | Direct eMASS import |
| **CNET Report** | `-r cnet` | CNET-formatted report | Network compliance |

## 🛠️ CLI Options

```bash
usage: cli.py [-h] [-o OUTPUT] [-f {html,pdf,csv,xlsx}]
              [-r {vulnerability,poam,ivv-test-plan,cnet,hw-sw-inventory,emass-inventory}]
              [--summary] [--template-dir TEMPLATE_DIR] [--verbose] [--version]
              input_file

positional arguments:
  input_file            Input .nessus file to process

options:
  -h, --help            Show help message
  -o OUTPUT, --output OUTPUT
                        Output file path (auto-generated if not specified)
  -f {html,pdf,csv,xlsx}, --format {html,pdf,csv,xlsx}
                        Output format (default: xlsx)
  -r {vulnerability,poam,...}, --report-type {vulnerability,poam,...}
                        Report type to generate (default: vulnerability)
  --summary             Export summary only (CSV format)
  --verbose             Enable verbose output
  --version             Show program version
```

## 📝 Examples

### Generate POAM for eMASS
```bash
python cli.py weekly_scan.nessus -o poam_2024-01-15.xlsx -r poam --verbose
```

### Complete Compliance Package
```bash
# Generate all required documents
python cli.py scan.nessus -o poam.xlsx -r poam
python cli.py scan.nessus -o vulnerabilities.xlsx -r vulnerability
python cli.py scan.nessus -o inventory.xlsm -r emass-inventory
python cli.py scan.nessus -o test_plan.xlsx -r ivv-test-plan
```

### Quick Summary for Management
```bash
python cli.py scan.nessus --summary -o executive_summary.csv
```

## 🏗️ Understanding POAM Generation

The POAM generator automatically:

1. **Categorizes vulnerabilities** by severity:
   - CAT I (Critical, Severity 4): 15-day remediation timeline
   - CAT II (High, Severity 3): 30-day remediation timeline
   - CAT III (Medium, Severity 2): 90-day remediation timeline

2. **Groups findings** by vulnerability type to avoid duplication

3. **Tracks affected hosts** for each vulnerability

4. **Maps to controls** using CVE references when available

5. **Applies DoD formatting**:
   - Classification banners (UNCLASSIFIED//FOUO)
   - Risk-based color coding
   - Standard eMASS columns
   - Proper cell formatting and borders

## 🔍 Requirements

- Python 3.8 or higher
- Tenable Nessus .nessus export files
- Required packages (auto-installed):
  - openpyxl (Excel generation)
  - lxml (XML parsing)
  - pandas (data processing)

## 🤝 Contributing

This is an open-source tool built for the DoD cybersecurity community. Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Test your changes with real .nessus files
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for DoD GRC professionals and eMASS users
- Designed to simplify compliance workflows
- Community-driven development

## 📞 Support

- Create an issue for bug reports
- Use discussions for feature requests
- Check examples/ directory for sample outputs

---

**Virtual POAM Generator** - Making DoD compliance documentation faster and easier! 🛡️

### Common Workflows

**Initial Scan Processing:**
```bash
# Get the vulnerability scan
nessus-export scan.nessus

# Generate POAM for eMASS
python cli.py scan.nessus -o poam.xlsx -r poam
```

**Monthly Compliance Package:**
```bash
# Generate all required monthly reports
python cli.py monthly_scan.nessus -o monthly_poam.xlsx -r poam
python cli.py monthly_scan.nessus -o monthly_vulns.xlsx -r vulnerability
python cli.py monthly_scan.nessus --summary -o monthly_summary.csv
```

**After Remediation:**
```bash
# Generate test plan for verification
python cli.py scan.nessus -o verification_tests.xlsx -r ivv-test-plan
```
