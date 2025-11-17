# vISSM - Virtual Information System Security Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**vISSM (Virtual Information System Security Manager)** is an open-source tool designed specifically for DoD GRC (Governance, Risk, and Compliance) teams working with eMASS (Enterprise Mission Assurance Support Service). It processes Tenable Nessus vulnerability scan reports and generates standardized compliance documentation required for DoD cybersecurity workflows.

## 🎯 Purpose

vISSM bridges the gap between vulnerability scanning and compliance documentation by automatically converting Nessus .nessus files into DoD-compliant Excel templates, including:

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

# Optional: Install as a command-line tool
pip install -e .
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

After installation, you can also use the convenience commands:
```bash
poam-generator scan.nessus -o poam.xlsx -r poam
# or
virtual-poam scan.nessus -o poam.xlsx -r poam
```

## 📋 Key Features

### 1. POAM Generation
Automatically creates Plan of Action & Milestones documents with:
- CAT I/II/III severity categorization
- Risk-based completion timelines (15/30/90 days)
- Grouped findings by vulnerability type (eliminates duplicates)
- Affected host tracking with hostnames and IPs
- Remediation guidance from Nessus plugins
- DoD-compliant formatting with classification banners
- Color-coded risk levels (Very High/High highlighted)
- eMASS-standard column structure

### 2. Vulnerability Reports
- Complete vulnerability details with descriptions
- CVSS scoring and CVE references
- Port, protocol, and service information
- Severity-based color coding
- Host-by-host breakdowns
- Plugin family categorization

### 3. IV&V Test Plans
- Automated test case generation for CAT I/II findings
- Pass/fail criteria for each vulnerability
- Test environment specifications
- Step-by-step verification procedures
- Target host information

### 4. eMASS Integration
- Hardware and software inventory sheets
- Classification markings (UNCLASSIFIED//FOUO)
- Import-ready format for direct eMASS upload
- Dropdown lists for standard fields
- Multiple worksheet support

### 5. STIG and NIST 800-53 Compliance
- Automated STIG ID mapping for vulnerabilities
- NIST 800-53 Rev 5 control mapping
- CVE enrichment with CVSS scores
- DISA STIG Viewer checklist generation (.ckl format)
- Control Correlation Identifier (CCI) references
- RMF baseline support (LOW, MODERATE, HIGH)

### 6. Additional Exports
- CSV summaries for executive reporting
- HTML reports with interactive features and detailed vulnerability listings
- PDF exports (with optional WeasyPrint)
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
| **STIG Checklist** | `-r stig-checklist` | DISA STIG Viewer format (.ckl) | STIG compliance verification |

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
  --version             Show program version (vISSM v1.0.0)
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
   - Eliminates duplicate findings across multiple hosts
   - Shows all affected hosts per vulnerability
   - Maintains unique POAM IDs

3. **Tracks affected hosts** for each vulnerability
   - Hostname and IP address
   - Lists up to 5 hosts per finding (with overflow indicator)

4. **Maps to controls** using CVE references when available
   - Uses CVE IDs when present
   - Falls back to V-[Plugin ID] format

5. **Applies DoD formatting**:
   - Classification banners (UNCLASSIFIED//FOUO)
   - Risk-based color coding (red for Very High, yellow for High)
   - Standard eMASS columns (POAM ID, Control ID, Weakness, POC, etc.)
   - Proper cell formatting and borders
   - Optimized column widths and row heights

## 🔍 Requirements

- Python 3.8 or higher
- Tenable Nessus .nessus export files
- Required packages (auto-installed):
  - openpyxl >= 3.0.0 (Excel generation)
  - lxml >= 4.9.0 (XML parsing)
  - pandas >= 1.3.0 (data processing)
  - jinja2 >= 3.1.0 (template rendering)
- Optional packages:
  - weasyprint >= 60.0 (PDF generation)

## 🏗️ Architecture

```
virtual-poam-generator/
├── cli.py                      # Command-line interface
├── src/
│   ├── parser/
│   │   └── nessus_parser.py   # Nessus XML parser
│   ├── processor/
│   │   └── vulnerability_processor.py  # Data analysis
│   ├── exporters/
│   │   ├── excel_exporter.py  # POAM, inventory, reports
│   │   ├── csv_exporter.py    # CSV exports
│   │   ├── html_exporter.py   # HTML reports
│   │   └── pdf_exporter.py    # PDF generation
│   └── templates/
│       └── template_engine.py # Jinja2 templates
├── tests/                     # Test suite
├── README.md                  # This file
├── QUICKSTART.md             # Quick start guide
└── requirements.txt          # Dependencies
```

## 🤝 Contributing

This is an open-source tool built for the DoD cybersecurity community. Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Test your changes with real .nessus files
4. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -e .[dev]

# Run tests
python -m pytest tests/

# Format code
black .

# Lint code
flake8 .
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for DoD GRC professionals and eMASS users
- Designed to simplify compliance workflows
- Community-driven development
- Special thanks to security practitioners who provided feedback

## 📞 Support

- Create an issue for bug reports
- Use discussions for feature requests
- Check QUICKSTART.md for quick reference
- Review examples/ directory for sample outputs

## 🔒 Security & Compliance

- **Classification**: All generated reports include appropriate classification banners
- **Data Handling**: No data is sent to external services
- **Privacy**: All processing is done locally
- **FOUO Markings**: Templates include "FOR OFFICIAL USE ONLY" markings

## 🚀 Roadmap

- [x] STIG compliance mapping (✓ Completed - see `src/compliance/stig_mapper.py`)
- [x] Automated control mapping to NIST 800-53 (✓ Completed - see `src/compliance/nist_mapper.py`)
- [x] STIG Viewer checklist export (✓ Completed - use `-r stig-checklist`)
- [ ] Integration with ACAS exports
- [ ] Dashboard web interface
- [ ] Automated RMF package generation

---

**vISSM** - Virtual Information System Security Manager
Making DoD compliance documentation faster and easier! 🛡️

## 📖 Common Workflows

### Initial Scan Processing
```bash
# Export from Nessus
# File → Export → .nessus format

# Generate POAM for eMASS
python cli.py scan.nessus -o poam.xlsx -r poam
```

### Monthly Compliance Package
```bash
# Generate all required monthly reports
python cli.py monthly_scan.nessus -o monthly_poam.xlsx -r poam
python cli.py monthly_scan.nessus -o monthly_vulns.xlsx -r vulnerability
python cli.py monthly_scan.nessus --summary -o monthly_summary.csv
```

### After Remediation
```bash
# Generate test plan for verification
python cli.py scan.nessus -o verification_tests.xlsx -r ivv-test-plan

# Re-scan and verify fixes
python cli.py rescan.nessus -o poam_updated.xlsx -r poam
```

### Batch Processing
```bash
# Process multiple scans
for file in scans/*.nessus; do
    python cli.py "$file" -o "poams/$(basename $file .nessus)_poam.xlsx" -r poam
done
```

## 💡 Tips & Best Practices

1. **Always use --verbose** when testing to see detailed processing information
2. **Review POAMs before submitting** to customize POC names and completion dates
3. **Keep .nessus files** as audit evidence
4. **Use consistent naming** for tracking: `SystemName_YYYY-MM-DD.nessus`
5. **Generate all report types** for complete documentation packages
6. **Test import into eMASS** with a small dataset first
7. **Update completion dates** based on your organization's policies

## ❓ FAQ

**Q: Can this replace KARP.exe?**
A: Yes! vISSM provides the same functionality as KARP.exe but is open-source, cross-platform, and includes additional DoD-specific features like POAM generation.

**Q: Does this work with ACAS exports?**
A: Currently supports .nessus format. ACAS .nessus exports work fine.

**Q: Can I customize the Excel templates?**
A: The templates follow eMASS standards, but you can modify the code in `src/exporters/excel_exporter.py` to customize headers and formatting.

**Q: What about classified systems?**
A: vISSM generates templates with UNCLASSIFIED markings. For classified systems, manually update the classification banners in the generated files according to your organization's policies.

**Q: How do I handle large scans (1000+ hosts)?**
A: vISSM can handle large scans. Use `--verbose` to monitor progress. Excel files have a 1,048,576 row limit, so extremely large scans may need to be split.
