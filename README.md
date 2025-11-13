# KARP Clone - Nessus Report Processor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**KARP Clone** is an open-source Nessus vulnerability report processor that replicates the functionality of KARP.exe. It parses .nessus files and exports vulnerability data to various formats including HTML, PDF, and CSV.

## 🚀 Features

- **Complete Nessus Parsing**: Parse .nessus XML files with full vulnerability data extraction
- **Multiple Export Formats**: HTML, PDF, and CSV output formats
- **Vulnerability Analysis**: Risk scoring, categorization, and trend analysis
- **Interactive HTML Reports**: Collapsible sections, filtering, and modern UI
- **Summary Reports**: High-level overview with key metrics and recommendations
- **Command-line Interface**: Easy-to-use CLI with comprehensive options
- **Template System**: Customizable report templates using Jinja2

## 📋 Requirements

- Python 3.8 or higher
- Required packages: jinja2, lxml
- Optional: weasyprint (for PDF generation)

## 🛠️ Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-username/karp-clone.git
cd karp-clone

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Using pip (when published)

```bash
pip install karp-clone
```

## 🎯 Quick Start

### Basic Usage

```bash
# Process a Nessus file and export to HTML
python cli.py report.nessus -o report.html -f html

# Export to CSV format
python cli.py report.nessus -o report.csv -f csv

# Generate summary only
python cli.py report.nessus --summary -o summary.csv
```

### Command-line Options

```bash
usage: cli.py [-h] [-o OUTPUT] [-f {html,pdf,csv}] [--summary] [--template-dir TEMPLATE_DIR] [--verbose] [--version] input_file

positional arguments:
  input_file            Input .nessus file to process

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file path
  -f {html,pdf,csv}, --format {html,pdf,csv}
                        Output format (default: html)
  --summary             Export summary only (CSV format)
  --template-dir TEMPLATE_DIR
                        Custom template directory
  --verbose             Enable verbose output
  --version             show program's version number and exit
```

## 📊 Output Formats

### HTML Reports
- Interactive web-based reports
- Collapsible host sections
- Severity-based color coding
- Responsive design
- Executive summary with recommendations

### PDF Reports
- Print-ready PDF documents
- Professional formatting
- Page breaks for large reports
- Optimized for printing

### CSV Reports
- Machine-readable format
- Detailed vulnerability data
- Summary reports available
- Excel-compatible

## 🔧 Advanced Usage

### Custom Templates

```bash
# Use custom template directory
python cli.py report.nessus -o report.html -f html --template-dir /path/to/templates
```

### Programmatic Usage

```python
from src.parser.nessus_parser import parse_nessus_file
from src.processor.vulnerability_processor import process_nessus_report
from src.exporters.html_exporter import export_html_report

# Parse Nessus file
report = parse_nessus_file('report.nessus')

# Process vulnerability data
analysis_data = process_nessus_report(report)
analysis_data['report'] = report

# Export to HTML
export_html_report(analysis_data, 'output.html')
```

## 📈 Analysis Features

### Vulnerability Categorization
- **Critical**: Immediate attention required
- **High**: Address within 30 days
- **Medium**: Address within 90 days
- **Low**: Address within 6 months
- **Info**: Informational findings

### Risk Scoring
- Host-based risk scores (0-100)
- Weighted severity calculations
- Priority recommendations

### Trend Analysis
- Vulnerability family analysis
- Host vulnerability patterns
- Security recommendations

## 🏗️ Architecture

```
karp-clone/
├── src/
│   ├── parser/          # Nessus XML parsing
│   ├── processor/       # Vulnerability analysis
│   ├── templates/       # Report templates
│   └── exporters/       # Output format handlers
├── cli.py              # Command-line interface
├── setup.py            # Package configuration
└── requirements.txt    # Dependencies
```

### Core Components

1. **Nessus Parser** (`src/parser/nessus_parser.py`)
   - XML parsing and data extraction
   - Host and vulnerability data structures
   - Error handling and validation

2. **Vulnerability Processor** (`src/processor/vulnerability_processor.py`)
   - Risk analysis and scoring
   - Trend identification
   - Recommendation generation

3. **Template Engine** (`src/templates/template_engine.py`)
   - Jinja2-based templating
   - Custom filters and functions
   - Multi-format support

4. **Exporters** (`src/exporters/`)
   - HTML, PDF, CSV output formats
   - Format-specific optimizations
   - Error handling

## 🧪 Testing

```bash
# Run tests
python -m pytest tests/

# Test with sample data
python cli.py tests/fixtures/sample.nessus -o test_output.html -f html --verbose
```

## 📝 Examples

### Example 1: Basic HTML Report
```bash
python cli.py vulnerability_scan.nessus -o report.html -f html
```

### Example 2: CSV Export with Summary
```bash
python cli.py vulnerability_scan.nessus -o detailed_report.csv -f csv
python cli.py vulnerability_scan.nessus --summary -o summary.csv
```

### Example 3: PDF Report
```bash
python cli.py vulnerability_scan.nessus -o report.pdf -f pdf
```

## 🔍 Comparison with KARP.exe

| Feature | KARP.exe | KARP Clone |
|---------|----------|------------|
| Nessus parsing | ✅ | ✅ |
| HTML export | ✅ | ✅ |
| PDF export | ✅ | ✅ |
| CSV export | ✅ | ✅ |
| Risk scoring | ✅ | ✅ |
| Template system | ✅ | ✅ |
| Command-line interface | ✅ | ✅ |
| Open source | ❌ | ✅ |
| Cross-platform | ❌ | ✅ |
| Customizable | ❌ | ✅ |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by KARP.exe functionality
- Built with Python and Jinja2
- Uses WeasyPrint for PDF generation
- Thanks to the open-source community

## 📞 Support

- Create an issue for bug reports
- Use discussions for feature requests
- Check the documentation for usage questions

---

**KARP Clone** - Making Nessus report processing open and accessible! 🛡️
