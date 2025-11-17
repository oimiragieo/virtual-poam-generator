# vISSM - Virtual POAM Generator

## Project Overview

**vISSM** (Virtual Information System Security Manager) is a Python CLI tool for DoD cybersecurity compliance. It converts Tenable Nessus vulnerability scans into DoD-compliant documentation including POAMs, STIG checklists, and eMASS-ready templates.

**Primary Use Case**: Automating compliance documentation for DoD systems going through the RMF/ATO process.

**Target Users**: DoD GRC professionals, ISSOs, ISSMs, cybersecurity teams working with eMASS.

## Architecture

### Data Flow Pipeline
```
.nessus file → Parser → Processor → Compliance Mapper → Exporter → Output (XLSX/CKL/CSV/HTML/PDF)
```

### Module Organization

```
virtual-poam-generator/
├── cli.py                          # Entry point - orchestrates the pipeline
├── src/
│   ├── parser/                     # Stage 1: XML parsing
│   │   └── nessus_parser.py        # Parses .nessus XML → Python dataclasses
│   │
│   ├── processor/                  # Stage 2: Analysis & risk scoring
│   │   └── vulnerability_processor.py  # Calculates risk scores, generates summaries
│   │
│   ├── compliance/                 # Stage 3: DoD compliance mapping
│   │   ├── stig_mapper.py          # Maps to DISA STIG IDs (CAT I/II/III)
│   │   ├── nist_mapper.py          # Maps to NIST 800-53 Rev 5 controls
│   │   └── cve_database.py         # Enriches CVE data with CVSS/CWE
│   │
│   ├── exporters/                  # Stage 4: Multi-format output
│   │   ├── excel_exporter.py       # POAM, inventory, reports (openpyxl)
│   │   ├── stig_exporter.py        # DISA STIG Viewer .ckl format
│   │   ├── csv_exporter.py         # CSV summaries
│   │   ├── html_exporter.py        # Interactive HTML reports
│   │   └── pdf_exporter.py         # PDF reports (WeasyPrint)
│   │
│   └── templates/                  # HTML/PDF template rendering
│       └── template_engine.py      # Jinja2-based template system
│
└── tests/
    └── test_vissm.py               # 9 unit tests (all passing)
```

### Key Design Patterns

1. **Dataclass-based Domain Model**: All data structures use Python dataclasses for type safety
2. **Pipeline Architecture**: Each stage has single responsibility, easy to extend
3. **Strategy Pattern**: Multiple exporters implement common interface
4. **Template Method**: Jinja2 templates for HTML/PDF generation

## Development Workflow

### Setup
```bash
pip install -r requirements.txt
pip install -e .  # Installs `poam-generator` and `virtual-poam` commands
```

### Running Tests
```bash
python -m pytest tests/ -v  # All 9 tests should pass
```

### Code Quality
```bash
python -m black .                    # Format code
python -m flake8 . --max-line-length=88 --extend-ignore=E203,W503
```

**Current Status**:
- ✅ 9/9 tests passing
- ✅ Black formatted
- ⚠️ 25 flake8 warnings (E501 line length - acceptable technical debt)

### Adding New Report Types

1. Create exporter function in `src/exporters/`
2. Import in `cli.py`
3. Add to `--report-type` choices in argparse
4. Route in `cli.py` main switch statement
5. Add documentation to README.md

Example from `stig_exporter.py`:
```python
def export_stig_checklist(analysis_data: Dict[str, Any], output_file: str) -> str:
    """Generate DISA STIG Viewer .ckl file"""
    # Implementation here
    return output_path
```

## Common Tasks

### Understanding Vulnerabilities
- Parsed from `.nessus` XML in `nessus_parser.py`
- Stored in `Vulnerability` dataclass with plugin ID, severity, CVE, CVSS, etc.
- Severity scale: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
- Maps to CAT I (Critical), CAT II (High), CAT III (Medium) for POAMs

### POAM Generation
- Located in `excel_exporter.py::export_excel_poam()`
- Groups vulnerabilities by plugin ID to avoid duplicates
- Tracks affected hosts per vulnerability
- Applies DoD formatting: classification banners, color coding, timelines
- Outputs eMASS-ready Excel with standard columns

### STIG Mapping
- `stig_mapper.py` maintains hardcoded plugin_to_stig and cve_to_stig mappings
- Returns `STIGFinding` objects with Rule ID, CCI, severity (CAT I/II/III)
- Used by `stig_exporter.py` to generate .ckl files for STIG Viewer

### NIST 800-53 Mapping
- `nist_mapper.py` maps CVEs and vulnerability categories to controls
- Supports RMF baselines: LOW, MODERATE, HIGH
- Control families: AC, CM, IA, SC, SI, etc.

## File Conventions

### Naming
- Classes: PascalCase (`VulnerabilityProcessor`)
- Functions: snake_case (`export_excel_poam`)
- Files: snake_case matching primary class/function
- Dataclasses: Used for all data models

### Imports
- Standard library first, then third-party, then local
- In `cli.py`, imports after `sys.path.insert()` use `# noqa: E402`

### Documentation
- All modules, classes, and functions have docstrings
- Complex logic includes inline comments
- Type hints on dataclasses

## Testing Strategy

### Current Test Coverage
- **Import tests**: Verify modules can be imported (smoke tests)
- **Structure tests**: Validate dataclass construction
- **Integration tests**: Full pipeline (parse → process → export)
- **CLI tests**: Verify --help, --version output

### Running Individual Tests
```bash
python -m pytest tests/test_vissm.py::TestVISSM::test_html_export -v
```

### Test Data
- Uses in-memory `NessusReport` objects (no fixture files needed)
- Creates temporary output directories with `tempfile`
- Verifies file creation and basic content validation

## Dependencies

### Core
- **lxml**: Fast XML parsing for .nessus files
- **openpyxl**: Excel generation (POAM, inventories)
- **pandas**: Data analysis and CSV export
- **jinja2**: HTML/PDF template rendering

### Optional
- **weasyprint**: PDF generation (can be skipped for Excel-only workflows)

### Dev
- **pytest**: Testing framework
- **black**: Code formatting
- **flake8**: Linting

## Known Limitations

1. **STIG/NIST mappings are hardcoded**: Not dynamic from DISA/NIST databases
2. **Line length**: Some lines >88 chars (acceptable, marked with # noqa: E501 if critical)
3. **HTML template**: Inline in `template_engine.py` (no separate .html files)
4. **No external APIs**: Fully offline (pro and con)

## Troubleshooting

### "File not found" errors
- Ensure .nessus file path is absolute or relative to CWD
- Use quotes around paths with spaces

### "Invalid XML" errors
- Re-export .nessus from Nessus scanner
- Ensure file wasn't corrupted during transfer

### Empty POAM/reports
- Verify scan has vulnerabilities (not all Info severity)
- Use `--verbose` flag to see processing details

### Import errors
- Ensure `pip install -r requirements.txt` completed successfully
- Check Python version ≥3.8

## Extension Points

### Adding New Compliance Frameworks
1. Create new mapper in `src/compliance/`
2. Follow pattern from `stig_mapper.py` or `nist_mapper.py`
3. Integrate in processor or exporter as needed

### Custom Excel Templates
- Modify functions in `excel_exporter.py`
- Use openpyxl for formatting: colors, fonts, borders
- Reference existing POAM generation for DoD styling

### New Output Formats
1. Create exporter in `src/exporters/`
2. Import and route in `cli.py`
3. Add tests in `test_vissm.py`

## AI Assistant Guidance

### When asked to add features
1. Follow the pipeline architecture: Parser → Processor → Compliance → Exporter
2. Maintain dataclass pattern for data structures
3. Add tests for new functionality
4. Update README.md and QUICKSTART.md documentation

### When debugging
1. Start with `--verbose` flag to see pipeline execution
2. Check `analysis_data` dictionary structure in exporters
3. Verify dataclass construction in parser/processor
4. Look for exceptions in try/except blocks

### When refactoring
1. Run `python -m pytest tests/ -v` after changes
2. Format with `python -m black .`
3. Keep functions focused (single responsibility)
4. Preserve backward compatibility for CLI arguments

## Resources

- **README.md**: User-facing documentation, feature list
- **QUICKSTART.md**: Quick reference, common commands
- **COMPREHENSIVE_REVIEW_SUMMARY.md**: Detailed code review, architecture decisions
- **setup.py**: Package configuration, entry points
- **requirements.txt**: All dependencies

## Version History

- **v1.0.0**: Initial release with POAM, inventory, STIG features
- Feature complete for DoD compliance workflows
- All tests passing, production-ready

---

**For questions or contributions**: See README.md for project overview and QUICKSTART.md for usage examples.
