# Changelog

All notable changes to the Virtual POAM Generator (vISSM) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MIT License file
- Contributing guidelines (CONTRIBUTING.md)
- This changelog
- EditorConfig for consistent code formatting across editors

### Changed
- Updated README.md to accurately reflect current codebase structure
- Updated README.md architecture section to include compliance module
- Updated setup.py with correct repository URL and email
- Improved documentation consistency across all files
- Cleaned up root folder by removing outdated documentation files

### Fixed
- README.md architecture diagram now accurately shows all modules
- QUICKSTART.md GitHub URL updated to correct repository
- Removed outdated audit and review documents from root folder

## [1.0.0] - 2024-11-15

### Added
- Initial release of Virtual POAM Generator (vISSM)
- Nessus XML parser for vulnerability data extraction
- Vulnerability processor with risk scoring and analysis
- STIG mapper for DISA STIG compliance
- NIST 800-53 Rev 5 control mapper
- CVE database with CVSS enrichment
- Excel exporter supporting 7 report types:
  - Plan of Action & Milestones (POAM)
  - Vulnerability Report
  - IV&V Test Plan
  - CNET Report
  - Hardware/Software Inventory
  - eMASS Inventory (import-ready format)
  - STIG Checklist (.ckl format for DISA STIG Viewer)
- CSV exporter for summary reports
- HTML exporter with interactive features
- PDF exporter (WeasyPrint-based)
- Jinja2 template engine for report rendering
- Command-line interface (CLI) with comprehensive options
- Console entry points: `poam-generator` and `virtual-poam`
- Comprehensive test suite (9 tests, 100% pass rate)
- DoD-compliant formatting:
  - Classification banners (UNCLASSIFIED//FOUO)
  - Color-coded severity levels (CAT I/II/III)
  - Risk-based remediation timelines (15/30/90 days)
  - eMASS-compatible column structure
- Documentation:
  - README.md with feature overview and examples
  - QUICKSTART.md for quick reference
  - claude.md for architecture and development guide
  - CONTRIBUTING.md with contribution guidelines
  - CHANGELOG.md for version tracking
  - Claude AI rules (project_context.md, coding_standards.md)
- Python 3.8+ support
- Cross-platform compatibility (Windows, Linux, macOS)
- Offline operation (no external API calls)
- Batch processing support

### Security
- No hardcoded credentials or secrets
- Safe XML parsing with lxml
- Input validation on file paths
- No data sent to external services
- All processing done locally

### Dependencies
- openpyxl >= 3.0.0 (Excel generation)
- lxml >= 4.9.0 (XML parsing)
- pandas >= 1.3.0 (data processing)
- jinja2 >= 3.1.0 (template rendering)
- xlsxwriter >= 3.0.0 (Excel features)
- weasyprint >= 60.0 (PDF generation, optional)
- pytest >= 7.0 (testing framework)
- black >= 22.0 (code formatting)
- flake8 >= 5.0 (linting)

## Version History

### Versioning Strategy

We use Semantic Versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Incompatible API changes or breaking changes to eMASS import format
- **MINOR**: New features added in a backward-compatible manner
- **PATCH**: Backward-compatible bug fixes

### Upcoming Features (Roadmap)

See README.md for the complete roadmap. Planned features include:

- [ ] Integration with ACAS exports
- [ ] Dashboard web interface
- [ ] Automated RMF package generation
- [ ] Enhanced STIG mapping coverage
- [ ] Real-time vulnerability database updates
- [ ] Custom report templates
- [ ] Multi-format batch exports
- [ ] Progress indicators for large scans
- [ ] Dry-run mode
- [ ] Validation mode (parse only, no export)

### Deprecation Policy

- Deprecated features will be announced at least one MINOR version before removal
- Security issues may result in immediate deprecation
- eMASS format compatibility will be maintained across versions

### Migration Guides

When major changes occur, migration guides will be provided to help users update their workflows.

---

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Reporting bugs
- Suggesting features
- Submitting pull requests
- Documentation updates

## Release Notes Distribution

Release notes are distributed through:
- GitHub Releases page
- This CHANGELOG.md file
- Git tags (e.g., v1.0.0)

## Support

For questions, issues, or feature requests:
- **Bugs**: Open a GitHub issue
- **Features**: Use GitHub discussions
- **Security**: Email poam-generator@users.noreply.github.com

---

**vISSM** - Virtual Information System Security Manager
Making DoD compliance documentation faster and easier! 🛡️
