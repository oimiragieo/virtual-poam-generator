# Contributing to Virtual POAM Generator

Thank you for your interest in contributing to the Virtual POAM Generator (vISSM)! This tool supports DoD cybersecurity professionals in their compliance workflows, and community contributions help make it better for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Documentation](#documentation)

## Code of Conduct

This project follows a professional code of conduct. We expect all contributors to:

- Be respectful and inclusive
- Focus on constructive feedback
- Prioritize accuracy and correctness in DoD compliance features
- Keep security and data privacy in mind

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub first, then:
git clone https://github.com/YOUR-USERNAME/virtual-poam-generator.git
cd virtual-poam-generator
```

### 2. Set Up Development Environment

```bash
# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -e .[dev]

# Verify installation
python cli.py --version
python -m pytest tests/ -v
```

### 3. Create a Branch

```bash
# Create a descriptive branch name
git checkout -b feature/add-new-export-format
# or
git checkout -b fix/stig-mapping-issue
```

## Development Workflow

### Understanding the Architecture

vISSM follows a 4-stage pipeline:

```
Parse (nessus_parser.py)
  → Process (vulnerability_processor.py)
  → Comply (stig_mapper.py, nist_mapper.py)
  → Export (excel_exporter.py, etc.)
```

**Before making changes, please review:**
- `claude.md` - Architecture and design patterns
- `.claude/rules/project_context.md` - Domain concepts and constraints
- `.claude/rules/coding_standards.md` - Code quality standards

### Making Changes

1. **Understand the impact**
   - Will this change affect eMASS import compatibility?
   - Could this alter STIG/NIST mapping accuracy?
   - Does this maintain DoD formatting standards?

2. **Write tests first** (TDD approach recommended)
   ```bash
   # Add test to tests/test_vissm.py
   def test_new_feature(self):
       # Test implementation
       pass
   ```

3. **Implement your changes**
   - Follow the dataclass pattern for data structures
   - Maintain single responsibility principle
   - Add comprehensive docstrings

4. **Run tests frequently**
   ```bash
   python -m pytest tests/ -v
   ```

## Coding Standards

### Style Guide

We follow **PEP 8** with **Black** formatting:

```bash
# Format your code
python -m black .

# Check for issues
python -m flake8 . --max-line-length=88 --extend-ignore=E203,W503
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `VulnerabilityProcessor`)
- **Functions**: `snake_case` (e.g., `export_excel_poam`)
- **Variables**: `snake_case` (e.g., `analysis_data`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `PLUGIN_TO_STIG`)
- **Files**: `snake_case` matching primary class/function

### Type Hints

Use dataclasses for all data structures:

```python
from dataclasses import dataclass

@dataclass
class MyDataClass:
    field1: str
    field2: int
    field3: Optional[str] = None
```

### Documentation

**All** modules, classes, and functions must have docstrings:

```python
def my_function(param1: str, param2: int) -> str:
    """
    Brief description of what the function does.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When param2 is negative
    """
    pass
```

### DoD-Specific Guidelines

1. **Never hardcode classified markings** - Use UNCLASSIFIED//FOUO as default
2. **STIG mappings must be accurate** - Cite sources in comments
3. **NIST controls must match SP 800-53 Rev 5** - Verify against official publication
4. **POAM formatting must match eMASS requirements** - Test imports before committing
5. **No external API calls** - Tool must work offline (air-gapped environments)

## Testing

### Test Requirements

- **All new features must have tests**
- **All tests must pass before submitting PR**
- **Maintain 100% test pass rate**

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_vissm.py::TestVISSM::test_html_export -v

# Run with coverage (if installed)
python -m pytest tests/ --cov=src --cov-report=html
```

### Writing Tests

Follow the Arrange-Act-Assert pattern:

```python
def test_my_feature(self):
    """Test description"""
    # Arrange: Create test data
    test_report = NessusReport(...)

    # Act: Execute function
    result = my_function(test_report)

    # Assert: Verify expectations
    self.assertEqual(result.status, "success")
    self.assertGreater(len(result.findings), 0)
```

### Test Data

- Use in-memory `NessusReport` objects
- Don't commit actual .nessus files (may contain sensitive data)
- Clean up temporary files with `tempfile` module

## Submitting Changes

### Before You Submit

**Pre-submission checklist:**

- [ ] Code is formatted with `python -m black .`
- [ ] All tests pass: `python -m pytest tests/ -v`
- [ ] Flake8 is clean (or justified `# noqa`)
- [ ] Documentation updated (README, QUICKSTART, claude.md if needed)
- [ ] Docstrings added to new functions/classes
- [ ] Commit messages follow format (see below)

### Commit Message Format

```
type: Brief description (50 chars max)

Detailed explanation if needed (wrap at 72 chars).

- Additional context
- References to issues (#123)
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding tests
- `refactor:` Code restructure without behavior change
- `style:` Formatting, no code change
- `chore:` Maintenance (dependencies, build, etc.)

**Examples:**

```
feat: Add STIG checklist export to CLI

Implemented DISA STIG Viewer .ckl format export using stig_exporter.py.
Includes plugin-to-STIG mapping and CAT I/II/III categorization.

Closes #42
```

```
fix: Correct NIST control mapping for CVE-2017-0144

Updated nist_mapper.py to properly map EternalBlue vulnerability
to SC-7 (Boundary Protection) instead of SI-2.

Fixes #56
```

### Creating a Pull Request

1. **Push your branch**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** on GitHub

3. **Fill out the PR template** with:
   - Description of changes
   - Related issue numbers
   - Testing performed
   - Screenshots (if UI changes)
   - Checklist confirmation

4. **Respond to feedback**
   - Address reviewer comments
   - Update code as needed
   - Re-request review when ready

### PR Review Process

**What reviewers check:**

1. **Correctness**: STIG/NIST mappings accurate, POAM format matches eMASS
2. **Security**: No hardcoded secrets, safe XML parsing, input validation
3. **Readability**: Clear variable names, helpful comments, logical structure
4. **Testability**: Functions are testable, dependencies injectable
5. **DoD Compliance**: Classification markings, FOUO warnings, proper formatting

**Typical timeline:**
- Initial review: 1-3 days
- Final approval: 1-7 days
- Merge: Shortly after approval

## Reporting Issues

### Bug Reports

**Use the GitHub issue tracker.** Include:

1. **vISSM version**: `python cli.py --version`
2. **Python version**: `python --version`
3. **Operating system**: Windows/Linux/macOS + version
4. **Steps to reproduce**
5. **Expected behavior**
6. **Actual behavior**
7. **Error messages** (use `--verbose` flag)
8. **Sample .nessus file** (sanitize sensitive data!)

### Feature Requests

**Use GitHub discussions or issues.** Include:

1. **Use case**: Who needs this and why?
2. **Proposed solution**: How would it work?
3. **Alternatives considered**: What else could solve this?
4. **DoD compliance impact**: Will this affect eMASS/STIG compatibility?

### Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, email: poam-generator@users.noreply.github.com

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Documentation

### What to Document

**Update documentation when:**
- Adding new report types
- Changing CLI arguments
- Adding new compliance frameworks
- Modifying Excel template structure
- Changing STIG/NIST mappings

### Documentation Files

- **README.md**: User-facing features, installation, examples
- **QUICKSTART.md**: Quick reference, common commands
- **claude.md**: Architecture, design decisions, development guide
- **Module claude.md files**: Module-specific documentation
- **Inline comments**: Complex logic, workarounds, DoD requirements

### Documentation Style

- Use clear, concise language
- Include code examples
- Explain the "why", not just the "what"
- Keep DoD domain context in mind (define acronyms)

## Additional Resources

### Learning About DoD Compliance

- **NIST SP 800-53**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **DISA STIGs**: https://public.cyber.mil/stigs/
- **RMF Process**: https://csrc.nist.gov/projects/risk-management
- **eMASS**: DoD-internal resource

### Understanding the Codebase

- Start with `cli.py` to see the pipeline flow
- Review `claude.md` for architecture overview
- Read `tests/test_vissm.py` for usage examples
- Check `.claude/rules/` for domain context

### Getting Help

- **Questions**: Open a GitHub discussion
- **Bugs**: Open a GitHub issue
- **Real-time**: Check if there's a community chat

## Recognition

Contributors will be recognized in:
- CHANGELOG.md (for each release)
- GitHub contributors page
- Special thanks in README.md (for significant contributions)

## License

By contributing, you agree that your contributions will be licensed under the same **MIT License** that covers this project.

---

Thank you for contributing to Virtual POAM Generator! Your efforts help DoD cybersecurity professionals streamline their compliance workflows and keep systems secure. 🛡️
