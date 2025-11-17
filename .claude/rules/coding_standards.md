# Coding Standards for vISSM

## Code Style

### Follow PEP 8 with Black formatting
- Line length: 88 characters (Black default)
- Use `python -m black .` before committing
- Acceptable to use `# noqa: E501` for strings that cannot be split

### Naming Conventions
- **Classes**: `PascalCase` (e.g., `VulnerabilityProcessor`)
- **Functions**: `snake_case` (e.g., `export_excel_poam`)
- **Variables**: `snake_case` (e.g., `analysis_data`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `PLUGIN_TO_STIG`)
- **Files**: `snake_case` matching primary class/function

### Type Hints
- Use dataclasses for all data structures
- Include type hints on dataclass fields
- Example:
  ```python
  @dataclass
  class Vulnerability:
      plugin_id: str
      plugin_name: str
      severity: int
  ```

## Documentation

### Docstrings Required
- Module-level: Describe module purpose
- Class-level: Describe class responsibility
- Function-level: Describe what function does (not how)
- Use Google/NumPy style for parameters and returns

Example:
```python
def export_excel_poam(analysis_data: Dict[str, Any], output_file: str) -> str:
    """
    Generate Plan of Action & Milestones Excel report.

    Args:
        analysis_data: Processed vulnerability data from processor
        output_file: Path where Excel file should be written

    Returns:
        Absolute path to generated Excel file
    """
```

### Inline Comments
- Explain **why**, not what
- Required for complex logic, algorithms, workarounds
- Keep concise and up-to-date

## Error Handling

### Always validate inputs
```python
if not os.path.exists(input_file):
    print(f"Error: Input file '{input_file}' not found")
    sys.exit(1)
```

### Use specific exceptions
```python
try:
    wb = load_workbook(filepath)
except FileNotFoundError:
    print(f"File not found: {filepath}")
except Exception as e:
    print(f"Error loading workbook: {e}")
```

### Provide helpful error messages
- Include file paths, expected vs actual values
- Use --verbose flag for detailed debugging

## Testing

### Test Requirements
- All new features must have tests
- Maintain 100% test pass rate
- Run `python -m pytest tests/ -v` before committing

### Test Structure
```python
def test_feature_name(self):
    """Test description"""
    # Arrange: Create test data
    test_data = create_test_data()

    # Act: Execute function
    result = function_under_test(test_data)

    # Assert: Verify expectations
    self.assertTrue(condition)
```

### Use in-memory test data
- Don't rely on external files
- Create `NessusReport` objects directly
- Clean up temporary files with `tempfile`

## Import Order

1. Standard library
2. Third-party packages
3. Local modules

```python
import os
from pathlib import Path

import pandas as pd
from openpyxl import load_workbook

from parser.nessus_parser import parse_nessus_file
```

### Special Cases
- In `cli.py` and `tests/`: imports after `sys.path.insert()` need `# noqa: E402`

## Dataclass Pattern

### Use for all data structures
```python
from dataclasses import dataclass

@dataclass
class HostProperties:
    hostname: str
    ip: str
    os: str = ""
    mac_address: str = ""
```

### Benefits
- Type safety
- Automatic `__init__`, `__repr__`
- Immutable with `@dataclass(frozen=True)`
- Clear data contracts

## Function Design

### Single Responsibility Principle
- Each function does one thing well
- Keep functions focused and small (<100 lines)
- Extract complex logic into helper functions

### Return Consistent Types
- Functions should return same type in all branches
- Use `Optional[Type]` for nullable returns
- Document return types in docstring

### Avoid Side Effects
- Functions should not modify global state
- Return new objects instead of mutating inputs
- Exception: File I/O functions (clearly named `export_*`, `write_*`)

## DoD-Specific Guidelines

### Classification Markings
- Default to `UNCLASSIFIED//FOUO`
- Make classification configurable
- Never hardcode classified markings

### Data Privacy
- No data sent to external services
- All processing is local
- Log minimal PII (no IPs in logs unless --verbose)

### Compliance Standards
- STIG mappings should be accurate
- NIST 800-53 controls match official publications
- POAM format matches eMASS requirements

## Performance

### Optimize for typical use cases
- Small scans (1-10 hosts): < 1 second
- Medium scans (10-100 hosts): 1-5 seconds
- Large scans (100-1000 hosts): 5-30 seconds

### Memory Efficiency
- Stream large files when possible
- Don't load entire XML into memory at once
- Use generators for large datasets

### Avoid Premature Optimization
- Readable code > clever code
- Optimize after profiling shows bottleneck
- Document performance-critical sections

## Git Commit Messages

### Format
```
type: Brief description (50 chars max)

Detailed explanation if needed (wrap at 72 chars).

- Additional context
- References to issues
```

### Types
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding tests
- `refactor:` Code restructure without behavior change
- `style:` Formatting, no code change
- `chore:` Maintenance (dependencies, build, etc.)

### Examples
```
feat: Add STIG checklist export to CLI

Implemented DISA STIG Viewer .ckl format export using stig_exporter.py.
Includes plugin-to-STIG mapping and CAT I/II/III categorization.
```

## Pre-Commit Checklist

- [ ] Code formatted with `python -m black .`
- [ ] Tests pass: `python -m pytest tests/ -v`
- [ ] Flake8 clean (or justified # noqa)
- [ ] Updated documentation if needed (README, QUICKSTART, claude.md)
- [ ] Docstrings on new functions/classes
- [ ] Meaningful commit message

## Code Review Focus Areas

1. **Security**: No hardcoded secrets, safe XML parsing, input validation
2. **Correctness**: STIG/NIST mappings accurate, POAM formatting matches eMASS
3. **Readability**: Clear variable names, helpful comments, logical structure
4. **Testability**: Functions are testable, dependencies injectable
5. **DoD Compliance**: Classification markings, FOUO warnings, proper formatting

---

**Remember**: This is DoD compliance software - accuracy and reliability are paramount. When in doubt, prefer explicit over implicit, and clear over clever.
