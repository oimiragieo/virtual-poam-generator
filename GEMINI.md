# Project Overview

This project, "KARP Clone," is a Python-based command-line tool designed to process Nessus vulnerability reports. It parses `.nessus` files, analyzes the vulnerability data, and exports the findings into various formats, including HTML, PDF, CSV, and Excel. The tool provides features like risk scoring, vulnerability categorization, and trend analysis.

## Building and Running

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/karp-clone.git
    cd karp-clone
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install in development mode:**
    ```bash
    pip install -e .
    ```

### Running the tool

The tool is run from the command line using the `karp-clone` command (after installation) or `python cli.py`.

**Basic Usage:**

```bash
# Process a Nessus file and export to HTML
karp-clone report.nessus -o report.html -f html

# Export to CSV format
karp-clone report.nessus -o report.csv -f csv

# Generate an Excel vulnerability report
karp-clone report.nessus -o report.xlsx -f xlsx -r vulnerability
```

**Command-line Options:**

| Flag | Description |
| :--- | :--- |
| `input_file` | (Required) Input `.nessus` file to process. |
| `-o`, `--output` | Output file path. |
| `-f`, `--format` | Output format (`html`, `pdf`, `csv`, `xlsx`). Default: `xlsx`. |
| `-r`, `--report-type` | Report type for Excel (`vulnerability`, `ivv-test-plan`, `cnet`, `hw-sw-inventory`, `emass-inventory`). Default: `vulnerability`. |
| `--summary` | Export summary only (CSV format). |
| `--template-dir` | Custom template directory. |
| `--verbose` | Enable verbose output. |
| `--version` | Show program's version number. |

## Development Conventions

### Testing

The project uses `pytest` for testing. To run the tests:

```bash
python -m pytest tests/
```

### Code Style

The project appears to follow standard Python conventions (PEP 8). While no specific linter configuration is provided in the immediate file listing, the `requirements.txt` file lists `black` and `flake8` as development dependencies, suggesting they are used for code formatting and linting.

### Project Structure

The project is organized into the following main directories:

*   `src/`: Contains the main source code.
    *   `parser/`: Handles parsing of `.nessus` files.
    *   `processor/`: Performs vulnerability analysis and data processing.
    *   `exporters/`: Manages exporting data to different formats.
    *   `templates/`: Contains Jinja2 templates for reports.
*   `tests/`: Contains tests for the project.
*   `cli.py`: The command-line interface entry point.
*   `setup.py`: The package configuration file.
*   `requirements.txt`: Lists the project's dependencies.
