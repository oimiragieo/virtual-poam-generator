# Templates Module Documentation

## Overview

The `templates` module provides **Jinja2-based template rendering** for HTML and PDF report generation. It's a supporting module used by HTML and PDF exporters to create formatted, styled output.

**Primary Responsibility**: Transform analysis data into formatted HTML using templates and custom filters.

## Module Structure

```
src/templates/
├── __init__.py              # Empty module marker
└── template_engine.py       # Jinja2 template engine (480 lines)
```

## Key Components

### Classes

#### `TemplateEngine`
Main template rendering class with Jinja2 integration and custom filters.

**Initialization:**
```python
engine = TemplateEngine(template_dir=None)
```

**Parameters:**
- `template_dir`: Optional path to custom template directory. If `None`, uses inline templates.

### Key Methods

##### `render_template(template_name: str, context: Dict) -> str`
Render a Jinja2 template file.

**Parameters:**
- `template_name`: Name of template file (e.g., "report.html")
- `context`: Dictionary of variables for template

**Returns:**
- Rendered HTML string

**Example:**
```python
engine = TemplateEngine(template_dir="/path/to/templates")
html = engine.render_template("vulnerability_report.html", {
    "title": "Vulnerability Report",
    "summary": summary_data,
    "hosts": host_list
})
```

**Raises:**
- `TemplateNotFound`: If template file doesn't exist
- `TemplateSyntaxError`: If template has syntax errors

##### `render_string(template_string: str, context: Dict) -> str`
Render a Jinja2 template from string.

**Parameters:**
- `template_string`: Template content as string
- `context`: Dictionary of variables for template

**Returns:**
- Rendered HTML string

**Example:**
```python
template = """
<h1>{{ title }}</h1>
<p>Total vulnerabilities: {{ total }}</p>
"""
html = engine.render_string(template, {
    "title": "Quick Report",
    "total": 234
})
```

##### `render_html_report(analysis_data: Dict, output_file: str) -> str`
High-level function to render complete HTML vulnerability report.

**Parameters:**
- `analysis_data`: Processed data from vulnerability_processor
- `output_file`: Path where HTML should be saved

**Returns:**
- Path to saved HTML file

**Template Structure:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
    <style>
        /* Embedded CSS for styling */
        .critical { background-color: #dc3545; }
        .high { background-color: #ffc107; }
        /* ... more styles */
    </style>
</head>
<body>
    <h1>{{ report.scan_name }}</h1>

    <!-- Summary Section -->
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Vulnerabilities: {{ summary.total_vulnerabilities }}</p>
        <p>Critical: {{ summary.critical_count }}</p>
        <!-- ... more summary stats -->
    </div>

    <!-- Vulnerability List -->
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Plugin Name</th>
                <th>Affected Hosts</th>
                <!-- ... more columns -->
            </tr>
        </thead>
        <tbody>
            {% for vuln in vulnerabilities %}
            <tr class="{{ vuln.severity | severity_name | lower }}">
                <td>{{ vuln.severity | severity_name }}</td>
                <td>{{ vuln.plugin_name }}</td>
                <td>{{ vuln.hosts | join(', ') }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
```

## Custom Jinja2 Filters

The template engine provides three custom filters for data formatting:

### 1. `severity_name` Filter

**Purpose:** Convert numeric severity to human-readable name.

**Signature:**
```python
def severity_name(severity: int) -> str
```

**Mapping:**
```python
{
    0: "Info",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical"
}
```

**Usage in Templates:**
```jinja2
<span class="severity-{{ severity | severity_name | lower }}">
    {{ severity | severity_name }}
</span>
```

**Example:**
```jinja2
Input:  {{ 4 | severity_name }}
Output: Critical

Input:  {{ 2 | severity_name }}
Output: Medium
```

### 2. `risk_level` Filter

**Purpose:** Convert 0-100 risk score to risk level category.

**Signature:**
```python
def risk_level(score: float) -> str
```

**Mapping:**
```python
score >= 80: "Critical"
score >= 60: "High"
score >= 40: "Medium"
score >= 20: "Low"
score < 20:  "Minimal"
```

**Usage in Templates:**
```jinja2
<div class="risk-{{ host.risk_score | risk_level | lower }}">
    Risk Level: {{ host.risk_score | risk_level }}
    (Score: {{ host.risk_score | round(1) }})
</div>
```

**Example:**
```jinja2
Input:  {{ 85.5 | risk_level }}
Output: Critical

Input:  {{ 42.0 | risk_level }}
Output: Medium

Input:  {{ 15.2 | risk_level }}
Output: Minimal
```

### 3. `format_date` Filter

**Purpose:** Parse and format dates from various input formats.

**Signature:**
```python
def format_date(date_str: str, format: str = "%Y-%m-%d %H:%M:%S") -> str
```

**Supported Input Formats:**
- ISO 8601: `2024-01-15T10:30:00Z`
- Nessus format: `Mon Jan 15 10:30:00 2024`
- Standard: `2024-01-15 10:30:00`
- Date only: `2024-01-15`

**Default Output Format:** `YYYY-MM-DD HH:MM:SS`

**Usage in Templates:**
```jinja2
<p>Scan started: {{ report.scan_start | format_date }}</p>
<p>Date only: {{ report.scan_start | format_date("%Y-%m-%d") }}</p>
<p>Custom: {{ report.scan_start | format_date("%B %d, %Y at %I:%M %p") }}</p>
```

**Example:**
```jinja2
Input:  {{ "2024-01-15T10:30:00" | format_date }}
Output: 2024-01-15 10:30:00

Input:  {{ "2024-01-15T10:30:00" | format_date("%B %d, %Y") }}
Output: January 15, 2024
```

## Inline Templates

Since vISSM doesn't use external template files by default, templates are embedded as strings in the code.

### HTML Report Template (Simplified)

```python
VULNERABILITY_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.scan_name }} - Vulnerability Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #003f87;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .classification {
            background-color: #00ff00;
            color: black;
            text-align: center;
            padding: 10px;
            font-weight: bold;
        }
        .summary {
            background-color: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat {
            display: inline-block;
            margin: 10px 20px;
        }
        .stat-label {
            font-weight: bold;
            color: #666;
        }
        .stat-value {
            font-size: 24px;
            margin-left: 5px;
        }
        table {
            width: 100%;
            background-color: white;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th {
            background-color: #003f87;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:hover {
            background-color: #f0f0f0;
        }
        .severity-critical {
            background-color: #dc3545;
            color: white;
        }
        .severity-high {
            background-color: #ffc107;
            color: black;
        }
        .severity-medium {
            background-color: #17a2b8;
            color: white;
        }
        .severity-low {
            background-color: #28a745;
            color: white;
        }
        .severity-info {
            background-color: #6c757d;
            color: white;
        }
    </style>
</head>
<body>
    <div class="classification">
        UNCLASSIFIED//FOR OFFICIAL USE ONLY
    </div>

    <div class="header">
        <h1>Vulnerability Assessment Report</h1>
        <h2>{{ report.scan_name }}</h2>
        <p>Generated: {{ generation_date | format_date }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stat">
            <span class="stat-label">Total Hosts:</span>
            <span class="stat-value">{{ summary.host_counts | length }}</span>
        </div>
        <div class="stat">
            <span class="stat-label">Total Vulnerabilities:</span>
            <span class="stat-value">{{ summary.total_vulnerabilities }}</span>
        </div>
        <div class="stat">
            <span class="stat-label severity-critical">Critical:</span>
            <span class="stat-value">{{ summary.critical_count }}</span>
        </div>
        <div class="stat">
            <span class="stat-label severity-high">High:</span>
            <span class="stat-value">{{ summary.high_count }}</span>
        </div>
        <div class="stat">
            <span class="stat-label severity-medium">Medium:</span>
            <span class="stat-value">{{ summary.medium_count }}</span>
        </div>
    </div>

    <h2>Vulnerability Details</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Plugin ID</th>
                <th>Vulnerability</th>
                <th>Affected Hosts</th>
                <th>CVSS</th>
            </tr>
        </thead>
        <tbody>
            {% for vuln in vulnerabilities %}
            <tr>
                <td class="severity-{{ vuln.severity | severity_name | lower }}">
                    {{ vuln.severity | severity_name }}
                </td>
                <td>{{ vuln.plugin_id }}</td>
                <td>{{ vuln.plugin_name }}</td>
                <td>{{ vuln.affected_hosts | length }}</td>
                <td>{{ vuln.cvss_base_score or 'N/A' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="classification">
        UNCLASSIFIED//FOR OFFICIAL USE ONLY
    </div>
</body>
</html>
"""
```

## Jinja2 Configuration

The template engine is configured with:

```python
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader(template_dir) if template_dir else None,
    autoescape=select_autoescape(['html', 'xml']),  # XSS protection
    trim_blocks=True,        # Remove first newline after block
    lstrip_blocks=True,      # Remove leading whitespace before blocks
)

# Add custom filters
env.filters['severity_name'] = severity_name
env.filters['risk_level'] = risk_level
env.filters['format_date'] = format_date
```

**Security Features:**
- **Autoescape**: Prevents XSS by automatically escaping HTML/XML
- **No code execution**: Templates can't execute arbitrary Python

## Integration with Exporters

### HTML Exporter Usage

```python
# From exporters/html_exporter.py
from templates.template_engine import TemplateEngine

def export_html_report(analysis_data, output_file, template_dir=None):
    """Export HTML vulnerability report"""
    engine = TemplateEngine(template_dir=template_dir)

    # Prepare context
    context = {
        "report": analysis_data["report"],
        "summary": analysis_data["summary"],
        "host_summaries": analysis_data["host_summaries"],
        "vulnerabilities": analysis_data["vulnerabilities"],
        "generation_date": datetime.now().isoformat()
    }

    # Render HTML
    html = engine.render_html_report(analysis_data, output_file)

    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_file
```

### PDF Exporter Usage

```python
# From exporters/pdf_exporter.py
from templates.template_engine import TemplateEngine
from weasyprint import HTML

def export_pdf_report(analysis_data, output_file, template_dir=None):
    """Export PDF vulnerability report"""
    engine = TemplateEngine(template_dir=template_dir)

    # Render HTML first
    html = engine.render_html_report(analysis_data, output_file)

    # Convert HTML to PDF using WeasyPrint
    HTML(string=html).write_pdf(output_file)

    return output_file
```

## Template Context Variables

When rendering templates, the following context variables are available:

### report (NessusReport)
```python
{
    "scan_name": str,
    "policy_name": str,
    "scan_start": str,
    "scan_end": str,
    "total_hosts": int,
    "total_vulnerabilities": int,
    "hosts": List[ReportHost]
}
```

### summary (VulnerabilitySummary)
```python
{
    "total_vulnerabilities": int,
    "critical_count": int,
    "high_count": int,
    "medium_count": int,
    "low_count": int,
    "info_count": int,
    "severity_counts": Dict[int, int],
    "family_counts": Dict[str, int],
    "host_counts": Dict[str, int]
}
```

### host_summaries (List[HostSummary])
```python
[
    {
        "hostname": str,
        "ip": str,
        "os": str,
        "risk_score": float,
        "critical_count": int,
        "high_count": int,
        "medium_count": int,
        "low_count": int,
        "info_count": int,
        "total_vulnerabilities": int
    },
    # ... more hosts
]
```

### vulnerabilities (List[Dict])
```python
[
    {
        "plugin_id": str,
        "plugin_name": str,
        "severity": int,
        "family": str,
        "description": str,
        "solution": str,
        "cve": str,
        "cvss_base_score": str,
        "affected_hosts": List[str]
    },
    # ... more vulnerabilities
]
```

## Design Decisions

### Why Jinja2?

**Rationale:**
1. **Industry standard**: Widely used, well-documented
2. **Powerful**: Supports loops, conditionals, filters, inheritance
3. **Secure**: Auto-escaping prevents XSS
4. **Familiar**: Similar to Django/Flask templates

**Alternatives considered:**
- Python f-strings: Too limited for complex templates
- Mako: More powerful but less secure by default
- Mustache: Too simple, lacks built-in filters

### Why Inline Templates?

**Rationale:**
1. **Simplicity**: No external files to manage
2. **Portability**: Single-file distribution
3. **Consistency**: Templates version-controlled with code

**Trade-offs:**
- Less flexible for customization
- Code file becomes longer
- Can't edit templates without code changes

**Future consideration:** Move to external template files for easier customization

### Why Custom Filters?

**Rationale:**
1. **Reusability**: Same logic across all templates
2. **Readability**: `{{ severity | severity_name }}` is clearer than raw mapping
3. **Consistency**: Centralized formatting logic

## Testing

### Test Coverage

Located in `tests/test_vissm.py`:

1. **`test_html_export()`** - Verifies HTML generation works

**Recommended additions:**
```python
def test_severity_name_filter(self):
    """Test severity_name filter"""
    engine = TemplateEngine()
    result = engine.render_string("{{ 4 | severity_name }}", {})
    self.assertEqual(result, "Critical")

def test_risk_level_filter(self):
    """Test risk_level filter"""
    engine = TemplateEngine()
    result = engine.render_string("{{ 85.5 | risk_level }}", {})
    self.assertEqual(result, "Critical")

def test_format_date_filter(self):
    """Test format_date filter"""
    engine = TemplateEngine()
    result = engine.render_string(
        "{{ '2024-01-15T10:30:00' | format_date('%Y-%m-%d') }}",
        {}
    )
    self.assertEqual(result, "2024-01-15")

def test_html_escaping(self):
    """Test that HTML is properly escaped"""
    engine = TemplateEngine()
    result = engine.render_string(
        "<p>{{ text }}</p>",
        {"text": "<script>alert('XSS')</script>"}
    )
    self.assertIn("&lt;script&gt;", result)
    self.assertNotIn("<script>", result)
```

## Common Patterns

### Conditional Rendering

```jinja2
{% if summary.critical_count > 0 %}
    <div class="alert alert-danger">
        <strong>Critical:</strong> {{ summary.critical_count }} critical vulnerabilities found!
    </div>
{% endif %}
```

### Looping with Index

```jinja2
{% for host in host_summaries %}
    <tr class="{{ 'odd' if loop.index % 2 == 1 else 'even' }}">
        <td>{{ loop.index }}</td>
        <td>{{ host.hostname }}</td>
        <td>{{ host.risk_score | round(1) }}</td>
    </tr>
{% endfor %}
```

### Default Values

```jinja2
<p>CVE: {{ vuln.cve or 'N/A' }}</p>
<p>CVSS: {{ vuln.cvss_base_score | default('Not Rated') }}</p>
```

### Nested Loops

```jinja2
{% for family, count in summary.family_counts.items() %}
    <h3>{{ family }} ({{ count }} findings)</h3>
    <ul>
        {% for vuln in vulnerabilities %}
            {% if vuln.family == family %}
                <li>{{ vuln.plugin_name }}</li>
            {% endif %}
        {% endfor %}
    </ul>
{% endfor %}
```

### Custom CSS Classes

```jinja2
<tr class="
    {% if host.risk_score >= 80 %}risk-critical
    {% elif host.risk_score >= 60 %}risk-high
    {% elif host.risk_score >= 40 %}risk-medium
    {% else %}risk-low
    {% endif %}
">
    <td>{{ host.hostname }}</td>
    <td>{{ host.risk_score | round(1) }}</td>
</tr>
```

## Extending the Template Engine

### Adding Custom Filters

```python
# In template_engine.py
def cvss_rating(score: float) -> str:
    """Convert CVSS score to rating"""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    else:
        return "None"

# Register filter
env.filters['cvss_rating'] = cvss_rating
```

**Usage:**
```jinja2
<td class="cvss-{{ vuln.cvss_base_score | float | cvss_rating | lower }}">
    {{ vuln.cvss_base_score | float | cvss_rating }}
</td>
```

### Adding Template Inheritance

**Base Template (base.html):**
```jinja2
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}{% endblock %}</title>
    {% block styles %}
    <style>
        /* Common styles */
    </style>
    {% endblock %}
</head>
<body>
    <div class="classification">
        UNCLASSIFIED//FOR OFFICIAL USE ONLY
    </div>

    <div class="header">
        {% block header %}{% endblock %}
    </div>

    <div class="content">
        {% block content %}{% endblock %}
    </div>

    <div class="footer">
        {% block footer %}
        <p>Generated: {{ generation_date | format_date }}</p>
        {% endblock %}
    </div>
</body>
</html>
```

**Child Template (vulnerability_report.html):**
```jinja2
{% extends "base.html" %}

{% block title %}Vulnerability Report{% endblock %}

{% block header %}
    <h1>{{ report.scan_name }}</h1>
{% endblock %}

{% block content %}
    <h2>Vulnerabilities</h2>
    <table>
        <!-- Vulnerability table -->
    </table>
{% endblock %}
```

### Adding Template Macros

```jinja2
{% macro severity_badge(severity) %}
    <span class="badge badge-{{ severity | severity_name | lower }}">
        {{ severity | severity_name }}
    </span>
{% endmacro %}

<!-- Usage -->
{{ severity_badge(vuln.severity) }}
```

## Troubleshooting

### Issue: TemplateNotFound

**Cause:** Template file doesn't exist or wrong path

**Solution:**
```python
# Check template directory
import os
print(f"Template dir: {template_dir}")
print(f"Templates: {os.listdir(template_dir)}")

# Use absolute path
engine = TemplateEngine(template_dir=os.path.abspath("templates"))
```

### Issue: HTML Not Rendering Properly

**Cause:** Missing context variables

**Solution:**
```python
# Always provide all required context
context = {
    "report": report,
    "summary": summary or {},
    "host_summaries": host_summaries or [],
    "vulnerabilities": vulnerabilities or [],
    "generation_date": datetime.now().isoformat()
}
```

### Issue: Dates Not Formatting

**Cause:** Date format string incorrect

**Solution:**
```python
# Test date parsing
from datetime import datetime

date_str = "2024-01-15T10:30:00"
parsed = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
formatted = parsed.strftime("%Y-%m-%d %H:%M:%S")
print(formatted)
```

### Issue: XSS in Output

**Cause:** Autoescape disabled or using `| safe` filter

**Solution:**
```python
# Ensure autoescape is enabled
env = Environment(
    autoescape=select_autoescape(['html', 'xml'])
)

# Avoid using | safe unless absolutely necessary
```

## Performance Considerations

### Template Caching

Jinja2 automatically caches compiled templates:

```python
# First render: Compiles template
html1 = engine.render_template("report.html", context1)

# Second render: Uses cached compiled template
html2 = engine.render_template("report.html", context2)  # Faster!
```

### Large Data Sets

For reports with >10,000 vulnerabilities:

```python
# Paginate data
vulnerabilities_page_1 = vulnerabilities[0:1000]
vulnerabilities_page_2 = vulnerabilities[1000:2000]

# Or filter before rendering
critical_only = [v for v in vulnerabilities if v["severity"] == 4]
```

## Related Modules

- **exporters.html_exporter** - Primary consumer
- **exporters.pdf_exporter** - Uses HTML output for PDF generation
- **processor.vulnerability_processor** - Provides analysis_data context

## Additional Resources

- **Jinja2 Documentation**: https://jinja.palletsprojects.com/
- **Template Designer Documentation**: https://jinja.palletsprojects.com/en/3.1.x/templates/
- **WeasyPrint**: https://weasyprint.org/ (for PDF generation)

---

**Module Maintainer Notes:**
- Keep templates simple and readable
- Always test with real data (edge cases: empty scans, very large scans)
- Document all custom filters with examples
- Consider moving to external template files in future for easier customization
- Maintain DoD formatting standards in all templates
