# Quick Start Guide - Virtual POAM Generator

Get started in 5 minutes!

## Step 1: Install

```bash
# Clone the repo
git clone https://github.com/yourusername/virtual-poam-generator.git
cd virtual-poam-generator

# Install dependencies
pip install -r requirements.txt
```

## Step 2: Get Your Nessus File

Export a `.nessus` file from your Tenable Nessus scanner:
1. Log into Nessus web interface
2. Go to Scans → Select your scan
3. Click Export → Select ".nessus" format
4. Save the file (e.g., `scan.nessus`)

## Step 3: Generate Your First POAM

```bash
python cli.py scan.nessus -o my_poam.xlsx -r poam
```

That's it! Open `my_poam.xlsx` in Excel.

## What You Get

Your POAM will include:
- ✅ All Cat I/II/III vulnerabilities
- ✅ Automatic risk categorization
- ✅ Scheduled completion dates
- ✅ Affected host lists
- ✅ Remediation guidance
- ✅ DoD-compliant formatting

## Common Commands

### Generate POAM (Most Common)
```bash
python cli.py scan.nessus -o poam.xlsx -r poam
```

### Detailed Vulnerability Report
```bash
python cli.py scan.nessus -o vulnerabilities.xlsx -r vulnerability
```

### eMASS Hardware/Software Inventory
```bash
python cli.py scan.nessus -o inventory.xlsm -r emass-inventory
```

### Executive Summary (CSV)
```bash
python cli.py scan.nessus --summary -o summary.csv
```

### All Reports at Once
```bash
python cli.py scan.nessus -o poam.xlsx -r poam
python cli.py scan.nessus -o vulns.xlsx -r vulnerability
python cli.py scan.nessus -o inventory.xlsm -r emass-inventory
python cli.py scan.nessus -o tests.xlsx -r ivv-test-plan
```

## Need Help?

```bash
# See all options
python cli.py --help

# Verbose output for debugging
python cli.py scan.nessus -o output.xlsx -r poam --verbose
```

## Troubleshooting

**Error: File not found**
- Make sure the .nessus file path is correct
- Use quotes around filenames with spaces

**Error: Invalid XML**
- Re-export the .nessus file from Nessus
- Ensure the file wasn't corrupted during transfer

**Empty output**
- Check if the scan has vulnerabilities
- Use `--verbose` flag to see details
- Ensure scan completed successfully in Nessus

## Next Steps

1. Customize POC names in the POAM
2. Adjust completion dates as needed
3. Add specific milestones
4. Import into eMASS

## Report Types Explained

| Type | When to Use |
|------|------------|
| **poam** | For eMASS POAM tracking - START HERE |
| **vulnerability** | Technical deep-dive, patch planning |
| **emass-inventory** | Hardware/software inventory for eMASS |
| **ivv-test-plan** | After remediation verification |
| **hw-sw-inventory** | Detailed asset tracking |
| **cnet** | Network compliance reporting |

## Pro Tips

1. **Name your files meaningfully:**
   ```bash
   python cli.py scan.nessus -o POAM_SystemName_2024-01.xlsx -r poam
   ```

2. **Generate all reports monthly:**
   ```bash
   python cli.py monthly.nessus -o monthly_poam.xlsx -r poam
   python cli.py monthly.nessus -o monthly_vulns.xlsx -r vulnerability
   ```

3. **Keep raw .nessus files for audit trail**

4. **Use verbose mode when testing:**
   ```bash
   python cli.py scan.nessus -o test.xlsx -r poam --verbose
   ```

---

**Ready?** Just run: `python cli.py your_scan.nessus -o poam.xlsx -r poam`
