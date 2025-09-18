[![PowerShell Script Analyzer](https://github.com/CainLabs/CMMC-L2-Baseline-Auditor/actions/workflows/lint.yml/badge.svg)](https://github.com/CainLabs/CMMC-L2-Baseline-Auditor/actions/workflows/lint.yml)

# CMMC Level 2 Baseline Auditor

A PowerShell script to perform a read-only audit of a Windows system against a core set of CMMC 2.0 Level 2 technical controls derived from NIST SP 800-171.

## The Problem

Many small and medium-sized businesses in the Defense Industrial Base (DIB) are overwhelmed by the technical requirements of CMMC 2.0. They often lack the resources for expensive auditing tools and need a simple, effective way to get a snapshot of their current compliance posture. Answering the basic question, "How far off are we?", is a critical first step on their compliance journey.

## The Solution

This script provides a no-cost, lightweight solution to this problem. It runs on any Windows Server or Workstation and audits a key set of technical controls related to access control, authentication, and logging. It is entirely **read-only** and makes no changes to the system.

The script generates a clean, easy-to-understand compliance report in either **HTML** or **CSV** format, highlighting any identified gaps between the system's current configuration and CMMC requirements.

## Key Features

* **Targeted CMMC Auditing:** Checks a high-impact subset of CMMC 2.0 Level 2 technical controls.
* **Read-Only & Safe:** Makes no configuration changes to the system it's run on.
* **Clear Pass/Fail Reporting:** Generates a report with color-coding for at-a-glance identification of compliance gaps.
* **Flexible Output:** Provides reports in both user-friendly HTML and data-friendly CSV formats.
* **No Dependencies:** Runs with built-in PowerShell commands, requiring no external modules.

## Usage

To run the script, open a PowerShell console with administrative privileges, navigate to the script's directory, and execute it with the required parameters.

**HTML Report Example:**
```powershell
.\CMMC-L2-Baseline-Auditor.ps1 -ReportPath "C:\CMMC-Audits\report.html" -Verbose
```

**CSV Report Example:**
```powershell
.\CMMC-L2-Baseline-Auditor.ps1 -ReportPath "C:\CMMC-Audits\report.csv" -Format CSV
```

## Sample HTML Report

![Sample CMMC HTML Report](https://github.com/CainLabs/CMMC-L2-Baseline-Auditor/blob/main/assets/sample_html_report.png?raw=true)

## Disclaimer

This tool is provided as-is to assist with security and compliance efforts. It is not a guarantee of CMMC compliance and only covers a subset of the required controls. Always use this tool as one component of a comprehensive security and compliance program.
