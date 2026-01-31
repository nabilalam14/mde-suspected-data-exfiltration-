# Threat Hunting Lab: mde-suspected-data-exfiltration-

## Overview
This project documents a threat hunting investigation conducted in **Microsoft Defender for Endpoint (MDE)** to assess whether a potentially disgruntled employee was staging data for exfiltration. The hunt focused on detecting suspicious file archiving activity, process execution, and correlated network behavior.

No confirmed data exfiltration was identified; however, multiple indicators of **data staging** were observed.

---

## Scenario Summary
An employee under a Performance Improvement Plan (PIP) raised concerns about potential insider threat activity. The employee had local administrator privileges and unrestricted application access. The goal of this hunt was to determine whether sensitive data was being compressed and prepared for exfiltration.

---

## Data Sources
- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

---

## Timeline Summary & Findings

### 1. ZIP Archive Activity Identified
A search of file activity logs revealed repeated creation of `.zip` files on the endpoint, consistent with bulk data archiving behavior.

```kql
DeviceFileEvents
| where DeviceName == "vm-mde"
| where FileName endswith ".zip"
| order by Timestamp desc
```

2. Process Correlation Around Archive Creation

Using the timestamp of a ZIP file creation event, process activity was analyzed within a ±2 minute window. This revealed a PowerShell script that silently installed 7-Zip and immediately used it to compress employee data.
```
let VMName = "vm-mde";
let specificTime = datetime(2026-01-31T14:57:24.3368002Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
Key Observations

    PowerShell executed with bypassed execution policy

    7-Zip installed silently

    Archive creation occurred immediately after installation

    Activity repeated at regular intervals

3. Network Activity Review

Network events were reviewed around the same time window. No evidence of outbound data transfer or exfiltration was observed during the investigation period.
Assessment

    Confirmed: Data staging via scripted ZIP archive creation

    Not Confirmed: External data exfiltration

    Risk Level: Medium (Insider threat preparation behavior)

The activity strongly suggests pre-exfiltration staging, but no network indicators supported actual data theft at this time.
MITRE ATT&CK Mapping

Response:
I relayed the information to the employee’s manager, including everything with the archives being created at
regular intervals via PowerShell script. There didn’t appear to be any evidence of exfiltration. Standing by for
further instructions from management.
Potential alert rule
```
DeviceFileEvents
| where FileName endswith ".zip"
| summarize ZipFileActivity = count() by RequestAccountName
| where ZipFileActivity > 50
```
## MITRE ATT&CK Framework Mapping

- **T1059.001 – Command and Scripting Interpreter: PowerShell**  
  PowerShell was used to silently install 7-Zip and execute archive creation, indicating potential malicious script-based activity.

- **T1560.001 – Archive Collected Data: Archive via Utility**  
  7-Zip was leveraged to compress employee data into ZIP archives, consistent with data staging prior to possible exfiltration.

- **T1070.004 – Indicator Removal on Host: File Deletion**  
  Repeated archiving and backup behavior may indicate an attempt to obscure activity or stage data while minimizing detection.

- **T1105 – Ingress Tool Transfer**  
  The silent installation of 7-Zip suggests the transfer and execution of a tool onto the endpoint.

- **T1055.011 – Process Injection: Extra Window Memory Injection**  
  While no direct evidence of injection was observed, PowerShell-based silent execution can be associated with injection-style execution techniques.

- **T1027 – Obfuscated Files or Information**  
  Scripted installation and execution of utilities may be used to mask malicious intent and evade detection mechanisms.

- **T1047 – Windows Management Instrumentation**  
  Although not explicitly confirmed, silent installations and scripted execution on Windows systems are commonly associated with WMI-based automation.

Response Actions

  -Findings escalated to management
  
  -Employee activity documented
  
  -Continued monitoring recommended
  
  -No immediate containment required due to lack of confirmed exfiltration

Detection Improvement
Potential Alert Rule
```
DeviceFileEvents
| where FileName endswith ".zip"
| summarize ZipFileActivity = count() by RequestAccountName
| where ZipFileActivity > 50
```
This detection can help identify abnormal bulk archiving behavior indicative of insider threat activity.
Skills Demonstrated

    Microsoft Defender for Endpoint (Advanced Hunting)

    Insider threat investigation

    KQL correlation across file, process, and network telemetry

    MITRE ATT&CK TTP mapping

    Incident documentation and reporting****
