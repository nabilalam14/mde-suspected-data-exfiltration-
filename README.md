# Microsoft Defender for Endpoint Threat Hunting  
## Suspected Internal Data Staging & Exfiltration Preparation

---

## 📌 Overview
This project documents a **threat hunting investigation** conducted using **Microsoft Defender for Endpoint (MDE)** to assess potential insider threat activity involving data staging and preparation for exfiltration.

The investigation focused on correlating **file creation**, **process execution**, and **network activity** to determine whether sensitive data was being compressed and prepared for removal from the environment.

---

## 🧠 Scenario Summary
An employee with **local administrator privileges** was placed on a Performance Improvement Plan (PIP), raising concerns of potential malicious insider behavior. The employee had unrestricted application access and the capability to install utilities and execute scripts.

**Objective:**  
Determine whether data was being archived and staged for potential exfiltration.

---

## 📊 Data Sources
- DeviceFileEvents  
- DeviceProcessEvents  
- DeviceNetworkEvents  

---

## 🕒 Timeline Summary & Findings

### 1️⃣ ZIP Archive Creation Activity
A review of file activity logs revealed repeated creation of `.zip` files on the endpoint, consistent with bulk data archiving behavior.

```kql
DeviceFileEvents
| where DeviceName == "vm-mde"
| where FileName endswith ".zip"
| order by Timestamp desc
```
<img width="1512" height="499" alt="Screenshot 2026-01-31 114541" src="https://github.com/user-attachments/assets/fa0ae4b9-1b1e-4a70-aab7-86e2b8a53131" />

---

### 2️⃣ Process Activity Correlation (±2 Minutes)
Using the timestamp of a ZIP file creation event, process execution was reviewed within a two-minute window before and after the event.

```kql
let VMName = "vm-mde";
let specificTime = datetime(2026-01-31T14:57:24.3368002Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
<img width="1496" height="631" alt="Screenshot 2026-01-31 114333" src="https://github.com/user-attachments/assets/1d557f5b-fd73-4c6e-ba98-6e64572b1595" />

**Key Observations**
- PowerShell executed with bypassed execution policy  
- 7-Zip was silently installed  
- ZIP archives were created immediately after installation  
- Behavior occurred at regular intervals  

---

### 3️⃣ Network Activity Review
Network telemetry was reviewed around the same time window.  
**No evidence of outbound data exfiltration** was observed during the investigation period.

---

## 🛡️ MITRE ATT&CK Framework Mapping

- **T1059.001 – Command and Scripting Interpreter: PowerShell**  
  PowerShell was used to silently install 7-Zip and execute archive creation.

- **T1560.001 – Archive Collected Data: Archive via Utility**  
  7-Zip was used to compress data into ZIP archives, consistent with data staging behavior.

- **T1070.004 – Indicator Removal on Host: File Deletion**  
  Repeated archiving and backup behavior may indicate an attempt to obscure activity.

- **T1105 – Ingress Tool Transfer**  
  Silent installation of 7-Zip demonstrates tool transfer to the endpoint.

- **T1055.011 – Process Injection: Extra Window Memory Injection**  
  While not directly observed, PowerShell-based silent execution can overlap with injection-style techniques.

- **T1027 – Obfuscated Files or Information**  
  Scripted execution and silent utility usage may reduce visibility of malicious activity.

- **T1047 – Windows Management Instrumentation**  
  Silent installations and automated execution are commonly associated with WMI-based techniques.

---

## 🚨 Detection Improvement

### Potential Alert Rule – Bulk ZIP Creation
```kql
DeviceFileEvents
| where FileName endswith ".zip"
| summarize ZipFileActivity = count() by RequestAccountName
| where ZipFileActivity > 50
```

This detection may help identify abnormal bulk archiving activity related to insider threat behavior.

---

## 🧾 Final Assessment
- **Confirmed:** Data staging via scripted archive creation  
- **Not Confirmed:** Data exfiltration  
- **Risk Level:** Medium  
- **Recommendation:** Continued monitoring and alert tuning  

---

## 🚀 Skills Demonstrated
- Microsoft Defender for Endpoint Advanced Hunting  
- KQL query development and pivoting  
- Insider threat investigation  
- MITRE ATT&CK TTP mapping  
- Incident documentation and reporting  
