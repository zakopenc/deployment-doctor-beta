---
name: Test report
about: Report the results of running a Deployment Doctor beta script
title: "[Test report] <script name>"
labels: test-report
---

<!--
BEFORE YOU POST: remove tenant names, tenant IDs, device IDs, user/object IDs,
UPNs and email addresses, serial numbers, hostnames, and any secrets, tokens
or client secrets. Replace them with placeholders like <TENANT>, <DEVICE-ID>, <UPN>.
Do not attach unredacted HTML/JSON reports or log files.
-->

## Script
- [ ] kit1/Invoke-TenantPreCheck.ps1
- [ ] kit1/Invoke-DeviceDiagnostic.ps1
- [ ] kit2/Invoke-TenantPreCheck.ps1
- [ ] kit2/Invoke-DeviceDiagnostic.ps1

## Environment
- Tenant type (test / production-like / dev):
- Windows version and build:
- PowerShell version (`$PSVersionTable.PSVersion`):
- Microsoft.Graph.Authentication version (tenant scripts):
- Deployment type (Autopilot v1 / Device Prep / Win32 app):
- Run context (admin / SYSTEM / Shift+F10 / offline logs):

## Results
- What did you expect?
- What did the script report (redacted)?
- Were the findings correct? Any false positives or missed issues?

## Errors
Paste redacted error messages or warnings here.

```
<redacted output>
```
