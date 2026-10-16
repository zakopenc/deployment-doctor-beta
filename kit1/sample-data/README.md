# Sample data (fake)
Practice runs for `Invoke-DeviceDiagnostic.ps1` on any computer. Each folder holds a `device.json` (registry values, event log entries, OS and IME service state) and an `IMELogs` folder. **All of it is invented**: placeholder names (Contoso, Fabrikam), placeholder IDs and made-up messages. None of it comes from a real device.

| Folder | What it simulates | Expected verdicts |
|---|---|---|
| `device-prep-failure` | Autopilot device preparation: an app failed in the progress data, Bootstrapper error events, "actively refused" in the IME log | D_DP_PROGRESS_FAILURE (Fail), Bootstrapper errors, actively refused |
| `autopilot-esp-app-error` | Autopilot v1 (ESP): a Win32 app in InstallationState 4 (Error), a script timeout line | D_ESP_APP_ERROR (Fail), script timeout |

Run from the kit's top folder:
```powershell
.\scripts\Invoke-DeviceDiagnostic.ps1 -SamplePath .\sample-data\device-prep-failure -OutputPath .\sample-out
.\scripts\Invoke-DeviceDiagnostic.ps1 -SamplePath .\sample-data\autopilot-esp-app-error -OutputPath .\sample-out
```
In `-SamplePath` mode the script reads only the sample folder. It does not query this computer's registry, event logs, WMI or services, and nothing is sent anywhere. The report header shows "SAMPLE" and the sample folder as the source.
