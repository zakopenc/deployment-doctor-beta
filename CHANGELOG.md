# Changelog
Script versions for this beta repository. Script versions are numbered separately from the paid kit (guide) versions; the matching kit version is listed for each release. The scripts in each release are byte-identical to the ones in the matching paid kit.

## 2026-10-16: Kit 1 scripts 1.3.2, Kit 2 scripts 1.2.2 (paid kits: Kit 1 v1.4.2, Kit 2 v1.3.2)
- Kit 1 tenant pre-check: with a Standard-user Device Prep policy, the Entra local-admin check reports Warn, not Pass, when that setting can't be read. An empty Graph object no longer turns the check into NotChecked.
- Kit 2 tenant pre-check: each app is checked in its own try/catch; an app that can't be evaluated gets a Warning finding (T00) and the rest of the run still writes a report.
- Kit 2: one PSScriptAnalyzer unused-parameter warning fixed. KC-004 and T09 relabelled Multi-source in `known-causes.json` (v1.2.1).
- HTML report: Scope and Check columns no longer break words mid-word. Kit 1 sample data uses fixed timestamps.

## 2026-10-16: Kit 1 scripts 1.3.1, Kit 2 scripts 1.2.1 (paid kits: Kit 1 v1.4.1, Kit 2 v1.3.1)
- Kit 1 tenant pre-check: the Device Prep service principal and custom-role checks report Info ("Not applicable now") when the tenant has no Device Prep policy. The report's Finding column shows the actual detail.
- Kit 1 device diagnostic: new `-SamplePath` mode that runs on fake data in `kit1/sample-data` and reads nothing on the computer. TPM log-collection text follows Learn.
- Kit 2 report: Kit 2 branding, real status with a separate Confidence column, the analysed log source shown for `-LogPath`, and no "live tenant" wording on the device banner.

## 2026-10-16: Kit 1 scripts 1.3.0, Kit 2 scripts 1.2.0 (paid kits: Kit 1 v1.4.0, Kit 2 v1.3.0)
- HTML dashboard report for all four scripts: health score, status cards, filters, light/dark themes, print layout, `-NoHtml`.
- Any Critical finding caps the health score at 49 with a red "Critical issues present" flag; the score weighting is shown as a legend. Severity pills no longer wrap.

## 2026-10-16: first beta release (Kit 1 scripts 1.3.0, Kit 2 scripts 1.2.0)
- Read-only scripts from Kit 1 v1.3.0 and Kit 2 v1.2.0 with Pester tests.
