# Invoke-DFIRParse-AllArtefacts

[![Platform](https://img.shields.io/badge/Platform-Windows-blue)](#requirements)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A PowerShell orchestrator for parsing artefacts from a mounted or collected Windows filesystem. It runs Eric Zimmerman's tools, optional third-party parsers, and built-in collectors, then organises results by hostname and artefact category.

Outputs include CSV, JSON, browser XLSX reports, text summaries, and copied source artefacts. Coverage depends on the collected files, installed tools, and selected RECmd batch.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Forensic coverage](#forensic-coverage)
- [Tools directory](#tools-directory)
- [Output layout](#output-layout)
- [Evidence handling and limitations](#evidence-handling-and-limitations)
- [Logs and troubleshooting](#logs-and-troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Requirements

- Windows with PowerShell. The script targets Windows PowerShell 5.1 and PowerShell 7 on Windows; end-to-end compatibility across these versions and external parser versions has not been verified for this initial publication.
- An already mounted or extracted Windows filesystem, with paths such as `Windows\System32\config` and `Users` beneath `-ImageRoot`. The script does not mount E01/VHD files or accept those image files directly.
- An existing `-ToolsDir` containing the parsers you want to run. External tools are optional; missing tools or source artefacts generally cause the corresponding processing step to be skipped.
- An elevated PowerShell session for registry-loading features, including BAM/DAM, persistence, firewall rules, Office MRU, and hostname/IP resolution. The built-in SAM reader does not use registry mounting.
- A writable output directory outside the evidence tree, with space for reports, ESE working copies, and collected email stores.
- A valid `.reb` file if you want RECmd batch processing. No batch file is bundled with this repository; supply a batch appropriate to your investigation from your RECmd installation or your own collection.

Optional runtimes:

- Perl and `mactime.pl` for converting the MFT bodyfile into a timeline CSV. Obtain `mactime.pl` separately and pass its actual location.
- Python and each parser's dependencies for Python-based integrations. IconCacheReader and Defender Python fallbacks invoke `python` from PATH; ChromeSessions searches for `py`, `python`, then `python3`.

## Quick start

Download [Invoke-DFIRParse-AllArtefacts.ps1](Invoke-DFIRParse-AllArtefacts.ps1), prepare your tools directory, and open an elevated PowerShell session in the script's directory.

Run these commands directly in PowerShell. If script execution is blocked, use an execution-policy setting permitted by your environment.

```powershell
# Run available parsers and built-in collectors; RECmd batch processing is skipped.
.\Invoke-DFIRParse-AllArtefacts.ps1 `
    -ImageRoot 'E:\' `
    -OutputDir 'C:\Cases\CASE001\Run01' `
    -ToolsDir 'C:\Tools\DFIR'
```

To include RECmd batch processing, point to an existing batch file:

```powershell
.\Invoke-DFIRParse-AllArtefacts.ps1 `
    -ImageRoot 'E:\' `
    -OutputDir 'C:\Cases\CASE001\Run02' `
    -ToolsDir 'C:\Tools\DFIR' `
    -RebFile 'C:\Tools\DFIR\RECmd\BatchExamples\YourBatch.reb'
```

Replace the example batch path with your actual file. To add an MFT timeline and skip selected steps:

```powershell
.\Invoke-DFIRParse-AllArtefacts.ps1 `
    -ImageRoot 'C:\Cases\HOST1\C' `
    -OutputDir 'C:\Cases\CASE001\Run03' `
    -ToolsDir 'C:\Tools\DFIR' `
    -MactimePath 'C:\Tools\SleuthKit\mactime.pl' `
    -SkipTools Hindsight, sidr, Email
```

## Usage

| Parameter | Required | Meaning |
|---|---|---|
| `-ImageRoot` | Yes | Root of the mounted or collected Windows filesystem. |
| `-OutputDir` | Yes | Output base directory; the script appends a hostname subfolder. Use a fresh directory for each run. |
| `-ToolsDir` | Yes | Existing tools directory, searched recursively for supported executables and scripts. |
| `-RebFile` | No | Existing RECmd batch file. Without it, RECmd batch processing is skipped. |
| `-DateTimeFormat` | No | Format string passed through `--dt` to selected external tool invocations. It does not standardise all output timestamps or convert time zones. |
| `-MactimePath` | No | Path to `mactime.pl`; requires Perl for MFT timeline conversion. |
| `-SkipTools` | No | Array of step identifiers to skip; see below. |

### Skip identifiers

Use these identifiers, which do not always match executable names:

```text
RECmd, AppCompatCacheParser, AmcacheParser, PECmd, MFTECmd,
SrumECmd, SBECmd, JLECmd, LECmd, WxTCmd, RBCmd,
CryptNet, PSReadline, OfficeMRU, Hindsight, ChromeSessions,
sidr, SUM, IconCache, Defender, RegPersistence, BAM,
Firewall, SAM, Evtx, PCA, Email, OsDetails
```

For example, `-SkipTools SUM, IconCache, Evtx` skips SumECmd, IconCacheReader, and EvtxECmd processing. Unknown identifiers are not validated. Skipping a step does not suppress overlapping artefacts produced by other tools, and hostname resolution still runs during setup.

## Forensic coverage

| Category | Artefacts / output | Provider or dependency |
|---|---|---|
| Execution | Prefetch, ShimCache, Amcache, Windows Timeline | PECmd, AppCompatCacheParser, AmcacheParser, WxTCmd |
| Execution | BAM/DAM, PCA, PowerShell command history | Built-in parsing or collection |
| Execution | Historical icon-cache paths, CSV and JSON | IconCacheReader; the wrapper does not request Amcache enrichment |
| Registry-derived activity | UserAssist, RecentDocs, USBSTOR, MountedDevices, ProfileList, TaskCache | Depends on the supplied RECmd batch and plugins |
| File/folder activity | ShellBags, Jump Lists, LNK files, Recycle Bin | SBECmd, JLECmd, LECmd, RBCmd |
| File/folder activity | Office File/Place MRU | Built-in registry extraction |
| File/folder activity | Windows Search index | sidr |
| NTFS | MFT CSV and bodyfile; USN journal with MFT path resolution when available | MFTECmd; optional Perl/mactime timeline |
| Network | SRUM; SUM client-access data | SrumECmd; SumECmd |
| Network / persistence | Run keys, Winlogon, IFEO, AppInit, services, shares, RDP MRU, PuTTY, network drives, firewall rules/logs and other selected registry keys | Built-in extraction; some data may also appear in RECmd results |
| Accounts | Local SAM account inventory | Built-in raw hive reader |
| Browser | Chromium profile reports | Hindsight; profiles without a History database are skipped |
| Browser | Chrome session/tab recovery | External SNSS Python parser |
| Cache | CryptnetUrlCache URL extraction | Built-in collector |
| Defender | MPDetection/MPLog copies; DetectionHistory parser output or raw copies | Optional DetectionHistory parser |
| Email | Selected Outlook and Thunderbird files, copied without parsing | Built-in collector |
| System information | OS summary, hostname, configured IPv4 addresses | Registry extraction and available RECmd output |
| Event logs | CSV from collected Windows event logs | EvtxECmd |

Scheduled-task coverage is registry TaskCache coverage through the selected RECmd batch, not a dedicated task-file parser. A category folder does not establish that all artefacts in that category were collected or successfully parsed. Artefact categories are organisational labels, not standalone conclusions about execution or user activity.

## Tools directory

1. Obtain [Eric Zimmerman's tools](https://ericzimmerman.github.io/), including the tools relevant to your collection. Keep their required runtime files and supporting resources with them.
2. Place tools beneath one directory. Both flat and per-tool-subfolder layouts are supported; the script searches recursively and selects the first matching executable when no root-level match exists.
3. Add optional integrations below and their dependencies.
4. Provide your chosen RECmd batch through `-RebFile`.

The wrapper recognises these EZ executables:

```text
RECmd.exe, AppCompatCacheParser.exe, AmcacheParser.exe, PECmd.exe,
MFTECmd.exe, SrumECmd.exe, SBECmd.exe, JLECmd.exe, LECmd.exe,
RBCmd.exe, WxTCmd.exe, SumECmd.exe, EvtxECmd.exe
```

| Optional integration | Expected file in the tools directory |
|---|---|
| [Hindsight](https://github.com/obsidianforensics/hindsight) | `hindsight.exe` |
| [sidr](https://github.com/strozfriedberg/sidr) | `sidr.exe` |
| [IconCacheReader](https://github.com/peli-rufus/IconCacheReader) | `IconCacheReader.exe`, or `IconCacheReader.py` with Python |
| ChromeSessions | `SNSS-parser-win_v1.py` or `SNSS-parser-win.py` with Python |
| Defender DetectionHistory | `DefenderHistoryParser.exe` or `defender-detectionhistory-parser.py` with Python |

Third-party tools and custom Python parsers are not bundled. Matching a filename does not guarantee a compatible command-line interface; check the tool's documentation and inspect the resulting logs and reports.

## Output layout

```text
<OutputDir>\<HOSTNAME>\
  00_Execution\
  01_FileFolderActivity\
  02_NTFS\
  03_USB\
  04_Network\
  05_Persistence\
  06_Accounts\
  07_SystemInfo\        # OS_Details.txt
  08_Registry_Raw\      # RECmd batch and plugin output
  09_BrowserAndCache\
  10_BrowserForensics\  # Hindsight and ChromeSessions results
  11_Defender\
  12_Email\            # Selected copied mail files
  13_EventLogs\
  _logs\               # Main log and available per-tool logs
```

Many categories contain per-artefact or per-user subfolders. Recognised RECmd plugin CSVs are copied into categories while the original RECmd output remains in `08_Registry_Raw`.

Hostname resolution falls back to `UnknownHost` when unsuccessful. Hosts with the same resolved name share the same destination beneath a given output base. Reusing an output directory can overwrite fixed-name reports, mix old and new results, and reset the main log.

## Evidence handling and limitations

- **Registry loading:** `Use-MountedHive` copies hives and available transaction logs to temporary storage before loading them. However, initial hostname/IP resolution in `Resolve-SystemInfo` loads the source SYSTEM hive directly. The current script therefore does not provide a blanket guarantee that every hive is loaded from a copy. Use a separate working collection when source preservation is required.
- **ESE recovery:** SUM and Search Index recovery uses copied database sets. The script checks database state, attempts soft recovery, and may automatically run hard repair on the working copy. Hard repair can discard data from that copy; inspect recovery logs when interpreting results.
- **Temporary files:** Registry work uses the host's temporary directory. Jump List parsing uses a short temporary directory on the system drive. Allow sufficient space and write access.
- **Collection limits:** Outlook collection searches the standard per-user local Outlook directory. Thunderbird collection selects `.msf`, `.mbox`, and files named `Inbox` or `Sent`; it is not a complete profile backup.
- **Broad searches:** LNK and ChromeSessions processing can search throughout the image root. Keep outputs and tools outside that tree.
- **Tool versions:** There is no pinned dependency set or automatic compatibility check. Parser options and output formats may change between versions.
- **Validation:** The published script has passed a PowerShell syntax check. This is not an end-to-end validation against a forensic image.

## Logs and troubleshooting

Review `_logs\Invoke-DFIRParse.log`, available per-tool logs, and the actual output files after each run.

- Missing tools and input files generally cause individual steps to be skipped, but not every skip is logged.
- Hindsight prints directly to the console; its full console output is not captured in a per-tool log.
- A final `Done` message does not certify success for every parser. External exit codes are not checked consistently, and there is no consolidated success/partial-failure exit-code contract.
- Missing RECmd results: check `RECmd.exe`, `-RebFile`, and the batch's coverage.
- Missing registry results: check elevation, available hives, and hive-load messages.
- Missing Python results: check the expected script filename, interpreter command, and dependencies.
- Missing MFT timeline: check the MFT/bodyfile output, Perl installation, and actual `mactime.pl` path.

These are operational logs, not a complete chain-of-custody record or evidence-hash manifest.

## Contributing

Issues and pull requests are welcome. For bug reports, include the script revision, PowerShell and parser versions, relevant command, collection layout, and redacted logs. Describe expected and actual output; avoid including case evidence or personal data in public reports.

## License

[MIT](LICENSE). Third-party tools retain their own licences.
