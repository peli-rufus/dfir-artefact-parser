# Invoke-DFIRParse-AllArtefacts

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://learn.microsoft.com/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue)](#requirements)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A PowerShell orchestrator that chains **Eric Zimmerman's DFIR tools** and an **RECmd batch run** across a full Windows Forensics Artefact Value Matrix — Execution, Persistence, Network, USB, Accounts, Event Logs, and more — against a mounted or collected image.

Built for incident response triage. Point it at an image root and a tools directory; it categorises every CSV into a clean, numbered folder structure per host, with automatic ESE database recovery and elevation-aware registry extraction for artefacts that have no existing parser.

---

## Table of Contents

- [What it does](#what-it-does)
- [Forensic Coverage](#forensic-coverage)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Output Layout](#output-layout)
- [Notes on Specific Artefacts](#notes-on-specific-artefacts)
- [Building Your Tools Directory](#building-your-tools-directory)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

Given an offline image root (a mounted E01/VHD, or a flattened `C:\` collection), the script runs — **only if the corresponding EXE is present** in your tools directory — the following against it:

`RECmd` · `AppCompatCacheParser` · `AmcacheParser` · `PECmd` · `MFTECmd` · `SrumECmd` · `SBECmd` · `JLECmd` · `LECmd` · `RBCmd` · `WxTCmd` · `sidr` · `SumECmd` · `IconCacheReader` · `Hindsight`

...plus a set of custom parsers for artefacts that have **no existing EZ tool**, written in pure PowerShell:

- `CryptnetUrlCache` — per-user + SYSTEM URL carve from MetaData blobs
- `RegPersistence` — Run/RunOnce/Winlogon/IFEO/AppInit/AppPaths/Services/Uninstall/Shares + per-user RDP MRU/MountPoints2/RecentApps/NetworkDrives/PuTTY/MUICache
- `BAM/DAM` — execution evidence with decoded FILETIME, per SID
- `SAM` — local accounts decoded directly from raw hive bytes (bypasses ACL restrictions that block a reg-mount read)
- `Firewall` — rules parsed from the SYSTEM hive + `pfirewall.log` collection
- `OfficeMRU` — per-user Office File/Place MRU with decoded per-entry FILETIME
- `PCA` — Win11 22H2+ Program Compatibility Assistant execution artefact
- `PSReadline` — typed PowerShell command history
- `Defender` — MPDetection/MPLog + DetectionHistory
- `Email` — Outlook `.ost`/`.pst` and Thunderbird store collection (copy only, opened offline later)
- `OsDetails` — hostname, OS build, time zone, and IPv4 addresses summarised to a plain-text file

Every category, folder, and skip condition is logged to `_logs\Invoke-DFIRParse.log` for chain-of-custody and troubleshooting.

---

## Forensic Coverage

| Category | Examples |
|---|---|
| Execution | Prefetch, ShimCache, Amcache, BAM/DAM, UserAssist, Timeline, PCA, PSReadline |
| File/Folder Activity | ShellBags, LNK, Jump Lists, RecentDocs, Office MRU, Search Index |
| NTFS | `$MFT` (CSV + mactime bodyfile), `$J` (UsnJrnl, MFT-resolved) |
| USB | USBSTOR, MountedDevices, MountPoints2 |
| Network | SRUM, RDP MRU, PuTTY, Shares, Network Drives, Firewall rules/logs, SUM |
| Persistence | Run keys, Winlogon, IFEO, AppInit_DLLs, Services, Scheduled Tasks |
| Accounts | SAM (raw-parsed), ProfileList |
| Registry Raw | Full RECmd batch + plugin CSVs |
| Browser | Chromium history via Hindsight, CryptnetUrlCache |
| Defender | Detection history, MPLog |
| Email | Outlook/Thunderbird store collection |
| Event Logs | Consolidated EvtxECmd CSV across all channels |

Each category is a numbered subfolder (`00_Execution` → `13_EventLogs`) so triage stays consistent across cases.

---

## Requirements

- Windows PowerShell 5.1+ (or PowerShell 7 on Windows)
- **Run elevated** — several artefacts (BAM/DAM, SAM via raw parse doesn't need it, RegPersistence, Firewall, hostname/IP resolution) load hives via `reg.exe load`, which requires the restore privilege
- [Eric Zimmerman's tools](https://ericzimmerman.github.io/) placed in a single `-ToolsDir` (flat or per-tool-folder layout both work)
- An `.reb` batch file for RECmd (ships with EZ Tools, or build your own)
- Optional: Perl (Strawberry Perl) + `mactime.pl` for `$MFT` timeline conversion
- Optional: [Hindsight](https://github.com/obsidianforensics/hindsight) for Chromium browser parsing
- Optional: [sidr](https://github.com/strozfriedberg/sidr) for Windows Search index parsing
- Optional: [IconCacheReader](https://github.com/peli-rufus/IconCacheReader) for historical icon-cache binary paths

Every tool is optional — the script skips gracefully (with a log entry) if an EXE isn't found.

---

## Quick Start

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DFIRParse-AllArtefacts.ps1 `
    -ImageRoot "E:\" `
    -OutputDir "C:\Cases\HOSTNAME\parsed" `
    -ToolsDir  "C:\Tools\EZ" `
    -RebFile   "C:\Tools\EZ\WindowsForensics_Matrix.reb"
```

With `$MFT` mactime timeline and skipping a couple of slow tools:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DFIRParse-AllArtefacts.ps1 `
    -ImageRoot "C:\Cases\HOST1\C" `
    -OutputDir "C:\Cases\HOST1\parsed" `
    -ToolsDir  "C:\Tools\EZ" `
    -RebFile   "C:\Tools\EZ\WindowsForensics_Matrix.reb" `
    -MactimePath "C:\Strawberry\perl\bin\mactime.pl" `
    -SkipTools Hindsight, sidr
```

---

## Usage

```
Invoke-DFIRParse-AllArtefacts.ps1
    -ImageRoot <path>       (required) Root of the mounted/collected image — must contain Windows\ and Users\
    -OutputDir <path>       (required) Destination for categorised CSV output (nested under a hostname subfolder)
    -ToolsDir  <path>       (required) Directory containing the EZ tool EXEs and RECmd.exe
    -RebFile   <path>       Full path to the RECmd .reb batch file
    -DateTimeFormat <str>   Optional custom --dt format string passed to each tool
    -MactimePath <path>     Optional path to mactime.pl for $MFT bodyfile → timeline CSV
    -SkipTools <string[]>   Optional array of tool names to skip, e.g. MFTECmd, SrumECmd
```

### Examples

```powershell
# Minimal run — RECmd + whatever EZ tools are present, no timeline conversion
.\Invoke-DFIRParse-AllArtefacts.ps1 -ImageRoot E:\ -OutputDir C:\Cases\Parsed -ToolsDir C:\Tools\EZ

# Skip email collection and firewall parsing on a fast triage pass
.\Invoke-DFIRParse-AllArtefacts.ps1 -ImageRoot E:\ -OutputDir C:\Cases\Parsed `
    -ToolsDir C:\Tools\EZ -RebFile C:\Tools\EZ\Matrix.reb -SkipTools Email, Firewall

# Custom timestamp format across every tool
.\Invoke-DFIRParse-AllArtefacts.ps1 -ImageRoot E:\ -OutputDir C:\Cases\Parsed `
    -ToolsDir C:\Tools\EZ -DateTimeFormat "yyyy-MM-dd HH:mm:ss"
```

---

## Output Layout

```
<OutputDir>\<HOSTNAME>\
  00_Execution\
  01_FileFolderActivity\
  02_NTFS\
  03_USB\
  04_Network\
  05_Persistence\
  06_Accounts\
  07_SystemInfo\        ← OS_Details.txt (hostname, build, time zone, IPs)
  08_Registry_Raw\      ← full RECmd batch + plugin CSVs
  09_BrowserAndCache\
  10_BrowserForensics\  ← Hindsight XLSX
  11_Defender\
  12_Email\             ← copied .ost/.pst/.msf (not parsed)
  13_EventLogs\
  _logs\                ← Invoke-DFIRParse.log + per-tool console logs
```

Output is nested under a hostname folder automatically resolved from the SYSTEM hive, so multiple hosts can share one `-OutputDir`.

---

## Notes on Specific Artefacts

| Artefact | Note |
|---|---|
| ESE databases (SUM, Search Index) | Recovered on a **working copy** via `esentutl` (soft recovery → hard repair) before parsing. Originals are never touched. |
| SAM | Parsed directly from raw hive bytes (regf/hbin/nk/vk walk), since SAM subkeys are ACL-protected even for elevated `reg.exe load` reads. |
| Hostname / IP resolution | SYSTEM hive is mounted once up front to resolve both, with an RECmd CSV fallback for hostname-only if not elevated. |
| Hive mounts | Every hive is copied to a private temp file before `reg.exe load` — never loaded from the original, and never held open longer than the scriptblock needs. |
| $J / UsnJrnl | Script checks `$Extend\$J`, `$Extend\$UsnJrnl_$J`, and a few flattened-collection alternates. |
| Jump Lists | Parsed to a short temp path first to avoid `MAX_PATH` (260-char) failures from long AppID filenames. |

---

## Building Your Tools Directory

1. Download [EZ Tools](https://ericzimmerman.github.io/) (via `Get-ZimmermanTools.ps1` is easiest)
2. Drop everything into one folder — flat or per-tool-subfolder layout, the script searches recursively
3. Add optional third-party tools: [Hindsight](https://github.com/obsidianforensics/hindsight), [sidr](https://github.com/strozfriedberg/sidr), [IconCacheReader](https://github.com/peli-rufus/IconCacheReader)
4. Point `-ToolsDir` at that folder

---

## Contributing

Issues and PRs welcome — especially additional artefact coverage, alternate `$J`/collection-layout paths encountered in the wild, and fixes for tool CLI drift.

---

## License

[MIT](LICENSE)
