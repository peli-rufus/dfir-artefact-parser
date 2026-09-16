<#
  powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DFIRParse-AllArtefacts.ps1 `
      -ImageRoot "E:\" `
      -OutputDir "C:\Cases\HOSTNAME\parsed" `
      -ToolsDir  "C:\Tools\EZ" `
      -RebFile   "C:\Tools\EZ\WindowsForensics_Matrix.reb"

.SYNOPSIS
  Master DFIR artefact parser for a mounted/collected Windows image.
  Chains Eric Zimmerman tools + RECmd batch across all artefact categories
  from the Windows Forensics Artefact Value Matrix, organising CSV output
  into category subfolders (Execution, Persistence, Network, etc.).

.DESCRIPTION
  Runs the following tools, each only if its EXE is present in -ToolsDir:
    RECmd                 - registry batch (all hives) via .reb file
    AppCompatCacheParser  - ShimCache (binary blob in SYSTEM)
    AmcacheParser         - AmCache.hve (SHA1 + file entries)
    PECmd                 - Prefetch (.pf run times)
    MFTECmd               - $MFT (CSV + bodyfile->mactime timeline), $J (MFT-resolved)
    SrumECmd              - SRUDB.dat (network + process usage)
    SBECmd                - ShellBags (all user profiles)
    JLECmd                - Jump Lists (Automatic + Custom, all users)
    LECmd                 - LNK files (Recent, Desktop, Startup, Downloads, Start Menu, all users)
    RBCmd                 - Recycle Bin ($I files)
    WxTCmd                - Win10 Timeline (ActivitiesCache.db, all users)
    sidr                  - Windows.edb / Windows.db search index (auto ESE recovery)
    SumECmd               - SUM client-access DB, Server 2012+ (auto ESE recovery)
    IconCacheReader       - IconCache.db historical binary paths (all users)
    CryptnetUrlCache      - per-user + SYSTEM URL carve (pure PowerShell)
    Hindsight             - Chromium browser forensics (Chrome/Edge/Brave, XLSX, all users)
    ChromeSessions        - Chrome SNSS session/tab URL recovery (not in History DB/Hindsight)
    PSReadline            - ConsoleHost_history.txt typed PS commands (all users)
    Defender              - MPDetection/MPLog + DetectionHistory detections
    RegPersistence        - Run/Winlogon/IFEO/SilentProcessExit/AppInit/AppPaths/Services/Uninstall/Shares +
                            per-user Run/RDP/MountPoints2/RecentApps/NetworkDrives/PuTTY/MUICache (reg.exe mount)
    BAM                   - BAM/DAM execution evidence with decoded FILETIME (reg.exe mount)
    Firewall              - firewall rules parsed from SYSTEM hive + pfirewall.log copy
    SAM                   - local accounts decoded from SAM\Domains\Account\Users (RID, logon times)
    Evtx                  - EvtxECmd parse of all .evtx event logs to consolidated CSV
    OfficeMRU             - per-user Office File/Place MRU with decoded per-entry FILETIME
    PCA                   - Win11 22H2+ Program Compatibility Assistant exec artefact (copy + parse)
    Email                 - copy Outlook .ost/.pst + Thunderbird stores (no parse)
    OsDetails             - OS / system summary written to 07_SystemInfo\OS_Details.txt

  Output layout:
    <OutputDir>\
      00_Execution\
      01_FileFolderActivity\
      02_NTFS\
      03_USB\
      04_Network\
      05_Persistence\
      06_Accounts\
      07_SystemInfo\
      08_Registry_Raw\
      09_BrowserAndCache\
      10_BrowserForensics\
      11_Defender\
      12_Email\
      13_EventLogs\
      _logs\

.PARAMETER ImageRoot
  Root of the mounted image or collected file structure, e.g. E:\ or
  C:\Cases\HOST\C. Must contain Windows\ and Users\ beneath it.

.PARAMETER OutputDir
  Directory where categorised CSV output will be written.

.PARAMETER ToolsDir
  Directory containing the Eric Zimmerman tool EXEs and RECmd.exe.

.PARAMETER RebFile
  Full path to the RECmd batch (.reb) file.

.PARAMETER DateTimeFormat
  Optional custom dt format passed to each tool's --dt argument.

.PARAMETER MactimePath
  Optional full path to mactime.pl. When supplied (and Perl is installed),
  the $MFT bodyfile is converted to a comma-delimited timeline CSV
  (mft_timeline.csv) in the 02_NTFS folder.

.PARAMETER SkipTools
  Optional array of tool names to skip, e.g. -SkipTools MFTECmd,SrumECmd
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$ImageRoot,

  [Parameter(Mandatory=$true)]
  [string]$OutputDir,

  [Parameter(Mandatory=$true)]
  [string]$ToolsDir,

  [string]$RebFile = "",

  [string]$DateTimeFormat = "",

  [string]$MactimePath = "",

  [string[]]$SkipTools = @()
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-DirIfMissing([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
}

$script:LogPath = $null

function Write-Log([string]$Message) {
  $line = "[$(Get-Date -Format s)] $Message"
  $line | Out-File -FilePath $script:LogPath -Append -Encoding utf8
  Write-Host $line
}

function Resolve-Tool([string]$ExeName) {
  # Returns full path if the tool exists in ToolsDir, else $null.
  # Handles both flat layout (ToolsDir\Tool.exe) and per-tool-folder
  # layout (ToolsDir\PECmd\PECmd.exe) by searching recursively.
  $candidate = Join-Path $ToolsDir $ExeName
  if (Test-Path -LiteralPath $candidate) { return $candidate }
  $found = Get-ChildItem -LiteralPath $ToolsDir -Filter $ExeName -File -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
  if ($found) { return $found.FullName }
  return $null
}

function Resolve-ToolPy([string]$PyName) {
  # Locate a .py script in ToolsDir for tools shipped as source (e.g. IconCacheReader.py)
  $found = Get-ChildItem -LiteralPath $ToolsDir -Filter $PyName -File -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
  if ($found) { return $found.FullName }
  return $null
}

function Resolve-Perl {
  # Find a Perl interpreter: PATH first, then common Strawberry/ActivePerl
  # install locations. Returns full path to perl.exe or $null.
  $cmd = Get-Command perl.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $candidates = @(
    "C:\Strawberry\perl\bin\perl.exe",
    "C:\Perl64\bin\perl.exe",
    "C:\Perl\bin\perl.exe",
    (Join-Path $env:ProgramFiles "Git\usr\bin\perl.exe")
  )
  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) { return $c }
  }
  # Last resort: search under ToolsDir (some SleuthKit bundles ship perl)
  $found = Get-ChildItem -LiteralPath $ToolsDir -Filter "perl.exe" -File -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
  if ($found) { return $found.FullName }
  return $null
}

function Resolve-SystemInfo([string]$SystemHive) {
  # Mount the offline SYSTEM hive ONCE via reg.exe load (needs an elevated
  # session) and read both the ComputerName and the per-interface IPv4
  # addresses from it. Walking a mounted hive with Get-ChildItem/Get-ItemProperty
  # handles the recursive Interfaces subkeys naturally, which a RECmd --kn
  # query against the parent does not. Falls back to a RECmd CSV read for the
  # hostname only if the mount is refused (e.g. not elevated).
  # Returns @{ Name; Ips = @(); Diag }.
  $result = [PSCustomObject]@{ Name = "UnknownHost"; Ips = @(); Diag = "" }
  if (-not (Test-Path -LiteralPath $SystemHive)) {
    $result.Diag = "SYSTEM hive not found at $SystemHive"
    return $result
  }
  $mount = "HKLM\DFIR_TEMP_SYSTEM"
  & reg.exe unload $mount 2>$null | Out-Null

  $loadOut = & reg.exe load $mount "$SystemHive" 2>&1
  if ($LASTEXITCODE -eq 0) {
    try {
      # Resolve active ControlSet via Select\Current, with fallbacks.
      $cur = $null
      try {
        $sel = Get-ItemProperty -Path "Registry::$mount\Select" -Name "Current" -ErrorAction Stop
        $cur = [int]$sel.Current
      } catch { $cur = $null }
      $csCandidates = @()
      if ($cur) { $csCandidates += ("ControlSet{0:D3}" -f $cur) }
      $csCandidates += @("ControlSet001","ControlSet002")
      $csCandidates = $csCandidates | Select-Object -Unique

      # --- Hostname ---
      foreach ($cs in $csCandidates) {
        $cnPath = "Registry::$mount\$cs\Control\ComputerName\ComputerName"
        try {
          $cn = Get-ItemProperty -Path $cnPath -Name "ComputerName" -ErrorAction Stop
          if ($cn -and $cn.ComputerName) {
            $result.Name = ($cn.ComputerName -replace '[<>:"/\\|?*]', '_').Trim()
            break
          }
        } catch { continue }
      }

      # --- IP addresses: walk Tcpip\Parameters\Interfaces\<GUID> subkeys ---
      $ipList = New-Object System.Collections.ArrayList
      $seen = @{}
      foreach ($cs in $csCandidates) {
        $ifRoot = "Registry::$mount\$cs\Services\Tcpip\Parameters\Interfaces"
        if (-not (Test-Path -LiteralPath $ifRoot)) { continue }
        $ifaces = Get-ChildItem -LiteralPath $ifRoot -ErrorAction SilentlyContinue
        foreach ($if in $ifaces) {
          try {
            $props = Get-ItemProperty -Path $if.PSPath -ErrorAction SilentlyContinue
          } catch { continue }
          if (-not $props) { continue }
          # Static IPAddress (REG_MULTI_SZ -> array) and DhcpIPAddress (string).
          foreach ($vn in @("IPAddress","DhcpIPAddress")) {
            $raw = $props.$vn
            if (-not $raw) { continue }
            $vals = @($raw)   # normalise scalar or array to array
            foreach ($entry in $vals) {
              foreach ($m in [regex]::Matches([string]$entry, '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')) {
                $ip = $m.Value
                if ($ip -eq "0.0.0.0") { continue }
                if ($seen.ContainsKey($ip)) { continue }
                $seen[$ip] = $true
                $kind = if ($vn -eq "DhcpIPAddress") { "DHCP" } else { "Static" }
                [void]$ipList.Add(("{0} ({1})" -f $ip, $kind))
              }
            }
          }
        }
        if ($ipList.Count -gt 0) { break }
      }
      $result.Ips = $ipList.ToArray()
      $result.Diag = "reg load OK (hostname + $($result.Ips.Count) IP(s))"
    } catch {
      $result.Diag = "reg load OK but read failed: $($_.Exception.Message)"
    } finally {
      & reg.exe unload $mount 2>$null | Out-Null
    }
    if ($result.Name -ne "UnknownHost") { return $result }
  }

  # Fallback (hostname only): RECmd CSV read, for non-elevated sessions.
  $recmd = Resolve-Tool "RECmd.exe"
  if (-not $recmd) {
    $result.Diag = "reg load refused (not elevated?) and RECmd.exe not found for fallback"
    return $result
  }
  try {
    $tmpCsvDir = Join-Path $env:TEMP ("hn_{0}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    New-DirIfMissing $tmpCsvDir
    $kn = "ControlSet001\Control\ComputerName\ComputerName"
    & $recmd -f "$SystemHive" --kn $kn --csv $tmpCsvDir --csvf "hn.csv" --nl 2>&1 | Out-Null
    $csvFile = Join-Path $tmpCsvDir "hn.csv"
    if (Test-Path -LiteralPath $csvFile) {
      $rows = Import-Csv -LiteralPath $csvFile -ErrorAction SilentlyContinue
      $row = $rows | Where-Object { $_.ValueName -eq "ComputerName" } | Select-Object -First 1
      if ($row -and $row.ValueData) {
        $result.Name = ($row.ValueData -replace '[<>:"/\\|?*]', '_').Trim()
        $result.Diag = "RECmd CSV fallback for hostname (reg load refused; IPs unavailable without elevation)"
      }
    }
    Remove-Item -LiteralPath $tmpCsvDir -Recurse -Force -ErrorAction SilentlyContinue
  } catch {
    $result.Diag = "reg load refused; RECmd fallback errored: $($_.Exception.Message)"
  }
  return $result
}

function Should-Skip([string]$ToolName) {
  return ($SkipTools -contains $ToolName)
}

function Add-DtArg([System.Collections.ArrayList]$ArgList) {
  if ($DateTimeFormat -and $DateTimeFormat.Trim().Length -gt 0) {
    [void]$ArgList.Add("--dt")
    [void]$ArgList.Add($DateTimeFormat)
  }
}

function Get-CsvSnapshot([string]$Dir) {
  # Capture current CSV filenames in a dir so we can later identify which
  # files a tool newly created (avoids re-prefixing another user's output).
  $existing = @{}
  Get-ChildItem -LiteralPath $Dir -Filter "*.csv" -File -ErrorAction SilentlyContinue |
    ForEach-Object { $existing[$_.FullName] = $true }
  return $existing
}

function Prefix-NewCsvs([string]$Dir, [string]$Prefix, [hashtable]$Snapshot) {
  # Rename ONLY the CSVs that appeared since $Snapshot was taken, prepending
  # $Prefix. This guarantees each user's files get that user's name and no
  # previously-renamed file is touched again.
  $new = Get-ChildItem -LiteralPath $Dir -Filter "*.csv" -File -ErrorAction SilentlyContinue |
         Where-Object { -not $Snapshot.ContainsKey($_.FullName) }
  foreach ($csv in $new) {
    $newName = "{0}_{1}" -f $Prefix, $csv.Name
    $dest = Join-Path $Dir $newName
    if (Test-Path -LiteralPath $dest) {
      $guid = [guid]::NewGuid().ToString('N').Substring(0,6)
      $newName = "{0}_{1}_{2}" -f $Prefix, $guid, $csv.Name
    }
    Rename-Item -LiteralPath $csv.FullName -NewName $newName -ErrorAction SilentlyContinue
  }
}

function Get-UserProfiles {
  $usersRoot = Join-Path $ImageRoot "Users"
  if (-not (Test-Path -LiteralPath $usersRoot)) {
    Write-Log "WARNING: Users directory not found at $usersRoot"
    return @()
  }
  $skip = @("All Users","Default","Default User","DefaultAppPool","Public","desktop.ini")
  return Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $skip -notcontains $_.Name }
}

# ---------------------------------------------------------------------------
# Custom parsers (not Eric Zimmerman tools)
# ---------------------------------------------------------------------------

function Invoke-CryptNetExtract {
  # Pure-PowerShell URL carve from CryptnetUrlCache MetaData blobs.
  param([string]$ProfileName, [string]$BasePath, [string]$OutDir)
  $metaDir = Join-Path $BasePath "AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData"
  if (-not (Test-Path -LiteralPath $metaDir)) {
    Write-Log "[$ProfileName] CryptNet: no MetaData folder"; return
  }
  $files = Get-ChildItem -LiteralPath $metaDir -File -Recurse -ErrorAction SilentlyContinue
  if (-not $files -or $files.Count -eq 0) {
    Write-Log "[$ProfileName] CryptNet: MetaData empty"; return
  }
  $outFile = Join-Path $OutDir ("CryptNetUrlCache_{0}.csv" -f $ProfileName)
  $rows = New-Object System.Collections.ArrayList
  foreach ($file in $files) {
    try {
      $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
      $text = [System.Text.Encoding]::Unicode.GetString($bytes)
      if ($text -notmatch 'https?://|ldap://|ftp://') { $text = [System.Text.Encoding]::UTF8.GetString($bytes) }
      if ($text -notmatch 'https?://|ldap://|ftp://') { $text = [System.Text.Encoding]::ASCII.GetString($bytes) }
      $text = $text -replace "`0", ""
      $urlMatches = [regex]::Matches($text, '(?:https?|ldap|ftp)://[^\s"<>|]+')
      foreach ($m in $urlMatches) {
        [void]$rows.Add([PSCustomObject]@{
          Profile      = $ProfileName
          MetaDataFile = $file.Name
          LastModified = $file.LastWriteTimeUtc.ToString("o")
          URL          = $m.Value
        })
      }
    } catch {
      Write-Log "[$ProfileName] CryptNet ERROR on $($file.Name): $($_.Exception.Message)"
    }
  }
  if ($rows.Count -gt 0) {
    $rows | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8
    Write-Log "[$ProfileName] CryptNet: $($rows.Count) URL(s) extracted"
  } else {
    Write-Log "[$ProfileName] CryptNet: no URLs found in blobs"
  }
}

function Invoke-IconCacheReader {
  # https://github.com/peli-rufus/IconCacheReader (v2.1.1)
  # Runs ONCE against the whole Users dir (-users-dir mode handles all profiles).
  # Targets IconCache.db only - iconcache_*.db are image stores with no paths.
  param([string]$UsersRoot, [string]$OutDir)
  $iconExe = Resolve-Tool "IconCacheReader.exe"
  $iconPy  = $null
  if (-not $iconExe) { $iconPy = Resolve-ToolPy "IconCacheReader.py" }
  if (-not $iconExe -and -not $iconPy) {
    Write-Log "IconCache: SKIPPED (IconCacheReader.exe/.py not in ToolsDir)"; return
  }
  if (-not (Test-Path -LiteralPath $UsersRoot)) {
    Write-Log "IconCache: Users dir not found at $UsersRoot"; return
  }
  $outCsv  = Join-Path $OutDir "IconCache_AllUsers.csv"
  $outJson = Join-Path $OutDir "IconCache_AllUsers.json"
  # Flags (single-dash, multi-char): -users-dir, -csv, -json
  $a = [System.Collections.ArrayList]@("-users-dir", $UsersRoot, "-csv", $outCsv, "-json", $outJson)
  Write-Log "IconCache: parsing all profiles under $UsersRoot"
  try {
    if ($iconExe) { & $iconExe @a 2>&1 | Out-File (Join-Path $logDir "IconCacheReader.log") -Encoding utf8 }
    else          { & python $iconPy @a 2>&1 | Out-File (Join-Path $logDir "IconCacheReader.log") -Encoding utf8 }
    Write-Log "IconCache: done"
  } catch {
    Write-Log "IconCache ERROR: $($_.Exception.Message)"
  }
}

function Invoke-EseRecovery {
  # Copy an ESE database set to a writable work dir, then bring it to a clean
  # state using esentutl: check header (/mh) -> soft recovery (/r) -> hard
  # repair (/p) only if still dirty -> integrity check (/g). Operates entirely
  # on the COPY so originals are never modified (forensic soundness).
  #
  # Returns the path to the work directory containing the recovered DB(s),
  # or $null if recovery could not be performed.
  param(
    [string]$SourceDir,      # dir containing the .mdb/.edb + transaction logs
    [string]$WorkDir,        # writable destination for the working copy
    [string]$PrimaryDb,      # main DB filename, e.g. Current.mdb or Windows.edb
    [string]$LogPrefix,      # ESE log prefix for /r, e.g. svc (SUM) or edb (search)
    [string]$Label           # for logging, e.g. SUM or SearchIndex
  )
  $esentutl = Join-Path $env:SystemRoot "System32\esentutl.exe"
  if (-not (Test-Path -LiteralPath $esentutl)) {
    Write-Log "$Label recovery: esentutl.exe not found on host - cannot recover"
    return $null
  }
  if (-not (Test-Path -LiteralPath $SourceDir)) {
    Write-Log "$Label recovery: source dir not found ($SourceDir)"
    return $null
  }

  # 1. Copy the whole DB set (DBs + logs) to the work dir, clear read-only.
  New-DirIfMissing $WorkDir
  try {
    Copy-Item -Path (Join-Path $SourceDir "*") -Destination $WorkDir -Recurse -Force -ErrorAction Stop
  } catch {
    Write-Log "$Label recovery: copy failed - $($_.Exception.Message)"
    return $null
  }
  Get-ChildItem -LiteralPath $WorkDir -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object { try { $_.IsReadOnly = $false } catch {} }

  $dbPath = Join-Path $WorkDir $PrimaryDb
  if (-not (Test-Path -LiteralPath $dbPath)) {
    Write-Log "$Label recovery: primary DB '$PrimaryDb' not present in copy"
    return $null
  }

  # 2. Check header state. esentutl /mh reports "Clean Shutdown" or "Dirty".
  Push-Location -LiteralPath $WorkDir
  try {
    $mh = & $esentutl /mh $PrimaryDb 2>&1
    $mh | Out-File (Join-Path $logDir "${Label}_esentutl_mh_before.log") -Encoding utf8
    $isClean = ($mh | Select-String -SimpleMatch "Clean Shutdown" -Quiet)

    if ($isClean) {
      Write-Log "$Label recovery: $PrimaryDb already Clean Shutdown - no recovery needed"
      Pop-Location
      return $WorkDir
    }

    # 3. Soft recovery (replay logs). Non-destructive. /i ignores missing logs.
    Write-Log "$Label recovery: $PrimaryDb is dirty - attempting soft recovery (/r $LogPrefix /i)"
    $r = & $esentutl /r $LogPrefix /i 2>&1
    $r | Out-File (Join-Path $logDir "${Label}_esentutl_softrecovery.log") -Encoding utf8

    $mh2 = & $esentutl /mh $PrimaryDb 2>&1
    $mh2 | Out-File (Join-Path $logDir "${Label}_esentutl_mh_after_soft.log") -Encoding utf8
    if ($mh2 | Select-String -SimpleMatch "Clean Shutdown" -Quiet) {
      Write-Log "$Label recovery: soft recovery succeeded - now Clean Shutdown"
      Pop-Location
      return $WorkDir
    }

    # 4. Hard repair (destructive - may discard unreconcilable pages). Last
    #    resort, and only safe because we are on a copy. Repair every DB.
    #    esentutl /p ALWAYS shows an interactive "data loss may result" prompt
    #    requiring OK. In an unattended script that would hang, so we feed the
    #    confirmation via stdin using cmd's echo pipe.
    Write-Log "$Label recovery: soft recovery insufficient - attempting hard repair (/p) [DESTRUCTIVE on copy]"
    $dbs = Get-ChildItem -LiteralPath $WorkDir -File -ErrorAction SilentlyContinue |
           Where-Object { $_.Extension -in @(".mdb", ".edb") }
    foreach ($db in $dbs) {
      $repairLog = Join-Path $logDir "${Label}_esentutl_repair_$($db.BaseName).log"
      # echo OK | esentutl /p <db>   -- the piped OK answers the confirmation
      # prompt. cd into WorkDir explicitly so the relative DB name resolves
      # regardless of the cmd child's inherited working directory.
      $cmdStr = 'cd /d "{0}" & echo OK| "{1}" /p "{2}"' -f $WorkDir, $esentutl, $db.Name
      cmd.exe /c $cmdStr 2>&1 | Out-File $repairLog -Encoding utf8
    }
    # Verify integrity after repair.
    $g = & $esentutl /g $PrimaryDb 2>&1
    $g | Out-File (Join-Path $logDir "${Label}_esentutl_integrity.log") -Encoding utf8
    $mh3 = & $esentutl /mh $PrimaryDb 2>&1
    $mh3 | Out-File (Join-Path $logDir "${Label}_esentutl_mh_after_repair.log") -Encoding utf8
    if ($mh3 | Select-String -SimpleMatch "Clean Shutdown" -Quiet) {
      Write-Log "$Label recovery: hard repair brought $PrimaryDb to Clean Shutdown"
    } else {
      Write-Log "$Label recovery: WARNING - $PrimaryDb still not clean after hard repair; parsing may be partial"
    }
    Pop-Location
    return $WorkDir
  } catch {
    Write-Log "$Label recovery ERROR: $($_.Exception.Message)"
    Pop-Location
    return $WorkDir   # return what we have; parser may still salvage data
  }
}

function Invoke-Sidr {
  # https://github.com/strozfriedberg/sidr - parses Windows.edb / Windows.db
  # Usage: sidr [OPTIONS] <INPUT>
  #   <INPUT>          positional - dir recursively scanned for Windows.edb/.db
  #   -f, --format     json|csv (default json)
  #   -o, --outdir     output directory (created if missing)
  # sidr does its own recursive scan, so we pass the search dir as positional
  # and let it find the DB. Output filenames are HOSTNAME_ReportName_DateTime.
  param([string]$OutDir)
  $sidr = Resolve-Tool "sidr.exe"
  if (-not $sidr) { Write-Log "sidr: SKIPPED (sidr.exe not in ToolsDir)"; return }
  $searchDir = Join-Path $ImageRoot "ProgramData\Microsoft\Search\Data\Applications\Windows"
  if (-not (Test-Path -LiteralPath $searchDir)) {
    Write-Log "sidr: search index dir not found at $searchDir"; return
  }

  # Windows.edb is frequently dirty when collected from a live system. Recover
  # a working copy first (soft recovery / hard repair) so sidr can open it.
  $parseDir = $searchDir
  $edbPath = Join-Path $searchDir "Windows.edb"
  if (Test-Path -LiteralPath $edbPath) {
    $workDir = Join-Path $OutDir "_SearchIndex_WORK"
    $recovered = Invoke-EseRecovery -SourceDir $searchDir -WorkDir $workDir `
                   -PrimaryDb "Windows.edb" -LogPrefix "edb" -Label "SearchIndex"
    if ($recovered) { $parseDir = $recovered }
  } else {
    Write-Log "sidr: no Windows.edb (may be Win11 Windows.db) - passing dir as-is"
  }

  Write-Log "sidr: parsing search index in $parseDir"
  # -o and -f are options; the input dir is the trailing positional argument
  $a = [System.Collections.ArrayList]@("-f", "csv", "-o", $OutDir, $parseDir)
  try {
    & $sidr @a 2>&1 | Out-File (Join-Path $logDir "sidr.log") -Encoding utf8
    Write-Log "sidr: done"
  } catch {
    Write-Log "sidr ERROR: $($_.Exception.Message)"
  }
}

function Invoke-Sum {
  # SUM (Software Usage Monitor) - Server 2012+ only. ESE databases at
  # System32\LogFiles\SUM\ tracking client access (CAL) per service. Recover
  # dirty DBs on a copy, then parse with SumECmd (-d takes the SUM directory).
  param([string]$OutDir)
  $tool = Resolve-Tool "SumECmd.exe"
  if (-not $tool) { Write-Log "SumECmd: SKIPPED (SumECmd.exe not in ToolsDir)"; return }
  $sumDir = Join-Path $ImageRoot "Windows\System32\LogFiles\SUM"
  if (-not (Test-Path -LiteralPath $sumDir)) {
    Write-Log "SumECmd: SUM directory not found at $sumDir (normal on non-Server OS)"; return
  }

  # Recover a working copy. SUM log prefix is 'svc'; primary DB Current.mdb.
  $workDir = Join-Path $OutDir "_SUM_WORK"
  $recovered = Invoke-EseRecovery -SourceDir $sumDir -WorkDir $workDir `
                 -PrimaryDb "Current.mdb" -LogPrefix "svc" -Label "SUM"
  $parseDir = if ($recovered) { $recovered } else { $sumDir }

  Write-Log "SumECmd: parsing SUM databases in $parseDir"
  $a = [System.Collections.ArrayList]@("-d", $parseDir, "--csv", $OutDir)
  Add-DtArg $a
  try {
    & $tool @a 2>&1 | Out-File (Join-Path $logDir "SumECmd.log") -Encoding utf8
    Write-Log "SumECmd: done"
  } catch {
    Write-Log "SumECmd ERROR: $($_.Exception.Message)"
  }
}

function Copy-PSReadlineHistory {
  # PSReadline ConsoleHost_history.txt - plaintext record of interactively
  # typed PowerShell commands. Per-user. We copy the file as-is (it is already
  # human-readable) with a username-prefixed name.
  param([string]$ProfileName, [string]$BasePath, [string]$OutDir)
  $histPath = Join-Path $BasePath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
  if (-not (Test-Path -LiteralPath $histPath)) {
    Write-Log "[$ProfileName] PSReadline: no ConsoleHost_history.txt"
    return
  }
  $dest = Join-Path $OutDir ("PSReadline_{0}_ConsoleHost_history.txt" -f $ProfileName)
  try {
    Copy-Item -LiteralPath $histPath -Destination $dest -Force -ErrorAction Stop
    $lineCount = (Get-Content -LiteralPath $dest -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
    Write-Log "[$ProfileName] PSReadline: copied history ($lineCount line(s))"
  } catch {
    Write-Log "[$ProfileName] PSReadline ERROR: $($_.Exception.Message)"
  }
}

function Invoke-DefenderDetections {
  # Microsoft Defender detection history. Two sources:
  #   1. MPDetection-*.log (text) at ProgramData\Microsoft\Windows Defender\Support\
  #   2. DetectionHistory binary files at ...\Scans\History\Service\DetectionHistory\
  # We copy the human-readable MPDetection/MPLog files, and parse the binary
  # DetectionHistory with DHParser if present in ToolsDir.
  param([string]$OutDir)
  $support = Join-Path $ImageRoot "ProgramData\Microsoft\Windows Defender\Support"
  $copied = 0
  if (Test-Path -LiteralPath $support) {
    Get-ChildItem -LiteralPath $support -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '^(MPDetection|MPLog).*\.log$' } |
      ForEach-Object {
        $dest = Join-Path $OutDir $_.Name
        Copy-Item -LiteralPath $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
        $copied++
      }
    Write-Log "Defender: copied $copied MPDetection/MPLog file(s) from Support"
  } else {
    Write-Log "Defender: Support directory not found at $support"
  }

  # DHParser writes JSON files; console text belongs in a separate log.
  $dhDir = Join-Path $ImageRoot "ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory"
  if (-not (Test-Path -LiteralPath $dhDir)) { return }

  $dhExe = Resolve-Tool "dhparser.exe"
  $dhPy = $null
  $pythonExe = $null
  if (-not $dhExe) {
    $dhPy = Resolve-ToolPy "dhparser.py"
    if ($dhPy) {
      foreach ($name in @("python", "py", "python3")) {
        $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { $pythonExe = $cmd.Source; break }
      }
    }
  }
  $canParse = $dhExe -or ($dhPy -and $pythonExe)
  if (-not $canParse) {
    Write-Log "Defender: DHParser or Python unavailable; copying raw DetectionHistory files"
  }

  $dhLog = Join-Path $logDir "Defender_DetectionHistory.log"
  if ($canParse) { Set-Content -LiteralPath $dhLog -Value "" -Encoding utf8 }
  $dhFiles = @(Get-ChildItem -LiteralPath $dhDir -File -Recurse -ErrorAction SilentlyContinue)
  $parsed = 0
  $rawCopied = 0
  foreach ($f in $dhFiles) {
    # Preserve the source-relative directory structure to avoid basename collisions.
    $relative = $f.FullName.Substring($dhDir.TrimEnd('\').Length).TrimStart('\')
    $succeeded = $false
    $tmpOut = $null
    if ($canParse) {
      try {
        # Fresh output prevents an old JSON file from masking a failed invocation.
        $tmpOut = Join-Path $env:TEMP ("dfir_dh_" + [guid]::NewGuid().ToString("N"))
        New-DirIfMissing $tmpOut
        # Invoke per file: DHParser 1.0.1 has a directory-input edge case when
        # recursive discovery finds exactly one file. Explicit -f avoids it.
        $a = @("-f", $f.FullName, "-o", $tmpOut)
        "Input: $($f.FullName)" | Out-File -LiteralPath $dhLog -Append -Encoding utf8
        $LASTEXITCODE = 0
        if ($dhExe) {
          & $dhExe @a 2>&1 | Out-File -LiteralPath $dhLog -Append -Encoding utf8
        } else {
          & $pythonExe $dhPy @a 2>&1 | Out-File -LiteralPath $dhLog -Append -Encoding utf8
        }
        $exitCode = $LASTEXITCODE
        $jsonPath = Join-Path $tmpOut ($f.Name + ".json")
        if ($exitCode -ne 0) {
          Write-Log "Defender: DHParser exit code $exitCode for $($f.FullName); retaining raw file"
        } elseif (-not (Test-Path -LiteralPath $jsonPath)) {
          # DHParser can report a caught parsing error yet exit with code zero.
          Write-Log "Defender: no JSON produced for $($f.FullName); see $dhLog; retaining raw file"
        } else {
          $json = Get-Content -LiteralPath $jsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
          if ($null -eq $json -or -not $json.GUID) { throw "JSON is missing the DetectionHistory GUID" }
          $dest = Join-Path (Get-ArtefactDir $OutDir "DetectionHistory") ($relative + ".json")
          New-DirIfMissing (Split-Path -Path $dest -Parent)
          Move-Item -LiteralPath $jsonPath -Destination $dest -Force -ErrorAction Stop
          $parsed++
          $succeeded = $true
        }
      } catch {
        Write-Log "Defender: DetectionHistory ERROR on $($f.FullName): $($_.Exception.Message); retaining raw file"
      } finally {
        if ($tmpOut -and (Test-Path -LiteralPath $tmpOut)) {
          Remove-Item -LiteralPath $tmpOut -Recurse -Force -ErrorAction SilentlyContinue
        }
      }
    }
    if (-not $succeeded) {
      try {
        $dest = Join-Path (Get-ArtefactDir $OutDir "DetectionHistory_raw") $relative
        New-DirIfMissing (Split-Path -Path $dest -Parent)
        Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction Stop
        $rawCopied++
      } catch {
        Write-Log "Defender: raw DetectionHistory copy FAILED for $($f.FullName): $($_.Exception.Message)"
      }
    }
  }
  Write-Log "Defender: DetectionHistory files found=$($dhFiles.Count), JSON reports=$parsed, raw files copied=$rawCopied"
}

function Copy-FileShared([string]$Src, [string]$Dst) {
  # Copy a file even when another process holds it open. Copy-Item opens with
  # FileShare.Read which fails ("being used by another process") if the file
  # was opened for write elsewhere - e.g. a still-settling reg mount or the
  # imaging layer. Opening with FileShare.ReadWrite lets us read it anyway.
  try {
    $in = [System.IO.File]::Open($Src, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $out = [System.IO.File]::Open($Dst, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
      try { $in.CopyTo($out) } finally { $out.Dispose() }
    } finally { $in.Dispose() }
    return $true
  } catch {
    return $false
  }
}

function Clear-DfirMounts {
  # Unload any leftover DFIR_* hive mounts from this or a prior aborted run.
  # A lingering mount keeps a handle on the underlying hive file, which then
  # causes "Access is denied" / "being used by another process" on the next
  # load or copy. Sweep them before the registry-extraction phase.
  $out = & reg.exe query HKLM 2>$null
  foreach ($line in $out) {
    if ($line -match '(HKEY_LOCAL_MACHINE\\(DFIR_\w+))') {
      $name = $matches[2]
      & reg.exe unload "HKLM\$name" 2>$null | Out-Null
    }
  }
}

function Use-MountedHive {
  # Load a hive to a temp mount, run a scriptblock that receives the mount
  # root path (e.g. "Registry::HKLM\DFIR_TMP") plus any extra args, then
  # always unload. Returns whatever the scriptblock returns, or $null if the
  # load failed. Requires elevation (reg.exe load needs the restore privilege).
  #
  # IMPORTANT: we COPY the hive to a private temp file and load the copy, not
  # the original. Loading the original frequently fails with "being used by
  # another process" or "Access is denied" when any handle (the imaging mount,
  # AV, indexer, or an earlier load in this same run) is open on it. A private
  # copy has no such locks. It is also forensically cleaner - the source hive
  # is never opened for write by reg.exe.
  param([string]$HivePath, [string]$MountName, [scriptblock]$Action, [object[]]$ActionArgs = @())
  if (-not (Test-Path -LiteralPath $HivePath)) {
    Write-Log "Use-MountedHive: hive not found at $HivePath"
    return $null
  }

  # Copy hive (and its transaction logs, if present) to a temp working dir so
  # a dirty hive can still be loaded - reg load needs the .LOG1/.LOG2 alongside.
  $tmpDir = Join-Path $env:TEMP ("hive_{0}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
  New-DirIfMissing $tmpDir
  $hiveLeaf = Split-Path $HivePath -Leaf
  $tmpHive = Join-Path $tmpDir $hiveLeaf
  if (-not (Copy-FileShared $HivePath $tmpHive)) {
    Write-Log "Use-MountedHive: could not copy hive $HivePath (locked even for shared read)"
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    return $null
  }
  foreach ($ext in @(".LOG", ".LOG1", ".LOG2")) {
    $src = "$HivePath$ext"
    if (Test-Path -LiteralPath $src) {
      [void](Copy-FileShared $src (Join-Path $tmpDir ($hiveLeaf + $ext)))
    }
  }

  # Unique mount name per call so a slow-to-release unload from a previous
  # iteration can never collide with this one.
  $mount = "HKLM\${MountName}_$([guid]::NewGuid().ToString('N').Substring(0,8))"
  & reg.exe unload $mount 2>$null | Out-Null
  $loadOut = & reg.exe load $mount "$tmpHive" 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Log "Use-MountedHive: reg load FAILED for $HivePath (exit $LASTEXITCODE): $loadOut"
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    return $null
  }
  try {
    return & $Action "Registry::$mount" @ActionArgs
  } catch {
    Write-Log "Hive mount action error on $HivePath : $($_.Exception.Message)"
    return $null
  } finally {
    & reg.exe unload $mount 2>$null | Out-Null
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-RegKeyLastWrite([string]$RegistryPath) {
  # Return a key's LastWriteTime (UTC string) - the registry provider does not
  # expose it, so use the .NET RegistryKey handle + RegQueryInfoKey via P/Invoke.
  # $RegistryPath is a "Registry::HKLM\Mount\Sub\Key" path. For many artefacts
  # (RDP MRU, MountPoints2, PuTTY Sessions) the key LastWriteTime IS the
  # forensic timestamp of last use.
  if (-not ('DfirRegLastWrite' -as [type])) {
    Add-Type -Namespace 'Dfir' -Name 'RegLastWrite' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto)]
public static extern int RegQueryInfoKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
  System.Text.StringBuilder lpClass, ref uint lpcchClass, System.IntPtr lpReserved,
  ref uint lpcSubKeys, ref uint lpcbMaxSubKeyLen, ref uint lpcbMaxClassLen,
  ref uint lpcValues, ref uint lpcbMaxValueNameLen, ref uint lpcbMaxValueLen,
  ref uint lpcbSecurityDescriptor, out System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime);
'@ -ErrorAction SilentlyContinue
    # Provide a typed marker so the -as [type] check above works on re-entry.
    Add-Type 'public class DfirRegLastWrite {}' -ErrorAction SilentlyContinue
  }
  try {
    # Normalise the path: strip the PS provider prefixes so we are left with
    # "HKLM\<mount>\<sub...>". PSPath comes as "Microsoft.PowerShell.Core\
    # Registry::HKLM\..."; a plain path may be "Registry::HKLM\...".
    $clean = $RegistryPath -replace '^Microsoft\.PowerShell\.Core\\Registry::','' -replace '^Registry::',''
    if ($clean -notmatch '^(HKLM|HKEY_LOCAL_MACHINE)\\(.+)$') { return "" }
    $sub = $matches[2]
    $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub)
    if (-not $rk) { return "" }
    try {
      $cls = New-Object System.Text.StringBuilder 0
      [uint32]$cchClass=0; [uint32]$subkeys=0; [uint32]$maxSub=0; [uint32]$maxCls=0
      [uint32]$vals=0; [uint32]$maxVN=0; [uint32]$maxVL=0; [uint32]$secDesc=0
      $ft = New-Object System.Runtime.InteropServices.ComTypes.FILETIME
      $rc = [Dfir.RegLastWrite]::RegQueryInfoKey($rk.Handle, $cls, [ref]$cchClass, [System.IntPtr]::Zero,
              [ref]$subkeys, [ref]$maxSub, [ref]$maxCls, [ref]$vals, [ref]$maxVN, [ref]$maxVL, [ref]$secDesc, [ref]$ft)
      if ($rc -ne 0) { return "" }
      $high = [uint32]$ft.dwHighDateTime
      $low  = [uint32]$ft.dwLowDateTime
      $val = ([int64]$high -shl 32) -bor $low
      return [DateTime]::FromFileTimeUtc($val).ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
    } finally { $rk.Close() }
  } catch { return "" }
}

function Get-RegValuesAsRows {
  # Read all values at a registry key (and optionally its immediate subkeys)
  # into PSCustomObject rows. $KeyPath is a "Registry::..." path. Returns rows
  # with Source, KeyPath, KeyLastWrite, ValueName, ValueData.
  param([string]$KeyPath, [string]$SourceLabel, [switch]$Subkeys)
  $rows = New-Object System.Collections.ArrayList
  if (-not (Test-Path -LiteralPath $KeyPath)) { return ,$rows }

  $targets = New-Object System.Collections.ArrayList
  [void]$targets.Add($KeyPath)
  if ($Subkeys) {
    Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue |
      ForEach-Object { [void]$targets.Add($_.PSPath) }
  }
  foreach ($t in $targets) {
    try { $item = Get-ItemProperty -LiteralPath $t -ErrorAction Stop } catch { continue }
    $displayKey = ($t -replace '^Microsoft\.PowerShell\.Core\\Registry::', '') -replace '^Registry::',''
    $lastWrite = Get-RegKeyLastWrite $t
    foreach ($prop in $item.PSObject.Properties) {
      if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
      $data = $prop.Value
      if ($data -is [byte[]]) { $data = ($data | ForEach-Object { $_.ToString("x2") }) -join '' }
      elseif ($data -is [array]) { $data = ($data -join '; ') }
      [void]$rows.Add([PSCustomObject]@{
        Source       = $SourceLabel
        KeyPath      = $displayKey
        KeyLastWrite = $lastWrite
        ValueName    = $prop.Name
        ValueData    = $data
      })
    }
  }
  # Comma operator prevents PowerShell from unrolling the ArrayList in the
  # pipeline (an empty ArrayList would otherwise return as $null, and a
  # single-item one as a scalar - both break the caller's .AddRange()).
  return ,$rows
}

function Add-RowsSafe([System.Collections.ArrayList]$Target, $Rows) {
  # Null/empty-safe AddRange: tolerates $null or scalar returns so a missing
  # registry key never throws "Collection cannot be null" in the caller.
  if ($null -eq $Rows) { return }
  if ($Rows -is [System.Collections.ICollection]) {
    if ($Rows.Count -gt 0) { [void]$Target.AddRange($Rows) }
  } else {
    [void]$Target.Add($Rows)
  }
}

function Invoke-RegPersistence {
  # Extract plaintext persistence / system-config registry keys that have no
  # RECmd plugin, via reg.exe mount. Writes one CSV per artefact into its
  # category folder. Needs elevation. Covers HKLM (SOFTWARE/SYSTEM) and each
  # user's NTUSER.DAT (HKCU-equivalent).
  param([string]$SoftwareHive, [string]$SystemHive)

  # --- HKLM SOFTWARE-based keys ---
  if (Test-Path -LiteralPath $SoftwareHive) {
    Use-MountedHive -HivePath $SoftwareHive -MountName "DFIR_SOFTWARE" -Action {
      param($root)
      # Run / RunOnce (machine)
      $runRows = New-Object System.Collections.ArrayList
      foreach ($k in @("Microsoft\Windows\CurrentVersion\Run",
                       "Microsoft\Windows\CurrentVersion\RunOnce",
                       "Microsoft\Windows\CurrentVersion\RunServices",
                       "Microsoft\Windows\CurrentVersion\RunServicesOnce",
                       "Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                       "Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce")) {
        Add-RowsSafe $runRows (Get-RegValuesAsRows -KeyPath "$root\$k" -SourceLabel "HKLM\SOFTWARE\$k")
      }
      if ($runRows.Count) { $runRows | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "RunKeys") "RunKeys_HKLM.csv") -NoTypeInformation -Encoding UTF8 }

      # Winlogon (Shell, Userinit, Notify)
      $wl = Get-RegValuesAsRows -KeyPath "$root\Microsoft\Windows NT\CurrentVersion\Winlogon" -SourceLabel "HKLM\SOFTWARE\...\Winlogon"
      if ($wl.Count) { $wl | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "Winlogon") "Winlogon.csv") -NoTypeInformation -Encoding UTF8 }

      # IFEO (Debugger / GlobalFlag hijacks) - walk per-image subkeys
      $ifeo = Get-RegValuesAsRows -KeyPath "$root\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -SourceLabel "HKLM\SOFTWARE\...\IFEO" -Subkeys
      if ($ifeo.Count) { $ifeo | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "IFEO") "IFEO.csv") -NoTypeInformation -Encoding UTF8 }

      # SilentProcessExit - launches MonitorProcess when a target exits. A
      # persistence / defense-evasion technique (sibling of IFEO): each subkey
      # is a target image (e.g. explorer.exe) whose MonitorProcess runs on exit.
      $spe = Get-RegValuesAsRows -KeyPath "$root\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" -SourceLabel "HKLM\SOFTWARE\...\SilentProcessExit" -Subkeys
      if ($spe.Count) { $spe | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "SilentProcessExit") "SilentProcessExit.csv") -NoTypeInformation -Encoding UTF8 }

      # AppInit_DLLs (both native + Wow64)
      $appinit = New-Object System.Collections.ArrayList
      Add-RowsSafe $appinit (Get-RegValuesAsRows -KeyPath "$root\Microsoft\Windows NT\CurrentVersion\Windows" -SourceLabel "HKLM\SOFTWARE\...\Windows")
      Add-RowsSafe $appinit (Get-RegValuesAsRows -KeyPath "$root\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -SourceLabel "HKLM\SOFTWARE\Wow6432Node\...\Windows")
      if ($appinit.Count) { $appinit | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "AppInit_DLLs") "AppInit_DLLs.csv") -NoTypeInformation -Encoding UTF8 }

      # App Paths
      $apppaths = Get-RegValuesAsRows -KeyPath "$root\Microsoft\Windows\CurrentVersion\App Paths" -SourceLabel "HKLM\SOFTWARE\...\App Paths" -Subkeys
      if ($apppaths.Count) { $apppaths | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "AppPaths") "AppPaths.csv") -NoTypeInformation -Encoding UTF8 }

      # Software Uninstall (installed products - native + Wow6432Node)
      $uninstall = New-Object System.Collections.ArrayList
      Add-RowsSafe $uninstall (Get-RegValuesAsRows -KeyPath "$root\Microsoft\Windows\CurrentVersion\Uninstall" -SourceLabel "HKLM\SOFTWARE\...\Uninstall" -Subkeys)
      Add-RowsSafe $uninstall (Get-RegValuesAsRows -KeyPath "$root\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -SourceLabel "HKLM\SOFTWARE\Wow6432Node\...\Uninstall" -Subkeys)
      if ($uninstall.Count) { $uninstall | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "Uninstall") "Uninstall.csv") -NoTypeInformation -Encoding UTF8 }
      return $true
    } | Out-Null
    Write-Log "RegPersistence: HKLM SOFTWARE keys extracted (RunKeys, Winlogon, IFEO, SilentProcessExit, AppInit_DLLs, AppPaths)"
  } else {
    Write-Log "RegPersistence: SOFTWARE hive not found"
  }

  # --- HKLM SYSTEM-based: Services ---
  if (Test-Path -LiteralPath $SystemHive) {
    Use-MountedHive -HivePath $SystemHive -MountName "DFIR_SYSTEM2" -Action {
      param($root)
      $cur = 1
      try { $sel = Get-ItemProperty -Path "$root\Select" -Name "Current" -ErrorAction Stop; $cur = [int]$sel.Current } catch {}
      $cs = "ControlSet{0:D3}" -f $cur
      $svc = Get-RegValuesAsRows -KeyPath "$root\$cs\Services" -SourceLabel "HKLM\SYSTEM\$cs\Services" -Subkeys
      if ($svc.Count) { $svc | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "Services") "Services_raw.csv") -NoTypeInformation -Encoding UTF8 }

      # Decoded one-row-per-service view with the investigation-relevant fields:
      # service Type and Start mode decoded to text, ImagePath/ServiceDll, the
      # account it runs as, and the key LastWriteTime (often the install time).
      $svcRoot = "$root\$cs\Services"
      $svcRows = New-Object System.Collections.ArrayList
      $startMap = @{ 0="Boot"; 1="System"; 2="Automatic"; 3="Manual"; 4="Disabled" }
      $typeMap  = @{ 1="KernelDriver"; 2="FileSystemDriver"; 16="Win32OwnProcess"; 32="Win32ShareProcess"; 272="Win32OwnProcess(Interactive)"; 288="Win32ShareProcess(Interactive)" }
      foreach ($svcKey in (Get-ChildItem -LiteralPath $svcRoot -ErrorAction SilentlyContinue)) {
        try { $sp = Get-ItemProperty -LiteralPath $svcKey.PSPath -ErrorAction Stop } catch { continue }
        $imgPath = $sp.ImagePath
        # ServiceDll + the Parameters key's own LastWriteTime (svchost services).
        $svcDll = $null
        $paramsLastWrite = ""
        $paramsPath = Join-Path $svcKey.PSPath "Parameters"
        if (Test-Path -LiteralPath $paramsPath) {
          try { $pp = Get-ItemProperty -LiteralPath $paramsPath -Name "ServiceDll" -ErrorAction Stop; $svcDll = $pp.ServiceDll } catch {}
          $paramsLastWrite = Get-RegKeyLastWrite $paramsPath
        }
        $typeVal = $sp.Type
        $startVal = $sp.Start
        # RequiredPrivileges is a REG_MULTI_SZ; flatten to a single cell.
        $reqPriv = $sp.RequiredPrivileges
        if ($reqPriv -is [array]) { $reqPriv = ($reqPriv -join '; ') }
        [void]$svcRows.Add([PSCustomObject]@{
          ServiceName        = $svcKey.PSChildName
          DisplayName        = $sp.DisplayName
          Description        = $sp.Description
          StartMode          = if ($null -ne $startVal -and $startMap.ContainsKey([int]$startVal)) { "$startVal ($($startMap[[int]$startVal]))" } else { $startVal }
          ServiceType        = if ($null -ne $typeVal -and $typeMap.ContainsKey([int]$typeVal)) { "$typeVal ($($typeMap[[int]$typeVal]))" } else { $typeVal }
          NameKeyLastWrite   = (Get-RegKeyLastWrite $svcKey.PSPath)
          ParametersKeyLastWrite = $paramsLastWrite
          Group              = $sp.Group
          ImagePath          = $imgPath
          ServiceDll         = $svcDll
          ObjectName         = $sp.ObjectName
          RequiredPrivileges = $reqPriv
        })
      }
      if ($svcRows.Count) { $svcRows | Sort-Object ServiceName | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "Services") "Services_decoded.csv") -NoTypeInformation -Encoding UTF8 }

      # Network Shares (LanmanServer\Shares) - defined SMB shares on this host
      $shares = Get-RegValuesAsRows -KeyPath "$root\$cs\Services\LanmanServer\Shares" -SourceLabel "HKLM\SYSTEM\$cs\...\LanmanServer\Shares"
      if ($shares.Count) { $shares | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Network "Shares") "Shares.csv") -NoTypeInformation -Encoding UTF8 }
      return $true
    } | Out-Null
    Write-Log "RegPersistence: HKLM SYSTEM Services extracted"
  }

  # --- Per-user NTUSER.DAT: Run keys, RDP MRU, MountPoints2 ---
  foreach ($p in (Get-UserProfiles)) {
    $ntuser = Join-Path $p.FullName "NTUSER.DAT"
    if (-not (Test-Path -LiteralPath $ntuser)) { continue }
    $uname = $p.Name
    Use-MountedHive -HivePath $ntuser -MountName "DFIR_NTUSER" -ActionArgs @($uname) -Action {
      param($root, $uname)
      $rows = New-Object System.Collections.ArrayList
      Add-RowsSafe $rows (Get-RegValuesAsRows -KeyPath "$root\Software\Microsoft\Windows\CurrentVersion\Run" -SourceLabel "HKCU\...\Run")
      Add-RowsSafe $rows (Get-RegValuesAsRows -KeyPath "$root\Software\Microsoft\Windows\CurrentVersion\RunOnce" -SourceLabel "HKCU\...\RunOnce")
      if ($rows.Count) { $rows | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Persistence "RunKeys") ("RunKeys_{0}.csv" -f $uname)) -NoTypeInformation -Encoding UTF8 }

      $rdp = Get-RegValuesAsRows -KeyPath "$root\Software\Microsoft\Terminal Server Client\Default" -SourceLabel "HKCU\...\Terminal Server Client\Default"
      $rdpServers = Get-RegValuesAsRows -KeyPath "$root\Software\Microsoft\Terminal Server Client\Servers" -SourceLabel "HKCU\...\Terminal Server Client\Servers" -Subkeys
      $rdpAll = New-Object System.Collections.ArrayList
      Add-RowsSafe $rdpAll $rdp; Add-RowsSafe $rdpAll $rdpServers
      if ($rdpAll.Count) { $rdpAll | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Network "RDP_MRU") ("RDP_MRU_{0}.csv" -f $uname)) -NoTypeInformation -Encoding UTF8 }

      $mp2 = Get-RegValuesAsRows -KeyPath "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -SourceLabel "HKCU\...\MountPoints2" -Subkeys
      if ($mp2.Count) { $mp2 | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.USB "MountPoints2") ("MountPoints2_{0}.csv" -f $uname)) -NoTypeInformation -Encoding UTF8 }

      # RecentApps - evidence of execution (per-user)
      $recentApps = Get-RegValuesAsRows -KeyPath "$root\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps" -SourceLabel "HKCU\...\Search\RecentApps" -Subkeys
      if ($recentApps.Count) { $recentApps | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Execution "RecentApps") ("RecentApps_{0}.csv" -f $uname)) -NoTypeInformation -Encoding UTF8 }

      # Network Drive Mappings (mapped drives + Map Network Drive MRU)
      $netDrives = New-Object System.Collections.ArrayList
      Add-RowsSafe $netDrives (Get-RegValuesAsRows -KeyPath "$root\Network" -SourceLabel "HKCU\Network" -Subkeys)
      Add-RowsSafe $netDrives (Get-RegValuesAsRows -KeyPath "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" -SourceLabel "HKCU\...\Map Network Drive MRU")
      if ($netDrives.Count) { $netDrives | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Network "NetworkDrives") ("NetworkDrives_{0}.csv" -f $uname)) -NoTypeInformation -Encoding UTF8 }

      # PuTTY - saved sessions and known SSH host keys (lateral movement / remote access)
      $putty = New-Object System.Collections.ArrayList
      Add-RowsSafe $putty (Get-RegValuesAsRows -KeyPath "$root\Software\SimonTatham\PuTTY\Sessions" -SourceLabel "HKCU\...\PuTTY\Sessions" -Subkeys)
      Add-RowsSafe $putty (Get-RegValuesAsRows -KeyPath "$root\Software\SimonTatham\PuTTY\SshHostKeys" -SourceLabel "HKCU\...\PuTTY\SshHostKeys")
      if ($putty.Count) { $putty | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Network "PuTTY") ("PuTTY_{0}.csv" -f $uname)) -NoTypeInformation -Encoding UTF8 }
      return $true
    } | Out-Null
    Write-Log "[$uname] RegPersistence: NTUSER keys extracted (Run, RDP MRU, MountPoints2, RecentApps, NetworkDrives, PuTTY)"

    # MUICache lives in UsrClass.dat (Vista+), separate hive from NTUSER.
    $usrclass = Join-Path $p.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"
    if (Test-Path -LiteralPath $usrclass) {
      Use-MountedHive -HivePath $usrclass -MountName "DFIR_USRCLASS" -ActionArgs @($uname) -Action {
        param($root, $uname)
        $mui = Get-RegValuesAsRows -KeyPath "$root\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" -SourceLabel "UsrClass\...\Shell\MuiCache"
        if ($mui.Count) { $mui | Export-Csv -LiteralPath (Join-Path (Get-ArtefactDir $script:cat.Execution "MUICache") ("MUICache_{0}.csv" -f $uname)) -NoTypeInformation -Encoding UTF8 }
        return $true
      } | Out-Null
      Write-Log "[$uname] RegPersistence: MUICache extracted from UsrClass.dat"
    }
  }
}

function Invoke-BamDam {
  # BAM/DAM (Background/Desktop Activity Moderator) - evidence of execution.
  # Path: SYSTEM\<ControlSet>\Services\bam\State\UserSettings\<SID>\<exe path>
  # (pre-1809 used bam\UserSettings). Each value's data begins with an 8-byte
  # FILETIME of last execution. We mount SYSTEM, walk each SID, decode the
  # FILETIME, and write a CSV. Needs elevation.
  param([string]$SystemHive, [string]$OutDir)
  if (-not (Test-Path -LiteralPath $SystemHive)) { Write-Log "BAM/DAM: SYSTEM hive not found"; return }

  $rows = Use-MountedHive -HivePath $SystemHive -MountName "DFIR_BAM" -Action {
    param($root)
    $out = New-Object System.Collections.ArrayList
    $cur = 1
    try { $sel = Get-ItemProperty -Path "$root\Select" -Name "Current" -ErrorAction Stop; $cur = [int]$sel.Current } catch {}
    $cs = "ControlSet{0:D3}" -f $cur

    foreach ($svc in @("bam","dam")) {
      $userSettingsPaths = @(
        "$root\$cs\Services\$svc\State\UserSettings",
        "$root\$cs\Services\$svc\UserSettings"
      )
      foreach ($usPath in $userSettingsPaths) {
        if (-not (Test-Path -LiteralPath $usPath)) { continue }
        $sidKeys = Get-ChildItem -LiteralPath $usPath -ErrorAction SilentlyContinue
        foreach ($sidKey in $sidKeys) {
          $sid = $sidKey.PSChildName
          try { $vals = Get-ItemProperty -LiteralPath $sidKey.PSPath -ErrorAction Stop } catch { continue }
          foreach ($prop in $vals.PSObject.Properties) {
            if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider","SequenceNumber","Version")) { continue }
            $bytes = $prop.Value
            if ($bytes -isnot [byte[]] -or $bytes.Length -lt 8) { continue }
            # First 8 bytes = little-endian FILETIME of last execution.
            $ft = [BitConverter]::ToInt64($bytes, 0)
            $when = ""
            if ($ft -gt 0) {
              try { $when = [DateTime]::FromFileTimeUtc($ft).ToString("yyyy-MM-dd HH:mm:ss") + " UTC" } catch { $when = "(undecodable: $ft)" }
            }
            [void]$out.Add([PSCustomObject]@{
              Source         = $svc.ToUpper()
              SID            = $sid
              ExecutablePath = $prop.Name
              LastExecution  = $when
              RawFiletime    = $ft
            })
          }
        }
      }
    }
    return $out
  }

  if ($rows -and $rows.Count -gt 0) {
    $csv = Join-Path (Get-ArtefactDir $OutDir "BAM_DAM") "BAM_DAM.csv"
    $rows | Sort-Object LastExecution -Descending | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Log "BAM/DAM: $($rows.Count) entries decoded (FILETIME last-execution per SID)"
  } else {
    Write-Log "BAM/DAM: no entries found (or not elevated / not present)"
  }
}

function Invoke-ChromeSessions {
  # Wrapper for the Chrome SNSS + History forensic parser (Python). This
  # recovers tab/session URLs from Chrome's binary SNSS files (Sessions\
  # Session_*/Tabs_*, plus legacy Current/Last Session/Tabs) that the SQLite
  # History DB - and therefore Hindsight - does NOT contain. Also cross-checks
  # History, Downloads, Cookies, cleared-visit gaps, etc.
  #
  # The script auto-discovers ALL Chrome profiles across ALL users under the
  # path it is given, so we hand it the image root and let it enumerate. It
  # writes chrome_forensic_<timestamp>.csv into ITS OWN directory (not a path
  # we pass), so afterwards we locate the newest such CSV and move it into the
  # output tree.
  param([string]$OutDir)
  $py = Resolve-ToolPy "SNSS-parser-win_v1.py"
  if (-not $py) { $py = Resolve-ToolPy "SNSS-parser-win.py" }
  if (-not $py) { Write-Log "ChromeSessions: SKIPPED (SNSS parser .py not in ToolsDir)"; return }

  # Resolve a Python interpreter.
  $pyExe = $null
  foreach ($cand in @("py","python","python3")) {
    $c = Get-Command $cand -ErrorAction SilentlyContinue
    if ($c) { $pyExe = $c.Source; break }
  }
  if (-not $pyExe) { Write-Log "ChromeSessions: SKIPPED (no Python interpreter found)"; return }

  $dest = Get-ArtefactDir $OutDir "ChromeSessions"
  $scriptDir = Split-Path $py -Parent
  # Snapshot existing chrome_forensic_*.csv in the script dir so we can find
  # the one this run produces.
  $before = @{}
  Get-ChildItem -LiteralPath $scriptDir -Filter "chrome_forensic_*.csv" -File -ErrorAction SilentlyContinue |
    ForEach-Object { $before[$_.FullName] = $true }

  Write-Log "ChromeSessions: parsing Chrome SNSS + History under image root"
  try {
    & $pyExe $py "$ImageRoot" 2>&1 | Out-File (Join-Path $logDir "ChromeSessions.log") -Encoding utf8
  } catch {
    Write-Log "ChromeSessions ERROR: $($_.Exception.Message)"
    return
  }

  # Find newly-created chrome_forensic_*.csv (and its skipped log) and move them.
  $newCsvs = Get-ChildItem -LiteralPath $scriptDir -Filter "chrome_forensic_*.csv" -File -ErrorAction SilentlyContinue |
             Where-Object { -not $before.ContainsKey($_.FullName) }
  $moved = 0
  foreach ($csv in $newCsvs) {
    $rowN = 0
    try { $rowN = (@(Import-Csv -LiteralPath $csv.FullName -ErrorAction SilentlyContinue)).Count } catch {}
    Move-Item -LiteralPath $csv.FullName -Destination (Join-Path $dest $csv.Name) -Force -ErrorAction SilentlyContinue
    # Bring the matching _skipped.log alongside, if present.
    $logTwin = $csv.FullName -replace '\.csv$','_skipped.log'
    if (Test-Path -LiteralPath $logTwin) {
      Move-Item -LiteralPath $logTwin -Destination (Join-Path $dest (Split-Path $logTwin -Leaf)) -Force -ErrorAction SilentlyContinue
    }
    $moved++
    Write-Log "ChromeSessions: $($csv.Name) - $rowN entries (moved to 10_BrowserForensics\ChromeSessions)"
  }
  if ($moved -eq 0) { Write-Log "ChromeSessions: no output CSV produced (no Chrome profiles found?)" }
}

function Invoke-LnkSweep {
  # Parse EVERY .lnk file across the whole image in one recursive pass, rather
  # than from a hardcoded folder list. LECmd's -d is recursive, so pointing it
  # at the image root finds .lnk files in ANY location - each user's Recent\ and
  # Desktop, Public\Desktop, Startup (persistence), Downloads, temp dirs, other
  # drives, wherever. This is location-agnostic and works on any collected
  # package structure, not just one layout. Output: one LNK_AllLocations.csv
  # whose "Source File" column shows exactly where each .lnk lived.
  param([string]$OutDir)
  $tool = Resolve-Tool "LECmd.exe"
  if (-not $tool) { Write-Log "LECmd: SKIPPED (LECmd.exe not in ToolsDir)"; return }
  $lnkDir = Get-ArtefactDir $OutDir "LNK"
  Write-Log "LECmd: recursive .lnk sweep across entire image root"
  # -d <root> recurses; -q quiet; --csv/--csvf one consolidated file.
  $a = [System.Collections.ArrayList]@("-d", $ImageRoot, "--csv", $lnkDir, "--csvf", "LNK_AllLocations.csv", "-q")
  Add-DtArg $a
  try {
    & $tool @a 2>&1 | Out-File (Join-Path $logDir "LECmd_sweep.log") -Encoding utf8
    $csv = Join-Path $lnkDir "LNK_AllLocations.csv"
    if (Test-Path -LiteralPath $csv) {
      $n = (@(Import-Csv -LiteralPath $csv -ErrorAction SilentlyContinue)).Count
      Write-Log "LECmd: done ($n .lnk file(s) parsed across the image)"
    } else {
      Write-Log "LECmd: sweep produced no CSV (no .lnk files found?)"
    }
  } catch {
    Write-Log "LECmd sweep ERROR: $($_.Exception.Message)"
  }
}

function Invoke-SamAccounts {
  # SAM\Domains\Account\Users - local account inventory. The SAM hive's keys
  # are ACL-protected against the Win32 registry API even for elevated admins,
  # so a reg-mount + Get-ChildItem returns nothing. Tools like Registry Explorer
  # and RECmd succeed by parsing the RAW HIVE BYTES directly, ignoring ACLs.
  # We do the same here: a minimal regf/hbin/nk/vk/lf-lh parser that walks to
  # SAM\Domains\Account\Users, then decodes each RID's F record (timestamps +
  # flags + counts) and V record (username). No reg.exe, no elevation needed.
  param([string]$SamHive, [string]$OutDir)
  if (-not (Test-Path -LiteralPath $SamHive)) { Write-Log "SAM: hive not found at $SamHive"; return }

  try {
    $bytes = [System.IO.File]::ReadAllBytes($SamHive)
  } catch {
    # File may be locked; copy via shared read first.
    $tmp = Join-Path $env:TEMP ("sam_{0}.hive" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    if (Copy-FileShared $SamHive $tmp) {
      try { $bytes = [System.IO.File]::ReadAllBytes($tmp) } catch { Write-Log "SAM: could not read hive bytes: $($_.Exception.Message)"; return }
      Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    } else { Write-Log "SAM: could not read or copy hive ($SamHive)"; return }
  }
  if (-not $bytes -or $bytes.Length -lt 4096 -or $bytes[0] -ne 0x72 -or $bytes[1] -ne 0x65 -or $bytes[2] -ne 0x67 -or $bytes[3] -ne 0x66) {
    Write-Log "SAM: not a valid registry hive (regf signature missing)"; return
  }

  # All cell offsets are relative to the start of the first hbin, which is at
  # file offset 0x1000. A cell at "offset" lives at file position 0x1000+offset.
  $base = 0x1000
  function script:_U16($b,$o){ if ($o -lt 0 -or ($o+2) -gt $b.Length) { return 0 } return [BitConverter]::ToUInt16($b,$o) }
  function script:_U32($b,$o){ if ($o -lt 0 -or ($o+4) -gt $b.Length) { return 0 } return [BitConverter]::ToUInt32($b,$o) }
  function script:_I32($b,$o){ if ($o -lt 0 -or ($o+4) -gt $b.Length) { return 0 } return [BitConverter]::ToInt32($b,$o) }

  # Root cell offset is at 0x24 in the regf header.
  $rootOff = script:_I32 $bytes 0x24

  # --- helpers to read nk (key) and find subkeys / values ---
  # An nk cell: at cell+0 is 'nk' sig; +0x14 subkey count; +0x1c subkeys list
  # offset; +0x24 values count; +0x28 values list offset; name len at +0x48,
  # name at +0x4c.
  $getNkName = {
    param($nkOff)
    $p = $base + $nkOff + 4   # skip 4-byte cell size
    if ($p -lt 0 -or ($p+0x4c) -gt $bytes.Length) { return $null }
    if ([System.Text.Encoding]::ASCII.GetString($bytes,$p,2) -ne 'nk') { return $null }
    $nameLen = script:_U16 $bytes ($p+0x48)
    $flags   = script:_U16 $bytes ($p+0x02)
    $nameOff = $p + 0x4c
    if ($nameLen -le 0 -or ($nameOff+$nameLen) -gt $bytes.Length) { return $null }
    if ($flags -band 0x20) { return [System.Text.Encoding]::ASCII.GetString($bytes,$nameOff,$nameLen) }
    else { return [System.Text.Encoding]::Unicode.GetString($bytes,$nameOff,$nameLen) }
  }

  # Return hashtable of childName -> nkOffset for an nk's subkeys.
  $getSubkeys = {
    param($nkOff)
    $res = @{}
    $p = $base + $nkOff + 4
    if ($p -lt 0 -or ($p+0x20) -gt $bytes.Length) { return $res }
    if ([System.Text.Encoding]::ASCII.GetString($bytes,$p,2) -ne 'nk') { return $res }
    $subCount = script:_U32 $bytes ($p+0x14)
    if ($subCount -eq 0 -or $subCount -gt 100000) { return $res }
    $listOff = script:_I32 $bytes ($p+0x1c)
    if ($listOff -le 0) { return $res }
    $lp = $base + $listOff + 4
    if ($lp -lt 0 -or ($lp+4) -gt $bytes.Length) { return $res }
    $sig = [System.Text.Encoding]::ASCII.GetString($bytes,$lp,2)
    $entries = New-Object System.Collections.ArrayList
    if ($sig -eq 'lf' -or $sig -eq 'lh') {
      $cnt = script:_U16 $bytes ($lp+2)
      for ($i=0; $i -lt $cnt; $i++) {
        $eOff = script:_I32 $bytes ($lp + 4 + ($i*8))   # 4-byte nk offset + 4-byte hash
        [void]$entries.Add($eOff)
      }
    } elseif ($sig -eq 'ri') {
      $cnt = script:_U16 $bytes ($lp+2)
      for ($i=0; $i -lt $cnt; $i++) {
        $subListOff = script:_I32 $bytes ($lp + 4 + ($i*4))
        $slp = $base + $subListOff + 4
        $ssig = [System.Text.Encoding]::ASCII.GetString($bytes,$slp,2)
        if ($ssig -eq 'lf' -or $ssig -eq 'lh') {
          $scnt = script:_U16 $bytes ($slp+2)
          for ($j=0; $j -lt $scnt; $j++) { [void]$entries.Add((script:_I32 $bytes ($slp + 4 + ($j*8)))) }
        }
      }
    }
    foreach ($eOff in $entries) {
      $nm = & $getNkName $eOff
      if ($nm -ne $null) { $res[$nm] = $eOff }
    }
    return $res
  }

  # Return hashtable of valueName -> byte[] data for an nk's values.
  $getValues = {
    param($nkOff)
    $res = @{}
    $p = $base + $nkOff + 4
    if ([System.Text.Encoding]::ASCII.GetString($bytes,$p,2) -ne 'nk') { return $res }
    $valCount = script:_U32 $bytes ($p+0x24)
    if ($valCount -eq 0 -or $valCount -gt 100000) { return $res }
    $valListOff = script:_I32 $bytes ($p+0x28)
    if ($valListOff -le 0) { return $res }
    $vlp = $base + $valListOff + 4
    for ($i=0; $i -lt $valCount; $i++) {
      $vkOff = script:_I32 $bytes ($vlp + ($i*4))
      $vp = $base + $vkOff + 4
      if ($vp -lt 0 -or ($vp+0x14) -gt $bytes.Length) { continue }
      if ([System.Text.Encoding]::ASCII.GetString($bytes,$vp,2) -ne 'vk') { continue }
      $nameLen = script:_U16 $bytes ($vp+0x02)
      $dataLen = script:_U32 $bytes ($vp+0x04)
      $dataOff = script:_I32 $bytes ($vp+0x08)
      $flags   = script:_U16 $bytes ($vp+0x10)
      $vname = ""
      if ($nameLen -gt 0 -and ($vp+0x14+$nameLen) -le $bytes.Length) { $vname = [System.Text.Encoding]::ASCII.GetString($bytes,$vp+0x14,$nameLen) }
      # If high bit of dataLen set, data is resident inline (in the dataOff field).
      $inline = ($dataLen -band 0x80000000)
      $realLen = $dataLen -band 0x7fffffff
      $data = New-Object byte[] 0
      if ($inline) {
        $data = New-Object byte[] ([Math]::Min($realLen,4))
        [Array]::Copy($bytes, $vp+0x08, $data, 0, $data.Length)
      } elseif ($realLen -gt 0 -and $realLen -lt 1000000) {
        $dp = $base + $dataOff + 4
        if (($dp + $realLen) -le $bytes.Length) {
          $data = New-Object byte[] $realLen
          [Array]::Copy($bytes, $dp, $data, 0, $realLen)
        }
      }
      $res[$vname] = $data
    }
    return $res
  }

  # Navigate root -> SAM -> Domains -> Account -> Users
  $cur = $rootOff
  foreach ($seg in @("SAM","Domains","Account","Users")) {
    $subs = & $getSubkeys $cur
    $match = $null
    foreach ($k in $subs.Keys) { if ($k -ieq $seg) { $match = $subs[$k]; break } }
    if ($null -eq $match) { Write-Log "SAM: path segment '$seg' not found in hive"; return }
    $cur = $match
  }

  $ftAt = {
    param($b,$off)
    if ($b.Length -lt ($off+8)) { return "" }
    $v = [BitConverter]::ToInt64($b,$off)
    if ($v -le 0) { return "" }
    try { return [DateTime]::FromFileTimeUtc($v).ToString("yyyy-MM-dd HH:mm:ss") + " UTC" } catch { return "" }
  }

  $rows = New-Object System.Collections.ArrayList
  $ridSubs = & $getSubkeys $cur
  foreach ($ridName in $ridSubs.Keys) {
    if ($ridName -notmatch '^[0-9A-Fa-f]{8}$') { continue }
    $ridDec = [Convert]::ToInt32($ridName,16)
    $vals = & $getValues $ridSubs[$ridName]
    $f = $vals['F']; $v = $vals['V']
    $lastLogon=""; $pwdLastSet=""; $acctExpiry=""; $lastBadPwd=""; $pwdCanChange=""; $pwdMustChange=""
    $loginCount=""; $badPwdCount=""
    $disabled=$false; $pwdNotReq=$false; $pwdNoExpire=$false; $locked=$false; $normalAcct=$false
    if ($f -is [byte[]] -and $f.Length -ge 60) {
      $lastLogon     = & $ftAt $f 8     # 0x08 last logon
      $pwdLastSet    = & $ftAt $f 24    # 0x18 password last set
      $acctExpiry    = & $ftAt $f 32    # 0x20 account expires
      $lastBadPwd    = & $ftAt $f 40    # 0x28 last incorrect password
      # ACB flags word at 0x38 - expand the meaningful bits to columns.
      $acb = script:_U16 $f 56
      $disabled    = [bool]($acb -band 0x0001)
      $pwdNotReq   = [bool]($acb -band 0x0008)   # password not required
      $pwdNoExpire = [bool]($acb -band 0x0200)   # password does not expire
      $locked      = [bool]($acb -band 0x0400)   # account auto-locked
      $normalAcct  = [bool]($acb -band 0x0010)   # normal user account
      if ($f.Length -ge 68) {
        $badPwdCount = script:_U16 $f 64   # 0x40
        $loginCount  = script:_U16 $f 66   # 0x42
      }
    }

    # V record: reusable reader for the (offset,length) descriptor table.
    # Descriptors are 12 bytes apart; offsets are relative to 0xCC. Index:
    #   0x0c=Username  0x18=FullName  0x24=Comment
    $readV = {
      param($vbytes, $descOff)
      if ($vbytes -isnot [byte[]] -or $vbytes.Length -lt ($descOff + 8)) { return "" }
      try {
        $off = (script:_I32 $vbytes $descOff) + 0xCC
        $len = script:_I32 $vbytes ($descOff + 4)
        if ($len -gt 0 -and ($off + $len) -le $vbytes.Length) {
          return [System.Text.Encoding]::Unicode.GetString($vbytes, $off, $len)
        }
      } catch {}
      return ""
    }
    $userName = & $readV $v 0x0c
    $fullName = & $readV $v 0x18
    $comment  = & $readV $v 0x24

    [void]$rows.Add([PSCustomObject]@{
      RID=$ridDec; Username=$userName; FullName=$fullName; Comment=$comment
      AccountDisabled=$disabled; AccountLocked=$locked; NormalAccount=$normalAcct
      PasswordNotRequired=$pwdNotReq; PasswordNeverExpires=$pwdNoExpire
      LastLogon=$lastLogon; PasswordLastSet=$pwdLastSet; LastBadPassword=$lastBadPwd
      AccountExpires=$acctExpiry; LoginCount=$loginCount; BadPasswordCount=$badPwdCount
    })
  }

  if ($rows.Count -gt 0) {
    $csv = Join-Path (Get-ArtefactDir $OutDir "SAM") "SAM_Accounts.csv"
    $rows | Sort-Object RID | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Log "SAM: $($rows.Count) local account(s) decoded from raw hive (Domains\Account\Users)"
  } else {
    Write-Log "SAM: no accounts decoded from raw hive"
  }
}

function Invoke-Evtx {
  # EvtxECmd (Eric Zimmerman) - parse Windows event logs (.evtx) to CSV with
  # the maps that normalise event fields. We point it at the whole winevt\Logs
  # directory (-d) so every channel is parsed in one pass, output to a single
  # consolidated CSV in 13_EventLogs. Optionally a -SkipTools "Evtx" disables it.
  param([string]$OutDir)
  $tool = Resolve-Tool "EvtxECmd.exe"
  if (-not $tool) { Write-Log "EvtxECmd: SKIPPED (EvtxECmd.exe not in ToolsDir)"; return }
  $logsDir = Join-Path $ImageRoot "Windows\System32\winevt\Logs"
  if (-not (Test-Path -LiteralPath $logsDir)) {
    # Some collections flatten the logs elsewhere; try a couple of alternates.
    $alt = @(
      (Join-Path $ImageRoot "Windows\System32\winevt\logs"),
      (Join-Path $ImageRoot "winevt\Logs")
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($alt) { $logsDir = $alt } else {
      Write-Log "EvtxECmd: winevt\Logs not found at $logsDir"; return
    }
  }
  $csvOut = Get-ArtefactDir $OutDir "EventLogs"
  Write-Log "EvtxECmd: parsing event logs in $logsDir"
  # -d <dir> processes recursively; --csv <dir> --csvf <file> for one combined CSV.
  $a = [System.Collections.ArrayList]@("-d", $logsDir, "--csv", $csvOut, "--csvf", "AllEventLogs.csv")
  Add-DtArg $a
  try {
    & $tool @a 2>&1 | Out-File (Join-Path $logDir "EvtxECmd.log") -Encoding utf8
    Write-Log "EvtxECmd: done"
  } catch {
    Write-Log "EvtxECmd ERROR: $($_.Exception.Message)"
  }
}

function Copy-EmailStores {
  # Locate and COPY email client data stores (we do not parse them - .ost/.pst
  # are opened offline with XstReader/pff-tools; .mbox with a mail reader).
  # Outlook: AppData\Local\Microsoft\Outlook\*.ost|*.pst
  # Thunderbird: AppData\Roaming\Thunderbird\Profiles\*\*.msf / Mail / ImapMail
  # Copies per-user into 12_Email\<user>\. Large files - logged with size.
  param([string]$OutDir)
  $found = 0
  foreach ($p in (Get-UserProfiles)) {
    $userName = $p.Name
    $userBase = $p.FullName
    $userOut = $null   # created lazily only if something is found

    # --- Outlook .ost / .pst ---
    $outlookDir = Join-Path $userBase "AppData\Local\Microsoft\Outlook"
    if (Test-Path -LiteralPath $outlookDir) {
      $stores = Get-ChildItem -LiteralPath $outlookDir -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @(".ost",".pst") }
      foreach ($s in $stores) {
        if (-not $userOut) { $userOut = Get-ArtefactDir $OutDir $userName }
        $sizeMB = [math]::Round($s.Length / 1MB, 1)
        Write-Log "[$userName] Email: copying Outlook $($s.Name) (${sizeMB} MB)"
        try {
          Copy-Item -LiteralPath $s.FullName -Destination (Join-Path $userOut $s.Name) -Force -ErrorAction Stop
          $found++
        } catch { Write-Log "[$userName] Email copy ERROR ($($s.Name)): $($_.Exception.Message)" }
      }
    }

    # --- Thunderbird profiles (Mail, ImapMail, *.msf, and any *.mbox) ---
    $tbird = Join-Path $userBase "AppData\Roaming\Thunderbird\Profiles"
    if (Test-Path -LiteralPath $tbird) {
      $tbStores = Get-ChildItem -LiteralPath $tbird -File -Recurse -ErrorAction SilentlyContinue |
                  Where-Object { $_.Extension -in @(".msf",".mbox") -or $_.Name -eq "Inbox" -or $_.Name -eq "Sent" }
      foreach ($s in $tbStores) {
        if (-not $userOut) { $userOut = Get-ArtefactDir $OutDir $userName }
        $tbOut = Get-ArtefactDir $userOut "Thunderbird"
        $sizeMB = [math]::Round($s.Length / 1MB, 1)
        Write-Log "[$userName] Email: copying Thunderbird $($s.Name) (${sizeMB} MB)"
        try {
          # Prefix with parent folder to avoid Inbox/Sent name collisions
          $prefix = Split-Path (Split-Path $s.FullName -Parent) -Leaf
          Copy-Item -LiteralPath $s.FullName -Destination (Join-Path $tbOut ("{0}_{1}" -f $prefix, $s.Name)) -Force -ErrorAction SilentlyContinue
          $found++
        } catch { Write-Log "[$userName] Email Thunderbird copy ERROR: $($_.Exception.Message)" }
      }
    }
  }
  if ($found -eq 0) {
    Write-Log "Email: no Outlook/Thunderbird stores found in any profile"
  } else {
    Write-Log "Email: copied $found mail store file(s) into 12_Email (open .ost/.pst with XstReader or pff-tools)"
  }
}

function Invoke-OfficeMRU {
  # Microsoft Office File/Place MRU - per-user recent documents with a decoded
  # per-entry timestamp. Format of each "Item N" value:
  #   [F00000000][T<hexFILETIME>][O00000000]*<path>
  # The T-bracket is a 64-bit FILETIME as an uppercase hex string = last time
  # the file/folder was accessed FROM the Office app (distinct from RecentDocs).
  # Covers direct "<App>\File MRU" and Microsoft 365 "<App>\User MRU\LiveId_*\
  # File MRU" (and Place MRU). Per-user via NTUSER.DAT mount. Needs elevation.
  param([string]$Ntuser, [string]$UserName, [string]$OutDir)
  if (-not (Test-Path -LiteralPath $Ntuser)) { return }

  $result = Use-MountedHive -HivePath $Ntuser -MountName "DFIR_OFFMRU" -ActionArgs @($UserName) -Action {
    param($root, $uname)
    $fileRows  = New-Object System.Collections.ArrayList
    $placeRows = New-Object System.Collections.ArrayList
    $officeRoot = "$root\Software\Microsoft\Office"
    if (-not (Test-Path -LiteralPath $officeRoot)) { return [PSCustomObject]@{ File = $fileRows; Place = $placeRows } }

    # Decode an Office MRU value string into @{ Time=<utc>; Path=<str> }.
    $decode = {
      param($valStr)
      $time = ""
      $path = $valStr
      $m = [regex]::Match($valStr, '\[T([0-9A-Fa-f]+)\]')
      if ($m.Success) {
        try {
          $ft = [Convert]::ToInt64($m.Groups[1].Value, 16)
          if ($ft -gt 0) { $time = [DateTime]::FromFileTimeUtc($ft).ToString("yyyy-MM-dd HH:mm:ss") + " UTC" }
        } catch {}
      }
      # Path is everything after the last "*" separator.
      $star = $valStr.LastIndexOf('*')
      if ($star -ge 0 -and $star -lt ($valStr.Length - 1)) { $path = $valStr.Substring($star + 1) }
      return @{ Time = $time; Path = $path }
    }

    # Harvest every "Item N" value from a given File/Place MRU key into rows.
    $harvest = {
      param($mruKeyPath, $mruType, $version, $app, $account, $bag)
      if (-not (Test-Path -LiteralPath $mruKeyPath)) { return }
      $klw = Get-RegKeyLastWrite $mruKeyPath
      try { $item = Get-ItemProperty -LiteralPath $mruKeyPath -ErrorAction Stop } catch { return }
      foreach ($prop in $item.PSObject.Properties) {
        if ($prop.Name -notmatch '^Item \d+$') { continue }
        $dec = & $decode ([string]$prop.Value)
        [void]$bag.Add([PSCustomObject]@{
          User          = $uname
          OfficeVersion = $version
          App           = $app
          MruType       = $mruType
          Account       = $account
          ItemName      = $prop.Name
          LastOpened    = $dec.Time
          Path          = $dec.Path
          KeyLastWrite  = $klw
        })
      }
    }

    # Walk each version (e.g. 16.0) and each app under it.
    foreach ($verKey in (Get-ChildItem -LiteralPath $officeRoot -ErrorAction SilentlyContinue)) {
      $version = $verKey.PSChildName
      if ($version -notmatch '^\d+\.\d+$') { continue }
      foreach ($appKey in (Get-ChildItem -LiteralPath $verKey.PSPath -ErrorAction SilentlyContinue)) {
        $app = $appKey.PSChildName
        if ($app -notin @("Word","Excel","PowerPoint","Access","Publisher","OneNote","Project","Visio")) { continue }

        # Direct (local-account) File MRU / Place MRU
        & $harvest (Join-Path $appKey.PSPath "File MRU")  "File"  $version $app "Local" $fileRows
        & $harvest (Join-Path $appKey.PSPath "Place MRU") "Place" $version $app "Local" $placeRows

        # Microsoft 365 / LiveId: <App>\User MRU\<LiveId_*>\File MRU|Place MRU
        $userMru = Join-Path $appKey.PSPath "User MRU"
        if (Test-Path -LiteralPath $userMru) {
          foreach ($acct in (Get-ChildItem -LiteralPath $userMru -ErrorAction SilentlyContinue)) {
            $acctName = $acct.PSChildName
            & $harvest (Join-Path $acct.PSPath "File MRU")  "File"  $version $app $acctName $fileRows
            & $harvest (Join-Path $acct.PSPath "Place MRU") "Place" $version $app $acctName $placeRows
          }
        }
      }
    }
    return [PSCustomObject]@{ File = $fileRows; Place = $placeRows }
  }

  if ($result) {
    $wrote = 0
    if ($result.File.Count) {
      $dest = Get-ArtefactDir $OutDir "OfficeMRU"
      $result.File | Sort-Object LastOpened -Descending | Export-Csv -LiteralPath (Join-Path $dest ("OfficeFileMRU_{0}.csv" -f $UserName)) -NoTypeInformation -Encoding UTF8
      $wrote += $result.File.Count
    }
    if ($result.Place.Count) {
      $dest = Get-ArtefactDir $OutDir "OfficeMRU"
      $result.Place | Sort-Object LastOpened -Descending | Export-Csv -LiteralPath (Join-Path $dest ("OfficePlaceMRU_{0}.csv" -f $UserName)) -NoTypeInformation -Encoding UTF8
      $wrote += $result.Place.Count
    }
    if ($wrote) { Write-Log "[$UserName] Office MRU: $wrote entry(ies) extracted (File + Place, decoded timestamps)" }
  }
}

function Invoke-Firewall {
  # Windows Firewall artefacts:
  #   1. Rules from SYSTEM\<CS>\Services\SharedAccess\Parameters\FirewallPolicy
  #      (FirewallRules + Mdm + RestrictedServices stores). Each value is one
  #      rule: pipe-delimited Key=Value attributes. We dump raw AND parse into
  #      named columns. Needs elevation (reg.exe mount).
  #   2. Firewall logs (pfirewall.log*) - copied from System32\LogFiles\Firewall.
  param([string]$SystemHive, [string]$OutDir)

  # --- Rules (registry) ---
  if (Test-Path -LiteralPath $SystemHive) {
    $parsed = Use-MountedHive -HivePath $SystemHive -MountName "DFIR_FW" -Action {
      param($root)
      $cur = 1
      try { $sel = Get-ItemProperty -Path "$root\Select" -Name "Current" -ErrorAction Stop; $cur = [int]$sel.Current } catch {}
      $cs = "ControlSet{0:D3}" -f $cur
      $fwBase = "$root\$cs\Services\SharedAccess\Parameters\FirewallPolicy"
      $stores = @(
        @{ Path = "$fwBase\FirewallRules";                         Label = "FirewallRules" },
        @{ Path = "$fwBase\RestrictedServices\Configurable\System"; Label = "RestrictedServices-Configurable" },
        @{ Path = "$fwBase\RestrictedServices\Static\System";       Label = "RestrictedServices-Static" },
        @{ Path = "$fwBase\Mdm\FirewallRules";                      Label = "Mdm" }
      )
      $rawRows    = New-Object System.Collections.ArrayList
      $parsedRows = New-Object System.Collections.ArrayList
      # Friendly names for the common pipe-delimited rule attribute keys.
      foreach ($store in $stores) {
        if (-not (Test-Path -LiteralPath $store.Path)) { continue }
        $klw = Get-RegKeyLastWrite $store.Path
        try { $item = Get-ItemProperty -LiteralPath $store.Path -ErrorAction Stop } catch { continue }
        foreach ($prop in $item.PSObject.Properties) {
          if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
          $ruleStr = [string]$prop.Value
          Add-RowsSafe $rawRows ([PSCustomObject]@{
            Store        = $store.Label
            KeyLastWrite = $klw
            RuleId       = $prop.Name
            RawRule      = $ruleStr
          })
          # Parse pipe-delimited Key=Value attributes into a flat hashtable.
          $h = @{}
          foreach ($tok in ($ruleStr -split '\|')) {
            if ($tok -match '^([^=]+)=(.*)$') { $h[$matches[1]] = $matches[2] }
          }
          Add-RowsSafe $parsedRows ([PSCustomObject]@{
            Store        = $store.Label
            RuleId       = $prop.Name
            Name         = $h['Name']
            Action       = $h['Action']
            Active       = $h['Active']
            Direction    = $h['Dir']
            Protocol     = $h['Protocol']
            LocalPort    = $h['LPort']
            RemotePort   = $h['RPort']
            App          = $h['App']
            Service      = $h['Svc']
            Profile      = $h['Profile']
            RA4          = $h['RA4']
            RA6          = $h['RA6']
            Description  = $h['Desc']
            KeyLastWrite = $klw
          })
        }
      }
      return [PSCustomObject]@{ Raw = $rawRows; Parsed = $parsedRows }
    }
    if ($parsed -and $parsed.Parsed.Count) {
      $dest = Get-ArtefactDir $OutDir "FirewallRules"
      $parsed.Raw    | Export-Csv -LiteralPath (Join-Path $dest "FirewallRules_raw.csv")    -NoTypeInformation -Encoding UTF8
      $parsed.Parsed | Export-Csv -LiteralPath (Join-Path $dest "FirewallRules_parsed.csv") -NoTypeInformation -Encoding UTF8
      Write-Log "Firewall: $($parsed.Parsed.Count) rule(s) extracted and parsed"
    } else {
      Write-Log "Firewall: no rules found (or hive locked / not elevated)"
    }
  }

  # --- Logs (plain text) ---
  $fwLogDir = Join-Path $ImageRoot "Windows\System32\LogFiles\Firewall"
  if (Test-Path -LiteralPath $fwLogDir) {
    $logs = Get-ChildItem -LiteralPath $fwLogDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^pfirewall.*\.log$' }
    if ($logs) {
      $dest = Get-ArtefactDir $OutDir "FirewallLogs"
      foreach ($l in $logs) {
        Copy-Item -LiteralPath $l.FullName -Destination (Join-Path $dest $l.Name) -Force -ErrorAction SilentlyContinue
      }
      Write-Log "Firewall: copied $($logs.Count) firewall log file(s)"
    } else {
      Write-Log "Firewall: log dir present but no pfirewall*.log files"
    }
  } else {
    Write-Log "Firewall: no firewall log dir (logging may be disabled)"
  }
}

function Invoke-PCA {
  # Windows 11 22H2+ Program Compatibility Assistant execution artefacts at
  # Windows\appcompat\pca\. Copies the raw .txt files and parses the pipe-
  # delimited PcaAppLaunchDic.txt (format: <timestamp>|<...>|<path> or
  # <path>|<timestamp> depending on build) into a clean CSV. No elevation needed.
  param([string]$OutDir)
  $pcaDir = Join-Path $ImageRoot "Windows\appcompat\pca"
  if (-not (Test-Path -LiteralPath $pcaDir)) {
    Write-Log "PCA: no appcompat\pca dir (normal on Win10/Server or pre-22H2)"; return
  }
  $dest = Get-ArtefactDir $OutDir "PCA"
  $copied = 0
  Get-ChildItem -LiteralPath $pcaDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^Pca.*\.txt$' } |
    ForEach-Object {
      Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $dest $_.Name) -Force -ErrorAction SilentlyContinue
      $copied++
    }

  # Parse PcaAppLaunchDic.txt -> CSV. Each line is pipe-delimited; we extract
  # the timestamp (YYYY-MM-DD HH:MM:SS[.f] UTC) and the executable path.
  $dic = Join-Path $pcaDir "PcaAppLaunchDic.txt"
  if (Test-Path -LiteralPath $dic) {
    $rows = New-Object System.Collections.ArrayList
    foreach ($line in (Get-Content -LiteralPath $dic -ErrorAction SilentlyContinue)) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      $parts = $line -split '\|'
      # Find the timestamp field and the path field regardless of column order.
      $ts = ($parts | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}' } | Select-Object -First 1)
      $path = ($parts | Where-Object { $_ -match '[\\/].+\.\w+$' -or $_ -match '^[a-zA-Z]:\\' } | Select-Object -First 1)
      if (-not $path) { $path = ($parts | Sort-Object Length -Descending | Select-Object -First 1) }
      [void]$rows.Add([PSCustomObject]@{
        LastExecution  = $ts
        ExecutablePath = $path
        RawLine        = $line
      })
    }
    if ($rows.Count) {
      $rows | Export-Csv -LiteralPath (Join-Path $dest "PcaAppLaunchDic_parsed.csv") -NoTypeInformation -Encoding UTF8
    }
    Write-Log "PCA: copied $copied raw file(s); parsed $($rows.Count) PcaAppLaunchDic entries"
  } else {
    Write-Log "PCA: copied $copied raw file(s) (no PcaAppLaunchDic.txt to parse)"
  }
}

function Write-OsDetails {
  # Build a plain-text OS/system summary from the SOFTWARE and SYSTEM hives
  # using the values RECmd already extracted, plus a few direct reads. Output
  # is a single human-readable .txt for quick case orientation.
  param([string]$OutFile)
  $lines = New-Object System.Collections.ArrayList
  [void]$lines.Add("Windows OS / System Details")
  [void]$lines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
  [void]$lines.Add("Hostname:  $hostName")
  [void]$lines.Add("ImageRoot: $ImageRoot")
  [void]$lines.Add(("=" * 60))

  # Pull from the RECmd main batch CSV if present (it has OS Version, Computer
  # Name, Time Zone, network interfaces, etc. already extracted as rows).
  $batchCsv = Get-ChildItem -LiteralPath $cat.RegistryRaw -Filter "*RECmd_Batch*.csv" -File -ErrorAction SilentlyContinue |
              Select-Object -First 1
  if ($batchCsv) {
    try {
      $rows = Import-Csv -LiteralPath $batchCsv.FullName
      $wanted = @{
        "OS Version"                  = @("ProductName","CurrentBuild","ReleaseId","DisplayVersion","UBR","InstallDate","RegisteredOwner")
        "Computer Name"               = @("ComputerName")
        "Time Zone"                   = @("TimeZoneKeyName","Bias","StandardName","DaylightName")
        "CurrentControlSet Resolver"  = @("Current","Default")
      }
      foreach ($desc in $wanted.Keys) {
        $matchRows = $rows | Where-Object { $_.Description -eq $desc }
        if ($matchRows) {
          [void]$lines.Add("")
          [void]$lines.Add("[$desc]")
          foreach ($r in $matchRows) {
            if ($wanted[$desc] -contains $r.ValueName) {
              $val = $r.ValueData
              # InstallDate is a Unix epoch (seconds) - render it readable too.
              if ($r.ValueName -eq "InstallDate" -and $val -match '^\d{9,10}$') {
                try {
                  $dt = [DateTimeOffset]::FromUnixTimeSeconds([int64]$val).UtcDateTime
                  $val = "{0}  ({1} UTC)" -f $val, $dt.ToString("yyyy-MM-dd HH:mm:ss")
                } catch {}
              }
              [void]$lines.Add(("  {0,-22} : {1}" -f $r.ValueName, $val))
            }
          }
        }
      }

      # Network interfaces - IP addresses were read from the SYSTEM hive up
      # front (same reg.exe mount that resolved the hostname) and cached in
      # $script:SystemIps.
      [void]$lines.Add("")
      [void]$lines.Add("[IP Addresses]")
      if ($script:SystemIps -and $script:SystemIps.Count -gt 0) {
        foreach ($entry in $script:SystemIps) { [void]$lines.Add(("  {0}" -f $entry)) }
      } else {
        [void]$lines.Add("  (no IPv4 addresses found in SYSTEM hive Tcpip Interfaces)")
      }
    } catch {
      [void]$lines.Add("(could not read RECmd batch CSV: $($_.Exception.Message))")
    }
  } else {
    [void]$lines.Add("(RECmd batch CSV not found - run RECmd step first)")
  }

  # Profile list (SID -> username) summary, if the plugin CSV exists.
  $plCsv = Get-ChildItem -LiteralPath (Join-Path $cat.Accounts "ProfileList") -Filter "*.csv" -File -ErrorAction SilentlyContinue |
           Select-Object -First 1
  if ($plCsv) {
    [void]$lines.Add("")
    [void]$lines.Add("[User Profiles (SID -> path)]")
    try {
      Import-Csv -LiteralPath $plCsv.FullName | ForEach-Object {
        $sid  = $_.Sid; if (-not $sid) { $sid = $_.SID }
        $path = $_.ProfileImagePath; if (-not $path) { $path = $_.ProfilePath }
        if ($sid) { [void]$lines.Add(("  {0,-50} {1}" -f $sid, $path)) }
      }
    } catch {}
  }

  try {
    Set-Content -LiteralPath $OutFile -Value $lines -Encoding UTF8
    Write-Log "OS details: written to $OutFile"
  } catch {
    Write-Log "OS details ERROR: $($_.Exception.Message)"
  }
}

# ---------------------------------------------------------------------------
# Validation + setup
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $ImageRoot)) {
  throw "ImageRoot not found: $ImageRoot"
}
if (-not (Test-Path -LiteralPath $ToolsDir)) {
  throw "ToolsDir not found: $ToolsDir"
}

New-DirIfMissing $OutputDir

# Resolve hostname AND IP addresses from the SYSTEM hive up front (single
# reg.exe mount), then nest ALL output under <OutputDir>\<hostname>\.
$earlySystemHive = Join-Path $ImageRoot "Windows\System32\config\SYSTEM"
$sysInfo = Resolve-SystemInfo $earlySystemHive
$hostName = $sysInfo.Name
$script:SystemIps = $sysInfo.Ips
$OutputDir = Join-Path $OutputDir $hostName
New-DirIfMissing $OutputDir

$logDir = Join-Path $OutputDir "_logs"
New-DirIfMissing $logDir
$script:LogPath = Join-Path $logDir "Invoke-DFIRParse.log"
"" | Out-File -FilePath $script:LogPath -Encoding utf8

Write-Log "=== DFIR artefact parse starting ==="
Write-Log "Hostname  : $hostName"
if ($sysInfo.Diag) { Write-Log "System info: $($sysInfo.Diag)" }
Write-Log "ImageRoot : $ImageRoot"
Write-Log "OutputDir : $OutputDir"
Write-Log "ToolsDir  : $ToolsDir"
Write-Log "RebFile   : $RebFile"

# Category output directories (numbered to mirror matrix section order)
# NOTE: script-scoped ($script:cat) so that scriptblocks invoked inside
# functions (e.g. via Use-MountedHive) can still resolve it. A plain $cat
# would be invisible inside those scriptblocks, silently producing $null
# paths and skipping every CSV write in the registry-mount collectors.
$script:cat = @{
  Execution    = Join-Path $OutputDir "00_Execution"
  FileActivity = Join-Path $OutputDir "01_FileFolderActivity"
  NTFS         = Join-Path $OutputDir "02_NTFS"
  USB          = Join-Path $OutputDir "03_USB"
  Network      = Join-Path $OutputDir "04_Network"
  Persistence  = Join-Path $OutputDir "05_Persistence"
  Accounts     = Join-Path $OutputDir "06_Accounts"
  SystemInfo   = Join-Path $OutputDir "07_SystemInfo"
  RegistryRaw  = Join-Path $OutputDir "08_Registry_Raw"
  BrowserCache = Join-Path $OutputDir "09_BrowserAndCache"
  Browser      = Join-Path $OutputDir "10_BrowserForensics"
  Defender     = Join-Path $OutputDir "11_Defender"
  Email        = Join-Path $OutputDir "12_Email"
  EventLogs    = Join-Path $OutputDir "13_EventLogs"
}
$cat = $script:cat
foreach ($d in $cat.Values) { New-DirIfMissing $d }

# Returns (and creates) a per-artefact subfolder under a category folder,
# e.g. Get-ArtefactDir $cat.Execution "Prefetch" -> 00_Execution\Prefetch\
function Get-ArtefactDir([string]$CategoryDir, [string]$ArtefactName) {
  $d = Join-Path $CategoryDir $ArtefactName
  New-DirIfMissing $d
  return $d
}

# Common image paths
$configDir   = Join-Path $ImageRoot "Windows\System32\config"
$amcachePath = Join-Path $ImageRoot "Windows\AppCompat\Programs\Amcache.hve"
$prefetchDir = Join-Path $ImageRoot "Windows\Prefetch"
$systemHive  = Join-Path $configDir "SYSTEM"
$srumPath    = Join-Path $ImageRoot "Windows\System32\sru\SRUDB.dat"
$mftPath     = Join-Path $ImageRoot '$MFT'

# UsnJrnl ($J) location varies by collector. Check the standard $Extend\$J
# first, then common alternates (flattened, or $J carved to its own file).
$usnPath = $null
$usnCandidates = @(
  (Join-Path $ImageRoot '$Extend\$J'),
  (Join-Path $ImageRoot '$Extend\$UsnJrnl_$J'),
  (Join-Path $ImageRoot '$J'),
  (Join-Path $ImageRoot '$UsnJrnl_$J'),
  (Join-Path $ImageRoot '$UsnJrnl%3A$J')
)
foreach ($c in $usnCandidates) {
  if (Test-Path -LiteralPath $c) { $usnPath = $c; break }
}

# ---------------------------------------------------------------------------
# 1. RECmd - registry batch (all hives)
#    Plugin CSVs land in RegistryRaw; the main batch CSV also lands there.
#    Post-run, plugin CSVs are sorted into category folders by name.
# ---------------------------------------------------------------------------
if (-not (Should-Skip "RECmd")) {
  $recmd = Resolve-Tool "RECmd.exe"
  if ($recmd -and $RebFile -and (Test-Path -LiteralPath $RebFile)) {
    Write-Log "RECmd: batch parse against $ImageRoot"
    $a = [System.Collections.ArrayList]@("-d", $ImageRoot, "--bn", $RebFile, "--csv", $cat.RegistryRaw, "--recover", "--nl")
    Add-DtArg $a
    try {
      & $recmd @a 2>&1 | Out-File (Join-Path $logDir "RECmd.console.log") -Encoding utf8
    } catch {
      Write-Log "RECmd ERROR: $_"
    }

    # RECmd writes plugin detail CSVs into a <timestamp> SUBFOLDER beneath the
    # --csv dir, and the main batch CSV at the --csv root. We COPY each plugin
    # CSV into its category's per-artefact subfolder (originals stay in
    # 08_Registry_Raw so the raw set remains intact). Map keyword -> (category,
    # artefact subfolder name).
    $sortMap = @{
      "UserAssist"      = @($cat.Execution,    "UserAssist")
      "RecentApps"      = @($cat.Execution,    "RecentApps")
      "AppCompatCache"  = @($cat.Execution,    "ShimCache")
      "BamDam"          = @($cat.Execution,    "BAM_DAM")
      "RecentDocs"      = @($cat.FileActivity, "RecentDocs")
      "CIDSizeMRU"      = @($cat.FileActivity, "ComDlg32")
      "LastVisited"     = @($cat.FileActivity, "ComDlg32")
      "OpenSave"        = @($cat.FileActivity, "ComDlg32")
      "OfficeMRU"       = @($cat.FileActivity, "OfficeMRU")
      "TrustedDocuments"= @($cat.FileActivity, "TrustedDocuments")
      "WordWheelQuery"  = @($cat.FileActivity, "WordWheelQuery")
      "MountedDevices"  = @($cat.USB,          "MountedDevices")
      "USBSTOR"         = @($cat.USB,          "USBSTOR")
      "USB"             = @($cat.USB,          "USB")
      "NetworkList"     = @($cat.Network,      "NetworkList")
      "TaskCache"       = @($cat.Persistence,  "TaskCache")
      "Services"        = @($cat.Persistence,  "Services")
      "ProfileList"     = @($cat.Accounts,     "ProfileList")
      "SAM"             = @($cat.Accounts,     "SAM")
    }
    # Find plugin CSVs recursively (they live in the <timestamp> subfolder),
    # excluding the main batch CSV.
    $pluginCsvs = Get-ChildItem -LiteralPath $cat.RegistryRaw -Filter "*.csv" -File -Recurse -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notmatch "RECmd_Batch" }
    $copied = 0
    foreach ($csv in $pluginCsvs) {
      foreach ($key in $sortMap.Keys) {
        if ($csv.Name -match $key) {
          $catDir      = $sortMap[$key][0]
          $artefactSub = $sortMap[$key][1]
          $destDir = Get-ArtefactDir $catDir $artefactSub
          $dest = Join-Path $destDir $csv.Name
          if (-not (Test-Path -LiteralPath $dest)) {
            Copy-Item -LiteralPath $csv.FullName -Destination $dest -ErrorAction SilentlyContinue
            $copied++
          }
          break
        }
      }
    }
    Write-Log "RECmd: done (main batch CSV + plugin CSVs in 08_Registry_Raw; $copied plugin CSV(s) copied into category folders)"
  } else {
    Write-Log "RECmd: SKIPPED (RECmd.exe or .reb file missing)"
  }
}

# ---------------------------------------------------------------------------
# 2. AppCompatCacheParser - ShimCache
# ---------------------------------------------------------------------------
if (-not (Should-Skip "AppCompatCacheParser")) {
  $tool = Resolve-Tool "AppCompatCacheParser.exe"
  if ($tool -and (Test-Path -LiteralPath $systemHive)) {
    Write-Log "AppCompatCacheParser: $systemHive"
    $a = [System.Collections.ArrayList]@("-f", $systemHive, "--csv", (Get-ArtefactDir $cat.Execution "ShimCache"), "--csvf", "ShimCache.csv", "--nl")
    Add-DtArg $a
    try { & $tool @a 2>&1 | Out-File (Join-Path $logDir "AppCompatCacheParser.log") -Encoding utf8 }
    catch { Write-Log "AppCompatCacheParser ERROR: $_" }
  } else {
    Write-Log "AppCompatCacheParser: SKIPPED (tool or SYSTEM hive missing)"
  }
}

# ---------------------------------------------------------------------------
# 3. AmcacheParser - AmCache.hve
# ---------------------------------------------------------------------------
if (-not (Should-Skip "AmcacheParser")) {
  $tool = Resolve-Tool "AmcacheParser.exe"
  if ($tool -and (Test-Path -LiteralPath $amcachePath)) {
    Write-Log "AmcacheParser: $amcachePath"
    $a = [System.Collections.ArrayList]@("-f", $amcachePath, "--csv", (Get-ArtefactDir $cat.Execution "Amcache"), "--csvf", "Amcache.csv", "-i", "--nl")
    Add-DtArg $a
    try { & $tool @a 2>&1 | Out-File (Join-Path $logDir "AmcacheParser.log") -Encoding utf8 }
    catch { Write-Log "AmcacheParser ERROR: $_" }
  } else {
    Write-Log "AmcacheParser: SKIPPED (tool or Amcache.hve missing)"
  }
}

# ---------------------------------------------------------------------------
# 4. PECmd - Prefetch
# ---------------------------------------------------------------------------
if (-not (Should-Skip "PECmd")) {
  $tool = Resolve-Tool "PECmd.exe"
  if ($tool -and (Test-Path -LiteralPath $prefetchDir)) {
    Write-Log "PECmd: $prefetchDir"
    $a = [System.Collections.ArrayList]@("-d", $prefetchDir, "--csv", (Get-ArtefactDir $cat.Execution "Prefetch"), "--csvf", "Prefetch.csv")
    Add-DtArg $a
    try { & $tool @a 2>&1 | Out-File (Join-Path $logDir "PECmd.log") -Encoding utf8 }
    catch { Write-Log "PECmd ERROR: $_" }
  } else {
    Write-Log "PECmd: SKIPPED (tool or Prefetch dir missing - normal on Server OS)"
  }
}

# ---------------------------------------------------------------------------
# 5. MFTECmd - $MFT (CSV + body/mactime timeline) and $J (UsnJrnl, MFT-resolved)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "MFTECmd")) {
  $tool = Resolve-Tool "MFTECmd.exe"
  if ($tool) {
    $mftDir = Get-ArtefactDir $cat.NTFS "MFT"
    if (Test-Path -LiteralPath $mftPath) {

      # 5a. Standard CSV output
      Write-Log 'MFTECmd: $MFT -> CSV'
      $a = [System.Collections.ArrayList]@("-f", $mftPath, "--csv", $mftDir, "--csvf", "MFT.csv")
      Add-DtArg $a
      try { & $tool @a 2>&1 | Out-File (Join-Path $logDir "MFTECmd_MFT_csv.log") -Encoding utf8 }
      catch { Write-Log "MFTECmd (`$MFT CSV) ERROR: $_" }

      # 5b. Bodyfile output (TSK-compatible) for mactime timeline
      #     MFTECmd writes <timestamp>_MFTECmd_$MFT_Output.body into --body dir.
      Write-Log 'MFTECmd: $MFT -> bodyfile (--bdl c)'
      $b = [System.Collections.ArrayList]@("-f", $mftPath, "--body", $mftDir, "--bdl", "c")
      Add-DtArg $b
      try { & $tool @b 2>&1 | Out-File (Join-Path $logDir "MFTECmd_MFT_body.log") -Encoding utf8 }
      catch { Write-Log "MFTECmd (`$MFT body) ERROR: $_" }

      # 5c. mactime - convert bodyfile to a timeline CSV (requires Perl + mactime.pl)
      if ($MactimePath -and (Test-Path -LiteralPath $MactimePath)) {
        $perlExe = Resolve-Perl
        if (-not $perlExe) {
          Write-Log "mactime: SKIPPED (no Perl interpreter found - install Strawberry Perl or add perl.exe to PATH)"
        } else {
          $bodyFile = Get-ChildItem -LiteralPath $mftDir -Filter "*_MFTECmd_*MFT*Output.body" -File -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending | Select-Object -First 1
          if ($bodyFile) {
            $timelineCsv = Join-Path $mftDir "mft_timeline.csv"
            Write-Log "mactime: $($bodyFile.Name) -> mft_timeline.csv (perl: $perlExe)"
            try {
              # perl mactime.pl -b <bodyfile> -d  > timeline.csv  (-d = comma-delimited)
              & $perlExe $MactimePath -b $bodyFile.FullName -d 2>(Join-Path $logDir "mactime.err.log") |
                Out-File -FilePath $timelineCsv -Encoding utf8
              Write-Log "mactime: done"
            } catch {
              Write-Log "mactime ERROR: $($_.Exception.Message)"
            }
          } else {
            Write-Log "mactime: SKIPPED (no .body file produced by MFTECmd)"
          }
        }
      } else {
        Write-Log "mactime: SKIPPED (mactime.pl path not supplied via -MactimePath)"
      }

    } else {
      Write-Log 'MFTECmd: $MFT not found at image root (may not be in collection)'
    }

    # 5d. $J (UsnJrnl) - pass -m $MFT so entries resolve to full parent paths
    if ($usnPath -and (Test-Path -LiteralPath $usnPath)) {
      Write-Log "MFTECmd: `$J (UsnJrnl) at $usnPath"
      $j = [System.Collections.ArrayList]@("-f", $usnPath)
      if (Test-Path -LiteralPath $mftPath) { [void]$j.Add("-m"); [void]$j.Add($mftPath) }
      [void]$j.Add("--csv");  [void]$j.Add((Get-ArtefactDir $cat.NTFS "UsnJrnl"))
      [void]$j.Add("--csvf"); [void]$j.Add("UsnJrnl.csv")
      Add-DtArg $j
      try { & $tool @j 2>&1 | Out-File (Join-Path $logDir "MFTECmd_J.log") -Encoding utf8 }
      catch { Write-Log "MFTECmd (`$J) ERROR: $_" }
    } else {
      Write-Log 'MFTECmd: $J not found in any known location (UsnJrnl may not be in collection)'
    }
  } else {
    Write-Log "MFTECmd: SKIPPED (tool missing)"
  }
}

# ---------------------------------------------------------------------------
# 6. SrumECmd - SRUDB.dat (needs SOFTWARE hive for ID resolution)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "SrumECmd")) {
  $tool = Resolve-Tool "SrumECmd.exe"
  if ($tool -and (Test-Path -LiteralPath $srumPath)) {
    Write-Log "SrumECmd: $srumPath"
    $softwareHive = Join-Path $configDir "SOFTWARE"
    $a = [System.Collections.ArrayList]@("-f", $srumPath, "--csv", (Get-ArtefactDir $cat.Network "SRUM"))
    if (Test-Path -LiteralPath $softwareHive) { [void]$a.Add("-r"); [void]$a.Add($softwareHive) }
    Add-DtArg $a
    try { & $tool @a 2>&1 | Out-File (Join-Path $logDir "SrumECmd.log") -Encoding utf8 }
    catch { Write-Log "SrumECmd ERROR: $_" }
  } else {
    Write-Log "SrumECmd: SKIPPED (tool or SRUDB.dat missing)"
  }
}

# ---------------------------------------------------------------------------
# Per-user tools: SBECmd, JLECmd, LECmd, RBCmd, WxTCmd
# ---------------------------------------------------------------------------
$profiles = Get-UserProfiles
Write-Log "Found $($profiles.Count) user profile(s) to process"

foreach ($p in $profiles) {
  $userName = $p.Name
  $userBase = $p.FullName

  # --- 7. SBECmd - ShellBags (reads UsrClass.dat + NTUSER.DAT under a dir) ---
  if (-not (Should-Skip "SBECmd")) {
    $tool = Resolve-Tool "SBECmd.exe"
    if ($tool) {
      Write-Log "[$userName] SBECmd"
      $sbeDir = Get-ArtefactDir $cat.FileActivity "ShellBags"
      $snap = Get-CsvSnapshot $sbeDir
      $a = [System.Collections.ArrayList]@("-d", $userBase, "--csv", $sbeDir)
      Add-DtArg $a
      try {
        & $tool @a 2>&1 | Out-File (Join-Path $logDir "SBECmd_$userName.log") -Encoding utf8
        Prefix-NewCsvs $sbeDir "ShellBags_$userName" $snap
      } catch { Write-Log "[$userName] SBECmd ERROR: $_" }
    }
  }

  # --- 8. JLECmd - Jump Lists (Automatic + Custom) ---
  # JLECmd can emit very long intermediate filenames (AppID + entry detail).
  # Combined with a deep --csv path this trips the 260-char MAX_PATH limit on
  # Windows PowerShell 5.1. Workaround: write to a short temp dir (C:\jle_tmp)
  # then move the CSVs into the category folder with the proper prefix.
  if (-not (Should-Skip "JLECmd")) {
    $tool = Resolve-Tool "JLECmd.exe"
    if ($tool) {
      $recent = Join-Path $userBase "AppData\Roaming\Microsoft\Windows\Recent"
      foreach ($sub in @("AutomaticDestinations","CustomDestinations")) {
        $src = Join-Path $recent $sub
        if (Test-Path -LiteralPath $src) {
          Write-Log "[$userName] JLECmd $sub"
          # Short temp output dir at drive root keeps total path well under 260
          $jleTmp = Join-Path $env:SystemDrive ("jle_{0}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
          New-DirIfMissing $jleTmp
          $a = [System.Collections.ArrayList]@("-d", $src, "--csv", $jleTmp)
          Add-DtArg $a
          try {
            & $tool @a 2>&1 | Out-File (Join-Path $logDir "JLECmd_${userName}_$sub.log") -Encoding utf8
            # Move outputs into per-artefact subfolder with prefix
            $jleDir = Get-ArtefactDir $cat.FileActivity "JumpLists"
            Get-ChildItem -LiteralPath $jleTmp -Filter "*.csv" -File -ErrorAction SilentlyContinue | ForEach-Object {
              $newName = "JumpList_${userName}_${sub}_$($_.Name)"
              $dest = Join-Path $jleDir $newName
              if (Test-Path -LiteralPath $dest) {
                $newName = "JumpList_${userName}_${sub}_$([guid]::NewGuid().ToString('N').Substring(0,6))_$($_.Name)"
                $dest = Join-Path $jleDir $newName
              }
              Move-Item -LiteralPath $_.FullName -Destination $dest -ErrorAction SilentlyContinue
            }
          } catch { Write-Log "[$userName] JLECmd ($sub) ERROR: $_" }
          finally {
            Remove-Item -LiteralPath $jleTmp -Recurse -Force -ErrorAction SilentlyContinue
          }
        }
      }
    }
  }

  # --- 9. LECmd - handled by a whole-image recursive sweep AFTER this loop ---
  # (LNK files are collected once across the entire image root rather than from
  # a hardcoded per-user folder list - see Invoke-LnkSweep below. This catches
  # .lnk files in ANY location: Desktop, Startup, Downloads, Public, temp dirs,
  # secondary drives, etc. - not just each user's Recent\.)

  # --- 10. WxTCmd - Win10 Timeline (ActivitiesCache.db, may be multiple) ---
  if (-not (Should-Skip "WxTCmd")) {
    $tool = Resolve-Tool "WxTCmd.exe"
    if ($tool) {
      $cdp = Join-Path $userBase "AppData\Local\ConnectedDevicesPlatform"
      if (Test-Path -LiteralPath $cdp) {
        $dbs = Get-ChildItem -LiteralPath $cdp -Recurse -Filter "ActivitiesCache.db" -File -ErrorAction SilentlyContinue
        $idx = 0
        foreach ($db in $dbs) {
          $idx++
          Write-Log "[$userName] WxTCmd DB$idx : $($db.FullName)"
          $tlDir = Get-ArtefactDir $cat.Execution "Timeline"
          $snap = Get-CsvSnapshot $tlDir
          $a = [System.Collections.ArrayList]@("-f", $db.FullName, "--csv", $tlDir)
          Add-DtArg $a
          try {
            & $tool @a 2>&1 | Out-File (Join-Path $logDir "WxTCmd_${userName}_DB$idx.log") -Encoding utf8
            Prefix-NewCsvs $tlDir ("Timeline_{0}_DB{1:D2}" -f $userName, $idx) $snap
          } catch { Write-Log "[$userName] WxTCmd ERROR: $_" }
        }
      }
    }
  }

  # --- 11. CryptnetUrlCache - per-user URL carve (pure PowerShell) ---
  if (-not (Should-Skip "CryptNet")) {
    Invoke-CryptNetExtract -ProfileName $userName -BasePath $userBase -OutDir $cat.BrowserCache
  }

  # --- 11b. PSReadline ConsoleHost_history.txt - per-user typed PS commands ---
  if (-not (Should-Skip "PSReadline")) {
    Copy-PSReadlineHistory -ProfileName $userName -BasePath $userBase -OutDir (Get-ArtefactDir $cat.Execution "PSReadlineHistory")
  }

  # --- 11c. Office File/Place MRU - per-user recent docs with decoded times ---
  if (-not (Should-Skip "OfficeMRU")) {
    Invoke-OfficeMRU -Ntuser (Join-Path $userBase "NTUSER.DAT") -UserName $userName -OutDir $cat.FileActivity
  }

  # --- 12. Hindsight - Chromium browser forensics (Chrome / Edge / Brave) ---
  # hindsight.exe -i <profile dir> -o <base name> -f xlsx [-b Chrome|Brave]
  # Notes on output placement:
  #  * -o accepts a FULL PATH base name (no extension), so we pass an absolute
  #    path rather than relying on CWD - PyInstaller exes don't always honour
  #    Push-Location for output.
  #  * We still Push-Location into $hsDir as a belt-and-braces fallback, then
  #    sweep for any *.xlsx Hindsight may have dropped elsewhere and move it in.
  if (-not (Should-Skip "Hindsight")) {
    $tool = Resolve-Tool "hindsight.exe"
    if ($tool) {
      $browsers = @{
        Chrome = @{ Path = (Join-Path $userBase "AppData\Local\Google\Chrome\User Data");        BType = "Chrome" }
        Edge   = @{ Path = (Join-Path $userBase "AppData\Local\Microsoft\Edge\User Data");        BType = "Chrome" }
        Brave  = @{ Path = (Join-Path $userBase "AppData\Local\BraveSoftware\Brave-Browser\User Data"); BType = "Brave" }
      }
      $hsDir = Get-ArtefactDir $cat.Browser $userName
      foreach ($bName in $browsers.Keys) {
        $udir = $browsers[$bName].Path
        if (-not (Test-Path -LiteralPath $udir)) { continue }

        # Hindsight wants a single profile dir. Try "Default" first, then any
        # "Profile *" folders, then the User Data root. Only run on dirs that
        # actually contain a History DB so we don't get empty no-op runs.
        $candidateProfiles = New-Object System.Collections.ArrayList
        $defaultP = Join-Path $udir "Default"
        if (Test-Path -LiteralPath $defaultP) { [void]$candidateProfiles.Add($defaultP) }
        Get-ChildItem -LiteralPath $udir -Directory -Filter "Profile *" -ErrorAction SilentlyContinue |
          ForEach-Object { [void]$candidateProfiles.Add($_.FullName) }
        if ($candidateProfiles.Count -eq 0) { [void]$candidateProfiles.Add($udir) }

        foreach ($profileDir in $candidateProfiles) {
          $historyDb = Join-Path $profileDir "History"
          if (-not (Test-Path -LiteralPath $historyDb)) {
            Write-Log "[$userName] Hindsight $bName : no History DB in $profileDir - skipped"
            continue
          }
          $profileLabel = Split-Path $profileDir -Leaf
          $baseName = "Hindsight_{0}_{1}_{2}" -f $userName, $bName, ($profileLabel -replace '\s','')
          $outBase  = Join-Path $hsDir $baseName   # absolute base path for -o
          Write-Log "[$userName] Hindsight $bName ($profileLabel): $profileDir"

          $snapXlsx = @{}
          Get-ChildItem -LiteralPath $hsDir -Filter "*.xlsx" -File -ErrorAction SilentlyContinue |
            ForEach-Object { $snapXlsx[$_.FullName] = $true }

          # hindsight.exe is a PyInstaller-frozen exe using 'rich'. Its banner
          # output crashes ONLY when stdout is redirected (rich's legacy Win32
          # writer hits cp1252 on glyphs like U+25BC). The XLSX deliverable is
          # written entirely via -o and does NOT depend on stdout. So we simply
          # DO NOT capture/redirect Hindsight's console at all - we let it print
          # freely, which keeps rich on its normal (non-crashing) path. The -o
          # file is the artefact we care about; the console chatter is discarded.
          Push-Location -LiteralPath $hsDir
          try {
            $a = [System.Collections.ArrayList]@("-i", $profileDir, "-o", $outBase, "-f", "xlsx", "-b", $browsers[$bName].BType)
            # Call directly with NO redirection and NO pipe. rich sees a real
            # console and uses its normal renderer, so the banner does not crash.
            & $tool @a
            if ($LASTEXITCODE -ne 0) {
              Write-Log "[$userName] Hindsight $bName ($profileLabel): exit code $LASTEXITCODE"
            }
          } catch {
            Write-Log "[$userName] Hindsight $bName ERROR: $($_.Exception.Message)"
          } finally {
            Pop-Location
          }

          # Sweep: if Hindsight wrote the xlsx somewhere other than $hsDir
          # (CWD, tool dir, or with its default timestamp name), pull it in.
          $sweepLocations = @($hsDir, (Get-Location).Path, (Split-Path $tool -Parent), $env:TEMP)
          foreach ($loc in ($sweepLocations | Select-Object -Unique)) {
            Get-ChildItem -LiteralPath $loc -Filter "*.xlsx" -File -ErrorAction SilentlyContinue |
              Where-Object { -not $snapXlsx.ContainsKey($_.FullName) -and $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
              ForEach-Object {
                $want = Join-Path $hsDir ("{0}_{1}" -f $baseName, $_.Name)
                if ($_.DirectoryName -ne $hsDir) {
                  Move-Item -LiteralPath $_.FullName -Destination $want -ErrorAction SilentlyContinue
                }
              }
          }
        }
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 11. RBCmd - Recycle Bin ($I files across all SIDs)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "RBCmd")) {
  $tool = Resolve-Tool "RBCmd.exe"
  $recycle = Join-Path $ImageRoot '$Recycle.Bin'
  if ($tool -and (Test-Path -LiteralPath $recycle)) {
    Write-Log "RBCmd: $recycle"
    $a = [System.Collections.ArrayList]@("-d", $recycle, "--csv", (Get-ArtefactDir $cat.FileActivity "RecycleBin"), "--csvf", "RecycleBin.csv", "-q")
    Add-DtArg $a
    try { & $tool @a 2>&1 | Out-File (Join-Path $logDir "RBCmd.log") -Encoding utf8 }
    catch { Write-Log "RBCmd ERROR: $_" }
  } else {
    Write-Log "RBCmd: SKIPPED (tool or \$Recycle.Bin missing)"
  }
}

# ---------------------------------------------------------------------------
# 11b. LECmd - whole-image recursive .lnk sweep (any location, any package).
# ---------------------------------------------------------------------------
if (-not (Should-Skip "LECmd")) {
  Invoke-LnkSweep -OutDir $cat.FileActivity
}

# ---------------------------------------------------------------------------
# 11c. Chrome SNSS session parser - recovers tab/session URLs absent from the
#      History DB (and Hindsight). Whole-image, all users, all Chrome variants.
# ---------------------------------------------------------------------------
if (-not (Should-Skip "ChromeSessions")) {
  Invoke-ChromeSessions -OutDir $cat.Browser
}

# ---------------------------------------------------------------------------
# 12b. CryptnetUrlCache - SYSTEM profile (not under Users\)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "CryptNet")) {
  $sysProfile = Join-Path $ImageRoot "Windows\System32\config\systemprofile"
  if (Test-Path -LiteralPath $sysProfile) {
    Invoke-CryptNetExtract -ProfileName "SYSTEM" -BasePath $sysProfile -OutDir $cat.BrowserCache
  }
  # LocalService / NetworkService also have CryptNet caches worth checking
  foreach ($svc in @("LocalService","NetworkService")) {
    $svcProfile = Join-Path $ImageRoot "Windows\ServiceProfiles\$svc"
    if (Test-Path -LiteralPath $svcProfile) {
      Invoke-CryptNetExtract -ProfileName $svc -BasePath $svcProfile -OutDir $cat.BrowserCache
    }
  }
}

# ---------------------------------------------------------------------------
# 13. sidr - windows.edb / Windows.db search index (per-system)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "sidr")) {
  Invoke-Sidr -OutDir (Get-ArtefactDir $cat.FileActivity "SearchIndex")
}

# ---------------------------------------------------------------------------
# 13b. SumECmd - SUM database (Server 2012+ client access / CAL usage)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "SUM")) {
  Invoke-Sum -OutDir (Get-ArtefactDir $cat.Network "SUM")
}

# ---------------------------------------------------------------------------
# 14. IconCacheReader - all user profiles in one pass (-users-dir mode)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "IconCache")) {
  $usersRoot = Join-Path $ImageRoot "Users"
  Invoke-IconCacheReader -UsersRoot $usersRoot -OutDir (Get-ArtefactDir $cat.Execution "IconCache")
}

# ---------------------------------------------------------------------------
# 15. Microsoft Defender detection logs (MPDetection/MPLog + DetectionHistory)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "Defender")) {
  Invoke-DefenderDetections -OutDir $cat.Defender
}

# ---------------------------------------------------------------------------
# 16. Registry persistence keys without a RECmd plugin (reg.exe mount).
#     Run/Winlogon/IFEO/AppInit/AppPaths/Services + per-user Run/RDP/MountPoints2.
#     Requires elevation (reg.exe load needs the restore privilege).
# ---------------------------------------------------------------------------
if (-not (Should-Skip "RegPersistence")) {
  Clear-DfirMounts   # sweep any leftover mounts holding hive file handles
  $softwareHiveMain = Join-Path $configDir "SOFTWARE"
  Invoke-RegPersistence -SoftwareHive $softwareHiveMain -SystemHive $systemHive
}

# ---------------------------------------------------------------------------
# 17. BAM/DAM - evidence of execution with decoded FILETIME (reg.exe mount).
# ---------------------------------------------------------------------------
if (-not (Should-Skip "BAM")) {
  Invoke-BamDam -SystemHive $systemHive -OutDir $cat.Execution
}

# ---------------------------------------------------------------------------
# 17b. Firewall - rules (parsed from SYSTEM hive) + firewall logs.
# ---------------------------------------------------------------------------
if (-not (Should-Skip "Firewall")) {
  Invoke-Firewall -SystemHive $systemHive -OutDir $cat.Network
}

# ---------------------------------------------------------------------------
# 17c. SAM - local account inventory decoded from SAM\Domains\Account\Users.
# ---------------------------------------------------------------------------
if (-not (Should-Skip "SAM")) {
  $samHive = Join-Path $configDir "SAM"
  Invoke-SamAccounts -SamHive $samHive -OutDir $cat.Accounts
}

# ---------------------------------------------------------------------------
# 17d. EvtxECmd - parse Windows event logs (.evtx) to consolidated CSV.
# ---------------------------------------------------------------------------
if (-not (Should-Skip "Evtx")) {
  Invoke-Evtx -OutDir $cat.EventLogs
}

# ---------------------------------------------------------------------------
# 18. PCA - Windows 11 22H2+ Program Compatibility Assistant execution artefact
# ---------------------------------------------------------------------------
if (-not (Should-Skip "PCA")) {
  Invoke-PCA -OutDir $cat.Execution
}

# ---------------------------------------------------------------------------
# 19. Email artefacts - copy Outlook/Thunderbird stores (open offline later)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "Email")) {
  Copy-EmailStores -OutDir $cat.Email
}

# ---------------------------------------------------------------------------
# 20. OS / system details summary (plain text)
# ---------------------------------------------------------------------------
if (-not (Should-Skip "OsDetails")) {
  Write-OsDetails -OutFile (Join-Path $cat.SystemInfo "OS_Details.txt")
}

Write-Log "=== DFIR artefact parse finished ==="
Write-Host ""
Write-Host "Done. Categorised output in: $OutputDir"
Write-Host "Logs: $logDir"
