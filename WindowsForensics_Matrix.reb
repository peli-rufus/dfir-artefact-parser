Description: Windows Forensics Artefact Matrix
Author: Peli Rufus
Version: 1.0
Id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Keys:

# ====================
# SYSTEM INFO
# ====================

    -
        Description: OS Version
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        Recursive: false
        Comment: "ProductName, CurrentBuild, ReleaseId, UBR. Critical for selecting correct artefact paths and interpreting schema differences."

    -
        Description: Computer Name
        HiveType: SYSTEM
        Category: System Info
        KeyPath: CurrentControlSet\Control\ComputerName\ComputerName
        Recursive: false
        Comment: "Confirms machine identity. First step in any investigation."

    -
        Description: CurrentControlSet Resolver
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        Recursive: false
        Comment: "Current value identifies which ControlSet was active at boot. Resolve before querying offline hives."

    -
        Description: Time Zone
        HiveType: SYSTEM
        Category: System Info
        KeyPath: CurrentControlSet\Control\TimeZoneInformation
        Recursive: false
        Comment: "Essential for timeline normalisation. Some artefacts use local time, others UTC."

    -
        Description: Network Interfaces
        HiveType: SYSTEM
        Category: System Info
        KeyPath: CurrentControlSet\Services\Tcpip\Parameters\Interfaces
        Recursive: true
        Comment: "IP config, DHCP, DNS per interface. Confirms machine identity and network context."

    -
        Description: LanmanServer Shares
        HiveType: SYSTEM
        Category: System Info
        KeyPath: CurrentControlSet\Services\LanmanServer\Shares
        Recursive: false
        Comment: "Active SMB shares hosted by this machine. Reveals exposed data and network attack surface."

    -
        Description: Firewall Rules
        HiveType: SYSTEM
        Category: System Info
        KeyPath: CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
        Recursive: false
        Comment: "Attacker-added allow rules for C2 ports are high-fidelity IOC. Review all non-default rules."

    -
        Description: ProfileList - SID to Username Mapping
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList
        Recursive: true
        Comment: "Maps SIDs to usernames and profile paths. Essential for attributing per-user artefacts to account names."

    -
        Description: Session Manager BootExecute
        HiveType: SYSTEM
        Category: System Info
        KeyPath: CurrentControlSet\Control\Session Manager
        Recursive: false
        Comment: "BootExecute value other than 'autocheck autochk *' is suspicious."

# ====================
# EVIDENCE OF EXECUTION
# ====================

    -
        Description: UserAssist
        HiveType: NTUSER
        Category: Evidence of Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
        Recursive: true
        Comment: "GUI execution evidence only. ROT13-encoded subkeys decoded by Registry Explorer. Run count + last execution timestamp per binary. CLI executions not recorded."

    -
        Description: RecentApps
        HiveType: NTUSER
        Category: Evidence of Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentApps
        Recursive: true
        Comment: "Win10+ only. AppLaunched subkey proves shell execution. AppSwitched proves user interaction. AppLaunched with no AppSwitched = automated/background execution (service, scheduled task, C2)."

    -
        Description: MuiCache (Vista+)
        HiveType: USRCLASS
        Category: Evidence of Execution
        KeyPath: Local Settings\Software\Microsoft\Windows\Shell\MuiCache
        Recursive: false
        Comment: "Explorer-launched binaries only. No per-entry timestamps. Blank or @ PE description = no resource section (suspicious). Entry survives binary deletion."

    -
        Description: MuiCache (XP - NTUSER)
        HiveType: NTUSER
        Category: Evidence of Execution
        KeyPath: Software\Microsoft\Windows\ShellNoRoam\MUICache
        Recursive: false
        Comment: "Legacy XP path. Same forensic value as Vista+ variant."

    -
        Description: BAM - Background Activity Moderator
        HiveType: SYSTEM
        Category: Evidence of Execution
        KeyPath: CurrentControlSet\Services\bam\State\UserSettings
        Recursive: true
        Comment: "Per-SID last execution time per binary. Strong execution evidence. Resets on some Windows updates. Covers background and foreground processes."

    -
        Description: DAM - Desktop Activity Moderator
        HiveType: SYSTEM
        Category: Evidence of Execution
        KeyPath: CurrentControlSet\Services\dam\State\UserSettings
        Recursive: true
        Comment: "Desktop app variant of BAM. Same forensic value and structure."

    -
        Description: ShimCache (AppCompatCache)
        HiveType: SYSTEM
        Category: Evidence of Execution
        KeyPath: CurrentControlSet\Control\Session Manager\AppCompatCache
        Recursive: false
        Comment: "Presence evidence only on Win10+. Executed flag unreliable. Must correlate with Prefetch or BAM to claim execution. Parse binary blob with AppCompatCacheParser."

    -
        Description: PrefetchParameters - Prefetch Enabled State
        HiveType: SYSTEM
        Category: Evidence of Execution
        KeyPath: CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
        Recursive: false
        Comment: "EnablePrefetcher: 0=disabled (suspicious on workstation), 3=enabled. Key LastWrite shows when it was changed."

    -
        Description: PcaAppLaunchDic - Win11 22H2+
        HiveType: SYSTEM
        Category: Evidence of Execution
        KeyPath: CurrentControlSet\Control\AppCompatFlags\Compatibility Assistant\Store
        Recursive: false
        Comment: 'Win11 22H2+ execution evidence. Correlate with PcaAppLaunchDic.txt at C:\Windows\appcompat\pca\.'

# ====================
# FILE & FOLDER ACTIVITY
# ====================

    -
        Description: RecentDocs
        HiveType: NTUSER
        Category: File and Folder Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        Recursive: true
        Comment: "MRU-ordered recently opened files per extension subkey. Filename only - no full path. Correlate with LNK files for full path reconstruction."

    -
        Description: ComDlg32 CIDSizeMRU
        HiveType: NTUSER
        Category: File and Folder Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU
        Recursive: false
        Comment: "Recently launched applications globally via open/save dialog. Does not prove execution alone."

    -
        Description: ComDlg32 LastVisitedPidlMRU
        HiveType: NTUSER
        Category: File and Folder Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: false
        Comment: "Executable + last directory used per application. Reveals which app accessed which directory via dialog."

    -
        Description: ComDlg32 OpenSavePidlMRU
        HiveType: NTUSER
        Category: File and Folder Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
        Recursive: true
        Comment: "Full paths of files opened/saved per extension. High value for data theft investigations."

    -
        Description: WordWheelQuery - Explorer Search Terms
        HiveType: NTUSER
        Category: File and Folder Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
        Recursive: false
        Comment: "Windows Explorer search terms. Binary encoded MRU. Key LastWrite only for timestamp. High value in insider threat and data theft cases."

    -
        Description: Office MRU - Recently Opened Documents
        HiveType: NTUSER
        Category: File and Folder Activity
        KeyPath: Software\Microsoft\Office
        Recursive: true
        Comment: "Recently opened Office documents. Full path per entry. Version-specific subkey path. O365 uses LiveID subkey path."

    -
        Description: Shell Folders
        HiveType: SOFTWARE
        Category: File and Folder Activity
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
        Recursive: false
        Comment: "Startup folder path resolution. Correlate with physical files dropped in startup directories."

    -
        Description: User Shell Folders
        HiveType: SOFTWARE
        Category: File and Folder Activity
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
        Recursive: false
        Comment: "Per-user startup folder path. Redirected startup folder = persistence or data staging indicator."

# ====================
# USB & EXTERNAL DEVICES
# ====================

    -
        Description: USBSTOR - Mass Storage Devices
        HiveType: SYSTEM
        Category: USB and External Devices
        KeyPath: CurrentControlSet\Enum\USBSTOR
        Recursive: true
        Comment: "Mass storage USB devices. Vendor/product/serial. Timestamps via {83da6326} property key: 0064=first connect, 0066=last connect, 0067=last removal."

    -
        Description: USB - All Device Classes
        HiveType: SYSTEM
        Category: USB and External Devices
        KeyPath: CurrentControlSet\Enum\USB
        Recursive: true
        Comment: "All USB device classes including keyboards, cameras, dongles. VID/PID identification. Broader scope than USBSTOR."

    -
        Description: MountedDevices
        HiveType: SYSTEM
        Category: USB and External Devices
        KeyPath: MountedDevices
        Recursive: false
        Comment: "Drive letter to volume signature mapping. Essential for exfiltration path reconstruction and LNK volume serial correlation."

    -
        Description: MountPoints2 - Per-User Device Attribution
        HiveType: NTUSER
        Category: USB and External Devices
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        Recursive: true
        Comment: "Per-user USB and network share interaction. Critical attribution artefact - proves which user account interacted with the device."

# ====================
# NETWORK
# ====================

    -
        Description: NetworkList - Managed Networks
        HiveType: SOFTWARE
        Category: Network
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
        Recursive: true
        Comment: "Domain-joined networks. SSID, GUID, first/last connected timestamps via key LastWrite."

    -
        Description: NetworkList - Unmanaged Networks
        HiveType: SOFTWARE
        Category: Network
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
        Recursive: true
        Comment: "Public/home networks. Unmanaged = non-domain network connection."

    -
        Description: NetworkList - NLA Cache
        HiveType: SOFTWARE
        Category: Network
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache
        Recursive: true
        Comment: "Network location awareness cache. Supplements Signatures keys."

    -
        Description: RDP MRU - tsclient Default
        HiveType: NTUSER
        Category: Network
        KeyPath: Software\Microsoft\Terminal Server Client\Default
        Recursive: false
        Comment: "RDP target hostnames/IPs. Key LastWrite = last RDP connection time. Combine with Event ID 1149 for server-side confirmation."

    -
        Description: RDP MRU - tsclient Servers
        HiveType: NTUSER
        Category: Network
        KeyPath: Software\Microsoft\Terminal Server Client\Servers
        Recursive: true
        Comment: "Per-server subkeys with UsernameHint (account attribution) and CertHash (endpoint verification)."

    -
        Description: PuTTY SSH Host Keys
        HiveType: NTUSER
        Category: Network
        KeyPath: Software\SimonTatham\PuTTY\SshHostKeys
        Recursive: false
        Comment: "SSH server fingerprints from PuTTY/FileZilla connections. Key LastWrite per host."

# ====================
# PERSISTENCE
# ====================

    -
        Description: HKCU Run Key
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: "User-level persistence. No admin rights required. Very common malware location. Key LastWrite = when entry was added."

    -
        Description: HKCU RunOnce Key
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: "Entry deleted after first execution. May be absent at collection time. Check RegBack hive backups."

    -
        Description: HKLM Run Key
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: "System-wide persistence. Admin rights required. Key LastWrite timestamp."

    -
        Description: HKLM RunOnce Key
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: "System-wide, deleted after first run. Check RegBack hive backups."

    -
        Description: Services
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: CurrentControlSet\Services
        Recursive: true
        Comment: "ImagePath = executable. ServiceDll in Parameters subkey for svchost-hosted services. Start: 0x00/0x01=kernel driver, 0x02=auto, 0x03=manual. Key LastWrite = creation/modification time."

    -
        Description: Winlogon - HKLM
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        Recursive: false
        Comment: "Userinit and Shell values. Default Userinit=userinit.exe, (trailing comma normal). Any addition after comma is malicious."

    -
        Description: Winlogon - HKCU
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Winlogon
        Recursive: false
        Comment: "User-level Winlogon hijacking. No admin rights required. Same forensic logic as HKLM variant."

    -
        Description: IFEO - Image File Execution Options
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows NT\CurrentVersion\Image File Execution Options
        Recursive: true
        Comment: "Debugger value replaces named process with attacker binary. Common targets: sethc.exe, osk.exe, magnify.exe, utilman.exe (all launchable from locked screen)."

    -
        Description: SilentProcessExit
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows NT\CurrentVersion\SilentProcessExit
        Recursive: true
        Comment: "Alternate IFEO persistence via ReportingMode + MonitorProcess values."

    -
        Description: AppInit_DLLs
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: AppInit_DLLs
        Recursive: false
        Comment: "DLLs injected into every process loading user32.dll. Deprecated/blocked with Secure Boot on Win8+. High signal if populated on modern system."

    -
        Description: LSA Authentication Packages
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: CurrentControlSet\Control\Lsa
        Recursive: false
        Comment: "Authentication Packages and Security Packages values. Malicious DLLs registered here load into lsass.exe at boot."

    -
        Description: Security Providers
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: CurrentControlSet\Control\SecurityProviders
        Recursive: false
        Comment: "SSP/AP DLL registration loaded by lsass.exe. Attacker-added DLLs = credential interception capability."

    -
        Description: Print Monitors
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: CurrentControlSet\Control\Print\Monitors
        Recursive: true
        Comment: "DLL loaded by spoolsv.exe in SYSTEM context. Print monitor DLL hijacking persistence."

    -
        Description: TaskCache Tasks
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        Recursive: true
        Comment: 'Registry-side scheduled task records. Survives XML deletion. Hash, last run time, triggers. Correlate with XML files in C:\Windows\System32\Tasks\.'

    -
        Description: TaskCache Tree
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
        Recursive: true
        Comment: "Task name hierarchy. Key LastWrite = task creation time. Always check both TaskCache and XML."

    -
        Description: WBEM Configuration
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\WBEM
        Recursive: false
        Comment: 'WMI service settings. WMI subscription persistence stored in repository at System32\wbem\Repository\ - use Velociraptor Windows.Persistence.PermanentWMIEvents for repository analysis.'

# ====================
# ACCOUNTS & CREDENTIALS
# ====================

    -
        Description: SAM User Accounts
        HiveType: SAM
        Category: Accounts and Credentials
        KeyPath: Domains\Account\Users
        Recursive: true
        Comment: "Username, RID, login count, last login, last failed login, last password change. Requires SYSTEM hive for hash decryption."

    -
        Description: SAM Builtin Groups
        HiveType: SAM
        Category: Accounts and Credentials
        KeyPath: Domains\Builtin\Aliases
        Recursive: true
        Comment: "Local group membership. Identifies which accounts hold admin/privileged group membership."

    -
        Description: LSA Bootkey JD
        HiveType: SYSTEM
        Category: Accounts and Credentials
        KeyPath: CurrentControlSet\Control\Lsa\JD
        Recursive: false
        Comment: "Bootkey component 1 of 4. Required with SYSTEM hive to decrypt SAM hashes offline."

    -
        Description: LSA Bootkey Skew1
        HiveType: SYSTEM
        Category: Accounts and Credentials
        KeyPath: CurrentControlSet\Control\Lsa\Skew1
        Recursive: false
        Comment: "Bootkey component 2 of 4."

    -
        Description: LSA Bootkey GBG
        HiveType: SYSTEM
        Category: Accounts and Credentials
        KeyPath: CurrentControlSet\Control\Lsa\GBG
        Recursive: false
        Comment: "Bootkey component 3 of 4."

    -
        Description: LSA Bootkey Data
        HiveType: SYSTEM
        Category: Accounts and Credentials
        KeyPath: CurrentControlSet\Control\Lsa\Data
        Recursive: false
        Comment: "Bootkey component 4 of 4. All four components needed for offline SAM decryption."

    -
        Description: Windows Credential Manager
        HiveType: NTUSER
        Category: Accounts and Credentials
        KeyPath: Software\Microsoft\Credentials
        Recursive: true
        Comment: 'Saved credential references. Actual blobs in %APPDATA%\Microsoft\Credentials\. Encrypted with DPAPI.'

# ====================
# CLOUD STORAGE
# ====================

    -
        Description: OneDrive Personal Account
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\Microsoft\OneDrive\Accounts\Personal
        Recursive: true
        Comment: "Linked account email, tenant ID, sync folder path. SPOResourceID links to SharePoint instance."

    -
        Description: OneDrive Business Account
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\Microsoft\OneDrive\Accounts\Business1
        Recursive: true
        Comment: "Corporate tenant linkage. Shared folders under Tenants subkey. High value in corporate data exfiltration cases."

    -
        Description: Dropbox Encrypted Key
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\Dropbox\ks\client
        Recursive: false
        Comment: "DPAPI-derived key for filecache.db decryption. host_id can authenticate to Dropbox API if not revoked."

# ====================
# BITS
# ====================

    -
        Description: BITS Service Configuration
        HiveType: SYSTEM
        Category: BITS
        KeyPath: CurrentControlSet\Services\BITS
        Recursive: false
        Comment: "ImagePath, Start value, failure actions. Confirms BITS service state. Correlate with qmgr.db and BITS Operational event log. MITRE ATT&CK T1197."

