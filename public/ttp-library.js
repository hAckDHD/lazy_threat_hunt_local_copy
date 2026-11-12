// TTP / Behavioral Hunt Template Library
// Loaded inline by server.ts getHTML(). Independent of any specific IOC value —
// these are behavior/technique-based hunt queries (MITRE ATT&CK-mapped), the
// complement to the IOC-value hunting in src/hunting/*.ts.

// ══════════════════ TTP TECHNIQUE DATA ══════════════════

var TTP_TECHNIQUES = [
  {
    id: 'T1218', tactic: 'Defense Evasion', name: 'Signed Binary Proxy Execution (LOLBins)',
    description: 'Adversary abuses a trusted, signed Windows binary (rundll32, regsvr32, mshta, certutil, etc.) to execute malicious code or fetch a payload, evading allow-lists and AV that trust signed binaries.',
    platforms: {
      sigma: "title: LOLBin Proxy Execution - Suspicious Rundll32/Regsvr32/Mshta/Certutil Usage\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith:\n            - '\\rundll32.exe'\n            - '\\regsvr32.exe'\n            - '\\mshta.exe'\n            - '\\certutil.exe'\n    net_cmdline:\n        CommandLine|contains:\n            - 'http://'\n            - 'https://'\n            - '-urlcache'\n            - '-decode'\n    condition: selection and net_cmdline\nlevel: high",
      kql: '// Hunt for LOLBins making network calls or decoding payloads\nDeviceProcessEvents\n| where FileName in~ ("rundll32.exe","regsvr32.exe","mshta.exe","certutil.exe")\n| where ProcessCommandLine has_any ("http://","https://","-urlcache","-decode","javascript:")\n| project TimeGenerated,DeviceName,AccountName,FileName,ProcessCommandLine,InitiatingProcessFileName\n| order by TimeGenerated desc',
      splunk: 'index=* sourcetype=XmlWinEventLog EventCode=1\n  (Image="*\\\\rundll32.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\certutil.exe")\n  (CommandLine="*http*" OR CommandLine="*-urlcache*" OR CommandLine="*-decode*")\n| stats count by _time,Computer,User,Image,CommandLine,ParentImage\n| sort -count',
      elastic: 'process.name:(rundll32.exe OR regsvr32.exe OR mshta.exe OR certutil.exe) AND process.command_line:(*http* OR *urlcache* OR *-decode*)',
    },
  },
  {
    id: 'T1055', tactic: 'Defense Evasion / Privilege Escalation', name: 'Process Injection',
    description: 'Adversary injects code into the address space of another, legitimate process (DLL injection, process hollowing, reflective loading) to evade detection and inherit that process\u2019s permissions.',
    platforms: {
      sigma: "title: Reflective DLL / CLR Injection into Non-.NET Process\nlogsource:\n    category: image_load\n    product: windows\ndetection:\n    selection:\n        ImageLoaded|endswith:\n            - '\\clr.dll'\n            - '\\clrjit.dll'\n    filter:\n        Image|endswith:\n            - '\\devenv.exe'\n            - '\\dotnet.exe'\n            - '\\w3wp.exe'\n    condition: selection and not filter\nlevel: high",
      kql: '// .NET runtime loaded into a process that has no business loading it\nDeviceImageLoadEvents\n| where FileName in~ ("clr.dll","clrjit.dll")\n| where InitiatingProcessFileName !in~ ("devenv.exe","dotnet.exe","w3wp.exe","ServiceHub.VSDetouredHost.exe")\n| project TimeGenerated,DeviceName,InitiatingProcessFileName,InitiatingProcessCommandLine,FileName\n| order by TimeGenerated desc',
      splunk: 'index=* sourcetype=Sysmon EventCode=7 (ImageLoaded="*clr.dll" OR ImageLoaded="*clrjit.dll")\n| search NOT (Image="*devenv.exe" OR Image="*dotnet.exe" OR Image="*w3wp.exe")\n| stats count by _time,Computer,Image,ImageLoaded\n| sort -count',
      elastic: 'event.category:library AND dll.name:(clr.dll OR clrjit.dll) AND NOT process.name:(devenv.exe OR dotnet.exe OR w3wp.exe)',
    },
  },
  {
    id: 'T1021', tactic: 'Lateral Movement', name: 'Remote Services (PsExec / WMI / RDP)',
    description: 'Adversary uses legitimate remote administration tooling (PsExec, WMI, RDP, WinRM) to move between hosts using valid credentials, blending into normal admin activity.',
    platforms: {
      sigma: "title: Lateral Movement - PsExec/WMI Service Creation on Remote Host\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith:\n            - '\\PsExec.exe'\n            - '\\wmic.exe'\n        CommandLine|contains:\n            - '\\\\\\\\'\n    condition: selection\nlevel: medium",
      kql: '// Detect a single account authenticating to many hosts in a short window\nIdentityLogonEvents\n| where LogonType in ("RemoteInteractive","Network")\n| summarize TargetDevices=make_set(DeviceName), LogonCount=count() by AccountName, bin(Timestamp,1h)\n| where array_length(TargetDevices) > 5\n| sort by LogonCount desc',
      splunk: 'index=* sourcetype=WinEventLog EventCode=4624 (Logon_Type=3 OR Logon_Type=10)\n| stats dc(Computer) as unique_hosts, values(Computer) as hosts by Account_Name, Source_Network_Address\n| where unique_hosts > 5\n| sort -unique_hosts',
      elastic: 'event.category:authentication AND event.outcome:success | stats dc(host.name) as unique_hosts by user.name, source.ip | where unique_hosts > 5',
    },
  },
  {
    id: 'T1053', tactic: 'Persistence / Execution', name: 'Scheduled Task / Job',
    description: 'Adversary creates or modifies a scheduled task to establish persistence or execute code on a recurring basis, often disguised with a legitimate-sounding task name.',
    platforms: {
      sigma: "title: Suspicious Scheduled Task Creation via schtasks.exe\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\schtasks.exe'\n        CommandLine|contains: '/create'\n    filter:\n        ParentImage|endswith: '\\msiexec.exe'\n    condition: selection and not filter\nlevel: medium",
      kql: '// New scheduled tasks created outside normal deployment tooling\nDeviceProcessEvents\n| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"\n| where InitiatingProcessFileName !in~ ("msiexec.exe","ccmexec.exe")\n| project TimeGenerated,DeviceName,AccountName,ProcessCommandLine,InitiatingProcessFileName\n| order by TimeGenerated desc',
      splunk: 'index=* sourcetype=WinEventLog EventCode=4698\n| stats count by _time,Computer,Task_Name,Command,Subject_Account_Name\n| sort -count',
      elastic: 'event.category:process AND process.name:schtasks.exe AND process.command_line:*create* AND NOT process.parent.name:(msiexec.exe OR ccmexec.exe)',
    },
  },
  {
    id: 'T1547', tactic: 'Persistence', name: 'Boot or Logon Autostart Execution (Registry Run Keys)',
    description: 'Adversary adds an entry to a Run/RunOnce registry key (or equivalent autostart location) so their payload executes automatically at every logon/boot.',
    platforms: {
      sigma: "title: New Autostart Registry Run Key Entry\nlogsource:\n    category: registry_event\n    product: windows\ndetection:\n    selection:\n        TargetObject|contains:\n            - '\\CurrentVersion\\Run'\n            - '\\CurrentVersion\\RunOnce'\n    condition: selection\nlevel: medium",
      kql: '// New or modified Run-key entries, excluding known software installers\nDeviceRegistryEvents\n| where RegistryKey has_any ("CurrentVersion\\\\Run","CurrentVersion\\\\RunOnce")\n| where ActionType in ("RegistryValueSet","RegistryKeyCreated")\n| project TimeGenerated,DeviceName,RegistryKey,RegistryValueName,RegistryValueData,InitiatingProcessFileName\n| order by TimeGenerated desc',
      splunk: 'index=* sourcetype=WinEventLog EventCode IN (12,13,14) TargetObject="*CurrentVersion\\\\Run*"\n| stats count by _time,Computer,TargetObject,Details,Image\n| sort -count',
      elastic: 'event.category:registry AND registry.key.path:(*CurrentVersion\\\\Run* OR *CurrentVersion\\\\RunOnce*)',
    },
  },
  {
    id: 'T1071', tactic: 'Command and Control', name: 'Application Layer Protocol (C2 Beaconing)',
    description: 'Adversary blends C2 traffic into normal application-layer protocols (HTTPS, DNS). Hallmark is regular-interval outbound connections with low jitter — not a known-bad IOC, a behavioral pattern.',
    platforms: {
      sigma: "title: Potential C2 Beaconing - Regular Interval Outbound Connections\nlogsource:\n    category: network_connection\ndetection:\n    selection:\n        DestinationPort:\n            - 443\n            - 8443\n            - 8080\n    condition: selection\n    timeframe: 15m\n    groupby: SourceIp,DestinationIp\n    condition: selection and count() >= 3\nlevel: medium",
      kql: '// Low time-variance between successive connections = likely automated beacon\nDeviceNetworkEvents\n| where ActionType == "ConnectionSuccess" and RemotePort in (443,8443,8080)\n| summarize ConnTimes=make_set(Timestamp), ConnCount=count() by DeviceName,RemoteIP,bin(Timestamp,15m)\n| where ConnCount between (3 .. 10)\n| sort by ConnCount desc',
      splunk: 'index=* dest_port IN (443 8443 8080)\n| bin _time span=15m\n| stats count as conn_count by _time,src_ip,dest_ip\n| where conn_count >= 3 AND conn_count <= 10\n| eventstats stdev(conn_count) as beacon_score by src_ip,dest_ip\n| where beacon_score < 2',
      elastic: 'event.category:network AND destination.port:(443 OR 8443 OR 8080) | bucket span=15m @timestamp | stats count by source.ip,destination.ip | where count >= 3',
    },
  },
  {
    id: 'T1003', tactic: 'Credential Access', name: 'OS Credential Dumping (LSASS Access)',
    description: 'Adversary accesses LSASS process memory (via Mimikatz-style tooling, comsvcs.dll MiniDump, or living-off-the-land equivalents) to harvest plaintext credentials and hashes.',
    platforms: {
      sigma: "title: LSASS Memory Access - Potential Credential Dumping\nlogsource:\n    category: process_access\n    product: windows\ndetection:\n    selection:\n        TargetImage|endswith: '\\lsass.exe'\n        GrantedAccess:\n            - '0x1010'\n            - '0x1410'\n            - '0x1fffff'\n    filter:\n        SourceImage|endswith:\n            - '\\MsMpEng.exe'\n            - '\\werfault.exe'\n    condition: selection and not filter\nlevel: critical",
      kql: '// Process opening a handle to lsass.exe with high-privilege access rights\nDeviceEvents\n| where ActionType == "OpenProcessApiCall" and TargetProcessFileName =~ "lsass.exe"\n| where InitiatingProcessFileName !in~ ("MsMpEng.exe","werfault.exe")\n| project TimeGenerated,DeviceName,InitiatingProcessFileName,InitiatingProcessAccountName,GrantedAccess\n| order by TimeGenerated desc',
      splunk: 'index=* sourcetype=Sysmon EventCode=10 TargetImage="*lsass.exe"\n| search NOT (SourceImage="*MsMpEng.exe" OR SourceImage="*werfault.exe")\n| stats count by _time,Computer,SourceImage,GrantedAccess,User\n| sort -count',
      elastic: 'event.category:process_access AND process.target.name:lsass.exe AND NOT process.name:(MsMpEng.exe OR werfault.exe)',
    },
  },
  {
    id: 'T1027', tactic: 'Defense Evasion', name: 'Obfuscated Files or Information',
    description: 'Adversary encodes, encrypts, or obfuscates commands and payloads (Base64 PowerShell, AMSI bypass strings, packed binaries) to evade static detection and content inspection.',
    platforms: {
      sigma: "title: Encoded/Obfuscated PowerShell Command Line\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\powershell.exe'\n        CommandLine|contains:\n            - '-enc'\n            - '-EncodedCommand'\n            - 'FromBase64String'\n            - 'amsiutils'\n    condition: selection\nlevel: high",
      kql: '// PowerShell invoked with encoded command or known AMSI-bypass strings\nDeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| where ProcessCommandLine has_any ("-enc","-EncodedCommand","FromBase64String","amsiutils","-noni","-nop")\n| project TimeGenerated,DeviceName,AccountName,ProcessCommandLine,InitiatingProcessFileName\n| order by TimeGenerated desc',
      splunk: 'index=* sourcetype=XmlWinEventLog EventCode=1 Image="*powershell.exe"\n  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*")\n| stats count by _time,Computer,User,CommandLine,ParentImage\n| sort -count',
      elastic: 'process.name:powershell.exe AND process.command_line:(*-enc* OR *EncodedCommand* OR *FromBase64String* OR *amsiutils*)',
    },
  },
  {
    id: 'T1087', tactic: 'Discovery', name: 'Account Discovery',
    description: 'Adversary enumerates local or domain accounts/groups (net user, net group, Get-ADUser, dsquery) to scope privileges and find targets for lateral movement or escalation.',
    platforms: {
      sigma: "title: Account/Group Enumeration Command Execution\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith:\n            - '\\net.exe'\n            - '\\net1.exe'\n            - '\\dsquery.exe'\n        CommandLine|contains:\n            - 'user'\n            - 'group'\n            - '/domain'\n    condition: selection\nlevel: low",
      kql: '// Burst of account/group enumeration commands from a single host\nDeviceProcessEvents\n| where FileName in~ ("net.exe","net1.exe","dsquery.exe")\n| where ProcessCommandLine has_any ("user","group","/domain")\n| summarize EnumCount=count() by DeviceName,AccountName,bin(TimeGenerated,10m)\n| where EnumCount > 5\n| sort by EnumCount desc',
      splunk: 'index=* sourcetype=XmlWinEventLog EventCode=1 (Image="*net.exe" OR Image="*net1.exe" OR Image="*dsquery.exe")\n  (CommandLine="*user*" OR CommandLine="*group*" OR CommandLine="*/domain*")\n| bin _time span=10m\n| stats count as enum_count by _time,Computer,User\n| where enum_count > 5',
      elastic: 'process.name:(net.exe OR net1.exe OR dsquery.exe) AND process.command_line:(*user* OR *group* OR */domain*)',
    },
  },
  {
    id: 'T1048', tactic: 'Exfiltration', name: 'Exfiltration Over Alternative Protocol (DNS Tunneling)',
    description: 'Adversary exfiltrates data encoded into DNS queries (or another non-C2 protocol) to evade egress controls that only inspect HTTP(S)/common ports.',
    platforms: {
      sigma: "title: Potential DNS Tunneling - High-Volume Unique Subdomain Queries\nlogsource:\n    category: dns\ndetection:\n    selection:\n        QueryName|re: '^[a-f0-9]{32,}\\.'\n    condition: selection\n    timeframe: 10m\n    groupby: ClientIp\n    condition: selection and count() > 20\nlevel: medium",
      kql: '// Many unique long/hex-looking subdomain queries from one host = likely tunneling\nDnsEvents\n| extend Label = tostring(split(Name,".")[0])\n| where strlen(Label) >= 32\n| summarize UniqueLabels=dcount(Label), QueryCount=count() by ClientIP,bin(TimeGenerated,10m)\n| where UniqueLabels > 20\n| sort by UniqueLabels desc',
      splunk: 'index=* sourcetype=dns\n| eval label=split(query,".")\n| where len(mvindex(label,0)) >= 32\n| bin _time span=10m\n| stats dc(query) as unique_labels by _time,src\n| where unique_labels > 20',
      elastic: 'event.category:dns | bucket span=10m @timestamp | stats cardinality(dns.question.name) as unique_q by source.ip | where unique_q > 20',
    },
  },
];

// Environments beyond the first four, keyed by technique id and merged into
// each technique below, so the library covers the same list as the Hunt Builder.
var TTP_EXTRA_PLATFORMS = {
  "T1218": {
    "cql": "// LOLBins fetching or decoding a payload\n#event_simpleName=ProcessRollup2\n| in(field=\"FileName\", values=[\"rundll32.exe\", \"regsvr32.exe\", \"mshta.exe\", \"certutil.exe\"], ignoreCase=true)\n| CommandLine=/http|urlcache|-decode|javascript:|scrobj/i\n| groupBy([ComputerName, UserName, FileName], function=[count(as=hits), collect(CommandLine, limit=20)])\n| sort(hits, order=desc)",
    "s1ql": "// LOLBins fetching or decoding a payload\nevent.type = 'Process Creation'\n  and tgt.process.name in:anycase ('rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe')\n  and tgt.process.cmdline matches:anycase ('http|urlcache|-decode|javascript:|scrobj')\n| group hits = count() by endpoint.name, src.process.user, tgt.process.name, tgt.process.cmdline\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:1 AND data.win.eventdata.image:(*\\\\rundll32.exe OR *\\\\regsvr32.exe OR *\\\\mshta.exe OR *\\\\certutil.exe) AND data.win.eventdata.commandLine:(*http* OR *urlcache* OR *-decode* OR *javascript\\:* OR *scrobj*)",
    "tql": "// Trellix EDR real-time search. LOLBins fetching or decoding a payload\nHostInfo hostname and Processes name, cmdline, user, parentname\n  where (Processes name equals \"rundll32.exe\" or Processes name equals \"regsvr32.exe\" or Processes name equals \"mshta.exe\" or Processes name equals \"certutil.exe\")\n  and (Processes cmdline contains \"http\" or Processes cmdline contains \"urlcache\" or Processes cmdline contains \"-decode\" or Processes cmdline contains \"javascript:\" or Processes cmdline contains \"scrobj\")"
  },
  "T1021": {
    "cql": "// Remote execution tooling aimed at another host\n#event_simpleName=ProcessRollup2\n| in(field=\"FileName\", values=[\"psexec.exe\", \"psexec64.exe\", \"wmic.exe\", \"winrs.exe\"], ignoreCase=true)\n| CommandLine=/\\\\\\\\|\\/node:|process call create|-r:/i\n| groupBy([ComputerName, UserName, FileName], function=[count(as=hits), collect(CommandLine, limit=20)])\n| sort(hits, order=desc)",
    "s1ql": "// Remote execution tooling aimed at another host\nevent.type = 'Process Creation'\n  and tgt.process.name in:anycase ('psexec.exe', 'psexec64.exe', 'wmic.exe', 'winrs.exe')\n  and tgt.process.cmdline matches:anycase ('\\\\\\\\|/node:|process call create|-r:')\n| group hits = count() by endpoint.name, src.process.user, tgt.process.name, tgt.process.cmdline\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:1 AND data.win.eventdata.image:(*\\\\psexec.exe OR *\\\\psexec64.exe OR *\\\\wmic.exe OR *\\\\winrs.exe) AND data.win.eventdata.commandLine:(*\\\\* OR *\\/node\\:* OR *process\\ call\\ create* OR *-r\\:*)",
    "tql": "// Trellix EDR real-time search. Remote execution tooling aimed at another host\nHostInfo hostname and Processes name, cmdline, user, parentname\n  where (Processes name equals \"psexec.exe\" or Processes name equals \"psexec64.exe\" or Processes name equals \"wmic.exe\" or Processes name equals \"winrs.exe\")\n  and (Processes cmdline contains \"\\\\\" or Processes cmdline contains \"/node:\" or Processes cmdline contains \"process call create\" or Processes cmdline contains \"-r:\")"
  },
  "T1053": {
    "cql": "// Scheduled task created from the command line\n#event_simpleName=ProcessRollup2\n| in(field=\"FileName\", values=[\"schtasks.exe\"], ignoreCase=true)\n| CommandLine=/\\/create/i\n| groupBy([ComputerName, UserName, FileName], function=[count(as=hits), collect(CommandLine, limit=20)])\n| sort(hits, order=desc)",
    "s1ql": "// Scheduled task created from the command line\nevent.type = 'Process Creation'\n  and tgt.process.name in:anycase ('schtasks.exe')\n  and tgt.process.cmdline matches:anycase ('/create')\n| group hits = count() by endpoint.name, src.process.user, tgt.process.name, tgt.process.cmdline\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:1 AND data.win.eventdata.image:(*\\\\schtasks.exe) AND data.win.eventdata.commandLine:(*\\/create*)",
    "tql": "// Trellix EDR real-time search. Scheduled task created from the command line\nHostInfo hostname and Processes name, cmdline, user, parentname\n  where (Processes name equals \"schtasks.exe\")\n  and (Processes cmdline contains \"/create\")"
  },
  "T1027": {
    "cql": "// Encoded or obfuscated PowerShell\n#event_simpleName=ProcessRollup2\n| in(field=\"FileName\", values=[\"powershell.exe\", \"pwsh.exe\"], ignoreCase=true)\n| CommandLine=/-enc|-encodedcommand|frombase64string|-bxor|char\\]/i\n| groupBy([ComputerName, UserName, FileName], function=[count(as=hits), collect(CommandLine, limit=20)])\n| sort(hits, order=desc)",
    "s1ql": "// Encoded or obfuscated PowerShell\nevent.type = 'Process Creation'\n  and tgt.process.name in:anycase ('powershell.exe', 'pwsh.exe')\n  and tgt.process.cmdline matches:anycase ('-enc|-encodedcommand|frombase64string|-bxor|char\\]')\n| group hits = count() by endpoint.name, src.process.user, tgt.process.name, tgt.process.cmdline\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:1 AND data.win.eventdata.image:(*\\\\powershell.exe OR *\\\\pwsh.exe) AND data.win.eventdata.commandLine:(*-enc* OR *-encodedcommand* OR *frombase64string* OR *-bxor* OR *char]*)",
    "tql": "// Trellix EDR real-time search. Encoded or obfuscated PowerShell\nHostInfo hostname and Processes name, cmdline, user, parentname\n  where (Processes name equals \"powershell.exe\" or Processes name equals \"pwsh.exe\")\n  and (Processes cmdline contains \"-enc\" or Processes cmdline contains \"-encodedcommand\" or Processes cmdline contains \"frombase64string\" or Processes cmdline contains \"-bxor\" or Processes cmdline contains \"char]\")",
    "yara": "rule TTP_T1027_Encoded_PowerShell_Script\n{\n    meta:\n        description = \"Script or shortcut carrying an encoded PowerShell command\"\n        technique = \"T1027\"\n    strings:\n        $p = \"powershell\" ascii wide nocase\n        $e1 = \" -enc \" ascii wide nocase\n        $e2 = \"-EncodedCommand\" ascii wide nocase\n        $e3 = \"FromBase64String(\" ascii wide nocase\n        $b1 = \"SQBFAFgA\" ascii wide\n        $b2 = \"JABzAD0A\" ascii wide\n        $b3 = \"aQBlAHgA\" ascii wide\n    condition:\n        filesize < 2MB and $p and (any of ($e*)) and (any of ($b*) or #e3 > 1)\n}"
  },
  "T1087": {
    "cql": "// Account and group discovery commands\n#event_simpleName=ProcessRollup2\n| in(field=\"FileName\", values=[\"net.exe\", \"net1.exe\", \"whoami.exe\", \"nltest.exe\", \"dsquery.exe\"], ignoreCase=true)\n| CommandLine=/user|group|\\/all|\\/domain|domain_trusts|localgroup/i\n| groupBy([ComputerName, UserName, FileName], function=[count(as=hits), collect(CommandLine, limit=20)])\n| sort(hits, order=desc)",
    "s1ql": "// Account and group discovery commands\nevent.type = 'Process Creation'\n  and tgt.process.name in:anycase ('net.exe', 'net1.exe', 'whoami.exe', 'nltest.exe', 'dsquery.exe')\n  and tgt.process.cmdline matches:anycase ('user|group|/all|/domain|domain_trusts|localgroup')\n| group hits = count() by endpoint.name, src.process.user, tgt.process.name, tgt.process.cmdline\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:1 AND data.win.eventdata.image:(*\\\\net.exe OR *\\\\net1.exe OR *\\\\whoami.exe OR *\\\\nltest.exe OR *\\\\dsquery.exe) AND data.win.eventdata.commandLine:(*user* OR *group* OR *\\/all* OR *\\/domain* OR *domain_trusts* OR *localgroup*)",
    "tql": "// Trellix EDR real-time search. Account and group discovery commands\nHostInfo hostname and Processes name, cmdline, user, parentname\n  where (Processes name equals \"net.exe\" or Processes name equals \"net1.exe\" or Processes name equals \"whoami.exe\" or Processes name equals \"nltest.exe\" or Processes name equals \"dsquery.exe\")\n  and (Processes cmdline contains \"user\" or Processes cmdline contains \"group\" or Processes cmdline contains \"/all\" or Processes cmdline contains \"/domain\" or Processes cmdline contains \"domain_trusts\" or Processes cmdline contains \"localgroup\")"
  },
  "T1055": {
    "cql": "// .NET runtime loaded into a process that should not host it\n#event_simpleName=ClassifiedModuleLoad\n| ImageFileName=/\\\\(clr|clrjit)\\.dll$/i\n| TargetImageFileName!=/\\\\(devenv|dotnet|w3wp|powershell|msbuild)\\.exe$/i\n| groupBy([ComputerName, TargetImageFileName], function=[count(as=hits)])\n| sort(hits, order=desc)",
    "s1ql": "// .NET runtime loaded into a process that should not host it\nevent.type = 'Module Load'\n  and module.path matches:anycase ('\\\\\\\\(clr|clrjit)\\\\.dll$')\n  and not (src.process.name in:anycase ('devenv.exe','dotnet.exe','w3wp.exe','powershell.exe','msbuild.exe'))\n| group hits = count() by endpoint.name, src.process.name, module.path\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:7 AND data.win.eventdata.imageLoaded:(*\\\\clr.dll OR *\\\\clrjit.dll) AND NOT data.win.eventdata.image:(*\\\\devenv.exe OR *\\\\dotnet.exe OR *\\\\w3wp.exe OR *\\\\powershell.exe)",
    "yara": "rule TTP_T1055_Process_Injection_API_Set\n{\n    meta:\n        description = \"PE that imports the classic remote-injection API set\"\n        technique = \"T1055\"\n    strings:\n        $a1 = \"VirtualAllocEx\" ascii wide\n        $a2 = \"WriteProcessMemory\" ascii wide\n        $a3 = \"CreateRemoteThread\" ascii wide\n        $a4 = \"NtCreateThreadEx\" ascii wide\n        $a5 = \"QueueUserAPC\" ascii wide\n    condition:\n        uint16(0) == 0x5A4D and $a1 and $a2 and any of ($a3, $a4, $a5)\n}"
  },
  "T1547": {
    "cql": "// New value under a Run / RunOnce autostart key\n#event_simpleName=AsepValueUpdate\n| RegObjectName=/\\\\CurrentVersion\\\\Run(Once)?$/i\n| groupBy([ComputerName, RegObjectName, RegValueName, RegStringValue], function=[count(as=hits)])\n| sort(hits, order=desc)",
    "s1ql": "// New value under a Run / RunOnce autostart key\nevent.type in ('Registry Value Create', 'Registry Value Modified')\n  and registry.keyPath matches:anycase ('\\\\\\\\CurrentVersion\\\\\\\\Run(Once)?\\\\\\\\')\n| group hits = count() by endpoint.name, src.process.name, registry.keyPath, registry.value\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:13 AND data.win.eventdata.targetObject:(*\\\\CurrentVersion\\\\Run\\\\* OR *\\\\CurrentVersion\\\\RunOnce\\\\*)",
    "tql": "// Trellix EDR real-time search. Values under the Run keys\nHostInfo hostname and WinRegistry keypath, keyvalue, value\n  where WinRegistry keypath contains \"CurrentVersion\\\\Run\""
  },
  "T1071": {
    "cql": "// Regular outbound connections from one process to one address (beaconing)\n#event_simpleName=NetworkConnectIP4\n| RemotePort=/^(80|443|8080|8443)$/\n| !cidr(RemoteAddressIP4, subnet=[\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\", \"127.0.0.0/8\"])\n| groupBy([ComputerName, ContextBaseFileName, RemoteAddressIP4], function=[count(as=connections), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])\n| connections > 100\n| sort(connections, order=desc)",
    "s1ql": "// Regular outbound connections from one process to one address (beaconing)\nevent.type = 'IP Connect' and event.network.direction = 'OUTGOING'\n  and dst.port.number in (80, 443, 8080, 8443)\n| group connections = count(), first_seen = min(event.time), last_seen = max(event.time) by endpoint.name, src.process.name, dst.ip.address\n| filter connections > 100\n| sort -connections",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:3 AND data.win.eventdata.initiated:true AND data.win.eventdata.destinationPort:(80 OR 443 OR 8080 OR 8443) AND NOT data.win.eventdata.destinationIp:(10.* OR 192.168.* OR 127.*)",
    "tql": "// Trellix EDR real-time search. Processes holding outbound web connections\nHostInfo hostname and NetworkFlow process, dst_ip, dst_port, direction\n  where NetworkFlow direction equals \"out\"\n  and (NetworkFlow dst_port equals 443 or NetworkFlow dst_port equals 80 or NetworkFlow dst_port equals 8443)"
  },
  "T1003": {
    "cql": "// Command lines that dump or read LSASS memory\n#event_simpleName=ProcessRollup2\n| CommandLine=/comsvcs.*MiniDump|procdump.*lsass|sekurlsa|lsass\\.dmp|rundll32.*lsass/i\n| groupBy([ComputerName, UserName, FileName], function=[count(as=hits), collect(CommandLine, limit=20)])\n| sort(hits, order=desc)",
    "s1ql": "// A process opening a handle to LSASS\nevent.type = 'Open Remote Process Handle'\n  and tgt.process.name = 'lsass.exe'\n  and not (src.process.name in:anycase ('MsMpEng.exe','csrss.exe','wininit.exe','services.exe','svchost.exe'))\n| group hits = count() by endpoint.name, src.process.name, src.process.cmdline\n| sort -hits",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:10 AND data.win.eventdata.targetImage:*\\\\lsass.exe AND NOT data.win.eventdata.sourceImage:(*\\\\MsMpEng.exe OR *\\\\csrss.exe OR *\\\\wininit.exe OR *\\\\svchost.exe)",
    "tql": "// Trellix EDR real-time search. Command lines that dump LSASS\nHostInfo hostname and Processes name, cmdline, user, parentname\n  where Processes cmdline contains \"lsass\"\n  and (Processes cmdline contains \"MiniDump\" or Processes cmdline contains \"procdump\" or Processes cmdline contains \"sekurlsa\")",
    "yara": "rule TTP_T1003_Credential_Dumper_Strings\n{\n    meta:\n        description = \"Strings typical of LSASS credential dumpers\"\n        technique = \"T1003\"\n    strings:\n        $s1 = \"sekurlsa::logonpasswords\" ascii wide nocase\n        $s2 = \"lsadump::\" ascii wide nocase\n        $s3 = \"SamIConnect\" ascii wide\n        $s4 = \"MiniDumpWriteDump\" ascii wide\n        $s5 = \"lsass.exe\" ascii wide nocase\n    condition:\n        any of ($s1, $s2) or ($s3 and $s5) or (uint16(0) == 0x5A4D and $s4 and $s5)\n}"
  },
  "T1048": {
    "cql": "// Many long, unique sub-domain labels from one host (DNS tunnelling)\n#event_simpleName=DnsRequest\n| DomainName=/^(?<label>[^.]+)\\./\n| length(\"label\", as=label_len)\n| label_len >= 32\n| groupBy([ComputerName], function=[count(DomainName, distinct=true, as=unique_names)])\n| unique_names > 20\n| sort(unique_names, order=desc)",
    "s1ql": "// Many long, unique sub-domain labels from one host (DNS tunnelling)\nevent.type = 'DNS Resolved'\n  and event.dns.request matches '^[^.]{32,}\\\\.'\n| group unique_names = estimate_distinct(event.dns.request) by endpoint.name, src.process.name\n| filter unique_names > 20\n| sort -unique_names",
    "wazuh": "data.win.system.channel:\"Microsoft-Windows-Sysmon/Operational\" AND data.win.system.eventID:22 AND data.win.eventdata.queryName:/[^.]{32,}\\..*/",
    "tql": "// Trellix EDR real-time search. Long host names in the DNS cache\nHostInfo hostname and DNSCache hostname, ipaddress\n  where DNSCache hostname matches \"^[^.]{32,}\\\\.\""
  }
};
for (var ti = 0; ti < TTP_TECHNIQUES.length; ti++) {
  var extra = TTP_EXTRA_PLATFORMS[TTP_TECHNIQUES[ti].id] || {};
  for (var key in extra) TTP_TECHNIQUES[ti].platforms[key] = extra[key];
}

// Filter order and labels; same order as the Hunt Builder's environment list.
var TTP_PLATFORMS = [["splunk", "Splunk SPL"], ["kql", "Sentinel/Defender KQL"], ["cql", "CrowdStrike CQL"], ["s1ql", "SentinelOne S1QL"], ["wazuh", "Wazuh"], ["elastic", "Elastic DSL"], ["tql", "Trellix"], ["sigma", "Sigma"], ["yara", "YARA"]];

// ══════════════════ THREAT ACTOR DATA ══════════════════
// Public, general TTP associations (MITRE ATT&CK Groups-style reference) —
// not exhaustive, meant as a starting point for hypothesis building.

var THREAT_ACTORS = [
  {
    id: 'apt29', name: 'APT29 (Cozy Bear / The Dukes)', aliases: ['Cozy Bear', 'The Dukes', 'Midnight Blizzard'],
    description: 'Russia-attributed, SVR-linked. Known for patient, stealthy operations: living-off-the-land, process injection, credential theft, and custom low-and-slow C2 rather than loud malware.',
    techniqueIds: ['T1218', 'T1055', 'T1003', 'T1071', 'T1027'],
  },
  {
    id: 'fin7', name: 'FIN7', aliases: ['Carbon Spider'],
    description: 'Financially motivated, historically targeting retail/hospitality POS systems. Heavy LOLBin use, scheduled-task persistence, and lateral movement via legitimate admin tooling.',
    techniqueIds: ['T1218', 'T1053', 'T1021', 'T1071', 'T1027'],
  },
  {
    id: 'lazarus', name: 'Lazarus Group', aliases: ['Hidden Cobra', 'APT38'],
    description: 'North Korea-attributed. Mixes destructive and financially-motivated operations: process injection, LSASS credential dumping, registry-based persistence, DNS-based C2.',
    techniqueIds: ['T1055', 'T1003', 'T1547', 'T1071', 'T1048'],
  },
  {
    id: 'scattered_spider', name: 'Scattered Spider', aliases: ['UNC3944', 'Muddled Libra'],
    description: 'Social-engineering/help-desk focused initial access, then heavy account/group discovery and lateral movement using legitimate remote-admin tools (RDP, RMM) rather than custom malware.',
    techniqueIds: ['T1087', 'T1021', 'T1053', 'T1027'],
  },
  {
    id: 'volt_typhoon', name: 'Volt Typhoon', aliases: ['Vanguard Panda'],
    description: 'China-attributed, focused on critical infrastructure. Almost entirely living-off-the-land — minimal custom malware, extensive LOLBin use, discovery, and persistence via legitimate accounts/scheduled tasks.',
    techniqueIds: ['T1218', 'T1087', 'T1053', 'T1027'],
  },
];

function ttpTechniqueById(id) {
  for (var i = 0; i < TTP_TECHNIQUES.length; i++) if (TTP_TECHNIQUES[i].id === id) return TTP_TECHNIQUES[i];
  return null;
}
function ttpActorById(id) {
  for (var i = 0; i < THREAT_ACTORS.length; i++) if (THREAT_ACTORS[i].id === id) return THREAT_ACTORS[i];
  return null;
}
function ttpActorsForTechnique(techId) {
  var out = [];
  for (var i = 0; i < THREAT_ACTORS.length; i++) {
    if (THREAT_ACTORS[i].techniqueIds.indexOf(techId) !== -1) out.push(THREAT_ACTORS[i]);
  }
  return out;
}

// ══════════════════ RENDERING ══════════════════

// Multi-select, same as the actor filter below — a checkbox per platform,
// OR semantics (checked = shown). All 4 checked by default == previously
// the "All" sentinel value; no separate all/none state to track.
function selectedTTPPlatforms() {
  var boxes = document.querySelectorAll('#ttpPlatformFilterGroup input:checked');
  var ids = [];
  for (var i = 0; i < boxes.length; i++) ids.push(boxes[i].value);
  return ids;
}

function filterTTPLibrary() { renderTTPLibrary(); }
function loadTTPLibrary() {
  // Dropdown: "All actors" or exactly one — not multi-select.
  var sel = document.getElementById('ttpActorFilter');
  if (sel && !sel.dataset.filled) {
    var html = '<option value="">All actors</option>';
    for (var i = 0; i < THREAT_ACTORS.length; i++) html += '<option value="' + escHtml(THREAT_ACTORS[i].id) + '">' + escHtml(THREAT_ACTORS[i].name) + '</option>';
    sel.innerHTML = html;
    sel.dataset.filled = '1';
  }
  renderTTPLibrary();
}

function selectedTTPActorIds() {
  var sel = document.getElementById('ttpActorFilter');
  var val = sel ? sel.value : '';
  return val ? [val] : [];
}

// Jump here from a Hypothesis Builder suggestion chip — pre-filters to one technique.
function jumpToTechnique(techId) {
  showTab('ttp');
  var search = document.getElementById('ttpSearch');
  if (search) search.value = techId;
  var sel = document.getElementById('ttpActorFilter');
  if (sel) sel.value = '';
  renderTTPLibrary();
}

function renderTTPLibrary() {
  var search = ((document.getElementById('ttpSearch') || {}).value || '').toLowerCase();
  var selectedActorIds = selectedTTPActorIds();
  var filtered = [];
  for (var i = 0; i < TTP_TECHNIQUES.length; i++) {
    var t = TTP_TECHNIQUES[i];
    if (selectedActorIds.length) {
      var matchesAny = false;
      for (var j = 0; j < selectedActorIds.length; j++) {
        var a2 = ttpActorById(selectedActorIds[j]);
        if (a2 && a2.techniqueIds.indexOf(t.id) !== -1) { matchesAny = true; break; }
      }
      if (!matchesAny) continue;
    }
    if (search && t.id.toLowerCase().indexOf(search) === -1 && t.name.toLowerCase().indexOf(search) === -1 &&
        t.tactic.toLowerCase().indexOf(search) === -1 && t.description.toLowerCase().indexOf(search) === -1) continue;
    filtered.push(t);
  }
  var div = document.getElementById('ttpResults');
  if (!div) return;
  if (!filtered.length) { div.innerHTML = '<div class="loading">No techniques match your filter.</div>'; return; }
  var selectedPlatforms = selectedTTPPlatforms();
  var html = '';
  for (var i = 0; i < filtered.length; i++) {
    var t = filtered[i];
    var sections = '';
    for (var p = 0; p < TTP_PLATFORMS.length; p++) {
      var code = t.platforms[TTP_PLATFORMS[p][0]];
      if (code && selectedPlatforms.indexOf(TTP_PLATFORMS[p][0]) !== -1) sections += makeQBlock(TTP_PLATFORMS[p][1], code);
    }
    var actors = ttpActorsForTechnique(t.id);
    var actorChips = '';
    for (var j = 0; j < actors.length; j++) {
      actorChips += '<span class="badge type" title="' + escHtml(actors[j].description) + '" style="margin-right:4px;">' + escHtml(actors[j].name) + '</span>';
    }
    html += '<div class="panel" style="margin-bottom:12px;">' +
      '<div class="panel-header" style="display:flex;align-items:center;gap:8px;">' +
      '<span style="font-family:monospace;color:var(--accent);font-weight:700;">' + escHtml(t.id) + '</span>' +
      '<span style="flex:1;">' + escHtml(t.name) + '</span>' +
      '<span style="font-size:10px;color:var(--text2);font-weight:400;">' + escHtml(t.tactic) + '</span></div>' +
      '<div class="panel-body">' +
      '<div style="font-size:12px;color:var(--text);margin-bottom:8px;">' + escHtml(t.description) + '</div>' +
      (actorChips ? '<div style="margin-bottom:10px;">' +
        '<div style="font-size:10px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;">Associated with</div>' +
        actorChips + '</div>' : '') +
      sections +
      '</div></div>';
  }
  div.innerHTML = html;
}
