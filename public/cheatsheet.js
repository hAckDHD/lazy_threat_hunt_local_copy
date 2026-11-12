// Cheat Sheet & Detection Engineering tab logic
// Loaded inline by server.ts getHTML()

// ══════════════════ CHEAT SHEET DATA ══════════════════

var CHEAT_SHEET = [
  {
    id:"ip", icon:"🌐", title:"IP Address / Network IOC",
    desc:"Hunt for known-malicious IPs across network logs, firewall, proxy, and DNS",
    kql:'// Hunt for malicious IP across all network tables\nlet ioc_ips = dynamic(["1.2.3.4","5.6.7.8"]);\nunion\n  (DeviceNetworkEvents\n    | where RemoteIP in (ioc_ips) or LocalIP in (ioc_ips)\n    | project TimeGenerated,DeviceName,LocalIP,RemoteIP,RemotePort,InitiatingProcessFileName,ActionType),\n  (CommonSecurityLog\n    | where SourceIP in (ioc_ips) or DestinationIP in (ioc_ips)\n    | project TimeGenerated,DeviceVendor,SourceIP,DestinationIP,DestinationPort,Activity),\n  (SigninLogs\n    | where IPAddress in (ioc_ips)\n    | project TimeGenerated,UserPrincipalName,IPAddress,Location,ResultType)\n| order by TimeGenerated desc',
    splunk:'index=* (src_ip IN ("1.2.3.4" "5.6.7.8") OR dest_ip IN ("1.2.3.4" "5.6.7.8"))\n| stats count by _time,src_ip,dest_ip,index,sourcetype\n| sort -count',
    elastic:'event.category:network AND (destination.ip:("1.2.3.4" "5.6.7.8") OR source.ip:("1.2.3.4" "5.6.7.8"))',
    sigma:"title: IOC Hunt - Network Connection to Malicious IP\nlogsource:\n    category: network_connection\ndetection:\n    selection:\n        DestinationIp|contains:\n            - '1.2.3.4'\n            - '5.6.7.8'\n    condition: selection\nlevel: high",
    huntMeaning:"A hit means a system in your environment communicated with a known-malicious IP. Check: Is this inbound or outbound? What process initiated the connection?",
    nextSteps:["Check the initiating process - is it a browser, PowerShell, or unknown binary?","Look at the timing - regular intervals suggest C2 beaconing","Cross-reference with proxy logs for HTTP context","Check if the IP is a known CDN/cloud provider (shared hosting FP risk)"]
  },
  {
    id:"domain", icon:"🔗", title:"Domain / DNS IOC",
    desc:"Hunt for DNS queries to known-malicious domains and resolve to IPs",
    kql:'// Hunt for malicious domains in DNS and network logs\nlet ioc_domains = dynamic(["evil.com","c2.htb"]);\nunion\n  (DeviceNetworkEvents\n    | where RemoteUrl has_any (ioc_domains)\n    | project TimeGenerated,DeviceName,RemoteUrl,RemoteIP,InitiatingProcessFileName),\n  (DnsEvents\n    | where Name in~ (ioc_domains)\n    | project TimeGenerated,Computer,Name,IPAddresses),\n  (DeviceEvents\n    | where RemoteUrl has_any (ioc_domains)\n    | project TimeGenerated,DeviceName,RemoteUrl,InitiatingProcessFileName)\n| order by TimeGenerated desc',
    splunk:'index=* (dns.query IN ("evil.com" "c2.htb") OR query IN ("evil.com" "c2.htb"))\n| eval ioc_match=coalesce(dns.query,query)\n| stats count by _time,src,ioc_match,index,sourcetype\n| sort -count',
    elastic:'event.category:dns AND dns.question.name:("evil.com" "c2.htb")',
    sigma:"title: IOC Hunt - DNS Query for Malicious Domain\nlogsource:\n    category: dns\ndetection:\n    selection:\n        query|contains:\n            - 'evil.com'\n            - 'c2.htb'\n    condition: selection\nlevel: high",
    huntMeaning:"A hit means a system resolved or connected to a known-malicious domain. This could indicate C2 communication, phishing, or malware download.",
    nextSteps:["Check the source process - was it a browser (user clicked link) or a binary (malware)?","Look at the resolved IP - does it match known C2 infrastructure?","Check WHOIS - newly registered domains (<30 days) are high risk","Add domain to DNS sinkhole if confirmed malicious"]
  },
  {
    id:"hash", icon:"#", title:"File Hash (SHA256/MD5/SHA1)",
    desc:"Hunt for known-malicious file hashes across endpoint telemetry",
    kql:'// Hunt for malicious file hashes across all endpoint tables\nlet ioc_hashes = dynamic(["a3b9e2c7d4f1e8a5b6c3d2e1f0a9b8c7"]);\nunion\n  (DeviceFileEvents\n    | where SHA256 in (ioc_hashes)\n    | project TimeGenerated,DeviceName,FileName,FolderPath,SHA256,InitiatingProcessAccountName),\n  (DeviceProcessEvents\n    | where SHA256 in (ioc_hashes)\n    | project TimeGenerated,DeviceName,FileName,FolderPath,SHA256,AccountName),\n  (DeviceImageLoadEvents\n    | where SHA256 in (ioc_hashes)\n    | project TimeGenerated,DeviceName,FileName,FolderPath,SHA256)\n| order by TimeGenerated desc',
    splunk:'index=* (sha256 IN ("a3b9e2c7d4f1e8a5b6c3d2e1f0a9b8c7") OR file_hash IN ("a3b9e2c7d4f1e8a5b6c3d2e1f0a9b8c7"))\n| stats count by _time,file_name,file_path,sha256,host,user\n| sort -count',
    elastic:'event.category:file AND (file.hash.sha256:("a3b9e2c7d4f1e8a5b6c3d2e1f0a9b8c7") OR process.hash.sha256:("a3b9e2c7d4f1e8a5b6c3d2e1f0a9b8c7"))',
    sigma:"title: IOC Hunt - Process with Malicious SHA256 Hash\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Hashes|contains:\n            - 'SHA256=a3b9e2c7d4f1e8a5b6c3d2e1f0a9b8c7'\n    condition: selection\nlevel: critical",
    huntMeaning:"A hit means a known-malicious file was found on an endpoint - either executed, loaded as a DLL, or written to disk. This is a high-confidence indicator of compromise.",
    nextSteps:["Isolate the affected endpoint immediately","Check the file path - temp directories are high risk","Look at parent process - what spawned this file?","Collect the file for forensic analysis","Add hash to EDR block list"]
  },
  {
    id:"email", icon:"✉", title:"Email / Phishing IOC",
    desc:"Hunt for phishing emails from known-malicious senders",
    kql:'// Hunt for malicious email senders\nlet ioc_emails = dynamic(["attacker@evil.com"]);\nunion\n  (EmailEvents\n    | where SenderFromAddress in~ (ioc_emails) or RecipientEmailAddress in~ (ioc_emails)\n    | project TimeGenerated,SenderFromAddress,RecipientEmailAddress,Subject,ThreatTypes,DeliveryAction),\n  (AuditLogs\n    | where InitiatedBy has_any (ioc_emails)\n    | project TimeGenerated,OperationName,InitiatedBy,Result)\n| order by TimeGenerated desc',
    splunk:'index=* (sender IN ("attacker@evil.com") OR recipient IN ("attacker@evil.com"))\n| stats count by _time,sender,recipient,subject,index\n| sort -count',
    elastic:'event.category:email AND (email.from.address:("attacker@evil.com") OR email.to.address:("attacker@evil.com"))',
    sigma:"title: IOC Hunt - Email from Malicious Sender\nlogsource:\n    category: email\ndetection:\n    selection:\n        sender|contains:\n            - 'attacker@evil.com'\n    condition: selection\nlevel: high",
    huntMeaning:"A hit means an email from a known-malicious sender was delivered to a mailbox.",
    nextSteps:["Check if the email was delivered, quarantined, or blocked","Look for any user clicks on links or attachments","Search for the sender across all mailboxes","Block sender domain at mail gateway"]
  },
  {
    id:"registry", icon:"🗝", title:"Registry / Persistence IOC",
    desc:"Hunt for registry modifications associated with persistence mechanisms",
    kql:'// Hunt for malicious registry keys\nlet ioc_keys = dynamic(["HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\malware"]);\nDeviceRegistryEvents\n| where RegistryKey has_any (ioc_keys) or PreviousRegistryKey has_any (ioc_keys)\n| project TimeGenerated,DeviceName,ActionType,RegistryKey,RegistryValueName,RegistryValueData,InitiatingProcessFileName,InitiatingProcessAccountName\n| order by TimeGenerated desc',
    splunk:'index=* sourcetype=xmlwineventlog EventCode IN (12,13,14) (TargetObject="HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\malware*")\n| stats count by _time,host,TargetObject,Details,EventCode\n| sort -count',
    elastic:'event.category:registry AND registry.key.path:("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\malware")',
    sigma:"title: IOC Hunt - Registry Persistence Key Modified\nlogsource:\n    category: registry_event\n    product: windows\ndetection:\n    selection:\n        TargetObject|startswith:\n            - 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware'\n    condition: selection\nlevel: high",
    huntMeaning:"A hit means a known-malicious registry key was created or modified. This is a strong indicator of persistence.",
    nextSteps:["Check the registry value data - what executable is it pointing to?","Hash the executable and check VirusTotal","Look at the modifying process - was it a legitimate installer?","Monitor for creation AND modification events on this key"]
  },
  {
    id:"cve", icon:"⚠", title:"CVE / Vulnerability Exploitation",
    desc:"Hunt for exploitation attempts targeting known CVEs",
    kql:'// Hunt for CVE exploitation activity\nlet ioc_cves = dynamic(["CVE-2024-1234"]);\nunion\n  (SecurityAlert\n    | where Entities has_any (ioc_cves) or ExtendedProperties has_any (ioc_cves)\n    | project TimeGenerated,AlertName,AlertSeverity,CompromisedEntity,Entities),\n  (CommonSecurityLog\n    | where FlexString2 in (ioc_cves) or Message has_any (ioc_cves)\n    | project TimeGenerated,Computer,SourceIP,DestinationIP,Activity,Message)\n| order by TimeGenerated desc',
    splunk:'index=* (vulnerability IN ("CVE-2024-1234") OR cve IN ("CVE-2024-1234") OR signature IN ("CVE-2024-1234"))\n| stats count by _time,host,signature,severity\n| sort -count',
    elastic:'event.category:vulnerability AND vulnerability.id:("CVE-2024-1234")',
    sigma:"title: IOC Hunt - CVE Exploitation Attempt\nlogsource:\n    category: vulnerability\ndetection:\n    selection:\n        cve|contains:\n            - 'CVE-2024-1234'\n    condition: selection\nlevel: critical",
    huntMeaning:"A hit means an exploitation attempt was detected targeting a known CVE.",
    nextSteps:["Check if the source is an authorized vulnerability scanner","Correlate with IDS/IPS alerts for confirmation","Check if the target system is patched for this CVE","Review the attack payload in network logs"]
  },
  {
    id:"lateral", icon:"↔", title:"Lateral Movement Detection",
    desc:"Hunt for unusual remote logons and authentication patterns",
    kql:'// Detect lateral movement - same account touching many machines\nIdentityLogonEvents\n| where LogonType == "RemoteInteractive" or LogonType == "Network"\n| summarize SourceIPs=make_set(IPAddress),TargetDevices=make_set(DeviceName),LogonCount=count() by AccountName,bin(Timestamp,1h)\n| where array_length(SourceIPs) > 5 or array_length(TargetDevices) > 5\n| sort by LogonCount desc',
    splunk:'index=* sourcetype=win* EventCode=4624 LogonType=3 OR LogonType=10\n| stats dc(Computer) as unique_hosts,values(Computer) as hosts by Account,src_ip\n| where unique_hosts > 5\n| sort -unique_hosts',
    elastic:'event.category:authentication AND (event.outcome:success) AND (user.name:*) | stats dc(host.name) as unique_hosts by user.name | where unique_hosts > 5',
    sigma:"title: Lateral Movement - Account Accessing Multiple Hosts\nlogsource:\n    category: authentication\ndetection:\n    selection:\n        EventID: 4624\n        LogonType: 3\n    condition: selection\n    filter:\n        TargetUserName: \"ANONYMOUS LOGON\"\n    timeframe: 1h\n    groupby: TargetUserName\n    condition: selection and count() > 10\nlevel: high",
    huntMeaning:"A hit means a single account is authenticating to many systems in a short time window. Classic lateral movement pattern.",
    nextSteps:["Verify if the account is a service account (expected behavior)","Check if the source IPs are jump servers or admin workstations","Look for Pass-the-Hash or Pass-the-Ticket indicators","Correlate with process creation events on target systems"]
  },
  {
    id:"beacon", icon:"📡", title:"C2 Beaconing Detection",
    desc:"Hunt for regular-interval outbound connections characteristic of C2 beaconing",
    kql:'// Detect C2 beaconing - regular interval outbound connections\nDeviceNetworkEvents\n| where ActionType == "ConnectionSuccess"\n| where RemotePort in (443,8443,8080,4443)\n| summarize ConnectionTimes=make_set(Timestamp),BytesOut=sum(BytesSent),BytesIn=sum(BytesReceived),ConnectionCount=count() by DeviceName,RemoteIP,RemoteUrl,LocalPort,bin(Timestamp,15m)\n| where ConnectionCount between (3 .. 10)\n| extend TimeVariance = stdev(ConnectionTimes)\n| where TimeVariance < 120\n| sort by TimeVariance asc',
    splunk:'index=* dest_port IN (4443 8443 8080)\n| bin _time span=15m\n| stats count as conn_count,dc(dest_ip) as unique_dests by _time,src_ip,dest_ip\n| where conn_count >= 3 AND conn_count <= 10\n| eventstats stdev(conn_count) as beacon_score by src_ip,dest_ip\n| where beacon_score < 2\n| sort beacon_score',
    elastic:'event.category:network AND destination.port:(443 8443 8080 4443) | bucket span=15m _time | stats count by _time,source.ip,destination.ip | where count >= 3',
    sigma:"title: Potential C2 Beaconing - Regular Interval Connections\nlogsource:\n    category: network_connection\ndetection:\n    selection:\n        DestinationPort: 4443\n    condition: selection\n    timeframe: 15m\n    groupby: SourceIp,DestinationIp\n    condition: selection and count() >= 3\nlevel: medium",
    huntMeaning:"A hit means a system is making regular outbound connections to an external IP. Low time variance suggests automated beaconing.",
    nextSteps:["Check the destination IP reputation","Look at the initiating process - is it a known binary?","Check if the domain resolves to a known C2 framework","Capture network traffic for analysis"]
  },
  {
    id:"exfil", icon:"📤", title:"Data Exfiltration Detection",
    desc:"Hunt for large outbound data transfers",
    kql:'// Detect potential data exfiltration - large outbound transfers\nDeviceNetworkEvents\n| where BytesSent > 5000000\n| summarize TotalBytes=sum(BytesSent),TransferCount=count(),DestIPs=make_set(RemoteIP),DestDomains=make_set(RemoteUrl) by DeviceName,InitiatingProcessFileName,bin(Timestamp,1h)\n| where TotalBytes > 50000000\n| extend DataVolumeMB = round(TotalBytes / 1048576,2)\n| sort by TotalBytes desc',
    splunk:'index=* bytes_out > 5000000\n| stats sum(bytes_out) as total_bytes,count as transfers by src_ip,dest_ip,_time span=1h\n| where total_bytes > 50000000\n| eval mb=round(total_bytes/1048576,2)\n| sort -total_bytes',
    elastic:'event.category:network AND network.bytes_out > 5000000 | stats sum(network.bytes_out) as total by source.ip,destination.ip,host.name | where total > 50000000',
    sigma:"title: Potential Data Exfiltration - Large Outbound Transfer\nlogsource:\n    category: network_connection\ndetection:\n    selection:\n        BytesSent|gte: 50000000\n    condition: selection\nlevel: high",
    huntMeaning:"A hit means a system transferred a large volume of data outbound. Could be legitimate (backup) or malicious (data theft).",
    nextSteps:["Check the destination - is it a known cloud storage or backup service?","Look at the initiating process - is it a backup agent or something unexpected?","Check the timing - business hours vs. off-hours","Review the data classification of the source system"]
  },
  {
    id:"injection", icon:"💉", title:"Process Injection Detection",
    desc:"Hunt for reflective DLL injection and process hollowing indicators",
    kql:'// Detect .NET DLL loaded into non-.NET process (reflective injection)\nDeviceImageLoadEvents\n| where FileName =~ "clr.dll" or FileName =~ "clrjit.dll"\n| where InitiatingProcessFileName !in~ ("devenv.exe","ServiceHub.VSDetouredHost.exe","dotnet.exe","w3wphost.exe")\n| project TimeGenerated,DeviceName,InitiatingProcessFileName,FileName,InitiatingProcessCommandLine',
    splunk:'index=* sourcetype=XmlWinEventLog EventCode=7 (ImageLoaded="*clr.dll" OR ImageLoaded="*clrjit.dll")\n| search NOT (SourceImage="*devenv.exe" OR SourceImage="*dotnet.exe")\n| stats count by _time,Computer,SourceImage,ImageLoaded\n| sort -count',
    elastic:'event.category:library AND (dll.name:clr.dll OR dll.name:clrjit.dll) AND NOT process.name:(devenv.exe dotnet.exe)',
    sigma:"title: Reflective DLL Injection - .NET DLL in Non-.NET Process\nlogsource:\n    category: image_load\ndetection:\n    selection:\n        ImageLoaded|endswith:\n            - '\\clr.dll'\n            - '\\clrjit.dll'\n    filter:\n        Image|endswith:\n            - '\\devenv.exe'\n            - '\\dotnet.exe'\n    condition: selection and not filter\nlevel: high",
    huntMeaning:"A hit means a .NET runtime DLL was loaded into a process that is not a .NET application. Strong indicator of reflective DLL injection.",
    nextSteps:["Isolate the affected endpoint","Dump the process memory for analysis","Check for other injection indicators","Look at the parent process chain"]
  }
];

// ══════════════════ CHEAT SHEET RENDERING ══════════════════

var _csPlatform = 'all';

function setCSPlatform(p) {
  _csPlatform = p;
  var btns = document.querySelectorAll('.cs-plat-btn');
  for (var i = 0; i < btns.length; i++) {
    var active = btns[i].id === 'cs-plat-' + p;
    btns[i].style.background = active ? 'var(--accent)' : '';
    btns[i].style.color = active ? 'var(--bg)' : '';
    btns[i].style.borderColor = active ? 'var(--accent)' : '';
  }
  renderCheatSheet();
}

function filterCheatSheet() { renderCheatSheet(); }
function loadCheatSheet() { renderCheatSheet(); }

function renderCheatSheet() {
  var search = (document.getElementById('csSearch') || {}).value || '';
  search = search.toLowerCase();
  var filtered = [];
  for (var i = 0; i < CHEAT_SHEET.length; i++) {
    var cs = CHEAT_SHEET[i];
    if (search && cs.title.toLowerCase().indexOf(search) === -1 && cs.desc.toLowerCase().indexOf(search) === -1) continue;
    filtered.push(cs);
  }
  var div = document.getElementById('csResults');
  if (!filtered.length) { div.innerHTML = '<div class="loading">No scenarios match your search.</div>'; return; }
  var html = '';
  for (var i = 0; i < filtered.length; i++) {
    var cs = filtered[i];
    var sections = '';
    if (_csPlatform === 'all' || _csPlatform === 'kql') sections += makeQBlock('KQL', cs.kql);
    if (_csPlatform === 'all' || _csPlatform === 'splunk') sections += makeQBlock('Splunk SPL', cs.splunk);
    if (_csPlatform === 'all' || _csPlatform === 'elastic') sections += makeQBlock('Elastic DSL', cs.elastic);
    if (_csPlatform === 'all' || _csPlatform === 'sigma') sections += makeQBlock('Sigma', cs.sigma);
    html += '<div class="panel" style="margin-bottom:12px;">' +
      '<div class="panel-header" style="display:flex;align-items:center;gap:8px;">' +
      '<span style="font-size:15px;">' + cs.icon + '</span>' +
      '<span style="flex:1;">' + escHtml(cs.title) + '</span>' +
      '<span style="font-size:10px;color:var(--text2);font-weight:400;">' + escHtml(cs.desc) + '</span></div>' +
      '<div class="panel-body">' + sections +
      '<div style="margin-top:10px;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;">' +
      '<div style="font-size:10px;color:var(--accent);font-weight:700;text-transform:uppercase;margin-bottom:4px;">What a hit means</div>' +
      '<div style="font-size:11px;color:var(--text);margin-bottom:6px;">' + escHtml(cs.huntMeaning) + '</div>' +
      '<div style="font-size:10px;color:var(--accent);font-weight:700;text-transform:uppercase;margin-bottom:4px;">Next steps</div>';
    for (var j = 0; j < cs.nextSteps.length; j++) {
      html += '<div style="font-size:11px;color:var(--text);padding:2px 0;">→ ' + escHtml(cs.nextSteps[j]) + '</div>';
    }
    html += '</div></div></div>';
  }
  div.innerHTML = html;
}

function makeQBlock(platform, code) {
  var escaped = escHtml(code);
  var codeId = 'csblk_' + Math.random().toString(36).slice(2);
  return '<div class="qblock">' +
    '<div class="qplat">[' + escHtml(platform) + '] ' +
    '<button class="secondary" style="font-size:10px;padding:2px 7px;" ' +
    'onclick="copy(document.getElementById(\'' + codeId + '\').textContent);this.textContent=\'✓\';setTimeout(function(){this.textContent=\'Copy\'}.bind(this),1500)">Copy</button></div>' +
    '<pre id="' + codeId + '">' + escaped + '</pre></div>';
}

// ══════════════════ DETECTION ENGINEERING ══════════════════
// Note: Detection Engineering functions are inlined in server.ts
// to avoid duplicate declaration errors. This file only contains
// Cheat Sheet rendering logic.
