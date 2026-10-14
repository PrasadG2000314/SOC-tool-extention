/**
 * MITRE ATT&CK Enterprise Knowledge Base & LOLBins Mapping
 * Curated for Tier 3 Threat Hunting & Incident Response
 */

export const MITRE_TECHNIQUES = {
  // Initial Access & Execution
  'T1059.001': {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    url: 'https://attack.mitre.org/techniques/T1059/001/',
    description: 'Adversaries may abuse PowerShell commands and scripts for execution, leveraging built-in cmdlets and bypass flags (-enc, -w hidden, -nop).'
  },
  'T1059.003': {
    id: 'T1059.003',
    name: 'Command and Scripting Interpreter: Windows Command Shell',
    tactic: 'Execution',
    url: 'https://attack.mitre.org/techniques/T1059/003/',
    description: 'Adversaries may abuse cmd.exe to execute commands, batch scripts, and living-off-the-land utilities.'
  },
  'T1059.004': {
    id: 'T1059.004',
    name: 'Command and Scripting Interpreter: Unix Shell',
    tactic: 'Execution',
    url: 'https://attack.mitre.org/techniques/T1059/004/',
    description: 'Adversaries may abuse Unix shells (bash, sh, zsh) to execute malicious commands and scripts.'
  },
  'T1047': {
    id: 'T1047',
    name: 'Windows Management Instrumentation',
    tactic: 'Execution',
    url: 'https://attack.mitre.org/techniques/T1047/',
    description: 'Adversaries may abuse WMI (wmic.exe or PowerShell WMI/CIM cmdlets) to execute malicious commands and discover system information.'
  },
  'T1053.005': {
    id: 'T1053.005',
    name: 'Scheduled Task/Job: Scheduled Task',
    tactic: 'Persistence / Privilege Escalation',
    url: 'https://attack.mitre.org/techniques/T1053/005/',
    description: 'Adversaries may abuse task scheduler (schtasks.exe) to execute programs at system startup or on a scheduled basis.'
  },
  'T1543.003': {
    id: 'T1543.003',
    name: 'Create or Modify System Process: Windows Service',
    tactic: 'Persistence / Privilege Escalation',
    url: 'https://attack.mitre.org/techniques/T1543/003/',
    description: 'Adversaries may create or modify Windows services (sc.exe or registry) to execute malicious binaries.'
  },
  'T1055': {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion / Privilege Escalation',
    url: 'https://attack.mitre.org/techniques/T1055/',
    description: 'Adversaries may inject code into running processes (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) to evade process-based defenses.'
  },
  'T1055.012': {
    id: 'T1055.012',
    name: 'Process Injection: Process Hollowing',
    tactic: 'Defense Evasion / Privilege Escalation',
    url: 'https://attack.mitre.org/techniques/T1055/012/',
    description: 'Adversaries may inject code into suspended processes and hollow out legitimate executables (e.g. svchost.exe, explorer.exe).'
  },
  'T1027': {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
    url: 'https://attack.mitre.org/techniques/T1027/',
    description: 'Adversaries may attempt to make an executable or script difficult to discover or analyze using encoding, encryption, or packing.'
  },
  'T1027.002': {
    id: 'T1027.002',
    name: 'Software Packing',
    tactic: 'Defense Evasion',
    url: 'https://attack.mitre.org/techniques/T1027/002/',
    description: 'Adversaries may compress or encrypt payloads using packers (UPX, custom crypters) to evade signature detection.'
  },
  'T1036.005': {
    id: 'T1036.005',
    name: 'Masquerading: Match Legitimate Name or Location',
    tactic: 'Defense Evasion',
    url: 'https://attack.mitre.org/techniques/T1036/005/',
    description: 'Adversaries may match or approximate legitimate names/paths (e.g. svch0st.exe or placing binaries in C:\\Windows\\Temp).'
  },
  'T1070.004': {
    id: 'T1070.004',
    name: 'Indicator Removal: File Deletion',
    tactic: 'Defense Evasion',
    url: 'https://attack.mitre.org/techniques/T1070/004/',
    description: 'Adversaries may delete files left behind by malware or tools using del, srm, or sdelete to hinder forensics.'
  },
  'T1562.001': {
    id: 'T1562.001',
    name: 'Impair Defenses: Disable or Modify Tools',
    tactic: 'Defense Evasion',
    url: 'https://attack.mitre.org/techniques/T1562/001/',
    description: 'Adversaries may disable security software (Windows Defender, AMSI, Sysmon, EDR drivers) via Set-MpPreference or registry edits.'
  },
  'T1003.001': {
    id: 'T1003.001',
    name: 'OS Credential Dumping: LSASS Memory',
    tactic: 'Credential Access',
    url: 'https://attack.mitre.org/techniques/T1003/001/',
    description: 'Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).'
  },
  'T1558.003': {
    id: 'T1558.003',
    name: 'Steal or Forge Kerberos Tickets: Kerberoasting',
    tactic: 'Credential Access',
    url: 'https://attack.mitre.org/techniques/T1558/003/',
    description: 'Adversaries may request Kerberos Service Principal Name (SPN) tickets (TGS-REQ) and crack the RC4/AES hashes offline.'
  },
  'T1082': {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
    url: 'https://attack.mitre.org/techniques/T1082/',
    description: 'Adversaries may attempt to get detailed information about the operating system and hardware (systeminfo, uname -a).'
  },
  'T1087': {
    id: 'T1087',
    name: 'Account Discovery',
    tactic: 'Discovery',
    url: 'https://attack.mitre.org/techniques/T1087/',
    description: 'Adversaries may attempt to get a listing of accounts on a system or network (net user, whoami /all, Get-ADUser).'
  },
  'T1021.002': {
    id: 'T1021.002',
    name: 'Remote Services: SMB/Windows Admin Shares',
    tactic: 'Lateral Movement',
    url: 'https://attack.mitre.org/techniques/T1021/002/',
    description: 'Adversaries may use SMB shares (ADMIN$, C$) or PsExec/WMI to execute commands on remote systems.'
  },
  'T1071.001': {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tactic: 'Command and Control',
    url: 'https://attack.mitre.org/techniques/T1071/001/',
    description: 'Adversaries may communicate using application layer protocols (HTTP/HTTPS) to blend in with normal network traffic for C2.'
  },
  'T1105': {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    url: 'https://attack.mitre.org/techniques/T1105/',
    description: 'Adversaries may transfer tools or other files from an external system into a compromised network (certutil, curl, bitsadmin).'
  },
  'T1505.003': {
    id: 'T1505.003',
    name: 'Server Software Component: Web Shell',
    tactic: 'Persistence',
    url: 'https://attack.mitre.org/techniques/T1505/003/',
    description: 'Adversaries may backdoor web servers by creating or modifying scripts (PHP, ASPX, JSP) to maintain persistent access.'
  },
  'T1486': {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    url: 'https://attack.mitre.org/techniques/T1486/',
    description: 'Adversaries may encrypt data on target systems or network shares to interrupt availability and demand ransom.'
  },
  'T1490': {
    id: 'T1490',
    name: 'Inhibit System Recovery',
    tactic: 'Impact',
    url: 'https://attack.mitre.org/techniques/T1490/',
    description: 'Adversaries may delete or disable volume shadow copies or backup mechanisms (vssadmin delete shadows /all /quiet).'
  }
};

export const LOLBINS = {
  'certutil.exe': {
    type: 'LOLBin',
    mitre: ['T1105', 'T1027'],
    risk: 'High',
    desc: 'Abused to download payloads via -urlcache -split -f or decode base64 files with -decode.'
  },
  'powershell.exe': {
    type: 'LOLBin / Shell',
    mitre: ['T1059.001', 'T1027'],
    risk: 'Critical',
    desc: 'Primary vector for in-memory payload execution, obfuscated IEX downloads, and API unhooking.'
  },
  'cmd.exe': {
    type: 'LOLBin / Shell',
    mitre: ['T1059.003'],
    risk: 'Medium',
    desc: 'Command interpreter used for reconnaissance, batch execution, and spawning child processes.'
  },
  'mshta.exe': {
    type: 'LOLBin',
    mitre: ['T1218.005'],
    risk: 'Critical',
    desc: 'Executes Microsoft HTML Applications (.hta), inline VBScript or JScript without dropping files.'
  },
  'rundll32.exe': {
    type: 'LOLBin',
    mitre: ['T1218.011'],
    risk: 'High',
    desc: 'Executes exported functions from arbitrary DLLs; frequently used to proxy execution of shellcode.'
  },
  'regsvr32.exe': {
    type: 'LOLBin',
    mitre: ['T1218.010'],
    risk: 'Critical',
    desc: 'Squiblydoo technique: registers DLLs or executes remote SCT scripts bypass via /s /n /u /i:http://.'
  },
  'wmic.exe': {
    type: 'LOLBin',
    mitre: ['T1047'],
    risk: 'High',
    desc: 'WMI command line used to launch remote processes or query system/hardware configurations.'
  },
  'bitsadmin.exe': {
    type: 'LOLBin',
    mitre: ['T1197', 'T1105'],
    risk: 'High',
    desc: 'Background Intelligent Transfer Service abused to download malicious payloads asynchronously.'
  },
  'vssadmin.exe': {
    type: 'LOLBin / Ransomware TTP',
    mitre: ['T1490'],
    risk: 'Critical',
    desc: 'Used by ransomware operators to delete Volume Shadow Copies (delete shadows /all /quiet).'
  },
  'schtasks.exe': {
    type: 'LOLBin',
    mitre: ['T1053.005'],
    risk: 'High',
    desc: 'Task scheduler command-line utility abused for persistence and privilege escalation.'
  },
  'sc.exe': {
    type: 'LOLBin',
    mitre: ['T1543.003'],
    risk: 'High',
    desc: 'Windows service controller abused to install malicious driver services or backdoors.'
  },
  'nltest.exe': {
    type: 'LOLBin',
    mitre: ['T1018', 'T1082'],
    risk: 'Medium',
    desc: 'Domain reconnaissance utility used to query domain trusts and domain controller lists.'
  },
  'whoami.exe': {
    type: 'LOLBin',
    mitre: ['T1033'],
    risk: 'Medium',
    desc: 'Reconnaissance utility used immediately post-exploitation to check user privileges (/priv, /groups).'
  }
};
