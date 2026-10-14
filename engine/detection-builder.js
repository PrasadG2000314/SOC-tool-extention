/**
 * Detection Engineering & Containment Automation Generator
 * Produces production-grade Sigma YAML rules, YARA signatures, and containment scripts.
 */

export function generateSigmaRule(parsedData) {
  const { lolbinsDetected, iocs, mitreTechniques, attribution } = parsedData;
  const primaryBin = lolbinsDetected[0]?.name || 'powershell.exe';
  const techId = mitreTechniques[0] || 'T1059.001';
  const suspiciousIp = iocs.ips.find(i => i.isSuspicious)?.ip;
  const dateStr = new Date().toISOString().split('T')[0];

  const ruleTitle = `Suspicious Process Execution - Potential ${attribution.type.split('/')[0].trim()}`;

  const sigmaYaml = `title: ${ruleTitle}
id: ${crypto.randomUUID ? crypto.randomUUID() : 'b41f23a0-8e12-4c55-9a89-0123456789ab'}
status: experimental
description: Detects suspicious command-line parameters or process execution matching ${attribution.type}.
references:
  - https://attack.mitre.org/techniques/${techId.replace('.', '/')}/
author: SOC Tier 3 Threat Hunter
date: ${dateStr}
modified: ${dateStr}
tags:
  - attack.${mitreTechniques[0] ? mitreTechniques[0].toLowerCase() : 't1059_001'}
  - attack.${parsedData.mitreTactics[0] ? parsedData.mitreTactics[0].toLowerCase().replace(/\s+/g, '_') : 'execution'}
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\\${primaryBin}'
      - '\\cmd.exe'
  selection_cli:
    CommandLine|contains:
      - '-enc'
      - '-w hidden'
      - 'bypass'
      - 'downloadstring'
      - 'IEX'
      ${suspiciousIp ? `- '${suspiciousIp}'` : ''}
  filter_legit:
    CommandLine|contains:
      - 'Program Files'
      - 'C:\\Windows\\System32\\WindowsPowerShell'
  condition: (selection_process and selection_cli) and not filter_legit
falsepositives:
  - Legitimate administrative automation scripts using encoded flags
level: high`;

  return sigmaYaml.trim();
}

export function generateYaraRule(parsedData) {
  const { iocs, attribution } = parsedData;
  const ruleName = `APT_Hunter_${(attribution.type.replace(/[^a-zA-Z0-9]/g, '_')).substring(0, 24)}`;
  const hash = iocs.hashes.sha256[0] || iocs.hashes.md5[0] || '';
  const domain = iocs.domains[0]?.value ? iocs.domains[0].value.replace(/https?:\/\//, '') : '';
  const dateStr = new Date().toISOString().split('T')[0];

  const yaraRule = `rule ${ruleName} {
    meta:
        description = "Detects artifacts related to ${attribution.type}"
        author = "Tier 3 Incident Response Hunter"
        reference = "Internal SOC Threat Intel"
        date = "${dateStr}"
        severity = "HIGH"
        sample_hash = "${hash || 'N/A'}"

    strings:
        $s1 = "powershell.exe -nop -w hidden -enc" ascii wide nocase
        $s2 = "DownloadString" ascii wide nocase
        $s3 = "VirtualAlloc" ascii wide
        $s4 = "CreateRemoteThread" ascii wide
        ${domain ? `$net1 = "${domain}" ascii wide` : '$net1 = "http" ascii'}
        ${hash ? `$hash_marker = "${hash.substring(0, 16)}" ascii` : ''}

    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $net1)
}`;

  return yaraRule.trim();
}

export function generateContainmentPlaybook(parsedData) {
  const suspiciousIp = parsedData.iocs.ips.find(i => i.isSuspicious)?.ip || '198.51.100.23';
  const targetHost = parsedData.agent?.name || 'TARGET-WKSTN-01';
  const targetUser = parsedData.iocs.users[0] || 'svc_operator';
  const primaryPid = parsedData.raw.match(/ProcessId[:\s=]+(\d+)/i)?.[1] || '4188';

  return {
    edrIsolation: {
      title: 'EDR Host Network Isolation (Defender / Falcon API / Local)',
      cli: `# PowerShell: Block all non-management outbound/inbound traffic instantly
New-NetFirewallRule -DisplayName "SOC_EMERGENCY_ISOLATION" -Direction Outbound -Action Block -Enabled True -Profile Any
New-NetFirewallRule -DisplayName "SOC_EMERGENCY_ISOLATION_IN" -Direction Inbound -Action Block -Enabled True -Profile Any

# Terminate malicious process tree by PID:
Stop-Process -Id ${primaryPid} -Force -ErrorAction SilentlyContinue`
    },
    adAccountRevocation: {
      title: 'Active Directory Identity Containment',
      cli: `# Disable compromised user/service account & invalidate Kerberos tickets:
Disable-ADAccount -Identity "${targetUser}"
Revoke-AzureADUserAllRefreshToken -ObjectId "${targetUser}" -ErrorAction SilentlyContinue
# Purge active Kerberos sessions on Domain Controllers:
klist purge`
    },
    perimeterNullRoute: {
      title: 'Perimeter Firewall / Edge Null-Route (Boundary Defense)',
      cli: `# Edge Null-Route for C2 IP (${suspiciousIp}):
# Cisco IOS / Juniper:
ip route ${suspiciousIp} 255.255.255.255 Null0

# Linux Gateway / iptables:
iptables -I INPUT -s ${suspiciousIp} -j DROP
iptables -I FORWARD -s ${suspiciousIp} -j DROP`
    }
  };
}
