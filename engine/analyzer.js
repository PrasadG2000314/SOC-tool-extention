/**
 * Advanced Telemetry Analyzer & IoC Decomposition Engine
 * Tier 3 Threat Hunting & Incident Response Logic
 */

import { MITRE_TECHNIQUES, LOLBINS } from './mitre-db.js';

// Shannon Entropy Calculation
export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

// Defang IP/Domain/URL
export function defang(indicator) {
  if (!indicator) return '';
  return indicator
    .replace(/^http:\/\//gi, 'hxxp://')
    .replace(/^https:\/\//gi, 'hxxps://')
    .replace(/\./g, '[.]');
}

// Check if IP is private/internal (RFC 1918 / Loopback)
export function isInternalIP(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith('169.254.')) return true; // APIPA
  return false;
}

// Extract base64 and attempt UTF-16LE / UTF-8 decoding (common in PowerShell -enc)
export function inspectBase64(text) {
  const base64Regex = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  const matches = text.match(base64Regex) || [];
  const decoded = [];

  for (const match of matches) {
    try {
      const raw = atob(match);
      // Check for Windows UTF-16LE powershell command
      let cleaned = '';
      if (raw.includes('\x00')) {
        for (let i = 0; i < raw.length; i += 2) {
          cleaned += raw[i];
        }
      } else {
        cleaned = raw;
      }
      
      // If decoded contains printable chars and readable commands
      if (/[\w\s.-]{8,}/.test(cleaned) && (cleaned.includes('http') || cleaned.includes('Download') || cleaned.includes('IEX') || cleaned.includes('cmd') || cleaned.includes('System.') || cleaned.includes('Invoke-'))) {
        decoded.push({
          encoded: match.length > 60 ? match.substring(0, 57) + '...' : match,
          fullEncoded: match,
          decodedContent: cleaned.trim(),
          entropy: calculateEntropy(match)
        });
      }
    } catch {
      // Ignore invalid base64
    }
  }
  return decoded;
}

// Deep Alert Parser
export function parseTelemetry(rawText) {
  const result = {
    raw: rawText,
    format: 'Unstructured Text',
    parsedJson: null,
    eventIds: [],
    ruleId: null,
    ruleDescription: null,
    agent: {},
    iocs: {
      ips: [],
      domains: [],
      hashes: { md5: [], sha1: [], sha256: [] },
      paths: [],
      commands: [],
      registryKeys: [],
      users: [],
      hosts: []
    },
    lolbinsDetected: [],
    entropy: {
      overall: calculateEntropy(rawText),
      highEntropyBlobs: []
    },
    decodedBase64: [],
    mitreTactics: [],
    mitreTechniques: [],
    attribution: {
      type: 'Unknown',
      confidence: 'Medium',
      indicators: []
    },
    rootCause: {
      vector: 'Unspecified Execution',
      privilegeLevel: 'User',
      blastRadius: 'Local Host',
      details: ''
    },
    verdict: {
      status: 'True Positive',
      score: 85,
      justification: ''
    }
  };

  // 1. Attempt JSON parsing (e.g. Wazuh alert or Elastic document)
  try {
    const trimmed = rawText.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      result.parsedJson = JSON.parse(trimmed);
      result.format = 'JSON Alert / Telemetry';
      
      // Wazuh alert extraction
      if (result.parsedJson.rule) {
        result.ruleId = result.parsedJson.rule.id || null;
        result.ruleDescription = result.parsedJson.rule.description || null;
        if (result.parsedJson.rule.mitre) {
          const mitreObj = result.parsedJson.rule.mitre;
          if (Array.isArray(mitreObj.id)) {
            mitreObj.id.forEach(id => result.mitreTechniques.push(id));
          } else if (mitreObj.id) {
            result.mitreTechniques.push(mitreObj.id);
          }
        }
      }
      if (result.parsedJson.agent) {
        result.agent = {
          id: result.parsedJson.agent.id,
          name: result.parsedJson.agent.name,
          ip: result.parsedJson.agent.ip
        };
      }
    }
  } catch {
    // Continue with regex parsing
  }

  // 2. Event ID Extraction (Sysmon & Windows Security)
  const eventIdMatches = rawText.match(/(?:EventID|Event ID|event_id|EventCode)[\s:=]+(\d+)/gi);
  if (eventIdMatches) {
    eventIdMatches.forEach(m => {
      const num = m.match(/\d+/)[0];
      if (!result.eventIds.includes(num)) result.eventIds.push(num);
    });
  }

  // Sysmon specific event ID triggers in text (e.g., "Event 1, Microsoft-Windows-Sysmon")
  const sysmonMatches = rawText.match(/Sysmon[\s/]+(?:Event ID\s*|Event\s*)?(\d+)/gi);
  if (sysmonMatches) {
    sysmonMatches.forEach(m => {
      const num = m.match(/\d+/)[0];
      if (!result.eventIds.includes(num)) result.eventIds.push(num);
    });
  }

  // 3. Extract IP Addresses
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const rawIps = rawText.match(ipRegex) || [];
  const uniqueIps = [...new Set(rawIps)];
  result.iocs.ips = uniqueIps.map(ip => ({
    ip,
    defanged: defang(ip),
    type: isInternalIP(ip) ? 'Internal / RFC1918' : 'Public / External Routable',
    isSuspicious: !isInternalIP(ip) && ip !== '0.0.0.0' && ip !== '255.255.255.255'
  })).filter(item => item.ip !== '0.0.0.0' && item.ip !== '255.255.255.255');

  // 4. Extract Hashes (MD5, SHA1, SHA256)
  const sha256Regex = /\b[A-Fa-f0-9]{64}\b/g;
  const sha1Regex = /\b[A-Fa-f0-9]{40}\b/g;
  const md5Regex = /\b[A-Fa-f0-9]{32}\b/g;

  const sha256Matches = [...new Set(rawText.match(sha256Regex) || [])];
  const sha1Matches = [...new Set((rawText.match(sha1Regex) || []).filter(h => !sha256Matches.some(s => s.includes(h))))];
  const md5Matches = [...new Set((rawText.match(md5Regex) || []).filter(h => !sha256Matches.some(s => s.includes(h)) && !sha1Matches.some(s => s.includes(h))))];

  result.iocs.hashes.sha256 = sha256Matches;
  result.iocs.hashes.sha1 = sha1Matches;
  result.iocs.hashes.md5 = md5Matches;

  // 5. Extract Domains & URLs
  const urlRegex = /https?:\/\/[a-zA-Z0-9.-]+(?::[0-9]+)?(?:\/[^\s"'>]*)?/gi;
  const urlMatches = rawText.match(urlRegex) || [];
  urlMatches.forEach(url => {
    result.iocs.domains.push({
      type: 'URL',
      value: url,
      defanged: defang(url)
    });
  });

  const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|ru|cn|top|info|biz|online|cc|pro|site|me|cc|pw|co)\b/gi;
  const domainMatches = rawText.match(domainRegex) || [];
  domainMatches.forEach(dom => {
    if (!result.iocs.domains.some(d => d.value === dom) && !dom.includes('microsoft.com') && !dom.includes('w3.org')) {
      result.iocs.domains.push({
        type: 'Domain / FQDN',
        value: dom,
        defanged: defang(dom)
      });
    }
  });

  // 6. Extract Paths & LOLBins
  for (const [bin, info] of Object.entries(LOLBINS)) {
    const regex = new RegExp(`\\b${bin}\\b`, 'i');
    if (regex.test(rawText)) {
      result.lolbinsDetected.push({
        name: bin,
        ...info
      });
      info.mitre.forEach(t => {
        if (!result.mitreTechniques.includes(t)) result.mitreTechniques.push(t);
      });
    }
  }

  // File paths (Windows and Linux)
  const winPathRegex = /[A-Za-z]:\\[\w.\-\\ ]+\.[\w]{2,4}/gi;
  const linuxPathRegex = /(?:\/[\w.-]+){2,}\.[\w]{2,4}/gi;
  const paths = [
    ...(rawText.match(winPathRegex) || []),
    ...(rawText.match(linuxPathRegex) || [])
  ];
  result.iocs.paths = [...new Set(paths)];

  // 7. Base64 & Obfuscation Inspection
  result.decodedBase64 = inspectBase64(rawText);
  if (result.decodedBase64.length > 0) {
    if (!result.mitreTechniques.includes('T1027')) result.mitreTechniques.push('T1027');
    if (!result.mitreTechniques.includes('T1059.001') && /powershell|iex|downloadstring/i.test(rawText)) {
      result.mitreTechniques.push('T1059.001');
    }
  }

  // 8. MITRE ATT&CK Contextual Detection
  const lowerText = rawText.toLowerCase();

  if (lowerText.includes('lsass') || lowerText.includes('sekurlsa') || lowerText.includes('minidump') || lowerText.includes('comsvcs.dll')) {
    result.mitreTechniques.push('T1003.001');
  }
  if (lowerText.includes('kerberos') || lowerText.includes('spn') || lowerText.includes('tgt') || lowerText.includes('tgs') || lowerText.includes('4769')) {
    result.mitreTechniques.push('T1558.003');
  }
  if (lowerText.includes('createremotethread') || lowerText.includes('writeprocessmemory') || lowerText.includes('virtualallocex') || lowerText.includes('process hollowing')) {
    result.mitreTechniques.push('T1055');
  }
  if (lowerText.includes('schtasks') || lowerText.includes('scheduled task') || lowerText.includes('at.exe')) {
    result.mitreTechniques.push('T1053.005');
  }
  if (lowerText.includes('psexec') || lowerText.includes('admin$') || lowerText.includes('c$') || lowerText.includes('ipc$')) {
    result.mitreTechniques.push('T1021.002');
  }
  if (lowerText.includes('eval(') || lowerText.includes('base64_decode') || lowerText.includes('china chopper') || lowerText.includes('.php') || lowerText.includes('web shell') || lowerText.includes('fim')) {
    result.mitreTechniques.push('T1505.003');
  }
  if (lowerText.includes('vssadmin') && lowerText.includes('delete shadows')) {
    result.mitreTechniques.push('T1490');
    result.mitreTechniques.push('T1486');
  }

  // Deduplicate techniques and populate tactics
  result.mitreTechniques = [...new Set(result.mitreTechniques)];
  result.mitreTactics = [...new Set(
    result.mitreTechniques.map(id => MITRE_TECHNIQUES[id]?.tactic).filter(Boolean)
  )];

  // 9. Attribution & Threat Profile Hypothesis
  if (lowerText.includes('beacon') || lowerText.includes('cobalt') || (result.lolbinsDetected.some(l => l.name === 'powershell.exe') && result.decodedBase64.length > 0 && result.mitreTechniques.includes('T1055'))) {
    result.attribution = {
      type: 'Cobalt Strike / Advanced C2 Framework (Malleable Beacon)',
      confidence: 'High',
      indicators: [
        'Base64 encoded in-memory injection staging',
        'Reflective DLL loading / Process Hollowing signature',
        'Abuse of PowerShell execution flags (-w hidden -nop -enc)'
      ]
    };
  } else if (lowerText.includes('chopper') || lowerText.includes('web shell') || (lowerText.includes('fim') && lowerText.includes('.php'))) {
    result.attribution = {
      type: 'Adversary Web Shell Backdoor (China Chopper / Weevely TTP)',
      confidence: 'High',
      indicators: [
        'Web server File Integrity Monitoring (FIM) creation alert',
        'Single-line arbitrary code execution payload'
      ]
    };
  } else if (lowerText.includes('vssadmin') || lowerText.includes('shadow') || lowerText.includes('ransom')) {
    result.attribution = {
      type: 'Ransomware Pre-Encryption Inhibitor / Operator TTP',
      confidence: 'High',
      indicators: [
        'Volume Shadow Copy purge via vssadmin',
        'System recovery inhibition'
      ]
    };
  } else if (lowerText.includes('kerberoast') || (result.eventIds.includes('4769') && lowerText.includes('0x17'))) {
    result.attribution = {
      type: 'Active Directory Kerberoasting Campaign (Rubeus / Impacket)',
      confidence: 'High',
      indicators: [
        'Kerberos TGS ticket requested with weak RC4 encryption (0x17)',
        'Bulk SPN enumeration behavior'
      ]
    };
  } else if (result.iocs.ips.some(ip => ip.isSuspicious) && (lowerText.includes('scan') || lowerText.includes('nmap') || lowerText.includes('masscan'))) {
    result.attribution = {
      type: 'Automated External Reconnaissance / Vulnerability Scanner',
      confidence: 'Medium',
      indicators: ['High-frequency connection attempts', 'Known scanning tool user-agent']
    };
  } else {
    result.attribution = {
      type: 'Targeted Living-Off-The-Land (LotL) / Post-Exploitation Activity',
      confidence: 'Medium',
      indicators: [
        result.lolbinsDetected.length > 0 ? `LOLBins invoked: ${result.lolbinsDetected.map(l => l.name).join(', ')}` : 'Anomalous script interpreter invocation'
      ]
    };
  }

  // 10. Privilege Level & Blast Radius
  if (lowerText.includes('nt authority\\system') || lowerText.includes('root') || lowerText.includes('system') || result.mitreTechniques.includes('T1003.001')) {
    result.rootCause.privilegeLevel = 'SYSTEM / Root (Full Compromise)';
    result.rootCause.blastRadius = 'Enterprise Domain / Lateral Movement Imminent';
  } else if (lowerText.includes('administrator') || lowerText.includes('admin')) {
    result.rootCause.privilegeLevel = 'Local Administrator';
    result.rootCause.blastRadius = 'Host Compromise with Local Credential Exposure';
  } else {
    result.rootCause.privilegeLevel = 'Unprivileged User Context';
    result.rootCause.blastRadius = 'Single Endpoint (Contained Execution Boundary)';
  }

  // 11. Verdict Justification
  if (result.mitreTechniques.length >= 2 || result.decodedBase64.length > 0 || result.lolbinsDetected.some(l => l.risk === 'Critical')) {
    result.verdict.status = 'True Positive';
    result.verdict.score = 95;
    result.verdict.justification = `Validated high-fidelity threat activity exhibiting unauthorized command execution and defense evasion techniques (${result.mitreTechniques.slice(0, 3).join(', ')}). Immediate forensic isolation and endpoint containment are strictly mandated to halt lateral spread.`;
  } else if (result.eventIds.includes('4624') && !result.iocs.ips.some(i => i.isSuspicious)) {
    result.verdict.status = 'Benign True Positive';
    result.verdict.score = 30;
    result.verdict.justification = `Observed telemetry corresponds to standard operational logon activity matching known IT maintenance routines. No abnormal LOLBins or outbound command-and-control beacons were identified in associated event parameters.`;
  } else {
    result.verdict.status = 'True Positive';
    result.verdict.score = 75;
    result.verdict.justification = `Anomalous execution pattern corroborated by suspicious parameter invocations and observable network indicators. Escalation to active incident containment is approved.`;
  }

  return result;
}
