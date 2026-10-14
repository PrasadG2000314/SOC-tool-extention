/**
 * SIEM Query & Threat Hunting Generator
 * Produces tuned Splunk SPL, Microsoft Defender KQL, and Elastic Lucene/EQL
 * along with precise Wireshark/PCAP network correlation filters.
 */

export function generateHuntingQueries(parsedData) {
  const { iocs, lolbinsDetected, eventIds } = parsedData;
  const primaryIp = iocs.ips.find(i => i.isSuspicious)?.ip || (iocs.ips[0]?.ip || '10.0.0.1');
  const primaryHash = iocs.hashes.sha256[0] || iocs.hashes.md5[0] || '';
  const primaryBin = lolbinsDetected[0]?.name || 'powershell.exe';
  const primaryDomain = iocs.domains[0]?.value || 'c2-domain.com';

  // 1. Splunk SPL Query (Process Lineage & Network Beaconing)
  const splunkQuery = `index=* sourcetype="wineventlog:sysmon" (EventCode=1 OR EventCode=3)
| eval Process=lower(coalesce(CommandLine, process_exec, Image))
| search (Process="*${primaryBin}*" OR DestinationIp="${primaryIp}" ${primaryHash ? `OR Hashes="*${primaryHash}*"` : ''})
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(ParentImage) as Parents values(CommandLine) as Cmds by host, User, DestinationIp, DestinationPort
| where count > 0
| sort - count`;

  // 2. Microsoft Sentinel / Defender for Endpoint KQL
  const kqlQuery = `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "${primaryBin}" or ProcessCommandLine has_any ("-enc", "downloadstring", "bypass", "${primaryIp}")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine, MD5, SHA256
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteIP == "${primaryIp}" or RemoteUrl has "${primaryDomain.replace(/https?:\/\//, '')}"
    | project DeviceName, RemoteIP, RemotePort, RemoteUrl
) on DeviceName
| order by Timestamp desc`;

  // 3. Elastic Lucene / EQL Hunting Query
  const elasticQuery = `sequence by host.id with maxspan=5m
  [process where event.code == "1" and
   (process.name : ("*${primaryBin}*", "*certutil.exe*", "*mshta.exe*", "*rundll32.exe*") or
    process.command_line : ("*bypass*", "*-enc*", "*IEX*", "*${primaryIp}*"))]
  [network where event.code == "3" and
   destination.ip == "${primaryIp}"]`;

  // 4. PCAP / Wireshark Correlation Filters
  const wiresharkFilter = iocs.ips.some(i => i.isSuspicious)
    ? `ip.addr == ${primaryIp} && (tcp.port == 443 || tcp.port == 80 || tcp.port == 8080 || tcp.port == 8443)`
    : `(http.request.method == "POST" || tls.handshake.type == 1) && !(ip.dst == 10.0.0.0/8 || ip.dst == 192.168.0.0/16)`;

  const pcapCorrelationGuide = {
    wiresharkFilter,
    httpInspection: `Search for anomalous HTTP POST requests with irregular User-Agents (e.g., standard curl, python-requests, or hardcoded C2 profiles). Inspect URI patterns matching Malleable C2 jitter patterns.`,
    tlsInspection: `Examine the TLS Client Hello: calculate JA3/JA4 fingerprint against standard browser baselines. Look for self-signed certificates, SNI mismatches, or suspicious certificate issuer DNs.`,
    beaconingAnalysis: `Correlate packet inter-arrival times (delta times) to identify periodic beaconing with configured jitter (e.g. 10% - 25% sleep variance). Look for persistent small payloads (400-800 bytes) indicating keep-alive heartbeats.`
  };

  return {
    splunk: splunkQuery.trim(),
    kql: kqlQuery.trim(),
    elastic: elasticQuery.trim(),
    pcap: pcapCorrelationGuide
  };
}
