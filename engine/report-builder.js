/**
 * Export-Ready Incident Report Builder
 * Generates formatted SOAR tickets for Jira, TheHive, ServiceNow, and Markdown.
 */

export function generateIncidentReport(parsedData) {
  const { attribution, agent, iocs, verdict, rootCause, mitreTechniques } = parsedData;
  const targetHost = agent.name || 'WKSTN-FIN-09';
  const targetIp = agent.ip || (iocs.ips.find(i => !i.isSuspicious)?.ip || '10.20.4.115');
  const severity = verdict.status === 'True Positive' ? 'HIGH / P1' : 'MEDIUM / P2';
  const threatName = attribution.type.split('/')[0].trim();
  const suspiciousIp = iocs.ips.find(i => i.isSuspicious)?.ip || '185.220.101.5';
  const primaryHash = iocs.hashes.sha256[0] || iocs.hashes.md5[0] || 'N/A';

  const ticketTitle = `[${severity}] - [${threatName}] - [${targetHost} / ${targetIp}]`;

  const incidentSummary = `A high-severity security incident was detected on host ${targetHost} (${targetIp}). Telemetry analysis confirmed unauthorized execution utilizing living-off-the-land techniques and obfuscated command-line arguments aligned with ${threatName}. The payload initiated outbound communications to suspicious infrastructure (${suspiciousIp}) with defense evasion mechanisms actively engaged. Privilege context was determined at ${rootCause.privilegeLevel}. Immediate containment was authorized.`;

  const validatedEvidence = `1. Process Execution: Anomalous process activity identified with execution flags (-enc, -w hidden, or process injection).
2. Network Artifacts: Outbound connection attempt observed to external C2 IP ${suspiciousIp}.
3. MITRE ATT&CK Mapping: ${mitreTechniques.join(', ')}.
4. Extracted Hashes: ${primaryHash}.
5. Obfuscation Level: Elevated command entropy (${parsedData.entropy.overall}) with base64 decoding corroborating stage-1 payload delivery.`;

  const approvedResponseActions = `1. Isolated host ${targetHost} from enterprise network via EDR isolation policy.
2. Null-routed remote command-and-control IP ${suspiciousIp} across border firewalls.
3. Terminated parent and child process trees associated with the suspicious execution.
4. Disabled associated Active Directory user/service credentials and revoked current Kerberos tickets.
5. Deployed tactical Sigma detection rule across SIEM to identify peer host lateral spread.`;

  const postIncidentRemediation = `1. Conduct dead-box memory acquisition and forensic timeline analysis on ${targetHost}.
2. Re-image infected endpoint from known-clean golden image prior to network re-admission.
3. Perform Active Directory audit for unauthorized persistence mechanisms (scheduled tasks, WMI subscriptions, registry Run keys).
4. Review perimeter proxy and DNS logs for historical beaconing patterns over the past 30 days.
5. Enforce PowerShell Constrained Language Mode (CLM) and AppLocker / WDAC application control policies.`;

  // Standard Markdown format
  const markdownReport = `### 5. Final Incident Report (Export-Ready Documentation)

* **Ticket Title:** ${ticketTitle}
* **Incident Summary:**
${incidentSummary}

* **Validated Evidence:**
${validatedEvidence}

* **Approved Response Actions:**
${approvedResponseActions}

* **Post-Incident Remediation:**
${postIncidentRemediation}`;

  // Jira Markup Format
  const jiraFormat = `h2. ${ticketTitle}

h3. Incident Summary
${incidentSummary}

h3. Validated Evidence
{noformat}
${validatedEvidence}
{noformat}

h3. Approved Response Actions
${approvedResponseActions}

h3. Post-Incident Remediation
${postIncidentRemediation}

*MITRE ATT&CK:* ${mitreTechniques.join(', ')}
*Assigned Tier:* Tier 3 Incident Response Hunter`;

  // TheHive JSON format
  const theHiveJson = {
    title: ticketTitle,
    description: incidentSummary,
    severity: verdict.status === 'True Positive' ? 3 : 2,
    tlp: 2, // TLP:AMBER
    pap: 2,
    tags: ['SOC-T3', 'Threat-Hunt', ...mitreTechniques],
    tasks: [
      { title: 'Host Isolation & Quarantine' },
      { title: 'Memory Dump Acquisition' },
      { title: 'Firewall Null-Route Deployment' },
      { title: 'AD Credential Reset' }
    ],
    observables: [
      ...iocs.ips.map(i => ({ dataType: 'ip', data: i.ip, message: i.type })),
      ...iocs.hashes.sha256.map(h => ({ dataType: 'hash', data: h, message: 'SHA256' })),
      ...iocs.domains.map(d => ({ dataType: 'domain', data: d.value, message: d.type }))
    ]
  };

  return {
    ticketTitle,
    incidentSummary,
    validatedEvidence,
    approvedResponseActions,
    postIncidentRemediation,
    markdown: markdownReport,
    jira: jiraFormat,
    theHiveJson: JSON.stringify(theHiveJson, null, 2)
  };
}
