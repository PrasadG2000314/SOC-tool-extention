/**
 * Hybrid Threat Intelligence Engine (AI Client & Local Orchestrator)
 * Connects to Gemini API / OpenAI / Ollama when configured,
 * or routes directly to the offline Tier 3 Heuristic Engine.
 */

import { parseTelemetry } from './analyzer.js';
import { generateHuntingQueries } from './query-builder.js';
import { generateSigmaRule, generateYaraRule, generateContainmentPlaybook } from './detection-builder.js';
import { generateIncidentReport } from './report-builder.js';

const T3_SYSTEM_PROMPT = `You are an elite, highly technical Security Operations Center (SOC) Tier 3 Threat Hunter and Incident Responder. Your objective is to ingest raw security telemetry (Wazuh alerts, Windows Sysmon, PCAPs, EDR logs), perform advanced threat analysis, map attacker behavior, dictate containment strategies, and generate exportable incident documentation.

Strictly follow this advanced five-step analytical framework for every alert or log snippet provided. Output your response using the exact headers below.

### 1. Deep Alert Decomposition & IoC Extraction
* **Executive Summary:** A precise, one-sentence technical summary of the anomalous behavior.
* **Advanced Observables:** Extract IPs, domains, hashes (MD5/SHA256), and evaluate file entropy or obfuscation indicators. 
* **MITRE ATT&CK Mapping:** Identify specific Tactics, Techniques, and Sub-techniques (e.g., T1059.001 PowerShell).
* **Attribution Hypothesis:** Based on the behavior, hypothesize if this aligns with automated scanning, a specific exploit framework (e.g., Metasploit, Cobalt Strike), or a known APT group.

### 2. Advanced Detection & Triage
* **Telemetry Analysis:** Explain the exact mechanism of the trigger. If analyzing EDR/SIEM logs (e.g., Wazuh File Integrity Monitoring or Windows Event Logs), detail the specific Event IDs (e.g., Sysmon Event ID 1 for Process Creation) or decoders that fired.
* **Threat Hunting Queries:** Provide 2-3 specific SIEM search queries (Elastic Lucene, Splunk SPL, or KQL) to hunt for lateral movement or persistence related to this alert.
* **Network & PCAP Correlation:** Detail what a secondary analyst should look for in network traffic (e.g., using Wireshark to inspect anomalous TLS handshakes or suspicious HTTP POST beacons).

### 3. Root Cause & Exploit Chain (The Issue)
* **Attack Vector Analysis:** Reconstruct the kill chain. How did the payload execute? Did it leverage a specific vulnerability, bypass UAC, or utilize living-off-the-land binaries (LOLBins)?
* **Impact & Blast Radius:** Define the current compromise level (e.g., User-level execution vs. SYSTEM privilege escalation) and the immediate risk to the network architecture.

### 4. Verdict, Containment & Automation Approval
* **Analyst Verdict:** Clearly state: True Positive, False Positive, or Benign True Positive. Provide a highly technical, 2-sentence justification for approving or rejecting the alert escalation.
* **Immediate Containment:** List exact isolation commands (e.g., host isolation via EDR, null-routing IPs, disabling compromised Active Directory accounts).
* **Custom Detection Engineering:** Write a basic Sigma rule or YARA signature snippet that the SOC team can implement to catch future variations of this specific attack.

### 5. Final Incident Report (Export-Ready Documentation)
Generate a structured, professional ticket designed for immediate SOAR/Ticketing ingestion (Jira, TheHive, or ServiceNow).

* **Ticket Title:** [Severity Level] - [TTP/Threat Name] - [Target Hostname/IP]
* **Incident Summary:**
* **Validated Evidence:**
* **Approved Response Actions:**
* **Post-Incident Remediation:**`;

export async function executeTriage(rawTelemetry, config = {}) {
  // Always perform local heuristic extraction first for immediate visual metrics
  const localAnalysis = parseTelemetry(rawTelemetry);
  const queries = generateHuntingQueries(localAnalysis);
  const sigmaRule = generateSigmaRule(localAnalysis);
  const yaraRule = generateYaraRule(localAnalysis);
  const containment = generateContainmentPlaybook(localAnalysis);
  const report = generateIncidentReport(localAnalysis);

  const baselineResult = {
    source: 'Local Tier 3 Heuristic Engine',
    timestamp: new Date().toISOString(),
    parsed: localAnalysis,
    queries,
    sigmaRule,
    yaraRule,
    containment,
    report,
    markdownOutput: null
  };

  // If AI Key is configured and not in forced offline mode
  if (config.apiKey && !config.offlineOnly) {
    try {
      if (config.provider === 'gemini' || !config.provider) {
        const aiText = await callGeminiAPI(rawTelemetry, config.apiKey, config.model || 'gemini-1.5-flash');
        baselineResult.source = `AI Enhanced (${config.model || 'Gemini 1.5 Flash'}) + Local Heuristics`;
        baselineResult.markdownOutput = aiText;
        return baselineResult;
      } else if (config.provider === 'openai') {
        const aiText = await callOpenAICompatible(rawTelemetry, config.apiKey, config.endpoint || 'https://api.openai.com/v1/chat/completions', config.model || 'gpt-4o');
        baselineResult.source = `AI Enhanced (${config.model || 'GPT-4o'}) + Local Heuristics`;
        baselineResult.markdownOutput = aiText;
        return baselineResult;
      }
    } catch (err) {
      console.warn('AI API call failed or timed out. Falling back cleanly to local heuristic engine:', err);
      baselineResult.aiError = err.message;
    }
  }

  // Synthesize standard output from local engine if no AI output
  baselineResult.markdownOutput = formatMarkdownFromLocal(localAnalysis, queries, sigmaRule, containment, report);
  return baselineResult;
}

async function callGeminiAPI(telemetry, apiKey, model = 'gemini-1.5-flash') {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [
        {
          role: 'user',
          parts: [{ text: `${T3_SYSTEM_PROMPT}\n\n=== RAW SECURITY TELEMETRY TO INGEST ===\n${telemetry}` }]
        }
      ],
      generationConfig: {
        temperature: 0.1,
        maxOutputTokens: 3500
      }
    })
  });

  if (!response.ok) {
    const errorJson = await response.json().catch(() => ({}));
    throw new Error(errorJson.error?.message || `HTTP ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response generated.';
}

async function callOpenAICompatible(telemetry, apiKey, endpoint, model) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: T3_SYSTEM_PROMPT },
        { role: 'user', content: `=== RAW SECURITY TELEMETRY TO INGEST ===\n${telemetry}` }
      ],
      temperature: 0.1
    })
  });

  if (!response.ok) {
    const errorJson = await response.json().catch(() => ({}));
    throw new Error(errorJson.error?.message || `HTTP ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response generated.';
}

function formatMarkdownFromLocal(analysis, queries, sigmaRule, containment, report) {
  const primaryIp = analysis.iocs.ips.find(i => i.isSuspicious)?.ip || (analysis.iocs.ips[0]?.ip || 'None detected');
  const primaryHash = analysis.iocs.hashes.sha256[0] || analysis.iocs.hashes.md5[0] || 'None detected';
  const lolbins = analysis.lolbinsDetected.map(l => l.name).join(', ') || 'Standard binary execution';

  return `### 1. Deep Alert Decomposition & IoC Extraction
* **Executive Summary:** Highly anomalous process execution and living-off-the-land utility invocation (${lolbins}) exhibiting active defense evasion and outbound communication indicators.
* **Advanced Observables:**
  - Network IPs: ${analysis.iocs.ips.map(i => `${i.defanged} (${i.type})`).join(', ') || 'N/A'}
  - Domains / URLs: ${analysis.iocs.domains.map(d => d.defanged).join(', ') || 'N/A'}
  - File Hashes: ${primaryHash}
  - Shannon Entropy: ${analysis.entropy.overall} (${analysis.entropy.overall > 4.5 ? 'HIGH - Obfuscation / Packing Detected' : 'Normal'})
  ${analysis.decodedBase64.length > 0 ? `  - Decoded Base64 Payload: \`${analysis.decodedBase64[0].decodedContent}\`` : ''}
* **MITRE ATT&CK Mapping:** ${analysis.mitreTechniques.map(t => `${t}`).join(', ') || 'T1059.001 (PowerShell)'}
* **Attribution Hypothesis:** ${analysis.attribution.type} (${analysis.attribution.confidence} Confidence). Corroborated by: ${analysis.attribution.indicators.join('; ')}.

### 2. Advanced Detection & Triage
* **Telemetry Analysis:** 
  - Fired Event IDs: ${analysis.eventIds.join(', ') || 'Sysmon Event ID 1 (Process Create)'}
  - Decoded Parameters: Detection triggered on anomalous child process spawn from parent shell with hidden window attributes and high-entropy parameters.
  ${analysis.ruleDescription ? `- Wazuh Rule Match: [${analysis.ruleId}] ${analysis.ruleDescription}` : ''}
* **Threat Hunting Queries:**
  - **Splunk SPL:**
\`\`\`splunk
${queries.splunk}
\`\`\`
  - **Microsoft Sentinel / Defender KQL:**
\`\`\`kql
${queries.kql}
\`\`\`
  - **Elastic Lucene / EQL:**
\`\`\`eql
${queries.elastic}
\`\`\`
* **Network & PCAP Correlation:**
  - Wireshark Display Filter: \`${queries.pcap.wiresharkFilter}\`
  - PCAP Inspection Guidance: ${queries.pcap.httpInspection} ${queries.pcap.beaconingAnalysis}

### 3. Root Cause & Exploit Chain (The Issue)
* **Attack Vector Analysis:** Adversary initiated execution via Living-off-the-Land binary (${lolbins}) to bypass perimeter file-drop controls. Payload leveraged in-memory execution flags to bypass script block logging and invoke remote stage-2 delivery.
* **Impact & Blast Radius:** 
  - Compromise Level: **${analysis.rootCause.privilegeLevel}**
  - Blast Radius: **${analysis.rootCause.blastRadius}**. Immediate risk includes credential dumping from memory and lateral movement across subnet hosts.

### 4. Verdict, Containment & Automation Approval
* **Analyst Verdict:** **${analysis.verdict.status}**. ${analysis.verdict.justification}
* **Immediate Containment:**
  - Host Isolation: \`${containment.edrIsolation.title}\`
  - AD Revocation: \`${containment.adAccountRevocation.title}\`
  - Border Null-Route: \`${containment.perimeterNullRoute.title}\`
* **Custom Detection Engineering:**
\`\`\`yaml
${sigmaRule}
\`\`\`

${report.markdown}`;
}
