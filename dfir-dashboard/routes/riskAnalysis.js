/**
 * routes/riskAnalysis.js
 * Structured AI Risk Intelligence — returns JSON risks
 * mapped to CIS Controls v8 and NIST SP 800-53.
 * Works with LM Studio, OpenAI, and Anthropic via aiClient.js
 */

const express  = require('express');
const router   = express.Router();
const aiClient = require('./aiClient');

const SECTION_CONTEXT = {
  network:     'Network activity, TCP connections, DNS cache, SMB shares, RDP sessions, firewall rules',
  users:       'Local and active user accounts on the system',
  persistence: 'Persistence mechanisms: autorun entries, scheduled tasks, registry run keys, WMI subscriptions',
  processes:   'Running processes with executable hashes and command lines',
  software:    'Installed software, drivers, and Windows updates',
  events:      'Windows Security Event Log entries',
  devices:     'USB and connected hardware devices',
  artifacts:   'Forensic artifacts: LNK files, Prefetch, ShimCache, Shellbags, recent files',
  security:    'Windows Defender logs and exclusions',
  other:       'Additional collected data'
};

/**
 * POST /api/risks/analyse
 * Body: { section, datasets, hostname, timestamp }
 * Returns: { summary, risks: [{severity, title, description, affected, cis_controls, remediation, nist}] }
 */
router.post('/analyse', async (req, res) => {
  if (!aiClient.isConfigured()) {
    return res.status(503).json({
      error: 'AI engine not configured. Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in .env and restart the server.'
    });
  }

  const { section, datasets, hostname, timestamp } = req.body;
  if (!section || !datasets) {
    return res.status(400).json({ error: 'Missing required fields: section, datasets' });
  }

  const dataSummary = datasets.map(ds => {
    const sample = ds.rows.slice(0, 25);
    return `### ${ds.label} (${ds.rows.length} total records)\nColumns: ${ds.columns.join(', ')}\nSample data:\n${JSON.stringify(sample, null, 2)}`;
  }).join('\n\n');

  const prompt = `You are a senior DFIR analyst and CIS Controls expert. Analyse the forensic data below and identify security risks.

System: ${hostname || 'Unknown'} | Collected: ${timestamp || 'Unknown'}
Section: ${section.toUpperCase()} — ${SECTION_CONTEXT[section] || 'Forensic data'}

FORENSIC DATA:
${dataSummary}

Return ONLY valid JSON in exactly this structure (no markdown fences, no preamble, no extra text):
{
  "summary": "2-sentence executive summary of what this section reveals",
  "risks": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "Concise risk title (under 65 chars)",
      "description": "What was found and why it poses a security risk (2-4 sentences). Be specific — reference actual values from the data.",
      "affected": "Specific file names, process names, IPs, users, registry keys, or other values from the data",
      "cis_controls": ["CIS Control X.Y: Control Name", "CIS Control Y.Z: Control Name"],
      "remediation": [
        "Step 1: specific action",
        "Step 2: PowerShell or registry command if applicable, e.g. \`Remove-ScheduledTask -TaskName 'X'\`",
        "Step 3: verification or monitoring step"
      ],
      "nist": "NIST SP 800-53 control(s), e.g. AC-2, CM-6, SI-3"
    }
  ]
}

Severity criteria:
- CRITICAL: Active exploitation, credential exposure, data exfiltration indicators, disabled AV/EDR, active C2
- HIGH: Malware indicators, unusual persistence, suspicious lateral movement, privilege escalation attempts
- MEDIUM: Suspicious but unconfirmed activity, weak configurations, unnecessary attack surface exposure
- LOW: Minor hardening opportunities, missing patches, audit gaps
- INFO: Normal findings worth documenting, no immediate risk

Always cite specific CIS Controls v8 by number and name. Return 3-8 risks. Provide actionable remediation steps.`;

  try {
    const raw   = await aiClient.complete(prompt, 3500);
    const clean = raw.replace(/^```(?:json)?\s*/m, '').replace(/\s*```$/m, '').trim();

    let result;
    try {
      result = JSON.parse(clean);
    } catch {
      // Some local models wrap the JSON in extra text — try to extract it
      const match = clean.match(/\{[\s\S]*\}/);
      if (match) {
        result = JSON.parse(match[0]);
      } else {
        throw new Error('AI returned malformed JSON. Try a larger or more capable model.');
      }
    }

    if (!result.risks)   result.risks   = [];
    if (!result.summary) result.summary = '';

    res.json(result);
  } catch (err) {
    console.error('Risk analysis error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;