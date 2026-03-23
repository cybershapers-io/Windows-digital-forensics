/**
 * routes/analysis.js
 * Streaming AI section analysis + per-row explanation.
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

// ── Streaming section analysis ────────────────────────────────────────────────
router.post('/section', async (req, res) => {
  if (!aiClient.isConfigured()) {
    return res.status(503).json({
      error: 'AI engine not configured. Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in .env and restart the server.'
    });
  }

  const { section, datasets, hostname, timestamp } = req.body;
  if (!section || !datasets) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const dataSummary = datasets.map(ds => {
    const sample = ds.rows.slice(0, 30);
    return `### ${ds.label} (${ds.rows.length} total records)\nColumns: ${ds.columns.join(', ')}\nSample data:\n${JSON.stringify(sample, null, 2)}`;
  }).join('\n\n');

  const prompt = `You are a senior Digital Forensics and Incident Response (DFIR) analyst and cybersecurity expert.

You are analysing forensic data collected from a Windows system.
- Hostname: ${hostname || 'Unknown'}
- Collection time: ${timestamp || 'Unknown'}
- Section: ${section.toUpperCase()} — ${SECTION_CONTEXT[section] || ''}

FORENSIC DATA:
${dataSummary}

Please provide a structured analysis in the following exact format:

## Executive Summary
[2-3 sentences describing what this data shows at a high level for C-suite executives]

## Key Findings
[List 3-8 specific notable findings from this data. For each finding include: what was found, why it matters, and its risk level (🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low / ⚪ Informational)]

## Indicators of Concern
[Any specific entries, values, or patterns that warrant further investigation or are suspicious]

## CIS Benchmark Guidance
[Relevant CIS Control recommendations (cite specific CIS Control numbers/names) applicable to what was found]

## NIST Framework Guidance
[Relevant NIST CSF functions and NIST SP 800-53 controls applicable to this section]

## Technical Remediation Steps
[Concrete, numbered, technically specific steps an administrator can follow to address findings. Include PowerShell commands, registry paths, or tool names where applicable]

## Risk Score
[Overall risk rating for this section: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL — with a 1-sentence justification]`;

  try {
    await aiClient.streamToSSE(prompt, 2000, res);
  } catch (err) {
    console.error('AI analysis error:', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    } else {
      res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
      res.end();
    }
  }
});

// ── Per-row explanation ───────────────────────────────────────────────────────
router.post('/explain', async (req, res) => {
  if (!aiClient.isConfigured()) {
    return res.status(503).json({
      error: 'AI engine not configured. Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in .env and restart the server.'
    });
  }

  const { rowData, context } = req.body;
  const prompt = `As a DFIR analyst, briefly explain this forensic data entry in 2-3 sentences. State if it looks suspicious or benign, and why.\n\nContext: ${context}\nData: ${JSON.stringify(rowData)}`;

  try {
    const text = await aiClient.complete(prompt, 400);
    res.json({ explanation: text || 'No explanation available' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;