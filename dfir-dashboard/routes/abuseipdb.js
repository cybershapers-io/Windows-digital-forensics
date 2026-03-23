/**
 * routes/abuseipdb.js
 * AbuseIPDB integration — checks external IPs found in forensic data
 *
 * Required .env variable:
 *   ABUSEIPDB_API_KEY=your_key_here   (get one at https://www.abuseipdb.com/api)
 */

const express = require('express');
const router = express.Router();
const https = require('https');

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Make an HTTPS GET request, return parsed JSON */
function httpsGet(url, headers) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Invalid JSON from AbuseIPDB')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('AbuseIPDB request timed out')); });
  });
}

/** Classify abuse score into a severity label */
function scoreSeverity(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 20) return 'MEDIUM';
  if (score > 0)  return 'LOW';
  return 'CLEAN';
}

/**
 * Extract public (non-RFC-1918 / non-loopback) IPs from any text blob.
 * Matches IPv4 addresses and deduplicates.
 */
function extractPublicIPs(text) {
  const ipRegex = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  const found = new Set();
  const matches = String(text).match(ipRegex) || [];
  matches.forEach(ip => {
    const parts = ip.split('.').map(Number);
    if (parts.some(p => p > 255)) return;          // invalid octet
    const [a, b] = parts;
    // Skip private / reserved ranges
    if (a === 10) return;
    if (a === 172 && b >= 16 && b <= 31) return;
    if (a === 192 && b === 168) return;
    if (a === 127) return;
    if (a === 0)   return;
    if (a === 169 && b === 254) return;             // link-local
    if (a >= 224)  return;                          // multicast / reserved
    found.add(ip);
  });
  return [...found];
}

// ── Routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/abuseipdb/check
 * Body: { ips: string[] }          — explicit list of IPs to check
 *  OR   { text: string }           — raw text; IPs will be extracted automatically
 *  OR   { datasets: [...] }        — section datasets; IPs extracted from all values
 *
 * Returns: { results: [ { ip, abuseScore, totalReports, countryCode,
 *                          isp, domain, usageType, severity,
 *                          lastReportedAt, isWhitelisted } ] }
 */
router.post('/check', async (req, res) => {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey || apiKey === 'your_abuseipdb_api_key_here') {
    return res.status(503).json({
      error: 'AbuseIPDB not configured. Add ABUSEIPDB_API_KEY to your .env file.',
      hint: 'Get a free API key at https://www.abuseipdb.com/api'
    });
  }

  // Collect IPs to check
  let ips = [];

  if (Array.isArray(req.body.ips) && req.body.ips.length) {
    ips = req.body.ips.map(ip => ip.trim()).filter(Boolean);
  } else if (req.body.text) {
    ips = extractPublicIPs(req.body.text);
  } else if (Array.isArray(req.body.datasets)) {
    // Extract from all cell values across all datasets
    const blob = req.body.datasets
      .flatMap(ds => ds.rows || [])
      .flatMap(row => Object.values(row))
      .join(' ');
    ips = extractPublicIPs(blob);
  }

  // Deduplicate and cap at 50 IPs per request
  ips = [...new Set(ips)].slice(0, 50);

  if (ips.length === 0) {
    return res.json({ results: [], message: 'No public IP addresses found in the provided data.' });
  }

  // Check each IP against AbuseIPDB (with concurrency cap of 5)
  const CONCURRENCY = 5;
  const results = [];

  for (let i = 0; i < ips.length; i += CONCURRENCY) {
    const batch = ips.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(ip => checkSingleIP(ip, apiKey))
    );
    results.push(...batchResults);
  }

  res.json({ results });
});

/**
 * GET /api/abuseipdb/status
 * Returns whether AbuseIPDB is configured
 */
router.get('/status', (req, res) => {
  const configured = !!(
    process.env.ABUSEIPDB_API_KEY &&
    process.env.ABUSEIPDB_API_KEY !== 'your_abuseipdb_api_key_here'
  );
  res.json({ configured });
});

async function checkSingleIP(ip, apiKey) {
  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const json = await httpsGet(url, {
      'Key': apiKey,
      'Accept': 'application/json'
    });

    if (json.errors) {
      return { ip, error: json.errors[0]?.detail || 'AbuseIPDB error' };
    }

    const d = json.data || {};
    const score = d.abuseConfidenceScore ?? 0;
    return {
      ip,
      abuseScore:      score,
      totalReports:    d.totalReports ?? 0,
      countryCode:     d.countryCode ?? '—',
      isp:             d.isp ?? '—',
      domain:          d.domain ?? '—',
      usageType:       d.usageType ?? '—',
      isWhitelisted:   d.isWhitelisted ?? false,
      lastReportedAt:  d.lastReportedAt ?? null,
      severity:        scoreSeverity(score),
      hostnames:       (d.hostnames || []).slice(0, 3)
    };
  } catch (err) {
    return { ip, error: err.message };
  }
}

module.exports = router;
module.exports.extractPublicIPs = extractPublicIPs;
