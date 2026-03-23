require('dotenv').config();
const express = require('express');
const path    = require('path');
const fs      = require('fs');

const uploadRouter    = require('./routes/upload');
const analysisRouter  = require('./routes/analysis');
const riskRouter      = require('./routes/riskAnalysis');
const abuseipdbRouter = require('./routes/abuseipdb');
const aiClient        = require('./routes/aiClient');

const app  = express();
const PORT = process.env.PORT || 3000;

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Allow large file uploads up to 10 minutes
app.use((req, res, next) => {
  if (req.path === '/api/upload') {
    req.setTimeout(10 * 60 * 1000);
    res.setTimeout(10 * 60 * 1000);
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/upload',    uploadRouter);
app.use('/api/analysis',  analysisRouter);
app.use('/api/risks',     riskRouter);
app.use('/api/abuseipdb', abuseipdbRouter);

// ── Health / status endpoint ──────────────────────────────────────────────────
// The frontend polls this on load to know which engines are active.
app.get('/api/health', (req, res) => {
  const backend  = aiClient.getBackend();
  const abuseKey = (process.env.ABUSEIPDB_API_KEY || '').trim();

  res.json({
    status:    'ok',
    version:   '2.0.0',
    ai:        !!backend,
    aiEngine:  backend ? backend.type  : null,   // 'lmstudio' | 'openai' | 'anthropic' | null
    aiLabel:   backend ? backend.label : null,   // 'LM Studio' | 'OpenAI' | 'Anthropic' | null
    aiModel:   backend ? backend.model : null,
    aiBase:    backend && backend.type === 'lmstudio' ? backend.base : null,
    abuseipdb: !!(abuseKey && abuseKey !== 'your_abuseipdb_api_key_here')
  });
});

// Serve index for all other routes (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Startup banner ────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const backend  = aiClient.getBackend();
  const abuseKey = (process.env.ABUSEIPDB_API_KEY || '').trim();
  const hasAbuse = !!(abuseKey && abuseKey !== 'your_abuseipdb_api_key_here');

  console.log(`\n╔════════════════════════════════════════════╗`);
  console.log(`║   DFIR Intelligence Dashboard  v2.0.0     ║`);
  console.log(`╚════════════════════════════════════════════╝`);
  console.log(`  → http://localhost:${PORT}\n`);

  if (!backend) {
    console.log(`  ✗  AI Engine   : not configured`);
    console.log(`     → Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in .env`);
  } else if (backend.type === 'lmstudio') {
    console.log(`  ✓  AI Engine   : LM Studio (local)`);
    console.log(`     URL         : ${backend.base}`);
    console.log(`     Model       : ${backend.model}`);
  } else if (backend.type === 'openai') {
    console.log(`  ✓  AI Engine   : OpenAI`);
    console.log(`     Model       : ${backend.model}`);
  } else if (backend.type === 'anthropic') {
    console.log(`  ✓  AI Engine   : Anthropic Claude`);
    console.log(`     Model       : ${backend.model}`);
  }

  console.log(hasAbuse
    ? `  ✓  AbuseIPDB   : enabled`
    : `  ✗  AbuseIPDB   : not configured (set ABUSEIPDB_API_KEY in .env)`
  );
  console.log('');
});
