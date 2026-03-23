const express = require('express');
const router = express.Router();
const multer = require('multer');
const AdmZip = require('adm-zip');
const path = require('path');
const fs = require('fs');
const { parse } = require('csv-parse/sync');
const { v4: uuidv4 } = require('uuid');

const uploadsDir = path.join(__dirname, '..', 'uploads');

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => cb(null, `${uuidv4()}-${file.originalname}`)
});

const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB

// Multer's fileSize limit uses a signed 32-bit int internally — values
// above ~2.1 GB overflow to negative, causing false LIMIT_FILE_SIZE errors.
// We set Infinity to bypass Multer's counter and enforce the cap ourselves.
const upload = multer({
  storage,
  limits: { fileSize: Infinity },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === 'application/zip' ||
      file.mimetype === 'application/x-zip-compressed' ||
      file.mimetype === 'application/octet-stream' ||
      file.originalname.endsWith('.zip')
    ) {
      cb(null, true);
    } else {
      cb(new Error('Only ZIP files are allowed'));
    }
  }
});

// Enforce 2 GB cap via Content-Length, then surface Multer errors as clean JSON
function uploadMiddleware(req, res, next) {
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);
  if (contentLength > MAX_FILE_BYTES) {
    return res.status(413).json({ error: 'File too large. Maximum allowed size is 2 GB.' });
  }
  upload.single('zipfile')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'File too large. Maximum allowed size is 2 GB.' });
      }
      return res.status(400).json({ error: err.message });
    }
    next();
  });
}

// CSV file → section name mapping
const CSV_MAP = {
  'IPConfiguration.csv':         { section: 'network',      label: 'IP Configuration' },
  'OpenTCPConnections.csv':      { section: 'network',      label: 'Open TCP Connections' },
  'DNSCache.csv':                { section: 'network',      label: 'DNS Cache' },
  'NetworkShares.csv':           { section: 'network',      label: 'Network Shares' },
  'SMBShares.csv':               { section: 'network',      label: 'SMB Shares' },
  'OfficeConnections.csv':       { section: 'network',      label: 'Office Connections' },
  'RDPSessions.csv':             { section: 'network',      label: 'RDP Sessions' },
  'RemotelyOpenedFiles.csv':     { section: 'network',      label: 'Remotely Opened Files' },
  'LocalUsers.csv':              { section: 'users',        label: 'Local Users' },
  'ActiveUsers.csv':             { section: 'users',        label: 'Active Users' },
  'AutoRun.csv':                 { section: 'persistence',  label: 'AutoRun Entries' },
  'Win32RegRunKey.csv':          { section: 'persistence',  label: 'Win32 Registry Run Keys' },
  'ScheduledTasks.csv':          { section: 'persistence',  label: 'Scheduled Tasks' },
  'ScheduledTasksRunInfo.csv':   { section: 'persistence',  label: 'Scheduled Tasks Run Info' },
  'WMIConsumers.csv':            { section: 'persistence',  label: 'WMI Consumers' },
  'WMIFilters.csv':              { section: 'persistence',  label: 'WMI Filters' },
  'Processes.csv':               { section: 'processes',    label: 'Running Processes' },
  'ProcessList.csv':             { section: 'processes',    label: 'Process List (with hashes)' },
  'RunningServices.csv':         { section: 'processes',    label: 'Running Services' },
  'InstalledPrograms.csv':       { section: 'software',     label: 'Installed Programs' },
  'InstalledUpdates.csv':        { section: 'software',     label: 'Installed Updates' },
  'Drivers.csv':                 { section: 'software',     label: 'Installed Drivers' },
  'SecurityEvents.csv':          { section: 'events',       label: 'Security Events' },
  'USBDevices.csv':              { section: 'devices',      label: 'USB Devices' },
  'ConnectedDevices.csv':        { section: 'devices',      label: 'Connected Devices' },
  'ShadowCopy.csv':              { section: 'artifacts',    label: 'Shadow Copies' },
  'LnkDetails.csv':              { section: 'artifacts',    label: 'LNK File Details' },
  'RecentFiles.csv':             { section: 'artifacts',    label: 'Recent Files' },
  'FirewallRules.csv':           { section: 'network',      label: 'Firewall Rules' },
  'DefenderExclusions.csv':      { section: 'security',     label: 'Defender Exclusions' },
  'MPLogs.csv':                  { section: 'security',     label: 'Windows Defender Logs' },
  'ShimCache.csv':               { section: 'artifacts',    label: 'ShimCache' },
  'Shellbags.csv':               { section: 'artifacts',    label: 'Shellbags' },
  'Prefetch.csv':                { section: 'artifacts',    label: 'Prefetch Files' },
  'PrefetchFiles.csv':           { section: 'artifacts',    label: 'Prefetch File Listing' },
  'Amcache.csv':                 { section: 'artifacts',    label: 'Amcache' },
  'UserAssist.csv':              { section: 'artifacts',    label: 'UserAssist' },
  'RestorePoints.csv':           { section: 'artifacts',    label: 'System Restore Points' },
};

function parseCSV(content) {
  try {
    const records = parse(content, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
      relax_column_count: true,
      relax_quotes: true,
      skip_records_with_error: true
    });
    return records;
  } catch {
    return [];
  }
}

function extractMetaFromPath(zipEntryName) {
  // Try to pull hostname & timestamp from folder name like DFIR-HOSTNAME-2024-01-15_10-30-00
  const match = zipEntryName.match(/DFIR-([^/\\]+?)-(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})/);
  if (match) return { hostname: match[1], timestamp: match[2].replace(/_/, ' ').replace(/-/g, ':').slice(0, 16) };
  return null;
}

router.post('/', uploadMiddleware, async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const zip = new AdmZip(req.file.path);
    const entries = zip.getEntries();

    let meta = { hostname: 'Unknown Host', timestamp: new Date().toISOString().slice(0, 16) };
    const sections = {};
    const rawTexts = {};
    let totalCSVs = 0;

    // Try to get meta from first entry path
    for (const entry of entries) {
      const m = extractMetaFromPath(entry.entryName);
      if (m) { meta = m; break; }
    }

    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const fileName = path.basename(entry.entryName);
      const ext = path.extname(fileName).toLowerCase();

      if (ext === '.csv') {
        const content = entry.getData().toString('utf8');
        const rows = parseCSV(content);
        const mapping = CSV_MAP[fileName];

        if (mapping && rows.length > 0) {
          const { section, label } = mapping;
          if (!sections[section]) sections[section] = [];
          sections[section].push({ id: uuidv4(), label, filename: fileName, rows, columns: Object.keys(rows[0] || {}) });
          totalCSVs++;
        } else if (rows.length > 0) {
          // Unmapped CSV — put into 'other'
          if (!sections['other']) sections['other'] = [];
          sections['other'].push({ id: uuidv4(), label: fileName.replace('.csv',''), filename: fileName, rows, columns: Object.keys(rows[0] || {}) });
          totalCSVs++;
        }
      } else if (ext === '.txt' && entry.getData().length < 200000) {
        rawTexts[fileName] = entry.getData().toString('utf8').slice(0, 5000);
      }
    }

    // Cleanup uploaded zip
    fs.unlink(req.file.path, () => {});

    res.json({
      success: true,
      meta,
      sections,
      rawTexts,
      stats: {
        totalCSVs,
        totalSections: Object.keys(sections).length,
        totalRows: Object.values(sections).flat().reduce((a, t) => a + t.rows.length, 0)
      }
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
