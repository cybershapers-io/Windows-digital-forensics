# Windows Digital Forensics Toolkit

A Windows incident response toolkit for SOC analysts and digital forensic investigators. It consists of two components that work together: a PowerShell triage collector and a Node.js web dashboard with AI-powered analysis.

---

## Repository Structure

```
windows-digital-forensics/
├── forensics-v2.ps1        ← PowerShell DFIR triage collector (run on target host)
├── forensics-script.md     ← Full documentation for the PowerShell script
└── dfir-dashboard/         ← Node.js web dashboard for analysing collected evidence
    ├── server.js
    ├── routes/
    ├── public/
    └── README.md           ← Full dashboard setup and usage guide
```

---

## Components

### forensics-v2.ps1

A live-response PowerShell script that collects a broad set of forensic artifacts from a Windows workstation or server. It exports structured CSV files for SIEM ingestion and optionally compresses the entire case folder into a ZIP for transport.

**Collected artifacts include:** running processes and hashes, network connections, DNS cache, persistence mechanisms (autoruns, scheduled tasks, WMI subscriptions), Security Event Log, browser artifacts, Prefetch, Amcache, ShimCache, Shellbags, SRUM, USB devices, Defender exclusions, and more.

See [forensics-script.md](forensics-script.md) for full documentation.

### dfir-dashboard

A local web application for ingesting and analysing the ZIP produced by `forensics-v2.ps1`. Features include interactive sortable tables, AI-powered risk analysis with CIS Controls v8 and NIST SP 800-53 compliance mappings, AbuseIPDB IP reputation checks, and support for both Anthropic Claude (cloud) and LM Studio (local, air-gapped).

See [dfir-dashboard/README.md](dfir-dashboard/README.md) for full setup and usage instructions.

---

## Quick Start

### 1 — Collect evidence (on the target Windows host)

```powershell
# Run as Administrator for full coverage
.\forensics-v2.ps1

# Extended event window (last 7 days, saved to a specific path)
.\forensics-v2.ps1 -sw 7 -OutputPath C:\Evidence
```

This produces `DFIR-<HOSTNAME>-<TIMESTAMP>.zip`.

### 2 — Analyse evidence (on your analyst workstation)

```bash
cd dfir-dashboard
npm install
cp .env.example .env   # fill in API keys
npm start
```

Open [http://localhost:3000](http://localhost:3000), upload the ZIP, and begin analysis.

---

## Requirements

| Component | Requirement |
|---|---|
| forensics-v2.ps1 | Windows PowerShell 5.1+ — run as Administrator for full artifact coverage |
| dfir-dashboard | Node.js >= 18.x, npm >= 9.x |
| AI analysis (cloud) | Anthropic API key |
| AI analysis (local) | LM Studio >= 0.3.x with a loaded model |
| IP reputation | AbuseIPDB API key (free tier: 1,000 checks/day) |

---

## Security Notice

The dashboard processes sensitive forensic evidence. It is designed for use on a local or isolated analyst network and must not be exposed to the public internet without authentication and TLS termination. See the [production deployment section](dfir-dashboard/README.md#production-deployment) for hardening guidance.

---

## License

MIT — see [LICENSE](LICENSE) for details.
Copyright (c) 2026 Jordy Lok
