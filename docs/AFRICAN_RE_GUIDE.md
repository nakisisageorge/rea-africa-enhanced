# rea-africa-enhanced — African Reverse Engineering Guide

## Overview

This guide covers using rea-africa-enhanced for African fintech reverse engineering tasks, including mobile money app analysis, malware detection, and threat intelligence.

## Quick Start

### Prerequisites

- Node.js 22+ (see `.nvmrc`)
- npm 11+ (see `package.json#packageManager`)
- Optional: Ghidra, IDA Pro, Frida for native analysis
- Optional: Android SDK for dynamic analysis

### Installation

```bash
# Install globally
npm install -g rea-africa-enhanced

# Or use via npx (recommended for latest)
npx rea-africa-enhanced@latest mcp

# Verify installation
rea --version
```

### Configuration

Create `~/.rea-africa-enhanced/config.json`:

```json
{
  "profiles": {
    "autoDetect": true,
    "preferredProviders": ["mpesa", "mtn-momo", "airtel-money"]
  },
  "malware": {
    "scanOnAnalyze": true,
    "severityThreshold": "high",
    "updateSignatures": true
  },
  "mcp": {
    "defaultTransport": "stdio",
    "httpPort": 3000,
    "rateLimit": 100
  },
  "benchmark": {
    "enabled": true,
    "threshold": 5,
    "storagePath": "~/.rea-africa-enhanced/benchmarks.db"
  },
  "security": {
    "sandboxing": true,
    "auditLogging": true,
    "rateLimit": 100
  }
}
```

## African Fintech Profiles

### Using Profiles

Profiles are automatically detected based on package name, but can be specified explicitly:

```bash
# Auto-detect (recommended)
rea analyze /path/to/app.apk

# Explicit provider
rea analyze /path/to/app.apk --provider mpesa
rea analyze /path/to/app.apk --provider mtn-momo
rea analyze /path/to/app.apk --provider airtel-money
```

### Profile Capabilities

| Provider | USSD | API | Cert Pinning | ProGuard | Native | Malware |
|----------|------|-----|--------------|----------|--------|---------|
| M-Pesa | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MTN MoMo | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Airtel Money | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Orange Money | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Wave | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| EcoCash | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Paga | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Opay | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Flutterwave | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Chipper Cash | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| WorldRemit | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Paystack | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PayPal Africa | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Vodacom M-Pesa | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Tigo Pesa | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Halopesa | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| EazzyPay | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| M-Pawa | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Profile Output

Analysis produces structured evidence including:

```json
{
  "profile": "mpesa",
  "packageName": "com.safaricom.mpesa",
  "version": "12.5.0",
  "ussdFlows": [...],
  "apiEndpoints": [...],
  "certificatePinning": {...},
  "proguardMapping": {...},
  "nativeLibraries": [...],
  "malwareFindings": [...],
  "evidence": {...}
}
```

## Malware Intelligence Database

### Querying Signatures

```bash
# List all categories
rea malware list-categories

# Search by category
rea malware search --category mobile-money-fraud
rea malware search --category fintech-trojan

# Search by provider
rea malware search --provider mpesa

# Search by country
rea malware search --country KE

# Export YARA rules
rea malware export --format yara --output ./rules/

# Export STIX
rea malware export --format stix --output ./stix/
```

### Signature Structure

Each signature includes:

```json
{
  "id": "mmf-simswap-001",
  "name": "SIM Swap Detector - M-Pesa",
  "family": "SimSwapFraud",
  "category": "mobile-money-fraud",
  "targetCountries": ["KE", "TZ", "GH", "EG"],
  "targetProviders": ["M-Pesa"],
  "yaraRule": "rule SimSwapFraud_Mpesa { ... }",
  "iocHashes": ["sha256:..."],
  "networkIocs": [...],
  "behavioralPatterns": [...],
  "mitreTechniques": ["T1655", "T1553.002"],
  "severity": "critical"
}
```

### Using with YARA

```bash
# Compile rules
yara -c compiled_rules.yara ./rules/*.yar

# Scan file
yara compiled_rules.yara suspicious.apk

# Scan directory
yara -r compiled_rules.yara /path/to/apps/
```

## MCP Server Usage

### Starting the Server

```bash
# STDIO (default)
rea mcp

# HTTP server
rea mcp --transport http --port 3000

# SSE server
rea mcp --transport sse --port 3001

# Streamable HTTP
rea mcp --transport streamable --port 3002

# All transports
rea mcp --all-transports
```

### Using with AI Agents

#### Claude Code

Add to `~/.claude-code/mcp.json`:

```json
{
  "mcpServers": {
    "rea-africa-enhanced": {
      "command": "npx",
      "args": ["-y", "rea-africa-enhanced@latest", "mcp"]
    }
  }
}
```

#### Codex CLI

```bash
codex mcp add rea-africa-enhanced -- npx -y rea-africa-enhanced@latest mcp
```

#### Cursor

Add to Cursor settings:

```json
{
  "mcp": {
    "servers": {
      "rea-africa-enhanced": {
        "command": "npx",
        "args": ["-y", "rea-africa-enhanced@latest", "mcp"]
      }
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `analyze_african_fintech_apk` | Android APK with fintech profiles |
| `analyze_african_fintech_ipa` | iOS IPA with fintech profiles |
| `scan_mobile_money_malware` | 50+ malware patterns |
| `extract_ussd_flows` | USSD menu extraction |
| `analyze_certificate_pinning` | Pinning detection/bypass |
| `reverse_engineer_protocol` | STK Push/USSD/REST |
| `extract_proguard_mapping` | ProGuard mappings |
| `analyze_native_libraries` | JNI/NDK security |
| `compare_binary_versions` | Security regression |
| `generate_threat_report` | African threat reports |
| `benchmark_re_analysis` | Performance benchmarks |
| `visualize_architecture` | Interactive diagrams |
| `audit_dependencies` | Vulnerability scanning |
| `generate_sbom` | CycloneDX SBOM |
| `run_mutation_tests` | Stryker mutation testing |
| `list_african_fintech_profiles` | Profile discovery |
| `get_malware_signatures` | Signature export |

### Example Agent Workflows

#### Analyze M-Pesa App for Security Issues

```
User: "Analyze this M-Pesa APK for security vulnerabilities"
Agent: [Calls analyze_african_fintech_apk with provider=mpesa, deepAnalysis=true, malwareScan=true]
Agent: "Found certificate pinning with 2 pinned certs. Detected 3 native libraries with crypto constants. No malware signatures matched. USSD flow extraction shows 7 menu options with 2 high-risk actions (Send Money, Withdraw Cash)."
```

#### Generate Threat Report for Kenya

```
User: "Generate a threat report for mobile money fraud in Kenya"
Agent: [Calls generate_threat_report with countries=["KE"], categories=["mobile-money-fraud"], timeRange="last-30-days"]
Agent: "Found 12 active SIM swap campaigns targeting M-Pesa users in Kenya. Top IOC: domain mpesa-verify-ke.example.com (phishing). Recommend enabling SIM lock and reporting phishing to 28628."
```

#### Scan App for Malware

```
User: "Scan this suspicious APK for mobile money malware"
Agent: [Calls scan_mobile_money_malware with filePath="/path/to/app.apk", categories=["sim-swap", "stk-intercept"]]
Agent: "MATCHED: mmf-simswap-001 (SIM Swap Detector - M-Pesa) - CRITICAL. App requests RECEIVE_SMS, SYSTEM_ALERT_WINDOW, BIND_ACCESSIBILITY_SERVICE. Contains STK Push overlay logic. Recommend immediate removal."
```

## Benchmarking

### Running Benchmarks

```bash
# Run all suites
rea benchmark --all

# Specific suite
rea benchmark --suite android-apk
rea benchmark --suite ios-ipa
rea benchmark --suite native-lib

# With regression detection
rea benchmark --compare-baseline --threshold 5
```

### CI Integration

```yaml
# .github/workflows/benchmark.yml
- name: Run Benchmarks
  run: rea benchmark --ci --threshold 5

# Fails if any regression > 5%
```

## Security Hardening

### Enabling Sandboxing

```json
{
  "security": {
    "sandboxing": true,
    "seccompProfile": "default",
    "namespaces": ["pid", "network", "mount", "user"],
    "cgroups": true,
    "readOnlyFs": true
  }
}
```

### Rate Limiting

```json
{
  "mcp": {
    "rateLimit": 100,
    "burstLimit": 20,
    "adaptive": true
  }
}
```

### Audit Logging

```json
{
  "security": {
    "auditLogging": true,
    "logPath": "~/.rea-africa-enhanced/audit.log",
    "format": "json",
    "includeEvidence": true
  }
}
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Provider not detected" | Use `--provider` flag explicitly |
| "Ghidra not found" | Set `GHIDRA_HOME` env var |
| "IDA Pro not found" | Set `IDA_HOME` env var |
| "Frida connection failed" | Check `frida-server` on device |
| "Benchmark DB locked" | Run `rea benchmark --cleanup` |
| "MCP connection refused" | Check transport config, port availability |

### Debug Mode

```bash
# Enable debug logging
DEBUG=rea:* rea analyze app.apk

# MCP debug
DEBUG=mcp:* rea mcp --transport http
```

### Logs

- Application logs: `~/.rea-africa-enhanced/logs/`
- Audit logs: `~/.rea-africa-enhanced/audit.log`
- Benchmark DB: `~/.rea-africa-enhanced/benchmarks.db`
- MCP logs: `~/.rea-africa-enhanced/mcp.log`

## Getting Help

- **Documentation**: https://nakisisageorge.github.io/rea-africa-enhanced/
- **Issues**: https://github.com/nakisisageorge/rea-africa-enhanced/issues
- **Discussions**: https://github.com/nakisisageorge/rea-africa-enhanced/discussions
- **Security**: security@rea-africa-enhanced.com

## Contributing

See [CONTRIBUTING_AFRICA.md](CONTRIBUTING_AFRICA.md) for guidelines on adding:
- New fintech profiles
- Malware signatures
- Protocol decoders
- MCP tools
- Architecture views