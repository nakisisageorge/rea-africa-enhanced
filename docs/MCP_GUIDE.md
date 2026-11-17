# rea-africa-enhanced — MCP Server Guide

## Overview

The rea-africa-enhanced MCP server exposes 17 African reverse engineering tools via 4 transport protocols, enabling AI agents to perform specialized African fintech analysis tasks.

## Transport Protocols

### 1. STDIO (Local)

**Use Case**: CLI tools, local AI agents (Claude Code, Codex CLI, Cursor)

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

**Authentication**: Local user context (no additional auth required)

### 2. HTTP (REST + JSON-RPC)

**Use Case**: Remote agents, webhooks, service-to-service

**Endpoint**: `https://api.rea-africa-enhanced.com/mcp`

**Authentication**: API Key header
```bash
curl -X POST https://api.rea-africa-enhanced.com/mcp \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

**Rate Limit**: 100 requests/minute per API key (adaptive)

### 3. SSE (Server-Sent Events)

**Use Case**: Real-time streaming for long-running analysis

**Endpoint**: `https://api.rea-africa-enhanced.com/mcp/sse`

**Connection**:
```javascript
const eventSource = new EventSource('https://api.rea-africa-enhanced.com/mcp/sse', {
  headers: { 'Authorization': 'Bearer YOUR_API_KEY' }
});

eventSource.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};
```

**Use Case**: Streaming analysis progress, large evidence bundles

### 4. Streamable HTTP (Bidirectional)

**Use Case**: Long-running analysis with client↔server communication

**Endpoint**: `https://api.rea-africa-enhanced.com/mcp/stream`

**Protocol**: Bidirectional streams over HTTP/2

```javascript
const response = await fetch('https://api.rea-africa-enhanced.com/mcp/stream', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: {...} })
});

const reader = response.body.getReader();
while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  console.log(new TextDecoder().decode(value));
}
```

## Authentication

### API Key

Generate in dashboard: `https://rea-africa-enhanced.com/dashboard`

```bash
export REA_API_KEY="rea_ak_..."
```

### OAuth2 (Service Accounts)

```bash
# Client credentials flow
curl -X POST https://auth.rea-africa-enhanced.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=rea:read rea:write rea:analyze"
```

### Capability Tokens

Fine-grained per-tool authorization:

```json
{
  "capabilities": [
    "analyze_african_fintech_apk",
    "scan_mobile_money_malware",
    "extract_ussd_flows"
  ],
  "rateLimit": 50,
  "expiresAt": "2026-12-31T23:59:59Z"
}
```

## Tool Reference

### African Fintech Analysis Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `analyze_african_fintech_apk` | Android APK with fintech profiles | `apkPath`, `provider?`, `deepAnalysis?`, `extractUssd?`, `checkCertificatePinning?`, `malwareScan?` |
| `analyze_african_fintech_ipa` | iOS IPA with fintech profiles | `ipaPath`, `provider?`, `deepAnalysis?`, `checkCertificatePinning?`, `malwareScan?` |
| `scan_mobile_money_malware` | 50+ malware patterns | `filePath`, `categories?`, `severityFilter?` |
| `extract_ussd_flows` | USSD menu extraction | `apkPath`, `provider?`, `outputFormat?` |
| `analyze_certificate_pinning` | Pinning detection/bypass | `filePath`, `provider?`, `checkBypass?` |
| `reverse_engineer_protocol` | STK Push/USSD/REST | `filePath`, `protocolType?`, `provider?`, `pcapPath?` |
| `extract_proguard_mapping` | ProGuard mappings | `apkPath`, `mappingFile?`, `useReference?` |
| `analyze_native_libraries` | JNI/NDK security | `apkPath`, `architectures?`, `analysisTypes?` |
| `compare_binary_versions` | Security regression | `oldApkPath`, `newApkPath`, `provider?`, `focusAreas?` |

### Intelligence & Reporting Tools

| Tool | Description |
|------|-------------|
| `generate_threat_report` | African threat intelligence reports |
| `benchmark_re_analysis` | Performance benchmarks with regression detection |
| `visualize_architecture` | Interactive React Flow diagrams |
| `audit_dependencies` | Vulnerability scanning (npm/cargo/maven) |
| `generate_sbom` | CycloneDX SBOM generation |
| `run_mutation_tests` | Stryker mutation testing |

### Discovery Tools

| Tool | Description |
|------|-------------|
| `list_african_fintech_profiles` | List all 18 profiles (filter by country/category) |
| `get_malware_signatures` | Export 200+ signatures (YARA/STIX/CSV/JSON) |

## Usage Examples

### Analyze M-Pesa APK

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "analyze_african_fintech_apk",
    "arguments": {
      "apkPath": "/path/to/mpesa.apk",
      "provider": "mpesa",
      "deepAnalysis": true,
      "extractUssd": true,
      "checkCertificatePinning": true,
      "malwareScan": true
    }
  },
  "id": 1
}
```

### Scan for Mobile Money Malware

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_mobile_money_malware",
    "arguments": {
      "filePath": "/path/to/suspicious.apk",
      "categories": ["sim-swap", "stk-intercept", "ussd-forward", "fake-agent"],
      "severityFilter": "high"
    }
  },
  "id": 2
}
```

### Extract USSD Flows

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "extract_ussd_flows",
    "arguments": {
      "apkPath": "/path/to/mtn-momo.apk",
      "provider": "mtn-momo",
      "outputFormat": "mermaid"
    }
  },
  "id": 3
}
```

### Generate Threat Report

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "generate_threat_report",
    "arguments": {
      "countries": ["KE", "UG", "TZ", "NG", "GH", "ZA"],
      "categories": ["mobile-money-fraud", "fintech-trojan", "smishing-usd-phishing"],
      "timeRange": "last-30-days",
      "format": "markdown"
    }
  },
  "id": 4
}
```

### Run Benchmarks

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "benchmark_re_analysis",
    "arguments": {
      "suite": "android-apk",
      "iterations": 10,
      "compareBaseline": true,
      "threshold": 5
    }
  },
  "id": 5
}
```

## Streaming Usage

### SSE Progress Updates

```javascript
const eventSource = new EventSource('https://api.rea-africa-enhanced.com/mcp/sse', {
  headers: { 'Authorization': 'Bearer YOUR_API_KEY' }
});

eventSource.addEventListener('progress', (event) => {
  const data = JSON.parse(event.data);
  console.log(`${data.tool}: ${data.percent}% - ${data.message}`);
});

eventSource.addEventListener('result', (event) => {
  const data = JSON.parse(event.data);
  console.log('Analysis complete:', data.result);
});
```

### Streamable HTTP for Large Evidence

```javascript
async function* streamAnalysis(apkPath) {
  const response = await fetch('https://api.rea-africa-enhanced.com/mcp/stream', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'analyze_african_fintech_apk',
        arguments: { apkPath, provider: 'mpesa', deepAnalysis: true }
      }
    })
  });

  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    yield JSON.parse(decoder.decode(value));
  }
}

for await (const chunk of streamAnalysis('/path/to/app.apk')) {
  console.log('Chunk:', chunk);
}
```

## Error Handling

| Code | Meaning | Resolution |
|------|---------|------------|
| -32600 | Invalid Request | Check JSON-RPC format |
| -32601 | Method Not Found | Verify tool name |
| -32602 | Invalid Params | Check tool schema |
| -32603 | Internal Error | Check server logs |
| -32000 | Auth Failed | Verify API key/OAuth token |
| -32001 | Rate Limited | Wait and retry with backoff |
| -32002 | Tool Not Found | Verify tool name spelling |
| -32003 | Transport Error | Check network/connection |

## Rate Limits

| Transport | Limit | Burst |
|-----------|-------|-------|
| STDIO | Unlimited | N/A |
| HTTP | 100 req/min | 20 req/10s |
| SSE | 50 connections | 10 conn/10s |
| Streamable | 20 streams | 5 streams/10s |

## Best Practices

1. **Use appropriate transport**: STDIO for local, HTTP/SSE for remote, Streamable for long-running
2. **Handle rate limits**: Implement exponential backoff
3. **Stream large results**: Use SSE/Streamable for evidence bundles >1MB
4. **Validate inputs**: All tools use JSON Schema validation
5. **Monitor rate limits**: Check `X-RateLimit-*` headers
6. **Use capability tokens**: For fine-grained access control
7. **Rotate API keys**: Regular rotation (90 days recommended)