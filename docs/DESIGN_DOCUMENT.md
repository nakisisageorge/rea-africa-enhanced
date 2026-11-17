# rea-africa-enhanced — Design Document

## Overview

rea-africa-enhanced is a specialized reverse engineering framework for African fintech and mobile money applications. It extends the upstream rea project with 18 African fintech profiles, 200+ malware signatures, enhanced MCP server with 4 transports, benchmark regression detection, and comprehensive security hardening.

## Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────────────┐
│                      MCP Server (4 Transports)                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐    │
│  │  STDIO   │  │   HTTP   │  │   SSE    │  │  Streamable  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Android Pipeline│ │ iOS Pipeline    │ │ Native Bridges  │
│ APK→apktool→Jadx│ │ IPA→class-dump  │ │ Ghidra, IDA,    │
│ →Analysis       │ │ →Ghidra/IDA     │ │ Frida, Hopper,  │
└─────────────────┘ └─────────────────┘ └─────────────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    African RE Extensions                        │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │ 18 Fintech       │  │ 200+ Malware     │                    │
│  │ Profiles         │  │ Signatures       │                    │
│  │ (M-Pesa, MTN,    │  │ (8 categories)   │                    │
│  │  Airtel, etc.)   │  │                  │                    │
│  └──────────────────┘  └──────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
            ┌───────────────┐   ┌───────────────┐
            │ Benchmark     │   │ Security      │
            │ System        │   │ Boundaries    │
            │ (5% threshold)│   │ (Sandboxing,  │
            │               │   │  Rate limit,  │
            │               │   │  Audit log)   │
            └───────────────┘   └───────────────┘
```

### Core Design Principles

1. **Defensive Reverse Engineering**: All analysis is read-only; no modification of target binaries
2. **Evidence Provenance**: Every finding traces back to source evidence with timestamps
3. **Transport Agnosticism**: MCP tools work identically across all 4 transports
4. **African-First Design**: Profiles and signatures prioritize African fintech threats
5. **Security by Default**: Sandboxing, rate limiting, and audit logging enabled by default

## African Fintech Profiles

### Profile Structure

Each fintech profile contains:
- **USSD Patterns**: Menu trees with risk levels for each option
- **API Endpoints**: REST/gRPC endpoints with auth types and schemas
- **Certificate Pinning**: Pinned certs, backup pins, custom validators
- **ProGuard Strategy**: Mapping patterns, rename rules, reference mappings
- **Native Library Rules**: JNI bindings, crypto constants, anti-tamper detection
- **Malware Signatures**: YARA rules for provider-specific threats
- **Protocol Decoders**: STK Push, USSD, REST API message formats

### Supported Providers (18)

| Provider | Countries | USSD Codes | Category |
|----------|-----------|------------|----------|
| M-Pesa | KE, TZ, GH, EG, CD, LS, MZ | *150#, *150*00# | Mobile Money |
| MTN MoMo | UG, GH, NG, ZA, RW, ZM, CI, CM, BF, BJ, GN, LR, SL, SS, SY | *165#, *170#, *556# | Mobile Money |
| Airtel Money | NG, KE, TZ, UG, RW, MW, ZM, CD, GA, NE, TD, SC, MG, CG | *185*1*1#, *185# | Mobile Money |
| Orange Money | CI, SN, ML, BF, GN, BJ, LR, SL, CM | *144# | Mobile Money |
| Wave | SN, CI | *123#, *123*1# | Mobile Money |
| EcoCash | ZW | *151# | Mobile Money |
| Paga | NG | *242# | Payment Gateway |
| Opay | NG, EG | *955# | Mobile Money |
| Flutterwave | Pan-African | API-only | Payment Gateway |
| Chipper Cash | Multi-country | API + USSD | Remittance |
| WorldRemit | Global→Africa | API-only | Remittance |
| Paystack | NG, GH, ZA | API-only | Payment Gateway |
| PayPal Africa | Regional | API-only | Remittance |
| Vodacom M-Pesa | TZ, CD, LS, MZ | *150*00# | Mobile Money |
| Tigo Pesa | TZ, RW, GH | *150*01# | Mobile Money |
| Halopesa | TZ | *148*88# | Mobile Money |
| EazzyPay | KE | *838# | Banking |
| M-Pawa | TZ | *150*00# | Savings/Loans |

## Malware Intelligence Database

### Categories (200+ Signatures)

| Category | Count | Description |
|----------|-------|-------------|
| Mobile Money Fraud | 50+ | SIM swap, STK intercept, USSD forwarding, fake agents |
| FinTech Trojans | 40+ | EventBot, Alien, Cerberus, Anubis, BRATA, TeaBot variants |
| Regional APTs | 20+ | TranslucentLotus, OilRig, MuddyWater, APT33, SideWinder |
| SMS/USSD Phishing | 30+ | M-Pesa, MTN MoMo, Airtel, Orange smishing campaigns |
| Cryptojacking | 15+ | XMRig, CoinHive, CryptoLoot in fake fintech apps |
| Spyware/Stalkerware | 20+ | mSpy, FlexiSPY, Hoverwatch targeting journalists |
| Ransomware | 10+ | LockBit, BlackCat, Cl0p targeting African banks |
| Supply Chain | 15+ | SolarWinds, Log4Shell, Codecov, Kaseya, 3CX incidents |

### Signature Format

Each signature includes:
- YARA rule with metadata (author, date, tags, MITRE references)
- IOC hashes (SHA-256)
- Network IOCs (domains, IPs, URLs, certificates)
- Behavioral patterns (pseudocode logic, APIs, permissions)
- MITRE ATT&CK technique mappings
- Threat actor and campaign associations

## MCP Server Enhancements

### Transport Matrix

| Transport | Protocol | Auth | Use Case |
|-----------|----------|------|----------|
| STDIO | JSON-RPC 2.0 | Local user | CLI, local agents |
| HTTP | REST + JSON-RPC | API Key / OAuth2 | Remote agents, webhooks |
| SSE | Server-Sent Events | API Key | Real-time streaming |
| Streamable HTTP | Bidirectional streams | API Key + OAuth2 | Long-running analysis |

### Tool Registration

17 African RE tools registered:
1. `analyze_african_fintech_apk` - Android APK analysis with fintech profiles
2. `analyze_african_fintech_ipa` - iOS IPA analysis with fintech profiles
3. `scan_mobile_money_malware` - 50+ malware pattern scan
4. `extract_ussd_flows` - USSD menu flow extraction
5. `analyze_certificate_pinning` - Pinning detection and bypass analysis
6. `reverse_engineer_protocol` - STK Push, USSD, REST protocol reversing
7. `extract_proguard_mapping` - ProGuard mapping extraction
8. `analyze_native_libraries` - JNI/NDK security analysis
9. `compare_binary_versions` - Security regression detection
10. `generate_threat_report` - African threat intelligence reports
11. `benchmark_re_analysis` - Performance benchmarking
12. `visualize_architecture` - Interactive architecture diagrams
13. `audit_dependencies` - Vulnerability scanning
14. `generate_sbom` - CycloneDX SBOM generation
15. `run_mutation_tests` - Stryker mutation testing
16. `list_african_fintech_profiles` - Profile discovery
17. `get_malware_signatures` - Signature export (YARA, STIX, CSV)

## Benchmark Regression Detection

### Design

- **Storage**: SQLite database with historical baselines
- **Threshold**: 5% regression triggers alert
- **Metrics**: Duration (ms), Memory (MB), CPU (%)
- **Baseline**: Minimum 10 samples required
- **Retention**: 90 days default

### Alert Levels

| Change | Severity | Action |
|--------|----------|--------|
| 5-10% | Warning | Log + notify |
| >10% | Critical | Block CI + alert |

### CI Integration

```yaml
# .github/workflows/benchmark.yml
- name: Run Benchmarks
  run: npm run benchmark:ci
- name: Check Regressions
  run: npm run benchmark:check --threshold=5
```

## Security Hardening

### Analysis Sandboxing

- **seccomp profiles**: Restrict syscalls for untrusted binary analysis
- **Linux namespaces**: PID, network, mount, user isolation
- **cgroups v2**: CPU, memory, I/O limits per analysis worker
- **Read-only filesystems**: Prevent target binary modification

### MCP Server Security

- **Input Validation**: All tool inputs validated against JSON schemas
- **Rate Limiting**: Adaptive per-client limits (100 req/min default)
- **Audit Logging**: Immutable structured logs for all operations
- **Capability Tokens**: Fine-grained authorization per tool/transport
- **Transport Auth**: API keys for HTTP/SSE/Streamable; local user for STDIO

### Supply Chain Security

- **SBOM Generation**: CycloneDX for npm and native dependencies
- **Signed Releases**: cosign signatures for all artifacts
- **Reproducible Builds**: hermetic build environment
- **Dependency Verification**: npm audit, OSV scanner, GitHub CodeQL

## Data Flow

```
User/Agent Request
       │
       ▼
┌──────────────────┐
│ Transport Layer  │ ◄── STDIO / HTTP / SSE / Streamable
│ (Auth + Validate)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ MCP Router       │ ◄── Tool registry (17 African RE tools)
│ (Rate Limit)     │
└────────┬─────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│Android│ │ iOS   │
│Pipeline│ │Pipeline│
└───┬───┘ └───┬───┘
    │         │
    └────┬────┘
         ▼
┌──────────────────┐
│ Native Bridges   │ ◄── Ghidra, IDA, Frida, Hopper, etc.
│ (Sandboxed)      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ African RE Exts  │ ◄── 18 Profiles, 200+ Signatures
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Evidence Bundle  │ ◄── Structured evidence with provenance
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ MCP Delivery     │ ◄── Streamed via selected transport
└──────────────────┘
```

## Deployment

### Docker

```dockerfile
# Multi-stage build for minimal attack surface
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
USER node
EXPOSE 3000
CMD ["node", "dist/server/index.js"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rea-africa-enhanced
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rea-africa-enhanced
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: rea
        image: ghcr.io/nakisisageorge/rea-africa-enhanced:latest
        ports:
        - containerPort: 3000
        env:
        - name: MCP_API_KEY
          valueFrom:
            secretKeyRef:
              name: rea-secrets
              key: mcp-api-key
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "500m"
            memory: "1Gi"
```

## Testing Strategy

### Test Pyramid

1. **Unit Tests** (90%+ coverage): Individual tool handlers, profile logic, signature matching
2. **Integration Tests**: End-to-end MCP tool execution with real African apps
3. **Benchmark Tests**: Automated regression detection in CI
4. **Mutation Tests**: Stryker mutation testing for critical RE logic
5. **Contract Tests**: MCP protocol compliance verification

### African App Test Corpus

Curated test samples for each provider:
- Official APKs from Play Store (where available)
- Synthetic test apps with known vulnerabilities
- Malware samples from African threat intelligence feeds

## Future Extensions

1. **ML-Assisted Analysis**: TensorFlow Lite models for anomaly detection
2. **Distributed Analysis**: Kubernetes operator for horizontal scaling
3. **Real-time Threat Feeds**: Integration with MISP, OpenCTI
4. **Mobile App Store Monitoring**: Automated Play Store/App Store scanning
5. **Regulatory Compliance**: PCI-DSS, GDPR, NDPR reporting modules