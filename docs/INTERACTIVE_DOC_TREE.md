# rea-africa-enhanced — Interactive Documentation Tree

## Navigation

```
rea-africa-enhanced/
├── README.md                          # Project overview, quick start
├── LICENSE                            # MIT License
├── CHANGELOG.md                       # Version history
├── CONTRIBUTING.md                    # Contribution guidelines
├── SECURITY.md                        # Security policy
│
├── docs/
│   ├── DESIGN_DOCUMENT.md             # Architecture, profiles, malware DB, MCP, benchmarks, security
│   ├── PORTFOLIO_CASE_STUDY.md        # Executive summary, before/after, impact, attribution
│   ├── BEFORE_AFTER.md                # This comparison (quantitative/qualitative)
│   ├── INTERACTIVE_DOC_TREE.md        # This navigation tree
│   ├── MCP_GUIDE.md                   # Transport config, tool reference, auth, streaming
│   ├── AFRICAN_RE_GUIDE.md            # Profile usage, malware DB, case studies
│   ├── CONTRIBUTING_AFRICA.md         # African fintech/malware contribution guidelines
│   │
│   ├── architecture/
│   │   ├── index.html                 # React Flow interactive visualization (10 views)
│   │   ├── overview.html              # View 1: System Overview
│   │   ├── mcp-server.html            # View 2: MCP Server
│   │   ├── android-pipeline.html      # View 3: Android Pipeline
│   │   ├── ios-pipeline.html          # View 4: iOS Pipeline
│   │   ├── native-bridges.html        # View 5: Native Bridges
│   │   ├── evidence-flow.html         # View 6: Evidence Flow
│   │   ├── agent-integration.html     # View 7: Agent Integration
│   │   ├── benchmark-system.html      # View 8: Benchmark System
│   │   ├── security-boundaries.html   # View 8: Security Boundaries
│   │   └── african-re-extensions.html # View 10: African RE Extensions
│   │
│   ├── api/
│   │   ├── mcp-tools.md               # All 17 African RE tool specifications
│   │   ├── transports.md              # STDIO, HTTP, SSE, Streamable config
│   │   ├── auth.md                    # API keys, OAuth2, capability tokens
│   │   └── streaming.md               # SSE + Streamable HTTP usage
│   │
│   ├── guides/
│   │   ├── african-re-guide.md        # Profile usage, malware DB, case studies
│   │   ├── mcp-guide.md               # Transport config, tool reference, auth
│   │   ├── benchmark-guide.md         # Regression detection, CI integration
│   │   ├── security-guide.md          # Sandboxing, rate limiting, audit, capabilities
│   │   ├── profile-development.md     # Adding new fintech profiles
│   │   ├── malware-signatures.md      # Adding YARA rules, IOCs, MITRE mappings
│   │   └── protocol-decoders.md       # Adding STK Push, USSD, REST decoders
│   │
│   ├── references/
│   │   ├── fintech-profiles.md        # All 18 provider profiles reference
│   │   ├── malware-signatures.md      # All 200+ signatures by category
│   │   ├── mitre-techniques.md        # MITRE ATT&CK technique reference
│   │   ├── threat-actors.md           # Threat actor profiles
│   │   ├── campaigns.md               # Campaign timelines and IOCs
│   │   ├── ussd-codes.md              # All USSD codes by provider/country
│   │   ├── api-endpoints.md           # All API endpoints by provider
│   │   ├── certificate-pinning.md     # Pinning configs by provider
│   │   └── mitre-att&ck.md            # Technique ID → description mapping
│   │
│   └── assets/
│       ├── diagrams/                  # Architecture diagrams (Mermaid source)
│       ├── screenshots/               # UI screenshots
│       └── videos/                    # Demo recordings
│
├── src/
│   ├── domain/
│   │   ├── android/african/           # 18 fintech profiles
│   │   ├── malware/african/           # 200+ malware signatures
│   │   └── benchmark/                 # Regression detection
│   ├── server/
│   │   ├── registerAfricanReTools.ts  # 17 MCP tool registrations
│   │   └── http/                      # HTTP/SSE/Streamable transports
│   ├── visualization/                 # React Flow architecture (10 views)
│   └── benchmark/                     # Regression detection (SQLite, 5%)
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                     # Main CI pipeline
│   │   ├── benchmark.yml              # Regression detection
│   │   ├── security.yml               # TruffleHog, OSV, CodeQL
│   │   ├── release.yml                # Signed releases + SBOM
│   │   └── dependency-review.yml      # Dependency review
│   └── dependabot.yml                 # Dependency updates
│
├── package.json                       # Scripts, dependencies, config
├── turbo.json                         # Turbo monorepo config
├── tsconfig.json                      # TypeScript config
├── vitest.config.ts                   # Vitest config
├── stryker.config.mjs                 # Mutation testing config
└── mcp.json                           # MCP server config (4 transports)
```

## Quick Links

### By Role

**Security Researcher**
- [African RE Guide](guides/african-re-guide.md) — Profile usage, malware analysis
- [Malware Signatures Reference](references/malware-signatures.md) — 200+ YARA rules
- [Architecture Views](architecture/) — Interactive React Flow diagrams
- [MCP Tools](api/mcp-tools.md) — 17 African RE tools

**African Fintech Engineer**
- [Fintech Profiles](references/fintech-profiles.md) — 18 provider profiles
- [USSD Codes](references/ussd-codes.md) — All codes by provider/country
- [API Endpoints](references/api-endpoints.md) — REST/STK Push/USSD endpoints
- [Certificate Pinning](references/certificate-pinning.md) — Pinning configs

**AI Agent Developer**
- [MCP Guide](api/transports.md) — 4 transports, auth, streaming
- [MCP Tools](api/mcp-tools.md) — 17 African RE tools
- [Streaming](api/streaming.md) — SSE + Streamable HTTP

**Security Engineer**
- [Security Guide](guides/security-guide.md) — Sandboxing, rate limiting, audit
- [Malware Signatures](references/malware-signatures.md) — YARA rules
- [Threat Actors](references/threat-actors.md) — APT profiles
- [Security Boundaries](architecture/security-boundaries.html) — Interactive view

**DevOps Engineer**
- [CI/CD Pipelines](../.github/workflows/) — All workflows
- [Benchmark Guide](guides/benchmark-guide.md) — Regression detection
- [Security Scanning](../.github/workflows/security.yml) — TruffleHog, OSV, CodeQL
- [SBOM Generation](../.github/workflows/release.yml) — CycloneDX, cosign

**Contributor**
- [Contributing Africa](CONTRIBUTING_AFRICA.md) — African fintech/malware guidelines
- [Profile Development](guides/profile-development.md) — Adding profiles
- [Malware Signatures](guides/malware-signatures.md) — Adding YARA rules
- [Protocol Decoders](guides/protocol-decoders.md) — Adding decoders

### By Task

| Task | Documentation |
|------|---------------|
| Quick start | [README.md](../README.md) |
| Analyze M-Pesa APK | [MCP Tools → analyze_african_fintech_apk](api/mcp-tools.md) |
| Scan for malware | [MCP Tools → scan_mobile_money_malware](api/mcp-tools.md) |
| Extract USSD flows | [MCP Tools → extract_ussd_flows](api/mcp-tools.md) |
| Generate threat report | [MCP Tools → generate_threat_report](api/mcp-tools.md) |
| Run benchmarks | [Benchmark Guide](guides/benchmark-guide.md) |
| View architecture | [Architecture Views](architecture/) |
| Configure MCP HTTP | [Transports → HTTP](api/transports.md) |
| Add fintech profile | [Profile Development](guides/profile-development.md) |
| Add malware signature | [Malware Signatures](guides/malware-signatures.md) |
| Configure sandboxing | [Security Guide](guides/security-guide.md) |
| Set up CI/CD | [CI/CD Pipelines](../.github/workflows/) |

### Search

Use the documentation search (top-right) or browse by:
- **Category**: [Guides](guides/) | [References](references/) | [Architecture](architecture/) | [API](api/)
- **Topic**: [Profiles](references/fintech-profiles.md) | [Malware](references/malware-signatures.md) | [MCP](api/mcp-tools.md) | [Security](guides/security-guide.md)
- **Provider**: [M-Pesa](references/fintech-profiles.md#mpesa) | [MTN MoMo](references/fintech-profiles.md#mtn-momo) | [Airtel](references/fintech-profiles.md#airtel-money) | [All](references/fintech-profiles.md)
- **Malware Type**: [Fraud](references/malware-signatures.md#mobile-money-fraud) | [Trojans](references/malware-signatures.md#fintech-trojans) | [APTs](references/malware-signatures.md#regional-apts) | [All](references/malware-signatures.md)