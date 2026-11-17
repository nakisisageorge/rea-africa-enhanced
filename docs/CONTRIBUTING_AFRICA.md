# Contributing to rea-africa-enhanced — African Fintech/Malware Extensions

## Overview

This document provides guidelines for contributing African fintech reverse engineering profiles, malware signatures, protocol decoders, and other Africa-specific enhancements to rea-africa-enhanced.

## Code of Conduct

By contributing, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Key principles:

- **Responsible Disclosure**: Report security vulnerabilities privately
- **Defensive Focus**: All contributions must be for defensive reverse engineering
- **Attribution**: Credit original researchers and threat intelligence sources
- **Legal Compliance**: Respect all applicable laws and licenses

## Contribution Types

### 1. African Fintech Profiles

Add reverse engineering profiles for new African fintech providers.

#### Requirements

- Provider must operate in Africa (or serve African markets)
- Profile must include all required sections (see template)
- Must not facilitate offensive attacks
- Must include at least 3 malware signatures

#### Profile Template

```typescript
// src/domain/android/african/profiles/NewProviderProfile.ts
import { BaseAfricanFintechProfile } from './BaseAfricanFintechProfile.js';
import type { UssdPattern, ApiEndpoint, ... } from '../types.js';

export class NewProviderProfile extends BaseAfricanFintechProfile {
  override readonly id = 'new-provider';
  override readonly name = 'New Provider';
  override readonly countries = ['XX', 'YY']; // ISO 3166-1 alpha-2
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = ['com.newprovider.app'];
  override readonly signingCertificates = ['SHA256:...'];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '2.0.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'Your Name/Org';

  override readonly ussdPatterns: UssdPattern[] = [
    // Define USSD menu trees with risk levels
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    // Define REST/USSD/STK Push endpoints
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/...'],
    backupPins: ['sha256/...'],
    mode: 'strict',
    domains: ['api.newprovider.com'],
    allowUserCAs: false,
    requireCT: true,
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt'],
    classPatterns: [/^New[A-Z]/],
    methodPatterns: [/^newMethod/],
    fieldPatterns: [/^newField/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libnewprovider.*\\.so'),
    this.createRootDetectionNativeRule('libnewprovider.*\\.so'),
    this.createAntiTamperNativeRule('libnewprovider.*\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'newprovider-fakeapp-001',
      'Fake New Provider App',
      'FakeNewProviderApp',
      ['New Provider'],
      ['XX', 'YY'],
      `rule FakeNewProviderApp { ... }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
    // Add at least 2 more signatures
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'New Provider API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'NewProviderDecoder',
      messageTypes: [...],
    },
  ];
}
```

#### Registration

Add to `src/domain/android/african/index.ts`:

```typescript
export { NewProviderProfile } from './profiles/NewProviderProfile.js';
```

Add to `src/domain/android/african/AfricanFintechProfileRegistry.ts`:

```typescript
import { NewProviderProfile } from './profiles/NewProviderProfile.js';
// In registerBuiltinProfiles():
() => new NewProviderProfile(),
```

### 2. Malware Signatures

Add YARA rules for African malware threats.

#### Requirements

- Must target African fintech/mobile money threats
- Must include valid YARA rule with metadata
- Must map to MITRE ATT&CK techniques
- Must include IOC hashes and network IOCs
- Must specify threat actor/campaign if known

#### Signature Template

```typescript
// src/domain/malware/african/signatures/NewCategorySignatures.ts
import type { MalwareEntry } from '../types.js';

export class NewCategorySignatures {
  static getSignatures(): MalwareEntry[] {
    return [
      {
        id: 'newcat-threat-001',
        name: 'Descriptive Name',
        family: 'ThreatFamily',
        variant: 'AfricanVariant',
        category: 'new-category', // or existing category
        targetCountries: ['KE', 'NG', 'ZA'],
        targetProviders: ['M-Pesa', 'MTN MoMo'],
        targetPlatforms: ['android'],
        yaraRule: `rule NewCategory_ThreatName {
  meta:
    description = "Description of threat"
    author = "Your Name/Org"
    severity = "critical"
    date = "2026-11-15"
    version = "1.0"
    tags = ["tag1", "tag2"]
    reference = "T1655,T1553.002"
  strings:
    $str1 = "indicator1" ascii wide
    $str2 = "indicator2" ascii wide
  condition:
    any of ($str*)
}`,
        iocHashes: ['sha256:...'],
        networkIocs: [
          { type: 'domain', value: 'malicious.example.com', description: 'C2 domain', confidence: 0.9, firstSeen: '2026-01-01', tags: ['c2'] },
        ],
        behavioralPatterns: [
          { id: 'newcat-behav-001', name: 'Behavior Name', description: 'Description', logic: 'Pseudocode logic', apis: ['API1', 'API2'], permissions: ['PERM1'], confidence: 0.9 },
        ],
        mitreTechniques: [
          { id: 'T1655', name: 'SIM Swap', tactic: 'Credential Access', confidence: 0.95 },
        ],
        threatActors: [
          { id: 'ta-new-001', name: 'Threat Actor Name', aliases: ['Alias'], origin: 'XX', motivation: 'financial', sophistication: 'high', campaigns: [], mitreGroups: ['GXXXX'], description: 'Description' },
        ],
        campaigns: [
          { id: 'camp-new-2026', name: 'Campaign Name', startDate: '2026-01-01', targetCountries: ['KE', 'NG'], targetSectors: ['fintech'], actors: ['ta-new-001'], techniques: ['T1655'], description: 'Campaign description', status: 'active' },
        ],
        severity: 'critical',
        confidence: 0.95,
        discoveredAt: '2026-11-15',
        lastUpdated: '2026-11-15',
        source: 'Your Org Threat Intelligence',
        tags: ['tag1', 'tag2'],
        description: 'Detailed description of the threat',
        mitigations: ['Mitigation 1', 'Mitigation 2'],
      },
    ];
  }
}
```

#### Registration

Add to `src/domain/malware/african/index.ts`:

```typescript
export { NewCategorySignatures } from './signatures/NewCategorySignatures.js';
```

Add to `AfricanMalwareDatabase.ts` in `initialize()`:

```typescript
import { NewCategorySignatures } from './signatures/NewCategorySignatures.js';
// In signatureModules array:
NewCategorySignatures.getSignatures(),
```

### 3. Protocol Decoders

Add decoders for new mobile money protocols.

#### Requirements

- Must support STK Push, USSD, REST, or TCP binary protocols
- Must define message types with field schemas
- Must include encryption scheme if applicable
- Must provide decoder class name

### 4. MCP Tools

Add new African RE tools to the MCP server.

#### Requirements

- Must use existing African profiles/malware DB
- Must follow existing tool patterns
- Must include JSON Schema for inputs
- Must handle errors gracefully

### 5. Architecture Views

Add new React Flow architecture views.

#### Requirements

- Must use existing node/edge types
- Must include at least 10 nodes
- Must have meaningful layout
- Must include filters

## Development Setup

```bash
# Clone fork
git clone https://github.com/yourusername/rea-africa-enhanced.git
cd rea-africa-enhanced

# Install dependencies
npm ci

# Run development checks
npm run check:fast

# Run tests
npm run test:local

# Build
npm run build:cached

# Run benchmark
npm run benchmark -- --threshold 5
```

## Testing

### Unit Tests

Place tests alongside source files with `.test.ts` suffix.

```typescript
// src/domain/android/african/profiles/NewProviderProfile.test.ts
import { NewProviderProfile } from './NewProviderProfile.js';

describe('NewProviderProfile', () => {
  it('should have correct USSD patterns', () => {
    const profile = new NewProviderProfile();
    expect(profile.ussdPatterns.length).toBeGreaterThan(0);
  });
});
```

### Integration Tests

Test with real African apps (where legally obtained):

```typescript
// tests/integration/african-profiles.test.ts
import { analyzeAfricanFintechApkTool } from '../../src/server/registerAfricanReTools.js';

describe('African Profiles Integration', () => {
  it('should analyze M-Pesa APK', async () => {
    const result = await analyzeAfricanFintechApkTool.handler({
      apkPath: '/path/to/mpesa.apk',
      provider: 'mpesa',
    });
    expect(result.content[0].text).toContain('M-Pesa');
  });
});
```

### Benchmark Tests

```bash
# Run benchmark suite
npm run benchmark -- --suite android-apk --iterations 10
```

## Code Style

- Follow existing TypeScript patterns
- Use `override` for all overridden members
- Add JSDoc comments for public APIs
- Run `npm run check:fast` before committing
- Run `npm run format` for formatting

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feat/african-new-provider`
3. **Commit** with conventional commits: `feat(african): add NewProvider profile`
4. **Push** to your fork
5. **Open PR** against `main` branch
6. **CI Checks** must pass:
   - `check:fast` (typecheck, lint, format)
   - `test:local` (unit tests)
   - `benchmark` (regression threshold 5%)
   - `security` (TruffleHog, OSV, CodeQL)
7. **Review** by maintainers
8. **Merge** after approval

## Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `security`

Scopes: `african`, `malware`, `mcp`, `benchmark`, `security`, `viz`, `docs`

Examples:
```
feat(african): add M-Pesa Kenya USSD flow extraction
fix(malware): correct YARA rule for SimSwapFraud
docs(african): update AFRICAN_RE_GUIDE with new provider
security(mcp): add rate limiting to HTTP transport
```

## Security Considerations

- **Never** include offensive exploit code
- **Never** include real malware samples in repo
- **Always** use defensive language
- **Report** vulnerabilities privately to security@rea-africa-enhanced.com
- **Verify** all IOCs before committing
- **Respect** responsible disclosure timelines

## Legal

- All contributions licensed under MIT License
- Contributors retain copyright
- Project maintains right to relicense under compatible licenses
- No patent grants implied

## Recognition

Contributors recognized in:
- `CHANGELOG.md`
- Release notes
- Contributors section in README
- Annual contributor report

## Questions?

- **Discussions**: https://github.com/nakisisageorge/rea-africa-enhanced/discussions
- **Issues**: https://github.com/nakisisageorge/rea-africa-enhanced/issues
- **Email**: contributions@rea-africa-enhanced.com
- **Security**: security@rea-africa-enhanced.com

Thank you for contributing to African fintech security! 🌍🔐