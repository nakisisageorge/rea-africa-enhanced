/**
 * Base class for African Fintech Profiles
 *
 * Provides common functionality and default implementations
 * that can be extended by specific provider profiles.
 */

import type {
  AfricanFintechProfile,
  UssdPattern,
  ApiEndpoint,
  CertificatePinningConfig,
  ProGuardStrategy,
  NativeLibraryRule,
  MalwareSignature,
  ProtocolDecoder,
} from '../types.js';

export abstract class BaseAfricanFintechProfile implements AfricanFintechProfile {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly countries: string[];
  abstract readonly category: AfricanFintechProfile['category'];
  abstract readonly packageNames: string[];
  abstract readonly signingCertificates: string[];
  abstract readonly minVersion: string;
  abstract readonly maxVersionTested: string;
  abstract readonly profileVersion: string;
  abstract readonly lastUpdated: string;
  abstract readonly maintainer: string;

  // Default implementations that can be overridden
  ussdPatterns: UssdPattern[] = [];
  apiEndpoints: ApiEndpoint[] = [];
  certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: [],
    backupPins: [],
    mode: 'strict',
    domains: [],
    allowUserCAs: false,
    requireCT: true,
  };
  proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt', 'build/outputs/mapping/release/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^[a-z][A-Z][a-z]+$/],
    methodPatterns: [/^[a-z]{1,2}$/, /^[a-z][A-Z][a-z]+$/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^[a-z][A-Z][a-z]+$/],
    renameRules: [],
    useReferenceMapping: true,
  };
  nativeLibraryRules: NativeLibraryRule[] = [];
  malwareSignatures: MalwareSignature[] = [];
  protocolDecoders: ProtocolDecoder[] = [];

  /**
   * Create a standard USSD pattern for balance checking
   */
  protected createBalanceUssdPattern(
    id: string,
    code: string,
    name: string,
    region: string[],
    provider: string
  ): UssdPattern {
    return {
      id,
      name,
      code,
      region,
      provider,
      sessionTimeout: 180,
      responsePatterns: [
        /balance/i,
        /available/i,
        /account/i,
        /\d+[,.]\d{2}/,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Main Menu',
        options: [
          {
            key: '1',
            text: 'Check Balance',
            action: 'balance',
            riskLevel: 'low',
          },
        ],
      },
    };
  }

  /**
   * Create a standard USSD pattern for money transfer
   */
  protected createTransferUssdPattern(
    id: string,
    code: string,
    name: string,
    region: string[],
    provider: string
  ): UssdPattern {
    return {
      id,
      name,
      code,
      region,
      provider,
      sessionTimeout: 300,
      responsePatterns: [
        /transfer/i,
        /send money/i,
        /recipient/i,
        /amount/i,
        /confirm/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Main Menu',
        options: [
          {
            key: '1',
            text: 'Send Money',
            action: 'transfer',
            childNodeId: 'transfer_menu',
            riskLevel: 'high',
          },
        ],
      },
    };
  }

  /**
   * Create a standard API endpoint
   */
  protected createApiEndpoint(
    id: string,
    method: ApiEndpoint['method'],
    path: string,
    baseUrl: string,
    description: string,
    authType: ApiEndpoint['authType'] = 'bearer',
    riskLevel: ApiEndpoint['riskLevel'] = 'medium'
  ): ApiEndpoint {
    return {
      id,
      method,
      path,
      baseUrl,
      description,
      authType,
      riskLevel,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
    };
  }

  /**
   * Create a standard malware signature
   */
  protected createMalwareSignature(
    id: string,
    name: string,
    family: string,
    targetProviders: string[],
    targetCountries: string[],
    yaraRule: string,
    severity: MalwareSignature['severity'] = 'high',
    mitreTechniques: string[] = []
  ): MalwareSignature {
    const dateStr = new Date().toISOString().split('T')[0];
    return {
      id,
      name,
      family,
      targetProviders,
      targetCountries,
      yaraRule,
      iocHashes: [],
      networkIocs: [],
      behavioralPatterns: [],
      severity,
      discoveredAt: dateStr ?? new Date().toISOString(),
      source: 'rea-africa-enhanced',
      mitreTechniques,
    };
  }

  /**
   * Create a standard native library rule for certificate pinning
   */
  protected createCertPinningNativeRule(libraryPattern: string): NativeLibraryRule {
    return {
      libraryPattern: new RegExp(libraryPattern),
      arch: 'all',
      analysisType: 'certificate-pinning',
      suspiciousPatterns: [
        /X509TrustManager/,
        /checkServerTrusted/,
        /getAcceptedIssuers/,
        /Pinning/,
        /CertificatePinner/,
        /OkHttpClient/,
        /CertificateTransparency/,
      ],
      riskLevel: 'high',
    };
  }

  /**
   * Create a standard native library rule for root detection
   */
  protected createRootDetectionNativeRule(libraryPattern: string): NativeLibraryRule {
    return {
      libraryPattern: new RegExp(libraryPattern),
      arch: 'all',
      analysisType: 'root-detection',
      suspiciousPatterns: [
        /su\b/,
        /magisk/,
        /superuser/,
        /RootBeer/,
        /SafetyNet/,
        /PlayIntegrity/,
        /isDeviceRooted/,
        /checkRoot/,
        /suBinary/,
      ],
      riskLevel: 'medium',
    };
  }

  /**
   * Create a standard native library rule for anti-tamper
   */
  protected createAntiTamperNativeRule(libraryPattern: string): NativeLibraryRule {
    return {
      libraryPattern: new RegExp(libraryPattern),
      arch: 'all',
      analysisType: 'anti-tamper',
      suspiciousPatterns: [
        /verifySignature/,
        /checkInstaller/,
        /packageManager/,
        /getPackageInfo/,
        /SIGNATURE/,
        /dex2oat/,
        /oatdump/,
        /integrity/,
        /tamper/,
      ],
      riskLevel: 'high',
    };
  }
}