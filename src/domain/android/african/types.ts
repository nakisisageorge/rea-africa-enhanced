/**
 * Type definitions for African Fintech Reverse Engineering Profiles
 */

/**
 * USSD pattern for mobile money menu navigation
 */
export interface UssdPattern {
  /** Unique identifier for this USSD pattern */
  id: string;
  /** Human-readable name */
  name: string;
  /** USSD code (e.g., "*150#" for M-Pesa Kenya) */
  code: string;
  /** Menu tree structure */
  menuTree: UssdMenuNode;
  /** Expected response patterns for validation */
  responsePatterns: RegExp[];
  /** Session timeout in seconds */
  sessionTimeout: number;
  /** Country/region this pattern applies to */
  region: string[];
  /** Provider name */
  provider: string;
}

/**
 * USSD menu node in the navigation tree
 */
export interface UssdMenuNode {
  /** Menu title/text */
  title: string;
  /** Menu options */
  options: UssdMenuOption[];
  /** Parent node reference (for breadcrumbs) */
  parent?: string;
  /** Unique node ID */
  nodeId: string;
}

/**
 * Individual USSD menu option
 */
export interface UssdMenuOption {
  /** Option number/key */
  key: string;
  /** Option text */
  text: string;
  /** Next USSD code to dial */
  nextCode?: string;
  /** Child menu node ID */
  childNodeId?: string;
  /** Action type */
  action: 'menu' | 'input' | 'confirm' | 'transaction' | 'balance' | 'transfer' | 'withdraw' | 'deposit' | 'billpay' | 'airtime' | 'loan' | 'savings';
  /** Expected input pattern if action is 'input' */
  inputPattern?: RegExp;
  /** Risk level for security analysis */
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * API endpoint definition for fintech services
 */
export interface ApiEndpoint {
  /** Endpoint identifier */
  id: string;
  /** HTTP method */
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  /** API path */
  path: string;
  /** Base URL pattern */
  baseUrl: string;
  /** Required headers */
  headers: Record<string, string>;
  /** Authentication type */
  authType: 'bearer' | 'api-key' | 'hmac' | 'oauth2' | 'mutual-tls' | 'none';
  /** Request schema (JSON Schema) */
  requestSchema?: object;
  /** Response schema (JSON Schema) */
  responseSchema?: object;
  /** Rate limit (requests per minute) */
  rateLimit?: number;
  /** Risk level */
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  /** Description */
  description: string;
}

/**
 * Certificate pinning configuration
 */
export interface CertificatePinningConfig {
  /** Whether certificate pinning is enabled */
  enabled: boolean;
  /** Pinned certificate SHA-256 hashes */
  pins: string[];
  /** Backup pins for rotation */
  backupPins?: string[];
  /** Pinning enforcement mode */
  mode: 'strict' | 'report-only' | 'custom';
  /** Custom validation logic class name */
  customValidatorClass?: string;
  /** Domains where pinning applies */
  domains: string[];
  /** Whether to allow user-installed CAs */
  allowUserCAs: boolean;
  /** Certificate transparency enforcement */
  requireCT: boolean;
}

/**
 * ProGuard mapping strategy for deobfuscation
 */
export interface ProGuardStrategy {
  /** Mapping file patterns to search for */
  mappingPatterns: string[];
  /** Known obfuscated class name patterns */
  classPatterns: RegExp[];
  /** Known obfuscated method name patterns */
  methodPatterns: RegExp[];
  /** Known obfuscated field name patterns */
  fieldPatterns: RegExp[];
  /** Custom renaming rules */
  renameRules: ProGuardRenameRule[];
  /** Whether to use reference mapping from Play Store */
  useReferenceMapping: boolean;
}

/**
 * ProGuard renaming rule
 */
export interface ProGuardRenameRule {
  /** Original pattern */
  pattern: RegExp;
  /** Replacement template */
  replacement: string;
  /** Confidence level */
  confidence: number;
}

/**
 * Native library analysis rule
 */
export interface NativeLibraryRule {
  /** Library name pattern */
  libraryPattern: RegExp;
  /** Architecture */
  arch: 'arm64-v8a' | 'armeabi-v7a' | 'x86' | 'x86_64' | 'all';
  /** Analysis type */
  analysisType: 'jni-bindings' | 'crypto-constants' | 'anti-tamper' | 'root-detection' | 'certificate-pinning' | 'custom';
  /** Expected exported functions */
  expectedExports?: string[];
  /** Suspicious patterns to detect */
  suspiciousPatterns: RegExp[];
  /** Custom analyzer class */
  customAnalyzer?: string;
  /** Risk level */
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Malware signature for African fintech threats
 */
export interface MalwareSignature {
  /** Unique signature ID */
  id: string;
  /** Signature name */
  name: string;
  /** Threat family */
  family: string;
  /** Target providers */
  targetProviders: string[];
  /** Target countries */
  targetCountries: string[];
  /** YARA rule */
  yaraRule: string;
  /** IOC hashes (SHA-256) */
  iocHashes: string[];
  /** Network IOCs */
  networkIocs: NetworkIoc[];
  /** Behavioral patterns */
  behavioralPatterns: BehavioralPattern[];
  /** Severity */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Discovery date */
  discoveredAt: string;
  /** Source */
  source: string;
  /** MITRE ATT&CK techniques */
  mitreTechniques: string[];
}

/**
 * Network indicator of compromise
 */
export interface NetworkIoc {
  /** Type of IOC */
  type: 'domain' | 'ip' | 'url' | 'certificate';
  /** Value */
  value: string;
  /** Description */
  description: string;
  /** Confidence */
  confidence: number;
}

/**
 * Behavioral pattern for malware detection
 */
export interface BehavioralPattern {
  /** Pattern ID */
  id: string;
  /** Description */
  description: string;
  /** Detection logic (pseudocode) */
  logic: string;
  /** APIs/permissions involved */
  apis: string[];
  /** Confidence */
  confidence: number;
}

/**
 * Protocol decoder for mobile money protocols
 */
export interface ProtocolDecoder {
  /** Protocol name */
  name: string;
  /** Protocol version */
  version: string;
  /** Transport protocol */
  transport: 'ussd' | 'http' | 'tcp' | 'sms' | 'custom';
  /** Message format */
  format: 'json' | 'xml' | 'protobuf' | 'tlv' | 'custom';
  /** Decoder implementation */
  decoderClass: string;
  /** Known message types */
  messageTypes: ProtocolMessageType[];
  /** Encryption scheme */
  encryption?: EncryptionScheme;
}

/**
 * Protocol message type definition
 */
export interface ProtocolMessageType {
  /** Message type identifier */
  typeId: string;
  /** Message name */
  name: string;
  /** Direction */
  direction: 'request' | 'response' | 'notification';
  /** Field definitions */
  fields: ProtocolField[];
}

/**
 * Protocol field definition
 */
export interface ProtocolField {
  /** Field name */
  name: string;
  /** Field type */
  type: 'string' | 'number' | 'boolean' | 'bytes' | 'struct' | 'array';
  /** Whether required */
  required: boolean;
  /** Description */
  description: string;
  /** Nested fields for struct type */
  fields?: ProtocolField[];
  /** Validation rules */
  validation?: string[];
}

/**
 * Encryption scheme for protocol
 */
export interface EncryptionScheme {
  /** Algorithm */
  algorithm: 'AES-GCM' | 'AES-CBC' | 'ChaCha20-Poly1305' | 'RSA-OAEP' | 'custom';
  /** Key derivation */
  keyDerivation: 'PBKDF2' | 'HKDF' | 'scrypt' | 'custom';
  /** Key length */
  keyLength: number;
  /** IV/Nonce length */
  ivLength: number;
  /** Custom implementation class */
  customClass?: string;
}

/**
 * Complete African fintech profile
 */
export interface AfricanFintechProfile {
  /** Provider identifier */
  id: string;
  /** Display name */
  name: string;
  /** Countries where this provider operates */
  countries: string[];
  /** Provider category */
  category: 'mobile-money' | 'banking' | 'remittance' | 'payment-gateway' | 'lending' | 'savings' | 'insurance';
  /** USSD patterns */
  ussdPatterns: UssdPattern[];
  /** API endpoints */
  apiEndpoints: ApiEndpoint[];
  /** Certificate pinning config */
  certificatePinning: CertificatePinningConfig;
  /** ProGuard strategy */
  proGuardStrategy: ProGuardStrategy;
  /** Native library rules */
  nativeLibraryRules: NativeLibraryRule[];
  /** Malware signatures */
  malwareSignatures: MalwareSignature[];
  /** Protocol decoders */
  protocolDecoders: ProtocolDecoder[];
  /** Known package names */
  packageNames: string[];
  /** Known signing certificates */
  signingCertificates: string[];
  /** Minimum app version supported */
  minVersion: string;
  /** Maximum app version tested */
  maxVersionTested: string;
  /** Profile version */
  profileVersion: string;
  /** Last updated */
  lastUpdated: string;
  /** Maintainer */
  maintainer: string;
}