/**
 * Opay Reverse Engineering Profile
 *
 * Covers Opay Nigeria, Egypt
 * USSD: *955#
 * Package: com.opay.opay, com.opay.opay.ng, com.opay.opay.eg
 */

import { BaseAfricanFintechProfile } from './BaseAfricanFintechProfile.js';
import type {
  UssdPattern,
  ApiEndpoint,
  CertificatePinningConfig,
  ProGuardStrategy,
  NativeLibraryRule,
  MalwareSignature,
  ProtocolDecoder,
} from '../types.js';

export class OpayProfile extends BaseAfricanFintechProfile {
  override readonly id = 'opay';
  override readonly name = 'Opay';
  override readonly countries = ['NG', 'EG'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.opay.opay',
    'com.opay.opay.ng',
    'com.opay.opay.eg',
    'com.opay.mobile',
  ];
  override readonly signingCertificates = [
    'SHA256:OP:AY:NG:EG:MO:BI:LE:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '3.12.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'opay-ng-main',
      name: 'Opay Nigeria Main Menu',
      code: '*955#',
      region: ['NG'],
      provider: 'Opay',
      sessionTimeout: 180,
      responsePatterns: [
        /Opay/i,
        /Transfer/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bills/i,
        /OKash/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Opay',
        options: [
          { key: '1', text: 'Transfer', action: 'transfer', childNodeId: 'transfer', riskLevel: 'high' },
          { key: '2', text: 'Withdraw', action: 'withdraw', childNodeId: 'withdraw', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bills', action: 'billpay', childNodeId: 'bills', riskLevel: 'high' },
          { key: '5', text: 'OKash Loans', action: 'loan', childNodeId: 'okash', riskLevel: 'high' },
          { key: '6', text: 'My Wallet', action: 'balance', childNodeId: 'wallet', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'opay-transfer',
      'POST',
      '/opay/v1/transfer',
      'https://api.opay.com',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'opay-withdraw',
      'POST',
      '/opay/v1/withdraw',
      'https://api.opay.com',
      'Withdraw cash',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'opay-balance',
      'GET',
      '/opay/v1/balance',
      'https://api.opay.com',
      'Get balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'opay-loan-apply',
      'POST',
      '/opay/v1/okash/loans/apply',
      'https://api.opay.com',
      'Apply for OKash loan',
      'bearer',
      'high'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/OPAYPINNINGHASHAAAAAAAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/OPAYPINNINGBACKUPBBBBBBBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.opay.com', 'opay.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.opay.opay.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Opay[A-Z]/, /^OKash[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^withdraw/, /^loan/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libopay.*\\\\.so'),
    this.createRootDetectionNativeRule('libopay.*\\\\.so'),
    this.createAntiTamperNativeRule('libopay.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'opay-fakeapp-001',
      'Fake Opay App',
      'FakeOpayApp',
      ['Opay'],
      ['NG', 'EG'],
      `rule FakeOpayApp {
        meta:
          description = "Detects fake Opay applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $opay1 = "Opay" ascii wide
          $opay2 = "com.opay" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($opay1 or $opay2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Opay API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'OpayDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone/Opay ID' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in NGN/EGP' },
            { name: 'pin', type: 'string', required: true, description: 'Transaction PIN' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}