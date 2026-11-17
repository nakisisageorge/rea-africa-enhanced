/**
 * M-Pawa Reverse Engineering Profile
 *
 * Covers M-Pawa Tanzania (M-Pesa savings/loan product)
 * USSD: *150*00# (via M-Pesa)
 * Package: com.vodacom.mpawa, com.vodacom.mpawa.tz
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

export class MPawaProfile extends BaseAfricanFintechProfile {
  override readonly id = 'mpawa';
  override readonly name = 'M-Pawa';
  override readonly countries = ['TZ'];
  override readonly category = 'savings' as const;
  override readonly packageNames = [
    'com.vodacom.mpawa',
    'com.vodacom.mpawa.tz',
    'com.vodacom.mpesatz',
  ];
  override readonly signingCertificates = [
    'SHA256:MP:AW:A:SA:VI:N:GS:LO:AN:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '1.8.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'mpawa-tz-main',
      name: 'M-Pawa Tanzania Menu',
      code: '*150*00#',
      region: ['TZ'],
      provider: 'M-Pawa',
      sessionTimeout: 180,
      responsePatterns: [
        /M-Pawa/i,
        /Savings/i,
        /Loans/i,
        /Deposit/i,
        /Withdraw/i,
        /Balance/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'M-Pawa',
        options: [
          { key: '1', text: 'Savings', action: 'savings', childNodeId: 'savings_menu', riskLevel: 'medium' },
          { key: '2', text: 'Loans', action: 'loan', childNodeId: 'loans_menu', riskLevel: 'high' },
          { key: '3', text: 'Deposit', action: 'deposit', childNodeId: 'deposit', riskLevel: 'high' },
          { key: '4', text: 'Withdraw', action: 'withdraw', childNodeId: 'withdraw', riskLevel: 'high' },
          { key: '5', text: 'Balance', action: 'balance', childNodeId: 'balance', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'mpawa-deposit',
      'POST',
      '/mpawa/v1/deposit',
      'https://api.vodacom.co.tz',
      'Deposit to savings',
      'bearer',
      'high'
    ),
    this.createApiEndpoint(
      'mpawa-withdraw',
      'POST',
      '/mpawa/v1/withdraw',
      'https://api.vodacom.co.tz',
      'Withdraw from savings',
      'bearer',
      'high'
    ),
    this.createApiEndpoint(
      'mpawa-loan-apply',
      'POST',
      '/mpawa/v1/loans/apply',
      'https://api.vodacom.co.tz',
      'Apply for loan',
      'bearer',
      'high'
    ),
    this.createApiEndpoint(
      'mpawa-balance',
      'GET',
      '/mpawa/v1/balance',
      'https://api.vodacom.co.tz',
      'Get savings balance',
      'bearer',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/MPAWAPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/MPAWAPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.vodacom.co.tz', 'vodacom.co.tz'],
    allowUserCAs: false,
    requireCT: true,
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Mpawa[A-Z]/, /^Mpesa[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^deposit/, /^withdraw/, /^loan/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^amount/, /^account/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libmpawa.*\\\\.so'),
    this.createRootDetectionNativeRule('libmpawa.*\\\\.so'),
    this.createAntiTamperNativeRule('libmpawa.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'mpawa-fakeapp-001',
      'Fake M-Pawa App',
      'FakeMpawaApp',
      ['M-Pawa'],
      ['TZ'],
      `rule FakeMpawaApp {
        meta:
          description = "Detects fake M-Pawa applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $mpawa1 = "M-Pawa" ascii wide
          $mpawa2 = "com.vodacom.mpawa" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($mpawa1 or $mpawa2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'M-Pawa API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'MpawaDecoder',
      messageTypes: [
        {
          typeId: 'deposit_request',
          name: 'Deposit Request',
          direction: 'request',
          fields: [
            { name: 'amount', type: 'number', required: true, description: 'Deposit amount in TZS' },
            { name: 'source', type: 'string', required: true, description: 'Source (M-Pesa wallet)' },
            { name: 'pin', type: 'string', required: true, description: 'User PIN' },
          ],
        },
      ],
    },
  ];
}