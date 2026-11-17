/**
 * EazzyPay Reverse Engineering Profile
 *
 * Covers EazzyPay by Equity Bank Kenya
 * USSD: *838#
 * Package: com.equitybank.eazzy, com.equitybank.eazzy.ke
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

export class EazzyPayProfile extends BaseAfricanFintechProfile {
  override readonly id = 'eazzy-pay';
  override readonly name = 'EazzyPay';
  override readonly countries = ['KE'];
  override readonly category = 'banking' as const;
  override readonly packageNames = [
    'com.equitybank.eazzy',
    'com.equitybank.eazzy.ke',
    'com.equitybank.mobile',
  ];
  override readonly signingCertificates = [
    'SHA256:EA:ZZ:YP:AY:BA:NK:KE:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '3.8.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'eazzy-pay-ke-main',
      name: 'EazzyPay Kenya Main Menu',
      code: '*838#',
      region: ['KE'],
      provider: 'EazzyPay',
      sessionTimeout: 180,
      responsePatterns: [
        /EazzyPay/i,
        /Send Money/i,
        /Withdraw/i,
        /Pay Bill/i,
        /Buy Airtime/i,
        /Loans/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'EazzyPay',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw Cash', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '4', text: 'Buy Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '5', text: 'Loans', action: 'loan', childNodeId: 'loans', riskLevel: 'high' },
          { key: '6', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'eazzy-transfer',
      'POST',
      '/eazzy/v1/transfer',
      'https://api.eazzy.net',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'eazzy-withdraw',
      'POST',
      '/eazzy/v1/withdraw',
      'https://api.eazzy.net',
      'Withdraw cash',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'eazzy-balance',
      'GET',
      '/eazzy/v1/balance',
      'https://api.eazzy.net',
      'Get balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'eazzy-loan-apply',
      'POST',
      '/eazzy/v1/loans/apply',
      'https://api.eazzy.net',
      'Apply for loan',
      'bearer',
      'high'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/EAZZYPAYPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/EAZZYPAYPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.eazzy.net', 'eazzy.net'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.equitybank.eazzy.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Eazzy[A-Z]/, /^Equity[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^withdraw/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libeazzy.*\\\\.so'),
    this.createRootDetectionNativeRule('libeazzy.*\\\\.so'),
    this.createAntiTamperNativeRule('libeazzy.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'eazzy-fakeapp-001',
      'Fake EazzyPay App',
      'FakeEazzyApp',
      ['EazzyPay'],
      ['KE'],
      `rule FakeEazzyPayApp {
        meta:
          description = "Detects fake EazzyPay applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $eazzy1 = "EazzyPay" ascii wide
          $eazzy2 = "com.equitybank.eazzy" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($eazzy1 or $eazzy2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'EazzyPay API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'EazzyPayDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone/identifier' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in KES' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}