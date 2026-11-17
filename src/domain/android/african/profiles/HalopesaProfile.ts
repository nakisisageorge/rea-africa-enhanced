/**
 * Halopesa Reverse Engineering Profile
 *
 * Covers Halopesa Tanzania
 * USSD: *148*88#
 * Package: com.halopesa.halopesa, com.halopesa.halopesa.tz
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

export class HalopesaProfile extends BaseAfricanFintechProfile {
  override readonly id = 'halopesa';
  override readonly name = 'Halopesa';
  override readonly countries = ['TZ'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.halopesa.halopesa',
    'com.halopesa.halopesa.tz',
    'com.halotel.halopesa',
  ];
  override readonly signingCertificates = [
    'SHA256:HA:LO:PE:SA:TZ:TE:LE:CO:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '2.5.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'halopesa-tz-main',
      name: 'Halopesa Tanzania Main Menu',
      code: '*148*88#',
      region: ['TZ'],
      provider: 'Halopesa',
      sessionTimeout: 180,
      responsePatterns: [
        /Halopesa/i,
        /Send Money/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bill/i,
        /Save/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Halopesa',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'Save', action: 'savings', childNodeId: 'save', riskLevel: 'medium' },
          { key: '6', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'halopesa-transfer',
      'POST',
      '/halopesa/v1/transfer',
      'https://api.halopesa.com',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'halopesa-withdraw',
      'POST',
      '/halopesa/v1/withdraw',
      'https://api.halopesa.com',
      'Withdraw cash',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'halopesa-balance',
      'GET',
      '/halopesa/v1/balance',
      'https://api.halopesa.com',
      'Get balance',
      'bearer',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/HALOPESAPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/HALOPESAPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.halopesa.com', 'halopesa.com'],
    allowUserCAs: false,
    requireCT: true,
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Halo[A-Z]/, /^Pesa[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^withdraw/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libhalopesa.*\\\\.so'),
    this.createRootDetectionNativeRule('libhalopesa.*\\\\.so'),
    this.createAntiTamperNativeRule('libhalopesa.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'halopesa-fakeapp-001',
      'Fake Halopesa App',
      'FakeHalopesaApp',
      ['Halopesa'],
      ['TZ'],
      `rule FakeHalopesaApp {
        meta:
          description = "Detects fake Halopesa applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $halo1 = "Halopesa" ascii wide
          $halo2 = "com.halopesa" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($halo1 or $halo2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Halopesa API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'HalopesaDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone number' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in TZS' },
            { name: 'pin', type: 'string', required: true, description: 'User PIN' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}