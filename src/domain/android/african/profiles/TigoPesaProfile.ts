/**
 * Tigo Pesa Reverse Engineering Profile
 *
 * Covers Tigo Pesa Tanzania, Rwanda, Ghana
 * USSD: *150*01# (TZ), *150*01# (RW), *150*01# (GH)
 * Package: com.tigo.pesa, com.tigo.pesa.tz, com.tigo.pesa.rw, com.tigo.pesa.gh
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

export class TigoPesaProfile extends BaseAfricanFintechProfile {
  override readonly id = 'tigo-pesa';
  override readonly name = 'Tigo Pesa';
  override readonly countries = ['TZ', 'RW', 'GH'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.tigo.pesa',
    'com.tigo.pesa.tz',
    'com.tigo.pesa.rw',
    'com.tigo.pesa.gh',
  ];
  override readonly signingCertificates = [
    'SHA256:TI:GO:PE:SA:AF:RI:CA:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '3.2.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'tigo-pesa-tz-main',
      name: 'Tigo Pesa Tanzania Main Menu',
      code: '*150*01#',
      region: ['TZ'],
      provider: 'Tigo Pesa',
      sessionTimeout: 180,
      responsePatterns: [
        /Tigo Pesa/i,
        /Send Money/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bill/i,
        /Tigo Cash/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Tigo Pesa',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'Tigo Cash', action: 'loan', childNodeId: 'tigo_cash', riskLevel: 'high' },
          { key: '6', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
    {
      id: 'tigo-pesa-rw-main',
      name: 'Tigo Pesa Rwanda Main Menu',
      code: '*150*01#',
      region: ['RW'],
      provider: 'Tigo Pesa',
      sessionTimeout: 180,
      responsePatterns: [
        /Tigo Cash/i,
        /Transfer/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bill/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Tigo Cash',
        options: [
          { key: '1', text: 'Transfer', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'balance', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'tigo-pesa-transfer',
      'POST',
      '/tigo/pesa/v1/transfer',
      'https://api.tigo.com',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'tigo-pesa-withdraw',
      'POST',
      '/tigo/pesa/v1/withdraw',
      'https://api.tigo.com',
      'Withdraw cash',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'tigo-pesa-balance',
      'GET',
      '/tigo/pesa/v1/balance',
      'https://api.tigo.com',
      'Get balance',
      'bearer',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/TIGOPESAPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/TIGOPESAPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.tigo.com', 'tigo.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.tigo.pesa.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Tigo[A-Z]/, /^Pesa[A-Z]/, /^Cash[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^withdraw/, /^cash/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libtigo.*\\\\.so'),
    this.createRootDetectionNativeRule('libtigo.*\\\\.so'),
    this.createAntiTamperNativeRule('libtigo.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'tigo-pesa-fakeapp-001',
      'Fake Tigo Pesa App',
      'FakeTigoPesaApp',
      ['Tigo Pesa'],
      ['TZ', 'RW', 'GH'],
      `rule FakeTigoPesaApp {
        meta:
          description = "Detects fake Tigo Pesa applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $tigo1 = "Tigo Pesa" ascii wide
          $tigo2 = "Tigo Cash" ascii wide
          $tigo3 = "com.tigo.pesa" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($tigo1 or $tigo2 or $tigo3) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Tigo Pesa API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'TigoPesaDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone number' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in local currency' },
            { name: 'pin', type: 'string', required: true, description: 'User PIN' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}