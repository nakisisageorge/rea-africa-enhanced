/**
 * EcoCash Reverse Engineering Profile
 *
 * Covers EcoCash Zimbabwe
 * USSD: *151#
 * Package: com.ecocash.ecocash, com.ecocash.ecocash.zw
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

export class EcoCashProfile extends BaseAfricanFintechProfile {
  override readonly id = 'ecocash';
  override readonly name = 'EcoCash';
  override readonly countries = ['ZW'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.ecocash.ecocash',
    'com.ecocash.ecocash.zw',
    'com.econet.ecocash',
  ];
  override readonly signingCertificates = [
    'SHA256:EC:OC:AS:HZ:IM:BA:BW:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '4.2.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'ecocash-zw-main',
      name: 'EcoCash Zimbabwe Main Menu',
      code: '*151#',
      region: ['ZW'],
      provider: 'EcoCash',
      sessionTimeout: 180,
      responsePatterns: [
        /EcoCash/i,
        /Send Money/i,
        /Cash Out/i,
        /Airtime/i,
        /Pay Merchant/i,
        /Banking/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'EcoCash',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Cash Out', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Merchant', action: 'billpay', childNodeId: 'pay_merchant', riskLevel: 'high' },
          { key: '5', text: 'Banking', action: 'menu', childNodeId: 'banking', riskLevel: 'high' },
          { key: '6', text: 'My Wallet', action: 'balance', childNodeId: 'my_wallet', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'ecocash-transfer',
      'POST',
      '/ecocash/v1/transfer',
      'https://api.ecocash.co.zw',
      'Send money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'ecocash-cashout',
      'POST',
      '/ecocash/v1/cashout',
      'https://api.ecocash.co.zw',
      'Cash out',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'ecocash-balance',
      'GET',
      '/ecocash/v1/balance',
      'https://api.ecocash.co.zw',
      'Get balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'ecocash-merchant-payment',
      'POST',
      '/ecocash/v1/merchant/payment',
      'https://api.ecocash.co.zw',
      'Merchant payment',
      'bearer',
      'high'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/ECOCASHPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/ECOCASHPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.ecocash.co.zw', 'ecocash.co.zw'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.ecocash.ecocash.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Eco[A-Z]/, /^Cash[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^send/, /^cashOut/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libecocash.*\\\\.so'),
    this.createRootDetectionNativeRule('libecocash.*\\\\.so'),
    this.createAntiTamperNativeRule('libecocash.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'ecocash-fakeapp-001',
      'Fake EcoCash App',
      'FakeEcoCashApp',
      ['EcoCash'],
      ['ZW'],
      `rule FakeEcoCashApp {
        meta:
          description = "Detects fake EcoCash applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $ecocash1 = "EcoCash" ascii wide
          $ecocash2 = "com.ecocash" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($ecocash1 or $ecocash2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'EcoCash API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'EcoCashDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient EcoCash number' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in ZWL' },
            { name: 'pin', type: 'string', required: true, description: 'User PIN' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}