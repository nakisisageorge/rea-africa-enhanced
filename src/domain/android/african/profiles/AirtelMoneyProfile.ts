/**
 * Airtel Money Reverse Engineering Profile
 *
 * Covers Airtel Money across 14 African countries
 * USSD: *185*1*1# (Nigeria), *185# (Kenya), *185*1# (Tanzania), *185*1# (Uganda), *185*1# (Rwanda), *185*1# (Malawi), *185*1# (Zambia), *185*1# (DRC), *185*1# (Gabon), *185*1# (Niger), *185*1# (Chad), *185*1# (Seychelles), *185*1# (Madagascar), *185*1# (Congo)
 * Package: com.airtel.money, com.airtel.money.ng, com.airtel.money.ke, etc.
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

export class AirtelMoneyProfile extends BaseAfricanFintechProfile {
  override readonly id = 'airtel-money';
  override readonly name = 'Airtel Money';
  override readonly countries = ['NG', 'KE', 'TZ', 'UG', 'RW', 'MW', 'ZM', 'CD', 'GA', 'NE', 'TD', 'SC', 'MG', 'CG'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.airtel.money',
    'com.airtel.money.ng',
    'com.airtel.money.ke',
    'com.airtel.money.tz',
    'com.airtel.money.ug',
    'com.airtel.money.rw',
    'com.airtel.money.mw',
    'com.airtel.money.zm',
    'com.airtel.money.cd',
    'com.airtel.money.ga',
    'com.airtel.money.ne',
    'com.airtel.money.td',
    'com.airtel.money.sc',
    'com.airtel.money.mg',
    'com.airtel.money.cg',
  ];
  override readonly signingCertificates = [
    'SHA256:AI:RT:EL:MO:NE:YC:ER:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '5.2.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'airtel-money-ng-main',
      name: 'Airtel Money Nigeria Main Menu',
      code: '*185*1*1#',
      region: ['NG'],
      provider: 'Airtel Money',
      sessionTimeout: 180,
      responsePatterns: [
        /Airtel Money/i,
        /Send Money/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bills/i,
        /My Account/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Airtel Money',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw Cash', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Buy Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bills', action: 'billpay', childNodeId: 'pay_bills', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
    {
      id: 'airtel-money-ke-main',
      name: 'Airtel Money Kenya Main Menu',
      code: '*185#',
      region: ['KE'],
      provider: 'Airtel Money',
      sessionTimeout: 180,
      responsePatterns: [
        /Airtel Money/i,
        /Send Money/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bills/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Airtel Money',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw Cash', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Buy Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bills', action: 'billpay', childNodeId: 'pay_bills', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'airtel-money-transfer',
      'POST',
      '/airtel/money/v1/transfer',
      'https://api.airtel.africa',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'airtel-money-cashout',
      'POST',
      '/airtel/money/v1/cashout',
      'https://api.airtel.africa',
      'Cash out/withdraw',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'airtel-money-balance',
      'GET',
      '/airtel/money/v1/balance',
      'https://api.airtel.africa',
      'Get balance',
      'bearer',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/AIRTELMONEYPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/AIRTELMONEYPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.airtel.africa', 'api.airtel.money'],
    allowUserCAs: false,
    requireCT: true,
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Airtel[A-Z]/, /^Money[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^cashout/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libairtel.*\\.so'),
    this.createRootDetectionNativeRule('libairtel.*\\.so'),
    this.createAntiTamperNativeRule('libairtel.*\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'airtel-money-fakeapp-001',
      'Fake Airtel Money App',
      'FakeAirtelApp',
      ['Airtel Money'],
      ['NG', 'KE', 'TZ', 'UG', 'RW'],
      `rule FakeAirtelMoneyApp {
        meta:
          description = "Detects fake Airtel Money applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $airtel1 = "Airtel Money" ascii wide
          $airtel2 = "com.airtel.money" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($airtel1 or $airtel2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Airtel Money API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'AirtelMoneyDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone number' },
            { name: 'amount', type: 'number', required: true, description: 'Amount to transfer' },
            { name: 'currency', type: 'string', required: true, description: 'Currency code' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}