/**
 * Wave Reverse Engineering Profile
 *
 * Covers Wave Senegal, Ivory Coast
 * USSD: *123# (SN), *123*1# (CI)
 * Package: com.waveapp, com.waveapp.sn, com.waveapp.ci
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

export class WaveProfile extends BaseAfricanFintechProfile {
  override readonly id = 'wave';
  override readonly name = 'Wave';
  override readonly countries = ['SN', 'CI'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.waveapp',
    'com.waveapp.sn',
    'com.waveapp.ci',
  ];
  override readonly signingCertificates = [
    'SHA256:WA:VE:AP:P:CE:RT:IF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '4.5.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'wave-sn-main',
      name: 'Wave Senegal Main Menu',
      code: '*123#',
      region: ['SN'],
      provider: 'Wave',
      sessionTimeout: 180,
      responsePatterns: [
        /Wave/i,
        /Send/i,
        /Cash Out/i,
        /Airtime/i,
        /Bill/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Wave',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Cash Out', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bills', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
    {
      id: 'wave-ci-main',
      name: 'Wave Côte d\'Ivoire Main Menu',
      code: '*123*1#',
      region: ['CI'],
      provider: 'Wave',
      sessionTimeout: 180,
      responsePatterns: [
        /Wave/i,
        /Envoyer/i,
        /Retrait/i,
        /Recharge/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Wave',
        options: [
          { key: '1', text: 'Envoyer', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Retrait', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Recharge', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Payer', action: 'billpay', childNodeId: 'pay_bills', riskLevel: 'high' },
          { key: '5', text: 'Mon Compte', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'wave-transfer',
      'POST',
      '/wave/v1/transfer',
      'https://api.wave.com',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'wave-cashout',
      'POST',
      '/wave/v1/cashout',
      'https://api.wave.com',
      'Cash out',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'wave-balance',
      'GET',
      '/wave/v1/balance',
      'https://api.wave.com',
      'Get balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'wave-merchant-payment',
      'POST',
      '/wave/v1/merchant/payment',
      'https://api.wave.com',
      'Merchant payment',
      'bearer',
      'critical'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/WAVEPINNINGHASHAAAAAAAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/WAVEPINNINGBACKUPBBBBBBBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.wave.com', 'wave.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.waveapp.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Wave[A-Z]/, /^Transfer[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^sendMoney/, /^cashOut/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libwave.*\\.so'),
    this.createRootDetectionNativeRule('libwave.*\\.so'),
    this.createAntiTamperNativeRule('libwave.*\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'wave-fakeapp-001',
      'Fake Wave App',
      'FakeWaveApp',
      ['Wave'],
      ['SN', 'CI'],
      `rule FakeWaveApp {
        meta:
          description = "Detects fake Wave applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $wave1 = "Wave" ascii wide
          $wave2 = "com.waveapp" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($wave1 or $wave2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Wave API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'WaveDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone/identifier' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in smallest currency unit' },
            { name: 'currency', type: 'string', required: true, description: 'Currency code (XOF)' },
            { name: 'idempotencyKey', type: 'string', required: true, description: 'Idempotency key' },
          ],
        },
      ],
    },
  ];
}