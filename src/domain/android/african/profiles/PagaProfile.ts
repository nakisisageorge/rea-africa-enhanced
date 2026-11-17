/**
 * Paga Reverse Engineering Profile
 *
 * Covers Paga Nigeria
 * USSD: *242#
 * Package: com.paga.paga, com.paga.paga.ng
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

export class PagaProfile extends BaseAfricanFintechProfile {
  override readonly id = 'paga';
  override readonly name = 'Paga';
  override readonly countries = ['NG'];
  override readonly category = 'payment-gateway' as const;
  override readonly packageNames = [
    'com.paga.paga',
    'com.paga.paga.ng',
    'com.paga.agent',
  ];
  override readonly signingCertificates = [
    'SHA256:PA:GA:NG:PA:YM:EN:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '4.5.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'paga-ng-main',
      name: 'Paga Nigeria Main Menu',
      code: '*242#',
      region: ['NG'],
      provider: 'Paga',
      sessionTimeout: 180,
      responsePatterns: [
        /Paga/i,
        /Send Money/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bills/i,
        /Agent/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Paga',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bills', action: 'billpay', childNodeId: 'pay_bills', riskLevel: 'high' },
          { key: '5', text: 'Find Agent', action: 'menu', childNodeId: 'find_agent', riskLevel: 'low' },
          { key: '6', text: 'My Account', action: 'balance', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'paga-transfer',
      'POST',
      '/paga/v1/transfer',
      'https://api.paga.com',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'paga-withdraw',
      'POST',
      '/paga/v1/withdraw',
      'https://api.paga.com',
      'Withdraw cash',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'paga-balance',
      'GET',
      '/paga/v1/balance',
      'https://api.paga.com',
      'Get balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'paga-agent-find',
      'GET',
      '/paga/v1/agents/nearby',
      'https://api.paga.com',
      'Find nearby agents',
      'bearer',
      'low'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/PAGAPINNINGHASHAAAAAAAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/PAGAPINNINGBACKUPBBBBBBBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.paga.com', 'paga.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.paga.paga.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Paga[A-Z]/, /^Agent[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^withdraw/, /^agent/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libpaga.*\\\\.so'),
    this.createRootDetectionNativeRule('libpaga.*\\\\.so'),
    this.createAntiTamperNativeRule('libpaga.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'paga-fakeapp-001',
      'Fake Paga App',
      'FakePagaApp',
      ['Paga'],
      ['NG'],
      `rule FakePagaApp {
        meta:
          description = "Detects fake Paga applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $paga1 = "Paga" ascii wide
          $paga2 = "com.paga" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($paga1 or $paga2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Paga API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'PagaDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone/Paga ID' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in NGN' },
            { name: 'pin', type: 'string', required: true, description: 'Transaction PIN' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}