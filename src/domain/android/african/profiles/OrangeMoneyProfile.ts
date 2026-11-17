/**
 * Orange Money Reverse Engineering Profile
 *
 * Covers Orange Money West Africa (CI, SN, ML, BF, GN, BJ, LR, SL, CM)
 * USSD: *144# (CI/SN), *144*1# (ML), *144*2# (BF), *144*3# (GN)
 * Package: com.orange.money, com.orange.money.ci, com.orange.money.sn, etc.
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

export class OrangeMoneyProfile extends BaseAfricanFintechProfile {
  override readonly id = 'orange-money';
  override readonly name = 'Orange Money';
  override readonly countries = ['CI', 'SN', 'ML', 'BF', 'GN', 'BJ', 'LR', 'SL', 'CM'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.orange.money',
    'com.orange.money.ci',
    'com.orange.money.sn',
    'com.orange.money.ml',
    'com.orange.money.bf',
    'com.orange.money.gn',
    'com.orange.money.bj',
    'com.orange.money.lr',
    'com.orange.money.sl',
    'com.orange.money.cm',
  ];
  override readonly signingCertificates = [
    'SHA256:OR:AN:GE:MO:NE:YC:ER:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '6.1.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'orange-money-ci-main',
      name: 'Orange Money Côte d\'Ivoire Main Menu',
      code: '*144#',
      region: ['CI'],
      provider: 'Orange Money',
      sessionTimeout: 180,
      responsePatterns: [
        /Orange Money/i,
        /Transfert/i,
        /Retrait/i,
        /Recharge/i,
        /Paiement/i,
        /Mon Compte/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Orange Money',
        options: [
          { key: '1', text: 'Transfert', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Retrait', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Recharge', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Paiement', action: 'billpay', childNodeId: 'pay_bills', riskLevel: 'high' },
          { key: '5', text: 'Mon Compte', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
    {
      id: 'orange-money-sn-main',
      name: 'Orange Money Senegal Main Menu',
      code: '*144#',
      region: ['SN'],
      provider: 'Orange Money',
      sessionTimeout: 180,
      responsePatterns: [
        /Orange Money/i,
        /Transfert/i,
        /Retrait/i,
        /Recharge/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'Orange Money',
        options: [
          { key: '1', text: 'Transfert', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Retrait', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Recharge', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Paiement', action: 'billpay', childNodeId: 'pay_bills', riskLevel: 'high' },
          { key: '5', text: 'Mon Compte', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'orange-money-transfer',
      'POST',
      '/orange/money/v1/transfer',
      'https://api.orange.com',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'orange-money-withdraw',
      'POST',
      '/orange/money/v1/withdraw',
      'https://api.orange.com',
      'Withdraw cash',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'orange-money-balance',
      'GET',
      '/orange/money/v1/balance',
      'https://api.orange.com',
      'Get balance',
      'bearer',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/ORANGEMONEYPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/ORANGEMONEYPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.orange.com', 'api.orange.money'],
    allowUserCAs: false,
    requireCT: true,
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Orange[A-Z]/, /^Money[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^withdraw/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('liborange.*\\.so'),
    this.createRootDetectionNativeRule('liborange.*\\.so'),
    this.createAntiTamperNativeRule('liborange.*\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'orange-money-fakeapp-001',
      'Fake Orange Money App',
      'FakeOrangeApp',
      ['Orange Money'],
      ['CI', 'SN', 'ML', 'BF'],
      `rule FakeOrangeMoneyApp {
        meta:
          description = "Detects fake Orange Money applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $orange1 = "Orange Money" ascii wide
          $orange2 = "com.orange.money" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($orange1 or $orange2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Orange Money API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'OrangeMoneyDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'recipient', type: 'string', required: true, description: 'Recipient phone number' },
            { name: 'amount', type: 'number', required: true, description: 'Amount to transfer' },
            { name: 'currency', type: 'string', required: true, description: 'Currency code (XOF/XAF)' },
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
  ];
}