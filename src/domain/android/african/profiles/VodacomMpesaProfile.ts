/**
 * Vodacom M-Pesa Reverse Engineering Profile
 *
 * Covers Vodacom M-Pesa Tanzania, DRC, Lesotho, Mozambique
 * USSD: *150*00# (TZ), *150*00# (CD), *150*00# (LS), *150*00# (MZ)
 * Package: com.vodacom.mpesa, com.vodacom.mpesa.tz, com.vodacom.mpesa.cd, etc.
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

export class VodacomMpesaProfile extends BaseAfricanFintechProfile {
  override readonly id = 'vodacom-mpesa';
  override readonly name = 'Vodacom M-Pesa';
  override readonly countries = ['TZ', 'CD', 'LS', 'MZ'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.vodacom.mpesa',
    'com.vodacom.mpesa.tz',
    'com.vodacom.mpesa.cd',
    'com.vodacom.mpesa.ls',
    'com.vodacom.mpesa.mz',
    'com.vodacom.mpesatz',
    'com.vodacom.mpesacd',
  ];
  override readonly signingCertificates = [
    'SHA256:VO:DA:CO:MP:ES:A:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '5.8.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'vodacom-mpesa-tz-main',
      name: 'Vodacom M-Pesa Tanzania Main Menu',
      code: '*150*00#',
      region: ['TZ'],
      provider: 'Vodacom M-Pesa',
      sessionTimeout: 180,
      responsePatterns: [
        /M-PESA/i,
        /Send Money/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bill/i,
        /M-Pawa/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'M-PESA',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'M-Pawa', action: 'savings', childNodeId: 'mpawa', riskLevel: 'high' },
          { key: '6', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
    {
      id: 'vodacom-mpesa-cd-main',
      name: 'Vodacom M-Pesa DRC Main Menu',
      code: '*150*00#',
      region: ['CD'],
      provider: 'Vodacom M-Pesa',
      sessionTimeout: 180,
      responsePatterns: [
        /M-PESA/i,
        /Envoyer/i,
        /Retirer/i,
        /Recharger/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'M-PESA',
        options: [
          { key: '1', text: 'Envoyer', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Retirer', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Recharger', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Paiement', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'vodacom-mpesa-transfer',
      'POST',
      '/mpesa/v1/transfer',
      'https://api.vodacom.co.tz',
      'Transfer money',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'vodacom-mpesa-withdraw',
      'POST',
      '/mpesa/v1/withdraw',
      'https://api.vodacom.co.tz',
      'Withdraw cash',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'vodacom-mpesa-balance',
      'GET',
      '/mpesa/v1/balance',
      'https://api.vodacom.co.tz',
      'Get balance',
      'bearer',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/VODACOMPESAPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/VODACOMPESAPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: [
      'api.vodacom.co.tz',
      'api.vodacom.co.cd',
      'api.vodacom.co.ls',
      'api.vodacom.co.mz',
    ],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.vodacom.mpesa.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Vodacom[A-Z]/, /^Mpesa[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^transfer/, /^withdraw/, /^send/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libvodacom.*\\\\.so'),
    this.createRootDetectionNativeRule('libvodacom.*\\\\.so'),
    this.createAntiTamperNativeRule('libvodacom.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'vodacom-mpesa-fakeapp-001',
      'Fake Vodacom M-Pesa App',
      'FakeVodacomMpesaApp',
      ['Vodacom M-Pesa'],
      ['TZ', 'CD', 'LS', 'MZ'],
      `rule FakeVodacomMpesaApp {
        meta:
          description = "Detects fake Vodacom M-Pesa applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $vod1 = "M-PESA" ascii wide
          $vod2 = "Vodacom" ascii wide
          $vod3 = "com.vodacom.mpesa" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($vod1 or $vod2 or $vod3) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Vodacom M-Pesa API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'VodacomMpesaDecoder',
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