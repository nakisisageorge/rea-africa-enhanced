/**
 * MTN MoMo (Mobile Money) Reverse Engineering Profile
 *
 * Covers MTN MoMo Uganda, Ghana, Nigeria, South Africa, Rwanda, Zambia, etc.
 * USSD: *165# (Uganda), *170# (Ghana), *556# (Nigeria), *120*321# (South Africa)
 * Package: com.mtn.momo, com.mtn.momo.ug, com.mtn.momo.gh, com.mtn.momo.ng
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

export class MtnMoMoProfile extends BaseAfricanFintechProfile {
  override readonly id = 'mtn-momo';
  override readonly name = 'MTN MoMo';
  override readonly countries = ['UG', 'GH', 'NG', 'ZA', 'RW', 'ZM', 'CI', 'CM', 'BF', 'BJ', 'GN', 'LR', 'SL', 'SS', 'SY'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.mtn.momo',
    'com.mtn.momo.ug',
    'com.mtn.momo.gh',
    'com.mtn.momo.ng',
    'com.mtn.momo.za',
    'com.mtn.momo.rw',
    'com.mtn.momo.zm',
    'com.mtn.momo.ci',
    'com.mtn.momo.cm',
  ];
  override readonly signingCertificates = [
    'SHA256:MT:N:MO:MO:CE:RT:IF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '8.4.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'mtn-momo-ug-main',
      name: 'MTN MoMo Uganda Main Menu',
      code: '*165#',
      region: ['UG'],
      provider: 'MTN MoMo',
      sessionTimeout: 180,
      responsePatterns: [
        /MoMo/i,
        /Send Money/i,
        /Withdraw Cash/i,
        /Buy Airtime/i,
        /Pay Bill/i,
        /My Account/i,
        /Loans/i,
        /Savings/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'MTN MoMo',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw Cash', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Buy Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
          { key: '6', text: 'Loans', action: 'loan', childNodeId: 'loans', riskLevel: 'high' },
          { key: '7', text: 'Savings', action: 'savings', childNodeId: 'savings', riskLevel: 'high' },
          { key: '8', text: 'Insurance', action: 'menu', childNodeId: 'insurance', riskLevel: 'medium' },
        ],
      },
    },
    {
      id: 'mtn-momo-gh-main',
      name: 'MTN MoMo Ghana Main Menu',
      code: '*170#',
      region: ['GH'],
      provider: 'MTN MoMo',
      sessionTimeout: 180,
      responsePatterns: [
        /MoMo/i,
        /Transfer/i,
        /Cash Out/i,
        /Airtime/i,
        /Pay Bill/i,
        /Bank Services/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'MTN MoMo',
        options: [
          { key: '1', text: 'Transfer Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Cash Out', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime & Bundles', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'Bank Services', action: 'menu', childNodeId: 'bank_services', riskLevel: 'high' },
          { key: '6', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
    {
      id: 'mtn-momo-ng-main',
      name: 'MTN MoMo Nigeria Main Menu',
      code: '*556#',
      region: ['NG'],
      provider: 'MTN MoMo',
      sessionTimeout: 180,
      responsePatterns: [
        /MoMo/i,
        /Send Money/i,
        /Withdraw/i,
        /Airtime/i,
        /Pay Bill/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'MTN MoMo',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw Cash', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'mtn-momo-collection',
      'POST',
      '/collection/v1_0/requesttopay',
      'https://proxy.momoapi.mtn.com',
      'Request to pay (collection)',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'mtn-momo-disbursement',
      'POST',
      '/disbursement/v1_0/transfer',
      'https://proxy.momoapi.mtn.com',
      'Disbursement transfer',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'mtn-momo-remittance',
      'POST',
      '/remittance/v1_0/transfer',
      'https://proxy.momoapi.mtn.com',
      'Remittance transfer',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'mtn-momo-account-holder',
      'GET',
      '/collection/v1_0/accountholder/msisdn/{msisdn}',
      'https://proxy.momoapi.mtn.com',
      'Get account holder info',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'mtn-momo-transaction-status',
      'GET',
      '/collection/v1_0/requesttopay/{referenceId}',
      'https://proxy.momoapi.mtn.com',
      'Get transaction status',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'mtn-momo-balance',
      'GET',
      '/collection/v1_0/account/balance',
      'https://proxy.momoapi.mtn.com',
      'Get account balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'mtn-momo-token',
      'POST',
      '/collection/token/',
      'https://proxy.momoapi.mtn.com',
      'Generate API token',
      'api-key',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: [
      'sha256/MTNMMOMPINNINGHASHESHEREAAAAAAAAAAAAAAAAAAAA=',
      'sha256/MTNMMOMPINNINGHASHBACKUPBBBBBBBBBBBBBBBBBBBB=',
    ],
    backupPins: [
      'sha256/MTNMMOMPINNINGHASHBACKUP2CCCCCCCCCCCCCCCCCCCC=',
    ],
    mode: 'strict',
    domains: [
      'proxy.momoapi.mtn.com',
      'momoapi.mtn.com',
      'api.mtn.com',
    ],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.mtn.momo.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: [
      'mapping.txt',
      'proguard/mapping.txt',
      'build/outputs/mapping/release/mapping.txt',
    ],
    classPatterns: [
      /^[a-z]{1,3}$/,
      /^[a-z][A-Z][a-z]+$/,
      /^MoMo[A-Z]/,
      /^Collection/,
      /^Disbursement/,
    ],
    methodPatterns: [
      /^[a-z]{1,2}$/,
      /^[a-z][A-Z][a-z]+$/,
      /^requestToPay/,
      /^transfer/,
      /^getBalance/,
    ],
    fieldPatterns: [
      /^[a-z]{1,2}$/,
      /^[a-z][A-Z][a-z]+$/,
      /^payer$/,
      /^payee$/,
      /^amount$/,
    ],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libmomo.*\\.so'),
    this.createRootDetectionNativeRule('libmomo.*\\.so'),
    this.createAntiTamperNativeRule('libmomo.*\\.so'),
    {
      libraryPattern: /libmomo.*\.so/,
      arch: 'all',
      analysisType: 'jni-bindings',
      expectedExports: [
        'Java_com_mtn_momo_security_NativeCrypto_encrypt',
        'Java_com_mtn_momo_security_NativeCrypto_decrypt',
        'Java_com_mtn_momo_security_NativeCrypto_generateKey',
      ],
      suspiciousPatterns: [
        /AES/,
        /RSA/,
        /ECDSA/,
        /HMAC/,
      ],
      riskLevel: 'high',
    },
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'mtn-momo-fakeapp-001',
      'Fake MTN MoMo App',
      'FakeMomoApp',
      ['MTN MoMo'],
      ['UG', 'GH', 'NG', 'ZA'],
      `rule FakeMtnMomoApp {
        meta:
          description = "Detects fake MTN MoMo applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $momo1 = "MTN MoMo" ascii wide
          $momo2 = "com.mtn.momo" ascii wide
          $fake1 = "com.fake" ascii wide
          $fake2 = "com.malicious" ascii wide
        condition:
          ($momo1 or $momo2) and ($fake1 or $fake2)
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
    this.createMalwareSignature(
      'mtn-momo-ussd-phishing-001',
      'MTN MoMo USSD Phishing Malware',
      'MomoUssdPhisher',
      ['MTN MoMo', 'M-Pesa', 'Airtel Money'],
      ['UG', 'GH', 'NG', 'KE', 'TZ'],
      `rule MtnMomoUssdPhishing {
        meta:
          description = "Detects malware that phishes MTN MoMo USSD credentials"
          author = "GICT Africa"
          severity = "high"
        strings:
          $ussd1 = "*165#" ascii wide
          $ussd2 = "*170#" ascii wide
          $phish = "credential" ascii wide
          $overlay = "SYSTEM_ALERT_WINDOW" ascii wide
        condition:
          ($ussd1 or $ussd2) and $phish and $overlay
      }`,
      'high',
      ['T1655', 'T1056.001', 'T1082']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'MTN MoMo Collection API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'MtnMomoCollectionDecoder',
      messageTypes: [
        {
          typeId: 'collection_request',
          name: 'Collection Request',
          direction: 'request',
          fields: [
            { name: 'amount', type: 'string', required: true, description: 'Amount to collect' },
            { name: 'currency', type: 'string', required: true, description: 'Currency code (e.g., UGX)' },
            { name: 'externalId', type: 'string', required: true, description: 'External transaction ID' },
            { name: 'payer', type: 'struct', required: true, description: 'Payer info', fields: [
              { name: 'partyIdType', type: 'string', required: true, description: 'MSISDN' },
              { name: 'partyId', type: 'string', required: true, description: 'Phone number' },
            ]},
            { name: 'payerMessage', type: 'string', required: false, description: 'Message to payer' },
            { name: 'payeeNote', type: 'string', required: false, description: 'Note for payee' },
          ],
        },
        {
          typeId: 'collection_response',
          name: 'Collection Response',
          direction: 'response',
          fields: [
            { name: 'ref', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
      ],
    },
    {
      name: 'MTN MoMo USSD Protocol',
      version: '1.0',
      transport: 'ussd',
      format: 'custom',
      decoderClass: 'MtnMomoUssdDecoder',
      messageTypes: [
        {
          typeId: 'ussd_request',
          name: 'USSD Request',
          direction: 'request',
          fields: [
            { name: 'sessionId', type: 'string', required: true, description: 'Session identifier' },
            { name: 'phoneNumber', type: 'string', required: true, description: 'Phone number' },
            { name: 'text', type: 'string', required: true, description: 'User input' },
          ],
        },
        {
          typeId: 'ussd_response',
          name: 'USSD Response',
          direction: 'response',
          fields: [
            { name: 'sessionId', type: 'string', required: true, description: 'Session identifier' },
            { name: 'message', type: 'string', required: true, description: 'Menu text to display' },
            { name: 'continueSession', type: 'boolean', required: true, description: 'Whether session continues' },
          ],
        },
      ],
    },
  ];
}