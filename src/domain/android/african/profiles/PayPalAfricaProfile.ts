/**
 * PayPal Africa Reverse Engineering Profile
 *
 * Covers PayPal regional services in Africa
 * API-only (no USSD), cross-border payments
 * Package: com.paypal.android, com.paypal.africa
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

export class PayPalAfricaProfile extends BaseAfricanFintechProfile {
  override readonly id = 'paypal-africa';
  override readonly name = 'PayPal Africa';
  override readonly countries = ['ZA', 'NG', 'KE', 'GH', 'MA', 'EG', 'TN', 'MU', 'SC', 'BW', 'LS', 'NA', 'SZ', 'ZW', 'ZM', 'MW', 'MZ', 'BW'];
  override readonly category = 'remittance' as const;
  override readonly packageNames = [
    'com.paypal.android',
    'com.paypal.africa',
    'com.paypal.mobile',
  ];
  override readonly signingCertificates = [
    'SHA256:PA:YP:AL:AF:RI:CA:RE:GI:ON:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '8.45.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'paypal-payment',
      'POST',
      '/v2/payments',
      'https://api-m.paypal.com',
      'Create payment',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'paypal-payout',
      'POST',
      '/v1/payments/payouts',
      'https://api-m.paypal.com',
      'Create payout',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'paypal-balance',
      'GET',
      '/v1/reporting/balances',
      'https://api-m.paypal.com',
      'Get balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'paypal-transaction-search',
      'GET',
      '/v1/reporting/transactions',
      'https://api-m.paypal.com',
      'Search transactions',
      'bearer',
      'low'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/PAYPALAFRICAPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/PAYPALAFRICAPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api-m.paypal.com', 'api.sandbox.paypal.com', 'paypal.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.paypal.android.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^PayPal[A-Z]/, /^Payment[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^createPayment/, /^executePayment/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^amount/, /^currency/, /^intent/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libpaypal.*\\\\.so'),
    this.createRootDetectionNativeRule('libpaypal.*\\\\.so'),
    this.createAntiTamperNativeRule('libpaypal.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'paypal-fakeapp-001',
      'Fake PayPal Africa App',
      'FakePayPalApp',
      ['PayPal'],
      ['ZA', 'NG', 'KE', 'GH'],
      `rule FakePayPalAfricaApp {
        meta:
          description = "Detects fake PayPal applications targeting African users"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $paypal1 = "PayPal" ascii wide
          $paypal2 = "com.paypal" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($paypal1 or $paypal2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'PayPal REST API Protocol',
      version: '2.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'PayPalDecoder',
      messageTypes: [
        {
          typeId: 'payment_request',
          name: 'Payment Request',
          direction: 'request',
          fields: [
            { name: 'intent', type: 'string', required: true, description: 'sale, authorize, order' },
            { name: 'payer', type: 'struct', required: true, description: 'Payer info', fields: [
              { name: 'payment_method', type: 'string', required: true, description: 'paypal, credit_card' },
            ]},
            { name: 'transactions', type: 'array', required: true, description: 'Transaction list', fields: [
              { name: 'amount', type: 'struct', required: true, description: 'Amount', fields: [
                { name: 'total', type: 'string', required: true, description: 'Total amount' },
                { name: 'currency', type: 'string', required: true, description: 'Currency code' },
              ]},
            ]},
          ],
        },
      ],
    },
  ];
}