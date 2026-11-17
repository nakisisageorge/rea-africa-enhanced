/**
 * Flutterwave Reverse Engineering Profile
 *
 * Covers Flutterwave pan-African payment gateway
 * API-only (no USSD), multi-country payments
 * Package: com.flutterwave.flutterwave, com.flutterwave.pay
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

export class FlutterwaveProfile extends BaseAfricanFintechProfile {
  override readonly id = 'flutterwave';
  override readonly name = 'Flutterwave';
  override readonly countries = ['NG', 'GH', 'KE', 'ZA', 'UG', 'TZ', 'RW', 'ZM', 'MW', 'CM', 'CI', 'SN', 'BF', 'ML', 'BJ', 'GN', 'LR', 'SL', 'US', 'GB', 'EU'];
  override readonly category = 'payment-gateway' as const;
  override readonly packageNames = [
    'com.flutterwave.flutterwave',
    'com.flutterwave.pay',
    'com.ravepay.rave',
    'com.flutterwave.rave',
  ];
  override readonly signingCertificates = [
    'SHA256:FL:UT:TE:RW:AV:EP:AY:GA:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '2.15.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'flutterwave-charge',
      'POST',
      '/v3/charges',
      'https://api.flutterwave.com',
      'Initiate payment charge',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'flutterwave-verify',
      'GET',
      '/v3/transactions/{id}/verify',
      'https://api.flutterwave.com',
      'Verify transaction',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'flutterwave-transfer',
      'POST',
      '/v3/transfers',
      'https://api.flutterwave.com',
      'Initiate transfer/payout',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'flutterwave-banks',
      'GET',
      '/v3/banks/{country}',
      'https://api.flutterwave.com',
      'List supported banks',
      'bearer',
      'low'
    ),
    this.createApiEndpoint(
      'flutterwave-exchange-rates',
      'GET',
      '/v3/exchange-rates',
      'https://api.flutterwave.com',
      'Get exchange rates',
      'bearer',
      'low'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/FLUTTERWAVEPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/FLUTTERWAVEPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.flutterwave.com', 'flutterwave.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.flutterwave.flutterwave.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Flutter[A-Z]/, /^Rave[A-Z]/, /^Pay[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^charge/, /^transfer/, /^verify/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^amount/, /^currency/, /^reference/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libflutterwave.*\\\\.so'),
    this.createRootDetectionNativeRule('libflutterwave.*\\\\.so'),
    this.createAntiTamperNativeRule('libflutterwave.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'flutterwave-fakeapp-001',
      'Fake Flutterwave App',
      'FakeFlutterwaveApp',
      ['Flutterwave'],
      ['NG', 'GH', 'KE', 'ZA'],
      `rule FakeFlutterwaveApp {
        meta:
          description = "Detects fake Flutterwave applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $fw1 = "Flutterwave" ascii wide
          $fw2 = "com.flutterwave" ascii wide
          $rave = "Rave" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($fw1 or $fw2 or $rave) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Flutterwave API Protocol',
      version: '3.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'FlutterwaveDecoder',
      messageTypes: [
        {
          typeId: 'charge_request',
          name: 'Charge Request',
          direction: 'request',
          fields: [
            { name: 'tx_ref', type: 'string', required: true, description: 'Unique transaction reference' },
            { name: 'amount', type: 'number', required: true, description: 'Amount to charge' },
            { name: 'currency', type: 'string', required: true, description: 'Currency code (NGN, GHS, KES, ZAR, etc.)' },
            { name: 'redirect_url', type: 'string', required: true, description: 'Redirect URL after payment' },
            { name: 'customer', type: 'struct', required: true, description: 'Customer details', fields: [
              { name: 'email', type: 'string', required: true, description: 'Customer email' },
              { name: 'phone_number', type: 'string', required: true, description: 'Customer phone' },
              { name: 'name', type: 'string', required: true, description: 'Customer name' },
            ]},
            { name: 'customizations', type: 'struct', required: false, description: 'UI customizations', fields: [
              { name: 'title', type: 'string', required: false, description: 'Payment page title' },
              { name: 'logo', type: 'string', required: false, description: 'Logo URL' },
            ]},
          ],
        },
      ],
    },
  ];
}