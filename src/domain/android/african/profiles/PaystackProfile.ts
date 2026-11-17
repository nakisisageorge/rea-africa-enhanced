/**
 * Paystack Reverse Engineering Profile
 *
 * Covers Paystack Nigeria, Ghana, South Africa
 * API-only (no USSD), payment gateway
 * Package: com.paystack.paystack, com.paystack.paystack.ng, com.paystack.paystack.gh
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

export class PaystackProfile extends BaseAfricanFintechProfile {
  override readonly id = 'paystack';
  override readonly name = 'Paystack';
  override readonly countries = ['NG', 'GH', 'ZA'];
  override readonly category = 'payment-gateway' as const;
  override readonly packageNames = [
    'com.paystack.paystack',
    'com.paystack.paystack.ng',
    'com.paystack.paystack.gh',
    'com.paystack.paystack.za',
  ];
  override readonly signingCertificates = [
    'SHA256:PA:YS:TA:CK:NG:GH:ZA:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '2.8.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'paystack-charge',
      'POST',
      '/transaction/initialize',
      'https://api.paystack.co',
      'Initialize transaction',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'paystack-verify',
      'GET',
      '/transaction/verify/{reference}',
      'https://api.paystack.co',
      'Verify transaction',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'paystack-transfer',
      'POST',
      '/transfer',
      'https://api.paystack.co',
      'Initiate transfer',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'paystack-banks',
      'GET',
      '/bank',
      'https://api.paystack.co',
      'List supported banks',
      'bearer',
      'low'
    ),
    this.createApiEndpoint(
      'paystack-customer',
      'POST',
      '/customer',
      'https://api.paystack.co',
      'Create customer',
      'bearer',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/PAYSTACKPINNINGHASHAAAAAAAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/PAYSTACKPINNINGBACKUPBBBBBBBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.paystack.co', 'paystack.co'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.paystack.paystack.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Paystack[A-Z]/, /^Transaction[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^charge/, /^verify/, /^transfer/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^amount/, /^reference/, /^email/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libpaystack.*\\\\.so'),
    this.createRootDetectionNativeRule('libpaystack.*\\\\.so'),
    this.createAntiTamperNativeRule('libpaystack.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'paystack-fakeapp-001',
      'Fake Paystack App',
      'FakePaystackApp',
      ['Paystack'],
      ['NG', 'GH', 'ZA'],
      `rule FakePaystackApp {
        meta:
          description = "Detects fake Paystack applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $ps1 = "Paystack" ascii wide
          $ps2 = "com.paystack" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($ps1 or $ps2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Paystack API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'PaystackDecoder',
      messageTypes: [
        {
          typeId: 'initialize_request',
          name: 'Initialize Transaction Request',
          direction: 'request',
          fields: [
            { name: 'email', type: 'string', required: true, description: 'Customer email' },
            { name: 'amount', type: 'number', required: true, description: 'Amount in kobo/cents' },
            { name: 'currency', type: 'string', required: true, description: 'Currency (NGN, GHS, ZAR)' },
            { name: 'reference', type: 'string', required: false, description: 'Unique transaction reference' },
            { name: 'callback_url', type: 'string', required: false, description: 'Redirect URL' },
          ],
        },
        {
          typeId: 'verify_response',
          name: 'Verify Transaction Response',
          direction: 'response',
          fields: [
            { name: 'status', type: 'boolean', required: true, description: 'Verification status' },
            { name: 'data', type: 'struct', required: true, description: 'Transaction data', fields: [
              { name: 'amount', type: 'number', required: true, description: 'Amount' },
              { name: 'currency', type: 'string', required: true, description: 'Currency' },
              { name: 'reference', type: 'string', required: true, description: 'Reference' },
              { name: 'gateway_response', type: 'string', required: true, description: 'Gateway response' },
            ]},
          ],
        },
      ],
    },
  ];
}