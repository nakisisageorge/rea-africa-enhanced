/**
 * Chipper Cash Reverse Engineering Profile
 *
 * Covers Chipper Cash multi-country remittance service
 * API-only (no USSD), cross-border payments
 * Package: com.chipper.cash, com.chipper.cash.ng, com.chipper.cash.gh, etc.
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

export class ChipperCashProfile extends BaseAfricanFintechProfile {
  override readonly id = 'chipper-cash';
  override readonly name = 'Chipper Cash';
  override readonly countries = ['NG', 'GH', 'UG', 'KE', 'RW', 'TZ', 'ZA', 'US', 'GB', 'CA'];
  override readonly category = 'remittance' as const;
  override readonly packageNames = [
    'com.chipper.cash',
    'com.chipper.cash.ng',
    'com.chipper.cash.gh',
    'com.chipper.cash.ug',
    'com.chipper.cash.ke',
    'com.chipper.cash.rw',
    'com.chipper.cash.tz',
    'com.chipper.cash.za',
  ];
  override readonly signingCertificates = [
    'SHA256:CH:IP:PE:RC:AS:HC:ER:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '5.12.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'chipper-transfer',
      'POST',
      '/v1/transfers',
      'https://api.chippercash.com',
      'Initiate cross-border transfer',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'chipper-balance',
      'GET',
      '/v1/accounts/balance',
      'https://api.chippercash.com',
      'Get account balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'chipper-exchange-rate',
      'GET',
      '/v1/exchange-rates',
      'https://api.chippercash.com',
      'Get exchange rates',
      'bearer',
      'low'
    ),
    this.createApiEndpoint(
      'chipper-beneficiaries',
      'GET',
      '/v1/beneficiaries',
      'https://api.chippercash.com',
      'List beneficiaries',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'chipper-add-beneficiary',
      'POST',
      '/v1/beneficiaries',
      'https://api.chippercash.com',
      'Add beneficiary',
      'bearer',
      'high'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/CHIPPERCASHPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/CHIPPERCASHPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.chippercash.com', 'chippercash.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.chipper.cash.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^Chipper[A-Z]/, /^Transfer[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^sendMoney/, /^createTransfer/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^recipient/, /^amount/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libchipper.*\\\\.so'),
    this.createRootDetectionNativeRule('libchipper.*\\\\.so'),
    this.createAntiTamperNativeRule('libchipper.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'chipper-fakeapp-001',
      'Fake Chipper Cash App',
      'FakeChipperApp',
      ['Chipper Cash'],
      ['NG', 'GH', 'UG', 'KE'],
      `rule FakeChipperCashApp {
        meta:
          description = "Detects fake Chipper Cash applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $chipper1 = "Chipper Cash" ascii wide
          $chipper2 = "com.chipper.cash" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($chipper1 or $chipper2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'Chipper Cash API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'ChipperCashDecoder',
      messageTypes: [
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'sourceCurrency', type: 'string', required: true, description: 'Source currency (e.g., NGN)' },
            { name: 'destinationCurrency', type: 'string', required: true, description: 'Destination currency (e.g., USD)' },
            { name: 'sourceAmount', type: 'number', required: true, description: 'Amount in source currency' },
            { name: 'recipient', type: 'struct', required: true, description: 'Recipient details', fields: [
              { name: 'name', type: 'string', required: true, description: 'Recipient name' },
              { name: 'phone', type: 'string', required: true, description: 'Recipient phone' },
              { name: 'bankCode', type: 'string', required: false, description: 'Bank code' },
              { name: 'accountNumber', type: 'string', required: false, description: 'Account number' },
            ]},
            { name: 'reference', type: 'string', required: true, description: 'Transaction reference' },
          ],
        },
        {
          typeId: 'transfer_response',
          name: 'Transfer Response',
          direction: 'response',
          fields: [
            { name: 'transferId', type: 'string', required: true, description: 'Transfer identifier' },
            { name: 'status', type: 'string', required: true, description: 'Transfer status' },
            { name: 'exchangeRate', type: 'number', required: true, description: 'Applied exchange rate' },
            { name: 'fees', type: 'number', required: true, description: 'Transfer fees' },
            { name: 'estimatedDelivery', type: 'string', required: true, description: 'Estimated delivery time' },
          ],
        },
      ],
    },
  ];
}