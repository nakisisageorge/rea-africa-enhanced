/**
 * WorldRemit Reverse Engineering Profile
 *
 * Covers WorldRemit global-to-Africa remittance
 * API-only (no USSD), cross-border remittance
 * Package: com.worldremit.worldremit, com.worldremit.africa
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

export class WorldRemitProfile extends BaseAfricanFintechProfile {
  override readonly id = 'worldremit';
  override readonly name = 'WorldRemit';
  override readonly countries = ['NG', 'GH', 'KE', 'UG', 'TZ', 'RW', 'ZM', 'MW', 'ZW', 'ZA', 'ET', 'SO', 'SD', 'SS', 'CM', 'CI', 'SN', 'ML', 'BF', 'BJ', 'GN', 'LR', 'SL', 'GA', 'CG', 'CD', 'AO', 'MZ', 'BW', 'NA', 'SZ', 'LS', 'ZW', 'US', 'GB', 'CA', 'AU', 'EU'];
  override readonly category = 'remittance' as const;
  override readonly packageNames = [
    'com.worldremit.worldremit',
    'com.worldremit.africa',
    'com.worldremit.send',
  ];
  override readonly signingCertificates = [
    'SHA256:WO:RL:DR:EM:IT:GL:OB:AL:TF:IC:AT:ES:HA:SH:ES:HE:RE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '4.20.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'worldremit-quote',
      'POST',
      '/v1/quotes',
      'https://api.worldremit.com',
      'Get transfer quote',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'worldremit-transfer',
      'POST',
      '/v1/transfers',
      'https://api.worldremit.com',
      'Create transfer',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'worldremit-track',
      'GET',
      '/v1/transfers/{id}/status',
      'https://api.worldremit.com',
      'Track transfer',
      'bearer',
      'low'
    ),
    this.createApiEndpoint(
      'worldremit-recipients',
      'GET',
      '/v1/recipients',
      'https://api.worldremit.com',
      'List recipients',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'worldremit-countries',
      'GET',
      '/v1/countries',
      'https://api.worldremit.com',
      'List supported countries',
      'bearer',
      'low'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: ['sha256/WORLDREMITPINNINGHASHAAAAAAAAAAAAAAAAAAAA='],
    backupPins: ['sha256/WORLDREMITPINNINGBACKUPBBBBBBBBBBBBBBBBBBBB='],
    mode: 'strict',
    domains: ['api.worldremit.com', 'worldremit.com'],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.worldremit.worldremit.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: ['mapping.txt', 'proguard/mapping.txt'],
    classPatterns: [/^[a-z]{1,3}$/, /^World[A-Z]/, /^Remit[A-Z]/, /^Transfer[A-Z]/],
    methodPatterns: [/^[a-z]{1,2}$/, /^quote/, /^transfer/, /^track/],
    fieldPatterns: [/^[a-z]{1,2}$/, /^amount/, /^currency/, /^recipient/],
    renameRules: [],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libworldremit.*\\\\.so'),
    this.createRootDetectionNativeRule('libworldremit.*\\\\.so'),
    this.createAntiTamperNativeRule('libworldremit.*\\\\.so'),
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'worldremit-fakeapp-001',
      'Fake WorldRemit App',
      'FakeWorldRemitApp',
      ['WorldRemit'],
      ['NG', 'GH', 'KE', 'ZA'],
      `rule FakeWorldRemitApp {
        meta:
          description = "Detects fake WorldRemit applications"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $wr1 = "WorldRemit" ascii wide
          $wr2 = "com.worldremit" ascii wide
          $fake1 = "com.fake" ascii wide
        condition:
          ($wr1 or $wr2) and $fake1
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'WorldRemit API Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'WorldRemitDecoder',
      messageTypes: [
        {
          typeId: 'quote_request',
          name: 'Quote Request',
          direction: 'request',
          fields: [
            { name: 'sourceCountry', type: 'string', required: true, description: 'Source country code' },
            { name: 'destinationCountry', type: 'string', required: true, description: 'Destination country code' },
            { name: 'sourceAmount', type: 'number', required: true, description: 'Amount in source currency' },
            { name: 'sourceCurrency', type: 'string', required: true, description: 'Source currency code' },
          ],
        },
        {
          typeId: 'transfer_request',
          name: 'Transfer Request',
          direction: 'request',
          fields: [
            { name: 'quoteId', type: 'string', required: true, description: 'Quote identifier' },
            { name: 'recipient', type: 'struct', required: true, description: 'Recipient details', fields: [
              { name: 'name', type: 'string', required: true, description: 'Recipient name' },
              { name: 'phone', type: 'string', required: true, description: 'Recipient phone' },
              { name: 'bankCode', type: 'string', required: false, description: 'Bank code' },
              { name: 'accountNumber', type: 'string', required: false, description: 'Account number' },
              { name: 'payoutMethod', type: 'string', required: true, description: 'bank, mobile, cash' },
            ]},
          ],
        },
      ],
    },
  ];
}