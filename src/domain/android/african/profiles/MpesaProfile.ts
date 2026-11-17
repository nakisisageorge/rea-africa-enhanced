/**
 * M-Pesa (Safaricom/Vodacom) Reverse Engineering Profile
 *
 * Covers M-Pesa Kenya, Tanzania, Ghana, Egypt, DRC, Lesotho, Mozambique
 * USSD: *150# (Kenya), *150*00# (Tanzania), *150*00# (Ghana)
 * Package: com.safaricom.mpesa, com.vodacom.mpesa, com.safaricom.mpesa.ke
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

export class MpesaProfile extends BaseAfricanFintechProfile {
  override readonly id = 'mpesa';
  override readonly name = 'M-Pesa';
  override readonly countries = ['KE', 'TZ', 'GH', 'EG', 'CD', 'LS', 'MZ'];
  override readonly category = 'mobile-money' as const;
  override readonly packageNames = [
    'com.safaricom.mpesa',
    'com.vodacom.mpesa',
    'com.safaricom.mpesa.ke',
    'com.safaricom.mpesa.tz',
    'com.safaricom.mpesa.gh',
    'com.vodacom.mpesatz',
    'com.vodacom.mpesacd',
    'com.vodacom.mpesa.ls',
    'com.vodacom.mpesa.mz',
  ];
  override readonly signingCertificates = [
    'SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
    'SHA256:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
  ];
  override readonly minVersion = '1.0.0';
  override readonly maxVersionTested = '12.5.0';
  override readonly profileVersion = '1.0.0';
  override readonly lastUpdated = '2026-11-15';
  override readonly maintainer = 'GICT Africa Technologies';

  override readonly ussdPatterns: UssdPattern[] = [
    {
      id: 'mpesa-ke-main',
      name: 'M-Pesa Kenya Main Menu',
      code: '*150#',
      region: ['KE'],
      provider: 'M-Pesa',
      sessionTimeout: 180,
      responsePatterns: [
        /M-PESA/i,
        /Send Money/i,
        /Withdraw Cash/i,
        /Buy Airtime/i,
        /Lipa na M-PESA/i,
        /My Account/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'M-PESA',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw Cash', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Buy Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Lipa na M-PESA', action: 'billpay', childNodeId: 'lipa_na_mpesa', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
          { key: '6', text: 'M-Shwari', action: 'loan', childNodeId: 'm_shwari', riskLevel: 'high' },
          { key: '7', text: 'KCB M-PESA', action: 'savings', childNodeId: 'kcb_mpesa', riskLevel: 'high' },
        ],
      },
    },
    {
      id: 'mpesa-tz-main',
      name: 'M-Pesa Tanzania Main Menu',
      code: '*150*00#',
      region: ['TZ'],
      provider: 'M-Pesa',
      sessionTimeout: 180,
      responsePatterns: [
        /M-PESA/i,
        /Send Money/i,
        /Withdraw Cash/i,
        /Buy Airtime/i,
        /Pay Bill/i,
        /My Account/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'M-PESA',
        options: [
          { key: '1', text: 'Send Money', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Withdraw Cash', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Buy Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
          { key: '6', text: 'M-Pawa', action: 'savings', childNodeId: 'mpawa', riskLevel: 'high' },
        ],
      },
    },
    {
      id: 'mpesa-gh-main',
      name: 'M-Pesa Ghana Main Menu',
      code: '*150*00#',
      region: ['GH'],
      provider: 'M-Pesa',
      sessionTimeout: 180,
      responsePatterns: [
        /M-PESA/i,
        /Transfer/i,
        /Cash Out/i,
        /Airtime/i,
        /Pay Bill/i,
      ],
      menuTree: {
        nodeId: 'root',
        title: 'M-PESA',
        options: [
          { key: '1', text: 'Transfer', action: 'transfer', childNodeId: 'send_money', riskLevel: 'high' },
          { key: '2', text: 'Cash Out', action: 'withdraw', childNodeId: 'withdraw_cash', riskLevel: 'high' },
          { key: '3', text: 'Airtime', action: 'airtime', childNodeId: 'buy_airtime', riskLevel: 'medium' },
          { key: '4', text: 'Pay Bill', action: 'billpay', childNodeId: 'pay_bill', riskLevel: 'high' },
          { key: '5', text: 'My Account', action: 'menu', childNodeId: 'my_account', riskLevel: 'low' },
        ],
      },
    },
  ];

  override readonly apiEndpoints: ApiEndpoint[] = [
    this.createApiEndpoint(
      'mpesa-stk-push',
      'POST',
      '/mpesa/stkpush/v1/processrequest',
      'https://api.safaricom.co.ke',
      'Initiate STK Push for customer payment',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'mpesa-b2c',
      'POST',
      '/mpesa/b2c/v1/paymentrequest',
      'https://api.safaricom.co.ke',
      'Business to Customer payment',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'mpesa-b2b',
      'POST',
      '/mpesa/b2b/v1/paymentrequest',
      'https://api.safaricom.co.ke',
      'Business to Business payment',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'mpesa-c2b-register',
      'POST',
      '/mpesa/c2b/v1/registerurl',
      'https://api.safaricom.co.ke',
      'Register C2B confirmation/validation URLs',
      'bearer',
      'high'
    ),
    this.createApiEndpoint(
      'mpesa-reversal',
      'POST',
      '/mpesa/reversal/v1/request',
      'https://api.safaricom.co.ke',
      'Reverse a transaction',
      'bearer',
      'critical'
    ),
    this.createApiEndpoint(
      'mpesa-query',
      'POST',
      '/mpesa/stkpushquery/v1/query',
      'https://api.safaricom.co.ke',
      'Query STK Push status',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'mpesa-balance',
      'GET',
      '/mpesa/accountbalance/v1/query',
      'https://api.safaricom.co.ke',
      'Query account balance',
      'bearer',
      'medium'
    ),
    this.createApiEndpoint(
      'mpesa-token',
      'GET',
      '/oauth/v1/generate?grant_type=client_credentials',
      'https://api.safaricom.co.ke',
      'Generate OAuth access token',
      'api-key',
      'medium'
    ),
  ];

  override readonly certificatePinning: CertificatePinningConfig = {
    enabled: true,
    pins: [
      'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    ],
    backupPins: [
      'sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
    ],
    mode: 'strict',
    domains: [
      'api.safaricom.co.ke',
      'api.vodacom.co.tz',
      'api.vodacom.co.mz',
      'api.vodacom.cd',
      'api.vodacom.ls',
    ],
    allowUserCAs: false,
    requireCT: true,
    customValidatorClass: 'com.safaricom.mpesa.security.CertificatePinningValidator',
  };

  override readonly proGuardStrategy: ProGuardStrategy = {
    mappingPatterns: [
      'mapping.txt',
      'proguard/mapping.txt',
      'build/outputs/mapping/release/mapping.txt',
      'app/build/outputs/mapping/release/mapping.txt',
    ],
    classPatterns: [
      /^[a-z]{1,3}$/,
      /^[a-z][A-Z][a-z]+$/,
      /^Mpesa[A-Z]/,
      /^StkPush/,
      /^B2c/,
      /^B2b/,
    ],
    methodPatterns: [
      /^[a-z]{1,2}$/,
      /^[a-z][A-Z][a-z]+$/,
      /^processStkPush/,
      /^initiateB2c/,
      /^queryBalance/,
    ],
    fieldPatterns: [
      /^[a-z]{1,2}$/,
      /^[a-z][A-Z][a-z]+$/,
      /^phoneNumber$/,
      /^amount$/,
      /^accountRef$/,
    ],
    renameRules: [
      { pattern: /^a$/, replacement: 'sendMoney', confidence: 0.8 },
      { pattern: /^b$/, replacement: 'withdrawCash', confidence: 0.8 },
      { pattern: /^c$/, replacement: 'buyAirtime', confidence: 0.7 },
    ],
    useReferenceMapping: true,
  };

  override readonly nativeLibraryRules: NativeLibraryRule[] = [
    this.createCertPinningNativeRule('libmpesa.*\\.so'),
    this.createRootDetectionNativeRule('libmpesa.*\\.so'),
    this.createAntiTamperNativeRule('libmpesa.*\\.so'),
    {
      libraryPattern: /libmpesa.*\.so/,
      arch: 'all',
      analysisType: 'jni-bindings',
      expectedExports: [
        'Java_com_safaricom_mpesa_security_NativeCrypto_encrypt',
        'Java_com_safaricom_mpesa_security_NativeCrypto_decrypt',
        'Java_com_safaricom_mpesa_security_NativeCrypto_generateKey',
        'Java_com_safaricom_mpesa_security_NativeCrypto_verifySignature',
      ],
      suspiciousPatterns: [
        /AES/,
        /RSA/,
        /ECDSA/,
        /HMAC/,
        /PBKDF2/,
        /HKDF/,
      ],
      riskLevel: 'high',
    },
    {
      libraryPattern: /libstkpush.*\.so/,
      arch: 'all',
      analysisType: 'custom',
      suspiciousPatterns: [
        /STK/,
        /push/,
        /prompt/,
        /pin/,
        /validate/,
      ],
      riskLevel: 'critical',
    },
  ];

  override readonly malwareSignatures: MalwareSignature[] = [
    this.createMalwareSignature(
      'mpesa-fakesim-001',
      'Fake M-Pesa SIM Toolkit App',
      'FakeSimToolkit',
      ['M-Pesa'],
      ['KE', 'TZ', 'GH'],
      `rule FakeMpesaSimToolkit {
        meta:
          description = "Detects fake M-Pesa SIM Toolkit apps"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $stk1 = "STK Push" ascii wide
          $stk2 = "M-PESA" ascii wide
          $stk3 = "com.safaricom.mpesa" ascii wide
          $fake1 = "com.fake" ascii wide
          $fake2 = "com.malicious" ascii wide
        condition:
          ($stk1 or $stk2 or $stk3) and ($fake1 or $fake2)
      }`,
      'critical',
      ['T1655', 'T1553.002']
    ),
    this.createMalwareSignature(
      'mpesa-stk-intercept-001',
      'STK Push Interception Malware',
      'StkInterceptor',
      ['M-Pesa'],
      ['KE', 'TZ'],
      `rule StkPushInterceptor {
        meta:
          description = "Detects malware that intercepts STK Push prompts"
          author = "GICT Africa"
          severity = "critical"
        strings:
          $accessibility = "AccessibilityService" ascii wide
          $stk = "STK" ascii wide
          $pin = "PIN" ascii wide
          $overlay = "SYSTEM_ALERT_WINDOW" ascii wide
        condition:
          $accessibility and $stk and $pin and $overlay
      }`,
      'critical',
      ['T1655', 'T1056.001', 'T1082']
    ),
    this.createMalwareSignature(
      'mpesa-ussd-forward-001',
      'USSD Forwarding Trojan',
      'UssdForwarder',
      ['M-Pesa', 'MTN MoMo', 'Airtel Money'],
      ['KE', 'TZ', 'UG', 'NG', 'GH'],
      `rule UssdForwardingTrojan {
        meta:
          description = "Detects malware that forwards USSD sessions to attacker"
          author = "GICT Africa"
          severity = "high"
        strings:
          $ussd = "*150#" ascii wide
          $forward = "forward" ascii wide
          $sms = "sendSMS" ascii wide
          $permission = "SEND_SMS" ascii wide
        condition:
          $ussd and $forward and $sms and $permission
      }`,
      'high',
      ['T1553.002', 'T1081', 'T1486']
    ),
  ];

  override readonly protocolDecoders: ProtocolDecoder[] = [
    {
      name: 'M-Pesa STK Push Protocol',
      version: '1.0',
      transport: 'http',
      format: 'json',
      decoderClass: 'MpesaStkPushDecoder',
      messageTypes: [
        {
          typeId: 'stk_push_request',
          name: 'STK Push Request',
          direction: 'request',
          fields: [
            { name: 'BusinessShortCode', type: 'string', required: true, description: 'Organization shortcode' },
            { name: 'Password', type: 'string', required: true, description: 'Base64 encoded password' },
            { name: 'Timestamp', type: 'string', required: true, description: 'YYYYMMDDHHMMSS format' },
            { name: 'TransactionType', type: 'string', required: true, description: 'CustomerPayBillOnline' },
            { name: 'Amount', type: 'number', required: true, description: 'Transaction amount' },
            { name: 'PartyA', type: 'string', required: true, description: 'Customer phone number' },
            { name: 'PartyB', type: 'string', required: true, description: 'Organization shortcode' },
            { name: 'PhoneNumber', type: 'string', required: true, description: 'Customer phone number' },
            { name: 'CallBackURL', type: 'string', required: true, description: 'Callback URL' },
            { name: 'AccountReference', type: 'string', required: true, description: 'Account reference' },
            { name: 'TransactionDesc', type: 'string', required: true, description: 'Transaction description' },
          ],
        },
        {
          typeId: 'stk_push_response',
          name: 'STK Push Response',
          direction: 'response',
          fields: [
            { name: 'MerchantRequestID', type: 'string', required: true, description: 'Merchant request ID' },
            { name: 'CheckoutRequestID', type: 'string', required: true, description: 'Checkout request ID' },
            { name: 'ResponseCode', type: 'string', required: true, description: 'Response code' },
            { name: 'ResponseDescription', type: 'string', required: true, description: 'Response description' },
            { name: 'CustomerMessage', type: 'string', required: false, description: 'Customer message' },
          ],
        },
        {
          typeId: 'stk_push_callback',
          name: 'STK Push Callback',
          direction: 'notification',
          fields: [
            { name: 'Body', type: 'struct', required: true, description: 'Callback body', fields: [
              { name: 'stkCallback', type: 'struct', required: true, description: 'STK callback object', fields: [
                { name: 'MerchantRequestID', type: 'string', required: true, description: 'Merchant request identifier' },
                { name: 'CheckoutRequestID', type: 'string', required: true, description: 'Checkout request identifier' },
                { name: 'ResultCode', type: 'number', required: true, description: 'Result code (0 for success)' },
                { name: 'ResultDesc', type: 'string', required: true, description: 'Result description' },
                { name: 'CallbackMetadata', type: 'struct', required: false, description: 'Optional callback metadata', fields: [
                  { name: 'Item', type: 'array', required: false, description: 'Metadata items array', fields: [
                    { name: 'Name', type: 'string', required: true, description: 'Metadata item name' },
                    { name: 'Value', type: 'string', required: true, description: 'Metadata item value' },
                  ]},
                ]},
              ]},
            ]},
          ],
        },
      ],
      encryption: {
        algorithm: 'AES-GCM',
        keyDerivation: 'HKDF',
        keyLength: 256,
        ivLength: 12,
      },
    },
    {
      name: 'M-Pesa USSD Protocol',
      version: '1.0',
      transport: 'ussd',
      format: 'custom',
      decoderClass: 'MpesaUssdDecoder',
      messageTypes: [
        {
          typeId: 'ussd_request',
          name: 'USSD Request',
          direction: 'request',
          fields: [
            { name: 'sessionId', type: 'string', required: true, description: 'Session identifier' },
            { name: 'phoneNumber', type: 'string', required: true, description: 'Phone number' },
            { name: 'text', type: 'string', required: true, description: 'User input (e.g., "1*2547XXXXXXXX*100*1234")' },
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