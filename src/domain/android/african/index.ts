/**
 * African Mobile Money/Fintech Reverse Engineering Profiles
 *
 * This module provides specialized analysis profiles for African fintech applications.
 * Each profile defines USSD patterns, API endpoints, certificate pinning configurations,
 * ProGuard mapping strategies, and native library analysis rules specific to the provider.
 *
 * @packageDocumentation
 */

export { AfricanFintechProfileRegistry } from './AfricanFintechProfileRegistry.js';
export { MpesaProfile } from './profiles/MpesaProfile.js';
export { MtnMoMoProfile } from './profiles/MtnMoMoProfile.js';
export { AirtelMoneyProfile } from './profiles/AirtelMoneyProfile.js';
export { OrangeMoneyProfile } from './profiles/OrangeMoneyProfile.js';
export { WaveProfile } from './profiles/WaveProfile.js';
export { EcoCashProfile } from './profiles/EcoCashProfile.js';
export { PagaProfile } from './profiles/PagaProfile.js';
export { OpayProfile } from './profiles/OpayProfile.js';
export { FlutterwaveProfile } from './profiles/FlutterwaveProfile.js';
export { ChipperCashProfile } from './profiles/ChipperCashProfile.js';
export { WorldRemitProfile } from './profiles/WorldRemitProfile.js';
export { PaystackProfile } from './profiles/PaystackProfile.js';
export { PayPalAfricaProfile } from './profiles/PayPalAfricaProfile.js';
export { VodacomMpesaProfile } from './profiles/VodacomMpesaProfile.js';
export { TigoPesaProfile } from './profiles/TigoPesaProfile.js';
export { HalopesaProfile } from './profiles/HalopesaProfile.js';
export { EazzyPayProfile } from './profiles/EazzyPayProfile.js';
export { MPawaProfile } from './profiles/MPawaProfile.js';

export type {
  AfricanFintechProfile,
  UssdPattern,
  ApiEndpoint,
  CertificatePinningConfig,
  ProGuardStrategy,
  NativeLibraryRule,
  MalwareSignature,
  ProtocolDecoder,
} from './types.js';