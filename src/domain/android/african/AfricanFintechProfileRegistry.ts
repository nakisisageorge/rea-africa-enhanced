/**
 * African Fintech Profile Registry
 *
 * Central registry for all African fintech reverse engineering profiles.
 * Provides lookup, validation, and profile management capabilities.
 */

import type {
  AfricanFintechProfile,
  UssdPattern,
  ApiEndpoint,
  CertificatePinningConfig,
  ProGuardStrategy,
  NativeLibraryRule,
  MalwareSignature,
  ProtocolDecoder,
} from './types.js';

import { MpesaProfile } from './profiles/MpesaProfile.js';
import { MtnMoMoProfile } from './profiles/MtnMoMoProfile.js';
import { AirtelMoneyProfile } from './profiles/AirtelMoneyProfile.js';
import { OrangeMoneyProfile } from './profiles/OrangeMoneyProfile.js';
import { WaveProfile } from './profiles/WaveProfile.js';
import { EcoCashProfile } from './profiles/EcoCashProfile.js';
import { PagaProfile } from './profiles/PagaProfile.js';
import { OpayProfile } from './profiles/OpayProfile.js';
import { FlutterwaveProfile } from './profiles/FlutterwaveProfile.js';
import { ChipperCashProfile } from './profiles/ChipperCashProfile.js';
import { WorldRemitProfile } from './profiles/WorldRemitProfile.js';
import { PaystackProfile } from './profiles/PaystackProfile.js';
import { PayPalAfricaProfile } from './profiles/PayPalAfricaProfile.js';
import { VodacomMpesaProfile } from './profiles/VodacomMpesaProfile.js';
import { TigoPesaProfile } from './profiles/TigoPesaProfile.js';
import { HalopesaProfile } from './profiles/HalopesaProfile.js';
import { EazzyPayProfile } from './profiles/EazzyPayProfile.js';
import { MPawaProfile } from './profiles/MPawaProfile.js';

/**
 * Registry of all African fintech profiles
 */
export class AfricanFintechProfileRegistry {
  private static instance: AfricanFintechProfileRegistry;
  private profiles: Map<string, AfricanFintechProfile> = new Map();
  private profileInstances: Map<string, () => AfricanFintechProfile> = new Map();

  private constructor() {
    this.registerBuiltinProfiles();
  }

  static getInstance(): AfricanFintechProfileRegistry {
    if (!AfricanFintechProfileRegistry.instance) {
      AfricanFintechProfileRegistry.instance = new AfricanFintechProfileRegistry();
    }
    return AfricanFintechProfileRegistry.instance;
  }

  private registerBuiltinProfiles(): void {
    const profileFactories = [
      () => new MpesaProfile(),
      () => new MtnMoMoProfile(),
      () => new AirtelMoneyProfile(),
      () => new OrangeMoneyProfile(),
      () => new WaveProfile(),
      () => new EcoCashProfile(),
      () => new PagaProfile(),
      () => new OpayProfile(),
      () => new FlutterwaveProfile(),
      () => new ChipperCashProfile(),
      () => new WorldRemitProfile(),
      () => new PaystackProfile(),
      () => new PayPalAfricaProfile(),
      () => new VodacomMpesaProfile(),
      () => new TigoPesaProfile(),
      () => new HalopesaProfile(),
      () => new EazzyPayProfile(),
      () => new MPawaProfile(),
    ];

    for (const factory of profileFactories) {
      const profile = factory();
      this.profileInstances.set(profile.id, factory);
      this.profiles.set(profile.id, profile);
    }
  }

  /**
   * Get a profile by ID
   */
  getProfile(id: string): AfricanFintechProfile | undefined {
    return this.profiles.get(id);
  }

  /**
   * Get all registered profiles
   */
  getAllProfiles(): AfricanFintechProfile[] {
    return Array.from(this.profiles.values());
  }

  /**
   * Get profiles by country
   */
  getProfilesByCountry(countryCode: string): AfricanFintechProfile[] {
    return this.getAllProfiles().filter(p => p.countries.includes(countryCode.toUpperCase()));
  }

  /**
   * Get profiles by category
   */
  getProfilesByCategory(category: AfricanFintechProfile['category']): AfricanFintechProfile[] {
    return this.getAllProfiles().filter(p => p.category === category);
  }

  /**
   * Get profile IDs
   */
  getProfileIds(): string[] {
    return Array.from(this.profiles.keys());
  }

  /**
   * Register a custom profile
   */
  registerProfile(profile: AfricanFintechProfile): void {
    if (this.profiles.has(profile.id)) {
      throw new Error(`Profile with ID ${profile.id} already registered`);
    }
    this.profiles.set(profile.id, profile);
    this.profileInstances.set(profile.id, () => profile);
  }

  /**
   * Validate all profiles
   */
  validateAll(): ValidationResult[] {
    const results: ValidationResult[] = [];
    for (const profile of this.profiles.values()) {
      results.push(this.validateProfile(profile));
    }
    return results;
  }

  private validateProfile(profile: AfricanFintechProfile): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!profile.id || !profile.name) {
      errors.push('Missing required fields: id, name');
    }

    if (profile.countries.length === 0) {
      warnings.push('No countries specified');
    }

    if (profile.packageNames.length === 0) {
      warnings.push('No package names specified');
    }

    if (profile.ussdPatterns.length === 0) {
      warnings.push('No USSD patterns defined');
    }

    if (profile.apiEndpoints.length === 0) {
      warnings.push('No API endpoints defined');
    }

    if (profile.malwareSignatures.length === 0) {
      warnings.push('No malware signatures defined');
    }

    // Validate USSD patterns
    for (const ussd of profile.ussdPatterns) {
      if (!ussd.code.startsWith('*') || !ussd.code.endsWith('#')) {
        warnings.push(`USSD code ${ussd.code} should start with * and end with #`);
      }
    }

    // Validate API endpoints
    for (const api of profile.apiEndpoints) {
      if (!api.baseUrl.startsWith('https://')) {
        warnings.push(`API endpoint ${api.path} should use HTTPS`);
      }
    }

    return {
      profileId: profile.id,
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Get malware signatures for a specific provider
   */
  getMalwareSignatures(providerId: string): MalwareSignature[] {
    const profile = this.profiles.get(providerId);
    return profile?.malwareSignatures ?? [];
  }

  /**
   * Get all malware signatures across all profiles
   */
  getAllMalwareSignatures(): MalwareSignature[] {
    const signatures: MalwareSignature[] = [];
    for (const profile of this.profiles.values()) {
      signatures.push(...profile.malwareSignatures);
    }
    return signatures;
  }

  /**
   * Get protocol decoders for a provider
   */
  getProtocolDecoders(providerId: string): ProtocolDecoder[] {
    const profile = this.profiles.get(providerId);
    return profile?.protocolDecoders ?? [];
  }

  /**
   * Find profiles by package name
   */
  findByPackageName(packageName: string): AfricanFintechProfile[] {
    return this.getAllProfiles().filter(p =>
      p.packageNames.some(pkg => pkg === packageName || packageName.startsWith(pkg + '.'))
    );
  }

  /**
   * Get statistics about registered profiles
   */
  getStatistics(): RegistryStatistics {
    const profiles = this.getAllProfiles();
    const totalMalwareSignatures = profiles.reduce((sum, p) => sum + p.malwareSignatures.length, 0);
    const totalApiEndpoints = profiles.reduce((sum, p) => sum + p.apiEndpoints.length, 0);
    const totalUssdPatterns = profiles.reduce((sum, p) => sum + p.ussdPatterns.length, 0);
    const totalProtocolDecoders = profiles.reduce((sum, p) => sum + p.protocolDecoders.length, 0);
    const countries = new Set(profiles.flatMap(p => p.countries));
    const categories = new Set(profiles.map(p => p.category));

    return {
      totalProfiles: profiles.length,
      totalCountries: countries.size,
      totalCategories: categories.size,
      totalMalwareSignatures,
      totalApiEndpoints,
      totalUssdPatterns,
      totalProtocolDecoders,
      countries: Array.from(countries).sort(),
      categories: Array.from(categories).sort(),
    };
  }
}

/**
 * Validation result for a profile
 */
export interface ValidationResult {
  profileId: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Registry statistics
 */
export interface RegistryStatistics {
  totalProfiles: number;
  totalCountries: number;
  totalCategories: number;
  totalMalwareSignatures: number;
  totalApiEndpoints: number;
  totalUssdPatterns: number;
  totalProtocolDecoders: number;
  countries: string[];
  categories: string[];
}

// Export singleton instance
export const africanFintechRegistry = AfricanFintechProfileRegistry.getInstance();