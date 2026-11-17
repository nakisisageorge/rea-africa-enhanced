/**
 * African Fintech Profile Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AfricanFintechProfileRegistry } from './AfricanFintechProfileRegistry.js';

describe('AfricanFintechProfileRegistry', () => {
  let registry: AfricanFintechProfileRegistry;

  beforeEach(() => {
    registry = AfricanFintechProfileRegistry.getInstance();
  });

  it('should have 18 registered profiles', () => {
    const profiles = registry.getAllProfiles();
    expect(profiles.length).toBe(18);
  });

  it('should have correct profile IDs', () => {
    const profileIds = registry.getProfileIds();
    expect(profileIds).toContain('mpesa');
    expect(profileIds).toContain('mtn-momo');
    expect(profileIds).toContain('airtel-money');
    expect(profileIds).toContain('orange-money');
    expect(profileIds).toContain('wave');
    expect(profileIds).toContain('ecocash');
    expect(profileIds).toContain('paga');
    expect(profileIds).toContain('opay');
    expect(profileIds).toContain('flutterwave');
    expect(profileIds).toContain('chipper-cash');
    expect(profileIds).toContain('worldremit');
    expect(profileIds).toContain('paystack');
    expect(profileIds).toContain('paypal-africa');
    expect(profileIds).toContain('vodacom-mpesa');
    expect(profileIds).toContain('tigo-pesa');
    expect(profileIds).toContain('halopesa');
    expect(profileIds).toContain('eazzy-pay');
    expect(profileIds).toContain('mpawa');
  });

  it('should retrieve profiles by country', () => {
    const kenyaProfiles = registry.getProfilesByCountry('KE');
    expect(kenyaProfiles.length).toBeGreaterThan(0);
    expect(kenyaProfiles.some((p: any) => p.id === 'mpesa')).toBe(true);
    expect(kenyaProfiles.some((p: any) => p.id === 'airtel-money')).toBe(true);

    const nigeriaProfiles = registry.getProfilesByCountry('NG');
    expect(nigeriaProfiles.length).toBeGreaterThan(0);
    expect(nigeriaProfiles.some((p: any) => p.id === 'mtn-momo')).toBe(true);
    expect(nigeriaProfiles.some((p: any) => p.id === 'opay')).toBe(true);
  });

  it('should retrieve profiles by category', () => {
    const mobileMoneyProfiles = registry.getProfilesByCategory('mobile-money');
    expect(mobileMoneyProfiles.length).toBeGreaterThan(0);

    const remittanceProfiles = registry.getProfilesByCategory('remittance');
    expect(remittanceProfiles.length).toBeGreaterThan(0);
    expect(remittanceProfiles.some((p: any) => p.id === 'chipper-cash')).toBe(true);
  });

  it('should validate all profiles', () => {
    const results = registry.validateAll();
    expect(results.length).toBe(18);

    // All profiles should be valid (no errors)
    for (const result of results) {
      expect(result.valid).toBe(true);
      expect(result.errors.length).toBe(0);
    }
  });

  it('should find profiles by package name', () => {
    const mpesaProfiles = registry.findByPackageName('com.safaricom.mpesa');
    expect(mpesaProfiles.length).toBe(1);
    expect(mpesaProfiles[0]!.id).toBe('mpesa');
  });

  it('should get registry statistics', () => {
    const stats = registry.getStatistics();
    expect(stats.totalProfiles).toBe(18);
    expect(stats.totalCountries).toBeGreaterThan(10);
    expect(stats.totalCategories).toBeGreaterThan(3);
    expect(stats.totalMalwareSignatures).toBeGreaterThan(0);
    expect(stats.totalApiEndpoints).toBeGreaterThan(0);
    expect(stats.totalUssdPatterns).toBeGreaterThan(0);
    expect(stats.totalProtocolDecoders).toBeGreaterThan(0);
    expect(stats.countries.length).toBe(stats.totalCountries);
    expect(stats.categories.length).toBe(stats.totalCategories);
  });

  it('should get malware signatures for provider', () => {
    const mpesaSignatures = registry.getMalwareSignatures('mpesa');
    expect(mpesaSignatures.length).toBeGreaterThan(0);
  });

  it('should get protocol decoders for provider', () => {
    const mpesaDecoders = registry.getProtocolDecoders('mpesa');
    expect(mpesaDecoders.length).toBeGreaterThan(0);
  });

  it('should get all malware signatures', () => {
    const allSignatures = registry.getAllMalwareSignatures();
    expect(allSignatures.length).toBeGreaterThan(0);
  });
});