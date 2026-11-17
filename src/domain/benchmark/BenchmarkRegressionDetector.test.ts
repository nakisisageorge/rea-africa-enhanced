/**
 * Benchmark Regression Detection Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { BenchmarkRegressionDetector, type BenchmarkConfig, type BenchmarkResult } from '../../benchmark/BenchmarkRegressionDetector.js';
import { join } from 'path';
import { tmpdir } from 'os';
import { existsSync, rmSync } from 'fs';

describe('BenchmarkRegressionDetector', () => {
  let detector: BenchmarkRegressionDetector;
  const testDbPath = join(tmpdir(), 'rea-test-benchmarks.db');

  beforeEach(() => {
    // Clean up any existing test database
    if (existsSync(testDbPath)) {
      rmSync(testDbPath);
    }

    const config: Partial<BenchmarkConfig> = {
      storagePath: testDbPath,
      regressionThreshold: 5,
      minSamplesForBaseline: 3,
      retentionDays: 90,
    };

    detector = new BenchmarkRegressionDetector(config);
  });

  afterEach(() => {
    detector.close();
    if (existsSync(testDbPath)) {
      rmSync(testDbPath);
    }
  });

  it('should initialize database with required tables', () => {
    const result: BenchmarkResult = {
      timestamp: new Date().toISOString(),
      suite: 'test-suite',
      testName: 'test-benchmark',
      durationMs: 100,
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { iterations: 10 },
      isBaseline: true,
    };

    const id = detector.recordResult(result);
    expect(id).toBeGreaterThan(0);
  });

  it('should record benchmark results', () => {
    const result: BenchmarkResult = {
      timestamp: new Date().toISOString(),
      suite: 'test-suite',
      testName: 'test-benchmark',
      durationMs: 100,
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { iterations: 10 },
      isBaseline: true,
    };

    const id = detector.recordResult(result);
    expect(id).toBeGreaterThan(0);

    const history = detector.getHistory('test-suite', 'test-benchmark');
    expect(history.length).toBe(1);
    expect(history[0]!.durationMs).toBe(100);
    expect(history[0]!.isBaseline).toBe(true);
  });

  it('should detect regression when threshold exceeded', () => {
    const baseTime = new Date().toISOString();

    // Record baseline samples
    for (let i = 0; i < 5; i++) {
      detector.recordResult({
        timestamp: new Date(Date.parse(baseTime) + i * 1000).toISOString(),
        suite: 'regression-suite',
        testName: 'regression-test',
        durationMs: 100,
        memoryMb: 50,
        cpuPercent: 25,
        metadata: { run: i },
        isBaseline: true,
      });
    }

    // Record a result with 10% regression (should trigger alert)
    const currentResult = detector.recordResult({
      timestamp: new Date().toISOString(),
      suite: 'regression-suite',
      testName: 'regression-test',
      durationMs: 110, // 10% increase
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { run: 'current' },
      isBaseline: false,
    });

    expect(currentResult).toBeGreaterThan(0);

    const regressions = detector.getRegressions();
    expect(regressions.length).toBeGreaterThan(0);
    const firstRegression = regressions[0]!;
    expect(firstRegression.changePercent).toBeGreaterThan(5);
    expect(firstRegression.severity).toBe('warning');
  });

  it('should detect critical regression when threshold doubled', () => {
    const baseTime = new Date().toISOString();

    // Record baseline samples
    for (let i = 0; i < 5; i++) {
      detector.recordResult({
        timestamp: new Date(Date.parse(baseTime) + i * 1000).toISOString(),
        suite: 'critical-suite',
        testName: 'critical-test',
        durationMs: 100,
        memoryMb: 50,
        cpuPercent: 25,
        metadata: { run: i },
        isBaseline: true,
      });
    }

    // Record a result with 15% regression (should trigger critical alert)
    detector.recordResult({
      timestamp: new Date().toISOString(),
      suite: 'critical-suite',
      testName: 'critical-test',
      durationMs: 115, // 15% increase
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { run: 'current' },
      isBaseline: false,
    });

    const regressions = detector.getRegressions();
    const critical = regressions.filter(r => r.severity === 'critical');
    expect(critical.length).toBeGreaterThan(0);
  });

  it('should not detect regression for non-baseline tests with insufficient baselines', () => {
    const result = detector.recordResult({
      timestamp: new Date().toISOString(),
      suite: 'no-baseline-suite',
      testName: 'no-baseline-test',
      durationMs: 200,
      memoryMb: 100,
      cpuPercent: 50,
      metadata: { run: 'current' },
      isBaseline: false,
    });

    expect(result).toBeGreaterThan(0);

    const regressions = detector.getRegressions();
    const suiteRegressions = regressions.filter(r => r.suite === 'no-baseline-suite');
    expect(suiteRegressions.length).toBe(0);
  });

  it('should get baseline statistics', () => {
    const baseTime = new Date().toISOString();

    for (let i = 0; i < 5; i++) {
      detector.recordResult({
        timestamp: new Date(Date.parse(baseTime) + i * 1000).toISOString(),
        suite: 'stats-suite',
        testName: 'stats-test',
        durationMs: 100 + i * 2,
        memoryMb: 50 + i,
        cpuPercent: 25,
        metadata: { run: i },
        isBaseline: true,
      });
    }

    const baseline = detector.getBaseline('stats-suite', 'stats-test');
    expect(baseline).toBeDefined();
    expect(baseline.sample_count).toBe(5);
    expect(baseline.avg_duration).toBeCloseTo(104, 0); // Average of 100, 102, 104, 106, 108
  });

  it('should generate regression report', () => {
    const baseTime = new Date().toISOString();

    for (let i = 0; i < 5; i++) {
      detector.recordResult({
        timestamp: new Date(Date.parse(baseTime) + i * 1000).toISOString(),
        suite: 'report-suite',
        testName: 'report-test',
        durationMs: 100,
        memoryMb: 50,
        cpuPercent: 25,
        metadata: { run: i },
        isBaseline: true,
      });
    }

    detector.recordResult({
      timestamp: new Date().toISOString(),
      suite: 'report-suite',
      testName: 'report-test',
      durationMs: 110,
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { run: 'current' },
      isBaseline: false,
    });

    const report = detector.generateReport();
    expect(report).toContain('Benchmark Regression Report');
    expect(report).toContain('report-suite');
    expect(report).toContain('report-test');
  });

  it('should acknowledge regressions', () => {
    const baseTime = new Date().toISOString();

    for (let i = 0; i < 5; i++) {
      detector.recordResult({
        timestamp: new Date(Date.parse(baseTime) + i * 1000).toISOString(),
        suite: 'ack-suite',
        testName: 'ack-test',
        durationMs: 100,
        memoryMb: 50,
        cpuPercent: 25,
        metadata: { run: i },
        isBaseline: true,
      });
    }

    detector.recordResult({
      timestamp: new Date().toISOString(),
      suite: 'ack-suite',
      testName: 'ack-test',
      durationMs: 110,
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { run: 'current' },
      isBaseline: false,
    });

    const regressions = detector.getRegressions();
    expect(regressions.length).toBeGreaterThan(0);

    const regression = regressions[0]!;
    expect(regression.id).toBeDefined();

    detector.acknowledgeRegression(regression.id!);

    const unacknowledged = detector.getRegressions();
    const ackRegressions = unacknowledged.filter(r => r.id === regression.id);
    expect(ackRegressions.length).toBe(0);
  });

  it('should cleanup old records', () => {
    const oldDate = new Date();
    oldDate.setDate(oldDate.getDate() - 100);

    detector.recordResult({
      timestamp: oldDate.toISOString(),
      suite: 'cleanup-suite',
      testName: 'cleanup-test',
      durationMs: 100,
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { run: 'old' },
      isBaseline: true,
    });

    detector.recordResult({
      timestamp: new Date().toISOString(),
      suite: 'cleanup-suite',
      testName: 'cleanup-test',
      durationMs: 100,
      memoryMb: 50,
      cpuPercent: 25,
      metadata: { run: 'new' },
      isBaseline: true,
    });

    const deleted = detector.cleanup();
    expect(deleted).toBe(1);

    const history = detector.getHistory('cleanup-suite', 'cleanup-test');
    expect(history.length).toBe(1);
    expect(history[0]!.metadata.run).toBe('new');
  });

  it('should set baseline from recent results', () => {
    for (let i = 0; i < 5; i++) {
      detector.recordResult({
        timestamp: new Date().toISOString(),
        suite: 'baseline-suite',
        testName: 'baseline-test',
        durationMs: 100,
        memoryMb: 50,
        cpuPercent: 25,
        metadata: { run: i },
        isBaseline: false,
      });
    }

    const updated = detector.setBaseline('baseline-suite', 'baseline-test', 3);
    expect(updated).toBe(3);

    const baseline = detector.getBaseline('baseline-suite', 'baseline-test');
    expect(baseline.sample_count).toBe(3);
  });
});