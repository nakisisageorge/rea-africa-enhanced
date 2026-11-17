/**
 * Benchmark Regression Detection System
 *
 * Provides automated performance regression detection for RE analysis operations
 * with SQLite storage, 5% threshold, and CI integration.
 */

import Database, { type Database as DatabaseType } from 'better-sqlite3';
import { join } from 'path';
import { homedir } from 'os';
import { existsSync, mkdirSync } from 'fs';

export interface BenchmarkResult {
  id?: number;
  timestamp: string;
  suite: string;
  testName: string;
  durationMs: number;
  memoryMb: number;
  cpuPercent: number;
  metadata: Record<string, any>;
  gitCommit?: string;
  gitBranch?: string;
  isBaseline: boolean;
}

export interface RegressionAlert {
  id?: number;
  testName: string;
  suite: string;
  currentValue: number;
  baselineValue: number;
  changePercent: number;
  threshold: number;
  severity: 'warning' | 'critical';
  timestamp: string;
}

export interface BenchmarkConfig {
  storagePath: string;
  regressionThreshold: number; // percentage
  minSamplesForBaseline: number;
  retentionDays: number;
}

export class BenchmarkRegressionDetector {
  private db: DatabaseType;
  private config: BenchmarkConfig;

  constructor(config: Partial<BenchmarkConfig> = {}) {
    this.config = {
      storagePath: config.storagePath || join(homedir(), '.rea-africa-enhanced', 'benchmarks.db'),
      regressionThreshold: config.regressionThreshold || 5, // 5%
      minSamplesForBaseline: config.minSamplesForBaseline || 10,
      retentionDays: config.retentionDays || 90,
    };

    // Ensure storage directory exists
    const dir = join(this.config.storagePath, '..');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(this.config.storagePath);
    this.initializeDatabase();
  }

  private initializeDatabase(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS benchmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        suite TEXT NOT NULL,
        test_name TEXT NOT NULL,
        duration_ms REAL NOT NULL,
        memory_mb REAL NOT NULL,
        cpu_percent REAL NOT NULL,
        metadata TEXT NOT NULL,
        git_commit TEXT,
        git_branch TEXT,
        is_baseline INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_benchmarks_suite_test ON benchmarks(suite, test_name);
      CREATE INDEX IF NOT EXISTS idx_benchmarks_timestamp ON benchmarks(timestamp);
      CREATE INDEX IF NOT EXISTS idx_benchmarks_git ON benchmarks(git_commit, git_branch);

      CREATE TABLE IF NOT EXISTS regressions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        suite TEXT NOT NULL,
        test_name TEXT NOT NULL,
        current_value REAL NOT NULL,
        baseline_value REAL NOT NULL,
        change_percent REAL NOT NULL,
        threshold REAL NOT NULL,
        severity TEXT NOT NULL,
        acknowledged INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_regressions_suite_test ON regressions(suite, test_name);
      CREATE INDEX IF NOT EXISTS idx_regressions_timestamp ON regressions(timestamp);
    `);
  }

  /**
   * Record a benchmark result
   */
  recordResult(result: BenchmarkResult): number {
    const stmt = this.db.prepare(`
      INSERT INTO benchmarks (timestamp, suite, test_name, duration_ms, memory_mb, cpu_percent, metadata, git_commit, git_branch, is_baseline)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const info = stmt.run(
      result.timestamp,
      result.suite,
      result.testName,
      result.durationMs,
      result.memoryMb,
      result.cpuPercent,
      JSON.stringify(result.metadata),
      result.gitCommit || null,
      result.gitBranch || null,
      result.isBaseline ? 1 : 0
    );

    // Check for regression if not a baseline
    if (!result.isBaseline) {
      this.checkRegression(result);
    }

    return info.lastInsertRowid as number;
  }

  /**
   * Check for regression against baseline
   */
  private checkRegression(result: BenchmarkResult): RegressionAlert[] {
    const alerts: RegressionAlert[] = [];

    // Get baseline statistics for this test
    const baselines = this.db.prepare(`
      SELECT AVG(duration_ms) as avg_duration, AVG(memory_mb) as avg_memory,
             AVG(cpu_percent) as avg_cpu, COUNT(*) as sample_count
      FROM benchmarks
      WHERE suite = ? AND test_name = ? AND is_baseline = 1
    `).get(result.suite, result.testName) as any;

    if (!baselines || baselines.sample_count < this.config.minSamplesForBaseline) {
      return alerts; // Not enough baseline samples
    }

    // Check duration regression
    const durationChange = ((result.durationMs - baselines.avg_duration) / baselines.avg_duration) * 100;
    if (Math.abs(durationChange) > this.config.regressionThreshold) {
      alerts.push({
        testName: result.testName,
        suite: result.suite,
        currentValue: result.durationMs,
        baselineValue: baselines.avg_duration,
        changePercent: durationChange,
        threshold: this.config.regressionThreshold,
        severity: Math.abs(durationChange) > this.config.regressionThreshold * 2 ? 'critical' : 'warning',
        timestamp: result.timestamp,
      });
    }

    // Check memory regression
    const memoryChange = ((result.memoryMb - baselines.avg_memory) / baselines.avg_memory) * 100;
    if (Math.abs(memoryChange) > this.config.regressionThreshold) {
      alerts.push({
        testName: result.testName,
        suite: result.suite,
        currentValue: result.memoryMb,
        baselineValue: baselines.avg_memory,
        changePercent: memoryChange,
        threshold: this.config.regressionThreshold,
        severity: Math.abs(memoryChange) > this.config.regressionThreshold * 2 ? 'critical' : 'warning',
        timestamp: result.timestamp,
      });
    }

    // Store alerts
    for (const alert of alerts) {
      this.db.prepare(`
        INSERT INTO regressions (timestamp, suite, test_name, current_value, baseline_value, change_percent, threshold, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        alert.timestamp,
        alert.suite,
        alert.testName,
        alert.currentValue,
        alert.baselineValue,
        alert.changePercent,
        alert.threshold,
        alert.severity
      );
    }

    return alerts;
  }

  /**
   * Get regression alerts
   */
  getRegressions(since?: string, severity?: 'warning' | 'critical'): RegressionAlert[] {
    let query = 'SELECT id, timestamp, suite, test_name as testName, current_value as currentValue, baseline_value as baselineValue, change_percent as changePercent, threshold, severity, acknowledged FROM regressions WHERE acknowledged = 0';
    const params: any[] = [];

    if (since) {
      query += ' AND timestamp >= ?';
      params.push(since);
    }
    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }
    query += ' ORDER BY timestamp DESC';

    return this.db.prepare(query).all(...params) as RegressionAlert[];
  }

  /**
   * Acknowledge a regression
   */
  acknowledgeRegression(id: number): void {
    this.db.prepare('UPDATE regressions SET acknowledged = 1 WHERE id = ?').run(id);
  }

  /**
   * Get benchmark history for a test
   */
  getHistory(suite: string, testName: string, limit = 100): BenchmarkResult[] {
    const rows = this.db.prepare(`
      SELECT id, timestamp, suite, test_name as testName, duration_ms as durationMs,
             memory_mb as memoryMb, cpu_percent as cpuPercent, metadata,
             git_commit as gitCommit, git_branch as gitBranch, is_baseline as isBaseline
      FROM benchmarks
      WHERE suite = ? AND test_name = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `).all(suite, testName, limit) as any[];

    return rows.map(row => ({
      ...row,
      metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata,
      isBaseline: Boolean(row.isBaseline),
    })) as BenchmarkResult[];
  }

  /**
   * Get baseline statistics
   */
  getBaseline(suite: string, testName: string): any {
    return this.db.prepare(`
      SELECT AVG(duration_ms) as avg_duration, AVG(memory_mb) as avg_memory,
             AVG(cpu_percent) as avg_cpu, COUNT(*) as sample_count,
             MIN(duration_ms) as min_duration, MAX(duration_ms) as max_duration,
             MIN(memory_mb) as min_memory, MAX(memory_mb) as max_memory
      FROM benchmarks
      WHERE suite = ? AND test_name = ? AND is_baseline = 1
    `).get(suite, testName);
  }

  /**
   * Mark recent results as baseline
   */
  setBaseline(suite: string, testName: string, count: number): number {
    const stmt = this.db.prepare(`
      UPDATE benchmarks
      SET is_baseline = 1
      WHERE id IN (
        SELECT id FROM benchmarks
        WHERE suite = ? AND test_name = ? AND is_baseline = 0
        ORDER BY timestamp DESC
        LIMIT ?
      )
    `);
    const info = stmt.run(suite, testName, count);
    return info.changes;
  }

  /**
   * Clean up old records
   */
  cleanup(): number {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.config.retentionDays);

    const stmt = this.db.prepare(`
      DELETE FROM benchmarks WHERE timestamp < ?
    `);
    const info = stmt.run(cutoff.toISOString());
    return info.changes;
  }

  /**
   * Generate benchmark report
   */
  generateReport(since?: string): string {
    const regressions = this.getRegressions(since);
    const critical = regressions.filter(r => r.severity === 'critical');
    const warnings = regressions.filter(r => r.severity === 'warning');

    let report = '# Benchmark Regression Report\n\n';
    report += `Generated: ${new Date().toISOString()}\n`;
    report += `Threshold: ${this.config.regressionThreshold}%\n`;
    report += `Total Regressions: ${regressions.length} (Critical: ${critical.length}, Warnings: ${warnings.length})\n\n`;

    if (critical.length > 0) {
      report += '## Critical Regressions\n\n';
      for (const r of critical) {
        report += `- **${r.suite}.${r.testName}**: ${r.changePercent.toFixed(2)}% change (${r.currentValue.toFixed(2)} vs ${r.baselineValue.toFixed(2)} baseline)\n`;
      }
      report += '\n';
    }

    if (warnings.length > 0) {
      report += '## Warnings\n\n';
      for (const r of warnings) {
        report += `- **${r.suite}.${r.testName}**: ${r.changePercent.toFixed(2)}% change (${r.currentValue.toFixed(2)} vs ${r.baselineValue.toFixed(2)} baseline)\n`;
      }
      report += '\n';
    }

    return report;
  }

  close(): void {
    this.db.close();
  }
}

// Singleton instance
let detectorInstance: BenchmarkRegressionDetector | null = null;

export function getBenchmarkDetector(config?: Partial<BenchmarkConfig>): BenchmarkRegressionDetector {
  if (!detectorInstance) {
    detectorInstance = new BenchmarkRegressionDetector(config);
  }
  return detectorInstance;
}

export function resetBenchmarkDetector(): void {
  if (detectorInstance) {
    detectorInstance.close();
    detectorInstance = null;
  }
}