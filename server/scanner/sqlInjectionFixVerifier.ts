import type { SqlInjectionFinding, SqlInjectionScanResult } from './sqlInjectionScanner.js';

export type SqlInjectionVerification = {
  status: 'Resolved' | 'Still Detected' | 'Verification Inconclusive';
  originalFinding: Pick<SqlInjectionFinding, 'id' | 'title' | 'severity' | 'ruleId' | 'file' | 'line' | 'sink' | 'pattern' | 'code' | 'historySignature'>;
  newScan: { startedAt: string; scannedFiles: number; finding: Pick<SqlInjectionFinding, 'id' | 'file' | 'line' | 'sink' | 'pattern' | 'code'> | null; skippedReason?: string };
  vulnerablePatternRemains: 'yes' | 'no' | 'unknown';
  explanation: string;
};

export function verifySqlInjectionFinding(original: SqlInjectionFinding, scan: SqlInjectionScanResult): SqlInjectionVerification {
  const base = {
    originalFinding: {
      id: original.id, title: original.title, severity: original.severity, ruleId: original.ruleId,
      file: original.file, line: original.line, sink: original.sink, pattern: original.pattern,
      code: original.code, historySignature: original.historySignature,
    },
  };
  const skipped = scan.skippedFiles.find(item => item.file.replaceAll('\\', '/') === original.file.replaceAll('\\', '/'));
  if (skipped) return {
    ...base, status: 'Verification Inconclusive', vulnerablePatternRemains: 'unknown',
    newScan: { startedAt: scan.startedAt, scannedFiles: scan.scannedFiles, finding: null, skippedReason: skipped.reason },
    explanation: `The scanner could not analyze ${original.file}: ${skipped.reason} The original finding is preserved.`
  };
  if (!scan.scannedFilePaths.some(file => file.replaceAll('\\', '/') === original.file.replaceAll('\\', '/'))) return {
    ...base, status: 'Verification Inconclusive', vulnerablePatternRemains: 'unknown',
    newScan: { startedAt: scan.startedAt, scannedFiles: scan.scannedFiles, finding: null },
    explanation: `The fresh scan did not analyze ${original.file}, so ProofLayer cannot confirm whether the original vulnerability is resolved. The original finding is preserved.`
  };

  const inFile = scan.findings.filter(item => item.file.replaceAll('\\', '/') === original.file.replaceAll('\\', '/'));
  const exact = inFile.find(item => item.historySignature === original.historySignature);
  if (exact) return {
    ...base, status: 'Still Detected', vulnerablePatternRemains: 'yes',
    newScan: { startedAt: scan.startedAt, scannedFiles: scan.scannedFiles, finding: { id: exact.id, file: exact.file, line: exact.line, sink: exact.sink, pattern: exact.pattern, code: exact.code } },
    explanation: 'The new scan found the same SQL construction pattern in the affected file.'
  };

  const similar = inFile.find(item => item.ruleId === original.ruleId && item.sink.toLowerCase() === original.sink.toLowerCase());
  if (similar) return {
    ...base, status: 'Verification Inconclusive', vulnerablePatternRemains: 'unknown',
    newScan: { startedAt: scan.startedAt, scannedFiles: scan.scannedFiles, finding: { id: similar.id, file: similar.file, line: similar.line, sink: similar.sink, pattern: similar.pattern, code: similar.code } },
    explanation: 'A similar unsafe SQL pattern remains in the affected file, but its query signature changed, so ProofLayer cannot confidently match it to the original finding.'
  };

  return {
    ...base, status: 'Resolved', vulnerablePatternRemains: 'no',
    newScan: { startedAt: scan.startedAt, scannedFiles: scan.scannedFiles, finding: null },
    explanation: `The fresh scan successfully analyzed ${original.file} and did not find the original SQL pattern there.`
  };
}
