import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeSqlSource } from './sqlInjectionScanner.js';
import { verifySqlInjectionFinding } from './sqlInjectionFixVerifier.js';

const vulnerable = "import { Pool } from 'pg';\nconst pool = new Pool();\nconst userId = '42';\npool.query(`SELECT * FROM users WHERE id = ${userId}`);\n";
const original = analyzeSqlSource(vulnerable, 'src/queries.ts')[0]!;
function scan(source: string) {
  return { repositoryPath: 'fixture', scannedFiles: 1, scannedFilePaths: ['src/queries.ts'], skippedFiles: [], findings: analyzeSqlSource(source, 'src/queries.ts'), startedAt: new Date().toISOString(), durationMs: 1 };
}

test('a safely parameterized follow-up scan verifies the fix as Resolved', () => {
  const fresh = scan("import { Pool } from 'pg';\nconst pool = new Pool();\nconst userId = '42';\npool.query('SELECT * FROM users WHERE id = $1', [userId]);\n");
  const result = verifySqlInjectionFinding(original, fresh);
  assert.equal(result.status, 'Resolved');
  assert.equal(result.vulnerablePatternRemains, 'no');
  assert.equal(result.newScan.finding, null);
});

test('a patch that leaves the vulnerable construction is Still Detected', () => {
  const result = verifySqlInjectionFinding(original, scan(vulnerable));
  assert.equal(result.status, 'Still Detected');
  assert.equal(result.vulnerablePatternRemains, 'yes');
  assert.equal(result.newScan.finding?.file, original.file);
  assert.equal(result.newScan.finding?.line, original.line);
});

test('a skipped affected file produces Verification Inconclusive', () => {
  const fresh = { ...scan(''), scannedFilePaths: [], skippedFiles: [{ file: original.file, reason: 'Permission denied.' }] };
  const result = verifySqlInjectionFinding(original, fresh);
  assert.equal(result.status, 'Verification Inconclusive');
  assert.equal(result.vulnerablePatternRemains, 'unknown');
  assert.match(result.newScan.skippedReason ?? '', /Permission denied/);
});
