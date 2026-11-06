import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { PatchReviewManager } from './patchReviewManager.js';
import { analyzeSqlSource } from './sqlInjectionScanner.js';
import { suggestSqlInjectionPatch } from './sqlInjectionPatchSuggester.js';

const originalSource = [
  "import { Pool } from 'pg';",
  'const pool = new Pool();',
  "const userId = '42';",
  'pool.query(`SELECT * FROM users WHERE id = ${userId}`);',
  '',
].join('\n');

async function createReview() {
  const repositoryPath = await mkdtemp(path.join(process.cwd(), '..', 'prooflayer-patch-review-'));
  const sourcePath = path.join(repositoryPath, 'src', 'queries.ts');
  await mkdir(path.dirname(sourcePath), { recursive: true });
  await writeFile(sourcePath, originalSource, 'utf8');
  const [finding] = analyzeSqlSource(originalSource, 'src/queries.ts');
  assert.ok(finding, 'fixture should contain a scanner finding');
  const suggestion = await suggestSqlInjectionPatch(repositoryPath, finding);
  assert.equal(suggestion.status, 'suggested');
  assert.ok(suggestion.applyPlan);
  const manager = new PatchReviewManager();
  const created = manager.create(repositoryPath, suggestion);
  assert.ok(created.review);
  assert.ok(created.suggestion.reviewId);
  return { repositoryPath, sourcePath, manager, review: created.review, plan: suggestion.applyPlan };
}

test('confirmed apply changes only the reviewed file and records applied', async () => {
  const fixture = await createReview();
  try {
    const otherPath = path.join(fixture.repositoryPath, 'leave-alone.txt');
    await writeFile(otherPath, 'unrelated\n', 'utf8');
    const result = await fixture.manager.apply(fixture.repositoryPath, fixture.review.reviewId, true);
    assert.equal(result?.status, 'applied', result?.message);
    assert.equal(await readFile(fixture.sourcePath, 'utf8'), fixture.plan.patchedSource);
    assert.equal(await readFile(otherPath, 'utf8'), 'unrelated\n');
  } finally { await rm(fixture.repositoryPath, { recursive: true, force: true }); }
});

test('reject records the decision and leaves the source unchanged', async () => {
  const fixture = await createReview();
  try {
    const result = fixture.manager.reject(fixture.review.reviewId);
    assert.equal(result?.status, 'rejected');
    assert.equal(await readFile(fixture.sourcePath, 'utf8'), originalSource);
    assert.match(result?.message ?? '', /left unchanged/i);
  } finally { await rm(fixture.repositoryPath, { recursive: true, force: true }); }
});

test('a changed source is not overwritten and requires a fresh scan', async () => {
  const fixture = await createReview();
  try {
    const developerVersion = `${originalSource}// developer edit\n`;
    await writeFile(fixture.sourcePath, developerVersion, 'utf8');
    const result = await fixture.manager.apply(fixture.repositoryPath, fixture.review.reviewId, true);
    assert.equal(result?.status, 'stale', result?.message);
    assert.equal(await readFile(fixture.sourcePath, 'utf8'), developerVersion);
    assert.match(result?.message ?? '', /rescan/i);
  } finally { await rm(fixture.repositoryPath, { recursive: true, force: true }); }
});

test('apply refuses a request without explicit confirmation', async () => {
  const fixture = await createReview();
  try {
    await assert.rejects(fixture.manager.apply(fixture.repositoryPath, fixture.review.reviewId, false), /confirmation/i);
    assert.equal(await readFile(fixture.sourcePath, 'utf8'), originalSource);
  } finally { await rm(fixture.repositoryPath, { recursive: true, force: true }); }
});
