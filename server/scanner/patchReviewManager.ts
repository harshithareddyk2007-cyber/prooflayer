import { randomUUID, createHash } from 'node:crypto';
import { chmod, lstat, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createUnifiedDiff, type SqlInjectionPatchSuggestion, type SqlPatchApplyPlan } from './sqlInjectionPatchSuggester.js';

export type PatchReviewStatus = 'pending' | 'applied' | 'rejected' | 'stale' | 'error';

export type PatchReviewRecord = {
  reviewId: string;
  findingId: string;
  file: string;
  diff: string;
  status: PatchReviewStatus;
  createdAt: string;
  reviewedAt: string | null;
  message: string;
};

type StoredPatchReview = {
  record: PatchReviewRecord;
  repositoryPath: string;
  plan: SqlPatchApplyPlan;
};

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

function hash(source: string): string {
  return createHash('sha256').update(source).digest('hex');
}

function updated(record: PatchReviewRecord, status: PatchReviewStatus, message: string): PatchReviewRecord {
  return { ...record, status, message, reviewedAt: new Date().toISOString() };
}

async function pathHasNoSymlinks(repositoryPath: string, fullPath: string): Promise<boolean> {
  const root = path.resolve(repositoryPath);
  const relative = path.relative(root, fullPath);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return false;
  let current = root;
  const rootInfo = await lstat(current);
  if (rootInfo.isSymbolicLink()) return false;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const info = await lstat(current);
    if (info.isSymbolicLink()) return false;
  }
  return true;
}

function validPlan(plan: SqlPatchApplyPlan): boolean {
  if (!Number.isInteger(plan.replaceStart) || !Number.isInteger(plan.replaceEnd)
    || plan.replaceStart < 0 || plan.replaceEnd < plan.replaceStart
    || plan.replaceEnd > plan.originalSource.length) return false;
  if (hash(plan.originalSource) !== plan.sourceHash) return false;
  if (plan.originalSource.slice(plan.replaceStart, plan.replaceEnd) !== plan.expectedText) return false;
  const reconstructed = plan.originalSource.slice(0, plan.replaceStart) + plan.replacement + plan.originalSource.slice(plan.replaceEnd);
  return reconstructed === plan.patchedSource
    && plan.diff.length > 0
    && createUnifiedDiff(plan.file, plan.originalSource, plan.patchedSource) === plan.diff;
}

export class PatchReviewManager {
  private readonly reviews = new Map<string, StoredPatchReview>();

  create(repositoryPath: string, suggestion: SqlInjectionPatchSuggestion): { suggestion: Omit<SqlInjectionPatchSuggestion, 'applyPlan'> & { reviewId?: string }; review?: PatchReviewRecord } {
    const { applyPlan, ...publicSuggestion } = suggestion;
    if (suggestion.status !== 'suggested' || !applyPlan || !validPlan(applyPlan)) return { suggestion: publicSuggestion };
    const reviewId = randomUUID();
    const record: PatchReviewRecord = {
      reviewId,
      findingId: suggestion.findingId,
      file: suggestion.file,
      diff: suggestion.diff ?? '',
      status: 'pending',
      createdAt: new Date().toISOString(),
      reviewedAt: null,
      message: 'Awaiting developer review. The source file has not been changed.',
    };
    this.reviews.set(reviewId, { record, repositoryPath: path.resolve(repositoryPath), plan: applyPlan });
    return { suggestion: { ...publicSuggestion, reviewId }, review: record };
  }

  get(reviewId: string): PatchReviewRecord | null {
    return this.reviews.get(reviewId)?.record ?? null;
  }

  reject(reviewId: string): PatchReviewRecord | null {
    const stored = this.reviews.get(reviewId);
    if (!stored) return null;
    if (stored.record.status !== 'pending') return stored.record;
    stored.record = updated(stored.record, 'rejected', 'Rejected by the developer. The source file was left unchanged.');
    return stored.record;
  }

  async apply(repositoryPath: string, reviewId: string, confirmed: boolean): Promise<PatchReviewRecord | null> {
    const stored = this.reviews.get(reviewId);
    if (!stored) return null;
    if (!confirmed) throw new Error('Explicit confirmation is required before applying a patch.');
    if (stored.record.status !== 'pending') return stored.record;
    if (path.resolve(repositoryPath) !== stored.repositoryPath) {
      stored.record = updated(stored.record, 'error', 'The connected repository changed. Reconnect the original repository and review the patch again.');
      return stored.record;
    }
    if (!validPlan(stored.plan) || stored.plan.diff !== stored.record.diff) {
      stored.record = updated(stored.record, 'error', 'The stored patch failed its integrity check and was not applied.');
      return stored.record;
    }

    const fullPath = path.resolve(repositoryPath, stored.plan.file);
    const relativePath = path.relative(repositoryPath, fullPath);
    if (relativePath === '..' || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) {
      stored.record = updated(stored.record, 'error', 'The patch file resolves outside the connected repository.');
      return stored.record;
    }

    let tempPath: string | null = null;
    let phase = 'checking the reviewed source path';
    try {
      if (!await pathHasNoSymlinks(repositoryPath, fullPath)) {
        stored.record = updated(stored.record, 'error', 'The affected file resolves outside the connected repository.');
        return stored.record;
      }
      const info = await lstat(fullPath);
      if (!info.isFile() || info.size > MAX_SOURCE_BYTES) {
        stored.record = updated(stored.record, 'error', 'The affected path is no longer a regular source file within the size limit. No changes were made.');
        return stored.record;
      }
      const currentSource = await readFile(fullPath, 'utf8');
      if (hash(currentSource) !== stored.plan.sourceHash || currentSource !== stored.plan.originalSource) {
        stored.record = updated(stored.record, 'stale', 'The file changed after this patch was generated. Nothing was applied. Rescan and generate a fresh patch.');
        return stored.record;
      }

      const patchedSource = currentSource.slice(0, stored.plan.replaceStart)
        + stored.plan.replacement + currentSource.slice(stored.plan.replaceEnd);
      if (patchedSource !== stored.plan.patchedSource) {
        stored.record = updated(stored.record, 'error', 'The patch no longer applies cleanly to the reviewed source. No changes were made.');
        return stored.record;
      }

      tempPath = path.join(path.dirname(fullPath), `.${path.basename(fullPath)}.${randomUUID()}.prooflayer.tmp`);
      phase = 'writing the temporary reviewed file';
      await writeFile(tempPath, patchedSource, { flag: 'wx', mode: info.mode });
      if (process.platform !== 'win32') {
        phase = 'preserving file permissions';
        await chmod(tempPath, info.mode & 0o777);
      }

      phase = 'checking the source again before replacement';
      const latestInfo = await lstat(fullPath);
      if (!latestInfo.isFile() || latestInfo.mode !== info.mode) {
        stored.record = updated(stored.record, 'stale', 'The affected file type or permissions changed while applying. Nothing was applied.');
        return stored.record;
      }
      const latestSource = await readFile(fullPath, 'utf8');
      if (hash(latestSource) !== stored.plan.sourceHash || latestSource !== stored.plan.originalSource) {
        stored.record = updated(stored.record, 'stale', 'The file changed while the patch was being prepared. Nothing was applied. Rescan and generate a fresh patch.');
        return stored.record;
      }
      phase = 'checking the reviewed path before replacement';
      if (!await pathHasNoSymlinks(repositoryPath, fullPath)) {
        stored.record = updated(stored.record, 'stale', 'The affected path changed while the patch was being prepared. Nothing was applied.');
        return stored.record;
      }

      phase = 'replacing the reviewed source file';
      await rename(tempPath, fullPath);
      tempPath = null;
      phase = 'verifying the applied source';
      const writtenSource = await readFile(fullPath, 'utf8');
      if (hash(writtenSource) !== hash(patchedSource)) {
        stored.record = updated(stored.record, 'error', 'The file contents did not match the reviewed patch after writing. Inspect the file before continuing.');
        return stored.record;
      }
      stored.record = updated(stored.record, 'applied', 'Patch applied to the reviewed file. Run a new scan to refresh findings. No commit or push was made.');
      return stored.record;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      stored.record = updated(stored.record, code === 'ENOENT' || code === 'ENOTDIR' ? 'stale' : 'error', code === 'ENOENT' || code === 'ENOTDIR'
        ? 'The affected file is no longer available. Nothing was applied. Rescan and generate a fresh patch.'
        : code === 'EACCES' || code === 'EPERM'
        ? `Permission was denied while ${phase}. The patch was not committed or pushed.`
        : `The patch could not be applied while ${phase}. Check the affected file and try generating a fresh suggestion.`);
      return stored.record;
    } finally {
      if (tempPath) await unlink(tempPath).catch(() => {});
    }
  }
}
