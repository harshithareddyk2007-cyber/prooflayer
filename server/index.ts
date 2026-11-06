import cors from 'cors';
import express from 'express';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { scanSqlInjection, SqlInjectionScanError, type SqlInjectionScanResult } from './scanner/sqlInjectionScanner.js';
import { investigateGitHistory, type GitHistoryInvestigation } from './scanner/gitHistoryInvestigator.js';
import { suggestSqlInjectionPatch } from './scanner/sqlInjectionPatchSuggester.js';
import { PatchReviewManager } from './scanner/patchReviewManager.js';
import { verifySqlInjectionFinding } from './scanner/sqlInjectionFixVerifier.js';
import { scanNpmDependencies } from './scanner/dependencyAuditor.js';
import { ActivityLog } from './activityLog.js';

const app = express();
const port = Number(process.env.PORT ?? 4317);
const execFileAsync = promisify(execFile);

type Repository = {
  name: string;
  path: string;
  branch: string;
  latestCommit: { hash: string; message: string } | null;
  connectedAt: string;
};

let connectedRepository: Repository | null = null;
let latestSqlInjectionScan: SqlInjectionScanResult | null = null;
let latestGitHistoryInvestigations = new Map<string, GitHistoryInvestigation>();
const patchReviewManager = new PatchReviewManager();
const activityLog = new ActivityLog();
const patchReviewOrigins = new Map<string, { repositoryPath: string; finding: SqlInjectionScanResult['findings'][number] }>();
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    try {
      const url = new URL(origin);
      const localHost = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
      const vitePort = /^517[0-9]$/.test(url.port || '');
      callback(null, localHost && vitePort);
    } catch { callback(null, false); }
  },
}));
app.use(express.json({ limit: '8kb' }));

class RepositoryError extends Error {
  constructor(message: string, readonly status = 400) { super(message); }
}

async function git(args: string[], cwd?: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync('git', args, {
      cwd, windowsHide: true, timeout: 5000, maxBuffer: 1024 * 1024,
    });
    return stdout.trim();
  } catch (error) {
    const e = error as NodeJS.ErrnoException & { code?: string; stderr?: string };
    if (e.code === 'ENOENT') throw new RepositoryError('Git is not installed or is not available on the server PATH.', 503);
    if (e.code === 'EACCES' || e.code === 'EPERM') throw new RepositoryError('Permission denied while accessing this repository.', 403);
    if (e.code === 'ETIMEDOUT') throw new RepositoryError('Git took too long to inspect this repository. Check that the folder is accessible.', 422);
    if (e.stderr?.toLowerCase().includes('does not have any commits yet') || e.stderr?.toLowerCase().includes('needed a single revision')) {
      throw new RepositoryError('This repository has no commits yet.', 422);
    }
    if (e.stderr?.toLowerCase().includes('not a git repository')) {
      throw new RepositoryError('This folder is not a Git repository.', 422);
    }
    throw new RepositoryError('This folder could not be opened as a Git repository. Check that it is valid and accessible.', 422);
  }
}

app.get('/api/repository', (_req, res) => res.json({ repository: connectedRepository }));

app.get('/api/activity-log', (req, res) => {
  const requested = Number(req.query.limit ?? 200);
  const limit = Number.isFinite(requested) ? requested : 200;
  res.json({ events: activityLog.list(limit), sessionOnly: true, maxEvents: 500 });
});

app.post('/api/repository/connect', async (req, res) => {
  try {
    if (connectedRepository) throw new RepositoryError('Disconnect the current repository before connecting another one.', 409);
    const submittedPath = req.body?.path;
    if (typeof submittedPath !== 'string' || !submittedPath.trim()) {
      throw new RepositoryError('Enter the absolute path to a local repository folder.');
    }
    const enteredPath = submittedPath.trim();
    if (!path.isAbsolute(enteredPath)) throw new RepositoryError('Enter an absolute path to the repository folder.');
    const repositoryPath = path.resolve(enteredPath);
    let info;
    try { info = await stat(repositoryPath); }
    catch (error) {
      const e = error as NodeJS.ErrnoException;
      if (e.code === 'ENOENT' || e.code === 'ENOTDIR') throw new RepositoryError('No folder exists at that path.', 404);
      if (e.code === 'EACCES' || e.code === 'EPERM') throw new RepositoryError('Permission denied while accessing that folder.', 403);
      throw new RepositoryError('That folder is inaccessible. Check the path and your permissions.', 422);
    }
    if (!info.isDirectory()) throw new RepositoryError('The path points to a file. Enter a folder path instead.');

    await git(['--version']);
    const root = await git(['-C', repositoryPath, 'rev-parse', '--show-toplevel']);
    if (!root) throw new RepositoryError('This folder is not a Git repository.');
    const branch = await git(['-C', root, 'branch', '--show-current']);
    let latestCommit: Repository['latestCommit'] = null;
    try {
      const log = await git(['-C', root, 'log', '-1', '--format=%H%n%s']);
      const [hash, ...messageLines] = log.split('\n');
      if (hash) latestCommit = { hash, message: messageLines.join('\n') };
    } catch (error) {
      if (!(error instanceof Error) || error.message !== 'This repository has no commits yet.') throw error;
    }
    connectedRepository = {
      name: path.basename(root), path: root, branch: branch || 'Detached HEAD',
      latestCommit,
      connectedAt: new Date().toISOString(),
    };
    latestSqlInjectionScan = null;
    latestGitHistoryInvestigations.clear();
    patchReviewOrigins.clear();
    activityLog.record({ category:'repository',status:'success',title:'Repository connected',details:`Connected ${connectedRepository.name} on branch ${connectedRepository.branch}.`,repository:connectedRepository.name });
    res.json({ repository: connectedRepository });
  } catch (error) {
    const e = error as Error & { status?: number };
    activityLog.record({category:'repository',status:'error',title:'Repository connection failed',details:e.message||'Unable to connect repository.',repository:null});
    res.status(e.status ?? 422).json({ error: e.message || 'Unable to connect to this repository.' });
  }
});

app.delete('/api/repository', (_req, res) => {
  if (connectedRepository) activityLog.record({category:'repository',status:'info',title:'Repository disconnected',details:`Disconnected ${connectedRepository.name}.`,repository:connectedRepository.name});
  connectedRepository = null;
  latestSqlInjectionScan = null;
  latestGitHistoryInvestigations.clear();
  patchReviewOrigins.clear();
  res.json({ repository: null });
});

app.post('/api/scans/sql-injection', async (_req, res) => {
  if (!connectedRepository) {
    res.status(409).json({ error: 'Connect a local Git repository before starting a scan.' });
    return;
  }
  try {
    const result = await scanSqlInjection(connectedRepository.path);
    latestSqlInjectionScan = result;
    latestGitHistoryInvestigations.clear();
    activityLog.record({category:'security',status:result.findings.length?'warning':'success',title:'SQL injection scan completed',details:`Scanned ${result.scannedFiles} source files and found ${result.findings.length} supported SQL injection pattern${result.findings.length===1?'':'s'}.`,repository:connectedRepository.name});
    res.json({ result });
  } catch (error) {
    const e = error as Error & { status?: number };
    activityLog.record({category:'security',status:'error',title:'SQL injection scan failed',details:e.message || 'The scanner could not complete.',repository:connectedRepository.name});
    res.status(e instanceof SqlInjectionScanError ? e.status : (e.status ?? 500))
      .json({ error: e.message || 'The SQL injection scan could not be completed.' });
  }
});

app.post('/api/scans/git-history', async (req, res) => {
  if (!connectedRepository) {
    res.status(409).json({ error: 'Connect a local Git repository before investigating findings.' });
    return;
  }
  if (!latestSqlInjectionScan) {
    res.status(409).json({ error: 'Run a SQL injection scan before investigating Git history.' });
    return;
  }
  const findingId = req.body?.findingId;
  if (typeof findingId !== 'string' || !findingId.trim()) {
    res.status(400).json({ error: 'Select a finding to investigate.' });
    return;
  }
  const finding = latestSqlInjectionScan.findings.find(item => item.id === findingId);
  if (!finding) {
    res.status(404).json({ error: 'That finding is not part of the latest completed scan. Run a new scan and try again.' });
    return;
  }
  latestGitHistoryInvestigations.delete(finding.id);
  try {
    const result = await investigateGitHistory(connectedRepository.path, finding);
    latestGitHistoryInvestigations.set(finding.id, result);
    activityLog.record({category:'investigation',status:result.status==='determined'?'success':'warning',title:result.status==='determined'?'Git history investigated':'Git introducing commit uncertain',details:result.reason,repository:connectedRepository.name});
    res.json({ result });
  } catch (error) {
    activityLog.record({category:'investigation',status:'error',title:'Git history investigation failed',details:(error as Error).message||'Git history could not be investigated.',repository:connectedRepository.name});
    res.status(500).json({ error: 'Git history could not be investigated. Check repository access and try again.' });
  }
});

app.post('/api/scans/patch-suggestion', async (req, res) => {
  if (!connectedRepository) {
    res.status(409).json({ error: 'Connect a local Git repository before suggesting a patch.' });
    return;
  }
  if (!latestSqlInjectionScan) {
    res.status(409).json({ error: 'Run a SQL injection scan before requesting a patch suggestion.' });
    return;
  }
  const findingId = req.body?.findingId;
  if (typeof findingId !== 'string' || !findingId.trim()) {
    res.status(400).json({ error: 'Select a finding before requesting a patch suggestion.' });
    return;
  }
  const finding = latestSqlInjectionScan.findings.find(item => item.id === findingId);
  if (!finding) {
    res.status(404).json({ error: 'That finding is not part of the latest completed scan. Run a new scan and try again.' });
    return;
  }
  try {
    const generated = await suggestSqlInjectionPatch(connectedRepository.path, finding, latestGitHistoryInvestigations.get(finding.id));
    const { suggestion, review } = patchReviewManager.create(connectedRepository.path, generated);
    if (review) patchReviewOrigins.set(review.reviewId, { repositoryPath: connectedRepository.path, finding });
    activityLog.record({category:'patch',status:suggestion.status==='suggested'?'success':'warning',title:suggestion.status==='suggested'?'Patch suggestion prepared':'No safe patch suggested',details:`${finding.file}:${finding.line}. ${suggestion.reason}`,repository:connectedRepository.name});
    res.json({ result: suggestion, review });
  } catch (error) {
    activityLog.record({category:'patch',status:'error',title:'Patch suggestion failed',details:(error as Error).message||'The patch suggestion could not be prepared.',repository:connectedRepository.name});
    res.status(500).json({ error: 'A patch suggestion could not be prepared. The repository was not changed.' });
  }
});

app.post('/api/scans/patch-review/verify', async (req, res) => {
  if (!connectedRepository) {
    res.status(409).json({ error: 'Connect a local Git repository before verifying a patch.' });
    return;
  }
  const reviewId = req.body?.reviewId;
  if (typeof reviewId !== 'string' || !reviewId.trim()) {
    res.status(400).json({ error: 'Select an applied patch before verifying it.' });
    return;
  }
  const review = patchReviewManager.get(reviewId);
  const origin = patchReviewOrigins.get(reviewId);
  if (!review || review.status !== 'applied' || !origin) {
    res.status(409).json({ error: 'Verification is available after an applied patch while its original finding is available in this session.' });
    return;
  }
  if (origin.repositoryPath !== connectedRepository.path) {
    res.status(409).json({ error: 'This patch belongs to a different repository. Reconnect that repository to verify it.' });
    return;
  }
  try {
    const scan = await scanSqlInjection(connectedRepository.path);
    latestSqlInjectionScan = scan;
    latestGitHistoryInvestigations.clear();
    const verification=verifySqlInjectionFinding(origin.finding, scan);
    activityLog.record({category:'verification',status:verification.status==='Resolved'?'success':verification.status==='Still Detected'?'warning':'info',title:`Fix verification: ${verification.status}`,details:`${origin.finding.file}:${origin.finding.line}. ${verification.explanation}`,repository:connectedRepository.name});
    res.json({ verification, scan });
  } catch (error) {
    const e = error as Error & { status?: number };
    activityLog.record({category:'verification',status:'error',title:'Fix verification failed',details:e.message||'The repository could not be rescanned.',repository:connectedRepository.name});
    res.status(e instanceof SqlInjectionScanError ? e.status : (e.status ?? 500))
      .json({ error: `The repository rescan failed, so the finding could not be verified. ${e.message || ''}`.trim() });
  }
});

app.post('/api/scans/patch-review/reject', (req, res) => {
  if (!connectedRepository) {
    res.status(409).json({ error: 'Connect a local Git repository before recording a patch decision.' });
    return;
  }
  const reviewId = req.body?.reviewId;
  if (typeof reviewId !== 'string' || !reviewId.trim()) {
    res.status(400).json({ error: 'Select a patch review before rejecting it.' });
    return;
  }
  const review = patchReviewManager.reject(reviewId);
  if (!review) {
    res.status(404).json({ error: 'This patch review is no longer available.' });
    return;
  }
  activityLog.record({category:'patch',status:'info',title:'Patch rejected',details:`Rejected the suggested patch for ${review.file}. The source was left unchanged.`,repository:connectedRepository.name});
  res.json({ review });
});

app.post('/api/scans/patch-review/apply', async (req, res) => {
  if (!connectedRepository) {
    res.status(409).json({ error: 'Connect a local Git repository before applying a patch.' });
    return;
  }
  const reviewId = req.body?.reviewId;
  if (typeof reviewId !== 'string' || !reviewId.trim()) {
    res.status(400).json({ error: 'Select a patch review before applying it.' });
    return;
  }
  if (req.body?.confirmed !== true) {
    res.status(400).json({ error: 'Explicit confirmation is required before applying a patch.' });
    return;
  }
  try {
    const review = await patchReviewManager.apply(connectedRepository.path, reviewId, true);
    if (!review) {
      res.status(404).json({ error: 'This patch review is no longer available.' });
      return;
    }
    if (review.status === 'stale' || review.status === 'applied') latestSqlInjectionScan = null;
    activityLog.record({category:'patch',status:review.status==='applied'?'success':review.status==='stale'?'warning':'error',title:`Patch ${review.status}`,details:`${review.file}. ${review.message}`,repository:connectedRepository.name});
    res.json({ review });
  } catch (error) {
    activityLog.record({category:'patch',status:'error',title:'Patch apply failed',details:(error as Error).message||'Patch could not be applied.',repository:connectedRepository.name});
    res.status(500).json({ error: 'The patch could not be applied. The source repository was not committed or pushed.' });
  }
});

app.post('/api/scans/dependencies', async (_req, res) => {
  if (!connectedRepository) {
    res.status(409).json({ error: 'Connect a local Git repository before scanning dependencies.' });
    return;
  }
  try {
    const result=await scanNpmDependencies(connectedRepository.path);
    activityLog.record({category:'dependencies',status:result.notice?'warning':result.vulnerableCount?'warning':'success',title:'Dependency scan completed',details:result.lockfile?`Checked ${result.dependencyCount} npm lockfile entries. ${result.vulnerableCount} vulnerable, ${result.inconclusiveCount} inconclusive.${result.notice?` ${result.notice}`:''}`:result.notice??'No npm lockfile found.',repository:connectedRepository.name});
    res.json({result});
  } catch(error) {
    const message=(error as Error).message||'Dependency scan failed.';
    activityLog.record({category:'dependencies',status:'error',title:'Dependency scan failed',details:message,repository:connectedRepository.name});
    res.status(422).json({error:message});
  }
});

app.listen(port, '127.0.0.1', () => console.log(`ProofLayer API listening at http://127.0.0.1:${port}`));
