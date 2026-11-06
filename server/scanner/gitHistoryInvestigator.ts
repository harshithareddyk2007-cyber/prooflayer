import { execFile } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import path from 'node:path';
import { analyzeSqlSource, type SqlInjectionFinding } from './sqlInjectionScanner.js';

const execFileAsync = promisify(execFile);
const MAX_HISTORY_COMMITS = 250;
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_HISTORY_BYTES = 64 * 1024 * 1024;
const MAX_DIFF_BYTES = 4 * 1024 * 1024;
const MAX_EVIDENCE_DIFF_CHARS = 12_000;
const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

export type GitHistoryInvestigation = {
  status: 'determined' | 'undetermined';
  findingId: string;
  reason: string;
  historyCommitsExamined: number;
  commit?: {
    hash: string;
    message: string;
    author: string;
    date: string;
    file: string;
  };
  evidence?: {
    parentHash: string | null;
    findingLine: number;
    findingEndLine: number;
    before: string;
    after: string;
    diff: string;
    diffTruncated: boolean;
  };
};

type Commit = { hash: string; parents: string[]; author: string; date: string; message: string };
type HistoryLog = { commits: Commit[]; includesRename: boolean };
type LineRange = { start: number; count: number };
type DiffHunk = { oldLines: LineRange; newLines: LineRange; header: string };
type RevisionCheck = {
  commit: Commit;
  source: string;
  findings: SqlInjectionFinding[];
  parentSources: Array<{ hash: string; source: string; findings: SqlInjectionFinding[] }>;
  diffs: Array<{ hash: string; text: string; hunks: DiffHunk[] }>;
};

function undetermined(finding: SqlInjectionFinding, reason: string, historyCommitsExamined = 0): GitHistoryInvestigation {
  return { status: 'undetermined', findingId: finding.id, reason, historyCommitsExamined };
}

async function git(repositoryPath: string, args: string[], maxBuffer = 4 * 1024 * 1024): Promise<string> {
  const { stdout } = await execFileAsync('git', ['-C', repositoryPath, ...args], {
    windowsHide: true,
    timeout: 15_000,
    maxBuffer,
    encoding: 'utf8',
  });
  return stdout;
}

function parseHistoryLog(output: string): HistoryLog {
  const commits: Commit[] = [];
  let includesRename = false;
  for (const line of output.split(/\r?\n/)) {
    if (!line) continue;
    if (/^R\d*\t/.test(line)) { includesRename = true; continue; }
    const [hash, parents = '', author = '', date = '', ...messageParts] = line.split('\x1f');
    if (!/^[0-9a-f]{40,64}$/i.test(hash ?? '')) continue;
    commits.push({ hash, parents: parents ? parents.split(' ').filter(Boolean) : [], author, date, message: messageParts.join('\x1f') });
  }
  return { commits, includesRename };
}

function parseDiffHunks(diff: string): DiffHunk[] {
  return diff.split(/\r?\n/).flatMap(line => {
    const match = HUNK_HEADER.exec(line);
    if (!match) return [];
    return [{
      oldLines: { start: Number(match[1]), count: match[2] === undefined ? 1 : Number(match[2]) },
      newLines: { start: Number(match[3]), count: match[4] === undefined ? 1 : Number(match[4]) },
      header: line,
    }];
  });
}

function touches(range: LineRange, start: number, end: number): boolean {
  if (range.count === 0) return false;
  return start <= range.start + range.count - 1 && end >= range.start;
}

function touchesFinding(hunks: DiffHunk[], finding: SqlInjectionFinding, side: 'oldLines' | 'newLines'): boolean {
  const start = Math.min(finding.line, finding.sinkLine, finding.constructionEndLine);
  const end = Math.max(finding.line, finding.sinkLine, finding.constructionEndLine);
  return hunks.some(hunk => touches(hunk[side], start, end));
}

function matchingFindings(findings: SqlInjectionFinding[], target: SqlInjectionFinding): SqlInjectionFinding[] {
  return findings.filter(finding => finding.historySignature === target.historySignature);
}

function snippet(source: string, line: number): string {
  const lines = source.split(/\r?\n/);
  const center = Math.max(1, Math.min(lines.length, line));
  const from = Math.max(1, center - 3);
  const to = Math.min(lines.length, center + 3);
  return lines.slice(from - 1, to).map((code, index) => `${from + index}: ${code}`).join('\n');
}

function relevantDiff(diff: string, finding: SqlInjectionFinding): { text: string; truncated: boolean } {
  const lines = diff.split(/\r?\n/);
  const selected: string[] = [];
  let hunkLines: string[] = [];
  let includeHunk = false;
  for (const line of lines) {
    const header = HUNK_HEADER.exec(line);
    if (header) {
      if (includeHunk) selected.push(...hunkLines);
      const hunk: DiffHunk = {
        oldLines: { start: Number(header[1]), count: header[2] === undefined ? 1 : Number(header[2]) },
        newLines: { start: Number(header[3]), count: header[4] === undefined ? 1 : Number(header[4]) },
        header: line,
      };
      includeHunk = touchesFinding([hunk], finding, 'newLines');
      hunkLines = [line];
    } else if (line.startsWith('diff --git ') || line.startsWith('index ') || line.startsWith('--- ') || line.startsWith('+++ ')) {
      if (includeHunk) selected.push(...hunkLines);
      hunkLines = [];
      includeHunk = false;
      selected.push(line);
    } else if (hunkLines.length) hunkLines.push(line);
  }
  if (includeHunk) selected.push(...hunkLines);
  const text = selected.join('\n').trim();
  return { text: text.slice(0, MAX_EVIDENCE_DIFF_CHARS), truncated: text.length > MAX_EVIDENCE_DIFF_CHARS };
}

function introductionCandidate(check: RevisionCheck, target: SqlInjectionFinding): {
  finding: SqlInjectionFinding;
  parentHash: string | null;
  beforeSource: string;
  beforeLine: number;
  diff: string;
} | null {
  const matches = matchingFindings(check.findings, target);
  if (matches.length !== 1) return null;
  const introduced = matches[0];
  const changedParentIndex = check.diffs.findIndex(diff => touchesFinding(diff.hunks, introduced, 'newLines'));
  if (changedParentIndex < 0) return null;

  for (const parent of check.parentSources) {
    const parentDiff = check.diffs.find(diff => diff.hash === parent.hash);
    if (!parentDiff) continue;
    const priorMatches = matchingFindings(parent.findings, target);
    if (priorMatches.some(prior => touchesFinding(parentDiff.hunks, prior, 'oldLines'))) return null;
  }

  const selectedDiff = check.diffs[changedParentIndex];
  const selectedParent = check.parentSources.find(parent => parent.hash === selectedDiff.hash);
  const changedHunk = selectedDiff.hunks.find(hunk => touches(hunk.newLines, introduced.line, Math.max(introduced.constructionEndLine, introduced.sinkLine)));
  return {
    finding: introduced,
    parentHash: selectedParent?.hash ?? null,
    beforeSource: selectedParent?.source ?? '',
    beforeLine: changedHunk ? Math.max(1, changedHunk.oldLines.start) : introduced.line,
    diff: selectedDiff.text,
  };
}

async function getFileAtRevision(repositoryPath: string, revision: string, file: string): Promise<string> {
  try { return await git(repositoryPath, ['show', `${revision}:${file}`], MAX_SOURCE_BYTES + 1); }
  catch (error) {
    // A newly added or renamed file has no blob at this path in the parent tree.
    const e = error as NodeJS.ErrnoException & { stderr?: string };
    if (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') throw new Error('A historical source version exceeds the scanner file-size limit.');
    const stderr = e.stderr?.toLowerCase() ?? '';
    if (stderr.includes('does not exist in') || stderr.includes('exists on disk, but not in')) return '';
    throw new Error('A historical source version could not be read.');
  }
}

async function getRevisionCheck(repositoryPath: string, file: string, commit: Commit): Promise<RevisionCheck> {
  const source = await getFileAtRevision(repositoryPath, commit.hash, file);
  if (Buffer.byteLength(source, 'utf8') > MAX_SOURCE_BYTES) throw new Error('A historical source version exceeds the scanner file-size limit.');
  const findings = analyzeSqlSource(source, file);
  const parents = commit.parents.slice(0, 2);
  const parentResults = await Promise.all(parents.map(async hash => {
    const [parentSource, diff] = await Promise.all([
      getFileAtRevision(repositoryPath, hash, file),
      git(repositoryPath, ['diff', '--no-ext-diff', '--find-renames', '--unified=3', hash, commit.hash, '--', file], MAX_DIFF_BYTES),
    ]);
    if (Buffer.byteLength(parentSource, 'utf8') > MAX_SOURCE_BYTES) throw new Error('A historical source version exceeds the scanner file-size limit.');
    return {
      parent: { hash, source: parentSource, findings: analyzeSqlSource(parentSource, file) },
      diff: { hash, text: diff, hunks: parseDiffHunks(diff) },
    };
  }));
  if (parentResults.some(result => /^rename (?:from|to) /m.test(result.diff.text))) {
    throw new Error('The affected file was renamed. Historical paths cannot be mapped completely.');
  }
  if (commit.parents.length > 2) throw new Error('A merge commit has more than two parents, so the comparison is incomplete.');
  return {
    commit,
    source,
    findings,
    parentSources: parentResults.map(result => result.parent),
    diffs: parentResults.map(result => result.diff),
  };
}

/**
 * Trace one scanner finding through the file's reachable Git revisions. Each potential
 * introduction is checked against a real parent-to-commit diff and detector output on
 * both source versions. Anything that makes that comparison incomplete is reported as
 * undetermined instead of guessing.
 */
export async function investigateGitHistory(repositoryPath: string, finding: SqlInjectionFinding): Promise<GitHistoryInvestigation> {
  const normalizedFile = finding.file.replaceAll('\\', '/');
  const fullPath = path.resolve(repositoryPath, normalizedFile);
  const relativePath = path.relative(repositoryPath, fullPath);
  if (relativePath === '..' || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) {
    return undetermined(finding, 'The finding path resolves outside the connected repository.');
  }

  try {
    const info = await lstat(fullPath);
    if (!info.isFile() || info.size > MAX_SOURCE_BYTES) return undetermined(finding, 'The affected file is no longer a readable source file within the scanner size limit.');
    const currentSource = await readFile(fullPath, 'utf8');
    const currentMatches = analyzeSqlSource(currentSource, normalizedFile);
    if (!currentMatches.some(candidate => candidate.id === finding.id && candidate.historySignature === finding.historySignature)) {
      return undetermined(finding, 'The finding no longer matches the current file contents. Run a new scan before investigating its history.');
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    const reason = code === 'EACCES' || code === 'EPERM' ? 'Permission was denied while reading the affected file.' : 'The affected file could not be read; run a new scan before investigating its history.';
    return undetermined(finding, reason);
  }

  let history: Commit[];
  try {
    const output = await git(repositoryPath, [
      'log', '--follow', '--name-status', '--format=%H%x1f%P%x1f%an%x1f%cI%x1f%s', '--', normalizedFile,
    ], 8 * 1024 * 1024);
    const parsed = parseHistoryLog(output);
    if (parsed.includesRename) return undetermined(finding, 'The affected file was renamed in its Git history; historical path mapping is incomplete.');
    history = parsed.commits.reverse();
  } catch {
    return undetermined(finding, 'Git could not read the affected file history.');
  }
  if (!history.length) return undetermined(finding, 'No reachable Git history exists for this file; it may be untracked or newly created.');
  if (history.length > MAX_HISTORY_COMMITS) {
    return undetermined(finding, `The file has more than ${MAX_HISTORY_COMMITS} relevant commits. The bounded history comparison is incomplete.`);
  }

  const headSource = await getFileAtRevision(repositoryPath, 'HEAD', normalizedFile).catch(() => '');
  const headMatches = matchingFindings(analyzeSqlSource(headSource, normalizedFile), finding);
  const latestCommit = history.at(-1);
  if (headMatches.length !== 1 || !latestCommit) {
    return undetermined(finding, 'The matching unsafe SQL construction is ambiguous in the current file or its latest history is unavailable.');
  }

  let examined = 0;
  let totalBytes = 0;
  let activeIntroduction: { check: RevisionCheck; evidence: NonNullable<ReturnType<typeof introductionCandidate>> } | null = null;
  try {
    for (let offset = 0; offset < history.length; offset += 4) {
      const checks = await Promise.all(history.slice(offset, offset + 4).map(commit => getRevisionCheck(repositoryPath, normalizedFile, commit)));
      examined += checks.length;
      for (const check of checks) {
        totalBytes += Buffer.byteLength(check.source, 'utf8');
        for (const parent of check.parentSources) totalBytes += Buffer.byteLength(parent.source, 'utf8');
        if (totalBytes > MAX_TOTAL_HISTORY_BYTES) {
          return undetermined(finding, `The file history exceeds the ${MAX_TOTAL_HISTORY_BYTES / 1024 / 1024} MB comparison budget.`, examined);
        }

        const matches = matchingFindings(check.findings, finding);
        if (matches.length > 1) return undetermined(finding, 'Multiple identical SQL construction patterns occur in a historical revision, so the current finding cannot be traced uniquely.', examined);
        if (!matches.length) {
          activeIntroduction = null;
          continue;
        }

        if (!activeIntroduction) {
          const evidence = introductionCandidate(check, finding);
          if (!evidence) {
            return undetermined(finding, 'The pattern is already present in the earliest available version of this file, or its introducing change cannot be isolated in the available diffs.', examined);
          }
          activeIntroduction = { check, evidence };
        }
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    const reason = message.includes('exceeds the scanner file-size limit')
      ? message
      : 'A historical file version or Git diff could not be read completely. The introducing commit could not be determined.';
    return undetermined(finding, reason, examined);
  }

  if (!activeIntroduction || !activeIntroduction.check.commit.hash) {
    return undetermined(finding, 'No complete parent-to-commit comparison established when this unsafe SQL construction first appeared.', examined);
  }

  const { check, evidence } = activeIntroduction;
  const diffEvidence = relevantDiff(evidence.diff, evidence.finding);
  return {
    status: 'determined',
    findingId: finding.id,
    reason: `The detector's matching ${finding.pattern.toLowerCase()} construction at ${finding.sink}() first appears in this commit's changed lines. ProofLayer analyzed the source before and after the commit and found no matching unsafe construction at the changed location in the parent revision. This identifies when the pattern entered the available Git history; it does not establish intent or fault.`,
    historyCommitsExamined: examined,
    commit: {
      hash: check.commit.hash,
      message: check.commit.message,
      author: check.commit.author,
      date: check.commit.date,
      file: normalizedFile,
    },
    evidence: {
      parentHash: evidence.parentHash,
      findingLine: evidence.finding.line,
      findingEndLine: Math.max(evidence.finding.constructionEndLine, evidence.finding.sinkLine),
      before: !evidence.parentHash || !evidence.beforeSource.trim()
        ? '(Unsafe construction absent in the parent revision.)'
        : snippet(evidence.beforeSource, evidence.beforeLine),
      after: snippet(check.source, evidence.finding.line),
      diff: diffEvidence.text || evidence.diff.slice(0, MAX_EVIDENCE_DIFF_CHARS),
      diffTruncated: diffEvidence.truncated || evidence.diff.length > MAX_EVIDENCE_DIFF_CHARS,
    },
  };
}
