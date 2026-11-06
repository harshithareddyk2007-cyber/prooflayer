import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import ts from 'typescript';

const execFileAsync = promisify(execFile);
const excludedDirectories = new Set([
  '.git', 'node_modules', 'build', 'dist', 'out', 'coverage', 'target',
  '.next', '.nuxt', '.output', '.turbo', '.cache',
]);
const SQL_KEYWORD = /\b(select|insert|update|delete|replace|merge|with|call|exec|truncate)\b/i;
const SQL_SINKS = new Set([
  'query', 'execute', 'exec', 'raw', 'prepare', 'queryraw', 'executeraw',
  'queryrawunsafe', 'executerawunsafe', '$queryraw', '$executeraw',
  '$queryrawunsafe', '$executerawunsafe',
]);
const SQLI_RULES = {
  'Dynamic template literal': {
    id: 'PL-SQLI-001', title: 'SQL built with dynamic template interpolation', severity: 'High',
  },
  'String concatenation': {
    id: 'PL-SQLI-002', title: 'SQL built with string concatenation', severity: 'High',
  },
} as const;
const MAX_FILES = 50_000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

export type SqlInjectionFinding = {
  id: string;
  title: string;
  severity: (typeof SQLI_RULES)[keyof typeof SQLI_RULES]['severity'];
  ruleId: string;
  file: string;
  line: number;
  column: number;
  sinkLine: number;
  sink: string;
  pattern: 'Dynamic template literal' | 'String concatenation';
  message: string;
  code: string;
  codeContext: Array<{ line: number; code: string }>;
  constructionEndLine: number;
  historySignature: string;
};

export type SqlInjectionScanResult = {
  repositoryPath: string;
  scannedFiles: number;
  scannedFilePaths: string[];
  skippedFiles: Array<{ file: string; reason: string }>;
  findings: SqlInjectionFinding[];
  startedAt: string;
  durationMs: number;
};

export class SqlInjectionScanError extends Error {
  constructor(message: string, readonly status = 422) { super(message); }
}

type ConstructedSql = {
  unsafe: boolean;
  pattern: SqlInjectionFinding['pattern'] | null;
  position: number;
  endPosition: number;
  sqlShape: string;
};

function isSkippedPath(relativePath: string): boolean {
  const parts = relativePath.replaceAll('\\', '/').split('/');
  if (!relativePath.toLowerCase().endsWith('.ts') && !relativePath.toLowerCase().endsWith('.tsx')) return true;
  return parts.some(part => excludedDirectories.has(part.toLowerCase()));
}

function sinkName(expression: ts.Expression): string | null {
  if (ts.isIdentifier(expression)) return SQL_SINKS.has(expression.text.toLowerCase()) ? expression.text : null;
  if (ts.isPropertyAccessExpression(expression)) return SQL_SINKS.has(expression.name.text.toLowerCase()) ? expression.name.text : null;
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression && ts.isStringLiteral(expression.argumentExpression)) {
    const name = expression.argumentExpression.text;
    return SQL_SINKS.has(name.toLowerCase()) ? name : null;
  }
  return null;
}

function unwrap(expression: ts.Expression): ts.Expression {
  while (
    ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) ||
    ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression) ||
    ts.isSatisfiesExpression(expression)
  ) expression = expression.expression;
  return expression;
}

export function analyzeSqlSource(source: string, relativeFile: string): SqlInjectionFinding[] {
  const kind = relativeFile.toLowerCase().endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(relativeFile, source, ts.ScriptTarget.Latest, true, kind);
  const declarations = new Map<string, ts.Expression>();

  function collectDeclarations(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      declarations.set(node.name.text, node.initializer);
    }
    ts.forEachChild(node, collectDeclarations);
  }
  collectDeclarations(sourceFile);

  function inspect(expression: ts.Expression, visited = new Set<string>()): ConstructedSql {
    expression = unwrap(expression);
    const key = `${expression.pos}:${expression.end}`;
    if (visited.has(key)) return { unsafe: false, pattern: null, position: expression.getStart(sourceFile), endPosition: expression.end, sqlShape: '' };
    visited.add(key);

    if (ts.isTemplateExpression(expression)) {
      const staticText = expression.head.text + expression.templateSpans.map(span => span.literal.text).join('');
      return {
        unsafe: expression.templateSpans.length > 0 && SQL_KEYWORD.test(staticText),
        pattern: 'Dynamic template literal', position: expression.getStart(sourceFile), endPosition: expression.end, sqlShape: staticText,
      };
    }
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const literalText = staticSqlText(expression, declarations, new Set());
      const hasDynamicPart = hasDynamicValue(expression, declarations, new Set());
      return {
        unsafe: hasDynamicPart && SQL_KEYWORD.test(literalText),
        pattern: 'String concatenation', position: expression.getStart(sourceFile), endPosition: expression.end, sqlShape: literalText,
      };
    }
    if (ts.isIdentifier(expression)) {
      const initializer = declarations.get(expression.text);
      if (initializer) return inspect(initializer, visited);
    }
    return { unsafe: false, pattern: null, position: expression.getStart(sourceFile), endPosition: expression.end, sqlShape: '' };
  }

  function staticSqlText(expression: ts.Expression, vars: Map<string, ts.Expression>, seen: Set<string>): string {
    expression = unwrap(expression);
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) return expression.text;
    if (ts.isTemplateExpression(expression)) return expression.head.text + expression.templateSpans.map(span => span.literal.text).join('');
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return staticSqlText(expression.left, vars, seen) + staticSqlText(expression.right, vars, seen);
    }
    if (ts.isIdentifier(expression) && !seen.has(expression.text)) {
      const initializer = vars.get(expression.text);
      if (initializer) { seen.add(expression.text); return staticSqlText(initializer, vars, seen); }
    }
    return '';
  }

  function hasDynamicValue(expression: ts.Expression, vars: Map<string, ts.Expression>, seen: Set<string>): boolean {
    expression = unwrap(expression);
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) return false;
    if (ts.isTemplateExpression(expression)) return expression.templateSpans.length > 0;
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return hasDynamicValue(expression.left, vars, seen) || hasDynamicValue(expression.right, vars, seen);
    }
    if (ts.isIdentifier(expression) && !seen.has(expression.text)) {
      const initializer = vars.get(expression.text);
      if (initializer) { seen.add(expression.text); return hasDynamicValue(initializer, vars, seen); }
    }
    return true;
  }

  const findings: SqlInjectionFinding[] = [];
  const lines = source.split(/\r?\n/);
  function report(argument: ts.Expression, sink: string, sinkPosition: number): void {
    const result = inspect(argument);
    if (!result.unsafe || !result.pattern) return;
    const location = sourceFile.getLineAndCharacterOfPosition(result.position);
    const sinkLocation = sourceFile.getLineAndCharacterOfPosition(sinkPosition);
    const line = location.line + 1;
    const sinkLine = sinkLocation.line + 1;
    const endLocation = sourceFile.getLineAndCharacterOfPosition(Math.max(result.position, result.endPosition - 1));
    const rule = SQLI_RULES[result.pattern];
    const contextStart = Math.max(0, location.line - 3);
    const contextEnd = Math.min(lines.length, location.line + 4);
    findings.push({
      id: `${relativeFile}:${line}:${sinkLine}:${rule.id}`,
      title: rule.title, severity: rule.severity, ruleId: rule.id,
      file: relativeFile, line, column: location.character + 1, sinkLine, sink,
      pattern: result.pattern,
      constructionEndLine: endLocation.line + 1,
      historySignature: createHash('sha256').update([
        result.pattern,
        sink.toLowerCase(),
        result.sqlShape.replace(/\s+/g, ' ').trim().toLowerCase(),
      ].join('\0')).digest('hex'),
      message: `SQL-like text is dynamically constructed and passed to ${sink}(). Use a parameterized query for values.`,
      code: (lines[location.line] ?? '').trim().slice(0, 300),
      codeContext: lines.slice(contextStart, contextEnd).map((code, index) => ({ line: contextStart + index + 1, code })),
    });
  }

  function visit(node: ts.Node): void {
    if (ts.isCallExpression(node)) {
      const method = sinkName(node.expression);
      if (method && node.arguments.length > 0) report(node.arguments[0], method, node.getStart(sourceFile));
    } else if (ts.isTaggedTemplateExpression(node)) {
      const method = sinkName(node.tag);
      if (method) report(node.template, method, node.getStart(sourceFile));
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return findings;
}

export async function scanSqlInjection(repositoryPath: string): Promise<SqlInjectionScanResult> {
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  let files: string[];
  try {
    const { stdout } = await execFileAsync('git', [
      '-C', repositoryPath, 'ls-files', '--cached', '--others', '--exclude-standard', '-z',
    ], { windowsHide: true, timeout: 15_000, maxBuffer: 32 * 1024 * 1024 });
    files = stdout.split('\0').filter(Boolean).filter(file => !isSkippedPath(file));
  } catch (error) {
    const e = error as NodeJS.ErrnoException & { stderr?: string; code?: string };
    if (e.code === 'ENOENT') throw new SqlInjectionScanError('Git is not available while listing repository files.', 503);
    if (e.code === 'EACCES' || e.code === 'EPERM') throw new SqlInjectionScanError('Permission denied while listing repository files.', 403);
    throw new SqlInjectionScanError('Could not list non-ignored source files with Git. Check repository access and Git ignore configuration.');
  }
  if (files.length > MAX_FILES) throw new SqlInjectionScanError(`This repository has more than ${MAX_FILES.toLocaleString()} eligible TypeScript files. Narrow the repository before scanning.`, 413);

  const findings: SqlInjectionFinding[] = [];
  const skippedFiles: SqlInjectionScanResult['skippedFiles'] = [];
  const scannedFilePaths: string[] = [];
  let scannedFiles = 0;
  const concurrency = 16;
  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);
    const results = await Promise.all(batch.map(async relativeFile => {
      const fullPath = path.resolve(repositoryPath, relativeFile);
      const relative = path.relative(repositoryPath, fullPath);
      if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return { relativeFile, error: 'Resolved path is outside the repository.' };
      try {
        const info = await lstat(fullPath);
        if (!info.isFile()) return { relativeFile, error: 'Not a regular file.' };
        if (info.size > MAX_FILE_BYTES) return { relativeFile, error: `File exceeds the ${MAX_FILE_BYTES / 1024 / 1024} MB scan limit.` };
        const source = await readFile(fullPath, 'utf8');
        return { relativeFile, source };
      } catch (error) {
        const e = error as NodeJS.ErrnoException;
        return { relativeFile, error: e.code === 'EACCES' || e.code === 'EPERM' ? 'Permission denied.' : 'File could not be read.' };
      }
    }));
    for (const result of results) {
      if (!result.source) {
        skippedFiles.push({ file: result.relativeFile, reason: result.error ?? 'File could not be read.' });
        continue;
      }
      scannedFiles++;
      try { findings.push(...analyzeSqlSource(result.source, result.relativeFile)); scannedFilePaths.push(result.relativeFile.replaceAll('\\', '/')); }
      catch { skippedFiles.push({ file: result.relativeFile, reason: 'TypeScript source could not be analyzed (syntax or parser limit).' }); scannedFiles--; }
    }
  }
  return { repositoryPath, scannedFiles, scannedFilePaths, skippedFiles, findings, startedAt, durationMs: Date.now() - started };
}
