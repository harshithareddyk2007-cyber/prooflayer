import { lstat, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import ts from 'typescript';
import { analyzeSqlSource, type SqlInjectionFinding } from './sqlInjectionScanner.js';
import type { GitHistoryInvestigation } from './gitHistoryInvestigator.js';

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

export type SqlInjectionPatchSuggestion = {
  status: 'suggested' | 'unavailable';
  findingId: string;
  file: string;
  line: number;
  reason: string;
  diff?: string;
  applyPlan?: SqlPatchApplyPlan;
};

export type SqlPatchApplyPlan = {
  file: string;
  sourceHash: string;
  originalSource: string;
  patchedSource: string;
  replaceStart: number;
  replaceEnd: number;
  expectedText: string;
  replacement: string;
  diff: string;
};

type SqlParts = { segments: string[]; values: string[] };

function unavailable(finding: SqlInjectionFinding, reason: string): SqlInjectionPatchSuggestion {
  return { status: 'unavailable', findingId: finding.id, file: finding.file, line: finding.line, reason };
}

function unwrap(expression: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression) || ts.isSatisfiesExpression(expression)) expression = expression.expression;
  return expression;
}

function splitSqlExpression(expression: ts.Expression, source: string, parts: SqlParts): boolean {
  expression = unwrap(expression);
  if (ts.isTemplateExpression(expression)) {
    if (!parts.segments.length) parts.segments.push(expression.head.text);
    else parts.segments[parts.segments.length - 1] += expression.head.text;
    for (const span of expression.templateSpans) {
      parts.values.push(source.slice(span.expression.getStart(), span.expression.end));
      parts.segments.push(span.literal.text);
    }
    return parts.values.length > 0;
  }
  if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return splitSqlExpression(expression.left, source, parts) && splitSqlExpression(expression.right, source, parts);
  }
  if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
    if (!parts.segments.length || parts.segments.length === parts.values.length) parts.segments.push(expression.text);
    else parts.segments[parts.segments.length - 1] += expression.text;
    return true;
  }
  if (ts.isBinaryExpression(expression)) return false;
  if (!parts.segments.length) parts.segments.push('');
  parts.values.push(source.slice(expression.getStart(), expression.end));
  parts.segments.push('');
  return true;
}

function isSqlValuePosition(parts: SqlParts): boolean {
  if (parts.segments.some(segment => segment.includes('\\') || /\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$|\$\d+/.test(segment))) return false;
  let sqlBefore = '';
  let state: 'normal' | 'single' | 'double' | 'line-comment' | 'block-comment' = 'normal';
  for (let index = 0; index < parts.values.length; index++) {
    const segment = parts.segments[index] ?? '';
    for (let cursor = 0; cursor < segment.length; cursor++) {
      const char = segment[cursor];
      const next = segment[cursor + 1];
      if (state === 'line-comment') { if (char === '\n') state = 'normal'; continue; }
      if (state === 'block-comment') { if (char === '*' && next === '/') { state = 'normal'; cursor++; } continue; }
      if (state === 'single') { if (char === "'" && next === "'") cursor++; else if (char === "'") state = 'normal'; continue; }
      if (state === 'double') { if (char === '"' && next === '"') cursor++; else if (char === '"') state = 'normal'; continue; }
      if (char === '-' && next === '-') { state = 'line-comment'; cursor++; continue; }
      if (char === '/' && next === '*') { state = 'block-comment'; cursor++; continue; }
      if (char === "'") state = 'single';
      else if (char === '"') state = 'double';
    }
    if (state !== 'normal') return false;
    const prefix = `${sqlBefore}${segment}`;
    const trimmed = prefix.trimEnd();
    const valueContext = /(?:=|<>|!=|<=|>=|<|>|\bLIKE|\bILIKE|\bLIMIT|\bOFFSET)\s*$/i.test(trimmed)
      || /\bVALUES\s*\(\s*(?:\$\d+\s*,\s*)*$/i.test(trimmed);
    if (!valueContext) return false;
    sqlBefore = `${prefix}$${index + 1}`;
  }
  const finalSegment = parts.segments.at(-1) ?? '';
  for (let cursor = 0; cursor < finalSegment.length; cursor++) {
    const char = finalSegment[cursor];
    const next = finalSegment[cursor + 1];
    if (state === 'line-comment') { if (char === '\n') state = 'normal'; continue; }
    if (state === 'block-comment') { if (char === '*' && next === '/') { state = 'normal'; cursor++; } continue; }
    if (state === 'single') { if (char === "'" && next === "'") cursor++; else if (char === "'") state = 'normal'; continue; }
    if (state === 'double') { if (char === '"' && next === '"') cursor++; else if (char === '"') state = 'normal'; continue; }
    if (char === '-' && next === '-') { state = 'line-comment'; cursor++; continue; }
    if (char === '/' && next === '*') { state = 'block-comment'; cursor++; continue; }
    if (char === "'") state = 'single';
    else if (char === '"') state = 'double';
  }
  return state === 'normal';
}

function pgConstructors(sourceFile: ts.SourceFile): { named: Set<string>; namespaces: Set<string> } {
  const named = new Set<string>();
  const namespaces = new Set<string>();
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || statement.moduleSpecifier.text !== 'pg') continue;
    const clause = statement.importClause;
    if (!clause || clause.isTypeOnly) continue;
    if (clause.name) namespaces.add(clause.name.text);
    if (!clause.namedBindings) continue;
    if (ts.isNamespaceImport(clause.namedBindings)) namespaces.add(clause.namedBindings.name.text);
    else for (const element of clause.namedBindings.elements) {
      const importedName = element.propertyName?.text ?? element.name.text;
      if (!element.isTypeOnly && (importedName === 'Pool' || importedName === 'Client')) named.add(element.name.text);
    }
  }
  return { named, namespaces };
}

function isPgReceiver(sourceFile: ts.SourceFile, call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression) || call.expression.name.text !== 'query' || !ts.isIdentifier(call.expression.expression)) return false;
  const receiverName = call.expression.expression.text;
  const imported = pgConstructors(sourceFile);
  const declarations: ts.VariableDeclaration[] = [];
  const otherBindings: ts.Node[] = [];
  function collect(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === receiverName) declarations.push(node);
    else if ((node.kind === ts.SyntaxKind.Parameter && ts.isIdentifier((node as ts.ParameterDeclaration).name) && ((node as ts.ParameterDeclaration).name as ts.Identifier).text === receiverName)
      || (ts.isFunctionDeclaration(node) && node.name?.text === receiverName)
      || (ts.isClassDeclaration(node) && node.name?.text === receiverName)) otherBindings.push(node);
    ts.forEachChild(node, collect);
  }
  collect(sourceFile);
  if (declarations.length !== 1 || otherBindings.length) return false;
  const declaration = declarations[0];
  if (!declaration.initializer) return false;
  const declarationList = declaration.parent;
  if (!ts.isVariableDeclarationList(declarationList) || !(declarationList.flags & ts.NodeFlags.Const) || !ts.isVariableStatement(declarationList.parent)) return false;
  const initializer = unwrap(declaration.initializer);
  if (!ts.isNewExpression(initializer)) return false;
  if (ts.isIdentifier(initializer.expression)) return imported.named.has(initializer.expression.text);
  return ts.isPropertyAccessExpression(initializer.expression)
    && ts.isIdentifier(initializer.expression.expression)
    && imported.namespaces.has(initializer.expression.expression.text)
    && (initializer.expression.name.text === 'Pool' || initializer.expression.name.text === 'Client');
}

function findDirectQuery(sourceFile: ts.SourceFile, finding: SqlInjectionFinding): ts.CallExpression | null {
  const matching: ts.CallExpression[] = [];
  function visit(node: ts.Node): void {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
      && node.expression.name.text.toLowerCase() === finding.sink.toLowerCase() && node.arguments.length > 0) {
      const sourceLine = sourceFile.getLineAndCharacterOfPosition(node.arguments[0].getStart(sourceFile)).line + 1;
      const sinkLine = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
      if (sourceLine === finding.line && sinkLine === finding.sinkLine) matching.push(node);
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return matching.length === 1 ? matching[0] : null;
}

export function createUnifiedDiff(file: string, before: string, after: string): string {
  const lines = (value: string) => {
    const normalized = value.replace(/\r\n/g, '\n');
    const withoutFinalNewline = normalized.endsWith('\n') ? normalized.slice(0, -1) : normalized;
    return withoutFinalNewline ? withoutFinalNewline.split('\n') : [];
  };
  const oldLines = lines(before);
  const newLines = lines(after);
  let prefix = 0;
  while (prefix < oldLines.length && prefix < newLines.length && oldLines[prefix] === newLines[prefix]) prefix++;
  let suffix = 0;
  while (suffix < oldLines.length - prefix && suffix < newLines.length - prefix && oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]) suffix++;
  if (prefix === oldLines.length && prefix === newLines.length) return '';
  const contextBefore = Math.min(3, prefix);
  const contextAfter = Math.min(3, suffix);
  const oldChangedEnd = oldLines.length - suffix;
  const newChangedEnd = newLines.length - suffix;
  const oldChunk = oldLines.slice(prefix - contextBefore, oldChangedEnd + contextAfter);
  const newChunk = newLines.slice(prefix - contextBefore, newChangedEnd + contextAfter);
  const oldStart = prefix - contextBefore === 0 ? (oldChunk.length === 0 ? 0 : 1) : prefix - contextBefore + 1;
  const newStart = prefix - contextBefore === 0 ? (newChunk.length === 0 ? 0 : 1) : prefix - contextBefore + 1;
  const hunk = [
    `@@ -${oldStart},${oldChunk.length} +${newStart},${newChunk.length} @@`,
    ...oldLines.slice(prefix - contextBefore, prefix).map(line => ` ${line}`),
    ...oldLines.slice(prefix, oldChangedEnd).map(line => `-${line}`),
    ...newLines.slice(prefix, newChangedEnd).map(line => `+${line}`),
    ...oldLines.slice(oldChangedEnd, oldChangedEnd + contextAfter).map(line => ` ${line}`),
  ];
  return [`--- a/${file}`, `+++ b/${file}`, ...hunk].join('\n');
}

function parameterizedSql(parts: SqlParts): string | null {
  if (parts.values.length === 0 || parts.segments.length !== parts.values.length + 1 || !isSqlValuePosition(parts)) return null;
  return parts.segments.map((segment, index) => segment + (index < parts.values.length ? `$${index + 1}` : '')).join('');
}

export async function suggestSqlInjectionPatch(repositoryPath: string, finding: SqlInjectionFinding, history?: GitHistoryInvestigation): Promise<SqlInjectionPatchSuggestion> {
  const file = finding.file.replaceAll('\\', '/');
  const fullPath = path.resolve(repositoryPath, file);
  const relativePath = path.relative(repositoryPath, fullPath);
  if (relativePath === '..' || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) return unavailable(finding, 'The finding path resolves outside the connected repository.');
  try {
    const info = await lstat(fullPath);
    if (!info.isFile() || info.size > MAX_SOURCE_BYTES) return unavailable(finding, 'The affected file is unavailable or exceeds the 2 MB source limit.');
    const source = await readFile(fullPath, 'utf8');
    const currentFindings = analyzeSqlSource(source, file).filter(item => item.id === finding.id && item.historySignature === finding.historySignature);
    if (currentFindings.length !== 1) return unavailable(finding, 'The finding no longer matches exactly one construction in the current source. Run a fresh scan before requesting a patch.');
    const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.toLowerCase().endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const call = findDirectQuery(sourceFile, finding);
    if (!call || !call.arguments[0]) return unavailable(finding, 'The unsafe SQL expression is not a unique, direct query argument. Indirect SQL variables are not rewritten automatically.');
    if (call.arguments.length !== 1) return unavailable(finding, 'This query call already has additional arguments. Rewriting it automatically could change the existing parameter or callback behavior.');
    if (ts.isSpreadElement(call.arguments[0])) return unavailable(finding, 'Spread query arguments are not rewritten automatically because their runtime values cannot be verified.');
    if (finding.sink.toLowerCase() !== 'query' || !isPgReceiver(sourceFile, call)) return unavailable(finding, 'A safe parameter syntax could not be confirmed from this call. Automatic suggestions are limited to a directly imported pg Pool or Client query call.');
    const parts: SqlParts = { segments: [], values: [] };
    if (!splitSqlExpression(call.arguments[0], source, parts) || parts.values.length === 0) return unavailable(finding, 'The query expression contains unsupported syntax, so its dynamic values cannot be separated safely.');
    const sql = parameterizedSql(parts);
    if (!sql) return unavailable(finding, 'The dynamic expression is not in a recognized SQL value position. Parameters cannot safely replace table names, column names, or SQL syntax.');
    const values = `[${parts.values.join(', ')}]`;
    const originalArgument = source.slice(call.arguments[0].getStart(sourceFile), call.arguments[0].end);
    const replacement = `${JSON.stringify(sql)}, ${values}`;
    const before = source.slice(0, call.arguments[0].getStart(sourceFile)) + originalArgument + source.slice(call.arguments[0].end);
    const after = source.slice(0, call.arguments[0].getStart(sourceFile)) + replacement + source.slice(call.arguments[0].end);
    if (Buffer.byteLength(after, 'utf8') > MAX_SOURCE_BYTES) return unavailable(finding, 'The parameterized source would exceed the 2 MB scanner file limit.');
    const diff = createUnifiedDiff(file, before, after);
    if (!diff) return unavailable(finding, 'The suggested parameterized query would not change the source.');
    const evidenceContext = history?.status === 'determined' && history.commit
      ? `Root-cause history evidence: commit ${history.commit.hash} (${history.commit.message || 'no commit message'}) is the likely introduction according to the source and diff comparison. `
      : history?.status === 'undetermined'
        ? `The history investigator could not determine the introducing commit (${history.reason}). This suggestion is based on the current source and verified query API only. `
        : 'Git history has not been investigated for this finding; this suggestion is based on the current source and verified query API only. ';
    return {
      status: 'suggested', findingId: finding.id, file, line: finding.line,
      reason: `${evidenceContext}This review-only suggestion uses PostgreSQL $n parameters because the source imports pg and constructs the query receiver with its Pool or Client class. It preserves the existing SQL and values while moving dynamic expressions into the parameter array. Review it against the database schema and surrounding logic.`,
      diff,
      applyPlan: {
        file,
        sourceHash: createHash('sha256').update(source).digest('hex'),
        originalSource: source,
        patchedSource: after,
        replaceStart: call.arguments[0].getStart(sourceFile),
        replaceEnd: call.arguments[0].end,
        expectedText: originalArgument,
        replacement,
        diff,
      },
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return unavailable(finding, code === 'EACCES' || code === 'EPERM'
      ? 'Permission was denied while reading the affected file.'
      : 'The affected source could not be read; run a fresh scan and try again.');
  }
}
