import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';

const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024;
const MAX_DEPENDENCIES = 5000;
const OSV_BATCH_SIZE = 100;

type OsvAffected = { ranges?: Array<{ events?: Array<{ fixed?: string }> }>; ecosystem_specific?: { severity?: string } };
type OsvVulnerability = {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  references?: Array<{ type?: string; url?: string }>;
  affected?: OsvAffected[];
  database_specific?: { severity?: string };
  severity?: Array<{ type?: string; score?: string }>;
};
type OsvQueryBatchResponse = { results?: Array<{ vulns?: Array<Pick<OsvVulnerability, 'id'|'modified'>>; error?: string; next_page_token?: string }> };

export type DependencyAdvisory = {
  id: string;
  summary: string;
  severity: 'Critical' | 'High' | 'Moderate' | 'Low' | 'Unknown';
  aliases: string[];
  modified: string | null;
  fixedVersions: string[];
  url: string;
};
export type AuditedDependency = {
  name: string;
  version: string;
  direct: boolean;
  production: boolean;
  path: string;
  status: 'vulnerable' | 'no-known-vulnerabilities' | 'inconclusive';
  advisories: DependencyAdvisory[];
};
export type DependencyAuditResult = {
  repository: string;
  scannedAt: string;
  ecosystem: 'npm';
  lockfile: string | null;
  lockfileVersion: number | null;
  dependencyCount: number;
  directCount: number;
  transitiveCount: number;
  vulnerableCount: number;
  inconclusiveCount: number;
  truncatedCount: number;
  dependencies: AuditedDependency[];
  notice: string | null;
};

type LockedEntry = { name: string; version: string; path: string; dev: boolean; optional: boolean };

function dependencyNameFromPath(packagePath: string): string | null {
  const normalized = packagePath.replaceAll('\\', '/');
  const marker = '/node_modules/';
  const nestedMarker = normalized.lastIndexOf(marker);
  const markerStart = nestedMarker >= 0 ? nestedMarker + 1 : normalized.startsWith('node_modules/') ? 0 : -1;
  if (markerStart < 0 || (!normalized.startsWith('node_modules/') && markerStart === 0)) return null;
  const tail = normalized.slice(markerStart + 'node_modules/'.length);
  const parts = tail.split('/');
  if (!parts[0]) return null;
  return parts[0].startsWith('@') && parts[1] ? `${parts[0]}/${parts[1]}` : parts[0];
}

export function parseNpmLockData(manifest: unknown, lock: unknown): { entries: LockedEntry[]; lockfileVersion: number | null; directNames: Set<string>; productionNames: Set<string> } {
  if (!manifest || typeof manifest !== 'object' || !lock || typeof lock !== 'object') throw new Error('The npm manifest or lockfile is not a JSON object.');
  const manifestObject = manifest as Record<string, unknown>;
  const lockObject = lock as Record<string, unknown>;
  const lockfileVersion = typeof lockObject.lockfileVersion === 'number' ? lockObject.lockfileVersion : null;
  const dependencyGroups = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;
  const directNames = new Set<string>();
  const productionNames = new Set<string>();
  for (const group of dependencyGroups) {
    const declared = manifestObject[group];
    if (declared && typeof declared === 'object') {
      for (const name of Object.keys(declared)) {
        directNames.add(name);
        if (group !== 'devDependencies') productionNames.add(name);
      }
    }
  }

  const entries: LockedEntry[] = [];
  const packageMap = lockObject.packages;
  if (packageMap && typeof packageMap === 'object') {
    for (const [packagePath, raw] of Object.entries(packageMap as Record<string, unknown>)) {
      if (!packagePath || !raw || typeof raw !== 'object') continue;
      const value = raw as Record<string, unknown>;
      if (value.link === true) continue;
      const name = typeof value.name === 'string' ? value.name : dependencyNameFromPath(packagePath);
      if (!name || typeof value.version !== 'string' || !value.version.trim()) continue;
      entries.push({ name, version: value.version, path: packagePath.replaceAll('\\', '/'), dev: value.dev === true, optional: value.optional === true });
    }
  } else {
    const rootDeps = lockObject.dependencies;
    const visit = (deps: unknown, parentPath: string) => {
      if (!deps || typeof deps !== 'object') return;
      for (const [name, raw] of Object.entries(deps as Record<string, unknown>)) {
        if (!raw || typeof raw !== 'object') continue;
        const value = raw as Record<string, unknown>;
        const packagePath = parentPath ? `${parentPath}/node_modules/${name}` : `node_modules/${name}`;
        if (typeof value.version === 'string' && value.version.trim()) entries.push({ name, version: value.version, path: packagePath, dev: value.dev === true, optional: value.optional === true });
        visit(value.dependencies, packagePath);
      }
    };
    visit(rootDeps, '');
  }
  const unique = new Map<string, LockedEntry>();
  for (const entry of entries) unique.set(`${entry.path}\0${entry.version}`, entry);
  return { entries: [...unique.values()].sort((a,b)=>a.name.localeCompare(b.name)||a.version.localeCompare(b.version)||a.path.localeCompare(b.path)), lockfileVersion, directNames, productionNames };
}

function severityOf(vulnerability: OsvVulnerability): DependencyAdvisory['severity'] {
  const raw = (vulnerability.database_specific?.severity ?? vulnerability.affected?.map(item=>item.ecosystem_specific?.severity).find(Boolean) ?? '').toUpperCase();
  if (raw.includes('CRITICAL')) return 'Critical';
  if (raw.includes('HIGH')) return 'High';
  if (raw.includes('MODERATE') || raw.includes('MEDIUM')) return 'Moderate';
  if (raw.includes('LOW')) return 'Low';
  return 'Unknown';
}

function advisoryFromOsv(vulnerability: OsvVulnerability): DependencyAdvisory {
  const id = vulnerability.id?.trim() || 'OSV advisory';
  const summary = vulnerability.summary?.trim() || vulnerability.details?.split(/\r?\n/)[0]?.trim() || 'No advisory summary was provided.';
  const fixedVersions = [...new Set((vulnerability.affected ?? []).flatMap(affected=>(affected.ranges ?? []).flatMap(range=>(range.events ?? []).flatMap(event=>event.fixed ? [event.fixed] : []))))];
  return {
    id, summary: summary.slice(0, 400), severity: severityOf(vulnerability), aliases: vulnerability.aliases ?? [],
    modified: vulnerability.modified ?? vulnerability.published ?? null, fixedVersions,
    url: vulnerability.references?.find(reference=>reference.type === 'ADVISORY' && reference.url)?.url ?? vulnerability.references?.find(reference=>reference.url)?.url ?? `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
  };
}

async function queryOsv(queries: Array<{ package: { name: string; ecosystem: 'npm' }; version: string }>, fetcher: typeof fetch): Promise<OsvQueryBatchResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(), 20000);
  try {
    const response = await fetcher('https://api.osv.dev/v1/querybatch', {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ queries }), signal: controller.signal,
    });
    if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}.`);
    return await response.json() as OsvQueryBatchResponse;
  } finally { clearTimeout(timeout); }
}

async function getOsvVulnerability(id: string, fetcher: typeof fetch): Promise<OsvVulnerability> {
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),20000);
  try {
    const response=await fetcher(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,{headers:{accept:'application/json'},signal:controller.signal});
    if(!response.ok)throw new Error(`OSV advisory ${id} returned HTTP ${response.status}.`);
    return await response.json() as OsvVulnerability;
  } finally {clearTimeout(timeout);}
}

export async function scanNpmDependencies(repositoryPath: string, fetcher: typeof fetch = fetch): Promise<DependencyAuditResult> {
  const root = path.resolve(repositoryPath);
  const scannedAt = new Date().toISOString();
  let lockfile: string | null = null;
  for (const candidate of ['package-lock.json', 'npm-shrinkwrap.json']) {
    const fullPath = path.join(root, candidate);
    try {
      const info = await lstat(fullPath);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${candidate} must be a regular file in the repository root.`);
      if (info.size > MAX_LOCKFILE_BYTES) throw new Error(`${candidate} exceeds the 20 MB scan limit.`);
      lockfile = candidate;
      break;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') continue;
      throw error;
    }
  }
  if (!lockfile) return {
    repository: path.basename(root), scannedAt, ecosystem: 'npm', lockfile: null, lockfileVersion: null,
    dependencyCount: 0, directCount: 0, transitiveCount: 0, vulnerableCount: 0, inconclusiveCount: 0, truncatedCount: 0, dependencies: [],
    notice: 'No npm lockfile was found at the repository root. Add package-lock.json or npm-shrinkwrap.json to scan exact installed versions.',
  };
  const manifestPath = path.join(root, 'package.json');
  const manifestInfo = await lstat(manifestPath);
  if (!manifestInfo.isFile() || manifestInfo.isSymbolicLink() || manifestInfo.size > MAX_LOCKFILE_BYTES) throw new Error('package.json must be a regular repository-root file under 20 MB.');
  const [manifestText, lockText] = await Promise.all([readFile(manifestPath, 'utf8'), readFile(path.join(root, lockfile), 'utf8')]);
  let parsed;
  try { parsed = parseNpmLockData(JSON.parse(manifestText), JSON.parse(lockText)); }
  catch (error) { throw new Error(`The npm manifest or lockfile could not be parsed: ${(error as Error).message}`); }

  const included = parsed.entries.slice(0, MAX_DEPENDENCIES);
  const unique = [...new Map(included.map(entry=>[`${entry.name}\0${entry.version}`, { name: entry.name, version: entry.version }])).values()];
  const queryResults = new Map<string, string[]>();
  const advisoryDetails = new Map<string, DependencyAdvisory>();
  const failedKeys = new Set<string>();
  const queryErrors: string[] = [];
  let notice: string | null = null;
  try {
    for (let offset=0; offset<unique.length; offset+=OSV_BATCH_SIZE) {
      const batch=unique.slice(offset,offset+OSV_BATCH_SIZE);
      const data=await queryOsv(batch.map(item=>({package:{name:item.name,ecosystem:'npm' as const},version:item.version})),fetcher);
      if (!Array.isArray(data.results) || data.results.length !== batch.length) throw new Error('OSV returned an incomplete batch response.');
      data.results.forEach((result,index)=>{
        const key=`${batch[index].name}\0${batch[index].version}`;
        if(result.error||result.next_page_token){
          failedKeys.add(key);
          queryErrors.push(`${batch[index].name}@${batch[index].version}: ${result.error??'additional advisory pages are available'}`);
          return;
        }
        const ids=(result.vulns??[]).flatMap(vulnerability=>vulnerability.id?[vulnerability.id]:[]);
        if(ids.length!==(result.vulns??[]).length){failedKeys.add(key);queryErrors.push(`${batch[index].name}@${batch[index].version}: OSV returned an advisory without an ID.`);}
        queryResults.set(key,[...new Set(ids)]);
      });
    }
  } catch (error) { notice = `The dependency inventory was created, but OSV checks were inconclusive: ${(error as Error).message}`; }
  const allAdvisoryIds=[...new Set([...queryResults.values()].flat())];
  for(let offset=0;offset<allAdvisoryIds.length;offset+=8){
    const batch=allAdvisoryIds.slice(offset,offset+8);
    const results=await Promise.all(batch.map(async id=>{
      try{return {id,advisory:advisoryFromOsv(await getOsvVulnerability(id,fetcher))};}
      catch(error){return {id,error:(error as Error).message};}
    }));
    for(const result of results){
      if('advisory' in result&&result.advisory)advisoryDetails.set(result.id,result.advisory);
      else queryErrors.push(result.error);
    }
  }
  for(const [key,ids] of queryResults){
    if(ids.some(id=>!advisoryDetails.has(id)))failedKeys.add(key);
  }
  if(queryErrors.length) notice=[notice,`${queryErrors.length} package versions could not be checked by OSV.`].filter(Boolean).join(' ');

  const dependencies: AuditedDependency[] = included.map(entry=>{
    const key=`${entry.name}\0${entry.version}`;
    const ids=queryResults.get(key);
    const advisories=ids?.map(id=>advisoryDetails.get(id)).filter((item):item is DependencyAdvisory=>!!item);
    const inconclusive=failedKeys.has(key)||ids===undefined||advisories?.length!==ids.length;
    return {
      name:entry.name,version:entry.version,direct:entry.path===`node_modules/${entry.name}`&&parsed.directNames.has(entry.name),
      production:parsed.productionNames.has(entry.name)||!entry.dev, path:entry.path,
      status:inconclusive?'inconclusive':advisories!.length?'vulnerable':'no-known-vulnerabilities',
      advisories:advisories??[],
    };
  });
  const vulnerableCount=dependencies.filter(item=>item.status==='vulnerable').length;
  const inconclusiveCount=dependencies.filter(item=>item.status==='inconclusive').length;
  const truncatedCount=Math.max(0,parsed.entries.length-included.length);
  if (truncatedCount) notice=[notice,`${truncatedCount} additional lockfile entries were not checked because the scan limit is ${MAX_DEPENDENCIES.toLocaleString()} packages.`].filter(Boolean).join(' ');
  if (!unique.length && !notice) notice='The npm lockfile contains no versioned dependencies.';
  return {
    repository:path.basename(root),scannedAt,ecosystem:'npm',lockfile,lockfileVersion:parsed.lockfileVersion,
    dependencyCount:dependencies.length,directCount:dependencies.filter(item=>item.direct).length,
    transitiveCount:dependencies.filter(item=>!item.direct).length,vulnerableCount,inconclusiveCount,truncatedCount,dependencies,notice,
  };
}
