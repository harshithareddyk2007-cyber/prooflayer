import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, ArrowDownLeft, ArrowUpRight, Bell, BookOpen, ChevronDown, ChevronRight, CircleHelp, Clock3, ClipboardList, Code2, Command, Database, ExternalLink, FileCode2, GitBranch, GitCommitHorizontal, Github, HardDrive, LayoutDashboard, LockKeyhole, MoreHorizontal, PackageCheck, Play, Plus, RefreshCw, Search, Shield, ShieldCheck, Sparkles, Unplug, X } from 'lucide-react';

type Repo = { name: string; path: string; branch: string; latestCommit: { hash: string; message: string } | null; connectedAt: string };
type Page = 'Overview' | 'Repositories' | 'Security scans' | 'Investigations' | 'Dependencies' | 'Activity log';
type Finding = { id: string; title: string; severity: 'High'; ruleId: string; file: string; line: number; column: number; sinkLine: number; sink: string; pattern: string; message: string; code: string; codeContext: Array<{line:number;code:string}>; constructionEndLine: number; historySignature: string };
type ScanResult = { repositoryPath: string; scannedFiles: number; skippedFiles: Array<{file:string;reason:string}>; findings: Finding[]; startedAt: string; durationMs: number };
type GitHistoryInvestigation = { status: 'determined' | 'undetermined'; findingId: string; reason: string; historyCommitsExamined: number; commit?: {hash:string;message:string;author:string;date:string;file:string}; evidence?: {parentHash:string|null;findingLine:number;findingEndLine:number;before:string;after:string;diff:string;diffTruncated:boolean} };
type HistoryUi = { results: Record<string, GitHistoryInvestigation>; errors: Record<string,string>; loadingId: string|null; onInvestigate: (finding:Finding)=>void };
type PatchReviewRecord = {reviewId:string;findingId:string;file:string;diff:string;status:'pending'|'applied'|'rejected'|'stale'|'error';createdAt:string;reviewedAt:string|null;message:string};
type PatchSuggestion = {status:'suggested'|'unavailable';findingId:string;file:string;line:number;reason:string;diff?:string;reviewId?:string;review?:PatchReviewRecord};
type FixVerification = {status:'Resolved'|'Still Detected'|'Verification Inconclusive';originalFinding:{id:string;title:string;severity:string;ruleId:string;file:string;line:number;sink:string;pattern:string;code:string;historySignature:string};newScan:{startedAt:string;scannedFiles:number;finding:{id:string;file:string;line:number;sink:string;pattern:string;code:string}|null;skippedReason?:string};vulnerablePatternRemains:'yes'|'no'|'unknown';explanation:string};
type PatchUi = {results:Record<string,PatchSuggestion>;errors:Record<string,string>;loadingId:string|null;reviewingId:string|null;verifications:Record<string,FixVerification>;verificationLoadingId:string|null;verificationErrors:Record<string,string>;onSuggest:(finding:Finding)=>void;onApply:(findingId:string,suggestion:PatchSuggestion)=>void;onReject:(findingId:string,reviewId:string)=>void;onVerify:(findingId:string,suggestion:PatchSuggestion)=>void};
type DependencyAdvisory = {id:string;summary:string;severity:'Critical'|'High'|'Moderate'|'Low'|'Unknown';aliases:string[];modified:string|null;fixedVersions:string[];url:string};
type AuditedDependency = {name:string;version:string;direct:boolean;production:boolean;path:string;status:'vulnerable'|'no-known-vulnerabilities'|'inconclusive';advisories:DependencyAdvisory[]};
type DependencyAudit = {repository:string;scannedAt:string;ecosystem:'npm';lockfile:string|null;lockfileVersion:number|null;dependencyCount:number;directCount:number;transitiveCount:number;vulnerableCount:number;inconclusiveCount:number;truncatedCount:number;dependencies:AuditedDependency[];notice:string|null};
type ActivityEvent = {id:string;occurredAt:string;category:'repository'|'security'|'investigation'|'patch'|'verification'|'dependencies';status:'success'|'warning'|'error'|'info';title:string;details:string;repository:string|null};

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Something went wrong.');
  return data as T;
}

export default function App() {
  const [page, setPage] = useState<Page>('Repositories');
  const [repo, setRepo] = useState<Repo | null>(null);
  const [path, setPath] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const [ready, setReady] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState('');
  const [scanning, setScanning] = useState(false);
  const [historyResults, setHistoryResults] = useState<Record<string, GitHistoryInvestigation>>({});
  const [historyErrors, setHistoryErrors] = useState<Record<string, string>>({});
  const [investigatingId, setInvestigatingId] = useState<string | null>(null);
  const [patchSuggestions, setPatchSuggestions] = useState<Record<string, PatchSuggestion>>({});
  const [patchErrors, setPatchErrors] = useState<Record<string, string>>({});
  const [suggestingId, setSuggestingId] = useState<string | null>(null);
  const [confirmingPatch, setConfirmingPatch] = useState<{findingId:string;reviewId:string;file:string}|null>(null);
  const [reviewingPatchId, setReviewingPatchId] = useState<string | null>(null);
  const [patchReviewError, setPatchReviewError] = useState('');
  const [fixVerifications, setFixVerifications] = useState<Record<string,FixVerification>>({});
  const [verificationLoadingId, setVerificationLoadingId] = useState<string|null>(null);
  const [verificationErrors, setVerificationErrors] = useState<Record<string,string>>({});
  const [dependencyAudit,setDependencyAudit]=useState<DependencyAudit|null>(null);
  const [dependencyLoading,setDependencyLoading]=useState(false);
  const [dependencyError,setDependencyError]=useState('');
  const [activityEvents,setActivityEvents]=useState<ActivityEvent[]>([]);
  const [activityLoading,setActivityLoading]=useState(false);
  const [activityError,setActivityError]=useState('');
  const [activityFilter,setActivityFilter]=useState('all');

  useEffect(() => { api<{ repository: Repo | null }>('/api/repository').then(r => setRepo(r.repository)).catch(() => {}).finally(() => setReady(true)); }, []);

  async function connect(event: React.FormEvent) {
    event.preventDefault(); setError(''); setLoading(true);
    try { const result = await api<{ repository: Repo }>('/api/repository/connect', { method: 'POST', body: JSON.stringify({ path }) }); setRepo(result.repository); setScanResult(null); setScanError(''); setHistoryResults({}); setHistoryErrors({}); setPatchSuggestions({}); setPatchErrors({}); setFixVerifications({}); setVerificationErrors({}); setDependencyAudit(null);setDependencyError('');setPath(''); }
    catch (e) { setError(e instanceof Error ? e.message : 'Unable to connect to this repository.'); }
    finally { setLoading(false); }
  }
  async function disconnect() {
    setLoading(true);
    try { await api('/api/repository', { method: 'DELETE' }); setRepo(null); setScanResult(null); setScanError(''); setHistoryResults({}); setHistoryErrors({}); setPatchSuggestions({}); setPatchErrors({}); setFixVerifications({}); setVerificationErrors({}); setDependencyAudit(null);setDependencyError('');setError(''); setConfirmDisconnect(false); }
    catch (e) { setError(e instanceof Error ? e.message : 'Unable to disconnect.'); }
    finally { setLoading(false); }
  }
  async function runSqlScan() {
    setScanning(true); setScanError('');
    try { const response = await api<{result: ScanResult}>('/api/scans/sql-injection', { method: 'POST' }); setScanResult(response.result); setHistoryResults({}); setHistoryErrors({}); setPatchSuggestions({}); setPatchErrors({}); }
    catch (e) { setScanError(e instanceof Error ? e.message : 'The scan could not be completed.'); }
    finally { setScanning(false); }
  }
  async function investigateHistory(finding: Finding) {
    setInvestigatingId(finding.id);
    setHistoryErrors(previous => ({...previous, [finding.id]: ''}));
    setHistoryResults(previous => { const next = {...previous}; delete next[finding.id]; return next; });
    try {
      const response = await api<{result: GitHistoryInvestigation}>('/api/scans/git-history', { method: 'POST', body: JSON.stringify({findingId: finding.id}) });
      setHistoryResults(previous => ({...previous, [finding.id]: response.result}));
    } catch (e) {
      setHistoryErrors(previous => ({...previous, [finding.id]: e instanceof Error ? e.message : 'Git history investigation failed.'}));
    } finally { setInvestigatingId(null); }
  }
  async function suggestPatch(finding: Finding) {
    setSuggestingId(finding.id);
    setPatchErrors(previous => ({...previous, [finding.id]: ''}));
    setPatchSuggestions(previous => { const next = {...previous}; delete next[finding.id]; return next; });
    try {
      const response = await api<{result:PatchSuggestion;review?:PatchReviewRecord}>('/api/scans/patch-suggestion', { method: 'POST', body: JSON.stringify({findingId:finding.id}) });
      setPatchSuggestions(previous => ({...previous, [finding.id]: {...response.result, review:response.review}}));
    } catch (e) {
      setPatchErrors(previous => ({...previous, [finding.id]: e instanceof Error ? e.message : 'Patch suggestion failed.'}));
    } finally { setSuggestingId(null); }
  }
  function requestPatchApply(findingId:string, suggestion:PatchSuggestion) {
    if (!suggestion.reviewId || suggestion.review?.status !== 'pending') return;
    setPatchReviewError('');
    setConfirmingPatch({findingId,reviewId:suggestion.reviewId,file:suggestion.file});
  }
  async function confirmPatchApply() {
    if (!confirmingPatch) return;
    const pending = confirmingPatch;
    setReviewingPatchId(pending.reviewId);
    setPatchReviewError('');
    try {
      const response = await api<{review:PatchReviewRecord}>('/api/scans/patch-review/apply', {method:'POST',body:JSON.stringify({reviewId:pending.reviewId,confirmed:true})});
      setPatchSuggestions(previous => ({...previous,[pending.findingId]:{...previous[pending.findingId],review:response.review}}));
      setConfirmingPatch(null);
    } catch (e) { setPatchReviewError(e instanceof Error ? e.message : 'The patch could not be applied.'); }
    finally { setReviewingPatchId(null); }
  }
  async function rejectPatch(findingId:string, reviewId:string) {
    setReviewingPatchId(reviewId);
    setPatchReviewError('');
    try {
      const response = await api<{review:PatchReviewRecord}>('/api/scans/patch-review/reject', {method:'POST',body:JSON.stringify({reviewId})});
      setPatchSuggestions(previous => ({...previous,[findingId]:{...previous[findingId],review:response.review}}));
    } catch (e) { setPatchErrors(previous => ({...previous,[findingId]:e instanceof Error ? e.message : 'The rejection could not be recorded.'})); }
    finally { setReviewingPatchId(null); }
  }
  async function verifyPatch(findingId:string, suggestion:PatchSuggestion) {
    if (!suggestion.reviewId || suggestion.review?.status !== 'applied') return;
    setVerificationLoadingId(findingId);
    setVerificationErrors(previous=>({...previous,[findingId]:''}));
    try {
      const response=await api<{verification:FixVerification}>('/api/scans/patch-review/verify',{method:'POST',body:JSON.stringify({reviewId:suggestion.reviewId})});
      setFixVerifications(previous=>({...previous,[findingId]:response.verification}));
    } catch(e) { setVerificationErrors(previous=>({...previous,[findingId]:e instanceof Error?e.message:'The repository could not be rescanned for verification.'})); }
    finally { setVerificationLoadingId(null); }
  }
  async function runDependencyAudit() {
    setDependencyLoading(true);setDependencyError('');
    try {const response=await api<{result:DependencyAudit}>('/api/scans/dependencies',{method:'POST'});setDependencyAudit(response.result);}
    catch(e){setDependencyError(e instanceof Error?e.message:'Dependency scanning failed.');}
    finally{setDependencyLoading(false);}
  }
  async function loadActivityLog() {
    setActivityLoading(true);setActivityError('');
    try {const response=await api<{events:ActivityEvent[]}>('/api/activity-log');setActivityEvents(response.events);}
    catch(e){setActivityError(e instanceof Error?e.message:'The activity log could not be loaded.');}
    finally{setActivityLoading(false);}
  }
  useEffect(()=>{if(page==='Activity log')void loadActivityLog();},[page]);
  const historyUi: HistoryUi = {results: historyResults, errors: historyErrors, loadingId: investigatingId, onInvestigate: investigateHistory};
  const patchUi: PatchUi = {results: patchSuggestions, errors: patchErrors, loadingId:suggestingId, reviewingId:reviewingPatchId, verifications:fixVerifications, verificationLoadingId, verificationErrors, onSuggest:suggestPatch, onApply:requestPatchApply, onReject:rejectPatch, onVerify:verifyPatch};

  const navItems: { title: Page; icon: typeof LayoutDashboard; count?: string }[] = [
    { title: 'Overview', icon: LayoutDashboard }, { title: 'Repositories', icon: Database, count: repo ? '1' : undefined },
    { title: 'Security scans', icon: ShieldCheck }, { title: 'Investigations', icon: ClipboardList, count: scanResult ? String(scanResult.findings.length) : undefined }, { title: 'Dependencies', icon: Code2 }, { title: 'Activity log', icon: Activity },
  ];
  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={19} strokeWidth={2.2}/><span/></div><span>prooflayer</span><span className="brand-dot">.</span><button className="workspace-switch"><ChevronDown size={14}/></button></div>
      <div className="workspace"><div className="workspace-avatar">PL</div><div className="workspace-copy"><strong>Personal workspace</strong><span>Free plan</span></div><MoreHorizontal size={17} className="muted"/></div>
      <div className="side-label">WORKSPACE</div>
      <nav>{navItems.map(({title,icon:Icon,count})=><button key={title} onClick={()=>setPage(title)} className={`nav-item ${page===title?'active':''}`}><Icon size={17}/><span>{title}</span>{count&&<em>{count}</em>}</button>)}</nav>
      <div className="side-label tools-label">TOOLS</div>
      <button className="nav-item"><BookOpen size={17}/><span>Documentation</span><ArrowUpRight size={13} className="nav-external"/></button>
      <div className="sidebar-bottom"><div className="upgrade-card"><div className="upgrade-icon"><Sparkles size={15}/></div><b>Level up your security</b><p>Unlock automated scans and deeper insights.</p><button>Explore Pro <ArrowUpRight size={13}/></button></div><button className="profile"><div className="profile-avatar">H</div><span><b>Harsh</b><small>harsh@example.com</small></span><MoreHorizontal size={17}/></button></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><ChevronRight size={14}/><strong>{page}</strong></div><div className="top-actions"><button className="search-button"><Search size={15}/><span>Search anything...</span><kbd><Command size={10}/> K</kbd></button><button className="icon-button" aria-label="Help"><CircleHelp size={17}/></button><button className="icon-button notification" aria-label="Notifications"><Bell size={17}/><i/></button><div className="top-avatar">H</div></div></header>
      <section className="page-content">
        <div className="title-row"><div><div className="eyebrow"><span className="eyebrow-line"/>SECURITY WORKSPACE</div><h1>{page}</h1><p className="subtitle">{page==='Overview'?'A clear view of your codebase security and health.':page==='Security scans'?'Run a focused SQL injection scan on your connected TypeScript code.':page==='Investigations'?'Review actual findings from the latest SQL injection scan.':page==='Dependencies'?'Inventory npm packages and check versions against OSV advisories.':page==='Activity log'?'Review repository and security actions from this server session.':'Connect and manage the local codebases you want to keep secure.'}</p></div><div className="title-meta"><span className="live-dot"/>All systems operational</div></div>
        {page==='Overview' ? <Overview repo={repo} scanResult={scanResult} onManage={()=>setPage('Repositories')} onDisconnect={()=>setConfirmDisconnect(true)} onInvestigations={()=>setPage('Investigations')}/> : page==='Security scans' ? <SqlInjectionScanPage repo={repo} result={scanResult} error={scanError} scanning={scanning} onScan={runSqlScan} onInvestigations={()=>setPage('Investigations')} historyUi={historyUi} patchUi={patchUi}/> : page==='Investigations' ? <InvestigationsPage repo={repo} result={scanResult} error={scanError} scanning={scanning} onScan={runSqlScan} historyUi={historyUi} patchUi={patchUi}/> : page==='Dependencies' ? <DependenciesPage repo={repo} result={dependencyAudit} error={dependencyError} loading={dependencyLoading} onScan={runDependencyAudit}/> : page==='Activity log' ? <ActivityLogPage events={activityEvents} error={activityError} loading={activityLoading} filter={activityFilter} onFilter={setActivityFilter} onRefresh={loadActivityLog}/> : page==='Repositories' ? <>
          <div className="stats-grid"><Stat icon={Database} label="CONNECTED REPOSITORIES" value={repo?'01':'00'} detail={repo?'1 repository connected':'No repositories connected'} accent={!!repo}/><Stat icon={ShieldCheck} label="LAST SECURITY SCAN" value={scanResult?new Date(scanResult.startedAt).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):'—'} detail={scanResult?`${scanResult.findings.length} finding${scanResult.findings.length===1?'':'s'} · ${new Date(scanResult.startedAt).toLocaleDateString()}`:'Run a SQL injection scan'}/><Stat icon={GitCommitHorizontal} label="GIT HISTORY" value={repo?'Ready':'—'} detail={repo?'Investigate commits per finding':'Connect a repository'}/></div>
          <div className="section-heading"><div><h2>Your repositories</h2><p>Local repositories connected to your workspace.</p></div><span className="count-pill">{repo?'1 repository':'0 repositories'}</span></div>
          {repo ? <RepositoryCard repo={repo} onDisconnect={()=>setConfirmDisconnect(true)}/> : <div className="connect-card">
            <div className="connect-top"><div className="connect-icon"><HardDrive size={19}/></div><div><h3>Connect a local repository</h3><p>Link a Git repository from your computer to get started.</p></div><span className="local-badge"><span/>LOCAL ONLY</span></div>
            <form onSubmit={connect} className="connect-form"><label htmlFor="repo-path">Repository folder path</label><div className={`path-input ${error?'input-error':''}`}><HardDrive size={17}/><input id="repo-path" value={path} onChange={e=>{setPath(e.target.value);if(error)setError('');}} placeholder="C:\\Users\\you\\projects\\my-app" autoComplete="off" spellCheck={false}/><span className="input-suffix">ABSOLUTE PATH</span></div>
              <div className="path-hint"><span>Enter the full path to a folder containing a <code>.git</code> directory.</span><span className="os-hint">macOS / Linux <i>·</i> Windows</span></div>
              {error&&<div className="error-message" role="alert"><X size={15}/>{error}</div>}
              <div className="connect-footer"><div className="privacy-note"><LockKeyhole size={14}/><span>Your code stays on this machine. No files are uploaded.</span></div><button className="primary-button" type="submit" disabled={loading||!ready}>{loading?<span className="spinner"/>:<Plus size={16}/>}Connect repository<ArrowUpRight size={14}/></button></div>
            </form>
            <div className="connect-divider"/><div className="git-note"><GitBranch size={15}/><span>Git must be installed and available in your system PATH.</span><a href="https://git-scm.com/downloads" target="_blank" rel="noreferrer">Get Git <ArrowUpRight size={11}/></a></div>
          </div>}
          <div className="bottom-grid"><div className="info-panel"><div className="info-icon blue"><ShieldCheck size={17}/></div><div><b>Built for safe code reviews</b><p>ProofLayer inspects your repository locally. Your source code never leaves your machine.</p><button className="text-link">How it works <ArrowUpRight size={12}/></button></div></div><div className="info-panel"><div className="info-icon green"><GitBranch size={17}/></div><div><b>Ready when you are</b><p>Once connected, your repository details will appear here and in your overview.</p><button className="text-link">View documentation <ArrowUpRight size={12}/></button></div></div></div>
        </> : null}
        <footer className="page-footer"><span>© 2025 ProofLayer, Inc.</span><div><a>Privacy</a><a>Terms</a><a>Status <i className="live-dot"/></a><span className="version">v1.0.0</span></div></footer>
      </section>
    </main>
    {confirmDisconnect&&<div className="modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setConfirmDisconnect(false);}}><div className="modal" role="dialog" aria-modal="true" aria-labelledby="disconnect-title"><div className="modal-icon"><Unplug size={19}/></div><button className="modal-close" onClick={()=>setConfirmDisconnect(false)} aria-label="Close"><X size={17}/></button><h2 id="disconnect-title">Disconnect repository?</h2><p><b>{repo?.name}</b> will be removed from this workspace. Your local files and Git history will not be changed.</p><div className="modal-actions"><button className="secondary-button" onClick={()=>setConfirmDisconnect(false)}>Cancel</button><button className="danger-button" onClick={disconnect} disabled={loading}>{loading?'Disconnecting…':'Disconnect repository'}</button></div></div></div>}
      {confirmingPatch&&<div className="modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget&&!reviewingPatchId)setConfirmingPatch(null);}}><div className="modal patch-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="apply-patch-title"><div className="modal-icon"><Code2 size={19}/></div><button className="modal-close" onClick={()=>{if(!reviewingPatchId)setConfirmingPatch(null);}} aria-label="Close" disabled={!!reviewingPatchId}><X size={17}/></button><h2 id="apply-patch-title">Apply this patch?</h2><p>ProofLayer will recheck <b>{confirmingPatch.file}</b> against the reviewed version and apply only this diff. If the file changed, nothing will be applied. This will not commit or push anything.</p>{patchReviewError&&<div className="error-message" role="alert"><X size={14}/>{patchReviewError}</div>}<div className="modal-actions"><button className="secondary-button" onClick={()=>setConfirmingPatch(null)} disabled={!!reviewingPatchId}>Cancel</button><button className="primary-button" onClick={confirmPatchApply} disabled={!!reviewingPatchId}>{reviewingPatchId?<span className="spinner"/>:'Apply Patch'}</button></div></div></div>}
  </div>;
}

function Stat({icon:Icon,label,value,detail,accent}:{icon:typeof Database;label:string;value:string;detail:string;accent?:boolean}) { return <div className="stat-card"><div className="stat-top"><div className="stat-icon"><Icon size={17}/></div><span>{label}</span><MoreHorizontal size={16} className="stat-more"/></div><div className={`stat-value ${accent?'has-repo':''}`}>{value}{accent&&<span className="stat-up"><ArrowUpRight size={12}/></span>}</div><div className="stat-detail">{detail}</div></div>; }

function RepositoryCard({repo,onDisconnect}:{repo:Repo;onDisconnect:()=>void}) { return <div className="repo-card"><div className="repo-card-head"><div className="repo-avatar"><Github size={22}/></div><div className="repo-name-block"><div className="repo-name-line"><h3>{repo.name}</h3><span className="connected-badge"><i/>Connected</span></div><p>Local repository <span>·</span> Connected {new Date(repo.connectedAt).toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'})}</p></div><button className="repo-menu" aria-label="More options" onClick={onDisconnect}><MoreHorizontal size={19}/></button></div><div className="repo-path"><HardDrive size={14}/><span>{repo.path}</span><button title="Copy path" onClick={()=>navigator.clipboard?.writeText(repo.path)}><ArrowDownLeft size={13}/></button></div><div className="repo-metadata"><div><span className="meta-label">CURRENT BRANCH</span><span className="meta-value"><GitBranch size={14}/>{repo.branch}</span></div><div><span className="meta-label">LATEST COMMIT</span><span className="meta-value commit-value"><GitCommitHorizontal size={14}/>{repo.latestCommit?<><code>{repo.latestCommit.hash.slice(0,7)}</code><span className="commit-message" title={repo.latestCommit.message}>{repo.latestCommit.message}</span></>:'No commits yet'}</span></div><div><span className="meta-label">STATUS</span><span className="meta-value status-value"><i/>Connected</span></div></div><div className="repo-card-footer"><span><Clock3 size={13}/>Repository details verified on connection</span><button className="disconnect-link" onClick={onDisconnect}>Disconnect repository</button></div></div>; }

function DependenciesPage({repo,result,error,loading,onScan}:{repo:Repo|null;result:DependencyAudit|null;error:string;loading:boolean;onScan:()=>void}) {
  const [filter,setFilter]=useState<'all'|'vulnerable'|'inconclusive'|'direct'>('all');
  const filtered=result?.dependencies.filter(item=>filter==='all'||(filter==='vulnerable'?item.status==='vulnerable':filter==='inconclusive'?item.status==='inconclusive':item.direct))??[];
  const shown=filtered.slice(0,200);
  return <div className="feature-page">
    <div className="feature-toolbar"><div><b>{repo?`Repository: ${repo.name}`:'Connect a repository to scan its dependencies'}</b><p>Reads exact npm package versions from package-lock.json or npm-shrinkwrap.json.</p></div><button className="primary-button" onClick={onScan} disabled={!repo||loading}>{loading?<span className="spinner"/>:<PackageCheck size={15}/>} {loading?'Checking dependencies…':result?'Rescan dependencies':'Scan dependencies'}</button></div>
    {!repo?<div className="feature-empty"><div className="empty-symbol"><PackageCheck size={18}/></div><div><b>No repository connected</b><p>Connect a local Git repository before scanning its npm dependencies.</p></div></div>:error?<div className="error-message feature-error" role="alert"><X size={15}/>{error}</div>:!result?<div className="feature-empty"><div className="empty-symbol"><PackageCheck size={18}/></div><div><b>No dependency scan yet</b><p>Start a scan to inventory locked npm dependencies and check them against OSV advisories.</p></div></div>:<>
      <div className="dependency-summary"><div><span>LOCKED PACKAGES</span><b>{result.dependencyCount}</b></div><div><span>DIRECT</span><b>{result.directCount}</b></div><div><span>TRANSITIVE</span><b>{result.transitiveCount}</b></div><div><span>VULNERABLE</span><b className={result.vulnerableCount?'dependency-count-alert':''}>{result.vulnerableCount}</b></div><div><span>INCONCLUSIVE</span><b>{result.inconclusiveCount}</b></div></div>
      <div className="dependency-scan-meta"><span>{result.lockfile?`${result.lockfile} · lockfile v${result.lockfileVersion??'unknown'}`:'No npm lockfile'}</span><span>Scanned {new Date(result.scannedAt).toLocaleString()}</span></div>
      {result.notice&&<div className="dependency-notice" role="status"><AlertTriangle size={15}/><span>{result.notice}</span></div>}
      {result.dependencies.length>0&&<div className="dependency-list-card"><div className="dependency-list-heading"><div><h2>Dependencies</h2><p>{filtered.length} of {result.dependencyCount} locked package entries</p></div><select value={filter} onChange={event=>setFilter(event.target.value as typeof filter)} aria-label="Filter dependencies"><option value="all">All packages</option><option value="vulnerable">Vulnerable</option><option value="inconclusive">Inconclusive</option><option value="direct">Direct only</option></select></div>
        <div className="dependency-table-wrap"><table className="dependency-table"><thead><tr><th>PACKAGE</th><th>TYPE</th><th>OSV CHECK</th><th>ADVISORY</th></tr></thead><tbody>{shown.map((item,index)=><tr key={`${item.path}-${item.version}-${index}`}><td><b>{item.name}</b><code>{item.version}</code><small>{item.path}</small></td><td><span className="dependency-type">{item.direct?'Direct':'Transitive'} · {item.production?'Production':'Development'}</span></td><td><span className={`dependency-status dependency-status-${item.status}`}>{item.status==='vulnerable'?'Vulnerable':item.status==='inconclusive'?'Inconclusive':'No known advisory'}</span></td><td>{item.advisories.length?item.advisories.map(advisory=><div className="dependency-advisory" key={advisory.id}><div><a href={advisory.url} target="_blank" rel="noreferrer">{advisory.id}<ExternalLink size={11}/></a><span className={`advisory-severity advisory-${advisory.severity.toLowerCase()}`}>{advisory.severity}</span></div><p>{advisory.summary}</p>{advisory.fixedVersions.length>0&&<small>Fixed in {advisory.fixedVersions.join(', ')}</small>}</div>):<span className="dependency-no-advisory">{item.status==='inconclusive'?'Could not verify against OSV':'No matching OSV advisory'}</span>}</td></tr>)}</tbody></table></div>
        {filtered.length>shown.length&&<p className="dependency-truncated">Showing the first {shown.length} entries. The scan checked {result.dependencyCount} package entries.</p>}
      </div>}
      {result.dependencyCount===0&&result.lockfile&&<div className="feature-empty"><div className="empty-symbol"><PackageCheck size={18}/></div><div><b>No versioned dependencies found</b><p>The npm lockfile did not contain package versions to check.</p></div></div>}
      {!result.vulnerableCount&&!result.inconclusiveCount&&result.dependencyCount>0&&<div className="dependency-clean-note"><ShieldCheck size={15}/><span>No known vulnerabilities were returned by OSV for the scanned package versions. This is not a guarantee that packages are secure.</span></div>}
      <p className="dependency-privacy"><LockKeyhole size={13}/>Source files remain local. The OSV lookup sends npm package names and versions to <a href="https://osv.dev" target="_blank" rel="noreferrer">OSV</a> to check public vulnerability records.</p>
    </>}
  </div>;
}

function ActivityLogPage({events,error,loading,filter,onFilter,onRefresh}:{events:ActivityEvent[];error:string;loading:boolean;filter:string;onFilter:(value:string)=>void;onRefresh:()=>void}) {
  const filtered=events.filter(event=>filter==='all'||event.category===filter);
  const categoryLabel:Record<ActivityEvent['category'],string>={repository:'Repository',security:'Security scan',investigation:'Git investigation',patch:'Patch',verification:'Verification',dependencies:'Dependencies'};
  return <div className="feature-page">
    <div className="feature-toolbar"><div><b>{events.length?`${events.length} recent workspace actions`:'Workspace activity'}</b><p>Actions recorded by this ProofLayer server process, newest first.</p></div><div className="activity-controls"><select value={filter} onChange={event=>onFilter(event.target.value)} aria-label="Filter activity"><option value="all">All activity</option><option value="repository">Repository</option><option value="security">Security scans</option><option value="investigation">Investigations</option><option value="patch">Patch actions</option><option value="verification">Verifications</option><option value="dependencies">Dependencies</option></select><button className="secondary-button" onClick={onRefresh} disabled={loading}>{loading?<span className="spinner spinner-muted"/>:<RefreshCw size={13}/>}Refresh</button></div></div>
    {error&&<div className="error-message feature-error" role="alert"><X size={15}/>{error}</div>}
    <div className="activity-session-note"><Clock3 size={14}/><span>This log is kept in memory for this server session and holds up to 500 recent events. It clears when the API server restarts.</span></div>
    {loading&&!events.length?<div className="feature-empty"><span className="spinner spinner-muted"/><div><b>Loading activity…</b></div></div>:filtered.length?<div className="activity-feed">{filtered.map(event=><article className="activity-entry" key={event.id}><span className={`activity-marker activity-marker-${event.status}`}><Activity size={14}/></span><div className="activity-entry-main"><div className="activity-entry-title"><b>{event.title}</b><span className="activity-category">{categoryLabel[event.category]}</span></div><p>{event.details}</p>{event.repository&&<code>{event.repository}</code>}</div><time dateTime={event.occurredAt} title={new Date(event.occurredAt).toLocaleString()}>{new Date(event.occurredAt).toLocaleString()}</time></article>)}</div>:<div className="feature-empty"><div className="empty-symbol"><Activity size={18}/></div><div><b>{events.length?'No matching activity':'No activity recorded yet'}</b><p>{events.length?'Try another activity filter.':'Connect a repository or run a scan to start the activity log.'}</p></div></div>}
  </div>;
}

function Overview({repo,scanResult,onManage,onDisconnect,onInvestigations}:{repo:Repo|null;scanResult:ScanResult|null;onManage:()=>void;onDisconnect:()=>void;onInvestigations:()=>void}) { return <><div className="overview-welcome"><div><div className="overview-kicker"><Sparkles size={14}/> YOUR SECURITY SNAPSHOT</div><h2>{repo?'Your codebase is connected.':'A safer codebase starts here.'}</h2><p>{repo?`${repo.name} is connected and ready for analysis.`:'Connect a local Git repository to get started with ProofLayer.'}</p></div><button className="primary-button" onClick={scanResult?onInvestigations:onManage}>{scanResult?'View investigations':repo?'View repository':'Connect repository'}<ArrowUpRight size={14}/></button></div><div className="stats-grid overview-stats"><Stat icon={Database} label="CONNECTED REPOSITORIES" value={repo?'01':'00'} detail={repo?repo.name:'Connect your first repository'} accent={!!repo}/><Stat icon={AlertTriangle} label="LATEST SCAN FINDINGS" value={scanResult ? String(scanResult.findings.length) : '—'} detail={scanResult ? `${scanResult.scannedFiles} source files scanned` : 'Run a SQL injection scan'}/><Stat icon={GitCommitHorizontal} label="GIT HISTORY" value={repo?'Ready':'—'} detail={repo?'Per-finding commit evidence':'Connect a repository'}/></div><div className="section-heading"><div><h2>Workspace activity</h2><p>Recent repository and security actions.</p></div><button className="plain-button" onClick={onManage}>Manage repositories <ArrowUpRight size={13}/></button></div><div className="overview-repo">{repo?<RepositoryCard repo={repo} onDisconnect={onDisconnect}/>:<div className="overview-empty"><div className="empty-symbol"><Database size={19}/></div><div><b>No repositories yet</b><p>Connect a local Git repository to see your workspace activity.</p></div><button className="secondary-button" onClick={onManage}>Go to repositories <ArrowUpRight size={13}/></button></div>}</div><div className="overview-footnote"><div className="info-icon blue"><LockKeyhole size={16}/></div><span><b>Private by design.</b> Source files stay local. Dependency checks send package names and versions to OSV.</span></div></>; }

function SqlInjectionScanPage({repo,result,error,scanning,onScan,onInvestigations,historyUi,patchUi}:{repo:Repo|null;result:ScanResult|null;error:string;scanning:boolean;onScan:()=>void;onInvestigations:()=>void;historyUi:HistoryUi;patchUi:PatchUi}) {
  return <div className="scan-page">
    <div className="scan-intro-card"><div className="scan-intro-top"><div className="scan-icon"><ShieldCheck size={20}/></div><div className="scan-intro-copy"><h2>SQL injection pattern scan</h2><p>Inspect tracked and non-ignored TypeScript source for dynamically constructed SQL passed to query methods.</p></div><span className="scan-scope"><FileCode2 size={13}/> .TS + .TSX</span></div>
      <div className="scan-action-row"><div className="scan-target">{repo?<><span className="connected-indicator"/>Scanning <b>{repo.name}</b><span className="scan-path">{repo.path}</span></>:<span className="scan-no-repo">Connect a local Git repository before scanning.</span>}</div><button className="primary-button" onClick={onScan} disabled={!repo||scanning}>{scanning?<span className="spinner"/>:<Play size={14}/>} {scanning?'Scanning…':'Run SQL injection scan'}</button></div>
    </div>
    {error&&<div className="error-message scan-error" role="alert"><X size={15}/>{error}</div>}
    {result&&<>
      <div className="section-heading scan-results-heading"><div><h2>Scan results</h2><p>{new Date(result.startedAt).toLocaleString()} · completed in {(result.durationMs/1000).toFixed(1)}s</p></div><div className="investigation-actions"><span className={result.findings.length?'finding-count':'clean-count'}>{result.findings.length} {result.findings.length===1?'finding':'findings'}</span><button className="plain-button" onClick={onInvestigations}>Open investigations <ArrowUpRight size={12}/></button></div></div>
      <div className="scan-summary"><div><span className="summary-value">{result.scannedFiles}</span><span className="summary-label">SOURCE FILES SCANNED</span></div><div><span className={`summary-value ${result.findings.length?'summary-alert':''}`}>{result.findings.length}</span><span className="summary-label">POTENTIAL SQL INJECTIONS</span></div><div><span className="summary-value">{result.skippedFiles.length}</span><span className="summary-label">FILES SKIPPED</span></div></div>
      <div className="section-heading investigation-section-heading"><div><h2>Investigations</h2><p>Findings from the latest scan, linked to their source lines.</p></div></div>
      {result.findings.length ? <FindingList findings={result.findings} historyUi={historyUi} patchUi={patchUi}/> : <div className="clean-result"><div className="clean-result-icon"><ShieldCheck size={19}/></div><div><b>No supported SQL injection patterns found</b><p>Scanned {result.scannedFiles} TypeScript source {result.scannedFiles===1?'file':'files'} in {repo?.name}.</p></div></div>}
      {result.skippedFiles.length>0&&<details className="skipped-details"><summary>{result.skippedFiles.length} file{result.skippedFiles.length===1?'':'s'} skipped due to read or parse errors</summary><ul>{result.skippedFiles.slice(0,12).map(f=><li key={f.file}><code>{f.file}</code><span>{f.reason}</span></li>)}</ul>{result.skippedFiles.length>12&&<p>Showing first 12 skipped files.</p>}</details>}
    </>}
    <div className="scanner-limits"><AlertTriangle size={15}/><div><b>Pattern-based MVP scanner</b><p>Findings can be false positives, especially for parameterizing SQL template tags. It can miss renamed or indirect SQL builders, complex data flow, dynamic SQL stored in other files, or unsupported sink names. No findings does not guarantee the code is safe.</p></div></div>
  </div>;
}

function InvestigationsPage({repo,result,error,scanning,onScan,historyUi,patchUi}:{repo:Repo|null;result:ScanResult|null;error:string;scanning:boolean;onScan:()=>void;historyUi:HistoryUi;patchUi:PatchUi}) {
  return <div className="scan-page">
    {error&&<div className="error-message scan-error" role="alert"><X size={15}/>{error}</div>}
    <div className="investigations-overview"><div><div className="overview-kicker"><ClipboardList size={14}/> LATEST SCAN INVESTIGATIONS</div><h2>{repo?.name ?? 'No repository connected'}</h2><p>{result ? `${result.scannedFiles} source files scanned · ${new Date(result.startedAt).toLocaleString()}` : 'Run a SQL injection scan to create investigations from real source findings.'}</p></div><div className="investigations-overview-actions"><span className={result?.findings.length?'finding-count':'clean-count'}>{result?`${result.findings.length} ${result.findings.length===1?'finding':'findings'}`:'No scan yet'}</span><button className="primary-button" onClick={onScan} disabled={!repo||scanning}>{scanning?<span className="spinner"/>:<Play size={14}/>} {scanning?'Scanning…':'Run scan'}</button></div></div>
    {!repo ? <div className="investigations-empty"><div className="empty-symbol"><Database size={19}/></div><div><b>Connect a repository first</b><p>Connect a local Git repository before creating investigations.</p></div></div> : !result ? <div className="investigations-empty"><div className="empty-symbol"><ClipboardList size={19}/></div><div><b>No scan results yet</b><p>Run the SQL injection scanner to populate this section with actual findings.</p></div></div> : result.findings.length ? <FindingList findings={result.findings} historyUi={historyUi} patchUi={patchUi}/> : <div className="clean-result"><div className="clean-result-icon"><ShieldCheck size={19}/></div><div><b>No supported SQL injection findings</b><p>The latest scan checked {result.scannedFiles} TypeScript source files in {repo.name}.</p></div></div>}
    {result&&result.skippedFiles.length>0&&<details className="skipped-details"><summary>{result.skippedFiles.length} file{result.skippedFiles.length===1?'':'s'} skipped due to read or analysis errors</summary><ul>{result.skippedFiles.slice(0,12).map(f=><li key={f.file}><code>{f.file}</code><span>{f.reason}</span></li>)}</ul>{result.skippedFiles.length>12&&<p>Showing first 12 skipped files.</p>}</details>}
  </div>;
}

function FindingList({findings,historyUi,patchUi}:{findings:Finding[];historyUi:HistoryUi;patchUi:PatchUi}) { return <div className="finding-list">{findings.map(finding=><FindingCard key={finding.id} finding={finding} historyUi={historyUi} patchUi={patchUi}/>)}</div>; }

function FindingCard({finding,historyUi,patchUi}:{finding:Finding;historyUi:HistoryUi;patchUi:PatchUi}) {
  const basename=finding.file.replaceAll('\\','/').split('/').at(-1) || finding.file;
  const historyResult=historyUi.results[finding.id];
  const historyError=historyUi.errors[finding.id];
  const isLoading=historyUi.loadingId===finding.id;
  const patchResult=patchUi.results[finding.id];
  const patchError=patchUi.errors[finding.id];
  const isSuggesting=patchUi.loadingId===finding.id;
  return <details className="finding-details">
    <summary aria-label={`Inspect ${finding.title} in ${finding.file} at line ${finding.line}`}>
      <div className="finding-card-top"><span className="finding-alert-icon"><AlertTriangle size={15}/></span><div className="finding-title"><b>{finding.title}</b><span>{finding.pattern}</span></div><span className="severity-badge severity-high">{finding.severity}</span><code className="finding-rule">{finding.ruleId}</code></div>
      <div className="finding-location"><FileCode2 size={14}/><b>{basename}</b><code>{finding.file}</code><span className="finding-line-number">Line {finding.line}</span>{finding.sinkLine!==finding.line&&<span className="sink-location"> · {finding.sink}() at line {finding.sinkLine}</span>}</div>
    </summary>
    <div className="finding-detail-body"><div className="finding-detail-meta"><div><span>SEVERITY</span><b className="severity-text-high">{finding.severity}</b></div><div><span>DETECTION RULE</span><code>{finding.ruleId}</code></div><div><span>RELATIVE FILE</span><code>{finding.file}</code></div><div><span>DETECTED LINE</span><code>{finding.line}</code></div></div><h3>Source context</h3><pre className="source-context">{finding.codeContext.map(item=><div className={`source-context-line ${item.line===finding.line?'source-context-match':''}`} key={item.line}><span className="source-line-number">{item.line}</span><code>{item.code || ' '}</code></div>)}</pre><p className="finding-message">{finding.message}</p><RootCauseAnalysis finding={finding} history={historyResult} error={historyError}/><div className="finding-tools-actions"><div className="history-investigation-action"><button className="secondary-button" onClick={()=>historyUi.onInvestigate(finding)} disabled={!!historyUi.loadingId}>{isLoading?<span className="spinner"/>:<GitCommitHorizontal size={14}/>} {isLoading?'Comparing Git history…':historyResult?'Recheck Git history':'Investigate Git history'}</button><span>Uses source versions and Git diffs for this file.</span></div><div className="history-investigation-action patch-suggestion-action"><button className="secondary-button" onClick={()=>patchUi.onSuggest(finding)} disabled={!!patchUi.loadingId}>{isSuggesting?<span className="spinner"/>:<Code2 size={14}/>} {isSuggesting?'Preparing patch…':patchResult?'Refresh suggested patch':'Suggest patch'}</button><span>Creates a review-only diff; repository files are not changed.</span></div></div>{historyError&&<div className="error-message history-error" role="alert"><X size={14}/>{historyError}</div>}{historyResult&&<GitHistoryResultView result={historyResult} finding={finding}/>} {patchError&&<div className="error-message history-error" role="alert"><X size={14}/>{patchError}</div>}{patchResult&&<SuggestedPatchView result={patchResult} onApply={()=>patchUi.onApply(finding.id,patchResult)} onReject={()=>patchResult.reviewId&&patchUi.onReject(finding.id,patchResult.reviewId)} onVerify={()=>patchUi.onVerify(finding.id,patchResult)} verification={patchUi.verifications[finding.id]} verificationError={patchUi.verificationErrors[finding.id]} verifying={patchUi.verificationLoadingId===finding.id} reviewing={patchUi.reviewingId===patchResult.reviewId}/>}</div>
  </details>;
}

function RootCauseAnalysis({finding,history,error}:{finding:Finding;history:GitHistoryInvestigation|undefined;error:string|undefined}) {
  const construction = finding.pattern === 'Dynamic template literal'
    ? 'The SQL-like string is assembled with a template literal that inserts a dynamic value.'
    : 'The SQL-like string is assembled by concatenating a dynamic value with SQL text.';
  const changedLines = history?.status === 'determined' && history.evidence
    ? parseEvidenceDiff(history.evidence.diff, history.evidence.findingLine, history.evidence.findingEndLine).filter(line => line.kind === 'added' && line.relevant)
    : [];
  return <section className="root-cause-analysis" aria-labelledby={`root-cause-${finding.id}`}>
    <div className="root-cause-heading"><Shield size={14}/><h3 id={`root-cause-${finding.id}`}>Root Cause Analysis</h3></div>
    <div className="root-cause-block">
      <h4>Confirmed from the finding</h4>
      <p>{construction} The resulting expression is passed to <code>{finding.sink}()</code> in <code>{finding.file}:{finding.sinkLine}</code>.</p>
      <pre className="root-cause-source"><span>{finding.line}</span><code>{finding.code || '(source line unavailable)'}</code></pre>
    </div>
    <div className="root-cause-block root-cause-inference">
      <h4>Why this can be risky · assessment</h4>
      <p>If the inserted value can be controlled by an untrusted caller, embedding it in SQL text may let that value change the query's syntax. The scanner confirms dynamic SQL construction, but does not trace the value's origin or prove that an attacker can control it.</p>
    </div>
    <div className="root-cause-block root-cause-history">
      <h4>Git change evidence</h4>
      {history?.status === 'determined' && history.commit ? <>
        <p>The history investigator associated this construction with commit <code>{history.commit.hash}</code> ({history.commit.message || 'no commit message'}) in <code>{history.commit.file}</code>.</p>
        {changedLines.length > 0 && <><p>The relevant added source lines in that commit were:</p><pre className="root-cause-source root-cause-diff-lines">{changedLines.map((line,index)=><span className="root-cause-added-line" key={`${line.newLine}-${index}`}><span>{line.newLine}</span><code>+ {line.text}</code></span>)}</pre></>}
        {!changedLines.length && <p>The source comparison supports this association, but no relevant added line was available to quote from the returned diff.</p>}
        <p>{history.reason}</p>
        <span className="root-cause-evidence-label">Evidence-based association · does not attribute intent or fault.</span>
      </> : history?.status === 'undetermined' ? <>
        <p className="root-cause-uncertain">The introducing commit is uncertain. ProofLayer did not associate this finding with a specific change.</p>
        <p>{history.reason}</p>
      </> : error ? <>
        <p className="root-cause-uncertain">Git history evidence is unavailable, so the change that introduced this code cannot be assessed.</p>
        <p>{error}</p>
      </> : <p>Git history has not been investigated for this finding. Use <b>Investigate Git history</b> below to compare the actual source revisions and commit diff.</p>}
    </div>
  </section>;
}

type DiffDisplayLine = { kind: 'meta' | 'hunk' | 'context' | 'added' | 'removed'; oldLine: number | null; newLine: number | null; text: string; relevant: boolean };

function parseEvidenceDiff(diff: string, findingLine: number, findingEndLine: number): DiffDisplayLine[] {
  let oldLine: number | null = null;
  let newLine: number | null = null;
  const firstRelevantLine = findingLine;
  const lastRelevantLine = findingEndLine;
  return diff.split(/\r?\n/).filter(Boolean).map((text): DiffDisplayLine => {
    const hunk = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(text);
    if (hunk) {
      oldLine = Number(hunk[1]);
      newLine = Number(hunk[3]);
      return {kind:'hunk',oldLine:null,newLine:null,text,relevant:false};
    }
    if (text.startsWith('diff --git ') || text.startsWith('index ') || text.startsWith('--- ') || text.startsWith('+++ ')) return {kind:'meta',oldLine:null,newLine:null,text,relevant:false};
    if (text.startsWith('+') && !text.startsWith('+++')) {
      const number = newLine;
      newLine = newLine === null ? null : newLine + 1;
      return {kind:'added',oldLine:null,newLine:number,text:text.slice(1),relevant:number !== null && number >= firstRelevantLine && number <= lastRelevantLine};
    }
    if (text.startsWith('-') && !text.startsWith('---')) {
      const number = oldLine;
      oldLine = oldLine === null ? null : oldLine + 1;
      return {kind:'removed',oldLine:number,newLine:null,text:text.slice(1),relevant:false};
    }
    if (text.startsWith('\\')) return {kind:'meta',oldLine:null,newLine:null,text,relevant:false};
    if (text.startsWith(' ')) {
      const oldNumber = oldLine;
      const newNumber = newLine;
      oldLine = oldLine === null ? null : oldLine + 1;
      newLine = newLine === null ? null : newLine + 1;
      return {kind:'context',oldLine:oldNumber,newLine:newNumber,text:text.slice(1),relevant:newNumber !== null && newNumber >= firstRelevantLine && newNumber <= lastRelevantLine};
    }
    return {kind:'meta',oldLine:null,newLine:null,text,relevant:false};
  });
}

function EvidenceDiff({diff,findingLine,findingEndLine}:{diff:string;findingLine:number;findingEndLine:number}) {
  const lines=parseEvidenceDiff(diff,findingLine,findingEndLine);
  return <div className="evidence-diff" role="region" aria-label="Relevant Git diff" tabIndex={0}>{lines.map((line,index)=><div className={`evidence-diff-line evidence-diff-${line.kind}${line.relevant?' evidence-diff-relevant':''}`} key={`${index}-${line.kind}`}>
    {line.kind==='meta'||line.kind==='hunk' ? <><span className="evidence-diff-marker"/><code>{line.text}</code></> : <><span className="evidence-diff-old-number">{line.oldLine ?? ''}</span><span className="evidence-diff-new-number">{line.newLine ?? ''}</span><span className="evidence-diff-marker">{line.kind==='added'?'+':line.kind==='removed'?'-':' '}</span><code>{line.text || ' '}</code></>}
  </div>)}</div>;
}

function GitHistoryResultView({result,finding}:{result:GitHistoryInvestigation;finding:Finding}) {
  if(result.status==='undetermined') return <section className="git-history-result git-history-unknown" aria-live="polite"><h3>Introducing commit could not be determined.</h3><p>{result.reason}</p><span>{result.historyCommitsExamined} historical commits examined.</span></section>;
  if(!result.commit||!result.evidence) return null;
  return <section className="git-history-result" aria-live="polite"><div className="git-history-title"><GitCommitHorizontal size={16}/><h3>Git Evidence · likely introducing commit</h3></div><div className="git-history-meta"><div><span>FULL COMMIT HASH</span><code>{result.commit.hash}</code></div><div><span>COMMIT MESSAGE</span><b>{result.commit.message || '(no commit message)'}</b></div><div><span>AUTHOR</span><b>{result.commit.author}</b></div><div><span>COMMIT DATE</span><b>{new Date(result.commit.date).toLocaleString()}</b></div><div><span>AFFECTED FILE</span><code>{result.commit.file}</code></div></div><div className="git-history-why"><b>What changed and why it matters</b><p>{result.reason}</p><p>The finding concerns {finding.pattern.toLowerCase()} reaching <code>{finding.sink}()</code>. Dynamic values embedded in SQL text can alter the query structure; parameterized values keep data separate from SQL syntax.</p><span>{result.historyCommitsExamined} historical commits examined · source retrieved from actual Git revisions.</span></div><div className="git-history-evidence"><h4>Before code <span>{result.evidence.parentHash ? `· parent ${result.evidence.parentHash.slice(0,12)}` : '· original source unavailable'}</span></h4><pre className="evidence-source">{result.evidence.before}</pre><h4>After code <span>· commit {result.commit.hash.slice(0,12)}</span></h4><pre className="evidence-source">{result.evidence.after}</pre><div className="evidence-diff-heading"><h4>Actual Git diff</h4><div className="evidence-diff-legend"><span className="legend-added">+ added</span><span className="legend-removed">− removed</span><span className="legend-relevant">highlighted: finding lines</span></div></div>{result.evidence.diff ? <EvidenceDiff diff={result.evidence.diff} findingLine={result.evidence.findingLine} findingEndLine={result.evidence.findingEndLine}/> : <p className="evidence-limitation">Git returned no printable diff for the relevant source range. The source comparison is available above.</p>}{result.evidence.diffTruncated&&<span>The displayed relevant Git diff was truncated.</span>}{!result.evidence.parentHash&&<p className="evidence-limitation">The parent revision is unavailable, so ProofLayer cannot show original before code.</p>}</div></section>;
}

function SuggestedPatchView({result,onApply,onReject,onVerify,verification,verificationError,verifying,reviewing}:{result:PatchSuggestion;onApply:()=>void;onReject:()=>void;onVerify:()=>void;verification?:FixVerification;verificationError?:string;verifying:boolean;reviewing:boolean}) {
  const review=result.review;
  const statusLabel=review?.status==='pending'?'Awaiting decision':review?.status==='applied'?'Applied':review?.status==='rejected'?'Rejected':review?.status==='stale'?'File changed':review?.status==='error'?'Not applied':'Review unavailable';
  return <section className={`suggested-patch${result.status==='unavailable'?' suggested-patch-unavailable':''}`} aria-live="polite">
    <div className="suggested-patch-title"><Code2 size={15}/><h3>Suggested Patch</h3><span>{result.status==='suggested'?statusLabel:'No safe patch generated'}</span></div>
    <div className="suggested-patch-meta"><span>FILE <code>{result.file}</code></span><span>ORIGINAL LINE <code>{result.line}</code></span></div>
    <p>{result.reason}</p>
    {result.status==='suggested'&&<div className="patch-code-legend"><span className="legend-removed">− Original vulnerable code</span><span className="legend-added">+ Suggested secure code</span></div>}
    {result.status==='suggested' && result.diff
      ? <EvidenceDiff diff={result.diff} findingLine={result.line} findingEndLine={result.line}/>
      : <div className="suggested-patch-limitation">No diff was generated. ProofLayer only suggests a change when the source shows a supported database API and a safe value position.</div>}
    {review&&<><div className={`patch-review-message patch-review-${review.status}`} role="status">{review.message}</div>{review.status==='pending'&&<div className="patch-review-actions"><button className="danger-button" onClick={onReject} disabled={reviewing}>{reviewing?'Saving…':'Reject Patch'}</button><button className="primary-button" onClick={onApply} disabled={reviewing}>{reviewing?<span className="spinner"/>:'Apply Patch'}</button></div>}</>}
    {review?.status==='applied'&&<section className="fix-verification" aria-live="polite"><div className="fix-verification-heading"><div><h3>Rescan and Fix Verification</h3><p>Run the SQL injection scanner again against the connected repository.</p></div><button className="secondary-button" onClick={onVerify} disabled={verifying}>{verifying?<span className="spinner"/>:<Play size={13}/>} {verifying?'Rescanning…':'Rescan Repository'}</button></div>
      {verificationError&&<div className="error-message history-error" role="alert"><X size={14}/>{verificationError}</div>}
      {verification&&<><div className={`verification-result verification-${verification.status.toLowerCase().replaceAll(' ','-')}`}><b>{verification.status}</b><span>{verification.explanation}</span></div><div className="verification-comparison"><div><span>ORIGINAL FINDING</span><b>{verification.originalFinding.title}</b><code>{verification.originalFinding.file}:{verification.originalFinding.line}</code><pre>{verification.originalFinding.code}</pre></div><div><span>NEW SCAN RESULT</span><b>{verification.newScan.finding?`${verification.newScan.finding.pattern} detected`:'No matching finding detected'}</b><code>{verification.newScan.finding?`${verification.newScan.finding.file}:${verification.newScan.finding.line}`:`${verification.newScan.scannedFiles} files scanned · ${new Date(verification.newScan.startedAt).toLocaleString()}`}</code>{verification.newScan.finding?<pre>{verification.newScan.finding.code}</pre>:verification.newScan.skippedReason&&<p>Skipped: {verification.newScan.skippedReason}</p>}</div></div><div className="verification-pattern">Vulnerable code pattern remains: <b>{verification.vulnerablePatternRemains==='yes'?'Yes':verification.vulnerablePatternRemains==='no'?'No':'Unknown'}</b></div></>}
    </section>}
    {result.status==='suggested'&&!review&&<div className="suggested-patch-limitation">The review record could not be created. Generate a fresh suggestion before taking action.</div>}
    <span className="suggested-patch-readonly">A patch is never applied without the separate confirmation dialog.</span>
  </section>;
}
