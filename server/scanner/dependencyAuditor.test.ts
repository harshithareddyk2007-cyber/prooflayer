import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { scanNpmDependencies, parseNpmLockData } from './dependencyAuditor.js';

const rootManifest={name:'fixture',version:'1.0.0',dependencies:{express:'^4.17.0'},devDependencies:{'body-parser':'^1.0.0'}};
const rootLock={lockfileVersion:3,packages:{'':{name:'fixture'},'node_modules/express':{version:'4.17.1'},'node_modules/body-parser':{version:'1.20.0',dev:true},'node_modules/express/node_modules/ms':{version:'2.0.0'}}};

async function fixture(files:Record<string,string>={}) {
  const directory=await mkdtemp(path.join(process.cwd(),'..','prooflayer-dependency-fixture-'));
  for(const [name,contents] of Object.entries(files)){const destination=path.join(directory,name);await mkdir(path.dirname(destination),{recursive:true});await writeFile(destination,contents,'utf8');}
  return directory;
}

test('npm lockfile parsing identifies scoped, nested, direct and development dependencies',()=>{
  const parsed=parseNpmLockData({dependencies:{'@scope/pkg':'1.0.0'},devDependencies:{tool:'2.0.0'}},{lockfileVersion:3,packages:{'node_modules/@scope/pkg':{version:'1.0.0'},'node_modules/tool':{version:'2.0.0',dev:true},'node_modules/tool/node_modules/ms':{version:'2.1.0'}}});
  assert.equal(parsed.entries.find(entry=>entry.name==='@scope/pkg')?.path,'node_modules/@scope/pkg');
  assert.deepEqual([...parsed.directNames].sort(),['@scope/pkg','tool']);
  assert.equal(parsed.entries.find(entry=>entry.name==='ms')?.path,'node_modules/tool/node_modules/ms');
});

test('dependency scan reports advisory details from OSV responses',async()=>{
  const directory=await fixture({'package.json':JSON.stringify(rootManifest),'package-lock.json':JSON.stringify(rootLock)});
  try {
    const fetcher:typeof fetch=async(_input,init)=>{
      if(String(_input).includes('/v1/vulns/GHSA-test')) return new Response(JSON.stringify({id:'GHSA-test',summary:'Example vulnerability',aliases:['CVE-2099-1234'],modified:'2025-01-01T00:00:00Z',database_specific:{severity:'HIGH'},affected:[{ranges:[{events:[{introduced:'0'},{fixed:'4.18.3'}]}]}],references:[{type:'ADVISORY',url:'https://example.test/advisory'}]}),{status:200,headers:{'content-type':'application/json'}});
      const body=JSON.parse(String(init?.body)) as {queries:Array<{package:{name:string;ecosystem:string};version:string}>};
      assert.equal(body.queries.length,3);
      assert.ok(body.queries.every(item=>item.package.ecosystem==='npm'));
      return new Response(JSON.stringify({results:body.queries.map(item=>item.package.name==='express'?{vulns:[{id:'GHSA-test',modified:'2025-01-01T00:00:00Z'}]}:{} )}),{status:200,headers:{'content-type':'application/json'}});
    };
    const result=await scanNpmDependencies(directory,fetcher);
    assert.equal(result.dependencyCount,3);
    assert.equal(result.directCount,2);
    assert.equal(result.transitiveCount,1);
    assert.equal(result.vulnerableCount,1);
    const vulnerable=result.dependencies.find(item=>item.name==='express');
    assert.equal(vulnerable?.status,'vulnerable');
    assert.equal(vulnerable?.advisories[0]?.severity,'High');
    assert.deepEqual(vulnerable?.advisories[0]?.fixedVersions,['4.18.3']);
    assert.equal(vulnerable?.advisories[0]?.url,'https://example.test/advisory');
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('OSV service failures preserve the inventory and mark results inconclusive',async()=>{
  const directory=await fixture({'package.json':JSON.stringify(rootManifest),'package-lock.json':JSON.stringify(rootLock)});
  try {
    const fetcher:typeof fetch=async()=>new Response('unavailable',{status:503});
    const result=await scanNpmDependencies(directory,fetcher);
    assert.equal(result.dependencyCount,3);
    assert.equal(result.vulnerableCount,0);
    assert.equal(result.inconclusiveCount,3);
    assert.match(result.notice??'',/inconclusive/i);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('repositories without npm lockfiles receive a clear unsupported-scope result',async()=>{
  const directory=await fixture({'package.json':JSON.stringify(rootManifest)});
  try {
    const fetcher:typeof fetch=async()=>{throw new Error('OSV should not be called');};
    const result=await scanNpmDependencies(directory,fetcher);
    assert.equal(result.lockfile,null);
    assert.equal(result.dependencyCount,0);
    assert.match(result.notice??'',/No npm lockfile/i);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('advisory detail failures and paginated query responses are not reported as clean',async()=>{
  const directory=await fixture({'package.json':JSON.stringify(rootManifest),'package-lock.json':JSON.stringify(rootLock)});
  try {
    const fetcher:typeof fetch=async(input,init)=>{
      if(String(input).includes('/v1/vulns/'))return new Response('unavailable',{status:503});
      const body=JSON.parse(String(init?.body)) as {queries:Array<{package:{name:string}} >};
      return new Response(JSON.stringify({results:body.queries.map(item=>item.package.name==='express'?{vulns:[{id:'GHSA-detail-fail'}]}:item.package.name==='ms'?{vulns:[],next_page_token:'next-page'}:{})}),{status:200,headers:{'content-type':'application/json'}});
    };
    const result=await scanNpmDependencies(directory,fetcher);
    assert.equal(result.inconclusiveCount,2);
    assert.equal(result.dependencies.find(item=>item.name==='body-parser')?.status,'no-known-vulnerabilities');
    assert.equal(result.dependencies.find(item=>item.name==='express')?.status,'inconclusive');
    assert.equal(result.dependencies.find(item=>item.name==='ms')?.status,'inconclusive');
    assert.match(result.notice??'',/could not be checked/i);
  } finally {await rm(directory,{recursive:true,force:true});}
});
