// Local synthetic evidence. Version 3 stores bounded, normalized metadata only.
import {DatabaseSync} from 'node:sqlite';
import {openSync, closeSync, readFileSync, readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {validateArtifactFile} from './artifact-path.mjs';
const fixtures=new Set(['valid','invalid_schema','denied','unknown']);
const statuses=new Set(['pass','fail','error']);
const reasons=new Set(['timeout_unknown','timeout_child_terminated','timeout_late_completed','timeout_already_exited','timeout_not_started','evaluation_error']);
const dispositions=new Set(['terminated','late_completed','already_exited','not_started']);
const observations=new Set(['accepted','forbidden','invalid_input','unknown_operation','unmeasured']);
const uuid=/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const digest=/^[0-9a-f]{64}$/;
function requireValue(ok) {if(!ok) throw Error('invalid evidence');}
function limited(value,max=28) {requireValue(Number.isSafeInteger(value)&&value>=0&&value<=max);return value;}
function fixture(value) {requireValue(fixtures.has(value));return value;}
function expectedFixtureNames(seed,length) {
  const result=[];
  for(let group=0;group<length/4;group++) {
    let x=(seed+group)>>>0;
    const order=['valid','invalid_schema','denied','unknown'];
    for(let i=3;i>0;i--) {x=(Math.imul(x,1664525)+1013904223)>>>0;const j=x%(i+1);[order[i],order[j]]=[order[j],order[i]];}
    result.push(...order);
  }
  return result;
}
function id(value) {requireValue(typeof value==='string'&&uuid.test(value));return value;}
function timestamp(value) {requireValue(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value));return value;}
function outcome(o) {
  requireValue(o&&statuses.has(o.status)&&typeof o.elapsedMs==='number'&&Number.isFinite(o.elapsedMs)&&o.elapsedMs>=0&&o.elapsedMs<=86400000);
  const x={fixture:fixture(o.fixture),correlationId:id(o.correlationId),status:o.status,elapsedMs:o.elapsedMs};
  if(o.status==='error') {requireValue(reasons.has(o.reason));x.reason=o.reason;}
  else requireValue(o.reason===undefined&&o.termination===undefined);
  if(o.termination!==undefined) {
    const t=o.termination;
    requireValue(t&&dispositions.has(t.disposition)&&(t.pid===null||(Number.isSafeInteger(t.pid)&&t.pid>0))&&(t.sequence===null||(Number.isSafeInteger(t.sequence)&&t.sequence>=0&&t.sequence<28))&&typeof t.killRequested==='boolean'&&typeof t.exitObserved==='boolean'&&typeof t.normalExited==='boolean');
    const byDisposition={terminated:'timeout_child_terminated',late_completed:'timeout_late_completed',already_exited:'timeout_already_exited',not_started:'timeout_not_started'};
    requireValue(o.status==='error'&&o.reason===byDisposition[t.disposition]);
    if(t.disposition==='not_started') requireValue(t.pid===null&&t.sequence===null&&!t.killRequested&&!t.exitObserved&&!t.normalExited);
    else {
      requireValue(t.pid!==null&&t.sequence!==null&&t.exitObserved);
      if(t.disposition==='terminated') requireValue(t.killRequested&&!t.normalExited);
      if(t.disposition==='late_completed') requireValue(!t.killRequested&&t.normalExited);
    }
    x.termination={disposition:t.disposition,pid:t.pid,sequence:t.sequence,killRequested:t.killRequested,exitObserved:t.exitObserved,normalExited:t.normalExited};
  } else if(o.status==='error') requireValue(o.reason==='timeout_unknown'||o.reason==='evaluation_error');
  const response=v=>{requireValue(v&&(v.ok===null||typeof v.ok==='boolean')&&observations.has(v.reason));return {ok:v.ok,reason:v.reason};};
  x.observed={ordinary:response(o.observed?.ordinary),secure:response(o.observed?.secure)};
  return x;
}
function packed(value) {const s=JSON.stringify(value);requireValue(Buffer.byteLength(s,'utf8')<=8192);return s;}
export function stateDigest(state) {
  if(!state||typeof state!=='object'||Array.isArray(state)||Object.keys(state).length>4||Object.entries(state).some(([k,v])=>!/^case(?:[0-9]|1[0-9]|2[0-7])$/.test(k)||v!=='hello')) return null;
  return createHash('sha256').update(JSON.stringify(Object.entries(state).sort())).digest('hex');
}
export function sourceMetadata() {
  const files=['mixed-runner.mjs','local-comparison.mjs','sqlite-evidence.mjs','run-local.mjs','process-comparison.mjs','fixture-process.mjs','artifact-path.mjs'];
  const hash=createHash('sha256');
  for(const name of files) {hash.update(name+'\0');hash.update(readFileSync(new URL(name,import.meta.url)));}
  const sdk=new URL('../../sdks/javascript/src/',import.meta.url);
  for(const name of readdirSync(sdk).filter(x=>x.endsWith('.js')).sort()) {hash.update('sdk/'+name+'\0');hash.update(readFileSync(new URL(name,sdk)));}
  let commit='unavailable';
  try {
    const git=join(fileURLToPath(new URL('../..',import.meta.url)),'.git');
    const head=readFileSync(join(git,'HEAD'),'utf8').trim();
    let value=head;
    if (head.startsWith('ref: ')) {
      const ref=head.slice(5);
      if (!/^refs\/heads\/[A-Za-z0-9._/-]+$/.test(ref)||ref.includes('..')) throw Error('unsupported ref');
      try {value=readFileSync(join(git,ref),'utf8').trim();}
      catch {value=readFileSync(join(git,'packed-refs'),'utf8').split(/\r?\n/).find(line=>line.endsWith(' '+ref))?.split(' ')[0]??'';}
    }
    if(/^[0-9a-f]{40}$/.test(value)) commit=value;
  } catch {}
  return {sourceCommit:commit,sourceHash:hash.digest('hex'),runtime:process.version,fixtureVersion:1};
}
export function createEvidence(path) {
  if (typeof path !== 'string' || !path || path === ':memory:') throw new TypeError('new evidence file path required');
  path=validateArtifactFile(path);
  const fd=openSync(path,'wx'); closeSync(fd);
  const db=new DatabaseSync(path);
  db.exec(`PRAGMA application_id=1396789321; PRAGMA user_version=3;
    CREATE TABLE runs (run_id TEXT PRIMARY KEY, source TEXT NOT NULL CHECK(source='synthetic_fixture'), status TEXT NOT NULL, metadata TEXT NOT NULL, summary TEXT);
    CREATE TABLE events (run_id TEXT NOT NULL REFERENCES runs(run_id), seq INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run_id,seq));`);
  db.exec('PRAGMA foreign_keys=ON');
  const start=db.prepare('INSERT INTO runs(run_id,source,status,metadata) VALUES(?,?,?,?)');
  const event=db.prepare('INSERT INTO events(run_id,seq,kind,payload) VALUES(?,?,?,?)');
  const finish=db.prepare('UPDATE runs SET status=?, summary=? WHERE run_id=? AND status=\'running\'');
  let seq=0, runId=null, done=false, plan=[], pending=null, expectedState={}; const completed=[], seen=new Set();
  return {
    version:3,
    start(meta) {
      if(runId) throw Error('already started');
      const code=sourceMetadata();requireValue(digest.test(code.sourceHash));
      requireValue(Array.isArray(meta.planned)&&meta.planned.length>=4&&meta.planned.length<=28&&meta.planned.length%4===0);
      requireValue(['in_process_observed','process_callback_unverified'].includes(meta.timeoutMode));
      const m={version:3,runId:id(meta.runId),inputSource:'synthetic_fixture',targetProvenance:'unverified_callback',seed:limited(meta.seed,0xffffffff),planned:meta.planned.map(fixture),startedUtc:timestamp(meta.startedUtc),timeoutMode:meta.timeoutMode,...code};
      requireValue(JSON.stringify(m.planned)===JSON.stringify(expectedFixtureNames(m.seed,m.planned.length)));
      start.run(m.runId,'synthetic_fixture','running',packed(m));runId=m.runId;plan=m.planned;
    },
    event(kind,payload) {
      if(!runId||done) throw Error('run unavailable');
      requireValue(['started','result'].includes(kind));
      let p={index:limited(payload.index,27),group:limited(payload.group,6),fixture:fixture(payload.fixture)};
      requireValue(p.index===completed.length&&p.index<plan.length&&p.group===Math.floor(p.index/4)&&p.fixture===plan[p.index]);
      if(kind==='started') {
        p={...p,correlationId:id(payload.correlationId),startedUtc:timestamp(payload.startedUtc)};
        requireValue(!pending&&!seen.has(p.correlationId));
      } else {
        p={...p,result:outcome(payload.result),finishedUtc:timestamp(payload.finishedUtc)};
        requireValue(pending&&p.result.correlationId===pending.correlationId&&p.result.fixture===pending.fixture);
        if(p.result.termination?.sequence!==null&&p.result.termination?.sequence!==undefined) requireValue(p.result.termination.sequence===p.index);
        if(p.index%4===0) expectedState={};
        if(p.result.status==='pass') {
          const expectedReasons={valid:'accepted',invalid_schema:'invalid_input',denied:'forbidden',unknown:'unknown_operation'};
          const expectedReason=expectedReasons[p.fixture],expectedOk=p.fixture==='valid';
          for(const side of ['ordinary','secure']) requireValue(p.result.observed[side].ok===expectedOk&&p.result.observed[side].reason===expectedReason);
          const expectedAfter={...expectedState};if(expectedOk) expectedAfter['case'+p.index]='hello';
          const proof=payload.stateProof;
          requireValue(proof&&proof.beforeOrdinary===stateDigest(expectedState)&&proof.beforeSecure===stateDigest(expectedState)&&proof.afterOrdinary===stateDigest(expectedAfter)&&proof.afterSecure===stateDigest(expectedAfter));
          p.stateProof={beforeOrdinary:proof.beforeOrdinary,beforeSecure:proof.beforeSecure,afterOrdinary:proof.afterOrdinary,afterSecure:proof.afterSecure};
          expectedState=expectedAfter;
        }
      }
      event.run(runId,++seq,kind,packed(p));
      if(kind==='started') {pending=p;seen.add(p.correlationId);} else {completed.push(p.result);pending=null;}
    },
    finish(summary) {
      if(!runId||done) throw Error('run unavailable');
      requireValue(summary.runId===runId&&typeof summary.stopped==='boolean'&&typeof summary.pass==='boolean'&&Array.isArray(summary.outcomes)&&summary.outcomes.length<=28&&Array.isArray(summary.omittedFixtures)&&summary.omittedFixtures.length<=28);
      const s={version:3,runId,planned:limited(summary.planned),completed:limited(summary.completed),omitted:limited(summary.omitted),omittedFixtures:summary.omittedFixtures.map(fixture),stopped:summary.stopped,outcomes:summary.outcomes.map(outcome),pass:summary.pass};
      requireValue(!pending&&s.planned===plan.length&&s.completed===completed.length&&s.omitted===plan.length-completed.length&&JSON.stringify(s.outcomes)===JSON.stringify(completed)&&JSON.stringify(s.omittedFixtures)===JSON.stringify(plan.slice(completed.length)));
      requireValue(s.pass===(!s.stopped&&s.omitted===0&&completed.every(x=>x.status==='pass')));
      requireValue(s.stopped||s.omitted===0);
      const encoded=packed(s);db.exec('BEGIN IMMEDIATE');
      try { event.run(runId,++seq,'finish',encoded); const r=finish.run(s.pass?'fixture_consistent':'incomplete',encoded,runId); if(r.changes!==1) throw Error('run state conflict'); db.exec('COMMIT'); done=true; }
      catch(e) {db.exec('ROLLBACK'); throw e;}
    },
    close() {db.close();}
  };
}
// Read only a bounded summary; do not expose legacy raw event payloads.
export function readEvidenceSummary(path) {
  const db=new DatabaseSync(path,{readOnly:true});
  try {
    const app=db.prepare('PRAGMA application_id').get().application_id;
    const version=db.prepare('PRAGMA user_version').get().user_version;
    requireValue(app===1396789321&&[1,2,3].includes(version));
    const counts=db.prepare('SELECT count(*) AS runs FROM runs').get().runs;
    const events=db.prepare('SELECT count(*) AS events FROM events').get().events;
    return {version,runs:counts,events};
  } finally {db.close();}
}
