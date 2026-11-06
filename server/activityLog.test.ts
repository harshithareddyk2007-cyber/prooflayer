import assert from 'node:assert/strict';
import test from 'node:test';
import { ActivityLog } from './activityLog.js';

test('activity log records typed events newest first and filters the returned limit',()=>{
  const log=new ActivityLog();
  const first=log.record({category:'repository',status:'success',title:'Repository connected',details:'Connected sample.',repository:'sample'});
  const second=log.record({category:'security',status:'warning',title:'Scan completed',details:'One finding.',repository:'sample'});
  const events=log.list(1);
  assert.equal(events.length,1);
  assert.equal(events[0]?.id,second.id);
  assert.equal(events[0]?.category,'security');
  assert.ok(new Date(first.occurredAt).getTime()<=new Date(second.occurredAt).getTime());
});

test('activity log is bounded to the latest 500 events',()=>{
  const log=new ActivityLog();
  for(let index=0;index<503;index++) log.record({category:'security',status:'info',title:`Event ${index}`,details:'fixture',repository:null});
  const events=log.list(700);
  assert.equal(events.length,500);
  assert.equal(events[0]?.title,'Event 502');
  assert.equal(events.at(-1)?.title,'Event 3');
});
