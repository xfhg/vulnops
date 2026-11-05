"""Deterministic native-hook/IPC fixtures; no model, target, or saved scan execution."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = (ROOT / ".omp/guards/advantage-native.mjs").as_uri()
GUARD = (ROOT / ".omp/guards/target-readonly.ts").as_uri()


@unittest.skipUnless(shutil.which("node"), "Node is required for native guard fixtures")
class AdvantageSessionGuardTests(unittest.TestCase):
    def node(self, program):
        result = subprocess.run(
            ["node", "--input-type=module", "-e", program],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_effective_route_and_main_identity_control_in_session_entry(self):
        self.node(r'''
import assert from 'node:assert/strict';
import guard from GUARD_PATH;
const handlers = new Map();
let effort = 'high';
guard({setLabel() {}, on(name, callback) {
  const list = handlers.get(name) ?? []; list.push(callback); handlers.set(name, list);
}, events: {on() {}}, getThinkingLevel() {return effort}});
process.env.VULNOPS_MODEL_ROUTING = JSON.stringify({controllers: {advantage: 'fixture/controller:high'}});
const event = {toolName: 'bash', input: {command: 'python3 scripts/init-advantage.py --in-session audit-run'}};
const outcomes = [];
for (const [kind, provider, id, thinking] of [
  ['main', 'fixture', 'controller', 'high'], ['main', 'fixture', 'different', 'high'],
  ['main', 'fixture', 'controller', 'medium'], ['sub', 'fixture', 'controller', 'high'],
]) {
  effort = thinking;
  const results = await Promise.all(handlers.get('tool_call').map(fn => fn(event, {agent: {kind}, model: {provider, id}})));
  outcomes.push(results.some(result => result?.block === true));
}
assert.deepEqual(outcomes, [false, true, true, true]);
const supplied = {toolName: 'bash', input: {command: 'VULNOPS_ADVANTAGE_CALL=forged python3 scripts/validate-advantage.py'}};
assert.ok((await Promise.all(handlers.get('tool_call').map(fn => fn(supplied, {agent: {kind:'main'}})))).some(r=>r?.block));
'''.replace("GUARD_PATH", json.dumps(GUARD)))

    def test_actual_execution_and_strict_terminal_delivery_are_distinct(self):
        self.node(r'''
import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync, rmSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {NativeInvocation, literalArgv} from HELPER;
const dir = mkdtempSync(path.join(os.tmpdir(), 'advantage-native-'));
try {
  const input = path.join(dir, 'input.json'), packet = path.join(dir, 'packet.json');
  writeFileSync(input, '{}'); writeFileSync(packet, '{}');
  const context = {input_path:input,scan_base:dir,run_id:'fresh',launcher_session_id:'host',model_routing:{controllers:{advantage:'fixture/model:high'},agents:{worker:'fixture/model:high',planner:'fixture/model:high'}}};
  const live = new NativeInvocation(context, 'Main');
  const root = {id:'Main',kind:'main',selector:'fixture/model:high'};
  // The reported incident: 38 actual publications; 20 planned tasks and four
  // imagined retries have no native start and cannot become failed attempts.
  for (let i=0;i<38;i++) {
    const id=`TASK-${i}`;
    live.start({id,phase:'investigation',cohort:'original',input:packet,actor:'worker'},id,'worker','fixture/model:high');
    const draft=path.join(dir, `${id}.json`); writeFileSync(draft, JSON.stringify({id}));
    live.yield(id,{artifact:draft},true);
    live.settle(id,'completed',{mode:'strict',status:'valid'});
  }
  for (let i=38;i<58;i++) live.settle(`TASK-${i}`,'failed');
  for (let i=0;i<4;i++) live.settle(`UNLAUNCHED-RETRY-${i}`,'failed');
  assert.equal(live.call(root,'investigation').workers.length,38);
  assert.ok(live.call(root,'investigation').workers.every(w=>w.status==='completed' && w.attempt===1));
  assert.throws(()=>live.accept('investigation',{run_id:'fresh',phase:'investigation',valid:true}),/predecessor/);
  live.accept('baseline',{run_id:'fresh',phase:'baseline',valid:true,deterministic:true});
  live.start({id:'AdvantagePlanning',phase:'planning',cohort:'original',input:packet,actor:'planner'},'Planning','planner','fixture/model:high');
  live.yield('Planning',{artifact:packet},false);
  live.settle('Planning','completed',{mode:'strict',status:'valid'});
  live.accept('planning',{run_id:'fresh',phase:'planning',valid:true});
  // A real failed worker remains a limitation; it does not erase healthy work.
  live.start({id:'FAILED',phase:'investigation',cohort:'original',input:packet,actor:'worker'},'FAILED','worker','fixture/model:high');
  live.settle('FAILED','failed');
  assert.equal(live.call(root,'investigation').workers.filter(w=>w.status==='completed').length,39);
  assert.throws(()=>live.call({id:'Foreign'},'investigation'),/current native descendant/);
  assert.throws(()=>live.call({...root,selector:'wrong/model:high'},'investigation'),/caller route differs/);
  writeFileSync(input,'changed'); assert.throws(()=>live.checkInput(input),/changed invocation/);
  assert.deepEqual(literalArgv("python3 scripts/init-advantage.py 'source path'"),['python3','scripts/init-advantage.py','source path']);
  assert.equal(literalArgv('python3 scripts/init-advantage.py $(cat old)'),null);
  assert.equal(literalArgv('python3 scripts/init-advantage.py source; echo forged'),null);
  live.closed=true; assert.throws(()=>live.call(root,'report'),/ended/);
} finally {rmSync(dir,{recursive:true,force:true});}
'''.replace("HELPER", json.dumps(HELPER)))

    def test_terminal_envelope_does_not_hold_valid_evidence_hostage(self):
        self.node(r'''
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import path from 'node:path'; import os from 'node:os';
import {NativeInvocation} from HELPER;
const dir=mkdtempSync(path.join(os.tmpdir(),'advantage-terminal-failure-'));
try {
  const input=path.join(dir,'input.json'); writeFileSync(input,'{}');
  const live=new NativeInvocation({input_path:input,scan_base:dir,run_id:'fresh',
    model_routing:{agents:{planner:'fixture/model:high'}}},'Main');
  live.accept('baseline',{run_id:'fresh',phase:'baseline',valid:true,deterministic:true});
  const binding={id:'AdvantagePlanning',phase:'planning',cohort:'original',input,actor:'planner'};
  live.start(binding,'FailedPlanner','planner','fixture/model:high');
  live.yield('FailedPlanner',{status:'failed'},true);
  live.settle('FailedPlanner','completed');
  assert.equal(live.canRetry('FailedPlanner'),true);
  live.settle('FailedPlanner','completed',{mode:'strict',status:'valid',data:{status:'failed'}});
  assert.equal(live.workers.get('FailedPlanner').status,'completed');
  assert.equal(live.workers.get('FailedPlanner').yield_valid,false);
  assert.equal(live.canRetry('FailedPlanner'),true);
  const accepted={run_id:'fresh',phase:'planning',valid:true,status:'ok'};
  assert.throws(()=>live.accept('planning',{...accepted,valid:false}),/validator/);
  live.start(binding,'HealthyPlanner','planner','fixture/model:high');
  assert.throws(()=>live.accept('planning',accepted),/running or queued/);
  live.yield('HealthyPlanner',{status:'ok'},true);
  live.settle('HealthyPlanner','completed');
  assert.equal(live.canRetry('HealthyPlanner'),true);
  live.accept('planning',accepted);
  live.start({...binding,id:'InvalidWorker',phase:'investigation'},'InvalidWorker','planner','fixture/model:high');
  live.yield('InvalidWorker',{status:'ok'},true);
  live.settle('InvalidWorker','completed',{mode:'strict',status:'invalid'});
  assert.equal(live.canRetry('InvalidWorker'),true);
  assert.equal(live.canRetry('NeverLaunched'),false);
} finally {rmSync(dir,{recursive:true,force:true});}
'''.replace("HELPER", json.dumps(HELPER)))

    def test_phase_barrier_waits_for_running_and_queued_native_work(self):
        self.node(r'''
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import path from 'node:path'; import os from 'node:os';
import {NativeInvocation} from HELPER;
const dir=mkdtempSync(path.join(os.tmpdir(),'advantage-phase-barrier-'));
try {
  const input=path.join(dir,'input.json'); writeFileSync(input,'{}');
  const context={input_path:input,scan_base:dir,run_id:'fresh',model_routing:{agents:{planner:'fixture/model:high',worker:'fixture/model:high'}}};
  const live=new NativeInvocation(context,'Main');
  live.accept('baseline',{run_id:'fresh',phase:'baseline',valid:true,deterministic:true});
  live.start({id:'AdvantagePlanning',phase:'planning',cohort:'original',input,actor:'planner'},'Planner','planner','fixture/model:high');
  const semantic={run_id:'fresh',phase:'planning',valid:true,status:'ok'};
  assert.equal(live.acceptFromCaller({id:'Planner',kind:'sub'},'planning',semantic),false);
  assert.equal(live.accepted.has('planning'),false);
  assert.throws(()=>live.acceptFromCaller({id:'Main',kind:'main'},'planning',semantic),/running or queued/);
  live.yield('Planner',{status:'ok'},true);
  live.settle('Planner','completed',{mode:'strict',status:'valid'});
  live.start({id:'Child',phase:'planning',cohort:'original',input,actor:'worker'},'Child','worker','fixture/model:high');
  const result={run_id:'fresh',phase:'planning',valid:true,status:'degraded'};
  assert.throws(()=>live.accept('planning',result),/running or queued/);
  assert.throws(()=>live.accept('planning',{...result,deterministic:true}),/running or queued/);
  live.settle('Child','failed');
  const queued={id:'NotLaunched',phase:'planning',runtime_id:'QueuedNativeJob'};
  live.queue('Main:actual-tool-call',[queued]);
  assert.throws(()=>live.accept('planning',result),/running or queued/);
  queued.started=true; // Native lifecycle start can precede child session_start.
  assert.throws(()=>live.accept('planning',result),/running or queued/);
  live.settle('QueuedNativeJob','cancelled');
  assert.equal(queued.terminal,true);
  assert.equal(live.workers.size,2); // Cancellation is not an executed attempt.
  const foreign=new NativeInvocation(context,'Foreign');
  foreign.queue('Foreign:actual-tool-call',[{phase:'planning'}]);
  assert.equal(live.acceptFromCaller({id:'Main',kind:'main'},'planning',result),true);
  assert.equal(live.workers.get('Planner').yield_valid,true);
  assert.equal(live.workers.get('Child').status,'failed');
  assert.throws(()=>live.queue('Main:late-tool-call',[{phase:'planning'}]),/already accepted/);
} finally {rmSync(dir,{recursive:true,force:true});}
'''.replace("HELPER", json.dumps(HELPER)))

    def test_bound_publication_rejection_preserves_native_status_and_admission(self):
        self.node(r'''
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import path from 'node:path'; import os from 'node:os';
import {NativeInvocation} from HELPER;
const dir=mkdtempSync(path.join(os.tmpdir(),'advantage-publication-'));
try {
  for (const [phase,script,actor] of [
    ['investigation','finalize-advantage-investigation.py','vulnops-advantage-investigator'],
    ['final-verification','finalize-advantage-verification.py','vulnops-advantage-verify-one'],
    ['gap-exploration','gap-exploration-worker.py','vulnops-advantage-gap-investigator']]) {
    const input=path.join(dir,'input.json'), packet=path.join(dir,phase,'packets','TASK-001.json');
    mkdirSync(path.dirname(packet),{recursive:true}); writeFileSync(input,'{}'); writeFileSync(packet,'{}');
    const selector='fixture/model:high';
    const live=new NativeInvocation({input_path:input,scan_base:dir,run_id:'fresh',
      model_routing:{controllers:{advantage:selector},agents:{[actor]:selector}}},'Main');
    for (const attempt of [1,2]) {
      const runtimeId=`${phase}-${attempt}`, draftPath=path.join(dir,`${phase}-${attempt}.json`);
      live.start({id:'TASK-001',phase,cohort:'original',input:packet,actor},runtimeId,actor,selector);
      const row=live.workers.get(runtimeId);
      const draft={run_id:'fresh',execution_kind:'advantage',task_id:'TASK-001',finding_id:'TASK-001',attempt,
        packet_sha256:row.input_sha256,actor,model:selector,
        provenance:{execution_id:'fresh',actor,selector}};
      const bytes=attempt===1 ? (phase==='investigation' ? 'not valid JSON'
        : JSON.stringify({...draft,task_id:'WrongClaim',finding_id:'WrongClaim',run_id:'foreign'})) : JSON.stringify(draft);
      writeFileSync(draftPath,bytes);
      live.yield(runtimeId,{artifact:draftPath},true);
      live.settle(runtimeId,'completed',{mode:'strict',status:'valid'});
      const argv=['python3',`scripts/${script}`,...(phase==='gap-exploration'?['admit','--task-id','TASK-001']:[]),
        '--context',input,'--result',draftPath];
      assert.equal(live.publicationBinding(script,argv.slice(0,-2),dir),undefined);
      assert.equal(live.publicationBinding(script,[...argv,'--prepare'],dir),undefined);
      const unbound=path.join(dir,`${phase}-unbound.json`); writeFileSync(unbound,bytes);
      assert.equal(live.publicationBinding(script,[...argv.slice(0,-1),unbound],dir),undefined);
      if (phase==='gap-exploration')
        assert.equal(live.publicationBinding(script,argv.map(value=>value==='TASK-001'?'OtherTask':value),dir),undefined);
      writeFileSync(draftPath,JSON.stringify({...draft,run_id:'foreign'}));
      assert.equal(live.publicationBinding(script,argv,dir),undefined);
      writeFileSync(draftPath,bytes);
      const binding=live.publicationBinding(script,argv,dir); assert.ok(binding);
      writeFileSync(packet,'changed input');
      live.observePublication(binding,{code:1,exited:true});
      assert.equal(row.publicationAdmitted,undefined);
      writeFileSync(packet,'{}');
      live.observePublication(binding,{code:1,exited:false});
      assert.equal(row.publicationAdmitted,undefined);
      live.observePublication(binding,{code:0,exited:true,
        stdout:JSON.stringify({status:attempt===1?'not_admitted':'completed'})});
      assert.equal(row.status,'completed'); assert.equal(row.yield_valid,true);
      assert.equal(live.canRetry(runtimeId),attempt===1);
      live.observePublication(binding,{code:1,exited:true}); // Repeated bad admission cannot poison success.
      assert.equal(row.publicationAdmitted,attempt===1?undefined:true);
      assert.equal(Boolean(live.publicationBinding(script,argv,dir)),attempt===1);
    }
    const published=live.call({id:'Main',kind:'main',selector},phase).workers;
    assert.equal(published.length,2);
    assert.equal(Object.hasOwn(published[1],'publicationAdmitted'),false);
  }
} finally {rmSync(dir,{recursive:true,force:true});}
'''.replace("HELPER", json.dumps(HELPER)))

    def test_terminal_artifact_hash_and_fresh_invocation_do_not_reuse_control(self):
        self.node(r'''
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import path from 'node:path'; import os from 'node:os';
import {NativeInvocation} from HELPER;
const dir=mkdtempSync(path.join(os.tmpdir(),'advantage-binding-'));
try {
  const input=path.join(dir,'input.json'), draft=path.join(dir,'draft.json');
  writeFileSync(input,'{}'); writeFileSync(draft,'{"proof":1}');
  const context={input_path:input,scan_base:dir,run_id:'one',launcher_session_id:'host',model_routing:{agents:{worker:'fixture/model:high'}}};
  const live=new NativeInvocation(context,'Main');
  live.start({id:'TASK-1',phase:'investigation',cohort:'original',input,actor:'worker'},'Task1','worker','fixture/model:high');
  live.yield('Task1',{artifact:'draft.json'},true);
  const before=live.workers.get('Task1').artifact_sha256['draft.json'];
  writeFileSync(draft,'{"proof":2}');
  live.settle('Task1','completed',{mode:'permissive',status:'valid'});
  assert.equal(live.workers.get('Task1').yield_valid,false);
  live.settle('Task1','completed',{mode:'strict',status:'valid'});
  assert.equal(live.workers.get('Task1').artifact_sha256['draft.json'],before);
  const fresh=new NativeInvocation({...context,run_id:'two'},'Main2');
  assert.equal(fresh.workers.size,0); assert.equal(fresh.accepted.size,0);
  assert.throws(()=>fresh.start({id:'TASK-1',phase:'investigation',cohort:'original',input,actor:'worker'},'Task1','worker','fixture/fallback:high'),/route/);
} finally {rmSync(dir,{recursive:true,force:true});}
'''.replace("HELPER", json.dumps(HELPER)))

    def test_native_operation_binding_and_separate_gap_allowance(self):
        self.node(r'''
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {NativeInvocation} from HELPER;
const dir=mkdtempSync(path.join(os.tmpdir(),'advantage-operation-'));
try {
  const input=path.join(dir,'input.json'), original=path.join(dir,'original.json'), gap=path.join(dir,'gap.json');
  writeFileSync(input,'{}');
  writeFileSync(original,JSON.stringify({graph_questions:[{id:'original-question'}]}));
  writeFileSync(gap,JSON.stringify({graph_questions:[{id:'gap-question',owner:'Gap1'}]}));
  const context={input_path:input,scan_base:dir,model_routing:{agents:{worker:'fixture/model:high'}},
    gap_exploration_budget:{max_questions:1,graph_timeout_seconds:120,preparation_timeout_seconds:60}};
  const live=new NativeInvocation(context,'Main');
  live.start({id:'Original1',phase:'investigation',cohort:'original',input:original,actor:'worker'},'Original','worker','fixture/model:high');
  live.start({id:'Gap1',phase:'gap-exploration',cohort:'supplementary',input:gap,actor:'worker'},'Gap','worker','fixture/model:high');
  const first=live.reserve('same-call','codegraph-adapter.py',['--phase','investigation','--owner','Original1','--question','original-question'],{id:'Original'});
  const argv=['--phase','gap-exploration','--owner','Gap1','--question','gap-question'];
  const second=live.reserve('same-call','codegraph-adapter.py',argv,{id:'Gap'});
  assert.notEqual(first.id,second.id);
  assert.equal(second.timeout_seconds,120);
  assert.equal(live.graphQuestions.size,1);
  assert.throws(()=>live.reserve('same-call','codegraph-adapter.py',argv,{id:'Gap'}),/already used/);
  live.settle('Gap','running');
  assert.equal(live.workers.get('Gap').status,'running');
  assert.ok(live.terminalWaiters.has('Gap'));
} finally {rmSync(dir,{recursive:true,force:true});}
'''.replace("HELPER", json.dumps(HELPER)))

    def test_private_environment_uses_confined_shell_and_obeys_cancellation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            shell = root / "scripts/agent-shell.sh"
            shell.write_text('#!/bin/bash\nexport FIXTURE_CONFINEMENT=active\nexec /bin/bash "$@"\n')
            shell.chmod(0o755)
            self.node(r'''
import assert from 'node:assert/strict';
import {confinedCommand} from HELPER;
process.env.VULNOPSV3_ROOT=FIXTURE_ROOT_PATH;
const result=await confinedCommand('printf "%s:%s" "$FIXTURE_CONFINEMENT" "$VULNOPS_ADVANTAGE_CALL"',{timeout:2},{VULNOPS_ADVANTAGE_CALL:'private'});
assert.equal(result.code,0); assert.equal(result.output,'active:private');
assert.equal(process.env.VULNOPS_ADVANTAGE_CALL,undefined);
const payload=JSON.stringify({workers:'x'.repeat(500000)});
const piped=await confinedCommand("python3 -c 'import os; print(os.fdopen(3).read())'",
  {timeout:2,nativeCall:payload},{VULNOPS_ADVANTAGE_CALL:'fd:3'});
assert.equal(piped.code,0); assert.equal(piped.output,payload+'\n');
const controller=new AbortController();
setTimeout(()=>controller.abort(),40);
const cancelled=await confinedCommand('sleep 20',{timeout:25},{},controller.signal);
assert.notEqual(cancelled.code,0);
'''.replace("HELPER", json.dumps(HELPER)).replace("FIXTURE_ROOT_PATH", json.dumps(str(root))))

    def test_standalone_incomplete_exit_survives_print_mode_status_override(self):
        for standalone, native_status, expected in [(True, 0, 1), (True, 17, 17), (False, 0, 0)]:
            with self.subTest(standalone=standalone, native_status=native_status):
                program = r'''
import {installAdvantageNative} from HELPER;
if (STANDALONE) process.env.VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID='fixture-host';
else delete process.env.VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID;
const hooks=new Map();
installAdvantageNative({on(name,fn){hooks.set(name,fn)},events:{on(){}},getAllTools(){return []}});
const ctx={cwd:process.cwd(),agent:{id:'Main',kind:'main'}};
await hooks.get('session_start')({},ctx);
await hooks.get('session_shutdown')({},ctx);
process.on('exit',()=>process.stdout.write('other cleanup ran'));
// Native print mode computes and passes its own final status after disposal.
process.exit(NATIVE_STATUS);
'''.replace("HELPER", json.dumps(HELPER)).replace("STANDALONE", json.dumps(standalone)).replace(
                    "NATIVE_STATUS", str(native_status))
                result = subprocess.run(
                    ["node", "--input-type=module", "-e", program],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertIn("other cleanup ran", result.stdout)

