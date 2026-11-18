import { createHash } from "node:crypto";
import { readFileSync, realpathSync, lstatSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import os from "node:os";
// Rebound OMP factories share this module, but never serialize its live maps.
// Lifecycle starts, not task declarations or queued jobs, establish execution.
const phases = ["baseline", "planning", "investigation", "gap-exploration", "synthesis", "final-verification", "handoff", "report"];
const phaseActors = {
  planning: "vulnops-advantage-planning",
  investigation: "vulnops-advantage-investigation",
  "gap-exploration": "vulnops-advantage-gap-exploration",
  synthesis: "vulnops-advantage-synthesis",
  "final-verification": "vulnops-advantage-final-verification",
  handoff: "vulnops-advantage-investigation"
};
const phaseNames = {
  planning: "AdvantagePlanning",
  investigation: "AdvantageInvestigation",
  "gap-exploration": "AdvantageGapExploration",
  synthesis: "AdvantageSynthesis",
  "final-verification": "AdvantageVerification",
  handoff: "AdvantageHandoff"
};
const cohortNames = { synthesis: "AdvantageSynthesis", "final-verification": "AdvantageReview" };
const commands = {
  "init-advantage.py": "baseline",
  "validate-advantage.py": "baseline",
  "build-advantage-plan.py": "planning",
  "build-advantage-wave.py": "investigation",
  "finalize-advantage-investigation.py": "investigation",
  "finalize-advantage-synthesis.py": "synthesis",
  "finalize-advantage-verification.py": "final-verification",
  "finalize-advantage-handoff.py": "handoff",
  "prepare-advantage-patch.py": "baseline",
  "render-advantage-report.py": "report",
  "prepare-gap-exploration.py": "gap-exploration",
  "gap-exploration-worker.py": "gap-exploration",
  "finalize-gap-exploration.py": "gap-exploration",
  "gap-dossier.py": "synthesis",
  "codegraph-adapter.py": "investigation",
  "run-investigation-experiment.py": "investigation",
  "set-omp-deadline.py": "baseline",
};
const roots = new Map;
const sessions = new Map;
const pending = new Map;
const starting = new Map;
const initializing = new Set;
const ordinaryBaselines = new Map;
// Native session disposal runs after session_shutdown and can recreate a lock
// in a retired task directory. Retain only exact observed cleanup paths until
// final process exit, never execution authority or recoverable workflow state.
const ownedScratch = new Set;
let exitCleanupRegistered = false;
let standaloneExit;
const fileHash = (filename) => createHash("sha256").update(readFileSync(filename)).digest("hex");
const fail = (message) => {
  throw new Error(`[advantage-native] ${message}`);
};
const under = (base, filename) => filename === base || filename.startsWith(base + path.sep);
export function literalArgv(command) {
  const argv = [];
  let word = "", quote = "", started = false;
  for (let i = 0;i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      if (ch === quote)
        quote = "";
      else {
        if (quote === '"' && /[$`\\]/.test(ch))
          return null;
        word += ch;
      }
      started = true;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
    } else if (/\s/.test(ch)) {
      if (started) {
        argv.push(word);
        word = "";
        started = false;
      }
    } else if (/[;&|<>`$()\\]/.test(ch))
      return null;
    else {
      word += ch;
      started = true;
    }
  }
  if (quote)
    return null;
  if (started)
    argv.push(word);
  return argv;
}
const argument = (argv, flag) => {
  const i = argv.indexOf(flag);
  return i < 0 ? undefined : argv[i + 1];
};

export class NativeInvocation {
  rootId;
  context;
  accepted = new Set;
  workers = new Map;
  terminalWaiters = new Map;
  scratch = new Set;
  operations = new Set;
  graphQuestions = new Set;
  originalGraphQuestions = new Set;
  gapPlanHash;
  graphSeconds = 0;
  preparationSeconds = 0;
  experimentCount = 0;
  experimentRunning = false;
  closed = false;
  published = false;
  inputHash;
  constructor(context, rootId) {
    this.rootId = rootId;
    this.context = context;
    this.inputHash = fileHash(context.input_path);
  }
  checkInput(filename) {
    if (this.closed || path.resolve(filename) !== this.context.input_path || fileHash(filename) !== this.inputHash)
      fail("stale, foreign, or changed invocation input");
  }
  start(binding, runtimeId, actor, selector) {
    if (this.closed || this.workers.has(runtimeId))
      fail("duplicate or closed native execution");
    if (binding.actor !== actor || selector !== this.context.model_routing.agents[actor])
      fail("native actor route differs");
    const attempt = [...this.workers.values()].filter((row) => row.id === binding.id && row.cohort === binding.cohort).length + 1;
    const worker = {
      id: binding.id,
      runtime_id: runtimeId,
      phase: binding.phase,
      cohort: binding.cohort,
      actor,
      selector,
      attempt,
      status: "running",
      yield_valid: false,
      artifacts: [],
      artifact_sha256: {},
      input_sha256: fileHash(binding.input),
      input: binding.input,
      terminalYield: false,
      yieldFailed: false
    };
    this.workers.set(runtimeId, worker);
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    this.terminalWaiters.set(runtimeId, { promise, resolve });
  }
  yield(runtimeId, data, terminal) {
    const worker = this.workers.get(runtimeId);
    if (!worker || !terminal || worker.status !== "running")
      return;
    worker.terminalYield = true;
    worker.yieldFailed = data?.status === "failed";
    worker.artifacts = [];
    worker.artifact_sha256 = {};
    const visit = (value) => {
      if (typeof value === "string") {
        const filename = path.resolve(this.context.scan_base, value);
        if (!under(this.context.scan_base, filename))
          return;
        try {
          if (lstatSync(filename).isFile() && under(realpathSync(this.context.scan_base), realpathSync(filename))) {
            worker.artifact_sha256[value] = fileHash(filename);
            worker.artifacts.push(value);
          }
        } catch {}
      } else if (Array.isArray(value))
        value.forEach(visit);
      else if (value && typeof value === "object")
        Object.values(value).forEach(visit);
    };
    visit(data);
  }
  publicationBinding(script, argv, cwd) {
    const phase = { "finalize-advantage-investigation.py": "investigation",
      "finalize-advantage-verification.py": "final-verification",
      "finalize-advantage-synthesis.py": "synthesis",
      "gap-exploration-worker.py": "gap-exploration" }[script];
    if (!phase || this.accepted.has(phase)) return;
    const options = new Map;
    let admit = false;
    for (let index = 2; index < argv.length; index++) {
      const flag = argv[index];
      if (phase === "gap-exploration" && flag === "admit" && !admit) { admit = true; continue; }
      if (!(phase === "synthesis" ? ["--context", "--draft", "--stage"]
          : ["--context", "--result", ...(phase === "gap-exploration" ? ["--task-id"] : [])]).includes(flag)
          || options.has(flag) || !argv[index + 1]) return;
      options.set(flag, argv[++index]);
    }
    if (!options.has("--context")
        || (phase === "synthesis" ? !options.has("--draft") || options.get("--stage") !== "original"
          : !options.has("--result"))
        || phase === "gap-exploration" && (!admit || !options.has("--task-id"))) return;
    try {
      this.checkInput(path.resolve(cwd, options.get("--context")));
      const filename = realpathSync(path.resolve(cwd, options.get(phase === "synthesis" ? "--draft" : "--result")));
      if (!under(realpathSync(this.context.scan_base), filename)) return;
      const actor = phase === "investigation" ? "vulnops-advantage-investigator"
        : phase === "final-verification" ? "vulnops-advantage-verify-one"
        : phase === "synthesis" ? "vulnops-advantage-synthesis" : "vulnops-advantage-gap-investigator";
      const rows = [...this.workers.values()].filter(row => row.phase === phase && row.actor === actor);
      const matching = rows.filter(row => {
        if (row.status === "running" || row.publicationAdmitted
            || phase === "synthesis" && (row.id !== "AdvantageSynthesisOriginal" || row.cohort !== "original"
              || row.selector !== this.context.model_routing.agents[actor])
            || phase === "gap-exploration" && options.get("--task-id") !== row.id
            || rows.some(other => other.id === row.id && other.attempt > row.attempt)) return false;
        try {
          return realpathSync(row.input) === realpathSync(phase === "synthesis" ? this.context.input_path
              : path.join(this.context.scan_base, phase, "packets", `${row.id}.json`))
            && fileHash(row.input) === row.input_sha256
            && row.artifacts.some(ref => realpathSync(path.resolve(this.context.scan_base, ref)) === filename)
            && row.artifacts.every(ref => fileHash(path.resolve(this.context.scan_base, ref)) === row.artifact_sha256[ref]);
        } catch { return false; }
      });
      // Attribution comes from the actual author and immutable bytes, never
      // the untrusted draft's JSON syntax, claimed task ID, or provenance.
      if (matching.length === 1) return { runtimeId: matching[0].runtime_id, script, argv, cwd };
    } catch {
      // Missing, changed, or foreign bindings are not an attributable
      // terminal worker publication rejection.
      return;
    }
  }
  observePublication(binding, result) {
    if (!binding || !result.exited) return;
    const current = this.publicationBinding(binding.script, binding.argv, binding.cwd);
    if (!current || current.runtimeId !== binding.runtimeId) return;
    const row = this.workers.get(binding.runtimeId);
    if (result.code === 0) {
      try {
        const receipt = JSON.parse(result.stdout);
        if (binding.script === "finalize-advantage-synthesis.py") {
          const ref = "synthesis/original-findings.json";
          if (receipt.status !== "original_complete" || receipt.artifact_ref !== ref) return;
          const root = realpathSync(this.context.scan_base), filename = path.join(this.context.scan_base, ref);
          const resolved = realpathSync(filename);
          if (!lstatSync(filename).isFile() || resolved !== path.join(root, ref) || !under(root, resolved)) return;
          const checksum = fileHash(filename);
          if (!row.artifacts.includes(ref)) row.artifacts.push(ref);
          row.artifact_sha256[ref] = checksum;
          row.publicationAdmitted = true;
        } else if (receipt.status === "completed") row.publicationAdmitted = true;
      } catch {}
    }
  }
  queue(key, assignments) {
    if (assignments.some(binding => this.accepted.has(binding.phase)))
      fail("native assignment phase is already accepted");
    pending.set(key, { owner: this, assignments });
  }
  canRetry(runtimeId) {
    const worker = this.workers.get(runtimeId);
    if (!worker || worker.publicationAdmitted) return false;
    return ["completed", "failed", "cancelled"].includes(worker.status);
  }
  settle(runtimeId, status, structured) {
    if (!["completed", "failed", "cancelled", "aborted"].includes(status))
      return;
    for (const launch of pending.values())
      if (launch.owner === this)
        for (const binding of launch.assignments)
          if (binding.runtime_id === runtimeId) binding.terminal = true;
    const worker = this.workers.get(runtimeId);
    if (!worker) return;
    worker.status = status === "aborted" ? "cancelled" : status;
    if (structured || status !== "completed")
      worker.yield_valid = status === "completed" && worker.terminalYield && !worker.yieldFailed
        && structured?.mode === "strict" && structured?.status === "valid" && structured.data?.status !== "failed";
    if (status !== "completed")
      worker.error = status === "cancelled" || status === "aborted" ? "native execution cancelled" : "native execution failed";
    this.terminalWaiters.get(runtimeId)?.resolve();
    this.terminalWaiters.delete(runtimeId);
  }
  acceptFromCaller(caller, phase, result) {
    if (caller.id !== this.rootId || caller.kind !== "main") return false;
    this.accept(phase, result);
    return true;
  }
  accept(phase, result) {
    if (result.run_id !== this.context.run_id || result.phase !== phase || result.valid !== true)
      fail("validator returned foreign phase identity");
    if ([...this.workers.values()].some(row => row.phase === phase && row.status === "running")
        || [...pending.values()].some(launch => launch.owner === this
          && launch.assignments.some(binding => binding.phase === phase && !binding.terminal)))
      fail("phase still has running or queued native assignments");
    const index = phases.indexOf(phase);
    if (index < 0 || phases.slice(0, index).some((prior) => !this.accepted.has(prior)))
      fail("phase predecessor validation is missing");
    this.accepted.add(phase);
  }
  call(caller, phase, operation) {
    if (this.closed)
      fail("invocation has ended");
    if (caller.id !== this.rootId && !this.workers.has(caller.id))
      fail("caller is not a current native descendant");
    const expected = caller.id === this.rootId ? this.context.model_routing.controllers.advantage
      : this.context.model_routing.agents[this.workers.get(caller.id).actor];
    if (caller.selector !== expected)
      fail("current native caller route differs");
    return {
      run_id: this.context.run_id,
      launcher_session_id: this.context.launcher_session_id,
      context_sha256: this.inputHash,
      phase,
      caller,
      accepted_phases: [...this.accepted],
      workers: [...this.workers.values()].map(({ terminalYield, yieldFailed, input, publicationAdmitted, ...row }) => row),
      ...operation ? { operation } : {}
    };
  }
  reserve(id, command, argv, caller) {
    if (command !== "codegraph-adapter.py" && command !== "run-investigation-experiment.py")
      return;
    id = `${caller.id}:${id}`;
    if (this.operations.has(id))
      fail("native operation binding already used");
    this.operations.add(id);
    if (command === "codegraph-adapter.py") {
      const budget = this.context.gap_exploration_budget;
      const phase = argument(argv, "--phase"), owner = argument(argv, "--owner"), question = argument(argv, "--question");
      if (!owner || !question || !phase)
        fail("graph request lacks exact owner/question");
      if (phase !== "gap-exploration") {
        const worker = this.workers.get(caller.id);
        if (!worker || worker.id !== owner || worker.phase !== phase || fileHash(worker.input) !== worker.input_sha256)
          fail("graph request must belong to the calling native worker and unchanged packet");
        const packet = JSON.parse(readFileSync(worker.input, "utf8"));
        if (!packet.graph_questions?.some(item => item.id === question))
          fail("graph question is absent from the actual native packet");
        const key = `${phase}:${owner}:${question}`;
        if (this.originalGraphQuestions.has(key)) fail("original graph question already executed");
        this.originalGraphQuestions.add(key);
        return { id, kind: "graph", phase, owner_id: owner, question_id: question,
          timeout_seconds: 120, preparation_timeout_seconds: 0, cohort: worker.cohort };
      }
      const worker = this.workers.get(caller.id);
      if (!worker || worker.id !== owner || worker.phase !== phase || fileHash(worker.input) !== worker.input_sha256)
        fail("gap graph request must belong to the actual calling worker");
      const packetPath = owner === phaseNames["gap-exploration"]
        ? path.join(this.context.scan_base, "gap-exploration/plan.json") : worker.input;
      if (owner === phaseNames["gap-exploration"] && (!this.gapPlanHash || fileHash(packetPath) !== this.gapPlanHash))
        fail("gap coordinator graph plan was not admitted by this invocation");
      const packet = JSON.parse(readFileSync(packetPath, "utf8"));
      if (!packet.graph_questions?.some(item => item.id === question && item.owner === owner))
        fail("gap graph question is absent from the actual owner's admitted input");
      const key = `${phase}:${owner}:${question}`;
      if (!this.graphQuestions.has(key) && this.graphQuestions.size >= budget.max_questions)
        fail("current graph question allowance exhausted");
      const timeout = Math.min(120, budget.graph_timeout_seconds - this.graphSeconds);
      const preparation = budget.preparation_timeout_seconds - this.preparationSeconds;
      if (timeout <= 0 || preparation <= 0)
        fail("current graph allowance exhausted");
      this.graphQuestions.add(key);
      this.graphSeconds += timeout;
      this.preparationSeconds += preparation;
      return {
        id,
        kind: "graph",
        phase,
        owner_id: owner,
        question_id: question,
        timeout_seconds: timeout,
        preparation_timeout_seconds: preparation,
        cohort: this.workers.get(caller.id)?.cohort ?? "original"
      };
    }
    const requestPath = argument(argv, "--request");
    if (!requestPath)
      fail("experiment request is missing");
    const absolute = realpathSync(requestPath);
    if (!under(realpathSync(this.context.scan_base), absolute))
      fail("experiment request escapes invocation");
    const request = JSON.parse(readFileSync(absolute, "utf8"));
    const budget = this.context.experiment_budget;
    if (this.context.reproduction_mode === "safe") {
      if (this.experimentRunning || this.experimentCount >= budget.max_experiments)
        fail("current contained experiment allowance unavailable");
      this.experimentRunning = true;
      this.experimentCount++;
    }
    return {
      id,
      kind: "experiment",
      phase: request.owner_phase,
      owner_id: request.owner_id,
      question_id: request.question_id,
      request_ref: path.relative(this.context.scan_base, absolute),
      request_sha256: fileHash(absolute),
      timeout_seconds: budget.timeout_seconds,
      cohort: this.workers.get(caller.id)?.cohort ?? "original"
    };
  }
}
function invocation(ctx) {
  for (const live of roots.values())
    if (!live.closed && (live.rootId === ctx.agent.id || live.workers.has(ctx.agent.id)))
      return live;
}
function caller(ctx, pi) {
  return { ...ctx.agent, selector: ctx.model && `${ctx.model.provider}/${ctx.model.id}:${pi.getThinkingLevel()}` };
}
function observeSnapshot(ctx, live) {
  const snapshot = ctx.getAsyncJobSnapshot?.();
  for (const job of snapshot?.recent ?? []) {
    if (job.type === "task" && job.status !== "running")
      live.settle(job.agentId ?? job.id, job.status);
  }
}
export async function confinedCommand(command, options, env, signal) {
  const root = path.resolve(process.env.VULNOPSV3_ROOT ?? process.cwd());
  const shell = path.join(root, "scripts/agent-shell.sh");
  const timeout = options.timeout === 0 ? 0 : Math.min(options.timeout ?? 300, 3600) * 1000;
  if (signal?.aborted)
    fail("command cancelled before execution");
  return await new Promise((resolve, reject) => {
    const child = spawn(shell, ["-c", command], { cwd: options.cwd ?? root, env: { ...process.env, ...env },
      detached: true, stdio: options.nativeCall === undefined ? ["ignore", "pipe", "pipe"] : ["ignore", "pipe", "pipe", "pipe"] });
    let pipeFailed = false;
    if (options.nativeCall !== undefined) {
      // Anonymous per-execution IPC; never a command argument, file, or server.
      child.stdio[3].on("error", () => { pipeFailed = true; });
      child.stdio[3].end(options.nativeCall);
    }
    let stdout = "", stderr = "", bytes = 0, overflow = false;
    const stop = () => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    };
    const timer = timeout ? setTimeout(stop, timeout) : undefined;
    signal?.addEventListener("abort", stop, { once: true });
    const collect = (chunk, channel) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes <= (options.outputLimit ?? 4 * 1024 * 1024)) {
        if (channel === "stdout") stdout += chunk;
        else stderr += chunk;
      }
      else {
        overflow = true;
        stop();
      }
    };
    child.stdout.setEncoding("utf8").on("data", chunk => collect(chunk, "stdout"));
    child.stderr.setEncoding("utf8").on("data", chunk => collect(chunk, "stderr"));
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", stop);
    };
    child.on("error", (error) => {
      cleanup();
      reject(error);
    });
    child.on("close", (code) => {
      cleanup();
      resolve({ stdout, output: overflow ? "[advantage-native] canonical command exceeded bounded output"
        : pipeFailed ? "[advantage-native] private invocation channel failed" : stdout + stderr,
        code: overflow || pipeFailed ? 1 : code ?? 1,
        exited: Number.isInteger(code) && !overflow && !pipeFailed && !signal?.aborted });
    });
  });
}
export function installAdvantageNative(pi) {
  let hostId;
  pi.on("session_start", async (_event, ctx) => {
    hostId = ctx.agent.id;
    if (ctx.agent.kind === "main" && process.env.VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID && !standaloneExit)
      standaloneExit = { published: false, failed: false };
    if (ctx.agent.kind === "main" && !exitCleanupRegistered) {
      exitCleanupRegistered = true;
      // Print mode disposes sessions before its final exit. This is after
      // native session writers seal/close, unlike session_shutdown hooks.
      process.once("exit", code => {
        let cleanupFailed = false;
        for (const directory of ownedScratch) {
          try { rmSync(directory, { recursive: true, force: true }); }
          catch (error) {
            cleanupFailed = true;
            process.stderr.write(`[advantage-native] final owned scratch cleanup failed: ${error}\n`);
          }
        }
        ownedScratch.clear();
        if (cleanupFailed || standaloneExit && (!standaloneExit.published || standaloneExit.failed))
          process.exitCode = code || 1;
      });
    }
    sessions.set(ctx.agent.id, { ctx, pi });
    const begun = starting.get(ctx.agent.id);
    if (begun) {
      begun.owner.start(begun.binding, ctx.agent.id, ctx.agent.name, caller(ctx, pi).selector);
      starting.delete(ctx.agent.id);
    }
    const native = pi.getAllTools().find((tool) => tool.name === "bash");
    if (!native)
      return;
    const approvalTool = new pi.pi.BashTool({ settings: pi.pi.settings, cwd: ctx.cwd });
    pi.registerTool({
      name: "bash",
      label: "Bash",
      description: native.description,
      parameters: native.parameters,
      approval: approvalTool.approval,
      formatApprovalDetails: approvalTool.formatApprovalDetails,
      concurrency: approvalTool.concurrency,
      strict: approvalTool.strict,
      async execute(id, params, signal, _update, toolCtx) {
        const command = String(params.command ?? "");
        if (command.includes("VULNOPS_ADVANTAGE_CALL"))
          fail("caller-supplied native authority is forbidden");
        const argv = literalArgv(command);
        const script = argv && path.basename(argv[1] ?? "");
        let live = invocation(toolCtx);
        if (live && !argv && Object.keys(commands).some(name => command.includes(name)))
          fail("canonical Advantage operations require one literal Python argv command");
        const candidate = argv && /^(python3?|\/[^ ]*\/python3?)$/.test(argv[0]) && Object.hasOwn(commands, script);
        if (!candidate || !live && script !== "init-advantage.py")
          return toolCtx.invokeTool(params, { signal });
        const root = realpathSync(process.env.VULNOPSV3_ROOT ?? toolCtx.cwd);
        if (realpathSync(path.resolve(params.cwd ?? toolCtx.cwd, argv[1])) !== path.join(root, "scripts", script))
          fail("canonical script must belong to this harness");
        if (params.async || params.name || params.pty)
          fail("canonical operations require foreground non-PTY execution");
        const identity = caller(toolCtx, pi);
        let phase = argument(argv, "--phase") ?? live?.workers.get(identity.id)?.phase ?? commands[script];
        let operation;
        if (script === "init-advantage.py") {
          if (live || initializing.has(identity.id) || identity.kind !== "main" || identity.selector !== JSON.parse(process.env.VULNOPS_MODEL_ROUTING ?? "{}").controllers?.advantage)
            fail("fresh initialization requires the configured main Advantage controller and no active invocation");
          if (toolCtx.getAsyncJobSnapshot?.()?.running?.some(job => job.type === "task"))
            fail("current native work must stop before starting Advantage");
          initializing.add(identity.id);
        } else {
          const input = argument(argv, "--context") ?? (script === "set-omp-deadline.py" ? argv[2] : undefined);
          if (!input)
            fail("canonical operation requires explicit immutable --context input");
          live.checkInput(path.resolve(params.cwd ?? toolCtx.cwd, input));
          observeSnapshot(toolCtx, live);
          if (script === "set-omp-deadline.py")
            phase = argv[3];
          if (script === "render-advantage-report.py") {
            phase = "report";
            if (identity.id !== live.rootId || identity.kind !== "main")
              fail("reporting requires the root Advantage controller");
            if (phases.slice(0, -1).some((item) => !live.accepted.has(item)))
              fail("reporting requires all prior native phase acceptances");
          }
          operation = live.reserve(id, script, argv, identity);
        }
        const call = live?.call(identity, phase, operation) ?? {
          run_id: null, launcher_session_id: process.env.VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID ?? process.env.VULNOPS_LAUNCHER_SESSION_ID,
          phase: "initialization", caller: identity, accepted_phases: [], workers: [],
          baseline: ordinaryBaselines.get(identity.id),
        };
        let result;
        const startedAt = Date.now();
        const publication = live?.publicationBinding(script, argv, params.cwd ?? toolCtx.cwd);
        try {
          result = await confinedCommand(command, { ...params, cwd: params.cwd ?? toolCtx.cwd,
            outputLimit: script === "init-advantage.py" ? 16 * 1024 * 1024 + 4096 : undefined,
            nativeCall: JSON.stringify(call) },
            { VULNOPS_ADVANTAGE_CALL: "fd:3" }, signal);
        } finally {
          if (script === "init-advantage.py") initializing.delete(identity.id);
          if (operation?.kind === "experiment")
            live.experimentRunning = false;
        }
        if (publication) live.observePublication(publication, result);
        if (result.code === 0) {
          if (operation?.kind === "graph" && operation.phase === "gap-exploration") {
            // Charge each shared allowance conservatively by the whole real
            // command duration; failed/interrupted commands keep reservations.
            const elapsed = (Date.now() - startedAt) / 1000;
            live.graphSeconds -= Math.max(0, operation.timeout_seconds - elapsed);
            live.preparationSeconds -= Math.max(0, operation.preparation_timeout_seconds - elapsed);
          }
          if (script === "init-advantage.py") {
            const input = JSON.parse(result.stdout);
            const session = process.env.VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID ?? process.env.VULNOPS_LAUNCHER_SESSION_ID;
            if (!session || input.launcher_session_id !== session || !input.run_id || !under(path.join(root, ".harness/tmp"), input.input_path))
              fail("initializer returned foreign identity");
            live = new NativeInvocation(input, identity.id);
            roots.set(identity.id, live);
            if (input.source_scan) ordinaryBaselines.set(identity.id, input.source_scan);
            if (Buffer.byteLength(result.output) > 32768)
              result.output = JSON.stringify({ run_id: input.run_id, input_path: input.input_path,
                scan_base: input.scan_base, mode: input.mode, source_scan: input.source_scan,
                message: "Read the immutable input for the full source and routing bindings." });
          } else if (script === "render-advantage-report.py") {
            if (!result.exited) fail("report rendering did not exit successfully");
            const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
            const validation = await confinedCommand(
              `python3 scripts/validate-advantage.py ${quote(live.context.scan_base)} --phase report --context ${quote(live.context.input_path)}`,
              { ...params, cwd: root, nativeCall: JSON.stringify(live.call(identity, "report")) },
              { VULNOPS_ADVANTAGE_CALL: "fd:3" }, signal);
            if (!validation.exited) fail("final report validation did not exit successfully");
            if (validation.code !== 0) {
              result = validation;
            } else {
              if (!live.acceptFromCaller(identity, "report", JSON.parse(validation.stdout)))
                fail("final report acceptance requires the root controller");
              live.published = true;
              await teardown(live, toolCtx, pi);
              if (signal?.aborted) fail("report operation cancelled");
            }
          } else if (script === "validate-advantage.py" && argument(argv, "--phase") && result.exited
              && live.acceptFromCaller(identity, phase, JSON.parse(result.stdout))) {
            if (phase === "report") {
              live.published = true;
              await teardown(live, toolCtx, pi);
            }
          }
          if (script === "prepare-gap-exploration.py" && argument(argv, "--plan"))
            live.gapPlanHash = fileHash(path.join(live.context.scan_base, "gap-exploration/plan.json"));
        }
        return { content: [{ type: "text", text: result.output || "(no output)" }], isError: result.code !== 0, details: { exitCode: result.code } };
      }
    });
  });
  pi.on("tool_call", (event, ctx) => {
    const live = invocation(ctx);
    if (event.toolName === "bash" && String(event.input.command).includes("VULNOPS_ADVANTAGE_CALL"))
      return { block: true, reason: "Native invocation authority cannot be supplied by a caller" };
    if (live && ["edit", "write"].includes(event.toolName) && typeof event.input.path === "string"
        && path.resolve(ctx.cwd, event.input.path) === live.context.input_path)
      return { block: true, reason: "The current Advantage input is immutable" };
    if (live && event.toolName === "write" && String(event.input.path).startsWith("agent://")) {
      const target = live.workers.get(String(event.input.path).slice("agent://".length));
      if (target && target.status !== "running")
        return { block: true, reason: "Finished Advantage workers cannot be revived; use a newly bound native assignment" };
    }
    if (!live || event.toolName !== "task")
      return;
    try {
      const assignments = event.input.tasks;
      if (!Array.isArray(assignments) || !assignments.length)
        fail("native Advantage requires explicit batched assignments");
      const bindings = assignments.map((assignment) => {
        if (assignment.schemaMode !== "strict" || "outputSchema" in assignment || "effort" in assignment)
          fail("native strict actor schema and exact effort must remain intact");
        const prefix = String(assignment.task).split("\n", 1)[0];
        if (!prefix.startsWith("VULNOPS_ASSIGNMENT "))
          fail("missing exact native assignment binding");
        const binding = JSON.parse(prefix.slice("VULNOPS_ASSIGNMENT ".length));
        if (typeof binding.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(binding.id)
            || !phases.includes(binding.phase) || !["original", "supplementary"].includes(binding.cohort)
            || typeof binding.input !== "string" || !path.isAbsolute(binding.input))
          fail("invalid native assignment identity");
        const input = realpathSync(binding.input);
        const leafPhase = {
          "vulnops-advantage-investigator": "investigation",
          "vulnops-advantage-gap-investigator": "gap-exploration",
          "vulnops-advantage-verify-one": "final-verification",
        }[assignment.agent];
        if (leafPhase) {
          const packet = path.join(realpathSync(live.context.scan_base), leafPhase, "packets", `${binding.id}.json`);
          if (binding.phase !== leafPhase || input !== packet)
            fail("native leaf requires its exact phase and owner packet");
        } else if (input !== live.context.input_path)
          fail("native coordinator requires this invocation's immutable input");
        if (ctx.agent.kind === "main" && input !== live.context.input_path)
          fail("root phase requires this invocation's immutable input");
        if (ctx.agent.kind === "sub" && live.workers.get(ctx.agent.id)?.phase !== binding.phase)
          fail("child assignment cannot change its native parent phase");
        if (assignment.name !== binding.id.replace(/[^A-Za-z0-9]/g, ""))
          fail("native task name differs from canonical assignment identity");
        const index = phases.indexOf(binding.phase);
        if (phases.slice(0, index).some((prior) => !live.accepted.has(prior)))
          fail("native phase predecessors are not accepted");
        const cohortRoot = ["synthesis", "final-verification"].includes(binding.phase)
          && binding.id === `${cohortNames[binding.phase]}${binding.cohort === "supplementary" ? "Supplementary" : "Original"}`;
        if (ctx.agent.kind === "main" && ((!cohortRoot && binding.id !== phaseNames[binding.phase]) || assignment.agent !== phaseActors[binding.phase]))
          fail("root phase actor or name differs");
        const limits = binding.phase === "gap-exploration" || binding.cohort === "supplementary"
          ? live.context.gap_exploration_budget : live.context.budget;
        const existing = [...live.workers.values()].filter(row => row.phase === binding.phase && row.actor === assignment.agent);
        const reserved = [...pending.values()].filter(call => call.owner === live)
          .flatMap(call => call.assignments).filter(row => !row.started && !row.terminal && row.phase === binding.phase && row.actor === assignment.agent);
        const same = existing.filter(row => row.id === binding.id);
        if (same.some(row => !live.canRetry(row.runtime_id)) || reserved.some(row => row.id === binding.id))
          fail("native assignment is still active or already admitted; continue other work");
        if (existing.filter(row => row.status === "running").length + reserved.length
            + assignments.filter(row => row.agent === assignment.agent).length > limits.max_concurrency)
          fail("current native concurrency allowance exhausted");
        if (assignment.agent.endsWith("-investigator")
            && new Set([...existing, ...reserved, ...assignments.filter(row => row.agent === assignment.agent)
              .map(row => JSON.parse(row.task.split("\n", 1)[0].slice("VULNOPS_ASSIGNMENT ".length)))].map(row => row.id)).size > limits.max_tasks)
          fail("current native task allowance exhausted");
        return { ...binding, actor: assignment.agent };
      });
      if (new Set(bindings.map((row) => row.id.replace(/[^A-Za-z0-9]/g, ""))).size !== bindings.length)
        fail("ambiguous canonical task IDs");
      live.queue(`${ctx.agent.id}:${event.toolCallId}`, bindings);
    } catch (error) {
      return { block: true, reason: String(error) };
    }
  });
  pi.events.on("task:subagent:lifecycle", (event) => {
    const launch = pending.get(`${hostId}:${event.parentToolCallId}`);
    if (!launch || launch.owner.closed)
      return;
    const binding = launch.assignments[event.index];
    if (!binding)
      return;
    if (event.status === "started") {
      const child = sessions.get(event.id);
      if (child && !launch.owner.workers.has(event.id))
        launch.owner.start(binding, event.id, event.agent, caller(child.ctx, child.pi).selector);
      else if (!child) starting.set(event.id, { owner: launch.owner, binding });
      if (event.sessionFile) {
        const temporaryRoot = realpathSync(os.tmpdir());
        const relative = path.relative(temporaryRoot, realpathSync(path.dirname(event.sessionFile)));
        const directory = relative.split(path.sep)[0];
        if (/^omp-task-[A-Za-z0-9_-]+$/.test(directory)
            && under(temporaryRoot, realpathSync(path.join(temporaryRoot, directory)))) {
          const owned = path.join(temporaryRoot, directory);
          launch.owner.scratch.add(owned);
          ownedScratch.add(owned);
        }
      }
      binding.started = true;
      binding.runtime_id = event.id;
    } else {
      binding.runtime_id ??= event.id;
      launch.owner.settle(event.id, event.status);
    }
  });
  pi.on("tool_result", (event, ctx) => {
    if (event.toolName === "bash" && !event.isError && ctx.agent.kind === "main") {
      const argv = literalArgv(String(event.input.command ?? ""));
      const root = path.resolve(process.env.VULNOPSV3_ROOT ?? ctx.cwd);
      if (argv && ["run-audit.sh", "init-run.py"].includes(path.basename(argv[1] ?? ""))
          && path.resolve(ctx.cwd, argv[1]) === path.join(root, "scripts", path.basename(argv[1]))) {
        // Read only after THIS native initializer succeeds, never at startup.
        try {
          const document = JSON.parse(readFileSync(process.env.VULNOPS_AUDIT_CONTEXT ?? path.join(root, ".harness/audit-context.json"), "utf8"));
          if (document.launcher_session_id === process.env.VULNOPS_LAUNCHER_SESSION_ID)
            ordinaryBaselines.set(ctx.agent.id, document.scan_base);
        } catch { /* No current initializer publication means no implicit baseline. */ }
      }
    }
    const live = invocation(ctx);
    if (!live)
      return;
    if (event.toolName === "task") {
      const launch = pending.get(`${ctx.agent.id}:${event.toolCallId}`);
      if (launch) {
        for (const row of event.details?.progress ?? []) {
          const binding = launch.assignments[row.index];
          if (binding) binding.runtime_id = row.id;
        }
        if (event.isError) for (const row of launch.assignments) if (!row.started) row.terminal = true;
      }
    }
    if (event.toolName === "yield" && !event.isError)
      live.yield(ctx.agent.id, event.input.data, !Array.isArray(event.input.type));
    for (const result of event.details?.results ?? [])
      live.settle(result.id, result.aborted ? "cancelled" : result.exitCode === 0 ? "completed" : "failed", result.structuredOutput);
    observeSnapshot(ctx, live);
    for (const job of event.details?.jobs ?? [])
      if (job.type === "task") live.settle(job.agentUrlId ?? job.id, job.status, job.structured);
  });
  pi.on("message_end", (event, ctx) => {
    const live = invocation(ctx);
    if (!live || event.message?.customType !== "async-result") return;
    for (const job of event.message.details?.jobs ?? [])
      if (job.type === "task") live.settle(job.agentId ?? job.jobId, job.status, job.schema);
  });
  pi.on("session_stop", async (_event, ctx) => {
    const live = roots.get(ctx.agent.id);
    if (!live) return;
    await teardown(live, ctx, pi);
    if (!live.published)
      ctx.ui.notify("Advantage stopped before final report validation; check the saved report by explicit path.", "error");
  });
  pi.on("session_shutdown", async (_event, ctx) => {
    sessions.delete(ctx.agent.id);
    const live = roots.get(ctx.agent.id);
    if (!live)
      return;
    await teardown(live, ctx, pi);
  });
  for (const event of ["session_before_switch", "session_before_branch"]) {
    // Session changes do not carry an Advantage invocation into another host
    // conversation; ordinary baseline association is likewise process-local.
    pi.on(event, async (_event, ctx) => {
      const live = roots.get(ctx.agent.id);
      if (live) await teardown(live, ctx, pi);
      ordinaryBaselines.delete(ctx.agent.id);
    });
  }
}

async function teardown(live, ctx, pi) {
  if (live.closed) return;
  for (const id of live.workers.keys()) await sessions.get(id)?.ctx.abort();
  await Promise.all([...live.terminalWaiters.values()].map(waiter => waiter.promise));
  const call = live.call(caller(ctx, pi), "report");
  const command = `python3 scripts/advantage-cleanup.py --context '${live.context.input_path.replaceAll("'", "'\\''")}'`;
  try {
    const result = await confinedCommand(command, { cwd: process.env.VULNOPSV3_ROOT ?? ctx.cwd, timeout: 30,
      nativeCall: JSON.stringify(call) }, { VULNOPS_ADVANTAGE_CALL: "fd:3" });
    if (result.code !== 0) fail("owned invocation teardown failed");
    for (const directory of live.scratch) rmSync(directory, { recursive: true, force: true });
    if (standaloneExit && live.published) standaloneExit.published = true;
  } catch (error) {
    if (standaloneExit) standaloneExit.failed = true;
    throw error;
  } finally {
    if (standaloneExit && !live.published) standaloneExit.failed = true;
    live.closed = true;
    roots.delete(live.rootId);
    for (const id of live.workers.keys()) sessions.delete(id);
    for (const [id, launch] of pending) if (launch.owner === live) pending.delete(id);
    for (const [id, item] of starting) if (item.owner === live) starting.delete(id);
  }
}
