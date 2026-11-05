import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import path from "node:path";
import { installAdvantageNative } from "./advantage-native.mjs";

export default function targetReadonlyGuard(pi: ExtensionAPI) {
  pi.setLabel("VulnOps Target Read-Only Guard");
  installAdvantageNative(pi);
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName === "bash") {
      const command = String((event.input as Record<string, unknown>).command ?? "");
      if (command.includes("init-advantage.py") && command.includes("--in-session")) {
        const routing = JSON.parse(process.env.VULNOPS_MODEL_ROUTING ?? "{}");
        const selector = ctx.model && `${ctx.model.provider}/${ctx.model.id}:${pi.getThinkingLevel()}`;
        if (ctx.agent.kind !== "main" || !selector || selector !== routing.controllers?.advantage) {
          return { block: true, reason: "In-session Advantage requires the main controller on its configured model and effort; no nested OMP or fallback model." };
        }
      }
    }
    if (event.toolName === "task") {
      const input = event.input as Record<string, unknown>;
      const routing = JSON.parse(process.env.VULNOPS_MODEL_ROUTING ?? "{}");
      const assignments = Array.isArray(input.tasks) ? input.tasks : [];
      for (const assignment of assignments) {
        const expected = routing.agents?.[assignment.agent];
        if (!expected || ("model" in assignment && assignment.model !== expected)) {
          return { block: true, reason: "Task model must match its canonical actor route; fallback models are forbidden." };
        }
      }
      if ("model" in input) {
        return { block: true, reason: "Batch-level model overrides are forbidden by canonical routing." };
      }
    }
    if (event.toolName === "edit" || event.toolName === "write") {
      const requested = String((event.input as Record<string, unknown>).path ?? "");
      if (requested) {
        const absolute = path.resolve(ctx.cwd, requested);
        const targetRoot = path.resolve(process.env.VULNOPSV3_TARGET ?? path.resolve(ctx.cwd, "target"));
        if (absolute === targetRoot || absolute.startsWith(targetRoot + path.sep)) {
          return { block: true, reason: "The audit target is immutable input." };
        }
      }
    }
  });
}
