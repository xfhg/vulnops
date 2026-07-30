import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import path from "node:path";

export default function targetReadonlyGuard(pi: ExtensionAPI) {
  pi.setLabel("VulnOps Target Read-Only Guard");
  pi.on("tool_call", async (event, ctx) => {
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
