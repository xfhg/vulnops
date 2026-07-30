import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import path from "node:path";

const URL_RE = /^https?:\/\//i;
const NETWORK_COMMAND_RE =
  /(^|[;&|()\s])(?:curl|wget|aria2c|nc|ncat|netcat|telnet|ftp|sftp|scp|ssh)\b|\/dev\/tcp\/|https?:\/\/|git@[A-Za-z0-9.-]+:|\bgit\s+(?:clone|fetch|pull|push|ls-remote)\b|\b(?:npm|pnpm|yarn|bun|pip3?|uv|poetry|gem|bundle|composer)\s+(?:add|install|update|upgrade|download|publish)\b|\bgo\s+(?:get|install)\b|\bcargo\s+(?:install|search|publish)\b|\b(?:apt|apt-get|apk|dnf|yum|brew)\s+(?:install|update|upgrade)\b/i;

export default function offlineGuard(pi: ExtensionAPI) {
  pi.setLabel("VulnOps Offline Guard");
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName === "read") {
      const target = String(event.input.path ?? "");
      if (URL_RE.test(target)) {
        return { block: true, reason: "VulnOps offline policy blocks URL reads." };
      }
    }

    if (event.toolName === "bash") {
      const command = String(event.input.command ?? "");
      if (NETWORK_COMMAND_RE.test(command)) {
        return { block: true, reason: "VulnOps offline policy blocks network-capable shell commands." };
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
