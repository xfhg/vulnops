---
name: vulnops-attack-ai-llm
description: VulnOps AI, LLM, agent, tool, retrieval, output, and MCP attack classes
---

# VulnOps AI/LLM Attack Classes

The vulnerable boundary is code, not model temperament. Require untrusted text
to reach another principal's context, an unauthorized capability, sensitive
data, or a dangerous sink.

- Trace indirect instructions from retrieved documents, web content, files,
  messages, tool results, and metadata into a victim or privileged session.
- Treat model-created tool arguments as untrusted request parameters; check
  authorization and validation at each handler and resource.
- Compare the agent/service identity with the requesting user's authority.
- Bound model-controlled loops, spend, side effects, quotas, and subagent/tool
  inheritance.
- Trace model output into HTML, Markdown resource loading, SQL, shell, file,
  network, and other executable sinks.
- Verify tenant filters and cache/session keys for retrieval, embeddings,
  context, and conversation history.

Prompt injection affecting only the attacker's own harmless output is not a
finding. Prompt instructions are not a security boundary.
