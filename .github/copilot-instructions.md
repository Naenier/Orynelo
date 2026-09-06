# GitHub Copilot repository instructions

Read and follow the repository-root [AGENTS.md](../AGENTS.md). It is the shared
source of Orynelo coding instructions. The [agent guide](../docs/agents/README.md)
links to focused project context, development commands, and guardrails.

Orynelo is a Go CLI and Fyne desktop application over a shared application and
diagnostic core. Preserve its architecture, bounded network operations,
privacy boundaries, stable reports, and local persistence behavior.

Keep changes within the active task. If the user forbids checks, do not run
tests, linters, builds, or post-edit inspection commands. Keep detailed rules
in the shared files instead of expanding this adapter.
