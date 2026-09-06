# Working with AI agents

The repository uses one shared instruction set with small entry points for
different coding tools. Start with [AGENTS.md](../../AGENTS.md), then load only
the supporting material needed for the task. These files document the project;
they do not install tools, enable services, or grant additional permissions.

## Entry points

| File | Purpose |
| --- | --- |
| [AGENTS.md](../../AGENTS.md) | Shared repository instructions for Codex and other AGENTS-aware tools |
| [copilot-instructions.md](../../.github/copilot-instructions.md) | GitHub Copilot repository guidance |
| [project.mdc](../../.cursor/rules/project.mdc) | Cursor rule referring to the shared instructions |

Entry points live in the root or their tool-specific directories so they can
participate in those tools' instruction discovery. Detailed reference material
lives here. A file stored only under `docs/` should not be assumed to apply
automatically to source code elsewhere in the repository.

If a tool does not load repository instructions or cannot follow file links,
attach `AGENTS.md` and the relevant reference explicitly. Use `AGENTS.md` as the
canonical filename; no separate `AGENT.md` copy is needed.

## Focused references

- [Project map](project-map.md): package ownership, execution flow, and sources
  of truth for versions and contracts.
- [Development workflow](development.md): commands, relevant test selection,
  change recipes, and concise handoffs.
- [Guardrails](guardrails.md): privacy, network interpretation, cancellation,
  GUI lifecycle, persistence, and compatibility constraints.

The existing [architecture](../architecture.md),
[diagnostic model](../diagnostic-model.md), [security design](../security.md),
and [runtime resilience](../runtime-resilience.md) remain the detailed design
references. [README.md](../../README.md) describes user-facing behavior;
[the roadmap](../roadmap.md) also includes work that is not implemented.

## Maintenance

Keep tool entry points short. Update the shared rule or reference when an
architecture decision, command, or contract changes. Prefer links to source
constants over copied version numbers. Do not put secrets, local configuration,
machine-specific paths, transcripts, speculative implementation status, or
temporary task progress into these files. A task-specific instruction to skip
checks applies to that task and does not disable validation for future work.
