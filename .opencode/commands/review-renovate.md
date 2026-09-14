---
description: Review and safely process Renovate dependency pull requests
agent: code
---

The repository owner explicitly invokes the guarded Renovate batch workflow.
Load and follow the `renovate-pr-review` skill completely.

This invocation grants the limited advance merge authorization defined in
`AGENTS.md` for this command run only. It does not relax any skill gate,
authorize issue closure, or authorize a pull request whose final evaluation is
not clean.
