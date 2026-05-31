# Contributing to exalm

Thanks for your interest in contributing. This file points you to the right place.

---

## Where to start

- **Development setup, plugin guide, PR checklist →** [CONTRIBUTOR_WORKFLOW.md](CONTRIBUTOR_WORKFLOW.md)
- **System architecture and design rationale →** [ARCHITECTURE.md](ARCHITECTURE.md)
- **Security and responsible disclosure →** [SECURITY.md](SECURITY.md)

---

## Quick summary

1. For non-trivial changes, open an issue first to discuss the design.
2. New plugins follow the step-by-step in [CONTRIBUTOR_WORKFLOW.md](CONTRIBUTOR_WORKFLOW.md).
3. All LLM calls must pass through `args.Redactor.Redact()` — this is non-negotiable.
4. Use Conventional Commits in PR titles: `feat(k8s): ...`, `fix(redact): ...`.
5. Run `make test && make lint` before pushing.

---

## Code of conduct

Be direct. Disagree on substance, not on people. Make the project better than you found it.
