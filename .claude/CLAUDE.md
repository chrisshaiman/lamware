# CLAUDE.md — working rules for AI-assisted changes to lamware

This file is read by every Claude Code session. It is tracked at
`.claude/CLAUDE.md`. Developer-private context belongs in the gitignored
`CLAUDE.local.md`, not here. It exists because the PR history
through #635 has a shape: a change merges within minutes of opening, deploys,
fails on the host, and the next PR fixes what the last one missed. #582 → #584 →
#591 (one flag switched, then the transport, then seven more call sites). #617 →
#618 → #620 → #621 (four firewall PRs in four hours, the last reverting the
first). Every one of those PRs reported a green suite and mutation-tested guards.
The suite could not see the failure because the failure was on the host.

The rules below are the fix. They are about *where verification happens*, not
about trying harder.

Read alongside: `ARCHITECTURE.md`, `docs/SECURITY_CONSTRAINTS.md` (non-negotiable),
`docs/DECISIONS.md` (the ADR log), `CONTRIBUTING.md`.

## 1. Enumerate before you change anything

Fix the class, not the instance in front of you. Before editing, list:

- every call site of the function or pattern you are touching (`grep`, not memory);
- every config path that must carry the change: `defaults/main.yml`, the
  `config.json.j2` template, `PipelineConfig`, `ansible-vars`;
- every deploy task or manifest that must ship it — the pipeline role copies
  helpers by an explicit list (#325 landed as a no-op because the list was not
  updated);
- both IP families where iptables is involved (#343);
- every *copy* of duplicated logic (the investigate tools and the pipeline
  keep parallel validators; the interpret script has eight single-shot paths).

Put the list in the PR under **Scope**. "None found" is an answer. "Not checked"
is not.

## 2. The second-fix rule

If this is the second change to the same subsystem for the same underlying
reason within a day, stop. Do not open the fix. Write the ADR in
`docs/DECISIONS.md` first, naming the decision that was never made (ADR-020,
"one firewall mechanism", should have preceded #617, not followed #621). Then
make the change the ADR implies, once.

## 3. What counts as evidence

In descending order:

1. **Host evidence.** The command you ran on the sandbox and its output.
   Packet counts, `iptables -L -v`, `systemctl status`, a sample run's
   `report.json`, `make provenance`, `make security-test`.
2. **Behavioural tests.** Render the template and run `iptables-restore --test`;
   execute the monitor script against fake tables; call the function.
3. **Structural tests.** Regex over YAML or source text. These are memories of
   past bugs, not tests of the host. Write one only when nothing else can observe
   the property, and say so in the docstring.

"N tests pass" and "mutation-tested, all caught" are not evidence of anything
outside the tests you wrote. Do not lead a PR body with them. Lead with what was
observed.

Every PR body has a **Not verified** section. It is never empty for a change
that touches a host. #402 is the model for this: it says what was reproduced,
what was reasoned, and what was left unexamined.

## 4. Deploy before merge, not after

`main` is not a staging branch. A PR that touches anything Ansible deploys is
not mergeable until it has been deployed **from the PR branch** and the
post-deploy gates pass:

```bash
git checkout <pr-branch>
make deploy TAGS=<roles the PR touches>
make merge-check           # host sha == this HEAD, same branch, clean tree, security-test
```

Paste the `merge-check` output under **Host evidence** in the PR, including the
`Provenance commit:` line it prints. CI (`pr-evidence.yml`) fails the PR when
that hash is missing or does not match the PR head. Every push invalidates it:
redeploy and re-run.

Docs-only PRs are exempt automatically. Nothing else is.

One branch on the host at a time. Provenance already records that a later
deploy from `main` silently reverts a branch deploy (2026-08-03). Do not open a
second branch's deploy while the first is still under test.

## 5. Rollback before change

For anything touching auth (Keycloak, JWT, nginx listeners), the firewall,
the database schema, or OS hardening: state in the PR how to get back, and
confirm the path exists *before* the change goes on the host. #482 upgraded
Keycloak; #483 twenty minutes later needed a database restore because the
schema migration was one-way. Config reverts are not rollback when the data
moved.

## 6. When the deploy fails

The deploy failing is the test working. Do not open a new PR for the fix.
Commit to the same branch, redeploy, re-run `merge-check`. The PR merges once,
when the host is right. Five merged PRs for one change is the pattern this
file exists to end.

## 7. Session hygiene

Start from the observed host state, not from the previous session's summary.
The PR bodies that held up open with a measurement ("the overnight run showed
six of ten produced nothing"). The ones that were reverted open with a theory.
Run `make provenance` and look at the host before you reason about it.

## 8. Things that are never acceptable

- Skipping, disabling, or loosening a test to get green.
- Widening a PR beyond its topic. One topic per PR.
- Relaxing anything in `docs/SECURITY_CONSTRAINTS.md`, whatever it enables.
- Declaring success from a green suite on a change the suite cannot observe.
- Committing secrets, sample binaries, or machine-specific paths.

## 9. Conventions

- Conventional commit subjects (`fix(scope): what was wrong, in plain words`).
  The existing history's subjects say what the bug *was*, not what the patch
  *does*. Keep that.
- Type hints, docstrings, structured logging. Comments explain *why*.
- Python 3.12. `ruff check api/ shared/ pipeline/ ansible/` must be clean.
- Tests live next to the package they test (`shared/tests`, `pipeline/tests`,
  `api/tests`) or in top-level `tests/` for repo-shape guards.

## 10. LLM API cost tracking

Every code path that calls a model — cloud via the LiteLLM `/anthropic`
passthrough, or local via the `/v1/messages` router and the OpenAI leg used
by `single_shot_completion` — must capture the response's `usage` block and
propagate it to the turn trail (`turn` events in the interpret container) and
the report, so `db_ingest` can price it and the spend router can show it.
Local inference is priced at local rates, not Sonnet rates (#449). A path that
calls `messages.create` directly and drops `usage` is a bug, not a shortcut.
