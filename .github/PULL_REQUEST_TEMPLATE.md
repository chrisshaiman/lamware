## Summary

<!-- What was wrong, what this changes, and why. Link the issue if one exists.
     Lead with what was OBSERVED (a measurement, a log line, a host state),
     not with the theory. -->

## Scope

<!-- What else has this shape? Every call site, config path, template, deploy
     task or duplicated copy that must carry this change, and what you did about
     each. Paste the grep. "None found" is an answer; "not checked" is not. -->

## Host evidence

<!-- Deployed FROM THIS BRANCH before merge. Paste the output of:
       make deploy TAGS=<roles>
       make merge-check
     Every push invalidates this — redeploy and re-run.
     Docs-only PRs are exempt automatically; nothing else is. -->

Provenance commit: <paste the full 40-character SHA printed by `make merge-check`>

## Not verified

<!-- What this PR does NOT prove. Never empty for a change that touches a host.
     Test counts and "mutation-tested" belong here only as what they DO NOT cover. -->

## Rollback

<!-- Required for auth, firewall, database schema, or hardening changes: how to
     get back, and confirmation the path exists before this goes on the host.
     Otherwise: "n/a — <why>". -->

## Checklist

- [ ] `ruff check api/ shared/ pipeline/ ansible/` clean and `pytest` passes for the affected packages
- [ ] No secrets, sample binaries, or machine-specific paths introduced
- [ ] Security-relevant change? Confirmed it respects `docs/SECURITY_CONSTRAINTS.md`
- [ ] Second fix to this subsystem for the same reason today? Then the ADR is in this PR, first
