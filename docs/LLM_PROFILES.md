# LLM profiles

A run of the pipeline uses language models in four places:

- the agentic reverse-engineering stage, and its escalation model;
- the executive summary;
- the plain-English summary.

By default all of them are the **local** model, as deployed. An **LLM profile** lets one run use different models, without changing what every other run uses. The decision is ADR-036 in [DECISIONS.md](DECISIONS.md).

## Choosing a profile for a run

```bash
run-pipeline <sample> --llm-profile stub          # on the sandbox, one sample
make intake MANIFEST=scripts/intake/<batch>.json LLM_PROFILE=stub   # a batch
```

- No profile means `local`.
- An unknown name stops the run; it never falls back to another profile.
- API submissions and the automatic feeder never pass a profile, so they always run `local`.

Every report records what it ran with:

```json
"llm_profile": {"name": "stub", "cloud": false,
                "models": {"model": "stub", "escalation_model": "stub",
                           "summary_model": "stub", "plain_english_model": "stub"}}
```

A replayed report records `replay_llm_profile` as well.

## The built-in profiles

| Profile | What answers | Cost | Use it for |
|---|---|---|---|
| `local` | the deployed local model (`interpret_*` and `pipeline_*_model` variables) | none | normal runs |
| `stub` | `llm-stub`, a loopback server returning valid, fixed replies | none | permission changes, coverage runs, anything that needs every stage to *run* quickly |

**What `stub` proves.** Every LLM stage was called, got a reply in the shape it parses, and the pipeline carried on:

- tool calls in the agent loop;
- the structured final analysis;
- JSON with the keys each prompt asks for;
- usage blocks.

**What `stub` doesn't prove.** That a real model can still drive the tools. After a change that could affect that, run one sample on `local` or a cloud profile too.

## Adding a cloud profile

A cloud profile sends **decompiled code, extracted strings and behaviour of the sample** to that model's provider. It's your decision, run by run. The run logs a warning naming the models, and the report says `"cloud": true`.

1. **Expose the model through LiteLLM under an `eval-*` alias.** The repo's eval aliases (for example `eval-haiku55`) are examples. `eval-*` entries are kept out of every production setting by tests, and carry no production key.
2. **Define the profile** in your `ansible/vars/main.yml` (gitignored):

   ```yaml
   pipeline_llm_profiles:
     stub: {...}            # keep the default stub profile if you override the variable
     haiku:
       description: "fast cloud model for occasional coverage runs"
       cloud: true
       model: eval-haiku55
       escalation_model: eval-haiku55
       summary_model: eval-haiku55
       plain_english_model: eval-haiku55
       re_backend: router
       single_shot_backend: router
   ```

3. **Deploy** the `pipeline` role.

The config refuses a profile that breaks any of these rules, so the pipeline won't start with it:

- **`local` can't be redefined.** It is always the deployed defaults.
- **A profile with `cloud: false`** may name only local aliases (`local-qwen-llamacpp*`, `stub`). A test holds those names to the local servers' addresses in LiteLLM's config.
- **A profile with `cloud: true`** may name only `eval-*` aliases, and must use `re_backend: router` and `single_shot_backend: router`. On the local transports a cloud model takes code paths meant for the local model, which some models reject and which record no usage.

## Cost

Usage is recorded for every call, whatever the profile.

- **Local and `stub` runs** are priced at zero.
- **Cloud models** are priced by the pipeline's own rate table. An alias missing from it is billed at the default rate, with a warning in the ingest log.
- **LiteLLM** already computes an accurate per-call cost for these models. Making it the single price source is planned, and would replace the rate tables.

## For permission phases (ADR-031)

1. Run the coverage corpus (`scripts/usecase-check/coverage-corpus.json`) on `stub`.
2. Compare each report with its baseline using `scripts/usecase-check/report-shape.py`.
3. Run one sample on a real model.
