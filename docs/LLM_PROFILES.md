# LLM profiles

A run of the pipeline uses language models in three places:

- the agentic reverse-engineering stage, which uses one model from first turn to last (ADR-038: no escalation);
- the executive summary;
- the plain-English summary.

By default all of them are the **local** model, as deployed. An **LLM profile** is a named choice of those models. A run can name one, and the deployment has a **default profile** for every run that doesn't. The decisions are ADR-036 and ADR-038 in [DECISIONS.md](DECISIONS.md).

## Choosing a profile for a run

```bash
run-pipeline <sample> --llm-profile stub          # on the sandbox, one sample
make intake MANIFEST=scripts/intake/<batch>.json LLM_PROFILE=stub   # a batch
```

- No profile means **the deployment's default profile**, `local` unless you change it (below).
- An unknown name stops the run; it never falls back to another profile.
- API submissions and the automatic feeder never pass a profile, so they always run the default.

## Changing the default profile

```bash
make llm-default PROFILE=haiku     # or PROFILE=local to go back
```

- **What the command does:**
  - it checks that the name is defined: `local`, a built-in, or one of yours;
  - it sets `pipeline_default_llm_profile` in your `ansible/vars/main.yml`, changing only that line;
  - it deploys the `pipeline` role.

  Setting the variable yourself and running `make deploy TAGS=pipeline` does the same.
- **A deploy that names an undefined profile stops** before it writes the pipeline's config.
- **A cloud default is announced** at deploy, in every run's log, and in every report: `llm_profile.chosen_by` is `"default"` or `"flag"`. From then on API submissions, the feeder and intake send prompts off the host to that profile's models.

Every report records what it ran with:

```json
"llm_profile": {"name": "stub", "cloud": false, "chosen_by": "flag",
                "models": {"model": "stub",
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

## Choosing a model

The suite enables models; you choose them (ADR-038). It holds minimal opinions:

- **Check the model's terms first.** This pipeline reverse-engineers malware for security research. Some model licences and usage policies forbid reverse engineering or security research, and some of those offer no exception path. Choose a model whose terms allow this work, or whose provider offers an exception or approval process that covers it. The suite doesn't read licences or refuse a model; the terms you accept are yours.
- **Quality isn't ranked here.** Where the eval harness (`make eval`) has measured a model on this corpus, use those results. Nothing refuses a model for being weaker.
- **The sandbox is the control, not the model.** Models differ in how readily they cross a boundary when something outside looks useful. The containers the agents run in (no network, read-only, capabilities dropped) are what keep a run contained, whichever model you pick.
- **One agent model per run.** There is no escalation to a second model mid-run. For a hard sample, pick a profile with a stronger model for that run. The summaries can use their own, cheaper model (`summary_model`, `plain_english_model`).

## Providers

What a profile can name today, and how far each is verified on this host:

| Provider | How it is reached | Status |
|---|---|---|
| **Local llama.cpp** (`local-qwen-llamacpp*`) | LiteLLM's router to the llama.cpp server on this host | verified: the `local` default |
| **`llm-stub`** (`stub`) | LiteLLM's router to the loopback stub | verified: coverage and permission runs |
| **Anthropic API, eval credentials** (`eval-*`) | LiteLLM, then the Workload Identity Federation forwarder (ADR-033) or a workspace key | verified: `eval-haiku55` runs, priced by LiteLLM |
| **Anthropic API, production credentials** | LiteLLM with the production key | used by the investigation panel only; not available to profiles |
| **Your own providers:** Amazon Bedrock, Microsoft Foundry, Google Vertex, other local servers (Ollama, vLLM) | `litellm_operator_models` (below) | supported by the deploy; **none of the examples below is verified on this host** |

### Adding your own provider

Put LiteLLM model entries in `litellm_operator_models` and their credentials in `litellm_operator_env`, in your `ansible/vars/main.yml`, with the secret values from your vault. Then deploy `litellm` and `pipeline`. Each entry is a LiteLLM `model_list` entry plus `local`, which declares where the model runs.

**The deploy refuses:**
- an entry whose `model_name` is already used, so nothing can shadow a built-in alias;
- `local: true` whose `api_base` isn't on this host (`127.0.0.1`, `localhost` or `[::1]`);
- `local: true` named `eval-*`, or `local: false` named like a built-in local alias;
- a parameter whose name contains key, secret, token, password or credential, unless its value is an `os.environ/NAME` reference. Secrets stay in the env file, never in the config;
- an env variable that would replace `ANTHROPIC_API_KEY`, `ANTHROPIC_RESEARCH_API_KEY` or `DATABASE_URL`.

**What each kind can be used for:**
- **`local: true` entries** may appear in a profile with `cloud: false`. The pipeline reads them from the deploy, so declaring an entry local is a claim the deploy has checked.
- **Cloud entries named `eval-*`** may appear in a cloud profile. Any entry, local or cloud, may be listed for the investigation panel (`api_investigate_models`).

The parameter names follow LiteLLM's provider documentation; check it for your provider. These are starting points, **not verified here**:

```yaml
litellm_operator_models:
  # Amazon Bedrock (cloud). LiteLLM's model string is bedrock/<Bedrock model id>.
  - model_name: eval-bedrock-sonnet
    local: false
    litellm_params:
      model: bedrock/anthropic.claude-sonnet-5-5
      aws_region_name: us-east-1
      aws_access_key_id: os.environ/AWS_ACCESS_KEY_ID
      aws_secret_access_key: os.environ/AWS_SECRET_ACCESS_KEY

  # Microsoft Foundry (cloud): LiteLLM's azure_ai provider, with your endpoint.
  - model_name: eval-foundry-sonnet
    local: false
    litellm_params:
      model: azure_ai/claude-sonnet-5-5
      api_base: https://<your-resource>.services.ai.azure.com
      api_key: os.environ/AZURE_AI_API_KEY

  # Ollama on this host (local).
  - model_name: local-ollama-qwen
    local: true
    litellm_params:
      model: ollama/qwen3
      api_base: http://127.0.0.1:11434

  # vLLM's OpenAI-compatible server on this host (local).
  - model_name: local-vllm
    local: true
    litellm_params:
      model: openai/<served-model-name>
      api_base: http://127.0.0.1:8000/v1
      api_key: os.environ/VLLM_API_KEY

litellm_operator_env:
  AWS_ACCESS_KEY_ID: "{{ vault_aws_access_key_id }}"
  AWS_SECRET_ACCESS_KEY: "{{ vault_aws_secret_access_key }}"
  AZURE_AI_API_KEY: "{{ vault_azure_ai_api_key }}"
  VLLM_API_KEY: "{{ vault_vllm_api_key }}"
```

**Not covered yet:**
- **Google Vertex** usually authenticates with a service-account file. LiteLLM runs in a container, and the deploy doesn't mount files into it, so Vertex needs an environment-based credential, or that support adding later.
- **A local model other than the built-in llama.cpp one** takes the same pipeline paths as llama.cpp's, but those paths were tuned for it (for example how thinking is turned off). Run the `stub` and a real sample on it before relying on it.

The investigation panel has its own list, `api_investigate_models` in the api role: LiteLLM aliases with labels. It isn't a profile.

## Adding a cloud profile

A cloud profile sends **decompiled code, extracted strings and behaviour of the sample** to that model's provider. It's your decision: run by run, or as the default (above). The run logs a warning naming the models, and the report says `"cloud": true`.

1. **Expose the model through LiteLLM under an `eval-*` alias.** Today these are the repo's eval aliases (for example `eval-haiku55`); see "The gap" above. `eval-*` entries are kept out of every production setting by tests, and carry no production key.
2. **Define the profile** in your `ansible/vars/main.yml` (gitignored). Your profiles are added to the built-in ones (`stub`); a profile with a built-in's name replaces it.

   ```yaml
   pipeline_llm_profiles:
     haiku:
       description: "fast cloud model for occasional coverage runs"
       cloud: true
       model: eval-haiku55
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

- **LiteLLM's recorded cost is the price of record** (ADR-037). Every call carries a LiteLLM call ID. After the last LLM stage, the pipeline looks each one up in LiteLLM's spend log and writes `report["llm_cost"]`: dollars, calls, resolved, and `complete`.
- **When the record is incomplete,** for example a call the spend log doesn't have, the report lists the unresolved IDs, and the database row is priced from the pipeline's rate table instead. The tables remain only as that fallback.
- **Local and `stub` runs** cost zero.
- **The investigation panel** prices each turn at LiteLLM's per-model prices (`/v1/model/info`), and offers only models LiteLLM states a price for, so nothing is silently recorded as free. A local model is free by declaration: give its entry `input_cost_per_token: 0` and `output_cost_per_token: 0` in `litellm_params`.

## For permission phases (ADR-031)

1. Run the coverage corpus (`scripts/usecase-check/coverage-corpus.json`) on `stub`.
2. Compare each report with its baseline using `scripts/usecase-check/report-shape.py`.
3. Run one sample on a real model.
