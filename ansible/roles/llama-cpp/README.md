# Role: `llama-cpp`

Serves Qwen3.6-35B-A3B via [llama.cpp](https://github.com/ggml-org/llama.cpp)
(`llama-server`) for the agentic RE stage and the visual analysis stage, as a
root Podman container managed by systemd and bound to host loopback.

## Why this exists separately from `ollama`

Both serve the same model. They are not interchangeable for RE work:

* llama.cpp splits reasoning into a `reasoning_content` field, so `content`
  stays clean and parseable.
* It grammar-constrains forced-tool arguments, which is what makes structured
  RE output reliable.

Ollama still serves the summary stages. Retiring it is tracked in #191.

## Model files are NOT downloaded by this role

The two GGUFs (~23 GB total) are fetched out of band. The role asserts they are
present and fails loudly if they are not, rather than starting a server that
would never answer:

```
/opt/llama-cpp/models/Qwen3.6-35B-A3B-UD-Q4_K_M.gguf   # Unsloth UD quant
/opt/llama-cpp/models/mmproj-F16.gguf                  # vision projector
```

The vision projector is the same model's own `mmproj`, so one server serves both
the text and visual stages.

If a host still has them under `/opt/llamacpp-spike` (where the July 2026 spike
left them), the role migrates them once — a same-filesystem rename, not a copy.

## Sampling

Every sampling parameter is passed **explicitly**, including ones that look like
they could be left alone. Before this role, `min_p` came from llama.cpp's own
default of `0.05`, silently overriding Qwen's recommended `0.0` — a value nobody
had chosen and which appeared in no config file. An unset flag is not a neutral
flag.

The defaults are Qwen's published **thinking / precise-coding** profile
(`temp 0.6, top_p 0.95, top_k 20, min_p 0.0, presence_penalty 0.0`), not the
thinking/general profile: agentic RE wants correct symbol names and addresses,
not diverse reasoning paths.

`llamacpp_seed` is fixed so runs are reproducible and arm comparisons are
*paired*. **Do not tune it.** Running N seeds and keeping the best-scoring one is
selection on noise — it inflates the metric and would discredit any published
result. See #222.

Per-request seeds for multi-seed consensus come from LiteLLM model aliases
(`local-qwen-llamacpp-re-s<seed>`), not from here: the interpret client speaks
the Anthropic Messages shape, which has no `seed` field.

## Verification

The role checks the running server's `/props` and fails the play if the applied
sampling profile or context size differs from the intended one.

This is deliberately a **runtime** check. A previous timeout fix (#218) was
guarded only by a static test asserting the value appeared in the file — the
value was in the file and never reached the socket, and the guard passed for
days. Asking the server what it actually applied is the only check that catches
that class of bug.

## Context size

`--ctx-size` is **per slot**, so it is paired with `--parallel 1`. At 131072 the
container peaks around 27 GB against a 34 GB cap.

## Deploy

```bash
ansible-playbook site.yml --tags llama-cpp,litellm -i inventory/hosts --ask-vault-pass
```

Changing any sampling variable restarts the server, which re-reads the ~23 GB
model. Expect a few minutes before it answers.
