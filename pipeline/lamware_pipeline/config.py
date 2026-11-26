# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Runtime pipeline configuration, read from a Jinja-rendered config.json.

Phase 1 covers the malfind block (the config round-trip POC). Phase 2b-1 landed
the scalar tuning knobs + analysis-tool CMD paths (malfind from Phase 1). Phase
2b-2 landed the collection values: the interpret submodel plus the volatility
triggers and extra-plugins maps. Phase 3b landed the non-secret DB connection
fields (db_host/db_port/db_name/db_user) so db_ingest/pipeline_status can stop
carrying their own Jinja for them. Secrets (cape_api_key, db_password) are
intentionally NOT here — they stay in the no_log env path.
"""
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DotnetToolLimits(BaseModel):
    """Bounds of the agentic .NET path (#646). Every field >= 1: a zero bound
    would return nothing without saying why."""
    model_config = ConfigDict(extra="forbid")
    page_chars: int = Field(default=6_000, ge=1)            # one page of source
    lines_max: int = Field(default=150, ge=1)               # get_source_lines
    list_max: int = Field(default=150, ge=1)                # list_methods / list_classes
    search_max_hits: int = Field(default=50, ge=1)          # search_source
    search_line_chars: int = Field(default=240, ge=1)       # one search hit
    toc_max_classes: int = Field(default=200, ge=1)         # first message
    toc_max_methods: int = Field(default=220, ge=1)         # first message
    construct_max_locations: int = Field(default=40, ge=1)  # first message


class InterpretConfig(BaseModel):
    """LLM-interpretation stage knobs. model_dump() reproduces the dict the
    orchestrator body passes as interpret_config= and indexes by key name."""
    model_config = ConfigDict(extra="forbid")
    model: str          # the run's one agent model, first turn to last (ADR-038)
    max_output_tokens: int
    max_tool_calls: int
    max_imports: int
    max_strings: int
    max_string_length: int
    summary_model: str          # model for the executive/kill-chain summary
    plain_english_model: str    # model for the plain-English summary
    # TRANSPORT for the agentic RE path, and not implied by `model` above.
    # interpret-ghidra.py picks between LiteLLM's /anthropic passthrough (cloud
    # models only) and the /v1/messages router (model_list aliases) on
    # config["re_backend"] == "local". A local alias sent to the passthrough
    # returns 404 not_found_error on every call.
    #
    # Defaulted, not required: an older config.json — and the eval harness passes
    # whole config dicts through — must still load. The default reproduces the
    # historical behaviour, which is that the key was absent and the agentic path
    # used the cloud passthrough.
    re_backend: str = "cloud"
    # TRANSPORT for the single-shot paths (.NET, Java, Office, PowerShell), which
    # is SEPARATE from re_backend above. Defaulted so an older config.json still
    # loads, and "cloud" reproduces the historical behaviour.
    single_shot_backend: str = "cloud"
    # Which .NET interpret path runs (#646). "agentic": a map of the assembly
    # plus tools that read the decompiled C# on demand, through the same loop,
    # limits and forced-final salvage as the Ghidra path. "single_shot": the
    # previous path, the whole stored source in one request — 38-58k tokens and
    # 45-90 minutes of prefill on the local host, which the stage budget cannot
    # interrupt. Kept so the eval can A/B the two. A Literal, so a typo fails at
    # startup rather than silently choosing a path.
    dotnet_mode: Literal["agentic", "single_shot"] = "agentic"
    # Size bounds of the agentic .NET path (map and tool results). Defaults are
    # sized for CPU prefill on the current host; a faster host raises them here
    # instead of in code. Mirrors stages/dotnet_tools.DotnetToolLimits, whose
    # defaults test_dotnet_mode_config.py holds equal to these.
    dotnet_tool_limits: DotnetToolLimits = Field(default_factory=DotnetToolLimits)
    # The sandbox that executes those tools (ADR-021: never in this process) and
    # the container timeout it passes to podman; the broker adds 15 s on top.
    dotnet_tools_cmd: str = "/opt/pipeline/run-dotnet-tools"
    dotnet_tools_timeout: int = Field(default=30, ge=1)
    # Wall-clock budget for the whole summarize container run. Defaulted rather than
    # required so a config.json written before this key still loads — the eval harness
    # passes whole config dicts through and an older one would fail validation, which
    # `extra="forbid"` makes a hard error rather than a warning.
    summary_timeout: int = 900


# The InterpretConfig fields an LLM profile replaces: which models, and which
# transport reaches them. Nothing else (limits, timeouts, modes) changes with a profile.
# One agent model per run, plus the short single-shot prompts' own models (ADR-038).
MODEL_FIELDS = ("model", "summary_model", "plain_english_model")
PROFILE_FIELDS = MODEL_FIELDS + ("re_backend", "single_shot_backend")
LOCAL_PROFILE = "local"
# LiteLLM aliases served on this host. A profile with cloud: false may name only
# these; tests/test_llm_profile_routing.py holds every alias that matches this
# pattern to a loopback api_base in the rendered LiteLLM config, so the pattern
# cannot drift from where the traffic really goes.
LOCAL_ALIAS_RE = r"local-qwen-llamacpp[a-z0-9-]*|stub"
# Cloud aliases a profile may name: the eval-only entries, which carry no
# production key and which tests/test_frontier_arms_are_eval_only.py keeps out of
# every production setting. A cloud profile cannot borrow the analyst's models.
CLOUD_ALIAS_RE = r"eval-[a-z0-9-]+"


class LlmProfile(BaseModel):
    """A named choice of models for one run (ADR-036), chosen with --llm-profile.

    `cloud` declares that the profile sends prompts (decompiled code, strings,
    behaviour) off the host. It is checked against the LiteLLM routes at deploy
    and test time, and recorded in every report the profile produces.
    """
    model_config = ConfigDict(extra="forbid")
    description: str = ""
    cloud: bool
    model: str
    summary_model: str
    plain_english_model: str
    re_backend: str = "local"
    single_shot_backend: str = "local"

    @model_validator(mode="before")
    @classmethod
    def _no_escalation(cls, data):
        """ADR-038 removed escalation; say so, rather than pydantic's "extra field"."""
        if isinstance(data, dict) and ("escalation_model" in data or "escalation_threshold" in data):
            raise ValueError("escalation_model was removed (ADR-038: one model per run); "
                             "delete it from the profile, and set `model` to the model you want")
        return data


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    malfind_enabled: bool
    malfind_max_candidates: int
    malfind_min_size: int
    malfind_max_size: int
    malfind_min_score: int
    malfind_benign_processes: list[str]

    # Phase 2b-1 — analysis-tool command paths
    cape_api_url: str
    triage_cmd: str
    volatility_cmd: str
    ghidra_cmd: str
    dotnet_cmd: str
    go_cmd: str
    pyinstaller_cmd: str
    java_cmd: str
    office_cmd: str
    powershell_cmd: str
    screenshot_cmd: str
    pdf_cmd: str
    interpret_cmd: str
    pcap_cmd: str

    # Phase 2b-1 — scalar tuning knobs
    interpret_enabled: bool
    interpret_timeout: int
    # Grace for the forced final after interpret_timeout expires. Defaulted so
    # an older config.json still loads; 300 rather than the previous hardcoded
    # 30 because a local synthesis takes minutes, and at 30s the forced final
    # could never arrive — every timeout was reported as a crash.
    interpret_force_final_grace: int = 300
    # Seconds of interpret_timeout held back for synthesis: tool calls are not
    # granted inside it (#240). Defaulted to 0 (no reserve, the old behaviour) so
    # an older config.json still loads; config.json.j2 always renders it.
    interpret_synthesis_reserve: int = Field(default=0, ge=0)
    # Pass the behavioural evidence (stages/correlated_evidence.py) to the
    # agentic RE agent (#674). Top-level, not in InterpretConfig: that model is
    # dumped and sent to the container as-is, and this is the orchestrator's
    # choice of what to send. Defaulted True so an older config.json loads with
    # the new behaviour; false is the measured-against baseline.
    interpret_correlated_evidence: bool = True
    reports_dir: str
    cape_poll_interval: int
    cape_timeout: int
    # cuckoo.conf `freespace`, in MB: CAPE's scheduler starts nothing below it
    # and says nothing to the submitter (#795). The pipeline checks the same
    # number before submitting. Defaulted to CAPE's shipped value so an older
    # config.json still loads.
    cape_freespace_floor_mb: int = Field(default=50000, ge=0)
    # Which guest a submission is pinned to. Defaulted so an older config.json
    # still loads. Both guests are tagged x64 in kvm.conf, so tags alone do not
    # select one and an unpinned submission lands on whichever is free.
    cape_machine: str = "clean"
    cape_office_machine: str = "office"
    # Request a full-VM RAM dump. OFF by default: it is 8.6 GB a run and
    # conf/memory.conf sets delete_memdump=no, so eight runs filled the disk and
    # CAPE silently stopped scheduling below freespace=50000. The Volatility
    # stage is its only consumer and reports honestly when it is off.
    cape_memory_dump: bool = False
    pcap_enabled: bool
    pcap_timeout: int
    evasion_hunter_enabled: bool
    evasion_max_signatures: int
    evasion_min_binary_size: int
    volatility_parallel_workers: int

    # Phase 2b-2 — collections
    interpret: InterpretConfig
    volatility_triggers: list[str]
    volatility_extra_plugins: dict[str, dict[str, list[str]]]

    # Phase 3b — DB connection (non-secret; PIPELINE_DB_PASSWORD comes from the env)
    db_host: str
    db_port: int
    db_name: str
    db_user: str

    # Campaign-graph relationship thresholds (2026-06-26)
    relationship_max_ioc_frequency: int
    relationship_ssdeep_threshold: int

    # Named LLM profiles a run may choose with --llm-profile (ADR-036). The
    # "local" profile is the `interpret` block itself and cannot be redefined. A run
    # without the flag gets default_llm_profile. Defaulted empty so an older
    # config.json still loads.
    llm_profiles: dict[str, LlmProfile] = Field(default_factory=dict)
    # The profile every run without --llm-profile uses: API submissions, the feeder,
    # intake without LLM_PROFILE (ADR-038). Ships as "local"; the operator changes it
    # with pipeline_default_llm_profile (or `make llm-default PROFILE=...`).
    default_llm_profile: str = LOCAL_PROFILE
    # Where the orchestrator reads LiteLLM's spend log for a run's cost (ADR-037).
    # Defaulted so an older config.json still loads.
    # LiteLLM's Unix socket (litellm-socket.service). The pipeline user reaches LiteLLM
    # only this way; its egress rules drop TCP to LiteLLM's port.
    litellm_socket: str = "/run/litellm/litellm.sock"

    @model_validator(mode="after")
    def _profile_names_are_safe(self) -> "PipelineConfig":
        for name in self.llm_profiles:
            if name == LOCAL_PROFILE:
                raise ValueError(f'llm_profiles may not define "{LOCAL_PROFILE}": it is the '
                                 f"interpret block, so a run without --llm-profile is unchanged")
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", name):
                raise ValueError(f"llm profile name {name!r}: lowercase letters, digits, '-'")
            prof = self.llm_profiles[name]
            remote = [m for m in (getattr(prof, f) for f in MODEL_FIELDS)
                      if not re.fullmatch(LOCAL_ALIAS_RE, m)]
            if remote and not prof.cloud:
                # Fail closed: a mislabelled profile would send decompiled malware
                # off the host while its reports said it did not.
                raise ValueError(f"llm profile {name!r} has cloud: false but names "
                                 f"{', '.join(sorted(set(remote)))}, which is not a local alias")
            models = [getattr(prof, f) for f in MODEL_FIELDS]
            transports = (prof.re_backend, prof.single_shot_backend)
            if prof.cloud:
                bad = [m for m in models if not re.fullmatch(CLOUD_ALIAS_RE, m)]
                if bad:
                    raise ValueError(f"llm profile {name!r}: a cloud profile names only eval-* "
                                     f"aliases (no production key); got {', '.join(sorted(set(bad)))}")
                if transports != ("router", "router"):
                    # #722: a cloud model on the local transports takes the local
                    # synthesis paths, which some models reject and which bill nothing.
                    raise ValueError(f"llm profile {name!r}: a cloud profile needs re_backend "
                                     f"and single_shot_backend 'router', got {transports}")
            elif transports != ("local", "local"):
                raise ValueError(f"llm profile {name!r}: a local profile needs re_backend and "
                                 f"single_shot_backend 'local', got {transports}")
        return self

    @model_validator(mode="after")
    def _default_profile_is_defined(self) -> "PipelineConfig":
        if self.default_llm_profile not in self.profile_names():
            raise ValueError(f"default_llm_profile {self.default_llm_profile!r} is not a defined "
                             f"profile; defined: {', '.join(self.profile_names())}")
        return self

    def profile_names(self) -> list[str]:
        return [LOCAL_PROFILE, *sorted(self.llm_profiles)]

    def interpret_for(self, profile: str) -> InterpretConfig:
        """The interpret settings for a run under `profile`. Unknown names raise."""
        if profile == LOCAL_PROFILE:
            return self.interpret
        if profile not in self.llm_profiles:
            raise ValueError(f"unknown LLM profile {profile!r}; defined: "
                             f"{', '.join(self.profile_names())}")
        chosen = self.llm_profiles[profile]
        return self.interpret.model_copy(update={f: getattr(chosen, f) for f in PROFILE_FIELDS})

    def profile_is_cloud(self, profile: str) -> bool:
        return profile != LOCAL_PROFILE and self.llm_profiles[profile].cloud

    @model_validator(mode="after")
    def _reserve_leaves_a_tool_loop(self) -> "PipelineConfig":
        """A reserve at or above the budget refuses every tool call.

        That would not fail anything: every run would still return a final, built
        from the initial prompt alone, and look healthy. Refuse it at load time
        instead of letting it degrade silently.
        """
        if self.interpret_synthesis_reserve >= self.interpret_timeout:
            raise ValueError(
                f"interpret_synthesis_reserve ({self.interpret_synthesis_reserve}s) must "
                f"be below interpret_timeout ({self.interpret_timeout}s), or no tool "
                f"call is ever granted")
        return self

    @classmethod
    def load(cls, path: str) -> "PipelineConfig":
        return cls.model_validate_json(Path(path).read_text())
