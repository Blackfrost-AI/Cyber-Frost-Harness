from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _required(mapping: dict[str, Any], key: str, section: str) -> Any:
    if key not in mapping:
        raise ValueError(f"missing [{section}].{key}")
    return mapping[key]


def _path(value: str, base: Path) -> Path:
    candidate = Path(value).expanduser()
    return candidate if candidate.is_absolute() else (base / candidate).resolve()


@dataclass(frozen=True)
class ModelConfig:
    base_url: str
    model: str
    api_key_env: str = "CYBER_FROST_API_KEY"
    temperature: float = 1.0
    top_p: float = 0.95
    max_completion_tokens: int = 131072
    context_window_tokens: int = 262144
    context_safety_tokens: int = 4096
    min_completion_tokens: int = 16384
    estimated_chars_per_token: float = 3.0
    reasoning_effort: str = "xhigh"
    seed: int = 38421
    request_timeout_seconds: int = 900

    @property
    def api_key(self) -> str:
        return os.getenv(self.api_key_env, "EMPTY")


@dataclass(frozen=True)
class RuntimeConfig:
    transport: str
    ssh_target: str | None
    ssh_port: int
    ssh_key: Path | None
    known_hosts: Path | None
    container_prefix: str = "cfh"
    cpus: int = 24
    memory: str = "96g"
    pids_limit: int = 256
    command_timeout_seconds: int = 900
    network: str = "none"
    sanitizer_compat: bool = True


@dataclass(frozen=True)
class AgentConfig:
    mode: str
    max_steps: int
    max_repeated_tool_calls: int
    max_submissions: int
    max_tool_output_chars: int
    checkpoint_interval: int
    skill_dir: Path
    system_prompt: Path


@dataclass(frozen=True)
class BenchmarkConfig:
    cybergym_root: Path
    data_dir: Path
    mask_map: Path
    server_url: str
    submission_port: int
    difficulty: str


@dataclass(frozen=True)
class HarnessConfig:
    path: Path
    model: ModelConfig
    runtime: RuntimeConfig
    agent: AgentConfig
    benchmark: BenchmarkConfig


def load_config(path: str | Path) -> HarnessConfig:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)
    base = config_path.parent

    model_raw = raw.get("model", {})
    runtime_raw = raw.get("runtime", {})
    agent_raw = raw.get("agent", {})
    benchmark_raw = raw.get("benchmark", {})

    model = ModelConfig(
        base_url=str(_required(model_raw, "base_url", "model")).rstrip("/"),
        model=str(_required(model_raw, "model", "model")),
        api_key_env=str(model_raw.get("api_key_env", "CYBER_FROST_API_KEY")),
        temperature=float(model_raw.get("temperature", 1.0)),
        top_p=float(model_raw.get("top_p", 0.95)),
        max_completion_tokens=int(model_raw.get("max_completion_tokens", 131072)),
        context_window_tokens=int(model_raw.get("context_window_tokens", 262144)),
        context_safety_tokens=int(model_raw.get("context_safety_tokens", 4096)),
        min_completion_tokens=int(model_raw.get("min_completion_tokens", 16384)),
        estimated_chars_per_token=float(
            model_raw.get("estimated_chars_per_token", 3.0)
        ),
        reasoning_effort=str(model_raw.get("reasoning_effort", "xhigh")),
        seed=int(model_raw.get("seed", 38421)),
        request_timeout_seconds=int(model_raw.get("request_timeout_seconds", 900)),
    )

    transport = str(runtime_raw.get("transport", "local-docker"))
    if transport not in {"local-docker", "ssh-docker"}:
        raise ValueError("[runtime].transport must be local-docker or ssh-docker")
    ssh_key_value = runtime_raw.get("ssh_key")
    known_hosts_value = runtime_raw.get("known_hosts")
    runtime = RuntimeConfig(
        transport=transport,
        ssh_target=str(runtime_raw["ssh_target"]) if runtime_raw.get("ssh_target") else None,
        ssh_port=int(runtime_raw.get("ssh_port", 22)),
        ssh_key=_path(str(ssh_key_value), base) if ssh_key_value else None,
        known_hosts=_path(str(known_hosts_value), base) if known_hosts_value else None,
        container_prefix=str(runtime_raw.get("container_prefix", "cfh")),
        cpus=int(runtime_raw.get("cpus", 24)),
        memory=str(runtime_raw.get("memory", "96g")),
        pids_limit=int(runtime_raw.get("pids_limit", 256)),
        command_timeout_seconds=int(runtime_raw.get("command_timeout_seconds", 900)),
        network=str(runtime_raw.get("network", "none")),
        sanitizer_compat=bool(runtime_raw.get("sanitizer_compat", True)),
    )
    if transport == "ssh-docker" and not all(
        [runtime.ssh_target, runtime.ssh_key, runtime.known_hosts]
    ):
        raise ValueError("ssh-docker requires ssh_target, ssh_key, and known_hosts")
    if runtime.pids_limit < 32:
        raise ValueError("[runtime].pids_limit must be at least 32")
    if model.context_window_tokens <= model.context_safety_tokens:
        raise ValueError("[model].context_window_tokens must exceed context_safety_tokens")
    if not 0 < model.min_completion_tokens <= model.max_completion_tokens:
        raise ValueError(
            "[model].min_completion_tokens must be positive and no greater than "
            "max_completion_tokens"
        )
    if model.max_completion_tokens + model.context_safety_tokens >= model.context_window_tokens:
        raise ValueError(
            "[model].max_completion_tokens plus context_safety_tokens must leave room "
            "for the prompt"
        )
    if model.estimated_chars_per_token <= 0:
        raise ValueError("[model].estimated_chars_per_token must be positive")

    mode = str(agent_raw.get("mode", "red"))
    if mode not in {"red", "blue", "purple"}:
        raise ValueError("[agent].mode must be red, blue, or purple")
    agent = AgentConfig(
        mode=mode,
        max_steps=int(agent_raw.get("max_steps", 100)),
        max_repeated_tool_calls=int(agent_raw.get("max_repeated_tool_calls", 2)),
        max_submissions=int(agent_raw.get("max_submissions", 10)),
        max_tool_output_chars=int(agent_raw.get("max_tool_output_chars", 30000)),
        checkpoint_interval=int(agent_raw.get("checkpoint_interval", 12)),
        skill_dir=_path(str(agent_raw.get("skill_dir", "skills")), base),
        system_prompt=_path(str(agent_raw.get("system_prompt", "prompts/system.md")), base),
    )
    if agent.mode not in {"red", "blue", "purple"}:
        raise ValueError("[agent].mode must be red, blue, or purple")

    benchmark = BenchmarkConfig(
        cybergym_root=_path(
            str(_required(benchmark_raw, "cybergym_root", "benchmark")), base
        ),
        data_dir=_path(str(_required(benchmark_raw, "data_dir", "benchmark")), base),
        mask_map=_path(str(_required(benchmark_raw, "mask_map", "benchmark")), base),
        server_url=str(_required(benchmark_raw, "server_url", "benchmark")).rstrip("/"),
        submission_port=int(benchmark_raw.get("submission_port", 8668)),
        difficulty=str(benchmark_raw.get("difficulty", "level0")),
    )
    return HarnessConfig(config_path, model, runtime, agent, benchmark)
