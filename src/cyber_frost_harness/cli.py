from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from .agent import SecurityAgent
from .config import HarnessConfig, load_config
from .failure_analysis import write_analysis
from .model import OpenAICompatibleClient
from .session import RunSession, utc_now
from .skills import SkillLibrary
from .target import inspect_target
from .tools import ToolRegistry
from .transport import DockerTransport, image_for_task


def _json_print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")


def _tool_result(registry: ToolRegistry, name: str, arguments: dict[str, Any]) -> Any:
    payload = json.loads(registry.execute(name, arguments))
    if not payload.get("ok"):
        raise RuntimeError(f"{name} failed: {payload.get('error')}")
    return payload.get("result")


def _load(args: argparse.Namespace) -> HarnessConfig:
    return load_config(args.config)


def command_doctor(args: argparse.Namespace) -> int:
    config = _load(args)
    checks: dict[str, Any] = {}
    checks["config"] = {"ok": True, "path": str(config.path)}
    for label, path in {
        "skills": config.agent.skill_dir,
        "system_prompt": config.agent.system_prompt,
        "cybergym_root": config.benchmark.cybergym_root,
        "data_dir": config.benchmark.data_dir,
        "mask_map": config.benchmark.mask_map,
    }.items():
        checks[label] = {"ok": path.exists(), "path": str(path)}
    try:
        skills = SkillLibrary(config.agent.skill_dir)
        checks["skill_catalog"] = {"ok": True, "skills": skills.names()}
    except Exception as exc:
        checks["skill_catalog"] = {"ok": False, "error": str(exc)}
    try:
        models = OpenAICompatibleClient(config.model).models()
        ids = [str(item.get("id")) for item in models.get("data", [])]
        checks["model_endpoint"] = {
            "ok": config.model.model in ids,
            "base_url": config.model.base_url,
            "configured_model": config.model.model,
            "available_models": ids,
        }
    except Exception as exc:
        checks["model_endpoint"] = {"ok": False, "error": str(exc)}
    try:
        transport = DockerTransport(config.runtime)
        architecture = transport.host_architecture()
        checks["runtime_host"] = {
            "ok": architecture == "x86_64",
            "architecture": architecture,
            "transport": config.runtime.transport,
        }
        if args.task_id:
            image = image_for_task(args.task_id)
            checks["task_image"] = {
                "ok": transport.image_exists(image),
                "image": image,
            }
    except Exception as exc:
        checks["runtime_host"] = {"ok": False, "error": str(exc)}
    ok = all(bool(value.get("ok")) for value in checks.values())
    _json_print({"ok": ok, "checks": checks})
    return 0 if ok else 1


def command_list_skills(args: argparse.Namespace) -> int:
    config = _load(args)
    _json_print(SkillLibrary(config.agent.skill_dir).catalog())
    return 0


def command_probe_model(args: argparse.Namespace) -> int:
    config = _load(args)
    probe_model = replace(
        config.model,
        max_completion_tokens=min(config.model.max_completion_tokens, 8192),
    )
    client = OpenAICompatibleClient(probe_model)
    tools = [
        {
            "type": "function",
            "function": {
                "name": "echo_probe",
                "description": "Return the supplied protocol marker.",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "finish_probe",
                "description": "Complete the protocol probe after echo_probe returns.",
                "parameters": {
                    "type": "object",
                    "properties": {"status": {"type": "string", "enum": ["ready"]}},
                    "required": ["status"],
                    "additionalProperties": False,
                },
            },
        },
    ]
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "This is a two-step tool-protocol test. First call echo_probe exactly once "
                "with value cyber-frost-ready. After its tool result, call finish_probe "
                "exactly once with status ready. Do not answer in prose."
            ),
        },
        {"role": "user", "content": "Run the two-step probe now."},
    ]

    def parsed_calls(reply: Any) -> list[dict[str, Any]]:
        parsed: list[dict[str, Any]] = []
        for call in reply.message.get("tool_calls") or []:
            function = call.get("function") or {}
            raw_arguments = function.get("arguments") or "{}"
            try:
                arguments = raw_arguments if isinstance(raw_arguments, dict) else json.loads(raw_arguments)
            except json.JSONDecodeError:
                arguments = {"_invalid_json": raw_arguments}
            parsed.append({"name": function.get("name"), "arguments": arguments})
        return parsed

    first_reply = client.complete(messages, tools)
    first_calls = parsed_calls(first_reply)
    first_expected = {"name": "echo_probe", "arguments": {"value": "cyber-frost-ready"}}
    first_ok = len(first_calls) == 1 and first_calls[0] == first_expected
    second_reply = None
    second_calls: list[dict[str, Any]] = []
    if first_ok:
        raw_call = (first_reply.message.get("tool_calls") or [])[0]
        messages.append(SecurityAgent._assistant_message(first_reply))
        messages.append(
            {
                "role": "tool",
                "tool_call_id": str(raw_call.get("id")),
                "name": "echo_probe",
                "content": json.dumps({"ok": True, "value": "cyber-frost-ready"}),
            }
        )
        second_reply = client.complete(messages, tools)
        second_calls = parsed_calls(second_reply)
    second_expected = {"name": "finish_probe", "arguments": {"status": "ready"}}
    second_ok = len(second_calls) == 1 and second_calls[0] == second_expected
    ok = first_ok and second_ok
    _json_print(
        {
            "ok": ok,
            "model": first_reply.model,
            "first": {
                "finish_reason": first_reply.finish_reason,
                "tool_calls": first_calls,
                "reasoning_present": bool(first_reply.message.get("reasoning_content")),
                "usage": first_reply.usage,
            },
            "second": {
                "finish_reason": second_reply.finish_reason if second_reply else None,
                "tool_calls": second_calls,
                "reasoning_present": bool(
                    second_reply and second_reply.message.get("reasoning_content")
                ),
                "usage": second_reply.usage if second_reply else {},
            },
        }
    )
    return 0 if ok else 1


def _prepare_container(
    config: HarnessConfig,
    task_id: str,
    task_dir: Path,
    run_label: str,
) -> tuple[DockerTransport, str, str, str]:
    task_dir = task_dir.resolve()
    readme_path = task_dir / "README.md"
    submit_path = task_dir / "submit.sh"
    if not readme_path.is_file() or not submit_path.is_file():
        raise FileNotFoundError("task directory must contain README.md and submit.sh")
    transport = DockerTransport(config.runtime)
    container, image = transport.create(task_id, run_label)
    readme = readme_path.read_text(encoding="utf-8")
    transport.put_bytes(container, "/workspace/README.md", readme.encode())
    transport.put_bytes(
        container,
        "/workspace/submit.sh",
        (
            "#!/bin/sh\n"
            "echo 'Use the submit_candidate tool so the result is recorded by the harness.' >&2\n"
            "exit 2\n"
        ).encode(),
    )
    transport.exec(container, "chmod 700 /workspace/submit.sh", timeout=10)
    transport.put_bytes(
        container,
        "/workspace/HARNESS.md",
        (
            "# Native analysis environment\n\n"
            "- Vulnerable source: `/src`\n"
            "- Instrumented targets, corpora, dictionaries: `/out`\n"
            "- Durable generated artifacts: `/artifacts`\n"
            "- Working files: `/workspace`\n"
            "- Submit candidates with the `submit_candidate` tool.\n"
        ).encode(),
    )
    return transport, container, image, readme


def command_inspect_task(args: argparse.Namespace) -> int:
    config = _load(args)
    transport: DockerTransport | None = None
    container: str | None = None
    try:
        transport, container, image, _readme = _prepare_container(
            config, args.task_id, Path(args.task_dir), "inspect"
        )
        inventory = inspect_target(transport, container, image)
        _json_print(inventory.to_dict())
        return 0
    finally:
        if transport and container and not args.keep_container:
            transport.cleanup(container)


def command_smoke_task(args: argparse.Namespace) -> int:
    """Exercise real native tools without invoking the benchmark submission oracle."""
    config = _load(args)
    task_dir = Path(args.task_dir).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve()
    if run_dir.exists() and any(run_dir.iterdir()):
        raise FileExistsError(f"run directory is not empty: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    transport: DockerTransport | None = None
    container: str | None = None
    try:
        transport, container, image, _readme = _prepare_container(
            config, args.task_id, task_dir, f"smoke-{run_dir.name}"
        )
        inventory = inspect_target(transport, container, image)
        if not inventory.selected_target:
            raise RuntimeError("smoke test requires an unambiguous wrapper-selected target")
        session = RunSession(
            run_dir=run_dir,
            task_id=args.task_id,
            task_dir=task_dir,
            transport=transport,
            container=container,
            max_submissions=1,
        )
        registry = ToolRegistry(
            config.agent,
            transport,
            session,
            SkillLibrary(config.agent.skill_dir),
            inventory,
        )
        results: dict[str, Any] = {"inventory": inventory.to_dict()}
        results["write_workspace_file"] = _tool_result(
            registry,
            "write_workspace_file",
            {
                "path": "/workspace/cfh-smoke-marker.txt",
                "content": "cyber-frost-native-smoke\n",
            },
        )
        smoke_patch = (
            "--- /dev/null\n"
            "+++ b/cfh-smoke-patch.txt\n"
            "@@ -0,0 +1 @@\n"
            "+cyber-frost-blue-tool-smoke\n"
        )
        results["apply_source_patch"] = _tool_result(
            registry, "apply_source_patch", {"patch": smoke_patch, "strip": 1}
        )
        if int(results["apply_source_patch"].get("returncode", 1)) != 0:
            raise RuntimeError(
                "apply_source_patch returned nonzero: "
                + str(results["apply_source_patch"].get("stderr") or results["apply_source_patch"].get("stdout"))
            )
        results["prepare_corpus"] = _tool_result(registry, "prepare_corpus", {})
        corpus = str(results["prepare_corpus"]["corpus"])
        seed_result = transport.exec(
            container,
            f"find {shlex.quote(corpus)} -type f -print -quit",
            cwd="/",
            timeout=30,
        )
        seed = seed_result.stdout.strip()
        if seed_result.returncode or not seed:
            raise RuntimeError("prepared corpus contained no replayable seed")
        results["seed"] = seed
        results["replay_input"] = _tool_result(
            registry,
            "replay_input",
            {"target": inventory.selected_target, "input_path": seed, "timeout_seconds": 30},
        )
        results["run_fuzzer"] = _tool_result(
            registry,
            "run_fuzzer",
            {
                "target": inventory.selected_target,
                "corpus": corpus,
                "seconds": max(5, min(30, int(args.seconds))),
                "workers": 1,
                "seed": config.model.seed,
            },
        )
        artifact_dir = str(results["run_fuzzer"]["artifact_dir"])
        listing = transport.exec(
            container,
            f"find {shlex.quote(artifact_dir)} -maxdepth 1 -type f -print",
            cwd="/",
            timeout=30,
        )
        copied: list[dict[str, Any]] = []
        local_artifacts = run_dir / "artifacts"
        local_artifacts.mkdir(exist_ok=True)
        for remote_path in filter(None, listing.stdout.splitlines()):
            data = transport.get_bytes(container, remote_path)
            digest = hashlib.sha256(data).hexdigest()
            destination = local_artifacts / f"{digest[:12]}-{Path(remote_path).name}"
            destination.write_bytes(data)
            replay = _tool_result(
                registry,
                "replay_input",
                {
                    "target": inventory.selected_target,
                    "input_path": remote_path,
                    "timeout_seconds": 30,
                },
            )
            copied.append(
                {
                    "remote_path": remote_path,
                    "local_path": str(destination),
                    "sha256": digest,
                    "size": len(data),
                    "replay": replay,
                }
            )
        results["preserved_artifacts"] = copied
        results["ok"] = True
        _write_json(run_dir / "smoke-results.json", results)
        _json_print(
            {
                "ok": True,
                "task_id": args.task_id,
                "architecture": inventory.architecture,
                "target": inventory.selected_target,
                "seed": seed,
                "replay_returncode": results["replay_input"].get("returncode"),
                "fuzzer_returncode": results["run_fuzzer"].get("returncode"),
                "preserved_artifacts": len(copied),
                "result": str(run_dir / "smoke-results.json"),
            }
        )
        return 0
    finally:
        if transport and container and not args.keep_container:
            transport.cleanup(container)


def command_run_task(args: argparse.Namespace) -> int:
    config = _load(args)
    if args.mode:
        config = replace(config, agent=replace(config.agent, mode=args.mode))
    task_dir = Path(args.task_dir).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve()
    if run_dir.exists() and any(run_dir.iterdir()):
        raise FileExistsError(f"run directory is not empty: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    transport: DockerTransport | None = None
    container: str | None = None
    try:
        transport, container, image, readme = _prepare_container(
            config, args.task_id, task_dir, run_dir.name
        )
        inventory = inspect_target(transport, container, image)
        environment = {
            "created_at": utc_now(),
            "task_id": args.task_id,
            "task_dir": str(task_dir),
            "container": container,
            "image": image,
            "network": config.runtime.network,
            "model": asdict(config.model),
            "agent": asdict(config.agent),
            "inventory": inventory.to_dict(),
        }
        environment["model"].pop("api_key_env", None)
        _write_json(run_dir / "environment.json", environment)

        session = RunSession(
            run_dir=run_dir,
            task_id=args.task_id,
            task_dir=task_dir,
            transport=transport,
            container=container,
            max_submissions=config.agent.max_submissions,
        )
        skills = SkillLibrary(config.agent.skill_dir)
        registry = ToolRegistry(config.agent, transport, session, skills, inventory)
        agent = SecurityAgent(
            config=config,
            client=OpenAICompatibleClient(config.model),
            session=session,
            skills=skills,
            tools=registry,
            inventory=inventory,
            task_readme=readme,
        )
        result = agent.run()
        _json_print(result)
        return 0 if result.get("status") == "solved" else 2
    finally:
        if transport and container and not args.keep_container:
            transport.cleanup(container)


def command_finalize_candidate(args: argparse.Namespace) -> int:
    """Finalize preserved candidate bytes after an interrupted model session."""
    run_dir = Path(args.run_dir).expanduser().resolve()
    task_dir = Path(args.task_dir).expanduser().resolve()
    session = RunSession(
        run_dir=run_dir,
        task_id=args.task_id,
        task_dir=task_dir,
        transport=object(),  # Offline recovery does not access a task container.
        container="offline-recovery",
        max_submissions=max(2, int(args.max_submissions)),
    )
    session.submit_local_candidate(
        Path(args.candidate),
        args.remote_path,
        args.rationale,
    )
    result = session.finish(
        status=args.status,
        summary=args.summary,
        root_cause=args.root_cause,
        final_candidate=args.remote_path,
    )
    _json_print(result)
    return 0 if args.status == "solved" else 2


def command_analyze_run(args: argparse.Namespace) -> int:
    payload = write_analysis(
        Path(args.run_root),
        Path(args.output),
        Path(args.selection) if args.selection else None,
    )
    _json_print(payload["summary"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cfh", description="Cyber-Frost security harness")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="validate model, skills, paths, and runtime host")
    doctor.add_argument("--config", required=True)
    doctor.add_argument("--task-id")
    doctor.set_defaults(func=command_doctor)

    list_skills = subparsers.add_parser("list-skills", help="show the harness skill catalog")
    list_skills.add_argument("--config", required=True)
    list_skills.set_defaults(func=command_list_skills)

    probe_model = subparsers.add_parser(
        "probe-model", help="validate one real tool call against the configured model endpoint"
    )
    probe_model.add_argument("--config", required=True)
    probe_model.set_defaults(func=command_probe_model)

    inspect_task_parser = subparsers.add_parser(
        "inspect-task", help="create, inspect, and clean a native vulnerable task container"
    )
    inspect_task_parser.add_argument("--config", required=True)
    inspect_task_parser.add_argument("--task-id", required=True)
    inspect_task_parser.add_argument("--task-dir", required=True)
    inspect_task_parser.add_argument("--keep-container", action="store_true")
    inspect_task_parser.set_defaults(func=command_inspect_task)

    smoke_task = subparsers.add_parser(
        "smoke-task", help="exercise corpus, replay, fuzzing, file, and patch tools without submission"
    )
    smoke_task.add_argument("--config", required=True)
    smoke_task.add_argument("--task-id", required=True)
    smoke_task.add_argument("--task-dir", required=True)
    smoke_task.add_argument("--run-dir", required=True)
    smoke_task.add_argument("--seconds", type=int, default=5)
    smoke_task.add_argument("--keep-container", action="store_true")
    smoke_task.set_defaults(func=command_smoke_task)

    run_task = subparsers.add_parser("run-task", help="run one model-driven harness session")
    run_task.add_argument("--config", required=True)
    run_task.add_argument("--task-id", required=True)
    run_task.add_argument("--task-dir", required=True)
    run_task.add_argument("--run-dir", required=True)
    run_task.add_argument("--mode", choices=["red", "blue", "purple"])
    run_task.add_argument("--keep-container", action="store_true")
    run_task.set_defaults(func=command_run_task)

    finalize = subparsers.add_parser(
        "finalize-candidate",
        help="submit and finalize preserved candidate bytes from an interrupted run",
    )
    finalize.add_argument("--task-id", required=True)
    finalize.add_argument("--task-dir", required=True)
    finalize.add_argument("--run-dir", required=True)
    finalize.add_argument("--candidate", required=True)
    finalize.add_argument("--remote-path", required=True)
    finalize.add_argument("--rationale", required=True)
    finalize.add_argument("--status", default="solved")
    finalize.add_argument("--summary", required=True)
    finalize.add_argument("--root-cause", required=True)
    finalize.add_argument("--max-submissions", type=int, default=5)
    finalize.set_defaults(func=command_finalize_candidate)

    analyze = subparsers.add_parser("analyze-run", help="analyze an existing CyberGym run")
    analyze.add_argument("run_root")
    analyze.add_argument("--selection")
    analyze.add_argument("--output", required=True)
    analyze.set_defaults(func=command_analyze_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
