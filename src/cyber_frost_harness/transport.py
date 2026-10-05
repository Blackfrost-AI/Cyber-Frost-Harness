from __future__ import annotations

import re
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from uuid import uuid4

from .config import RuntimeConfig


CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
TASK_RE = re.compile(r"^(arvo|oss-fuzz):([0-9]+)$")
ALLOWED_FILE_ROOTS = ("/workspace", "/artifacts", "/tmp", "/src", "/out", "/work")
EXEC_LOG_ROOT = "/workspace/.cfh-command-logs"
EXEC_CAPTURE_BYTES = 128 * 1024


@dataclass(frozen=True)
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    stdout_path: str | None = None
    stderr_path: str | None = None
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    cleaned_processes: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def image_for_task(task_id: str) -> str:
    match = TASK_RE.fullmatch(task_id)
    if not match:
        raise ValueError(f"unsupported task id: {task_id}")
    family, ident = match.groups()
    if family == "arvo":
        return f"n132/arvo:{ident}-vul"
    return f"cybergym/oss-fuzz:{ident}-vul"


def _validate_container(name: str) -> None:
    if not CONTAINER_RE.fullmatch(name):
        raise ValueError(f"invalid container name: {name!r}")


def _validate_remote_path(path: str, *, writable: bool = False) -> str:
    candidate = str(PurePosixPath(path))
    if not candidate.startswith("/") or ".." in PurePosixPath(candidate).parts:
        raise ValueError(f"invalid container path: {path!r}")
    allowed = ("/workspace", "/artifacts", "/tmp") if writable else ALLOWED_FILE_ROOTS
    if not any(candidate == root or candidate.startswith(root + "/") for root in allowed):
        raise ValueError(f"container path is outside permitted roots: {path!r}")
    return candidate


class DockerTransport:
    """Run an ephemeral vulnerable-only Docker environment locally or over SSH."""

    def __init__(self, config: RuntimeConfig):
        self.config = config

    def _host_prefix(self) -> list[str]:
        if self.config.transport == "local-docker":
            return []
        assert self.config.ssh_target
        assert self.config.ssh_key
        assert self.config.known_hosts
        return [
            "ssh",
            "-F",
            "/dev/null",
            "-i",
            str(self.config.ssh_key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.config.known_hosts}",
            "-p",
            str(self.config.ssh_port),
            self.config.ssh_target,
        ]

    def _run_host(
        self,
        argv: list[str],
        *,
        timeout: int = 60,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        if self.config.transport == "ssh-docker":
            command = self._host_prefix() + [shlex.join(argv)]
        else:
            command = argv
        return subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

    def host_architecture(self) -> str:
        result = self._run_host(["uname", "-m"], timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return result.stdout.decode().strip()

    def _read_exec_log(
        self,
        container: str,
        path: str,
        *,
        max_bytes: int = EXEC_CAPTURE_BYTES,
    ) -> tuple[str, int | None, bool]:
        stat = self._run_host(
            ["docker", "exec", container, "stat", "-c", "%s", "--", path],
            timeout=30,
        )
        if stat.returncode:
            return "", None, False
        try:
            size = int(stat.stdout.decode().strip())
        except ValueError:
            return "", None, False
        if size <= max_bytes:
            content = self._run_host(
                ["docker", "exec", container, "cat", "--", path], timeout=60
            )
            return content.stdout.decode(errors="replace"), size, False

        head_bytes = max_bytes // 2
        tail_bytes = max_bytes - head_bytes
        head = self._run_host(
            ["docker", "exec", container, "head", "-c", str(head_bytes), "--", path],
            timeout=60,
        )
        tail = self._run_host(
            ["docker", "exec", container, "tail", "-c", str(tail_bytes), "--", path],
            timeout=60,
        )
        omitted = size - max_bytes
        marker = (
            f"\n[... {omitted} bytes omitted; full output preserved at {path} ...]\n"
        ).encode()
        output = head.stdout + marker + tail.stdout
        return output.decode(errors="replace"), size, True

    def image_exists(self, image: str) -> bool:
        if not image.endswith("-vul") or "-fix" in image:
            raise ValueError("runtime image must be a vulnerable image")
        return self._run_host(["docker", "image", "inspect", image], timeout=30).returncode == 0

    def create(self, task_id: str, run_label: str | None = None) -> tuple[str, str]:
        image = image_for_task(task_id)
        if not self.image_exists(image):
            raise RuntimeError(f"native vulnerable image is missing: {image}")
        ident = TASK_RE.fullmatch(task_id).group(2)  # type: ignore[union-attr]
        suffix = (run_label or uuid4().hex[:10]).lower()
        suffix = re.sub(r"[^a-z0-9_.-]", "-", suffix)[:32]
        name = f"{self.config.container_prefix}-{ident}-{suffix}"
        _validate_container(name)

        create = [
            "docker",
            "create",
            "--name",
            name,
            "--hostname",
            "cyber-frost-target",
            "--init",
            "--network",
            self.config.network,
            "--cpus",
            str(self.config.cpus),
            "--memory",
            self.config.memory,
            "--pids-limit",
            str(self.config.pids_limit),
        ]
        if self.config.sanitizer_compat:
            create += ["--security-opt", "seccomp=unconfined", "--cap-add", "SYS_ADMIN"]
        create += ["--entrypoint", "/bin/bash", image, "-lc", "sleep infinity"]
        result = self._run_host(create, timeout=60)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        started = self._run_host(["docker", "start", name], timeout=60)
        if started.returncode:
            self._run_host(["docker", "rm", "-f", name], timeout=30)
            raise RuntimeError(started.stderr.decode(errors="replace"))

        sanitize = (
            "rm -f -- /tmp/poc; "
            "find /src -type d -name .git -prune -exec rm -rf -- {} +; "
            "mkdir -p /workspace /workspace/corpus /artifacts; "
            "chmod 700 /workspace /artifacts"
        )
        cleaned = self.exec(name, sanitize, cwd="/", timeout=120)
        if cleaned.returncode:
            self.cleanup(name)
            raise RuntimeError(f"container sanitization failed: {cleaned.stderr or cleaned.stdout}")
        return name, image

    def _cleanup_exec_processes(self, container: str, token: str) -> int:
        """Terminate descendants that detached from a completed tool command."""
        script = r'''
marker="CFH_EXEC_TOKEN=$1"
pids=""
for envfile in /proc/[0-9]*/environ; do
    [ -r "$envfile" ] || continue
    if tr '\000' '\n' < "$envfile" 2>/dev/null | grep -Fqx -- "$marker"; then
        pid=${envfile#/proc/}
        pid=${pid%/environ}
        case "$pid" in ''|*[!0-9]*) continue ;; esac
        pids="$pids $pid"
    fi
done
count=0
for pid in $pids; do
    if kill -TERM "$pid" 2>/dev/null; then count=$((count + 1)); fi
done
if [ "$count" -gt 0 ]; then sleep 1; fi
for pid in $pids; do kill -KILL "$pid" 2>/dev/null || true; done
printf '%s\n' "$count"
'''.strip()
        result = self._run_host(
            [
                "docker",
                "exec",
                container,
                "/bin/bash",
                "-c",
                script,
                "cfh-cleanup",
                token,
            ],
            timeout=20,
        )
        if result.returncode:
            return 0
        try:
            return int(result.stdout.decode().strip() or "0")
        except ValueError:
            return 0

    def exec(
        self,
        container: str,
        command: str,
        *,
        cwd: str = "/workspace",
        timeout: int | None = None,
    ) -> CommandResult:
        _validate_container(container)
        cwd = "/" if cwd == "/" else _validate_remote_path(cwd)
        limit = timeout or self.config.command_timeout_seconds
        started = time.monotonic()
        log_token = uuid4().hex
        exec_token = uuid4().hex
        stdout_path = f"{EXEC_LOG_ROOT}/{log_token}.stdout"
        stderr_path = f"{EXEC_LOG_ROOT}/{log_token}.stderr"
        wrapper = (
            'umask 077; mkdir -p -- "$1"; '
            '/bin/bash -lc "$4" >"$2" 2>"$3"'
        )
        argv = [
            "timeout",
            "--signal=KILL",
            str(limit),
            "docker",
            "exec",
            "--env",
            f"CFH_EXEC_TOKEN={exec_token}",
            "-w",
            cwd,
            container,
            "/bin/bash",
            "-c",
            wrapper,
            "cfh-exec",
            EXEC_LOG_ROOT,
            stdout_path,
            stderr_path,
            command,
        ]
        try:
            result = self._run_host(argv, timeout=limit + 30)
            elapsed = time.monotonic() - started
            cleaned_processes = self._cleanup_exec_processes(container, exec_token)
            stdout, stdout_bytes, stdout_truncated = self._read_exec_log(
                container, stdout_path
            )
            stderr, stderr_bytes, stderr_truncated = self._read_exec_log(
                container, stderr_path
            )
            if result.stdout:
                stdout += result.stdout.decode(errors="replace")
            if result.stderr:
                stderr += result.stderr.decode(errors="replace")
            return CommandResult(
                command=command,
                returncode=result.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=elapsed,
                timed_out=result.returncode in {124, 137},
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                cleaned_processes=cleaned_processes,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - started
            cleaned_processes = self._cleanup_exec_processes(container, exec_token)
            stdout, stdout_bytes, stdout_truncated = self._read_exec_log(
                container, stdout_path
            )
            stderr, stderr_bytes, stderr_truncated = self._read_exec_log(
                container, stderr_path
            )
            stdout += (exc.stdout or b"").decode(errors="replace")
            stderr += (exc.stderr or b"").decode(errors="replace")
            return CommandResult(
                command=command,
                returncode=124,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=elapsed,
                timed_out=True,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                cleaned_processes=cleaned_processes,
            )

    def put_bytes(self, container: str, path: str, data: bytes) -> None:
        _validate_container(container)
        path = _validate_remote_path(path, writable=True)
        parent = str(PurePosixPath(path).parent)
        command = [
            "docker",
            "exec",
            "-i",
            container,
            "/bin/sh",
            "-c",
            'umask 077; mkdir -p -- "$1"; cat > "$2"',
            "sh",
            parent,
            path,
        ]
        result = self._run_host(command, timeout=120, input_bytes=data)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))

    def put_file(self, container: str, source: Path, destination: str) -> None:
        self.put_bytes(container, destination, source.read_bytes())

    def get_bytes(self, container: str, path: str, max_bytes: int = 64 * 1024 * 1024) -> bytes:
        _validate_container(container)
        path = _validate_remote_path(path)
        stat = self._run_host(
            ["docker", "exec", container, "stat", "-c", "%s", "--", path], timeout=30
        )
        if stat.returncode:
            raise FileNotFoundError(stat.stderr.decode(errors="replace") or path)
        size = int(stat.stdout.decode().strip())
        if size > max_bytes:
            raise ValueError(f"refusing to transfer {size} bytes; limit is {max_bytes}")
        result = self._run_host(["docker", "exec", container, "cat", "--", path], timeout=120)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return result.stdout

    def cleanup(self, container: str) -> None:
        _validate_container(container)
        self._run_host(["docker", "rm", "-f", container], timeout=60)

    def container_running(self, container: str) -> bool:
        _validate_container(container)
        result = self._run_host(
            ["docker", "inspect", "-f", "{{.State.Running}}", container], timeout=30
        )
        return result.returncode == 0 and result.stdout.decode().strip() == "true"
