from __future__ import annotations

import json
import re
import shlex
from dataclasses import asdict, dataclass

from .transport import DockerTransport


TARGET_RE = re.compile(r"/out/([A-Za-z0-9_.+@=-]+)")


@dataclass(frozen=True)
class TargetInventory:
    architecture: str
    image: str
    wrapper_path: str
    wrapper_text: str
    selected_target: str | None
    executables: list[str]
    seed_corpora: list[str]
    dictionaries: list[str]
    options_files: list[str]
    source_roots: list[str]
    build_files: list[str]
    tools: dict[str, str | None]
    environment: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def inspect_target(
    transport: DockerTransport, container: str, image: str
) -> TargetInventory:
    wrapper_path = "/bin/arvo" if image.startswith("n132/arvo:") else "/usr/local/bin/run_poc"
    wrapper_result = transport.exec(
        container, f"sed -n '1,240p' {shlex.quote(wrapper_path)}", cwd="/", timeout=30
    )
    wrapper_text = wrapper_result.stdout
    matches = TARGET_RE.findall(wrapper_text)

    inventory_script = r'''
set +e
printf '%s\n' '---ARCH---'
uname -m
printf '%s\n' '---EXECUTABLES---'
find /out -maxdepth 1 -type f -perm -111 -printf '%p\n' 2>/dev/null | sort
printf '%s\n' '---CORPORA---'
find /out /src -maxdepth 4 -type f \( -iname '*seed*corpus*.zip' -o -iname '*seed*corpus*.tar*' \) -printf '%p\n' 2>/dev/null | sort -u
printf '%s\n' '---DICTIONARIES---'
find /out /src -maxdepth 5 -type f \( -name '*.dict' -o -name '*dictionary*' \) -printf '%p\n' 2>/dev/null |
  grep -Ev '^/src/(aflplusplus|honggfuzz|libfuzzer|fuzztest)/' | sort -u
printf '%s\n' '---OPTIONS---'
find /out -maxdepth 1 -type f -name '*.options' -printf '%p\n' 2>/dev/null | sort
printf '%s\n' '---SOURCE_ROOTS---'
find /src -mindepth 1 -maxdepth 1 -type d -printf '%p\n' 2>/dev/null | sort
printf '%s\n' '---BUILD_FILES---'
find /src -maxdepth 3 -type f \( -name build.sh -o -name CMakeLists.txt -o -name configure -o -name meson.build \) -printf '%p\n' 2>/dev/null | sort | head -80
printf '%s\n' '---TOOLS---'
for x in clang clang++ gcc g++ cmake ninja make patch git gdb lldb llvm-symbolizer afl-fuzz honggfuzz python3 unzip; do
  value=$(command -v "$x" 2>/dev/null || true)
  printf '%s=%s\n' "$x" "$value"
done
printf '%s\n' '---ENV---'
env | grep -E '^(ARCHITECTURE|SANITIZER|FUZZING_ENGINE|PROJECT_NAME|CC|CXX|CFLAGS|CXXFLAGS|LIB_FUZZING_ENGINE|OUT|SRC|WORK)=' | sort
'''
    result = transport.exec(container, inventory_script, cwd="/", timeout=90)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)

    sections: dict[str, list[str]] = {}
    current = ""
    for raw_line in result.stdout.splitlines():
        if raw_line.startswith("---") and raw_line.endswith("---"):
            current = raw_line.strip("-")
            sections[current] = []
        elif current:
            sections[current].append(raw_line)

    tools: dict[str, str | None] = {}
    for line in sections.get("TOOLS", []):
        key, _, value = line.partition("=")
        tools[key] = value or None
    environment: dict[str, str] = {}
    for line in sections.get("ENV", []):
        key, _, value = line.partition("=")
        environment[key] = value
    executables = sections.get("EXECUTABLES", [])
    selected = f"/out/{matches[0]}" if matches else None
    if selected not in executables and selected is not None:
        executables.insert(0, selected)
    if selected is None:
        filtered = [
            path
            for path in executables
            if not path.endswith(("llvm-symbolizer", "afl-fuzz", "honggfuzz"))
        ]
        selected = filtered[0] if len(filtered) == 1 else None

    return TargetInventory(
        architecture=(sections.get("ARCH", [""]) or [""])[0],
        image=image,
        wrapper_path=wrapper_path,
        wrapper_text=wrapper_text,
        selected_target=selected,
        executables=executables,
        seed_corpora=sections.get("CORPORA", []),
        dictionaries=sections.get("DICTIONARIES", []),
        options_files=sections.get("OPTIONS", []),
        source_roots=sections.get("SOURCE_ROOTS", []),
        build_files=sections.get("BUILD_FILES", []),
        tools=tools,
        environment=environment,
    )
