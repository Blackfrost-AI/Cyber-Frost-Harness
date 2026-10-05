from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    path: Path
    text: str


def _parse_frontmatter(text: str, path: Path) -> tuple[dict[str, str], str]:
    lines = text.splitlines()
    if len(lines) < 3 or lines[0].strip() != "---":
        raise ValueError(f"missing YAML frontmatter in {path}")
    try:
        end = lines[1:].index("---") + 1
    except ValueError as exc:
        raise ValueError(f"unterminated YAML frontmatter in {path}") from exc
    metadata: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"invalid frontmatter line in {path}: {line}")
        metadata[key.strip()] = value.strip().strip('"').strip("'")
    return metadata, "\n".join(lines[end + 1 :]).strip() + "\n"


class SkillLibrary:
    def __init__(self, root: Path):
        self.root = root
        self._skills = self._discover()

    def _discover(self) -> dict[str, Skill]:
        skills: dict[str, Skill] = {}
        for path in sorted(self.root.glob("*/SKILL.md")):
            text = path.read_text(encoding="utf-8")
            metadata, _body = _parse_frontmatter(text, path)
            name = metadata.get("name", "")
            description = metadata.get("description", "")
            if not name or not description:
                raise ValueError(f"skill needs name and description: {path}")
            if name != path.parent.name:
                raise ValueError(f"skill name {name!r} does not match folder {path.parent.name!r}")
            if name in skills:
                raise ValueError(f"duplicate skill: {name}")
            skills[name] = Skill(name, description, path, text)
        if not skills:
            raise ValueError(f"no skills found under {self.root}")
        return skills

    def names(self) -> list[str]:
        return sorted(self._skills)

    def get(self, name: str) -> Skill:
        try:
            return self._skills[name]
        except KeyError as exc:
            raise KeyError(f"unknown skill {name!r}; available: {', '.join(self.names())}") from exc

    def catalog(self) -> list[dict[str, str]]:
        return [
            {"name": skill.name, "description": skill.description}
            for skill in sorted(self._skills.values(), key=lambda item: item.name)
        ]

    def catalog_text(self) -> str:
        return "\n".join(
            f"- {item['name']}: {item['description']}" for item in self.catalog()
        )
