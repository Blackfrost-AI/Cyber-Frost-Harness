import re
import unittest
from pathlib import Path

from cyber_frost_harness.skills import SkillLibrary


PROJECT = Path(__file__).resolve().parents[1]


class SkillTests(unittest.TestCase):
    def test_catalog_is_complete(self):
        library = SkillLibrary(PROJECT / "skills")
        self.assertEqual(
            set(library.names()),
            {
                "target-triage",
                "native-build-and-replay",
                "corpus-guided-discovery",
                "structured-input-crafting",
                "crash-triage-and-minimization",
                "source-audit-and-root-cause",
                "defensive-remediation",
                "purple-team-validation",
            },
        )

    def test_skill_text_is_procedural(self):
        forbidden = re.compile(r"\b(authori[sz](?:e|ed|ation)|permission|refusal)\b", re.I)
        library = SkillLibrary(PROJECT / "skills")
        for name in library.names():
            with self.subTest(skill=name):
                self.assertIsNone(forbidden.search(library.get(name).text))


if __name__ == "__main__":
    unittest.main()
