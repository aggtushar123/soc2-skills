"""Tests for scripts/soc2_init.py and scripts/control_map.py. Standard library only."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "soc2-dev"
SCRIPTS = SKILL / "scripts"


def run(script: str, *args: str, check=True) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], capture_output=True, text=True, check=check)


class Init(unittest.TestCase):
    def test_scaffold_detects_stack_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as t:
            r = Path(t)
            (r / "package.json").write_text('{"dependencies":{"express":"^4"}}')
            (r / ".gitignore").write_text("node_modules\n")
            out = run("soc2_init.py", str(r), "--company", "Acme", "--owner", "@sec").stdout
            self.assertIn("language=node framework=express", out)
            for f in (".soc2/config.yml", ".soc2/CONTROL_MAP.md", ".soc2/EXCEPTIONS.md", ".github/pull_request_template.md",
                      ".github/CODEOWNERS", ".github/workflows/soc2-gates.yml", "SECURITY.md", ".pre-commit-config.yaml"):
                self.assertTrue((r / f).exists(), f)
            cfg = (r / ".soc2/config.yml").read_text()
            self.assertIn('company: "Acme"', cfg)
            self.assertIn('owner: "@sec"', cfg)
            self.assertIn('language: "node"', cfg)
            self.assertRegex((r / ".gitignore").read_text(), r"(?m)^\.env$")
            # second run must not overwrite
            (r / ".soc2/config.yml").write_text("company: keep\n")
            out2 = run("soc2_init.py", str(r)).stdout
            self.assertIn("skipped", out2)
            self.assertEqual((r / ".soc2/config.yml").read_text(), "company: keep\n")
            run("soc2_init.py", str(r), "--force")
            self.assertIn("company:", (r / ".soc2/config.yml").read_text())
            self.assertNotEqual((r / ".soc2/config.yml").read_text(), "company: keep\n")


class ControlMap(unittest.TestCase):
    def test_reports_unknown_unmapped_and_stale(self):
        with tempfile.TemporaryDirectory() as t:
            r = Path(t)
            (r / "src").mkdir()
            (r / "src/auth.py").write_text("# SOC2:AUTH-01 deny by default\n# SOC2:LOG-99 typo\n")
            (r / ".soc2").mkdir()
            (r / ".soc2/CONTROL_MAP.md").write_text(
                "| Requirement | Status | Implementation | Evidence | Owner | Last verified |\n|--|--|--|--|--|--|\n"
                "| AUTH-01 | missing | | | | |\n"
                "| API-01 | met | `src/gone.py:validate` | | | |\n"
            )
            p = run("control_map.py", str(r), "--json", "--strict", check=False)
            self.assertEqual(p.returncode, 1)
            d = json.loads(p.stdout)
            self.assertTrue(d["drift"])
            self.assertEqual(d["unknown_ids"], ["LOG-99"])
            self.assertEqual(d["annotated_not_mapped"], ["AUTH-01"])
            self.assertEqual(d["stale_rows"], [["API-01", "src/gone.py"]])

    def test_clean_map_has_no_drift(self):
        with tempfile.TemporaryDirectory() as t:
            r = Path(t)
            (r / "src").mkdir()
            (r / "src/auth.py").write_text("# SOC2:AUTH-01 deny by default\n")
            (r / ".soc2").mkdir()
            (r / ".soc2/CONTROL_MAP.md").write_text(
                "| Requirement | Status | Implementation | Evidence | Owner | Last verified |\n|--|--|--|--|--|--|\n"
                "| AUTH-01 | met | `src/auth.py:require_auth` | test | @sec | 2026-09-14 |\n"
            )
            p = run("control_map.py", str(r), "--strict")
            self.assertIn("no drift", p.stdout)


class SkillConsistency(unittest.TestCase):
    """The registry is the single source of truth for requirement IDs."""

    def registry_ids(self):
        text = (SKILL / "references/requirements.md").read_text()
        return set(re.findall(r"^\|\s*([A-Z]+-\d{2})\s*\|", text, re.M))

    def test_every_id_used_anywhere_exists_in_registry(self):
        reg = self.registry_ids()
        self.assertGreaterEqual(len(reg), 60)
        bad = {}
        for f in SKILL.rglob("*"):
            if f.is_dir():
                continue
            for m in re.findall(r"\b([A-Z]{2,5}-\d{2})\b", f.read_text(errors="replace")):
                if m.split("-")[0] in ("AUTH", "API", "DATA", "LOG", "SEC", "CHG", "INFRA", "EVD") and m not in reg:
                    bad.setdefault(str(f.relative_to(SKILL)), set()).add(m)
        self.assertEqual(bad, {})

    def test_every_path_in_skill_md_exists(self):
        skill = (SKILL / "SKILL.md").read_text()
        for p in set(re.findall(r"`((?:references|templates|scripts)/[^`*]+)`", skill)):
            self.assertTrue((SKILL / p).exists(), p)

    def test_every_domain_reference_covers_its_ids(self):
        reg = self.registry_ids()
        files = {"AUTH": "auth-and-access.md", "API": "api-endpoint-checklist.md", "DATA": "data-handling.md",
                 "LOG": "logging-and-audit.md", "SEC": "secrets-and-config.md", "CHG": "change-management.md",
                 "INFRA": "infrastructure.md"}
        for prefix, name in files.items():
            text = (SKILL / "references" / name).read_text()
            for rid in sorted(i for i in reg if i.startswith(prefix + "-")):
                self.assertRegex(text, rf"(?m)^### {rid} ", f"{name} lacks a section for {rid}")

    def test_control_map_template_has_every_registry_row(self):
        text = (SKILL / "templates/CONTROL_MAP.md").read_text().split("## Example")[0]
        rows = set(re.findall(r"^\|\s*([A-Z]+-\d{2})\s*\|", text, re.M))
        self.assertEqual(self.registry_ids() - rows, set())


if __name__ == "__main__":
    unittest.main()
