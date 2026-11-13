"""Run the workflow's actual tag guard against an isolated local Git remote."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
if not BASH and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
    if candidate.is_file():
        BASH = str(candidate)


@unittest.skipUnless(BASH and shutil.which("git"), "Git and Bash are required")
class ReleaseTagTests(unittest.TestCase):
    def test_existing_tag_matches_archive_commit(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Check existing tag target\n", 1)[1].split("      - name:", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-c", "user.name=Release test", "-c", "user.email=test@example.invalid", *args],
                    cwd=cwd, text=True, stderr=subprocess.STDOUT,
                ).strip()

            git("init", "-q")
            git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "old")
            old = git("rev-parse", "HEAD")
            git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "current")
            current = git("rev-parse", "HEAD")
            git("remote", "add", "origin", ".")
            for name, target in (("v1.0.0", old), ("v1.0.1", current)):
                git("-c", "tag.gpgsign=false", "tag", name, target)
            for name, target in (("v2.0.0", old), ("v2.0.1", current)):
                git("-c", "tag.gpgsign=false", "tag", "-a", name, target, "-m", "annotation")

            def run(version):
                return subprocess.run(
                    [BASH, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                    cwd=cwd, env={**os.environ, "VERSION": version, "GITHUB_SHA": current},
                    text=True, capture_output=True,
                )

            for version, accepted in (("v9.0.0", True), ("v1.0.0", False),
                                      ("v1.0.1", True), ("v2.0.0", False), ("v2.0.1", True)):
                with self.subTest(version=version):
                    result = run(version)
                    self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                    if not accepted:
                        self.assertIn(old, result.stdout)
                        self.assertIn(current, result.stdout)
            git("remote", "set-url", "origin", "missing-local-remote")
            self.assertNotEqual(run("v9.0.0").returncode, 0)


if __name__ == "__main__":
    unittest.main()
