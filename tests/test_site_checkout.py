"""Exercise the site tools with a checkout and with extracted files."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
PAGES = ("index.html", "analysis/research-program.html")
HTML = """<html lang="ko"><head><link rel="stylesheet" href="{css}"></head>
<body><!-- chrome:top --><!-- /chrome:top -->
<main id="main"><h1>Report</h1><h2 id="map">Map</h2><h2 id="levels">Levels</h2></main>
<!-- chrome:bottom --><!-- /chrome:bottom --></body></html>
"""


class SiteCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(self.enterContext(TemporaryDirectory()))

    def make_site(self, root):
        (root / "tools").mkdir(parents=True)
        for tool in ("site_chrome.py", "check_site.py"):
            shutil.copyfile(TOOLS / tool, root / "tools" / tool)
        (root / "assets").mkdir()
        (root / "assets/site.css").touch()
        (root / "analysis").mkdir()
        for page, prefix in zip(PAGES, ("", "../"), strict=True):
            (root / page).write_text(HTML.format(css=prefix + "assets/site.css"), encoding="utf-8")
        site_map = {
            "camera": "k3iii", "name": "Test", "firmware": "0", "footer": "Test",
            "home": PAGES[0], "glossary": PAGES[0],
            "sections": [{"id": "start", "title": "Start", "nav": "Start", "hub": PAGES[0],
                          "pages": [{"file": page, "label": page} for page in PAGES]}],
        }
        (root / "site-map.json").write_text(json.dumps(site_map), encoding="utf-8")

    def run_tool(self, root, tool, *args):
        return subprocess.run([sys.executable, "-B", str(root / "tools" / tool), *args],
                              capture_output=True, text=True)

    def test_archive_without_its_own_checkout_is_rejected(self):
        parent = self.work / "parent"
        parent.mkdir()
        subprocess.run(["git", "init", "-q", str(parent)], check=True)
        (parent / ".gitignore").write_text(".private/\n", encoding="utf-8")
        for root in (self.work / "archive", parent / ".private" / "archive"):
            self.make_site(root)
            before = (root / PAGES[0]).read_bytes()
            for tool, args in (("site_chrome.py", ()), ("site_chrome.py", ("--check",)), ("check_site.py", ())):
                with self.subTest(root=root, tool=tool, args=args):
                    result = self.run_tool(root, tool, *args)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("Git checkout of this repository", result.stderr)
                    self.assertEqual((root / PAGES[0]).read_bytes(), before)

    def test_private_ancestor_is_allowed_but_private_links_are_rejected(self):
        root = self.work / ".private" / "checkout"
        self.make_site(root)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for tool, args in (("site_chrome.py", ()), ("site_chrome.py", ("--check",)), ("check_site.py", ())):
            result = self.run_tool(root, tool, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
        (root / ".private").mkdir()
        (root / ".private/evidence.txt").touch()
        page = root / PAGES[0]
        text = page.read_text(encoding="utf-8")
        page.write_text(text.replace("</main>", '<a href=".private/evidence.txt">Evidence</a></main>'),
                        encoding="utf-8")
        result = self.run_tool(root, "check_site.py")
        self.assertEqual(result.returncode, 1)
        self.assertIn("link into a private folder: .private/evidence.txt", result.stderr)


if __name__ == "__main__":
    unittest.main()
