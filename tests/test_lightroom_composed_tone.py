"""Composed-tone trust and non-clobber guards without scientific packages."""
import errno
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


TOOL = Path(__file__).resolve().parents[1] / "tools/check_lightroom_composed_tone.py"
SPEC = importlib.util.spec_from_file_location("composed", TOOL)
composed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(composed)


class ComposedToneGuards(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.root / "sdk.zip"
        self.source.write_bytes(b"sdk sentinel")
        self.output = self.root / "candidate.dcp"

    def cli(self, *flags, tool=TOOL):
        return subprocess.run(
            [sys.executable, "-B", "-I", "-S", *flags, str(tool), "build", "--sdk", str(self.source),
             "--output", str(self.output)], capture_output=True, text=True, timeout=20)

    def test_existing_output_and_input_alias(self):
        os.link(self.source, self.output)
        result = self.cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Output must be new", result.stderr)
        self.assertEqual(self.output.read_bytes(), b"sdk sentinel")
        self.assertEqual(self.source.read_bytes(), b"sdk sentinel")

    def test_dangling_output(self):
        try:
            self.output.symlink_to("missing.dcp")
        except NotImplementedError as exc:
            self.skipTest(str(exc))
        except OSError as exc:
            unavailable = exc.errno in {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP}
            if not unavailable and getattr(exc, "winerror", None) != 1314:
                raise
            self.skipTest(f"File symlinks unavailable: {exc}")
        result = self.cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Output must be new", result.stderr)
        self.assertEqual(self.output.readlink(), Path("missing.dcp"))

    def test_optimized_mode_stops_before_any_input(self):
        result = self.cli("-O")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Run without -O", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def test_report_sha_rejected_before_scientific_imports(self):
        tools, analysis = self.root / "tools", self.root / "analysis"
        tools.mkdir()
        analysis.mkdir()
        tool = tools / TOOL.name
        shutil.copyfile(TOOL, tool)
        (self.root / composed.REPORT).write_bytes(b"{}")
        result = self.cli(tool=tool)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch: lightroom-composed-tone.json", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def test_all_sources_pinned_before_first_exec_and_cache_ignored(self):
        first, second = self.root / "first.py", self.root / "second.py"
        sentinel = self.root / "sentinel"
        body = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('good')\n".encode()
        second_body = b"a=2\n"
        specs = {"first": (first.name, sha256(body).hexdigest()),
                 "second": (second.name, sha256(second_body).hexdigest())}
        first.write_bytes(b"raise ValueError('unchecked cache executed')\n")
        py_compile.compile(str(first), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        first.write_bytes(body.replace(b"\n", b"\r\n"))
        second.write_bytes(b"a=3\n")
        with patch.object(composed, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch: second.py"):
                composed.load_modules(specs)
            self.assertFalse(sentinel.exists())
            second.write_bytes(second_body)
            self.addCleanup(sys.modules.pop, "first", None)
            self.addCleanup(sys.modules.pop, "second", None)
            with patch.object(sys, "dont_write_bytecode", sys.dont_write_bytecode):
                composed.load_modules(specs)
        self.assertEqual(sentinel.read_text(), "good")
        self.assertEqual(sys.modules["second"].a, 2)

    def test_fresh_export_relaxes_file_identity_but_rejects_control_drift(self):
        archived = {"software": "Lightroom 16", "shape_yxc": [1, 1, 3], "storage": "RGB16",
                    "icc_sha256": "icc", "crs_attributes": {"Temperature": "5200"},
                    "crs_nested": {"curve": "identity"}, "file_sha256": "old"}
        record = {**archived, "file_sha256": "fresh", "pixel_sha256_le_uint16_rgb": "fresh pixel"}
        def reader(path, shape, profile, filename, expected_sha):
            if expected_sha is not None and expected_sha != record["file_sha256"]:
                raise ValueError("file identity")
            return None, None, record
        args = (reader, self.source, [1, 1, 3], {}, "fixture.dng", archived)
        with self.assertRaisesRegex(ValueError, "file identity"):
            composed.replay_export(*args, fresh=False)
        self.assertEqual(composed.replay_export(*args, fresh=True)[2]["file_sha256"], "fresh")
        record["crs_attributes"] = {"Temperature": "5300"}
        with self.assertRaisesRegex(ValueError, "archived export control differs: crs_attributes"):
            composed.replay_export(*args, fresh=True)

    def test_fresh_chart_matrix_requires_identical_decoded_pixels(self):
        key = "pixel_sha256_le_uint16_rgb"
        archive = {key: "pixels", "file_sha256": "old container"}
        composed.require_chart_matrix_pixels({key: "pixels", "file_sha256": "fresh container"}, archive)
        with self.assertRaisesRegex(ValueError, "frozen chart coordinates"):
            composed.require_chart_matrix_pixels({key: "translated pixels", "file_sha256": "fresh container"}, archive)

    def test_profile_binary_and_adobe_notice_match_links(self):
        root = TOOL.parents[1]
        report = json.loads(composed.pinned_text(root / composed.REPORT, composed.REPORT_SHA))
        recipe = report["domain_recipe"]
        names = ("pentax-k3ii-1376-composed-tone-offline-v1.dcp",
                 "Adobe-DNG-SDK-LICENSE.txt", "Adobe-DNG-SDK-NOTICE.txt")
        profile, license_text, notice = [(root / "profiles" / name).read_bytes() for name in names]
        self.assertEqual(sha256(profile).hexdigest(), recipe["dcp_sha256"])
        self.assertEqual(len(profile), 8500)
        self.assertEqual(sha256(license_text.replace(b"\r\n", b"\n")).hexdigest(), recipe["sdk_license_member_sha256"])
        self.assertEqual(sha256(notice.replace(b"\r\n", b"\n")).hexdigest(),
                         "e3d283e6f8aeb50a4c29691cd3b1dc3284b7b290e58a6aa0b03fec80ed1cbe1e")
        page = (root / "analysis/lightroom-composed-tone.html").read_text(encoding="utf-8")
        for name in names:
            self.assertIn(f'href="../profiles/{name}"', page)

    def test_canonical_result_preserves_relative_pass_absolute_failure(self):
        report = json.loads(composed.pinned_text(TOOL.parents[1] / composed.REPORT, composed.REPORT_SHA))
        self.assertFalse(report["delivery_tolerances_met"])
        self.assertTrue(all(scene["ratio_lt_half"] for scene in report["scenes"].values()))
        chart = report["scenes"]["1376"]
        self.assertFalse(chart["chart_patch_tolerance_met"])
        self.assertEqual(chart["chart_patch_delivery"]["full_200"]["patch_median_lab_delta_e00"]["max_patch"], 7)


if __name__ == "__main__":
    unittest.main()
