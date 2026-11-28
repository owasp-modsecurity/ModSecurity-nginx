"""Exercise the real NGINX patch applier at its filesystem/process boundary.

The minimal official close-stream guard is an application fixture, not a
native HTTP/2 runtime. The multiplexed .t regression proves reset delivery.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / ".github/scripts/apply-nginx-http2-patch.sh"
PATCH = ROOT / "patches/nginx-http2-close-stream-flush.patch"

PREFIX = (
    "/* Minimal official ngx_http_v2_close_stream application context. */\n"
    "void\nngx_http_v2_close_stream(void)\n{\n"
    "    h2c->processing--;\n\n"
)
OLD_GUARD = (
    "    if (h2c->processing || h2c->blocked) {\n"
    "        return;\n"
    "    }\n"
)
NEW_GUARD = (
    "    if (h2c->processing || h2c->blocked) {\n"
    "        /*\n"
    "         * A reset queued while finalizing this stream must not wait for\n"
    "         * another stream to finish or for a new socket read event.  Let the\n"
    "         * existing write handler flush it after this request is destroyed.\n"
    "         */\n"
    "        if (h2c->last_out && !h2c->blocked) {\n"
    "            ngx_post_event(h2c->connection->write, &ngx_posted_events);\n"
    "        }\n\n"
    "        return;\n"
    "    }\n"
)
SUFFIX = "\n    ev = h2c->connection->read;\n}\n"


def with_eol(text: str, ending: bytes) -> bytes:
    return text.encode("ascii").replace(b"\n", ending)


class NginxPatchRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shell = shutil.which("sh")
        patch = shutil.which("patch")
        if cls.shell is None or patch is None:
            raise RuntimeError("POSIX sh and GNU patch are required")
        version = subprocess.run(
            [patch, "--version"], capture_output=True, text=True,
            timeout=10, check=False,
        )
        if version.returncode or "GNU patch" not in version.stdout:
            raise RuntimeError("the patch-applier regressions require GNU patch")
        cls.helper_bytes = HELPER.read_bytes()
        cls.patch_bytes = PATCH.read_bytes().replace(b"\r\n", b"\n")

    def fixture(self, source_eol: bytes, patch_eol: bytes, *, spaces=False):
        temporary = tempfile.TemporaryDirectory(prefix="nginx patch fixture ")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        repository = root / ("connector checkout" if spaces else "connector")
        helper = repository / ".github/scripts/apply-nginx-http2-patch.sh"
        patch = repository / "patches/nginx-http2-close-stream-flush.patch"
        source_root = root / ("nginx source checkout" if spaces else "nginx")
        source = source_root / "src/http/v2/ngx_http_v2.c"
        helper.parent.mkdir(parents=True)
        patch.parent.mkdir(parents=True)
        source.parent.mkdir(parents=True)
        helper.write_bytes(self.helper_bytes)
        patch.write_bytes(self.patch_bytes.replace(b"\n", patch_eol))
        source.write_bytes(with_eol(PREFIX + OLD_GUARD + SUFFIX, source_eol))
        return root, helper, patch, source_root, source

    def invoke(self, helper: Path, *arguments: Path):
        return subprocess.run(
            [self.shell, str(helper), *(str(argument) for argument in arguments)],
            capture_output=True, text=True, timeout=15, check=False,
        )

    def assert_no_patch_debris(self, root: Path):
        leftovers = [str(path.relative_to(root)) for path in root.rglob("*")
                     if path.is_file() and path.suffix in (".rej", ".orig")]
        self.assertEqual(leftovers, [], "failed/dry-run application leaves no rejects/backups")

    def check_application(self, source_eol: bytes, patch_eol: bytes, *, spaces=False):
        root, helper, patch, source_root, source = self.fixture(
            source_eol, patch_eol, spaces=spaces,
        )
        original_patch = patch.read_bytes()
        result = self.invoke(helper, source_root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = with_eol(PREFIX + NEW_GUARD + SUFFIX, source_eol)
        self.assertEqual(source.read_bytes(), expected,
                         "only the requested hunk changes and the source EOL stays intact")
        self.assertEqual(patch.read_bytes(), original_patch, "input patch is never rewritten")
        again = self.invoke(helper, source_root)
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual(source.read_bytes(), expected, "second application is idempotent")
        self.assertEqual(patch.read_bytes(), original_patch)
        self.assert_no_patch_debris(root)

    def test_lf_source_lf_patch(self):
        self.check_application(b"\n", b"\n")

    def test_crlf_source_lf_patch(self):
        self.check_application(b"\r\n", b"\n")

    def test_lf_source_crlf_patch(self):
        self.check_application(b"\n", b"\r\n")

    def test_crlf_source_crlf_patch(self):
        self.check_application(b"\r\n", b"\r\n")

    def test_unmatched_hunk_preserves_source_without_rejects_or_backups(self):
        for ending in (b"\n", b"\r\n"):
            with self.subTest(source_eol=repr(ending)):
                root, helper, patch, source_root, source = self.fixture(ending, b"\n")
                invalid = with_eol(
                    PREFIX + OLD_GUARD.replace("h2c->processing || h2c->blocked", "h2c->processing")
                    + SUFFIX, ending,
                )
                source.write_bytes(invalid)
                original_patch = patch.read_bytes()
                result = self.invoke(helper, source_root)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(source.read_bytes(), invalid)
                self.assertEqual(patch.read_bytes(), original_patch)
                self.assert_no_patch_debris(root)

    def test_missing_http2_source_fails_without_creating_it(self):
        root, helper, patch, source_root, source = self.fixture(b"\n", b"\n")
        source.unlink()
        result = self.invoke(helper, source_root)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(source.exists())
        self.assertTrue(patch.is_file())
        self.assert_no_patch_debris(root)

    def test_usage_rejects_missing_or_extra_arguments(self):
        root, helper, patch, source_root, source = self.fixture(b"\n", b"\n")
        original = source.read_bytes()
        for arguments in ((), (source_root, source_root)):
            with self.subTest(argument_count=len(arguments)):
                result = self.invoke(helper, *arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage:", result.stderr)
                self.assertEqual(source.read_bytes(), original)
                self.assertTrue(patch.is_file())
        self.assert_no_patch_debris(root)

    def test_source_and_repository_paths_with_spaces(self):
        self.check_application(b"\r\n", b"\r\n", spaces=True)


if __name__ == "__main__":
    unittest.main()
