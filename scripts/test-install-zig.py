#!/usr/bin/env python3
"""Offline installer failure-path tests; no Zig downloads or compilation."""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


class InstallZigTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="test-install-zig-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        shutil.copyfile(Path(__file__).with_name("install-zig.sh"), self.scripts / "install-zig.sh")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "requests"
        self.install = self.root / "install with spaces"
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                        GITHUB_PATH=str(self.root / "github-path"),
                        REQUEST_LOG=str(self.log), TEST_OS="Darwin", TEST_ARCH="arm64",
                        ZIG_DOWNLOAD_MIRRORS="", RESPONSES="{}")
        self.executable("uname", '#!/bin/sh\ncase "$1" in -s) echo "$TEST_OS";; -m) echo "$TEST_ARCH";; esac\n')
        self.executable("curl", """#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
url = args[args.index('-o') - 1]
out = pathlib.Path(args[args.index('-o') + 1])
with open(os.environ['REQUEST_LOG'], 'a') as log:
    log.write(url + '\\n')
source = json.loads(os.environ['RESPONSES']).get(url)
if source is None:
    out.write_bytes(b'interrupted download')
    sys.exit(22)
shutil.copyfile(source, out)
""")
        self.archive = self.fixture()
        self.official = self.url("https://ziglang.org/download")
        self.env["RESPONSES"] = json.dumps({self.official: str(self.archive)})

    def executable(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def fixture(self, target="aarch64-macos", reported_version="0.16.0"):
        name = f"zig-{target}-0.16.0"
        archive = self.root / f"{name}.tar.xz"
        with tarfile.open(archive, "w:xz") as tar:
            for relative, content, mode in [
                ("zig", f"#!/bin/sh\necho {reported_version}\n", 0o755),
                ("lib/std/std.zig", "// complete distribution fixture\n", 0o644),
                ("LICENSE", "fixture license\n", 0o644),
            ]:
                data = content.encode()
                entry = tarfile.TarInfo(f"{name}/{relative}")
                entry.mode, entry.size = mode, len(data)
                tar.addfile(entry, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.scripts / "zig-checksums.txt").write_text(f"{digest}  {archive.name}\n")
        return archive

    def url(self, base):
        return f"{base}/0.16.0/{self.archive.name}"

    def run_installer(self, *args, success=True):
        result = subprocess.run(["sh", str(self.scripts / "install-zig.sh"), *args],
                                env=self.env, text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
        return result

    def install_zig(self, success=True):
        return self.run_installer("0.16.0", str(self.install), success=success)

    def requests(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_resolve_cache_path_has_no_network_or_filesystem_side_effects(self):
        result = self.run_installer("--print-cache-path", "0.16.0", str(self.install))
        self.assertEqual(Path(result.stdout.strip()), self.install / "downloads" / self.archive.name)
        self.assertFalse(self.install.exists())
        self.assertEqual(self.requests(), [])

    def test_cold_install_preserves_cli_stdout_and_github_path(self):
        result = self.install_zig()
        installed = Path(result.stdout.strip())
        self.assertEqual(installed, self.install / "0.16.0" / "zig-aarch64-macos-0.16.0")
        self.assertTrue((installed / "lib/std/std.zig").is_file())
        self.assertTrue((installed / "LICENSE").is_file())
        self.assertEqual((self.root / "github-path").read_text(), result.stdout)
        self.assertEqual(self.requests(), [self.official])
        self.assertFalse(list((self.install / "0.16.0").glob(".install-*")))

    def test_warm_cache_works_offline_and_repairs_extracted_files(self):
        installed = Path(self.install_zig().stdout.strip())
        (installed / "zig").write_text("#!/bin/sh\nexit 99\n")
        (installed / "lib/std/std.zig").unlink()
        self.env["RESPONSES"] = "{}"
        self.install_zig()
        self.assertTrue((installed / "lib/std/std.zig").is_file())
        self.assertEqual(self.requests(), [self.official])

    def test_failed_official_download_uses_r2_fallback(self):
        r2 = "https://zig.example.r2.dev"
        self.env["ZIG_DOWNLOAD_MIRRORS"] = f"\n{r2}/\n"
        self.env["RESPONSES"] = json.dumps({self.url(r2): str(self.archive)})
        self.install_zig()
        self.assertEqual(self.requests(), [self.official, self.url(r2)])

    def test_bad_mirror_checksum_is_rejected_before_valid_fallback(self):
        bad = self.root / "bad.tar.xz"
        bad.write_bytes(b"untrusted mirror contents")
        self.env["ZIG_DOWNLOAD_MIRRORS"] = "https://bad.example\nhttps://good.example"
        self.env["RESPONSES"] = json.dumps({self.url("https://bad.example"): str(bad),
                                            self.url("https://good.example"): str(self.archive)})
        result = self.install_zig()
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertEqual(self.requests(), [self.official, self.url("https://bad.example"),
                                          self.url("https://good.example")])

    def test_corrupt_cache_is_replaced_with_verified_download(self):
        cache = self.install / "downloads" / self.archive.name
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b"corrupt restored cache")
        self.assertIn("invalid SHA-256", self.install_zig().stderr)
        self.assertEqual(cache.read_bytes(), self.archive.read_bytes())

    def test_all_sources_fail_without_publishing_partial_install(self):
        self.env["RESPONSES"] = "{}"
        self.env["ZIG_DOWNLOAD_MIRRORS"] = "http://insecure.example\nhttps://offline.example"
        result = self.install_zig(success=False)
        self.assertIn("could not download a checksum-verified", result.stderr)
        self.assertFalse((self.install / "downloads" / self.archive.name).exists())
        self.assertFalse(list((self.install / "0.16.0").iterdir()))
        self.assertFalse((self.root / "github-path").exists())
        self.assertEqual(self.requests(), [self.official, self.url("https://offline.example")])

    def test_wrong_binary_version_is_rejected(self):
        self.fixture(reported_version="0.15.0")
        self.install_zig(success=False)
        self.assertFalse((self.install / "0.16.0" / "zig-aarch64-macos-0.16.0").exists())

    def test_unknown_version_fails_closed_before_downloading(self):
        self.run_installer("0.99.0", str(self.install), success=False)
        self.assertEqual(self.requests(), [])
        self.assertFalse(self.install.exists())

    def test_supported_platform_archive_names(self):
        for system, arch, target in [("Darwin", "x86_64", "x86_64-macos"),
                                     ("Darwin", "arm64", "aarch64-macos"),
                                     ("Linux", "amd64", "x86_64-linux"),
                                     ("Linux", "aarch64", "aarch64-linux")]:
            with self.subTest(system=system, arch=arch):
                archive = self.fixture(target)
                self.env.update(TEST_OS=system, TEST_ARCH=arch)
                result = self.run_installer("--print-cache-path", "0.16.0", str(self.install))
                self.assertEqual(Path(result.stdout.strip()).name, archive.name)

    def test_unsupported_platform_fails_before_downloading(self):
        for overrides in [dict(TEST_OS="Windows"), dict(TEST_ARCH="riscv64")]:
            with self.subTest(overrides=overrides):
                original = self.env.copy()
                self.env.update(overrides)
                self.install_zig(success=False)
                self.env = original
        self.assertEqual(self.requests(), [])


if __name__ == "__main__":
    unittest.main()
