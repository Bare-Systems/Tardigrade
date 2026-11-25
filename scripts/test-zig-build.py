#!/usr/bin/env python3
"""Exercise cache retention without compiling Tardigrade or touching real caches."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

WRAPPER = Path(__file__).with_name('zig-build')


class CachePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / 'scripts').mkdir()
        self.wrapper = self.repo / 'scripts' / 'zig-build'
        shutil.copy2(WRAPPER, self.wrapper)
        self.zig = self.repo / 'fake-zig'
        self.zig.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
pathlib.Path('args.json').write_text(json.dumps(args))
for option in ('--cache-dir', '--global-cache-dir'):
    cache = pathlib.Path(args[args.index(option) + 1])
    cache.mkdir(parents=True, exist_ok=True)
    (cache / 'object').write_bytes(b'x' * int(os.environ.get('OBJECT_BYTES', '8192')))
if os.environ.get('SLOW'):
    pathlib.Path('started').touch()
    time.sleep(0.5)
sys.exit(int(os.environ.get('EXIT_CODE', '0')))
''')
        self.zig.chmod(0o755)
        self.env = {**os.environ, 'ZIG': str(self.zig), 'TARDIGRADE_CACHE_MAX_GB': '1'}

    def run_build(self, *args, **env):
        return subprocess.run([str(self.wrapper), *args], env={**self.env, **env},
                              capture_output=True, text=True)

    def test_reuse_and_argument_forwarding(self):
        import json
        self.assertEqual(self.run_build('test-fast', '-Doptimize=Debug').returncode, 0)
        cache = self.repo / '.zig-cache-managed'
        self.assertTrue((cache / 'local/object').exists())
        self.assertTrue((cache / 'global/object').exists())
        self.assertEqual(json.loads((self.repo / 'args.json').read_text())[-2:],
                         ['test-fast', '-Doptimize=Debug'])

    def test_evict_on_failure_and_preserve_outputs_and_unmanaged_cache(self):
        for name in ('zig-out', '.zig-cache'):
            (self.repo / name).mkdir()
            (self.repo / name / 'keep').touch()
        result = self.run_build(TARDIGRADE_CACHE_MAX_GB='0.000001', EXIT_CODE='7')
        self.assertEqual(result.returncode, 7)
        self.assertFalse((self.repo / '.zig-cache-managed/local').exists())
        self.assertFalse((self.repo / '.zig-cache-managed/global').exists())
        for name in ('zig-out', '.zig-cache'):
            self.assertTrue((self.repo / name / 'keep').exists())

    def test_trim_before_build(self):
        path = self.repo / '.zig-cache-managed/local'
        path.mkdir(parents=True)
        (path / 'old').write_bytes(b'x' * 8192)
        self.assertEqual(self.run_build(TARDIGRADE_CACHE_MAX_GB='0.000001',
                                        OBJECT_BYTES='0').returncode, 0)
        self.assertFalse((path / 'old').exists())

    def test_reject_invalid_limit_and_path_override(self):
        for value in ('0', '-1', 'nan', 'inf', 'garbage'):
            self.assertEqual(self.run_build(TARDIGRADE_CACHE_MAX_GB=value).returncode, 1)
        self.assertEqual(self.run_build('--cache-dir=/tmp/elsewhere').returncode, 1)

    def test_reject_symlink(self):
        other = self.repo / 'precious'
        other.mkdir()
        (other / 'keep').touch()
        (self.repo / '.zig-cache-managed').symlink_to(other)
        self.assertEqual(self.run_build().returncode, 1)
        self.assertTrue((other / 'keep').exists())

    def test_serialized_builds(self):
        import time
        first = subprocess.Popen([str(self.wrapper)], env={**self.env, 'SLOW': '1'})
        try:
            deadline = time.monotonic() + 5
            while not (self.repo / 'started').exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            start = time.monotonic()
            self.assertEqual(self.run_build().returncode, 0)
            self.assertGreater(time.monotonic() - start, 0.3)
            self.assertEqual(first.wait(timeout=5), 0)
        finally:
            if first.poll() is None:
                first.kill()
                first.wait()


if __name__ == '__main__':
    unittest.main()
