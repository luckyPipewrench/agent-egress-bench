import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate_capability_registry_history.py")
SPEC = importlib.util.spec_from_file_location("registry_history", MODULE_PATH)
registry_history = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry_history)


class CapabilityRegistryHistoryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        path = self.repo / "capability-registry" / "aeb.core-capabilities" / "format-1"
        path.mkdir(parents=True)
        self.snapshot = path / "revision-1.json"
        self.snapshot.write_text('{"id":"aeb.core-capabilities","revision":1}\n')
        self.git("add", "capability-registry")
        self.git("commit", "-qm", "base snapshot")
        self.base = self.git("rev-parse", "HEAD").decode().strip()

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True).stdout

    def test_allows_unchanged_prior_snapshot_and_new_revision(self):
        second = self.snapshot.with_name("revision-2.json")
        second.write_text('{"id":"aeb.core-capabilities","revision":2}\n')
        self.git("add", "capability-registry")
        self.git("commit", "-qm", "append snapshot")
        self.assertEqual(registry_history.validate(self.repo, self.base), 1)

    def test_rejects_rewritten_prior_snapshot(self):
        self.snapshot.write_text('{"id":"aeb.core-capabilities","revision":1,"changed":true}\n')
        self.git("add", "capability-registry")
        self.git("commit", "-qm", "rewrite snapshot")
        with self.assertRaisesRegex(ValueError, "rewrote immutable registry snapshot"):
            registry_history.validate(self.repo, self.base)


if __name__ == "__main__":
    unittest.main()
