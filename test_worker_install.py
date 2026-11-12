"""Worker installer: Codex trusts exactly this checkout, and nothing else in its settings changes. Temporary Codex
settings; no Codex run."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import worker_install

try:
    import tomllib
except ImportError:                     # Python 3.10
    tomllib = None


@unittest.skipIf(tomllib is None, "needs Python 3.11 to read TOML")
class CodexTrust(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        kit = self.tmp / "fleet-pilot"
        kit.mkdir()
        self.key = os.path.realpath(kit)                # Codex records the folder's real path
        self.config = self.tmp / "codex" / "config.toml"
        for p in (patch.object(worker_install.fleet, "KIT", str(kit)),
                  patch.dict(os.environ, {"CODEX_HOME": str(self.tmp / "codex")})):
            p.start()
            self.addCleanup(p.stop)

    def write(self, text):
        self.config.parent.mkdir(mode=0o700, exist_ok=True)
        self.config.write_text(text)
        self.config.chmod(0o600)

    def test_a_new_user_gets_one_trusted_entry_for_exactly_this_checkout(self):
        self.assertEqual(worker_install.trust_codex_checkout(), "added")
        text = self.config.read_text()
        self.assertEqual(tomllib.loads(text), {"projects": {self.key: {"trust_level": "trusted"}}})
        self.assertEqual((self.config.stat().st_mode & 0o777, self.config.parent.stat().st_mode & 0o777), (0o600, 0o700))
        self.assertEqual(worker_install.trust_codex_checkout(), "present")      # a second run changes nothing
        self.assertEqual(self.config.read_text(), text)

    def test_existing_settings_stay_and_only_one_table_is_added(self):
        before = ('model = "gpt-5"\n\n[mcp_servers.other]\nurl = "http://127.0.0.1:1"\n\n'
                  '[projects."/srv/other"]\ntrust_level = "trusted"')       # no final newline
        self.write(before)
        self.assertEqual(worker_install.trust_codex_checkout(), "added")
        after = self.config.read_text()
        self.assertTrue(after.startswith(before))
        parsed = tomllib.loads(after)
        self.assertEqual(parsed["model"], "gpt-5")
        self.assertEqual(parsed["mcp_servers"], {"other": {"url": "http://127.0.0.1:1"}})
        self.assertEqual(parsed["projects"], {"/srv/other": {"trust_level": "trusted"},
                                              self.key: {"trust_level": "trusted"}})
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_an_owner_choice_or_a_broken_file_is_never_changed(self):
        own = "[projects.%s]\ntrust_level = \"untrusted\"\n" % json.dumps(self.key)
        self.write(own)
        self.assertEqual(worker_install.trust_codex_checkout(), "kept")
        self.assertEqual(self.config.read_text(), own)
        self.write("model = = broken\n")
        with self.assertRaises(ValueError):
            worker_install.trust_codex_checkout()
        self.assertEqual(self.config.read_text(), "model = = broken\n")


if __name__ == "__main__":
    unittest.main()
