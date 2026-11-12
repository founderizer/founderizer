"""The helper's own login steps. File mode is gone (11 November 2026): it read a Bitwarden token of this user, and
Founderizer has no Bitwarden backend any more, so no helper opens a saved login. Only a machine's vault broker does.
Dummy data; no network, no account and no real token."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import fleet


SECRET_ID = "11111111-1111-4111-8111-111111111111"
REF = "bws://" + SECRET_ID
LOGIN = {"username": "pilot-a", "password": "DummyOnlyPassword123456789", "url": "https://example.com/login"}
TOKEN = "dummy-token-never-use"


class HelperLogins(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        for p in (patch.object(fleet, "HOME", self.folder.name),
                  # vps and studio still say "file", the mode that the pilot started with
                  patch.object(fleet, "TEAM", {"agents": {n: {"vault": "file"} for n in ("vps", "studio")}})):
            p.start()
            self.addCleanup(p.stop)

    def test_file_mode_is_gone_and_no_helper_opens_a_saved_login(self):
        """A team.json entry that still says "file" is no credential access, also with a token file of the pilot
        in ~/.fleet and a Bitwarden program on the PATH: nothing is read and nothing runs."""
        token = Path(self.folder.name) / "bws-token"
        token.write_text(TOKEN)
        token.chmod(0o600)
        self.assertEqual([fleet.vault_mode(a) for a in ("vps", "studio", None, "nobody")], ["none"] * 4)
        for ref in (REF, "sealed:9", "op://fleet-pilot/pilot-site-a"):
            with self.subTest(ref), patch.object(fleet.shutil, "which", return_value="/dummy/bws"), \
                    patch.object(fleet.subprocess, "run", side_effect=AssertionError("a program ran")), \
                    patch.object(fleet, "http", side_effect=AssertionError("the hub was asked")), \
                    self.assertRaises(fleet.Refused) as refused:
                fleet.read_login(ref, "vps")
            self.assertEqual(str(refused.exception), fleet.NO_CREDENTIALS)
        for name in ("bws_token", "bws_get", "bws_item", "read_values", "probe_one", "cmd_register"):
            self.assertFalse(hasattr(fleet, name), name)
        self.assertNotIn("bws.toml", fleet.PROTECTED)
        with patch.object(sys, "argv", ["fleet.py", "register", REF]), self.assertRaises(SystemExit) as stopped, \
                contextlib.redirect_stderr(io.StringIO()) as said:
            fleet.main()
        self.assertEqual(stopped.exception.code, 2)                             # argparse: no such command
        self.assertIn("invalid choice: 'register'", said.getvalue())

    def test_a_saved_item_is_read_strictly_and_without_disclosing_data(self):
        """login_from_item: the shape of a saved login, {username, password, url[, totp]} in the value of an item
        with its name. Every other shape is refused, and no refusal repeats a value."""
        def item(**changes):
            return dict({"id": SECRET_ID, "key": "pilot-site-a", "value": json.dumps(LOGIN)}, **changes)
        self.assertEqual(fleet.login_from_item(item(), SECRET_ID), dict(LOGIN, label="pilot-site-a"))
        self.assertEqual(fleet.login_from_item(item(id=SECRET_ID.upper()), SECRET_ID)["label"], "pilot-site-a")
        for bad in (item(id="22222222-2222-4222-8222-222222222222"), item(id=3), item(value=LOGIN["password"]),
                    item(value="[]"), item(value=json.dumps({"password": LOGIN["password"]})),
                    item(value=json.dumps(dict(LOGIN, password=123))),
                    item(value=json.dumps(dict(LOGIN, url="file:///etc/passwd"))),
                    item(value=json.dumps(dict(LOGIN, url="https://user:pass@example.com"))),
                    item(value=json.dumps(dict(LOGIN, totp="not base32!"))), item(key=None), [], None):
            with self.assertRaises(fleet.Refused) as raised:
                fleet.login_from_item(bad, SECRET_ID)
            self.assertNotIn(LOGIN["password"], str(raised.exception))
            self.assertNotIn("not base32", str(raised.exception))
        for ref in ("bws://name", REF + "/", REF + "?x=1", "bws://--help", "bws://../token"):
            with self.assertRaises(fleet.Refused) as raised:
                fleet.split_ref(ref)
            self.assertIn("UUID in the fleet's vault", str(raised.exception))
        self.assertEqual(fleet.split_ref(REF), SECRET_ID)

    # The steps below come after a login is in hand. Only file mode had one in the helper, so each test gives it one.
    def test_signin_fills_only_a_login_that_it_has_and_refuses_if_the_tab_cannot_confirm_success(self):
        with patch.object(fleet, "vault_mode", return_value="file"), patch.object(fleet.sys, "platform", "darwin"), \
                patch.object(fleet, "read_login", return_value=dict(LOGIN, label="pilot-site-a")), \
                patch.object(fleet, "chrome_tab", side_effect=[42, 42]) as chrome, patch.object(fleet.time, "sleep"):
            result = fleet.do_signin(REF, "studio")
        self.assertEqual(chrome.call_args_list[0].args[0], "https://example.com")
        self.assertIn(LOGIN["password"], chrome.call_args_list[0].args[1])
        self.assertEqual(chrome.call_args_list[1].kwargs, {"tab_id": 42})
        self.assertEqual(chrome.call_args_list[1].args[2], "none")
        self.assertNotIn(LOGIN["password"], result)
        with patch.object(fleet, "vault_mode", return_value="file"), patch.object(fleet.sys, "platform", "darwin"), \
                patch.object(fleet, "read_login", side_effect=fleet.Refused("no login")), \
                patch.object(fleet, "chrome_tab") as chrome:
            with self.assertRaises(fleet.Refused):
                fleet.do_signin(REF, "studio")
            chrome.assert_not_called()
        for checked in (0, 99):
            with patch.object(fleet, "vault_mode", return_value="file"), patch.object(fleet.sys, "platform", "darwin"), \
                    patch.object(fleet, "read_login", return_value=dict(LOGIN, label="dummy")), \
                    patch.object(fleet, "chrome_tab", side_effect=[42, checked]), patch.object(fleet.time, "sleep"):
                with self.assertRaises(fleet.Refused):
                    fleet.do_signin(REF, "studio")

    def test_chrome_selects_one_tab_and_does_not_echo_script_errors(self):
        with patch.object(fleet.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "42\n", "")) as run:
            self.assertEqual(fleet.chrome_tab("https://example.com", "dummyScript", "none", tab_id=42), 42)
        script = run.call_args.kwargs["input"]
        self.assertIn('if "42" is "0" or (id of t as text) is "42" then', script)
        self.assertIn('if r is "none" then return id of t', script)
        with patch.object(fleet.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", LOGIN["password"])):
            with self.assertRaises(fleet.Refused) as raised:
                fleet.chrome_tab("https://example.com", LOGIN["password"], "filled")
        self.assertNotIn(LOGIN["password"], str(raised.exception))

    def test_handover_and_sealed_read_keep_existing_protocol(self):
        encrypted = "-----BEGIN AGE ENCRYPTED FILE-----\ndummy\n-----END AGE ENCRYPTED FILE-----"
        with patch.object(fleet, "vault_mode", return_value="file"), \
                patch.object(fleet, "read_login", return_value=dict(LOGIN, label="pilot-site-a")), \
                patch.object(fleet.shutil, "which", return_value="/dummy/age"), \
                patch.object(fleet.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, encrypted, "")) as run, \
                patch.object(fleet, "http", side_effect=[(200, {"pubkey": "age1dummy"}), (200, {"ref": "sealed:9"})]) as request:
            result = fleet.do_handover(REF, "vps", "studio", "T-99")
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), LOGIN)
        self.assertEqual(request.call_args.args[2]["ciphertext"], encrypted)
        self.assertNotIn(LOGIN["password"], str(request.call_args_list) + result)
        with patch.object(fleet, "vault_mode", return_value="file"), \
                patch.object(fleet.shutil, "which", return_value="/dummy/age"), \
                patch.object(fleet.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(LOGIN), "")) as run, \
                patch.object(fleet, "http", return_value=(200, {"ciphertext": encrypted, "label": "pilot-site-a"})):
            self.assertEqual(fleet.read_login("sealed:9", "studio"), dict(LOGIN, label="pilot-site-a"))
        self.assertEqual(run.call_args.args[0][0], "age")


if __name__ == "__main__":
    unittest.main()
