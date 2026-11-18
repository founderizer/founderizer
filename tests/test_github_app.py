"""The owner puts the GitHub App on their own hub from the app (owner feature github_app), with no console.

What these checks are really about. The model of requirement 9 is that the App ID and the App's private key live in
one mode-600 file on the **customer's** hub and that Founderizer holds nothing of them. That model does not change
here; what changes is that the owner no longer copies that file onto the machine by hand. So the checks are the file
and the absences:

  - the file is the one `github_app` reads back: the hub user's own, mode 600, in a folder of mode 700,
    `app_id=<App ID>` on the first line and the key as GitHub gave it after it,
  - a key that openssl cannot sign with never replaces a key that is in place, because the proof happens on a
    temporary file beside it,
  - a public key, a certificate, a key with a passphrase and a key with anything in front of it are refused,
  - the key reaches no row, no result, no event and no log line: the owner-command record keeps its SHA-256,
    exactly as the sign-in code's record does.

In-process hub, a throwaway RSA key made here, no real GitHub and no AI call.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid

import hub
from test_ui_api import OwnerAPI

APP_ID = "123456"
OWNER = "127.0.0.1"
MINE = object()                     # `save` without a key of its own uses this test's own key


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (AppFile, NoKeyKept):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class GitHubApp(OwnerAPI):
    """A hub whose `~/.fleet` is a folder of this test, and one throwaway RSA key to paste into it."""

    @classmethod
    def setUpClass(cls):
        cls.keys = Path(tempfile.mkdtemp(prefix="fleet-github-app-key-"))
        raw = cls.keys / "raw.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(raw), "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(raw), "-pubout", "-out", str(cls.keys / "public.pem")],
                       check=True, capture_output=True)
        # GitHub downloads the PKCS#1 spelling ("BEGIN RSA PRIVATE KEY"); openssl 3 writes PKCS#8 by default. The
        # hub takes either, so both are made here and both are checked.
        traditional = subprocess.run(["openssl", "rsa", "-traditional", "-in", str(raw)], capture_output=True, text=True)
        plain = raw.read_text()
        cls.key = traditional.stdout if "BEGIN RSA PRIVATE KEY" in traditional.stdout else plain
        cls.other = plain if cls.key != plain else traditional.stdout or plain
        cls.public = (cls.keys / "public.pem").read_text()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-github-app-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        self.path = self.root / ".fleet" / "github-app.pem"
        hub.CFG["github_app"] = str(self.path)
        self.addCleanup(hub.CFG.pop, "github_app", None)

    # ---- helpers
    def save(self, app_id=APP_ID, key=MINE, **changes):
        body = dict({"request_id": str(uuid.uuid4()), "db": "test-generation"}, **changes)
        if "delete" not in changes:
            body.update(app_id=app_id, key=self.key if key is MINE else key)
        return self.request("/ui/github-app", body, source=OWNER)

    def view(self):
        code, team = self.request("/ui/team?db=test-generation", source=OWNER)
        self.assertEqual(code, 200, team)
        return team["github"]

    def mode(self, path):
        return oct(Path(path).stat().st_mode & 0o777)


class AppFile(GitHubApp):
    """The file the hub writes, and what it refuses."""

    def test_the_owner_pastes_the_app_and_the_hub_writes_the_file(self):
        self.assertEqual(self.view(), {"app": False, "app_id": None, "problem": None, "unreached": {}, "door": False,
                                       "renew": False})
        code, answer = self.save()
        self.assertEqual(code, 200, answer)
        self.assertEqual({k: answer[k] for k in ("app", "app_id", "replaced")},
                         {"app": True, "app_id": APP_ID, "replaced": False})
        self.assertEqual(self.path.read_text(), f"app_id={APP_ID}\n{self.key.strip()}\n")
        self.assertEqual((self.mode(self.path), self.mode(self.path.parent)), ("0o600", "0o700"))
        self.assertEqual(self.path.stat().st_uid, os.getuid())
        # the hub reads back exactly what it wrote, which is the one proof that matters
        self.assertEqual(hub.github_app(), (APP_ID, str(self.path)))
        self.assertEqual(self.view(), {"app": True, "app_id": APP_ID, "problem": None, "unreached": {}, "door": False,
                                       "renew": False})

    def test_the_key_it_wrote_signs_the_apps_jwt(self):
        self.assertEqual(self.save()[0], 200)
        jwt = hub.github_jwt(*hub.github_app())
        signed, signature = jwt.rsplit(".", 1)
        claims = json.loads(hub.base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
        self.assertEqual(claims["iss"], int(APP_ID))
        sig = self.root / "sig"
        sig.write_bytes(hub.base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
        proof = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(self.keys / "public.pem"),
                                "-signature", str(sig)], input=signed.encode(), capture_output=True)
        self.assertEqual(proof.returncode, 0, proof.stderr)

    def test_a_second_app_replaces_the_first_and_delete_takes_it_away(self):
        self.assertEqual(self.save()[0], 200)
        code, answer = self.save(app_id="999")
        self.assertEqual((code, answer["replaced"], answer["app_id"]), (200, True, "999"))
        self.assertEqual(hub.github_app()[0], "999")
        self.assertEqual(len(list(self.path.parent.iterdir())), 1)      # no temporary file left behind
        code, answer = self.save(delete=True)
        self.assertEqual((code, answer["app"], answer["replaced"]), (200, False, True))
        self.assertFalse(self.path.exists())
        self.assertIsNone(hub.github_app())
        self.assertEqual(self.view(), {"app": False, "app_id": None, "problem": None, "unreached": {}, "door": False,
                                       "renew": False})
        self.assertEqual(self.save(delete=True)[1]["replaced"], False)

    def test_anything_that_is_not_a_private_key_is_refused(self):
        passphrase = subprocess.run(["openssl", "genrsa", "-aes256", "-passout", "pass:secret", "2048"],
                                    capture_output=True, text=True, check=True).stdout
        for key in (self.public,                                        # the public half
                    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
                    passphrase,                                         # openssl would ask for the passphrase
                    "app_id=1\n" + self.key,                            # a second app_id line in front of it
                    "ssh-rsa AAAAB3Nz" + "a" * 200,
                    "\n".join(self.key.strip().splitlines()[:-1]),      # no END line
                    self.key.strip() + "\nand one more line",
                    self.key[:100], "", "x" * 200, 42, None):
            code, answer = self.save(key=key)
            self.assertEqual(code, 400, (str(key)[:40], answer))
        for app_id in ("0", "", "abc", "12345678901234", "42.42", "-1", None, True, 4.2):
            self.assertEqual(self.save(app_id=app_id)[0], 400, app_id)
        self.assertEqual(self.save(**{"unknown": 1})[0], 400)
        self.assertEqual(self.save(delete=False)[0], 400)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.save(key=self.other)[0], 200)             # the other spelling of the same key
        self.assertEqual(self.save(app_id=" 4242\n")[1]["app_id"], "4242")      # an App ID pasted with its spaces
        self.assertEqual(self.save(app_id=4242)[1]["app_id"], "4242")           # or sent as a number

    def test_a_key_that_openssl_cannot_sign_with_never_replaces_the_one_in_place(self):
        """The shape of a key is not proof that it is one: the proof is a signature, made on a temporary file beside
        the live one, so a wrong key leaves the App that works exactly as it was."""
        self.assertEqual(self.save()[0], 200)
        before = self.path.read_text()
        lines = self.key.strip().splitlines()
        broken = "\n".join([lines[0], *lines[3:]])          # the right wrapper, a body that signs nothing
        code, answer = self.save(app_id="999", key=broken)
        self.assertEqual(code, 400, answer)
        self.assertIn("openssl cannot sign", answer["error"])
        self.assertEqual(self.path.read_text(), before)
        self.assertEqual(hub.github_app(), (APP_ID, str(self.path)))
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])     # the temporary file is gone
        self.assertEqual(self.count("ui_controls"), 1)                      # a refused command leaves no record

    def test_windows_line_ends_and_a_trailing_newline_are_taken_as_they_come(self):
        """A key that travelled through a form or a clipboard still signs: the hub settles the line ends, and refuses
        the key itself only when openssl cannot sign with it."""
        code, answer = self.save(key="\n " + self.key.replace("\n", "\r\n") + "\n\n")
        self.assertEqual(code, 200, answer)
        self.assertNotIn("\r", self.path.read_text())
        self.assertEqual(hub.github_app(), (APP_ID, str(self.path)))

    def test_the_route_is_the_owners_and_the_feature_is_offered(self):
        self.assertIn("github_app", self.request("/ui/state")[1]["ui_features"])
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "app_id": APP_ID, "key": self.key}
        self.assertEqual(self.request("/ui/github-app", body, source="127.0.0.9")[0], 403)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.count("ui_controls"), 0)


class NoKeyKept(GitHubApp):
    """The key reaches no row, no result, no event and no log line."""

    def test_nothing_of_the_key_is_written_down(self):
        code, answer = self.save()
        self.assertEqual(code, 200, answer)
        body = json.loads(hub.q1("SELECT * FROM ui_controls WHERE route='github-app'")["body"])
        self.assertEqual(body, {"app_id": APP_ID, "key_sha256": hashlib.sha256(self.key.strip().encode()).hexdigest()})
        secret = self.key.strip().splitlines()[2]           # one line of the key: it must be nowhere
        dumped = json.dumps([[dict(r) for r in hub.q("SELECT * FROM " + table)]
                             for table in ("ui_controls", "ui_requests", "log", "events", "secrets")])
        for word in (self.key.strip(), secret, "PRIVATE KEY"):
            self.assertNotIn(word, dumped)
            self.assertNotIn(word, json.dumps(answer))
            self.assertNotIn(word, json.dumps(self.view()))
        self.assertIn(f"saved the GitHub App {APP_ID}", json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))

    def test_the_same_request_id_answers_the_same_way_without_the_key(self):
        """The record keeps the key's SHA-256, so a repeat is still recognised while the key is in no row."""
        request_id = str(uuid.uuid4())
        self.assertEqual(self.save(request_id=request_id)[0], 200)
        self.path.unlink()                                  # the file is gone; the repeat must not write it again
        code, again = self.save(request_id=request_id)
        self.assertEqual((code, again["replayed"], again["app_id"]), (200, True, APP_ID))
        self.assertFalse(self.path.exists())
        self.assertEqual(self.save(request_id=request_id, app_id="999")[0], 409)
        self.assertEqual(self.count("ui_controls"), 1)


if __name__ == "__main__":
    unittest.main()
