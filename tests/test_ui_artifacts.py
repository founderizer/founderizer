"""Checked-output API boundary tests. Temporary Git repo; no agents or fleet calls."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
import urllib.error
import urllib.parse
import urllib.request

import hub
import test_ui_api as fixture


class CheckedArtifacts(unittest.TestCase):
    connect = fixture.OwnerAPI.connect
    request = fixture.OwnerAPI.request

    def setUp(self):
        fixture.OwnerAPI.setUp(self)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.old_repo = hub.CFG.get("artifact_repo")
        hub.CFG["artifact_repo"] = str(self.repo)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Artifact Test")
        self.git("config", "user.email", "test@example.invalid")
        (self.repo / "outputs").mkdir()
        (self.repo / "outputs/good.txt").write_text("Checked output\n")
        (self.repo / "outputs/pixel.png").write_bytes(base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j6mQAAAAASUVORK5CYII="))
        (self.repo / "private.txt").write_text("Not an output")
        (self.repo / "outputs/link.txt").symlink_to("../private.txt")
        (self.repo / "outputs/page.html").write_text("<script>throw 1</script>")
        (self.repo / "outputs/wrong.png").write_text("Not a picture")
        self.git("add", ".")
        self.git("commit", "-qm", "Fixture")
        self.tid = hub.ins("INSERT INTO tasks(title,state,accepted,where_) VALUES(?,?,?,?)",
            ("Checked artifact", "completed", 1, "outputs/good.txt and outputs/pixel.png"))

    def tearDown(self):
        if self.old_repo is None:
            hub.CFG.pop("artifact_repo", None)
        else:
            hub.CFG["artifact_repo"] = self.old_repo
        fixture.OwnerAPI.tearDown(self)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True).stdout.decode().strip()

    def manifest(self, **query):
        params = dict(db="test-generation", **query)
        return self.request(f"/ui/tasks/{self.tid}/artifacts?" + urllib.parse.urlencode(params))

    def binary(self, item, **changes):
        params = dict(db="test-generation", path=item["path"], commit=item["commit"])
        params.update(changes)
        url = self.base + f"/ui/tasks/{self.tid}/artifact?" + urllib.parse.urlencode(params)
        try:
            with urllib.request.urlopen(url) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as r:
            with r:
                return r.code, dict(r.headers), r.read()

    def test_checked_git_bytes_identity_and_no_side_effects(self):
        code, result = self.manifest()
        self.assertEqual(code, 200)
        self.assertEqual((result["db"], result["task"]), ("test-generation", self.tid))
        self.assertEqual(len(result["artifacts"]), 2)
        (self.repo / "outputs/good.txt").write_text("Uncommitted replacement")
        for item in result["artifacts"]:
            code, headers, data = self.binary(item)
            self.assertEqual(code, 200)
            self.assertEqual(headers["X-Fleet-DB"], result["db"])
            self.assertEqual(headers["X-Fleet-Task"], str(self.tid))
            self.assertEqual(headers["X-Fleet-Commit"], item["commit"])
            self.assertEqual(headers["Content-Type"], item["mime"])
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(len(data), item["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
            if item["mime"] == "text/plain":
                self.assertEqual(data, b"Checked output\n")
        self.assertEqual(hub.q1("SELECT count(*) n FROM events")["n"], 0)

    def test_owner_origin_generation_and_unaccepted_guards(self):
        url = f"/ui/tasks/{self.tid}/artifacts?db=test-generation"
        self.assertEqual(self.request(url, headers={"Origin": "https://example.invalid"})[0], 403)
        hub.TEAM["addresses"]["owner"] = "127.0.0.2"
        self.assertEqual(self.request(url)[0], 403)
        hub.TEAM["addresses"]["owner"] = "127.0.0.1"
        self.assertEqual(self.request(f"/ui/tasks/{self.tid}/artifacts")[0], 409)
        hub.q("UPDATE tasks SET accepted=NULL WHERE id=?", (self.tid,))
        self.assertEqual(self.manifest()[0], 409)

    def test_only_named_regular_supported_outputs(self):
        hub.q("UPDATE tasks SET where_=? WHERE id=?", (
            "private.txt outputs/../private.txt outputs/link.txt outputs/page.html outputs/wrong.png outputs/missing.txt",
            self.tid))
        self.assertEqual(self.manifest()[1]["artifacts"], [])

    def test_query_cannot_read_unlisted_or_stale_content(self):
        item = self.manifest()[1]["artifacts"][0]
        for path in ("private.txt", "outputs/../private.txt", "outputs/link.txt", "/etc/passwd"):
            self.assertEqual(self.binary(item, path=path)[0], 404)
        self.assertEqual(self.binary(item, commit="0" * 40)[0], 409)
        self.assertEqual(self.binary(item, db="old-generation")[0], 409)
        self.git("commit", "--allow-empty", "-qm", "New revision")
        self.assertEqual(self.binary(item)[0], 409)

    def test_large_text_is_refused_before_content_read(self):
        (self.repo / "outputs/good.txt").write_bytes(b"x" * (256 * 1024 + 1))
        self.git("commit", "-am", "Oversized fixture")
        self.assertEqual(self.manifest()[0], 413)

    def test_registered_secret_is_not_returned(self):
        canary = "SYNTHETICSECRET123"
        (self.repo / "outputs/good.txt").write_text(canary)
        self.git("commit", "-am", "Synthetic secret fixture")
        salt = "test-salt"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("synthetic", salt, hashlib.sha256((salt + canary).encode()).hexdigest(), len(canary)))
        code, body = self.manifest()
        self.assertEqual(code, 422)
        self.assertNotIn(canary, json.dumps(body))


if __name__ == "__main__":
    unittest.main()
