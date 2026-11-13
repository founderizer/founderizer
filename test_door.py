"""The door (DevOps plan version 44, section 2 and steps C1 and C2): who may ask, and the kinds of call.

- Callers (C1): a caller that the access file lists passes, and any other address fails, through `ops` and the
  door's own HTTP service; the door down is one line.
- Test 2: rule form arguments cannot reach root.
- Test 3: the refusals.
- Test 4: the door calls no model: rule calls run, and so do the agent's own calls (the owner, 11 November 2026:
  "it needs to be the agent itself"); door down, no write.
- Test 8: the order: the access file only from root, a second write on one host waits, a reboot inside a window is
  refused.
- Test 9: thirty events of the audit of the owner's past DevOps work, each a rule call, the agent's own call or a
  refusal as section 3 says. The names are generic.

Everything runs locally: the hosts' sshd and the providers are stubs that record what the door sends."""
import base64
import calendar
import contextlib
import copy
import datetime
import errno
import hashlib
import io
import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import door
import door_providers
import door_render
import door_targets
import ops
import vault

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"     # an example host key
KEY2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOfAnotherServerWithTheSameName0000000"    # of another server
ONE, TWO, HUB, STRANGER = "100.64.0.11", "100.64.0.12", "100.64.0.2", "100.64.0.99"
ZONE, TUNNEL = "a" * 32, "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


def slurp(path, mode="rb"):
    with open(path, mode) as f:
        return f.read()


def ref(n):
    return f"bws://{n:08d}-0000-4000-8000-000000000000"


ACCESS = {
    "v": 1,
    "hub": {"address": HUB, "port": 8765},
    "agents": {
        "ops-one": {"address": ONE, "business": "one",
                    "servers": {"web-1": "fix", "ci-1": "fix", "fleet-1": "fix", "db-1": "fix", "logs-1": "read",
                                "site-1": "fix"},
                    "providers": ["cloudflare:one", "hetzner:one", "backblaze:one", "github:one-org", "tailscale:net",
                                  "aws:one", "azure:one", "cloudflare:vendor"],
                    "repos": {"one-org/ops": {"kind": "devops"},
                              "one-org/shop": {"kind": "app", "deploy": "deploy.yml", "hold": "ops/hold"},
                              "one-org/cluster": {"kind": "gitops", "sync": "sync-app.yml"},
                              "one-org/website": {"kind": "app"}},
                    "github": {"one-org/ops": "read", "one-org/shop": "write"}},
        "ops-two": {"address": TWO, "business": "two", "servers": {"web-2": "fix", "ci-1": "fix"},
                    "providers": ["cloudflare:two"]},
    },
    "hosts": {
        "web-1": {"address": "100.64.1.1", "host_key": KEY, "business": "one", "mode": "fix", "kind": "app"},
        "db-1": {"address": "100.64.1.2", "host_key": KEY, "business": "one", "mode": "fix", "kind": "app"},
        "ci-1": {"address": "100.64.1.3", "host_key": KEY, "business": "one", "mode": "rule-only", "kind": "ci"},
        "fleet-1": {"address": "100.64.1.4", "host_key": KEY, "business": "one", "mode": "rule-only", "kind": "fleet"},
        "logs-1": {"address": "100.64.1.5", "host_key": KEY, "business": "one", "mode": "fix", "kind": "app"},
        "site-1": {"address": "100.64.1.6", "host_key": KEY, "business": "one", "mode": "fix", "kind": "app"},
        "web-2": {"address": "100.64.2.1", "host_key": KEY, "business": "two", "mode": "fix", "kind": "app"},
    },
    "credentials": {
        "cloudflare:one": {"secret": ref(1), "account_id": "b" * 32},
        "cloudflare:two": {"secret": ref(2), "account_id": "c" * 32},
        "cloudflare:vendor": {"secret": ref(3), "account_id": "d" * 32},
        "hetzner:one": {"secret": ref(4)}, "backblaze:one": {"secret": ref(5)},
        "github:one-org": {"secret": ref(6), "app_id": "12345"},
        "tailscale:net": {"secret": ref(7), "fleet_tags": ["tag:fleet"]},
        "aws:one": {"role": "arn:aws:iam::123456789012:role/fleet-door-aws", "region": "eu-central-1", "tag": "door"},
        "azure:one": {"secret": ref(9), "tenant": "t", "client_id": "c",
                      "sql_servers": ["/subscriptions/00000000-0000-4000-8000-000000000000/resourceGroups/rg/providers/"
                                      "Microsoft.Sql/servers/db"],
                      "sites": ["/subscriptions/00000000-0000-4000-8000-000000000000/resourceGroups/rg/providers/"
                                "Microsoft.Web/sites/shop"]},
    },
    "windows": [{"hosts": ["web-1"], "forms": ["deploy", "restart"], "deny": [["21:45", "00:30"], ["09:10", "09:45"]]},
                {"hosts": ["db-1"], "forms": ["reboot", "tailscale"], "only": [["00:00", "03:00"]]}],
    "never": {"repos": ["one-org/website"], "hosts": ["site-1"], "accounts": ["cloudflare:vendor"]},
    "workflows": {"one-org/cluster": {"health": ["cluster-health.yml"], "bootstrap": ["velero-bootstrap.yml"]}},
    "exposure": ["apps/legacy/**"],
    "pools": {"one": {"one-org/cluster": "write", "one-org/tools": "deploy"}},
    "images": {"registry.example/one-org/shop-api": "one-org/shop"},
}


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Access, Callers, RuleArguments, Refusals, OwnCalls, Order,
                                                    HubLine, HubRights, GitHubFacts, SyncRuns, CommitChecks, PruneParts, Prunes, Vault, AuditReplay, AWSRole,
                                                    OwnerYes, CallHash, ScriptsAndRuns, FullAccess, Routes, MadeDeletes,
                                                    HostPath, AppSettingsPath, ScriptPath, HostUpdates, KeyCardAccount,
                                                    WorkKeys,
                                                    Workflows, RunnerNew, Probe, CallerGone, Rendered, RenderPath,
                                                    GeneratedFiles, GeneratedPath, RenderBoxUnit, RenderBoxLive)
                              for name in cls.__dict__ if name.startswith("test_"))


class Stubs:
    """The door's outside world, recorded: the hosts' second sshd and HTTPS."""

    def __init__(self):
        self.ssh_calls, self.http_calls, self.lock = [], [], threading.Lock()
        self.running, self.overlap, self.pause = 0, 0, 0.0

    def ssh(self, host, req, stdin):
        with self.lock:
            self.running += 1
            self.overlap = max(self.overlap, self.running)
            self.ssh_calls.append((host["address"], req["op"], list(req["args"]), stdin))
        try:
            time.sleep(self.pause)
            return 0, f"{req['op']} done\n"
        finally:
            with self.lock:
                self.running -= 1

    def http(self, method, url, headers, data):
        self.http_calls.append((method, url, headers, data))
        return 404, {}

    def model_calls(self):
        """The calls that went to a model's API: the door makes none since 11 November 2026."""
        return [c for c in self.http_calls if "anthropic.com" in c[1] or "openai.com" in c[1]]


class DoorCase(unittest.TestCase):
    clock_at = datetime.datetime(2026, 11, 2, 12, 0, tzinfo=datetime.timezone.utc)

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fleet-door-")
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = patch.dict(os.environ, {"FLEET_DOOR_ROOT": self.root})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.write_access(ACCESS)
        # no test asks the network for a pinned program of the render box (door.ensure_render)
        patcher = patch.object(door, "http_raw", lambda method, url, headers, limit, timeout=120: (599, b""))
        patcher.start()
        self.addCleanup(patcher.stop)
        os.makedirs(self.root + door.SECRETS_DIR, exist_ok=True)
        for r in [c["secret"] for c in ACCESS["credentials"].values() if "secret" in c]:
            with open(os.path.join(self.root + door.SECRETS_DIR, hashlib.sha256(r.encode()).hexdigest()), "w") as f:
                f.write("value-of-" + r[-4:])
        # The door of these tests knows each saved Cloudflare key as a hand-made one that Cloudflare takes, for the
        # account that the file names: it asked before. KeyCardAccount and WorkKeys ask Cloudflare's stand-in.
        door.write_json(door.KEYS_FILE, {"kinds": {
            name: {"kind": "plain", "account_id": c["account_id"], "named": c["account_id"],
                   "at": int(time.time()) - 60,
                   "mark": door_providers.key_mark("value-of-" + c["secret"][-4:])}
            for name, c in ACCESS["credentials"].items() if name.startswith("cloudflare:")}})
        self.stubs = Stubs()
        self.door = door.Door(conf={"address": "127.0.0.1"}, http=self.stubs.http, ssh=self.stubs.ssh,
                              clock=lambda: self.clock_at)
        self.door.back = lambda access, host: None

    def write_access(self, data):
        os.makedirs(self.root + door.ETC, exist_ok=True)
        with open(self.root + door.ACCESS_FILE, "w") as f:
            json.dump(data, f)

    def call(self, address, target, op, *args, content=None):
        return self.door.call(address, target, op, list(args), content)


class Access(DoorCase):
    """The access file: only what validate_access takes, and only root writes it."""

    def test_the_file_of_the_fixture_is_valid(self):
        door.validate_access(json.loads(json.dumps(ACCESS)))

    def test_a_key_for_an_app_s_setting_is_app_name_and_its_secret(self):
        data = json.loads(json.dumps(ACCESS))
        data["credentials"]["app:shop:STRIPE_SECRET_KEY"] = {"secret": ref(11)}
        data["agents"]["ops-one"]["providers"].append("app:shop:STRIPE_SECRET_KEY")
        door.validate_access(data)
        for key, c in (("app:Shop:KEY", {"secret": ref(11)}), ("app:shop:lower", {"secret": ref(11)}),
                       ("app:shop", {"secret": ref(11)}), ("app:shop:KEY", {"secret": "plain"}),
                       ("app:shop:KEY", {"secret": ref(11), "account_id": "x"}), ("app:shop:KEY", "bws")):
            with self.subTest(key=key, c=c):
                bad = json.loads(json.dumps(ACCESS))
                bad["credentials"][key] = c
                with self.assertRaisesRegex(ValueError, "app:<app>:<NAME>"):
                    door.validate_access(bad)

    def test_a_gitops_target_s_sync_is_one_workflow_file_name(self):
        """DevOps plan X3: the caller workflow goes into a dispatch's path, so the file takes one file name, and only
        on a GitOps target."""
        for sync in ("../dispatches", "a/b.yml", "sync-app", ".hidden.yml", 7, ""):
            with self.subTest(sync=sync):
                data = json.loads(json.dumps(ACCESS))
                data["agents"]["ops-one"]["repos"]["one-org/cluster"]["sync"] = sync
                with self.assertRaisesRegex(ValueError, "file name of a GitOps target"):
                    door.validate_access(data)
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-one"]["repos"]["one-org/website"]["sync"] = "sync-app.yml"
        with self.assertRaisesRegex(ValueError, "file name of a GitOps target"):
            door.validate_access(data)

    def test_an_address_that_two_agents_share_is_refused(self):
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-two"]["address"] = ONE
        with self.assertRaisesRegex(ValueError, "share the address"):
            door.validate_access(data)
        data["agents"]["ops-two"]["address"] = HUB
        with self.assertRaisesRegex(ValueError, "share the address"):
            door.validate_access(data)

    def test_an_agent_with_no_address_calls_nothing_but_gets_its_tokens(self):
        """Two agents that share a box have no address in the file: neither calls the door, and the hub still asks for
        their GitHub tokens inside their business pool."""
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["support-one"] = {"business": "one"}
        data["agents"]["lead-one"] = {"business": "one", "github": {"one-org/ops": "read"}}
        door.validate_access(data)
        data["agents"]["lead-one"]["address"] = "8.8.8.8"
        with self.assertRaisesRegex(ValueError, "not one of the private network"):
            door.validate_access(data)
        data["agents"]["lead-one"].pop("address")
        self.write_access(data)
        self.assertNotIn(self.door.caller(ONE), ("support-one", "lead-one"))
        self.assertIsNone(self.door.caller("100.64.0.77"))
        # plan 13, item 4: an agent that only gets its tokens through the hub may name no business, and nothing else
        data["agents"]["dev-one"] = {"github": {"one-org/ops": "write"}}
        door.validate_access(data)
        for more in ({"address": ONE}, {"providers": ["cloudflare:one"]}, {"servers": {"web-1": "read"}}):
            with self.subTest(more=more), self.assertRaisesRegex(ValueError, "needs its business|no host|share"):
                door.validate_access(dict(data, agents=dict(data["agents"], **{"dev-one": dict(
                    {"github": {"one-org/ops": "write"}}, **more)})))

    def test_an_address_outside_the_private_network_and_fix_across_businesses_are_refused(self):
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-two"]["address"] = "8.8.8.8"
        with self.assertRaisesRegex(ValueError, "private network"):
            door.validate_access(data)
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-two"]["servers"]["web-1"] = "fix"
        with self.assertRaisesRegex(ValueError, "rule-only or nothing"):
            door.validate_access(data)

    def test_an_aws_account_is_a_role_and_never_a_stored_key(self):
        data = json.loads(json.dumps(ACCESS))
        data["credentials"]["aws:one"]["secret"] = ref(8)
        with self.assertRaisesRegex(ValueError, "names its role .* and no secret"):
            door.validate_access(data)
        data["credentials"]["aws:one"] = {"role": "AKIAABCDEFGHIJKLMNOP"}
        with self.assertRaisesRegex(ValueError, "names its role"):
            door.validate_access(data)

    def test_pools_and_images_are_checked(self):
        for path, value, words in ((("pools", "one", "Founderizer/Founderizer-Apps"), "read", "no product repository"),
                                   (("pools", "one", "one-org/tools"), "admin", "read, write or deploy"),
                                   (("images", "Bad Image"), "one-org/shop", "names the repository")):
            data = json.loads(json.dumps(ACCESS))
            where = data
            for key in path[:-1]:
                where = where[key]
            where[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, words):
                door.validate_access(data)

    def test_the_root_command_writes_the_file_and_refuses_a_bad_one(self):
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-two"]["servers"] = {}
        with patch("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(data).encode()))), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            door.cmd_access(None)
        self.assertIn("2 agents, 7 hosts", out.getvalue())
        self.assertEqual(door.read_json(door.ACCESS_FILE, {})["agents"]["ops-two"]["servers"], {})
        data["agents"]["ops-two"]["address"] = ONE
        with patch("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(data).encode()))), \
                self.assertRaises(SystemExit) as stop:
            door.cmd_access(None)
        self.assertIn("share the address", str(stop.exception))
        self.assertEqual(door.read_json(door.ACCESS_FILE, {})["agents"]["ops-two"]["address"], TWO)

    def test_an_update_leaves_the_code_readable_by_the_door_s_user(self):
        """The update clones the release into a folder that mkdtemp makes at 0700 for root, and the service runs as the
        door's own user, so the folder must end at 0755: on worker-6 the first install stopped at chdir."""
        revision = "ab" * 20
        os.makedirs(self.root + door.CODE, exist_ok=True)
        with patch("releases.check", lambda raw, keys: {"revision": revision, "version": "2026.11.1"}), \
                patch("releases.read_keys", lambda folder, name: []), \
                patch.object(door, "run_program", lambda argv, stdin, env, timeout=600: (0, "")), \
                patch("sys.stdin", io.StringIO("{}")), contextlib.redirect_stdout(io.StringIO()):
            door.cmd_update(None)
        target = os.path.join(self.root + door.CODE, revision)
        self.assertEqual(oct(os.stat(target).st_mode & 0o777), "0o755")
        self.assertEqual(os.path.realpath(os.path.join(self.root + door.CODE, "current")), os.path.realpath(target))

    def test_an_update_is_checked_with_both_pinned_key_files(self):
        """PRODUCT.md 4.3 "Two tracks": a fleet that takes releases early runs a release that the early key signed."""
        import releases
        seen = []

        def check(raw, keys):
            seen.append(list(keys))
            raise releases.Untrusted("no key of this test signed it")
        with patch("releases.read_keys", lambda folder, name: [name]), patch("releases.check", check), \
                patch("sys.stdin", io.StringIO("{}")), self.assertRaises(SystemExit):
            door.cmd_update(None)
        self.assertEqual(seen, [["release-key.pub", "early-key.pub"]])

    def test_a_held_release_or_one_below_the_running_one_is_refused(self):
        """Plan 13, item 2: the door refuses what every machine refuses (lifecycle.may_take): a held release, and a
        revision that does not descend from the one it runs, also when that older folder is still on the disk."""
        old, new = "ab" * 20, "cd" * 20
        os.makedirs(os.path.join(self.root + door.CODE, old))
        with open(self.root + door.FLOOR_FILE, "w") as f:
            f.write(new + "\n")
        ran = []

        def program(argv, stdin, env, timeout=600):
            ran.append(argv)
            return (1, "") if "merge-base" in argv else (0, "")
        for manifest, words in (({"revision": new, "version": "2026.11.9", "hold": True}, "is held"),
                                ({"revision": old, "version": "2026.11.8"}, "does not descend")):
            with self.subTest(words=words), patch("releases.check", lambda raw, keys, m=manifest: dict(m)), \
                    patch("releases.read_keys", lambda folder, name: []), patch.object(door, "run_program", program), \
                    self.assertRaisesRegex(SystemExit, words):
                door.take({})
        self.assertFalse(any("restart" in argv for argv in ran))
        self.assertFalse(os.path.lexists(os.path.join(self.root + door.CODE, "current")))

    def test_the_follow_timer_takes_the_hub_s_release_by_itself(self):
        """Plan 13, item 2: door.py follow asks the hub for its release on the private network, takes it when it is
        not the one that runs, writes its own timer, and keeps only the folder that ran last beside the new one."""
        old, new, older = "ab" * 20, "cd" * 20, "ef" * 20
        code = self.root + door.CODE
        for revision in (old, older):
            os.makedirs(os.path.join(code, revision))
        os.symlink(os.path.join(code, old), os.path.join(code, "current"))
        asked, ran = [], []

        def http(method, url, headers, data, timeout=30):
            asked.append((method, url, headers))
            return 200, {"revision": new, "version": "2026.11.9"}

        def program(argv, stdin, env, timeout=600):
            ran.append(argv)
            return 0, ""
        for _ in range(2):          # the second round finds the same release: nothing runs
            with patch("releases.check", lambda raw, keys: dict(raw)), \
                    patch("releases.read_keys", lambda folder, name: []), \
                    patch.object(door.door_providers, "http", http), patch.object(door, "run_program", program), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                door.cmd_follow(None)
            if not _:
                self.assertIn("2026.11.9", out.getvalue())
                self.assertEqual(door.running_revision(), new)
                self.assertEqual(sorted(os.listdir(code)), sorted([old, new, "current"]))
                self.assertIn(["systemctl", "restart", "fleet-door.service"], ran)
                self.assertIn(["systemctl", "enable", "--now", "fleet-door-follow.timer"], ran)
                with open(self.root + door.SYSTEMD + "/fleet-door-follow.service") as f:
                    self.assertIn("door.py follow", f.read())
                ran.clear()
        self.assertEqual(asked, [("GET", f"http://{HUB}:8765/door/release", {"X-Fleet-Client": "door"})] * 2)
        # nothing of the release runs again; the render box, whose socket is not there, is asked for once more
        self.assertEqual(ran, [["systemctl", "enable", "--now", "fleet-door-render.socket"]])
        # the door keeps the signed manifest of the release that it runs, for its hosts' self-update, also when the
        # code before it took that release and kept none
        self.assertEqual(door.read_json(door.RELEASE_JSON, None), {"revision": new, "version": "2026.11.9"})
        os.remove(self.root + door.RELEASE_JSON)
        with patch("releases.check", lambda raw, keys: dict(raw)), patch("releases.read_keys", lambda f, n: []), \
                patch.object(door.door_providers, "http", http), patch.object(door, "run_program", program), \
                contextlib.redirect_stdout(io.StringIO()):
            door.cmd_follow(None)
        self.assertEqual(door.read_json(door.RELEASE_JSON, None), {"revision": new, "version": "2026.11.9"})

    def test_follow_waits_while_the_access_file_names_no_hub(self):
        self.write_access(dict(ACCESS, hub={}))
        ran = []
        with patch.object(door.door_providers, "http", lambda *a, **k: self.fail("asked the hub")), \
                patch.object(door, "run_program", lambda argv, stdin, env, timeout=600: (ran.append(argv), (0, ""))[1]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            door.cmd_follow(None)
        self.assertIn("names no hub", out.getvalue())
        # the render box does not wait for the hub: every run of follow puts it in place
        self.assertIn(["systemctl", "enable", "--now", "fleet-door-render.socket"], ran)
        self.assertTrue(os.path.exists(self.root + door.SYSTEMD + "/fleet-door-render@.service"))

    def test_a_broken_file_names_nobody(self):
        with open(self.root + door.ACCESS_FILE, "w") as f:
            f.write("{not json")
        self.assertIsNone(self.door.caller(ONE))

    def test_the_hub_s_server_and_the_door_s_own_are_never_fix(self):
        """A fix host takes its agents' own calls, a file install and a script among them: on the hub's server they
        would reach the central vault, and on the door's own server the door's keys. Such a host is rule-only."""
        def with_host(address, mode, hub=HUB):
            data = json.loads(json.dumps(ACCESS))
            data["hub"]["address"] = hub
            data["hosts"]["own-1"] = {"address": address, "host_key": KEY, "business": "one", "mode": mode}
            return data
        with self.assertRaisesRegex(ValueError, "host own-1 is the hub's own server: its mode is rule-only"):
            door.validate_access(with_host(HUB, "fix"))
        door.validate_access(with_host(HUB, "rule-only"))
        with self.assertRaisesRegex(ValueError, "the hub's own server"):        # one address, written in two ways
            door.validate_access(with_host("fd7a:115c:a1e0:0:0:0:0:2", "fix", hub="fd7a:115c:a1e0::2"))
        door.validate_access(with_host("100.64.0.3", "fix"))        # a test's door has no file with its own address
        with open(self.root + door.CONF_FILE, "w") as f:
            json.dump({"address": "100.64.0.3", "port": door.DOOR_PORT}, f)
        with self.assertRaisesRegex(ValueError, "host own-1 is the door's own server: its mode is rule-only"):
            door.validate_access(with_host("100.64.0.3", "fix"))
        door.validate_access(with_host("100.64.0.3", "rule-only"))
        door.validate_access(with_host("100.64.0.4", "fix"))

    def test_a_file_from_before_that_rule_is_read_with_such_a_host_at_rule_only(self):
        """A new release must leave no door that names nobody: the door reads the old file with the host at
        rule-only, and root's command refuses the next file that says fix."""
        data = json.loads(json.dumps(ACCESS))
        data["hosts"]["hub-1"] = {"address": HUB, "host_key": KEY, "business": "one", "mode": "fix"}
        data["agents"]["ops-one"]["servers"]["hub-1"] = "fix"
        self.write_access(data)
        self.assertEqual(self.door.access()["hosts"]["hub-1"]["mode"], "rule-only")
        self.assertEqual(self.door.caller(ONE), "ops-one")
        got = self.call(ONE, "hub-1", "install", "htop")
        self.assertEqual(got["why"], "hub-1 is rule-only: only rule forms run there, and no file install")
        self.assertEqual(self.stubs.ssh_calls, [])
        with patch("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(data).encode()))), \
                self.assertRaisesRegex(SystemExit, "the hub's own server"):
            door.cmd_access(None)

    def test_the_new_file_has_its_group_before_it_takes_the_place_of_the_old_one(self):
        """Root's new file is the door's to read from its first moment. Before, the group came after the replace, and
        a door that read the file between the two steps could not open it."""
        steps, real = [], os.replace

        def replace(src, dst):
            steps.append(("replace", oct(os.stat(src).st_mode & 0o777)))
            return real(src, dst)
        group = type("Group", (), {"gr_gid": os.getgid()})
        with patch("grp.getgrnam", lambda name: group), patch.object(door.os, "replace", replace), \
                patch.object(door.os, "fchown", lambda fd, uid, gid: steps.append(("group", uid, gid))), \
                patch.object(door.os, "chown", lambda path, uid, gid: steps.append(("group", uid, gid))), \
                patch("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(ACCESS).encode()))), \
                contextlib.redirect_stdout(io.StringIO()):
            door.cmd_access(None)
        self.assertEqual(steps, [("group", 0, os.getgid()), ("replace", "0o640")])

    @unittest.skipIf(os.geteuid() == 0, "root reads every file")
    def test_a_read_that_failed_does_not_stay_when_the_door_can_read_the_file(self):
        """A new owner or a new mode of the file moves no mtime. Before, the door kept the empty file of a read that
        failed under that mtime, and refused every caller until it started again."""
        path = self.root + door.ACCESS_FILE
        os.chmod(path, 0)
        self.assertIsNone(self.door.caller(ONE))
        before = os.stat(path).st_mtime_ns
        os.chmod(path, 0o640)
        self.assertEqual(os.stat(path).st_mtime_ns, before)
        self.assertEqual(self.door.caller(ONE), "ops-one")


class TestHandler(door.Handler):
    """The door's handler with the caller's address of the test, as Tailscale gives the real one."""
    as_address = ONE

    def source(self):
        return self.headers.get("X-Test-Source") or TestHandler.as_address


class Served(DoorCase):
    def setUp(self):
        super().setUp()
        TestHandler.door = self.door
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        patcher = patch.dict(os.environ, {"FLEET_DOOR": f"127.0.0.1:{self.httpd.server_port}"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def ops(self, *argv, address=ONE):
        TestHandler.as_address = address
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = ops.main(list(argv))
        return code, out.getvalue()


class CallerGone(DoorCase):
    """A caller that ends its connection is no error of the door's: the hub or an agent's machine that gave up before
    the answer, in the middle of its request, or before it sent one. socketserver printed a traceback for each one, as
    it did on the hub. An error of the door's own still prints, also a connection that was reset in its own work."""

    def printed(self, act):
        """What the door's server writes to stderr while `act(port)` runs and until every request thread has ended."""
        TestHandler.door = self.door
        server = door.DoorServer(("127.0.0.1", 0), TestHandler)
        server.daemon_threads = False       # so that server_close joins the request threads, inside the capture
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                act(server.server_port)
            finally:
                server.shutdown()
                server.server_close()
        return out.getvalue()

    @staticmethod
    def reset(s):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))      # close with a reset
        s.close()

    def test_a_caller_that_closes_before_its_request_prints_nothing(self):
        def gone(port):
            self.reset(socket.create_connection(("127.0.0.1", port), timeout=5))
        self.assertEqual(self.printed(gone), "")

    def test_a_caller_that_gave_up_before_the_answer_prints_nothing(self):
        left, asked = threading.Event(), []

        def caller(source):                 # the door works on the call until its caller has gone
            asked.append(source)
            left.wait(5)
            return "ops-one"

        def gone(port):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                s.sendall(b"GET /ping HTTP/1.1\r\nHost: door\r\n\r\n")
                for _ in range(500):
                    if asked:
                        break
                    time.sleep(0.01)
            finally:
                self.reset(s)
                time.sleep(0.1)             # the reset has reached the door before it writes its answer
                left.set()
        with patch.object(self.door, "caller", caller):
            self.assertEqual(self.printed(gone), "")
        self.assertEqual(len(asked), 1)     # the request ran: the answer was what nobody read

    def test_a_caller_that_left_in_the_middle_of_its_request_prints_nothing(self):
        def gone(port):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:        # the head of a request and the start of its body, and then no more
                s.sendall(b"POST /call HTTP/1.1\r\nHost: door\r\nContent-Type: application/json\r\n"
                          b"Content-Length: 400\r\n\r\n{\"target\": ")
                time.sleep(0.2)             # the door waits for the rest of the body now
            finally:
                self.reset(s)
        self.assertEqual(self.printed(gone), "")

    def test_an_error_of_the_doors_own_still_prints(self):
        """Only a connection that its caller ended is left out. Any other error prints: one of the door's code, one of
        the operating system's, and a connection error of the door's own work, as when a provider resets the
        connection that the door reads its answer from."""
        def broken(port):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET /ping HTTP/1.1\r\nHost: door\r\n\r\n")
            with contextlib.suppress(ConnectionError):
                self.assertEqual(s.recv(1), b"")        # the door ended the connection with no answer
            s.close()
        for error in (ValueError("the door's own"), OSError(errno.EMFILE, "Too many open files"),
                      ConnectionAbortedError(errno.ECONNABORTED, "Software caused connection abort"),
                      ConnectionResetError(errno.ECONNRESET, "Connection reset by the provider"),
                      BrokenPipeError(errno.EPIPE, "Broken pipe to the provider")):
            with self.subTest(error=type(error).__name__), patch.object(self.door, "caller", side_effect=error):
                said = self.printed(broken)
                self.assertIn("Traceback", said)
                self.assertIn(str(error), said)

    def test_the_door_serves_with_this_server(self):
        """door.serve, which the door's service runs, starts the server that has this rule, at the door's own address
        and port, with the door's handler."""
        made = []

        def server(which):
            class Server:
                def __init__(self, address, handler):
                    made.append((which, address, handler))

                def serve_forever(self):
                    made.append("served")
            return Server
        with patch.object(door, "DoorServer", server("the door's")), \
                patch.object(door, "ThreadingHTTPServer", server("the plain one")), \
                patch.object(door, "vault_sweep", lambda door_: None):
            door.serve(self.door, "127.0.0.1", 18766)
        self.assertEqual(made, [("the door's", ("127.0.0.1", 18766), door.Handler), "served"])


class Callers(Served):
    """C1, done when: a listed caller passes, and another fails."""

    def test_a_listed_caller_passes_and_another_fails(self):
        self.assertEqual(self.ops("status"), (0, "the door answers, and knows this box as ops-one\n"))
        self.assertEqual(self.ops("web-1", "uptime"), (0, "uptime done\n"))
        self.assertEqual(self.stubs.ssh_calls, [("100.64.1.1", "uptime", [], None)])
        code, out = self.ops("web-1", "uptime", address=STRANGER)
        self.assertEqual((code, out), (3, "refused: this caller is not in the door's access file\nroute: the agent that "
                                          "holds it. Ask your requester with ask_my_requester: the manager gives this "
                                          "part of the work to the agent that holds web-1.\n"))
        self.assertEqual(self.ops("status", address=STRANGER)[0], 3)
        self.assertEqual(len(self.stubs.ssh_calls), 1)
        last = self.door.record.after(0)[-1]
        self.assertEqual((last["caller"], last["kind"], last["why"]), (STRANGER, "refused", "not in the access file"))

    def test_each_agent_reaches_only_what_it_holds(self):
        code, out = self.ops("web-1", "uptime", address=TWO)
        self.assertEqual((code, out), (3, "refused: ops-two holds no grant on web-1\nroute: the agent that holds it. "
                                          "Ask your requester with ask_my_requester and needs_access server:web-1 and "
                                          "needs_level read: the hub names the agent that holds it, and the manager "
                                          "gives this part of the work to that agent.\n"))
        self.assertEqual(self.ops("web-2", "uptime", address=TWO)[0], 0)
        self.assertEqual(self.ops("cloudflare:one", "zones", address=TWO)[0], 3)

    def test_a_write_and_a_refusal_carry_the_door_s_words(self):
        self.assertEqual(self.ops("web-1", "restart", "nginx"), (0, "restart done\n"))
        self.assertEqual(self.stubs.ssh_calls[-1][1:3], ("restart", ["nginx.service"]))
        code, out = self.ops("web-1", "restart", "poweroff.target")
        self.assertEqual(code, 3)
        self.assertIn("poweroff.target is a .target unit", out)

    def test_the_door_down_is_one_line_and_no_write(self):
        with patch.dict(os.environ, {"FLEET_DOOR": "127.0.0.1:9"}):
            self.assertEqual(self.ops("status"), (2, "the door does not answer at 127.0.0.1:9\n"))
            code, out = self.ops("web-1", "restart", "nginx")
        self.assertEqual((code, out.count("\n")), (2, 1))
        self.assertEqual(self.stubs.ssh_calls, [])

    def test_content_goes_with_the_call(self):
        path = os.path.join(self.root, "unit.timer")
        with open(path, "wb") as f:
            f.write(b"[Timer]\nOnCalendar=daily\n")
        code, out = self.ops("web-1", "file", "/etc/systemd/system/backup.timer", "0644", "root", "--content", path)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stubs.ssh_calls[-1][3], b"[Timer]\nOnCalendar=daily\n")

    def test_a_content_length_that_is_no_length_is_refused_at_once(self):
        """Before, a negative length made the door read to the end of the stream, with no cap, and a word in its
        place ended the request with an error of the door's own."""
        for length in (b"-1", b"many"):
            with self.subTest(length=length), \
                    socket.create_connection(("127.0.0.1", self.httpd.server_port), timeout=3) as s:
                s.sendall(b"POST /call HTTP/1.1\r\nHost: door\r\nContent-Length: " + length + b"\r\n\r\n")
                self.assertIn(b" 400 ", s.recv(4096).split(b"\r\n")[0])
        self.assertEqual(self.stubs.ssh_calls, [])


class RuleArguments(DoorCase):
    """Test 2: a rule form's arguments cannot reach root, at the door and again in ops-root on the host."""

    CASES = [
        ("exec", ["nginx", "-t", "-c", "/tmp/evil.conf"]),
        ("renew-certs", ["--deploy-hook", "sh -c id"]),
        ("journal", ["--cursor-file=/etc/shadow"]),
        ("journal", ["unit=nginx", "lines=200", "since=x; id"]),
        ("restart", ["poweroff.target"]),
        ("restart", ["reboot.target"]),
        ("restart", ["--kill-whom=all"]),
        ("enable", ["--now", "x"]),
        ("install", ["./evil.deb"]),
        ("install", ["/tmp/evil.deb"]),
        ("install", ["-o", "Dpkg::Pre-Invoke::=id"]),
        ("rollback", ["shop", "--to", "/tmp/old"]),
        ("rollback", ["../../bin/sh"]),
        ("upgrade", ["--dry-run"]),
        ("reboot", ["--force"]),
        ("status", ["nginx", "--pager"]),
        ("log", ["/etc/shadow"]),
        ("log", ["/var/log/../../etc/shadow"]),
        ("grow-pool", ["9999"]),
        ("timer", ["fire"]),
        ("place", ["/etc/x.env", "KEY", "0" * 64]),
        ("self-update", []),
    ]

    def test_each_form_refuses_arguments_that_reach_root(self):
        for op, args in self.CASES:
            with self.subTest(op=op, args=args):
                d = door_targets.decide(ACCESS, "ops-one", "web-1", op, args)
                self.assertEqual(d.kind, "refused", d)
                if op in door_targets.OPS_ROOT.FORMS and op not in door_targets.DOOR_ONLY:
                    with self.assertRaises(door_targets.OPS_ROOT.Refused):
                        door_targets.OPS_ROOT.check_args(op, list(args))

    def test_a_read_runs_with_no_pager_and_a_fixed_argv(self):
        argv = door_targets.OPS_READ.check_read("status", ["nginx"])
        self.assertEqual(argv, ["systemctl", "status", "--no-pager", "--lines=50", "--", "nginx"])
        self.assertEqual((door_targets.OPS_READ.ENV["PAGER"], door_targets.OPS_READ.ENV["SYSTEMD_PAGER"]), ("cat", ""))
        self.assertEqual(door_targets.OPS_READ.check_read("journal", ["unit=nginx", "since=-2h"]),
                         ["journalctl", "--no-pager", "-o", "short-iso", "-n", "200", "-u", "nginx", "--since", "-2h"])


class Refusals(DoorCase):
    """Test 3: every refusal of the plan's list, and a package install that works as the agent's own form."""

    def decide(self, target, op, *args, content=None, lookups=None, agent="ops-one"):
        return door_targets.decide(ACCESS, agent, target, op, list(args), content, lookups or {})

    def commit(self, *files, message="change"):
        return json.dumps({"message": message, "files": [
            {"path": p, "content": base64.b64encode(t.encode()).decode()} for p, t in files]}).encode()

    def test_programs_and_paths_an_exec_command_never_reaches(self):
        for args in (["bash"], ["sh", "-c", "id"], ["python3", "-c", "print(1)"], ["perl", "-e", "1"],
                     ["base64", "/etc/shadow"], ["cat", "/var/www/shop/.env"], ["cat", "/proc/1/environ"],
                     ["umount", "/"], ["debugfs", "/dev/sda1"], ["setpriv", "--reuid=0", "id"],
                     ["docker", "inspect", "shop"], ["nginx", "-T"], ["systemd-run", "id"],
                     ["find", "/", "-exec", "id", ";"], ["head", "/root/.ssh/id_ed25519"],
                     ["cp", "/tmp/x", "/usr/local/sbin/ops-root"], ["tee", "/etc/ld.so.preload"],
                     ["xargs", "id"], ["env", "id"], ["sudo", "id"]):
            with self.subTest(args=args):
                self.assertEqual(self.decide("web-1", "exec", *args).kind, "refused")

    def test_writes_to_ops_root_its_key_and_the_login_files(self):
        for path in ("/usr/local/sbin/ops-root", "/etc/ops-root/release-key.pub", "/etc/ops-root/mode",
                     "/etc/ld.so.preload", "/etc/ssh/sshd_config", "/etc/pam.d/sshd", "/etc/sudoers.d/ops-agent",
                     "/root/.ssh/authorized_keys", "/etc/systemd/system/ops-sshd.service",
                     "/etc/systemd/system/ops-sshd.service.d/x.conf", "/etc/passwd", "/etc/shadow"):
            with self.subTest(path=path):
                self.assertEqual(self.decide("web-1", "file", path, "0644", "root", content=b"x").kind, "refused")

    def test_cluster_forms_that_code_refuses_in_rendered_output(self):
        old = "kind: Deployment\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n" \
              "      - image: ghcr.io/one-org/shop:abc1234\n"
        news = {"a Secret object": "kind: Secret\ndata:\n  x: eA==\n",
                "RBAC": "kind: ClusterRoleBinding\n",
                "a new secretKeyRef": old + "        env:\n        - valueFrom:\n            secretKeyRef:\n",
                "a hostPath": old + "      volumes:\n      - hostPath:\n          path: /\n",
                "privileged": old + "        securityContext:\n          privileged: true\n",
                "a host namespace": old + "      hostNetwork: true\n",
                "an Application": "apiVersion: argoproj.io/v1alpha1\nkind: Application\n",
                "a CRD": "kind: CustomResourceDefinition\n",
                "a webhook": "kind: MutatingWebhookConfiguration\n",
                "a new LoadBalancer": "kind: Service\nspec:\n  type: LoadBalancer\n",
                "a k3s upgrade channel": "apiVersion: upgrade.cattle.io/v1\nkind: Plan\nspec:\n"
                                         "  channel: https://update.k3s.io/v1-release/channels/stable\n",
                "an external-secrets kind": "apiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\n",
                "a bigger volume claim": "kind: PersistentVolumeClaim\nspec:\n  resources:\n    requests:\n"
                                         "      storage: 50Gi\n",
                "a changed serviceAccountName": old + "      serviceAccountName: admin\n"}
        base = {"apps/shop/pvc.yaml": b"kind: PersistentVolumeClaim\nspec:\n  resources:\n    requests:\n"
                                      b"      storage: 10Gi\n"}
        for what, text in news.items():
            with self.subTest(what=what):
                path = "apps/shop/pvc.yaml" if "volume" in what else "apps/shop/x.yaml"
                d = self.decide("gitops:one-org/cluster", "push", content=self.commit((path, text)),
                                lookups={"base_file": lambda p: base.get(p, old.encode())})
                self.assertEqual(d.kind, "refused", (what, d))

    def test_a_k3s_patch_upgrade_is_the_agent_s_own_commit_of_its_plan(self):
        plan = "apiVersion: upgrade.cattle.io/v1\nkind: Plan\nmetadata:\n  name: k3s-agent\nspec:\n" \
               "  concurrency: 1\n  version: v1.35.9+k3s1\n"
        d = self.decide("gitops:one-org/cluster", "push",
                        content=self.commit(("platform/system-upgrade/plans.yaml",
                                             plan.replace("v1.35.9+k3s1", "v1.35.10+k3s1"))),
                        lookups={"base_file": lambda p: plan.encode()})
        self.assertEqual((d.kind, d.why), ("own", "platform/system-upgrade/plans.yaml: other manifest lines"))
        alerts = "kind: ConfigMap\ndata:\n  config: |\n    channel: ops\n"
        d = self.decide("gitops:one-org/cluster", "push",
                        content=self.commit(("apps/shop/alerts.yaml", alerts.replace("ops", "ops-2"))),
                        lookups={"base_file": lambda p: alerts.encode()})
        self.assertEqual(d.kind, "own")

    def test_provider_calls_that_are_never_the_door_s(self):
        self.assertEqual(self.decide("hetzner:one", "change", "POST", "/servers/1/actions/enable_rescue", "web-1",
                                     content=b"{}").kind, "refused")
        body = json.dumps({"config": {"ingress": [{"hostname": "x.example.com", "service": "ssh://localhost:22"}]}})
        self.assertEqual(self.decide("cloudflare:one", "change", "PUT",
                                     f"/accounts/{'b' * 32}/cfd_tunnel/{TUNNEL}/configurations",
                                     content=body.encode()).why,
                         "a tunnel to ssh://, tcp://, rdp://, smb:// or a socket is never the door's")
        self.assertEqual(self.decide("github:one-org", "token", "shop").kind, "refused")        # no read gives one
        self.assertEqual(self.decide("tailscale:net", "tags", "n1").kind, "refused")
        self.assertEqual(self.decide("cloudflare:vendor", "zones").why, "cloudflare:vendor is never a target of "
                                                                        "the door")

    def test_the_product_s_own_repositories_and_the_never_list(self):
        for target in (*(f"commit:{one}" for one in door_targets.VENDOR_REPOS), "deploy:miguelpieras/founderizer-fleet",
                       "commit:one-org/website", "deploy:Founderizer/Founderizer-Apps"):
            with self.subTest(target=target):
                self.assertIn("never a target", self.decide(target, "push", content=b"{}").why)
        self.assertIn("never a target", self.decide("site-1", "uptime").why)

    def test_commit_rules_at_any_depth(self):
        for path in (".claude/settings.json", "apps/x/.claude/hooks.json", "deep/a/.codex/config.toml", ".mcp.json",
                     "sub/AGENTS.md", "CLAUDE.md", ".github/workflows/x.yml", "a/.husky/pre-commit",
                     ".vscode/tasks.json", "policy.hujson", "scripts/security/check-tailnet-policy.mjs"):
            with self.subTest(path=path):
                self.assertEqual(self.decide("commit:one-org/ops", "push", content=self.commit((path, "x"))).kind,
                                 "refused")
        link = json.dumps({"message": "m", "files": [{"path": "docs/x", "mode": "120000",
                                                      "content": base64.b64encode(b"/etc").decode()}]}).encode()
        self.assertEqual(self.decide("commit:one-org/ops", "push", content=link).kind, "refused")

    def test_commit_rules_in_any_case_of_the_name(self):
        """A checkout on a disk that does not tell the cases apart, as a Mac's, reads claude.md as CLAUDE.md."""
        for path in ("claude.md", ".Claude/settings.json", "sub/Agents.MD", ".MCP.json", ".GitHub/workflows/x.yml",
                     "a/.HUSKY/pre-commit", "apps/x/.CODEX/config.toml", "Policy.hujson"):
            for target in ("commit:one-org/ops", "gitops:one-org/cluster"):
                with self.subTest(path=path, target=target):
                    self.assertEqual(self.decide(target, "push", content=self.commit((path, "x"))).kind, "refused")
        self.assertEqual(self.decide("commit:one-org/ops", "push",
                                     content=self.commit(("docs/claude.md.txt", "x"))).kind, "rule")

    def test_an_own_form_on_a_rule_only_host(self):
        for host in ("ci-1", "fleet-1"):
            d = self.decide(host, "install", "htop")
            self.assertEqual((d.kind, d.why),
                             ("refused", f"{host} is rule-only: only rule forms run there, and no file install"))
            self.assertEqual(self.decide(host, "upgrade").kind, "rule")

    def test_a_form_of_a_new_app_on_a_rule_only_host(self):
        """ops-root refuses the forms that make things for a new app on a rule-only host. The door refuses them first,
        with the host's own words: before, it took the ones that are rule calls, and made a value or a runner's
        tokens for a call that the host then refused."""
        made = {"made_app": lambda app: [{"agent": "ops-one", "app": "shop", "repo": "one-org/shop"}]}
        for op, args in (("app-new", ["shop", "8080", "/api/health"]),
                         ("env-new", ["shop", "SESSION_SECRET", "random"]), ("runner-new", ["shop"])):
            with self.subTest(op=op):
                self.assertIn(op, door_targets.OPS_ROOT.PLAN_WRITES)
                self.assertEqual(self.decide("web-1", op, *args, lookups=made).kind, "rule")
                for host in ("ci-1", "fleet-1"):
                    d = self.decide(host, op, *args, lookups=made)
                    self.assertEqual((d.kind, d.why),
                                     ("refused", f"{host} is rule-only: no form of a new app writes there"))
        for op in door_targets.OPS_ROOT.PLAN_WRITES:        # and the ones that are an agent's own forms, as before
            checked = ["shop", "SESSION_SECRET", "random"] if op.startswith("env-") else \
                ["shop", "8080", "/api/health"] if op == "app-new" else ["shop"]
            d = self.decide("ci-1", op, *checked, lookups=made,
                            content=b"x" if op in door_targets.HOST_CONTENT else None)
            self.assertEqual((d.kind, d.why.startswith("ci-1 is rule-only: ")), ("refused", True), (op, d))

    BLOCK = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop\n"

    def test_a_manifest_that_is_not_block_style_is_refused(self):
        """Code reads a manifest with patterns, line by line. YAML can write a refused form so that no line pattern
        reads it, so the door takes a YAML file only in block style, and refuses what it cannot read."""
        pod = self.BLOCK + "spec:\n  template:\n    spec:\n"
        cases = {
            "as JSON": '{"kind": "Pod", "spec": {"hostPID": true, "containers": [{"securityContext": '
                       '{"privileged": true}}]}}\n',
            "a flow mapping": pod + "      securityContext: {privileged: true}\n",
            "a flow mapping in a list": pod + "      containers:\n      - {name: a, securityContext: "
                                              "{privileged: true}}\n",
            "a flow sequence of mappings": pod + "      volumes: [{name: host, hostPath: {path: /}}]\n",
            "a pair in a flow sequence": pod + "      volumes: [hostPath: x]\n",
            "a flow sequence over lines": pod + "      args: [\n        a,\n        b]\n",
            "a quoted key": pod + '      "hostPID": true\n',
            "a quoted key in single quotes": pod + "      'hostNetwork': true\n",
            "an anchor and an alias": pod + "      hostPID: &yes true\n      hostIPC: *yes\n",
            "an alias": pod + "      securityContext: *context\n",
            "a merge key": pod + "      <<: *base\n",
            "a tag": pod + "      hostPID: !!bool yes\n",
            "an own mark of a key": pod + "      ? hostPID\n      : true\n",
            "a tab in the indentation": pod + "\thostPID: true\n",
            "a value on the next line": pod + "      hostPID:\n        true\n",
            "a value after a comment": "kind:\n  # which one\n  Secret\n",
            "a block scalar as a kind": "kind: |-\n  Secret\ndata:\n  x: eA==\n",
            "a block scalar on a line of its own": "kind:\n  >-\n    Secret\n",
            "an escape in a kind": 'kind: "\\x53ecret"\n',
            "a quoted text over lines": pod + '      note: "one\n        hostPID: true"\n',
            "a carriage return as a line end": pod + "      note: x\r      hostPID: true\n",
            "a line separator": pod + "      note: x\u2028kind: Secret\n",
            "a byte order mark": "\ufeffkind: Secret\n",
            "an expression of a template": pod + "      hostPID: {{ .Values.host }}\n",
            "a line of a template": "{{- if .Values.on }}\nkind: Secret\n{{- end }}\n",
            "content on a document mark": "--- {kind: Secret}\n",
            "a directive": "%YAML 1.1\n---\nkind: ConfigMap\n",
        }
        for what, text in cases.items():
            for path in ("apps/shop/x.yaml", "apps/shop/x.YML"):
                with self.subTest(what=what, path=path):
                    d = self.decide("gitops:one-org/cluster", "push", content=self.commit((path, text)),
                                    lookups={"base_file": lambda p: None})
                    self.assertEqual(d.kind, "refused", (what, d))
                    self.assertIn("the door takes it only in block style", d.why)
        wide = json.dumps({"message": "m", "files": [{"path": "apps/shop/x.yaml", "content": base64.b64encode(
            "kind: Secret\n".encode("utf-16")).decode()}]}).encode()
        d = self.decide("gitops:one-org/cluster", "push", content=wide)
        self.assertEqual((d.kind, "bytes that are not UTF-8" in d.why), ("refused", True), d)

    def test_refused_forms_in_every_spelling_of_block_style(self):
        """What block style still lets a writer choose: the case of a word, quotes, a comment, the depth of a line, the
        dash of a list, and the words that YAML 1.1 reads as true."""
        pod = self.BLOCK + "spec:\n  template:\n    spec:\n"
        cases = {
            "privileged": [pod + f"      securityContext:\n        privileged: {word}\n"
                           for word in ("True", "TRUE", "yes", "Yes", "on", "y", '"true"', "true # for the driver")],
            "a host namespace": [pod + "      hostPID: True\n", pod + "      hostNetwork: yes\n",
                                 pod + "      hostIPC:   ON\n"],
            "a Secret object": ["kind: List\nitems:\n- kind: Secret\n  data:\n    x: eA==\n",
                                "kind: List\nitems:\n  - apiVersion: v1\n    kind: Secret\n", 'kind: "Secret"\n',
                                "kind: 'Secret'\n", "kind: Secret # a key\n", "kind : Secret\n", "kind: secret\n",
                                "apiVersion: v1\r\nkind: Secret\r\nstringData:\r\n  key: secret\r\n",
                                "extraObjects:\n  - apiVersion: v1\n    kind: Secret   \n"],
            "RBAC": ["kind: 'ClusterRole'\n", "items:\n- kind: RoleBinding # x\n", "  kind: clusterrolebinding\n",
                     "apiVersion: rbac.authorization.k8s.io/v1\r\nkind: Role\r\n"],
            "a CRD": ['kind: "CustomResourceDefinition"\n'], "an Application": ["- kind: applicationset\n"],
            "a webhook": ["  kind: 'MutatingWebhookConfiguration' # x\n"],
            "an external-secrets kind": ['- apiVersion: "external-secrets.io/v1"\n  kind: ExternalSecret\n'],
            "a new LoadBalancer": ['kind: Service\nspec:\n  type: "LoadBalancer"\n'],
            "a new secret volume": [pod + "      volumes:\n      - secret: # the key\n          name: x\n"],
            "a k3s upgrade channel": ['- apiVersion: "upgrade.cattle.io/v1"\n  kind: Plan\n  spec:\n    channel: x\n'],
        }
        for what, texts in cases.items():
            for text in texts:
                with self.subTest(what=what, text=text):
                    d = self.decide("gitops:one-org/cluster", "push", content=self.commit(("apps/shop/x.yaml", text)),
                                    lookups={"base_file": lambda p: (self.BLOCK + "spec:\n").encode()})
                    self.assertEqual(d.kind, "refused", (what, d))
                    self.assertNotIn("block style", d.why)
                    if what != "a Secret object":
                        self.assertIn(what, d.why)

    def test_block_style_as_the_fleet_writes_it_still_passes(self):
        """What a real manifest holds: comments, empty flow collections, a flow list of plain values on one line, a
        block scalar with any text in it, a long plain text that a tool wrapped, and more than one document."""
        old = ("# the shop\n---\napiVersion: apps/v1\nkind: Deployment # the app\nmetadata:\n  name: shop\n"
               "  annotations:\n    note: one long text that a tool wrapped at the edge of its line, and\n"
               "      that goes on here, with a colon:in it\n    checksum/config: \"0a1b2c\"\n"
               "  labels: {}\nspec:\n  replicas: 2\n  template:\n    spec:\n      tolerations: []\n"
               "      containers:\n      - name: shop\n        image: ghcr.io/one-org/shop:1111111\n"
               "        command: [\"/bin/sh\", '-c', run --port=8080, $(POD_IP):80]\n        args: [ --verbose, -x ]\n"
               "        env:\n        - name: MODE\n          value: \"live: yes\"\n        - name: EMPTY\n"
               "          value: ''\n        volumeMounts:\n        - name: tmp\n          mountPath: /tmp\n"
               "      volumes:\n      - name: tmp\n        emptyDir: {}\n---\napiVersion: v1\nkind: ConfigMap\n"
               "data:\n  config.json: |\n    {\"privileged-ish\": [1, 2], \"x\": {\"y\": \"*.log\"}}\n"
               "  run.sh: |-\n    #!/bin/sh\n    exec \"$@\" &\n\n    wait\n  note: >\n    folded\n    text\n...\n")
        self.assertIsNone(door_targets.unread(old))
        for change_, kind in ((("replicas: 2", "replicas: 3"), "rule"), (("1111111", "2222222"), "rule"),
                              (("mountPath: /tmp", "mountPath: /var/tmp"), "own")):
            with self.subTest(change=change_):
                d = self.decide("gitops:one-org/cluster", "push",
                                content=self.commit(("apps/shop/deployment.yaml", old.replace(*change_))),
                                lookups={"base_file": lambda p: old.encode(), "image_made": lambda image: True})
                self.assertEqual(d.kind, kind, d)
        d = self.decide("gitops:one-org/cluster", "push", content=self.commit(("apps/shop/new.yaml", old)),
                        lookups={"base_file": lambda p: None})
        self.assertEqual((d.kind, d.why), ("own", "apps/shop/new.yaml is a new manifest"))
        # a file at HEAD that is not block style is no reason to refuse a block style file in its place
        d = self.decide("gitops:one-org/cluster", "push", content=self.commit(("apps/shop/deployment.yaml", old)),
                        lookups={"base_file": lambda p: b'{"kind": "Deployment"}\n'})
        self.assertEqual(d.kind, "own", d)
        # a file that is no YAML and no JSON is read as before
        d = self.decide("gitops:one-org/cluster", "push", lookups={"base_file": lambda p: None},
                        content=self.commit(("docs/README.md", "# The cluster\n\n- {a: b}\n\"quoted\": text\n")))
        self.assertEqual(d.kind, "own", d)

    def test_a_json_manifest_is_read_as_the_lines_that_say_the_same(self):
        """A cluster's tools apply a .json file as they apply YAML, so the door parses it and reads its keys as block
        style lines: before, no pattern read "kind": "Secret"."""
        def push(text, path="apps/shop/x.json"):
            return self.decide("gitops:one-org/cluster", "push", content=self.commit((path, text)),
                               lookups={"base_file": lambda p: None})
        pod = {"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [{"name": "a", "image": "x"}]}}
        self.assertEqual(push(json.dumps(pod)).kind, "own")
        self.assertEqual(push(json.dumps({"title": "Board", "panels": [{"id": 1, "targets": []}]}, indent=2)).kind,
                         "own")
        for what, change_ in (("a host namespace", lambda p: p["spec"].update(hostPID=True)),
                              ("privileged", lambda p: p["spec"]["containers"][0].update(
                                  securityContext={"privileged": True})),
                              ("a hostPath", lambda p: p["spec"].update(
                                  volumes=[{"name": "h", "hostPath": {"path": "/"}}])),
                              ("a new LoadBalancer", lambda p: p.update(kind="Service", spec={"type": "LoadBalancer"})),
                              ("RBAC", lambda p: p.update(kind="ClusterRoleBinding")),
                              ("holds a Secret object", lambda p: p.update(kind="Secret", data={"x": "eA=="})),
                              ("holds a Secret object", lambda p: p.update(kind="List", items=[{"kind": "Secret"}]))):
            with self.subTest(what=what):
                bad = json.loads(json.dumps(pod))
                change_(bad)
                for text in (json.dumps(bad), json.dumps(bad, indent=4), json.dumps([bad])):
                    d = push(text)
                    self.assertEqual((d.kind, what in d.why), ("refused", True), d)
        for text in ('{"kind": "ConfigMap", "kind": "Secret"}', "{kind: Secret}", '{"kind": "Secret"', "[" * 100000):
            with self.subTest(text=text[:40]):
                d = push(text)
                self.assertEqual((d.kind, "a JSON file that is not JSON with each key once" in d.why),
                                 ("refused", True), d)

    def test_a_file_with_another_name_gets_the_loose_reading_in_a_gitops_commit(self):
        """The block reader went by the file's name, and Kustomize takes any name in `resources:`, as Helm renders
        every file under templates/. Before, a flow style or JSON Pod in pod.txt, with a block style kustomization
        that lists it, was the agent's own call. A file with another name than .yaml, .yml or .json holds none of
        the words of a refused form, wherever the word stands, and nothing that may be a Secret."""
        def push(path, text, base=None):
            return self.decide("gitops:one-org/cluster", "push", content=self.commit((path, text)),
                               lookups={"base_file": lambda p: base})
        pod = json.dumps({"apiVersion": "v1", "kind": "Pod", "spec": {"hostPID": True, "containers": [
            {"name": "a", "securityContext": {"privileged": True}}]}})
        back = chr(92)
        cases = (("apps/x/pod.txt", pod, "the word privileged"),
                 ("apps/x/pod.txt", "spec: {hostPID: true, containers: [{name: a}]}\n", "the word hostpid"),
                 ("charts/shop/templates/secret.tpl", "{kind: Secret, metadata: {name: key}, data: {k: c2VjcmV0}}\n",
                  "what may be a Secret object"),
                 ("charts/shop/templates/key.tpl", '{"kind": "' + back + 'u0053ecret"}\n',
                  "what may be a Secret object"),
                 ("apps/x/volumes", "volumes: [{name: host, hostPath: {path: /}}]\n", "the word hostpath"),
                 ("apps/x/escape.txt", '{"host' + back + 'x4eetwork": true}\n', "the word hostnetwork"),
                 ("apps/x/joined.txt", '"host' + back + '\n    IPC": true\n', "the word hostipc"),
                 ("apps/x/binary.txt", "? !!binary aG9zdFBhdGg=\n: {path: /}\n", "the word !!binary"),
                 ("apps/x/binding.txt", "roleRef: {kind: Role, name: admin}\n", "the word kind: role"),
                 ("apps/x/admin.txt", "kind: ClusterRoleBinding\n", "the word clusterrolebinding"),
                 ("apps/x/app.txt", '{"kind": "Application"}\n', "the word kind: application"),
                 ("apps/x/account.txt", "serviceAccountName: admin\n", "the word serviceaccountname"),
                 ("apps/x/claim.txt", '{"resources": {"requests": {"storage": "500Gi"}}}\n', "a bigger volume claim"),
                 ("apps/x/service.txt", "spec: {type: LoadBalancer}\n", "the word loadbalancer"),
                 ("apps/x/env.txt", "env: [{valueFrom: {secretKeyRef: {name: k, key: k}}}]\n", "the word secretkeyref"),
                 ("apps/x/volume.txt", "volumes:\n- name: k\n  'secret': {secretName: k}\n", "the word secretname"),
                 ("docs/README.md", "# The cluster\n\nNo pod here mounts a hostPath.\n", "the word hostpath"))
        for path, text, word in cases:
            with self.subTest(path=path, word=word):
                d = push(path, text, None)              # a new file: one word is enough
                self.assertEqual(d.kind, "refused", d)
                self.assertTrue(d.why.startswith(f"{path}: {word}, more than the file holds at HEAD, which no commit "
                                                 f"passes in a file that code reads only loosely"), d.why)
                # the same words at HEAD, where the repository's own people wrote them: the file stays editable
                self.assertNotEqual(push(path, text + "# a note\n", text.encode()).kind, "refused")
        # a text that has the word at HEAD and becomes a manifest with it is refused for its new keys
        readme = "# The cluster\n\nNo pod here mounts a hostPath.\n"
        d = push("docs/README.md", "kind: Pod\nspec: {volumes: [{name: host, hostPath: {path: /}}]}\n",
                 readme.encode())
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("a kind or an apiVersion key", d.why)
        d = push("docs/README.md", readme + "securityContext: {privileged: true}\n", (readme + "privileged\n").encode())
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("privileged: true", d.why)
        for path, text in (("apps/x/Kustomization", "resources:\n- pod.txt\n- [not, block]\n"),
                           ("docs/README.md", "# The cluster\n\nThe roles, the storage and the secrets of an "
                                              "application: who may change a channel, and its type.\n"),
                           ("scripts/sync.sh", "#!/bin/sh\nset -eu\nkubectl get pods -o json | jq '{kind: .kind}'\n"),
                           ("charts/shop/templates/_helpers.tpl", '{{- define "shop.name" -}}\n{{ .Chart.Name }}\n'
                                                                  "{{- end }}\n")):
            with self.subTest(path=path):
                self.assertEqual(push(path, text).kind, "own")

    HELM = ("kind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\nspec:\n  replicas: 2\n  template:\n    spec:\n"
            "      serviceAccountName: shop\n      containers:\n      - name: shop\n"
            "        image: ghcr.io/one-org/shop:1111111\n        env: [{name: MODE, value: live}]\n"
            "        securityContext: {\"privileged\": false}\n      volumes: [{name: tmp, emptyDir: {}}]\n")

    def test_a_yaml_file_that_its_people_wrote_in_another_style_keeps_its_rule_calls(self):
        """A file that is not block style at HEAD was written so by the people of the repository. The door does not
        refuse a listed change of it for its style: a tag or a replica count in it is a rule call, as before the
        block reader. No other line of it changes, because a count of words cannot say what such a change does: a key
        that a template builds, a tag before a value and a word that moves out of a comment add no word. It holds no
        more of each word of a refused form than at HEAD, and no Secret that HEAD did not hold. A new file in that
        style, and one that was block style at HEAD, are refused as before."""
        def push(text, base=self.HELM, path="charts/shop/templates/deployment.yaml"):
            return self.decide("gitops:one-org/cluster", "push", content=self.commit((path, text)),
                               lookups={"base_file": lambda p: base and base.encode(),
                                        "image_made": lambda image: image.endswith(":2222222")})
        self.assertIsNotNone(door_targets.unread(self.HELM))
        for old, new, kind in (("replicas: 2", "replicas: 3", "rule"), ("shop:1111111", "shop:2222222", "rule"),
                               ("shop:1111111", "shop:3333333", "own")):
            with self.subTest(new=new):
                d = push(self.HELM.replace(old, new))
                self.assertEqual(d.kind, kind, d)
        commented = self.HELM + "# a note about hostPath and privileged: true\n"
        for base, old, new in (
                (self.HELM, "value: live", "value: test"),
                (self.HELM, "emptyDir: {}}]", "emptyDir: {medium: Memory}}]"),
                (self.HELM, '{"privileged": false}', "{ {{ .Values.flag }}: true }"),
                (self.HELM, '{"privileged": false}', '{"privileged": !!bool "true"}'),
                (self.HELM, "kind: Deployment", '? "kind"\n: {{ .Values.kind }}'),
                (self.HELM, "image: ghcr.io/one-org/shop:1111111", "image: {{ .Values.other }}"),
                # a line of another key that becomes a listed one: the first one is gone
                (self.HELM, '        securityContext: {"privileged": false}', "  replicas: 2"),
                (self.HELM, "        env: [{name: MODE, value: live}]", "        tag: 2222222"),
                # a line that holds more than its first key: a listed line in its place takes the rest out
                (self.HELM + "extra: {\n  replicas: 1, hostNetwork: false\n  }\n", "  replicas: 1, hostNetwork: false",
                 "  replicas: 2"),
                (self.HELM + '  image: app:1 {{- include "sec" . | nindent 2 }}\n',
                 '  image: app:1 {{- include "sec" . | nindent 2 }}', "  image: app:2"),
                (commented, "emptyDir: {}}]\n# a note about hostPath and privileged: true",
                 '"hostPath": {path: /}}]\n# a note about volumes and privileged: no')):
            with self.subTest(new=new):
                d = push(base.replace(old, new), base=base)
                self.assertEqual(d.kind, "refused", d)
                self.assertIn("is not block style, so code cannot read what this change of it does", d.why)
        loosely = "which no commit passes in a file that code reads only loosely"
        for old, new, word in (
                ('{"privileged": false}', '{"privileged": true}', "the word privileged: true"),
                ('{"privileged": false}', '{"privileged": false}\n      hostPID: yes', "the word hostpid"),
                ("emptyDir: {}", "hostPath: {path: /}", "the word hostpath"),
                ("{name: MODE, value: live}", "{name: MODE, valueFrom: {secretKeyRef: {name: k, key: k}}}",
                 "the word secretkeyref"),
                ("serviceAccountName: shop", '"serviceAccountName": "admin"', "a changed serviceAccountName"),
                ("kind: Deployment", '"kind": ClusterRole', "the word clusterrole"),
                ("[{name: tmp, emptyDir: {}}]",
                 "[{name: tmp, emptyDir: {}}]\nextra: [{kind: Secret, stringData: {k: v}}]",
                 "what may be a Secret object")):
            with self.subTest(word=word):
                d = push(self.HELM.replace(old, new))
                self.assertEqual((d.kind, d.why.split(", ")[0], loosely in d.why),
                                 ("refused", f"charts/shop/templates/deployment.yaml: {word}", True), d)
        style = "the door takes it only in block style"
        for what, d in (("a new file", push(self.HELM, base=None)),
                        ("block style at HEAD", push(self.HELM, base="kind: Deployment\nspec:\n  replicas: 2\n")),
                        ("a JSON file", push('{"kind": "Pod", "kind": "Pod"}', base='{"kind": "Pod", "kind": "Pod"}',
                                             path="apps/x/pod.json"))):
            with self.subTest(what=what):
                self.assertEqual((d.kind, style in d.why), ("refused", True), d)
        secret = self.HELM.replace("kind: Deployment", "kind: Secret")          # one that HEAD holds is no rule call
        self.assertEqual(push(secret.replace("replicas: 2", "replicas: 3"), base=secret).why,
                         "charts/shop/templates/deployment.yaml holds a Secret object")

    def test_a_rule_call_changes_a_value_and_never_a_key(self):
        """A change of equal line count that turns a line of another key into a listed one took the first line out
        as a rule call. A line keeps its key, its indentation and its dash, or the change is the agent's own call."""
        base = ("kind: Deployment\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n"
                "      - name: shop\n        image: ghcr.io/one-org/shop:1111111\n        securityContext:\n"
                "          runAsNonRoot: true\n")

        def push(text):
            return self.decide("gitops:one-org/cluster", "push", content=self.commit(("apps/shop/dep.yaml", text)),
                               lookups={"base_file": lambda p: base.encode(), "image_made": lambda image: True})
        self.assertEqual(push(base.replace("replicas: 2", "replicas: 3")).kind, "rule")
        self.assertEqual(push(base.replace("shop:1111111", "shop:2222222")).kind, "rule")
        for old, new in (("          runAsNonRoot: true", "  replicas: 2"),
                         ("  replicas: 2", "    replicas: 2"), ("  replicas: 2", "  - replicas: 2"),
                         ("          runAsNonRoot: true", "        image: ghcr.io/one-org/shop:1111111")):
            with self.subTest(new=new):
                self.assertEqual(push(base.replace(old, new)).kind, "own")

    def test_a_file_that_only_names_the_kind_secret_holds_no_secret_object(self):
        """An Application's ignoreDifferences and a patch's target name the kind Secret and hold none. Such a file
        keeps its calls, and a new one is the agent's own call. A Secret object is the kind at the top level of a
        document, or an item of a List, which has its data."""
        app = ("apiVersion: argoproj.io/v1alpha1\nkind: Deployment\nmetadata:\n  name: shop\nspec:\n  replicas: 2\n"
               "  ignoreDifferences:\n  - kind: Secret\n    jsonPointers:\n    - /data\n")
        self.assertFalse(door_targets.secret_object(app))

        def push(text, base):
            return self.decide("gitops:one-org/cluster", "push", content=self.commit(("apps/shop/app.yaml", text)),
                               lookups={"base_file": lambda p: base and base.encode()})
        self.assertEqual(push(app.replace("replicas: 2", "replicas: 3"), app).kind, "rule")
        self.assertEqual(push(app, None).kind, "own")
        self.assertEqual(push(app, app.replace("  ignoreDifferences:\n  - kind: Secret\n    jsonPointers:\n    - /data\n",
                                               "")).kind, "own")
        for text in ("kind: Secret\nmetadata:\n  name: k\n", 'kind: "secret" # one\ndata:\n  k: djE=\n',
                     "kind: List\nitems:\n- kind: Secret\n  stringData:\n    k: v\n",
                     "kind: List\nitems:\n  - apiVersion: v1\n    kind: Secret\n    data:\n      k: djE=\n"):
            with self.subTest(text=text):
                self.assertTrue(door_targets.secret_object(text))
                self.assertEqual(push(text, None).kind, "refused")
                self.assertEqual(push(text + "# a note\n", text).kind, "refused")

    def test_the_instruction_files_of_an_agent_s_runtime_are_under_the_commit_rules(self):
        """What a runtime reads as its instructions or its settings when a person or an agent starts it in a
        checkout: the local and override files of Claude Code and Codex, and the files of the other runtimes."""
        for path in ("CLAUDE.local.md", "apps/x/claude.LOCAL.md", "AGENTS.override.md", "sub/agents.Override.md",
                     ".agents/skills/deploy/SKILL.md", "GEMINI.md", "a/gemini.md", ".gemini/settings.json",
                     ".cursorrules", ".cursor/rules/style.mdc", ".windsurfrules", ".windsurf/rules/a.md", ".clinerules",
                     ".clinerules/a.md", ".roo/rules/a.md", ".roorules", ".continue/config.json", ".aider.conf.yml",
                     ".opencode/agent/review.md", "opencode.json", ".kiro/steering/a.md", ".junie/guidelines.md",
                     ".github/copilot-instructions.md"):
            for target in ("commit:one-org/ops", "gitops:one-org/cluster"):
                with self.subTest(path=path, target=target):
                    d = self.decide(target, "push", content=self.commit((path, "x")))
                    self.assertEqual((d.kind, "under the commit rules" in d.why), ("refused", True), d)
        for path in ("docs/cursor/notes.md", "docs/agents.override.md.txt", "docs/gemini.md.bak", "opencode.json.md"):
            with self.subTest(path=path):
                d = self.decide("commit:one-org/ops", "push", content=self.commit((path, "x")))
                self.assertEqual(d.kind, "rule", d)

    def test_a_hostile_lockfile_and_a_young_package(self):
        lock_old = {"packages": {"": {"dependencies": {"left-pad": "^1.0.0"}},
                                 "node_modules/left-pad": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/"
                                                           "left-pad/-/left-pad-1.0.0.tgz", "integrity": "sha512-a"}}}
        hostile = json.loads(json.dumps(lock_old))
        hostile["packages"]["node_modules/left-pad"] = {"version": "1.0.1", "resolved": "https://evil.example/x.tgz",
                                                        "integrity": "sha512-b"}
        registry = {"versions": {"1.0.1": {"dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.1"
                                                               ".tgz", "integrity": "sha512-b"}}},
                    "time": {"1.0.1": "2026-01-01T00:00:00.000Z"}}
        lookups = {"base_file": lambda p: json.dumps(lock_old).encode(), "npm": lambda name: registry}
        d = self.decide("commit:one-org/shop", "push", content=self.commit(("package-lock.json", json.dumps(hostile))),
                        lookups=lookups)
        self.assertEqual(d.kind, "own")         # any failure but its age makes it the agent's own call
        young = dict(registry, time={"1.0.1": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())})
        good = json.loads(json.dumps(hostile))
        good["packages"]["node_modules/left-pad"]["resolved"] = registry["versions"]["1.0.1"]["dist"]["tarball"]
        d = self.decide("commit:one-org/shop", "push", content=self.commit(("package-lock.json", json.dumps(good))),
                        lookups=dict(lookups, npm=lambda name: young))
        self.assertEqual(d.kind, "refused")
        self.assertIn("younger than 7 days", d.why)

    def test_a_package_install_works_from_the_agent_s_own_form(self):
        got = self.call(ONE, "web-1", "install", "nginx")
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        self.assertEqual(self.stubs.ssh_calls[-1][1:3], ("install", ["nginx"]))

    def test_a_hidden_app_tree_stays_hidden_in_the_transient_service(self):
        ran = []
        with patch.object(door_targets.OPS_ROOT, "run", lambda argv, **kw: (ran.append(argv), (0, "ok"))[1]):
            door_targets.OPS_ROOT.do_exec({"args": ["ls", "/etc/nginx"]}, None)
        argv = ran[0]
        self.assertEqual(argv[:5], ["systemd-run", "--pipe", "--wait", "--collect", "--quiet"])
        props = [argv[i + 1] for i, a in enumerate(argv) if a == "--property"]
        for hidden in ("/var/www", "/srv", "/opt", "/home", "/root", "/run/docker.sock", "/run/containerd",
                       "/etc/letsencrypt", "/var/lib/docker"):
            self.assertIn(f"InaccessiblePaths=-{hidden}", props)
        for prop in ("PrivateDevices=yes", "NoNewPrivileges=yes", "ProtectKernelModules=yes"):
            self.assertIn(prop, props)
        caps = next(p for p in props if p.startswith("CapabilityBoundingSet=~"))
        for cap in ("CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH", "CAP_SETUID", "CAP_SETGID",
                    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_MKNOD", "CAP_BPF"):
            self.assertIn(cap, caps)
        self.assertIn("ReadOnlyPaths=-/usr/local/sbin/ops-root", props)
        self.assertEqual(argv[argv.index("--") + 1:], ["ls", "/etc/nginx"])


class OwnCalls(DoorCase):
    """Test 4, since the owner's word of 11 November 2026 ("no, I dont want any api key! it needs to be the agent
    itself"): the door calls no model and reads no model key. A call that code does not list as a rule but that the
    agent's grant covers runs as the agent's own call, and the door's record names it so; the same call of an agent
    without that grant, or on a rule-only host, is refused by code. With the door down, nothing writes, and a check
    that runs `ops status` prints one line (Callers.test_the_door_down_is_one_line_and_no_write)."""

    def setUp(self):
        super().setUp()
        self.reads = []
        secret = self.door.secret
        self.door.secret = lambda ref: (self.reads.append(ref), secret(ref))[1]

    def line(self):
        return self.door.record.after(0)[-1]

    def test_a_call_outside_the_rules_runs_as_the_agent_s_own_call_and_the_record_says_so(self):
        got = self.call(ONE, "web-1", "exec", "ls", "/etc/nginx")
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        self.assertNotIn("call", got)
        self.assertEqual(self.stubs.ssh_calls, [("100.64.1.1", "exec", ["ls", "/etc/nginx"], None)])
        line = self.line()
        self.assertEqual((line["caller"], line["target"], line["action"], line["kind"], line["outcome"]),
                         ("ops-one", "web-1", "exec", "own", "done"))
        self.assertEqual(line["why"], "ops-one's own call, which it answers for: the host form exec")
        self.assertEqual((self.stubs.model_calls(), self.reads), ([], []))     # no model, and no key of one

    def test_rule_calls_and_own_calls_run_side_by_side_and_only_own_calls_say_so(self):
        self.assertEqual(self.call(ONE, "web-1", "restart", "nginx")["kind"], "rule")
        self.assertEqual(self.call(ONE, "web-1", "install", "htop")["kind"], "own")
        self.assertEqual(self.call(ONE, "web-1", "upgrade")["kind"], "rule")
        self.assertEqual([c[1] for c in self.stubs.ssh_calls], ["restart", "install", "upgrade"])
        self.assertEqual([(e["action"], e["kind"], e["why"].startswith("ops-one's own call, which it answers for"))
                          for e in self.door.record.after(0)],
                         [("restart", "rule", False), ("install", "own", True), ("upgrade", "rule", False)])

    def test_the_same_call_without_the_grant_or_on_a_rule_only_host_is_refused_by_code(self):
        for address, host, why in ((TWO, "web-1", "ops-two holds no grant on web-1"),
                                   (ONE, "logs-1", "ops-one holds Read on logs-1: no write"),
                                   (ONE, "ci-1", "ci-1 is rule-only: only rule forms run there, and no file install")):
            with self.subTest(host=host):
                got = self.call(address, host, "install", "htop")
                self.assertEqual((got["ok"], got["kind"], got["why"]), (False, "refused", why))
                self.assertNotIn("call", got)       # nothing for the owner to say yes to: code refused it
        self.assertEqual((self.stubs.ssh_calls, self.stubs.model_calls()), ([], []))

    def test_a_gitops_commit_that_deletes_files_runs_as_the_agent_s_own_call(self):
        """The first live call of this kind: an Operator's commit in the GitOps repository that deletes the files of
        idle copies. Code passes no deleted file as a rule, and nothing in it is a refusal of code, so it runs."""
        api, calls = "https://api.github.com/repos/one-org/cluster", []
        answers = {("GET", f"{api}/installation"): (200, {"id": 9}),
                   ("POST", "https://api.github.com/app/installations/9/access_tokens"): (201, {"token": "ghs_door"}),
                   ("GET", api): (200, {"default_branch": "main"}),
                   ("GET", f"{api}/git/ref/heads/main"): (200, {"object": {"sha": "h1"}}),
                   ("GET", f"{api}/git/commits/h1"): (200, {"tree": {"sha": "t1"}}),
                   ("POST", f"{api}/git/trees"): (201, {"sha": "t2"}),
                   ("POST", f"{api}/git/commits"): (201, {"sha": "c2"}),
                   ("PATCH", f"{api}/git/refs/heads/main"): (200, {})}

        def http(method, url, headers, data):
            calls.append((method, url, None if data is None else json.loads(data)))
            return answers.get((method, url), (404, {"message": "not stubbed"}))
        self.door.http = http
        door.GitHub.TOKENS.clear()
        door.GitHub.BRANCHES.clear()
        self.addCleanup(door.GitHub.TOKENS.clear)
        self.addCleanup(door.GitHub.BRANCHES.clear)
        content = json.dumps({"message": "Remove the idle canary and test copies", "files": [
            {"path": "apps/shop-canary/deployment.yaml", "delete": True},
            {"path": "apps/shop-test/values.yaml", "delete": True}]}).encode()
        with patch.object(door_providers, "app_jwt", lambda app_id, pem, sign=None: "jwt"):
            got = self.call(ONE, "gitops:one-org/cluster", "push", content=content)
        self.assertEqual((got["ok"], got["kind"], got.get("out")), (True, "own", "one-org/cluster main is at c2; "
                                                                  "the door could not read its checks (GitHub "
                                                                  "answered 404)"), got)
        tree = next(body for method, url, body in calls if url.endswith("/git/trees"))
        self.assertEqual([(e["path"], e["sha"]) for e in tree["tree"]],
                         [("apps/shop-canary/deployment.yaml", None), ("apps/shop-test/values.yaml", None)])
        line = self.line()
        self.assertEqual((line["caller"], line["target"], line["kind"], line["outcome"]),
                         ("ops-one", "gitops:one-org/cluster", "own", "done"))
        self.assertEqual(line["why"], "ops-one's own call, which it answers for: apps/shop-canary/deployment.yaml "
                                      "is deleted")
        self.assertEqual(self.stubs.model_calls(), [])
        self.assertNotIn("api.anthropic.com", json.dumps(calls))

    def test_the_door_knows_no_model_key(self):
        data = json.loads(json.dumps(ACCESS))
        data["credentials"]["model"] = {"secret": ref(10)}
        with self.assertRaisesRegex(ValueError, "credential 'model' is not <provider>:<account>"):
            door.validate_access(data)
        for name in ("JUDGE_URL", "JUDGE_MODEL", "JUDGE_SYSTEM", "NO_JUDGE", "REFUSED_FILE", "COUNTS_FILE"):
            self.assertFalse(hasattr(door, name), name)
        for name in ("judge", "judge_key", "ask_model"):
            self.assertFalse(hasattr(door.Door, name), name)
        with open(door.__file__, encoding="utf-8") as f:
            self.assertNotIn("anthropic", f.read().lower())


class Order(DoorCase):
    """Test 8: who may change the access file, the cap of a call's content, the order of writes and the windows."""

    def test_content_over_its_cap_is_refused_and_never_cut(self):
        got = self.call(ONE, "web-1", "file", "/etc/nginx/x.conf", "0644", "root",
                        content=b"x" * (door_targets.CONTENT_MAX + 1))
        self.assertEqual(got["kind"], "refused")
        self.assertIn("refused, never cut", got["why"])
        self.assertEqual(self.stubs.ssh_calls, [])

    def test_two_routes_of_one_tunnel_never_overlap(self):
        """New-projects plan N7: a route reads and writes the tunnel's whole configuration, so the second call on
        that tunnel waits for the first, and neither route is lost."""
        config, running, seen = {"ingress": [{"service": "http_status:404"}]}, [0], [0]
        lock = threading.Lock()
        tunnel = f"https://api.cloudflare.com/client/v4/accounts/{'b' * 32}/cfd_tunnel/{TUNNEL}/configurations"

        def http(method, url, headers, body):
            if url != tunnel:
                return self.stubs.http(method, url, headers, body)
            with lock:
                running[0] += 1
                seen[0] = max(seen[0], running[0])
            try:
                time.sleep(0.2)
                if method == "GET":
                    return 200, {"result": {"config": json.loads(json.dumps(config))}}
                config.update(json.loads(body)["config"])
                return 200, {"success": True}
            finally:
                with lock:
                    running[0] -= 1
        self.door.http = http
        threads = [threading.Thread(target=self.call, args=(ONE, "cloudflare:one", "tunnel-route", TUNNEL, name, port))
                   for name, port in (("a.example.com", "8081"), ("b.example.com", "8082"))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(seen[0], 1)
        self.assertEqual(sorted(r.get("hostname", "") for r in config["ingress"]), ["", "a.example.com", "b.example.com"])

    def test_a_second_write_on_one_host_waits(self):
        self.stubs.pause = 0.4
        threads = [threading.Thread(target=self.call, args=(ONE, "web-1", "restart", unit)) for unit in ("a", "b")]
        t0 = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertGreaterEqual(time.monotonic() - t0, 0.8)
        self.assertEqual(self.stubs.overlap, 1)
        self.stubs.overlap = 0
        threads = [threading.Thread(target=self.call, args=(ONE, host, "restart", "a")) for host in ("web-1", "db-1")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.stubs.overlap, 2)        # two hosts do not wait for each other

    def test_one_reboot_at_a_time_in_each_business(self):
        self.stubs.pause = 0.3
        self.clock_at = datetime.datetime(2026, 11, 2, 1, 0, tzinfo=datetime.timezone.utc)
        threads = [threading.Thread(target=self.call, args=(ONE, host, "reboot")) for host in ("web-1", "db-1")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.stubs.overlap, 1)
        self.assertEqual(sorted(c[0] for c in self.stubs.ssh_calls), ["100.64.1.1", "100.64.1.2"])

    def test_a_reboot_whose_session_ends_badly_still_holds_its_business_until_the_host_answers(self):
        """The reboot, or Tailscale's own restart in its upgrade, can cut the call's own session: ssh then ends with
        255 although the host goes down. The next reboot of the business waits for the host as after a clean answer;
        only a refusal of ops-root, which ran nothing, does not wait."""
        waited = []
        self.door.back = lambda access, host: waited.append((host, self.door.business_locks["one"].locked()))
        self.door.ssh = lambda host, req, stdin: (255, "Connection to 100.64.1.1 closed by remote host.")
        got = self.call(ONE, "web-1", "reboot")
        self.assertEqual((got["ok"], waited), (False, [("web-1", True)]))    # with its business still held
        self.door.ssh = lambda host, req, stdin: (3, "refused: this host reboots only from its own window")
        self.assertFalse(self.call(ONE, "web-1", "reboot")["ok"])
        self.assertEqual(waited, [("web-1", True)])

    def test_a_reboot_or_a_restart_inside_a_window_is_refused(self):
        self.clock_at = datetime.datetime(2026, 11, 2, 22, 0, tzinfo=datetime.timezone.utc)
        got = self.call(ONE, "web-1", "restart", "shop")
        self.assertIn("inside a window", got["why"])
        self.clock_at = datetime.datetime(2026, 11, 2, 0, 15, tzinfo=datetime.timezone.utc)
        self.assertIn("inside a window", self.call(ONE, "web-1", "rollback", "shop")["why"])
        self.clock_at = datetime.datetime(2026, 11, 2, 12, 0, tzinfo=datetime.timezone.utc)
        self.assertIn("runs only inside its window", self.call(ONE, "db-1", "reboot")["why"])
        self.assertTrue(self.call(ONE, "web-1", "restart", "shop")["ok"])
        self.clock_at = datetime.datetime(2026, 11, 2, 2, 30, tzinfo=datetime.timezone.utc)
        self.assertTrue(self.call(ONE, "db-1", "reboot")["ok"])
        self.assertTrue(self.call(ONE, "web-1", "journal-vacuum")["ok"])         # no window class

    def test_every_call_leaves_one_numbered_line_with_no_content(self):
        self.call(ONE, "web-1", "uptime")
        self.call(STRANGER, "web-1", "uptime")
        self.call(ONE, "web-1", "file", "/etc/nginx/x.conf", "0644", "root", content=b"secret-looking-bytes")
        entries = self.door.record.after(0)
        self.assertEqual([e["n"] for e in entries], [1, 2, 3])
        self.assertNotIn("secret-looking-bytes", slurp(self.root + door.RECORD_FILE, "r"))
        self.assertEqual(door.Record().last, 3)

    def test_a_caller_s_own_words_are_cut_in_its_line_of_the_record(self):
        """The target and the action of a refused call are the caller's own, as long as a request's body, and a
        caller that the file does not name can send them too. Each field of a line is one short text or a number."""
        self.call(STRANGER, "t" * 200000, "a" * 5000)
        self.call(ONE, "t" * 200000, "a" * 5000)
        self.door.call(STRANGER, {"host": "w" * 200000}, ["restart"] * 1000, [])
        lines = self.door.record.after(0)
        self.assertEqual([line["n"] for line in lines], [1, 2, 3])
        for line in lines:
            for field in ("target", "action"):
                self.assertIsInstance(line[field], str)
                self.assertLessEqual(len(line[field]), door.RECORD_TEXT)
        self.assertLess(os.path.getsize(self.root + door.RECORD_FILE), 4000)

    def test_the_door_reads_a_program_s_answer_up_to_its_cap_and_stops_it_there(self):
        """A host's answer had no cap, and the door read all of it. ops-read and ops-root cut their own answers far
        below HOST_OUT_MAX, so only a host that is not the door's own code writes more."""
        name = os.path.basename(sys.executable)
        loud = [sys.executable, "-c", "import sys; sys.stdout.write('x' * 300000)"]
        self.assertEqual(door.run_program(loud, None, {}, limit=1024),
                         (1, f"{name} wrote more than 1 KiB, which the door does not read"))
        self.assertEqual(door.run_program(loud, None, {}, limit=300000), (0, "x" * 300000))
        count = [sys.executable, "-c", "import sys; sys.stdout.write(str(len(sys.stdin.buffer.read())))"]
        self.assertEqual(door.run_program(count, b"y" * 500000, {}, limit=1024), (0, "500000"))
        self.assertEqual(door.run_program([sys.executable, "-c", "import time; time.sleep(30)"], None, {}, timeout=1,
                                          limit=1024), (124, f"{name} took longer than 1 seconds"))
        self.assertEqual(door.run_program([sys.executable, "-c", "raise SystemExit(3)"], None, {}, limit=1024), (3, ""))
        self.assertEqual(door.run_program(["/no/such/program"], None, {}, limit=1024)[0], 127)

    def test_a_host_s_answer_has_the_cap_and_its_help_a_short_wait(self):
        """The host sweep asks each host's help in turn, under that host's lock: with the hour of a long form, one
        host that hangs held every other host's update and its own writes."""
        seen = []

        def program(argv, stdin, env, timeout=600, limit=None):
            seen.append((json.loads(base64.b64decode(argv[-1]))["op"], timeout, limit))
            return 0, ""
        mine = door.Door(conf={"address": "127.0.0.1"}, http=self.stubs.http)
        with patch.object(door, "run_program", program):
            for op in ("help", "upgrade", "uptime"):
                mine.ssh_call(ACCESS["hosts"]["web-1"], {"v": 1, "op": op, "args": []}, None)
        self.assertEqual(seen, [("help", door.HELP_WAIT, door.HOST_OUT_MAX), ("upgrade", 3600, door.HOST_OUT_MAX),
                                ("uptime", 3600, door.HOST_OUT_MAX)])
        self.assertLessEqual(door.HELP_WAIT, 120)
        self.assertGreaterEqual(door.HOST_OUT_MAX, 4 * door_targets.OPS_READ.OUT_MAX)


class HubLine(Served):
    """Test 8: a line that the hub sends does not change the access file. The door has no route that writes it: only
    root, through `door.py access`, which the owner's app runs over its own SSH."""

    def test_a_line_the_hub_sends_does_not_change_the_file(self):
        import urllib.request
        before = slurp(self.root + door.ACCESS_FILE)
        self.assertEqual(self.door.call(HUB, "web-1", "uptime", [])["why"], "this caller is not in the door's access "
                                                                           "file")
        self.assertEqual(self.ops("status", address=HUB)[0], 3)
        for path in ("/access", "/call", "/grant", "/github/token"):
            req = urllib.request.Request(f"http://127.0.0.1:{self.httpd.server_port}{path}",
                                         data=json.dumps({"agents": {}, "target": "web-1", "action": "uptime"})
                                         .encode(), method="POST",
                                         headers={"Content-Type": "application/json", "X-Test-Source": HUB})
            with self.assertRaises(urllib.error.HTTPError) as answer:
                urllib.request.urlopen(req, timeout=5)
            self.assertIn(answer.exception.code, (403, 404))
        self.assertEqual(slurp(self.root + door.ACCESS_FILE), before)


class HubRights(Served):
    """The hub's two rights, each with its own secret, and nothing else: a GitHub token for a grant of the access
    file, and the record."""

    def setUp(self):
        super().setUp()
        with patch("sys.stdout", io.StringIO()) as out:
            door.cmd_hub_secrets(None)
        self.secrets = json.loads(out.getvalue())
        self.github = []

        def http(method, url, headers, data):
            self.github.append((method, url, data))
            if url.endswith("/installation"):
                return 200, {"id": 77}
            if url.endswith("/access_tokens"):
                return 201, {"token": "ghs_" + "x" * 36, "expires_at": "2026-11-02T13:00:00Z"}
            return self.stubs.http(method, url, headers, data)
        self.door.http = http
        patcher = patch.object(door_providers, "app_jwt", lambda app_id, pem, sign=None: "jwt")
        patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, path, body, token, source=HUB):
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{self.httpd.server_port}{path}", data=json.dumps(body).encode(),
                                     method="POST", headers={"Content-Type": "application/json",
                                                             "Authorization": f"Bearer {token}",
                                                             "X-Test-Source": source})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def get(self, path, token, source=HUB):
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{self.httpd.server_port}{path}",
                                     headers={"Authorization": f"Bearer {token}", "X-Test-Source": source})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_a_token_only_for_a_grant_of_the_access_file(self):
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {
            "one-org/shop": "write", "one-org/ops": "write", "one-org/other": "read",
            "founderizer/founderizer-apps": "read"}}, self.secrets["token"])
        self.assertEqual(status, 200, got)
        self.assertEqual([(t["access"], t["repos"]) for t in got["tokens"]], [("write", ["one-org/shop"])])
        self.assertEqual(sorted(r for e in got["errors"] for r in e["repos"]),
                         ["founderizer/founderizer-apps", "one-org/ops", "one-org/other"])
        asked = json.loads(next(d for m, u, d in self.github if u.endswith("/access_tokens")))
        self.assertEqual(asked, {"repositories": ["shop"], "permissions": door.GITHUB_ACCESS["write"]})

    def test_a_token_inside_the_business_pool_at_no_more_than_its_level(self):
        """The manager hands out what the pool holds, and the hub names the grant: the door makes a token for it inside
        the asking agent's business pool, at no more than the pool's level, and for no other business's agent."""
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {
            "one-org/tools": "deploy", "one-org/cluster": "deploy"}}, self.secrets["token"])
        self.assertEqual(status, 200, got)
        self.assertEqual([(t["access"], t["repos"]) for t in got["tokens"]], [("deploy", ["one-org/tools"])])
        self.assertEqual([e["repos"] for e in got["errors"]], [["one-org/cluster"]])
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {"one-org/cluster": "write"}},
                                self.secrets["token"])
        self.assertEqual([(t["access"], t["repos"]) for t in got["tokens"]], [("write", ["one-org/cluster"])])
        status, got = self.post("/github/token", {"agent": "ops-two", "repos": {"one-org/tools": "read"}},
                                self.secrets["token"])
        self.assertEqual((got["tokens"], [e["repos"] for e in got["errors"]]), ([], [["one-org/tools"]]))

    def test_a_read_or_write_token_reads_the_actions_runs_only_where_the_installation_holds_actions(self):
        """10 November 2026: a write token got 404 on the GitHub Actions runs of its repository, so no agent below
        deploy could show that CI passed. A read or write token asks for actions: read where the installation holds
        Actions, at read or at write. Where it does not (an older App), the token asks for exactly what it asked
        before, because GitHub refuses the whole token (422) when it asks for more than the installation holds. A
        deploy token stays as it was."""
        stubbed, held = self.door.http, {}

        def http(method, url, headers, body):
            if url.endswith("/installation"):
                return 200, {"id": 77, "permissions": dict(held)}
            return stubbed(method, url, headers, body)
        self.door.http = http

        def asked(repos):
            del self.github[:]
            status, got = self.post("/github/token", {"agent": "ops-one", "repos": repos}, self.secrets["token"])
            self.assertEqual(status, 200, got)
            self.assertEqual(sorted(t["access"] for t in got["tokens"]), sorted(repos.values()), got)
            return {json.loads(d)["repositories"][0]: json.loads(d)["permissions"]
                    for m, u, d in self.github if u.endswith("/access_tokens")}

        three = {"one-org/ops": "read", "one-org/shop": "write", "one-org/tools": "deploy"}
        before = {"contents": "write", "metadata": "read", "pull_requests": "write"}
        held.update(before, actions="write", workflows="write")
        self.assertEqual(asked(three), {"ops": dict(door.GITHUB_ACCESS["read"], actions="read"),
                                        "shop": dict(door.GITHUB_ACCESS["write"], actions="read"),
                                        "tools": door.GITHUB_ACCESS["deploy"]})
        held.clear()
        held.update(before, actions="read")
        self.assertEqual(asked({"one-org/shop": "write"}),
                         {"shop": dict(door.GITHUB_ACCESS["write"], actions="read")})
        held.clear()
        held.update(before)                 # an App without Actions: the tokens of before, to the letter
        self.assertEqual(asked({"one-org/ops": "read", "one-org/shop": "write"}),
                         {"ops": door.GITHUB_ACCESS["read"], "shop": door.GITHUB_ACCESS["write"]})
        self.assertNotIn("actions", door.GITHUB_ACCESS["read"])
        self.assertNotIn("actions", door.GITHUB_ACCESS["write"])

    def test_a_token_reads_the_issues_and_from_write_comments_on_them_only_where_the_installation_holds_issues(self):
        """12 November 2026: a write token got 403 on a comment in an issue, so an agent could not talk to the
        developer that its team's policy lets it talk to in GitHub issues. Where the installation holds Issues, a read
        token asks for issues: read, and a write or deploy token for issues: write, or for read where the installation
        holds Issues only at read. Where it does not hold Issues, the token asks for exactly what it asked before,
        because GitHub refuses the whole token (422) when it asks for more than the installation holds."""
        stubbed, held = self.door.http, {}

        def http(method, url, headers, body):
            if url.endswith("/installation"):
                return 200, {"id": 77, "permissions": dict(held)}
            return stubbed(method, url, headers, body)
        self.door.http = http

        def asked(repos):
            del self.github[:]
            status, got = self.post("/github/token", {"agent": "ops-one", "repos": repos}, self.secrets["token"])
            self.assertEqual(status, 200, got)
            self.assertEqual(sorted(t["access"] for t in got["tokens"]), sorted(repos.values()), got)
            return {json.loads(d)["repositories"][0]: json.loads(d)["permissions"]
                    for m, u, d in self.github if u.endswith("/access_tokens")}

        three = {"one-org/ops": "read", "one-org/shop": "write", "one-org/tools": "deploy"}
        before = {"contents": "write", "metadata": "read", "pull_requests": "write"}
        held.update(before, actions="write", workflows="write", issues="write")
        self.assertEqual(asked(three), {"ops": dict(door.GITHUB_ACCESS["read"], actions="read", issues="read"),
                                        "shop": dict(door.GITHUB_ACCESS["write"], actions="read", issues="write"),
                                        "tools": dict(door.GITHUB_ACCESS["deploy"], issues="write")})
        held.clear()
        held.update(before, issues="read")      # Issues only at read: no token asks for more than that
        self.assertEqual(asked(three), {"ops": dict(door.GITHUB_ACCESS["read"], issues="read"),
                                        "shop": dict(door.GITHUB_ACCESS["write"], issues="read"),
                                        "tools": dict(door.GITHUB_ACCESS["deploy"], issues="read")})
        for issues in ({}, {"issues": "none"}, {"issues": None}, {"issues": ["write"]}):
            with self.subTest(issues=issues):   # an App without Issues: the tokens of before, to the letter
                held.clear()
                held.update(before, **issues)
                self.assertEqual(asked(three), {"ops": door.GITHUB_ACCESS["read"], "shop": door.GITHUB_ACCESS["write"],
                                                "tools": door.GITHUB_ACCESS["deploy"]})
        self.assertEqual(door.token_permissions("write", ["issues"]), door.GITHUB_ACCESS["write"])
        self.assertIsNot(door.token_permissions("read", {"issues": "read"}), door.GITHUB_ACCESS["read"])
        self.assertNotIn("issues", json.dumps(door.GITHUB_ACCESS))      # the table itself never changes

    def test_the_highest_level_comes_first_because_the_first_token_is_gh_token(self):
        """The session's GH_TOKEN is the first token that the hub gives (fleet.integration_env), and the hub's own path
        sends the highest level first, so that gh and the GitHub tool get the token that does the most. 10 November
        2026: the door sent its tokens in the order of the level's name, so an agent with read and write had a GH_TOKEN
        for its read repositories only, and gh answered 404 for each repository that it holds at write."""
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-one"]["github"]["two-org/site"] = "read"
        self.write_access(data)
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {
            "one-org/ops": "read", "two-org/site": "read", "one-org/shop": "write", "one-org/tools": "deploy"}},
            self.secrets["token"])
        self.assertEqual(status, 200, got)
        self.assertEqual([(t["access"], t["repos"]) for t in got["tokens"]],
                         [("deploy", ["one-org/tools"]), ("write", ["one-org/shop"]), ("read", ["one-org/ops"]),
                          ("read", ["two-org/site"])])

    def test_what_the_app_reaches_is_read_for_the_hub_with_its_token_secret(self):
        """DevOps plan 13, item 4: once the hub holds no App key, the door reads what its App reaches, for the marks
        of the app's "What the App reaches". The pages are built from the account and the installation id."""
        stubbed = self.door.http

        def http(method, url, headers, data):
            if url == "https://api.github.com/app":
                return 200, {"slug": "fleet-app", "owner": {"login": "One-Org"}}
            if url.startswith("https://api.github.com/app/installations?"):
                return 200, [{"id": 77, "account": {"login": "One-Org", "type": "Organization"},
                              "repository_selection": "selected", "html_url": "https://evil.example/"},
                             {"id": 78, "account": {"login": "solo", "type": "User"}, "repository_selection": "all"},
                             {"id": 79, "account": {"login": "held", "type": "User"}, "suspended_at": "2026-11-01"},
                             {"id": "x", "account": {"login": "bad"}}]
            if url.startswith("https://api.github.com/installation/repositories"):
                self.github.append((method, url, headers.get("Authorization")))
                return 200, {"repositories": [{"full_name": "One-Org/Shop"}, {"full_name": "One-Org/Ops"}]}
            return stubbed(method, url, headers, data)
        self.door.http = http
        status, got = self.get("/github/reach", self.secrets["token"])
        self.assertEqual(status, 200, got)
        self.assertEqual(got, {"pages": {"one-org": "https://github.com/organizations/One-Org/settings/installations/77",
                                         "solo": "https://github.com/settings/installations/78",
                                         "held": "https://github.com/settings/installations/79"},
                               "all": ["solo"], "repos": ["one-org/ops", "one-org/shop"],
                               "install": "https://github.com/apps/fleet-app/installations/new",
                               "owners": ["one-org"]})
        self.assertIn(("GET", "https://api.github.com/installation/repositories?per_page=100&page=1",
                       "Bearer ghs_" + "x" * 36), self.github)
        self.assertEqual(self.get("/github/reach", self.secrets["record"])[0], 403)
        self.assertEqual(self.get("/github/reach", self.secrets["token"], source=ONE)[0], 403)

    def test_every_repository_that_the_apps_reach_is_listed_for_the_hub(self):
        """9 November 2026, the app's list that gives an agent its repositories: unlike /github/reach it lists an
        installation that has all its account's repositories too, and it leaves out archived repositories, suspended
        installations and names of another account. A page that GitHub does not give is an error, not a short list."""
        stubbed = self.door.http

        def http(method, url, headers, data):
            if url.startswith("https://api.github.com/app/installations?"):
                return 200, [{"id": 77, "account": {"login": "One-Org", "type": "Organization"},
                              "repository_selection": "all"},
                             {"id": 79, "account": {"login": "held", "type": "User"}, "suspended_at": "2026-11-01"},
                             {"id": "x", "account": {"login": "bad"}}]
            if url.startswith("https://api.github.com/installation/repositories"):
                return 200, {"repositories": [{"full_name": "One-Org/Shop"}, {"full_name": "One-Org/Old", "archived": True},
                                              {"full_name": "Other/Stray"}, "junk"]}
            return stubbed(method, url, headers, data)
        self.door.http = http
        status, got = self.get("/github/repos", self.secrets["token"])
        self.assertEqual((status, got), (200, {"accounts": {"one-org": {"name": "One-Org", "repos": ["one-org/shop"]}}}))
        self.assertEqual(self.get("/github/repos", self.secrets["record"])[0], 403)
        self.assertEqual(self.get("/github/repos", self.secrets["token"], source=ONE)[0], 403)

        def failing(method, url, headers, data):
            if url.startswith("https://api.github.com/installation/repositories"):
                return 502, {"message": "Bad gateway"}
            return http(method, url, headers, data)
        self.door.http = failing
        status, got = self.get("/github/repos", self.secrets["token"])
        self.assertEqual((status, got), (502, {"error": "GitHub gave no list of One-Org's repositories (502)"}))

    def test_an_app_key_s_fingerprint_and_whether_github_takes_it_are_read_for_the_hub(self):
        """Plan 13, item 4 (the coordinator's yes of 7 November 2026): for the renewal of the App key that the hub
        held, the door says which keys its file names for the App, and of one held key its fingerprint as GitHub's
        page shows it (SHA-256 of the public key, in base64), whether GitHub still takes it, and the App's page."""
        key = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
        path = os.path.join(self.root + door.SECRETS_DIR, hashlib.sha256(ref(6).encode()).hexdigest())
        with open(path, "wb") as f:
            f.write(key)
        der = subprocess.run(["openssl", "rsa", "-pubout", "-outform", "DER"], input=key, capture_output=True,
                             check=True).stdout          # GitHub's own command for the fingerprint
        printed = "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
        answers = {"status": 200}
        stubbed = self.door.http

        def http(method, url, headers, data):
            if url == "https://api.github.com/app":
                return answers["status"], {"slug": "fleet-app", "owner": {"login": "One-Org", "type": "Organization"}}
            return stubbed(method, url, headers, data)
        self.door.http = http
        status, got = self.post("/github/key", {"app_id": "12345"}, self.secrets["token"])
        self.assertEqual(status, 200, got)
        self.assertEqual(got, {"used": [ref(6)], "ref": ref(6), "fingerprint": printed, "signs": True,
                               "owner": "One-Org", "page": "https://github.com/organizations/One-Org/settings/apps/"
                                                           "fleet-app"})
        self.assertRegex(printed, r"^SHA256:[A-Za-z0-9+/]{43}=$")
        answers["status"] = 401             # the owner deleted the key on GitHub
        self.assertEqual(self.post("/github/key", {"app_id": "12345", "ref": ref(6)}, self.secrets["token"])[1],
                         {"used": [ref(6)], "ref": ref(6), "fingerprint": printed, "signs": False})
        self.assertEqual(self.post("/github/key", {"app_id": "999"}, self.secrets["token"])[0], 403)
        self.assertEqual(self.post("/github/key", {"app_id": "12345", "ref": ref(30)}, self.secrets["token"])[0], 403)
        self.assertEqual(self.post("/github/key", {"app_id": "12345"}, self.secrets["record"])[0], 403)
        self.assertEqual(self.post("/github/key", {"app_id": "12345"}, self.secrets["token"], source=ONE)[0], 403)

    def test_a_repository_that_github_no_longer_lists_does_not_stop_the_other_tokens(self):
        """New-projects plan N1: for an installation with selected repositories, the door drops each repository that
        the installation does not list before it asks for a token, and reads that list once a minute at most."""
        door.Door.SELECTED.clear()
        self.addCleanup(door.Door.SELECTED.clear)
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-one"]["github"] = {"one-org/gone": "read", "one-org/ops": "read", "one-org/shop": "read"}
        self.write_access(data)
        stubbed, lists = self.door.http, []

        def http(method, url, headers, body):
            if url.endswith("/repos/one-org/gone/installation"):
                return 404, {"message": "Not Found"}
            if url.endswith("/repos/one-org/ops/installation"):
                return 200, {"id": 77, "repository_selection": "selected", "account": {"login": "one-org"}}
            if "/installation/repositories" in url:
                lists.append(url)
                return 200, {"repositories": [{"full_name": "One-Org/ops"}, {"full_name": "one-org/shop"}]}
            return stubbed(method, url, headers, body)
        self.door.http = http
        for _ in range(2):
            status, got = self.post("/github/token", {"agent": "ops-one", "repos": {
                "one-org/gone": "read", "one-org/ops": "read", "one-org/shop": "read"}}, self.secrets["token"])
            self.assertEqual(status, 200, got)
            self.assertEqual([t["repos"] for t in got["tokens"]], [["one-org/ops", "one-org/shop"]])
            self.assertEqual([e["repos"] for e in got["errors"]], [["one-org/gone"]])
        asked = [json.loads(d) for m, u, d in self.github if u.endswith("/installations/77/access_tokens") and d]
        self.assertEqual(asked[-1]["repositories"], ["ops", "shop"])
        self.assertEqual(len(lists), 1)                     # the list is read once a minute at most

    def test_a_repository_that_the_door_made_gets_no_deploy_token_and_no_write_token_for_an_operator(self):
        """New-projects plan N3: the developer holds write on a repository that the door made, the Operator commits
        its workflow files through the door, and nobody gets a deploy token there."""
        door.write_json(door.REPOS_FILE, {"pending": {}, "made": {"one-org/shop": {"id": 5, "agent": "ops-one"}}})
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["dev"] = {"github": {"one-org/shop": "write"}}
        data["pools"]["one"]["one-org/shop"] = "deploy"
        self.write_access(data)
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {"one-org/shop": "write"}},
                                self.secrets["token"])
        self.assertEqual((got["tokens"], [e["repos"] for e in got["errors"]]), ([], [["one-org/shop"]]))
        self.assertIn("the door made this repository", got["errors"][0]["error"])
        status, got = self.post("/github/token", {"agent": "dev", "repos": {"one-org/shop": "write"}},
                                self.secrets["token"])
        self.assertEqual([t["repos"] for t in got["tokens"]], [["one-org/shop"]])
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {"one-org/shop": "deploy"}},
                                self.secrets["token"])
        self.assertEqual(got["tokens"], [])

    def test_repo_new_through_the_door_names_what_it_made_in_its_record_line(self):
        stubbed, gets = self.door.http, iter([(404, {}), (200, {"id": 501}), (200, {"id": 502})])
        install = {"id": 77, "app_slug": "door-app", "account": {"login": "one-org", "type": "User"},
                   "permissions": {"administration": "write", "repository_creation": "write", "metadata": "read"}}

        def http(method, url, headers, body):
            if url.endswith("/repos/one-org/ops/installation"):
                return 200, install
            if method == "GET" and url.endswith("/repos/one-org/newapp"):
                return next(gets)
            if url.endswith("/user/repos"):
                return 201, {"id": 501, "full_name": "one-org/newapp"}
            return stubbed(method, url, headers, body)
        self.door.http = http
        got = self.door.call(ONE, "github:one-org", "repo-new", ["newapp"])
        self.assertTrue(got["ok"], got)
        self.assertEqual(self.door.record.after(0)[-1]["made"], "one-org/newapp")
        self.assertEqual(self.door.repo_record("made", "one-org/newapp")["id"], 501)
        again = self.door.call(ONE, "github:one-org", "repo-new", ["newapp"])
        self.assertFalse(again["ok"])                       # that name is another repository now, not the door's
        self.assertNotIn("made", self.door.record.after(0)[-1])

    def test_a_repo_new_whose_reach_check_failed_finishes_when_it_is_asked_again(self):
        """GitHub made the repository and the App's installation did not reach it yet. The door's record shows that
        it made that repository for this agent, so the same call again runs the reach check again, and its record
        line names the repository for the hub."""
        stubbed, gets = self.door.http, iter([(404, {}), (404, {}), (200, {"id": 501}), (200, {"id": 501})])
        install = {"id": 77, "app_slug": "door-app", "account": {"login": "one-org", "type": "User"},
                   "permissions": {"administration": "write", "repository_creation": "write", "metadata": "read"}}

        def http(method, url, headers, body):
            if url.endswith("/repos/one-org/ops/installation"):
                return 200, install
            if method == "GET" and url.endswith("/repos/one-org/newapp"):
                return next(gets)
            if url.endswith("/user/repos"):
                return 201, {"id": 501, "full_name": "one-org/newapp"}
            return stubbed(method, url, headers, body)
        self.door.http = http
        got = self.door.call(ONE, "github:one-org", "repo-new", ["newapp"])
        self.assertFalse(got["ok"], got)
        self.assertIn("does not reach it", got["why"])
        self.assertNotIn("made", self.door.record.after(0)[-1])
        again = self.door.call(ONE, "github:one-org", "repo-new", ["newapp"])
        self.assertTrue(again["ok"], again)
        self.assertIn("the App reaches it", again["out"])
        self.assertEqual(self.door.record.after(0)[-1]["made"], "one-org/newapp")

    def test_an_account_installed_after_the_move_gets_its_token_from_the_one_app(self):
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["ops-one"]["github"]["two-org/site"] = "read"
        self.write_access(data)
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {"two-org/site": "read"}},
                                self.secrets["token"])
        self.assertEqual([(t["access"], t["repos"]) for t in got["tokens"]], [("read", ["two-org/site"])], got)
        self.assertIn("https://api.github.com/repos/two-org/site/installation", [u for _, u, _ in self.github])
        data["credentials"]["github:third"] = {"secret": ref(11), "app_id": "999"}
        self.write_access(data)
        status, got = self.post("/github/token", {"agent": "ops-one", "repos": {"two-org/site": "read"}},
                                self.secrets["token"])
        self.assertEqual((got["tokens"], [e["repos"] for e in got["errors"]]), ([], [["two-org/site"]]))

    def test_each_right_needs_its_own_secret_and_the_hub_s_address(self):
        body = {"agent": "ops-one", "repos": {"one-org/shop": "read"}}
        self.assertEqual(self.post("/github/token", body, self.secrets["record"])[0], 403)
        self.assertEqual(self.post("/github/token", body, self.secrets["token"], source=ONE)[0], 403)
        self.assertEqual(self.get("/record?after=0", self.secrets["token"])[0], 403)
        self.door.call(ONE, "web-1", "uptime", [])
        status, got = self.get("/record?after=0", self.secrets["record"])
        self.assertEqual((status, [e["action"] for e in got["entries"]]), (200, ["uptime"]))
        self.assertEqual(self.get("/record?after=1", self.secrets["record"])[1]["entries"], [])


def github_stubs(self):
    "GitHub as a test of the door reads it: the answers of its API by method and address, and the calls that came."
    door.GitHub.TOKENS.clear()
    door.GitHub.BRANCHES.clear()
    checks = patch.object(door, "CHECKS_FIND", 0)        # the runs of a commit's push are all there at once
    checks.start()
    self.addCleanup(checks.stop)
    patcher = patch.object(door_providers, "app_jwt", lambda app_id, pem, sign=None: "jwt")
    patcher.start()
    self.addCleanup(patcher.stop)
    self.calls, self.answers = [], {}
    api = "https://api.github.com"
    deployment = base64.b64encode(OLD_DEPLOYMENT.encode()).decode()
    self.answers.update({
        ("GET", f"{api}/repos/one-org/cluster/installation"): (200, {"id": 9}),
        ("GET", f"{api}/repos/one-org/shop/installation"): (200, {"id": 9}),
        ("POST", f"{api}/app/installations/9/access_tokens"): (201, {"token": "ghs_door"}),
        ("GET", f"{api}/repos/one-org/cluster"): (200, {"default_branch": "master"}),
        ("GET", f"{api}/repos/one-org/cluster/contents/apps/shop/deployment.yaml?ref=master"):
            (200, {"encoding": "base64", "content": deployment}),
        ("GET", f"{api}/repos/one-org/cluster/git/ref/heads/master"): (200, {"object": {"sha": "h1"}}),
        ("GET", f"{api}/repos/one-org/cluster/git/commits/h1"): (200, {"tree": {"sha": "t1"}}),
        ("POST", f"{api}/repos/one-org/cluster/git/blobs"): (201, {"sha": "b1"}),
        ("POST", f"{api}/repos/one-org/cluster/git/trees"): (201, {"sha": "t2"}),
        ("POST", f"{api}/repos/one-org/cluster/git/commits"): (201, {"sha": "c2"}),
        ("PATCH", f"{api}/repos/one-org/cluster/git/refs/heads/master"): (200, {}),
        ("POST", f"{api}/repos/one-org/cluster/actions/workflows/sync-app.yml/dispatches"):
            (200, {"workflow_run_id": 4242, "run_url": f"{api}/repos/one-org/cluster/actions/runs/4242",
                   "html_url": "https://github.com/one-org/cluster/actions/runs/4242"}),
        ("GET", f"{api}/repos/one-org/cluster/actions/runs/4242"):
            (200, {"status": "completed", "conclusion": "success",
                   "html_url": "https://github.com/one-org/cluster/actions/runs/4242"}),
        ("GET", f"{api}/repos/one-org/cluster/actions/runs?head_sha=c2&event=push&per_page=50"):
            (200, {"workflow_runs": [{"id": 5150, "name": "Validate manifests", "head_sha": "c2", "status": "completed",
                                      "conclusion": "success"}]}),
        ("GET", f"{api}/repos/one-org/shop/actions/runs?branch=v2.0.1&status=success&per_page=20"):
            (200, {"workflow_runs": [{"head_branch": "v2.0.1"}]}),
        ("GET", f"{api}/repos/one-org/web/actions/runs?status=success&per_page=100"):
            (200, {"workflow_runs": [{"head_sha": "3333333abcdef"}]}),
    })

    def http(method, url, headers, data):
        self.calls.append((method, url, None if data is None else json.loads(data)))
        return self.answers.get((method, url), (404, {"message": "not stubbed"}))
    self.door.http = http


class SyncRuns(DoorCase):
    """A GitOps sync's call waits for its run and answers with how it ended (finding (c) of 12 November 2026): the door
    wrote done when GitHub took the dispatch, also for a sync that then failed."""
    API = "https://api.github.com"
    RUN = f"{API}/repos/one-org/cluster/actions/runs/4242"
    RUNS = (f"{API}/repos/one-org/cluster/actions/workflows/sync-app.yml/runs?"
            "event=workflow_dispatch&branch=master&per_page=20")

    def setUp(self):
        super().setUp()
        github_stubs(self)
        for name, value in (("RUN_POLL", 0), ("RUN_FIND", 60)):
            patcher = patch.object(door, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.runs = []          # the answers that the run gives, one for each read, the last one again

    def sync(self):
        stub = self.door.http

        def http(method, url, headers, data):
            if method == "GET" and url == self.RUN and self.runs:
                self.calls.append((method, url, None))
                return self.runs.pop(0) if len(self.runs) > 1 else self.runs[0]
            return stub(method, url, headers, data)
        self.door.http = http
        return self.call(ONE, "gitops:one-org/cluster", "sync", "shop")

    def test_a_failed_run_is_a_failed_call_in_the_record_and_for_the_agent(self):
        self.runs = [(200, {"status": "queued"}), (200, {"status": "in_progress"}),
                     (200, {"status": "completed", "conclusion": "failure", "html_url": "https://github.com/x/4242"})]
        self.answers[("GET", self.RUN + "/jobs?per_page=50")] = (200, {"jobs": [
            {"name": "Verify authorized actor and application name", "conclusion": "success", "steps": []},
            {"name": "Sync the application / sync-app", "conclusion": "failure", "steps": [
                {"name": "ArgoCD app sync", "conclusion": "success"},
                {"name": "Verify app status", "conclusion": "failure"}]}]})
        got = self.sync()
        why = ("sync-app.yml of one-org/cluster: run 4242 ended failure, in Sync the application / sync-app / Verify "
               "app status (https://github.com/x/4242)")
        self.assertEqual((got["ok"], got["kind"], got["why"]), (False, "rule", why))
        last = self.door.record.after(0)[-1]
        self.assertEqual((last["action"], last["outcome"]), ("sync", "failed"))
        self.assertTrue(last["why"].startswith(why[:120]), last["why"])      # the record says how the run ended
        self.assertEqual(len([u for m, u, d in self.calls if u == self.RUN]), 3)

    def test_a_dispatch_whose_answer_names_no_run_finds_its_one_run_and_never_guesses_between_two(self):
        self.answers[("POST", f"{self.API}/repos/one-org/cluster/actions/workflows/sync-app.yml/dispatches")] = \
            (204, {})
        at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(door.now() + 1))
        old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(door.now() - 600))
        self.answers[("GET", self.RUNS)] = (200, {"workflow_runs": [{"id": 4242, "created_at": at},
                                                                   {"id": 4100, "created_at": old}]})
        self.runs = [(200, {"status": "completed", "conclusion": "success"})]
        got = self.sync()
        self.assertEqual((got["ok"], got["out"]), (True, "sync-app.yml of one-org/cluster: run 4242 passed "
                                                         "(https://github.com/one-org/cluster/actions/runs/4242)"))
        self.answers[("GET", self.RUNS)] = (200, {"workflow_runs": [{"id": 4242, "created_at": at},
                                                                   {"id": 4243, "created_at": at}]})
        got = self.sync()
        self.assertEqual(got["ok"], False)
        self.assertIn("2 runs began since, so the door cannot say which one is this call's", got["why"])

    def test_a_run_that_does_not_end_in_time_fails_the_call_and_says_so(self):
        self.runs = [(200, {"status": "in_progress"})]
        clock = [door.now()]

        def later():
            clock[0] += door.RUN_WAIT / 3
            return clock[0]
        with patch.object(door, "now", later):
            got = self.sync()
        self.assertEqual(got["ok"], False)
        self.assertIn("run 4242 did not end within 50 minutes, so the door cannot say that it passed", got["why"])

    def test_an_api_that_does_not_know_return_run_details_takes_the_plain_dispatch(self):
        url = f"{self.API}/repos/one-org/cluster/actions/workflows/sync-app.yml/dispatches"
        answers = [(422, {"message": "Invalid request. \"return_run_details\" is not a permitted key."}), (204, {})]
        stub = self.door.http

        def http(method, u, headers, data):
            if method == "POST" and u == url:
                self.calls.append((method, u, json.loads(data)))
                return answers.pop(0)
            return stub(method, u, headers, data)
        self.door.http = http
        at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(door.now() + 1))
        self.answers[("GET", self.RUNS)] = (200, {"workflow_runs": [{"id": 4242, "created_at": at}]})
        got = self.call(ONE, "gitops:one-org/cluster", "sync", "shop")
        self.assertTrue(got["ok"], got)
        sent = [d for m, u, d in self.calls if u == url]
        self.assertEqual(sent, [{"ref": "master", "inputs": {"app": "shop"}, "return_run_details": True},
                                {"ref": "master", "inputs": {"app": "shop"}}])


class CommitChecks(DoorCase):
    """A GitOps commit through the door waits for the runs that its push starts, and the agent and the record learn
    how they ended (11 November 2026: a door commit left the repository's checks red for about 31 hours)."""
    API = "https://api.github.com"
    CHECKS = f"{API}/repos/one-org/cluster/actions/runs?head_sha=c2&event=push&per_page=50"

    def setUp(self):
        super().setUp()
        github_stubs(self)
        for name, value in (("RUN_POLL", 0), ("CHECKS_FIND", 30)):
            patcher = patch.object(door, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.reads = []         # the answers that the runs of the commit give, one for each read, the last one again
        stub = self.door.http

        def http(method, url, headers, data):
            if method == "GET" and url == self.CHECKS and self.reads:
                self.calls.append((method, url, None))
                return self.reads.pop(0) if len(self.reads) > 1 else self.reads[0]
            return stub(method, url, headers, data)
        self.door.http = http
        self.clock = [door.now()]
        patcher = patch.object(door, "now", lambda: self.clock[0])
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(door.time, "sleep", lambda s: self.clock.__setitem__(0, self.clock[0] + 10))
        patcher.start()
        self.addCleanup(patcher.stop)

    def push(self):
        return self.call(ONE, "gitops:one-org/cluster", "push", content=change(
            ("apps/shop/deployment.yaml", OLD_DEPLOYMENT.replace("replicas: 2", "replicas: 3"))))

    @staticmethod
    def runs(*runs):
        return (200, {"workflow_runs": [dict(r, head_sha="c2") for r in runs]})

    def test_a_check_that_fails_is_a_failed_call_that_says_that_the_commit_is_made(self):
        self.reads = [self.runs({"id": 1, "name": "guardrails", "status": "in_progress"}),
                      self.runs({"id": 1, "name": "guardrails", "status": "completed", "conclusion": "failure",
                                 "html_url": "https://github.com/x/1"},
                                {"id": 2, "name": "manifests", "status": "completed", "conclusion": "success"})]
        self.answers[("GET", f"{self.API}/repos/one-org/cluster/actions/runs/1/jobs?per_page=50")] = (200, {"jobs": [
            {"name": "guardrails", "conclusion": "failure", "steps": [
                {"name": "Check exposure policy", "conclusion": "failure"}]}]})
        got = self.push()
        why = ("one-org/cluster master is at c2, and its check guardrails ended failure, in guardrails / Check exposure "
               "policy (https://github.com/x/1): fix the commit or revert it")
        self.assertEqual((got["ok"], got["kind"], got["why"]), (False, "rule", why))
        last = self.door.record.after(0)[-1]
        self.assertEqual((last["action"], last["outcome"]), ("push", "failed"))
        self.assertTrue(last["why"].startswith("one-org/cluster master is at c2, and its check guardrails"), last)

    def test_a_check_that_failed_before_the_commit_too_is_not_its_doing(self):
        """12 November 2026: a check that a commit of the day before had left red made each later door commit a failed
        call that said "revert it". A failed run whose workflow failed on its run before too leaves the call done."""
        bad = {"id": 1, "name": "images", "status": "completed", "conclusion": "failure", "workflow_id": 77,
               "run_number": 12, "html_url": "https://github.com/x/1"}
        self.reads = [self.runs(bad, {"id": 2, "name": "manifests", "status": "completed", "conclusion": "success"})]
        self.answers[("GET", f"{self.API}/repos/one-org/cluster/actions/runs/1/jobs?per_page=50")] = (200, {"jobs": [
            {"name": "images", "conclusion": "failure", "steps": [{"name": "Report", "conclusion": "failure"}]}]})
        history = (f"{self.API}/repos/one-org/cluster/actions/workflows/77/runs?branch=master&event=push"
                   f"&status=completed&per_page=20")
        self.answers[("GET", history)] = (200, {"workflow_runs": [
            {"run_number": 12, "conclusion": "failure"}, {"run_number": 11, "conclusion": "cancelled"},
            {"run_number": 10, "conclusion": "failure"}, {"run_number": 9, "conclusion": "success"}]})
        got = self.push()
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)
        self.assertEqual(got["out"], "one-org/cluster master is at c2; its checks passed, except 1 that failed on the run "
                                     "before this commit too, so not by this commit: images ended failure, in images / "
                                     "Report (https://github.com/x/1)")
        self.assertEqual(self.door.record.after(0)[-1]["outcome"], "done")
        # the run before it that ended passed: this commit made the check fail
        self.answers[("GET", history)] = (200, {"workflow_runs": [
            {"run_number": 11, "conclusion": "cancelled"}, {"run_number": 10, "conclusion": "success"}]})
        got = self.push()
        self.assertEqual((got["ok"], got["kind"]), (False, "rule"), got)
        self.assertIn("its check images ended failure, in images / Report", got["why"])
        # no run before it that GitHub gives, or a run with no workflow: the commit's failure, as before
        del self.answers[("GET", history)]
        self.assertFalse(self.push()["ok"])

    def test_a_late_run_is_waited_for_and_no_run_at_all_is_said(self):
        self.reads = [self.runs(), self.runs({"id": 3, "name": "manifests", "status": "queued"}),
                      self.runs({"id": 3, "name": "manifests", "status": "completed", "conclusion": "success"})]
        got = self.push()
        self.assertEqual((got["ok"], got["out"]), (True, "one-org/cluster master is at c2; its checks passed: manifests"))
        self.reads = [self.runs()]
        got = self.push()
        self.assertEqual((got["ok"], got["out"]), (True, "one-org/cluster master is at c2; no check ran for it"))

    def test_a_check_that_does_not_end_in_time_is_said_and_is_no_failure(self):
        self.reads = [self.runs({"id": 4, "name": "slow", "status": "in_progress"})]
        got = self.push()
        self.assertEqual((got["ok"], got["out"]), (True, "one-org/cluster master is at c2; 1 of its checks had not "
                                                         "ended after 20 minutes: slow"))


OLD_CONFIG = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: old-config\n  namespace: shop\n  labels:\n"
              "    name: not-this-one\ndata:\n  conf: |\n    kind: NotAnObject\n    name: nor-this\n---\n"
              "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: old-policy\n"
              "  namespace: \"shop\"  # quoted\nspec: {}\n")


def listing_line(prune, lb=(), app="shop"):
    "A listing run's log line, as the caller workflow prints it."
    body = json.dumps({"app": app, "prune": list(prune), "lb": list(lb)})
    return "2026-11-12T17:00:00.0000000Z DOOR-PRUNE-LIST " + base64.b64encode(body.encode()).decode() + "\n"


class PruneParts(unittest.TestCase):
    """The pure parts of the door's prune (DevOps plan X3): the objects of a file and of a commit, the listing line,
    and the decision, with the owner's answer of 12 November 2026."""

    def test_the_objects_of_a_block_style_file_and_what_cannot_be_read(self):
        self.assertEqual(door_targets.object_keys("a/old.yaml", OLD_CONFIG.encode()),
                         {":ConfigMap:shop/old-config", "networking.k8s.io:NetworkPolicy:shop/old-policy"})
        self.assertEqual(door_targets.object_keys("a/ns.yaml", b"apiVersion: v1\nkind: Namespace\nmetadata:\n"
                                                                b"  name: shop\n"), {":Namespace:/shop"})
        self.assertEqual(door_targets.object_keys("a/readme.md", b"kind: Deployment"), set())
        self.assertEqual(door_targets.object_keys("a/gone.yaml", None), set())
        for bad in (b'{"kind": "ConfigMap", "metadata": {"name": "x"}}', b"kind: ConfigMap\nmetadata:\n  name: x\n",
                    b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n",
                    b"apiVersion: v1\nkind: List\nitems: []\nmetadata:\n  name: l\n"):
            with self.subTest(bad=bad):
                self.assertIsNone(door_targets.object_keys("a/bad.yaml", bad))
        self.assertEqual(door_targets.object_keys("a/one.json", json.dumps(
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "shop"}}).encode()),
            {"apps:Deployment:shop/web"})

    def test_what_a_commit_removes_and_adds_from_files_and_from_the_render(self):
        heads = {"a/old.yaml": OLD_CONFIG.encode(), "a/flow.yaml": b'{"kind": "ConfigMap"}'}
        files = [("a/old.yaml", OLD_CONFIG.split("---")[0].encode(), "100644"),     # the policy goes
                 ("a/flow.yaml", None, "100644"),                                   # unreadable at HEAD: nothing
                 ("a/new.yaml", b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: n\n  namespace: shop\n",
                  "100644")]
        got = door_targets.commit_objects(files, None, {"base_file": heads.get})
        self.assertEqual(got, {"removed": ["networking.k8s.io:NetworkPolicy:shop/old-policy"],
                               "added": [":ConfigMap:shop/n"]})
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c", "namespace": "shop"}}
        report = {"files": {"chart/values.yaml": {"units": ["helm:chart"], "head": None}},
                  "units": {"helm:chart": {"ok": True, "closed": False, "changed": [
                      {"object": "an object", "set": "its own values", "before": [cm], "after": []}]},
                      "helm:shut": {"ok": True, "closed": True, "changed": [
                          {"object": "an object", "set": "x", "before": [dict(cm, kind="Secret")], "after": []}]}}}
        got = door_targets.commit_objects([("chart/values.yaml", b"x: 1\n", "100644")], report, {})
        self.assertEqual(got, {"removed": [":ConfigMap:shop/c"], "added": []})

    def test_a_listing_line_is_only_a_list_to_check(self):
        good = door_targets.listing(listing_line([":Service:shop/front", ":ConfigMap:shop/a"], [":Service:shop/front",
                                                                                                 ":Service:x/y"]), "shop")
        self.assertEqual(good, {"prune": [":ConfigMap:shop/a", ":Service:shop/front"], "lb": [":Service:shop/front"]})
        for text, why in ((listing_line([":ConfigMap:shop/a"], app="web"), "not the listing of shop"),
                          (listing_line(["ConfigMap/a"]), "not GROUP:KIND:NAMESPACE/NAME"),
                          (listing_line([":ConfigMap:shop/a", ":ConfigMap:shop/a"]), "names one twice"),
                          (listing_line([]) * 2, "2 lines"), ("no line\n", "0 lines"),
                          ("DOOR-PRUNE-LIST bm90IGpzb24=\n", "not base64 JSON"), ("DOOR-PRUNE-LIST !!!\n", "0 lines")):
            with self.subTest(why=why):
                self.assertIn(why, door_targets.listing(text, "shop"))
        # GitHub's log shows the step's script too: a script line that names the mark is no listing line
        echoed = ('2026-11-12T19:21:50.3320684Z \x1b[36;1mecho "DOOR-PRUNE-LIST $(printf \'{"app":"%s"}\' "${APP}" | '
                  'base64 -w0)"\x1b[0m\n+ echo \'DOOR-PRUNE-LIST e30=\'\n')
        self.assertEqual(door_targets.listing(echoed + listing_line([":ConfigMap:shop/a"]) + echoed, "shop"),
                         {"prune": [":ConfigMap:shop/a"], "lb": []})

    def decide(self, keys, lb=(), removed=(), made=()):
        found = {"prune": sorted(keys), "lb": sorted(lb)}
        return door_targets.decide_prune({"prune_listing": found, "removed_object": lambda k: k in removed,
                                          "made_object": lambda k: k in made},
                                         "one-org/cluster", "gitops:one-org/cluster", "sync-app.yml", "shop")

    def test_the_decision_rule_own_or_the_owner_s_card(self):
        a, b = ":ConfigMap:shop/a", "apps:Deployment:shop/b"
        d = self.decide([a, b], removed=[a, b], made=[a, b])
        self.assertEqual((d.kind, d.plan["inputs"]["prune_owner_yes"]), ("rule", "false"))
        d = self.decide([a, b], removed=[a, b], made=[a])
        self.assertEqual(d.kind, "own")
        self.assertIn('the owner, 12 November 2026: "The agent (Recommended)"', d.why)
        self.assertEqual(d.plan["inputs"], {"app": "shop", "prune": "yes", "prune_objects": f"{a}\n{b}",
                                            "prune_owner_yes": "false"})
        self.assertEqual((d.plan["pruned"], d.hash_content, d.window), ([a, b], f"{a}\n{b}".encode(), "deploy"))
        for keys, lb, why in (([a, ":Secret:shop/s"], (), ":Secret:shop/s is a Secret"),
                              (["v1:Namespace:/shop"], (), "is a Namespace"),
                              ([":Node:/n1"], (), ":Node:/n1 has no namespace"),
                              ([a, ":Service:shop/front"], [":Service:shop/front"], "is a Service of type LoadBalancer"),
                              ([a, ":ConfigMap:shop/z"], (), "no commit through the door removed :ConfigMap:shop/z"),
                              ([f":ConfigMap:shop/c{n}" for n in range(21)], (), "21 objects, more than 20")):
            with self.subTest(why=why):
                removed = [k for k in keys if not k.endswith("/z")]
                d = self.decide(keys, lb, removed=removed)
                self.assertEqual((d.kind, d.plan["inputs"]["prune_owner_yes"]), ("full", "true"))
                self.assertIn(why, d.why)
                self.assertIn("The whole list goes to the owner", d.why)
        d = self.decide([])
        self.assertEqual((d.kind, d.plan["inputs"], "pruned" in d.plan), ("rule", {"app": "shop"}, False))
        d = door_targets.decide_prune({"prune_listing": "the listing run failed: no"}, "one-org/cluster",
                                      "gitops:one-org/cluster", "sync-app.yml", "shop")
        self.assertEqual((d.kind, d.route), ("refused", "again"))


class GitHubFacts(DoorCase):
    """What the door reads from GitHub for its checks: each repository's default branch (one has only `master`), and
    the runs of the repository that built an image, never those of the GitOps repository."""

    def setUp(self):
        super().setUp()
        github_stubs(self)

    def test_the_filter_of_a_read_keeps_back_a_secret_in_any_spelling_and_what_it_cannot_read(self):
        """No Secret object leaves the door. Before, the filter read `kind: Secret` only at the start of a line with
        nothing after it, so a quoted or a nested one, one with a comment, and one in JSON or flow style came back."""
        api = "https://api.github.com/repos/one-org/cluster/contents/"
        held = "which the filter keeps back"
        unsure = "may hold a Secret, which the filter keeps back"    # no block style: the loose reading of its text
        files = {"apps/shop/quoted.yaml": ('apiVersion: v1\nkind: "Secret"\ndata:\n  key: c2VjcmV0\n', held),
                 "apps/shop/comment.yaml": ("kind: Secret # the key\nstringData:\n  key: secret\n", held),
                 "apps/shop/list.yaml": ("kind: List\nitems:\n- apiVersion: v1\n  kind: Secret\n  data: {}\n", held),
                 "apps/shop/values.yaml": ("extraObjects:\n  - kind: secret\n    stringData:\n      k: v\n", held),
                 "apps/shop/flow.yaml": ("{kind: Secret, stringData: {key: secret}}\n", unsure),
                 "apps/shop/json.yaml": ('{"kind": "Secret", "data": {"key": "c2VjcmV0"}}\n', unsure),
                 "apps/shop/key.yaml": ('"kind": Secret\nstringData:\n  key: secret\n', unsure),
                 "apps/shop/alias.yaml": ("a: &kind Secret\nkind: *kind\nstringData:\n  key: secret\n", unsure),
                 "apps/shop/next.yaml": ("kind:\n  Secret\nstringData:\n  key: secret\n", unsure),
                 "apps/shop/secret.json": ('{"kind": "Secret", "data": {"key": "c2VjcmV0"}}', held),
                 "apps/shop/items.json": ('{"kind": "List", "items": [{"kind": "Secret"}]}', held),
                 "apps/shop/broken.json": ('{"kind": "Secret", ', unsure),
                 "apps/shop/tls.yaml": ("data:\n  tls.key: |\n    -----BEGIN PRIVATE KEY-----\n", held)}
        board = json.dumps({"title": "Board", "panels": [{"id": 1}]}, indent=2)
        files["apps/shop/board.json"] = (board, None)
        files["docs/notes.md"] = ("# Notes\n\n- {a: b}\n", None)
        for path, (text, _) in files.items():
            self.answers[("GET", f"{api}{path}?ref=master")] = (200, {
                "encoding": "base64", "content": base64.b64encode(text.encode()).decode()})
        for path, (text, why) in files.items():
            with self.subTest(path=path):
                got = self.call(ONE, "gitops:one-org/cluster", "read", path)
                if why is None:
                    self.assertEqual((got["ok"], got.get("out")), (True, text), got)
                else:
                    self.assertEqual((got["ok"], why in got.get("why", "")), (False, True), got)
                    self.assertNotIn("out", got)

    def test_a_read_gives_a_file_that_is_not_block_style_unless_it_may_hold_a_secret(self):
        """Block style is the rule of a commit, where the agent writes the text. In a read the repository's own
        people wrote it, and the door is the agent's only way to read it: a file in flow style, a template, one with
        a quoted key or a quoted text over lines comes back, unless a loose reading of its text says that it may hold
        a Secret. A commit of each of these files as a new file is refused as before."""
        api = "https://api.github.com/repos/one-org/cluster/contents/"
        may = "may hold a Secret, which the filter keeps back"
        policy = ("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nspec:\n  egress:\n  - to:\n"
                  "    - podSelector: {matchLabels: {app: db}}\n    ports: [{port: 80, protocol: TCP}]\n")
        files = {"apps/shop/policy.yaml": (policy, None),
                 "charts/shop/templates/deployment.yaml": (
                     "kind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\nspec:\n  template:\n    spec:\n"
                     "      containers:\n      - image: {{ .Values.image }}\n{{- if .Values.debug }}\n"
                     "        args: [--debug]\n{{- end }}\n", None),
                 "apps/shop/roles.yaml": ("kind: role\nspec:\n  allow:\n    node_labels:\n      '*': '*'\n"
                                          "    note: \"a text\n      over two lines\"\n", None),
                 "apps/shop/store.yaml": ('"kind": SecretStore\nspec: {provider: {vault: {}}}\n', None),
                 "apps/shop/flow.yaml": ("{kind: Secret, metadata: {name: key}, data: {k: c2VjcmV0}}\n", may),
                 "apps/shop/json.yaml": ('{"kind": "Secret"}\n', may),
                 "apps/shop/spaced.yaml": ("metadata: {name: key}\nkind  :   \"Secret\"  \ndata: {k: c2VjcmV0}\n", may),
                 "apps/shop/quoted.yaml": ("'apiVersion': v1\n'kind': 'SECRET'\n", may),
                 "apps/shop/list.yaml": ('{"kind": "List", "items": [{"apiVersion": "v1", "kind": "Secret"}]}\n',
                                         may),
                 "apps/shop/text.yaml": ("metadata: {name: key}\nstringData:\n  k: v\n", may),
                 "apps/shop/twice.json": ('{"a": 1, "a": 2, "items": [{"Kind": "\\u0053ecret"}]}', may),
                 "apps/shop/pem.yaml": ("tls: {key: '-----BEGIN PRIVATE KEY-----'}\n", may)}
        for path, (text, _) in files.items():
            self.answers[("GET", f"{api}{path}?ref=master")] = (200, {
                "encoding": "base64", "content": base64.b64encode(text.encode()).decode()})
        self.answers[("GET", f"{api}apps/shop/wide.yaml?ref=master")] = (200, {
            "encoding": "base64", "content": base64.b64encode("kind: Secret\n".encode("utf-16")).decode()})
        for path, (text, why) in files.items():
            with self.subTest(path=path):
                self.assertIsNotNone(door_targets.manifest_text(path, text.encode())[1])    # no block style
                got = self.call(ONE, "gitops:one-org/cluster", "read", path)
                if why is None:
                    self.assertEqual((got["ok"], got.get("out")), (True, text), got)
                else:
                    self.assertEqual((got["ok"], got.get("why")), (False, f"{path} {why}"), got)
                    self.assertNotIn("out", got)
                pushed = self.call(ONE, "gitops:one-org/cluster", "push", content=change(("new/" + path, text)))
                self.assertEqual((pushed["kind"], "the door takes it only in block style" in pushed["why"]),
                                 ("refused", True), pushed)
        got = self.call(ONE, "gitops:one-org/cluster", "read", "apps/shop/wide.yaml")
        self.assertEqual((got["ok"], "is not UTF-8 text, so it may hold a Secret" in got["why"]), (False, True), got)
        self.assertFalse([m for m, u, d in self.calls if m in ("POST", "PATCH") and "/git/" in u])     # no commit

    def test_a_read_of_a_file_with_another_name_gets_the_loose_reading_too(self):
        """Before, the filter read a file with another name than .yaml, .yml or .json by its lines only, and
        {"kind": "Secret"} in x.txt came back. What a commit refuses for its words is no reason to keep a read back."""
        api = "https://api.github.com/repos/one-org/cluster/contents/"
        may, held = "may hold a Secret, which the filter keeps back", "holds a Secret, which the filter keeps back"
        files = {"apps/x/secret.txt": ('{"kind":"Secret","data":{"key":"c2VjcmV0"}}', may),
                 "charts/shop/templates/key.tpl": ("{kind: 'Secret', stringData: {key: {{ .Values.key }}}}\n", may),
                 "apps/x/Kustomization": ("secretGenerator:\n- name: key\nstringData: {key: secret}\n", may),
                 "charts/shop/templates/plain.tpl": ("apiVersion: v1\nkind: Secret\n", held),
                 "apps/x/key.pem": ("-----BEGIN PRIVATE KEY-----\n", held),
                 "apps/x/pod.txt": ('{"kind": "Pod", "spec": {"hostPID": true, "volumes": [{"hostPath": {}}]}}', None),
                 "docs/README.md": ("# The cluster\n\nThe kind SecretStore, and - {a: b}.\n", None),
                 "charts/shop/templates/_helpers.tpl": ('{{- define "name" -}}{{ .Chart.Name }}{{- end }}\n', None)}
        for path, (text, why) in files.items():
            self.answers[("GET", f"{api}{path}?ref=master")] = (200, {
                "encoding": "base64", "content": base64.b64encode(text.encode()).decode()})
            with self.subTest(path=path):
                got = self.call(ONE, "gitops:one-org/cluster", "read", path)
                if why is None:
                    self.assertEqual((got["ok"], got.get("out")), (True, text), got)
                else:
                    self.assertEqual((got["ok"], got.get("why")), (False, f"{path} {why}"), got)

    def test_a_read_a_commit_and_a_sync_use_the_default_branch(self):
        got = self.call(ONE, "gitops:one-org/cluster", "read", "apps/shop/deployment.yaml")
        self.assertEqual((got["ok"], got["out"]), (True, OLD_DEPLOYMENT))
        got = self.call(ONE, "gitops:one-org/cluster", "push", content=change(
            ("apps/shop/deployment.yaml", OLD_DEPLOYMENT.replace("replicas: 2", "replicas: 3"))))
        self.assertEqual((got["ok"], got["kind"], got["out"]),
                         (True, "rule", "one-org/cluster master is at c2; its checks passed: Validate manifests"))
        got = self.call(ONE, "gitops:one-org/cluster", "sync", "shop")
        self.assertEqual((got["ok"], got["out"]), (True, "sync-app.yml of one-org/cluster: run 4242 passed "
                                                     "(https://github.com/one-org/cluster/actions/runs/4242)"))
        sync = next(d for m, u, d in self.calls if u.endswith("/sync-app.yml/dispatches"))
        self.assertEqual(sync, {"ref": "master", "inputs": {"app": "shop"}, "return_run_details": True})
        self.assertFalse([u for m, u, d in self.calls if "main" in u])
        self.assertEqual(len([u for m, u, d in self.calls if u.endswith("/repos/one-org/cluster")]), 1)   # kept

    def test_an_image_counts_by_the_runs_of_the_repository_that_built_it(self):
        gitops = door.GitHub(self.door, ACCESS, "one-org/cluster")
        self.assertTrue(gitops.image_made("registry.example/one-org/shop-api:v2.0.1"))     # the access file's map
        self.assertTrue(gitops.image_made("ghcr.io/one-org/web:3333333"))                  # the image's own name
        self.assertFalse(gitops.image_made("registry.example/one-org/shop-api:v9.9.9"))
        self.assertFalse(gitops.image_made("ghcr.io/founderizer/founderizer-apps:3333333"))      # a product repository
        self.assertFalse([u for m, u, d in self.calls if "/repos/one-org/cluster/actions" in u])
        self.assertFalse([u for m, u, d in self.calls if "founderizer-apps" in u])

    def test_a_fact_that_cannot_be_read_refuses_the_call(self):
        self.answers[("GET", "https://api.github.com/repos/one-org/cluster")] = (502, {})
        got = self.call(ONE, "gitops:one-org/cluster", "push", content=change(
            ("apps/shop/deployment.yaml", OLD_DEPLOYMENT.replace("replicas: 2", "replicas: 3"))))
        self.assertEqual(got["kind"], "refused")
        self.assertIn("could not check this call: GitHub gave no default branch of one-org/cluster", got["why"])
        self.assertFalse([d for m, u, d in self.calls if m == "PATCH"])


class AWSRole(DoorCase):
    """The door's AWS rights come from its own bot's token, which it trades for an hour's session of the role."""

    def sts_and_ec2(self, method, url, headers, data):
        self.stubs.http_calls.append((method, url, headers, data))
        if url.startswith("https://sts."):
            return 200, ("<Credentials><AccessKeyId>ASIAX</AccessKeyId><SecretAccessKey>session-secret"
                         "</SecretAccessKey><SessionToken>session-token</SessionToken>"
                         "<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>")
        if url.startswith("https://ec2."):
            return 200, "<reservationSet/>"
        return self.stubs.http(method, url, headers, data)

    def test_a_read_takes_the_role_s_session_from_the_bot_s_token_and_keeps_it(self):
        self.door.http = self.sts_and_ec2
        os.makedirs(os.path.dirname(self.root + door.AWS_TOKEN_FILE), exist_ok=True)
        with open(self.root + door.AWS_TOKEN_FILE, "w") as f:
            f.write("jwt-of-the-bot\n")
        for _ in range(2):
            answer = self.call(ONE, "aws:one", "instances")
            self.assertTrue(answer["ok"], answer)
            self.assertNotIn("session", json.dumps(answer))
        self.assertEqual(sum(c[1].startswith("https://sts.") for c in self.stubs.http_calls), 1)
        self.assertIn(b"WebIdentityToken=jwt-of-the-bot&", self.stubs.http_calls[0][3] + b"&")

    def test_with_no_token_of_the_bot_a_call_fails_and_an_own_call_is_not_refused(self):
        answer = self.call(ONE, "aws:one", "instances")
        self.assertFalse(answer["ok"])
        self.assertIn("has written no AWS token", answer["why"])
        answer = self.call(ONE, "aws:one", "call", "ec2", "CreateVolume", content=b'{"Size": "500"}')
        self.assertEqual((answer["ok"], answer["kind"]), (False, "own"), answer)
        self.assertIn("has written no AWS token", answer["why"])
        self.assertEqual(self.stubs.model_calls(), [])


class OwnerYes(DoorCase):
    """A call that is the owner's (D25: a delete of what no agent made through the door, or an AWS delete) runs once
    after his signed yes to that exact call (D22): his app signs a door-call statement with his key, the hub carries
    it, and the door checks the signature itself."""

    def setUp(self):
        super().setUp()
        from test_vault_central import OWNER_C, owner_sign
        self.sign = owner_sign
        data = json.loads(json.dumps(ACCESS))
        data.update(owner_keys=[OWNER_C], fleet="fleet-1")
        self.write_access(data)
        self.answers = []
        hub = self.door.http

        self.devices = []

        providers = provider_http(self.stubs)

        def http(method, url, headers, body):
            if url.endswith("/door/approvals"):
                return 200, {"approvals": self.answers, "devices": self.devices}
            return providers(method, url, headers, body)
        self.door.http = http

    def statement(self, call, need=7, fleet="fleet-1", at=None, **more):
        return vault.canonical(dict({"v": 1, "kind": "door-call", "fleet": fleet, "need": need, "call": call,
                                     "at": round(time.time()) if at is None else at}, **more))

    DELETE = ("hetzner:one", "change", "DELETE", "/servers/42")      # a server that no agent made through the door

    def delete(self):
        return self.call(ONE, *self.DELETE)

    def deleted(self):
        return [c[:2] for c in self.stubs.http_calls if c[:2] == ("DELETE", f"{HZ}/servers/42")]

    def refused_once(self):
        got = self.delete()
        self.assertEqual(got["kind"], "refused")
        self.assertIn(got["call"], got["why"])
        return got["call"]

    def test_the_owners_signed_yes_lets_that_exact_call_through_once(self):
        call = self.refused_once()
        said = self.statement(call)
        self.answers = [{"need": 7, "statement": said, "signature": self.sign(said)}]
        self.assertEqual(door.fetch_approvals(self.door), 1)
        got = self.delete()
        self.assertTrue(got["ok"], got)
        self.assertEqual(got["kind"], "approved")
        self.assertEqual(self.deleted(), [("DELETE", f"{HZ}/servers/42")])
        self.assertEqual(self.door.record.after(0)[-1]["kind"], "approved")
        again = self.delete()
        self.assertEqual(again["kind"], "refused")
        self.assertEqual(len(self.deleted()), 1)
        self.assertEqual(self.stubs.model_calls(), [])

    def test_a_yes_of_another_call_fleet_key_or_age_or_not_canonical_lets_nothing_through(self):
        from test_vault_central import owner_point, owner_sign
        call = self.refused_once()
        other = self.statement("0" * 64)
        stranger = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        self.assertNotEqual(owner_point(stranger), door.read_json(door.ACCESS_FILE, {})["owner_keys"][0])
        wrong = [(other, self.sign(other)),
                 (self.statement(call, fleet="fleet-2"), None),
                 (self.statement(call, at=round(time.time()) - 8 * 86400), None),
                 (self.statement(call), owner_sign(self.statement(call), stranger)),
                 (json.dumps({"v": 1, "kind": "door-call", "fleet": "fleet-1", "need": 7, "call": call,
                              "at": round(time.time())}), None),
                 (self.statement(call, kind_extra="x"), None)]
        self.answers = [{"statement": st, "signature": sig or self.sign(st)} for st, sig in wrong]
        self.assertEqual(door.fetch_approvals(self.door), 1)          # only the yes to the other call is good
        self.assertEqual(self.delete()["kind"], "refused")
        self.assertEqual(self.deleted(), [])

    def test_a_phones_yes_counts_only_through_its_certificate_of_now(self):
        """The phone signs with its own key; the owner key on the Mac certified that key; the hub serves the
        certificates of the phones of now, so a removed phone's yes lets nothing through any more."""
        from test_vault_central import owner_point
        phone = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
        call = self.refused_once()
        cert = vault.canonical({"v": 1, "kind": "owner-device", "fleet": "fleet-1", "device": "iphone",
                                "key": owner_point(phone), "at": round(time.time())})
        said = self.statement(call)
        yes = {"statement": said, "signature": self.sign(said, phone)}
        self.answers = [yes]
        self.devices = [{"device": "iphone", "statement": cert, "signature": self.sign(cert, phone)}]   # self-signed
        self.assertEqual(door.fetch_approvals(self.door), 0)
        self.devices = [{"device": "iphone", "statement": cert, "signature": self.sign(cert)}]
        self.assertEqual(door.fetch_approvals(self.door), 1)
        self.devices = []                                   # the owner removed the phone: its certificate went
        self.assertEqual(door.fetch_approvals(self.door), 0)
        self.assertEqual(self.delete()["kind"], "refused")
        self.devices = [{"device": "iphone", "statement": cert, "signature": self.sign(cert)}]
        door.fetch_approvals(self.door)
        got = self.delete()
        self.assertEqual((got["kind"], got["ok"]), ("approved", True))

    def test_a_yes_never_opens_a_call_that_code_refuses(self):
        content = json.dumps({"message": "change", "files": [
            {"path": "apps/x.yaml", "content": base64.b64encode(b"kind: Secret\ndata:\n  x: eA==\n").decode()}]}).encode()
        got = self.call(ONE, "gitops:one-org/cluster", "push", content=content)
        self.assertEqual(got["kind"], "refused")
        self.assertNotIn("call", got)
        sha = hashlib.sha256(json.dumps(["gitops:one-org/cluster", "push", []], sort_keys=True).encode() +
                             content).hexdigest()
        said = self.statement(sha)
        self.answers = [{"statement": said, "signature": self.sign(said)}]
        door.fetch_approvals(self.door)
        self.assertEqual(self.call(ONE, "gitops:one-org/cluster", "push", content=content)["kind"], "refused")

    def test_the_d25_deletes_still_need_his_yes_and_run_once_after_it(self):
        """The owner's word of 11 November 2026 took the judge away, and not his own yes: a delete of what no agent
        made through the door, and every AWS delete, are refused with the call's hash for a Needs-you item, and his
        signed yes lets that exact call through once."""
        got = self.delete()
        self.assertEqual(got["kind"], "refused")
        self.assertIn("which no agent made through the door, and such a delete is the owner's", got["why"])
        self.assertIn(f"Its call hash is {got['call']}", got["why"])
        aws = self.call(ONE, "aws:one", "call", "ec2", "TerminateInstances",
                        content=b'{"InstanceId.1": "i-0123456789abcdef0"}')
        self.assertEqual(aws["kind"], "refused")
        self.assertIn("every AWS delete is the owner's", aws["why"])
        self.assertEqual(self.deleted(), [])
        said, aws_said = self.statement(got["call"]), self.statement(aws["call"], need=8)
        self.answers = [{"need": 7, "statement": said, "signature": self.sign(said)},
                        {"need": 8, "statement": aws_said, "signature": self.sign(aws_said)}]
        self.assertEqual(door.fetch_approvals(self.door), 2)
        got = self.delete()
        self.assertEqual((got["ok"], got["kind"]), (True, "approved"), got)
        self.assertEqual(self.deleted(), [("DELETE", f"{HZ}/servers/42")])
        line = self.door.record.after(0)[-1]
        self.assertEqual((line["kind"], line["why"]), ("approved", "the owner's signed yes (N-7) to this exact "
                                                                "call, used once"))
        aws = self.call(ONE, "aws:one", "call", "ec2", "TerminateInstances",
                        content=b'{"InstanceId.1": "i-0123456789abcdef0"}')
        self.assertEqual(aws["kind"], "approved", aws)  # it runs, and fails here for want of the bot's AWS token
        self.assertIn("has written no AWS token", aws["why"])
        self.assertEqual(self.stubs.model_calls(), [])
        self.assertEqual(self.delete()["kind"], "refused")

    def test_owner_keys_must_be_p256_points(self):
        data = json.loads(json.dumps(ACCESS))
        data["owner_keys"] = ["AAAA"]
        with self.assertRaisesRegex(ValueError, "uncompressed P-256"):
            door.validate_access(data)
        data["owner_keys"], data["fleet"] = [], "fleet-1"
        with self.assertRaisesRegex(ValueError, "owner_keys lists 1 to"):
            door.validate_access(data)


SCRIPT = b"exec 9>/run/lock/x.lock\nflock -n 9\nfor n in 1 2 3; do echo $n; done | wc -l\n"


def call_hash(target, op, content, *args):
    """The hash that the door gives with a refusal: the target, the form, the arguments and the content's bytes."""
    return hashlib.sha256(json.dumps([target, op, list(args)], sort_keys=True).encode() + content).hexdigest()


# The examples of a call's hash that both sides are tested with: the door (door.call_hash) and the owner's Mac, which
# computes the hash of the script that its card shows and signs only when it is the hash that the hub gave
# (DoorCall.hash in app/Sources/FleetCore/DoorCall.swift). One JSON line for each: [target, action, arguments, content
# as text, hash]. This is the one definition: app/Tests/FleetCoreTests/DoorCallTests.swift holds a copy of these lines
# between two marks, and CallHash fails when the copy differs.
CALL_HASHES = r'''
["web-1", "run", [], "id\n", "166f72a0e75ff9b58dd452f10cc9d93600ef1d33e15f1c38fe2071cafd688d70"]
["web-1", "run", [], "id", "6f32c97d1968a553afdbc5788ed7dee1c872feb1a740083e1ef11a1c44a22a23"]
["web-1", "run", [], "", "812f281547e30beda0ec6ce09ebcf4a10fe6859394d4390f1072b07d66973410"]
["db-1.example.internal", "run", [], "#!/bin/bash\nset -euo pipefail\nflock /run/lock/app.lock \\\n\tcp -a \"/srv/app/uploads\" /root/uploads-$(date +%F)\n", "195c09ac81728cad73a7a9f54af8c3939a2cb56f5b972300575279311b8c6d87"]
["web-1", "run", [], "echo 'caf\u00e9 \u00fc\u00f1 \u4e2d\u6587 \ud83d\ude00'\n", "cfd77784479f00274b0ad2154e69062aeaf395cd206386ee95ca593c96282161"]
["web-1", "restart", ["nginx"], "", "caef4b357ff328666c9390e2b13166e80ad10a97710c1fd8bb5fdcfc8b30b990"]
["hetzner:one", "server-delete", ["shop \"old\" \\ 1", "caf\u00e9", "\ud83d\ude00 \u007f"], "", "0428db94f078234bf77c8e1b7b416f01560359ff7573ade4db44ae96a2fb7cd8"]
["web-1", "file", ["/etc/app/a b.conf", "0644"], "key = \"value\"\n", "1ffa5dbd2fa34e5d48087a042d7dc3e5d0d292bf1119d39ecfee0f343e3da241"]
'''.strip().split("\n")


class CallHash(unittest.TestCase):
    """One definition of a call's hash for the door and for the owner's Mac (review point 5.6 of 11 November 2026:
    the Mac signs a hash only when it is the hash of what its card shows)."""

    def test_the_door_gives_the_hash_of_each_example(self):
        self.assertGreaterEqual(len(CALL_HASHES), 8)
        for line in CALL_HASHES:
            target, action, args, content, sha = json.loads(line)
            with self.subTest(line=line):
                self.assertEqual(door.call_hash(target, action, args, content.encode()), sha)
        # the first one by hand, with nothing of json.dumps: the JSON of the list, then the script's bytes
        self.assertEqual(hashlib.sha256(b'["web-1", "run", []]' + b"id\n").hexdigest(), json.loads(CALL_HASHES[0])[4])
        self.assertEqual(door.call_hash("web-1", "run", []), door.call_hash("web-1", "run", [], b""))

    def test_the_door_s_call_gives_that_hash_with_its_refusal(self):
        """The refusal of a run names door.call_hash of the call, so the examples are what an agent gets."""
        import inspect
        self.assertIn("sha = call_hash(target, op, args, content)", inspect.getsource(door.Door.call))

    def test_the_app_s_tests_hold_the_same_examples(self):
        """The Swift tests of DoorCall.hash read their examples from a copy of the lines above. A clone with no app
        folder (the published hub) has no copy to compare."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "Tests", "FleetCoreTests",
                            "DoorCallTests.swift")
        if not os.path.isdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "Tests")):
            self.skipTest("this clone has no app folder")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        copy = text.split("// call-hashes:begin\n")[1].split("// call-hashes:end")[0]
        self.assertEqual([line.strip() for line in copy.strip().split("\n")], CALL_HASHES)


class Signed:
    """The owner's keys in the door's file, and his signed yeses as the hub serves them (OwnerYes)."""

    def signed_setup(self):
        from test_vault_central import OWNER_C, owner_sign
        self.sign = owner_sign
        data = json.loads(json.dumps(ACCESS))
        data.update(owner_keys=[OWNER_C], fleet="fleet-1")
        self.write_access(data)
        self.answers = []
        self.door.http = lambda method, url, headers, body: (200, {"approvals": self.answers, "devices": []}) \
            if url.endswith("/door/approvals") else (404, {})

    def yes(self, call, need=9):
        said = vault.canonical({"v": 1, "kind": "door-call", "fleet": "fleet-1", "need": need, "call": call,
                                "at": round(time.time())})
        self.answers.append({"need": need, "statement": said, "signature": self.sign(said)})
        return door.fetch_approvals(self.door)


class Prunes(Signed, DoorCase):
    """A door sync with prune, on the whole path of Door.call: the listing run and its log line, the door's record of
    what its commits removed, the prune run, and the owner's card for a list that is his (DevOps plan X3; the owner,
    12 November 2026)."""
    API = "https://api.github.com"

    def setUp(self):
        super().setUp()
        self.signed_setup()             # the owner's keys in the door's file
        github_stubs(self)              # self.answers: GitHub's answers by method and address
        github, self.yeses = self.door.http, []
        self.door.http = lambda method, url, headers, body: (200, {"approvals": self.yeses, "devices": []}) \
            if url.endswith("/door/approvals") else github(method, url, headers, body)
        patcher = patch.object(door, "RUN_POLL", 0)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.line = listing_line([])
        # the jobs of a listing run as GitHub gives them: the sync job is skipped and has no log (GitHub answers 404)
        self.answers[("GET", f"{self.API}/repos/one-org/cluster/actions/runs/4242/jobs?per_page=50")] = \
            (200, {"jobs": [{"id": 97, "name": "Verify the caller", "conclusion": "success"},
                            {"id": 99, "name": "List what Argo CD wants to prune", "conclusion": "success"},
                            {"id": 98, "name": "Sync the application", "conclusion": "skipped"}]})
        self.late = []          # log addresses that GitHub does not give yet, one read each
        logs = {"https://logs.example/97": lambda: b"the caller may run this workflow\n",
                "https://logs.example/99": lambda: self.line.encode()}

        def log(method, url, headers, limit, timeout=120):
            if url in self.late:
                self.late.remove(url)
                return 404, b""
            return (200, logs[url]()) if url in logs else (599, b"")
        for p in (patch.object(door, "http_redirect", lambda method, url, headers, timeout=30:
                               (302, "https://logs.example/" + url.split("/")[-2]) if url.endswith(
                                   ("/actions/jobs/97/logs", "/actions/jobs/99/logs")) else (404, "")),
                  patch.object(door, "http_raw", log), patch.object(door, "LOG_PAUSE", 0)):
            p.start()
            self.addCleanup(p.stop)

    def yes(self, call, need=9):
        said = vault.canonical({"v": 1, "kind": "door-call", "fleet": "fleet-1", "need": need, "call": call,
                                "at": round(time.time())})
        self.yeses.append({"need": need, "statement": said, "signature": self.sign(said)})
        return door.fetch_approvals(self.door)

    def head(self, path, text):
        self.answers[("GET", f"{self.API}/repos/one-org/cluster/contents/{path}?ref=master")] = \
            (200, {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()})

    def dispatched(self):
        return [d["inputs"] for m, u, d in self.calls if u.endswith("/sync-app.yml/dispatches")]

    def prune(self):
        return self.call(ONE, "gitops:one-org/cluster", "sync", "shop", "prune")

    def test_a_prune_of_what_the_agent_s_own_commit_removed_runs_as_its_own_call(self):
        self.head("apps/shop/old.yaml", OLD_CONFIG)
        got = self.call(ONE, "gitops:one-org/cluster", "push", content=json.dumps(
            {"message": "retire", "files": [{"path": "apps/shop/old.yaml", "delete": True}]}).encode())
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        removed = json.loads(slurp(self.root + door.REMOVED_FILE, "r"))["one-org/cluster"]
        self.assertEqual(sorted(removed), [":ConfigMap:shop/old-config",
                                           "networking.k8s.io:NetworkPolicy:shop/old-policy"])
        self.assertEqual(removed[":ConfigMap:shop/old-config"]["commit"], "c2")
        self.line = listing_line([":ConfigMap:shop/old-config", "networking.k8s.io:NetworkPolicy:shop/old-policy"])
        got = self.prune()
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        self.assertEqual(self.dispatched(), [
            {"app": "shop", "prune": "list"},
            {"app": "shop", "prune": "yes", "prune_owner_yes": "false",
             "prune_objects": ":ConfigMap:shop/old-config\nnetworking.k8s.io:NetworkPolicy:shop/old-policy"}])
        lines = [(e["action"], e["kind"], e["outcome"]) for e in self.door.record.after(0)]
        self.assertEqual(lines[-2:], [("prune-list", "read", "done"), ("sync", "own", "done")])
        self.assertIn("own call, which it answers for: a prune in shop of what its own commits",
                      self.door.record.after(0)[-1]["why"])
        self.assertEqual(json.loads(slurp(self.root + door.REMOVED_FILE, "r"))["one-org/cluster"], {})

    def test_a_skipped_job_is_not_read_and_a_log_that_comes_late_is_read_again(self):
        "12 November 2026, the first live listing: the skipped sync job has no log, and GitHub answered 404 for it."
        self.line = listing_line([])
        self.late = ["https://logs.example/99"]
        got = self.prune()
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)
        self.assertEqual(self.late, [])
        self.assertIn("Argo CD wants to prune nothing in shop", self.door.record.after(0)[-1]["why"])
        # a log that never comes: the listing failed, and the door says which job
        self.late = ["https://logs.example/99"] * door.LOG_TRIES
        got = self.prune()
        self.assertEqual((got["ok"], got["route"]), (False, "again"), got)
        self.assertIn("the log of job 99 could not be read (404)", got["why"])

    def test_a_list_that_is_the_owner_s_goes_to_his_card_whole_and_runs_once_after_his_yes(self):
        keys = [":ConfigMap:shop/made-by-people", ":Service:shop/front"]
        self.line = listing_line(keys, [":Service:shop/front"])
        got = self.prune()
        self.assertEqual((got["ok"], got["route"]), (False, "yes"), got)
        sha = door.call_hash("gitops:one-org/cluster", "sync", ["shop", "prune"], "\n".join(keys).encode())
        self.assertEqual(got["call"], sha)
        self.assertIn(":Service:shop/front is a Service of type LoadBalancer", got["why"])
        self.assertIn("no commit through the door removed :ConfigMap:shop/made-by-people", got["why"])
        self.assertNotIn("Full access", got["why"])
        self.assertNotIn("full_access", got)
        self.assertEqual(self.dispatched(), [{"app": "shop", "prune": "list"}])        # no prune was sent
        self.yes(sha)
        got = self.prune()
        self.assertEqual((got["ok"], got["kind"]), (True, "approved"), got)
        self.assertEqual(self.dispatched()[-1], {"app": "shop", "prune": "yes", "prune_owner_yes": "true",
                                                 "prune_objects": "\n".join(keys)})
        got = self.prune()                                  # his yes lets that one call through, once
        self.assertEqual((got["ok"], got["route"]), (False, "yes"))
        self.line = listing_line(keys + [":ConfigMap:shop/more"], [":Service:shop/front"])
        self.assertNotEqual(self.prune()["call"], sha)      # another list is another call

    def test_what_door_commits_made_and_then_removed_prunes_as_a_rule_call(self):
        new = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: trial\n  namespace: shop\ndata:\n  k: v\n"
        got = self.call(ONE, "gitops:one-org/cluster", "push", content=change(("apps/shop/trial.yaml", new)))
        self.assertTrue(got["ok"], got)
        self.head("apps/shop/trial.yaml", new)
        got = self.call(ONE, "gitops:one-org/cluster", "push", content=json.dumps(
            {"message": "end the trial", "files": [{"path": "apps/shop/trial.yaml", "delete": True}]}).encode())
        self.assertTrue(got["ok"], got)
        self.line = listing_line([":ConfigMap:shop/trial"])
        got = self.prune()
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)

    def test_outside_the_deploy_window_a_prune_starts_no_listing_run(self):
        data = json.loads(slurp(self.root + door.ACCESS_FILE, "r"))
        data["windows"] = [{"hosts": ["gitops:one-org/cluster"], "forms": ["deploy"], "deny": [["11:00", "13:00"]]}]
        self.write_access(data)
        got = self.prune()
        self.assertEqual((got["ok"], got["route"]), (False, "window"), got)
        self.assertEqual(self.dispatched(), [])

    def test_nothing_to_prune_is_a_sync_and_a_failed_listing_is_no_prune(self):
        got = self.prune()
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)
        self.assertEqual(self.dispatched(), [{"app": "shop", "prune": "list"}, {"app": "shop"}])
        self.line = "the run printed something else\n"
        got = self.prune()
        self.assertEqual((got["ok"], got["route"]), (False, "again"))
        self.assertIn("printed 0 lines DOOR-PRUNE-LIST", got["why"])
        self.assertEqual(self.door.record.after(0)[-2]["outcome"], "failed")     # the listing's own line


class ScriptsAndRuns(Signed, DoorCase):
    """The door-modes proposal, steps 2 and 3. A host's script runs in its box as the agent's own call, with no card,
    so flock, pipes and loops work in Auto. A run, a root script with no box, is what the next mode allows: the door
    refuses it with its call hash, and the owner's signed yes to that hash lets that exact call through once. After
    either, the door ends the host's rollback countdown when the host answers it."""

    def setUp(self):
        super().setUp()
        self.signed_setup()
        patcher = patch.object(door, "TIMER_PAUSE", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_script_is_the_agent_s_own_call_and_the_door_ends_the_countdown_after_it(self):
        got = self.call(ONE, "web-1", "script", content=SCRIPT)
        self.assertEqual((got["ok"], got["kind"], got["out"]), (True, "own", "script done\ntimer done\n"), got)
        self.assertEqual([c[1:] for c in self.stubs.ssh_calls], [("script", [], SCRIPT), ("timer", ["cancel"], None)])
        line = self.door.record.after(0)[-1]
        self.assertEqual((line["kind"], line["outcome"], line["why"]),
                         ("own", "done", "ops-one's own call, which it answers for: the host form script"))

    def test_a_script_needs_its_content_a_fix_host_and_the_agent_s_fix(self):
        got = self.call(ONE, "web-1", "script")
        self.assertEqual((got["kind"], got["why"], got["route"]),
                         ("refused", "script takes its bytes as the call's content", "none"))
        got = self.call(ONE, "ci-1", "script", content=SCRIPT)
        self.assertEqual((got["why"], got["route"]),
                         ("ci-1 is rule-only: only rule forms run there, and no file install", "none"))
        got = self.call(ONE, "logs-1", "script", content=SCRIPT)
        self.assertEqual((got["why"], got["route"], got["needs"], got["level"]),
                         ("ops-one holds Read on logs-1: no write", "holder", "server:logs-1", "fix"))
        got = self.call(TWO, "web-1", "script", content=SCRIPT)
        self.assertEqual((got["why"], got["route"], got["needs"], got["level"]),
                         ("ops-two holds no grant on web-1", "holder", "server:web-1", "fix"))
        self.assertFalse([g for g in self.door.record.after(0) if g["kind"] != "refused"])
        self.assertEqual(self.stubs.ssh_calls, [])

    def test_a_run_is_refused_with_its_hash_and_one_signed_yes_runs_it_once(self):
        call = call_hash("web-1", "run", SCRIPT)
        got = self.call(ONE, "web-1", "run", content=SCRIPT)
        self.assertEqual((got["ok"], got["kind"], got["route"], got["call"]), (False, "refused", "yes", call))
        self.assertEqual(got["why"], "run is a root script with no box, which no grant on web-1 covers." +
                         door.APPROVAL_NOTE.format(sha=call) + door.FULL_NOTE.format(host="web-1"))
        self.assertEqual(self.door.record.after(0)[-1]["sha256"], call)
        self.assertEqual(self.yes(call), 1)
        changed = self.call(ONE, "web-1", "run", content=SCRIPT + b"id\n")      # one more byte is another call
        self.assertEqual((changed["kind"], changed["call"]), ("refused", call_hash("web-1", "run", SCRIPT + b"id\n")))
        self.assertEqual(self.stubs.ssh_calls, [])
        got = self.call(ONE, "web-1", "run", content=SCRIPT)
        self.assertEqual((got["ok"], got["kind"], got["out"]), (True, "approved", "run done\ntimer done\n"), got)
        self.assertEqual([c[1:] for c in self.stubs.ssh_calls], [("run", [], SCRIPT), ("timer", ["cancel"], None)])
        line = self.door.record.after(0)[-1]
        self.assertEqual((line["kind"], line["outcome"], line["why"]),
                         ("approved", "done", "the owner's signed yes (N-9) to this exact call, used once"))
        again = self.call(ONE, "web-1", "run", content=SCRIPT)
        self.assertEqual((again["kind"], again["route"], again["call"]), ("refused", "yes", call))
        self.assertEqual(len(self.stubs.ssh_calls), 2)

    def test_a_run_that_no_yes_opens_gets_no_hash(self):
        """Patch only is code's, and so are the grants and the never list: a refusal of those gives no hash, so no
        item can ask for it, and a yes to such a call opens nothing."""
        for address, host in ((ONE, "ci-1"), (ONE, "fleet-1"), (ONE, "logs-1"), (TWO, "web-1"), (ONE, "site-1")):
            with self.subTest(host=host):
                got = self.call(address, host, "run", content=SCRIPT)
                self.assertEqual(got["kind"], "refused")
                self.assertNotIn("call", got)
                self.assertNotEqual(got["route"], "yes")
        self.yes(call_hash("ci-1", "run", SCRIPT))
        self.assertNotIn("call", self.call(ONE, "ci-1", "run", content=SCRIPT))
        self.assertEqual(self.stubs.ssh_calls, [])

    def test_a_window_refuses_a_run_and_keeps_its_yes(self):
        """A script counts as a restart: inside a deny window the door refuses it, and the owner's yes stays unused."""
        call = call_hash("web-1", "run", SCRIPT)
        self.yes(call)
        self.door.clock = lambda: datetime.datetime(2026, 11, 2, 22, 0, tzinfo=datetime.timezone.utc)
        for op in ("run", "script"):
            got = self.call(ONE, "web-1", op, content=SCRIPT)
            self.assertEqual((got["kind"], got["route"]), ("refused", "window"))
            self.assertNotIn("call", got)
        self.door.clock = lambda: self.clock_at
        self.assertEqual(self.call(ONE, "web-1", "run", content=SCRIPT)["kind"], "approved")

    def test_a_host_that_does_not_answer_after_a_script_keeps_its_countdown(self):
        def ssh(host, req, stdin):
            self.stubs.ssh_calls.append((host["address"], req["op"], list(req["args"]), stdin))
            return (0, "3\n") if req["op"] == "script" else (255, "ssh: connect to host port 2244: timed out\n")
        self.door.ssh = ssh
        got = self.call(ONE, "web-1", "script", content=SCRIPT)
        self.assertTrue(got["ok"], got)
        self.assertEqual(got["out"], "3\nweb-1 did not answer the door after the script: if the script armed the "
                                     "rollback timer, it puts the firewall, the network, sshd and Tailscale back in "
                                     "600 seconds, unless `ops web-1 timer cancel` comes first\n")
        self.assertEqual([c[1] for c in self.stubs.ssh_calls], ["script"] + ["timer"] * door.TIMER_TRIES)

    def test_a_script_that_fails_still_ends_the_countdown(self):
        def ssh(host, req, stdin):
            self.stubs.ssh_calls.append((host["address"], req["op"], list(req["args"]), stdin))
            if req["op"] == "script":
                return 1, "failed: the rollback timer is armed\nflock: failed to get lock\n"
            return 0, "the rollback timer is off\n"
        self.door.ssh = ssh
        got = self.call(ONE, "web-1", "script", content=SCRIPT)
        self.assertEqual((got["ok"], got["kind"]), (False, "own"))
        self.assertEqual(got["why"], "failed: the rollback timer is armed\nflock: failed to get lock\nthe rollback "
                                     "timer is off")
        self.assertEqual(self.door.record.after(0)[-1]["outcome"], "failed")

    def test_a_host_with_the_ops_root_of_an_older_install_says_so(self):
        def ssh(host, req, stdin):
            self.stubs.ssh_calls.append((host["address"], req["op"], list(req["args"]), stdin))
            return 3, "refused: 'script' is no form of a host; `help` lists them\n"
        self.door.ssh = ssh
        got = self.call(ONE, "web-1", "script", content=SCRIPT)
        self.assertEqual((got["ok"], got["why"]), (False, "web-1 runs an ops-root older than the door's, which has no "
                                                          "form script: the door brings each host the ops-root of its "
                                                          "release (update_hosts), so send the same call again in a "
                                                          "few minutes"))
        self.assertEqual([c[1] for c in self.stubs.ssh_calls], ["script"])     # nothing armed: no cancel


class FullAccess(Signed, DoorCase):
    """The door-modes proposal, step 4: the card's second answer, Full access on <host>, is the owner's signed mode
    statement, which the hub carries beside his yeses. The door keeps the newest statement of each host, and lets
    every run on a host in Full access through as the agent's own call, with no yes. Auto is the default, and the door
    honours Full access only on a host that its file holds at fix, on no never list, for an agent that holds it at Fix
    in its own business. Only the owner key of his Mac signs a mode: his decision 3, the phone, is open."""

    def setUp(self):
        super().setUp()
        self.signed_setup()
        self.modes = []
        self.door.http = lambda method, url, headers, body: \
            (200, {"approvals": self.answers, "devices": [], "modes": self.modes}) \
            if url.endswith("/door/approvals") else (404, {})
        patcher = patch.object(door, "TIMER_PAUSE", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def statement(self, host, mode="full", at=None, fleet="fleet-1"):
        return vault.canonical({"v": 1, "kind": "door-mode", "fleet": fleet, "host": host, "mode": mode,
                                "at": round(time.time()) if at is None else at})

    def mode(self, host, mode="full", at=None, signature=None, **more):
        said = self.statement(host, mode, at, **more)
        self.modes.append({"statement": said, "signature": signature or self.sign(said)})
        door.fetch_approvals(self.door)
        return said

    def run_on(self, host="web-1", address=ONE, content=SCRIPT):
        return self.call(address, host, "run", content=content)

    def test_full_access_lets_every_run_on_its_host_through_with_no_yes(self):
        self.assertEqual(self.run_on()["kind"], "refused")
        self.mode("web-1")
        for content in (SCRIPT, SCRIPT + b"id\n"):
            got = self.run_on(content=content)
            self.assertEqual((got["ok"], got["kind"], got["out"]), (True, "own", "run done\ntimer done\n"), got)
        line = self.door.record.after(0)[-1]
        self.assertEqual((line["kind"], line["why"]), ("own", "ops-one's own call, which it answers for: a root "
                                                              "script with no box on web-1, which the owner set to "
                                                              "Full access"))
        self.assertEqual([c[1] for c in self.stubs.ssh_calls], ["run", "timer", "run", "timer"])
        self.assertEqual(self.run_on("db-1")["kind"], "refused")         # the mode of one host only

    def test_a_newer_statement_wins_and_an_older_one_never_comes_back(self):
        t = round(time.time())
        old = self.mode("web-1", at=t - 100)
        self.assertEqual(self.run_on()["kind"], "own")
        self.mode("web-1", "auto", at=t - 50)
        self.assertEqual(self.run_on()["kind"], "refused")
        self.modes = [{"statement": old, "signature": self.sign(old)}]          # the hub serves the old one again
        door.fetch_approvals(self.door)
        self.assertEqual(self.run_on()["kind"], "refused")
        self.modes = []                                                     # and then none: the door keeps its own
        door.fetch_approvals(self.door)
        self.assertEqual(door.read_json(door.MODES_FILE, {})["web-1"]["mode"], "auto")
        self.mode("web-1", at=t)
        self.assertEqual(self.run_on()["kind"], "own")

    def serve(self, *statements, signature=None):
        """The hub serves these statements, and the door refreshes one time."""
        self.modes = [{"statement": said, "signature": signature or self.sign(said)} for said in statements]
        door.fetch_approvals(self.door)

    def test_a_signed_auto_ends_full_access_at_the_next_refresh_and_no_older_full_comes_back(self):
        """The row of a server (door-modes proposal, E1; the owner's "Yes, as shown" of 11 November 2026) signs Auto
        as the card signs Full access. The hub serves the newest statement of each host: the door takes the Auto at
        its next refresh, and no Full access from before it comes back, whatever the hub serves afterwards and in
        whatever order: not the one that the Auto ended, not one between the two, and not one of the Auto's own
        second."""
        t = round(time.time())
        full = self.mode("web-1", at=t - 100)
        self.assertEqual((self.run_on()["kind"], self.door.modes_said()["web-1"]),
                         ("own", {"mode": "full", "at": t - 100}))
        auto = self.statement("web-1", "auto", at=t - 50)
        signature = self.sign(auto)
        self.modes = [{"statement": auto, "signature": signature}]
        self.assertEqual(self.run_on()["kind"], "own")                  # the door has not asked the hub yet
        door.fetch_approvals(self.door)                                 # its next refresh, each minute
        got = self.run_on()
        self.assertEqual((got["kind"], got["full_access"], got["route"]), ("refused", "web-1", "yes"), got)
        kept = self.kept()
        self.assertEqual(kept, {"mode": "auto", "at": t - 50, "statement": auto, "signature": signature,
                                "host_key": KEY})
        self.assertEqual(self.door.modes_said()["web-1"], {"mode": "auto", "at": t - 50})
        between, same = self.statement("web-1", at=t - 51), self.statement("web-1", at=t - 50)
        for old in (full, between, same):
            for served in ((old,), (old, auto), (auto, old), (old, old)):
                with self.subTest(old=old, served=served):
                    self.serve(*served)
                    self.assertEqual((self.run_on()["kind"], self.kept()), ("refused", kept))
        kept = self.kept()
        self.serve()                                                    # the hub serves none: the door keeps its own
        self.assertEqual(self.kept(), kept)
        fresh = door.Door(conf=self.door.conf, http=self.door.http, ssh=self.door.ssh)       # the door starts again
        self.serve(full, between, same)
        self.assertFalse(fresh.full_access(fresh.access(), "web-1", "ops-one"))
        self.assertEqual(self.kept(), kept)
        self.mode("web-1", at=t - 49)                                   # only a newer statement of the owner changes it
        self.assertEqual(self.run_on()["kind"], "own")
        self.mode("web-1", "auto", at=t - 48)
        self.assertEqual(self.run_on()["kind"], "refused")
        self.assertEqual(self.run_on("web-2", TWO)["kind"], "refused")  # no other host got a mode from these

    def test_a_signed_auto_far_down_the_hub_s_list_still_ends_full_access(self):
        """The door read the first 200 statements of the hub's answer. The hub serves one for each server that an
        agent holds, in the order of their names, so on a large fleet the signed Auto of a late name was never read
        and Full access stood. The door reads MODES_READ of them, and what is no statement costs it no signature
        check."""
        t = round(time.time())
        self.mode("web-1", at=t - 100)
        self.assertEqual(self.run_on()["kind"], "own")
        other = self.statement("web-2", at=t - 100)
        filler = [{"statement": other, "signature": "c2ln"}] * 300 + [None, 5, "text", {"statement": 5}] * 25
        auto = self.statement("web-1", "auto", at=t - 50)
        self.modes = filler + [{"statement": auto, "signature": self.sign(auto)}]
        self.assertGreater(len(self.modes), 200)
        door.fetch_approvals(self.door)
        self.assertEqual((self.run_on()["kind"], self.kept()["mode"]), ("refused", "auto"))
        self.assertGreaterEqual(door.MODES_READ, 2000)

    def test_a_statement_that_the_door_refuses_does_not_hold_back_the_signed_one_before_it(self):
        """The hub checks no signature, so it serves its newest few statements of each server, the newest first. A
        later one in the right form with no good signature must not keep the owner's signed Auto from the door; and
        the door checks at most MODE_CHECKS signatures of one server in one refresh, so that a hub cannot make it
        check thousands."""
        t = round(time.time())
        self.mode("web-1", at=t - 100)
        self.assertEqual(self.run_on()["kind"], "own")
        auto = self.statement("web-1", "auto", at=t - 50)
        forged = [{"statement": self.statement("web-1", at=t - 10 - n), "signature": "bm90LXNpZ25lZA=="} for n in range(4)]
        self.modes = forged + [{"statement": auto, "signature": self.sign(auto)}]
        door.fetch_approvals(self.door)
        self.assertEqual((self.run_on()["kind"], self.kept()["statement"]), ("refused", auto))
        # more of one name than the hub ever serves: the door reads MODE_CHECKS of them, and every other name
        newer = self.statement("web-1", at=t - 5)
        other = self.statement("web-2", at=t - 5)
        flood = [{"statement": self.statement("web-1", at=t - 40 + n), "signature": "bm90LXNpZ25lZA=="}
                 for n in range(door.MODE_CHECKS)]
        self.modes = flood + [{"statement": newer, "signature": self.sign(newer)},
                              {"statement": other, "signature": self.sign(other)}]
        door.fetch_approvals(self.door)
        self.assertEqual(self.kept()["statement"], auto)
        self.assertEqual(door.read_json(door.MODES_FILE, {})["web-2"]["statement"], other)
        self.modes = flood[:door.MODE_CHECKS - 1] + [{"statement": newer, "signature": self.sign(newer)}]
        door.fetch_approvals(self.door)
        self.assertEqual(self.kept()["statement"], newer)

    def test_an_auto_that_the_owner_key_did_not_sign_ends_no_full_access(self):
        """The hub carries a statement and checks no signature. An Auto that the door does not take leaves Full
        access as it was, and the door's own word (modes_said, which the hub reads with the record) says so."""
        from test_vault_central import owner_point
        t = round(time.time())
        self.mode("web-1", at=t - 100)
        phone = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
        cert = vault.canonical({"v": 1, "kind": "owner-device", "fleet": "fleet-1", "device": "iphone",
                                "key": owner_point(phone), "at": t})
        self.door.http = lambda method, url, headers, body: \
            (200, {"approvals": [], "devices": [{"device": "iphone", "statement": cert, "signature": self.sign(cert)}],
                   "modes": self.modes}) if url.endswith("/door/approvals") else (404, {})
        auto = self.statement("web-1", "auto", at=t - 50)
        for said, signature in ((auto, self.sign(auto, phone)), (auto, self.sign(auto.replace("auto", "full"))),
                                (auto, "c2ln"), (auto + " ", self.sign(auto + " ")),
                                (self.statement("web-1", "auto", at=t - 50, fleet="fleet-2"), None),
                                (self.statement("web-1", "auto", at=t + 3600), None),
                                (self.statement("web-1", "auto", at=t - 100), None),
                                (self.statement("web-1", "off", at=t - 50), None),
                                (auto.replace(str(t - 50), f"{t - 50}.0"), None),
                                (auto.replace(str(t - 50), "true"), None)):
            with self.subTest(said=said, signature=signature):
                self.serve(said, signature=signature or self.sign(said))
                self.assertEqual((self.run_on()["kind"], self.door.modes_said()["web-1"]),
                                 ("own", {"mode": "full", "at": t - 100}))
        self.serve(auto)
        self.assertEqual((self.run_on()["kind"], self.door.modes_said()["web-1"]),
                         ("refused", {"mode": "auto", "at": t - 50}))

    def test_the_first_seen_rule_holds_for_a_signed_auto_too(self):
        """mode_floor: the door takes no statement from before it first saw a server under its name, an Auto as
        little as a Full access. Were an old Auto taken, its time would be the entry's, and a Full access between
        that time and the door's first sight of the server would be newer than it. And the time of a signed Auto
        that the door did take stays the floor of the name through a new host key and through the server's leave."""
        t = round(time.time())
        self.door.access()
        first = self.kept()
        self.assertEqual((first["mode"], "statement" in first, self.door.modes_said()["web-1"]),
                         ("auto", False, {"mode": "auto", "at": None}))
        old_auto = self.statement("web-1", "auto", at=t - door.MODE_SKEW - 60)
        old_full = self.statement("web-1", at=t - door.MODE_SKEW - 30)             # newer than that Auto
        for served in ((old_auto,), (old_auto, old_full), (old_full, old_auto)):
            with self.subTest(served=served):
                self.serve(*served)
                self.assertEqual((self.run_on()["kind"], self.kept()), ("refused", first))
        auto = self.statement("web-1", "auto", at=t - 20)       # the Mac's clock a little behind the door's: taken
        self.serve(old_auto, old_full, auto)
        self.assertEqual((self.kept()["statement"], self.door.modes_said()["web-1"]),
                         (auto, {"mode": "auto", "at": t - 20}))
        self.serve(old_full, self.statement("web-1", at=t - 30), self.statement("web-1", at=t - 20))
        self.assertEqual((self.run_on()["kind"], self.kept()["statement"]), ("refused", auto))
        # another server under the name: the signed Auto's time stays the floor, and so through its leave and return
        self.file_with(lambda d: d["hosts"]["web-1"].update(host_key=KEY2))
        self.serve(old_full, auto, self.statement("web-1", at=t - 20))
        kept = self.kept()
        self.assertEqual((kept["mode"], kept["host_key"], kept["after"], "statement" in kept), ("auto", KEY2, t - 20, False))
        self.file_with(lambda d: (d["hosts"].pop("web-1"), d["agents"]["ops-one"]["servers"].pop("web-1")))
        self.serve(self.statement("web-1", at=t - 20))
        self.assertEqual(self.kept(), {"mode": "ended", "at": kept["at"], "after": t - 20})
        self.assertNotIn("web-1", self.door.modes_said())
        self.file_with(lambda d: (d["hosts"].update({"web-1": dict(ACCESS["hosts"]["web-1"], host_key=KEY)}),
                                  d["agents"]["ops-one"]["servers"].update({"web-1": "fix"})))
        self.serve(old_full, auto, self.statement("web-1", at=t - 20))
        self.assertEqual((self.run_on()["kind"], self.kept()["mode"], self.kept()["after"]), ("refused", "auto", t - 20))
        self.serve(self.statement("web-1", at=t - 19))                              # the owner's newer statement
        self.assertEqual(self.run_on()["kind"], "own")

    def test_only_the_owner_key_signs_a_mode_of_this_fleet_s_host(self):
        from test_vault_central import owner_point
        phone = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
        cert = vault.canonical({"v": 1, "kind": "owner-device", "fleet": "fleet-1", "device": "iphone",
                                "key": owner_point(phone), "at": round(time.time())})
        devices = [{"device": "iphone", "statement": cert, "signature": self.sign(cert)}]
        self.door.http = lambda method, url, headers, body: \
            (200, {"approvals": [], "devices": devices, "modes": self.modes}) if url.endswith("/door/approvals") \
            else (404, {})
        said = self.statement("web-1")
        wrong = [(said, self.sign(said, phone)),                             # a certified phone signs no mode
                 (self.statement("web-1", fleet="fleet-2"), None),
                 (self.statement("web-9"), None),                            # no host of the file
                 (self.statement("web-1", mode="root"), None),
                 (self.statement("web-1", at=round(time.time()) + 3600), None),
                 (json.dumps({"v": 1, "kind": "door-mode", "fleet": "fleet-1", "host": "web-1", "mode": "full",
                              "at": round(time.time())}), None)]                # not canonical
        self.modes = [{"statement": st, "signature": sig or self.sign(st)} for st, sig in wrong]
        door.fetch_approvals(self.door)
        kept = door.read_json(door.MODES_FILE, {}).values()       # what the door made when it first saw each host
        self.assertEqual(({e["mode"] for e in kept}, [e for e in kept if "statement" in e]), ({"auto"}, []))
        self.assertEqual(self.run_on()["kind"], "refused")

    def test_full_access_never_reaches_rule_only_the_never_list_read_or_another_business(self):
        for host in ("ci-1", "fleet-1", "site-1", "logs-1", "web-2"):
            self.mode(host)
        for address, host in ((ONE, "ci-1"), (ONE, "fleet-1"), (ONE, "site-1"), (ONE, "logs-1"), (ONE, "web-2")):
            with self.subTest(host=host):
                got = self.run_on(host, address)
                self.assertEqual(got["kind"], "refused")
                self.assertNotIn("full_access", got)
        self.assertEqual(self.run_on("web-2", TWO)["kind"], "own")     # its own business's agent at Fix
        # the door's own word says Full access only where full_access says it for an agent, so the two agree
        said = self.door.modes_said()
        self.assertEqual({host: said[host] for host in ("ci-1", "fleet-1", "site-1", "logs-1")},
                         {host: {"mode": "auto", "at": None} for host in ("ci-1", "fleet-1", "site-1", "logs-1")})
        self.assertEqual(said["web-2"]["mode"], "full")
        for host, word in said.items():
            holders = [a for a, me in self.door.access()["agents"].items() if (me.get("servers") or {}).get(host) == "fix"]
            self.assertEqual(word["mode"] == "full",
                             any(self.door.full_access(self.door.access(), host, a) for a in holders), host)
        data = json.loads(json.dumps(door.read_json(door.ACCESS_FILE, {})))
        data["hosts"]["web-2"]["mode"] = "rule-only"                    # a mode statement never lifts Patch only
        self.write_access(data)
        self.assertEqual(self.door.modes_said()["web-2"], {"mode": "auto", "at": None})
        self.assertEqual(self.run_on("web-2", TWO)["why"],
                         "web-2 is rule-only: only rule forms run there, and no file install")
        self.assertFalse(self.door.full_access(self.door.access(), "web-2", "ops-two"))
        self.assertEqual(self.stubs.ssh_calls[-2:], [("100.64.2.1", "run", [], SCRIPT),
                                                      ("100.64.2.1", "timer", ["cancel"], None)])

    def test_the_refusal_names_both_answers_and_a_yes_waits_while_full_access_holds(self):
        call = call_hash("web-1", "run", SCRIPT)
        got = self.run_on()
        self.assertEqual((got["route"], got["call"], got["full_access"]), ("yes", call, "web-1"))
        self.assertTrue(got["why"].endswith(door.FULL_NOTE.format(host="web-1")), got["why"])
        line = ops.route_line(got, "web-1")
        self.assertIn(f"door_call {call} and door_host web-1", line)
        self.assertIn("after Full access on web-1, it and every later root script there run", line)
        self.yes(call)
        t = round(time.time())
        self.mode("web-1", at=t - 10)
        self.assertEqual(self.run_on()["kind"], "own")                 # Full access, and the yes stays unused
        self.mode("web-1", "auto", at=t)
        self.assertEqual(self.run_on()["kind"], "approved")
        self.assertEqual(self.run_on()["kind"], "refused")

    def file_with(self, change_):
        """The access file of now with one change, written as root's command leaves it."""
        data = json.loads(json.dumps(door.read_json(door.ACCESS_FILE, {})))
        change_(data)
        self.write_access(door.validate_access(data))
        return data

    def kept(self):
        return door.read_json(door.MODES_FILE, {})["web-1"]

    def test_a_new_server_with_the_name_of_an_old_one_is_at_auto_until_a_new_statement(self):
        """A statement names its host by name only, and has no age limit. Before, a server that the owner removed
        left its Full access to the next server of that name, with no new yes. The door keeps the host key that a
        statement was accepted for, and the hub, which still serves the old statement, cannot bring it back."""
        t = round(time.time())
        old = self.mode("web-1", at=t - 100)
        self.assertEqual(self.run_on()["kind"], "own")
        self.assertEqual((self.kept()["mode"], self.kept()["host_key"]), ("full", KEY))
        self.file_with(lambda d: (d["hosts"].pop("web-1"), d["agents"]["ops-one"]["servers"].pop("web-1")))
        self.assertEqual(self.run_on()["why"], "web-1 is no host of the door")      # the first read of the new file
        self.assertEqual(self.kept(), {"mode": "ended", "at": t - 100, "after": t - 100})
        door.fetch_approvals(self.door)                                         # the hub serves the old statement
        self.assertEqual(self.kept(), {"mode": "ended", "at": t - 100, "after": t - 100})
        self.file_with(lambda d: (d["hosts"].update({"web-1": dict(ACCESS["hosts"]["web-1"], host_key=KEY2)}),
                                  d["agents"]["ops-one"]["servers"].update({"web-1": "fix"})))
        for _ in range(2):
            door.fetch_approvals(self.door)
            got = self.run_on()
            self.assertEqual((got["kind"], got["full_access"]), ("refused", "web-1"), got)
        kept = self.kept()
        self.assertEqual((kept["mode"], kept["host_key"], kept["after"], "statement" in kept),
                         ("auto", KEY2, t - 100, False))
        self.assertGreaterEqual(kept["at"], t)                                  # when the door first saw this server
        self.modes.append({"statement": self.statement("web-1", at=t - 200),       # an older one comes back no more
                           "signature": self.sign(self.statement("web-1", at=t - 200))})
        door.fetch_approvals(self.door)
        self.assertEqual(self.run_on()["kind"], "refused")
        self.assertEqual(self.modes[0]["statement"], old)
        self.mode("web-1", at=round(time.time()))                               # the owner's new yes for the new server
        self.assertEqual(self.run_on()["kind"], "own")
        self.assertEqual((self.kept()["mode"], self.kept()["host_key"]), ("full", KEY2))

    def test_a_host_key_that_changed_ends_full_access_with_no_window(self):
        """The same name, another server, and no read of a file without it in between: the first call ends the mode,
        and full_access itself refuses a kept mode whose key is not the host's, before any file of modes is settled."""
        self.mode("web-1")
        self.assertEqual(self.run_on()["kind"], "own")
        before = self.kept()
        data = json.loads(json.dumps(door.read_json(door.ACCESS_FILE, {})))
        data["hosts"]["web-1"]["host_key"] = KEY2
        self.assertTrue(self.door.full_access(self.door.access(), "web-1", "ops-one"))
        self.assertFalse(self.door.full_access(door.validate_access(data), "web-1", "ops-one"))
        self.assertEqual(self.kept(), before)
        self.write_access(data)
        self.assertEqual(self.run_on()["kind"], "refused")
        kept = self.kept()
        self.assertEqual((kept["mode"], kept["host_key"], kept["after"], "statement" in kept),
                         ("auto", KEY2, before["at"], False))
        self.file_with(lambda d: d["hosts"]["web-1"].update(host_key=KEY))      # the old key again is no way back
        door.fetch_approvals(self.door)
        self.assertEqual(self.run_on()["kind"], "refused")
        kept = self.kept()
        self.assertEqual((kept["mode"], kept["host_key"], kept["after"]), ("auto", KEY, before["at"]))
        self.assertEqual(self.run_on("web-2", TWO)["kind"], "refused")          # and no other host got a mode from it

    def test_a_mode_that_the_code_before_kept_goes_with_the_host_s_key_of_now(self):
        """An entry with no key is from the code before this rule. The door cannot know which server it was signed
        for: it binds it to the host's key of now at its first read of the access file, or at the next refresh."""
        said = self.mode("web-1")
        legacy = dict(door.read_json(door.MODES_FILE, {}),
                      **{"web-1": {k: v for k, v in self.kept().items() if k != "host_key"}})
        self.assertEqual(legacy["web-1"]["statement"], said)
        for settle in (lambda: door.Door(conf={"address": "127.0.0.1"}, http=self.door.http).access(),
                       lambda: door.fetch_approvals(self.door)):
            with self.subTest(settle=settle):
                door.write_json(door.MODES_FILE, legacy)
                self.assertFalse(self.door.full_access(self.door.access(), "web-1", "ops-one"))
                settle()
                self.assertEqual(self.kept(), dict(legacy["web-1"], host_key=KEY))
                self.assertEqual(self.run_on()["kind"], "own")
        legacy["gone-1"] = dict(legacy["web-1"])            # and one of a host that the file no longer has ends
        door.write_json(door.MODES_FILE, legacy)
        door.fetch_approvals(self.door)
        at = legacy["web-1"]["at"]
        self.assertEqual(door.read_json(door.MODES_FILE, {})["gone-1"], {"mode": "ended", "at": at, "after": at})

    def test_a_statement_from_before_the_door_first_saw_the_server_is_never_taken(self):
        """The door keeps, for every host of its file, when it first saw that name with its host key. Before, a door
        with no entry for a name took any statement for it, however old: one that the hub held back until after the
        server was replaced, and every one that the hub still serves to a door that is new or lost its file."""
        t = round(time.time())
        self.door.access()
        first = door.read_json(door.MODES_FILE, {})
        self.assertEqual(set(first), set(self.door.access()["hosts"]))
        for name, entry in first.items():
            self.assertEqual((entry["mode"], entry["host_key"], sorted(entry)),
                             ("auto", KEY, ["at", "host_key", "mode"]))
            self.assertLessEqual(abs(entry["at"] - t), 5)
        self.mode("web-1", at=t - door.MODE_SKEW - 60)          # signed for the server that had this name before
        self.assertEqual((self.run_on()["kind"], self.kept()), ("refused", first["web-1"]))
        recent = self.mode("web-1", at=t - 20)                  # the Mac's clock a little behind the door's
        self.assertEqual((self.run_on()["kind"], self.kept()["statement"]), ("own", recent))
        os.remove(self.root + door.MODES_FILE)                  # a door that lost its file, an hour later
        later = time.time() + 3600
        with patch.object(door, "now", lambda: later):
            door.fetch_approvals(self.door)                     # the hub serves both statements still
            self.assertEqual(self.run_on()["kind"], "refused")
            self.assertEqual(self.kept(), {"mode": "auto", "at": round(later), "host_key": KEY})
            self.mode("web-1", at=round(later) - 5)             # the owner's yes of now
            self.assertEqual(self.run_on()["kind"], "own")

    def test_the_file_of_modes_holds_one_entry_for_each_name_and_nothing_else(self):
        """What is no entry is dropped, a name that left the file keeps only its times, and neither is Full access."""
        self.mode("web-1")
        modes = door.read_json(door.MODES_FILE, {})
        modes.update({"text-1": "full", "list-1": ["full"], "left-1": dict(modes["web-1"]),
                      "ended-1": {"mode": "ended", "at": 5}, "auto-9": {"mode": "auto", "at": 7, "host_key": KEY}})
        door.write_json(door.MODES_FILE, modes)
        door.fetch_approvals(self.door)
        kept = door.read_json(door.MODES_FILE, {})
        self.assertEqual(set(kept), set(self.door.access()["hosts"]) | {"left-1", "ended-1", "auto-9"})
        at = modes["web-1"]["at"]
        self.assertEqual((kept["left-1"], kept["ended-1"], kept["auto-9"]),
                         ({"mode": "ended", "at": at, "after": at}, {"mode": "ended", "at": 5},
                          {"mode": "ended", "at": 7}))
        door.fetch_approvals(self.door)
        self.assertEqual(door.read_json(door.MODES_FILE, {}), kept)
        for mode in ("auto", "ended"):
            door.write_json(door.MODES_FILE, dict(kept, **{"web-1": dict(kept["web-1"], mode=mode)}))
            self.assertFalse(self.door.full_access(self.door.access(), "web-1", "ops-one"))


class Routes(Served):
    """The door-modes proposal, step 1: each refusal of the door names its route, and ops prints it under the
    refusal: the agent that holds the grant (by the name that needs_access takes), the owner's yes with the call hash,
    the owner's window, the same call again, or none."""

    def route(self, *argv, address=ONE):
        code, out = self.ops(*argv, address=address)
        lines = out.rstrip("\n").split("\n")
        self.assertEqual((code, len(lines)), (3, 2), out)
        self.assertTrue(lines[0].startswith("refused: "), out)
        return lines[1]

    def test_the_agent_that_holds_it(self):
        self.assertEqual(self.route("web-1", "restart", "nginx", address=TWO),
                         "route: the agent that holds it. Ask your requester with ask_my_requester and needs_access "
                         "server:web-1 and needs_level fix: the hub names the agent that holds it, and the manager "
                         "gives this part of the work to that agent.")
        self.assertIn("needs_access server:logs-1 and needs_level fix:", self.route("logs-1", "restart", "nginx"))
        self.assertEqual(self.route("cloudflare:one", "zones", address=TWO),
                         "route: the agent that holds it. Ask your requester with ask_my_requester: the manager gives "
                         "this part of the work to the agent that holds cloudflare:one.")

    def test_none_the_owner_s_window_and_again(self):
        none = ("route: none. No grant and no yes of the owner lets this call through: change the call, or plan "
                "another way.")
        self.assertEqual(self.route("web-1", "exec", "flock", "/run/lock/x.lock", "true"), none)
        self.assertEqual(self.route("ci-1", "install", "htop"), none)
        self.assertEqual(self.route("site-1", "uptime"), none)
        self.door.clock = lambda: datetime.datetime(2026, 11, 2, 22, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(self.route("web-1", "restart", "nginx"),
                         "route: the owner's window. Send the same call again when the window allows it.")
        with patch.object(door_targets, "decide", side_effect=door_providers.Stop("GitHub did not answer")):
            self.assertEqual(self.route("web-1", "uptime"),
                             "route: the same call again later. The door could not check it now.")
        self.assertEqual(self.stubs.ssh_calls, [])

    def test_the_owner_s_yes_names_the_call_hash(self):
        path = os.path.join(self.root, "fix.sh")
        with open(path, "wb") as f:
            f.write(SCRIPT)
        call = call_hash("web-1", "run", SCRIPT)
        self.assertEqual(self.route("web-1", "run", "--content", path),
                         f"route: the owner's yes. Ask your requester with ask_my_requester and this call hash, "
                         f"{call}: the manager raises a Needs-you item with door_call {call} and door_host web-1. Put "
                         f"the whole script in your question, character for character: the manager gives it as "
                         f"door_script, and the owner's Mac signs Run it once only for the script that its card shows. "
                         f"After the owner's Run it once, this same call runs once; after Full access on web-1, it and "
                         f"every later root script there run. Then send this same call again.")
        self.assertEqual(ops.route_line({"route": "yes", "call": call}, "hetzner:one"),        # a delete of D25
                         f"route: the owner's yes. Ask your requester with ask_my_requester and this call hash, "
                         f"{call}: the manager raises a Needs-you item with door_call {call}, and after the owner's "
                         f"yes you send this same call again, which then runs once.")

    def test_a_door_of_an_older_release_gives_the_hash_alone(self):
        self.assertTrue(ops.route_line({"call": "a" * 64}, "web-1").startswith("route: the owner's yes. "))
        self.assertIsNone(ops.route_line({}, "web-1"))
        self.assertIsNone(ops.route_line({"route": "yes"}, "web-1"))


CF, HZ, B2 = "https://api.cloudflare.com/client/v4", "https://api.hetzner.cloud/v1", "https://api.b2.example/b2api/v3/"
AZ_SUB = "/subscriptions/00000000-0000-4000-8000-000000000000"
PROVIDERS_ANSWER = [
    (("GET", "https://api.backblazeb2.com/b2api/v3/b2_authorize_account"),
     (200, {"apiInfo": {"storageApi": {"apiUrl": "https://api.b2.example"}}, "authorizationToken": "b2-session",
            "accountId": "acc1"})),
    (("POST", "https://login.microsoftonline.com/"), (200, {"access_token": "azure-session"})),
    (("POST", "https://api.tailscale.com/api/v2/oauth/token"), (200, {"access_token": "tailscale-session"})),
    (("POST", f"{CF}/zones/{ZONE}/dns_records"), (200, {"result": {"id": "r1"}})),
    (("DELETE", f"{CF}/zones/{ZONE}/dns_records/r1"), (200, {"result": {"id": "r1"}})),
    (("POST", f"{HZ}/servers"), (201, {"server": {"id": 42}, "root_password": None})),
    (("DELETE", f"{HZ}/servers/42"), (200, {"action": {"id": 1}})),
    (("POST", B2 + "b2_create_bucket"), (200, {"bucketId": "bk1"})),
    (("POST", B2 + "b2_delete_bucket"), (200, {"bucketId": "bk1"})),
    (("PUT", f"https://management.azure.com{AZ_SUB}/resourceGroups/Web"), (201, {"id": "rg"})),
    (("DELETE", f"https://management.azure.com{AZ_SUB}/resourcegroups/web"), (202, {})),
    (("DELETE", "https://api.tailscale.com/api/v2/device/n1234567"), (200, {}))]


def provider_http(stubs):
    """The stubbed providers of PROVIDERS_ANSWER, recorded as the door sent them; the model as Stubs answers it."""
    def http(method, url, headers, data):
        for (m, start), answer in PROVIDERS_ANSWER:
            if m == method and url.startswith(start):
                stubs.http_calls.append((method, url, headers, data))
                return answer
        return stubs.http(method, url, headers, data)
    return http


class MadeDeletes(DoorCase):
    """The coordinator's change to D25 (6 November 2026): a delete runs as the agent's own call only when the door's
    own record shows that an agent made its target through the door. Any other delete is the owner's: the call is
    refused with its hash for a Needs-you item."""
    DELETES = [("cloudflare:one", "change", ["DELETE", f"/zones/{ZONE}/dns_records/r1"], None),
               ("hetzner:one", "change", ["DELETE", "/servers/42"], None),
               ("hetzner:one", "change", ["POST", "/servers/42/actions/disable_backup"], None),
               ("azure:one", "change", ["DELETE", f"{AZ_SUB}/resourcegroups/web", "2021-04-01"], None),
               ("backblaze:one", "change", ["b2_delete_bucket"], b'{"bucketId": "bk1"}'),
               ("backblaze:one", "change", ["b2_hide_file"], b'{"bucketId": "bk1", "fileName": "db.tar"}'),
               ("backblaze:one", "key-revoke", ["k-other"], None),
               ("tailscale:net", "change", ["DELETE", "/device/n1234567"], None),
               ("tailscale:net", "delete", ["n1234567"], None)]

    def setUp(self):
        super().setUp()
        self.door.http = provider_http(self.stubs)

    def test_a_delete_of_what_no_agent_made_is_the_owner_s_and_no_model_reads_it(self):
        for target, op, args, content in self.DELETES:
            with self.subTest(target=target, op=op, args=args):
                got = self.call(ONE, target, op, *args, content=content)
                self.assertEqual(got["kind"], "refused", got)
                self.assertIn("which no agent made through the door", got["why"])
                self.assertIn(f"Its call hash is {got['call']}", got["why"])
        self.assertEqual(self.stubs.model_calls(), [])
        self.assertEqual(self.stubs.http_calls, [])
        self.assertEqual({e["kind"] for e in self.door.record.after(0)}, {"refused"})

    def test_a_delete_of_what_an_agent_made_runs_as_the_agent_s_own_call(self):
        made = [("cloudflare:one", ["POST", f"/zones/{ZONE}/dns_records"], b'{"type": "A", "name": "x", "content": '
                 b'"192.0.2.1"}', ["DELETE", f"/zones/{ZONE}/dns_records/r1"], None),
                ("hetzner:one", ["POST", "/servers"], b'{"name": "web-9", "ssh_keys": ["ops"]}',
                 ["DELETE", "/servers/42"], None),
                ("backblaze:one", ["b2_create_bucket"], b'{"bucketName": "logs", "bucketType": "allPrivate"}',
                 ["b2_delete_bucket"], b'{"bucketId": "bk1"}'),
                ("azure:one", ["PUT", f"{AZ_SUB}/resourceGroups/Web", "2021-04-01"], b'{"location": "westeurope"}',
                 ["DELETE", f"{AZ_SUB}/resourcegroups/web", "2021-04-01"], None)]
        for target, make, body, delete, delete_body in made:
            with self.subTest(target=target):
                got = self.call(ONE, target, "change", *make, content=body)
                self.assertTrue(got["ok"], got)
                got = self.call(ONE, target, "change", *delete, content=delete_body)
                self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
                self.assertEqual(self.door.record.after(0)[-1]["kind"], "own")
        self.assertEqual(self.stubs.model_calls(), [])
        self.assertEqual(door.read_json(door.MADE_FILE, {})["hetzner:one"].keys(), {"/servers/42"})

    def test_what_one_account_made_is_not_made_in_another(self):
        self.assertTrue(self.call(ONE, "cloudflare:one", "change", "POST", f"/zones/{ZONE}/dns_records",
                                  content=b'{"type": "A"}')["ok"])
        got = self.call(TWO, "cloudflare:two", "change", "DELETE", f"/zones/{ZONE}/dns_records/r1")
        self.assertEqual(got["kind"], "refused")
        self.assertIn("which no agent made through the door", got["why"])

    def test_every_aws_delete_is_the_owner_s_and_no_model_or_aws_reads_it(self):
        got = self.call(ONE, "aws:one", "call", "ec2", "TerminateInstances",
                        content=b'{"InstanceId.1": "i-0123456789abcdef0"}')
        self.assertEqual(got["kind"], "refused", got)
        self.assertIn("every AWS delete is the owner's", got["why"])
        self.assertIn(f"Its call hash is {got['call']}", got["why"])
        self.assertEqual((self.stubs.model_calls(), self.stubs.http_calls), ([], []))

    def test_a_key_the_door_minted_is_made(self):
        door.write_json(door.MINTED_FILE, {"k-minted": {"at": 1}, "kMinted123": {"at": 1}})
        got = self.call(ONE, "tailscale:net", "oauth-client", "revoke", "kOther123")
        self.assertIn("which no agent made through the door", got["why"])
        self.assertEqual(self.call(ONE, "tailscale:net", "oauth-client", "revoke", "kMinted123")["kind"], "own")
        self.assertEqual(self.call(ONE, "backblaze:one", "key-revoke", "k-minted")["kind"], "rule")

    def test_a_key_that_the_door_revoked_leaves_its_minted_list_and_its_secret(self):
        self.door.keep_minted({"applicationKeyId": "k-minted", "applicationKey": "SECRET-NEW", "keyName": "web-1"})
        self.assertTrue(self.door.minted("k-minted"))
        stubbed = self.door.http

        def http(method, url, headers, data):
            if method == "POST" and url == B2 + "b2_delete_key":
                return 200, {"applicationKeyId": "k-minted", "keyName": "web-1"}
            return stubbed(method, url, headers, data)
        self.door.http = http
        got = self.call(ONE, "backblaze:one", "key-revoke", "k-minted")
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)
        self.assertFalse(self.door.minted("k-minted"))
        with self.assertRaisesRegex(door_providers.Stop, "holds no value of k-minted"):
            self.door.minted_secret("k-minted")


class HostPath(DoorCase):
    """Plan N1: a file install on the whole path, with no stub of the door's ssh. The door's own ssh_call makes the
    command, ops-read reads it as the forced command of the second sshd, and ops-root installs the file. Only the two
    programs are this test's, in this process: `ssh` gives the last word of its command to ops-read as
    SSH_ORIGINAL_COMMAND, with the session's stdin, and `sudo` runs ops-root with its request and that stdin."""

    def setUp(self):
        super().setUp()
        self.host = os.path.realpath(tempfile.mkdtemp(prefix="ops-host-"))      # macOS: /var is /private/var
        self.addCleanup(shutil.rmtree, self.host, True)
        for folder in ("/etc/ops-root", "/run", "/etc/nginx"):
            os.makedirs(self.host + folder)
        with open(self.host + door_targets.OPS_ROOT.MODE_FILE, "w") as f:
            f.write("fix\n")
        for patcher in (patch.object(door_targets.OPS_ROOT, "ROOT", self.host),
                        patch.object(door, "run_program", self.sshd)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.door = door.Door(conf={"address": "127.0.0.1"}, http=self.stubs.http, clock=lambda: self.clock_at)
        self.commands = []

    def sshd(self, argv, stdin, env, timeout=600, limit=None):
        """ssh to the host, and its second sshd, whose forced command is ops-read."""
        self.commands.append(argv)
        out = io.StringIO()
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": argv[-1]}), \
                patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin or b""))), \
                patch.object(door_targets.OPS_READ.subprocess, "run", self.sudo), contextlib.redirect_stdout(out):
            status = door_targets.OPS_READ.main()
        return status, out.getvalue()

    def sudo(self, argv, stdin=None, env=None):
        """sudo -n with the one sudoers line of ops-agent: ops-root, with the request and the session's stdin."""
        self.assertEqual(argv[:3], ["sudo", "-n", door_targets.OPS_ROOT.SELF])
        with patch.object(sys, "stdin", stdin):
            status = door_targets.OPS_ROOT.main(argv[2:])
        return subprocess.CompletedProcess(argv, status)

    def test_a_file_install_reaches_ops_root_with_the_sha256_of_its_bytes(self):
        data = b"server { listen 8080; }\n"
        me = pwd.getpwuid(os.getuid()).pw_name
        got = self.call(ONE, "web-1", "file", "/etc/nginx/shop.conf", "0640", me, content=data)
        self.assertEqual((got["ok"], got["kind"], got.get("out")),
                         (True, "own", f"/etc/nginx/shop.conf installed ({len(data)} bytes)\n"), got)
        self.assertEqual(slurp(self.host + "/etc/nginx/shop.conf"), data)
        self.assertEqual(os.stat(self.host + "/etc/nginx/shop.conf").st_mode & 0o777, 0o640)
        argv = self.commands[0]
        self.assertEqual((argv[0], argv[-2]), ("ssh", "ops-agent@100.64.1.1"))
        self.assertEqual(json.loads(base64.b64decode(argv[-1])),
                         {"v": 1, "op": "file", "args": ["/etc/nginx/shop.conf", "0640", me],
                          "sha256": hashlib.sha256(data).hexdigest()})


class AppSettingsPath(HostPath):
    """New-projects plan N4 on the whole path: env-new and env-add take no value from the caller. The door sends 32
    random bytes, or the key that the owner saved for the door as app:<app>:<NAME>, on the host's stdin, and neither
    the answer nor the record shows it. unit-new sends the unit with its sha256."""
    KEY = 'sk_test_a"b$c'

    def setUp(self):
        super().setUp()
        data = json.loads(json.dumps(ACCESS))
        data["credentials"]["app:shop:STRIPE_SECRET_KEY"] = {"secret": ref(11)}
        data["agents"]["ops-one"]["providers"].append("app:shop:STRIPE_SECRET_KEY")
        self.write_access(data)
        with open(os.path.join(self.root + door.SECRETS_DIR, hashlib.sha256(ref(11).encode()).hexdigest()), "w") as f:
            f.write(self.KEY + "\n")
        for folder in ("/etc/ops-root/apps", "/var/www/shop/shared", "/etc/systemd/system"):
            os.makedirs(self.host + folder, exist_ok=True)
        with open(self.host + "/etc/ops-root/apps/shop.json", "w") as f:
            json.dump({"app": "shop", "port": 8080, "health": "/api/health"}, f)
        with open(os.open(self.host + "/var/www/shop/shared/.env", os.O_WRONLY | os.O_CREAT, 0o600), "w"):
            pass
        self.sent = []
        real = self.sshd

        def sshd(argv, stdin, env, timeout=600, limit=None):
            self.sent.append(stdin)
            return real(argv, stdin, env, timeout)
        patcher = patch.object(door, "run_program", sshd)
        patcher.start()
        self.addCleanup(patcher.stop)

    def settings(self):
        return slurp(self.host + "/var/www/shop/shared/.env", "r")

    def test_env_new_sends_the_door_s_random_bytes_or_the_owner_s_key(self):
        first = self.call(ONE, "web-1", "env-new", "shop", "SESSION_SECRET", "random")
        self.assertEqual((first["ok"], first["kind"]), (True, "rule"), first)
        value = self.sent[-1].decode()
        self.assertEqual(len(base64.b64decode(value, validate=True)), 32)
        self.assertEqual(self.settings(), f"SESSION_SECRET={value}\n")
        second = self.call(ONE, "web-1", "env-new", "shop", "STRIPE_SECRET_KEY", "key")
        self.assertEqual((second["ok"], second["kind"]), (True, "rule"), second)
        self.assertEqual(self.sent[-1], self.KEY.encode())
        self.assertEqual(self.settings(), f'SESSION_SECRET={value}\nSTRIPE_SECRET_KEY="sk_test_a\\"b\\$c"\n')
        for said in (json.dumps([first, second]), slurp(self.root + door.RECORD_FILE, "r")):
            self.assertNotIn("sk_test", said)
            self.assertNotIn(value, said)

    def test_env_new_takes_no_value_and_no_key_that_is_not_the_caller_s(self):
        got = self.call(ONE, "web-1", "env-new", "shop", "SESSION_SECRET", "random", content=b"mine")
        self.assertIn("takes no content: the door makes the value", got["why"])
        got = self.call(ONE, "web-1", "env-new", "shop", "OTHER_KEY", "key")
        self.assertIn("no key of yours is saved for the door as app:shop:OTHER_KEY", got["why"])
        got = self.call(TWO, "web-2", "env-new", "shop", "STRIPE_SECRET_KEY", "key")
        self.assertIn("no key of yours is saved for the door as app:shop:STRIPE_SECRET_KEY", got["why"])
        self.assertEqual(self.sent, [])
        data = json.loads(json.dumps(door.read_json(door.ACCESS_FILE, {})))
        data["credentials"]["app:shop:STRIPE_SECRET_KEY"] = {"secret": ref(4)}      # hetzner:one's key
        self.write_access(data)
        got = self.call(ONE, "web-1", "env-new", "shop", "STRIPE_SECRET_KEY", "key")
        self.assertIn("a key that the door uses for something else", got["why"])
        self.assertEqual(self.sent, [])

    def test_env_add_after_the_first_release_is_the_agent_s_own_call_and_its_value_stays_the_door_s(self):
        os.symlink("releases/one", self.host + "/var/www/shop/current")
        got = self.call(ONE, "web-1", "env-new", "shop", "STRIPE_SECRET_KEY", "key")
        self.assertFalse(got["ok"])
        self.assertIn("shop has a release: env-add adds a setting now", got["why"])
        got = self.call(ONE, "web-1", "env-add", "shop", "STRIPE_SECRET_KEY", "key")
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        line = self.door.record.after(0)[-1]
        self.assertEqual((line["action"], line["kind"], line["why"]),
                         ("env-add", "own", "ops-one's own call, which it answers for: the host form env-add"))
        self.assertNotIn("sk_test", json.dumps(got) + json.dumps(self.door.record.after(0)))
        self.assertEqual(self.stubs.model_calls(), [])
        self.assertIn('STRIPE_SECRET_KEY="sk_test_a', self.settings())

    def test_unit_new_sends_the_unit_with_its_sha256(self):
        import test_host_parts
        unit = test_host_parts.UNIT.encode()
        record = __import__("collections").namedtuple("pw", "pw_uid pw_gid pw_shell")
        ran = []

        def run(argv, stdin=None, timeout=900, env=None):
            ran.append(argv)
            return (0, "not-found\n") if "--property=LoadState" in argv else (0, "")
        with patch.object(door_targets.OPS_ROOT, "run", run), \
                patch.object(door_targets.OPS_ROOT.pwd, "getpwnam", lambda name: record(os.getuid(), os.getgid(), "")):
            self.assertIn("takes its bytes as the call's content", self.call(ONE, "web-1", "unit-new", "shop")["why"])
            got = self.call(ONE, "web-1", "unit-new", "shop", content=unit)
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        self.assertEqual(slurp(self.host + "/etc/systemd/system/shop.service"), unit)
        self.assertEqual(json.loads(base64.b64decode(self.commands[-1][-1])),
                         {"v": 1, "op": "unit-new", "args": ["shop"], "sha256": hashlib.sha256(unit).hexdigest()})
        self.assertIn(["systemctl", "--no-pager", "--no-ask-password", "enable", "shop.service"], ran)


class ScriptPath(Signed, HostPath):
    """The door-modes proposal, steps 2 and 3, on the whole path: the door, ops-read as the second sshd's forced
    command and ops-root, with only systemd stood in. A script with flock runs in the box as the agent's own call; a
    run is refused with its hash until the owner's signed yes, which runs it once as root with no box; after each,
    the door's cancel ends the countdown that ops-root armed."""

    def setUp(self):
        super().setUp()
        self.signed_setup()
        self.services = []
        root = door_targets.OPS_ROOT
        for patcher in (patch.object(root, "arm_timer", self.arm), patch.object(root, "run", self.systemd)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def arm(self):
        os.makedirs(self.host + door_targets.OPS_ROOT.STATE + "/rollback", exist_ok=True)
        return "the rollback timer is armed"

    def systemd(self, argv, stdin=None, timeout=900, env=None):
        """A script's transient service, as systemd-run starts it, and the stop of the timer's unit."""
        if argv[0] == "systemd-run":
            with open(self.host + argv[-1], "rb") as f:
                self.services.append((argv, f.read()))
            return 0, "3\n"
        return 0, ""

    def requests(self):
        return [json.loads(base64.b64decode(argv[-1])) for argv in self.commands]

    def test_a_script_with_flock_runs_in_the_box_and_the_door_ends_its_countdown(self):
        got = self.call(ONE, "web-1", "script", content=SCRIPT)
        self.assertEqual((got["ok"], got["kind"], got.get("out")),
                         (True, "own", "the rollback timer is armed\n3\nthe rollback timer is off\n"), got)
        (argv, script), = self.services
        self.assertEqual(script, SCRIPT)
        self.assertIn("InaccessiblePaths=-/var/www", argv)
        self.assertIn("StateDirectory=ops-backups", argv)
        self.assertEqual(self.requests(), [{"v": 1, "op": "script", "args": [],
                                            "sha256": hashlib.sha256(SCRIPT).hexdigest()},
                                           {"v": 1, "op": "timer", "args": ["cancel"]}])
        self.assertFalse(os.path.exists(self.host + door_targets.OPS_ROOT.STATE + "/rollback"))

    def test_a_run_waits_for_the_owner_s_yes_and_runs_once_as_root_with_no_box(self):
        got = self.call(ONE, "web-1", "run", content=SCRIPT)
        self.assertEqual((got["kind"], got["route"], self.commands), ("refused", "yes", []))
        self.assertEqual(self.yes(got["call"], need=12), 1)
        got = self.call(ONE, "web-1", "run", content=SCRIPT)
        self.assertEqual((got["ok"], got["kind"], got.get("out")),
                         (True, "approved", "the rollback timer is armed\n3\nthe rollback timer is off\n"), got)
        (argv, script), = self.services
        self.assertEqual((script, argv[argv.index("--"):][1:2]), (SCRIPT, ["/bin/bash"]))
        self.assertNotIn("--property", argv)
        self.assertEqual([r["op"] for r in self.requests()], ["run", "timer"])
        self.assertEqual(self.call(ONE, "web-1", "run", content=SCRIPT)["kind"], "refused")
        self.assertEqual(len(self.services), 1)


class HostUpdates(HostPath):
    """Each host takes the host parts of the release that the door runs (update_hosts): before, a host kept the copy of
    its install for good, and no code sent self-update. The door keeps the signed manifest of its release, asks each
    host's help for its release, and sends self-update, with the commits down to the host's own release, only to a
    host of another release. Here on the whole path: the door's ssh, ops-read as the forced command, and ops-root's
    own check of the release key's signature, of its version and of the way down."""

    SEED = bytes(range(32))         # the test's own release key; never the product's

    def setUp(self):
        super().setUp()
        import releases
        self.releases = releases
        for folder in ("/usr/local/sbin", "/usr/local/lib/ops-root"):
            os.makedirs(self.host + folder, exist_ok=True)
        with open(self.host + door_targets.OPS_ROOT.KEY_FILE, "w") as f:
            f.write(base64.b64encode(releases.public_key(self.SEED)).decode() + "\n")
        data = json.loads(json.dumps(ACCESS))
        data["agents"] = {"ops-one": {"address": ONE, "business": "one", "servers": {"web-1": "fix", "site-1": "fix"}}}
        data["hosts"] = {name: data["hosts"][name] for name in ("web-1", "site-1")}
        data["never"] = {"hosts": ["site-1"]}
        self.write_access(data)
        self.published = os.path.join(self.root, "published")
        os.makedirs(self.published + "/host")
        self.git("init", "-q", cwd=self.published)

    def git(self, *args, cwd=None):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c",
                               "commit.gpgsign=false", *args], cwd=cwd, check=True, capture_output=True).stdout

    def release(self, extra=""):
        """One more published release: the host files of this checkout, ops-root with a line more, one commit,
        signed with the test key; and the door's code folder at that revision, as take() leaves it."""
        here = os.path.dirname(os.path.abspath(door.__file__))
        for name in door.HOST_FILES:
            data = slurp(os.path.join(here, "host", name)) + (extra.encode() if name == "ops-root" else b"")
            with open(os.path.join(self.published, "host", name), "wb") as f:
                f.write(data)
        self.git("add", "-A", cwd=self.published)
        self.git("commit", "-q", "-m", f"release {extra}", cwd=self.published)
        revision = self.git("rev-parse", "HEAD", cwd=self.published).decode().strip()
        manifest = {"revision": revision, "version": f"2026.11.{len(os.listdir(self.root))}", "notes": None,
                    "minimum": None, "hold": False}
        manifest["signature"] = base64.b64encode(
            self.releases.sign(self.SEED, self.releases.signed_text(manifest))).decode()
        code = self.root + door.CODE
        os.makedirs(code, exist_ok=True)
        self.git("clone", "-q", "--no-local", self.published, os.path.join(code, revision))
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(code, "current"))
        os.symlink(os.path.join(code, revision), os.path.join(code, "current"))
        door.keep_release(manifest)
        return manifest

    def host_file(self, path):
        return slurp(self.host + path)

    def test_each_host_takes_the_host_parts_of_the_release_that_the_door_runs(self):
        self.assertEqual(door.update_hosts(self.door), [])          # no manifest kept yet: nothing to send
        first = self.release()
        self.assertEqual(door.update_hosts(self.door), [("web-1", "done")])     # site-1 is on the never list
        root = door_targets.OPS_ROOT
        self.assertEqual(self.host_file(root.SELF), self.git("show", f"{first['revision']}:host/ops-root",
                                                             cwd=self.published))
        self.assertEqual(self.host_file(root.RELEASE_FILE).decode().strip(), first["revision"])
        line = self.door.record.after(0)[-1]
        self.assertEqual((line["caller"], line["target"], line["action"], line["kind"], line["outcome"]),
                         ("door", "web-1", "self-update", "rule", "done"))
        self.assertEqual(door.update_hosts(self.door), [])          # once for each host and release
        second = self.release(extra="# the next release\n")
        self.assertEqual(door.update_hosts(self.door), [("web-1", "done")])
        self.assertTrue(self.host_file(root.SELF).endswith(b"# the next release\n"))
        self.assertEqual(self.host_file(root.RELEASE_FILE).decode().strip(), second["revision"])
        requests = [json.loads(base64.b64decode(argv[-1]))["op"] for argv in self.commands]
        self.assertEqual(requests, ["help", "self-update", "help", "self-update"])
        self.assertEqual(door.read_json(door.HOSTS_FILE, {}),
                         {"web-1": {"revision": second["revision"], "outcome": "done",
                                    "at": door.read_json(door.HOSTS_FILE, {})["web-1"]["at"]}})

    def test_a_host_that_runs_the_release_already_gets_nothing_and_writes_no_line(self):
        manifest = self.release()
        with open(self.host + door_targets.OPS_ROOT.RELEASE_FILE, "w") as f:
            f.write(manifest["revision"] + "\n")
        self.assertEqual(door.update_hosts(self.door), [("web-1", "current")])
        self.assertEqual([json.loads(base64.b64decode(a[-1]))["op"] for a in self.commands], ["help"])
        self.assertEqual(self.door.record.after(0), [])

    def test_a_host_that_does_not_answer_is_asked_again_later_and_a_refused_one_at_the_next_release(self):
        manifest, answers, sent = self.release(), {}, []

        def ssh(host, req, stdin):
            sent.append(req["op"])
            return answers[req["op"]]
        self.door.ssh = ssh
        answers["help"] = (255, "ssh: connect to host 100.64.1.1 port 2244: Connection timed out\n")
        self.assertEqual(door.update_hosts(self.door), [("web-1", "unreachable")])
        self.assertEqual(door.update_hosts(self.door), [])                      # not again at once
        answers.update(help=(0, "ops-root 1, mode fix\nhelp ...\n"),
                       **{"self-update": (3, "refused: no release key of this host signed this release\n")})
        later = time.time() + door.HOST_RETRY + 1
        with patch.object(door, "now", lambda: later):
            self.assertEqual(door.update_hosts(self.door), [("web-1", "refused")])
            self.assertEqual(door.update_hosts(self.door), [])                  # a refusal waits for the next release
        with patch.object(door, "now", lambda: later + 2 * door.HOST_RETRY):
            self.assertEqual(door.update_hosts(self.door), [])
        line = self.door.record.after(0)[-1]
        self.assertEqual((line["outcome"], line["why"]), ("refused", "no release key of this host signed this release"))
        self.assertEqual(sent, ["help", "help", "self-update"])
        self.release(extra="# next\n")
        answers["self-update"] = (0, "ops-root 2 from release 2026.11.9\n")
        self.assertEqual(door.update_hosts(self.door), [("web-1", "done")])
        self.assertEqual(manifest["revision"] != door.read_json(door.HOSTS_FILE, {})["web-1"]["revision"], True)

    def test_a_host_whose_help_does_not_answer_in_time_is_asked_again_later(self):
        """A help that ran into its short wait is a host that did not answer, not one that failed for this release."""
        self.release()
        self.door.ssh = lambda host, req, stdin: (124, f"ssh took longer than {door.HELP_WAIT} seconds")
        self.assertEqual(door.update_hosts(self.door), [("web-1", "unreachable")])
        self.assertEqual(door.update_hosts(self.door), [])
        later = time.time() + door.HOST_RETRY + 1
        with patch.object(door, "now", lambda: later):
            self.assertEqual(door.update_hosts(self.door), [("web-1", "unreachable")])

    def test_a_held_release_is_never_kept_and_no_host_gets_one(self):
        manifest = self.release()
        os.remove(self.root + door.RELEASE_JSON)
        door.keep_release(dict(manifest, hold=True))
        self.assertFalse(os.path.exists(self.root + door.RELEASE_JSON))
        self.assertEqual(door.update_hosts(self.door), [])
        door.keep_release(manifest)
        self.assertEqual(oct(os.stat(self.root + door.RELEASE_JSON).st_mode & 0o777), "0o644")


class KeyCardAccount(DoorCase):
    """Plan N1: a Cloudflare key card gives the door the token only, with no account_id. The door gets the account
    from GET /accounts with that token, and keeps its id with the credential, so that the next call and the names of
    what the calls make and delete have it. A token that reaches no account, or more than one, stops the call."""
    ACCOUNT = "e" * 32

    def setUp(self):
        super().setUp()
        data = json.loads(json.dumps(ACCESS))
        del data["credentials"]["cloudflare:one"]["account_id"]
        self.write_access(data)
        os.remove(self.root + door.KEYS_FILE)           # this door has not asked Cloudflare what its key is
        self.accounts, self.calls = [{"id": self.ACCOUNT, "name": "One"}], []
        tunnel = f"{CF}/accounts/{self.ACCOUNT}/cfd_tunnel/{TUNNEL}"
        answers = {("GET", f"{CF}/accounts?per_page=50"): lambda: (200, {"result": self.accounts, "success": True}),
                   ("GET", f"{CF}/accounts/{self.ACCOUNT}/tokens/verify"):
                       lambda: (200, {"result": {"id": "9" * 32, "status": "active"}, "success": True}),
                   ("GET", tunnel + "/configurations"):
                       lambda: (200, {"result": {"config": {"ingress": [{"service": "http_status:404"}]}}}),
                   ("PUT", tunnel + "/configurations"): lambda: (200, {"success": True}),
                   ("GET", tunnel): lambda: (200, {"result": {"id": TUNNEL}}),
                   ("GET", f"{CF}/zones/{ZONE}/dns_records?name=app.example.com"): lambda: (200, {"result": []}),
                   ("POST", f"{CF}/zones/{ZONE}/dns_records"): lambda: (200, {"result": {"id": "r9"}}),
                   ("POST", f"{CF}/accounts/{self.ACCOUNT}/r2/buckets"): lambda: (200, {"result": {"name": "media"}}),
                   ("DELETE", f"{CF}/accounts/{self.ACCOUNT}/r2/buckets/media"): lambda: (200, {"success": True})}

        def http(method, url, headers, body):
            self.calls.append((method, url))
            if url.startswith("https://api.anthropic.com"):
                return self.stubs.http(method, url, headers, body)
            return answers.get((method, url), lambda: (404, {"success": False}))()
        self.door.http = http

    def test_the_token_s_one_account_is_kept_with_the_credential(self):
        got = self.call(ONE, "cloudflare:one", "tunnel-route", TUNNEL, "app.example.com", "3000")
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)
        self.assertEqual([c for c in self.calls if "/accounts" in c[1]],
                         [("GET", f"{CF}/accounts?per_page=50"),
                          # once a day for each saved key: Cloudflare takes it, and does it make tokens? This one
                          # does not (WorkKeys has one that does)
                          ("GET", f"{CF}/accounts/{self.ACCOUNT}/tokens/verify"),
                          ("GET", f"{CF}/accounts/{self.ACCOUNT}/tokens/permission_groups"),
                          ("GET", f"{CF}/accounts/{self.ACCOUNT}/cfd_tunnel/{TUNNEL}/configurations"),
                          ("PUT", f"{CF}/accounts/{self.ACCOUNT}/cfd_tunnel/{TUNNEL}/configurations")])
        self.assertEqual(door.read_json(door.ACCOUNTS_FILE, {}),
                         {"cloudflare:one": {"secret": ref(1), "account_id": self.ACCOUNT}})
        self.calls.clear()
        got = self.call(ONE, "cloudflare:one", "cname", ZONE, "app.example.com", TUNNEL)
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)
        self.assertNotIn(("GET", f"{CF}/accounts?per_page=50"), self.calls)        # the kept id: no second list
        # what a write made is named with the account, and so is its delete, which then runs as the agent's own call
        self.assertTrue(self.call(ONE, "cloudflare:one", "change", "POST", "/accounts/{account_id}/r2/buckets",
                                  content=b'{"name": "media"}')["ok"])
        self.assertIn(f"/accounts/{self.ACCOUNT}/r2/buckets/media",
                      door.read_json(door.MADE_FILE, {})["cloudflare:one"])
        got = self.call(ONE, "cloudflare:one", "change", "DELETE", "/accounts/{account_id}/r2/buckets/media")
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)

    def test_a_token_that_reaches_no_account_or_more_than_one_stops_the_call(self):
        for accounts, words in (([], "reaches no Cloudflare account"),
                                ([{"id": "e" * 32}, {"id": "f" * 32}], "more than one Cloudflare account")):
            with self.subTest(accounts=accounts):
                self.accounts = accounts
                got = self.call(ONE, "cloudflare:one", "tunnel-route", TUNNEL, "app.example.com", "3000")
                self.assertFalse(got["ok"], got)
                self.assertIn(words, got["why"])
                self.assertFalse([c for c in self.calls if c[0] == "PUT"])
                self.assertEqual(door.read_json(door.ACCOUNTS_FILE, {}), {})


class Cloud:
    """Cloudflare's API for tokens, as its documents give it, for the door's tests: the accounts that a token lists,
    the verify of a user's token and of an account's token, the permission groups of an account, which only a token
    with a right on that account's API tokens lists (with the documented filters `name` and `scope`), the tokens that
    such a token makes, with their rights, their one account and their end, and their delete. A read of zones passes
    only for a token with Zone Read, a read of tunnels with Cloudflare Tunnel Read, and no token of these tests
    writes a Worker. Every request is kept with the name of the token that sent it."""
    RIGHTS = [name for name, _ in door_providers.CF_KEY_RIGHTS]
    GROUPS = ([{"id": f"{n:032x}", "name": name, "scopes": [door_providers.CF_SCOPES[scope]]}
               for n, (name, scope) in enumerate(door_providers.CF_KEY_RIGHTS, 1)] +
              [{"id": "f" * 31 + "1", "name": "Account API Tokens Write", "scopes": ["com.cloudflare.api.account"]},
               {"id": "f" * 31 + "2", "name": "Workers Scripts Write", "scopes": ["com.cloudflare.api.account"]},
               # the same name in another scope is another group, which the door never takes
               {"id": "f" * 31 + "3", "name": "Zone Read", "scopes": ["com.cloudflare.api.user"]},
               # a name that holds another one: the filter gives both, and the door takes the exact one
               {"id": "f" * 31 + "4", "name": "DNS Write Extra", "scopes": ["com.cloudflare.api.account.zone"]}])
    INVALID = (401, {"success": False, "errors": [{"code": 1000, "message": "Invalid API Token"}]})
    NO = (403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]})

    def __init__(self, clock, account="e" * 32):
        self.clock, self.account, self.calls, self.made, self.fault = clock, account, [], 0, {}
        self.groups = json.loads(json.dumps(self.GROUPS))
        self.page = None            # the size of one page of the list of permission groups, when it comes in pages
        self.filters = True         # False: the list comes whole, whatever filter a request names
        # value: {name, id, owner (account or user), accounts, makes (None, "account" or "user"), rights, until, gone}
        self.tokens = {"cfat_" + "M" * 40: {"name": "maker", "id": "a" * 31 + "0", "owner": "account",
                                            "accounts": [account], "makes": "account", "rights": [], "until": None}}
        self.change = None          # what the answer of the next new token says in place of what was asked
        self.no_value = False       # the next new token's answer has an id and no value

    def token(self, **fields):
        value = f"cfat_{fields['name']}_" + "x" * 30
        self.tokens[value] = dict({"id": hashlib.sha256(value.encode()).hexdigest()[:32], "owner": "account",
                                   "accounts": [self.account], "makes": None, "rights": [], "until": None}, **fields)
        return value

    def named(self, name):
        return next(t for t in self.tokens.values() if t["name"] == name)

    def alive(self, t):
        return t is not None and not t.get("gone") and (t["until"] is None or t["until"] > self.clock())

    def http(self, method, url, headers, data):
        full = url.removeprefix("https://api.cloudflare.com/client/v4")
        path, _, query = full.partition("?")
        t = self.tokens.get(headers.get("Authorization", "")[7:])
        self.calls.append((method, path if path.endswith("/permission_groups") else full, t["name"] if t else None))
        fault = next((status for part, status in self.fault.items() if part in full), None)
        if fault:
            return fault, {"success": False, "errors": [{"message": "a fault of the stand-in"}]}
        if not self.alive(t):
            return self.INVALID
        if full == "/accounts?per_page=50":
            return 200, {"success": True, "result": [{"id": a, "name": "An account"} for a in t["accounts"]]}
        if path == "/user/tokens/verify":
            return (200, {"success": True, "result": {"id": t["id"], "status": "active"}}) \
                if t["owner"] == "user" else self.INVALID
        if path == "/user/tokens/permission_groups":
            return (200, {"success": True, "result": self.groups}) if t["makes"] == "user" else self.NO
        account, _, rest = path.removeprefix("/accounts/").partition("/")
        if path.startswith("/accounts/") and rest.startswith("tokens"):
            if rest == "tokens/verify":
                return (200, {"success": True, "result": {"id": t["id"], "status": "active"}}) \
                    if t["owner"] == "account" and account in t["accounts"] else self.INVALID
            if t["makes"] != "account" or account not in t["accounts"]:
                return self.NO
            if method == "GET" and rest == "tokens/permission_groups":
                return self.listed(urllib.parse.parse_qs(query))
            if method == "POST" and rest == "tokens":
                return self.new(account, json.loads(data))
            if method == "DELETE":
                one = next((x for x in self.tokens.values() if x["id"] == rest.removeprefix("tokens/")), None)
                if one is None or one.get("gone"):
                    return 404, {"success": False, "errors": [{"message": "no such token"}]}
                one["gone"] = True
                return 200, {"success": True, "result": {"id": one["id"]}}
        for start, right, result in (("/zones", "Zone Read", [{"id": ZONE, "name": "example.com"}]),
                                     (f"/accounts/{account}/cfd_tunnel", "Cloudflare Tunnel Read", [])):
            if method == "GET" and path.startswith(start):
                return (200, {"success": True, "result": result}) \
                    if right in t["rights"] and (start == "/zones" or account in t["accounts"]) else self.NO
        if "/workers/" in path:
            return self.NO
        return 404, {"success": False, "errors": [{"message": "not in the stand-in"}]}

    def listed(self, query):
        """The account's permission groups, by the filters when the request has them, and in pages when the test
        says so: Cloudflare's documents show a page size in the answer and name no parameter for the next page."""
        name, scope = (query.get(k, [None])[0] if self.filters else None for k in ("name", "scope"))
        found = [g for g in self.groups if (name is None or name in g["name"]) and (scope is None or scope in g["scopes"])]
        answer = {"success": True, "result": found[:self.page] if self.page else found}
        if self.page:
            answer["result_info"] = {"page": 1, "per_page": self.page, "count": len(answer["result"]),
                                     "total_count": len(found)}
        return 200, answer

    def new(self, account, body):
        names = {g["id"]: g["name"] for g in self.groups}
        self.made += 1
        until = calendar.timegm(time.strptime(body["expires_on"], "%Y-%m-%dT%H:%M:%SZ"))
        value = self.token(name=f"work{self.made}", until=until, said=body["name"], policies=body["policies"],
                           accounts=[account],
                           rights=[names[g["id"]] for p in body["policies"] for g in p["permission_groups"]])
        policies = [dict(p, id=f"{n:032x}", permission_groups=[dict(g, name=names[g["id"]], meta={})
                                                                 for g in p["permission_groups"]])
                    for n, p in enumerate(body["policies"], 1)]
        if self.change:
            policies = self.change(policies)
        result = {"id": self.tokens[value]["id"], "value": value, "name": body["name"], "status": "active",
                  "policies": policies, "expires_on": body["expires_on"]}
        if self.no_value:
            del result["value"]
        return 200, {"success": True, "result": result}

    def sent_by(self, name):
        return [(method, path) for method, path, who in self.calls if who == name]


class WorkKeys(DoorCase):
    """The key that the owner saves for a Cloudflare account can be one that only makes tokens (12 November 2026).
    The door asks Cloudflare what a saved key is, and never sends a call with a key that makes tokens: it makes its
    own work key, with the rights of door_providers.CF_KEY_RIGHTS for that one account, which Cloudflare ends after a
    day. A new key replaces it when less than an hour is left, the key before is deleted, and the key ends with the
    grant. Only a key that Cloudflare takes is asked what it is, whatever Cloudflare does not say clearly stops the
    call, and no value shows in an answer or the record."""
    T0 = 1794500000

    def setUp(self):
        super().setUp()
        self.t = self.T0
        patcher = patch.object(door, "now", lambda: self.t)
        patcher.start()
        self.addCleanup(patcher.stop)
        data = json.loads(json.dumps(ACCESS))
        del data["credentials"]["cloudflare:one"]["account_id"]     # a key card gives the door the key only
        self.data = data
        self.write_access(data)
        os.remove(self.root + door.KEYS_FILE)                       # this door has asked Cloudflare nothing yet
        self.cloud = Cloud(lambda: self.t)
        self.account = self.cloud.account
        self.maker = next(iter(self.cloud.tokens))
        self.save(self.maker)
        self.door.http = self.cloud.http
        # what the saved key may send: its questions, and the making and the end of the door's own keys
        self.asks = [("GET", "/accounts?per_page=50"), ("GET", "/user/tokens/verify"),
                     ("GET", f"/accounts/{self.account}/tokens/verify"),
                     ("GET", f"/accounts/{self.account}/tokens/permission_groups")]
        self.mints = [("GET", f"/accounts/{self.account}/tokens/permission_groups")] * len(Cloud.RIGHTS) + \
            [("POST", f"/accounts/{self.account}/tokens")]

    def save(self, value, n=1):
        with open(os.path.join(self.root + door.SECRETS_DIR, hashlib.sha256(ref(n).encode()).hexdigest()), "w") as f:
            f.write(value)

    def zones(self):
        return self.call(ONE, "cloudflare:one", "zones")

    def work(self):
        return door.read_json(door.KEYS_FILE, {}).get("work", {}).get("cloudflare:one")

    def kind(self):
        return door.read_json(door.KEYS_FILE, {}).get("kinds", {}).get("cloudflare:one")

    def lines(self, action):
        return [e for e in self.door.record.after(0) if e["action"] == action]

    def names_file(self, account):
        data = json.loads(json.dumps(self.data))
        data["credentials"]["cloudflare:one"]["account_id"] = account
        self.write_access(data)

    def test_a_key_that_makes_tokens_is_never_sent_with_a_call(self):
        got = self.zones()
        self.assertEqual((got["ok"], got["kind"]), (True, "read"), got)
        # the saved key asks what it is, makes the work key and nothing else; the work key signs in and makes the call
        self.assertEqual(self.cloud.sent_by("maker"), self.asks + self.mints)
        self.assertEqual(self.cloud.sent_by("work1"),
                         [("GET", f"/accounts/{self.account}/tokens/verify"), ("GET", "/zones?per_page=50")])
        made = self.cloud.named("work1")
        self.assertEqual(sorted(made["rights"]), sorted(Cloud.RIGHTS))
        self.assertEqual(made["said"], "Founderizer door: cloudflare:one")
        self.assertEqual(made["until"], self.T0 + 24 * 3600)
        resource = f"com.cloudflare.api.account.{self.account}"
        self.assertEqual([p["resources"] for p in made["policies"]],
                         [{resource: "*"}, {resource: {"com.cloudflare.api.account.zone.*": "*"}}])
        self.assertEqual([[g["id"] for g in p["permission_groups"]] for p in made["policies"]],
                         [[f"{n:032x}" for n in (6, 7)], [f"{n:032x}" for n in (1, 2, 3, 4, 5)]])
        self.assertTrue(all(p["effect"] == "allow" for p in made["policies"]))
        # the door keeps the key's id and its end, and its value only in its own secrets, for its own user
        value = next(v for v, t in self.cloud.tokens.items() if t["name"] == "work1")
        work = self.work()
        self.assertEqual((work["id"], work["until"], work["account_id"], work["secret"]),
                         (made["id"], self.T0 + 24 * 3600, self.account, ref(1)))
        self.assertEqual(work["groups"], {g["name"]: g["id"] for g in Cloud.GROUPS[:7]})
        self.assertNotIn("value", work)
        path = self.door.work_path("cloudflare:one")
        self.assertEqual((slurp(path, "r"), os.stat(path).st_mode & 0o777), (value, 0o600))
        self.assertEqual(os.listdir(os.path.dirname(path)).count(os.path.basename(path) + ".new"), 0)
        self.assertEqual(door.read_json(door.ACCOUNTS_FILE, {}),
                         {"cloudflare:one": {"secret": ref(1), "account_id": self.account}})
        self.assertEqual({k: self.kind()[k] for k in ("kind", "account_id", "named", "at")},
                         {"kind": "maker", "account_id": self.account, "named": None, "at": self.T0})
        # no value in an answer, in the record or in the door's list
        record = json.dumps(self.door.record.after(0))
        for secret in (self.maker, value, self.maker[5:], value[5:]):
            self.assertNotIn(secret, json.dumps(got) + record + slurp(self.root + door.KEYS_FILE, "r"))
        line, = self.lines("key-new")
        self.assertEqual((line["caller"], line["target"], line["kind"], line["outcome"]),
                         ("door", "cloudflare:one", "key", "done"))
        self.assertIn("7 rights for one Cloudflare account", line["why"])
        self.assertIn(made["id"], line["why"])

    def test_one_work_key_serves_its_day_and_the_next_one_replaces_it(self):
        self.assertTrue(self.zones()["ok"])
        first = self.work()["id"]
        self.cloud.calls.clear()
        self.t += 22 * 3600                 # more than an hour is left: the same key, and the saved one asks nothing
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.calls, [("GET", "/zones?per_page=50", "work1")])
        self.t += 3600 + 1                  # less than an hour is left
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.sent_by("maker"),
                         self.mints + [("DELETE", f"/accounts/{self.account}/tokens/{first}")])
        self.assertEqual(self.cloud.sent_by("work2"),
                         [("GET", f"/accounts/{self.account}/tokens/verify"), ("GET", "/zones?per_page=50")])
        self.assertTrue(self.cloud.named("work1")["gone"])
        self.assertNotEqual(self.work()["id"], first)
        self.assertEqual(self.work()["until"], self.t + 24 * 3600)
        self.assertEqual(len(self.lines("key-new")), 2)

    def test_two_calls_at_once_make_one_key(self):
        slow = self.cloud.http

        def http(method, url, headers, data):
            if method == "POST":
                time.sleep(0.2)
            return slow(method, url, headers, data)
        self.door.http = http
        got = []
        threads = [threading.Thread(target=lambda: got.append(self.zones())) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual([g["ok"] for g in got], [True] * 3, got)
        self.assertEqual(self.cloud.made, 1)

    def test_a_new_value_under_the_same_name_is_asked_again(self):
        self.assertTrue(self.zones()["ok"])
        first = self.work()["id"]
        other = self.cloud.token(name="maker2", makes="account")
        self.save(other)
        self.cloud.calls.clear()
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.sent_by("maker"), [])               # the key before sends nothing more
        self.assertEqual(self.cloud.sent_by("maker2"),
                         self.asks + self.mints + [("DELETE", f"/accounts/{self.account}/tokens/{first}")])
        self.assertEqual(self.cloud.made, 2)

    def test_a_new_value_that_cloudflare_does_not_take_yet_is_never_taken_for_a_hand_made_key(self):
        """The fault that both reviews of 12 November 2026 found: the owner saves a new key that makes tokens under
        the same reference, the door knows the account from the key before, and Cloudflare answers 401 to each
        question while it does not know the new key yet. The door took it for a hand-made key, kept that for good,
        and sent each call with it. Only a key that Cloudflare's verify takes is asked what it is."""
        self.assertTrue(self.zones()["ok"])
        mark = self.kind()["mark"]
        new = "cfat_" + "N" * 40
        self.save(new)
        # the door knows the account from the key before; then its file names the account too
        for names in (None, self.account):
            with self.subTest(names=names):
                self.names_file(names) if names else None
                self.cloud.calls.clear()
                got = self.zones()
                self.assertFalse(got["ok"], got)
                self.assertIn("Cloudflare does not take the door's key now (401", got["why"])
                self.assertFalse([c for c in self.cloud.calls if c[1].startswith("/zones")])
                self.assertEqual(self.kind()["mark"], mark)     # nothing is kept of the new value
        # The second review's case: Cloudflare's verify takes the new key already, and its question about the
        # permission groups still gets 401. That is no "it makes no tokens" either.
        self.cloud.tokens[new] = dict(self.cloud.tokens[self.maker], name="maker-new")
        self.cloud.fault = {f"/accounts/{self.account}/tokens/permission_groups": 401}
        self.cloud.calls.clear()
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("Cloudflare does not take the door's key now (401, when the door asked whether its key makes "
                      "tokens)", got["why"])
        self.assertIn(("GET", f"/accounts/{self.account}/tokens/verify"), self.cloud.sent_by("maker-new"))
        self.assertFalse([c for c in self.cloud.calls if c[1].startswith("/zones")])
        self.assertEqual(self.kind()["mark"], mark)
        self.cloud.fault = {}
        self.cloud.calls.clear()
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.kind()["kind"], "maker")
        self.assertFalse([c for c in self.cloud.sent_by("maker-new") if c[1].startswith("/zones")])
        self.assertEqual(self.cloud.calls[-1], ("GET", "/zones?per_page=50", "work2"))

    def test_a_change_of_the_rights_in_the_code_makes_a_new_key(self):
        self.assertTrue(self.zones()["ok"])
        with patch.object(door_providers, "CF_KEY_RIGHTS", door_providers.CF_KEY_RIGHTS[:5]):
            self.assertTrue(self.zones()["ok"])
        self.assertEqual(sorted(self.cloud.named("work2")["rights"]), sorted(Cloud.RIGHTS[:5]))
        self.assertTrue(self.cloud.named("work1")["gone"])

    def test_a_hand_made_key_that_makes_no_tokens_is_used_as_before(self):
        plain = self.cloud.token(name="plain", rights=["Zone Read"])
        self.save(plain)
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.sent_by("plain"), self.asks + [("GET", "/zones?per_page=50")])
        self.cloud.calls.clear()
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.calls, [("GET", "/zones?per_page=50", "plain")])    # asked once a day
        self.assertEqual((self.cloud.made, self.work(), self.lines("key-new")), (0, None, []))
        user = self.cloud.token(name="user-plain", owner="user", rights=["Zone Read"])
        self.save(user)                             # a user's hand-made token: its verify is the user's
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.sent_by("user-plain"),
                         [("GET", "/accounts?per_page=50"), ("GET", "/user/tokens/verify"),
                          ("GET", "/user/tokens/permission_groups"),
                          ("GET", f"/accounts/{self.account}/tokens/permission_groups"), ("GET", "/zones?per_page=50")])

    def test_a_key_that_makes_tokens_for_a_user_or_in_two_accounts_is_refused(self):
        many = [f"{n:032x}" for n in range(100, 109)]
        for fields, words in (({"owner": "user", "makes": "user", "accounts": [self.account]},
                               "makes tokens for its user"),
                              ({"makes": "account", "accounts": [self.account, "c" * 32]},
                               "makes tokens and reaches more than one account"),
                              ({"owner": "user", "rights": ["Zone Read"], "accounts": many},
                               "reaches more than 8 Cloudflare accounts")):
            with self.subTest(fields=fields):
                self.save(self.cloud.token(name=f"wide{len(self.cloud.tokens)}", **fields))
                self.cloud.calls.clear()
                got = self.zones()
                self.assertFalse(got["ok"], got)
                self.assertIn(words, got["why"])
                self.assertEqual((self.cloud.made, self.work(), self.kind()), (0, None, None))
                self.assertFalse([c for c in self.cloud.calls if c[1].startswith("/zones")])

    def test_a_user_s_key_that_makes_tokens_for_one_account_makes_the_work_key_there(self):
        self.save(self.cloud.token(name="user-maker", owner="user", makes="account"))
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.kind()["kind"], "maker")
        self.assertFalse([c for c in self.cloud.sent_by("user-maker") if c[1].startswith("/zones")])
        self.assertEqual(self.cloud.calls[-1], ("GET", "/zones?per_page=50", "work1"))

    def test_what_cloudflare_does_not_say_clearly_stops_the_call_and_the_saved_key_makes_none(self):
        unsaid, unknown = "so the door cannot tell what its key is", "Cloudflare does not take the door's key now (401"
        for part, status, words in (("/accounts?per_page=50", 500, unsaid), ("/user/tokens/verify", 429, unsaid),
                                    (f"/accounts/{self.account}/tokens/verify", 599, unsaid),
                                    (f"/accounts/{self.account}/tokens/permission_groups", 503, unsaid),
                                    ("/accounts?per_page=50", 401, unknown),
                                    (f"/accounts/{self.account}/tokens/permission_groups", 401, unknown)):
            with self.subTest(part=part, status=status):
                self.cloud.fault = {part: status}
                self.cloud.calls.clear()
                got = self.zones()
                self.assertFalse(got["ok"], got)
                self.assertIn(words, got["why"])
                self.assertFalse([c for c in self.cloud.calls if c[1].startswith("/zones")])
                self.assertEqual(door.read_json(door.KEYS_FILE, {}), {})        # nothing is taken for a kind
        self.cloud.fault = {}
        self.assertTrue(self.zones()["ok"])

    def test_the_door_asks_again_after_a_day_and_the_answer_before_stands_while_cloudflare_is_silent(self):
        plain = self.cloud.token(name="plain", rights=["Zone Read"])
        self.save(plain)
        self.assertTrue(self.zones()["ok"])
        self.cloud.tokens[plain]["makes"] = "account"       # the owner gives the same token the right to make tokens
        self.t += 23 * 3600
        self.cloud.calls.clear()
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.calls, [("GET", "/zones?per_page=50", "plain")])    # inside the day: not asked
        self.t += 3600 + 1
        self.cloud.fault = {"/accounts?per_page=50": 502}   # the day is over, and Cloudflare does not say
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.calls[-1], ("GET", "/zones?per_page=50", "plain"))  # the answer before stands
        self.t += 24 * 3600                                 # but not for more than two days
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("so the door cannot tell what its key is", got["why"])
        self.t -= 3 * 24 * 3600                             # and not when the clock went back before its asking
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("so the door cannot tell what its key is", got["why"])
        self.t += 3 * 24 * 3600
        self.cloud.fault = {}
        self.cloud.calls.clear()
        self.assertTrue(self.zones()["ok"])                 # asked again: it makes tokens now
        self.assertEqual(self.kind()["kind"], "maker")
        self.assertFalse([c for c in self.cloud.sent_by("plain") if c[1].startswith("/zones")])
        self.assertEqual(self.cloud.calls[-1], ("GET", "/zones?per_page=50", "work1"))

    def test_no_call_goes_out_with_a_key_whose_one_account_the_door_does_not_know(self):
        none = self.cloud.token(name="none", makes="account", accounts=[])
        self.cloud.tokens[none]["owner"] = "account"
        self.save(none)
        got = self.zones()                          # Cloudflare lists no account for it: it may not read its account
        self.assertFalse(got["ok"], got)
        self.assertIn("reaches no Cloudflare account", got["why"])
        self.assertIn("Account Settings: Read", got["why"])
        two = self.cloud.token(name="two", owner="user", rights=["Zone Read"], accounts=[self.account, "c" * 32])
        self.save(two)
        got = self.zones()                          # a hand-made key of two accounts, and the file names neither
        self.assertFalse(got["ok"], got)
        self.assertIn("more than one Cloudflare account", got["why"])
        self.assertFalse([c for c in self.cloud.calls if c[1].startswith("/zones")])       # neither made a call
        self.assertEqual(door.read_json(door.KEYS_FILE, {}), {})                           # and nothing is kept of them

    def test_a_hand_made_key_goes_to_the_account_that_the_door_s_file_names_now(self):
        other = "c" * 32
        self.save(self.cloud.token(name="two", owner="user", rights=["Zone Read", "Cloudflare Tunnel Read"],
                                   accounts=[self.account, other]))
        self.names_file(self.account)
        self.assertTrue(self.call(ONE, "cloudflare:one", "tunnels")["ok"])
        self.assertEqual(self.cloud.calls[-1][1], f"/accounts/{self.account}/cfd_tunnel?is_deleted=false")
        self.names_file(other)                      # the file names the other account: the same value goes there
        self.assertTrue(self.call(ONE, "cloudflare:one", "tunnels")["ok"])
        self.assertEqual(self.cloud.calls[-1][1], f"/accounts/{other}/cfd_tunnel?is_deleted=false")
        self.assertEqual((self.kind()["account_id"], self.kind()["named"]), (other, other))
        # and a key that makes tokens for another account than the file's is refused
        self.save(self.cloud.token(name="maker-e", makes="account"))
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("names another Cloudflare account than the one that this key makes tokens for", got["why"])
        self.assertEqual(self.cloud.made, 0)

    def test_a_new_key_whose_answer_shows_another_right_or_account_is_deleted(self):
        other = f"com.cloudflare.api.account.{'c' * 32}"

        def more(policies):
            policies[0]["permission_groups"].append({"id": "f" * 31 + "2", "name": "Workers Scripts Write"})
            return policies

        def elsewhere(policies):
            policies[0]["resources"] = {other: "*"}
            return policies

        def every(policies):
            policies[1]["resources"] = {"com.cloudflare.api.account.zone.*": "*"}
            return policies

        def fewer(policies):
            policies[1]["permission_groups"].pop()
            return policies

        def deny(policies):
            policies[0]["effect"] = "deny"
            return policies
        changes = (more, elsewhere, every, fewer, deny, lambda policies: [], lambda policies: None)
        for n, change in enumerate(changes, 1):
            with self.subTest(change=change):
                self.cloud.change = change
                got = self.zones()
                self.assertFalse(got["ok"], got)
                self.assertIn("does not show the rights and the one account that the door asked for", got["why"])
                self.assertTrue(self.cloud.named(f"work{n}")["gone"])           # deleted with the key that makes tokens
                self.assertEqual(self.cloud.sent_by(f"work{n}"), [])            # and never used
                self.assertIsNone(self.work())
        failed = self.lines("key-new")
        self.assertEqual(({e["outcome"] for e in failed}, len(failed)), ({"failed"}, 1))    # the same words: one line
        self.cloud.change, self.cloud.no_value = None, True
        got = self.zones()                          # an answer with an id and no value: that token is deleted too
        self.assertFalse(got["ok"], got)
        self.assertIn("Cloudflare made the door no work key (200): no id and value", got["why"])
        self.assertTrue(self.cloud.named(f"work{len(changes) + 1}")["gone"])

    def test_each_right_is_one_group_of_the_account_s_own_list_by_its_exact_name_and_scope(self):
        for name, groups, words in (
                ("none", [g for g in Cloud.GROUPS if g["name"] != "Cache Purge"],
                 "lists no permission group 'Cache Purge' for a zone"),
                ("twice", Cloud.GROUPS + [{"id": "9" * 32, "name": "DNS Write",
                                           "scopes": ["com.cloudflare.api.account.zone"]}],
                 "lists more than one permission group 'DNS Write' for a zone")):
            with self.subTest(name=name):
                self.cloud.groups = groups
                got = self.zones()
                self.assertFalse(got["ok"], got)
                self.assertIn(words, got["why"])
                self.assertEqual(self.cloud.made, 0)
        self.cloud.groups, self.cloud.page = json.loads(json.dumps(Cloud.GROUPS)), 2
        self.assertTrue(self.zones()["ok"])         # a list in pages of two: each right is asked for by its own name
        self.assertEqual(sorted(self.cloud.named("work1")["rights"]), sorted(Cloud.RIGHTS))
        # a list that comes whole, whatever the filter: the door itself takes the exact name in the right scope, so
        # neither the Zone Read of a user nor DNS Write Extra is in the key
        os.remove(self.root + door.KEYS_FILE)
        self.cloud.page, self.cloud.filters = None, False
        self.assertTrue(self.zones()["ok"])
        self.assertEqual([[g["id"] for g in p["permission_groups"]] for p in self.cloud.named("work2")["policies"]],
                         [[f"{n:032x}" for n in (6, 7)], [f"{n:032x}" for n in (1, 2, 3, 4, 5)]])

    def test_a_right_whose_name_changed_keeps_the_id_that_its_name_gave_the_key_before(self):
        self.assertTrue(self.zones()["ok"])
        purge = next(g for g in self.cloud.groups if g["name"] == "Cache Purge")
        purge["name"] = "Cache Purge of a Zone"     # Cloudflare's documents: a group's name is subject to change
        self.t += 23 * 3600 + 60
        self.assertTrue(self.zones()["ok"])
        self.assertIn(purge["id"], [g["id"] for p in self.cloud.named("work2")["policies"]
                                    for g in p["permission_groups"]])
        os.remove(self.root + door.KEYS_FILE)       # a door that never had the key cannot name the right
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("lists no permission group 'Cache Purge' for a zone", got["why"])

    def test_a_new_key_that_does_not_sign_in_is_deleted_and_the_one_before_serves_its_last_minutes(self):
        self.assertTrue(self.zones()["ok"])
        first = self.work()["id"]
        self.t += 23 * 3600 + 60                # less than an hour is left, and the new key does not sign in
        slept, real = [], self.cloud.http

        def http(method, url, headers, data):
            status, answer = real(method, url, headers, data)
            if url.endswith("/tokens/verify") and self.cloud.calls[-1][2] not in ("work1", "maker"):
                return 401, {"success": False}
            return status, answer
        self.door.http = http
        with patch.object(door_providers.time, "sleep", slept.append):
            got = self.zones()
        self.assertTrue(got["ok"], got)                                 # the key before still has minutes left
        self.assertEqual(slept, [door_providers.CF_KEY_PAUSE] * (door_providers.CF_KEY_TRIES - 1))
        self.assertTrue(self.cloud.named("work2")["gone"])
        self.assertEqual(self.work()["id"], first)
        self.assertEqual(self.cloud.calls[-1], ("GET", "/zones?per_page=50", "work1"))
        self.assertIn("does not sign in", self.lines("key-new")[-1]["why"])
        self.t += 3600                          # its day ended: no key is left to go on with
        with patch.object(door_providers.time, "sleep", slept.append):
            got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("does not sign in", got["why"])

    def test_a_new_key_that_the_door_cannot_keep_is_deleted(self):
        with patch.object(self.door, "keep_work_key", side_effect=OSError(28, "No space left on device")):
            got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("could not keep its new work key (OSError), and deleted it", got["why"])
        self.assertTrue(self.cloud.named("work1")["gone"])
        self.assertEqual(self.cloud.sent_by("work1"), [("GET", f"/accounts/{self.account}/tokens/verify")])
        self.assertTrue(self.zones()["ok"])

    def test_a_key_that_makes_tokens_and_was_deleted_stops_the_next_key_with_words(self):
        self.assertTrue(self.zones()["ok"])
        self.cloud.tokens[self.maker]["gone"] = True
        self.t += 3600
        self.assertTrue(self.zones()["ok"])     # the work key goes on until less than an hour is left
        self.t += 22 * 3600 + 1
        self.assertTrue(self.zones()["ok"])     # and then until its last minute, with one line that says why
        self.assertIn("no longer takes the key that makes tokens (401)", self.lines("key-new")[-1]["why"])
        self.t += 3600
        got = self.zones()
        self.assertFalse(got["ok"], got)
        # the day is over: Cloudflare answers 401 to the door's questions, which says nothing about what the key
        # is, so the answer before stands, and the making of the next work key says why it stops
        self.assertIn("no longer takes the key that makes tokens (401): the owner makes a new one", got["why"])
        self.t += 2 * 24 * 3600                 # and after two days with no answer, the answer before no longer stands
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("Cloudflare does not take the door's key now (401, when the door asked which accounts its key "
                      "reaches)", got["why"])

    def test_a_work_key_that_cloudflare_no_longer_takes_leaves_the_door_and_the_next_call_makes_one(self):
        self.assertTrue(self.zones()["ok"])
        first = self.work()["id"]
        real = self.cloud.http

        def unsettled(method, url, headers, data):      # Cloudflare takes the new token at one place and not at another
            status, answer = real(method, url, headers, data)
            return Cloud.INVALID if self.cloud.calls[-1][2] == "work1" else (status, answer)
        self.door.http = unsettled
        for _ in range(3):                          # a key of less than five minutes stays, however often it is refused
            got = self.zones()
            self.assertFalse(got["ok"], got)
            self.assertIn("does not take the door's new work key yet (401): send the same call again in a minute",
                          got["why"])
        self.assertEqual((self.work()["id"], self.cloud.made, self.lines("key-end")), (first, 1, []))
        self.door.http = real
        self.assertTrue(self.zones()["ok"])
        self.t += door_providers.CF_KEY_SETTLE + 1
        # Cloudflare's verify does not take the key, and the door cannot delete it there now: the key may be live,
        # so it stays, and the door makes no second key beside it
        self.door.http = unsettled
        self.cloud.fault = {f"/tokens/{first}": 500}
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("could not delete it there now (500): send the same call again", got["why"])
        self.assertEqual((self.work()["id"], self.cloud.made, self.lines("key-end")), (first, 1, []))
        self.door.http, self.cloud.fault = real, {}
        self.cloud.named("work1")["gone"] = True    # somebody deleted the token named Founderizer door at Cloudflare
        self.cloud.calls.clear()
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("no longer takes the door's work key (401): the door makes a new one", got["why"])
        self.assertIsNone(self.work())
        self.assertFalse(os.path.exists(self.door.work_path("cloudflare:one")))
        # the door deletes it at Cloudflare too, with the key that makes tokens, so that no call leaves a token behind
        self.assertEqual(self.cloud.sent_by("maker"), [("DELETE", f"/accounts/{self.account}/tokens/{first}")])
        line, = self.lines("key-end")
        self.assertIn(f"Cloudflare no longer takes the work key, so it left the door (token {first})", line["why"])
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.calls[-1], ("GET", "/zones?per_page=50", "work2"))
        self.assertEqual(self.cloud.made, 2)

    def test_a_saved_key_that_makes_no_tokens_any_more_has_no_work_key(self):
        self.assertTrue(self.zones()["ok"])
        first = self.work()["id"]
        self.save(self.cloud.token(name="plain", rights=["Zone Read"]))     # the owner saves a hand-made key in its place
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(self.cloud.calls[-1], ("GET", "/zones?per_page=50", "plain"))
        self.assertIsNone(self.work())
        self.assertFalse(os.path.exists(self.door.work_path("cloudflare:one")))
        line, = self.lines("key-end")
        self.assertIn(f"the saved key makes no tokens, so the work key of the key before left the door, and "
                      f"Cloudflare ends it within the day (token {first})", line["why"])
        self.assertIn(("DELETE", f"/accounts/{self.account}/tokens/{first}"), self.cloud.sent_by("plain"))  # it tried
        self.assertTrue(self.zones()["ok"])
        self.assertEqual(len(self.lines("key-end")), 1)

    def test_the_words_of_each_refusal_while_the_door_makes_a_key(self):
        reader = self.cloud.token(name="reader", makes="account")       # Account API Tokens: Read, and no Edit
        self.save(reader)
        real = self.cloud.http

        def read_only(method, url, headers, data):
            if method == "POST" and url.endswith("/tokens"):
                self.cloud.calls.append((method, url.rpartition("/v4")[2], "reader"))
                return 403, {"success": False, "errors": [{"code": 9109, "message": "Unauthorized to access requested "
                                                                                      "resource"}]}
            return real(method, url, headers, data)
        self.door.http = read_only
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("Cloudflare made the door no work key (403): Unauthorized to access requested resource", got["why"])
        self.door.http = real
        self.cloud.fault = {"permission_groups?name=": 403}             # the list is refused when the key is made
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("gave the door no list of the account's permission groups (403): the key that makes tokens "
                      "needs Account API Tokens: Edit", got["why"])
        self.cloud.fault = {}
        self.assertEqual(self.cloud.made, 0)
        bad = self.cloud.token(name="bad", accounts=["not-an-account-id"])
        self.save(bad)
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("Cloudflare gave no account id that the door can use", got["why"])
        # a hand-made key that Cloudflare refuses a step for gets Cloudflare's own words, and no word of a work key
        self.save(self.cloud.token(name="narrow", rights=[]))
        got = self.zones()
        self.assertFalse(got["ok"], got)
        self.assertIn("cloudflare answered 403", got["why"])
        self.assertNotIn("work key", got["why"])

    def test_a_call_outside_the_work_key_s_rights_says_which_rights_it_has(self):
        got = self.call(ONE, "cloudflare:one", "change", "PUT", "/accounts/{account_id}/workers/scripts/edge",
                        content=b"{}")
        self.assertEqual((got["ok"], got["kind"]), (False, "own"), got)
        self.assertIn("cloudflare answered 403", got["why"])
        self.assertIn("holds these rights and no other: Zone Read, DNS Read, DNS Write, Cache Purge, Zone WAF Read, "
                      "Cloudflare Tunnel Read, Cloudflare Tunnel Write", got["why"])
        self.assertEqual(self.cloud.calls[-2:],
                         [("PUT", f"/accounts/{self.account}/workers/scripts/edge", "work1"),
                          ("GET", f"/accounts/{self.account}/tokens/verify", "work1")])
        self.assertIsNotNone(self.work())           # the key is active: it stays

    def test_the_work_key_ends_with_the_grant(self):
        self.assertTrue(self.zones()["ok"])
        first = self.work()["id"]
        self.assertEqual(door.end_keys(self.door), [])              # the grant stands: nothing ends
        self.assertIsNotNone(self.work())
        data = json.loads(json.dumps(self.data))
        data["agents"]["ops-one"]["providers"].remove("cloudflare:one")     # no agent holds the account any more
        self.write_access(data)
        self.cloud.calls.clear()
        self.assertEqual(door.end_keys(self.door), ["cloudflare:one"])
        self.assertEqual(self.cloud.calls, [("DELETE", f"/accounts/{self.account}/tokens/{first}", "maker")])
        self.assertTrue(self.cloud.named("work1")["gone"])
        self.assertIsNone(self.work())
        self.assertFalse(os.path.exists(self.door.work_path("cloudflare:one")))
        line, = self.lines("key-end")
        self.assertEqual((line["caller"], line["target"], line["kind"], line["outcome"]),
                         ("door", "cloudflare:one", "key", "done"))
        self.assertIn(f"the door deleted its work key (token {first})", line["why"])
        self.assertEqual(door.end_keys(self.door), [])

    def test_a_key_of_an_account_that_left_the_file_ends_and_one_that_cannot_be_deleted_leaves_the_door(self):
        self.assertTrue(self.zones()["ok"])
        data = json.loads(json.dumps(self.data))
        del data["credentials"]["cloudflare:one"]
        data["agents"]["ops-one"]["providers"].remove("cloudflare:one")
        self.write_access(data)
        self.cloud.fault = {"/tokens/": 503}                        # Cloudflare does not answer: asked again later
        self.assertEqual(door.end_keys(self.door), [])
        self.assertIsNotNone(self.work())
        self.cloud.fault = {}
        os.remove(os.path.join(self.root + door.SECRETS_DIR, hashlib.sha256(ref(1).encode()).hexdigest()))
        self.cloud.calls.clear()
        self.assertEqual(door.end_keys(self.door), ["cloudflare:one"])      # the key that made it is gone too
        self.assertEqual(self.cloud.calls, [])
        self.assertIsNone(self.work())
        self.assertIn("its provider ends it within the day", self.lines("key-end")[0]["why"])
        self.assertEqual(door.read_json(door.KEYS_FILE, {}), {"kinds": {}, "work": {}})

    def test_the_end_of_a_grant_by_each_answer_of_cloudflare(self):
        data = json.loads(json.dumps(self.data))
        data["agents"]["ops-one"]["providers"].remove("cloudflare:one")
        for name, before, said in (
                ("the token is gone at Cloudflare already", lambda: self.cloud.named("work1").update(gone=True),
                 "the door deleted its work key"),
                ("the saved key may not delete it", lambda: self.cloud.tokens[self.maker].update(makes=None),
                 "its provider ends it within the day"),
                ("Cloudflare does not answer, and the key's day is over",
                 lambda: (self.cloud.fault.update({"/tokens/": 503}), setattr(self, "t", self.t + 25 * 3600)),
                 "its provider ends it within the day")):
            with self.subTest(name=name):
                self.cloud = Cloud(lambda: self.t)
                self.door.http = self.cloud.http
                self.write_access(self.data)
                self.assertTrue(self.zones()["ok"])
                before()
                self.write_access(data)
                self.assertEqual(door.end_keys(self.door), ["cloudflare:one"])
                self.assertIn(said, self.lines("key-end")[-1]["why"])
                self.assertIsNone(self.work())
        held = door.kept_keys()
        held["work"]["cloudflare:one"] = "not an entry"
        door.write_json(door.KEYS_FILE, held)
        self.assertEqual(door.end_keys(self.door), [])
        self.assertEqual(door.kept_keys()["work"], {})

    def test_one_account_that_fails_holds_no_other_account_s_key(self):
        self.assertTrue(self.zones()["ok"])
        held = door.kept_keys()
        held["work"]["cloudflare:a-first"] = dict(held["work"]["cloudflare:one"], id="1" * 32)
        door.write_json(door.KEYS_FILE, held)
        data = json.loads(json.dumps(self.data))
        data["agents"]["ops-one"]["providers"].remove("cloudflare:one")
        self.write_access(data)
        real = door_providers.cloudflare_end

        def end(maker, account, token_id, ctx):
            if token_id == "1" * 32:
                raise RuntimeError("a fault of this test")
            return real(maker, account, token_id, ctx)
        with patch.object(door_providers, "cloudflare_end", end):
            self.assertEqual(door.end_keys(self.door), ["cloudflare:one"])
        self.assertTrue(self.cloud.named("work1")["gone"])

    def test_an_access_file_that_the_door_cannot_read_ends_no_key(self):
        self.assertTrue(self.zones()["ok"])
        with open(self.root + door.ACCESS_FILE, "w") as f:
            f.write("{")
        self.assertEqual(door.end_keys(self.door), [])
        self.assertIsNotNone(self.work())
        self.assertEqual(self.cloud.sent_by("maker")[-1][0], "POST")

    def test_a_key_file_that_is_lost_or_broken_costs_one_new_key(self):
        self.assertTrue(self.zones()["ok"])
        first = self.work()["id"]
        for text in ("[]", '{"work": 7, "kinds": "x"}', "{"):
            with self.subTest(text=text):
                with open(self.root + door.KEYS_FILE, "w") as f:
                    f.write(text)
                self.assertEqual(door.end_keys(self.door), [])
                self.assertTrue(self.zones()["ok"])             # asked again, and made again
        self.assertEqual(self.cloud.made, 4)
        self.assertFalse(self.cloud.named("work1").get("gone"))     # the door lost its id: its day ends it
        self.assertEqual(self.cloud.named("work1")["id"], first)
        for n, damage in enumerate((os.remove, lambda path: pathlib.Path(path).write_text(""),
                                    lambda path: pathlib.Path(path).write_bytes(b"\xff\xfe\x00"),
                                    # the value of another key than the one that the list names
                                    lambda path: pathlib.Path(path).write_text("cfat_" + "o" * 40)), 5):
            with self.subTest(damage=n):
                last = self.work()["id"]
                damage(self.door.work_path("cloudflare:one"))   # the value is gone, empty or no text; the list is not
                self.assertTrue(self.zones()["ok"])
                self.assertEqual(self.cloud.made, n)
                self.assertTrue(next(t for t in self.cloud.tokens.values() if t["id"] == last)["gone"])    # by its id

    def test_an_agent_s_own_call_reaches_no_token_of_the_account(self):
        for method, path in (("POST", "/accounts/{account_id}/tokens"),
                             ("DELETE", f"/accounts/{self.account}/tokens/{'a' * 32}"),
                             ("PUT", f"/accounts/{self.account}/tokens/{'a' * 32}/value")):
            with self.subTest(path=path):
                got = self.call(ONE, "cloudflare:one", "change", method, path, content=b"{}")
                self.assertEqual(got["kind"], "refused", got)
                self.assertIn("an API token's answer is its secret", got["why"])
        self.assertEqual(self.cloud.calls, [])


class Vault(DoorCase):
    """The door as a holder of the central vault: its sealed copies come from the hub, and only its user opens them."""

    def test_a_sealed_copy_is_opened_kept_at_600_and_confirmed(self):
        calls = []

        def http(method, url, headers, data):
            calls.append((method, url, data))
            if url.endswith("/door/sealed"):
                return 200, {"copies": [{"id": 5, "login": ref(6), "sealed": "-----BEGIN AGE ENCRYPTED FILE-----"},
                                        {"id": 6, "login": "not a ref", "sealed": "x"}]}
            return 200, {}
        self.door.http = http
        with patch.object(door, "run_program", lambda argv, stdin, env, timeout=600: (0, "the-new-value\n")):
            self.assertEqual(door.fetch_sealed(self.door), 1)
        path = os.path.join(self.root + door.SECRETS_DIR, hashlib.sha256(ref(6).encode()).hexdigest())
        self.assertEqual((slurp(path, "r"), oct(os.stat(path).st_mode & 0o777)), ("the-new-value", "0o600"))
        self.assertEqual(self.door.secret(ref(6)), "the-new-value")
        self.assertEqual(calls[0][1], f"http://{HUB}:8765/door/sealed")
        self.assertEqual(calls[1][1], f"http://{HUB}:8765/door/sealed/5")
        self.assertEqual(json.loads(calls[1][2]), {"sha256": hashlib.sha256(b"the-new-value").hexdigest()})

    def test_a_new_value_takes_the_place_of_the_old_one_as_one_whole_file(self):
        """Since the owner can replace a value, a copy comes for a secret that the door holds and uses. A call reads
        the old value or the new one, never a part: the new file is written beside the old one and then put in its
        place, so a write that stops leaves the old value."""
        values = iter(["the-old-value\n", "the-new-value\n", "the-third-value\n"])
        self.door.http = lambda method, url, headers, data: (200, {"copies": [
            {"id": 8, "login": ref(6), "sealed": "-----BEGIN AGE ENCRYPTED FILE-----"}]}) \
            if url.endswith("/door/sealed") else (200, {})
        folder = self.root + door.SECRETS_DIR
        with patch.object(door, "run_program", lambda argv, stdin, env, timeout=600: (0, next(values))):
            self.assertEqual(door.fetch_sealed(self.door), 1)
            self.assertEqual(self.door.secret(ref(6)), "the-old-value")
            with patch.object(door.os, "replace", side_effect=OSError("the disk is full")), self.assertRaises(OSError):
                door.fetch_sealed(self.door)
            self.assertEqual(self.door.secret(ref(6)), "the-old-value")     # the old value, whole
            self.assertEqual(door.fetch_sealed(self.door), 1)
        self.assertEqual(self.door.secret(ref(6)), "the-third-value")
        name = hashlib.sha256(ref(6).encode()).hexdigest()
        self.assertEqual([n for n in os.listdir(folder) if not re.fullmatch(r"[0-9a-f]{64}", n)
                          and not n.startswith(("minted-", "work-"))], [])  # and no file beside it is left
        self.assertEqual(oct(os.stat(os.path.join(folder, name)).st_mode & 0o777), "0o600")

    def test_the_door_keeps_the_key_of_an_item_and_not_the_item(self):
        """The central vault seals the item as the owner's app saved it: {"password": <the key>, "username": ""}. The
        door's providers need the key alone, a PEM file's lines included."""
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
        item = json.dumps({"password": pem, "username": ""}, sort_keys=True)
        self.door.http = lambda method, url, headers, data: (200, {"copies": [
            {"id": 7, "login": ref(6), "sealed": "-----BEGIN AGE ENCRYPTED FILE-----"}]}) \
            if url.endswith("/door/sealed") else (200, {})
        with patch.object(door, "run_program", lambda argv, stdin, env, timeout=600: (0, item + "\n")):
            self.assertEqual(door.fetch_sealed(self.door), 1)
        self.assertEqual(self.door.secret(ref(6)), pem)
        self.assertEqual(door.item_secret('{"password": "", "username": "x"}'), '{"password": "", "username": "x"}')
        self.assertEqual(door.item_secret("tskey-client-abc-def"), "tskey-client-abc-def")

    def test_a_grant_that_ended_leaves_the_door_and_a_minted_key_stays(self):
        folder = self.root + door.SECRETS_DIR
        minted = os.path.join(folder, "minted-" + "a" * 64)
        with open(minted, "w") as f:
            f.write("k:v")
        self.door.http = lambda method, url, headers, data: (200, {"copies": [], "keep": [ref(1), ref(9)]})
        door.fetch_sealed(self.door)
        left = sorted(os.listdir(folder))
        self.assertEqual(left, sorted([hashlib.sha256(ref(1).encode()).hexdigest(),
                                       hashlib.sha256(ref(9).encode()).hexdigest(), os.path.basename(minted)]))
        self.door.http = lambda method, url, headers, data: (200, {"copies": [], "keep": None})   # the vault is down
        door.fetch_sealed(self.door)
        self.assertEqual(sorted(os.listdir(folder)), left)

    def test_a_secret_the_door_does_not_hold_names_the_owner_s_step(self):
        with self.assertRaisesRegex(door.Refused, "the owner grants it to the door"):
            self.door.secret(ref(99))

    def test_a_hub_at_an_ipv6_address_is_asked_with_the_address_in_brackets(self):
        """The access file takes the hub's IPv6 address of the private network. Before, only `follow` put it in
        brackets, and the sealed copies and the owner's yeses were asked for at an address that is no URL."""
        from test_vault_central import OWNER_C
        data = json.loads(json.dumps(ACCESS))
        data.update(hub={"address": "fd7a:115c:a1e0::2", "port": 8765}, owner_keys=[OWNER_C], fleet="fleet-1")
        self.write_access(door.validate_access(data))
        asked = []
        self.door.http = lambda method, url, headers, body: (asked.append(url), (404, {}))[1]
        door.fetch_sealed(self.door)
        door.fetch_approvals(self.door)
        with patch.object(door.door_providers, "http", lambda method, url, headers, body: self.door.http(
                method, url, headers, body)), self.assertRaises(SystemExit), \
                patch.object(door, "run_program", lambda argv, stdin, env, timeout=600: (0, "")), \
                contextlib.redirect_stdout(io.StringIO()):
            door.cmd_follow(None)
        self.assertEqual(asked, [f"http://[fd7a:115c:a1e0::2]:8765/door/{what}"
                                 for what in ("sealed", "approvals", "release")])
        self.assertEqual(door.hub_url({"address": HUB}), f"http://{HUB}:8765")


# ---------------------------------------------------------------- test 9: the audit, replayed
#
# Thirty events of the owner's own DevOps work in the two weeks before the plan (audit/, beside the plan), with
# generic names. Each is one call of an Operator and the kind that section 3 gives it: read and rule calls, the
# agent's own calls, which its grant covers and for which it answers, and the door's refusals.

OLD_LOCK = {"packages": {"": {"dependencies": {"next": "^16.0.0"}},
                         "node_modules/next": {"version": "16.4.1", "integrity": "sha512-old",
                                               "resolved": "https://registry.npmjs.org/next/-/next-16.4.1.tgz"}}}
NEW_LOCK = {"packages": {"": {"dependencies": {"next": "^16.0.0"}},
                         "node_modules/next": {"version": "16.4.2", "integrity": "sha512-new",
                                               "resolved": "https://registry.npmjs.org/next/-/next-16.4.2.tgz"}}}
REGISTRY = {"versions": {"16.4.2": {"dist": {"tarball": "https://registry.npmjs.org/next/-/next-16.4.2.tgz",
                                             "integrity": "sha512-new"}}},
            "time": {"16.4.2": "2026-10-01T00:00:00.000Z"}}
OLD_DEPLOYMENT = "kind: Deployment\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n" \
                 "      - image: ghcr.io/one-org/shop:1111111\n"
LOOKUPS = {"base_file": lambda path: {"package-lock.json": json.dumps(OLD_LOCK).encode(),
                                      "apps/shop/deployment.yaml": OLD_DEPLOYMENT.encode()}.get(path),
           "npm": lambda name: REGISTRY, "image_made": lambda image: image.endswith(":2222222"),
           "deploy_facts": lambda repo: {"parent": "r1", "released": "r1", "door_made": True, "green": True,
                                         "hold": False},
           "minted": lambda key: key == "k-minted", "default_branch": lambda repo: "main"}


def change(*files):
    return json.dumps({"message": "fix", "files": [{"path": p, "content": base64.b64encode(t.encode()).decode()}
                                                   for p, t in files]}).encode()


EVENTS = [
    ("timers dead after a slow boot: the fixed timer unit", "web-1", "file",
     ["/etc/systemd/system/backup.timer", "0644", "root"], b"[Timer]\nOnBootSec=5min\n", "own"),
    ("the same: systemd reads its units again", "web-1", "daemon-reload", [], None, "rule"),
    ("security updates stopped for a month: run them", "web-1", "upgrade", [], None, "rule"),
    ("a half-installed package after an update failed", "web-1", "exec", ["dpkg", "--configure", "-a"], None,
     "own"),
    ("a kernel update: one host reboots outside its windows", "web-1", "reboot", [], None, "rule"),
    ("a tunnel token on a command line: a drop-in that reads a root file", "web-1", "file",
     ["/etc/systemd/system/cloudflared.service.d/token.conf", "0644", "root"], b"[Service]\n", "own"),
    ("an update restarts the database: a needrestart rule", "db-1", "file",
     ["/etc/needrestart/conf.d/50-postgres.conf", "0644", "root"], b"$nrconf{override_rc}{qr(^postgresql)} = 0;\n",
     "own"),
    ("a critical advisory in an app: the checked lockfile fix", "commit:one-org/shop", "push", [],
     change(("package-lock.json", json.dumps(NEW_LOCK))), "rule"),
    ("the same: the app's documented deploy", "deploy:one-org/shop", "run", [], None, "rule"),
    ("a host locked out by a sshd change: a power cycle", "hetzner:one", "power-cycle", ["web-1"], None, "rule"),
    ("a backup key that the provider refuses: a key for that host only", "backblaze:one", "key-mint",
     ["web-1", "4a5b6c7d8e9f"], None, "rule"),
    ("the same: the new key where the old one is", "backblaze:one", "key-place",
     ["web-1", "/etc/restic/b2.env", "k-minted", "B2_ACCOUNT_ID=id:" + "1" * 64, "B2_ACCOUNT_KEY=key:" + "2" * 64],
     None, "rule"),
    ("node keys of the private network about to expire", "tailscale:net", "key-expiry-off", ["n7a8b9c"], None, "rule"),
    ("old servers that no agent made: delete them", "hetzner:one", "change", ["DELETE", "/servers/42", "web-1"],
     None, "refused"),
    ("a public dashboard: an access app for three people", "cloudflare:one", "change",      # D25: the agent's own
     ["POST", f"/accounts/{'b' * 32}/access/apps"], b'{"name": "dash"}', "own"),           # call
    ("delete and rebuild protection on a server", "hetzner:one", "change",
     ["POST", "/servers/42/actions/change_protection", "web-1"], b'{"delete": true, "rebuild": true}', "own"),
    ("an OAuth client that scans the private network: revoke it", "tailscale:net", "oauth-client",
     ["revoke", "kQ2xY7"], None, "own"),
    ("alert noise: the new rules file", "web-1", "file", ["/etc/prometheus/rules/audit.yml", "0644", "root"],
     b"groups: []\n", "own"),
    ("the same: Prometheus reloads after promtool", "web-1", "monitoring-reload", [], None, "rule"),
    ("a PHP advisory: the packages of a host", "web-1", "packages", [], None, "read"),
    ("the same: what listens on a host", "logs-1", "listen", [], None, "read"),
    ("a Node.js security release: the fixed package", "web-1", "install", ["nodejs"], None, "own"),
    ("old sudoers copies: is a copy the same file", "web-1", "same",
     ["/etc/sudoers.d/90-app.bak", "/etc/sudoers.d/90-app"], None, "read"),
    ("the same: drop the copy after the yes", "web-1", "drop", ["/etc/sudoers.d/90-app.bak"], None, "rule"),
    ("certificate renewal broken by debris", "web-1", "renew-certs", [], None, "rule"),
    ("cached 404s on a CDN: purge the name", "cloudflare:one", "purge", [ZONE, "cdn.example.com"], None, "rule"),
    ("the same: the cache rule", "cloudflare:one", "change", ["PUT", f"/zones/{ZONE}/rulesets/{'e' * 32}"],
     b'{"rules": []}', "own"),
    ("a backup hangs: stop its process", "web-1", "exec", ["kill", "-INT", "4242"], None, "own"),
    ("a kernel RCE with no fix yet: a firewall rule", "web-1", "exec",
     ["nft", "add", "rule", "inet", "filter", "input", "ip", "option", "drop"], None, "own"),
    ("a new image of an app through GitOps", "gitops:one-org/cluster", "push", [],
     change(("apps/shop/deployment.yaml", OLD_DEPLOYMENT.replace("1111111", "2222222"))), "rule"),
    ("a cluster key as a Secret in a manifest", "gitops:one-org/cluster", "push", [],
     change(("apps/shop/key.yaml", "apiVersion: v1\nkind: Secret\n")), "refused"),
    ("a line of the tailnet policy", "commit:one-org/ops", "push", [], change(("policy.hujson", "{}")), "refused"),
    ("a workflow file of the operations repository", "commit:one-org/ops", "push", [],
     change((".github/workflows/apply.yml", "on: push\n")), "refused"),
    ("a runbook and a host record in the operations repository", "commit:one-org/ops", "push", [],
     change(("docs/runbook.md", "# Runbook\n"), ("hosts/web-1/README.md", "# web-1\n")), "rule"),
    ("a Rescue boot of a broken server", "hetzner:one", "change",
     ["POST", "/servers/42/actions/enable_rescue", "web-1"], b"{}", "refused"),
    ("a health workflow of the cluster", "github:one-org", "workflow", ["cluster", "cluster-health.yml"], None,
     "rule"),
    ("a bootstrap workflow of the cluster", "github:one-org", "workflow", ["cluster", "velero-bootstrap.yml"], None,
     "own"),
    ("a full build file stopped every runner: grow it from free space", "web-1", "grow-file", ["20"], None, "rule"),
    ("the same: restart each idle runner, which gets its lost network back", "web-1", "runner-restart",
     ["runner-01"], None, "rule"),
    ("a login that nobody uses any more: lock its password", "web-1", "passwd-lock", ["olduser"], None, "own"),
    ("an unused package with a known flaw: purge it", "web-1", "purge", ["telnetd"], None, "own"),
]


class AuditReplay(unittest.TestCase):
    def test_thirty_events_of_the_audit_take_the_kind_that_section_3_gives_them(self):
        self.assertGreaterEqual(len(EVENTS), 30)
        for what, target, op, args, content, kind in EVENTS:
            with self.subTest(what):
                d = door_targets.decide(ACCESS, "ops-one", target, op, args, content, LOOKUPS)
                self.assertEqual(d.kind, kind, f"{what}: {d.why}")

    def test_the_other_business_reaches_none_of_them(self):
        for what, target, op, args, content, kind in EVENTS:
            with self.subTest(what):
                self.assertEqual(door_targets.decide(ACCESS, "ops-two", target, op, args, content, LOOKUPS).kind,
                                 "refused")


if __name__ == "__main__":
    unittest.main()


CI = {"name": "CI", "on": {"push": {"branches": ["main"]}, "pull_request": {}}, "permissions": {"contents": "read"},
      "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
          {"uses": "actions/checkout@v4"},
          {"run": "npm ci && npm test && tar -czf shopapp-release.tar.gz dist && "
                  "sha256sum shopapp-release.tar.gz > shopapp-release.tar.gz.sha256"},
          {"uses": "actions/upload-artifact@v4", "with": {"name": "shopapp-release", "path": "shopapp-release.tar.gz*"},
           "env": {"TOKEN": "${{ secrets.GITHUB_TOKEN }}"}}]}}}


class Workflows(DoorCase):
    """New-projects plan N5: the workflow files of a repository that the door made come only through the door, for the
    Operator that made it, by the door's own record, while the developer holds write. Code reads each one as JSON and
    commits its own serialization of it: the deploy workflow is the product's template, and every other job runs on
    GitHub's runners with no job-level uses, no secret but GITHUB_TOKEN, no id-token write and no trigger that runs
    another's code with the repository's rights."""
    REPO = "one-org/shopapp"

    def setUp(self):
        super().setUp()
        data = json.loads(json.dumps(ACCESS))
        data["agents"]["dev-one"] = {"address": "100.64.0.21", "business": "one", "github": {self.REPO: "write"}}
        self.write_access(data)
        self.door.repo_record("made", self.REPO, id=77, agent="ops-one", app="shopapp")
        door.GitHub.TOKENS.clear()
        door.GitHub.BRANCHES.clear()
        patcher = patch.object(door_providers, "app_jwt", lambda app_id, pem, sign=None: "jwt")
        patcher.start()
        self.addCleanup(patcher.stop)
        api, self.calls = "https://api.github.com/repos/" + self.REPO, []
        answers = {("GET", f"https://api.github.com/repos/{self.REPO}/installation"): (200, {"id": 9}),
                   ("POST", "https://api.github.com/app/installations/9/access_tokens"): (201, {"token": "ghs_door"}),
                   ("GET", api): (200, {"default_branch": "main"}),
                   ("GET", f"{api}/git/ref/heads/main"): (200, {"object": {"sha": "h1"}}),
                   ("GET", f"{api}/git/commits/h1"): (200, {"tree": {"sha": "t1"}}),
                   ("POST", f"{api}/git/blobs"): (201, {"sha": "b1"}),
                   ("POST", f"{api}/git/trees"): (201, {"sha": "t2"}),
                   ("POST", f"{api}/git/commits"): (201, {"sha": "c2"}),
                   ("PATCH", f"{api}/git/refs/heads/main"): (200, {})}

        def http(method, url, headers, data):
            self.calls.append((method, url, None if data is None else json.loads(data)))
            return answers.get((method, url), (404, {"message": "not stubbed"}))
        self.door.http = http

    def template(self, artifact="shopapp-release"):
        got = self.call(ONE, f"commit:{self.REPO}", "deploy-template", artifact)
        self.assertEqual((got["ok"], got["kind"]), (True, "read"), got)
        return json.loads(got["out"])

    def decide(self, *files, agent="ops-one"):
        made = lambda name: self.door.repo_record("made", name)        # noqa: E731
        return door_targets.decide(door.read_json(door.ACCESS_FILE, {}), agent, f"commit:{self.REPO}", "push", [],
                                   change(*files), {"made_repo": made})

    def test_the_operator_that_made_the_repository_commits_its_workflows(self):
        deploy = self.template()
        self.assertEqual(deploy["path"], ".github/workflows/deploy.yml")
        self.assertIn("APP_RELEASE_SHA", deploy["contract"])
        ci = json.dumps(CI)
        got = self.call(ONE, f"commit:{self.REPO}", "push", content=change(
            (".github/workflows/ci.yml", ci), (deploy["path"], deploy["text"])))
        self.assertEqual((got["ok"], got["kind"], got["out"]), (True, "rule", f"{self.REPO} main is at c2"), got)
        blobs = [base64.b64decode(d["content"]) for m, u, d in self.calls if u.endswith("/git/blobs")]
        self.assertEqual(blobs, [door_targets.canonical(CI), deploy["text"].encode()])
        tree = next(d for m, u, d in self.calls if u.endswith("/git/trees"))["tree"]
        self.assertEqual([(e["path"], e["mode"]) for e in tree],
                         [(".github/workflows/ci.yml", "100644"), (".github/workflows/deploy.yml", "100644")])
        # the developer, who holds write, and another Operator get the commit rules' refusal
        for address, words in (("100.64.0.21", "commits nothing on one-org/shopapp"),
                               (TWO, "commits nothing on one-org/shopapp")):
            with self.subTest(address=address):
                got = self.call(address, f"commit:{self.REPO}", "push",
                                content=change((".github/workflows/ci.yml", ci)))
                self.assertIn(words, got["why"])
        self.assertIn("no repository that the door made for this agent",
                      self.call("100.64.0.21", f"commit:{self.REPO}", "deploy-template", "x")["why"])

    def test_code_refuses_what_a_workflow_may_not_do(self):
        deploy = self.template()["text"]
        def ci(**jobs_or_keys):     # noqa: E306
            w = json.loads(json.dumps(CI))
            for key, value in jobs_or_keys.items():
                w[key] = value
            return json.dumps(w)
        build = CI["jobs"]["build"]
        secret = dict(build, steps=build["steps"] + [{"run": "npm publish", "env": {"T": "${{ secrets.NPM_TOKEN }}"}}])
        cases = {
            "a second job on the runner's label": (
                ci(jobs={"build": dict(build, **{"runs-on": ["self-hosted", "shopapp"]})}),
                "runs on one of GitHub's runners"),
            "a label that a runner of the host has": (ci(jobs={"build": dict(build, **{"runs-on": "linux"})}),
                                                      "runs on one of GitHub's runners"),
            "a runner from an expression": (ci(jobs={"build": dict(build, **{"runs-on": "${{ matrix.os }}"})}),
                                            "runs on one of GitHub's runners"),
            "a job-level uses": (ci(jobs={"build": build, "call": {"uses": "one-org/x/.github/workflows/a.yml@main"}}),
                                 "calls a workflow with uses"),
            "a secret": (ci(jobs={"build": secret}), "the secret in 'secrets.NPM_TOKEN'"),
            "a secret in an if": (
                ci(jobs={"build": dict(build, steps=[{"if": "secrets.NPM_TOKEN != ''", "run": "x"}])}),
                "no secret but GITHUB_TOKEN"),
            "every secret": (ci(env={"ALL": "${{ toJSON(secrets) }}"}), "no secret but GITHUB_TOKEN"),
            "secrets passed on": (ci(on={"workflow_call": {"secrets": {"x": {}}}}), "a secrets key"),
            "id-token write": (ci(jobs={"build": dict(build, permissions={"id-token": "write"})}), "id-token write"),
            "every permission": (ci(permissions="write-all"), "id-token write"),
            "pull_request_target": (ci(on={"pull_request_target": {}}), "the trigger pull_request_target"),
            "workflow_run": (ci(on=["push", "workflow_run"]), "the trigger workflow_run"),
            "a key that is not a workflow's": (ci(container="x"), "container is not a key of a workflow"),
            "YAML text": ("name: CI\non: push\njobs: {}\n", "reads a workflow as JSON"),
        }
        for why, (text, words) in cases.items():
            with self.subTest(why):
                d = self.decide((".github/workflows/ci.yml", text))
                self.assertEqual(d.kind, "refused", d)
                self.assertIn(words, d.why)
        template = json.loads(deploy)
        checkout = json.loads(deploy)
        checkout["jobs"]["deploy"]["steps"].insert(0, {"uses": "actions/checkout@v4"})
        second = json.loads(deploy)
        second["jobs"]["build"] = dict(build, **{"runs-on": ["self-hosted", "shopapp"]})
        other = json.loads(json.dumps(template).replace('"shopapp"', '"blog"'))
        for why, workflow in (("a deploy job that runs a step from the repository", checkout),
                              ("a second job beside the deploy job", second), ("another app's runner", other)):
            with self.subTest(why):
                d = self.decide((".github/workflows/deploy.yml", json.dumps(workflow)))
                self.assertEqual(d.kind, "refused", d)
                self.assertIn("the product's deploy workflow", d.why)
        d = self.decide((".github/workflows/ci.yml", json.dumps(CI)), ("README.md", "hello"))
        self.assertIn("holds only workflow files", d.why)
        self.assertEqual(self.decide((".github/workflows/ci.yml", json.dumps(CI)), agent="ops-two").kind, "refused")
        self.assertEqual(self.decide((".github/workflows/ci.yml", json.dumps(CI))).kind, "rule")


class RunnerNew(DoorCase):
    """New-projects plan N6: runner-new takes the repository from the door's own record, for the agent that made it,
    gets a registration and a remove token with a token of its own for that one call, reads the runner's release and
    the SHA-256 that GitHub publishes for it, and sends it all on the host's stdin; no answer shows a token."""
    X64, ARM = "a" * 64, "b" * 64

    def setUp(self):
        super().setUp()
        door.write_json(door.REPOS_FILE, {"pending": {}, "made": {
            "one-org/shopapp": {"id": 5, "agent": "ops-one", "app": "shopapp", "repo": "one-org/shopapp"}}})
        patcher = patch.object(door_providers, "app_jwt", lambda app_id, pem, sign=None: "jwt")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.github, self.release = [], {
            "tag_name": "v2.329.0",
            "body": f"<!-- BEGIN SHA linux-x64 -->{self.X64}<!-- END SHA linux-x64 -->\n"
                    f"<!-- BEGIN SHA linux-arm64 -->{self.ARM}<!-- END SHA linux-arm64 -->",
            "assets": [{"name": "actions-runner-linux-x64-2.329.0.tar.gz", "digest": "sha256:" + self.X64},
                       {"name": "actions-runner-linux-arm64-2.329.0.tar.gz", "digest": "sha256:" + self.ARM}]}
        install = {"id": 77, "permissions": {"administration": "write", "metadata": "read"}}

        def http(method, url, headers, body):
            self.github.append((method, url, headers, body))
            api = "https://api.github.com"
            runners = f"{api}/repos/one-org/shopapp/actions/runners"
            answers = {f"{api}/repos/one-org/shopapp/installation": (200, install),
                       f"{api}/app/installations/77/access_tokens": (201, {"token": "ghs_onecall"}),
                       f"{runners}/registration-token": (201, {"token": "REGTOKEN0123456789ABCD"}),
                       f"{runners}/remove-token": (201, {"token": "REMTOKEN0123456789ABCD"}),
                       door_providers.RUNNER_RELEASE: (200, self.release)}
            return answers.get(url, (404, {}))
        self.door.http = http

    def test_runner_new_sends_the_tokens_and_the_release_on_stdin(self):
        got = self.call(ONE, "web-1", "runner-new", "shopapp")
        self.assertEqual((got["ok"], got["kind"]), (True, "rule"), got)
        address, op, args, stdin = self.stubs.ssh_calls[-1]
        self.assertEqual((address, op, args), ("100.64.1.1", "runner-new", ["shopapp"]))
        self.assertEqual(json.loads(stdin), {"token": "REGTOKEN0123456789ABCD", "remove": "REMTOKEN0123456789ABCD",
                                             "url": "https://github.com/one-org/shopapp", "name": "web-1-shopapp",
                                             "version": "2.329.0", "sha256": {"x64": self.X64, "arm64": self.ARM}})
        asked = json.loads(next(b for m, u, h, b in self.github if u.endswith("/access_tokens")))
        self.assertEqual(asked, {"permissions": {"administration": "write", "metadata": "read"}})
        release = next(h for m, u, h, b in self.github if u == door_providers.RUNNER_RELEASE)
        self.assertNotIn("Authorization", release)
        for said in (json.dumps(got), slurp(self.root + door.RECORD_FILE, "r")):
            self.assertNotIn("TOKEN0123", said)

    def test_runner_new_needs_the_door_s_own_repository_of_this_agent(self):
        for address, host, app, words in ((ONE, "web-1", "blog", "the door made no repository blog for this agent"),
                                          (TWO, "web-2", "shopapp", "the door made no repository shopapp")):
            with self.subTest(app=app):
                got = self.call(address, host, "runner-new", app)
                self.assertIn(words, got["why"])
        self.assertIn("takes no content", self.call(ONE, "web-1", "runner-new", "shopapp", content=b"x")["why"])
        self.assertEqual(self.stubs.ssh_calls, [])

    def test_runner_new_on_a_rule_only_host_makes_no_token(self):
        """Before, the door took runner-new on a rule-only host as a rule call: it made a registration and a remove
        token of the repository and sent them, and only the host refused."""
        got = self.call(ONE, "ci-1", "runner-new", "shopapp")
        self.assertEqual((got["ok"], got["kind"], got["why"]),
                         (False, "refused", "ci-1 is rule-only: no form of a new app writes there"))
        self.assertNotIn("call", got)                   # code refused it: no yes of the owner opens it
        self.assertEqual((self.github, self.stubs.ssh_calls), ([], []))

    def test_a_release_with_no_one_sha256_stops_the_call(self):
        for why, change in (("the notes disagree", lambda r: r.update(body=r["body"].replace(self.X64, "c" * 64))),
                            ("no asset", lambda r: r.update(assets=r["assets"][1:])),
                            ("no sum at all", lambda r: r.update(body="", assets=[{"name": a["name"]}
                                                                                   for a in r["assets"]]))):
            with self.subTest(why):
                release = json.loads(json.dumps(self.release))
                change(release)
                with self.assertRaisesRegex(door_providers.Stop, "no one SHA-256"):
                    door_providers.runner_release(release)
        release = json.loads(json.dumps(self.release))
        release["body"] = ""
        self.assertEqual(door_providers.runner_release(release), ("2.329.0", {"x64": self.X64, "arm64": self.ARM}))
        got = self.call(ONE, "web-1", "runner-new", "shopapp")
        self.assertTrue(got["ok"], got)
        self.release["tag_name"] = "latest"
        self.assertFalse(self.call(ONE, "web-1", "runner-new", "shopapp")["ok"])


class Probe(DoorCase):
    """New-projects plan N8 (b): test 1 of the DevOps plan as code, from the door, against a host's new second sshd:
    a login with no request, a shell, a TTY, scp, both TCP forwards, a Unix-socket forward and a form outside the
    list fail, and a read and a rule form through sudo ops-root work."""
    GOOD = (("-tt", (0, "PTY allocation request failed on channel 0\n 12:00 up 3 days, load average: 0.10")),
            ("-W", (255, "channel 0: open failed: administratively prohibited: open failed")),
            ("/tmp/door-probe.sock:127.0.0.1:22", (255, "Error: remote port forwarding failed for listen path")),
            ("127.0.0.1:0:127.0.0.1:22", (255, "Error: remote port forwarding failed for listen port 0")),
            ("scp", (1, "subsystem request failed on channel 0")))

    def setUp(self):
        super().setUp()
        self.ran, self.answers = [], dict(self.GOOD)

        def run_program(argv, stdin, env, timeout=600):
            self.ran.append(argv)
            for word, answer in self.answers.items():
                if word in argv or argv[0] == word:
                    return answer
            last = argv[-1]
            try:
                op = json.loads(base64.b64decode(last))["op"]
            except ValueError:
                op = None
            return {"uptime": (0, " 12:00 up 3 days, load average: 0.10"),
                    "daemon-reload": (0, "systemd read its units again"),
                    "nonsense": (3, "refused: nonsense is not a form of this host")}.get(
                op, (3, "refused: this login takes the door's requests only"))
        patcher = patch.object(door, "run_program", run_program)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_host_whose_second_sshd_refuses_all_but_its_forms_passes(self):
        checks = door.probe(ACCESS["hosts"]["web-1"])
        self.assertEqual([c[0] for c in checks if not c[1]], [], checks)
        self.assertEqual(len(checks), 10)
        ssh = self.ran[0]
        self.assertEqual(ssh[:3], ["ssh", "-p", "2244"])
        self.assertIn(self.root + door.SSH_KEY, ssh)
        self.assertIn("StrictHostKeyChecking=yes", ssh)
        self.assertEqual(ssh[-1], "ops-agent@100.64.1.1")              # the login with no request

    def test_a_host_that_lets_one_through_fails_and_says_which(self):
        self.answers["-W"] = (0, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
        self.answers["127.0.0.1:0:127.0.0.1:22"] = (124, "ssh took longer than 30 seconds")
        self.answers["-tt"] = (0, " 12:00 up 3 days, load average: 0.10")
        failed = {c[0]: c[2] for c in door.probe(ACCESS["hosts"]["web-1"]) if not c[1]}
        self.assertEqual(sorted(failed), ["no TCP forward", "no TTY", "no remote TCP forward"])
        self.assertIn("SSH-2.0", failed["no TCP forward"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as ended:
            door.main(["probe", "web-1"])
        self.assertEqual(ended.exception.code, 1)
        said = json.loads(out.getvalue())
        self.assertEqual((said["host"], said["passed"]), ("web-1", False))
        with self.assertRaises(SystemExit) as ended:
            door.main(["probe", "nowhere"])
        self.assertIn("no host of the access file", str(ended.exception.code))



# ---------------------------------------------------------------- chart rendering (door_render.py)

def render_tools(folder):
    """The two programs of the render as this machine has them, or None: the door's pinned ones, or helm with
    kustomize, or helm with the kustomize that kubectl carries, behind a script of two lines."""
    pinned = door_render.installed_tools()
    if pinned:
        return pinned
    helm, kustomize, kubectl = shutil.which("helm"), shutil.which("kustomize"), shutil.which("kubectl")
    if not helm or not (kustomize or kubectl):
        return None
    if not kustomize:
        kustomize = os.path.join(folder, "kustomize")
        with open(kustomize, "w") as f:
            f.write(f'#!/bin/sh\nshift\nexec "{kubectl}" kustomize "$@"\n')
        os.chmod(kustomize, 0o755)
    return {"helm": [helm], "kustomize": [kustomize]}


def tarball(tree, links=None):
    "A repository's tree as GitHub packs it: one top folder, and gzip."
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for path, data in sorted(tree.items()):
            data = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo("one-org-cluster-0123abc/" + path)
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
        for path, target in sorted((links or {}).items()):
            info = tarfile.TarInfo("one-org-cluster-0123abc/" + path)
            info.type, info.linkname = tarfile.SYMTYPE, target
            tar.addfile(info)
    return out.getvalue()


def subchart(name, templates):
    "A packed chart, as `helm package` makes one for a chart's charts/ folder."
    out = io.BytesIO()
    files = dict({"Chart.yaml": f"apiVersion: v2\nname: {name}\nversion: 1.0.0\n", "values.yaml": "{}\n"},
                 **{"templates/" + n: t for n, t in templates.items()})
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for path, text in files.items():
            info = tarfile.TarInfo(f"{name}/{path}")
            info.size, info.mode = len(text.encode()), 0o644
            tar.addfile(info, io.BytesIO(text.encode()))
    return out.getvalue()


def b64(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def at(obj, pointer, value):
    "A copy of an object with a value at a JSON pointer."
    obj = copy.deepcopy(obj)
    node, parts = obj, pointer.strip("/").split("/")
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node.setdefault(part, {})
    node[parts[-1]] = value
    return obj


HEAD_SHA = "0123abc" + "0" * 33
POD = "/spec/template/spec"
DEPLOYMENT = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
              "spec": {"replicas": 2, "selector": {"matchLabels": {"app": "web"}},
                       "template": {"metadata": {"labels": {"app": "web"}},
                                    "spec": {"hostNetwork": False, "containers": [
                                        {"name": "web", "image": "ghcr.io/one-org/web:1111111",
                                         "securityContext": {"privileged": False}}]}}}}
SERVICE = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "web"},
           "spec": {"type": "ClusterIP", "selector": {"app": "web"}, "ports": [{"port": 80}]}}
CLAIM = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data"},
         "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "10Gi"}}}}
CONFIG = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "extra"}, "data": {"mode": "plain"}}
BASE = {"deployment": DEPLOYMENT, "service": SERVICE, "pvc": CLAIM}
# Each refused form of door_targets.MANIFEST_REFUSED and the three counts beside it: (the form, the object that takes
# it and where, the value) or (the form, "new", a whole object of a refused kind).
FORMS = [
    ("a new secretKeyRef", "deployment", POD + "/containers/0/env",
     [{"name": "KEY", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}}]),
    ("a new secretRef", "deployment", POD + "/containers/0/envFrom", [{"secretRef": {"name": "db"}}]),
    ("a new secret volume", "deployment", POD + "/volumes", [{"name": "keys", "secret": {"secretName": "db"}}]),
    ("a hostPath", "deployment", POD + "/volumes", [{"name": "root", "hostPath": {"path": "/"}}]),
    ("privileged", "deployment", POD + "/containers/0/securityContext", {"privileged": True}),
    ("a host namespace", "deployment", POD + "/hostPID", True),
    ("a changed serviceAccountName", "deployment", POD + "/serviceAccountName", "cluster-admin"),
    ("a new LoadBalancer", "service", "/spec/type", "LoadBalancer"),
    ("a bigger volume claim", "pvc", "/spec/resources/requests/storage", "500Gi"),
    ("a Tailscale operator setting", "service", "/metadata/annotations", {"tailscale.com/tags": "tag:k8s"}),
    ("an Application", "new", {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
                               "metadata": {"name": "more"}, "spec": {"project": "default"}}),
    ("an external-secrets kind", "new", {"apiVersion": "external-secrets.io/v1beta1", "kind": "ExternalSecret",
                                         "metadata": {"name": "db"}, "spec": {"refreshInterval": "1h"}}),
    ("a CRD", "new", {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                      "metadata": {"name": "things.example.com"}, "spec": {"group": "example.com"}}),
    ("a webhook", "new", {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingWebhookConfiguration",
                          "metadata": {"name": "hook"}, "webhooks": []}),
    ("Secret object", "new", {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db"},
                              "stringData": {"password": "example"}}),
    ("RBAC", "new", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                     "metadata": {"name": "all"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}),
    ("a k3s upgrade channel", "new", {"apiVersion": "upgrade.cattle.io/v1", "kind": "Plan",
                                      "metadata": {"name": "server"},
                                      "spec": {"channel": "https://update.k3s.io/v1-release/channels/stable"}}),
]
STACK_VALUES = "replicas: 2\nimage:\n  repository: ghcr.io/one-org/web\n  tag: \"1111111\"\ndebug: false\n" \
               "hostNetwork: false\nstorage: 10Gi\nextraTemplate: \"\"\n"
STACK_DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-web
  labels: {{- include "stack.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicas }}
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      hostNetwork: {{ .Values.hostNetwork }}
      containers:
        - name: web
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          securityContext:
            privileged: {{ .Values.debug }}
"""
# The layout of a cluster repository that ArgoCD reads, with example names: Applications in a secret path that name a
# path only, a chart with templates and a packed subchart, a Kustomize folder, and a folder of plain manifests.
CLUSTER = {
    "_config/cluster/stack-argocd.yaml":
        "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: stack\n  namespace: argocd\nspec:\n"
        "  project: default\n  source:\n    repoURL: ssh://git@github.com/one-org/cluster.git\n"
        "    targetRevision: master\n    path: monitoring/stack\n  destination:\n    namespace: monitoring\n",
    "_config/cluster/core-argocd.yaml":
        "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: core\nspec:\n  source:\n"
        "    repoURL: ssh://git@github.com/one-org/cluster.git\n    path: apps/core/app\n    directory:\n"
        "      recurse: true\n  destination:\n    namespace: core\n",
    "monitoring/stack/Chart.yaml": "apiVersion: v2\nname: stack\nversion: 0.1.0\ndependencies:\n  - name: logs\n"
                                   "    version: 1.0.0\n    repository: https://charts.example.com\n",
    "monitoring/stack/charts/logs-1.0.0.tgz": subchart("logs", {
        "config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: logs\ndata: {level: info}\n"}),
    "monitoring/stack/values.yaml": STACK_VALUES,
    "monitoring/stack/templates/_helpers.tpl": '{{- define "stack.labels" -}}\napp: web\n{{- end }}\n',
    "monitoring/stack/templates/deployment.yaml": STACK_DEPLOYMENT,
    "monitoring/stack/templates/service.yaml":
        "apiVersion: v1\nkind: Service\nmetadata: {name: {{ .Release.Name }}-web}\n"
        "spec: {type: ClusterIP, selector: {app: web}, ports: [{port: 80}]}\n",
    "monitoring/stack/templates/pvc.yaml":
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: data\nspec:\n  accessModes: [ReadWriteOnce]\n"
        "  resources:\n    requests:\n      storage: {{ .Values.storage }}\n",
    "monitoring/stack/templates/secrets/basic-auth.yaml":
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: basic-auth\nstringData:\n  auth: example\n",
    "monitoring/stack/templates/extra.yaml": "{{- with .Values.extraTemplate }}{{ tpl . $ }}{{- end }}\n",
    "knative/kustomization.yaml": "resources:\n  - deployment.yaml\n  - service.yaml\n  - pvc.yaml\n  - config.yaml\n",
    "knative/deployment.yaml": json.dumps(DEPLOYMENT) + "\n",
    "knative/service.yaml": json.dumps(SERVICE) + "\n",
    "knative/pvc.yaml": json.dumps(CLAIM) + "\n",
    "knative/config.yaml": json.dumps(CONFIG) + "\n",
    "apps/core/app/web.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: web\ndata:\n  mode: plain\n",
    "README.md": "# The cluster\n",
}
GITOPS = "gitops:one-org/cluster"
# A repository that generates a file (door_render.generated): its declaration, a generator that this machine's Python
# runs in the place of the pinned Ruby, a rule that the generator reads, and the file as the generator writes it at HEAD
GEN_PATH = "monitoring/inventory/hosts.yaml"
GEN_SCRIPT = """import glob, hashlib, os, sys
prefix = open("tools/rules.txt").read().strip()
rows = []
for path in sorted(glob.glob("apps/core/app/*.yaml")):
    for line in open(path):
        if line.strip().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            if host == "fail":
                sys.exit("no inventory")
            rows.append(f"    {prefix} {host} {hashlib.sha256(host.encode()).hexdigest()[:12]}")
os.makedirs("monitoring/inventory", exist_ok=True)
with open("monitoring/inventory/hosts.yaml", "w") as f:
    f.write("apiVersion: v1\\nkind: ConfigMap\\nmetadata:\\n  name: inventory\\ndata:\\n  hosts: |\\n"
            + "".join(row + "\\n" for row in rows))
"""


def inventory(*hosts, prefix="public"):
    "The file of GEN_PATH as GEN_SCRIPT writes it for these hosts."
    return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: inventory\ndata:\n  hosts: |\n" + "".join(
        f"    {prefix} {h} {hashlib.sha256(h.encode()).hexdigest()[:12]}\n" for h in hosts)


def host_map(name, host):
    return f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {name}\ndata:\n  host: {host}\n"


GEN_TREE = dict(CLUSTER, **{
    ".founderizer/door.json": json.dumps({"generated": [
        {"path": GEN_PATH, "run": ["ruby", "tools/gen.py"], "rules": ["tools/rules.txt"]}]}),
    "tools/gen.py": GEN_SCRIPT, "tools/rules.txt": "public\n",
    "apps/core/app/a.yaml": host_map("a", "a.example.com"), "apps/core/app/b.yaml": host_map("b", "b.example.com"),
    GEN_PATH: inventory("a.example.com", "b.example.com")})


class RenderCase(unittest.TestCase):
    """A GitOps commit decided with a real render: door_render.answer with this machine's helm and kustomize, with no
    box (the box is the unit's, RenderBoxLive)."""
    tools = folder = None

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.mkdtemp(prefix="door-render-tools-")
        cls.addClassCleanup(shutil.rmtree, cls.folder, True)
        cls.tools = render_tools(cls.folder)
        cls.packed = tarball(CLUSTER)

    def setUp(self):
        if not self.tools:
            self.skipTest("this machine has no helm, or no kustomize and no kubectl")

    def lookup(self, tree=None, links=None):
        "The door's render lookup for one tree at HEAD."
        packed = self.packed if (tree is None or tree is CLUSTER) and not links else tarball(tree, links)

        def render(files):
            scratch = tempfile.mkdtemp(prefix="door-render-test-")
            self.addCleanup(shutil.rmtree, scratch, True)
            header = {"v": 1, "op": "render", "exposure": ACCESS["exposure"], "files": [
                {"path": p, "size": None if d is None else len(d), "mode": m} for p, d, m in files]}
            report = door_render.answer(header, packed, [d for _p, d, _m in files], self.tools, scratch)
            self.last = report
            return dict(report, head=HEAD_SHA) if report.get("ok") else report
        return render

    def push(self, files, tree=None, links=None, render=True):
        content = json.dumps({"message": "change", "files": [
            {"path": p, "delete": True} if t is None else
            {"path": p, "content": base64.b64encode(t if isinstance(t, bytes) else t.encode()).decode()}
            for p, t in files.items()]}).encode()
        tree = CLUSTER if tree is None else tree
        lookups = {"render": self.lookup(tree, links)} if render else \
            {"base_file": lambda p: tree[p].encode() if isinstance(tree.get(p), str) else tree.get(p),
             "declared": lambda: door_targets.DOOR_DECLARATION in tree}
        return door_targets.decide(ACCESS, "ops-one", GITOPS, "push", [], content, lookups)


class Rendered(RenderCase):
    """Done-when (b) of the chart rendering task: in a copy of the layout of a cluster repository, an ordinary line of
    a Helm template and a new template are the agent's own call, and each refused form is refused through a template
    function, a values file, a flow mapping, a Kustomize patch and a JSON 6902 patch."""

    def test_an_ordinary_line_of_a_template_and_a_new_template_are_the_agent_s_own_call(self):
        path = "monitoring/stack/templates/deployment.yaml"
        without = self.push({path: STACK_DEPLOYMENT.replace("matchLabels: {app: web}", "matchLabels: {app: web, x: y}")},
                            render=False)
        self.assertEqual(without.kind, "refused", without)          # the limit of version 1.124, with no render
        self.assertIn("only an image, a tag, a replica count and a restart time", without.why)
        d = self.push({path: STACK_DEPLOYMENT.replace("        - name: web\n", "        - name: web\n"
                                                      "          args: [\"--verbose\", {{ .Values.replicas | quote }}]\n")})
        self.assertEqual((d.kind, d.why), ("own", f"{path} changes more than its values"), d)
        self.assertEqual(d.plan["parent"], HEAD_SHA)                # the commit goes on the commit that was rendered
        new = "monitoring/stack/templates/policy.yaml"
        policy = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n" \
                 "  name: {{ .Release.Name }}-web\nspec:\n  podSelector: {matchLabels: {{ include \"stack.labels\" . " \
                 "| fromYaml | toJson }}}\n  policyTypes: [Ingress]\n"
        self.assertEqual(self.push({new: policy}, render=False).kind, "refused")
        d = self.push({new: policy})
        self.assertEqual((d.kind, d.why), ("own", f"{new} is a new manifest"), d)
        # a helper file with another name, with a word that the loose reading counts, and a new packed subchart
        d = self.push({"monitoring/stack/templates/_helpers.tpl":
                       CLUSTER["monitoring/stack/templates/_helpers.tpl"] + "{{/* no hostPath here */}}\n"})
        self.assertEqual(d.kind, "own", d)
        d = self.push({"monitoring/stack/charts/logs-1.0.0.tgz": subchart("logs", {
            "config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: logs\ndata: {level: debug}\n"})})
        self.assertEqual(d.kind, "own", d)
        # the listed values of a template stay rule calls
        d = self.push({"monitoring/stack/values.yaml": STACK_VALUES.replace("replicas: 2", "replicas: 3")})
        self.assertEqual((d.kind, d.why), ("rule", "a listed GitOps change"), d)

    def commits(self, form):
        "{route: the files of a commit that writes one refused form by that route}."
        name, kind = form[0], form[1]
        if kind == "new":
            new = fresh = form[2]
            ops = [{"op": "replace", "path": "/" + k, "value": v} for k, v in new.items() if k in ("apiVersion", "kind")] \
                + [{"op": "add", "path": "/" + k, "value": v} for k, v in new.items()
                   if k not in ("apiVersion", "kind", "metadata")]
            target, merge = "kind: ConfigMap\n      name: extra", None
        else:
            new = at(BASE[kind], form[2], form[3])
            # by a template, a value and a plain file the form comes in an object of its own; a patch changes the one
            # that is there
            fresh = at(new, "/metadata/name", new["metadata"]["name"] + "-2")
            ops = [{"op": "add", "path": form[2], "value": form[3]}]
            target, merge = f"kind: {new['kind']}\n      name: {new['metadata']['name']}", new
        text = f'{{{{ "{b64(fresh)}" | b64dec }}}}'
        kustomization = CLUSTER["knative/kustomization.yaml"] + "patches:\n  - path: patch.yaml\n"
        routes = {
            "a template function": {"monitoring/stack/templates/built.yaml": text + "\n"},
            "a values file": {"monitoring/stack/values.yaml": STACK_VALUES.replace('extraTemplate: ""',
                                                                                 f"extraTemplate: '{text}'")},
            "a flow mapping": {"apps/core/app/more.yaml": json.dumps(fresh) + "\n"},
            "a JSON 6902 patch": {"knative/patch.yaml": json.dumps(ops) + "\n",
                                  "knative/kustomization.yaml": kustomization + f"    target:\n      {target}\n"},
        }
        if merge:       # a merge patch changes no kind: a form that is a kind comes by the 6902 patch
            routes["a Kustomize patch"] = {"knative/patch.yaml": json.dumps(merge) + "\n",
                                           "knative/kustomization.yaml": kustomization}
        return routes

    def test_each_refused_form_is_refused_by_each_route(self):
        self.assertEqual({f[0] for f in FORMS} - {"Secret object"} | {"a Secret object"},
                         set(door_targets.MANIFEST_REFUSED) | {"a k3s upgrade channel", "a changed serviceAccountName",
                                                               "a bigger volume claim"})
        count = 0
        for form in FORMS:
            for route, files in self.commits(form).items():
                with self.subTest(form=form[0], route=route):
                    d = self.push(files)
                    self.assertEqual(d.kind, "refused", (d, self.last))
                    self.assertIn(form[0], d.why)
                    count += 1
        self.assertEqual(count, 17 * 4 + 10)

    def test_the_same_routes_pass_what_is_no_refused_form(self):
        "Each route of the test above with a harmless change is the agent's own call: the routes themselves work."
        harmless = ("ok", "deployment", POD + "/containers/0/args", ["--verbose"])
        for route, files in self.commits(harmless).items():
            with self.subTest(route=route):
                d = self.push(files)
                self.assertEqual(d.kind, "own", (route, d, self.last))
        added = ("ok", "new", {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "more"},
                               "data": {"a": "b"}})
        for route, files in self.commits(added).items():
            with self.subTest(route=route, new=True):
                self.assertEqual(self.push(files).kind, "own", (route, self.last))

    def test_a_value_that_a_template_of_head_turns_into_a_refused_form(self):
        """The hole that no line reader closes: the value and its template are two files. `debug: true` is no refused
        line, and the template that is there already makes it `privileged: true`."""
        flip = {"monitoring/stack/values.yaml": STACK_VALUES.replace("debug: false", "debug: true")}
        self.assertEqual(self.push(flip, render=False).kind, "own")         # before the render: it passed
        d = self.push(flip)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("the chart monitoring/stack, rendered with its own values: an object of "
                      "stack/templates/deployment.yaml: privileged", d.why)
        d = self.push({"monitoring/stack/values.yaml": STACK_VALUES.replace("hostNetwork: false", "hostNetwork: yes")})
        self.assertIn("a host namespace", d.why)
        d = self.push({"monitoring/stack/values.yaml": STACK_VALUES.replace("storage: 10Gi", "storage: 20Gi")})
        self.assertIn("a bigger volume claim", d.why)       # the block reader says it of the values file itself
        # a template that builds the key from parts, in a branch of a value: no word of it is in the file
        built = STACK_DEPLOYMENT + '      {{ printf "host%s" "PID" }}: {{ gt (int .Values.replicas) 1 }}\n'
        d = self.push({"monitoring/stack/templates/deployment.yaml": built})
        self.assertIn("a host namespace", d.why)
        # and a packed subchart with a privileged pod
        d = self.push({"monitoring/stack/charts/logs-1.0.0.tgz": subchart("logs", {
            "pod.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: logs\nspec:\n  containers:\n"
                        "    - name: logs\n      image: x\n      securityContext: {privileged: true}\n"})})
        self.assertIn("an object of stack/charts/logs/templates/pod.yaml: privileged", d.why)

    def test_a_form_does_not_move_from_one_object_to_another(self):
        "The count is of one object: a hostPath that leaves one workload does not pay for one in another."
        tree = dict(CLUSTER)
        tree["knative/deployment.yaml"] = json.dumps(at(DEPLOYMENT, POD + "/volumes",
                                                        [{"name": "root", "hostPath": {"path": "/var/log"}}])) + "\n"
        other = at(at(DEPLOYMENT, "/metadata/name", "other"), POD + "/volumes",
                   [{"name": "root", "hostPath": {"path": "/"}}])
        d = self.push({"knative/deployment.yaml": json.dumps(DEPLOYMENT) + "\n",
                       "knative/other.yaml": json.dumps(at(other, "/kind", "Deployment")) + "\n",
                       "knative/kustomization.yaml": tree["knative/kustomization.yaml"] + "  - other.yaml\n"}, tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("a hostPath", d.why)
        # and the same path in the same object is no new form
        moved = at(DEPLOYMENT, POD + "/volumes", [{"name": "root", "hostPath": {"path": "/var/log"}}])
        d = self.push({"knative/deployment.yaml": json.dumps(at(moved, "/spec/replicas", 3)) + "\n"}, tree)
        self.assertEqual(d.kind, "own", (d, self.last))

    def test_a_secret_of_the_render_is_neither_new_nor_changed(self):
        path = "monitoring/stack/templates/secrets/basic-auth.yaml"
        d = self.push({path: CLUSTER[path].replace("auth: example", "auth: {{ .Values.replicas | quote }}")})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("an object of stack/templates/secrets/basic-auth.yaml is a new or a changed Secret object", d.why)
        # the Secret that the chart holds at HEAD stops no other change of the chart
        d = self.push({"monitoring/stack/values.yaml": STACK_VALUES.replace("replicas: 2", "replicas: 4")})
        self.assertEqual(d.kind, "rule", d)

    def test_an_application_of_the_tree_gives_its_values(self):
        """A chart is rendered with each value set that an Application of the tree gives it, and each one must pass:
        a values file elsewhere in the repository, a parameter, the release name and the namespace."""
        tree = dict(CLUSTER)
        tree["argocd/stack-live.yaml"] = (
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: stack-live\nspec:\n  source:\n"
            "    repoURL: ssh://git@github.com/one-org/cluster.git\n    path: monitoring/stack\n    helm:\n"
            "      releaseName: live\n      valueFiles:\n        - ../../envs/live/stack.yaml\n      parameters:\n"
            "        - name: replicas\n          value: \"5\"\n  destination:\n    namespace: live\n")
        tree["envs/live/stack.yaml"] = "debug: false\n"
        d = self.push({"envs/live/stack.yaml": "debug: true\n"}, tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("rendered with the values of the Application stack-live: an object of "
                      "stack/templates/deployment.yaml: privileged", d.why)
        d = self.push({"envs/live/stack.yaml": "debug: false\nhostNetwork: false\n"}, tree)
        self.assertEqual(d.kind, "own", (d, self.last))
        sets = {c["set"] for u in self.last["units"].values() for c in u["changed"]}
        self.assertEqual(sets, set())                       # nothing differs, with either value set
        d = self.push({"monitoring/stack/values.yaml": STACK_VALUES.replace("ghcr.io/one-org/web", "ghcr.io/one-org/w")},
                      tree)
        self.assertEqual({c["set"] for u in self.last["units"].values() for c in u["changed"]},
                         {"its own values", "the values of an Application",       # of a secret path: no name
                          "the values of the Application stack-live"})
        # an input that the door cannot give the chart: its files keep the limit of version 1.124
        for odd, words in (("      valueFiles:\n        - https://example.com/values.yaml\n", "at a URL"),
                           ("      valueFiles:\n        - $values/stack.yaml\n", "another repository or revision"),
                           ("      postRenderers: []\n", "the helm setting postRenderers")):
            with self.subTest(odd=odd):
                other = dict(tree)
                other["argocd/stack-live.yaml"] = tree["argocd/stack-live.yaml"].replace(
                    "      valueFiles:\n        - ../../envs/live/stack.yaml\n", odd)
                d = self.push({"monitoring/stack/templates/deployment.yaml": STACK_DEPLOYMENT + "# a comment\n"}, other)
                self.assertEqual(d.kind, "refused", d)
                self.assertIn("The door could not render monitoring/stack (an Application gives it", d.why)
                self.assertIn(words, d.why)

    def test_a_unit_that_does_not_render_keeps_the_limit(self):
        template = "monitoring/stack/templates/deployment.yaml"
        change = {template: STACK_DEPLOYMENT.replace("app: web}", "app: web, tier: front}")}
        # a dependency that is not in charts/: no network gets it
        tree = {k: v for k, v in CLUSTER.items() if not k.endswith(".tgz")}
        d = self.push(change, tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("only an image, a tag, a replica count and a restart time", d.why)
        self.assertIn("The door could not render monitoring/stack (its render fails at HEAD too", d.why)
        self.assertEqual(self.push({"monitoring/stack/values.yaml": STACK_VALUES.replace("replicas: 2", "replicas: 3")},
                                   tree).kind, "rule")
        # a template with a random function: two renders differ, so the door did not read what a cluster applies
        tree = dict(CLUSTER)
        tree["monitoring/stack/templates/token.yaml"] = \
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: token\ndata:\n  salt: {{ randAlphaNum 12 | quote }}\n"
        d = self.push(change, tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("two renders of the same tree differ", d.why)
        # a commit that breaks the render of a chart that rendered at HEAD
        d = self.push({template: STACK_DEPLOYMENT + "{{ if }}\n"})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("the chart monitoring/stack renders at HEAD and not after this commit", d.why)
        d = self.push({"knative/kustomization.yaml": "resources:\n  - https://example.com/install.yaml\n"})
        self.assertIn("the Kustomize folder knative renders at HEAD and not after this commit", d.why)
        # a line that ends a document: one reader of a cluster stops there and another does not
        d = self.push({"monitoring/stack/templates/more.yaml":
                       "kind: ConfigMap\nmetadata: {name: x}\n...\nkind: Pod\nspec: {hostPID: true}\n"})
        self.assertIn("a line that ends a document", d.why)
        with self.assertRaises(door_render.Failed):
            door_render.split_docs("a: b\n--- kind: Pod\n")
        self.assertEqual(door_render.split_docs("---\na: b\n---  \n# only a comment\n---\r\nc: d\n"),
                         ["a: b\n", "c: d\n"])

    def test_no_commit_takes_a_unit_out_of_the_render(self):
        """Inside a unit that rendered, a template changed with no line rule. So the rules that read lines are no
        fallback there, and a commit that would leave the door unable to render the unit is refused: else an agent
        could first write a template that turns a value into a refused form, then stop the render, then set the
        value."""
        # a block style template, which the line rules pass, with a random function in a quoted text
        salt = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: salt\ndata:\n  salt: \"{{ randAlphaNum 12 }}\"\n"
        self.assertEqual(self.push({"monitoring/stack/templates/salt.yaml": salt}, render=False).kind, "own")
        d = self.push({"monitoring/stack/templates/salt.yaml": salt})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("renders at HEAD and not after this commit (two renders of the same tree differ", d.why)
        # an Application in a path that the agent may write, changed to give the chart an input that the door cannot
        tree = dict(CLUSTER)
        app = CLUSTER["_config/cluster/stack-argocd.yaml"]
        tree["argocd/stack.yaml"] = app
        d = self.push({"argocd/stack.yaml": app.replace("    path: monitoring/stack\n", "    path: monitoring/stack\n"
                                                        "    plugin:\n      name: other\n")}, tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("after this commit, an Application gives it a plugin", d.why)
        # and one that gives the chart a parameter: the chart is rendered with it, though no file of the chart changed
        d = self.push({"argocd/stack.yaml": app.replace("    path: monitoring/stack\n", "    path: monitoring/stack\n"
                                                        "    helm:\n      parameters:\n        - name: debug\n"
                                                        "          value: \"true\"\n")}, tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("rendered with the values of the Application stack: an object of "
                      "stack/templates/deployment.yaml: privileged", d.why)
        d = self.push({"argocd/stack.yaml": app.replace("    path: monitoring/stack\n", "    path: monitoring/stack\n"
                                                        "    helm:\n      parameters:\n        - name: replicas\n"
                                                        "          value: \"3\"\n")}, tree)
        self.assertEqual(d.kind, "own", (d, self.last))
        # a new chart that does not render
        d = self.push({"apps/new/Chart.yaml": "apiVersion: v2\nname: new\nversion: 0.1.0\ndependencies:\n"
                                              "  - name: far\n    version: 1.0.0\n    repository: https://charts.example.com\n",
                       "apps/new/templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: new\n"})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("the chart apps/new renders at HEAD and not after this commit", d.why)
        self.assertIn("missing in charts/ directory", d.why)
        # more units in one commit than the door renders, and a path that is a folder at HEAD: refusals, no fallback
        tree = dict(CLUSTER)
        files = {}
        for n in range(door_render.UNITS_MOST + 1):
            tree[f"many/c{n}/Chart.yaml"] = f"apiVersion: v2\nname: c{n}\nversion: 0.1.0\n"
            tree[f"many/c{n}/values.yaml"] = "a: 1\n"
            files[f"many/c{n}/values.yaml"] = "a: 2\n"
        d = self.push(files, tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("touches more than 16 charts and Kustomize folders", d.why)
        d = self.push({"monitoring/stack/values.yaml": STACK_VALUES.replace("debug: false", "debug: true"),
                       "knative": "a file where a folder is\n"})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("knative is a folder at HEAD", d.why)

    def test_a_file_of_no_unit_keeps_its_rules_and_the_real_parser_reads_flow_style(self):
        d = self.push({"apps/core/app/flow.yaml": '{apiVersion: v1, kind: ConfigMap, metadata: {name: f}, data: {}}\n'})
        self.assertEqual((d.kind, d.why), ("own", "apps/core/app/flow.yaml is a new manifest"), d)
        # spellings that a line reader does not read, read as the cluster reads them
        for text, what in (('{kind: Pod, spec: {"hostNetwork": yes}}\n', "a host namespace"),
                           ("a: &k Secret\nkind: *k\nstringData: {x: y}\n", "holds a Secret object"),
                           ("kind: Pod\nspec:\n  !!str hostPID: !!bool \"true\"\n", "a host namespace"),
                           ("kind: Pod\nspec: {containers: [{securityContext: {<<: {privileged: on}}}]}\n",
                            "privileged")):
            with self.subTest(text=text):
                d = self.push({"apps/core/app/odd.yaml": text})
                self.assertEqual(d.kind, "refused", d)
                self.assertIn(what, d.why)
        # a template outside every chart is read by nothing: it keeps the block reader's refusal
        d = self.push({"apps/core/app/t.yaml": "kind: ConfigMap\ndata:\n  a: {{ .Values.a }}\n"})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("the door takes it only in block style", d.why)
        # and a file with another name outside a unit keeps the loose reading
        d = self.push({"docs/notes.txt": "set hostPath here\n"})
        self.assertIn("the word hostpath", d.why)
        self.assertEqual(self.push({"README.md": "# The cluster, again\n"}).kind, "own")
        # the path rules come first, with a render too
        self.assertIn("secret path", self.push({"_config/cluster/x.yaml": "a: b\n"}).why)

    def test_a_delete_and_a_link_are_rendered_too(self):
        tree = dict(CLUSTER)
        tree["knative/kustomization.yaml"] += "patches:\n  - path: safe.yaml\n"
        tree["knative/deployment.yaml"] = json.dumps(at(DEPLOYMENT, POD + "/hostNetwork", True)) + "\n"
        tree["knative/safe.yaml"] = json.dumps(DEPLOYMENT) + "\n"       # the patch that turns the host network off
        d = self.push({"knative/safe.yaml": None, "knative/kustomization.yaml": CLUSTER["knative/kustomization.yaml"]},
                      tree)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("the Kustomize folder knative, rendered with its own values: an object: a host namespace", d.why)
        d = self.push({"knative/config.yaml": None,
                       "knative/kustomization.yaml": CLUSTER["knative/kustomization.yaml"].replace("  - config.yaml\n", "")})
        self.assertEqual((d.kind, d.why), ("own", "knative/config.yaml is deleted"), (d, self.last))
        # a chart reads a file of another folder through a link: the file's change is the chart's change
        tree = dict(CLUSTER)
        tree["shared/extra.yaml"] = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: shared\ndata:\n  a: b\n"
        links = {"monitoring/stack/templates/shared.yaml": "../../../shared/extra.yaml"}
        d = self.push({"shared/extra.yaml": tree["shared/extra.yaml"] +
                       '  c: "{{ "x\\"\\nkind: Secret\\nstringData:\\n  k: v\\n#" }}"\n'}, tree, links)
        self.assertEqual(d.kind, "refused", (d, self.last))
        self.assertIn("Secret object", d.why)

    def test_a_unit_that_reads_what_no_agent_may_read_names_nothing(self):
        """A template can copy what it reads into an object's name or into its own error. So no refusal has a name
        out of a render, in any unit. And a chart or a folder that can read a path that the door gives no agent (a
        secret path, a path of the exposure register, also through a link, or the values of an Application of such
        a path) is closed: it is rendered and decided, its refusal says only "an object" and the form, and its files
        keep the rules that need no render."""
        token = "s3cr3t-Value_42"
        leak = '{{ fail (printf "file: %s.yaml" (.Files.Get "_config/token.txt" | trim)) }}\n'
        named = "apiVersion: v1\nkind: Service\nmetadata:\n  name: \"{{ .Files.Get \"_config/token.txt\" | trim | lower }}\"\n" \
                "spec:\n  ports:\n    - port: 80\n  externalIPs:\n    - \"{{ .Values.replicas }}\"\n"
        flip = {"monitoring/stack/values.yaml": STACK_VALUES.replace("debug: false", "debug: true")}
        app = CLUSTER["_config/cluster/stack-argocd.yaml"].replace(
            "    path: monitoring/stack\n", "    path: monitoring/stack\n    helm:\n      parameters:\n"
            f"        - name: image.tag\n          value: {token}\n")
        sub = {"monitoring/stack/files/db.yaml": f"kind: Secret\nstringData:\n  pw: {token}\n"}
        live = CLUSTER["_config/cluster/stack-argocd.yaml"].replace(
            "    path: monitoring/stack\n", "    path: monitoring/stack\n    helm:\n      valueFiles:\n"
            "        - ../../values/live.yaml\n")
        trees = {"a file of a secret path": (dict(CLUSTER, **{"monitoring/stack/_config/token.txt": token + "\n"}), {}),
                 "a file of the exposure register": (dict(CLUSTER, **{"monitoring/stack/apps/legacy/token.txt": token}),
                                                     {}),
                 "a link in the chart to a secret path": (dict(CLUSTER, **{"live/Secrets/token.txt": token}),
                                                          {"monitoring/stack/files": "../../live/Secrets"}),
                 "a values file that is a link to a secret path": (
                     dict(CLUSTER, **{"argocd/stack-live.yaml": live, "live/Secrets/values.yaml": f"t: {token}\n"}),
                     {"values/live.yaml": "../live/Secrets/values.yaml"}),
                 "the values of an Application of a secret path": (dict(CLUSTER, **{
                     "_config/cluster/stack-argocd.yaml": app}), {})}
        for what, (tree, links) in trees.items():
            with self.subTest(what=what):
                d = self.push(flip, tree, links)                    # the render still decides
                self.assertEqual(d.kind, "refused", (d, self.last))
                self.assertIn(": an object: privileged", d.why)
                self.assertTrue(self.last["units"]["helm:monitoring/stack"]["closed"])
                for files in ({"monitoring/stack/templates/leak.yaml": leak},
                              {"monitoring/stack/templates/named.yaml": named},
                              {"monitoring/stack/templates/deployment.yaml": STACK_DEPLOYMENT + "# a comment\n"}):
                    d = self.push(files, tree, links)
                    self.assertNotIn(token.lower(), d.why.lower())
                    if "leak.yaml" in str(files):                   # the program's own words are in no refusal
                        self.assertEqual(d.kind, "refused", d)
                        self.assertTrue(d.why.endswith("(helm failed)"), d.why)
                    if "deployment.yaml" in str(files):             # the door widens nothing there
                        self.assertEqual(d.kind, "refused", d)
                        self.assertIn("can read a path that the door gives no agent", d.why)
        # A Kustomize folder whose resource is a link to a secret path
        tree = dict(CLUSTER, **{"live/Secrets/config.yaml": json.dumps(CONFIG) + "\n"})
        self.push({"knative/kustomization.yaml": CLUSTER["knative/kustomization.yaml"] + "namePrefix: a-\n"}, tree,
                  {"knative/more.yaml": "../live/Secrets/config.yaml"})
        self.assertTrue(self.last["units"]["kustomize:knative"]["closed"], self.last)
        # What a file holds closes nothing: a chart's templates read its other templates, files and values whatever
        # the door does. But no word of a refusal is a name out of a render, so none of it reaches a refusal.
        held = dict(CLUSTER, **sub, **{"monitoring/stack/files/tls.key": "-----BEGIN PRIVATE KEY-----\n" + token})
        for text in ('apiVersion: v1\nkind: Secret\nmetadata:\n  name: {{ .Files.Get "files/tls.key" | b64enc | '
                     'trunc 60 | quote }}\n',
                     '{{ fail (printf "file: %s.yaml" (.Files.Get "files/tls.key" | b64enc | trunc 40)) }}\n'):
            d = self.push({"monitoring/stack/templates/leak.yaml": text}, held)
            self.assertEqual(d.kind, "refused", d)
            self.assertFalse(self.last["units"]["helm:monitoring/stack"]["closed"])
            self.assertNotIn(base64.b64encode(b"-----BEGIN PRIVATE KEY").decode()[:20], d.why)
            self.assertNotIn(token, d.why)
        # an Application of a secret path that names only a path closes nothing, and its name is in no word
        d = self.push(flip)
        self.assertFalse(self.last["units"]["helm:monitoring/stack"]["closed"])
        self.assertIn("an object of stack/templates/deployment.yaml: privileged", d.why)
        # No refusal has a name out of a render, in any unit: a template writes an object's kind and name, and can
        # write there what it read. Here: the release name and the namespace that the hidden Application gives.
        d = self.push({"monitoring/stack/templates/leak.yaml":
                       '{{ if ne .Release.Namespace "default" }}apiVersion: v1\nkind: {{ print "Se" "cret" }}\n'
                       'metadata:\n  name: {{ .Release.Name }}.{{ .Release.Namespace }}\n{{ end }}\n'})
        self.assertEqual(d.why, "the chart monitoring/stack, rendered with the values of an Application: an object "
                                "is a new or a changed Secret object, which no commit passes")
        d = self.push({"monitoring/stack/templates/leak.yaml":
                       'apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Values.image.tag | quote }}\n'
                       'spec:\n  type: LoadBalancer\n'})
        self.assertNotIn("1111111", d.why)
        self.assertIn("an object of stack/templates/leak.yaml: a new LoadBalancer", d.why)
        sets = {c["set"] for c in self.last["units"]["helm:monitoring/stack"]["changed"]}
        self.assertEqual(sets, {"its own values", "the values of an Application"})
        # the helper's rule of a hidden path is the door's rule of a path that it refuses
        for path in ("_config/x.yaml", "a/_config/x", "live/Secrets/db.yaml", "Secrets/x", "apps/legacy/a/b.yaml",
                     "apps/shop/x.yaml", "secrets/x.yaml", "config/x", "x_config/y", "apps/legacyx/a.yaml"):
            self.assertEqual(door_render.hidden_path(path, ACCESS["exposure"]),
                             door_targets.gitops_path_refused(path, ACCESS) is not None, path)

    def test_a_file_under_a_chart_that_the_chart_does_not_read(self):
        """A folder below a chart's root can be the path of another Application, which applies its files as they are.
        The chart's render shows nothing of such a file, so the file itself is read: a jsonnet file keeps the loose
        reading, a YAML file is read by the parser document by document, and a stream that the door does not split
        is refused."""
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"},
               "spec": {"hostNetwork": True, "containers": [{"name": "c", "image": "x"}]}}
        for path, text, words in (
                ("monitoring/stack/extra/pod.jsonnet", json.dumps(pod), "the word hostnetwork"),
                ("monitoring/stack/extra/list.yaml", json.dumps({"Error": "none", "kind": "List", "items": [pod]}),
                 "a host namespace"),
                ("monitoring/stack/extra/two.yaml", json.dumps(pod) + "\n---\na: {{ .Values.x }}\n", "a host namespace"),
                ("monitoring/stack/extra/ends.yaml", "kind: ConfigMap\n...\n" + json.dumps(pod) + "\n",
                 "the door takes it only in block style"),
                ("monitoring/stack/extra/twice.json", '{"kind": "ConfigMap", "kind": "Pod", "spec": {"hostPID": true}}',
                 "a JSON file that is not JSON with each key once")):
            with self.subTest(path=path):
                d = self.push({path: text})
                self.assertEqual(d.kind, "refused", (d, self.last))
                self.assertIn(words, d.why)
        d = self.push({"monitoring/stack/extra/ok.yaml": "a: {{ .Values.x }}\n---\n{kind: ConfigMap, data: {a: b}}\n"})
        self.assertEqual(d.kind, "own", d)
        # a report that is no object is no report to fall back from
        content = json.dumps({"message": "m", "files": [{"path": "README.md", "content": "eA=="}]}).encode()
        for report in (["ok"], "ok", 1):
            d = door_targets.decide(ACCESS, "ops-one", GITOPS, "push", [], content, {"render": lambda files: report})
            self.assertEqual((d.kind, d.route), ("refused", "again"), d)

    def test_what_a_program_says_reaches_the_agent_only_as_fixed_words(self):
        "A program quotes the text that it could not read, and that text can be a file that the agent may not read."
        error = ("Error: unable to parse SM or JSON patch from [apiVersion: v1\nkind: Secret\nstringData:\n"
                 "  password: example-key-value\n]: yaml: line 4: mapping values are not allowed\n"
                 "template: stack/templates/deployment.yaml:12:20: executing at <.Values.x.y>: nil pointer evaluating")
        said = door_render.hint(error)
        self.assertNotIn("example-key-value", said)
        self.assertEqual(said, ": nil pointer evaluating")              # one fixed phrase, the first of the list
        self.assertEqual(door_render.hint("password: example-key-value"), "")
        # Where helm names a template at the start of its error, only that file: a template chooses the line where
        # it fails, the kind of its error and its text, and can choose them by what it read.
        self.assertEqual(door_render.hint("Error: template: stack/templates/deployment.yaml:12:20: executing at "
                                          "<.Values.x.y>: nil pointer evaluating interface {}.y"),
                         ": in stack/templates/deployment.yaml")
        self.assertEqual(door_render.hint("Error: execution error at (stack/templates/leak.yaml:31:3): file: "
                                          "example-key-value.yaml template: other/example-key-value.yaml:77 "
                                          "no such host"), ": in stack/templates/leak.yaml")
        self.assertEqual(door_render.hint("Error: an error occurred while checking for chart dependencies: found in "
                                          "Chart.yaml, but missing in charts/ directory: logs"),
                         ": missing in charts/ directory")

    def test_a_link_of_the_tarball_stays_in_the_tree(self):
        """A link can name its target through another link, so its text does not say where it ends. The helper keeps
        no link that ends outside the tree or above itself, and makes no folder under a link."""
        scratch = tempfile.mkdtemp(prefix="door-render-test-")
        self.addCleanup(shutil.rmtree, scratch, True)
        into = os.path.join(scratch, "inner", "before")
        os.makedirs(into)
        packed = tarball({"a/keep.txt": "x", "chart/Chart.yaml": "apiVersion: v2\nname: c\nversion: 0.1.0\n",
                          "shared/values.yaml": "a: b\n"},
                         {"a/b": "..", "chart/c": "../a/b/..", "e": "chart/c/..", "e/made/z": "../../a",
                          "chart/ok": "../shared", "chart/abs": "/etc", "chart/up": "../../.."})
        kept = door_render.unpack(packed, into)
        self.assertEqual(kept, [("chart/ok", "shared")])
        self.assertEqual(sorted(os.listdir(os.path.join(scratch, "inner"))), ["before"])   # nothing beside the tree
        self.assertEqual(sorted(os.listdir(scratch)), ["inner"])
        root = os.path.realpath(into)
        for folder, dirs, names in os.walk(into):
            for name in dirs + names:
                self.assertTrue(os.path.realpath(os.path.join(folder, name)).startswith(root + os.sep), name)
        self.assertEqual(door_render.stray_links(into), [])
        # each link to a folder is given by its own path, also the second one to the same folder
        os.makedirs(os.path.join(into, "chart", "zz", "Secrets"))
        os.symlink("../../../shared", os.path.join(into, "chart", "zz", "Secrets", "b"))
        self.assertEqual(sorted(door_render.tree_files(into, "chart")),
                         [("chart/Chart.yaml", "chart/Chart.yaml"), ("chart/ok", "shared"),
                          ("chart/ok/values.yaml", "shared/values.yaml"), ("chart/zz/Secrets/b", "shared")])
        # a chain of links that is longer than this Python reads (3.12 reads a path link by link, by recursion) is a
        # repository that the door does not render, and no error of the helper
        chain = {f"l{n}": f"l{n + 1}" for n in range(1500)}
        other = os.path.join(scratch, "inner", "chain")
        os.makedirs(other)
        try:
            self.assertEqual(len(door_render.unpack(tarball({"l1500": "x"}, chain), other)), 1500)
        except door_render.Skip as e:
            self.assertIn("links cannot be made", str(e))
        shutil.rmtree(other)
        # a file of the commit in the place of a link can turn another link of HEAD to a place outside the tree:
        # such a commit is refused
        tree = dict(CLUSTER, **{"a/b/S/keep.txt": "x", "a/b/c/keep.txt": "x", "r/keep.txt": "x"})
        links = {"p/q/D": "../../a/b/c", "p/q/S": "../../r", "p/q/L1": "D/../S/../.."}
        d = self.push({"p/q/D": None, "p/q/D/f": "x\n"}, tree, links)
        self.assertEqual(d.kind, "refused", (d, self.last))
        self.assertIn("after this commit a link of the repository ends outside it", d.why)


class RenderDoor(RenderCase, DoorCase):
    """The door with its render box: GitHub's answers, the tarball of the tree at HEAD (tree), and the box's helper."""
    tree = CLUSTER

    def setUp(self):
        RenderCase.setUp(self)
        DoorCase.setUp(self)
        github_stubs(self)
        api = "https://api.github.com/repos/one-org/cluster"
        self.answers[("GET", f"{api}/git/ref/heads/master")] = (200, {"object": {"sha": HEAD_SHA}})
        self.answers[("GET", f"{api}/git/commits/{HEAD_SHA}")] = (200, {"tree": {"sha": "t1"}})
        self.asked_raw = []

        def raw(method, url, headers, limit, timeout=120):
            self.asked_raw.append((method, url, headers.get("Authorization")))
            return 200, tarball(self.tree)
        self.door.raw = raw

        def box(header, blobs):         # the helper as the socket would start it, without the box's check
            out = io.BytesIO()
            door_render.serve(io.BytesIO(json.dumps(header).encode() + b"\n" + b"".join(blobs)), out, self.tools,
                              check=False)
            return json.loads(out.getvalue())
        self.door.box = box


class RenderPath(RenderDoor):
    """The door's own path of a rendered commit: the tarball of one commit, the box, and the commit on that parent."""

    def test_a_template_change_is_committed_on_the_commit_that_was_rendered(self):
        path = "monitoring/stack/templates/deployment.yaml"
        got = self.call(ONE, GITOPS, "push", content=change((path, STACK_DEPLOYMENT + "# a comment\n")))
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        api = "https://api.github.com/repos/one-org/cluster"
        self.assertEqual(self.asked_raw, [("GET", f"{api}/tarball/{HEAD_SHA}", "Bearer ghs_door")])
        made = next(body for method, url, body in self.calls if (method, url) == ("POST", f"{api}/git/commits"))
        self.assertEqual(made["parents"], [HEAD_SHA])
        # a branch that somebody set back to an earlier commit while the door rendered: GitHub would take the move as
        # a fast-forward, so the door reads the branch once more before it moves it
        reads = iter([(200, {"object": {"sha": HEAD_SHA}}), (200, {"object": {"sha": "f" * 40}})])
        answers, moves = dict(self.answers), len([c for c in self.calls if c[0] == "PATCH"])

        def http(method, url, headers, data):
            self.calls.append((method, url, None if data is None else json.loads(data)))
            if (method, url) == ("GET", f"{api}/git/ref/heads/master"):
                return next(reads)
            return answers.get((method, url), (404, {}))
        self.door.http = http
        got = self.call(ONE, GITOPS, "push", content=change((path, STACK_DEPLOYMENT + "# another comment\n")))
        self.assertEqual(got["ok"], False, got)
        self.assertIn("moved while the door rendered the commit", got["why"])
        self.assertEqual(len([c for c in self.calls if c[0] == "PATCH"]), moves)
        github_stubs(self)
        self.answers[("GET", f"{api}/git/ref/heads/master")] = (200, {"object": {"sha": HEAD_SHA}})
        self.answers[("GET", f"{api}/git/commits/{HEAD_SHA}")] = (200, {"tree": {"sha": "t1"}})
        # each file at HEAD came from the tarball: the door asked GitHub for no file
        self.assertFalse([url for _m, url, _b in self.calls if "/contents/" in url])
        got = self.call(ONE, GITOPS, "push", content=change(
            ("monitoring/stack/values.yaml", STACK_VALUES.replace("debug: false", "debug: true"))))
        self.assertEqual((got["ok"], got["kind"], got["route"]), (False, "refused", "none"), got)
        self.assertIn("privileged", got["why"])
        # The door has rendered this repository, so its templates changed with no line rule. From now on a render that
        # cannot be made is a refusal, and no return to the rules that read lines: not when the box says that it
        # cannot render the repository (an agent can make a repository grow), and not when the box is gone.
        self.assertEqual(list(door.read_json(door.RENDERED_FILE, {})), ["one-org/cluster"])
        flip = change(("monitoring/stack/values.yaml", STACK_VALUES.replace("debug: false", "debug: true")))
        for box in (lambda header, blobs: {"v": 1, "ok": False, "skip": "the repository has more than 100000 files"},
                    None):
            self.door.box = box
            got = self.call(ONE, GITOPS, "push", content=flip)
            self.assertEqual((got["kind"], got["route"]), ("refused", "again"), got)
            self.assertIn("the door rendered one-org/cluster before and cannot now", got["why"])

    def test_a_box_that_gives_no_answer_refuses_and_a_door_with_no_box_keeps_the_limit(self):
        path = "monitoring/stack/templates/deployment.yaml"
        content = change((path, STACK_DEPLOYMENT + "# a comment\n"))
        self.door.box = lambda header, blobs: {"v": 1, "ok": False, "again": True, "why": "the render box gave no answer"}
        got = self.call(ONE, GITOPS, "push", content=content)
        self.assertEqual((got["kind"], got["route"]), ("refused", "again"), got)
        self.assertIn("the door could not render this commit", got["why"])
        api = "https://api.github.com/repos/one-org/cluster/contents/"
        self.answers[("GET", f"{api}{path}?ref=master")] = (200, {
            "encoding": "base64", "content": base64.b64encode(STACK_DEPLOYMENT.encode()).decode()})
        for box in (lambda header, blobs: {"v": 1, "ok": False, "skip": "the pinned helm is not on the door yet"}, None):
            self.door.box = box         # None: no socket, so no render lookup at all
            got = self.call(ONE, GITOPS, "push", content=content)
            self.assertEqual(got["kind"], "refused", got)
            self.assertIn("only an image, a tag, a replica count and a restart time", got["why"])
        self.assertEqual(len(self.asked_raw), 2)            # the door with no box asked for no tarball
        # a tarball that GitHub does not give is a check that failed now
        self.door.box = lambda header, blobs: self.fail("the box was asked")
        self.door.raw = lambda method, url, headers, limit, timeout=120: (502, b"")
        got = self.call(ONE, GITOPS, "push", content=content)
        self.assertEqual((got["kind"], got["route"]), ("refused", "again"), got)

    def test_the_socket_carries_one_request_and_one_answer(self):
        "door.box_call against a socket that answers as the box's service does (door_render.serve)."
        short = tempfile.mkdtemp(prefix="fd-", dir="/tmp")      # a socket's path is 104 bytes at most
        self.addCleanup(shutil.rmtree, short, True)
        os.makedirs(short + "/run")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(short + door.RENDER_SOCKET)
        server.listen(2)
        self.addCleanup(server.close)

        def serve():
            for _ in range(2):
                conn, _addr = server.accept()
                with conn, conn.makefile("rb") as stream, conn.makefile("wb") as out:
                    door_render.serve(stream, out, self.tools, check=False)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with patch.dict(os.environ, {"FLEET_DOOR_ROOT": short}):
            facts = door.box_call({"v": 1, "op": "probe"}, [])
            self.assertEqual((facts["ok"], facts["boxed"]), (True, False))      # a test's process is in no box
            blob = b"replicas: 3\n"
            report = door.box_call({"v": 1, "op": "render", "tar": len(tarball(CLUSTER)), "files": [
                {"path": "monitoring/stack/values.yaml", "size": len(blob), "mode": "100644"}]},
                [tarball(CLUSTER), blob])
            self.assertEqual((report["ok"], list(report["units"])), (True, ["helm:monitoring/stack"]), report)
            thread.join(10)
            server.close()
            os.remove(short + door.RENDER_SOCKET)
            self.assertIn("skip", door.box_call({"v": 1, "op": "probe"}, []))   # no socket: no box


class GeneratedFiles(RenderCase):
    """A file that the repository generates, on the decision's side (DevOps plan X3, way A; the owner, 12 November 2026,
    "Me, one card each time (Recommended)"): the box writes it again with the generator at HEAD, an entry that leaves
    it goes with the commit, any other change of it is the owner's card, and a commit through the door never changes the
    declaration, the file or a rule of it."""

    def setUp(self):
        super().setUp()
        self.tools = dict(self.tools, ruby=[sys.executable, "-I"])     # Python in the place of the pinned Ruby

    def push_gen(self, files, tree=GEN_TREE, render=True):
        return self.push(files, tree=tree, render=render)

    def test_an_entry_that_leaves_goes_with_the_commit_which_keeps_its_kind(self):
        d = self.push_gen({"apps/core/app/b.yaml": None})
        self.assertEqual(d.kind, "own", d)
        self.assertIn("apps/core/app/b.yaml is deleted", d.why)
        self.assertIn(f"with {GEN_PATH} written again, from which entries leave", d.why)
        written = inventory("a.example.com").encode()
        self.assertEqual(d.plan["files"][-1], (GEN_PATH, written, "100644"))
        self.assertEqual([p for p, _d, _m in d.plan["files"]], ["apps/core/app/b.yaml", GEN_PATH])
        self.assertEqual(d.hash_content, GEN_PATH.encode() + b"\0" + written + b"\0")
        self.assertTrue(d.plan["message"].startswith("change\n\nThe door wrote " + GEN_PATH + " again"), d.plan)
        # the objects that the commit removed are its own files', not the written file's
        self.assertEqual(d.plan["objects"], {"removed": [":ConfigMap:/b"], "added": []})

    def test_a_new_entry_is_his_card_with_the_exact_change(self):
        d = self.push_gen({"apps/core/app/c.yaml": host_map("c", "c.example.com")})
        self.assertEqual(d.kind, "full", d)
        self.assertIn('the owner\'s (12 November 2026: "Me, one card each time (Recommended)")', d.why)
        row = inventory("c.example.com").splitlines()[-1].strip()
        self.assertIn(f"{GEN_PATH} gains 1 lines and loses 0; it gains: {row}", d.why)
        written = inventory("a.example.com", "b.example.com", "c.example.com").encode()
        self.assertEqual(d.plan["files"][-1], (GEN_PATH, written, "100644"))
        self.assertEqual(d.hash_content, GEN_PATH.encode() + b"\0" + written + b"\0")
        self.assertEqual(d.window, "deploy")
        # an entry that changes, as one that narrows: its digest line changes, so it is a change too
        d = self.push_gen({"apps/core/app/b.yaml": host_map("b", "b2.example.com")})
        self.assertEqual(d.kind, "full", d)
        self.assertIn(f"{GEN_PATH} gains 1 lines and loses 1", d.why)
        # the same lines in another order: no line leaves and none comes, but the file says something else
        d = self.push_gen({"apps/core/app/a.yaml": None, "apps/core/app/z.yaml": host_map("a", "a.example.com")})
        self.assertEqual(d.kind, "full", d)
        self.assertIn(f"{GEN_PATH} loses 0 lines, and lines of it move", d.why)
        # many new lines: the words show GEN_SHOWN of them, and say how many more
        many = {f"apps/core/app/n{i:02}.yaml": host_map(f"n{i:02}", f"n{i:02}.example.com") for i in range(45)}
        d = self.push_gen(many)
        self.assertEqual(d.kind, "full", d)
        self.assertIn("gains 45 lines and loses 0", d.why)
        self.assertTrue(d.why.endswith("| and 5 lines more"), d.why[-80:])

    def test_a_commit_that_leaves_the_file_as_it_is_adds_nothing(self):
        d = self.push_gen({"apps/core/app/web.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: web\n"
                                                      "data:\n  mode: fast\n"})
        self.assertEqual(d.kind, "own", d)
        self.assertEqual([p for p, _d, _m in d.plan["files"]], ["apps/core/app/web.yaml"])
        self.assertIsNone(d.hash_content)
        self.assertEqual(d.plan["message"], "change")
        self.assertEqual(self.last["generated"][0]["status"], "same")

    def test_a_file_that_the_door_cannot_write_refuses_the_commit(self):
        d = self.push_gen({"apps/core/app/c.yaml": host_map("c", "fail")})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn(f"the door could not write {GEN_PATH} again (ruby failed", d.why)
        self.assertIn("a commit without it fails the repository's checks", d.why)
        # a door whose update has not brought the pinned Ruby yet
        self.tools = {k: v for k, v in self.tools.items() if k != "ruby"}
        with patch.object(door_render, "tree_tool_path", lambda name: "/nonexistent/ruby"):
            d = self.push_gen({"apps/core/app/b.yaml": None})
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("the pinned ruby is not on the door yet", d.why)
        self.tools = dict(self.tools, ruby=[sys.executable, "-I"])
        # a declaration that the door cannot follow, at HEAD
        for text, words in (("{", "is not {generated: [1 to 4 files]}"),
                            (json.dumps({"generated": [{"path": GEN_PATH, "run": ["sh", "tools/gen.py"]}]}),
                             "is not {path, run: [ruby, paths], rules: [paths]}"),
                            (json.dumps({"generated": [{"path": "../x", "run": ["ruby", "tools/gen.py"]}]}),
                             "is not {path, run: [ruby, paths], rules: [paths]}")):
            d = self.push_gen({"apps/core/app/b.yaml": None}, tree=dict(GEN_TREE, **{".founderizer/door.json": text}))
            self.assertEqual(d.kind, "refused", d)
            self.assertIn(words, d.why)

    def test_the_declaration_the_file_and_its_rules_are_no_door_commit(self):
        for path in (".founderizer/door.json", ".Founderizer/Door.json"):
            d = self.push_gen({path: "{}\n"})
            self.assertEqual(d.kind, "refused", d)
            self.assertIn("names the files that the door writes itself", d.why)
        for path in (GEN_PATH, "tools/gen.py", "tools/rules.txt"):
            d = self.push_gen({path: "changed\n", "apps/core/app/b.yaml": None})
            self.assertEqual(d.kind, "refused", (path, d))
            self.assertIn(f"{path} is named in .founderizer/door.json: the door writes {GEN_PATH} itself", d.why)

    def test_the_box_runs_the_generator_as_it_is_at_head(self):
        "The box itself, asked for a commit that door_targets refuses: the generator and its rules come from HEAD."
        files = [("tools/rules.txt", b"private\n", "100644"),
                 ("tools/gen.py", b"open('monitoring/inventory/hosts.yaml', 'w').write('nothing')\n", "100644"),
                 ("apps/core/app/b.yaml", None, "100644")]
        scratch = tempfile.mkdtemp(prefix="door-render-test-")
        self.addCleanup(shutil.rmtree, scratch, True)
        header = {"v": 1, "op": "render", "exposure": ACCESS["exposure"], "files": [
            {"path": p, "size": None if d is None else len(d), "mode": m} for p, d, m in files]}
        report = door_render.answer(header, tarball(GEN_TREE), [d for _p, d, _m in files], self.tools, scratch)
        self.assertTrue(report["ok"], report)
        [g] = report["generated"]
        self.assertEqual((g["path"], g["status"], g["rules"]), (GEN_PATH, "removes", ["tools/rules.txt", "tools/gen.py"]))
        self.assertEqual(base64.b64decode(g["content"]).decode(), inventory("a.example.com"))
        # a repository with no declaration: nothing is generated
        report = door_render.answer(dict(header, files=[]), tarball(CLUSTER), [], self.tools, scratch + "/2")
        self.assertEqual(report["generated"], [])

    def test_a_door_with_no_render_refuses_a_repository_that_generates_files(self):
        d = self.push_gen({"apps/core/app/b.yaml": None}, render=False)
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("the door has no render of this commit that writes them again", d.why)
        d = self.push({"apps/core/app/web.yaml": None}, render=False)
        self.assertNotIn("writes them again", d.why)


class GeneratedPath(RenderDoor):
    """A file that the repository generates, on the door's whole path: the owner's signed yes to the exact call, which covers
    the written file, lets the commit through once, with the file in it; a commit from which an entry leaves is made
    at once, with the file."""
    tree = GEN_TREE

    def setUp(self):
        super().setUp()
        self.tools = dict(self.tools, ruby=[sys.executable, "-I"])
        from test_vault_central import OWNER_C, owner_sign
        self.sign = owner_sign
        data = json.loads(json.dumps(ACCESS))
        data.update(owner_keys=[OWNER_C], fleet="fleet-1")
        self.write_access(data)
        github, self.yeses = self.door.http, []
        self.door.http = lambda method, url, headers, body: (200, {"approvals": self.yeses, "devices": []}) \
            if url.endswith("/door/approvals") else github(method, url, headers, body)

    def yes(self, call, need=9):
        said = vault.canonical({"v": 1, "kind": "door-call", "fleet": "fleet-1", "need": need, "call": call,
                                "at": round(time.time())})
        self.yeses.append({"need": need, "statement": said, "signature": self.sign(said)})
        return door.fetch_approvals(self.door)

    def made(self):
        "The files and the message of the commit that the door made last."
        api = "https://api.github.com/repos/one-org/cluster/git"
        blobs = [base64.b64decode(b["content"]) for m, u, b in self.calls if (m, u) == ("POST", f"{api}/blobs")]
        tree = [b for m, u, b in self.calls if (m, u) == ("POST", f"{api}/trees")][-1]
        commit = [b for m, u, b in self.calls if (m, u) == ("POST", f"{api}/commits")][-1]
        return blobs, [e["path"] for e in tree["tree"]], commit["message"]

    def test_his_yes_lets_the_commit_through_once_with_the_written_file(self):
        content = change(("apps/core/app/c.yaml", host_map("c", "c.example.com")))
        got = self.call(ONE, GITOPS, "push", content=content)
        self.assertEqual((got["ok"], got["kind"], got["route"]), (False, "refused", "yes"), got)
        written = inventory("a.example.com", "b.example.com", "c.example.com").encode()
        sha = door.call_hash(GITOPS, "push", [], content + GEN_PATH.encode() + b"\0" + written + b"\0")
        self.assertEqual(got["call"], sha)
        self.assertIn("Me, one card each time (Recommended)", got["why"])
        self.assertFalse([u for _m, u, _b in self.calls if u.endswith("/git/commits")])
        self.yes(sha)
        got = self.call(ONE, GITOPS, "push", content=content)
        self.assertEqual((got["ok"], got["kind"]), (True, "approved"), got)
        blobs, paths, message = self.made()
        self.assertEqual(paths, ["apps/core/app/c.yaml", GEN_PATH])
        self.assertEqual(blobs[-1], written)
        self.assertIn(f"The door wrote {GEN_PATH} again, with the generator at HEAD.", message)
        got = self.call(ONE, GITOPS, "push", content=content)          # the owner's yes was used once
        self.assertEqual((got["ok"], got["route"]), (False, "yes"), got)

    def test_a_door_with_no_box_asks_github_for_the_declaration(self):
        self.door.box = None            # and it never rendered this repository: no render, and no tarball
        api = "https://api.github.com/repos/one-org/cluster/contents/"
        content = change(("apps/core/app/web.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: web\n"
                                                    "data:\n  mode: fast\n"))
        self.answers[("GET", f"{api}apps/core/app/web.yaml?ref=master")] = (200, {
            "encoding": "base64", "content": base64.b64encode(GEN_TREE["apps/core/app/web.yaml"].encode()).decode()})
        self.answers[("GET", f"{api}.founderizer/door.json?ref=master")] = (200, {
            "encoding": "base64", "content": base64.b64encode(GEN_TREE[".founderizer/door.json"].encode()).decode()})
        got = self.call(ONE, GITOPS, "push", content=content)
        self.assertEqual((got["ok"], got["kind"]), (False, "refused"), got)
        self.assertIn("the door has no render of this commit that writes them again", got["why"])
        self.assertEqual(self.asked_raw, [])
        del self.answers[("GET", f"{api}.founderizer/door.json?ref=master")]       # a repository with none
        got = self.call(ONE, GITOPS, "push", content=content)
        self.assertNotIn("writes them again", got.get("why", ""))

    def test_a_commit_from_which_an_entry_leaves_is_made_at_once_with_the_file(self):
        content = json.dumps({"message": "retire b", "files": [{"path": "apps/core/app/b.yaml", "delete": True}]}).encode()
        got = self.call(ONE, GITOPS, "push", content=content)
        self.assertEqual((got["ok"], got["kind"]), (True, "own"), got)
        blobs, paths, message = self.made()
        self.assertEqual(paths, ["apps/core/app/b.yaml", GEN_PATH])
        self.assertEqual(blobs, [inventory("a.example.com").encode()])
        self.assertEqual(message, f"retire b\n\nThe door wrote {GEN_PATH} again, with the generator at HEAD.")


class RenderBoxUnit(DoorCase):
    """Done-when (c), the part that every machine can check: the unit that is the box, and the install of its programs."""

    def test_the_unit_has_no_network_no_key_path_and_a_user_of_its_own(self):
        unit = door.RENDER_SERVICE
        for line in ("DynamicUser=yes", "PrivateNetwork=yes", "RestrictAddressFamilies=none", "IPAddressDeny=any",
                     "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "NoNewPrivileges=yes",
                     "CapabilityBoundingSet=", "RuntimeMaxSec=150", "MemoryMax=1G", "StandardInput=socket",
                     "ExecStart=/usr/bin/python3 -I /opt/fleet-door/current/door_render.py box"):
            self.assertIn(line + "\n", unit)
        hidden = next(line for line in unit.split("\n") if line.startswith("InaccessiblePaths="))
        for path in door_render.KEY_PATHS + (door.ETC, door.STATE, os.path.dirname(door.AWS_TOKEN_FILE)):
            self.assertIn(f"-{path} ", hidden + " ")
        self.assertNotIn("Environment", unit)
        self.assertIn("SocketMode=0660\n", door.RENDER_SOCKET_UNIT)
        self.assertIn("SocketGroup=door\n", door.RENDER_SOCKET_UNIT)
        self.assertEqual(door.RENDER_SOCKET_UNIT.count("ListenStream=" + door.RENDER_SOCKET), 1)

    def test_a_helper_outside_the_box_renders_nothing(self):
        out = io.BytesIO()
        request = json.dumps({"v": 1, "op": "render", "tar": 0, "files": []}).encode() + b"\n"
        door_render.serve(io.BytesIO(request), out, {"helm": ["/bin/false"], "kustomize": ["/bin/false"]})
        self.assertEqual(json.loads(out.getvalue()), {"v": 1, "ok": False, "skip": "the render helper is not in its box"})
        out = io.BytesIO()
        door_render.serve(io.BytesIO(b"not a request\n"), out, None)
        self.assertEqual(json.loads(out.getvalue())["ok"], False)
        with self.assertRaises(SystemExit):
            door_render.main(["render"])

    def test_the_update_installs_only_the_pinned_programs(self):
        patcher = patch.object(door_render, "TREE_PINS", {})      # the pinned folder has a test of its own
        patcher.start()
        self.addCleanup(patcher.stop)

        def archive(member, data):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode="w:gz") as tar:
                info = tarfile.TarInfo(member)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            return out.getvalue()
        arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[os.uname().machine]
        programs = {"helm": b"#!/bin/sh\necho helm\n", "kustomize": b"#!/bin/sh\necho kustomize\n"}
        archives = {name: archive(door_render.PINS[name]["member"].format(arch=arch), data)
                    for name, data in programs.items()}
        pins = {name: dict(pin, **{arch: {"archive": hashlib.sha256(archives[name]).hexdigest(),
                                          "program": hashlib.sha256(programs[name]).hexdigest()}})
                for name, pin in door_render.PINS.items()}
        asked, ran = [], []

        def raw(method, url, headers, limit, timeout=120):
            asked.append(url)
            return 200, archives["helm" if "helm" in url else "kustomize"]

        def program(argv, stdin, env, timeout=600):
            ran.append(argv)
            return 0, ""
        old = self.root + door_render.TOOLS_DIR + "/helm-v0.0.1"
        os.makedirs(old)
        with patch.object(door, "http_raw", raw), patch.object(door, "run_program", program):
            # the publisher's archive is not the pinned one: nothing is installed, and the door says so
            said = door.ensure_render()
            self.assertEqual(len(said), 2, said)
            self.assertIn("is not the pinned one", said[0])
            self.assertFalse(os.path.exists(self.root + door_render.tool_path("helm")))
            self.assertTrue(os.path.isdir(old))
            with patch.object(door_render, "PINS", pins):
                self.assertEqual(door.ensure_render(), [])
                for name, data in programs.items():
                    path = self.root + door_render.tool_path(name)
                    self.assertEqual(slurp(path), data)
                    self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o755")
                self.assertFalse(os.path.exists(old))           # the version before goes
                asked.clear()
                ran.clear()
                self.assertEqual(door.ensure_render(), [])
                self.assertEqual(asked, [])                     # both programs are the pinned ones: no download
                # a program that is not the pinned one is replaced
                with open(self.root + door_render.tool_path("helm"), "wb") as f:
                    f.write(b"another program")
                self.assertEqual(door.ensure_render(), [])
                self.assertEqual(slurp(self.root + door_render.tool_path("helm")), programs["helm"])
                # an archive that holds another program than the pinned one
                bad = dict(pins, helm=dict(pins["helm"], **{arch: dict(pins["helm"][arch], program="0" * 64)}))
                with patch.object(door_render, "PINS", bad):
                    self.assertIn("the program in its archive is not the pinned one", door.ensure_render()[0])
        self.assertEqual(asked[0], door_render.PINS["helm"]["url"].format(arch=arch))
        self.assertEqual(slurp(self.root + door.SYSTEMD + "/fleet-door-render@.service", "r"), door.RENDER_SERVICE)
        self.assertEqual(slurp(self.root + door.SYSTEMD + "/fleet-door-render.socket", "r"), door.RENDER_SOCKET_UNIT)
        self.assertEqual(ran[0], ["systemctl", "enable", "--now", "fleet-door-render.socket"])
        for name, pin in door_render.PINS.items():      # the real pins: an https address, and four SHA-256
            self.assertTrue(pin["url"].startswith("https://"))
            for arch in ("amd64", "arm64"):
                self.assertTrue(all(len(pin[arch][k]) == 64 for k in ("archive", "program")), name)


    def test_the_update_unpacks_a_pinned_folder_whole_and_only_that(self):
        "door.ensure_tree: the portable Ruby that a repository's generator runs in the box (DevOps plan X3)."
        arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[os.uname().machine]
        program = b"#!/bin/sh\necho ruby\n"

        def archive(*members):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode="w:gz") as tar:
                for name, data, mode in members:
                    info = tarfile.TarInfo(name)
                    if data is None:
                        info.type, info.mode = tarfile.DIRTYPE, 0o700
                        tar.addfile(info)
                    elif isinstance(data, tuple):           # a link
                        info.type, info.linkname = tarfile.SYMTYPE, data[0]
                        tar.addfile(info)
                    else:
                        info.size, info.mode = len(data), mode
                        tar.addfile(info, io.BytesIO(data))
            return out.getvalue()
        whole = [("portable-ruby/", None, 0), ("portable-ruby/3.4.6/", None, 0),
                 ("portable-ruby/3.4.6/bin/ruby", program, 0o555),
                 ("portable-ruby/3.4.6/lib/ruby/3.4.0/set.rb", b"# set\n", 0o444)]
        served = {"now": archive(*whole)}
        pins = {"ruby": dict(door_render.TREE_PINS["ruby"], **{arch: {
            "archive": hashlib.sha256(served["now"]).hexdigest(), "program": hashlib.sha256(program).hexdigest()}})}
        asked = []

        def raw(method, url, headers, limit, timeout=120):
            asked.append(url)
            return 200, served["now"]
        older = self.root + door_render.TOOLS_DIR + "/ruby-3.4.5"
        os.makedirs(older)
        path = self.root + door_render.tree_tool_path("ruby")
        with patch.object(door, "http_raw", raw), patch.object(door, "run_program", lambda *a, **k: (0, "")), \
                patch.object(door_render, "PINS", {}), patch.object(door_render, "TREE_PINS", pins):
            self.assertEqual(door.ensure_render(), [])
            self.assertEqual(slurp(path), program)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o755")
            folder = os.path.dirname(os.path.dirname(path))
            self.assertEqual(oct(os.stat(folder + "/lib/ruby/3.4.0/set.rb").st_mode & 0o777), "0o644")
            self.assertEqual(oct(os.stat(folder + "/lib/ruby").st_mode & 0o777), "0o755")
            self.assertFalse(os.path.exists(older))                 # the version before goes
            brew = door_render.TREE_PINS["ruby"]["brew"][arch]
            self.assertEqual(asked, [pins["ruby"]["url"].format(brew=brew)])
            self.assertIn(f"portable-ruby-3.4.6.{brew}_linux.bottle.tar.gz", asked[0])
            asked.clear()
            self.assertEqual(door.ensure_render(), [])
            self.assertEqual(asked, [])                             # the pinned program is there: no download
            # each archive that is not whole and only the folder: nothing of it lands, and the folder stays
            with open(path, "wb") as f:
                f.write(b"another program")
            for members, words in ((whole + [("portable-ruby/3.4.6/bin/irb", ("ruby",), 0)], "could not be unpacked"),
                                   (whole + [("elsewhere/x", b"x", 0o644)], "could not be unpacked"),
                                   (whole + [("portable-ruby/../x", b"x", 0o644)], "could not be unpacked"),
                                   ([m for m in whole if not m[0].endswith("bin/ruby")] +
                                    [("portable-ruby/3.4.6/bin/ruby", b"not ruby", 0o555)], "is not the pinned one")):
                served["now"] = archive(*members)
                bad = {"ruby": dict(pins["ruby"], **{arch: dict(pins["ruby"][arch],
                                                               archive=hashlib.sha256(served["now"]).hexdigest())})}
                with patch.object(door_render, "TREE_PINS", bad):
                    said = door.ensure_render()
                self.assertEqual(len(said), 1, said)
                self.assertIn(words, said[0])
                self.assertEqual(slurp(path), b"another program")
                self.assertFalse(os.path.exists(self.root + door_render.TOOLS_DIR + "/ruby-3.4.6.new"))
                self.assertFalse(os.path.exists(self.root + door_render.TOOLS_DIR + "/x"))
            served["now"] = b"not the pinned archive"
            self.assertIn("its archive did not come, or is not the pinned one", door.ensure_render()[0])
        for name, pin in door_render.TREE_PINS.items():     # the real pins: an https address, and four SHA-256
            self.assertTrue(pin["url"].startswith("https://"))
            for arch in ("amd64", "arm64"):
                self.assertTrue(all(len(pin[arch][k]) == 64 for k in ("archive", "program")), name)
            self.assertEqual(pin["member"], pin["tree"] + "bin/" + name)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and os.path.isdir("/run/systemd/system") and
                     os.environ.get("FLEET_DOOR_BOX_TEST") == "1",
                     "the render box is systemd's: a Linux machine with systemd, as root, with FLEET_DOOR_BOX_TEST=1 "
                     "(it installs the door's render units and its pinned programs on that machine)")
class RenderBoxLive(unittest.TestCase):
    """Done-when (c): the render cannot reach the network or the door's keys. On a machine that is only for this test:
    the door's own code installs the units and the pinned programs, and then the box itself is asked what it reaches,
    and renders a commit that asks for the network."""

    @classmethod
    def setUpClass(cls):
        os.environ.pop("FLEET_DOOR_ROOT", None)
        subprocess.run(["groupadd", "--system", "--force", "door"], check=True)
        for folder in (door.ETC, door.STATE, door.CODE):
            os.makedirs(folder, exist_ok=True)
        cls.planted = [door.ACCESS_FILE, door.VAULT_KEY]
        for path in cls.planted:
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write("a key that the box must not read\n")
                os.chmod(path, 0o644)           # readable by every user: only the unit keeps the box from it
        os.chmod(door.ETC, 0o755)
        os.chmod(door.STATE, 0o755)
        here = os.path.dirname(os.path.abspath(door.__file__))
        current = os.path.join(door.CODE, "current")
        if not os.path.lexists(current):
            os.symlink(here, current)
        cls.said = door.ensure_render()

    def test_the_box_reaches_no_network_and_no_key_and_renders(self):
        self.assertEqual(self.said, [])                         # both pinned programs came, with their SHA-256
        self.assertIsNotNone(door_render.installed_tools())
        facts = door.box_call({"v": 1, "op": "probe"}, [])
        self.assertEqual((facts["ok"], facts["boxed"], facts["sockets"], facts["keys"]), (True, True, [], []), facts)
        self.assertEqual(facts["interfaces"], [])               # no interface is up beside the loopback
        self.assertNotEqual(facts["user"], 0)
        self.assertEqual(facts["tools"], {"helm": True, "kustomize": True})
        # outside the box the same paths are readable, so the unit is what closes them
        self.assertTrue(all(slurp(path) for path in self.planted))
        self.assertFalse(door_render.probe()["boxed"])
        # a listener on this machine, which a render with a network would reach
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        self.addCleanup(listener.close)
        tar = tarball(CLUSTER)

        def render(files):
            blobs = [t.encode() for t in files.values()]
            return door.box_call({"v": 1, "op": "render", "tar": len(tar), "files": [
                {"path": p, "size": len(b), "mode": "100644"} for p, b in zip(files, blobs)]}, [tar] + blobs)
        report = render({"monitoring/stack/values.yaml": STACK_VALUES.replace("debug: false", "debug: true"),
                         "knative/kustomization.yaml": CLUSTER["knative/kustomization.yaml"] + "namePrefix: a-\n"})
        self.assertTrue(report["ok"], report)
        self.assertEqual({u: (i["ok"], bool(i["changed"])) for u, i in report["units"].items()},
                         {"helm:monitoring/stack": (True, True), "kustomize:knative": (True, True)}, report)
        self.assertIn("privileged", door_targets.render_refusal(report))
        for address in (f"http://127.0.0.1:{port}/install.yaml", "https://example.com/install.yaml"):
            report = render({"knative/kustomization.yaml": f"resources:\n  - {address}\n"})
            self.assertEqual((report["units"]["kustomize:knative"]["ok"], report["units"]["kustomize:knative"]["broke"]),
                             (False, True), report)
        with self.assertRaises(socket.timeout):
            listener.accept()                                   # no render reached the listener
        # a template that asks DNS for a name and reads a key path gets nothing
        report = render({"monitoring/stack/templates/probe.yaml":
                         'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\ndata:\n'
                         '  address: {{ getHostByName "example.com" | quote }}\n'
                         '  key: {{ .Files.Get "/etc/fleet-door/access.json" | quote }}\n'})
        probe = next(c["after"][0] for c in report["units"]["helm:monitoring/stack"]["changed"])
        self.assertEqual(probe["data"], {"address": "", "key": ""})
        with patch.object(sys, "argv", ["door.py", "render-check"]), contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit) as ended:
            door.main(["render-check"])
        self.assertEqual((ended.exception.code, json.loads(out.getvalue())["boxed"]), (0, True))
