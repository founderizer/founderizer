"""Installing a Linux machine leaves it with a working vault broker (PRODUCT.md P5).

Two halves. `hubsetup.vault_install` is the install step itself, against a stand-in machine that answers the readings
and records every script: nothing here touches this computer, and no credential of the owner's is read or written.
`vault.py` is the other half: a broker that belongs to a machine and not to one agent, so every agent user of that
machine reaches it through one group, and a machine whose agent user changed is repaired instead of silently broken.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hubsetup
import lifecycle
import releases
import vault

RECIPIENT = "age1" + "v" * 58
OTHER = "age1" + "w" * 58
HUB = "http://100.80.1.2:8765"
REPO = "git://100.80.1.2/fleet-pilot.git"       # the configuration ref as the hub serves it to a machine
UNIT = ("[Unit]\nDescription=Fleet vault broker for the agents of this machine\n\n[Service]\n"
        "User=fleet-vault\nGroup=fleet-agents\n"
        "ExecStart=/usr/bin/python3 /usr/local/lib/fleet-vault/vault.py serve --config /etc/fleet-vault/vault.json\n")
# An older broker of the fleet's own store, as a machine that ran one agent has it: its own agent, a stale caller (the
# user of the fleet that this machine ran before each agent got its own) and the ssh that an older installer wrote.
# No value of it is a secret.
OLDER = {"agent": "vps", "hub": HUB, "worker_uid": 1001, "store": "/var/lib/fleet-vault/store.age",
         "store_key": "/var/lib/fleet-vault/store.key", "age_key": "/var/lib/fleet-vault/age.key",
         "socket": "/run/fleet-vault/vault.sock", "age": "/usr/bin/age", "curl": "/usr/bin/curl", "ssh": "/usr/bin/ssh"}


class Machine:
    """The machine the installer works on. It answers the one reading the installer makes, records every script, and
    carries out the few effects the installer then looks for. A script that is expected to fail is named in `fail`."""

    def __init__(self, sha, **state):
        self.sha, self.ran, self.files, self.fail = sha, [], {}, {}
        self.waits = {}         # how long the installer lets each script run
        self.crashes = "0"      # what NRestarts reads after the start: above zero is a broker that did not stay up
        self.state = dict({"user": "no", "group": "yes", "age": "no", "keygen": "no", "program": "",
                           "key": "no", "active": "", "restarts": "0", "recipient": ""}, **state)

    def run(self, script, timeout=120):
        self.ran.append(script)
        self.waits[script] = timeout
        for fragment, answer in self.fail.items():
            if fragment in script:
                return answer
        if "echo active=" in script:                    # the reading, which changes nothing
            return 0, "\n".join(f"{k}={v}" for k, v in self.state.items()), ""
        if "vault.py unit" in script:
            return 0, UNIT, ""
        if "useradd --system" in script:
            self.state["user"] = "yes"
        if "apt-get" in script:
            self.state.update(age="yes", keygen="yes")
        if "age-keygen -o" in script and self.state["key"] == "no":
            self.state.update(key="yes", recipient=RECIPIENT)
        for source, target in re.findall(r"install -o root -g root -m 644 (\S+) (\S+)", script):
            self.files[target.rstrip("\n")] = Path(source).read_text(encoding="utf-8")
            if target.endswith("vault.py"):
                self.state["program"] = self.sha
        if "systemctl reset-failed" in script:
            self.state["restarts"] = "0"
        if "systemctl restart" in script:
            self.state["active"] = "active"
            self.state["restarts"] = self.crashes
        return 0, "", ""

    def read(self, path):
        if path not in self.files:
            raise OSError(f"no {path}")
        return self.files[path]

    def config(self):
        return json.loads(self.files[hubsetup.VAULT_CONF])

    def script(self, fragment):
        return [s for s in self.ran if fragment in s]


class Installer(unittest.TestCase):
    """The install step: what it puts on a machine that has no vault, and what it leaves alone on one that has."""

    def setUp(self):
        self.kit = Path(tempfile.mkdtemp(prefix="fleet-vault-kit-"))
        self.addCleanup(shutil.rmtree, self.kit, True)
        shutil.copy(os.path.join(hubsetup.KIT, "vault.py"), self.kit / "vault.py")
        self.program = hashlib.sha256((self.kit / "vault.py").read_bytes()).hexdigest()
        p = patch.object(hubsetup, "say", lambda text: None)
        p.start()
        self.addCleanup(p.stop)

    def install(self, machine, **extra):
        return hubsetup.vault_install(kit=str(self.kit), hub_address=HUB, run=machine.run, read=machine.read, **extra)

    def test_a_machine_with_no_vault_gets_the_fleets_own_store_and_needs_nothing_of_the_owners(self):
        box = Machine(self.program)
        done = self.install(box)
        self.assertEqual((done["state"], done["recipient"], done["active"]), ("made", RECIPIENT, True))
        self.assertEqual(done["store"], "the fleet's own store")
        conf = box.config()
        # The fleet's own store: one age file on this machine. No region, no token and no Bitwarden key of any kind.
        self.assertEqual(set(conf) & vault.BITWARDEN_KEYS, set())
        self.assertTrue(vault.STORE_KEYS <= set(conf))
        self.assertEqual(conf["worker_group"], hubsetup.AGENT_GROUP)
        # It belongs to the machine, not to one agent: it is installed before the machine has its first agent.
        self.assertNotIn("agent", conf)
        self.assertNotIn("worker_uid", conf)
        # Every mechanical step, in the order that each one needs: the user and the folders, age, the handover key,
        # the root-owned program, then its configuration, the store, the service.
        for fragment in ("useradd --system", "groupadd -f", "install -d -o root -g root -m 755", "apt-get",
                         "age-keygen -o", "vault.py store-init", "vault.py unit", "systemctl daemon-reload",
                         "systemctl enable fleet-vault", "systemctl restart fleet-vault"):
            self.assertTrue(box.script(fragment), fragment)
        self.assertLess(box.ran.index([s for s in box.ran if "vault.py store-init" in s][0]),
                        box.ran.index([s for s in box.ran if "systemctl restart" in s][0]))
        self.assertEqual(box.files[hubsetup.VAULT_UNIT], UNIT)

    def test_a_second_run_changes_nothing(self):
        box = Machine(self.program)
        self.install(box)
        box.ran.clear()
        done = self.install(box)
        self.assertEqual((done["state"], done["recipient"]), ("there", RECIPIENT))
        self.assertEqual(len(box.ran), 1)                       # the reading, and nothing else
        self.assertIn("echo active=", box.ran[0])

    def test_an_existing_broker_keeps_its_store_and_is_repointed_at_its_machines_agent_users(self):
        """The repair this closes: a machine whose agent user changed. The broker admitted one user ID, the move to
        one OS user for each agent gave the agent another, and the broker became unreachable while it still ran."""
        box = Machine(self.program, user="yes", age="yes", keygen="yes", key="yes", recipient=OTHER,
                      program=self.program, active="active")
        box.files[hubsetup.VAULT_CONF] = json.dumps(OLDER, indent=2) + "\n"
        done = self.install(box)
        self.assertEqual((done["state"], done["store"], done["recipient"]), ("made", "the fleet's own store", OTHER))
        conf = box.config()
        self.assertEqual(conf["worker_group"], hubsetup.AGENT_GROUP)     # every agent user of the machine reaches it
        kept = {k: v for k, v in OLDER.items() if k != "ssh"}            # place left the broker, and its ssh with it
        self.assertEqual({k: conf[k] for k in kept}, kept)               # and its store is untouched
        self.assertNotIn("ssh", conf)
        self.assertTrue(box.script("store-init"))                        # which keeps the key and the store it finds
        # The handover key it already has stays: the hub pins its public half, and a new key would leave every
        # handover already made for this machine unreadable. The one script that could make one reads first.
        self.assertEqual(box.state["recipient"], OTHER)
        for script in box.script("age-keygen -o"):
            self.assertIn("test -s /var/lib/fleet-vault/age.key || age-keygen", script)
        self.assertTrue(box.script("systemctl restart fleet-vault"))     # the service reads the new configuration

    def test_every_broker_it_installs_can_send_an_api_request(self):
        """A broker whose configuration names no curl program sends no request, so worker4, installed by this step,
        refused every call_api with broker_without_requests (24 October 2026), and vps sent them only because its
        curl was added by hand. A new machine and a broker made before curl both get it; a path that is there stays."""
        box = Machine(self.program)
        self.install(box)
        self.assertEqual(box.config()[vault.REQUEST_KEY], "/usr/bin/curl")       # the key vault.py reads
        older = {k: v for k, v in box.config().items() if k != vault.REQUEST_KEY}
        box.files[hubsetup.VAULT_CONF] = json.dumps(older, indent=2) + "\n"
        box.ran.clear()
        self.assertEqual(self.install(box)["state"], "made")
        self.assertEqual(box.config(), dict(older, curl="/usr/bin/curl"))      # and nothing else of it changed
        self.assertTrue(box.script("systemctl restart fleet-vault"))           # the broker reads it at its start
        box.files[hubsetup.VAULT_CONF] = json.dumps(dict(older, curl="/opt/curl/bin/curl"), indent=2) + "\n"
        self.assertEqual(self.install(box)["state"], "there")
        self.assertEqual(box.config()[vault.REQUEST_KEY], "/opt/curl/bin/curl")

    def test_a_mac_has_nothing_of_this_and_is_left_alone(self):
        box = Machine(self.program)
        done = hubsetup.vault_install(kit=str(self.kit), hub_address=HUB, run=box.run, read=box.read, system="Darwin")
        self.assertEqual((done["state"], done["recipient"]), ("there", None))
        self.assertEqual((box.ran, box.files), ([], {}))

    def test_age_is_installed_only_when_it_is_missing(self):
        box = Machine(self.program, age="yes", keygen="yes")
        self.install(box)
        self.assertFalse(box.script("apt-get"))

    def test_age_waits_out_the_first_updates_of_a_new_server(self):
        """A new Ubuntu server runs its first updates for about 9 minutes after its first boot, and they hold the
        package lock: in the proof run of 5 November 2026 a wait of 5 minutes stopped a join here. Each apt-get has
        the wait of 20 minutes. apt reads it only for the lock of dpkg, which `apt-get install` takes: `apt-get update`
        tries the lock of the package lists once (apt 2.6.2, measured on 11 November 2026), so it gets up to 10 tries,
        15 seconds apart (hubsetup.APT_UPDATE). The step outlasts the wait of each install and the 9 pauses."""
        box = Machine(self.program)
        self.install(box)
        [script] = box.script("apt-get")
        waits = [int(w) for w in re.findall(r"apt-get -o DPkg::Lock::Timeout=(\d+) ", script)]
        self.assertEqual(waits, [hubsetup.APT_LOCK_WAIT] * script.count("apt-get "))
        self.assertGreaterEqual(hubsetup.APT_LOCK_WAIT, 1200)
        self.assertIn(hubsetup.APT_UPDATE, script)
        installs = len(re.findall(r"apt-get -o DPkg::Lock::Timeout=\d+ install ", script))
        self.assertGreater(box.waits[script], hubsetup.APT_LOCK_WAIT * installs + 9 * 15)

    def test_a_check_run_reads_and_changes_nothing(self):
        box = Machine(self.program)
        done = self.install(box, check=True)
        self.assertEqual(done["state"], "would make")
        self.assertEqual(len(box.ran), 1)
        self.assertEqual(box.files, {})

    def test_a_service_that_does_not_come_up_stops_the_install_and_says_where_to_look(self):
        box = Machine(self.program)
        box.fail["systemctl restart"] = (0, "", "")         # it answers well and the service is still not running
        with self.assertRaises(hubsetup.Stop) as stopped:
            self.install(box)
        self.assertIn("journalctl -u fleet-vault", str(stopped.exception))

    def test_a_broker_that_starts_and_crashes_is_not_a_finished_install(self):
        """A broker that refuses its own configuration is `active` for an instant and then gone, and systemd starts
        it again. Reading `is-active` alone therefore reported three finished installs over a service systemd had
        already given up on, and worker4 was left holding a vault that served nobody. The count of restarts since
        this start is what says whether it stayed up."""
        box = Machine(self.program)
        box.crashes = "5"
        with self.assertRaises(hubsetup.Stop) as stopped:
            self.install(box)
        self.assertIn("restarted 5 time(s)", str(stopped.exception))
        self.assertIn("no agent of this machine can use a secret it holds", str(stopped.exception))
        self.assertTrue(box.script("systemctl reset-failed"))      # so the count is this start's and no earlier one
        box = Machine(self.program)
        box.fail["vault.py store-init"] = (1, "", "age-keygen is not installed")
        with self.assertRaises(hubsetup.Stop) as stopped:
            self.install(box)
        self.assertIn("the fleet's own store could not be made", str(stopped.exception))

    def test_the_configuration_is_root_with_mode_644_and_holds_no_secret(self):
        """Group-reading it would be worse than useless: the service sets Group=, so the vault user's own group is
        not among its groups, and the broker would fail on its own configuration for ever."""
        box = Machine(self.program)
        self.install(box)
        self.assertTrue(box.script(f"install -o root -g root -m 644 "))
        self.assertEqual([s for s in box.ran if hubsetup.VAULT_CONF in s and "install -o" in s and " -m 644 " not in s], [])
        for value in box.config().values():
            self.assertNotIn("AGE-SECRET-KEY", str(value))
            self.assertFalse(str(value).startswith("0."), value)      # no Bitwarden token shape


class Callers(unittest.TestCase):
    """The broker's own half: who may ask it, and a broker that has no agent of its own."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fleet-vault-conf-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o755)
        state = self.dir / "state"
        state.mkdir(mode=0o700)
        self.key = state / "age.key"
        self.key.write_text(f"# created: 2026-10-22T00:00:00Z\n# public key: {RECIPIENT}\nAGE-SECRET-KEY-1FAKE\n")
        self.key.chmod(0o600)

    def written(self, conf):
        path = self.dir / "vault.json"
        path.write_text(json.dumps(conf) + "\n")
        path.chmod(0o644)
        return str(path)

    def base(self, **extra):
        age = self.dir / "age"
        age.write_text("#!/bin/sh\nexit 0\n")
        age.chmod(0o755)
        return dict({"hub": HUB, "age_key": str(self.key), "socket": "/run/fleet-vault/vault.sock",
                     "age": str(age), "store": "/var/lib/fleet-vault/store.age",
                     "store_key": "/var/lib/fleet-vault/store.key"}, **extra)

    def test_a_user_of_the_group_may_ask_and_another_user_may_not(self):
        mine, group = os.getuid(), "fleet-agents"
        me = __import__("pwd").getpwuid(mine)
        members = type("Group", (), {"gr_mem": [me.pw_name], "gr_gid": me.pw_gid + 9000})()
        with patch.object(vault.grp, "getgrnam", return_value=members):
            conf = {"worker_group": group}
            self.assertTrue(vault.admitted(conf, mine))
            with patch.object(vault.pwd, "getpwuid", side_effect=KeyError):
                self.assertFalse(vault.admitted(conf, mine + 1))

    def test_the_one_user_form_still_works_and_admits_nobody_else(self):
        self.assertTrue(vault.admitted({"worker_uid": 1003}, 1003))
        self.assertFalse(vault.admitted({"worker_uid": 1003}, 1001))
        self.assertFalse(vault.admitted({}, 0))                 # no caller field at all admits nobody, uid 0 included

    def test_a_configuration_with_no_caller_at_all_is_refused(self):
        with self.assertRaises(SystemExit) as refused:
            vault.load_config(self.written(self.base()))
        self.assertIn("who may ask it", str(refused.exception))

    def test_a_group_the_vault_user_is_in_is_refused(self):
        me = __import__("pwd").getpwuid(os.getuid())
        for members in (type("Group", (), {"gr_mem": [me.pw_name], "gr_gid": me.pw_gid + 9000})(),   # a member
                        type("Group", (), {"gr_mem": [], "gr_gid": me.pw_gid})()):                   # its own group
            with patch.object(vault.grp, "getgrnam", return_value=members), self.assertRaises(SystemExit) as refused:
                vault.load_config(self.written(self.base(worker_group="fleet-agents")))
            self.assertIn("never one the vault user is in", str(refused.exception))
        with patch.object(vault.grp, "getgrnam", side_effect=KeyError), self.assertRaises(SystemExit) as missing:
            vault.load_config(self.written(self.base(worker_group="fleet-agents")))
        self.assertIn("there is no group fleet-agents", str(missing.exception))

    def test_the_group_the_service_runs_as_is_no_reason_to_refuse(self):
        """systemd gives the broker `Group=<the worker group>` so that the machine's agent users can open its
        socket, so the running process's own gid **is** that group. The rule is about the vault user's own groups,
        and reading the process's gid instead refused every correctly installed broker: worker4's first install
        crash-looped on exactly this, with the vault user in no group but its own."""
        me = __import__("pwd").getpwuid(os.getuid())
        theirs = type("Group", (), {"gr_mem": ["fleet-worker4"], "gr_gid": me.pw_gid + 9000})()
        with patch.object(vault.grp, "getgrnam", return_value=theirs), \
                patch.object(vault.os, "getgid", return_value=theirs.gr_gid):
            conf = vault.load_config(self.written(self.base(worker_group="fleet-agents")))
        self.assertEqual(conf["worker_group"], "fleet-agents")

    def test_a_broker_with_no_agent_of_its_own_needs_every_request_to_name_its_caller(self):
        conf = self.base(worker_group="fleet-agents", worker_uid=os.getuid())
        status = vault.handle(conf, json.dumps({"v": vault.PROTOCOL, "op": "status"}), os.getuid())
        self.assertIsNone(status["agent"])                      # it belongs to the machine, not to one agent
        self.assertIs(status["callers"], True)
        with self.assertRaises(vault.Refused) as refused:
            vault.handle(conf, json.dumps({"v": vault.PROTOCOL, "op": "read"}), os.getuid())
        self.assertIn("must name its caller", str(refused.exception))
        # With an agent of its own, as a machine that ran one agent has, such a request is answered as before.
        with patch.object(vault, "read", return_value={"ok": True, "secrets": []}) as answered:
            vault.handle(dict(conf, agent="vps"), json.dumps({"v": vault.PROTOCOL, "op": "read"}), os.getuid())
        self.assertEqual(answered.call_args[0][0]["agent"], "vps")

    def test_the_service_starts_when_the_broker_has_no_agent_of_its_own(self):
        """`main`'s serve path read `conf['agent']` directly to say what it was serving, so a broker with no agent
        of its own died with KeyError at start — after `status` and `unit` had both been made to do without one.
        Nothing reached `main` before this: every other test builds a `Broker` itself. worker4's install
        crash-looped on it five times, which is where it was found."""
        me = __import__("pwd").getpwuid(os.getuid())
        theirs = type("Group", (), {"gr_mem": ["fleet-worker4"], "gr_gid": me.pw_gid + 9000})()
        said, served = [], []

        class Stub:
            def __init__(self, conf):
                self.conf = conf

            def open(self):
                return self

            def serve(self):
                served.append(self.conf)

        program = self.dir / "vault.py"         # as root installs it: serve refuses a checkout in /tmp
        program.write_text("x")
        program.chmod(0o644)
        with patch.object(vault.grp, "getgrnam", return_value=theirs), patch.object(vault, "Broker", Stub), \
                patch.object(vault, "log", said.append), patch.object(vault, "__file__", str(program)):
            self.assertEqual(vault.main(["serve", "--config", self.written(self.base(worker_group="fleet-agents"))]), 0)
        self.assertEqual(len(served), 1)
        self.assertTrue(any("the agents of this machine" in line for line in said), said)

    def test_the_service_of_a_broker_with_no_agent_names_the_machines_agents(self):
        path = self.written(self.base(worker_group="fleet-agents"))
        with patch("sys.stdout") as out:
            vault.main(["unit", "--config", path, "--group", "fleet-agents"])
        text = "".join(call.args[0] for call in out.write.call_args_list)
        self.assertIn("Description=Fleet vault broker for the agents of this machine", text)
        self.assertIn("Group=fleet-agents", text)


class LiveConfigurations(unittest.TestCase):
    """Every configuration that the installer writes on a Linux machine, made here by hubsetup.vault_config itself,
    loads in this vault.py, and its broker says what the hub and the apps read: it opens the fleet's own store, and it
    takes and gives back what the owner delivers. So every live server keeps working after an update of vault.py. The
    central vault's own configuration, made by hubsetup.central_config, loads as it is too.

    The configurations keep the installer's keys and values. Only their paths move into this test's own folders: the
    state folder, the socket's folder, and the two programs that load_config checks (this Mac has no /usr/bin/age)."""

    AGENT_UID = os.getuid() + 1             # an agent user of the machine, never the vault user

    def setUp(self):
        from test_vault import FAKE_AGE, FLEET, OWNER
        self.fleet, self.owner = FLEET, OWNER
        self.dir = Path(tempfile.mkdtemp(prefix="fvl-"))       # short: a Unix socket path has at most 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o755)                                   # as root's folders: nobody else may change it
        self.programs = {"age": self.dir / "age", "curl": self.dir / "curl"}
        for name, program in self.programs.items():
            program.write_text(FAKE_AGE.format(python=sys.executable) if name == "age" else "#!/bin/sh\nexit 0\n")
            program.chmod(0o755)
        self.me = __import__("pwd").getpwuid(os.getuid())
        agents = type("Group", (), {"gr_mem": ["fleet-vps"], "gr_gid": self.me.pw_gid + 9000})()
        member = type("User", (), {"pw_name": "fleet-vps", "pw_gid": self.me.pw_gid + 9000})()
        real = vault.pwd.getpwuid
        for p in (patch.object(vault.grp, "getgrnam", return_value=agents),       # fleet-agents, without the vault user
                  patch.object(vault.pwd, "getpwuid", lambda uid: member if uid == self.AGENT_UID else real(uid)),
                  patch.object(vault, "log", lambda text: None)):
            p.start()
            self.addCleanup(p.stop)

    def here(self, conf, name):
        """(the installer's configuration with its paths in this test's folder `name`, the file it is written to)."""
        folder = self.dir / name
        state, run = folder / "state", folder / "run"
        folder.mkdir(mode=0o755)
        state.mkdir(mode=0o700)
        run.mkdir(mode=0o750)
        moved = {}
        for key, value in conf.items():
            if isinstance(value, str) and value.startswith(hubsetup.VAULT_STATE + "/"):
                value = str(state) + value[len(hubsetup.VAULT_STATE):]
            elif value == hubsetup.VAULT_SOCKET:
                value = str(run / os.path.basename(value))
            elif isinstance(value, str) and value.startswith("/usr/bin/") and os.path.basename(value) in self.programs:
                value = str(self.programs[os.path.basename(value)])
            moved[key] = value
        self.assertEqual(set(moved), set(conf))
        path = folder / "vault.json"
        path.write_text(json.dumps(moved, indent=2) + "\n")       # root with mode 644, as vault_install writes it
        path.chmod(0o644)
        return moved, str(path)

    def started(self, conf, name):
        """The broker of this configuration after the install's own steps: its handover key (vault_key_script), the
        store-init of the installed program, and the broker's start. Gives its configuration and its status, which an
        agent user of the machine asked."""
        moved, path = self.here(conf, name)
        loaded = vault.load_config(path)
        self.assertEqual(loaded, moved)                         # it loads as the installer wrote it
        recipient = "age1" + "h" * 58
        Path(loaded["age_key"]).write_text(f"# public key: {recipient}\nAGE-SECRET-KEY-1FAKE\n")
        Path(loaded["store_key"]).write_text(f"# public key: {'age1' + 'k' * 58}\nAGE-SECRET-KEY-1FAKESTORE\n")
        for key in ("age_key", "store_key"):
            os.chmod(loaded[key], 0o600)
        made = vault.store_init(path, self.me.pw_name, keygen="/nonexistent/age-keygen")   # this Mac has no age-keygen
        self.assertEqual(made["made"], ["store"])
        self.assertEqual(vault.LocalStore(loaded).opened(), {})
        broker = vault.Broker(loaded)
        self.addCleanup(broker.close)
        status = vault.handle(broker.conf, json.dumps({"v": vault.PROTOCOL, "op": "status"}), self.AGENT_UID)
        self.assertEqual(status["recipient"], recipient)
        return loaded, status

    def test_every_configuration_that_the_installer_writes_loads_and_opens_the_fleets_own_store(self):
        fresh = hubsetup.vault_config(HUB)
        owned = hubsetup.vault_config(HUB, owner_keys=[self.owner], fleet=self.fleet)
        # An older file, of a machine that ran one agent: its agent, its one caller and the ssh of an older installer,
        # and no curl and no worker_group yet. vault_config keeps the caller and the agent, and drops the ssh.
        older = dict({k: v for k, v in fresh.items() if k not in ("curl", "worker_group")}, agent="vps",
                     worker_uid=self.AGENT_UID, ssh="/usr/bin/ssh")
        cases = {"fresh": fresh, "with the owner's keys": owned,
                 "run again": hubsetup.vault_config(HUB, before=owned, owner_keys=[self.owner], fleet=self.fleet),
                 "older, brought up to date": hubsetup.vault_config(HUB, before=older, owner_keys=[self.owner],
                                                                    fleet=self.fleet),
                 # the same older file where no installer ran again since: its ssh is still there
                 "older, as it was left": older}
        self.assertEqual(cases["run again"], owned)
        self.assertEqual((cases["older, brought up to date"]["worker_uid"], "ssh" in cases["older, brought up to date"]),
                         (self.AGENT_UID, False))
        for index, (name, conf) in enumerate(cases.items()):
            with self.subTest(name):
                self.assertEqual(set(conf) & vault.BITWARDEN_KEYS, set())
                loaded, status = self.started(conf, f"m{index}")
                self.assertEqual((status["backend"], status["deposits"], status["withdrawals"], status["creates"]),
                                 ("store", True, True, True))
                self.assertEqual(status.get("requests"), True if "curl" in conf else None)
                self.assertEqual(status["agent"], conf.get("agent"))

    def test_the_central_vaults_own_configuration_loads_as_it_is(self):
        conf = hubsetup.central_config(os.getuid() + 1, self.fleet, self.owner)
        self.assertEqual(set(conf), vault.CENTRAL_KEYS)
        here = dict(conf, age=str(self.programs["age"]))      # the one program that load_config checks
        path = self.dir / "central.json"
        path.write_text(json.dumps(here, indent=2) + "\n")
        path.chmod(0o644)
        self.assertEqual(vault.load_config(str(path)), here)
        self.assertTrue(vault.admitted(here, os.getuid() + 1))
        self.assertFalse(vault.admitted(here, os.getuid()))


class LoginTestLines(unittest.TestCase):
    """What `fleet.py check` says under "For the login tests", by what opens this agent's logins.

    Twice this block failed a machine that was exactly as it should be. A broker keeps its store and its programs in
    its own root-owned configuration, and an agent with no credential access has nothing to open. Both read `FAIL
    Bitwarden region is eu or us`, a line of file mode, on `vps` with a working broker and then on `worker4` with a new
    one. File mode is gone now, and so is that line.
    """

    def check(self, vault, settings=None):
        import fleet
        home = Path(tempfile.mkdtemp(prefix="fleet-doctor-home-"))
        self.addCleanup(shutil.rmtree, home, True)
        team = {"agents": {"w": dict({"role": "worker", "runtime": "codex", "machine": "box", "can": ["shell"]},
                                     **({"vault": vault} if vault else {}))},
                "addresses": {"box": "100.80.1.3", "owner": "100.80.1.1"}}
        if settings is not None:
            team["settings"] = settings
        out = io.StringIO()
        with patch.object(fleet, "TEAM", team), patch.object(fleet, "HOME", str(home)), \
                patch.object(fleet, "HUB", ""), patch.object(fleet, "KIT", str(home)), \
                patch.object(fleet, "vault_socket", return_value=str(home / "none.sock")), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            fleet.cmd_check(type("Args", (), {"agent": "w"})())
        text = out.getvalue()
        block = text[text.index("For the login tests:"):]
        # Without the closing summary, whose own word FAIL is about the whole run and not about these lines.
        return "\n".join(l for l in block.splitlines() if not l.startswith(("READY", "NOT READY")))

    def test_no_credential_access_says_so_and_fails_nothing(self):
        said = self.check("none")
        self.assertIn("no credential access, so this agent has no login to test", said)
        self.assertNotIn("Bitwarden", said)
        self.assertNotIn("FAIL", said)

    def test_a_broker_is_not_asked_about_bitwarden_either(self):
        said = self.check("broker")
        self.assertNotIn("Bitwarden region", said)
        self.assertIn("vault broker", said)

    def test_file_mode_is_gone_and_one_line_says_so(self):
        """An entry that still says "file" is no credential access: file mode read a Bitwarden token of this user, and
        Founderizer has no Bitwarden backend any more. One line says so, and it fails, because the owner must give the
        agent its machine's vault broker."""
        said = self.check("file")
        self.assertIn("FAIL  vault file is gone: this agent's vault must be broker", said)
        self.assertIn("no credential access, so this agent has no login to test", said)
        for gone in ("Bitwarden region", "bws", "token file"):
            self.assertNotIn(gone, said)

    def test_an_entry_that_says_nothing_is_no_credential_access(self):
        self.assertIn("no credential access", self.check(None))

    def test_a_macs_catch_up_line_names_the_early_track_only_for_an_early_fleet(self):
        """A Mac's vault updater takes the early track only when install.py, as root, was given --track early
        (WORKER-INSTALL.md, "Vault broker (macOS)"), so the command that this line gives says so for a fleet whose
        setting releases.early is on, and for no other fleet."""
        import fleet
        status = {"user": "dana", "backend": "store", "recipient": None, "deposits": False}
        for settings, flag in (({"releases.early": True}, " --track early"), ({"releases.early": False}, ""),
                               (None, "")):
            with self.subTest(settings=settings), patch.object(fleet, "vault_call", return_value=status), \
                    patch.object(fleet, "vault_readable", return_value=[]), patch.object(sys, "platform", "darwin"):
                said = self.check("broker", settings)
                self.assertIn("vault broker takes the keys the owner delivers", said)
                self.assertIn(f"install.py --updater-only --fleet <fleet id>{flag} (WORKER-INSTALL.md", said)


class TerminalToolLines(unittest.TestCase):
    """What `fleet.py check` says about the team tools, and about which session it is talking.

    The helper puts the team tools on the command line when it starts a session: Codex gets
    `-c mcp_servers.fleet.url=...`, Claude gets `--strict-mcp-config --mcp-config ...`, which uses only that
    configuration and so ignores the registered server on purpose. These two lines read what a runtime started by
    hand in a terminal there would use, which decides nothing for the agent, and a `FAIL` on them read as a broken
    machine: vps said NOT READY over a Codex whose own sessions were wired all along.
    """

    def check(self, runtime, listed=""):
        import fleet
        home = Path(tempfile.mkdtemp(prefix="fleet-tools-home-"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / ".codex").mkdir()
        (home / ".codex" / "config.toml").write_text("")        # no fleet block, as on a joined machine
        team = {"agents": {"w": {"role": "worker", "runtime": runtime, "machine": "box", "can": ["shell"],
                                 "vault": "none"}},
                "addresses": {"box": "100.80.1.3", "owner": "100.80.1.1"}}
        done = type("Done", (), {"stdout": listed, "returncode": 0})()
        out = io.StringIO()
        with patch.object(fleet, "TEAM", team), patch.object(fleet, "HOME", str(home)), \
                patch.object(fleet, "HUB", "http://100.80.1.2:8765"), patch.object(fleet, "KIT", str(home)), \
                patch.object(fleet.os.path, "expanduser", lambda p: p.replace("~", str(home))), \
                patch.object(fleet, "http", side_effect=OSError("no hub in this test")), \
                patch.object(fleet.shutil, "which", lambda name: "/usr/bin/" + name), \
                patch.object(fleet.subprocess, "run", return_value=done), \
                patch.object(fleet, "vault_socket", return_value=str(home / "none.sock")), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            fleet.cmd_check(type("Args", (), {"agent": "w"})())
        return [l for l in out.getvalue().splitlines() if "team tools" in l]

    def test_a_codex_that_nobody_wired_by_hand_is_no_failure(self):
        said = self.check("codex")
        self.assertEqual(len(said), 1, said)
        self.assertTrue(said[0].startswith("  --  "), said[0])
        self.assertIn("in a terminal here", said[0])
        self.assertIn("need this for nothing", said[0])

    def test_a_claude_whose_registered_server_is_ignored_is_no_failure_either(self):
        said = self.check("claude")
        self.assertEqual(len(said), 1, said)
        self.assertTrue(said[0].startswith("  --  "), said[0])
        self.assertIn("in a terminal here", said[0])

    def test_one_that_is_wired_by_hand_still_reads_ok(self):
        said = self.check("claude", listed="fleet: http://100.80.1.2:8765/mcp/w (HTTP) - ✓ Connected\n")
        self.assertEqual(len(said), 1, said)
        self.assertTrue(said[0].startswith("  ok  "), said[0])


class VaultProgram(unittest.TestCase):
    """`/usr/local/sbin/fleet-vault-program`: the one root command that brings this machine's vault broker onto the
    `vault.py` of a signed release, which is how a release reaches a program no release can touch.

    The script itself is run here, with a stub for every command it uses but git and python3, and its paths moved
    into a folder of this test, so nothing of this computer is changed and no root is needed. git is real (its stub
    writes the command down and runs the real one) against a repository of this test whose configuration ref carries
    a release signed with this test's key, and the check is the real releases.py, copied as the root step copies it.
    What is measured is what the script decides: it takes vault.py only from a release that a pinned key signed and
    that comes after its floor (DevOps plan 0.3), it changes nothing while the broker already runs that program, it
    installs and restarts when it does not, it gives back the program that was serving when the broker does not come
    up, and it takes nothing at all from its caller -- which is the whole of the right the service user is given.
    """

    TOOLS = ("id", "git", "sha256sum", "install", "systemctl", "sleep")
    SEED, OTHER_SEED = bytes(range(32, 64)), bytes(range(64, 96))       # this test's release key, and a stranger's

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-vault-program-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.lib, self.state = self.tmp / "lib", self.tmp / "state"
        self.lib.mkdir()
        self.state.mkdir()
        self.conf = self.tmp / "vault.json"
        self.conf.write_text('{"hub": "' + HUB + '"}\n', encoding="utf-8")
        self.program = self.lib / "vault.py"
        self.program.write_text("# the vault, one\n", encoding="utf-8")
        # root's own copies of the check and of the release keys, as the root step of the machine puts them here
        shutil.copy(Path(hubsetup.KIT) / "releases.py", self.lib / "releases.py")
        (self.lib / "release-key.pub").write_text(
            __import__("base64").b64encode(releases.public_key(self.SEED)).decode() + "\n")
        self.floor = self.lib / "release-floor"
        self.repo = self.tmp / "fleet"                     # the configuration ref, as the hub serves it
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.released = self.release("# the vault, two\n")
        self.fetch_fails = self.tmp / "fetch-fails"        # touched: this machine cannot reach the ref
        self.active = self.tmp / "active"
        self.active.write_text("active\n", encoding="utf-8")
        self.crashes = self.tmp / "crashes"
        self.crashes.write_text("0\n", encoding="utf-8")
        self.log = self.tmp / "ran"
        self.stubs = self.tmp / "bin"
        self.stubs.mkdir()
        for tool, body in self.bodies().items():
            one = self.stubs / tool
            one.write_text(f'#!/bin/sh\nprintf "%s\\n" "{tool} $*" >> {self.log}\n{body}exit 0\n')
            one.chmod(0o755)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                              check=True, capture_output=True, text=True).stdout.strip()

    def release(self, vault_text, seed=None, manifest=True):
        """A release whose revision carries this vault.py (none for None), and the configuration ref on top of it
        with its release.json signed by `seed` (this test's key by default). Returns the released revision."""
        self.repo.mkdir(exist_ok=True)
        if vault_text is None:
            (self.repo / "vault.py").unlink(missing_ok=True)
        else:
            (self.repo / "vault.py").write_text(vault_text, encoding="utf-8")
        (self.repo / "hub.py").write_text(f"# the hub of {len(list(self.tmp.iterdir()))}\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "a release")
        revision = self.git("rev-parse", "HEAD")
        if manifest:
            body = {"revision": revision, "version": "2026.11.9", "notes": None, "minimum": None, "hold": False}
            signed = releases.sign(seed or self.SEED, releases.signed_text(body))
            (self.repo / "release.json").write_text(json.dumps(dict(
                body, signature=__import__("base64").b64encode(signed).decode())) + "\n")
            self.git("add", "release.json")
            self.git("commit", "-q", "-m", "the fleet takes it")
        self.git("branch", "-f", lifecycle.CONFIG_BRANCH, "HEAD")
        return revision

    def bodies(self):
        """One stub for each command the script uses. `git` runs the real one, unless this machine cannot reach the
        ref; `systemctl` answers from two files this test writes."""
        real_git = shutil.which("git")
        return {
            "id": 'if [ "$1" = -u ]; then echo 0; fi\n',
            "sleep": "",
            "sha256sum": f'exec {shlex.quote(sys.executable)} -c "'
                         "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest(),"
                         ' sys.argv[1])" "$1"\n',
            "git": (f'case " $* " in *" fetch "*) test ! -e {self.fetch_fails} || '
                    '{ echo "fatal: unable to connect" >&2; exit 128; };; esac\n'
                    f'exec {shlex.quote(real_git)} "$@"\n'),
            "install": ('for a in "$@"; do b=$c; c=$a; done\n'
                        'cp "$b" "$c"\n'),
            "systemctl": (f'case "$1" in is-active) cat {self.active};; '
                          f'show) cat {self.crashes};; esac\n'),
        }

    def script(self, repo=None, tools=()):
        """The script this version writes, with its paths inside this test's folder, the stubs and this Python on
        the PATH it sets for itself, and no settle to wait. It sets that PATH so that none of the commands it runs can
        be chosen by its caller, which is why the stubs go in there and not into the environment."""
        path = os.pathsep.join([*(str(one) for one in tools), str(self.stubs), os.path.dirname(sys.executable),
                                hubsetup.ROOT_PATH])
        with patch.object(hubsetup, "VAULT_CONF", str(self.conf)), \
                patch.object(hubsetup, "VAULT_LIB", str(self.lib)), \
                patch.object(hubsetup, "VAULT_FLOOR", str(self.floor)), \
                patch.object(hubsetup, "VAULT_SOURCE", str(self.tmp / "source.git")), \
                patch.object(hubsetup, "ROOT_PATH", path), \
                patch.object(hubsetup, "VAULT_SETTLE", 0):
            return hubsetup.vault_program_script(str(self.repo) if repo is None else repo)

    def not_root(self):
        """A stub `id` that answers a uid which is not 0, so the script's own root check is measured here whether
        or not the test itself runs as root."""
        folder = self.tmp / "notroot"
        folder.mkdir(exist_ok=True)
        (folder / "id").write_text('#!/bin/sh\nif [ "$1" = -u ]; then echo 1000; fi\nexit 0\n')
        (folder / "id").chmod(0o755)
        return folder

    def run_it(self, *args, repo=None, root=True):
        one = self.tmp / "fleet-vault-program"
        one.write_text(self.script(repo, () if root else (self.not_root(),)), encoding="utf-8")
        done = subprocess.run(["sh", str(one), *args], capture_output=True, text=True)
        return done.returncode, done.stdout + done.stderr

    def lines(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def changes(self):
        """What it ran that changes this machine. A reading changes nothing, and neither does making root's own
        repository or fetching into it."""
        return [one for one in self.lines()
                if one.startswith(("install ", "systemctl restart", "systemctl reset-failed"))]

    # ---- the signed release (DevOps plan 0.3)

    def test_it_takes_vault_py_from_the_signed_revision_and_never_from_the_refs_own_tree(self):
        """A commit of the ref with a forged vault.py and the release.json it had: the program is read out of the
        revision that the release names, so the forged bytes are never installed."""
        (self.repo / "vault.py").write_text("# forged\n", encoding="utf-8")
        self.git("commit", "-q", "-am", "forged vault.py under the same release.json")
        self.git("branch", "-f", lifecycle.CONFIG_BRANCH, "HEAD")
        code, said = self.run_it()
        self.assertEqual(code, 0, said)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, two\n")
        self.assertEqual(self.floor.read_text().strip(), self.released)        # the floor follows it

    def test_a_release_that_no_pinned_key_signed_installs_nothing(self):
        self.release("# forged\n", seed=self.OTHER_SEED)
        code, said = self.run_it()
        self.assertEqual(code, 6, said)
        self.assertIn("is refused", said)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, one\n")
        self.assertEqual(self.changes(), [])

    def test_a_release_that_a_pinned_early_key_signed_is_taken(self):
        """PRODUCT.md 4.3 "Two tracks": a fleet that takes releases early runs one that the early key signed, so the
        root copy of early-key.pub checks it too."""
        (self.lib / "early-key.pub").write_text(
            __import__("base64").b64encode(releases.public_key(self.OTHER_SEED)).decode() + "\n")
        self.released = self.release("# the vault, early\n", seed=self.OTHER_SEED)
        code, said = self.run_it()
        self.assertEqual(code, 0, said)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, early\n")

    def test_a_ref_with_no_signed_release_installs_nothing(self):
        self.release("# forged\n", manifest=False)
        self.git("rm", "-q", "release.json")
        self.git("commit", "-q", "-m", "no release")
        self.git("branch", "-f", lifecycle.CONFIG_BRANCH, "HEAD")
        code, said = self.run_it()
        self.assertEqual(code, 4, said)
        self.assertIn("carries no signed release", said)
        self.assertEqual(self.changes(), [])

    def test_an_older_release_than_the_floor_installs_nothing(self):
        newer = self.release("# the vault, three\n")
        self.git("branch", "-f", lifecycle.CONFIG_BRANCH, self.git("rev-parse", "HEAD~2"))   # back to the older
        self.floor.write_text(newer + "\n")
        code, said = self.run_it()
        self.assertEqual(code, 7, said)
        self.assertIn("does not come after the release this broker took", said)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, one\n")
        self.assertEqual(self.changes(), [])

    # ---- what it decides

    def test_a_broker_that_already_runs_this_vault_py_is_left_alone(self):
        self.release(self.program.read_text(encoding="utf-8"))
        code, said = self.run_it()
        self.assertEqual(code, 0, said)
        self.assertIn("already runs this vault.py", said)
        self.assertEqual(self.changes(), [])

    def test_a_release_that_changed_vault_py_is_installed_and_the_broker_restarted(self):
        code, said = self.run_it()
        self.assertEqual(code, 0, said)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, two\n")
        self.assertIn(hashlib.sha256(b"# the vault, two\n").hexdigest(), said)
        # One file, root-owned with mode 644, and one service.
        installs = [one for one in self.lines() if one.startswith("install ")]
        self.assertEqual(len(installs), 1, installs)
        self.assertIn("-o root -g root -m 644", installs[0])
        self.assertTrue(installs[0].endswith(str(self.program)), installs[0])
        self.assertEqual([one for one in self.lines() if one.startswith("systemctl restart")],
                         ["systemctl restart fleet-vault"])

    def test_a_broker_that_does_not_come_up_gets_back_the_program_that_was_serving(self):
        """It runs unattended after a release, and an installed broker that is not serving means no agent of that
        machine can use a secret it holds. So the copy that was serving goes back, and the hub's own `vault_behind`
        warning is left to say that this machine needs a person."""
        self.active.write_text("failed\n", encoding="utf-8")
        code, said = self.run_it()
        self.assertEqual(code, 5, said)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, one\n")
        self.assertIn("keeps the one that was serving", said)
        self.assertIn("journalctl -u fleet-vault", said)
        self.assertEqual(len([one for one in self.lines() if one.startswith("systemctl restart")]), 2)

    def test_a_broker_that_does_not_come_up_keeps_its_floor(self):
        """The floor moves only to a release whose vault.py the broker runs, so after the program that was serving
        goes back, a release before the refused one is still one that this broker may take."""
        self.release("# the vault, three\n")
        self.floor.write_text(self.released + "\n")
        self.active.write_text("failed\n", encoding="utf-8")
        code, said = self.run_it()
        self.assertEqual(code, 5, said)
        self.assertEqual(self.floor.read_text().strip(), self.released)

    def test_a_broker_that_starts_and_then_crashes_gets_the_same_treatment(self):
        """A broker that refuses its own program is `active` for an instant and then gone, as the installer already
        reads: the restarts since the reset are what say whether it stayed up."""
        self.crashes.write_text("2\n", encoding="utf-8")
        code, said = self.run_it()
        self.assertEqual(code, 5, said)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, one\n")

    def test_an_older_systemd_that_answers_no_restart_count_is_not_a_crash(self):
        for answer in ("\n", "unknown\n"):
            self.setUp()
            self.crashes.write_text(answer, encoding="utf-8")
            code, said = self.run_it()
            self.assertEqual(code, 0, said)
            self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, two\n")

    def test_a_machine_that_cannot_reach_the_ref_changes_nothing(self):
        self.fetch_fails.write_text("", encoding="utf-8")
        code, said = self.run_it()
        self.assertNotEqual(code, 0)
        self.assertEqual(self.program.read_text(encoding="utf-8"), "# the vault, one\n")
        self.assertEqual(self.changes(), [])

    def test_a_ref_that_carries_no_vault_py_changes_nothing(self):
        self.release(None)
        code, said = self.run_it()
        self.assertEqual(code, 4, said)
        self.assertIn("carries no vault.py", said)
        self.assertEqual(self.changes(), [])

    def test_a_machine_with_no_vault_broker_is_not_behind(self):
        """A Mac, or a server the owner gave no broker: there is nothing here to bring up to date, and that is not
        a failure of anything."""
        for gone in ("vault.json", "lib/vault.py"):
            self.setUp()
            (self.tmp / gone).unlink()
            code, said = self.run_it()
            self.assertEqual(code, 0, said)
            self.assertIn("no vault broker", said)
            self.assertEqual(self.changes(), [])

    # ---- the right the service user is given, and its edges

    def test_every_command_it_runs_is_rootetc_own_and_not_the_callers(self):
        """It sets its own PATH, so none of the commands it runs can be chosen by whoever ran it. sudo resets
        PATH on a stock Debian or Ubuntu; this does not depend on that."""
        text = hubsetup.vault_program_script(REPO)
        self.assertEqual(hubsetup.ROOT_PATH, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertIn(f"PATH={hubsetup.ROOT_PATH}\nexport PATH\n", text)
        self.assertLess(text.index("PATH="), text.index("git "))

    def test_it_takes_no_argument_at_all(self):
        """The whole of what the caller may say is "do it". An argument would be a path, a value or a revision, and
        each of those is a way for the service user to choose what root installs."""
        for args in (["/tmp/mine.py"], ["--revision", "e" * 40], [""]):
            self.setUp()
            code, said = self.run_it(*args)
            self.assertEqual(code, 2, said)
            self.assertIn("takes no argument", said)
            self.assertEqual(self.changes(), [])

    def test_it_needs_root_and_says_so(self):
        code, said = self.run_it(root=False)
        self.assertEqual(code, 1, said)
        self.assertIn("needs root", said)
        self.assertEqual(self.changes(), [])

    def test_with_no_address_for_the_ref_it_refuses_and_names_the_join_line(self):
        """A source read from anywhere else on this machine is a source somebody else can write, so there is no
        second-best source: it refuses and says what settles it."""
        code, said = self.run_it(repo="")
        self.assertEqual(code, 3, said)
        self.assertIn("Run the join line again", said)
        self.assertEqual(self.changes(), [])

    def test_the_bytes_come_from_the_ref_and_from_no_checkout(self):
        """The caller passes no bytes: the program is fetched here, from the one address this machine already takes
        all of its code from, into a bare repository only root can write. The pasted command this replaces
        installed from a checkout that a user of the machine can write, so this is the narrower of the two."""
        text = hubsetup.vault_program_script(REPO)
        branch = lifecycle.CONFIG_BRANCH
        self.assertIn(f'fetch -q --no-tags "$repo" {shlex.quote("+%s:refs/heads/%s" % (branch, branch))}', text)
        self.assertIn(f"repo={shlex.quote(REPO)}", text)
        self.assertIn(f"cat-file blob {shlex.quote('refs/heads/' + branch)}:release.json", text)
        self.assertIn('cat-file blob "$revision:vault.py"', text)          # the signed revision's (plan 0.3)
        self.assertIn("--bare", text)
        for never in ("/home/", "~", "$1", "git clone", "git checkout", "git -C . "):
            self.assertNotIn(never, text.split("set -eu", 1)[1])

    def test_nothing_fetched_is_ever_checked_out_or_run(self):
        """A working tree of a fetched repository is a hook, a filter and a submodule that would run as root. The
        program is read out of the fetch instead."""
        text = hubsetup.vault_program_script(REPO).split("set -eu", 1)[1]
        self.assertNotIn("checkout", text)
        self.assertNotIn("submodule", text)
        # it never runs the program it installs: the one python3 it runs is root's own copy of the release check
        self.assertEqual(re.findall(r"python3 [^\n]*", text), [f"python3 -I -S -c {shlex.quote(hubsetup.VAULT_CHECK)}"
                                                              f" {hubsetup.VAULT_LIB} \"$manifest\") || exit 6"[:0]
                                                              or re.findall(r"python3 [^\n]*", text)[0]])
        self.assertIn("python3 -I -S -c", text)

    def test_it_installs_one_file_and_restarts_one_service(self):
        text = hubsetup.vault_program_script(REPO)
        self.assertEqual(set(re.findall(r"install -o root -g root -m 644 \S+ (\S+)", text)),
                         {hubsetup.VAULT_LIB + "/vault.py"})
        self.assertEqual(set(re.findall(r"systemctl (?:restart|reset-failed) (\S+)", text)), {"fleet-vault"})

    def test_it_reads_neither_key_nor_store_and_never_remakes_the_handover_key(self):
        """The broker's own protections are not this command's business: a new handover key would leave every value
        the store holds unreadable and turn every agent's access into `vault_store_mismatch`."""
        text = hubsetup.vault_program_script(REPO)
        for never in (hubsetup.VAULT_STATE, "age-keygen", "age.key", "store.key", "store-init", "bws"):
            self.assertNotIn(never, text)

    def test_it_says_in_the_file_why_a_second_root_right_is_not_a_way_out_of_this_user(self):
        """The next reader meets this decision in the file itself, on the machine it is installed on."""
        text = hubsetup.vault_program_script(REPO)
        for wanted in ("Founderizer", "hubsetup.py", hubsetup.SUDOERS, "takes no argument",
                       "passes no bytes", "only root can", "handover\n# key is never remade"):
            self.assertIn(wanted, text)
