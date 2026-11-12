"""The door's parts on a managed host (DevOps plan section 2, "The host login", and step C3), here on this machine with
every path under a temporary folder: ops-root's forms that touch files (same, covers, drop, place, file), its mode
file and its one lock, the signed self-update and its floor, and ops-read, the forced command of the second sshd.
What needs a real Ubuntu host (the transient service, the second sshd, an upgrade whose session is killed, a reboot)
runs on a temporary server of each distribution release: test 5, through host/check.sh."""
import base64
import contextlib
import fcntl
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import door_targets
import releases

ROOT = door_targets.OPS_ROOT
READ = door_targets.OPS_READ
SEED = bytes(range(32))         # the test's own release key; never the product's


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Files, ModeAndLock, ScriptForms, Runners, Accounts, SelfUpdate,
                                                    Reader, Scripts, NewApp, AppUnitAndSettings, AppRunner, AppVhost,
                                                    ReleaseHelper)
                              for name in cls.__dict__ if name.startswith("test_"))


class HostCase(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="ops-root-"))     # macOS: /var is /private/var
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for folder in ("/etc/ops-root", "/var/lib/ops-root", "/run", "/etc/nginx", "/usr/local/sbin",
                       "/usr/local/lib/ops-root", "/etc/restic", "/etc/sudoers.d", "/var/log/nginx"):
            os.makedirs(self.tmp + folder, exist_ok=True)
        patcher = patch.object(ROOT, "ROOT", self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put(self, path, text, mode=0o644):
        with open(self.tmp + path, "w") as f:
            f.write(text)
        os.chmod(self.tmp + path, mode)

    def get(self, path):
        with open(self.tmp + path) as f:
            return f.read()

    def call(self, op, *args, data=None, sha256=None):
        req = {"v": 1, "op": op, "args": list(args)}
        if sha256:
            req["sha256"] = sha256
        return ROOT.call(req, data)


class Files(HostCase):
    def test_same_and_covers_print_only_yes_or_no(self):
        self.put("/etc/nginx/a.conf", "x\ny\n")
        self.put("/etc/nginx/a.conf.bak", "x\ny\n")
        self.put("/etc/nginx/b.conf", "x\ny\nz\n")
        self.assertEqual(self.call("same", "/etc/nginx/a.conf.bak", "/etc/nginx/a.conf"), "yes")
        self.assertEqual(self.call("same", "/etc/nginx/a.conf.bak", "/etc/nginx/b.conf"), "no")
        self.assertEqual(self.call("covers", "/etc/nginx/a.conf.bak", "/etc/nginx/b.conf"), "yes")
        self.assertEqual(self.call("covers", "/etc/nginx/b.conf", "/etc/nginx/a.conf"), "no")
        self.assertEqual(self.call("same", "/etc/nginx/none", "/etc/nginx/a.conf"), "no")

    def test_drop_only_after_a_yes_and_while_the_file_is_unchanged(self):
        self.put("/etc/nginx/a.conf", "x\n")
        self.put("/etc/nginx/a.conf.bak", "x\n")
        self.put("/etc/nginx/c.bak", "c\n")
        with self.assertRaisesRegex(ROOT.Refused, "had no yes"):
            self.call("drop", "/etc/nginx/c.bak")
        self.assertEqual(self.call("same", "/etc/nginx/a.conf.bak", "/etc/nginx/a.conf"), "yes")
        self.put("/etc/nginx/a.conf.bak", "x\nchanged since\n")
        with self.assertRaisesRegex(ROOT.Refused, "had no yes"):
            self.call("drop", "/etc/nginx/a.conf.bak")
        self.put("/etc/nginx/a.conf.bak", "x\n")
        self.assertEqual(self.call("drop", "/etc/nginx/a.conf.bak"), "/etc/nginx/a.conf.bak deleted")
        self.assertFalse(os.path.exists(self.tmp + "/etc/nginx/a.conf.bak"))
        self.assertTrue(os.path.exists(self.tmp + "/etc/nginx/a.conf"))

    def test_a_yes_needs_a_second_file(self):
        """`same /x /x` said yes, and `drop /x` then deleted the file: any file that is not protected, on a rule-only
        host too. One file under two names is no second copy, and a link or a device holds no bytes of its own."""
        self.put("/etc/nginx/a.conf", "x\n")
        self.put("/etc/nginx/copy", "x\n")
        self.put("/etc/nginx/empty", "")
        os.symlink(self.tmp + "/etc/nginx/a.conf", self.tmp + "/etc/nginx/a.link")
        os.link(self.tmp + "/etc/nginx/a.conf", self.tmp + "/etc/nginx/a.hard")
        os.mkdir(self.tmp + "/etc/nginx/conf.d")
        for op in ("same", "covers"):
            for other in ("/etc/nginx/a.conf", "/etc/nginx/../nginx/a.conf", "/etc/nginx/a.link", "/etc/nginx/a.hard"):
                with self.subTest(op=op, other=other), self.assertRaisesRegex(ROOT.Refused, "are one file"):
                    self.call(op, "/etc/nginx/a.conf", other)
            for first, other in (("/etc/nginx/a.link", "/etc/nginx/copy"), ("/etc/nginx/conf.d", "/etc/nginx/empty"),
                                 ("/etc/nginx/copy", "/etc/nginx/conf.d")):
                with self.subTest(op=op, first=first), self.assertRaisesRegex(ROOT.Refused, "is no plain file"):
                    self.call(op, first, other)
        for path in ("/etc/nginx/a.conf", "/etc/nginx/a.link", "/etc/nginx/conf.d"):
            with self.subTest(path=path), self.assertRaisesRegex(ROOT.Refused, "had no yes"):
                self.call("drop", path)
            self.assertTrue(os.path.lexists(self.tmp + path))
        self.put("/etc/nginx/blank", "\n\n")                # no line that says something: any file would cover it
        for old in ("/etc/nginx/empty", "/etc/nginx/blank"):
            self.assertEqual(self.call("covers", old, "/etc/nginx/a.conf"), "no")

    def test_a_drop_checks_at_the_delete_that_the_other_file_still_holds_it(self):
        bak, conf = "/etc/nginx/a.conf.bak", "/etc/nginx/a.conf"
        self.put(bak, "x\ny\n")
        self.put(conf, "x\ny\n")
        self.assertEqual(self.call("same", bak, conf), "yes")
        self.put(conf, "x\n")                               # the other file changed after the yes
        with self.assertRaisesRegex(ROOT.Refused, f"{conf} no longer holds what {bak} holds: nothing was deleted"):
            self.call("drop", bak)
        os.remove(self.tmp + conf)                          # it is gone
        with self.assertRaisesRegex(ROOT.Refused, "no longer holds"):
            self.call("drop", bak)
        os.symlink(self.tmp + bak, self.tmp + conf)         # it is the file itself now
        with self.assertRaisesRegex(ROOT.Refused, "are one file"):
            self.call("drop", bak)
        os.remove(self.tmp + conf)
        self.assertEqual(self.get(bak), "x\ny\n")
        self.put(conf, "x\ny\n")
        self.assertEqual(self.call("drop", bak), f"{bak} deleted")
        old, new = "/etc/nginx/b.old", "/etc/nginx/b.new"
        self.put(old, "x\n")
        self.put(new, "x\ny\n")
        self.assertEqual(self.call("covers", old, new), "yes")
        self.put(new, "y\n")
        with self.assertRaisesRegex(ROOT.Refused, "no longer holds"):
            self.call("drop", old)
        self.put(new, "z\nx\n")                             # another text, which still has each line
        self.assertEqual(self.call("drop", old), f"{old} deleted")
        self.assertEqual(json.loads(self.get("/var/lib/ops-root/yes.json")), {})

    def test_a_yes_of_an_older_ops_root_gives_no_drop(self):
        self.put("/etc/nginx/c.bak", "c\n")
        self.put("/var/lib/ops-root/yes.json", json.dumps({"/etc/nginx/c.bak": hashlib.sha256(b"c\n").hexdigest()}))
        with self.assertRaisesRegex(ROOT.Refused, "an older ops-root, which kept no name of the other file: ask same "
                                                  "or covers again"):
            self.call("drop", "/etc/nginx/c.bak")
        self.assertEqual(self.get("/etc/nginx/c.bak"), "c\n")

    def test_same_covers_and_drop_refuse_a_protected_and_a_hidden_path(self):
        """They run as root outside the box: `covers` told whether a guessed line is in an app's settings, and a
        `drop` checked only the protected paths."""
        env, guess = "/var/www/shop/shared/.env", "/etc/nginx/guess"
        os.makedirs(self.tmp + "/var/www/shop/shared")
        self.put(env, "KEY=1\n")
        self.put(guess, "KEY=1\n")
        self.put("/etc/restic/b2.env", "KEY=1\n")
        self.put("/etc/ops-root/hidden", "/etc/restic\n")   # the host's own list
        self.put("/etc/ops-root/mode", "KEY=1\n")
        os.symlink(self.tmp + env, self.tmp + "/etc/nginx/env.link")
        self.put("/var/lib/ops-root/yes.json", json.dumps({env: hashlib.sha256(b"KEY=1\n").hexdigest()}))
        for op, args in (("covers", [guess, env]), ("same", [guess, env]), ("same", [env, guess]),
                         ("covers", [guess, "/etc/restic/b2.env"]), ("same", [guess, "/etc/nginx/env.link"]),
                         ("same", [guess, "/etc/ops-root/mode"]), ("covers", ["/etc/ops-root/mode", guess]),
                         ("drop", [env]), ("drop", ["/etc/restic/b2.env"]), ("drop", ["/etc/ops-root/mode"])):
            with self.subTest(op=op, args=args), self.assertRaisesRegex(
                    ROOT.Refused, "is protected on this host|is an app tree or a secret path"):
                self.call(op, *args)
        self.assertEqual(self.get(env), "KEY=1\n")

    def test_the_door_s_own_folders_are_protected_and_hidden(self):
        """A door can run on a host that it manages: its keys, its state and its code are no file of an agent's."""
        props = ROOT.box("x")
        for folder, path in (("/etc/fleet-door", "/etc/fleet-door/door.json"),
                             ("/var/lib/fleet-door", "/var/lib/fleet-door/ssh/id_ed25519"),
                             ("/opt/fleet-door", "/opt/fleet-door/current/door.py")):
            with self.subTest(path=path):
                self.assertTrue(ROOT.protected(path))
                self.assertIn(f"ReadOnlyPaths=-{folder}", props)
                with self.assertRaisesRegex(ROOT.Refused, "is protected on this host"):
                    ROOT.check_args("exec", ["ls", path])
                with self.assertRaisesRegex(ROOT.Refused, "is protected: no file install writes it"):
                    ROOT.check_args("file", [path, "0644", "root"])
        for folder in ("/etc/fleet-door", "/var/lib/fleet-door", "/opt", "/var/lib/fleet-vault-central"):
            self.assertIn(f"InaccessiblePaths=-{folder}", props)        # the hub's central vault: its keys and store

    def test_place_puts_a_value_only_where_the_old_one_is(self):
        old = "OLD-KEY-VALUE"
        self.put("/etc/restic/b2.env", f"B2_ACCOUNT_ID=id1\nB2_ACCOUNT_KEY={old}\nRESTIC_REPOSITORY=b2:x\n", 0o600)
        digest = hashlib.sha256(old.encode()).hexdigest()
        with self.assertRaisesRegex(ROOT.Refused, "no one line"):
            self.call("place", "/etc/restic/b2.env", "B2_ACCOUNT_KEY", "0" * 64, data=b"NEW")
        said = self.call("place", "/etc/restic/b2.env", "B2_ACCOUNT_KEY", digest, data=b"NEW-KEY-VALUE\n")
        self.assertEqual(said, "B2_ACCOUNT_KEY in /etc/restic/b2.env has its new value")
        self.assertEqual(self.get("/etc/restic/b2.env"),
                         "B2_ACCOUNT_ID=id1\nB2_ACCOUNT_KEY=NEW-KEY-VALUE\nRESTIC_REPOSITORY=b2:x\n")
        self.assertEqual(os.stat(self.tmp + "/etc/restic/b2.env").st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ROOT.Refused, "no one line"):        # the old value is gone: no second place
            self.call("place", "/etc/restic/b2.env", "B2_ACCOUNT_KEY", digest, data=b"OTHER")

    def test_a_file_install_checks_its_hash_its_place_and_its_link(self):
        data = b"server { listen 80; }\n"
        digest = hashlib.sha256(data).hexdigest()
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        with patch.object(ROOT, "mode", lambda: "fix"):
            with self.assertRaisesRegex(ROOT.Refused, "do not have the request's sha256"):
                self.call("file", "/etc/nginx/x.conf", "0644", me, data=data, sha256="0" * 64)
            self.assertEqual(self.call("file", "/etc/nginx/x.conf", "0644", me, data=data, sha256=digest),
                             "/etc/nginx/x.conf installed (22 bytes)")
            self.assertEqual(self.get("/etc/nginx/x.conf"), data.decode())
            os.symlink(self.tmp + "/etc/ops-root/mode", self.tmp + "/etc/nginx/link.conf")
            with self.assertRaisesRegex(ROOT.Refused, "is a link|protected"):
                self.call("file", "/etc/nginx/link.conf", "0644", me, data=data, sha256=digest)
            os.symlink(self.tmp + "/etc/ops-root", self.tmp + "/etc/nginx/sub")
            with self.assertRaisesRegex(ROOT.Refused, "protected"):
                self.call("file", "/etc/nginx/sub/mode", "0644", me, data=data, sha256=digest)
            with self.assertRaisesRegex(ROOT.Refused, "protected"):
                self.call("file", "/etc/ops-root/release-key.pub", "0644", me, data=data, sha256=digest)

    def test_a_sudoers_file_passes_visudo_first(self):
        data = b"deploy ALL=(root) NOPASSWD: /usr/local/sbin/shop-deploy deploy *\n"
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        ran = []
        with patch.object(ROOT, "mode", lambda: "fix"), \
                patch.object(ROOT, "run", lambda argv, **kw: (ran.append(argv), (1, "parse error"))[1]):
            with self.assertRaisesRegex(ROOT.Refused, "visudo refused"):
                self.call("file", "/etc/sudoers.d/95-app-shop", "0440", me, data=data,
                          sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(ran[0][:4], ["visudo", "-c", "-q", "-f"])
        self.assertFalse(os.path.exists(self.tmp + "/etc/sudoers.d/95-app-shop"))

    def test_a_firewall_file_arms_the_rollback_timer_first(self):
        os.makedirs(self.tmp + "/etc/ufw", exist_ok=True)
        data = b"# rules\n"
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        armed = []
        with patch.object(ROOT, "mode", lambda: "fix"), patch.object(ROOT, "arm_timer", lambda: armed.append(1) or
                                                                     "armed"):
            said = self.call("file", "/etc/ufw/user.rules", "0640", me, data=data,
                             sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual((armed, said.split("\n")[0]), ([1], "armed"))


class ModeAndLock(HostCase):
    def test_a_missing_or_unknown_mode_is_rule_only(self):
        self.assertEqual(ROOT.mode(), "rule-only")
        self.put("/etc/ops-root/mode", "anything\n")
        self.assertEqual(ROOT.mode(), "rule-only")
        self.put("/etc/ops-root/mode", "fix\n")
        self.assertEqual(ROOT.mode(), "fix")

    def test_a_rule_only_host_refuses_the_agent_s_own_forms_and_file_installs_by_itself(self):
        self.put("/etc/ops-root/mode", "rule-only\n")
        own = sorted(name for name, f in ROOT.FORMS.items() if f["kind"] == "own")
        self.assertEqual(own, ["env-add", "exec", "file", "install", "passwd-lock", "purge", "script", "unit-new",
                               "vhost-new"])
        self.assertEqual([name for name, f in ROOT.FORMS.items() if f["kind"] == "full"], ["run"])
        self.assertEqual({f["kind"] for f in ROOT.FORMS.values()}, {"rule", "own", "full"})
        for op, args in (("exec", ["ls", "/etc"]), ("install", ["htop"]), ("purge", ["telnetd"]),
                         ("passwd-lock", ["olduser"]), ("file", ["/etc/nginx/x.conf", "0644", "root"]),
                         ("script", []), ("run", [])):
            with self.subTest(op=op), self.assertRaisesRegex(
                    ROOT.Refused, "this host is rule-only: only rule forms run here, and no file install"):
                self.call(op, *args, data=b"x" if op in ("file", "script", "run") else None)

    def test_no_form_starts_a_unit_that_powers_the_host_off_or_is_ops_root_s_own(self):
        """`restart systemd-poweroff` powered a rule-only host off, outside the reboot form and its rules."""
        for op in ("restart", "enable"):
            for unit in ("systemd-poweroff", "systemd-poweroff.service", "systemd-halt", "systemd-reboot",
                         "systemd-kexec.service", "systemd-soft-reboot", "systemd-suspend", "emergency",
                         "rescue.service", "debug-shell"):
                with self.subTest(op=op, unit=unit), self.assertRaisesRegex(
                        ROOT.Refused, "powers the host off, restarts it or opens a root console: only the reboot "
                                      "form restarts a host"):
                    ROOT.check_args(op, [unit])
            for unit in ("ops-root-rollback", "ops-root-rollback.service", "ops-root-reboot", "ops-root-run-4711",
                         "ops-root-install-1790000000.service", ROOT.BOOT_UNIT):
                with self.subTest(op=op, unit=unit), self.assertRaisesRegex(ROOT.Refused, "ops-root's own"):
                    ROOT.check_args(op, [unit])
        with self.assertRaisesRegex(ROOT.Refused, "ops-root's own"):
            ROOT.check_args("enable", ["ops-root-rollback.timer"])
        self.assertEqual(ROOT.check_args("restart", ["nginx"]), ["nginx.service"])
        self.assertEqual(ROOT.check_args("enable", ["certbot.timer"]), ["certbot.timer"])

    def test_nothing_comes_on_stdin_but_a_file_s_bytes_and_the_door_s_values(self):
        with self.assertRaisesRegex(ROOT.Refused, "takes nothing on stdin"):
            self.call("restart", "nginx", data=b"x")

    def test_a_second_write_waits_for_the_first(self):
        spans = []

        def slow(argv, **kw):
            t0 = time.monotonic()
            time.sleep(0.3)
            spans.append((t0, time.monotonic()))
            return 0, ""
        with patch.object(ROOT, "run", slow):
            threads = [threading.Thread(target=self.call, args=("restart", unit)) for unit in ("a", "b")]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        spans.sort()
        self.assertGreaterEqual(spans[1][0], spans[0][1] - 0.01)

    def test_a_long_step_runs_in_its_own_unit_that_the_session_only_watches(self):
        """An upgrade or a package install must outlive a session that ends: systemd-run only queues it (--no-block),
        and ops-root reads the unit's state until it ends. A oneshot started without --no-block held systemd-run to
        the end of the upgrade, and the door answered "failed" after a minute while the upgrade went on."""
        for states, ok in ((["ActiveState=activating\nResult=success", "ActiveState=inactive\nResult=success"], True),
                           (["ActiveState=active\nResult=success", "ActiveState=failed\nResult=exit-code"], False)):
            calls, given = [], iter(states)

            def run(argv, **kw):
                calls.append(argv)
                return (0, next(given)) if argv[:2] == ["systemctl", "show"] else (0, "apt says done")
            with patch.object(ROOT, "run", run), patch.object(ROOT.time, "sleep", lambda s: None):
                if ok:
                    self.assertEqual(ROOT.detached("upgrade", ["unattended-upgrade", "-v"]), "upgrade done\napt says done")
                else:
                    with self.assertRaisesRegex(ROOT.Failed, "install failed \\(exit-code\\)"):
                        ROOT.detached("install", ["apt-get", "install", "-y", "htop"])
                    self.assertEqual(calls[-1][:2], ["systemctl", "reset-failed"])
            self.assertEqual(calls[0][:2], ["systemd-run", "--no-block"])
            self.assertNotIn("--wait", calls[0])

    def test_a_second_arm_keeps_the_first_snapshot_until_the_host_boots_again(self):
        """A firewall file arms the timer, and so does the `ufw` that applies it. A snapshot at that second arm held
        the new file, so a timer that fired after a lockout put the lockout back. The countdown starts again; the
        files and the Tailscale version stay those of the first arm until a cancel, the fire or a new boot, also when
        a start of the timer failed in between."""
        os.makedirs(self.tmp + "/proc/sys/kernel/random")
        self.put("/proc/sys/kernel/random/boot_id", "boot-one\n")
        calls, start = [], {"fails": False}

        def run(argv, **kw):
            calls.append(argv)
            if argv[0] == "tar":
                with open(argv[4], "w") as f:
                    f.write(f"snapshot {sum(1 for c in calls if c[0] == 'tar')}")
            if argv[0] == "dpkg-query":
                return 0, f"1.80.{len(calls)}"
            if argv[0] == "systemd-run" and start["fails"]:
                return 1, "Failed to start transient timer unit"
            return 0, ""
        with patch.object(ROOT, "run", run):
            first = ROOT.arm_timer()
            version = self.get("/var/lib/ops-root/rollback/tailscale")
            again = ROOT.arm_timer()
            start["fails"] = True
            with self.assertRaisesRegex(ROOT.Failed, "could not start"):
                ROOT.arm_timer()                # it stopped the countdown, and started none
            start["fails"] = False
            ROOT.arm_timer()
            self.assertEqual(self.get("/var/lib/ops-root/rollback/snapshot.tar"), "snapshot 1")
            self.assertEqual(self.get("/var/lib/ops-root/rollback/tailscale"), version)
            self.put("/proc/sys/kernel/random/boot_id", "boot-two\n")
            ROOT.arm_timer()
            self.assertEqual(self.get("/var/lib/ops-root/rollback/snapshot.tar"), "snapshot 2")
            ROOT.cancel_timer()
            self.assertFalse(os.path.exists(self.tmp + "/var/lib/ops-root/rollback"))
            start["fails"] = True               # a first arm that does not start leaves no snapshot behind
            with self.assertRaisesRegex(ROOT.Failed, "could not start"):
                ROOT.arm_timer()
            self.assertFalse(os.path.exists(self.tmp + "/var/lib/ops-root/rollback"))
            start["fails"] = False
            ROOT.arm_timer()
            self.assertEqual(self.get("/var/lib/ops-root/rollback/snapshot.tar"), "snapshot 4")
        self.assertEqual([c[0] for c in calls].count("systemd-run"), 7)     # each arm starts the countdown again
        self.assertNotIn("first arm", first)
        self.assertIn("as they were at its first arm", again)

    def test_a_reboot_in_the_countdown_puts_the_snapshot_back_at_boot(self):
        """The timer is a transient unit, which a reboot ends, and ufw applies its files again at boot: a firewall or
        sshd change that locked the door out stayed for good when the host rebooted before the countdown ended. The
        arm puts a unit in place (a self-update brings none), whose `--boot` fires a countdown that a reboot or a soft
        reboot ended, under the host's lock; a countdown that runs takes no lock and runs on, a cancel or a re-arm
        that started no countdown leaves nothing to fire, only systemd runs it, and no unit means no arm."""
        os.makedirs(self.tmp + "/proc/sys/kernel/random")
        self.put("/proc/sys/kernel/random/boot_id", "boot-one\n")
        folder, lock = self.tmp + "/var/lib/ops-root/rollback", self.tmp + "/run/ops-root.lock"
        timer, enabled, start_fails, calls = [False], [False], [False], []

        def run(argv, **kw):                    # systemd as the timer and the unit see it
            calls.append(argv)
            words = argv[3:] if argv[0] == "systemctl" else []
            if argv[0] == "tar" and argv[3] == "-cpf":
                with open(argv[4], "w") as f:
                    f.write("the files of the first arm")
            if argv[0] == "tar" and argv[3] == "-xpf":
                with open(lock) as other, self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if argv[0] == "systemd-run":
                timer[0] = not start_fails[0]
                return (1, "Failed to start transient timer unit") if start_fails[0] else (0, "")
            if words[:1] == ["stop"]:
                timer[0] = False
            if words[:1] == ["enable"]:
                enabled[0] = True
            if words[:1] == ["is-active"]:
                return (0, "active") if timer[0] else (3, "inactive")
            if words == ["is-enabled", ROOT.BOOT_UNIT]:
                return 0, "enabled" if enabled[0] else "disabled"
            return 0, ""

        def boot():
            with patch.object(ROOT.os, "getppid", lambda: 1):
                return ROOT.main(["ops-root", "--boot"])

        def reboot(boot_id):
            timer[0] = False                    # no transient unit outlives it
            self.put("/proc/sys/kernel/random/boot_id", boot_id + "\n")
            return boot()

        def restores():
            return sum(1 for c in calls if c[:4] == ["tar", "-C", self.tmp + "/", "-xpf"])
        with patch.object(ROOT, "run", run), contextlib.redirect_stdout(io.StringIO()):
            ROOT.arm_timer()
            ROOT.arm_timer()
            self.assertEqual([c[3:] for c in calls if c[3:4] in (["daemon-reload"], ["enable"])],
                             [["daemon-reload"], ["enable", ROOT.BOOT_UNIT]])         # once, then in place
            self.assertEqual(ROOT.main(["ops-root", "--boot"]), 3)
            with patch.object(ROOT.fcntl, "flock", side_effect=AssertionError("a running countdown takes no lock")):
                self.assertEqual((boot(), restores()), (0, 0))
            self.assertEqual((reboot("boot-two"), restores()), (0, 1))
            self.assertFalse(os.path.exists(folder))
            self.assertIn("no snapshot waited", ROOT.cancel_timer())     # the agent sees that its files went back
            ROOT.arm_timer()
            self.assertEqual((reboot("boot-two"), restores()), (0, 2))   # a soft reboot keeps the boot id
            ROOT.arm_timer()
            ROOT.cancel_timer()
            self.assertEqual((reboot("boot-three"), restores()), (0, 2))
            ROOT.arm_timer()
            start_fails[0] = True
            with self.assertRaisesRegex(ROOT.Failed, "could not start"):
                ROOT.arm_timer()                # it stopped the countdown and started none: a boot has none to end
            start_fails[0] = False
            self.assertEqual((reboot("boot-four"), restores()), (0, 2))
            self.assertEqual(ROOT.cancel_timer(), "the rollback timer is off")
            calls.clear()
            enabled[0] = False
            with patch.object(ROOT, "run", lambda argv, **kw: calls.append(argv) or
                              ((1, "Access denied") if "enable" in argv else (0, ""))):
                with self.assertRaisesRegex(ROOT.Failed, "could not put " + ROOT.BOOT_UNIT):
                    ROOT.arm_timer()
            self.assertEqual([c for c in calls if c[0] in ("tar", "systemd-run")], [])
            with self.assertRaisesRegex(ROOT.Refused, "boot unit"):
                self.call("restart", ROOT.BOOT_UNIT)     # its start would wait for the lock that the form holds
        unit = self.get("/etc/systemd/system/" + ROOT.BOOT_UNIT)
        for line in (f"ConditionPathExists={ROOT.ARMED}", f"ConditionFileIsExecutable={ROOT.SELF}",   # systemd's key
                     "After=network-online.target", "Type=oneshot",
                     f"ExecStart={ROOT.SELF} --boot", "WantedBy=multi-user.target"):
            self.assertIn(line + "\n", unit)
        self.assertTrue(ROOT.protected("/etc/systemd/system/" + ROOT.BOOT_UNIT))
        self.assertIsNone(ROOT.APP_NAME.fullmatch(ROOT.BOOT_UNIT.removesuffix(".service")))    # never an app's unit
        with open("host/install.sh") as f:
            text = f.read()
        self.assertIn("BOOT_UNIT=/etc/systemd/system/" + ROOT.BOOT_UNIT + " ", text)
        start = text.index("remove() {")
        self.assertIn('rm -f "$UNIT" "$BOOT_UNIT"', text[start:text.index("\n}\n", start)])

    def test_a_fire_puts_every_path_that_arms_the_timer_back_as_it_was_at_the_arm(self):
        """A file of /etc/netplan, /etc/iptables, /etc/nftables.d or a tailscaled drop-in arms the timer, but the
        snapshot held only sshd's and the firewall's files, and tar put back what it held over every file that came
        later: no fire and no boot undid such a change. Each path that arms the timer is in the snapshot now, and a
        fire leaves each one exactly as at the arm: a file that came later goes, a path that was absent goes, a folder
        where the snapshot has a file goes, a link goes as a link, a link with no target comes back, and a file that a
        package lists goes too (the door can have edited it). It applies what it restored, after the files and in
        this order: systemd's units, netplan only when its bytes changed, sshd's socket, nftables before ufw, a ufw
        that its changed ufw.conf disables stopped first, netfilter-persistent only when /etc/iptables changed, the
        Tailscale downgrade, then Tailscale and the door's sshd. Only a snapshot with the digest of its arm removes
        anything, and a tar that fails says so, at a boot too. Real tar, under the test's own root only."""
        for path in ROOT.TIMED_PATHS:
            self.assertIn(path.rstrip("/"), ROOT.SNAPSHOT)
        paths = ["/etc/ssh"] + [p.rstrip("/") for p in ROOT.TIMED_PATHS]
        files = {"/etc/ssh/sshd_config": "Port 22\n", "/etc/ufw/user.rules": "*filter\nCOMMIT\n",
                 "/etc/ufw/ufw.conf": "ENABLED=no\n", "/etc/default/ufw": "IPV6=yes\n",
                 "/etc/nftables.conf": "flush ruleset\n", "/etc/iptables/rules.v4": "*filter\nCOMMIT\n",
                 "/etc/netplan/50-cloud-init.yaml": "network: {}\n", "/var/lib/dpkg/info/ufw.list":
                 "/etc/ufw\n/etc/ufw/sysctl.conf\n"}
        for path, text in files.items():
            os.makedirs(os.path.dirname(self.tmp + path), exist_ok=True)
            self.put(path, text, 0o600)
        os.symlink("/nowhere/tailscaled", self.tmp + "/etc/default/tailscaled")
        os.makedirs(self.tmp + "/etc/nftables.d")
        os.makedirs(self.tmp + "/outside")
        self.put("/outside/keep", "not the snapshot's\n")
        enabled = {"ssh.socket", "nftables.service", "ufw.service", "netfilter-persistent.service",
                   "tailscaled.service", ROOT.SSHD_UNIT}
        calls, real, version, full_disk = [], ROOT.run, ["1.80.0"], [False]

        def run(argv, **kw):
            calls.append(argv)
            if argv[0] == "tar":
                self.assertEqual(argv[1:3], ["-C", self.tmp + "/"])         # never the real root
                if full_disk[0] and argv[3] == "-xpf":
                    return 2, "tar: etc/ssh/sshd_config: Cannot open: No space left on device"
                return real(argv, **kw)
            if argv[:4] == ["systemctl", "--no-pager", "--no-ask-password", "is-enabled"]:
                return (0, "enabled") if argv[4] in enabled else (1, "disabled")
            if argv[0] == "dpkg-query":
                return 0, version[0]
            return 0, ""

        def tree():                 # each path under the saved ones: its mode, a file's text and a link's target
            found, todo = {}, list(paths)
            while todo:
                path = todo.pop()
                full = self.tmp + path
                if os.path.islink(full):
                    found[path] = os.readlink(full)
                elif os.path.isdir(full):
                    found[path] = oct(os.stat(full).st_mode)
                    todo += [path + "/" + name for name in os.listdir(full)]
                elif os.path.exists(full):
                    found[path] = (oct(os.stat(full).st_mode), self.get(path))
            return found

        def fire():
            calls.clear()
            with patch.object(ROOT.os, "getppid", lambda: 1):
                self.assertEqual(ROOT.main(["ops-root", "--fire"]), 0)
            self.assertFalse(os.path.exists(self.tmp + "/var/lib/ops-root/rollback"))
            return [["tar", c[3]] if c[0] == "tar" else c[3:] if c[0] == "systemctl" else [c[0], c[-1]]
                    for c in calls if c[0] in ("netplan", ROOT.UFW_INIT, "apt-get") or
                    c[3:4] in (["-xpf"], ["daemon-reload"], ["restart"])]
        at_arm = tree()
        with patch.object(ROOT, "run", run), contextlib.redirect_stdout(io.StringIO()) as out:
            ROOT.arm_timer()
            version[0] = "1.82.0"                   # a Tailscale upgrade in the countdown
            self.put("/etc/ssh/sshd_config", "Port 2200\n", 0o600)
            os.remove(self.tmp + "/etc/ufw/user.rules")
            os.makedirs(self.tmp + "/etc/ufw/applications.d")
            self.put("/etc/ufw/applications.d/web", "[web]\n")
            self.put("/etc/ufw/ufw.conf", "ENABLED=yes\n", 0o600)
            self.put("/etc/ufw/sysctl.conf", "net/ipv4/ip_forward=0\n")    # dpkg's list names it: it goes too
            os.remove(self.tmp + "/etc/nftables.conf")
            os.makedirs(self.tmp + "/etc/nftables.conf")
            self.put("/etc/nftables.conf/x", "x\n")
            self.put("/etc/nftables.d/drop.nft", "drop\n")
            os.symlink(self.tmp + "/outside", self.tmp + "/etc/nftables.d/outside")
            os.remove(self.tmp + "/etc/default/tailscaled")
            self.put("/etc/default/tailscaled", "PORT=0\n")
            self.put("/etc/iptables/rules.v4", "*filter\n-A INPUT -j DROP\nCOMMIT\n", 0o644)
            self.put("/etc/iptables/rules.v6", "*filter\nCOMMIT\n")
            os.makedirs(self.tmp + "/etc/systemd/system/tailscaled.service.d")
            self.put("/etc/systemd/system/tailscaled.service.d/override.conf", "[Service]\n")
            self.put("/etc/netplan/50-cloud-init.yaml", "network: {ethernets: {}}\n", 0o600)    # its bytes only
            self.assertEqual(fire(), [["tar", "-xpf"], ["daemon-reload"], ["netplan", "apply"],
                                      ["restart", "ssh.socket"], ["restart", "nftables.service"],
                                      [ROOT.UFW_INIT, "force-stop"], ["restart", "ufw.service"],
                                      ["restart", "netfilter-persistent.service"], ["apt-get", "tailscale=1.80.0"],
                                      ["restart", "tailscaled.service"], ["restart", ROOT.SSHD_UNIT]])
            self.assertEqual(tree(), at_arm)
            self.assertEqual(self.get("/outside/keep"), "not the snapshot's\n")
            version[0] = "1.80.0"
            ROOT.arm_timer()
            self.put("/etc/ufw/user.rules", "*filter\n-A ufw-user-input -j DROP\nCOMMIT\n", 0o600)
            self.assertEqual(fire(), [["tar", "-xpf"], ["daemon-reload"], ["restart", "ssh.socket"],
                                      ["restart", "nftables.service"], ["restart", "ufw.service"],
                                      ["restart", "tailscaled.service"], ["restart", ROOT.SSHD_UNIT]])
            self.assertEqual(tree(), at_arm)
            ROOT.arm_timer()
            listed = json.loads(self.get("/var/lib/ops-root/rollback/snapshot.json"))
            self.put("/var/lib/ops-root/rollback/snapshot.json", json.dumps(dict(listed, sha256="0" * 64)))   # cut
            self.put("/etc/ufw/user.rules", "changed\n", 0o600)
            self.put("/etc/netplan/90-door.yaml", "network: {}\n", 0o600)
            fire()
            self.assertEqual(self.get("/etc/ufw/user.rules"), files["/etc/ufw/user.rules"])     # tar put it back
            self.assertTrue(os.path.exists(self.tmp + "/etc/netplan/90-door.yaml"))     # and nothing was removed
            ROOT.arm_timer()
            full_disk[0] = True                     # a reboot ended the countdown, and tar cannot write
            with patch.object(ROOT.os, "getppid", lambda: 1):
                self.assertEqual(ROOT.main(["ops-root", "--boot"]), 0)
        self.assertIn("the rollback's tar could not put every file back: tar: etc/ssh/sshd_config: Cannot open",
                      out.getvalue())
        self.assertIn("the reboot ended a rollback countdown: tar could not put every file back", out.getvalue())

    def test_the_timer_s_own_fire_needs_systemd_as_its_parent(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(ROOT.main(["ops-root", "--fire"]), 3)
        self.assertIn("rollback timer's own", out.getvalue())

    def test_a_request_that_is_not_base64_json_is_refused(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, patch("sys.stdin", None):
            self.assertEqual(ROOT.main(["ops-root", "bash -c id"]), 3)
            self.assertEqual(ROOT.main(["ops-root"]), 3)
        self.assertEqual(out.getvalue().count("refused:"), 2)


class ScriptForms(HostCase):
    """The door-modes proposal, steps 2 and 3: a bash script in the box of exec (script), and one as root with no box
    (run), each from stdin with the request's sha256 and after the rollback timer is armed; and the backup folder that
    the box writes. The transient service itself runs on a real host: host/check.sh access."""

    SCRIPT = b"set -euo pipefail\nexec 9>/run/lock/x.lock\nflock -n 9\nfor n in 1 2 3; do echo $n; done | wc -l\n"

    def setUp(self):
        super().setUp()
        self.put("/etc/ops-root/mode", "fix\n")
        self.ran, self.armed, self.scripts = [], [], []
        self.status, self.out = 0, "3\n"
        for patcher in (patch.object(ROOT, "arm_timer", lambda: self.armed.append(1) or "armed"),
                        patch.object(ROOT, "run", self.service)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def service(self, argv, stdin=None, timeout=900, env=None):
        """systemd-run: the script as the service reads it, and the service's status and output."""
        self.ran.append((argv, timeout))
        if argv[-2:-1] == ["/bin/bash"]:
            path = self.tmp + argv[-1]
            with open(path, "rb") as f:
                self.scripts.append((f.read(), os.stat(path).st_mode & 0o777))
        return self.status, self.out

    def send(self, op, data, sha256=None):
        return self.call(op, data=data, sha256=sha256 or hashlib.sha256(data).hexdigest())

    def test_a_script_runs_in_the_box_after_the_timer_is_armed(self):
        self.assertEqual(self.send("script", self.SCRIPT), "armed\n3\n")
        (argv, timeout), = self.ran
        self.assertEqual(argv[:7], ["systemd-run", "--pipe", "--wait", "--collect", "--quiet", "--unit",
                                    f"ops-root-script-{os.getpid()}"])
        self.assertEqual(argv[argv.index("--"):], ["--", "/bin/bash", f"{ROOT.STATE}/script-{os.getpid()}.sh"])
        props = [argv[i + 1] for i, a in enumerate(argv) if a == "--property"]
        for prop in ("InaccessiblePaths=-/var/www", "InaccessiblePaths=-/root", "InaccessiblePaths=-/var/backups",
                     "ReadOnlyPaths=-/var/lib/ops-root", "NoNewPrivileges=yes", "PrivateDevices=yes",
                     "StateDirectory=ops-backups", "StateDirectoryMode=0700"):
            self.assertIn(prop, props)
        self.assertEqual(props, [argv[i + 1] for i, a in enumerate(ROOT.box("x")) if a == "--property"])
        self.assertIn("--setenv=LANG=C.UTF-8", argv)
        self.assertEqual(timeout, ROOT.SCRIPT_WAIT)
        self.assertEqual(self.scripts, [(self.SCRIPT, 0o700)])
        self.assertEqual(os.listdir(self.tmp + ROOT.STATE), [])         # the script's file went when it ended
        self.assertEqual(self.armed, [1])

    def test_exec_runs_in_the_same_box(self):
        self.out = "ok\n"
        self.assertEqual(self.call("exec", "ls", "/etc/nginx"), "ok\n")
        (argv, _), = self.ran
        self.assertEqual(argv[:argv.index("--")], ROOT.box(f"ops-root-exec-{os.getpid()}"))
        self.assertEqual(self.armed, [])

    def test_a_run_is_root_with_no_box(self):
        self.assertEqual(self.send("run", self.SCRIPT), "armed\n3\n")
        (argv, timeout), = self.ran
        self.assertEqual(argv[:7], ["systemd-run", "--pipe", "--wait", "--collect", "--quiet", "--unit",
                                    f"ops-root-run-{os.getpid()}"])
        self.assertNotIn("--property", argv)
        self.assertEqual(argv[-3:], ["--", "/bin/bash", f"{ROOT.STATE}/run-{os.getpid()}.sh"])
        self.assertEqual((timeout, self.scripts, self.armed), (ROOT.SCRIPT_WAIT, [(self.SCRIPT, 0o700)], [1]))

    def test_each_needs_its_bytes_with_their_sha256_and_arms_nothing_without_them(self):
        for op in ("script", "run"):
            with self.subTest(op=op):
                with self.assertRaisesRegex(ROOT.Refused, f"^{op} takes the script on stdin, at most 256 KiB$"):
                    self.call(op)
                with self.assertRaisesRegex(ROOT.Refused, "^the bytes do not have the request's sha256$"):
                    self.send(op, b"echo hi\n", sha256="0" * 64)
                with self.assertRaisesRegex(ROOT.Refused, f"^the script of {op} is text for bash, with no NUL byte$"):
                    self.send(op, b"echo\0hi\n")
                with self.assertRaisesRegex(ROOT.Refused, "at most 256 KiB"):
                    self.send(op, b"#" * (ROOT.SCRIPT_MAX + 1))
                with self.assertRaisesRegex(ROOT.Refused, f"^{op} takes no arguments$"):
                    self.call(op, "x", data=b"echo\n", sha256=hashlib.sha256(b"echo\n").hexdigest())
        self.assertEqual((self.armed, self.ran), ([], []))

    def test_a_script_that_fails_gives_what_it_printed(self):
        self.status, self.out = 1, "flock: failed to get lock\n"
        with self.assertRaises(ROOT.Failed) as failed:
            self.send("script", self.SCRIPT)
        self.assertEqual(str(failed.exception), "armed\nflock: failed to get lock")
        self.status, self.out = 7, ""
        with self.assertRaisesRegex(ROOT.Failed, "^armed\nthe script ended with status 7$"):
            self.send("run", self.SCRIPT)
        self.assertEqual(os.listdir(self.tmp + ROOT.STATE), [])

    def test_exec_s_refusals_name_the_script_form_and_the_backup_folder(self):
        with self.assertRaises(ROOT.Refused) as refused:
            ROOT.check_args("exec", ["flock", "/run/lock/x.lock", "true"])
        self.assertEqual(str(refused.exception), "flock is a shell, an interpreter or a program that runs others, "
                                                 "which exec never runs: the script form runs a bash script in the "
                                                 "same box")
        with self.assertRaises(ROOT.Refused) as refused:
            ROOT.check_args("exec", ["cp", "/etc/nginx/nginx.conf", "/root/nginx.conf"])
        self.assertEqual(str(refused.exception), "/root/nginx.conf is an app tree or a secret path, which nothing in "
                                                 "the box reads: copies go to /var/lib/ops-backups, and a root script "
                                                 "that needs the path is the run form")
        copy = ["cp", "/etc/nginx/nginx.conf", f"{ROOT.BACKUPS}/nginx.conf"]
        self.assertEqual(ROOT.check_args("exec", copy), copy)
        self.assertFalse(ROOT.protected(f"{ROOT.BACKUPS}/nginx.conf"))
        self.assertFalse([h for h in ROOT.hidden_paths() if (ROOT.BACKUPS + "/").startswith(h.rstrip("/") + "/")])

    def test_the_help_names_both_forms_and_the_version(self):
        said = self.call("help")
        self.assertEqual(said.split("\n")[0], f"ops-root {ROOT.VERSION}, mode fix, release none")
        self.assertRegex(said, r"\nscript +own +a bash script in the box of exec, under the rollback timer")
        self.assertRegex(said, r"\nrun +full +a bash script as root with no box, under the rollback timer")
        self.assertEqual(ROOT.VERSION, 2)


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True).stdout


class SelfUpdate(HostCase):
    """A new ops-root only from a release that the release key signed, and never an older one."""

    def setUp(self):
        super().setUp()
        self.put("/etc/ops-root/release-key.pub",
                 "# test\n" + base64.b64encode(releases.public_key(SEED)).decode() + "\n")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo + "/host")
        git("init", "-q", self.repo)

    def release(self, version_line, extra="", seed=SEED, hold=False):
        """A commit with host/ops-root of that VERSION, a manifest of it signed with the test key, and the bundle the
        door sends: the commit, the root tree and host/'s tree as raw git objects, the files, and the commits below
        the revision as its history."""
        text = ROOT.__loader__.get_data(ROOT.__file__).decode()
        self.assertIn(f"\nVERSION = {ROOT.VERSION} ", text)
        text = text.replace(f"VERSION = {ROOT.VERSION} ", version_line + " ", 1) + extra
        for name, body in (("ops-root", text), ("ops-read", "#!/bin/sh\n"), ("inventory", "#!/bin/sh\n")):
            with open(f"{self.repo}/host/{name}", "w") as f:
                f.write(body)
        with open(f"{self.repo}/README", "w") as f:
            f.write("x\n")
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "release", cwd=self.repo)
        revision = git("rev-parse", "HEAD", cwd=self.repo).decode().strip()
        manifest = {"revision": revision, "version": "2026.11.200", "notes": None, "minimum": None, "hold": hold}
        manifest["signature"] = base64.b64encode(releases.sign(seed, releases.signed_text(manifest))).decode()

        def raw(kind, name):
            return base64.b64encode(git("cat-file", kind, name, cwd=self.repo)).decode()
        bundle = {"manifest": manifest, "commit": raw("commit", revision), "root": raw("tree", f"{revision}^{{tree}}"),
                  "host": raw("tree", f"{revision}:host"),
                  "files": {n: base64.b64encode(git("cat-file", "blob", f"{revision}:host/{n}", cwd=self.repo))
                            .decode() for n in ("ops-root", "ops-read", "inventory")},
                  "history": [raw("commit", c) for c in
                              git("rev-list", "--skip=1", revision, cwd=self.repo).decode().split()]}
        return bundle, text

    def update(self, bundle):
        return self.call("self-update", data=json.dumps(bundle).encode())

    NEWER = f"VERSION = {ROOT.VERSION + 1}"       # the next version of this file, and its words
    TAKEN = f"ops-root {ROOT.VERSION + 1} from release 2026.11.200"

    def test_a_signed_release_replaces_ops_root_and_its_helpers(self):
        bundle, text = self.release(self.NEWER)
        self.assertEqual(self.call("help").split("\n")[0], f"ops-root {ROOT.VERSION}, mode rule-only, release none")
        self.assertEqual(self.update(bundle), self.TAKEN)
        self.assertEqual(self.get("/usr/local/sbin/ops-root"), text)
        self.assertEqual(self.call("help").split("\n")[0],          # the door reads which release the host runs
                         f"ops-root {ROOT.VERSION}, mode rule-only, release {bundle['manifest']['revision']}")
        self.assertEqual(self.get("/usr/local/lib/ops-root/ops-read"), "#!/bin/sh\n")
        self.assertEqual(self.get("/etc/ops-root/release"), bundle["manifest"]["revision"] + "\n")
        self.assertEqual(os.stat(self.tmp + "/usr/local/sbin/ops-root").st_mode & 0o777, 0o755)

    def test_a_release_that_an_early_key_signed_replaces_it_too(self):
        """PRODUCT.md 4.3 "Two tracks": a fleet that takes releases early runs one that the early key signed."""
        early = bytes(range(100, 132))
        self.put("/etc/ops-root/early-key.pub", base64.b64encode(releases.public_key(early)).decode() + "\n")
        bundle, _ = self.release(self.NEWER, seed=early)
        self.assertEqual(self.update(bundle), self.TAKEN)

    def test_an_older_ops_root_is_refused(self):
        bundle, _ = self.release(f"VERSION = {ROOT.VERSION - 1}")
        with self.assertRaisesRegex(ROOT.Refused, f"older than {ROOT.VERSION}: never an older one"):
            self.update(bundle)
        self.assertFalse(os.path.exists(self.tmp + "/usr/local/sbin/ops-root"))

    def test_a_held_release_and_one_before_the_floor_are_refused_whatever_their_version(self):
        """What the door's own take refuses (door.take): a held release, and one that does not descend from the
        release that this ops-root came from. Its history shows the way down; a way that it does not show is none."""
        first, _ = self.release(self.NEWER)
        self.update(first)
        self.release(self.NEWER, extra="# between\n")
        later, text = self.release(self.NEWER, extra="# later\n")
        with self.assertRaisesRegex(ROOT.Refused, "does not descend from"):
            self.update(dict(later, history=[]))
        self.assertEqual(self.update(later), self.TAKEN)
        with self.assertRaisesRegex(ROOT.Refused, f"does not descend from {later['manifest']['revision']}, the "
                                                  "release this ops-root came from: never an older one"):
            self.update(first)
        held, _ = self.release(f"VERSION = {ROOT.VERSION + 2}", extra="# held\n", hold=True)
        with self.assertRaisesRegex(ROOT.Refused, "release 2026.11.200 is held"):
            self.update(held)
        self.assertEqual(self.get("/usr/local/sbin/ops-root"), text)
        self.assertEqual(self.get("/etc/ops-root/release"), later["manifest"]["revision"] + "\n")

    def test_a_forged_file_a_forged_tree_and_a_foreign_signature_are_refused(self):
        bundle, _ = self.release(self.NEWER)
        forged = json.loads(json.dumps(bundle))
        forged["files"]["ops-root"] = base64.b64encode(b"#!/bin/sh\nVERSION = 9\nid\n").decode()
        with self.assertRaisesRegex(ROOT.Refused, "host/ops-root is not the signed revision's"):
            self.update(forged)
        forged = json.loads(json.dumps(bundle))
        forged["host"] = forged["root"]
        with self.assertRaisesRegex(ROOT.Refused, "host/ is not"):
            self.update(forged)
        forged = json.loads(json.dumps(bundle))
        forged["manifest"]["signature"] = base64.b64encode(
            releases.sign(bytes(32), releases.signed_text(forged["manifest"]))).decode()
        with self.assertRaisesRegex(ROOT.Refused, "no release key of this host signed"):
            self.update(forged)
        forged = json.loads(json.dumps(bundle))
        forged["manifest"]["version"] = "2026.12.1"         # the signature covers the version
        with self.assertRaisesRegex(ROOT.Refused, "no release key"):
            self.update(forged)
        self.assertFalse(os.path.exists(self.tmp + "/usr/local/sbin/ops-root"))

    def test_the_door_never_sends_it_for_an_agent(self):
        d = door_targets.decide({"agents": {"a-1": {"address": "100.64.0.1", "servers": {"h": "fix"}}},
                                 "hosts": {"h": {"mode": "fix", "business": "b"}}}, "a-1", "h", "self-update", [])
        self.assertEqual((d.kind, d.why), ("refused", "self-update is the door's own form"))


class Reader(HostCase):
    """ops-read: the forced command of the second sshd."""

    def run_read(self, req, ran=None):
        env = {"SSH_ORIGINAL_COMMAND": base64.b64encode(json.dumps(req).encode()).decode() if req is not None else ""}
        calls = ran if ran is not None else []

        def fake(argv, **kw):
            calls.append((argv, kw.get("env")))
            return subprocess.CompletedProcess(argv, 0, b"read\n", b"")
        with patch.dict(os.environ, env, clear=False), patch.object(READ.subprocess, "run", fake), \
                patch.object(READ, "ROOT", self.tmp), contextlib.redirect_stdout(io.StringIO()) as out:
            code = READ.main()
        return code, out.getvalue(), calls

    def test_a_login_with_no_request_gets_nothing(self):
        code, out, calls = self.run_read(None)
        self.assertEqual((code, calls), (3, []))
        self.assertIn("the door's requests only", out)
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "bash -i"}):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(READ.main(), 3)

    def test_a_read_runs_here_with_a_fixed_argv_and_no_pager(self):
        code, out, calls = self.run_read({"v": 1, "op": "journal", "args": ["unit=nginx", "lines=50"]})
        self.assertEqual((code, out), (0, "read\n"))
        self.assertEqual(calls[0][0], ["journalctl", "--no-pager", "-o", "short-iso", "-n", "50", "-u", "nginx"])
        self.assertEqual(calls[0][1]["PAGER"], "cat")

    def test_a_log_file_is_read_only_under_var_log(self):
        with open(self.tmp + "/var/log/nginx/error.log", "w") as f:
            f.write("".join(f"line {i}\n" for i in range(10)))
        code, out, _ = self.run_read({"v": 1, "op": "log", "args": ["/var/log/nginx/error.log", "3"]})
        self.assertEqual((code, out), (0, "line 7\nline 8\nline 9\n"))
        os.symlink("/etc/passwd", self.tmp + "/var/log/nginx/passwd.log")
        code, out, _ = self.run_read({"v": 1, "op": "log", "args": ["/var/log/nginx/passwd.log"]})
        self.assertEqual(code, 3)

    def test_every_other_form_goes_to_ops_root_through_sudo(self):
        req = {"v": 1, "op": "restart", "args": ["nginx"]}
        code, _, calls = self.run_read(req)
        argv = calls[0][0]
        self.assertEqual(argv[:3], ["sudo", "-n", "/usr/local/sbin/ops-root"])
        self.assertEqual(json.loads(base64.b64decode(argv[3])), req)


class Runners(HostCase):
    """A CI host whose runners are containers of a rootless Docker on a sparse ext4 file (event E50): the file grows
    online from free space, and an idle runner restarts and gets its lost network back."""
    ME = __import__("pwd").getpwuid(os.getuid()).pw_name

    def setUp(self):
        super().setUp()
        os.makedirs(self.tmp + "/var/lib", exist_ok=True)
        self.put("/etc/ops-root/build-file", "/var/lib/ci-build.ext4\n")
        self.put("/etc/ops-root/runner-user", self.ME + "\n")
        with open(self.tmp + "/var/lib/ci-build.ext4", "wb") as f:
            f.write(b"x" * 4096)
        self.calls, self.free = [], 100
        self.ext4_mounts, self.docker_on = "/dev/sda1\n/dev/loop7\n", "/dev/loop7"     # what findmnt shows
        self.containers = {"runner-01": ("running", 1, "bridge 172.17.0.2 "), "runner-02": ("exited", 1, "bridge  "),
                           "runner-03": ("running", 0, "bridge 172.17.0.4 ")}
        for p in (patch.object(ROOT, "GIB", 1024), patch.object(ROOT, "run", self.run_stub),
                  patch.object(ROOT.os, "statvfs", lambda path: type("V", (), {"f_bavail": self.free * 1024,
                                                                              "f_frsize": 1})())):
            p.start()
            self.addCleanup(p.stop)

    def run_stub(self, argv, stdin=None, timeout=900, env=None):
        self.calls.append(argv)
        if argv[:4] == ["runuser", "-u", self.ME, "--"]:
            uid = os.getuid()
            self.assertEqual(argv[4:8], ["env", f"HOME={os.path.expanduser('~' + self.ME)}",
                                         f"XDG_RUNTIME_DIR=/run/user/{uid}",
                                         f"DOCKER_HOST=unix:///run/user/{uid}/docker.sock"])
            words = argv[9:]
            if words[0] == "ps":
                return 0, "".join(f"{n}\t{state}\n" for n, (state, _, _) in self.containers.items())
            if words[0] == "exec":
                return self.containers[words[1]][1], ""
            if words[0] == "inspect":
                return 0, self.containers[words[-1]][2]
            if words[:3] == ["info", "--format", "{{.DockerRootDir}}"]:     # run() gives errors with the output
                return 0, "WARNING: bridge-nf-call-iptables is disabled\n/var/lib/ci-docker\n"
            return 0, ""
        if argv[0] == "losetup" and argv[1] == "--associated":
            return 0, "/dev/loop7: []: (/var/lib/ci-build.ext4)\n"
        if argv[0] == "losetup" and argv[1:] == ["--noheadings", "--output", "BACK-FILE", "/dev/loop7"]:
            return 0, "/var/lib/ci-build.ext4\n"
        if argv[0] == "findmnt" and "--types" in argv:
            return 0, self.ext4_mounts
        if argv[0] == "findmnt" and argv[-2:] == ["--target", "/var/lib/ci-docker"]:
            return 0, self.docker_on + "\n"
        if argv[0] == "findmnt":
            return 0, "ext4\n"
        return 0, ""

    def socket_of(self, uid):
        """/run/user/<uid>/docker.sock as a socket of this test's user, as a rootless Docker makes it."""
        folder = self.tmp + f"/run/user/{uid}"
        os.makedirs(folder, exist_ok=True)
        here = os.getcwd()
        os.chdir(folder)                # a relative name: a socket's full path has a short limit on macOS
        try:
            sock = socket.socket(socket.AF_UNIX)
            sock.bind("docker.sock")
            self.addCleanup(sock.close)
        finally:
            os.chdir(here)

    def test_a_host_whose_install_named_neither_finds_its_runner_user_and_its_build_file(self):
        """The app's install passes no --build-file and no --runner-user (a CI host, 11 November 2026: grow-file
        "names no build file"). ops-root finds them: the one rootless Docker whose data is on a mounted ext4 loop
        device, and that device's file."""
        os.remove(self.tmp + "/etc/ops-root/build-file")
        os.remove(self.tmp + "/etc/ops-root/runner-user")
        self.socket_of(os.getuid())
        self.assertEqual(self.call("grow-file", "20"),
                         "/var/lib/ci-build.ext4 grew to 24 GiB, and its file system with it")
        self.assertEqual(os.path.getsize(self.tmp + "/var/lib/ci-build.ext4"), 4096 + 20 * 1024)
        self.assertIn(["findmnt", "--noheadings", "--output", "SOURCE", "--target", "/var/lib/ci-docker"], self.calls)
        self.assertEqual(self.call("runner-status"), "runner-01\tidle\tcontainer\nrunner-02\texited\tcontainer\n"
                                                     "runner-03\tbusy\tcontainer")
        self.assertEqual(self.call("runner-restart", "runner-02"), "runner-02 restarted, and its lost network is back")
        infos = [c for c in self.calls if c[0] == "runuser" and c[9] == "info"]
        self.assertEqual(len(infos), 3)                 # once in each of the three calls, however many docker calls

    def test_a_host_finds_its_layout_only_when_one_user_s_docker_is_on_a_loop_file(self):
        os.remove(self.tmp + "/etc/ops-root/build-file")
        os.remove(self.tmp + "/etc/ops-root/runner-user")

        def refused():
            with self.assertRaisesRegex(ROOT.Refused, "names no build file"):
                self.call("grow-file", "5")
            self.assertEqual(self.call("runner-status"), "no runner")
        refused()                                       # no rootless Docker at all
        self.socket_of(1)                               # a socket in another uid's folder is not that user's Docker
        refused()
        self.socket_of(os.getuid())
        self.docker_on = "/dev/sda1"                    # its data on the host's own disk
        refused()
        self.docker_on, self.ext4_mounts, self.calls = "/dev/loop7", "/dev/sda1\n", []
        refused()                                       # no ext4 loop device mounted: no Docker is asked
        self.assertEqual([c for c in self.calls if c[0] == "runuser"], [])
        self.ext4_mounts = "/dev/loop7\n"
        with patch.object(ROOT, "rootless_users", lambda: [self.ME, self.ME]):
            refused()                                   # two such users: neither is the one
        self.put("/etc/ops-root/runner-user", self.ME + "\n")
        self.calls = []
        with self.assertRaisesRegex(ROOT.Refused, "names no build file"):
            self.call("grow-file", "5")                 # an install that named one: only what it named
        self.assertEqual([c for c in self.calls if "--types" in c], [])

    def test_the_build_file_grows_from_free_space_and_keeps_its_margin(self):
        said = self.call("grow-file", "20")             # 4 + 20: one GiB is 1 KiB here
        self.assertEqual(said, "/var/lib/ci-build.ext4 grew to 24 GiB, and its file system with it")
        self.assertEqual(os.path.getsize(self.tmp + "/var/lib/ci-build.ext4"), 4096 + 20 * 1024)
        self.assertEqual([c for c in self.calls if c[0] != "findmnt"][1:],
                         [["losetup", "--set-capacity", "/dev/loop7"], ["resize2fs", "/dev/loop7"]])
        self.free = 30          # 20 more could be taken, and 20 GiB stay free beyond it: 40 > 30
        with self.assertRaisesRegex(ROOT.Refused, "keeps 20 GiB beyond that"):
            self.call("grow-file", "20")
        self.assertEqual(os.path.getsize(self.tmp + "/var/lib/ci-build.ext4"), 4096 + 20 * 1024)
        for bad in ("0", "101", "-5", "1G"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ROOT.Refused, "adds 1 to 100 GiB"):
                self.call("grow-file", bad)

    def test_the_build_file_must_be_one_mounted_ext4_loop(self):
        self.free = 1000
        with patch.object(ROOT, "run", lambda argv, **kw: (0, "") if argv[0] == "losetup" else (0, "ext4")):
            with self.assertRaisesRegex(ROOT.Refused, "on no one loop device"):
                self.call("grow-file", "5")
        with patch.object(ROOT, "run", lambda argv, **kw: (0, "/dev/loop7: []: (x)") if argv[0] == "losetup"
                          else (0, "xfs")):
            with self.assertRaisesRegex(ROOT.Refused, "no mounted ext4"):
                self.call("grow-file", "5")
        os.remove(self.tmp + "/etc/ops-root/build-file")
        with self.assertRaisesRegex(ROOT.Refused, "names no build file"):
            self.call("grow-file", "5")

    def test_status_and_a_restart_of_an_idle_runner_with_its_network_back(self):
        self.assertEqual(self.call("runner-status"), "runner-01\tidle\tcontainer\nrunner-02\texited\tcontainer\n"
                                                     "runner-03\tbusy\tcontainer")
        with self.assertRaisesRegex(ROOT.Refused, "runs a job now"):
            self.call("runner-restart", "runner-03")
        self.assertEqual(self.call("runner-restart", "runner-02"), "runner-02 restarted, and its lost network is back")
        docker = [c[9:] for c in self.calls if c[0] == "runuser"]
        self.assertIn(["restart", "--time", "60", "runner-02"], docker)
        self.assertEqual(docker[-1], ["network", "connect", "bridge", "runner-02"])
        self.calls.clear()
        self.assertEqual(self.call("runner-restart", "runner-01"), "runner-01 restarted")
        self.assertNotIn("network", [c[9] for c in self.calls if c[0] == "runuser"])
        with self.assertRaisesRegex(ROOT.Refused, "not a runner of this host"):
            self.call("runner-restart", "runner-09")


class Accounts(HostCase):
    """passwd -l and a package purge are the agent's own forms (DevOps plan section 9): the exec form cannot run them,
    because an exec command sees /etc/shadow read-only and never runs apt-get."""

    def setUp(self):
        super().setUp()
        self.put("/etc/ops-root/mode", "fix\n")
        self.calls = []

    def test_passwd_lock_of_one_user_never_root_or_ops_agent(self):
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        with patch.object(ROOT, "run", lambda argv, **kw: (self.calls.append(argv), (0, ""))[1]):
            self.assertEqual(self.call("passwd-lock", me), f"the password of {me} is locked")
            self.assertEqual(self.calls, [["passwd", "-l", me]])
            for bad in ("root", "ops-agent", "-l", "a b"):
                with self.subTest(user=bad), self.assertRaisesRegex(ROOT.Refused, "not a user whose password"):
                    self.call("passwd-lock", bad)
            with self.assertRaisesRegex(ROOT.Refused, "no user of this host"):
                self.call("passwd-lock", "nobody-here-at-all")
            with patch.object(ROOT.pwd, "getpwnam", lambda name: type("P", (), {"pw_uid": 0})()), \
                    self.assertRaisesRegex(ROOT.Refused, "is root"):
                self.call("passwd-lock", "toor")
        self.assertEqual(len(self.calls), 1)

    def test_a_purge_runs_only_when_apt_s_dry_run_spares_the_door_s_way_in(self):
        said = {"telnetd": "Purg telnetd [0.17-44]\n", "sshd-only": "Remv openssh-server [1:9.6p1]\nPurg x [1]\n",
                "many": "".join(f"Purg p{i} [1]\n" for i in range(21)), "gone": "0 upgraded, 0 to remove\n",
                "py": "Purg libpython3.12-minimal:amd64 [3.12.3]\n"}
        detached = []
        with patch.object(ROOT, "run", lambda argv, **kw: (self.calls.append(argv), (0, said[argv[-1]]))[1]), \
                patch.object(ROOT, "detached", lambda name, argv: (detached.append((name, argv)), "purge done")[1]):
            self.assertEqual(self.call("purge", "telnetd"), "purge done")
            self.assertEqual(self.calls[0], ["apt-get", "--simulate", "purge", "telnetd"])
            self.assertEqual(detached, [("purge", ["apt-get", "purge", "-y", "-o", "DPkg::Lock::Timeout=600",
                                                   "telnetd"])])
            with self.assertRaisesRegex(ROOT.Refused, "remove openssh-server, which the door's way in needs"):
                self.call("purge", "sshd-only")
            with self.assertRaisesRegex(ROOT.Refused, "remove libpython3.12-minimal"):
                self.call("purge", "py")
            with self.assertRaisesRegex(ROOT.Refused, "21 packages: 20 at most"):
                self.call("purge", "many")
            self.assertEqual(self.call("purge", "gone"), "nothing to purge")
        self.assertEqual(len(detached), 1)
        for bad in ("telnetd=0.17", "telnet*", "-y", "Telnetd"):
            with self.subTest(name=bad), self.assertRaisesRegex(ROOT.Refused, "not a package name"):
                self.call("purge", bad)


class Scripts(unittest.TestCase):
    """The two install scripts parse, refuse to run as another user, and name each part the plan names."""

    def test_both_scripts_parse(self):
        for script in ("host/install.sh", "door.sh"):
            with self.subTest(script=script):
                subprocess.run(["bash", "-n", script], check=True)

    def test_install_names_the_parts_of_the_plan(self):
        with open("host/install.sh") as f:
            text = f.read()
        for part in ("AllowUsers ops-agent", "PermitTTY no", "AllowTcpForwarding no", "AllowStreamLocalForwarding no",
                     "PermitTunnel no", "ForceCommand", "UsePAM no", "usermod -p '*'", "After=network-online.target "
                     "tailscaled.service", "Restart=always", "RestartSec=5", "StartLimitIntervalSec=0",
                     "systemctl mask ssh.service ssh.socket", "ops-agent ALL=(root) NOPASSWD: %s",
                     "COVERED=\"ubuntu:24.04 ubuntu:26.04\"", "visudo -c", "--remove"):
            self.assertIn(part, text)
        self.assertNotIn("Sandbox", text)       # no sandbox line of the main sshd: those kill sudo

    def test_the_config_test_has_the_folder_that_sshd_needs(self):
        """On a host that Tailscale's own SSH serves, OpenSSH is masked and /run/sshd is not there, so `sshd -t`
        stopped the install with "Missing privilege separation directory: /run/sshd" (7 November 2026)."""
        with open("host/install.sh") as f:
            text = f.read()
        folder = text.index("install -d -m 0755 -o root -g root /run/sshd")
        self.assertLess(folder, text.index('/usr/sbin/sshd -t -f "$ETC/sshd_config"'))

    def test_read_takes_away_the_files_that_only_ops_root_reads(self):
        """From Fix down to Read, ops-root's own files go with it, so a later Fix without one of their options finds
        no old one: the level's own block of install.sh, run with its paths in a temporary folder."""
        with open("host/install.sh") as f:
            text = f.read()
        start = text.index('if [ "$LEVEL" = fix ]; then')
        block = text[start:text.index("\nfi\n", start) + 4]
        with tempfile.TemporaryDirectory() as tmp:
            etc = os.path.join(tmp, "etc")
            os.mkdir(etc)
            fix_only = ("mode", "fleet-kit", "pool", "build-file", "runner-user")
            for name in fix_only:
                with open(os.path.join(etc, name), "w") as f:
                    f.write("/somewhere\n")
            rollback = os.path.join(tmp, "state", "rollback")      # no ops-root fires it at Read
            os.makedirs(rollback)
            open(os.path.join(rollback, "snapshot.tar"), "w").close()
            subprocess.run(["bash", "-c", "set -euo pipefail\n" + block], check=True, capture_output=True,
                           env={"PATH": os.environ["PATH"], "LEVEL": "read", "ETC": etc,
                                "SBIN": os.path.join(tmp, "ops-root"), "SUDOERS": os.path.join(tmp, "sudoers"),
                                "STATE": os.path.join(tmp, "state")})
            self.assertEqual([name for name in fix_only if os.path.exists(os.path.join(etc, name))], [])
            self.assertFalse(os.path.exists(rollback))

    def test_a_remove_runs_on_any_release(self):
        """A host that was upgraded to a release that the install does not cover could never lose the door's parts:
        the release check came before the remove."""
        with open("host/install.sh") as f:
            text = f.read()
        self.assertLess(text.index('if [ "$REMOVE" = 1 ]; then'), text.index(". /etc/os-release"))
        self.assertLess(text.index(". /etc/os-release"), text.index('case "$LEVEL" in'))

    def remove_files(self, apps):
        """What install.sh --remove leaves of ops-root's folders on a host with these apps: its last block, run with
        its paths in a temporary folder."""
        with open("host/install.sh") as f:
            text = f.read()
        self.assertIn('\n    apps=""\n', text)
        start = text.index('    apps=""\n')
        block = text[start:text.index("\n    fi\n", start) + 8]
        with tempfile.TemporaryDirectory() as tmp:
            etc, lib, state = (os.path.join(tmp, name) for name in ("etc", "lib", "state"))
            os.makedirs(os.path.join(etc, "apps"))
            os.makedirs(os.path.join(state, "rollback"))
            os.mkdir(lib)
            for path in [f"{etc}/{n}" for n in ("mode", "release", "hidden", "authorized_keys", "release-key.pub")] + \
                    [f"{lib}/{n}" for n in ("ops-read", "inventory", "app-release")] + \
                    [f"{etc}/apps/{app}.json" for app in apps] + [f"{tmp}/ops-root", f"{state}/yes.json"]:
                open(path, "w").close()
            said = subprocess.run(["bash", "-c", "set -euo pipefail\n" + block], check=True, capture_output=True,
                                  env={"PATH": os.environ["PATH"], "ETC": etc, "LIB": lib, "STATE": state,
                                       "SBIN": os.path.join(tmp, "ops-root")}).stdout.decode()
            return said, sorted(os.path.relpath(os.path.join(here, name), tmp)
                                for here, _, names in os.walk(tmp) for name in names)

    def test_a_remove_keeps_the_release_helper_and_the_settings_of_the_apps_that_are_there(self):
        """Each /usr/local/sbin/<app>-deploy is a link to the release helper, which reads the app's settings: a remove
        that took both left every app of app-new with no deploy and no rollback."""
        self.assertEqual(self.remove_files([]), ("", []))
        said, left = self.remove_files(["shop", "blog"])
        self.assertEqual(left, ["etc/apps/blog.json", "etc/apps/shop.json", "lib/app-release"])
        self.assertEqual(said, "kept: the release helper and the settings of blog shop, whose deploys go on\n")

    def test_a_second_install_keeps_the_release_file_only_with_the_parts_that_it_names(self):
        """ops-root's help says which release self-update gave the host, and the door sends no update to a host that
        names the door's own release. A second install wrote its own ops-root and kept the file."""
        with open("host/install.sh") as f:
            text = f.read()
        first = ('for f in ops-read inventory app-release; do cmp -s "$HERE/$f" "$LIB/$f" || rm -f "$ETC/release"; '
                 'done\n')
        last = '[ "$LEVEL" = read ] || cmp -s "$HERE/ops-root" "$SBIN" || rm -f "$ETC/release"\n'
        self.assertIn(first + last, text)
        self.assertLess(text.index(first), text.index('install -m 0755 -o root -g root "$HERE/ops-read"'))

        def kept(level="fix", **bundle):
            with tempfile.TemporaryDirectory() as tmp:
                here, lib, etc = (os.path.join(tmp, name) for name in ("here", "lib", "etc"))
                for folder in (here, lib, etc):
                    os.mkdir(folder)
                for folder, sbin in ((here, f"{here}/ops-root"), (lib, f"{tmp}/sbin")):
                    for path in [f"{folder}/{n}" for n in ("ops-read", "inventory", "app-release")] + [sbin]:
                        with open(path, "w") as f:
                            f.write(bundle.get(os.path.basename(path), "") if folder == here else "")
                for name in bundle.get("gone", ()):
                    os.remove(f"{tmp}/sbin" if name == "ops-root" else f"{lib}/{name}")
                open(f"{etc}/release", "w").close()
                subprocess.run(["bash", "-c", "set -euo pipefail\n" + first + last], check=True, capture_output=True,
                               env={"PATH": os.environ["PATH"], "HERE": here, "LIB": lib, "ETC": etc, "LEVEL": level,
                                    "SBIN": f"{tmp}/sbin"})
                return os.path.exists(f"{etc}/release")
        self.assertTrue(kept())                             # the same parts again: the file is still true
        self.assertFalse(kept(**{"ops-root": "another\n"}))
        self.assertFalse(kept(**{"app-release": "another\n"}))
        self.assertFalse(kept(gone=["ops-root"]))           # from Read up to Fix: a new copy of ops-root
        self.assertTrue(kept(level="read", gone=["ops-root"]))

    def test_door_sh_has_no_release_timer(self):
        with open("door.sh") as f:
            text = f.read()
        self.assertNotIn("OnCalendar", text)
        self.assertIn("door.py update", text)
        self.assertIn("unattended-upgrades", text)


if __name__ == "__main__":
    unittest.main()


class AppShape(HostCase):
    """A fix host with the release helper, whose programs are stubs that record what they were asked."""

    def setUp(self):
        super().setUp()
        os.makedirs(self.tmp + "/var/www", exist_ok=True)
        os.makedirs(self.tmp + "/etc/systemd/system", exist_ok=True)
        self.put(ROOT.RELEASE_HELPER, "#!/usr/bin/python3\n", 0o755)
        self.argv, self.listening, self.failing, self.loaded = [], "", None, set()

        def run(argv, stdin=None, timeout=900, env=None):
            self.argv.append(argv)
            if argv[0] == "ss":
                return 0, self.listening
            if self.failing and self.failing in argv:
                return 1, f"{self.failing} failed"
            if argv[0] == "systemctl" and "--property=LoadState" in argv:
                return 0, "loaded\n" if argv[-1] in self.loaded else "not-found\n"
            return 0, ""
        patches = [patch.object(ROOT, "run", run), patch.object(ROOT, "account_exists", lambda name: False),
                   patch.object(ROOT, "mode", lambda: "fix")]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


class NewApp(AppShape):
    """New-projects plan N4: app-new makes the product's one app shape, refuses a name or a port that is taken, takes
    back all that it made when a step fails, and writes only on a fix host; app-check reads the shape back."""

    def test_its_arguments(self):
        for args in (["Bad", "8080", "/health"], ["1app", "8080", "/health"], ["a" * 25, "8080", "/health"],
                     ["shop", "80", "/health"], ["shop", "70000", "/health"], ["shop", "8080", "health"],
                     ["shop", "8080", "/a/../b"], ["shop", "8080"]):
            with self.subTest(args=args), self.assertRaises(ROOT.Refused):
                ROOT.check_args("app-new", args)
        self.assertEqual(ROOT.check_args("app-new", ["shop", "8080", "/api/health"]), ["shop", "8080", "/api/health"])

    def test_app_new_makes_the_whole_shape(self):
        said = self.call("app-new", "shop", "8080", "/api/health")
        self.assertIn("in place, on port 8080", said)
        users = [a for a in self.argv if a[0] == "useradd"]
        self.assertEqual([a[-1] for a in users], ["shop-app", "shop-deploy"])
        self.assertIn("/usr/sbin/nologin", users[0])
        self.assertEqual(users[1][users[1].index("--shell") + 1], "/bin/bash")
        self.assertEqual([a for a in self.argv if a[0] == "passwd"],
                         [["passwd", "--lock", "shop-app"], ["passwd", "--lock", "shop-deploy"]])
        for folder in ("", "/releases", "/artifacts", "/artifacts/incoming", "/shared"):
            self.assertEqual(os.stat(self.tmp + "/var/www/shop" + folder).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(self.tmp + "/var/www/shop/shared/.env").st_mode & 0o777, 0o600)
        self.assertEqual(self.get("/var/www/shop/shared/.env"), "")
        self.assertEqual(os.stat(self.tmp + "/var/www/shop/release-blocklist").st_mode & 0o777, 0o644)
        self.assertEqual(json.loads(self.get("/etc/ops-root/apps/shop.json")),
                         {"app": "shop", "port": 8080, "health": "/api/health"})
        self.assertEqual(os.readlink(self.tmp + "/usr/local/sbin/shop-deploy"), ROOT.RELEASE_HELPER)
        self.assertEqual(self.get("/etc/sudoers.d/95-app-shop"),
                         "shop-deploy ALL=(root) NOPASSWD: /usr/local/sbin/shop-deploy deploy *\n")
        self.assertIn(["visudo", "-cf", self.tmp + "/etc/sudoers.d/95-app-shop"], self.argv)
        with self.assertRaisesRegex(ROOT.Refused, "exists already"):
            self.call("app-new", "shop", "8081", "/api/health")

    def test_app_new_refuses_a_taken_name_port_or_a_host_without_its_helper(self):
        with patch.object(ROOT, "account_exists", lambda name: name == "nginx"):
            with self.assertRaisesRegex(ROOT.Refused, "nginx exists already"):
                self.call("app-new", "nginx", "8080", "/health")
        self.listening = "LISTEN 0 511 127.0.0.1:8080 0.0.0.0:*\n"
        with self.assertRaisesRegex(ROOT.Refused, "listens on port 8080"):
            self.call("app-new", "shop", "8080", "/health")
        self.listening = ""
        os.makedirs(self.tmp + "/etc/ops-root/apps", exist_ok=True)
        self.put("/etc/ops-root/apps/blog.json", json.dumps({"app": "blog", "port": 8090, "health": "/"}))
        with self.assertRaisesRegex(ROOT.Refused, "another app has it"):
            self.call("app-new", "shop", "8090", "/health")
        os.remove(self.tmp + ROOT.RELEASE_HELPER)
        with self.assertRaisesRegex(ROOT.Refused, "release helper is not on this host"):
            self.call("app-new", "shop", "8091", "/health")
        with patch.object(ROOT, "mode", lambda: "rule-only"):
            with self.assertRaisesRegex(ROOT.Refused, "rule-only: no form of a new app"):
                self.call("app-new", "shop", "8091", "/health")

    def test_app_new_refuses_a_name_that_systemd_or_the_system_has(self):
        """nginx has no user and no unit in /etc/systemd/system on Ubuntu: its unit in /usr/lib and its /etc/nginx
        refuse it. A folder that a unit's StateDirectory or CacheDirectory would give the app refuses its name too."""
        self.loaded = {"nginx.service", "cron.service"}
        with self.assertRaisesRegex(ROOT.Refused, r"/etc/nginx, /var/log/nginx, nginx.service exists already"):
            self.call("app-new", "nginx", "8080", "/health")
        with self.assertRaisesRegex(ROOT.Refused, r"^cron.service exists already"):
            self.call("app-new", "cron", "8080", "/health")
        os.makedirs(self.tmp + "/var/lib/dpkg")
        with self.assertRaisesRegex(ROOT.Refused, r"^/var/lib/dpkg exists already"):
            self.call("app-new", "dpkg", "8080", "/health")

    def test_app_new_that_stops_half_way_leaves_nothing(self):
        self.failing = "visudo"
        with self.assertRaisesRegex(ROOT.Failed, "took back what it made"):
            self.call("app-new", "shop", "8080", "/api/health")
        for path in ("/var/www/shop", "/usr/local/sbin/shop-deploy", "/etc/sudoers.d/95-app-shop",
                     "/etc/ops-root/apps/shop.json"):
            self.assertFalse(os.path.lexists(self.tmp + path), path)
        self.assertEqual([a for a in self.argv if a[0] == "userdel"],
                         [["userdel", "--remove", "shop-deploy"], ["userdel", "--remove", "shop-app"]])

    def test_app_check_reads_the_shape_back(self):
        self.call("app-new", "shop", "8080", "/api/health")
        users = {"shop-app": "/usr/sbin/nologin", "shop-deploy": "/bin/bash"}
        record = __import__("collections").namedtuple("pw", "pw_shell")

        def getpwnam(name):
            if name not in users:
                raise KeyError(name)
            return record(users[name])

        def run(argv, stdin=None, timeout=900, env=None):
            if argv[:2] == ["passwd", "--status"]:
                return 0, f"{argv[2]} L 2026-11-06 0 99999 7 -1\n"
            if "is-active" in argv:
                return 3, "inactive\n"
            return 0, ""
        with patch.object(ROOT.pwd, "getpwnam", getpwnam), patch.object(ROOT, "run", run):
            got = json.loads(self.call("app-check", "shop"))
        self.assertEqual(got["shop-app"], "ok")
        self.assertEqual(got["shop-deploy"], "ok")
        self.assertEqual(got["/var/www/shop/shared/.env"], "ok")
        self.assertEqual(got["/usr/local/sbin/shop-deploy"], "ok")
        self.assertEqual(got["/etc/sudoers.d/95-app-shop"], "ok")
        self.assertEqual((got["service"], got["runner"]), ("inactive", "none"))
        os.chmod(self.tmp + "/var/www/shop/shared/.env", 0o644)
        with patch.object(ROOT.pwd, "getpwnam", getpwnam), patch.object(ROOT, "run", run):
            got = json.loads(self.call("app-check", "shop"))
        self.assertEqual(got["/var/www/shop/shared/.env"], "mode 644, owner " + str(os.getuid()))


UNIT = """[Unit]
Description=shop
After=network.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=shop-app
Group=shop-app
WorkingDirectory=/var/www/shop/current
EnvironmentFile=/var/www/shop/shared/.env
EnvironmentFile=-/var/www/shop/current/.release.env
Environment=NODE_ENV=production
Environment=PORT=8080 "HOSTNAME=127.0.0.1"
ExecStart=/usr/bin/node /var/www/shop/current/server.js
Restart=on-failure
RestartSec=2
UMask=0027
CacheDirectory=shop/next
CacheDirectoryMode=0750
BindPaths=/var/cache/shop/next:/var/www/shop/current/.next/cache
# the sandbox
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/shop/data
RestrictSUIDSGID=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""


class AppUnitAndSettings(AppShape):
    """New-projects plan N4: unit-new installs the app's unit only after code read each line of it, and env-new and
    env-add add one setting with the door's value, which no answer shows. The unit runs as the app's own user, with no
    new privileges and the app's own settings file, and nothing in it runs with privileges, pulls in a unit that is
    not the app's or the network's, or gives the app a folder that is not its own."""

    def setUp(self):
        super().setUp()
        self.call("app-new", "shop", "8080", "/api/health")
        self.uid = os.getuid()
        record = __import__("collections").namedtuple("pw", "pw_uid pw_gid pw_shell")

        def getpwnam(name):
            if name != "shop-app":
                raise KeyError(name)
            return record(self.uid, os.getgid(), "/usr/sbin/nologin")
        p = patch.object(ROOT.pwd, "getpwnam", getpwnam)
        p.start()
        self.addCleanup(p.stop)
        self.argv.clear()

    def unit(self, text=UNIT):
        data = text.encode()
        return self.call("unit-new", "shop", data=data, sha256=hashlib.sha256(data).hexdigest())

    def test_unit_new_installs_and_enables_the_unit(self):
        self.assertEqual(self.unit(), "shop.service is installed and enabled: the app's first release starts it")
        self.assertEqual(self.get("/etc/systemd/system/shop.service"), UNIT)
        self.assertEqual(os.stat(self.tmp + "/etc/systemd/system/shop.service").st_mode & 0o777, 0o644)
        self.assertEqual([a[3:] for a in self.argv if a[0] == "systemctl" and "show" not in a],
                         [["daemon-reload"], ["enable", "shop.service"]])
        with self.assertRaisesRegex(ROOT.Refused, "exists already: unit-new installs a new unit only"):
            self.unit()

    def test_unit_new_refuses_what_code_reads_in_the_unit(self):
        user, prefix, release = "runs as shop-app", "no prefix that gives it privileges", "runs the release under"
        files, pulls = "reads /var/www/shop/shared/.env", "is not a setting that an app's unit has"
        cases = {
            "another user": ("User=shop-app", "User=root", user),
            "a second user line": ("Group=shop-app", "Group=shop-app\nUser=", user),
            "another group": ("Group=shop-app", "Group=docker", user),
            "no NoNewPrivileges": ("NoNewPrivileges=true", "NoNewPrivileges=false", "NoNewPrivileges=true"),
            "a command with privileges": ("ExecStart=/usr/bin/node", "ExecStart=+/usr/bin/node", prefix),
            "a first command with privileges": ("Restart=on-failure", "ExecStartPre=!/bin/sh -c id\nRestart=no",
                                                prefix),
            "two commands on one line": ("Restart=on-failure", "ExecStartPre=/bin/true ; /bin/id\nRestart=no", prefix),
            "a release of another folder": ("/var/www/shop/current/server.js", "/srv/other/server.js", release),
            "a way out of current": ("/var/www/shop/current/server.js", "/var/www/shop/current/../../blog/x.js",
                                     release),
            "two ExecStart": ("Restart=on-failure", "ExecStart=/usr/bin/node /var/www/shop/current/b.js",
                              "one ExecStart"),
            "another app's settings": ("EnvironmentFile=-/var/www/shop/current/.release.env",
                                       "EnvironmentFile=/var/www/blog/shared/.env", files),
            "no settings file": ("EnvironmentFile=/var/www/shop/shared/.env\n", "", files),
            "another port": ("PORT=8080", "PORT=9090", "PORT is 8080"),
            "a public address": ('"HOSTNAME=127.0.0.1"', "HOSTNAME=0.0.0.0", "HOSTNAME is a loopback address"),
            "an alias over a unit": ("WantedBy=multi-user.target", "WantedBy=multi-user.target\nAlias=ssh.service",
                                     "Alias " + pulls),
            "a reboot when it fails": ("Description=shop", "Description=shop\nOnFailure=reboot.target",
                                       "OnFailure " + pulls),
            "a unit that it pulls in": ("Wants=network-online.target", "Wants=systemd-reboot.service",
                                        "pulls in systemd-reboot.service"),
            "a folder of the system": ("CacheDirectory=shop/next", "StateDirectory=dpkg", "StateDirectory is shop"),
            "a bind of another folder": ("BindPaths=/var/cache/shop/next:", "BindPaths=/root/notes:",
                                         "binds folders of the app only"),
            "a capability": ("UMask=0027", "UMask=0027\nAmbientCapabilities=CAP_NET_BIND_SERVICE",
                             "AmbientCapabilities " + pulls),
            "a section of another kind": ("[Install]", "[Socket]\nListenStream=80\n[Install]", "sections [Unit]"),
            "a line that goes on": ("Restart=on-failure", "Restart=on-failure \\\nUser=root", "goes on to the next"),
            "output into a file of root's": ("UMask=0027", "UMask=0027\nStandardOutput=file:/etc/passwd",
                                             "StandardOutput is one of journal"),
            "a control character": ("Description=shop", "Description=shop\x1b[2J", "no control character"),
            "no install line": ("WantedBy=multi-user.target", "", "wanted by multi-user.target"),
            "a key before any section": ("[Unit]", "User=root\n[Unit]", "is not a setting of a section"),
        }
        for why, (old, new, words) in cases.items():
            with self.subTest(why):
                self.assertIn(old, UNIT)
                with self.assertRaises(ROOT.Refused) as refused:
                    self.unit(UNIT.replace(old, new, 1))
                self.assertIn(words, str(refused.exception))
        self.assertFalse(os.path.lexists(self.tmp + "/etc/systemd/system/shop.service"))

    def test_unit_new_refuses_without_the_app_its_bytes_or_a_free_name(self):
        with self.assertRaisesRegex(ROOT.Refused, "blog is no app of this host"):
            self.call("unit-new", "blog", data=UNIT.encode(), sha256=hashlib.sha256(UNIT.encode()).hexdigest())
        with self.assertRaisesRegex(ROOT.Refused, "sha256"):
            self.call("unit-new", "shop", data=UNIT.encode(), sha256="0" * 64)
        self.loaded = {"shop.service"}
        with self.assertRaisesRegex(ROOT.Refused, "^shop.service exists already"):
            self.unit()
        self.loaded = set()
        os.makedirs(self.tmp + "/var/cache/shop/next")
        self.uid = os.getuid() + 1
        with self.assertRaisesRegex(ROOT.Refused, "/var/cache/shop/next of CacheDirectory exists and is not shop-app"):
            self.unit()
        self.uid = os.getuid()
        with patch.object(ROOT, "mode", lambda: "rule-only"), self.assertRaisesRegex(ROOT.Refused, "rule-only"):
            self.unit()

    def test_a_unit_that_systemd_does_not_take_is_taken_back(self):
        self.failing = "enable"
        with self.assertRaisesRegex(ROOT.Failed, "took the unit back"):
            self.unit()
        self.assertFalse(os.path.lexists(self.tmp + "/etc/systemd/system/shop.service"))
        self.assertEqual([a[3:] for a in self.argv if a[0] == "systemctl" and "show" not in a],
                         [["daemon-reload"], ["enable", "shop.service"], ["daemon-reload"]])

    def test_env_new_adds_one_setting_with_the_door_s_value(self):
        said = self.call("env-new", "shop", "SESSION_SECRET", "random", data=b"q83v+/9z==")
        self.assertEqual(said, "SESSION_SECRET is in shop's settings, from 32 random bytes of the door: the app reads "
                               "it when it next starts")
        self.assertNotIn("q83v", said)
        said = self.call("env-new", "shop", "STRIPE_SECRET_KEY", "key", data='sk_a b"c$d\\e`'.encode())
        self.assertIn("the key that the owner saved as app:shop:STRIPE_SECRET_KEY", said)
        self.assertEqual(self.get("/var/www/shop/shared/.env"),
                         'SESSION_SECRET=q83v+/9z==\nSTRIPE_SECRET_KEY="sk_a b\\"c\\$d\\\\e\\`"\n')
        self.assertEqual(os.stat(self.tmp + "/var/www/shop/shared/.env").st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ROOT.Refused, "SESSION_SECRET is in shop's settings already"):
            self.call("env-new", "shop", "SESSION_SECRET", "random", data=b"other")

    def test_env_new_refuses_names_values_and_a_release(self):
        for args in (["shop", "PORT", "random"], ["shop", "NODE_OPTIONS", "key"], ["shop", "LD_PRELOAD", "random"],
                     ["shop", "lower", "random"], ["shop", "KEY", "typed"], ["shop", "KEY"], ["Shop", "KEY", "key"]):
            with self.subTest(args=args), self.assertRaises(ROOT.Refused):
                ROOT.check_args("env-new", args)
        for data in (None, b"", b"two\nlines", b"tab\there", b"\xff\xfe", b"x" * 4097):
            with self.subTest(data=data), self.assertRaisesRegex(ROOT.Refused, "value"):
                self.call("env-new", "shop", "API_KEY", "random", data=data)
        with self.assertRaisesRegex(ROOT.Refused, "blog is no app of this host"):
            self.call("env-new", "blog", "API_KEY", "random", data=b"v")
        os.symlink("releases/one", self.tmp + "/var/www/shop/current")
        with self.assertRaisesRegex(ROOT.Refused, "shop has a release: env-add adds a setting now"):
            self.call("env-new", "shop", "API_KEY", "random", data=b"v")
        self.assertIn("API_KEY is in shop's settings", self.call("env-add", "shop", "API_KEY", "random", data=b"v"))
        for op in ("env-new", "env-add"):
            with self.subTest(op=op), patch.object(ROOT, "mode", lambda: "rule-only"), \
                    self.assertRaisesRegex(ROOT.Refused, "rule-only"):
                self.call(op, "shop", "OTHER_KEY", "random", data=b"v")
        os.chmod(self.tmp + "/var/www/shop/shared/.env", 0o644)
        with self.assertRaisesRegex(ROOT.Refused, "not root's file of mode 0600"):
            self.call("env-add", "shop", "THIRD_KEY", "random", data=b"v")


class AppRunner(AppShape):
    """New-projects plan N6: runner-new makes the app's runner as its deploy user from the door's stdin: root checks the
    archive's SHA-256, the deploy user unpacks root's stream and registers with the token in its environment only,
    root writes the unit, and a step that fails after the registration takes it back with the remove token."""
    TOKEN, REMOVE = "AAAAREGISTRATIONTOKEN0001", "BBBBREMOVETOKEN000000002"
    ARCHIVE = b"the runner's archive"

    def setUp(self):
        super().setUp()
        self.call("app-new", "shop", "8080", "/api/health")
        os.makedirs(self.tmp + "/home/shop-deploy")
        record = __import__("collections").namedtuple("pw", "pw_uid pw_gid pw_shell")
        self.ran, self.icu = [], "libicuuc.so.74 (libc6,AArch64) => /lib/libicuuc.so.74\n"

        def run(argv, stdin=None, timeout=900, env=None):
            self.ran.append((argv, env, stdin))
            if argv[0] == "ldconfig":
                return 0, self.icu
            if self.failing and self.failing in argv:
                return 1, f"{self.failing} failed, said {self.TOKEN}"
            if argv[:4] == ["runuser", "-u", "shop-deploy", "--"] and argv[4] == "tar":
                os.makedirs(self.tmp + "/home/shop-deploy/actions-runner/bin", exist_ok=True)
            return 0, ""

        def fetch(url, path, limit):
            self.fetched = url
            with open(path, "wb") as f:
                f.write(self.ARCHIVE)
            return hashlib.sha256(self.ARCHIVE).hexdigest()
        for p in (patch.object(ROOT, "run", run), patch.object(ROOT, "fetch", fetch),
                  patch.object(ROOT, "machine", lambda: "aarch64"),
                  patch.object(ROOT.pwd, "getpwnam", lambda name: record(os.getuid(), os.getgid(), "/bin/bash"))):
            p.start()
            self.addCleanup(p.stop)

    def given(self, **more):
        sums = {"x64": "1" * 64, "arm64": hashlib.sha256(self.ARCHIVE).hexdigest()}
        return json.dumps(dict({"token": self.TOKEN, "remove": self.REMOVE, "url": "https://github.com/one-org/shop",
                                "name": "web-1-shop", "version": "2.329.0", "sha256": sums}, **more)).encode()

    def runner(self, data=None):
        return self.call("runner-new", "shop", data=self.given() if data is None else data)

    def users(self):
        return [(argv[4:], env) for argv, env, _ in self.ran if argv[:4] == ["runuser", "-u", "shop-deploy", "--"]]

    def test_runner_new_makes_the_runner_as_its_deploy_user(self):
        said = self.runner()
        self.assertEqual(said, "web-1-shop runs as shop-deploy (actions.runner.one-org-shop.web-1-shop.service), with "
                               "the labels self-hosted, linux, arm64 and shop")
        self.assertEqual(self.fetched, "https://github.com/actions/runner/releases/download/v2.329.0/"
                                       "actions-runner-linux-arm64-2.329.0.tar.gz")
        folder = "/home/shop-deploy/actions-runner"
        steps = self.users()
        self.assertEqual(steps[0][0], ["tar", "-xzf", "-", "-C", folder, "--no-same-owner"])
        tar = next(stdin for argv, env, stdin in self.ran if argv[4:5] == ["tar"])
        self.assertTrue(hasattr(tar, "fileno"))                         # root's own stream, never a path of the user's
        self.assertEqual(steps[1], ([f"{folder}/config.sh", "--unattended", "--url", "https://github.com/one-org/shop",
                                     "--name", "web-1-shop", "--labels", "shop", "--work", "_work"],
                                    {"ACTIONS_RUNNER_INPUT_TOKEN": self.TOKEN}))
        self.assertFalse([argv for argv, _, _ in self.ran if any(self.TOKEN in a or self.REMOVE in a for a in argv)])
        unit = self.get("/etc/systemd/system/actions.runner.one-org-shop.web-1-shop.service")
        self.assertIn(f"ExecStart={folder}/runsvc.sh\nUser=shop-deploy\nWorkingDirectory={folder}\n", unit)
        self.assertNotIn("NoNewPrivileges", unit)                       # the deploy job's sudo needs it off
        self.assertIn((["systemctl", "--no-pager", "--no-ask-password", "enable", "--now",
                        "actions.runner.one-org-shop.web-1-shop.service"], None, None), self.ran)
        self.assertEqual(os.stat(self.tmp + folder).st_mode & 0o777, 0o750)
        for here, _, names in os.walk(self.tmp):
            for name in (n for n in names if not os.path.islink(os.path.join(here, n))):
                with open(os.path.join(here, name), "rb") as f:
                    self.assertNotIn(self.TOKEN.encode(), f.read(), os.path.join(here, name))
        with self.assertRaisesRegex(ROOT.Refused, "exists already: runner-new makes the app's one runner"):
            self.runner()

    def test_a_runner_that_stops_after_its_registration_takes_it_back(self):
        self.failing = "enable"
        with self.assertRaisesRegex(ROOT.Failed, "took back what it made") as failed:
            self.runner()
        self.assertNotIn(self.TOKEN, str(failed.exception))
        folder = "/home/shop-deploy/actions-runner"
        self.assertIn(([f"{folder}/config.sh", "remove"], {"ACTIONS_RUNNER_INPUT_TOKEN": self.REMOVE}), self.users())
        self.assertFalse(os.path.lexists(self.tmp + folder))
        unit = "/etc/systemd/system/actions.runner.one-org-shop.web-1-shop.service"
        self.assertFalse(os.path.lexists(self.tmp + unit))
        self.failing, self.ran = None, []
        self.assertIn("web-1-shop runs as shop-deploy", self.runner())         # the retry runs

    def test_runner_new_refuses_a_wrong_archive_its_input_and_a_host_without_icu(self):
        sums = {"x64": "1" * 64, "arm64": "2" * 64}
        with self.assertRaisesRegex(ROOT.Refused, "does not have the SHA-256 that GitHub publishes"):
            self.runner(self.given(sha256=sums))
        self.assertFalse(os.path.lexists(self.tmp + "/home/shop-deploy/actions-runner"))
        self.assertFalse(self.users())
        for data in (b"", b"{}", self.given(token="lower-case"), self.given(url="https://evil.example/x"),
                     self.given(name="web.1"), self.given(extra=1)):
            with self.subTest(data=data), self.assertRaisesRegex(ROOT.Refused, "stdin"):
                self.runner(data)
        self.icu = ""
        with self.assertRaisesRegex(ROOT.Refused, "needs ICU"):
            self.runner()
        with patch.object(ROOT, "mode", lambda: "rule-only"), self.assertRaisesRegex(ROOT.Refused, "rule-only"):
            self.runner()
        with self.assertRaisesRegex(ROOT.Refused, "blog is no app of this host"):
            self.call("runner-new", "blog", data=self.given())


VHOST = """server {
    listen 127.0.0.1:8081;
    listen [::1]:8081;
    server_name shop.example.com www.shop.example.com;
    access_log /var/log/nginx/shop.access.log;
    include /etc/nginx/snippets/security-headers.conf;

    location /assets/ {
        alias /var/www/shop/current/public/assets/;
    }
    location / {
        include /etc/nginx/proxy_params;
        proxy_pass http://127.0.0.1:8080;   # the app's own port
    }
}
"""


class AppVhost(AppShape):
    """New-projects plan N7: vhost-new installs the app's vhost on a loopback port of its own once code has read it;
    nginx -t must pass with no new warning; the folders' immutable bit goes back as it was, and a step that fails
    leaves nginx as it was."""

    def setUp(self):
        super().setUp()
        self.call("app-new", "shop", "8080", "/api/health")
        for folder in ("/etc/nginx/sites-available", "/etc/nginx/sites-enabled", "/etc/nginx/conf.d"):
            os.makedirs(self.tmp + folder, exist_ok=True)
        self.ran, self.nginx, self.sticky = [], [(0, "syntax is ok")], {"/etc/nginx/sites-enabled"}

        def run(argv, stdin=None, timeout=900, env=None):
            self.ran.append(argv)
            if argv[0] == "ss":
                return 0, self.listening
            if argv[0] == "lsattr":
                held = argv[-1][len(self.tmp):] in self.sticky
                return 0, ("----i---------e------- " if held else "--------------e------- ") + argv[-1]
            if argv[0] == "chattr":
                (self.sticky.add if argv[1] == "+i" else self.sticky.discard)(argv[2][len(self.tmp):])
                return 0, ""
            if argv[0] == "nginx":
                return self.nginx.pop(0) if len(self.nginx) > 1 else self.nginx[0]
            if self.failing and self.failing in argv:
                return 1, f"{self.failing} failed"
            return 0, ""
        p = patch.object(ROOT, "run", run)
        p.start()
        self.addCleanup(p.stop)

    def vhost(self, text=VHOST):
        data = text.encode()
        return self.call("vhost-new", "shop", data=data, sha256=hashlib.sha256(data).hexdigest())

    def test_vhost_new_installs_links_and_reloads(self):
        said = self.vhost()
        self.assertIn("serves shop.example.com, www.shop.example.com on 127.0.0.1:8081 and [::1]:8081", said)
        self.assertEqual(self.get("/etc/nginx/sites-available/shop"), VHOST)
        self.assertEqual(os.readlink(self.tmp + "/etc/nginx/sites-enabled/shop"), "/etc/nginx/sites-available/shop")
        self.assertEqual(json.loads(self.get("/etc/ops-root/apps/shop.json"))["vhost_port"], 8081)
        self.assertIn(["systemctl", "--no-pager", "--no-ask-password", "reload", "nginx"], self.ran)
        chattr = [a[1:] for a in self.ran if a[0] == "chattr"]
        self.assertEqual(chattr, [["-i", self.tmp + "/etc/nginx/sites-enabled"],
                                  ["+i", self.tmp + "/etc/nginx/sites-enabled"]])
        self.assertEqual(self.sticky, {"/etc/nginx/sites-enabled"})
        with self.assertRaisesRegex(ROOT.Refused, "has a vhost already"):
            self.vhost()
        self.assertIn(8081, ROOT.ports_taken())

    def test_vhost_new_refuses_what_code_reads_in_the_vhost(self):
        cases = {
            "port 80": ("127.0.0.1:8081;\n    listen [::1]:8081", "127.0.0.1:80;\n    listen [::1]:80", "never 80"),
            "a public address": ("listen [::1]:8081;", "listen 0.0.0.0:8081;", "listens only on 127.0.0.1"),
            "every address": ("listen [::1]:8081;", "listen 8081;", "listens only on 127.0.0.1"),
            "a second port": ("listen [::1]:8081;", "listen [::1]:8082;", "one port of its own"),
            "the app's own port": ("127.0.0.1:8081;\n    listen [::1]:8081", "127.0.0.1:8080;\n    listen [::1]:8080",
                                   "never 80, 443 or the app's own port"),
            "a listen with more": ("listen [::1]:8081;", "listen [::1]:8081 default_server;", "with nothing more"),
            "another service": ("proxy_pass http://127.0.0.1:8080;", "proxy_pass http://127.0.0.1:2375;",
                                "only to the app's own port"),
            "a target in a variable": ("proxy_pass http://127.0.0.1:8080;", "proxy_pass http://$host:8080;",
                                       "with no variable"),
            "files of the system": ("alias /var/www/shop/current/public/assets/;", "alias /etc/;",
                                    "serves files from /var/www/shop only"),
            "files of another app": ("alias /var/www/shop/current/public/assets/;",
                                     "alias /var/www/shop/../blog/shared/;", "serves files from /var/www/shop only"),
            "an include of the app's own": ("include /etc/nginx/snippets/security-headers.conf;",
                                            "include /var/www/shop/current/nginx.conf;", "include takes nginx's own"),
            "a log where root writes": ("access_log /var/log/nginx/shop.access.log;", "access_log /etc/cron.d/x;",
                                        "writes to /var/log/nginx only"),
            "a backend of another kind": ("proxy_pass http://127.0.0.1:8080;", "fastcgi_pass unix:/run/php.sock;",
                                          "fastcgi_pass is not a directive"),
            "a block beside the server": ("server {", "upstream evil { server 127.0.0.1:22; }\nserver {",
                                          "server blocks only"),
            "a file that root opens": ("access_log /var/log/nginx/shop.access.log;",
                                       "ssl_certificate_key /etc/shadow;", "opens as root"),
            "no hostname": ("server_name shop.example.com www.shop.example.com;", "server_name _;",
                            "server_name names the app's hostnames"),
            "a block that does not close": ("    }\n}\n", "    }\n", "does not parse"),
        }
        for why, (old, new, words) in cases.items():
            with self.subTest(why):
                self.assertIn(old, VHOST)
                with self.assertRaises(ROOT.Refused) as refused:
                    self.vhost(VHOST.replace(old, new, 1))
                self.assertIn(words, str(refused.exception))
        self.assertFalse(os.path.lexists(self.tmp + "/etc/nginx/sites-available/shop"))
        self.assertFalse([a for a in self.ran if a[0] == "chattr"])

    def test_vhost_new_refuses_a_taken_port_or_name(self):
        self.listening = "LISTEN 0 511 127.0.0.1:8081 0.0.0.0:*\n"
        with self.assertRaisesRegex(ROOT.Refused, "something listens on port 8081"):
            self.vhost()
        self.listening = ""
        self.put("/etc/nginx/sites-enabled/blog", "server {\n listen 80;\n server_name WWW.shop.example.com;\n}\n")
        with self.assertRaisesRegex(ROOT.Refused, "another vhost serves www.shop.example.com already"):
            self.vhost()
        with patch.object(ROOT, "mode", lambda: "rule-only"), self.assertRaisesRegex(ROOT.Refused, "rule-only"):
            self.vhost()

    def test_a_vhost_that_nginx_refuses_leaves_nginx_and_the_bit_as_they_were(self):
        for why, answers, words in (
                ("nginx -t fails", [(0, "ok"), (1, "nginx: [emerg] unknown directive")], "did not pass"),
                ("a new warning", [(0, "ok"), (0, 'nginx: [warn] conflicting server name "x"')], "no new warning")):
            with self.subTest(why):
                self.nginx = answers
                with self.assertRaisesRegex(ROOT.Refused, words):
                    self.vhost()
                self.assertFalse(os.path.lexists(self.tmp + "/etc/nginx/sites-available/shop"))
                self.assertFalse(os.path.lexists(self.tmp + "/etc/nginx/sites-enabled/shop"))
                self.assertNotIn("vhost_port", json.loads(self.get("/etc/ops-root/apps/shop.json")))
                self.assertEqual(self.sticky, {"/etc/nginx/sites-enabled"})
        self.nginx = [(0, 'nginx: [warn] an old warning'), (0, 'nginx: [warn] an old warning')]
        self.failing = "reload"
        with self.assertRaisesRegex(ROOT.Failed, "took the vhost back"):
            self.vhost()
        self.assertFalse(os.path.lexists(self.tmp + "/etc/nginx/sites-enabled/shop"))
        self.assertNotIn("vhost_port", json.loads(self.get("/etc/ops-root/apps/shop.json")))
        self.assertEqual(self.sticky, {"/etc/nginx/sites-enabled"})
        self.failing, self.nginx = None, [(0, 'nginx: [warn] an old warning')]
        self.assertIn("serves shop.example.com", self.vhost())        # an old warning is not this vhost's


def load_release_helper():
    from importlib.machinery import SourceFileLoader
    from importlib.util import module_from_spec, spec_from_loader
    loader = SourceFileLoader("app_release", os.path.join(os.path.dirname(os.path.abspath(__file__)), "host",
                                                          "app-release"))
    module = module_from_spec(spec_from_loader("app_release", loader))
    loader.exec_module(module)
    return module


REL = load_release_helper()


class ReleaseHelper(unittest.TestCase):
    """New-projects plan N4: the product's release helper checks an artifact before it reads it, unpacks it as the
    deploy user with no link and no special file, makes a root-owned read-only release, switches `current` in one
    rename, checks the health path with the release's sha, rolls back on a failure, and keeps five releases."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="app-release-"))
        self.addCleanup(self.clean)
        for folder in ("/var/www/shop/releases", "/var/www/shop/artifacts/incoming", "/var/www/shop/shared",
                       "/etc/ops-root/apps", "/run", "/home/shop-deploy/_work/out"):
            os.makedirs(self.tmp + folder, exist_ok=True)
        for name in ("release-blocklist", "security-blocked-releases.tsv"):
            open(self.tmp + "/var/www/shop/" + name, "w").close()
        with open(self.tmp + "/etc/ops-root/apps/shop.json", "w") as f:
            json.dump({"app": "shop", "port": 8080, "health": "/api/health"}, f)
        record = __import__("collections").namedtuple("pw", "pw_dir pw_uid pw_gid")
        self.restarts, self.healthy = [], lambda sha: True

        def run(argv, stdin=None, timeout=300):
            if argv[:2] == ["systemctl", "restart"]:
                self.restarts.append(argv[2])
                return 0, ""
            return 1, "not stubbed"
        for p in (patch.object(REL, "ROOT", self.tmp), patch.object(REL, "run", run),
                  patch.object(REL, "unpack_argv", lambda user: [__import__("sys").executable, "-I", "-c", REL.UNPACK]),
                  patch.object(REL.pwd, "getpwnam", lambda name: record("/home/shop-deploy", os.getuid(), os.getgid())),
                  patch.object(REL, "healthy", lambda port, health, sha, wait=90: self.healthy(sha))):
            p.start()
            self.addCleanup(p.stop)

    def clean(self):
        for here, names, _ in os.walk(self.tmp):
            for name in names:
                with contextlib.suppress(OSError):
                    os.chmod(os.path.join(here, name), 0o755)
        shutil.rmtree(self.tmp, True)

    def artifact(self, files, sha, link=None, wrong=False):
        """(artifact, checksum) paths, as the deploy job leaves them in the runner's workspace."""
        import tarfile
        path = f"/home/shop-deploy/_work/out/{sha[:7]}.tar.gz"
        with tarfile.open(self.tmp + path, "w:gz") as t:
            for name, (body, mode) in files.items():
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(body), mode
                t.addfile(info, io.BytesIO(body))
            if link:
                info = tarfile.TarInfo(link)
                info.type, info.linkname = tarfile.SYMTYPE, "/etc/shadow"
                t.addfile(info)
        with open(self.tmp + path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        with open(self.tmp + path + ".sha256", "w") as f:
            f.write(("0" * 64 if wrong else digest) + "  app.tar.gz\n")
        return path, path + ".sha256"

    def deploy(self, sha, **more):
        files = more.pop("files", {"server.js": (b"console.log(1)\n", 0o644), "bin/start": (b"#!/bin/sh\n", 0o755)})
        return REL.deploy("shop", *self.artifact(files, sha, **more), sha)

    def test_a_release_is_root_owned_read_only_and_current(self):
        sha = "a" * 40
        self.assertEqual(self.deploy(sha), f"shop runs {sha}")
        release = self.tmp + f"/var/www/shop/releases/{sha}"
        self.assertEqual(os.stat(release).st_mode & 0o777, 0o555)
        self.assertEqual(os.stat(release + "/server.js").st_mode & 0o777, 0o444)
        self.assertEqual(os.stat(release + "/bin/start").st_mode & 0o777, 0o555)
        with open(release + "/.release.env") as f:
            self.assertEqual(f.read(), f"APP_RELEASE_SHA={sha}\n")
        self.assertEqual(os.readlink(self.tmp + "/var/www/shop/current"), f"/var/www/shop/releases/{sha}")
        self.assertFalse(os.path.lexists(self.tmp + "/var/www/shop/previous"))
        self.assertTrue(os.path.isfile(self.tmp + f"/var/www/shop/artifacts/{sha}.tar"))
        self.assertEqual(os.listdir(self.tmp + "/var/www/shop/artifacts/incoming"), [])
        self.assertEqual(self.restarts, ["shop.service"])

    def test_a_failed_health_check_puts_the_previous_release_back(self):
        first, second = "a" * 40, "b" * 40
        self.deploy(first)
        self.healthy = lambda sha: sha == first
        with self.assertRaisesRegex(REL.Failed, f"{first} runs again"):
            self.deploy(second)
        self.assertEqual(os.readlink(self.tmp + "/var/www/shop/current"), f"/var/www/shop/releases/{first}")
        self.healthy = lambda sha: True
        self.deploy(second)
        self.assertEqual(os.readlink(self.tmp + "/var/www/shop/previous"), f"/var/www/shop/releases/{first}")
        self.assertEqual(REL.rollback("shop"), f"shop runs {first} again")
        self.assertEqual(os.readlink(self.tmp + "/var/www/shop/current"), f"/var/www/shop/releases/{first}")
        self.assertEqual(os.readlink(self.tmp + "/var/www/shop/previous"), f"/var/www/shop/releases/{second}")
        self.assertEqual(self.deploy(second), f"shop runs {second}")           # the return to the newest release

    def test_a_failed_deploy_puts_both_links_back_so_a_rollback_leaves_the_release_that_runs(self):
        first, second, third = "a" * 40, "b" * 40, "c" * 40
        self.healthy = lambda sha: sha != third
        self.deploy(first)
        with self.assertRaisesRegex(REL.Failed, f"{first} runs again"):
            self.deploy(third)
        self.assertFalse(os.path.lexists(self.tmp + "/var/www/shop/previous"))     # none before, so none after
        self.deploy(second)
        with self.assertRaisesRegex(REL.Failed, f"{second} runs again"):
            self.deploy(third)
        self.assertEqual(os.readlink(self.tmp + "/var/www/shop/current"), f"/var/www/shop/releases/{second}")
        self.assertEqual(os.readlink(self.tmp + "/var/www/shop/previous"), f"/var/www/shop/releases/{first}")
        self.assertEqual(REL.rollback("shop"), f"shop runs {first} again")

    def test_what_it_refuses(self):
        sha = "c" * 40
        with open(self.tmp + "/var/www/shop/release-blocklist", "w") as f:
            f.write(f"# a known bad release\n{sha}\n")
        with self.assertRaisesRegex(REL.Refused, "on a blocklist"):
            self.deploy(sha)
        sha = "d" * 40
        with self.assertRaisesRegex(REL.Refused, "SHA-256 is not the one"):
            self.deploy(sha, wrong=True)
        self.assertEqual(os.listdir(self.tmp + "/var/www/shop/artifacts/incoming"), [])
        with self.assertRaisesRegex(REL.Refused, "link or a special file"):
            self.deploy(sha, link="evil")
        self.assertFalse(os.path.exists(self.tmp + f"/var/www/shop/releases/{sha}"))
        self.assertFalse(os.path.exists(self.tmp + f"/var/www/shop/releases/{sha}.new"))
        self.assertEqual(os.listdir(self.tmp + "/var/www/shop/artifacts/incoming"), [])
        with self.assertRaisesRegex(REL.Refused, "outside|absolute|link or a special"):
            self.deploy(sha, files={"../escape": (b"x", 0o644)})
        with self.assertRaisesRegex(REL.Refused, "own home"):
            REL.deploy("shop", "/etc/passwd", "/etc/passwd", sha)
        with self.assertRaisesRegex(REL.Refused, "own home"):
            REL.deploy("shop", "/home/shop-deploy/_work/../../../etc/passwd", "/etc/passwd", sha)
        with self.assertRaisesRegex(REL.Refused, "40 lowercase hex"):
            REL.deploy("shop", "/x", "/y", "HEAD")
        os.environ["SUDO_USER"] = "shop-deploy"
        self.addCleanup(os.environ.pop, "SUDO_USER", None)
        with patch("sys.stdout", io.StringIO()) as out:
            self.assertEqual(REL.main(["/usr/local/sbin/shop-deploy", "rollback"]), 3)
        self.assertIn("rollback is root's", out.getvalue())
        with patch("sys.stdout", io.StringIO()) as out:
            self.assertEqual(REL.main(["/usr/local/sbin/app-release", "deploy", "a", "b", sha]), 3)

    def test_a_prune_keeps_five_releases_and_the_two_that_run(self):
        shas = [f"{n:x}" * 40 for n in range(1, 8)]
        for n, sha in enumerate(shas):
            self.deploy(sha)
            os.utime(self.tmp + f"/var/www/shop/releases/{sha}", (1000 + n, 1000 + n))
        left = sorted(os.listdir(self.tmp + "/var/www/shop/releases"))
        self.assertEqual(len(left), 5)
        self.assertIn(shas[-1], left)
        self.assertIn(shas[-2], left)

