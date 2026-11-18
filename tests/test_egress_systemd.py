"""The outgoing gate's root step and units under a real systemd (vault.py, "the outgoing gate";
agent-outgoing-connections-proposal.md, section 10). It runs only when the variable FLEET_EGRESS_SYSTEMD=1 asks for it:
it builds an image and starts a privileged container whose first process is systemd, as key-swap-probes/systemd/ did.

    FLEET_EGRESS_SYSTEMD=1 python3 -m unittest test_egress_systemd

Inside: Ubuntu 24.04 with systemd 255, systemd-resolved, D-Bus and nftables; an installed vault program and a broker's
configuration (no broker runs: the gate does not need one); the service user fleet and an agent user. The real root
step, `vault.py configure --egress on`, then:

  the gate's unit runs the installed program through its launcher, and the kernel rules are loaded with the agent;
  the path unit fills the agents' set again for a new agent user, and takes an agent user out of the group docker;
  the closures: no agent user connects to systemd-resolved's Varlink socket or asks its D-Bus name, another user
  does, and the same after a restart of systemd-resolved (its drop-in);
  an agent's connection to another user's local service goes through the gate;
  a new program takes over with no restart (MAINPID); a program that does not start at a cold start gives way to
  the safe copy, and so does one that ends three times with no stop asked for (the unit's ExecStopPost counts);
  the table stays while the gate does not run, after a stop and while a start fails because another program holds
  its port: the agent's connection fails at once, and works again once the gate serves;
  a path unit for each file: a new agent user, a change of the group docker, the browsers' ports and a sub-uid range
  each reach the table;
  a restart and a stop of nftables.service, which flush every table, are followed by the gate's table again;
  a second run changes nothing, and --egress off takes the table, the units, the drop-ins and the closures away.

Every name and address is made up. The image and the container are removed at the end."""
import json
import os
import shutil
import subprocess
import sys
import unittest

from leftovers import ROOT, TEST_DIR

KIT = ROOT
# this file as the container sees it: KIT is /kit there, and this file is in tests/ of a published copy
INSIDE = os.path.normpath(os.path.join("/kit", os.path.relpath(TEST_DIR, ROOT), "test_egress_systemd.py"))
IMAGE = "founderizer-egress-systemd-test"
DOCKERFILE = """FROM ubuntu:24.04
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends systemd \\
    systemd-sysv systemd-resolved dbus python3 nftables curl iproute2 procps acl ca-certificates >/dev/null && \\
    rm -rf /var/lib/apt/lists/* && systemctl mask getty@tty1.service >/dev/null 2>&1 || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
"""


def docker():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(os.environ.get("FLEET_EGRESS_SYSTEMD") == "1", "set FLEET_EGRESS_SYSTEMD=1 to run it: it builds "
                     "an image and starts a privileged container")
class Systemd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not docker():
            raise unittest.SkipTest("Docker does not answer on this machine")
        built = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"], input=DOCKERFILE, capture_output=True,
                               text=True, timeout=900)
        if built.returncode != 0:
            raise AssertionError("the image did not build:\n" + built.stderr[-3000:])
        name = f"egress-systemd-{os.getpid()}"
        started = subprocess.run(["docker", "run", "-d", "--name", name, "--privileged", "--cgroupns=host",
                                  "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-v", f"{KIT}:/kit:ro",
                                  "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024", IMAGE],
                                 capture_output=True, text=True, timeout=120)
        if started.returncode != 0:
            raise AssertionError("the container did not start:\n" + started.stderr[-3000:])
        try:
            done = subprocess.run(["docker", "exec", name, "python3", INSIDE, "--inside"],
                                  capture_output=True, text=True, timeout=1200)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=120)
            subprocess.run(["docker", "rmi", IMAGE], capture_output=True, timeout=120)
        cls.log = done.stdout[-8000:] + done.stderr[-8000:]
        lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
        if not lines:
            raise AssertionError("the container's run did not end with its result:\n" + cls.log)
        cls.got = json.loads(lines[-1][7:])

    def test_the_root_step_starts_the_gate_and_loads_the_table(self):
        self.assertEqual((self.got["configure ok"], self.got["configure egress"], self.got["configure table"]),
                         (True, True, 1), self.log)
        self.assertEqual(self.got["gate active"], "active")
        self.assertIn("/usr/local/lib/fleet-vault/vault.py egress", self.got["gate runs"])
        self.assertIn("2001", self.got["agents set"])
        self.assertEqual(self.got["path unit"], "active\nactive\nactive\nactive")

    def test_the_path_unit_follows_the_groups(self):
        self.assertIn("2002", self.got["agents set after a new agent user"], self.log)
        self.assertNotIn("docker", self.got["alpha's groups after docker"])
        self.assertIn("2001 . 9301", self.got["browser set after the ports"])
        self.assertIn("700000-700009", self.got["subagents after usermod"])

    def test_the_closures_hold_also_after_a_restart_of_resolved(self):
        if self.got["acl support"] != "yes":
            # A kernel whose tmpfs keeps no ACL (Docker Desktop's): the step says which closure it could not make,
            # and the rest of the gate goes on. A real server's closures are proved on it (A1, A2, and the live proof)
            self.assertTrue(any("resolved" in u for u in self.got["configure answer"].get("unclosed", [])), self.log)
            self.skipTest("this kernel's /run keeps no ACL")
        for when in ("", " after a restart"):
            self.assertIn("Permission denied", self.got["alpha varlink" + when], self.log)
            self.assertNotIn("Permission denied", self.got["other varlink" + when])
        self.assertIn("Access denied", self.got["alpha dbus"])
        self.assertIn("group:fleet-agents:r--", self.got["socket acl"])

    def test_an_agents_connection_goes_through_the_gate(self):
        self.assertEqual(self.got["alpha reaches a local service"], "the page of other", self.log)
        self.assertIn(["127.0.0.1", 9000], self.got["rows"])

    def test_a_new_program_takes_over_and_the_safe_copy_serves_a_cold_start(self):
        self.assertNotEqual(self.got["mainpid before"], self.got["mainpid after"], self.log)
        self.assertEqual(self.got["crashes"].split(), ["3", self.got["crashes"].split()[1]])
        self.assertIn("/usr/local/lib/founderizer-egress/vault.py egress", self.got["gate runs after three crashes"])
        self.assertEqual(self.got["restarts after the hand-over"], "0")
        self.assertIn("/usr/local/lib/founderizer-egress/vault.py egress", self.got["gate runs after a cold start"])
        self.assertEqual(self.got["page after a cold start"], "the page of other")

    def test_the_table_stays_while_the_gate_does_not_run(self):
        self.assertEqual(self.got["loaded file"], "1", self.log)
        for when in ("after a stop", "with its port taken", "after the port is free"):
            self.assertIn("table inet founderizer_egress", self.got[f"tables {when}"], when)
            self.assertTrue(self.got[f"tables {when}"].endswith("\n1"), when)
        self.assertNotEqual(self.got["gate with its port taken"], "active")
        self.assertEqual((self.got["alpha after a stop"], self.got["alpha with no gate"]), ("000", "000"))
        self.assertEqual(self.got["gate after the port is free"], "active")
        self.assertEqual(self.got["alpha after the port is free"], "the page of other")

    def test_the_table_comes_back_after_nftables_flushes_the_kernels_rules(self):
        self.assertEqual(self.got["nftables drop-in"], "3", self.log)
        for when in ("a restart", "a stop"):
            self.assertIn("table inet founderizer_egress", self.got[f"tables after {when} of nftables"], when)

    def test_a_second_run_changes_nothing_and_off_takes_everything_away(self):
        self.assertEqual((self.got["again state"], self.got["again changed"]), ("there", []), self.log)
        self.assertEqual(self.got["off ok"], True)
        self.assertEqual(self.got["table after off"], "")
        if self.got["acl support"] == "yes":
            self.assertNotIn("fleet-agents", self.got["socket acl after off"])
        self.assertIn(self.got["gate after off"], ("inactive", "unknown", ""))


def sh(script, timeout=120):
    done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=timeout)
    return (done.stdout + done.stderr).strip()


def as_user(user, script):
    return sh(f"setpriv --reuid={user} --regid={user} --init-groups -- bash -c {json.dumps(script)}")


def configure(*words):
    text = sh(f"python3 -I /usr/local/lib/fleet-vault/vault.py configure {' '.join(words)}", timeout=600)
    for line in reversed(text.splitlines()):            # its one JSON line; the log's lines are beside it
        try:
            answer = json.loads(line)
        except ValueError:
            continue
        if isinstance(answer, dict):
            return answer
    return {"ok": False, "raw": text[-1500:]}


def inside():
    got = {}
    sh("for i in $(seq 1 60); do systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; "
       "sleep 1; done")
    sh("""set -e
groupadd -f fleet-agents
useradd -m -u 1100 fleet
useradd -m -u 2001 -G fleet-agents fleet-alpha
useradd -m -u 2500 other
install -d -o root -g root -m 755 /usr/local/lib/fleet-vault /etc/fleet-vault
install -o root -g root -m 644 /kit/vault.py /usr/local/lib/fleet-vault/vault.py
printf '%s\\n' '{"hub": "http://198.51.100.9:8765", "worker_group": "fleet-agents", "socket": "/run/fleet-vault/vault.sock", "store": "/var/lib/fleet-vault/store.age", "store_key": "/var/lib/fleet-vault/store.key", "age_key": "/var/lib/fleet-vault/age.key", "age": "/usr/bin/age"}' > /etc/fleet-vault/vault.json
chmod 644 /etc/fleet-vault/vault.json
systemctl enable --now systemd-resolved >/dev/null 2>&1 || true
mkdir -p /srv/o && echo 'the page of other' > /srv/o/index.html
""")
    sh("systemd-run --uid=2500 --unit=other-site python3 -m http.server 9000 --bind 127.0.0.1 --directory /srv/o")
    got["acl support"] = sh("touch /run/acl-probe && setfacl -m g:fleet-agents:r /run/acl-probe 2>/dev/null && echo yes "
                            "|| echo no; rm -f /run/acl-probe")
    answer = configure("--egress", "on")
    got["configure ok"], got["configure egress"] = answer.get("ok"), answer.get("egress")
    got["configure table"], got["configure answer"] = answer.get("egress_table"), answer
    got["gate active"] = sh("systemctl is-active fleet-egress")
    pid = sh("systemctl show -p MainPID --value fleet-egress")
    got["gate runs"] = sh(f"ps -o args= -p {pid}")
    got["agents set"] = sh("nft list set inet founderizer_egress agents")
    got["path unit"] = sh("systemctl is-active fleet-egress-rules.path fleet-egress-subuid.path "
                          "fleet-egress-browser.path fleet-egress-rules.timer")
    got["loaded file"] = sh("cat /run/founderizer-egress-table")
    sh("useradd -m -u 2002 -G fleet-agents fleet-beta; sleep 3")
    got["agents set after a new agent user"] = sh("nft list set inet founderizer_egress agents")
    sh("groupadd docker; usermod -aG docker fleet-alpha; sleep 4")
    got["alpha's groups after docker"] = sh("id -nG fleet-alpha")
    sh("mkdir -p /etc/fleet-browser && printf 'fleet-alpha 9301 5911\\n' > /etc/fleet-browser/ports; sleep 3")
    got["browser set after the ports"] = sh("nft list set inet founderizer_egress browser")
    sh("usermod --add-subuids 700000-700009 fleet-alpha; sleep 3")
    got["subagents after usermod"] = sh("nft list set inet founderizer_egress subagents")
    varlink = "varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname " \
              "'{\"name\":\"localhost\"}'"
    got["alpha varlink"], got["other varlink"] = as_user("fleet-alpha", varlink), as_user("other", varlink)
    got["alpha dbus"] = as_user("fleet-alpha", "busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 "
                                               "org.freedesktop.resolve1.Manager ResolveHostname isit 0 localhost 0 0")
    got["socket acl"] = sh("getfacl -p /run/systemd/resolve/io.systemd.Resolve")
    sh("systemctl restart systemd-resolved; sleep 2")
    got["alpha varlink after a restart"] = as_user("fleet-alpha", varlink)
    got["other varlink after a restart"] = as_user("other", varlink)
    got["alpha reaches a local service"] = as_user("fleet-alpha", "curl -s -m 5 http://127.0.0.1:9000/")
    counts = as_user("fleet", "python3 -c \"import json, socket; s = socket.socket(socket.AF_UNIX); s.connect("
                              "'/run/founderizer-egress/control.sock'); s.sendall(b'{\\\"op\\\": \\\"counts\\\"}\\n'); "
                              "print(s.makefile().readline())\"")
    try:
        got["rows"] = sorted({(r["host"], r["port"]) for r in json.loads(counts)["rows"]})
    except (ValueError, KeyError):
        got["rows"] = counts[-500:]
    # a new program: the service user's word starts the hand-over, and systemd takes the new main process
    got["mainpid before"] = sh("systemctl show -p MainPID --value fleet-egress")
    sh("echo '# a new release' >> /usr/local/lib/fleet-vault/vault.py")
    as_user("fleet", "python3 -c \"import socket; s = socket.socket(socket.AF_UNIX); s.connect("
                     "'/run/founderizer-egress/control.sock'); s.sendall(b'{\\\"op\\\": \\\"status\\\"}\\n'); "
                     "s.makefile().readline()\"")
    sh("for i in $(seq 1 60); do [ \"$(systemctl show -p MainPID --value fleet-egress)\" != "
       f"\"{got['mainpid before']}\" ] && break; sleep 0.5; done")
    got["mainpid after"] = sh("systemctl show -p MainPID --value fleet-egress")
    got["restarts after the hand-over"] = sh("systemctl show -p NRestarts --value fleet-egress")
    # a cold start with an installed program that does not start: the launcher's safe copy
    sh("echo 'this is no python' >> /usr/local/lib/fleet-vault/vault.py; systemctl restart fleet-egress; sleep 4")
    pid = sh("systemctl show -p MainPID --value fleet-egress")
    got["gate runs after a cold start"] = sh(f"ps -o args= -p {pid}")
    got["page after a cold start"] = as_user("fleet-alpha", "curl -s -m 5 http://127.0.0.1:9000/")
    # a program that passes its check and ends at once: three ends that nobody asked for, then the safe copy serves
    sh("printf 'import sys\\nsys.exit(0 if \"--check\" in sys.argv else 1)\\n' > /usr/local/lib/fleet-vault/vault.py")
    sh("systemctl restart fleet-egress; sleep 14")
    got["crashes"] = sh("cut -d' ' -f1 /run/founderizer-egress/crashes | sort | uniq -c")
    pid = sh("systemctl show -p MainPID --value fleet-egress")
    got["gate runs after three crashes"] = sh(f"ps -o args= -p {pid}")
    sh("install -o root -g root -m 644 /kit/vault.py /usr/local/lib/fleet-vault/vault.py")
    # the table stays while the gate does not run: a stop, then a start that fails on a port that another program
    # holds
    tables = "nft list tables; cat /run/founderizer-egress-table 2>/dev/null || echo 'no file'"
    sh("systemctl stop fleet-egress")
    got["tables after a stop"] = sh(tables)
    got["alpha after a stop"] = as_user("fleet-alpha", "curl -s -m 5 -o /dev/null -w '%{http_code}' "
                                                       "http://127.0.0.1:9000/")
    sh("systemd-run --unit=squatter python3 -c 'import socket, time; s = socket.socket(); "
       "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\"127.0.0.1\", 877)); s.listen(1); "
       "time.sleep(600)'; sleep 1")
    sh("systemctl start fleet-egress; sleep 6")
    got["gate with its port taken"] = sh("systemctl is-active fleet-egress")
    got["tables with its port taken"] = sh(tables)
    got["alpha with no gate"] = as_user("fleet-alpha", "curl -s -m 5 -o /dev/null -w '%{http_code}' "
                                                       "http://127.0.0.1:9000/")
    sh("systemctl stop squatter; sleep 8")
    got["gate after the port is free"] = sh("systemctl is-active fleet-egress")
    got["tables after the port is free"] = sh(tables)
    got["alpha after the port is free"] = as_user("fleet-alpha", "curl -s -m 5 http://127.0.0.1:9000/")
    # nftables.service flushes every table at its restart and its stop: the drop-in loads the gate's table again
    got["nftables drop-in"] = sh("systemctl cat nftables.service | grep -c 'egress-rules --config'")
    for when, verb in (("a restart", "restart"), ("a stop", "stop")):
        sh(f"systemctl {verb} nftables.service; sleep 2")
        got[f"tables after {when} of nftables"] = sh(tables)
    again = configure("--egress", "on")
    got["again state"], got["again changed"] = again.get("state"), again.get("changed")
    got["again answer"] = again
    off = configure("--egress", "off")
    got["off ok"], got["off answer"] = off.get("ok"), off
    got["table after off"] = sh("nft list table inet founderizer_egress 2>/dev/null")
    got["socket acl after off"] = sh("getfacl -p /run/systemd/resolve/io.systemd.Resolve")
    got["gate after off"] = sh("systemctl is-active fleet-egress")
    got["journal"] = sh("journalctl -u fleet-egress -n 15 --no-pager")[-2000:]
    print("RESULT " + json.dumps(got))


if __name__ == "__main__":
    if sys.argv[1:] == ["--inside"]:
        inside()
    else:
        unittest.main()
