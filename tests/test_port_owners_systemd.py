"""The hub's ports belong to their own users on a server that also runs agents (VAULT.md limit 29; the one-server port
piece). A proof rig under a real systemd: it runs only when the variable FLEET_PORT_SYSTEMD=1 asks for it, and it builds
an image and starts a privileged container whose first process is systemd, as test_egress_systemd does.

    FLEET_PORT_SYSTEMD=1 python3 -m unittest test_port_owners_systemd

The fault that it catches: while the hub or its git service does not run (a release's restart, a crash, a stop by hand),
a program of an agent's own user listens on 8765 or 9418, or on 127.0.0.1:8767 while the connect gate does not run, and
it then gets what the other servers' brokers and helpers, the door and Funnel send to the hub or the gate. On today's
server (no port step) the tests of a foreign listener fail: that is the fault. The port piece puts its root step in
STEP and its fixed root command in HOLDER; then every test passes.

Inside: Ubuntu 24.04 with systemd, nftables and sudo; the hub's user fleet (it also runs the git service), the connect
gate's user founderizer-connect, the agent user fleet-alpha and another user. Each listener is a small Python program
that sends one line, "held by <user>", to each client. A probe makes a TCP handshake and reads that line, from root and
from the other user, at 127.0.0.1, at the container's own address and at ::1.

  a listener of the agent's user on 8765 and 9418 (each address) and on 127.0.0.1:8767 gives no client a handshake;
  such a listener with a backlog of 1, whose queue a first client filled, gives the next client no handshake by a SYN
  cookie either;
  a listener of the port's own user, and one of root's (the claim and its second claim), still answers;
  the same after a reboot of the container (its systemd starts again, and the kernel's rules are gone until the step's
  boot unit loads them again);
  HOLDER, run with `sudo -n` by the port's own user, ends a listener of the agent's user, and the own user binds after
  it; it ends no listener of root's.

Not here (the port piece's own tests): a broker that asks a foreign listener and gets nothing, the claim's pause
marker, the words of --check. Every name is made up. The image and the container are removed at the end."""
import json
import os
import shutil
import subprocess
import sys
import unittest

from leftovers import ROOT, TEST_DIR

KIT = ROOT
# this file as the container sees it: KIT is /kit there
INSIDE = os.path.normpath(os.path.join("/kit", os.path.relpath(TEST_DIR, ROOT), "test_port_owners_systemd.py"))
IMAGE = "founderizer-port-owners-test"
# The port piece's root step: one shell line that root runs in the container after the users exist, with this checkout
# at /kit (read only). It loads the kernel's rule, installs the boot unit that loads it again, and writes the sudoers
# line for HOLDER. It leaves the hub, the git service and the gate stopped. Empty: today's server.
STEP = os.environ.get("FLEET_PORT_STEP", "")
# The port piece's fixed root command, with no argument, that the port's own user runs with `sudo -n`. Empty: none yet.
HOLDER = os.environ.get("FLEET_PORT_HOLDER", "")
# The shell of the line that the hub's and the git service's units run before each start (lifecycle.PORT_HOLD), which
# the outer test takes from lifecycle.py and gives the container. Empty: not given.
UNIT_PRE = os.environ.get("FLEET_PORT_UNIT_PRE", "")
HUB, GIT, GATE = 8765, 9418, 8767
OWN = {HUB: "fleet", GIT: "fleet", GATE: "founderizer-connect"}
AGENT, CLIENTS = "fleet-alpha", ("root", "other")
REBOOT = " after a reboot"
DOCKERFILE = """FROM ubuntu:24.04
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends systemd \\
    systemd-sysv dbus python3 nftables iproute2 procps sudo ca-certificates >/dev/null && \\
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


def result(done):
    lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    return json.loads(lines[-1][7:]) if lines else None


@unittest.skipUnless(os.environ.get("FLEET_PORT_SYSTEMD") == "1", "set FLEET_PORT_SYSTEMD=1 to run it: it builds an "
                     "image and starts a privileged container")
class PortOwners(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not docker():
            raise unittest.SkipTest("Docker does not answer on this machine")
        built = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"], input=DOCKERFILE, capture_output=True,
                               text=True, timeout=900)
        if built.returncode != 0:
            raise AssertionError("the image did not build:\n" + built.stderr[-3000:])
        name = f"port-owners-{os.getpid()}"
        started = subprocess.run(["docker", "run", "-d", "--name", name, "--privileged", "--cgroupns=host",
                                  "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-v", f"{KIT}:/kit:ro",
                                  "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024",
                                  "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                                  "--sysctl", "net.ipv6.conf.lo.disable_ipv6=0", IMAGE],
                                 capture_output=True, text=True, timeout=120)
        if started.returncode != 0:
            subprocess.run(["docker", "rmi", IMAGE], capture_output=True, timeout=120)
            raise AssertionError("the container did not start:\n" + started.stderr[-3000:])
        import lifecycle            # the outer side only: the container runs this file with no checkout's modules
        pre = lifecycle.PORT_HOLD.split(" -c ", 1)[1].strip().strip('"') if HOLDER else ""
        env = ["-e", f"FLEET_PORT_STEP={STEP}", "-e", f"FLEET_PORT_HOLDER={HOLDER}", "-e", f"FLEET_PORT_UNIT_PRE={pre}"]
        try:
            first = subprocess.run(["docker", "exec", *env, name, "python3", INSIDE, "--inside", "1"],
                                   capture_output=True, text=True, timeout=1200)
            # a reboot: the container's systemd stops and starts again, with a new network namespace (no kernel rules)
            subprocess.run(["docker", "restart", "-t", "30", name], capture_output=True, timeout=180)
            second = subprocess.run(["docker", "exec", *env, name, "python3", INSIDE, "--inside", "2"],
                                    capture_output=True, text=True, timeout=1200)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=120)
            subprocess.run(["docker", "rmi", IMAGE], capture_output=True, timeout=120)
        cls.log = "\n".join(done.stdout[-6000:] + done.stderr[-6000:] for done in (first, second))
        one, two = result(first), result(second)
        if one is None or two is None:
            raise AssertionError("a run in the container did not end with its result:\n" + cls.log)
        cls.got = {**one, **{key + REBOOT: value for key, value in two.items()}}

    def answers(self, user, port, suffix=""):
        """Each probe of a listener of `user` on `port`, in one phase: {"<client> at <address>": what it got}."""
        head = f"{user} on {port}, "
        return {key[len(head):len(key) - len(suffix)]: value for key, value in self.got.items()
                if key.startswith(head) and key.endswith(suffix) and (suffix or not key.endswith(REBOOT))}

    def assertNoHandshake(self, port, suffix=""):
        self.assertEqual(self.got[f"bind {AGENT} {port}{suffix}"], "listening", self.log)
        got = self.answers(AGENT, port, suffix)
        self.assertTrue(got, self.log)
        self.assertEqual({where: what for where, what in got.items() if what not in ("no handshake", "refused")}, {},
                         f"a listener of the agent's user on {port}{suffix} answered these clients")

    def assertAnswered(self, port, suffix=""):
        for user in (OWN[port], "root"):
            self.assertEqual(self.got[f"bind {user} {port}{suffix}"], "listening", self.log)
            got = self.answers(user, port, suffix)
            self.assertTrue(got, self.log)
            self.assertEqual({where: what for where, what in got.items() if what != f"answer held by {user}"}, {},
                             f"a listener of {user} on {port}{suffix} did not answer these clients")

    def test_the_rig_probes_ipv4_and_ipv6(self):
        self.assertEqual(self.got["step"], {"given": bool(STEP), "exit": 0} if STEP else {"given": False}, self.log)
        self.assertTrue(self.got["ipv6"], "the container has no ::1, so the rig proves nothing for IPv6")
        self.assertIn("root at ::1", self.answers("fleet", HUB))

    def test_an_agent_user_on_the_hubs_port_gives_no_client_a_handshake(self):
        self.assertNoHandshake(HUB)

    def test_an_agent_user_on_the_git_port_gives_no_client_a_handshake(self):
        self.assertNoHandshake(GIT)

    def test_an_agent_user_on_the_gates_port_gives_no_client_a_handshake(self):
        self.assertNoHandshake(GATE)

    def test_the_ports_own_user_and_root_still_answer(self):
        for port in (HUB, GIT, GATE):
            self.assertAnswered(port)

    def test_after_a_reboot_an_agent_user_still_gives_no_client_a_handshake(self):
        for port in (HUB, GIT, GATE):
            self.assertNoHandshake(port, REBOOT)

    def test_after_a_reboot_the_ports_own_user_and_root_still_answer(self):
        for port in (HUB, GIT, GATE):
            self.assertAnswered(port, REBOOT)

    def test_an_agent_user_whose_queue_is_full_gives_no_client_a_handshake_by_a_syn_cookie(self):
        """A cookie's SYN-ACK leaves with no socket, so a rule of the socket's user alone lets it out: an agent's
        listener that fills its own queue (its own SYN-ACKs are dropped) then completes the next client's handshake
        by cookie and reads that client's first data. Before and after a reboot."""
        for suffix in ("", REBOOT):
            self.assertEqual(self.got["syncookies" + suffix], "1", "SYN cookies are off: this case proves nothing")
            self.assertEqual(self.got[f"cookie bind {HUB}{suffix}"], "listening", self.log)
            self.assertIn(self.got[f"cookie {HUB}{suffix}"], ("no handshake", "refused"),
                          f"a client got a handshake by cookie from the agent's listener{suffix}")

    def test_the_line_of_the_hubs_unit_as_the_hubs_user_ends_an_agents_listener(self):
        """The line that the hub's unit runs before each start (lifecycle.PORT_HOLD), run as the hub's user: an agent's
        listener on 8765 goes, and the hub's user binds after it. Bug it catches (the Door area's read of 24 November
        2026): a line whose test the hub's user can never pass (the sudoers folder is root's 0750), so that it runs
        nothing and the hub loops on a taken port."""
        if not HOLDER:
            self.fail("the port piece's fixed root command is not in HOLDER yet")
        self.assertTrue(self.got.get("unit line ended the agent"), self.got.get("unit line"))
        self.assertEqual(self.got["own binds after the unit line"], "listening", self.log)

    def test_the_holder_command_ends_a_foreign_listener_and_keeps_roots(self):
        if not HOLDER:
            self.fail("the port piece's fixed root command is not in HOLDER yet")
        for port in (HUB, GIT, GATE):
            self.assertTrue(self.got[f"holder ended {AGENT} on {port}"], self.got[f"holder line {port}"])
            self.assertEqual(self.got[f"own binds after the holder {port}"], "listening", self.log)
        self.assertTrue(self.got["root's listener after the holder"], self.got["holder line for root's"])


LISTENER = r'''
import socket, sys
host, port, user = sys.argv[1], int(sys.argv[2]), sys.argv[3]
backlog = int(sys.argv[4]) if len(sys.argv) > 4 else 16
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
# as the hub's own HTTP server does: the connections that an earlier listener closed stay in TIME_WAIT, and they
# must not keep the next user's bind out (it never lets two listeners hold the port at once)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if family == socket.AF_INET6:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind((host, port))
s.listen(backlog)
print("listening", flush=True)
line = ("held by " + user + "\n").encode()
while True:
    c, _ = s.accept()
    try:
        c.sendall(line)
    finally:
        c.close()
'''

PROBE = r'''
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect((host, port))
except socket.timeout:
    print("no handshake"); sys.exit()
except ConnectionRefusedError:
    print("refused"); sys.exit()
except OSError as e:
    print("error " + e.__class__.__name__); sys.exit()
try:
    data = s.recv(100).decode(errors="replace").strip()
except socket.timeout:
    data = ""
print("answer " + data if data else "handshake, no line")
'''


def sh(script, timeout=120):
    done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=timeout)
    return (done.stdout + done.stderr).strip()


def as_user(user, script):
    return sh(f"setpriv --reuid={user} --regid={user} --init-groups -- bash -c {json.dumps(script)}")


def listen(user, host, port, backlog=16):
    proc = subprocess.Popen(["setpriv", f"--reuid={user}", f"--regid={user}", "--init-groups", "--", "python3", "-I",
                             "/opt/port-rig/listener.py", host, str(port), user, str(backlog)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    first = proc.stdout.readline().strip()
    if first != "listening":                    # its error's last line says why, for the log
        rest = [line.strip() for line in (proc.stdout.read() or "").splitlines() if line.strip()]
        first = rest[-1] if rest else (first or "ended")
    return proc, first


def stop(proc):
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=10)


def inside(phase):
    got = {}
    sh("for i in $(seq 1 60); do systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; "
       "sleep 1; done")
    if phase == 1:
        sh("""set -e
useradd -m -u 1100 fleet
useradd -r -s /usr/sbin/nologin founderizer-connect
groupadd -f fleet-agents
useradd -m -u 2001 -G fleet-agents fleet-alpha
useradd -m -u 2500 other
""")
        got["step"] = {"given": False}
        if STEP:
            done = subprocess.run(["bash", "-c", STEP], capture_output=True, text=True, timeout=600)
            got["step"] = {"given": True, "exit": done.returncode}
            got["step output"] = (done.stdout + done.stderr)[-3000:]
    os.makedirs("/opt/port-rig", exist_ok=True)
    for name, text in (("listener.py", LISTENER), ("probe.py", PROBE)):
        with open(f"/opt/port-rig/{name}", "w") as f:
            f.write(text)
        os.chmod(f"/opt/port-rig/{name}", 0o644)
    with open("/proc/net/if_inet6") as f:
        got["ipv6"] = any(line.startswith("0" * 31 + "1") for line in f)
    own_address = sh("hostname -I").split()[0]
    wide = "::" if got["ipv6"] else "0.0.0.0"
    targets = ["127.0.0.1", own_address] + (["::1"] if got["ipv6"] else [])
    for port in (HUB, GIT, GATE):
        host, where = ("127.0.0.1", ["127.0.0.1"]) if port == GATE else (wide, targets)
        for user in (AGENT, OWN[port], "root"):
            proc, first = listen(user, host, port)
            got[f"bind {user} {port}"] = first
            for client in CLIENTS:
                for address in where:
                    got[f"{user} on {port}, {client} at {'own address' if address == own_address else address}"] = \
                        as_user(client, f"python3 -I /opt/port-rig/probe.py {address} {port}") \
                        if first == "listening" else "not listening"
            stop(proc)
    # A SYN cookie (the Door area's read of 24 November 2026): an agent's listener with a backlog of 1. The first
    # client's SYN-ACK is the agent's, which the rule drops, so that half-open connection fills the queue for about a
    # minute; the next client's SYN then gets a cookie, whose SYN-ACK the kernel sends with no socket. Without a rule
    # for such a SYN-ACK the second client completes its handshake and reads the agent's line.
    with open("/proc/sys/net/ipv4/tcp_syncookies") as f:
        got["syncookies"] = f.read().strip()
    proc, first = listen(AGENT, wide, HUB, backlog=1)
    got[f"cookie bind {HUB}"] = first
    if first == "listening":
        got[f"cookie fill {HUB}"] = as_user("root", f"python3 -I /opt/port-rig/probe.py 127.0.0.1 {HUB}")
        got[f"cookie {HUB}"] = as_user("other", f"python3 -I /opt/port-rig/probe.py 127.0.0.1 {HUB}")
    stop(proc)
    if phase == 1 and HOLDER:
        for port in (HUB, GIT, GATE):
            host = "127.0.0.1" if port == GATE else wide
            proc, first = listen(AGENT, host, port)
            got[f"holder line {port}"] = as_user(OWN[port], f"sudo -n {HOLDER}")
            try:
                proc.wait(timeout=10)
                got[f"holder ended {AGENT} on {port}"] = first == "listening"
            except subprocess.TimeoutExpired:
                got[f"holder ended {AGENT} on {port}"] = False
                stop(proc)
            again, line = listen(OWN[port], host, port)
            got[f"own binds after the holder {port}"] = line
            stop(again)
        if UNIT_PRE:            # the units' own line, as the hub's user, while an agent's program holds 8765
            proc, first = listen(AGENT, wide, HUB)
            got["unit line"] = as_user("fleet", 'sh -c "$FLEET_PORT_UNIT_PRE"')
            try:
                proc.wait(timeout=10)
                got["unit line ended the agent"] = first == "listening"
            except subprocess.TimeoutExpired:
                got["unit line ended the agent"] = False
                stop(proc)
            again, line = listen("fleet", wide, HUB)
            got["own binds after the unit line"] = line
            stop(again)
        proc, first = listen("root", wide, HUB)
        got["holder line for root's"] = as_user("fleet", f"sudo -n {HOLDER}")
        got["root's listener after the holder"] = first == "listening" and proc.poll() is None
        stop(proc)
    got["nft"] = sh("nft list ruleset")[-3000:]
    print("RESULT " + json.dumps(got))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--inside"]:
        inside(int(sys.argv[2]))
    else:
        unittest.main()
