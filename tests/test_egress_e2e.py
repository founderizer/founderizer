"""The outgoing gate with the real kernel, in one Docker container (vault.py, "the outgoing gate";
agent-outgoing-connections-proposal.md, section 10). It runs only when the variable FLEET_EGRESS_E2E=1 asks for it: it
starts a container and installs packages, and no ordinary test run does that.

    FLEET_EGRESS_E2E=1 python3 -m unittest test_egress_e2e

Inside the container, as on a server: the real table from `vault.py egress-rules` (root, from the safe copy), the real
gate (`vault.py egress`) as founderizer-egress with the right to its low ports, an agent user (fleet-alpha), another
user (other), the service user (fleet) and the swap proxy's user (founderizer-swap). A network namespace "world"
behind a veth pair plays the internet: a site, another host, a stand-in hub, a name server and an IPv6 host; a
second veth pair, named tailscale0 on this side, plays another Tailscale machine with a stand-in door. It
proves, in the order of the probe of 13 November 2026 (P1 to P12) and of the proposal's section 10:

  a user that is no agent is not touched, and the gate counts nothing of it;
  an agent's DNS question to any name server reaches the gate's resolver, and its TCP the gate, which records the
  name from the HTTP head, the TLS ClientHello or its resolver, and the bytes; in this step it connects to the address
  that the program chose (records only), also to another user's local listener and over IPv6;
  UDP other than DNS and ping of an agent are refused by the kernel, the same of another user pass;
  the hub's address and port go direct, also while the gate is down, and the agent's other connections then fail
  at once;
  an agent's TCP connection to another Tailscale machine (the door) goes direct over IPv4, because Tailscale's own
  rule (played here, as Tailscale 1.104 writes it) drops each answer of the gate from its IPv4 range, while this
  machine's own Tailscale address still goes through the gate's local port, and Tailscale's IPv6 range, which has
  no such rule, through the gate with its record;
  an agent's connection to its own browser's DevTools port goes direct, with its own UID, which the browsers' table
  reads; and a process with a sub-uid of the agent, as newuidmap gives one in a user namespace, is refused;
  the relay port takes the swap proxy's CONNECT with the agent's UID and nobody else's, and the kernel refuses the
  swap proxy's own connection and its DNS;
  the control socket answers the service user and no other user;
  a new program takes over with no cut of a download, and the counts of the process that gave way reach the new one;
  a new program that does not start is not taken; at a cold start the launcher runs the safe copy; and after three
  ends of a program that nobody asked for (the unit's ExecStopPost, played here), the launcher runs the safe copy
  too.

All names and addresses are made up (the documentation ranges, and Tailscale's own ranges for its part). Nothing is
written outside the container, which is removed at the end."""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

from leftovers import ROOT, TEST_DIR

IMAGE = "ubuntu:24.04"
KIT = ROOT
# this file as the container sees it: KIT is /kit there, and this file is in tests/ of a published copy
INSIDE = os.path.normpath(os.path.join("/kit", os.path.relpath(TEST_DIR, ROOT), "test_egress_e2e.py"))
PACKAGES = "nftables python3 curl iproute2 iputils-ping util-linux openssl ca-certificates"


def docker():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(os.environ.get("FLEET_EGRESS_E2E") == "1", "set FLEET_EGRESS_E2E=1 to run it: it starts a Docker "
                     "container")
class Kernel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not docker():
            raise unittest.SkipTest("Docker does not answer on this machine")
        done = subprocess.run(["docker", "run", "--rm", "--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN",
                               "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                               "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024",
                               "--sysctl", "net.ipv4.ping_group_range=0 2147483647",
                               "-v", f"{KIT}:/kit:ro", IMAGE, "bash", "-c",
                               "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && apt-get install "
                               f"-y -qq --no-install-recommends {PACKAGES} >/dev/null 2>&1 && "
                               f"python3 {INSIDE} --inside"],
                              capture_output=True, text=True, timeout=1500)
        cls.log = done.stdout[-8000:] + done.stderr[-8000:]
        lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
        if not lines:
            raise AssertionError("the container's run did not end with its result:\n" + cls.log)
        cls.got = json.loads(lines[-1][7:])

    def test_a_user_that_is_no_agent_is_not_touched(self):
        self.assertEqual(self.got["P1 other reaches the site"], "the page of site", self.log)
        self.assertEqual(self.got["P1 rows of other"], 0)

    def test_an_agents_dns_and_tcp_reach_the_gate_which_records_the_names(self):
        self.assertEqual(self.got["P2 getent"], "198.51.100.7", self.log)
        self.assertEqual(self.got["P2 http"], "the page of site")
        self.assertEqual(self.got["P2 https handshake reached the site"], True)
        self.assertEqual(self.got["P2 any name server"], "198.51.100.7")
        self.assertEqual(self.got["P2 a socket connected to any name server"], "198.51.100.7")
        self.assertEqual(self.got["DNS over TCP"], "198.51.100.7")
        rows = self.got["rows of alpha"]
        self.assertIn(["site.example.test", 53, "dns"], rows)
        self.assertIn(["site.example.test", 80, "host"], rows)
        self.assertIn(["site.example.test", 443, "sni"], rows)
        self.assertGreater(self.got["bytes down of the http row"], 0)

    def test_records_only_connects_to_the_address_that_the_program_chose(self):
        self.assertEqual(self.got["P3 pinned address"], "the page of other", self.log)
        self.assertEqual(self.got["P6 other host"], "the page of other")

    def test_udp_and_ping_of_an_agent_are_refused_and_of_another_user_pass(self):
        self.assertEqual(self.got["P7 alpha udp"], "PermissionError", self.log)
        self.assertNotEqual(self.got["P7 other udp"], "PermissionError")
        self.assertEqual((self.got["P8 alpha ping"], self.got["P8 other ping"]), (False, True))

    def test_local_listeners_and_ipv6_go_through_the_gate(self):
        self.assertEqual(self.got["P9 own listener"], "alpha's own server", self.log)
        self.assertEqual(self.got["P9 other's listener (records only)"], "other's server")
        self.assertIn(["127.0.0.1", 9000, "local"], self.got["local rows"])
        self.assertEqual(self.got["P10 ipv6 through the gate, loopback"], "other's server",
                         (self.got.get("gate listens six"), self.got.get("lo six")))
        self.assertIn(["::1", 9002, "local"], self.got["local rows"])
        # A user that is no agent reaches the IPv6 host directly: the kernel's own neighbour discovery, which no
        # user's socket makes, meets no rule of the table (it did, and IPv6 stopped, before the review of 17 November)
        self.assertEqual(self.got["P10 other direct"], "the page of six", self.got.get("P10 ipv6 error"))
        self.assertEqual(self.got["P10 ipv6"], "the page of six", self.got.get("P10 ipv6 error"))

    def test_the_hub_goes_direct_also_while_the_gate_is_down(self):
        # the table stays while the gate does not run (the proposal's section 5.4)
        self.assertEqual(self.got["P11 hub up"], "the page of hub", self.log)
        self.assertEqual(self.got["P11 hub, gate down"], "the page of hub")
        self.assertTrue(self.got["P11 site fails at once, gate down"])
        self.assertEqual(self.got["P12 cgroup"], "0::/")

    def test_an_agent_reaches_another_tailscale_machine_whose_answers_tailscales_own_rule_would_drop(self):
        """An agent reaches another Tailscale machine over IPv4 (19 November 2026: through the gate, no agent reached
        the door, as Tailscale's rule dropped each answer of the gate), and that rule drops nothing of it; the gate
        has no row of that connection, and keeps its rows of this machine's own Tailscale address (its local port)
        and of Tailscale's IPv6 range, where Tailscale has no such rule."""
        self.assertEqual(self.got["tailnet: the door"], "the page of door", self.log)
        self.assertEqual(self.got["tailnet: drops of Tailscale's rule"], [0], self.log)
        self.assertEqual(self.got["tailnet: the door over IPv6"], "the page of door", self.log)
        self.assertEqual(self.got["tailnet: this machine's own address"], "other's server", self.log)
        self.assertEqual(self.got["tailnet rows"],
                         [["100.64.0.1", 9003, "local"], ["fd7a:115c:a1e0::7", 8766, "fleet"]])

    def test_the_table_loads_before_the_gate_serves_and_root_s_file_names_it(self):
        self.assertEqual(self.got["rules"], "loaded", self.log)
        self.assertEqual(self.got["loaded file"], "1\n")

    def test_a_program_that_ends_three_times_with_no_stop_asked_for_gives_way_to_the_safe_copy(self):
        self.assertEqual(self.got["crashes: counted"], [1, 2, 3, 3], self.log)
        self.assertEqual(self.got["crashes: safe copy serves"], True)
        # ... but no program serves in the place of a policy that a later program stored
        code, words = self.got["later policy: check"]
        self.assertNotEqual(code, 0, words)
        self.assertIn("a later program stored a policy that this program does not take", words)

    def test_an_agents_own_browser_keeps_its_uid_and_a_sub_uid_is_refused(self):
        # through the gate, the browsers' table would read the gate's user and reset the connection
        self.assertEqual(self.got["P14 alpha's own browser"], "alpha's browser", self.log)
        self.assertIn("9301", self.got["P14 browser set"])
        self.assertIn("600000-665535", self.got["P15 subagents set"])
        self.assertEqual(self.got["P15 a sub-uid of alpha"], "000")
        self.assertEqual(self.got["P15 the same with another uid"], "200")

    def test_the_relay_port_is_the_swap_proxys_only_and_the_kernel_keeps_that_user_to_it(self):
        self.assertEqual(self.got["relay as the swap user"], "200", self.log)
        self.assertIn(["site.example.test", 443, "relay"], self.got["rows of alpha"])
        self.assertEqual(self.got["relay as other"], "closed")
        self.assertEqual(self.got["swap user direct"], "refused")
        self.assertEqual(self.got["swap user dns"], "PermissionError")
        self.assertEqual(self.got["swap proxy's start check under the table"], "True")

    def test_the_gate_finds_a_caller_by_the_kernels_exact_lookup(self):
        # root's own sockets: uid 0 each, and no socket for an end that no socket has
        self.assertEqual(self.got["diag"], [0, 0, 0, None], self.log)
        self.assertEqual(self.got["lookup check"], {"tcp": True, "udp": True})
        # a socket that connected to another name server: not by the exact lookups, by the dump of its port
        self.assertEqual(self.got["udp dump"], [0, [], None])
        self.assertEqual(self.got["the gate's lookups"], {"tcp": True, "udp": True})

    def test_the_control_socket_answers_the_service_user_only(self):
        self.assertEqual(self.got["control as fleet"], True, self.log)
        self.assertEqual(self.got["control closes an agent before a byte"], "True")
        self.assertEqual(self.got["control as other"], False)
        self.assertEqual(self.got["control as alpha"], False)

    def test_a_new_program_takes_over_with_no_cut_and_its_counts_are_merged(self):
        self.assertEqual(self.got["handover: download whole"], True, self.log)
        self.assertNotEqual(self.got["handover: pid before"], self.got["handover: pid after"])
        self.assertEqual(self.got["handover: systemd heard MAINPID"], True)
        self.assertEqual(self.got["handover: old process ended"], True)
        self.assertGreater(self.got["handover: bytes of the download in the new gate's counts"], 20_000_000)
        self.assertEqual(self.got["handover: new connection works"], "the page of site")

    def test_a_program_that_does_not_start_is_not_taken_and_the_safe_copy_serves_a_cold_start(self):
        self.assertEqual(self.got["takeback: same pid"], True, self.log)
        self.assertEqual(self.got["takeback: still serves"], "the page of site")
        self.assertEqual(self.got["takeback: tries"], 1)
        self.assertEqual(self.got["launcher: safe copy serves"], True)
        self.assertEqual(self.got["launcher: page"], "the page of site")


# ---------------------------------------------------------------- inside the container (as root)
WORLD_DNS = '''
import socket, struct, threading
NAMES = {"site.example.test": "198.51.100.7", "other.example.test": "198.51.100.8"}
def answer(q):
    i, labels = 12, []
    while q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode()); i += 1 + q[i]
    name, kind = ".".join(labels).lower(), struct.unpack_from("!H", q, i + 1)[0]
    ip = NAMES.get(name) if kind == 1 else None
    head = q[:2] + b"\\x81\\x80" + q[4:6] + struct.pack("!H", 1 if ip else 0) + b"\\x00\\x00\\x00\\x00"
    body = q[12:i + 5] + ((b"\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04" + socket.inet_aton(ip)) if ip else b"")
    return head + body
def tcp():
    t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("198.51.100.53", 53)); t.listen(16)
    while True:
        c, _ = t.accept()
        n = struct.unpack("!H", c.recv(2))[0]
        q = b""
        while len(q) < n:
            q += c.recv(n - len(q))
        a = answer(q)
        c.sendall(struct.pack("!H", len(a)) + a); c.close()
threading.Thread(target=tcp, daemon=True).start()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("198.51.100.53", 53))
while True:
    q, a = s.recvfrom(4096)
    s.sendto(answer(q), a)
'''


def sh(script, check=False, **more):
    done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, **more)
    if check and done.returncode != 0:
        raise SystemExit(f"{script}\n{done.stdout}\n{done.stderr}")
    return done


def as_user(user, script, timeout=30):
    return sh(f"setpriv --reuid={user} --regid={user} --init-groups -- bash -c {json.dumps(script)}", timeout=timeout)


def out(user, script, timeout=30):
    try:
        return as_user(user, script, timeout).stdout.strip()
    except subprocess.TimeoutExpired:
        return "timeout"


SCRIPTS = 0


def program(text):
    """A Python program in a file that each user reads, run as `python3 <file>`: no quoting through two shells."""
    global SCRIPTS
    SCRIPTS += 1
    path = f"/opt/scripts/{SCRIPTS}.py"
    os.makedirs("/opt/scripts", exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o644)
    os.chmod("/opt/scripts", 0o755)
    return f"python3 {path}"


def table_of(text):
    """The `table` of the rules step's one JSON line, or the text's end."""
    try:
        return json.loads(text.strip().splitlines()[-1]).get("table")
    except (ValueError, IndexError, AttributeError):
        return text.strip()[-300:]


def tailnet(host):
    """True for an address in Tailscale's ranges; a row's host is a name or an address."""
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(a in net for net in map(ipaddress.ip_network, ("100.64.0.0/10", "fd7a:115c:a1e0::/48"))
               if net.version == a.version)


def inside():
    sys.path.insert(0, "/kit")
    import vault
    got = {}
    sh("""set -e
groupadd fleet-agents
useradd -m -u 1100 fleet
useradd -m -u 2001 -G fleet-agents fleet-alpha
useradd -m -u 2500 other
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin founderizer-egress
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin founderizer-swap
install -d -o root -g root -m 755 /usr/local/lib/fleet-vault /usr/local/lib/founderizer-egress /etc/founderizer-egress
install -o root -g root -m 644 /kit/vault.py /usr/local/lib/fleet-vault/vault.py
install -o root -g root -m 644 /kit/vault.py /usr/local/lib/founderizer-egress/vault.py
install -d -o founderizer-egress -g founderizer-egress -m 700 /var/lib/founderizer-egress
install -d -o founderizer-egress -g founderizer-egress -m 755 /run/founderizer-egress
ip netns add world
ip link add v0 type veth peer name v1
ip link set v1 netns world
ip addr add 10.99.0.1/24 dev v0 && ip link set v0 up
ip netns exec world sh -c 'ip addr add 10.99.0.2/24 dev v1; ip link set v1 up; ip link set lo up;
  for a in 7 8 9 53; do ip addr add 198.51.100.$a/32 dev lo; done; ip route add default via 10.99.0.1'
ip route add 198.51.100.0/24 via 10.99.0.2
ip -6 addr add 2001:db8:99::1/64 dev v0 nodad
ip netns exec world ip -6 addr add 2001:db8:99::2/64 dev v1 nodad
# Tailscale's interface, and its rule as Tailscale 1.104 writes it (its chain ts-input): a packet from its IPv4 range
# that does not come in on tailscale0 is dropped, but this machine's own address on the loopback interface. It has
# no such rule for IPv6.
ip link add tailscale0 type veth peer name t1
ip link set t1 netns world
ip addr add 100.64.0.1/24 dev tailscale0 && ip -6 addr add fd7a:115c:a1e0::1/64 dev tailscale0 nodad
ip link set tailscale0 up
ip netns exec world sh -c 'set -e; ip addr add 100.64.0.7/24 dev t1; ip -6 addr add fd7a:115c:a1e0::7/64 dev t1 nodad
  ip link set t1 up'
nft -f - <<'EOF'
table ip tailscale_rule {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr 100.64.0.1 iifname "lo" accept
    iifname "tailscale0" accept
    ip saddr 100.64.0.0/10 iifname != "tailscale0" counter drop
  }
}
EOF
for n in site other hub six door; do mkdir -p /srv/$n; echo "the page of $n" > /srv/$n/index.html; done
head -c 40000000 /dev/zero > /srv/site/big
mkdir -p /srv/a /srv/o /srv/b /etc/fleet-browser; echo "alpha's own server" > /srv/a/index.html
echo "other's server" > /srv/o/index.html; echo "alpha's browser" > /srv/b/index.html
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=site.example.test -keyout /srv/key.pem -out /srv/cert.pem \
  -days 2 >/dev/null 2>&1
""", check=True)
    with open("/etc/founderizer-egress/egress.json", "w") as f:
        f.write(vault.egress_conf_text({"hub": "http://198.51.100.9:8765", "worker_group": "fleet-agents"}))
    with open("/etc/founderizer-egress/rules.nft", "w") as f:
        f.write(vault.egress_table())
    launch = vault.egress_files('{}')[vault.EGRESS_LAUNCH][0]
    with open(vault.EGRESS_LAUNCH, "w") as f:
        f.write(launch)
    os.chmod(vault.EGRESS_LAUNCH, 0o755)
    world = "ip netns exec world python3"
    servers = [
        f"{world} -m http.server 80 --bind 198.51.100.7 --directory /srv/site",
        f"{world} -m http.server 80 --bind 198.51.100.8 --directory /srv/other",
        f"{world} -m http.server 8765 --bind 198.51.100.9 --directory /srv/hub",
        f"{world} -m http.server 80 --bind 2001:db8:99::2 --directory /srv/six",
        f"ip netns exec world {program(WORLD_DNS)}",
        # the door on another Tailscale machine; another user's server on this machine's own Tailscale address
        f"{world} -m http.server 8766 --bind 100.64.0.7 --directory /srv/door",
        f"{world} -m http.server 8766 --bind fd7a:115c:a1e0::7 --directory /srv/door",
        "setpriv --reuid=2500 --regid=2500 --clear-groups python3 -m http.server 9003 --bind 100.64.0.1 --directory "
        "/srv/o",
        f"{world} -c \"import http.server, ssl; s = http.server.ThreadingHTTPServer(('198.51.100.7', 443), "
        f"lambda *a: http.server.SimpleHTTPRequestHandler(*a, directory='/srv/site')); c = ssl.SSLContext("
        f"ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain('/srv/cert.pem', '/srv/key.pem'); "
        f"s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()\"",
        "setpriv --reuid=2500 --regid=2500 --clear-groups python3 -m http.server 9000 --bind 127.0.0.1 --directory /srv/o",
        "setpriv --reuid=2001 --regid=2001 --clear-groups python3 -m http.server 9001 --bind 127.0.0.1 --directory /srv/a",
        "setpriv --reuid=2500 --regid=2500 --clear-groups python3 -m http.server 9002 --bind ::1 --directory /srv/o",
    ]
    for line in servers:
        subprocess.Popen(["bash", "-c", line + " >/dev/null 2>&1"])
    with open("/etc/resolv.conf", "w") as f:
        f.write("nameserver 198.51.100.53\n")
    sh("sleep 2")
    # an agent's browser (build plan 04): its DevTools port, which the browsers' own table opens to its own agent only;
    # and a sub-uid range of the agent, as useradd gives one
    with open("/etc/fleet-browser/ports", "w") as f:
        f.write("fleet-alpha 9301 5911\n")
    with open("/etc/subuid", "a") as f:
        f.write("fleet-alpha:600000:65536\n")      # far from the ranges that useradd gives
    subprocess.Popen(["bash", "-c", "setpriv --reuid=2001 --regid=2001 --clear-groups python3 -m http.server 9301 "
                                    "--bind 127.0.0.1 --directory /srv/b >/dev/null 2>&1"])
    sh("nft -f - <<'EOF'\ntable inet fleet_browser {\n chain out {\n"
       "  type filter hook output priority 0; policy accept;\n"
       "  tcp dport 9301 meta skuid != { 0, 2001 } reject with tcp reset\n }\n}\nEOF", check=True)
    # the table, from the safe copy, as the rules' unit loads it at boot, before the gate serves
    loaded = sh(f"python3 -I {vault.EGRESS_SAFE} egress-rules --config {vault.EGRESS_CONF}")
    got["rules"] = table_of(loaded.stdout)
    got["loaded file"] = sh(f"cat {vault.EGRESS_LOADED}").stdout
    # systemd's notify socket, played by this process: the gate says MAINPID on it at a hand-over
    import socket
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify.bind("/run/notify.sock")
    os.chmod("/run/notify.sock", 0o777)
    notify.settimeout(0.2)
    heard = []

    def start(program=None):
        """The gate as its own user with the right to its low ports, as its unit starts it."""
        cmd = vault.EGRESS_LAUNCH if program is None else f"/usr/bin/python3 -I {program} egress --config " \
                                                           f"{vault.EGRESS_CONF}"
        return subprocess.Popen(["setpriv", "--reuid=founderizer-egress", "--regid=founderizer-egress",
                                 "--init-groups", "--inh-caps=+net_bind_service", "--ambient-caps=+net_bind_service",
                                 "--", "env", "NOTIFY_SOCKET=/run/notify.sock", "bash", "-c", f"exec {cmd}"],
                                stdout=open("/tmp/gate.out", "a"), stderr=subprocess.STDOUT)

    def listening(port=877):
        return f":{port} " in sh("ss -Hltn").stdout

    def wait_for(test, tries=100):
        for _ in range(tries):
            if test():
                return True
            sh("sleep 0.1")
        return False

    def ask(user, request):
        script = program("import json, socket\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(30)\n"
                         f"s.connect('{vault.EGRESS_CONTROL}')\ns.sendall((json.dumps({request!r}) + '\\n').encode())\n"
                         "print(s.makefile().readline())\n")
        text = out(user, script, timeout=60)
        try:
            return json.loads(text)
        except ValueError:
            return {"ok": False, "raw": text[-300:]}

    # The kernel's exact lookups themselves (sock_diag): a socket of a TCP connection, a UDP socket that did not
    # connect, and one that did. None or False here would mean a fall back to /proc, or a gate that resets each one.
    import socket as sk
    listener = sk.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = sk.create_connection(listener.getsockname())
    loose = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
    loose.bind(("127.0.0.1", 0))
    tied = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
    tied.connect(("127.0.0.53", 53))
    got["diag"] = [vault.egress_diag(sk.AF_INET, sk.IPPROTO_TCP, client.getsockname(), listener.getsockname()),
                   vault.egress_diag(sk.AF_INET, sk.IPPROTO_UDP, loose.getsockname(), ("0.0.0.0", 0)),
                   vault.egress_diag(sk.AF_INET, sk.IPPROTO_UDP, tied.getsockname(), ("127.0.0.53", 53)),
                   vault.egress_diag(sk.AF_INET, sk.IPPROTO_TCP, ("127.0.0.1", 1), ("127.0.0.1", 2))]
    elsewhere = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)       # connected to a name server that is not this machine's
    elsewhere.connect(("127.0.0.9", 53))
    free = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
    free.bind(("127.0.0.1", 0))
    free_port = free.getsockname()[1]
    free.close()
    got["lookup check"] = vault.egress_lookup_check()
    got["udp dump"] = [vault.egress_udp_uid(elsewhere.getsockname()), vault.egress_udp_port(sk.AF_INET, free_port),
                       vault.egress_udp_fast(elsewhere.getsockname(), ["127.0.0.53"])]
    for one in (listener, client, loose, tied, elsewhere):
        one.close()
    gate = start(vault.INSTALLED)
    got["gate listens"] = wait_for(listening)
    got["gate listens six"] = "[::1]:877" in sh("ss -Hltn").stdout
    got["lo six"] = sh("ip -6 addr show dev lo").stdout.strip()[-200:]
    if not got["gate listens"]:
        got["gate output"] = open("/tmp/gate.out").read()[-2000:]
    curl = "curl -s -m 5"
    got["P1 other reaches the site"] = out("other", f"{curl} http://198.51.100.7/")
    got["P2 getent"] = out("fleet-alpha", "getent hosts site.example.test | cut -d' ' -f1")
    got["P2 http"] = out("fleet-alpha", f"{curl} http://site.example.test/")
    https = as_user("fleet-alpha", f"{curl} -k -o /dev/null -w '%{{http_code}}' https://site.example.test/")
    got["P2 https handshake reached the site"] = https.stdout.strip() == "200"
    any_server = program("import socket\nq = b'\\x12\\x34\\x01\\x00\\x00\\x01' + bytes(6) + "
                         "b'\\x04site\\x07example\\x04test\\x00\\x00\\x01\\x00\\x01'\n"
                         "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(5)\n"
                         "s.sendto(q, ('9.9.9.9', 53))\na = s.recv(512)\nprint(socket.inet_ntoa(a[-4:]))\n")
    got["P2 any name server"] = out("fleet-alpha", any_server)
    connected_server = program("import socket\nq = b'\\x12\\x35\\x01\\x00\\x00\\x01' + bytes(6) + "
                               "b'\\x04site\\x07example\\x04test\\x00\\x00\\x01\\x00\\x01'\n"
                               "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(5)\n"
                               "s.connect(('9.9.9.9', 53))\ns.send(q)\na = s.recv(512)\nprint(socket.inet_ntoa(a[-4:]))\n")
    got["P2 a socket connected to any name server"] = out("fleet-alpha", connected_server)
    got["P3 pinned address"] = out("fleet-alpha", f"{curl} --resolve site.example.test:80:198.51.100.8 "
                                                  "http://site.example.test/")
    got["P6 other host"] = out("fleet-alpha", f"{curl} http://other.example.test/")
    udp_text = ("import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ntry:\n"
                "    s.connect(('198.51.100.7', 443))\n    s.send(b'x' * 1200)\n    print('sent')\n"
                "except Exception as e:\n    print(type(e).__name__)\n")
    udp = program(udp_text)
    got["P7 alpha udp"] = out("fleet-alpha", udp)
    got["P7 other udp"] = out("other", udp)
    got["P8 alpha ping"] = as_user("fleet-alpha", "ping -c 1 -W 2 198.51.100.7").returncode == 0
    got["P8 other ping"] = as_user("other", "ping -c 1 -W 2 198.51.100.7").returncode == 0
    got["P9 own listener"] = out("fleet-alpha", f"{curl} http://127.0.0.1:9001/")
    got["P9 other's listener (records only)"] = out("fleet-alpha", f"{curl} http://127.0.0.1:9000/")
    got["P10 ipv6"] = out("fleet-alpha", f"{curl} -g 'http://[2001:db8:99::2]/'")
    got["P10 ipv6 error"] = as_user("fleet-alpha", "curl -sS -m 5 -g 'http://[2001:db8:99::2]/' 2>&1").stdout[-300:]
    got["P10 other direct"] = as_user("other", "curl -sS -m 5 -g 'http://[2001:db8:99::2]/' 2>&1").stdout.strip()
    got["P10 ipv6 through the gate, loopback"] = out("fleet-alpha", f"{curl} -g 'http://[::1]:9002/'")
    got["P11 hub up"] = out("fleet-alpha", f"{curl} http://198.51.100.9:8765/")
    # another Tailscale machine: direct, because Tailscale's own rule drops each answer of the gate from its IPv4 range
    got["tailnet: the door"] = out("fleet-alpha", f"{curl} http://100.64.0.7:8766/")
    got["tailnet: the door over IPv6"] = out("fleet-alpha", f"{curl} -g 'http://[fd7a:115c:a1e0::7]:8766/'")
    got["tailnet: this machine's own address"] = out("fleet-alpha", f"{curl} http://100.64.0.1:9003/")
    got["tailnet: drops of Tailscale's rule"] = [int(n) for n in re.findall(
        r"packets (\d+)", sh("nft list table ip tailscale_rule").stdout)]
    got["P14 alpha's own browser"] = out("fleet-alpha", f"{curl} http://127.0.0.1:9301/")
    got["P14 browser set"] = sh("nft list set inet founderizer_egress browser").stdout
    for uid, key in ((600007, "P15 a sub-uid of alpha"), (900007, "P15 the same with another uid")):
        got[key] = sh(f"setpriv --reuid={uid} --regid={uid} --clear-groups -- {curl} -o /dev/null -w "
                      "'%{http_code}' http://127.0.0.1:9000/").stdout.strip()
    got["P15 subagents set"] = sh("nft list set inet founderizer_egress subagents").stdout
    # the relay port: the swap proxy's CONNECT with the agent's UID, and nobody else's
    relay = program("import socket\ntry:\n    s = socket.create_connection(('127.0.0.1', 879), timeout=10)\n"
                    "    s.sendall(b'CONNECT site.example.test:443 HTTP/1.1\\r\\nHost: site.example.test:443\\r\\n"
                    "X-Founderizer-Agent-Uid: 2001\\r\\n\\r\\n')\n    a = s.recv(100)\n"
                    "    print(a.split()[1].decode() if a else 'closed')\nexcept OSError:\n    print('closed')\n")
    got["relay as the swap user"] = out("founderizer-swap", relay)
    got["relay as other"] = out("other", relay)
    direct = program("import socket\ntry:\n    socket.create_connection(('198.51.100.7', 443), timeout=5)\n"
                     "    print('reached')\nexcept OSError:\n    print('refused')\n")
    got["swap user direct"] = out("founderizer-swap", direct)
    got["swap user dns"] = out("founderizer-swap", program(udp_text.replace("443", "53")))
    tcp_dns = program("import socket, struct\nq = b'\\x12\\x34\\x01\\x00\\x00\\x01' + bytes(6) + "
                      "b'\\x04site\\x07example\\x04test\\x00\\x00\\x01\\x00\\x01'\n"
                      "s = socket.create_connection(('9.9.9.9', 53), timeout=5)\n"
                      "s.sendall(struct.pack('!H', len(q)) + q)\nn = struct.unpack('!H', s.recv(2))[0]\na = b''\n"
                      "while len(a) < n:\n    a += s.recv(n - len(a))\nprint(socket.inet_ntoa(a[-4:]))\n")
    got["DNS over TCP"] = out("fleet-alpha", tcp_dns)
    silent = program("import socket, time\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(5)\n"
                     f"s.connect('{vault.EGRESS_CONTROL}')\nt = time.monotonic()\n"
                     "try:\n    gone = s.recv(1) == b''\nexcept OSError:\n    gone = True\n"
                     "print(gone and time.monotonic() - t < 2)\n")
    got["control closes an agent before a byte"] = out("fleet-alpha", silent)
    # the swap proxy's own start check under the table: its fixed port, which its user may reach (SwapProxy.reads_users)
    check = program("import sys\nsys.path.insert(0, '/usr/local/lib/fleet-vault')\nimport vault\n"
                    "p = vault.SwapProxy.__new__(vault.SwapProxy)\np.peer = vault.swap_peer\n"
                    "print(vault.egress_lookup_check(('127.0.0.1', vault.EGRESS_PORTS['relay']))['tcp'] and "
                    "p.reads_users())\n")
    got["swap proxy's start check under the table"] = sh(
        f"setpriv --reuid=founderizer-swap --regid=founderizer-swap --init-groups --inh-caps=+net_bind_service "
        f"--ambient-caps=+net_bind_service -- {check}").stdout.strip()
    got["control as fleet"] = ask("fleet", {"op": "status"}).get("ok")
    got["the gate's lookups"] = ask("fleet", {"op": "status"}).get("lookup")
    got["control as other"] = ask("other", {"op": "status"}).get("ok")
    got["control as alpha"] = ask("fleet-alpha", {"op": "status"}).get("ok")
    rows = ask("fleet", {"op": "counts"}).get("rows", [])
    got["P1 rows of other"] = sum(1 for r in rows if r["uid"] == 2500)
    got["rows of alpha"] = sorted({(r["host"], r["port"], r["how"]) for r in rows if r["uid"] == 2001})
    got["local rows"] = sorted({(r["host"], r["port"], r["cls"]) for r in rows if r["cls"] == "local"})
    got["tailnet rows"] = sorted({(r["host"], r["port"], r["cls"]) for r in rows if tailnet(r["host"])})
    got["bytes down of the http row"] = sum(r["down"] for r in rows if r["port"] == 80 and r["how"] == "host")
    # a hand-over during a download: the installed program changes, the service user's word, the new process
    pid_before = gate.pid
    download = subprocess.Popen(["setpriv", "--reuid=2001", "--regid=2001", "--init-groups", "--", "curl", "-s",
                                 "--limit-rate", "8M", "-o", "/tmp/big", "http://site.example.test/big"])
    sh("sleep 1; echo '# a new release' >> /usr/local/lib/fleet-vault/vault.py")
    ask("fleet", {"op": "status"})
    mainpid = None
    for _ in range(100):
        try:
            words = notify.recv(256).decode()
        except OSError:
            continue
        heard.append(words)
        if words.startswith("MAINPID="):
            mainpid = int(words.split("\n")[0].split("=")[1])
            break
    got["handover: systemd heard MAINPID"] = mainpid is not None and mainpid != pid_before
    download.wait(timeout=60)
    got["handover: download whole"] = os.path.getsize("/tmp/big") == 40000000 if os.path.exists("/tmp/big") else False
    got["handover: pid before"], got["handover: pid after"] = pid_before, mainpid
    got["handover: old process ended"] = wait_for(lambda: gate.poll() is not None, 100)
    got["handover: new connection works"] = out("fleet-alpha", f"{curl} http://site.example.test/")
    rows = ask("fleet", {"op": "counts"}).get("rows", [])
    got["handover: bytes of the download in the new gate's counts"] = sum(r["down"] for r in rows if r["uid"] == 2001)
    # a new program that does not start is not taken
    sh("echo 'this is no python' >> /usr/local/lib/fleet-vault/vault.py")
    before = ask("fleet", {"op": "status"})
    sh("sleep 3")
    after = ask("fleet", {"op": "status"})
    got["takeback: same pid"] = before.get("since") == after.get("since") and mainpid is not None and \
        os.path.exists(f"/proc/{mainpid}")
    got["takeback: still serves"] = out("fleet-alpha", f"{curl} http://site.example.test/")
    got["takeback: tries"] = (after.get("failed") or {}).get("tries")
    # the gate down: the hub goes direct, the rest fails at once
    if mainpid:
        sh(f"kill -9 {mainpid}")
    wait_for(lambda: not listening(), 50)
    got["P11 hub, gate down"] = out("fleet-alpha", f"{curl} http://198.51.100.9:8765/")
    down = as_user("fleet-alpha", "time -p curl -s -m 5 http://198.51.100.7/")
    got["P11 site fails at once, gate down"] = down.returncode != 0 and "real 0." in down.stderr
    got["P12 cgroup"] = out("fleet-alpha", "cat /proc/self/cgroup")
    # a cold start with the installed program that does not start: the launcher's safe copy serves
    cold = start()
    got["launcher: safe copy serves"] = wait_for(listening) and vault.EGRESS_SAFE in sh(
        "ps -o args= -u founderizer-egress").stdout
    got["launcher: page"] = out("fleet-alpha", f"{curl} http://site.example.test/")
    cold.kill()
    wait_for(lambda: not listening(), 50)
    # a new program that passes its check and stops at once: each end that nobody asked for counts (the unit's
    # ExecStopPost, played here with systemd's word for it), a stop that somebody asked for does not, and after three
    # the safe copy serves
    def stopped(result):
        sh(f"setpriv --reuid=founderizer-egress --regid=founderizer-egress --init-groups -- env "
           f"SERVICE_RESULT={result} {vault.EGRESS_LAUNCH} --stopped")

    def crashes():
        return len(open(vault.EGRESS_CRASHES).read().splitlines()) if os.path.exists(vault.EGRESS_CRASHES) else 0
    with open(vault.INSTALLED, "w") as f:
        f.write("import sys\nsys.exit(0 if '--check' in sys.argv else 1)\n")
    counted = []
    for _ in range(3):
        start().wait(timeout=60)
        stopped("exit-code")
        counted.append(crashes())
    stopped("success")
    got["crashes: counted"] = counted + [crashes()]
    fourth = start()
    got["crashes: safe copy serves"] = wait_for(listening) and vault.EGRESS_SAFE in sh(
        "ps -o args= -u founderizer-egress").stdout
    fourth.kill()
    wait_for(lambda: not listening(), 50)
    # a policy that a later program stored: this program does not start in its place (the table stays)
    sh("printf '%s' '{\"version\": 2, \"mode\": \"lists\"}' > /var/lib/founderizer-egress/policy.json; "
       "chown founderizer-egress: /var/lib/founderizer-egress/policy.json")
    check = sh(f"setpriv --reuid=founderizer-egress --regid=founderizer-egress --init-groups -- /usr/bin/python3 -I "
               f"{vault.EGRESS_SAFE} egress --config {vault.EGRESS_CONF} --check")
    # the message is 431 characters; a cut of 300 left out its start, which the test reads (seen 19 November 2026)
    got["later policy: check"] = (check.returncode, (check.stdout + check.stderr).strip()[-1000:])
    sh("rm -f /var/lib/founderizer-egress/policy.json")
    got["listeners"] = sh("ss -Hltnu | awk '{print $5}' | sort -u").stdout.split()
    got["gate output"] = open("/tmp/gate.out").read()[-3000:]
    got["world ipv6"] = sh("ip netns exec world ss -Hltn").stdout[-500:]
    print("RESULT " + json.dumps(got))


if __name__ == "__main__":
    if sys.argv[1:] == ["--inside"]:
        inside()
    else:
        unittest.main()
