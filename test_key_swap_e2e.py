"""The key swap, end to end, in one Docker container (VAULT.md, "The key swap"). It runs only when the variable
FLEET_KEY_SWAP_E2E=1 asks for it: it starts a container and installs a package, and no ordinary test run does that.

    FLEET_KEY_SWAP_E2E=1 python3 -m unittest test_key_swap_e2e

Inside the container, as on a server: the real vault.py as the broker (user fleet-vault) and as the swap proxy (user
founderizer-swap, on port 876), the real age program, two agent users (fleet-alpha, fleet-beta), each with a key of
its own for the same site, a stub hub, and two local HTTPS sites whose certificates the system trusts. The helper's
own step (fleet.read_env) gives each agent's session its variables. Then curl, Node and Python call the site as the
agent's user. It proves:

  the key reaches its site, with each of the three clients;
  no variable of the session and no file of the agent has the key;
  another host gets the placeholder, and a direct connection too;
  the placeholder of another agent of the same server is refused;
  the end of the grant stops the next request, and the grant given again works with the same placeholder;
  a hub that does not answer is a refusal;
  the proxy's CA for the site is not taken for another host;
  a new vault program takes over from the proxy that runs, with no cut: a tunnel from before still passes bytes, a
  key call works after it, and the old process ends after its tunnel (with a stand-in for systemd's notify socket);
  a new vault program whose proxy does not start is not taken: the proxy that runs goes on.

All keys are made up. Nothing is written outside the container, which is removed at the end."""
import json
import os
import shutil
import subprocess
import sys
import unittest

IMAGE = "node:24-trixie"            # Debian 13, with python3 (3.13: the helper needs 3.12), curl, openssl, Node 24
KIT = os.path.dirname(os.path.abspath(__file__))
SITE, OTHER = "api.example.test", "files.example.test"
KEYS = {"alpha": "sk-example-alpha-0123456789abcdefghij", "beta": "sk-example-beta-zyxwvutsrqponmlkjihg"}
REFS = {"alpha": "bws://11111111-2222-4333-8444-55555555555a", "beta": "bws://11111111-2222-4333-8444-55555555555b"}
AGENT_KEYS = {"alpha": "A" * 43, "beta": "B" * 43}


def docker():
    """True when Docker answers on this machine."""
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(os.environ.get("FLEET_KEY_SWAP_E2E") == "1", "set FLEET_KEY_SWAP_E2E=1 to run it: it starts a "
                     "Docker container")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not docker():
            raise unittest.SkipTest("Docker does not answer on this machine")
        # The proxy's port is below 1024, and a server keeps it from its users: the same setting as a server's.
        done = subprocess.run(["docker", "run", "--rm", "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024",
                               "-v", f"{KIT}:/kit:ro", IMAGE, "python3", "/kit/test_key_swap_e2e.py", "--inside"],
                              capture_output=True, text=True, timeout=1500)
        cls.log = done.stdout[-6000:] + done.stderr[-6000:]
        lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
        if done.returncode != 0 or not lines:
            raise AssertionError("the container's run did not end with its result:\n" + cls.log)
        cls.got = json.loads(lines[-1][7:])

    def test_the_key_reaches_its_site_with_each_client(self):
        self.assertEqual(self.got["reaches"], {"curl": "key of alpha", "node": "key of alpha", "python": "key of alpha",
                                               "curl basic": "placeholder refused by the proxy"}, self.log)

    def test_the_session_never_holds_the_key(self):
        self.assertRegex(self.got["variable"], r"^vaultswap_[0-9a-f]{40}$")
        self.assertEqual(self.got["key in the session's variables"], False)
        self.assertEqual(self.got["key in the agent's files"], False)
        self.assertEqual(self.got["agent reads the vault's files"], False)
        self.assertEqual(self.got["agent opens the proxy's socket of the broker"], "no answer")

    def test_another_host_and_a_direct_connection_get_the_placeholder(self):
        self.assertEqual(self.got["other host"], {"curl": "placeholder", "python": "placeholder"})
        self.assertEqual(self.got["direct"], "placeholder")
        self.assertEqual(self.got["site's CA for another host"], {"curl": "refused", "node": "refused", "python": "refused"})

    def test_another_agents_placeholder_is_refused_and_its_own_works(self):
        self.assertEqual(self.got["beta with the placeholder of alpha"], 403)
        self.assertEqual(self.got["beta with its own"], "key of beta")
        self.assertNotEqual(self.got["variable"], self.got["variable of beta"])

    def test_the_end_of_the_grant_stops_the_next_request(self):
        self.assertEqual(self.got["after the end of the grant"], {"status": 403, "site got a request": False})
        self.assertEqual(self.got["grant given again"], "key of alpha")

    def test_a_hub_that_does_not_answer_is_a_refusal(self):
        self.assertEqual(self.got["hub does not answer"], {"status": 503, "site got a request": False})
        self.assertEqual(self.got["hub answers again"], "key of alpha")

    def test_a_new_program_takes_over_with_no_cut_of_an_open_connection(self):
        self.assertEqual(self.got["hand-over"], {
            "a normal start says": "READY=1", "a tunnel before it": "open",
            "the new process says": "MAINPID=<pid>\nREADY=1",
            "the new process is another one, started to take over": True,
            "the old process lives on with its tunnel": True, "a key call after it": "key of alpha",
            "the tunnel from before still works": "other", "the old process ended after its tunnel": 0}, self.log)

    def test_a_new_program_whose_proxy_does_not_start_is_not_taken(self):
        self.assertEqual(self.got["take-back"], {"systemd hears": "MAINPID=<the process that serves>",
                                                 "the main process is still there": True,
                                                 "a key call": "key of alpha", "the proxy's log says why": True}, self.log)

    def test_the_two_processes_run_as_their_own_users(self):
        self.assertEqual(self.got["users"], {"broker": "fleet-vault", "proxy": "founderizer-swap"})
        self.assertEqual(self.got["modes"], {"/run/fleet-vault": "751", "/run/fleet-vault/vault.sock": "660",
                                             "/run/fleet-vault/swap.sock": "666", "/var/lib/fleet-vault-swap": "700"})


# ---------------------------------------------------------------- inside the container, as root

HUB = r'''
import http.server, hmac, hashlib, json, os, sys
KEYS, REFS, SITE = json.loads(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3]
def token(agent): return hmac.new(b"stub hub", (agent + REFS[agent]).encode(), hashlib.sha256).hexdigest()
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        parts = self.path.strip("/").split("/")
        agent, what = parts[2], parts[3] if len(parts) > 3 else ""
        code, out = 404, {"error": "no such route"}
        if agent in REFS and what == "read" and self.headers.get("Authorization") == "Bearer " + KEYS[agent]:
            code, out = 200, {"ok": True, "secrets": [{"login": REFS[agent], "env": "SHOP_API_KEY",
                "fingerprint_salts": {"password": "a" * 32, "totp": "b" * 32},
                "site": "https://" + SITE, "form": "bearer", "swap": token(agent)}]}
        elif agent in REFS and what == "fingerprints":
            code, out = 200, {"ok": True, "login": body.get("login"), "stored": len(body.get("fingerprints") or []), "known": 0}
        elif agent in REFS and what == "swap":      # the grant is live while no file says that it ended
            live = not os.path.exists("/srv/hub/ended-" + agent) and body == {"login": REFS[agent],
                "site": "https://" + SITE, "form": "bearer", "swap": token(agent)}
            code, out = (200, {"ok": True, "login": REFS[agent]}) if live else (409, {"error": "no such grant now"})
        data = json.dumps(out).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
http.server.ThreadingHTTPServer(("127.0.0.1", 8765), H).serve_forever()
'''

HTTPS_SITE = r'''
import http.server, json, ssl, sys
name, ip, keys = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        auth = self.headers.get("Authorization") or ""
        got = next(("key of " + agent for agent, key in keys.items() if auth == "Bearer " + key), None) or \
            ("placeholder" if "vaultswap_" in auth else "other")
        with open("/var/log/e2e/" + name + ".log", "a") as f:
            f.write(json.dumps({"path": self.path, "got": got}) + "\n")
        out = (json.dumps({"got": got}) + "\n").encode()
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(out) + out)
    do_POST = do_GET
cert, key, port = (sys.argv[4], sys.argv[5], int(sys.argv[6])) if len(sys.argv) > 4 else \
    ("/world/" + name + ".leaf.pem", "/world/leaf.key", 443)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(cert, key)
s = http.server.ThreadingHTTPServer((ip, port), H); s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
'''

SESSION = r'''
import json, os, sys
os.environ["FLEET_HUB"] = "http://127.0.0.1:8765"
sys.path.insert(0, "/opt/kit")
import fleet
agent = sys.argv[1]
env = fleet.read_env(agent, {"runtime": "claude", "role": "worker", "can": ["shell"]}, "task")
print(json.dumps(env))
'''

# One tunnel through the proxy to another host that stays open: it says "open", waits for a file, and then sends one
# request through the same tunnel.
HOLD = r'''
import os, socket, ssl, sys, time
host, proxy = sys.argv[1], os.environ["HTTPS_PROXY"].split("://")[1]
s = socket.create_connection((proxy.split(":")[0], int(proxy.split(":")[1])), timeout=60)
s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
assert b" 200 " in s.recv(4096)
t = ssl.create_default_context().wrap_socket(s, server_hostname=host)
print("open", flush=True)
while not os.path.exists("/tmp/hold-go"):
    time.sleep(0.2)
t.sendall(f"GET /held HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
data = b""
while True:
    chunk = t.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.split(b"\r\n\r\n", 1)[1].decode().strip(), flush=True)
'''

NODE = ('fetch("https://%s/x", {headers: {Authorization: "Bearer " + process.env.SHOP_API_KEY}})'
        '.then(r => r.text()).then(t => console.log(t)).catch(e => console.log(JSON.stringify({got: "ERROR " + e.message})))')
PYTHON = ('import json, os, urllib.request\n'
          'r = urllib.request.Request("https://%s/x", headers={"Authorization": "Bearer " + os.environ["SHOP_API_KEY"]})\n'
          'try:\n    print(urllib.request.urlopen(r, timeout=30).read().decode())\n'
          'except Exception as e:\n    print(json.dumps({"got": "ERROR " + type(e).__name__}))\n')


def sh(script, check=True, **more):
    return subprocess.run(["bash", "-c", "set -eu\n" + script], capture_output=True, text=True, check=check, **more)


def as_user(user, argv, env=None, text=None):
    """One program as this user, with that user's own groups and home, and only this environment."""
    base = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": f"/home/{user}", "LANG": "C.UTF-8"}
    done = subprocess.run(["setpriv", "--reuid", user, "--regid", user, "--init-groups", "env", "-i",
                           *[f"{k}={v}" for k, v in dict(base, **(env or {})).items()], *argv],
                          capture_output=True, text=True, input=text, timeout=120)
    return done.stdout.strip(), done


def got(text):
    """What a client printed: what the site said that it got, or the proxy's own answer."""
    try:
        said = json.loads(text.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return "no answer: " + text[-200:]
    return said.get("got") or said.get("error") or said


def listens(port):
    """True when a program on this machine takes a connection on this port."""
    import socket
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        return True
    except OSError:
        return False


def listens_at(address, port):
    import socket
    try:
        socket.create_connection((address, port), timeout=2).close()
        return True
    except OSError:
        return False


def site_lines(name):
    try:
        with open(f"/var/log/e2e/{name}.log") as f:
            return [json.loads(line) for line in f]
    except OSError:
        return []


def inside():
    import pwd
    import time
    conf = "/etc/fleet-vault/vault.json"
    sh("export DEBIAN_FRONTEND=noninteractive\napt-get update -q >/dev/null\n"
       "apt-get install -y -q --no-install-recommends age util-linux >/dev/null")
    # the users of a server: the vault's, the proxy's, and two agents in the group of the agent users
    sh("groupadd -f fleet-agents\n"
       "useradd --system --home-dir /var/lib/fleet-vault --shell /usr/sbin/nologin fleet-vault\n"
       "useradd --system --user-group --home-dir /var/lib/fleet-vault-swap --shell /usr/sbin/nologin founderizer-swap\n"
       "for a in alpha beta; do useradd -m -G fleet-agents fleet-$a; chmod 700 /home/fleet-$a; done\n"
       "useradd -m site\n"
       "install -d -o root -g root -m 755 /usr/local/lib/fleet-vault /etc/fleet-vault /opt/kit /srv/hub\n"
       "install -o root -g root -m 644 /kit/vault.py /usr/local/lib/fleet-vault/vault.py\n"
       "install -d -o fleet-vault -g fleet-vault -m 700 /var/lib/fleet-vault\n"
       "install -d -o fleet-vault -g fleet-agents -m 750 /run/fleet-vault\n"           # as systemd makes it
       "install -d -o founderizer-swap -g founderizer-swap -m 700 /var/lib/fleet-vault-swap\n"
       "install -d -o founderizer-swap -g founderizer-swap -m 755 /run/fleet-vault-swap\n"
       "install -d -m 777 /var/log/e2e\nchown site /srv/hub\n"
       "cp /kit/*.py /opt/kit/ && cp -r /kit/prices /opt/kit/ 2>/dev/null || true\n")
    with open(conf, "w") as f:
        json.dump({"hub": "http://127.0.0.1:8765", "store": "/var/lib/fleet-vault/store.age",
                   "store_key": "/var/lib/fleet-vault/store.key", "age_key": "/var/lib/fleet-vault/age.key",
                   "socket": "/run/fleet-vault/vault.sock", "age": "/usr/bin/age", "curl": "/usr/bin/curl",
                   "worker_group": "fleet-agents",
                   "swap": {"user": "founderizer-swap", "vault": "fleet-vault", "port": 876,
                            "openssl": "/usr/bin/openssl"}}, f)
    os.chmod(conf, 0o644)
    sh(f"python3 /usr/local/lib/fleet-vault/vault.py store-init --config {conf} --user fleet-vault >/dev/null\n"
       "age-keygen -o /var/lib/fleet-vault/age.key 2>/dev/null\n"
       "chown fleet-vault:fleet-vault /var/lib/fleet-vault/age.key; chmod 600 /var/lib/fleet-vault/age.key")
    fill = ("import json, sys\nsys.path.insert(0, '/usr/local/lib/fleet-vault')\nimport vault\n"
            f"conf = vault.load_config({conf!r})\nstore = vault.LocalStore(conf)\n"
            "for ref, key in json.loads(sys.argv[1]):\n"
            "    store.put(ref[6:], 'SHOP_API_KEY', json.dumps({'username': '', 'password': key}), vault.DELIVERED)\n")
    out, done = subprocess.run(["setpriv", "--reuid", "fleet-vault", "--regid", "fleet-agents", "--clear-groups",
                                "python3", "-c", fill, json.dumps([[REFS[a], KEYS[a]] for a in KEYS])],
                               capture_output=True, text=True), None
    assert out.returncode == 0, out.stderr
    # two HTTPS sites whose certificates the system trusts, as a public CA's are: the vault's own code makes them,
    # as a second set that the proxy never sees
    world = ("import sys\nsys.path.insert(0, '/usr/local/lib/fleet-vault')\nimport vault\n"
             "a = vault.SwapAuthority('/world', '/world/public', '/usr/bin/openssl')\n"
             f"[a.context(h) for h in ({SITE!r}, {OTHER!r})]\n")
    sh("mkdir -p /world/public")
    subprocess.run(["python3", "-c", world], check=True)
    sh(f"for h in {SITE} {OTHER}; do cp /world/public/$h.pem /usr/local/share/ca-certificates/example-$h.crt; done\n"
       "update-ca-certificates >/dev/null 2>&1\nchmod 644 /world/*.pem /world/leaf.key\n"
       f"printf '127.0.0.2 {SITE}\\n127.0.0.3 {OTHER}\\n' >> /etc/hosts")
    running = []

    def start(argv, **more):
        running.append(subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=open("/var/log/e2e/servers.err", "a"),
                                        **more))
        return running[-1]
    for name, ip in ((SITE, "127.0.0.2"), (OTHER, "127.0.0.3")):
        start(["python3", "-c", HTTPS_SITE, name, ip, json.dumps(KEYS)])

    def start_hub():
        return start(["setpriv", "--reuid", "site", "--regid", "site", "--clear-groups", "python3", "-c", HUB,
                      json.dumps(AGENT_KEYS), json.dumps(REFS), SITE])
    hub = start_hub()

    def start_broker():
        return start(["setpriv", "--reuid", "fleet-vault", "--regid", "fleet-agents", "--clear-groups", "bash", "-c",
                      f"umask 077; exec python3 /usr/local/lib/fleet-vault/vault.py serve --config {conf}"])

    def start_proxy(notify=None):
        """The proxy as its unit starts it. notify: a stand-in for systemd's socket, as NotifyAccess=all gives it."""
        return start(["setpriv", "--reuid", "founderizer-swap", "--regid", "founderizer-swap", "--clear-groups",
                      "--inh-caps", "+net_bind_service", "--ambient-caps", "+net_bind_service", "env",
                      "STATE_DIRECTORY=/var/lib/fleet-vault-swap", "RUNTIME_DIRECTORY=/run/fleet-vault-swap",
                      *(["NOTIFY_SOCKET=" + notify] if notify else []), "bash", "-c",
                      f"umask 077; exec python3 /usr/local/lib/fleet-vault/vault.py swap --config {conf}"])

    def up():
        for _ in range(100):            # until both sockets and the proxy's port are there
            if os.path.exists("/run/fleet-vault/swap.sock") and listens(876):
                return
            time.sleep(0.2)
        raise SystemExit("the broker or the proxy did not start:\n" + open("/var/log/e2e/servers.err").read()[-3000:])
    broker, proxy = start_broker(), start_proxy()
    up()
    # the helper's own checkout: this kit, with a team of the two agents
    with open("/opt/kit/team.json", "w") as f:
        json.dump({"hub": {"machine": "hub", "port": 8765}, "addresses": {"hub": "127.0.0.1", "app-1": "127.0.0.1"},
                   "agents": {a: {"role": "worker", "runtime": "claude", "machine": "app-1", "can": ["shell"],
                                  "vault": "broker", "secrets": {REFS[a]: "read"}} for a in KEYS}}, f)
    result, envs = {}, {}
    for agent in KEYS:
        user = "fleet-" + agent
        sh(f"install -d -o {user} -g {user} -m 700 /home/{user}/.fleet\n"
           f"printf %s {AGENT_KEYS[agent]} > /home/{user}/.fleet/agent-{agent}.key\n"
           f"chown {user}:{user} /home/{user}/.fleet/agent-{agent}.key; chmod 600 /home/{user}/.fleet/agent-{agent}.key")
        out, done = as_user(user, ["python3", "-c", SESSION, agent])
        try:
            envs[agent] = json.loads(out.splitlines()[-1])
        except (ValueError, IndexError):
            raise SystemExit(f"the helper's step of {agent} gave no variables:\n{out}\n{done.stderr[-3000:]}")
        if "HTTPS_PROXY" not in envs[agent]:
            raise SystemExit(f"the session of {agent} got no proxy variables: {envs[agent]}\n{done.stderr[-2000:]}")
    alpha, beta = envs["alpha"], envs["beta"]
    result["variable"], result["variable of beta"] = alpha["SHOP_API_KEY"], beta["SHOP_API_KEY"]
    result["key in the session's variables"] = any(key in json.dumps(envs) for key in KEYS.values())
    found = sh("grep -rl -e '" + "' -e '".join(KEYS.values()) + "' /home/fleet-alpha /home/fleet-beta /run/fleet-vault-swap "
               "2>/dev/null | head -3", check=False).stdout.strip()
    result["key in the agent's files"] = bool(found)
    out, done = as_user("fleet-alpha", ["bash", "-c", "cat /var/lib/fleet-vault/store.key /var/lib/fleet-vault/store.age "
                                        "/var/lib/fleet-vault/swaps.json /var/lib/fleet-vault-swap/leaf.key 2>&1; echo rc=$?"])
    result["agent reads the vault's files"] = "rc=0" in out
    ask = ("import json, socket\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(10)\n"
           "try:\n    s.connect('/run/fleet-vault/swap.sock')\n"
           "    s.sendall((json.dumps({'op': 'swap', 'uid': %d, 'host': %r, 'port': 443, 'name': %r, 'form': 'bearer'}) + '\\n').encode())\n"
           "    print(s.recv(4096).decode() or 'no answer')\nexcept OSError:\n    print('no answer')\n"
           % (pwd.getpwnam("fleet-alpha").pw_uid, SITE, alpha["SHOP_API_KEY"]))
    result["agent opens the proxy's socket of the broker"] = as_user("fleet-alpha", ["python3", "-c", ask])[0]

    def call(agent, client, host=SITE, env=None, extra=()):
        env = dict(envs[agent] if env is None else env)
        if client == "curl":
            argv = ["curl", "-sS", "-m", "60", *extra, "-H", "Authorization: Bearer " + env["SHOP_API_KEY"], f"https://{host}/x"]
        elif client == "node":
            argv = ["node", "-e", NODE % host]
        else:
            argv = ["python3", "-c", PYTHON % host]
        out, done = as_user("fleet-" + agent, argv, env)
        return got(out or done.stderr)
    result["reaches"] = {client: call("alpha", client) for client in ("curl", "node", "python")}
    out, done = as_user("fleet-alpha", ["curl", "-sS", "-m", "60", "-o", "/dev/null", "-w", "%{http_code}", "-u",
                                        alpha["SHOP_API_KEY"] + ":", f"https://{SITE}/x"], alpha)
    # the key's form is bearer: as the user name of Basic, the broker gives no value
    result["reaches"]["curl basic"] = "placeholder refused by the proxy" if out == "403" else out
    result["other host"] = {client: call("alpha", client, OTHER) for client in ("curl", "python")}
    result["direct"] = call("alpha", "curl", extra=("--noproxy", "*"))
    # The limit of the site's CA: root, which reads the proxy's CA key here, signs a certificate for the other host
    # with the CA of the key's site, and serves it. The session trusts that CA, and must still refuse this host.
    forge = ("cd /tmp && printf 'subjectAltName=DNS:%(o)s\\nbasicConstraints=critical,CA:FALSE\\nextendedKeyUsage=serverAuth\\n"
             "subjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid:always\\n' > f.ext\n"
             "openssl ecparam -name prime256v1 -genkey -noout -out f.key\n"
             "openssl req -new -key f.key -subj /CN=x -out f.csr\n"
             "openssl x509 -req -in f.csr -CA /var/lib/fleet-vault-swap/%(s)s.ca.pem -CAkey /var/lib/fleet-vault-swap/%(s)s.ca.key "
             "-set_serial 0x77 -days 2 -sha256 -extfile f.ext -out f.pem 2>/dev/null\nchmod 644 f.pem f.key\n"
             % {"o": OTHER, "s": SITE})
    sh(forge)
    start(["python3", "-c", HTTPS_SITE, OTHER, "127.0.0.3", json.dumps(KEYS), "/tmp/f.pem", "/tmp/f.key", "8443"])
    for _ in range(50):
        if listens_at("127.0.0.3", 8443):
            break
        time.sleep(0.2)
    limit = {}
    for client, argv in (("curl", ["curl", "-sS", "-m", "30", "--noproxy", "*", f"https://{OTHER}:8443/x"]),
                         ("node", ["node", "-e", (NODE % (OTHER + ":8443")).replace("process.env.SHOP_API_KEY", '"x"')]),
                         ("python", ["python3", "-c", (PYTHON % (OTHER + ":8443")).replace('os.environ["SHOP_API_KEY"]', '"x"')])):
        direct = {k: v for k, v in alpha.items() if k not in ("HTTPS_PROXY", "https_proxy")}
        out, done = as_user("fleet-alpha", argv, direct)
        limit[client] = "refused" if done.returncode != 0 or "ERROR" in out else "taken: " + out[-80:]
    result["site's CA for another host"] = limit

    def status(agent, placeholder):
        before = len(site_lines(SITE))
        out, done = as_user("fleet-" + agent, ["curl", "-sS", "-m", "60", "-o", "/dev/null", "-w", "%{http_code}", "-H",
                                               "Authorization: Bearer " + placeholder, f"https://{SITE}/x"], envs[agent])
        return {"status": int(out) if out.isdigit() else out, "site got a request": len(site_lines(SITE)) > before}
    result["beta with the placeholder of alpha"] = status("beta", alpha["SHOP_API_KEY"])["status"]
    result["beta with its own"] = call("beta", "curl")
    open("/srv/hub/ended-alpha", "w").close()                   # the owner ends the grant of alpha
    result["after the end of the grant"] = status("alpha", alpha["SHOP_API_KEY"])
    os.unlink("/srv/hub/ended-alpha")
    result["grant given again"] = call("alpha", "curl")
    hub.kill()
    hub.wait()
    result["hub does not answer"] = status("alpha", alpha["SHOP_API_KEY"])
    start_hub()
    for _ in range(50):
        if listens(8765):
            break
        time.sleep(0.2)
    result["hub answers again"] = call("alpha", "curl")
    users = sh("ps -eo user:20,args | grep '[v]ault.py'").stdout
    result["users"] = {"broker": next(line.split()[0] for line in users.splitlines() if " serve " in line),
                       "proxy": next(line.split()[0] for line in users.splitlines() if " swap " in line)}
    result["modes"] = {path: oct(os.stat(path).st_mode & 0o777)[2:] for path in
                       ("/run/fleet-vault", "/run/fleet-vault/vault.sock", "/run/fleet-vault/swap.sock",
                        "/var/lib/fleet-vault-swap")}
    # ---- a new vault program: the proxy gives way to it with no cut, and a program whose proxy fails is not taken
    import socket
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify.bind("/run/e2e-notify.sock")
    os.chmod("/run/e2e-notify.sock", 0o666)
    notify.settimeout(30)

    def told():
        try:
            return notify.recv(4096).decode()
        except OSError:
            return "nothing"

    def new_program(words):
        """A release: another program file, and the broker starts again on it, as fleet-vault-program does."""
        nonlocal broker
        sh(f"printf '\\n# {words}\\n' >> /usr/local/lib/fleet-vault/vault.py")
        broker.kill()
        broker.wait()
        broker = start_broker()
        for _ in range(100):            # until the broker answers the proxy again; the proxy then sees its new program
            if call("alpha", "curl") == "key of alpha":
                return
            time.sleep(0.2)
    proxy.kill()
    proxy.wait()
    proxy = start_proxy("/run/e2e-notify.sock")         # as under the unit with NotifyAccess=all
    up()
    handover = {"a normal start says": told()}
    hold = subprocess.Popen(["setpriv", "--reuid", "fleet-alpha", "--regid", "fleet-alpha", "--init-groups", "env", "-i",
                             *[f"{k}={v}" for k, v in dict(alpha, PATH="/usr/bin:/bin", HOME="/home/fleet-alpha").items()],
                             "python3", "-c", HOLD, OTHER], stdout=subprocess.PIPE, text=True)
    handover["a tunnel before it"] = hold.stdout.readline().strip()
    new_program("a newer program")                      # its calls also let the proxy see the broker's new program
    said = told()
    main = int(said.split("MAINPID=")[1].split()[0]) if "MAINPID=" in said else 0
    handover["the new process says"] = said.replace(str(main), "<pid>")
    time.sleep(2)                                       # the old process looks each second, then closes its listener
    handover["the new process is another one, started to take over"] = bool(main) and main != proxy.pid and \
        "--take" in open(f"/proc/{main}/cmdline").read().replace("\0", " ")
    handover["a key call after it"] = call("alpha", "curl")
    time.sleep(8)                                       # longer than the old process's grace (vault.SWAP_GRACE)
    handover["the old process lives on with its tunnel"] = proxy.poll() is None
    open("/tmp/hold-go", "w").close()
    handover["the tunnel from before still works"] = got(hold.communicate(timeout=60)[0])
    for _ in range(100):
        if proxy.poll() is not None:
            break
        time.sleep(0.2)
    handover["the old process ended after its tunnel"] = proxy.poll()
    result["hand-over"] = handover
    # a program whose proxy cannot start (its own check of its state folder fails): the proxy that runs goes on
    os.chmod("/var/lib/fleet-vault-swap", 0o755)
    new_program("a program whose proxy fails")
    notify.settimeout(4)
    # the proxy that runs tells systemd again that it is the main process: the candidate can have said otherwise
    refused = {"systemd hears": told().replace(str(main), "<the process that serves>"),
               "the main process is still there": os.path.exists(f"/proc/{main}"),
               "a key call": call("alpha", "curl"),
               "the proxy's log says why": "did not start (exit 1)" in open("/var/log/e2e/servers.err").read()}
    os.chmod("/var/lib/fleet-vault-swap", 0o700)
    result["take-back"] = refused
    sh("pkill -f 'vault.py swap' || true", check=False)
    for process in running:
        process.kill()
    print("RESULT " + json.dumps(result))
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--inside"]:
        sys.exit(inside())
    unittest.main()
