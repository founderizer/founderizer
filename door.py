#!/usr/bin/env python3
"""The door (DevOps plan version 44, section 2, "The door"): one small Fleet service on a server of its own. Every
write of an Operator and every read of a host passes through it. Standard library only.

    python3 door.py serve           the service, as the OS user `door` (door.sh installs it)
    python3 door.py access          root: the access file, one JSON object on stdin (the owner's app writes it)
    python3 door.py update          root: a signed release manifest on stdin; the code of that release, never an
                                    older one, cloned from the public repository at that revision
    python3 door.py hub-secrets     root: the hub's two secrets, made here; their SHA-256 stays, the secrets go once
                                    to stdout for the hub's own file
    python3 door.py render-check    what the render box can reach, as one JSON line; status 0 when it is closed
    python3 door.py status          one line

Who may ask. The door knows a caller by its tailnet address, which Tailscale proves, and only by that: the access file
names each agent's address and what it holds, and each business's repository pool. Only root writes that file,
through `door.py access`, and it refuses an address that two agents share, so the hub can name no agent and add no
grant or pool. The hub has two rights of its own, each with its own secret: ask for a GitHub token (POST /github/token)
for a grant that it names, which the door makes inside the agent's business pool or its own grants only, with the
reading of what the door's App reaches (GET /github/reach) and the state of one App key (POST /github/key: its
fingerprint and whether GitHub takes it, never the key) for the same secret, and read the record (GET /record).

What it does. A call is a rule call (code passes it at once), the agent's own call (code does not list it as a rule,
but the agent's grant covers it: it runs, and the agent answers for it), a call that the next mode allows (a host's
`run`, a root script with no box), or a refusal (door_targets.py). The door calls no model. A delete of what no agent
made through the door, every AWS delete, and a call that the next mode allows are the owner's: his signed yes lets that
exact call through once, and the refusal gives the call's hash for it. His signed Full access on a host (a mode
statement, which the hub carries as it carries his yeses) lets every such call on that host through, and Auto is the
default. Every refusal names its route (ROUTES). Writes on
one host wait for each other, one reboot-class call runs at a time in each business, and inside a window of the access
file a deploy, a restart, a script or a reboot is refused. A script or a run arms the host's rollback timer first, and
the door ends the countdown when the host answers it after the call. Each host takes the host parts of the release that
the door runs (update_hosts, by ops-root's self-update), within a minute of the door's start on that release.
A commit on a GitOps repository is decided on what it makes a cluster apply: a box with no network and no key of the
door renders each chart and each Kustomize folder that the commit touches (door_render.py, ensure_render), and a door
that has no box keeps the rules that need no render.
Every call leaves one numbered line in the record, which the hub reads each minute; if the hub is down, the door
still works. No value reaches an agent: the door's tokens and keys are secrets of the central vault with the door as
their holder, sealed to the door's own key, and only this OS user opens them. Where a provider has an API that makes
keys, the key that the owner saves once can be one that only makes keys: the door then makes its own work key from it,
with the rights that its rules need, which the provider ends after a day, and the door ends it when the grant ends
(door_providers.cloudflare_work_key, end_keys).
"""
import argparse
import base64
import calendar
import contextlib
import datetime
import hashlib
import hmac
import io
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # python3 -I leaves the code's own folder out
import door_providers       # noqa: E402
import door_render          # noqa: E402  the helper of the render box, and the pins of its two programs
import door_targets         # noqa: E402
import vault                # noqa: E402  the central vault's own check of an owner's signed statement

DOOR_PORT = 8766            # the door's service on the private network (the tailnet policy opens it, plan 2.7)
SSHD_PORT = 2244            # the second sshd on every managed host (host/install.sh; the policy opens it to tag:door)
ETC = "/etc/fleet-door"
STATE = "/var/lib/fleet-door"
CODE = "/opt/fleet-door"
ACCESS_FILE = ETC + "/access.json"          # root writes it; the door's user reads it
CONF_FILE = ETC + "/door.json"              # door.sh writes it: the address and the port
HUB_FILE = ETC + "/hub.json"                # the SHA-256 of the hub's two secrets
KEY_FILE = ETC + "/release-key.pub"         # the release keys, pinned at install
EARLY_FILE = ETC + "/early-key.pub"         # and the early ones (releases.every_key), when the install had them
FLOOR_FILE = ETC + "/floor"                 # the revision the door runs; update never moves below it
RELEASE_JSON = ETC + "/release.json"        # the signed manifest of that release, which root keeps for the hosts
HOSTS_FILE = STATE + "/hosts.json"          # each host's self-update: the release that it was sent, and how it ended
HOST_FILES = ("ops-root", "ops-read", "inventory", "app-release")     # what self-update takes (host/ops-root)
HOST_RETRY = 3600                           # seconds before a host that did not answer is asked again for a release
RECORD_FILE = STATE + "/record.jsonl"
MINTED_FILE = STATE + "/minted.json"        # ids of the keys this door minted (never their values)
MADE_FILE = STATE + "/made.json"            # names of what writes through the door made, by provider account (D25)
REMOVED_FILE = STATE + "/removed.json"      # objects that GitOps commits through the door removed, for a prune (X3)
REMOVED_DAYS = 30                           # a removal older than this is no longer the door's own for a prune
REPOS_FILE = STATE + "/repos.json"          # the repositories that the door made, and a repo-new that is pending (N3)
ACCOUNTS_FILE = STATE + "/accounts.json"    # the Cloudflare account of a token whose credential names none (plan N1)
KEYS_FILE = STATE + "/keys.json"            # what each saved Cloudflare key is, and the work keys that the door made
KEY_SAID_AGAIN = 600                        # seconds before the same failure of a work key gets a second record line
SECRETS_DIR = STATE + "/secrets"            # opened values, one file each, mode 600, this user only
VAULT_KEY = STATE + "/vault.key"            # the door's own age identity (its recipient is pinned in the vault)
SSH_KEY = STATE + "/ssh/id_ed25519"         # the door's SSH key to the second sshd of each host
AWS_TOKEN_FILE = "/opt/machine-id/jwt_svid"  # the door's own Teleport bot writes its JWT-SVID here (plan 5.4)
RENDERED_FILE = STATE + "/rendered.json"    # the GitOps repositories whose commits this door has rendered
APPROVALS_FILE = STATE + "/approvals.json"  # the owner's signed yeses for exact calls that are his, from the hub
APPROVED_FILE = STATE + "/approved.json"    # the yeses that were used: each lets its one call through once
APPROVAL_DAYS = 7                           # a signed yes older than this lets nothing through
DEVICES_FILE = STATE + "/devices.json"      # the owner's phones whose signing key his owner key certified
MODES_FILE = STATE + "/modes.json"          # the owner's signed mode of each host: the newest statement of each
MODES = ("auto", "full")                    # door-modes proposal, step 4: Auto, the default, and Full access
MODES_READ = 2000                           # statements that the door reads of one answer of the hub: the hub serves
                                            # the newest of every server first, the held ones before the others,
                                            # then the older ones; a signed Auto past the cut would leave Full
                                            # access standing (it was 200)
MODE_CHECKS = 8                             # signature checks of one host's statements in one refresh: the hub serves
                                            # its newest 5 of each host (hub.DOOR_MODES_KEPT)
MODE_SKEW = 300                             # seconds that the clock of the owner's Mac may be behind the door's
UPSTREAM = "https://github.com/founderizer/founderizer.git"
SYSTEMD = "/etc/systemd/system"
FOLLOW_UNIT = "fleet-door-follow"           # the root timer by which the door takes each signed release (plan 13.2)
FOLLOW_SERVICE = """[Unit]
Description=The door takes the hub's signed release (Founderizer)
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /opt/fleet-door/current/door.py follow
ProtectHome=yes
PrivateTmp=yes
"""
FOLLOW_TIMER = """[Unit]
Description=The door asks the hub for its release every 10 minutes (Founderizer)

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
"""
# The render box (door_render.py): systemd starts one instance of the service for each connection to the socket, as a
# user of its own that exists for that run, with no network, no socket of any family and no path of the door's keys.
# The door's own service has no capability, so it can start no unit: it only connects.
RENDER_UNIT = "fleet-door-render"
RENDER_SOCKET = "/run/fleet-door-render.sock"
RENDER_SOCKET_UNIT = """[Unit]
Description=The render box of the door: one instance for each GitOps commit (Founderizer)

[Socket]
ListenStream=/run/fleet-door-render.sock
SocketUser=root
SocketGroup=door
SocketMode=0660
Accept=yes
MaxConnections=4

[Install]
WantedBy=sockets.target
"""
RENDER_SERVICE = """[Unit]
Description=One render of a chart or a Kustomize folder, with no network and no key (Founderizer)
CollectMode=inactive-or-failed

[Service]
ExecStart=/usr/bin/python3 -I /opt/fleet-door/current/door_render.py box
StandardInput=socket
StandardOutput=socket
StandardError=journal
DynamicUser=yes
PrivateNetwork=yes
RestrictAddressFamilies=none
IPAddressDeny=any
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateUsers=yes
PrivateIPC=yes
InaccessiblePaths=-/etc/fleet-door -/var/lib/fleet-door -/opt/machine-id -/dev/shm -/run/tailscale -/var/lib/tailscale
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
KeyringMode=private
UMask=0077
RuntimeMaxSec=150
TimeoutStopSec=5
MemoryMax=1G
TasksMax=256
LimitNOFILE=4096
LimitCORE=0
"""
RENDER_WAIT = 170           # seconds that the door waits for the box, which systemd stops after 150
RENDER_ANSWER_MAX = 32 * 1024 * 1024
TOOL_MAX = 128 * 1024 * 1024    # bytes of one archive of a pinned program
REBOOT_BACK = 900           # seconds a reboot-class call holds its business while the host comes back
BODY_MAX = 512 * 1024
RECORD_PAGE = 500
RECORD_TEXT = 300           # characters of one field of a record line: a caller's own words are cut to it
# Bytes that the door reads of one host's answer. ops-read cuts its own at 256 KiB of text and ops-root at 64 KiB, so
# no form needs more, and a host that writes more is stopped.
HOST_OUT_MAX = 2 * 1024 * 1024
HELP_WAIT = 60              # seconds for a host's help, which the host sweep asks of each host in turn
GITHUB_REACH_PAGES = 30     # pages of 100 repositories that the door reads of one installation, at most
# The permissions of an agent's token at each grant level. A read or write token also gets actions: read where the
# installation holds Actions, and a token of each level gets issues where the installation holds Issues: read at read,
# write at write and deploy (token_permissions).
GITHUB_ACCESS = {"read": {"contents": "read", "pull_requests": "read", "metadata": "read"},
                 "write": {"contents": "write", "pull_requests": "write", "metadata": "read"},
                 "deploy": {"contents": "write", "pull_requests": "write", "metadata": "read",
                            "workflows": "write", "actions": "write"}}
NAME = re.compile(r"[a-z][a-z0-9-]{1,30}")
HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
REF = re.compile(r"bws://[0-9a-f-]{36}", re.I)
# new-projects plan N4: a key that the owner saved for one setting of one app, app:<app>:<NAME>
APP_KEY = re.compile(r"app:" + door_targets.OPS_ROOT.APP_NAME.pattern + ":" + door_targets.OPS_ROOT.ENV_NAME.pattern)
ROLE = re.compile(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}")
HOST_KEY = re.compile(r"ssh-ed25519 [A-Za-z0-9+/=]{60,100}")
WINDOW_CLASSES = ("upgrade", "restart", "reboot", "deploy", "tailscale")
APPROVAL_NOTE = (" Its call hash is {sha}: a Needs-you item that names it (raise_needs_you door_call) lets this exact "
                 "call through once, when the owner answers yes.")
FULL_NOTE = (" Its second answer, Full access on {host} (raise_needs_you door_host), lets it and every later root script "
             "on {host} through.")
# The route of a refusal, in the door's answer (door-modes proposal, step 1: "a door refusal names its route"); ops
# prints it. yes: the owner's signed yes to the call hash that the answer gives lets that exact call through once.
# holder: the agent lacks the grant, and the agent that holds it does that part (needs names it as ask_my_requester's
# needs_access takes it, with its level). window: the owner's window refuses it now, and it runs outside the window.
# again: the door could not check it now. none: no grant and no yes lets this call through: the call or the plan
# changes.
ROUTES = ("yes", "holder", "window", "again", "none")
TIMER_TRIES = 6             # times that the door asks a host to end its rollback countdown after a script or a run
TIMER_PAUSE = 10            # seconds between them, while the host does not answer
RUN_WAIT = 50 * 60          # how long a GitOps sync's call waits for its run to end: less than an agent's ops call waits
RUN_POLL = 15               # seconds between two reads of that run
RUN_FIND = 60               # seconds in which the run of a dispatch whose answer gave no run id must show up
LOG_MOST = 1024 * 1024      # bytes of a job's log that the door reads: a listing run prints one line
LOG_TRIES = 3               # reads of a job's log that GitHub does not give yet, when its job just ended
LOG_PAUSE = 5               # seconds between them
CHECKS_FIND = 45            # seconds after a GitOps commit in which its push's runs show up, the late ones too
CHECKS_WAIT = 20 * 60       # how long the commit's call waits for those runs to end


class Refused(Exception):
    pass


def P(path):
    return os.environ.get("FLEET_DOOR_ROOT", "") + path


def now():
    return time.time()


def read_json(path, default):
    try:
        with open(P(path), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o600, group=None):
    """The file, replaced whole. group: root's file for that group, set before the replace, so that no reader of the
    group finds a file that it cannot read yet."""
    folder = os.path.dirname(P(path))
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=folder, prefix=".door-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True)
            if group is not None:
                with contextlib.suppress(OSError):
                    os.fchown(f.fileno(), 0, group)
        os.chmod(temp, mode)
        os.replace(temp, P(path))
    finally:
        with contextlib.suppress(OSError):
            os.remove(temp)


# ---------------------------------------------------------------- the access file

def tailnet_address(text):
    """True for an address of the private network: 100.64.0.0/10 or Tailscale's IPv6 range."""
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return False
    return a in ipaddress.ip_network("100.64.0.0/10") or a in ipaddress.ip_network("fd7a:115c:a1e0::/48")


def own_servers(data):
    """{address: "hub" or "door"}: the hub's server and the door's own, by address, however an IPv6 address is
    written. The door reads its own address from the file that door.sh wrote; a test has none, and then only the hub's
    counts. On such a server an agent's own call, a file install or a script, would reach the central vault or the
    door's keys, so a host at one of these addresses is rule-only (own_server)."""
    out, hub = {}, data.get("hub") if isinstance(data.get("hub"), dict) else {}
    for who, text in (("door", read_json(CONF_FILE, {}).get("address")), ("hub", hub.get("address"))):
        with contextlib.suppress(ValueError):
            if isinstance(text, str):
                out[ipaddress.ip_address(text)] = who
    return out


def own_server(own, host):
    """"hub" or "door" for a host at one of the addresses of own_servers, or None."""
    try:
        return own.get(ipaddress.ip_address(host.get("address"))) if isinstance(host.get("address"), str) else None
    except ValueError:
        return None


def validate_access(data):
    """The access file, checked whole: ValueError with the first thing wrong. An address that two agents share, or
    the hub's address on an agent, is refused, because the door tells callers apart by address alone."""
    if not isinstance(data, dict) or data.get("v") != 1:
        raise ValueError("the access file is {v: 1, ...}")
    known = {"v", "hub", "agents", "hosts", "credentials", "windows", "never", "workflows", "exposure", "pools",
             "images", "owner_keys", "fleet"}
    if set(data) - known:
        raise ValueError(f"unknown field {sorted(set(data) - known)[0]}")
    hub = data.get("hub") or {}
    if not tailnet_address(hub.get("address", "")) or not isinstance(hub.get("port", 8765), int):
        raise ValueError("hub is {address, port}: the hub's address on the private network")
    keys = data.get("owner_keys")       # the owner's public keys, which sign his yes to an exact call (approval)
    if keys is not None and (not isinstance(keys, list) or not 1 <= len(keys) <= vault.OWNER_KEYS):
        raise ValueError(f"owner_keys lists 1 to {vault.OWNER_KEYS} public keys of the owner")
    for key in keys or []:
        try:
            vault.owner_key(key)
        except ValueError:
            raise ValueError("each of owner_keys is the base64 of an uncompressed P-256 public key") from None
    if "fleet" in data and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(data["fleet"])):
        raise ValueError("fleet is the fleet's id, which the owner's signed statements name")
    hosts, own = data.get("hosts") or {}, own_servers(data)
    for name, h in hosts.items():
        if not HOST.fullmatch(name) or not isinstance(h, dict):
            raise ValueError(f"host {name!r} is not a host name")
        if not tailnet_address(h.get("address", "")) or not HOST_KEY.fullmatch(h.get("host_key", "")):
            raise ValueError(f"host {name} needs its address on the private network and its second sshd's host key")
        if h.get("mode") not in ("fix", "rule-only") or not NAME.fullmatch(h.get("business", "")):
            raise ValueError(f"host {name} needs a mode, fix or rule-only, and a business")
        if h["mode"] == "fix" and own_server(own, h):
            raise ValueError(f"host {name} is the {own_server(own, h)}'s own server: its mode is rule-only, never fix")
        if not isinstance(h.get("port", SSHD_PORT), int):
            raise ValueError(f"host {name}: the port is a number")
    credentials = data.get("credentials") or {}
    for key, c in credentials.items():
        kind, _, name = key.partition(":")
        if kind == "app":       # new-projects plan N4: a key that the owner saved for one setting of one app
            if not APP_KEY.fullmatch(key) or not isinstance(c, dict) or set(c) != {"secret"} or \
                    not REF.fullmatch(str(c["secret"])):
                raise ValueError(f"credential {key!r} is app:<app>:<NAME> and names its secret by bws://<uuid>")
            continue
        if kind not in door_providers.PROVIDERS or not name:
            raise ValueError(f"credential {key!r} is not <provider>:<account>")
        if kind == "aws":       # no AWS key is stored: the door assumes the account's role with its bot's token
            if not isinstance(c, dict) or "secret" in c or not ROLE.fullmatch(str(c.get("role", ""))):
                raise ValueError(f"credential {key} names its role (arn:aws:iam::<account>:role/<name>) and no secret")
        elif not isinstance(c, dict) or not REF.fullmatch(str(c.get("secret", ""))):
            raise ValueError(f"credential {key} names its secret by bws://<uuid>")
    seen = {hub["address"]: "the hub"}
    for name, a in (data.get("agents") or {}).items():
        if not NAME.fullmatch(name) or not isinstance(a, dict):
            raise ValueError(f"agent {name!r} is not an agent name")
        # An agent with no address calls nothing: the hub asks for its GitHub tokens, inside its business pool. One
        # that shares its box with another agent's user has none, because the door tells callers apart by address.
        address = a.get("address")
        if address is not None:
            if not tailnet_address(address):
                raise ValueError(f"agent {name}: its address is not one of the private network")
            if address in seen:
                raise ValueError(f"{name} and {seen[address]} share the address {address}: the door refuses it")
            seen[address] = name
        # An agent that only gets its GitHub tokens from the door, through the hub (plan 13, item 4), names no
        # business: it has no address, no server, no provider and no repository of its own forms here.
        tokens_only = address is None and not any(a.get(k) for k in ("servers", "providers", "repos"))
        if not (tokens_only and "business" not in a) and not NAME.fullmatch(a.get("business", "")):
            raise ValueError(f"agent {name} needs its business")
        for host, level in (a.get("servers") or {}).items():
            if host not in hosts or level not in ("read", "fix"):
                raise ValueError(f"agent {name}: {host} is no host of this file, or {level!r} is not read or fix")
            if level == "fix" and hosts[host]["business"] != a["business"] and hosts[host]["mode"] != "rule-only":
                raise ValueError(f"agent {name}: Fix on {host} of another business is rule-only or nothing")
        for target in a.get("providers") or []:
            if target not in credentials:
                raise ValueError(f"agent {name}: {target} has no credential in this file")
        for repo, entry in (a.get("repos") or {}).items():
            if not door_targets.REPO.fullmatch(repo) or not isinstance(entry, dict) or \
                    entry.get("kind") not in ("devops", "app", "gitops"):
                raise ValueError(f"agent {name}: repos[{repo!r}] needs a kind, devops, app or gitops")
            # the sync caller goes into a dispatch's path, so it is one file name of a GitOps target, nothing else
            if "sync" in entry and (entry["kind"] != "gitops" or not isinstance(entry["sync"], str) or
                                    not door_targets.WORKFLOW_FILE.fullmatch(entry["sync"])):
                raise ValueError(f"agent {name}: repos[{repo!r}].sync is the file name of a GitOps target's caller "
                                 f"workflow")
        for repo, level in (a.get("github") or {}).items():
            if not door_targets.REPO.fullmatch(repo) or level not in GITHUB_ACCESS:
                raise ValueError(f"agent {name}: github[{repo!r}] is read, write or deploy")
    for business, pool in (data.get("pools") or {}).items():
        if not NAME.fullmatch(business) or not isinstance(pool, dict):
            raise ValueError(f"pools[{business!r}] is one business's repositories, each with its highest level")
        for repo, level in pool.items():
            if not door_targets.REPO.fullmatch(repo) or level not in GITHUB_ACCESS or door_targets.vendor(repo):
                raise ValueError(f"pools[{business}][{repo!r}] is read, write or deploy, on no product repository")
    for image, repo in (data.get("images") or {}).items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9._/:-]{0,199}", image) or not door_targets.REPO.fullmatch(str(repo)):
            raise ValueError(f"images[{image!r}] names the repository that builds that image, as owner/name")
    for w in data.get("windows") or []:
        if not isinstance(w, dict) or set(w) - {"hosts", "forms", "deny", "only"} or \
                not set(w.get("forms") or []) <= set(WINDOW_CLASSES) or bool(w.get("deny")) == bool(w.get("only")):
            raise ValueError("a window is {hosts, forms, deny or only: [[HH:MM, HH:MM], ...]} in UTC")
        for start, end in w.get("deny") or w.get("only"):
            for t in (start, end):
                if not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", t):
                    raise ValueError(f"{t!r} is not HH:MM")
    return data


def device_keys(access, items):
    """{device: key} of the owner's phones whose signing key his owner key certified: {v: 1, kind: "owner-device",
    fleet, device, key, at} in its canonical form, signed by one of the owner keys of the access file. The hub serves
    the phones of now, so a removed phone's certificate goes with it: the hub can hold one back and forge none."""
    keys, fleet, out = access.get("owner_keys"), access.get("fleet"), {}
    for item in (items or [])[:20] if keys and fleet else []:
        statement = item.get("statement") if isinstance(item, dict) else None
        try:
            said = json.loads(statement) if isinstance(statement, str) else None
        except (ValueError, RecursionError):
            said = None
        if not isinstance(said, dict) or set(said) != {"v", "kind", "fleet", "device", "key", "at"} or \
                vault.canonical(said) != statement or said["kind"] != "owner-device" or said["fleet"] != fleet or \
                type(said["v"]) is not int or said["v"] != 1 or not NAME.fullmatch(str(said["device"])) or \
                type(said["at"]) is not int:
            continue
        try:
            vault.owner_key(said["key"])
        except ValueError:
            continue
        if vault.owner_signed({"owner_keys": keys}, statement, item.get("signature")):
            out[said["device"]] = said["key"]
    return out


def approval(access, statement, signature, devices=None):
    """(call, need) of the owner's signed yes to one exact call, or None. The statement is {v: 1, kind: "door-call",
    fleet, need, call, at} in its canonical form: of this fleet, at most APPROVAL_DAYS old, and signed by one of the
    owner keys of the access file, with the central vault's own check, or by one of his phones' certified keys
    (device_keys). call is the call's hash, which the door gave with its refusal; need is the Needs-you item that took
    it to him."""
    keys, fleet = access.get("owner_keys"), access.get("fleet")
    if not keys or not fleet or not isinstance(statement, str) or not isinstance(signature, str):
        return None
    try:
        said = json.loads(statement)
    except (ValueError, RecursionError):
        return None
    if not isinstance(said, dict) or set(said) != {"v", "kind", "fleet", "need", "call", "at"} or \
            vault.canonical(said) != statement:
        return None
    if type(said["v"]) is not int or said["v"] != 1 or said["kind"] != "door-call" or said["fleet"] != fleet or \
            not re.fullmatch(r"[0-9a-f]{64}", str(said["call"])) or type(said["need"]) is not int or \
            said["need"] < 1 or type(said["at"]) is not int or \
            not now() - APPROVAL_DAYS * 86400 <= said["at"] <= now() + 300:
        return None
    if not vault.owner_signed({"owner_keys": keys}, statement, signature) and \
            not (devices and vault.owner_signed({"owner_keys": sorted(devices.values())}, statement, signature)):
        return None
    return said["call"], said["need"]


class RunFailed(door_providers.Stop):
    """A run that the door waited for ended badly. Its words are the door's own (run_word, the run's address), so
    they go in the record too, where a provider's answer never goes."""


def run_word(value):
    "A name that GitHub gives for a run, a job or a step, as an answer prints it: 80 plain characters at most."
    return re.sub(r"[^\w .:/()-]", "?", str(value))[:80]


def call_hash(target, op, args, content=None):
    """The hash of one call, which the door gives with a refusal that the owner's yes lifts, and which his yes names:
    SHA-256 of the JSON of [target, action, arguments], as json.dumps writes it (", " between the items, and every
    character outside the printable ASCII ones as \\uXXXX), then the content's bytes. One changed byte is another
    hash. The owner's Mac computes the same hash from the server and the script that its card shows, and signs only
    when the two agree (DoorCall.hash in the app; test_door.CallHash holds the examples that both sides are tested
    with)."""
    return hashlib.sha256(json.dumps([target, op, args], sort_keys=True).encode() + (content or b"")).hexdigest()


def mode_form(access, statement):
    """(host, mode, at) of a mode statement by its form alone, or None: the checks of mode_statement without the
    signature. The refresh reads the form first, so that a statement that is not newer than the kept one costs no
    signature check."""
    fleet = access.get("fleet")
    if not fleet or not isinstance(statement, str):
        return None
    try:
        said = json.loads(statement)
    except (ValueError, RecursionError):
        return None
    if not isinstance(said, dict) or set(said) != {"v", "kind", "fleet", "host", "mode", "at"} or \
            vault.canonical(said) != statement:
        return None
    if type(said["v"]) is not int or said["v"] != 1 or said["kind"] != "door-mode" or said["fleet"] != fleet or \
            not isinstance(said["host"], str) or said["host"] not in (access.get("hosts") or {}) or \
            said["mode"] not in MODES or type(said["at"]) is not int or said["at"] > now() + 300:
        return None
    return said["host"], said["mode"], said["at"]


def mode_statement(access, statement, signature):
    """(host, mode, at) of the owner's signed mode of one server, or None (door-modes proposal, step 4: the card's
    second answer, Full access on <host>; and the server's own row, Auto or Full access). The statement is {v: 1,
    kind: "door-mode", fleet, host, mode, at} in its canonical form: of this fleet, a host of the access file, a mode
    of MODES, not from the future (mode_form), and signed by one of the owner keys of the access file, his Mac, with
    the central vault's own check. A phone's key signs no mode: the owner's decision 3, whether the phone sets one,
    is open. A mode has no age limit, as a yes has: it stands until a newer statement of the same host, or until the
    host of that name is another server, and the door takes none from before it first saw the server
    (settle_modes)."""
    keys = access.get("owner_keys")
    if not keys or not isinstance(signature, str):
        return None
    found = mode_form(access, statement)
    if found is None or not vault.owner_signed({"owner_keys": keys}, statement, signature):
        return None
    return found


def mode_time(entry, field="at"):
    value = entry.get(field)
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def mode_signed(entry):
    """{"after": time} of the last statement that the door took for a name, as its entry says it, or {}: the time of
    the statement that the entry holds, or the `after` that it carries. An ended entry of an older release has no
    `after`, and its time is that of the statement that it ended."""
    older = entry.get("mode") == "ended" and "after" not in entry
    signed = mode_time(entry) if "statement" in entry or older else mode_time(entry, "after")
    return {} if signed is None else {"after": signed}


def settle_modes(access, modes):
    """The kept modes against the access file of now; True when one changed. A statement names its host by name only
    and has no age limit, so the door keeps, for every host of the access file, the host key that the name stands for
    and when it first saw the name with that key: a host with no entry gets Auto with the time of now, and so does a
    name that stands for a server with another key, or that left the file and came back. A statement from before
    that time is never taken (mode_floor), so no old Full access reaches a new server: not one that the door has
    kept, and not one that the hub held back, or serves to a door that is new or lost its file. `after` is the time
    of the last statement that the door took for the name, which the same statement and every older one never pass.
    A name that left the file keeps only its times ("ended"), and what is no entry is dropped, so the file holds one
    entry for each name that the access file ever had. An entry that the code before this wrote has no key: the door
    cannot know which server it was signed for, and binds it to the key that the host has now, with its time."""
    hosts, changed, t = access.get("hosts") or {}, False, round(now())
    for name, entry in list(modes.items()):
        if not isinstance(entry, dict):
            del modes[name]
        elif name not in hosts and entry.get("mode") != "ended":
            modes[name] = dict({"mode": "ended", "at": mode_time(entry)}, **mode_signed(entry))
        else:
            continue
        changed = True
    for name, host in hosts.items():
        key, entry = host.get("host_key"), modes.get(name)
        if entry is None:
            modes[name] = {"mode": "auto", "at": t, "host_key": key}
        elif entry.get("mode") == "ended" or entry.get("host_key", key) != key:
            modes[name] = dict({"mode": "auto", "at": t, "host_key": key}, **mode_signed(entry))
        elif "host_key" not in entry:
            modes[name] = dict(entry, host_key=key)
        else:
            continue
        changed = True
    return changed


def mode_floor(entry):
    """The time that a statement is newer than, to take the place of this entry: the time of the statement that the
    entry holds, so that only a newer one changes it; or, for an entry that the door made when it first saw the server,
    that time less MODE_SKEW, by which the clock of the owner's Mac may be behind the door's; and never the time of
    the last statement that the door took for the name before (settle_modes)."""
    at, after = mode_time(entry), mode_time(entry, "after")
    floor = -1 if at is None else at if "statement" in entry else at - MODE_SKEW
    return floor if after is None else max(floor, after)


def in_window(spans, t):
    minute = t.hour * 60 + t.minute
    for start, end in spans:
        a, b = (int(x[:2]) * 60 + int(x[3:]) for x in (start, end))
        if (a <= minute < b) if a <= b else (minute >= a or minute < b):
            return True
    return False


def window_refusal(access, host, window, t=None):
    """The reason a write of this window class is refused on this host now, or None."""
    if not window:
        return None
    t = t or datetime.datetime.now(datetime.timezone.utc)
    for w in access.get("windows") or []:
        if window not in (w.get("forms") or []) or (w.get("hosts") and host not in w["hosts"]):
            continue
        if w.get("deny") and in_window(w["deny"], t):
            return f"a {window} on {host} is not allowed now, inside a window of the owner's policy"
        if w.get("only") and not in_window(w["only"], t):
            return f"a {window} on {host} runs only inside its window ({', '.join('-'.join(s) for s in w['only'])} " \
                   f"UTC)"
    return None


# ---------------------------------------------------------------- the record

class Record:
    """One numbered line for each call, never a value, a token or the content. The hub reads it after a number."""

    def __init__(self, path=RECORD_FILE):
        self.path, self.lock = path, threading.Lock()
        self.last = 0
        with contextlib.suppress(OSError):
            with open(P(path), "rb") as f:
                for line in f:
                    with contextlib.suppress(ValueError):
                        self.last = max(self.last, json.loads(line)["n"])

    def add(self, **entry):
        # A field can hold a caller's own words (the target and the action of a call that the door refuses), as long
        # as a request's body: each field is one short text or a number
        entry = {k: v if v is None or isinstance(v, (int, float)) else str(v)[:RECORD_TEXT] for k, v in entry.items()}
        with self.lock:
            self.last += 1
            entry = dict(entry, n=self.last, ts=round(now(), 3))
            os.makedirs(os.path.dirname(P(self.path)), mode=0o700, exist_ok=True)
            with open(P(self.path), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return self.last

    def after(self, n, limit=RECORD_PAGE):
        out = []
        with contextlib.suppress(OSError):
            with open(P(self.path), encoding="utf-8") as f:
                for line in f:
                    with contextlib.suppress(ValueError):
                        e = json.loads(line)
                        if e["n"] > n:
                            out.append(e)
                            if len(out) >= limit:
                                break
        return out


# ---------------------------------------------------------------- the door

class Door:
    """The door's state in one process. call(), run() and the order of calls; the HTTP handler only parses."""

    def __init__(self, conf=None, http=None, ssh=None, clock=None, raw=None, box=None):
        self.conf = conf if conf is not None else read_json(CONF_FILE, {})
        self.http = http or door_providers.http
        self.raw = raw or http_raw      # a GET of bytes: the tarball of a GitOps repository
        self.box = box                  # the render box of a test; the door's own is its socket (box_call)
        self.ssh = ssh or self.ssh_call
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self.record = Record()
        self.lock = threading.Lock()
        self.host_locks, self.business_locks, self.repo_locks, self.tunnel_locks = {}, {}, {}, {}
        self.key_locks, self.key_failures = {}, {}      # one call of an account makes its work key; what failed last
        self.access_cache = (None, None)
        self.aws_sessions = {}          # each AWS role's session of an hour, in memory only (door_providers.aws_session)

    # ---- the files
    def access(self):
        try:
            st = os.stat(P(ACCESS_FILE))
        except OSError:
            return {"v": 1, "agents": {}, "hosts": {}}
        # A new owner or a new mode of the file moves no mtime, and a read that failed before it must not stay: the
        # door reads the file again when any of these four changes.
        mark = (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)
        if self.access_cache[0] != mark:
            try:
                with open(P(ACCESS_FILE), encoding="utf-8") as f:
                    data = json.load(f)
            except OSError:         # not kept: the next call reads the file again
                return {"v": 1, "agents": {}, "hosts": {}}
            except ValueError:
                data = None
            # A file from before the rule of own_servers can hold the hub's server or the door's own at fix. The door
            # reads such a host as rule-only, so that a new release leaves no door that names nobody, and `door.py
            # access` refuses the next file that says fix there.
            hosts = data.get("hosts") if isinstance(data, dict) else None
            own = own_servers(data) if isinstance(hosts, dict) else {}
            for h in hosts.values() if own else []:
                if isinstance(h, dict) and h.get("mode") == "fix" and own_server(own, h):
                    h["mode"] = "rule-only"
            try:
                self.access_cache = (mark, validate_access(data))
            except ValueError:
                self.access_cache = (mark, {"v": 1, "agents": {}, "hosts": {}})     # a broken file names nobody
            else:
                self.keep_modes(data)       # the first read of a new file: a mode of a host that left it ends
        return self.access_cache[1]

    def keep_modes(self, access):
        """settle_modes on the door's file of modes, at the first read of an access file that changed."""
        with contextlib.suppress(OSError), self.lock:
            modes = read_json(MODES_FILE, {})
            if isinstance(modes, dict) and settle_modes(access, modes):
                write_json(MODES_FILE, modes)

    def modes_said(self):
        """{host: {mode, at}}: the mode that the door keeps for each host of its access file now, auto or full, and
        the time of the owner's statement that set it (null for a host at Auto with no statement). The hub reads it
        with the record and shows it to the owner beside the statement that it carries, so that a statement that
        the door did not take (another key signed it, or its time is not newer than the door's own) shows as not
        taken. Full access is said only while full_access says it for an agent that holds the host at Fix: a host
        at rule-only, on the never list or with no such agent is at Auto in this word, whatever statement the door
        keeps for it. It is a reading: nothing of the door's reads it back."""
        access = self.access()
        hosts = access.get("hosts") or {}
        modes = read_json(MODES_FILE, {})
        out = {}
        for name in sorted(hosts)[:500]:
            entry = modes.get(name) if isinstance(modes, dict) else None
            if not isinstance(entry, dict) or entry.get("mode") not in MODES:
                continue
            at = mode_time(entry) if "statement" in entry else None
            # Full access is said when full_access itself says it for an agent: the same check, so the two agree
            holders = [a for a, me in (access.get("agents") or {}).items()
                       if isinstance(me, dict) and (me.get("servers") or {}).get(name) == "fix"]
            if entry["mode"] == "full" and not any(self.full_access(access, name, a) for a in holders):
                out[name] = {"mode": "auto", "at": None}
            else:
                out[name] = {"mode": entry["mode"], "at": at}
        return out

    def caller(self, address):
        """The agent at this address, or None: Tailscale proves the address, and the access file names it."""
        for name, a in (self.access().get("agents") or {}).items():
            if a.get("address") == address:
                return name
        return None

    def secret(self, ref):
        """A value that the vault sealed to the door, opened by the vault sweep; never passed on."""
        if not isinstance(ref, str) or not REF.fullmatch(ref):
            raise Refused("this account names no secret of the door")
        path = os.path.join(P(SECRETS_DIR), hashlib.sha256(ref.lower().encode()).hexdigest())
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            raise Refused(f"the door does not hold {ref} yet: the owner grants it to the door") from None

    def setting(self, access, value):
        """The value of an app's new setting (new-projects plan N4), as bytes for the host's stdin: 32 random bytes in
        base64, or the key that the owner saved for the door as app:<app>:<NAME>, and never a provider's key."""
        source, name = value
        if source == "random":
            return base64.b64encode(secrets.token_bytes(32))
        credentials = access.get("credentials") or {}
        ref = (credentials.get(name) or {}).get("secret")
        if not ref:
            raise Refused(f"the door holds no key as {name}")
        if any(isinstance(c, dict) and c.get("secret") == ref for k, c in credentials.items() if k != name):
            raise Refused(f"{name} names a key that the door uses for something else: it goes in no app")
        return self.secret(ref).encode()

    def runner_input(self, access, value):
        """What runner-new sends on the host's stdin (new-projects plan N6): a registration token and a remove token
        of the repository that the door made, from a token of the door's own for that one call, the repository's
        address, the runner's name, and the runner's latest release with the SHA-256 that GitHub publishes for it."""
        _, full, name = value
        owner = full.split("/")[0]
        conf = dict(github_app(access, owner) or {}, owner=owner)
        if not conf.get("app_id") or not conf.get("secret"):
            raise Refused(f"the door has no App of {owner}")
        ctx = {"credentials": conf, "http": self.http, "secret": self.secret}
        _, token = door_providers.one_call(conf, ctx, full, door_providers.RUNNER_TOKENS)
        got = {}
        for kind in ("registration", "remove"):
            status, answer = door_providers.gh(ctx, token, "POST", f"/repos/{full}/actions/runners/{kind}-token")
            if status != 201 or not isinstance(answer, dict) or not isinstance(answer.get("token"), str):
                raise door_providers.Stop(f"GitHub gave no {kind} token of {full} ({status})")
            got[kind] = answer["token"]
        status, release = self.http("GET", door_providers.RUNNER_RELEASE, {"Accept": "application/vnd.github+json"},
                                    None)
        if status != 200 or not isinstance(release, dict):
            raise door_providers.Stop(f"GitHub gave no release of the runner ({status})")
        version, sums = door_providers.runner_release(release)
        return json.dumps({"token": got["registration"], "remove": got["remove"], "url": f"https://github.com/{full}",
                           "name": name, "version": version, "sha256": sums}).encode()

    def minted(self, key_id):
        return key_id in read_json(MINTED_FILE, {})

    def keep_made(self, target, key):
        """A thing that a write through the door made, by its provider account: a later delete of it may run as an
        agent's own call (door_providers.made_keys)."""
        with self.lock:
            made = read_json(MADE_FILE, {})
            made.setdefault(target, {})[key] = round(now())
            write_json(MADE_FILE, made)

    def repo_record(self, kind, full, **fields):
        """The door's record of the repositories that it made (new-projects plan N3): "pending" before a repo-new
        is sent, "made" by the repository's id once GitHub answers, "deleted" after a repo-delete. With no fields, a
        "pending" or "made" asks for that entry, or None."""
        key = full.lower()
        with self.lock:
            held = read_json(REPOS_FILE, {"pending": {}, "made": {}})
            if not fields and kind in ("pending", "made"):
                return (held.get(kind) or {}).get(key)
            if kind == "pending":
                held.setdefault("pending", {})[key] = dict(fields, at=round(now()))
            elif kind == "made":
                held.setdefault("made", {})[key] = dict(fields, repo=full, at=round(now()))
                held.setdefault("pending", {}).pop(key, None)
            elif kind == "deleted":
                held.setdefault("made", {}).pop(key, None)
            write_json(REPOS_FILE, held)
        return None

    def made(self, target, key):
        """True when the door's own record shows that an agent made this through the door: a key that it minted, or a
        thing that a write made."""
        if key.startswith("key:"):
            return self.minted(key[4:])
        return key in (read_json(MADE_FILE, {}).get(target) or {})

    def aws_token(self):
        """The JWT-SVID of the door's own bot, which tbot renews; the door trades it at STS for a role's session."""
        try:
            with open(P(AWS_TOKEN_FILE), encoding="utf-8") as f:
                token = f.read().strip()
        except OSError:
            token = ""
        if not token:
            raise door_providers.Stop(f"the door's bot has written no AWS token in {AWS_TOKEN_FILE}")
        return token

    def approved(self, access, sha):
        """The owner's signed yes to this exact call, now used, or None: each yes lets its one call through once."""
        with self.lock:
            entry = read_json(APPROVALS_FILE, {}).get(sha)
            if not isinstance(entry, dict) or approval(access, entry.get("statement"), entry.get("signature"),
                                                       read_json(DEVICES_FILE, {})) is None:
                return None
            used = read_json(APPROVED_FILE, {})
            key = hashlib.sha256(entry["statement"].encode()).hexdigest()
            if key in used:
                return None
            used = {k: v for k, v in used.items() if v > now() - 2 * APPROVAL_DAYS * 86400}
            used[key] = round(now())
            write_json(APPROVED_FILE, used)
        return entry

    def update_host(self, host, name, manifest, code):
        """(outcome, words) of one host's update to the host parts of the release that the door runs: current, done,
        refused, failed or unreachable. Its help says its version and its release (an ops-root of version 1 names no
        release, and one that no self-update gave says none): a host of another release gets the bundle, with the
        commits down to its own release, which self-update checks the way down by."""
        status, out = self.ssh(host, {"v": 1, "op": "help", "args": []}, None)
        if status in (255, 124):        # no session, or no answer within HELP_WAIT: the door asks again later
            return "unreachable", f"{name} did not answer the door: {out.strip()[-200:]}"
        found = re.match(r"ops-root [0-9]{1,6}, mode [a-z-]+(?:, release ([0-9a-f]{40}|none))?", out.strip()) \
            if status == 0 else None
        if not found:
            return "failed", f"{name}'s ops-root gave no version ({status}): {out.strip()[-200:]}"
        if found.group(1) == manifest["revision"]:
            return "current", f"{name} runs the host parts of release {manifest['version']}"
        try:
            bundle = host_bundle(code, manifest, found.group(1) if found.group(1) not in (None, "none") else "")
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            return "failed", f"the door could not make the bundle for {name}: {e}"
        status, out = self.ssh(host, {"v": 1, "op": "self-update", "args": []}, json.dumps(bundle).encode())
        if status == 0:
            return "done", out.strip() or f"{name} takes release {manifest['version']}"
        return ("refused" if status == 3 else "unreachable" if status == 255 else "failed"), \
            out.strip().removeprefix("refused: ")[-300:]

    def full_access(self, access, host, agent):
        """True when the owner's signed mode of this host is Full access and the door honours it here: the access file
        holds the host at fix, the host is on no never list, and the caller holds it at Fix in the host's own business
        (door-modes proposal, section 2). The door checks it all at each call, the statement's signature too, because
        the file's owner keys can change: a host at rule-only, or on the never list, ignores any statement. So does a
        host whose host key is not the one that the statement was accepted for (settle_modes): a new server that got
        the name of an old one is at Auto until the owner signs a new statement."""
        h = (access.get("hosts") or {}).get(host)
        me = (access.get("agents") or {}).get(agent) or {}
        if not h or h.get("mode") != "fix" or host in ((access.get("never") or {}).get("hosts") or []) or \
                me.get("business") != h.get("business") or (me.get("servers") or {}).get(host) != "fix":
            return False
        entry = read_json(MODES_FILE, {}).get(host)
        if not isinstance(entry, dict) or entry.get("mode") != "full" or entry.get("host_key") != h.get("host_key"):
            return False
        return mode_statement(access, entry.get("statement"), entry.get("signature")) == (host, "full", entry.get("at"))

    def keep_minted(self, answer):
        """A key that the door minted: its id goes in the minted list, and its secret into the door's own secrets,
        where only the door reads it, until the door places it."""
        key_id = answer.get("applicationKeyId") or answer.get("id")
        value = answer.get("applicationKey") or answer.get("key")
        if not isinstance(key_id, str) or not isinstance(value, str):
            raise door_providers.Stop("the provider gave no key id and value")
        with self.lock:
            minted = read_json(MINTED_FILE, {})
            minted[key_id] = {"at": round(now()), "name": answer.get("keyName")}
            write_json(MINTED_FILE, minted)
        path = os.path.join(P(SECRETS_DIR), "minted-" + hashlib.sha256(key_id.encode()).hexdigest())
        os.makedirs(P(SECRETS_DIR), mode=0o700, exist_ok=True)
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(f"{key_id}:{value}")

    def forget_minted(self, key_id):
        """A key that the door revoked: its id leaves the minted list, and its secret leaves the door's secrets."""
        with self.lock:
            minted = read_json(MINTED_FILE, {})
            if minted.pop(key_id, None) is not None:
                write_json(MINTED_FILE, minted)
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(P(SECRETS_DIR), "minted-" + hashlib.sha256(key_id.encode()).hexdigest()))

    def minted_secret(self, key_id):
        path = os.path.join(P(SECRETS_DIR), "minted-" + hashlib.sha256(key_id.encode()).hexdigest())
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError:
            raise door_providers.Stop(f"the door holds no value of {key_id}") from None

    # ---- one call
    def call(self, address, target, op, args, content=None):
        """{ok, kind, out, why, n}: what the agent at this address reads."""
        agent = self.caller(address)
        if agent is None:
            n = self.record.add(caller=address, target=target, action=op, kind="refused", outcome="refused",
                                why="not in the access file")
            return {"ok": False, "kind": "refused", "why": "this caller is not in the door's access file", "n": n,
                    "route": "holder"}
        access = self.access()
        listing = early = None  # DevOps plan X3: a sync with prune decides on what Argo CD wants to prune now
        if isinstance(target, str) and target.startswith("gitops:") and op == "sync" and args[1:] == ["prune"]:
            early = window_refusal(access, target, "deploy", self.clock())     # no listing run outside the window
            listing = None if early else self.prune_listing(access, agent, target, args[0])
        try:
            d = door_targets.refused(early, target=target, route="window") if early else door_targets.decide(
                access, agent, target, op, args, content, self.lookups(access, target, agent, listing))
        except (Refused, door_providers.Stop) as e:
            d = door_targets.refused(f"the door could not check this call: {e}", target=target, route="again")
        if d.kind != "refused" and d.write:
            why = window_refusal(access, d.host or target, d.window, self.clock())
            if why:
                d = door_targets.refused(why, target=d.target, route="window")
        if getattr(d, "hash_content", None) is not None:
            # what the door adds to the call: a prune's list, a commit's regenerated file. The owner's yes is to them too (X3)
            content = (content or b"") + d.hash_content
        sha = call_hash(target, op, args, content)
        hashed = d.kind in ("own", "full")      # a refusal of these two kinds is the owner's to lift: it gives the hash
        full_host = d.host if d.kind == "full" else None
        full = full_host is not None and self.full_access(access, full_host, agent)
        yes = self.approved(access, sha) if hashed and not full else None
        if full:                # door-modes proposal, step 4: the owner set this server to Full access
            d.kind, d.why = "own", f"{agent}'s own call, which it answers for: a root script with no box on " \
                                   f"{full_host}, which the owner set to Full access"
        elif yes:               # the owner said yes to this exact call: it runs once
            d.kind, d.why = "approved", f"the owner's signed yes (N-{yes['need']}) to this exact call, used once"
        elif d.kind == "full":  # door-modes proposal, step 3: what the next mode allows runs only with his yes
            d = door_targets.refused(d.why + "." + APPROVAL_NOTE.format(sha=sha) +
                                     (FULL_NOTE.format(host=full_host) if full_host else ""), target=d.target)
        elif d.kind == "own":
            # D25: a delete of what no agent made through the door, and every AWS delete, is the owner's, by code
            unmade = [key for key in door_providers.deletes(d.plan, self.credential(access, d.target))
                      if not self.made(d.target, key)]
            if unmade:
                d = door_targets.refused(door_providers.delete_refusal(unmade[0]) + APPROVAL_NOTE.format(sha=sha),
                                         target=d.target)
            else:               # the owner, 11 November 2026: no model decides, "it needs to be the agent itself"
                d.why = f"{agent}'s own call, which it answers for: {d.why}"
        if d.kind == "refused":
            n = self.record.add(caller=agent, target=target, action=op, kind="refused", outcome="refused",
                                why=d.why[:300], sha256=sha)
            answer = {"ok": False, "kind": "refused", "why": d.why, "n": n, "route": "yes" if hashed else
                      d.route if d.route in ROUTES else "none"}
            if hashed:
                answer["call"] = sha
            if full_host:       # the server whose Full access lets this call, and each later one, through
                answer["full_access"] = full_host
            if d.needs:
                answer.update(needs=d.needs, **({"level": d.level} if d.level else {}))
            return answer
        ran = None              # a run that the door waited for and that ended badly: the record says how
        try:
            out = self.run(agent, access, d, op, args, content)
            ok, outcome = True, "done"
        except (Refused, door_providers.Stop) as e:
            ok, outcome, out = False, "failed", str(e)
            ran = str(e) if isinstance(e, RunFailed) else None
        made = ((d.plan or {}).get("repo_new") or {}).get("name") if ok else None     # N3: what the call made
        n = self.record.add(caller=agent, target=target, action=op, kind=d.kind, outcome=outcome,
                            why=(f"{ran}. {d.why}" if ran else d.why)[:300], sha256=sha, **({"made": made} if made else {}))
        return {"ok": ok, "kind": d.kind, "out" if ok else "why": out, "n": n}

    def run(self, agent, access, d, op, args, content):
        """What a decision runs: a host form through its second sshd, or a provider's plan. A write on one host waits
        for the one before it, and a reboot-class call holds its business until the host answers again. A repo-new or
        a repo-delete holds its repository's lock (new-projects plan N3), runner-new its repository's and then its
        host's (N6), and a tunnel route its tunnel's (N7)."""
        tunnel = (d.plan or {}).get("tunnel")
        if tunnel:          # N7: a tunnel's whole configuration, which a route reads and writes, one call at a time
            with self.held(self.tunnel_locks, tunnel.lower()):
                return self.act(access, d, op, args, content)
        repo = ((d.plan or {}).get("repo_new") or (d.plan or {}).get("repo_delete") or {}).get("name") or \
            (d.value[1] if d.value and d.value[0] == "runner" else None)
        if repo:
            with self.held(self.repo_locks, repo.lower()):
                if d.host and d.write:          # runner-new (N6): its repository's lock, then its host's
                    with self.held(self.host_locks, d.host):
                        return self.act(access, d, op, args, content)
                return self.act(access, d, op, args, content)
        if d.host and d.write:
            with self.held(self.host_locks, d.host):
                if d.reboot:
                    with self.held(self.business_locks, d.business or "-"):
                        try:
                            out = self.act(access, d, op, args, content)
                        except Refused:
                            raise                   # ops-root refused it: nothing ran on the host
                        except Exception:
                            # A session that ends badly can be the reboot itself, or Tailscale's own restart in its
                            # upgrade: the host may be going down all the same, so its business waits for it.
                            self.back(access, d.host)
                            raise
                        self.back(access, d.host)
                        return out
                return self.act(access, d, op, args, content)
        return self.act(access, d, op, args, content)

    def held(self, table, key):
        with self.lock:
            lock = table.setdefault(key, threading.Lock())
        return lock

    def act(self, access, d, op, args, content):
        if d.plan is None:
            req = {"v": 1, "op": op, "args": d.args}
            stdin = content if op in door_targets.HOST_CONTENT else None
            if stdin is not None:       # ops-root installs only the bytes that have the request's sha256
                req["sha256"] = hashlib.sha256(stdin).hexdigest()
            if d.value:
                stdin = self.runner_input(access, d.value) if d.value[0] == "runner" else self.setting(access, d.value)
            status, out = self.ssh(access["hosts"][d.host], req, stdin)
            if status == 3:             # ops-root refused it before it ran, and before a script armed the timer
                said = out.strip().removeprefix("refused: ")
                if said.startswith(f"{op!r} is no form of a host"):    # the door has not updated the host yet
                    said = (f"{d.host} runs an ops-root older than the door's, which has no form {op}: the door "
                            f"brings each host the ops-root of its release (update_hosts), so send the same call "
                            f"again in a few minutes")
                raise Refused(said)
            if op in door_targets.TIMED_FORMS:
                out = out.rstrip("\n") + "\n" + self.timer_off(access["hosts"][d.host], d.host) + "\n"
            if status != 0:
                raise door_providers.Stop(out.strip()[-4000:] or f"the host answered {status}")
            return out
        plan = d.plan
        if plan.get("provider"):
            return door_providers.execute(plan, self.provider_ctx(access, d.target))
        if "text" in plan:              # a text that the door gives, such as the product's deploy workflow (N5)
            return plan["text"]
        hub = GitHub(self, access, plan["repo"])
        if "files" in plan:
            out = hub.commit(plan)
            self.keep_objects(plan, out)
            if plan.get("checks"):          # a GitOps commit: the agent learns how its checks ended, at once
                passed, words = hub.wait_checks(hub.commit_sha, hub.commit_branch)
                if not passed:
                    raise RunFailed(f"{out}, and {words}: fix the commit or revert it")
                out = f"{out}; {words}"
            return out
        if "read" in plan:
            return hub.read(plan["read"], access)
        if "workflow" in plan:
            out = hub.dispatch(plan["workflow"], plan["inputs"], wait=bool(plan.get("wait")))
            if plan.get("pruned"):          # the run passed: what it pruned is no longer waiting
                self.prune_done(plan["repo"], plan["pruned"])
            return out
        raise Refused("the door cannot run this")

    def keep_objects(self, plan, out):
        """What a GitOps commit through the door removed and added (door_targets.commit_objects), once it is made. A
        removed object can then prune as the agent's own call (DevOps plan X3), and an added one is made, so that its
        later prune is a rule call. An object that a later commit adds again is no longer removed."""
        objects = plan.get("objects") or {}
        removed, added = objects.get("removed") or [], objects.get("added") or []
        if not removed and not added:
            return
        target = "gitops:" + plan["repo"]
        for key in added:
            self.keep_made(target, "object:" + key)
        commit = out.rsplit(" ", 1)[-1] if isinstance(out, str) else ""
        with self.lock:
            held = read_json(REMOVED_FILE, {})
            mine = held.setdefault(plan["repo"].lower(), {})
            for key in added:
                mine.pop(key, None)
            for key in removed:
                mine[key] = {"commit": commit, "at": round(now())}
            write_json(REMOVED_FILE, held)

    def removed_object(self, repo, key):
        "True when a commit through the door removed this object within REMOVED_DAYS (keep_objects)."
        entry = (read_json(REMOVED_FILE, {}).get(repo.lower()) or {}).get(key)
        return isinstance(entry, dict) and now() - (entry.get("at") or 0) < REMOVED_DAYS * 86400

    def prune_done(self, repo, keys):
        "The objects of a prune whose run passed: no longer waiting for one."
        with self.lock:
            held = read_json(REMOVED_FILE, {})
            mine = held.get(repo.lower()) or {}
            for key in keys:
                mine.pop(key, None)
            write_json(REMOVED_FILE, held)

    def prune_listing(self, access, agent, target, app):
        """What Argo CD wants to prune in one app now, for a sync with prune (DevOps plan X3): the door dispatches the
        repository's caller with prune=list, waits for that run, and reads its line LISTING_MARK from the logs of its
        jobs (door_targets.listing). None for a call that decide refuses anyway; a str says why there is no listing.
        That run is on a shared runner, so its listing is only a list to check: the door decides with its own record,
        and the prune run reads Argo CD again before it deletes anything."""
        repo = target.split(":", 1)[1]
        me = (access.get("agents") or {}).get(agent) or {}
        entry = door_targets.repo_entry(me, repo, ("gitops",)) if door_targets.REPO.fullmatch(repo) else None
        if not entry or not entry.get("sync") or not door_targets.APP_NAME.fullmatch(str(app)):
            return None
        hub = GitHub(self, access, repo)
        try:
            hub.dispatch(entry["sync"], {"app": app, "prune": "list"}, wait=True)
            found = door_targets.listing(hub.run_text(hub.run_id), app)
        except (Refused, door_providers.Stop) as e:
            found = f"the listing run failed: {e}"
        self.record.add(caller=agent, target=target, action="prune-list", kind="read",
                        outcome="done" if isinstance(found, dict) else "failed",
                        why=(f"Argo CD wants to prune {len(found['prune'])} objects in {app}" if isinstance(found, dict)
                             else found)[:300])
        return found

    def timer_off(self, host, name):
        """After a script or a run, which armed the host's rollback timer first: a host that answers the door now did not
        lock the door out, so the door ends the countdown, and the change stays. A host that does not answer keeps the
        countdown, and the timer puts its firewall, its network, sshd and Tailscale back. One line for the answer."""
        for attempt in range(TIMER_TRIES):
            if attempt:
                time.sleep(TIMER_PAUSE)
            status, out = self.ssh(host, {"v": 1, "op": "timer", "args": ["cancel"]}, None)
            if status == 0:
                return out.strip() or "the rollback timer is off"
            if status == 3:
                return f"{name} refused to end the rollback countdown: {out.strip().removeprefix('refused: ')}"
        return (f"{name} did not answer the door after the script: if the script armed the rollback timer, it puts the "
                f"firewall, the network, sshd and Tailscale back in 600 seconds, unless `ops {name} timer cancel` comes "
                f"first")

    def lookups(self, access, target, agent=None, listing=None):
        """The facts that the code checks of a commit or a deploy read from outside, each asked only when a check
        needs it: a file at the head of the branch that the commit goes to, the npm registry, a release run, the
        state of the default branch, a repository's default branch."""
        kind, _, repo = target.partition(":") if isinstance(target, str) else ("", "", "")
        facts = {"minted": self.minted, "default_branch": lambda name: GitHub(self, access, name).branch(),
                 "made_repo": lambda name: self.repo_record("made", name),
                 "made_app": lambda app: [r for r in (read_json(REPOS_FILE, {}).get("made") or {}).values()
                                          if isinstance(r, dict) and r.get("app") == app]}
        if kind not in ("commit", "gitops", "deploy") or not door_targets.REPO.fullmatch(repo):
            return facts
        hub = GitHub(self, access, repo)
        entry = (((access.get("agents") or {}).get(agent) or {}).get("repos") or {}).get(repo)
        branch = entry.get("branch") if isinstance(entry, dict) else None
        facts.update(base_file=lambda path: hub.file_at_head(path, branch), image_made=hub.image_made,
                     deploy_facts=hub.deploy_facts, npm=self.npm, schema_ok=lambda path, data: True)
        if kind == "gitops":    # a sync with prune (DevOps plan X3): the listing, and the door's own record
            facts.update(prune_listing=listing, removed_object=lambda key: self.removed_object(repo, key),
                         made_object=lambda key: self.made(target, "object:" + key),
                         # a repository that generates files, for a commit that no render writes them for (X3)
                         declared=lambda: hub.file_at_head(door_targets.DOOR_DECLARATION, branch) is not None)
        box = self.box or (box_call if os.path.exists(P(RENDER_SOCKET)) else None)
        # A door with no render box gives no render, and the rules that need none stay. But only for a repository that
        # this door never rendered: where it did, templates changed under the render, and the rules that read lines
        # no longer say what a commit does.
        if kind == "gitops" and (box or self.rendered(repo)):
            facts["render"] = lambda files: self.render(hub, branch, files, box or box_call)
        return facts

    def rendered(self, repo, keep=False):
        "True when this door has rendered a commit of this repository. keep: it has now."
        with self.lock:
            known = read_json(RENDERED_FILE, {})
            known = known if isinstance(known, dict) else {}
            if keep and repo.lower() not in known:
                write_json(RENDERED_FILE, dict(known, **{repo.lower(): round(now())}))
            return repo.lower() in known

    def render(self, hub, branch, files, box):
        """The render of one GitOps commit (door_render.answer). The door reads the commit id of the branch, gets the
        tarball of that one commit, and gives it to the box with the commit's files. The report names that commit
        (head): each file at HEAD comes from it, and the door makes its commit on it, so what the door rendered is
        what the commit changes. A report with `skip` says that this repository cannot be rendered here (no programs
        yet, a tarball over the cap), and its commits keep the rules that need no render: but not once the door has
        rendered the repository, because an agent can make a repository grow. Then it is a refusal."""
        name = branch or hub.branch()
        status, ref = hub.call("GET", f"/repos/{hub.repo}/git/ref/heads/{name}")
        head = (ref.get("object") or {}).get("sha") if status == 200 and isinstance(ref, dict) else None
        if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40,64}", head):
            raise door_providers.Stop(f"GitHub answered {status} for {name}")
        status, tar = self.raw("GET", f"{GitHub.API}/repos/{hub.repo}/tarball/{head}", {
            "Authorization": "Bearer " + hub.token(), "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}, door_render.TAR_MAX + 1)
        if status != 200:
            raise door_providers.Stop(f"GitHub answered {status} for the tarball of {hub.repo}")
        if len(tar) > door_render.TAR_MAX:
            report = {"v": 1, "ok": False, "skip": f"its tarball is over {door_render.TAR_MAX // 2 ** 20} MiB"}
        else:
            header = {"v": 1, "op": "render", "repo": hub.repo, "tar": len(tar),
                      "exposure": [p for p in self.access().get("exposure") or [] if isinstance(p, str)],
                      "files": [{"path": path, "size": None if data is None else len(data), "mode": mode}
                                for path, data, mode in files]}
            report = box(header, [tar] + [data for _path, data, _mode in files if data is not None])
        if not isinstance(report, dict):
            report = {"v": 1, "ok": False, "again": True, "why": "the render box gave no report"}
        if report.get("ok"):
            report["head"] = head
            self.rendered(hub.repo, keep=True)
        elif "skip" in report and self.rendered(hub.repo):
            report = {"v": 1, "ok": False, "again": True,
                      "why": f"the door rendered {hub.repo} before and cannot now ({report['skip']})"}
        return report

    def npm(self, name):
        if not re.fullmatch(r"(@[a-z0-9._-]+/)?[a-z0-9._-]{1,214}", name or ""):
            return None
        status, doc = self.http("GET", "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"),
                                {"Accept": "application/json"}, None)
        return doc if status == 200 and isinstance(doc, dict) else None

    def back(self, access, host):
        """Wait until a host that a reboot-class call touched answers a read again, so that the next reboot of its
        business waits for it."""
        h = access["hosts"].get(host)
        if not h:
            return
        end = time.monotonic() + REBOOT_BACK
        time.sleep(20)
        while time.monotonic() < end:
            status, _ = self.ssh(h, {"v": 1, "op": "uptime", "args": []}, None)
            if status == 0:
                return
            time.sleep(10)

    def credential(self, access, target):
        """The access file's credential of one provider account, with the account id that the door got for its token
        when the file names none (keep_account)."""
        conf = dict((access.get("credentials") or {}).get(target) or {})
        kept = read_json(ACCOUNTS_FILE, {}).get(target) or {}
        if not conf.get("account_id") and kept.get("account_id") and kept.get("secret") == conf.get("secret"):
            # account_kept: the door's own reading of the key before, not the file's word. The names of what a call
            # makes and deletes take it; what a saved key is, and which account it is for, is asked of its provider
            conf.update(account_id=kept["account_id"], account_kept=True)
        return conf

    def keep_account(self, access, target, account_id):
        """The one account that a credential's token reaches, kept with that credential under the name of its
        secret: a new token on the card is asked again."""
        secret = ((access.get("credentials") or {}).get(target) or {}).get("secret")
        with self.lock:
            kept = read_json(ACCOUNTS_FILE, {})
            kept[target] = {"secret": secret, "account_id": account_id}
            write_json(ACCOUNTS_FILE, kept)

    # ---- the keys that the door makes for itself (door_providers.cloudflare_work_key)
    def key_kind(self, target, mark):
        """What the door knows of the key that is saved for this account, by the mark of its value, or None."""
        known = kept_keys()["kinds"].get(target)
        return known if isinstance(known, dict) and known.get("mark") == mark else None

    def keep_key_kind(self, target, mark, key):
        with self.lock:
            held = kept_keys()
            held["kinds"][target] = dict(key, mark=mark)
            write_json(KEYS_FILE, held)

    def work_path(self, target):
        return os.path.join(P(SECRETS_DIR), "work-" + hashlib.sha256(target.encode()).hexdigest())

    def work_key(self, target):
        """The work key that the door holds for this account, with its value, or None. One whose value the door cannot
        read, or whose value file is not the one that its entry names (value_mark: a write of one of the two files
        failed), comes without a value: the door then makes a new key, and deletes this one by its id."""
        entry = kept_keys()["work"].get(target)
        if not isinstance(entry, dict):
            return None
        try:
            with open(self.work_path(target), encoding="utf-8") as f:
                value = f.read().strip()
        except (OSError, ValueError):       # not there, or no text
            value = ""
        return dict(entry, value=value) if value and door_providers.key_mark(value) == entry.get("value_mark") \
            else dict(entry)

    def keep_work_key(self, target, made):
        """A work key that the door made and that signed in: its value in the door's own secrets, where only the door
        reads it, and its id, its end and what made it in the list. None takes both away."""
        path = self.work_path(target)
        if made is None:
            with contextlib.suppress(FileNotFoundError):
                os.remove(path)
        else:           # whole or not at all: a file that a stop of the door cut would be a key that signs in nowhere
            os.makedirs(P(SECRETS_DIR), mode=0o700, exist_ok=True)
            try:
                with open(os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                    os.fchmod(f.fileno(), 0o600)
                    f.write(made["value"])
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(path + ".new", path)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(path + ".new")
        with self.lock:
            held = kept_keys()
            if made is None:
                held["work"].pop(target, None)
            else:
                held["work"][target] = dict({k: v for k, v in made.items() if k != "value"}, at=round(now()))
            write_json(KEYS_FILE, held)

    def key_said(self, target, action, outcome, why):
        """One line of the record for a work key that the door made or ended. A failure with the same words is said
        once in KEY_SAID_AGAIN seconds, so a call that an agent sends again and again fills no record."""
        if outcome == "failed":
            last = self.key_failures.get(target)
            if last and last[0] == why and now() - last[1] < KEY_SAID_AGAIN:
                return
            self.key_failures[target] = (why, now())
        else:
            self.key_failures.pop(target, None)
        self.record.add(caller="door", target=target, action=action, kind="key", outcome=outcome, why=why)

    def provider_ctx(self, access, target):
        return {"credentials": dict(self.credential(access, target), owner=target.partition(":")[2]),
                "http": self.http, "secret": self.secret,
                "key_kind": lambda mark: self.key_kind(target, mark),
                "keep_key_kind": lambda mark, key: self.keep_key_kind(target, mark, key),
                "work_key": lambda: self.work_key(target),
                "keep_work_key": lambda made: self.keep_work_key(target, made),
                "key_lock": self.held(self.key_locks, target), "now": now,
                "said": lambda action, outcome, why: self.key_said(target, action, outcome, why),
                "keep": lambda kind, value: self.forget_minted(value) if kind == "revoked" else self.keep_minted(value),
                "made": lambda key: self.keep_made(target, key),
                "repos": self.repo_record,
                "account": lambda account_id: self.keep_account(access, target, account_id),
                "minted_secret": self.minted_secret, "aws_token": self.aws_token, "aws_sessions": self.aws_sessions,
                "host": lambda host, op, args, stdin: self.ssh(access["hosts"][host],
                                                               {"v": 1, "op": op, "args": args}, stdin),
                "run": lambda argv, stdin, env: run_program(argv, stdin, env)}

    def ssh_call(self, host, req, stdin):
        """One request through a host's second sshd, as ops-agent with the door's key, pinned to its host key. The
        door reads HOST_OUT_MAX of the answer at most, and a host's help, which answers at once, gets HELP_WAIT: the
        host sweep asks it of each host in turn, and one host that hangs must not hold the others for an hour."""
        known = os.path.join(P(STATE), f"known_hosts-{host['address']}-{host.get('port', SSHD_PORT)}")
        line = f"[{host['address']}]:{host.get('port', SSHD_PORT)} {host['host_key']}\n"
        os.makedirs(os.path.dirname(known), mode=0o700, exist_ok=True)
        with open(known, "w") as f:
            f.write(line)
        argv = ["ssh", "-T", "-p", str(host.get("port", SSHD_PORT)), "-i", P(SSH_KEY), "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes", "-o", f"UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30", f"ops-agent@{host['address']}",
                base64.b64encode(json.dumps(req).encode()).decode()]
        return run_program(argv, stdin, {}, timeout=HELP_WAIT if req.get("op") == "help" else 3600, limit=HOST_OUT_MAX)

    # ---- the hub's two rights
    def hub_allowed(self, address, token, which):
        hub = (self.access().get("hub") or {})
        want = read_json(HUB_FILE, {}).get(which)
        return address == hub.get("address") and isinstance(token, str) and isinstance(want, str) and \
            hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), want)

    def github_tokens(self, agent, repos):
        """The hub asks for one agent's tokens, and names each grant: the door makes one for a repository that the
        access file gives that agent, or one in its business's pool, because the manager hands out what the pool
        holds, at no more than the level there. One installation token for each owner and level, from the door's App
        of that owner (credentials github:<owner>)."""
        access = self.access()
        me = (access.get("agents") or {}).get(agent)
        if me is None:
            raise Refused(f"{agent} is not in the door's access file")
        granted = me.get("github") or {}
        pool = (access.get("pools") or {}).get(me.get("business")) or {}
        levels = list(GITHUB_ACCESS)
        groups, refused = {}, []
        operator, kept = bool(me.get("servers") or me.get("business")), []
        for repo, level in sorted((repos or {}).items()):
            tops = [levels.index(x) for x in (granted.get(repo), pool.get(repo)) if x in GITHUB_ACCESS]
            if door_targets.vendor(repo) or level not in GITHUB_ACCESS or not tops or levels.index(level) > max(tops):
                refused.append(repo)
                continue
            # new-projects plan N3: no deploy token on a repository that the door made, and no write token on it for
            # an Operator, whose workflow files there go through the door
            if self.repo_record("made", repo) and (level == "deploy" or (level == "write" and operator)):
                kept.append(repo)
                continue
            groups.setdefault((repo.split("/")[0], level), []).append(repo)
        tokens, errors = [], [{"repos": [r], "error": "neither the door's access file nor the business's pool gives "
                                                      "this agent that level"} for r in refused]
        errors += [{"repos": [r], "error": "the door made this repository: it makes no deploy token on it, and no write "
                                          "token for an Operator, whose workflow files there go through the door"}
                   for r in kept]
        # the highest level first, as the hub's own path sends them: the session's GH_TOKEN is the first token
        # (fleet.py integration_env), so gh and the GitHub tool get the token that does the most
        for (owner, level), names in sorted(groups.items(), key=lambda g: (-levels.index(g[0][1]), g[0][0])):
            conf = github_app(access, owner) or sole_app(access) or {}
            try:
                ctx = {"credentials": dict(conf, owner=owner), "http": self.http, "secret": self.secret}
                jwt = door_providers.app_jwt(conf["app_id"], self.secret(conf.get("secret")))
                inst = self.installation(jwt, names)
                # new-projects plan N1: a repository that the installation no longer lists (deleted on GitHub, or no
                # longer selected) is dropped before the token, so that it does not stop the tokens of the others
                listed = self.selected(jwt, inst)
                if listed is not None:
                    gone = [n for n in names if n.lower() not in listed]
                    if gone:
                        errors.append({"repos": gone, "error": "GitHub does not list it in the App's installation: it "
                                                               "was deleted, or it is not selected there"})
                    names = [n for n in names if n.lower() in listed]
                    if not names:
                        continue
                status, got = self.http("POST", f"https://api.github.com/app/installations/{inst['id']}/access_tokens",
                                        {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json",
                                         "Content-Type": "application/json"},
                                        json.dumps({"repositories": [n.split("/", 1)[1] for n in names],
                                                    "permissions": token_permissions(
                                                        level, inst.get("permissions"))}).encode())
                if status != 201 or not isinstance(got.get("token"), str):
                    raise door_providers.Stop(f"GitHub gave no token ({status})")
                tokens.append({"token": got["token"], "expires_at": got.get("expires_at"), "access": level,
                               "repos": names})
                del ctx
            except (KeyError, Refused, door_providers.Stop) as e:
                errors.append({"repos": names, "error": str(e)})
        self.record.add(caller="hub", target="github", action="token", kind="token",
                        outcome="done" if tokens else "failed", why=f"{agent}: {len(tokens)} tokens")
        return tokens, errors

    def installation(self, jwt, names):
        """The installation of the door's App that holds these repositories, from the first of them that GitHub
        answers for: a repository that GitHub no longer has answers 404, and the next one asks."""
        for name in names:
            status, inst = self.http("GET", f"https://api.github.com/repos/{name}/installation",
                                     {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json"}, None)
            if status == 200 and isinstance(inst, dict) and isinstance(inst.get("id"), int) \
                    and not isinstance(inst.get("id"), bool):
                return inst
        raise door_providers.Stop("GitHub gave no installation of the App for these repositories")

    SELECTED = {}       # installation id -> (time, its repositories in lower case), for a minute

    def selected(self, jwt, inst):
        """The repositories of an installation that has selected repositories, in lower case and kept a minute, or
        None for one that has all of them, or more than the door reads."""
        if inst.get("repository_selection") != "selected":
            return None
        got = self.SELECTED.get(inst["id"])
        if got and got[0] > now() - 60:
            return got[1]
        repos = self.installation_repos(jwt, inst["id"], inst.get("account", {}).get("login", "?"))
        if repos is not None:
            self.SELECTED[inst["id"]] = (now(), repos)
        return repos

    def installation_repos(self, jwt, iid, login, active=False):
        """Every repository of one installation, in lower case, read with a token of metadata only; None when it has
        more than the door reads. active (github_repos): archived repositories are left out, and a page that GitHub
        does not give is an error instead of the end of the list."""
        status, got = self.http("POST", f"{GitHub.API}/app/installations/{iid}/access_tokens",
                                {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json",
                                 "Content-Type": "application/json"},
                                json.dumps({"permissions": {"metadata": "read"}}).encode())
        token = got.get("token") if status == 201 and isinstance(got, dict) else None
        if not isinstance(token, str):
            raise door_providers.Stop(f"GitHub gave no token to read {login}'s installation ({status})")
        repos = set()
        for page in range(1, GITHUB_REACH_PAGES + 1):
            status, got = self.http("GET", f"{GitHub.API}/installation/repositories?per_page=100&page={page}",
                                    {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}, None)
            rows = got.get("repositories") if status == 200 and isinstance(got, dict) else None
            if active and not isinstance(rows, list):
                raise door_providers.Stop(f"GitHub gave no list of {login}'s repositories ({status})")
            rows = [r for r in rows or [] if isinstance(r, dict)]
            repos.update(r["full_name"].lower() for r in rows
                         if isinstance(r.get("full_name"), str) and not (active and r.get("archived")))
            if len(rows) < 100:
                return repos
        return None

    def github_repos(self):
        """Every repository that the door's GitHub Apps reach, for the app's list that gives an agent its repositories
        (9 November 2026, the owner's yes to that list): {"accounts": {account: {"name": the account as GitHub writes
        it, "repos": [owner/name, ...]}}}, account and repository names in lower case. Unlike github_reach it lists an
        installation that has all its account's repositories too. Archived repositories and suspended installations
        are left out; an installation with more than the door reads is an error."""
        apps = sorted({(str(c["app_id"]), c["secret"]) for k, c in (self.access().get("credentials") or {}).items()
                       if k.lower().startswith("github:") and isinstance(c, dict) and c.get("app_id") and c.get("secret")})
        accounts = {}
        for app_id, ref in apps:
            jwt = door_providers.app_jwt(app_id, self.secret(ref))
            status, installs = self.http("GET", f"{GitHub.API}/app/installations?per_page=100",
                                         {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json"},
                                         None)
            if status != 200 or not isinstance(installs, list):
                raise door_providers.Stop(f"GitHub gave no list of the App's installations ({status})")
            for one in installs:
                account = (one.get("account") if isinstance(one, dict) else None) or {}
                iid, login = one.get("id") if isinstance(one, dict) else None, account.get("login")
                if isinstance(iid, bool) or not isinstance(iid, int) or not isinstance(login, str) or \
                        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", login) or one.get("suspended_at"):
                    continue
                listed = self.installation_repos(jwt, iid, login, active=True)
                if listed is None:
                    raise door_providers.Stop(f"{login} has more repositories than the door reads")
                entry = accounts.setdefault(login.lower(), {"name": login, "repos": set()})
                entry["repos"] |= {r for r in listed if door_targets.REPO.fullmatch(r) and
                                   r.split("/")[0] == login.lower()}
        return {"accounts": {a: {"name": e["name"], "repos": sorted(e["repos"])} for a, e in sorted(accounts.items())}}

    def github_key(self, app_id, ref=None):
        """One key of an App of the door's file, for the hub's renewal of the key that it held (plan 13, item 4, the
        coordinator's yes of 7 November 2026): the references that the file names for that App, and of ref (the first
        of them, or another key that the door still holds) its fingerprint as GitHub's page shows it, whether GitHub
        still takes it, and the App's settings page. No key and no token leaves the door."""
        app_id = str(app_id or "")
        if not re.fullmatch(r"[1-9][0-9]{0,11}", app_id):
            raise Refused("app_id is the App's number")
        used = sorted({c["secret"] for k, c in (self.access().get("credentials") or {}).items()
                       if k.lower().startswith("github:") and isinstance(c, dict) and str(c.get("app_id")) == app_id
                       and isinstance(c.get("secret"), str)})
        if not used:
            raise Refused(f"the door's file names no key of App {app_id}")
        ref = ref or used[0]
        pem = door_providers.app_pem(self.secret(ref))
        try:
            der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem.encode(),
                                 capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            raise door_providers.Stop("openssl could not read the App key") from None
        if der.returncode != 0 or not der.stdout:
            raise door_providers.Stop("openssl could not read the App key")
        out = {"used": used, "ref": ref,
               "fingerprint": "SHA256:" + base64.b64encode(hashlib.sha256(der.stdout).digest()).decode()}
        status, app = self.http("GET", f"{GitHub.API}/app", {"Authorization": "Bearer " + door_providers.app_jwt(
            app_id, pem), "Accept": "application/vnd.github+json"}, None)
        if status == 401:
            return dict(out, signs=False)
        if status != 200 or not isinstance(app, dict):
            raise door_providers.Stop(f"GitHub did not say whether it takes the App key ({status})")
        owner = app.get("owner") if isinstance(app.get("owner"), dict) else {}
        login, slug = owner.get("login"), app.get("slug")
        if not (isinstance(login, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", login) and
                isinstance(slug, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", slug)):
            raise door_providers.Stop("GitHub gave no account and no name of the App")
        where = f"organizations/{login}/settings" if owner.get("type") == "Organization" else "settings"
        return dict(out, signs=True, owner=login, page=f"https://github.com/{where}/apps/{slug}")

    def github_reach(self):
        """What the door's GitHub Apps reach, for the hub's marks of "What the App reaches" once the hub holds no App
        key (DevOps plan 13, item 4): each installation's settings page, built here from its account and its id and
        never taken from GitHub's answer; the accounts whose installation has all their repositories; the repositories
        of the others; the page that installs the App on another account; and the accounts that own the Apps. Every
        name in lower case."""
        apps = sorted({(str(c["app_id"]), c["secret"]) for k, c in (self.access().get("credentials") or {}).items()
                       if k.lower().startswith("github:") and isinstance(c, dict) and c.get("app_id") and c.get("secret")})
        pages, every, repos, install, owners = {}, set(), set(), None, set()
        for app_id, ref in apps:
            headers = {"Authorization": "Bearer " + door_providers.app_jwt(app_id, self.secret(ref)),
                       "Accept": "application/vnd.github+json"}
            status, app = self.http("GET", f"{GitHub.API}/app", headers, None)
            slug = app.get("slug") if status == 200 and isinstance(app, dict) else None
            login = ((app.get("owner") if status == 200 and isinstance(app, dict) else None) or {}).get("login")
            if isinstance(login, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", login):
                owners.add(login.lower())       # a private App reaches only the account that made it
            if install is None and isinstance(slug, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", slug):
                install = f"https://github.com/apps/{slug}/installations/new"
            status, installs = self.http("GET", f"{GitHub.API}/app/installations?per_page=100", headers, None)
            if status != 200 or not isinstance(installs, list):
                raise door_providers.Stop(f"GitHub gave no list of the App's installations ({status})")
            for one in installs:
                account = (one.get("account") if isinstance(one, dict) else None) or {}
                iid, login = one.get("id") if isinstance(one, dict) else None, account.get("login")
                if isinstance(iid, bool) or not isinstance(iid, int) or not isinstance(login, str) or \
                        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", login):
                    continue
                pages[login.lower()] = (f"https://github.com/organizations/{login}/settings/installations/{iid}"
                                        if account.get("type") == "Organization" else
                                        f"https://github.com/settings/installations/{iid}")
                if one.get("suspended_at"):
                    continue        # it reaches nothing until the owner lets it work again, on that same page
                if one.get("repository_selection") == "all":
                    every.add(login.lower())
                    continue
                listed = self.installation_repos(headers["Authorization"][7:], iid, login)
                if listed is None:
                    every.add(login.lower())    # more than the door reads: the hub marks none of this account's
                else:
                    repos.update(listed)
        return {"pages": pages, "all": sorted(every), "repos": sorted(repos), "install": install,
                "owners": sorted(owners)}


class GitHub:
    """One repository through the door's App of its owner: the commits the door makes, the filtered read of the
    GitOps repository, workflow runs, and the facts of the checks. A token of the App lasts an hour and stays here."""
    API = "https://api.github.com"
    TOKENS = {}                 # owner -> (token, until)
    BRANCHES = {}               # repository -> (its default branch, until)

    def __init__(self, door, access, repo):
        self.door, self.access, self.repo = door, access, repo
        self.owner = repo.split("/")[0]
        self.run_id = None          # the run that this object's last waited dispatch started
        self.commit_sha = self.commit_branch = None     # the commit that this object made last

    def token(self):
        got = self.TOKENS.get(self.owner.lower())
        if got and got[1] > now() + 300:
            return got[0]
        conf = github_app(self.access, self.owner) or {}
        ctx = {"credentials": dict(conf, owner=self.owner), "http": self.door.http, "secret": self.door.secret}
        try:
            token = door_providers.github_token(dict(conf, owner=self.owner), ctx, self.repo)
        except KeyError:
            raise Refused(f"the door has no App of {self.owner}") from None
        self.TOKENS[self.owner.lower()] = (token, now() + 3300)
        return token

    def branch(self):
        """The repository's default branch, as GitHub names it (main, master, ...), kept for an hour."""
        got = self.BRANCHES.get(self.repo.lower())
        if got and got[1] > now():
            return got[0]
        status, answer = self.call("GET", f"/repos/{self.repo}")
        name = answer.get("default_branch") if status == 200 and isinstance(answer, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", name):
            raise door_providers.Stop(f"GitHub gave no default branch of {self.repo} ({status})")
        self.BRANCHES[self.repo.lower()] = (name, now() + 3600)
        return name

    def call(self, method, path, body=None):
        status, answer = self.door.http(method, self.API + path, {
            "Authorization": "Bearer " + self.token(), "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"},
            None if body is None else json.dumps(body).encode())
        return status, answer

    def file_at_head(self, path, branch=None):
        ref = urllib.parse.quote(branch or self.branch(), safe="")
        status, answer = self.call("GET", f"/repos/{self.repo}/contents/{urllib.parse.quote(path)}?ref={ref}")
        if status != 200 or not isinstance(answer, dict) or answer.get("encoding") != "base64":
            return None
        return base64.b64decode(answer["content"])

    def read(self, path, access):
        """A read at HEAD of the GitOps repository, through the filter: no Secret object leaves the door."""
        data = self.file_at_head(path)
        if data is None:
            raise Refused(f"{path} is not a file at HEAD")
        # The file as the patterns read it. One that is not block style is no refusal here, as it is in a commit: the
        # repository's own people wrote it, and the door is the agent's only way to read it. So it comes back, unless
        # the filter keeps it back (door_targets.kept_back).
        kept = door_targets.kept_back(path, data)
        if kept:
            raise Refused(f"{path} {kept}")
        text, why = door_targets.manifest_text(path, data)
        return data.decode("utf-8") if why else data.decode("utf-8", "replace")

    def commit(self, plan):
        """One commit on the branch's head, made through the API: the blobs, one tree on the head's tree, the commit,
        and the branch moved to it only when nothing moved it meanwhile. A commit that the door rendered goes on the
        commit that it rendered (plan parent), not on a head that it reads now."""
        branch = plan.get("branch") or self.branch()
        head = plan.get("parent")       # the commit that the door rendered: GitHub refuses the move if the branch left it
        if not head:
            status, ref = self.call("GET", f"/repos/{self.repo}/git/ref/heads/{branch}")
            if status != 200:
                raise door_providers.Stop(f"GitHub answered {status} for {branch}")
            head = ref["object"]["sha"]
        status, base = self.call("GET", f"/repos/{self.repo}/git/commits/{head}")
        if status != 200:
            raise door_providers.Stop(f"GitHub answered {status} for the head commit")
        entries = []
        for path, data, mode in plan["files"]:
            if data is None:
                entries.append({"path": path, "mode": mode, "type": "blob", "sha": None})
                continue
            status, blob = self.call("POST", f"/repos/{self.repo}/git/blobs",
                                     {"content": base64.b64encode(data).decode(), "encoding": "base64"})
            if status != 201:
                raise door_providers.Stop(f"GitHub answered {status} for a blob")
            entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})
        status, tree = self.call("POST", f"/repos/{self.repo}/git/trees",
                                 {"base_tree": base["tree"]["sha"], "tree": entries})
        if status != 201:
            raise door_providers.Stop(f"GitHub answered {status} for the tree")
        status, made = self.call("POST", f"/repos/{self.repo}/git/commits",
                                 {"message": plan["message"], "tree": tree["sha"], "parents": [head]})
        if status != 201:
            raise door_providers.Stop(f"GitHub answered {status} for the commit")
        if plan.get("parent"):
            # GitHub takes every move that is a fast-forward, also from a commit before the one that was rendered (a
            # branch that somebody set back). So the door reads the branch once more, just before it moves it.
            status, ref = self.call("GET", f"/repos/{self.repo}/git/ref/heads/{branch}")
            if status != 200 or ((ref or {}).get("object") or {}).get("sha") != head:
                raise door_providers.Stop(f"{branch} moved while the door rendered the commit: nothing changed")
        status, moved = self.call("PATCH", f"/repos/{self.repo}/git/refs/heads/{branch}",
                                  {"sha": made["sha"], "force": False})
        if status != 200:
            raise door_providers.Stop(f"{branch} moved meanwhile, or GitHub refused ({status}): nothing changed")
        self.commit_sha, self.commit_branch = made["sha"], branch
        return f"{self.repo} {branch} is at {made['sha']}"

    def dispatch(self, workflow, inputs, wait=False):
        """One workflow_dispatch on the default branch. wait (a GitOps sync): the call waits for that run to end and
        answers with how it ended, so a sync that fails is a failed call, in the door's record and for the agent;
        before, the door wrote done as soon as GitHub took the dispatch. GitHub gives the run's id when the request
        asks for it (return_run_details, REST API 2022-11-28; version 2026-03-10 gives it always). A plain 204 with
        no id: the door finds the run by its workflow, branch and start."""
        branch, started = self.branch(), now()
        path = f"/repos/{self.repo}/actions/workflows/{workflow}/dispatches"
        status, answer = self.call("POST", path, {"ref": branch, "inputs": inputs, "return_run_details": True})
        if status == 422 and "return_run_details" in json.dumps(answer):     # an API that does not know it
            status, answer = self.call("POST", path, {"ref": branch, "inputs": inputs})
        if status not in (200, 204):
            raise door_providers.Stop(f"GitHub answered {status} for {workflow}")
        if not wait:
            return f"{workflow} of {self.repo} started"
        run = answer.get("workflow_run_id") if status == 200 and isinstance(answer, dict) else None
        if not isinstance(run, int) or isinstance(run, bool) or run <= 0:
            run = self.find_run(workflow, branch, started)
        self.run_id = run
        return self.wait_run(workflow, run)

    def find_run(self, workflow, branch, started):
        """The id of the run that a dispatch started, when GitHub's answer named none: the one run of this workflow
        on this branch, by workflow_dispatch, that began at the dispatch or after it. Two such runs are no answer: the
        door cannot tell which one is its own."""
        query = urllib.parse.urlencode({"event": "workflow_dispatch", "branch": branch, "per_page": "20"})
        deadline = now() + RUN_FIND
        while True:
            status, runs = self.call("GET", f"/repos/{self.repo}/actions/workflows/{workflow}/runs?{query}")
            mine = []
            for r in ((runs or {}).get("workflow_runs") or []) if status == 200 and isinstance(runs, dict) else []:
                try:
                    begun = calendar.timegm(time.strptime(str(r.get("created_at"))[:19], "%Y-%m-%dT%H:%M:%S"))
                except ValueError:
                    continue
                if begun >= int(started) - 2 and isinstance(r.get("id"), int):
                    mine.append(r["id"])
            if len(mine) == 1:
                return mine[0]
            if len(mine) > 1:
                raise door_providers.Stop(f"{workflow} of {self.repo} started, and GitHub named no run: {len(mine)} "
                                          f"runs began since, so the door cannot say which one is this call's")
            if now() >= deadline:
                raise door_providers.Stop(f"{workflow} of {self.repo} started, and no run of it showed up within "
                                          f"{RUN_FIND} seconds")
            time.sleep(RUN_POLL)

    def wait_run(self, workflow, run):
        """How one run ended, once GitHub says that it is completed: the answer for success, Stop for every other
        conclusion (with the jobs and steps that failed) and for a run that has not ended after RUN_WAIT."""
        url = f"https://github.com/{self.repo}/actions/runs/{run}"
        deadline = now() + RUN_WAIT
        while True:
            status, got = self.call("GET", f"/repos/{self.repo}/actions/runs/{run}")
            if status == 200 and isinstance(got, dict):
                url = got.get("html_url") if isinstance(got.get("html_url"), str) else url
                if got.get("status") == "completed":
                    ended = got.get("conclusion")
                    if ended == "success":
                        return f"{workflow} of {self.repo}: run {run} passed ({url})"
                    raise RunFailed(f"{workflow} of {self.repo}: run {run} ended "
                                    f"{run_word(ended)}{self.failed_steps(run)} ({url})")
            if now() >= deadline:
                raise RunFailed(f"{workflow} of {self.repo}: run {run} did not end within "
                                f"{RUN_WAIT // 60} minutes, so the door cannot say that it passed ({url})")
            time.sleep(RUN_POLL)

    def wait_checks(self, sha, branch=None):
        """(passed, words): how the workflow runs that the push of this commit started ended, for a GitOps commit
        through the door. The door waits CHECKS_FIND seconds for them to show up, the late ones too, then until each
        has ended, CHECKS_WAIT at most. Before, nobody learned that a commit broke the repository's own checks: on 11
        November 2026 they stayed red for about 31 hours. A run that does not end in time, or runs that GitHub does not
        give, are no failure of the commit: the words say so, and so do they of a check that failed on its run before
        this commit too (failed_before)."""
        query = urllib.parse.urlencode({"head_sha": sha, "event": "push", "per_page": "50"})
        begun = now()
        while True:
            status, got = self.call("GET", f"/repos/{self.repo}/actions/runs?{query}")
            if status != 200 or not isinstance(got, dict):
                return True, f"the door could not read its checks (GitHub answered {status})"
            runs = [r for r in got.get("workflow_runs") or [] if isinstance(r, dict) and isinstance(r.get("id"), int)
                    and not isinstance(r.get("id"), bool) and r.get("head_sha") in (None, sha)]
            settled = now() - begun >= CHECKS_FIND
            if settled and not runs:
                return True, "no check ran for it"
            if settled and all(r.get("status") == "completed" for r in runs):
                break
            if now() - begun >= CHECKS_WAIT:
                going = [run_word(r.get("name")) for r in runs if r.get("status") != "completed"]
                return True, (f"{len(going)} of its checks had not ended after {CHECKS_WAIT // 60} minutes: "
                              f"{', '.join(going[:5])}")
            time.sleep(RUN_POLL)
        bad = [r for r in runs if r.get("conclusion") not in ("success", "skipped", "neutral")]
        if not bad:
            return True, "its checks passed: " + ", ".join(sorted({run_word(r.get("name")) for r in runs}))

        def said(some):
            return "; ".join(f"{run_word(r.get('name'))} ended {run_word(r.get('conclusion'))}"
                             f"{self.failed_steps(r['id'])} ({r.get('html_url') if isinstance(r.get('html_url'), str) else r['id']})"
                             for r in some[:3])
        # A check that failed on its run before this commit too is not this commit's doing (12 November 2026: one that a
        # commit of the day before left red made each later door commit a failed call, which says "revert it").
        old = [r for r in bad if self.failed_before(r, branch)] if branch else []
        new = [r for r in bad if r not in old]
        if not new:
            return True, (f"its checks passed, except {len(old)} that failed on the run before this commit too, so not "
                          f"by this commit: {said(old)}")
        also = f"; and {len(old)} more that failed on the run before this commit too" if old else ""
        return False, (f"its check {said(new)}" if len(new) == 1 else f"{len(new)} of its checks failed: {said(new)}") + also

    def failed_before(self, run, branch):
        """True when the newest run of the same workflow on the branch before this run that passed or failed (and was
        not cancelled), failed."""
        wid, number = run.get("workflow_id"), run.get("run_number")
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (wid, number)):
            return False
        query = urllib.parse.urlencode({"branch": branch, "event": "push", "status": "completed", "per_page": "20"})
        status, got = self.call("GET", f"/repos/{self.repo}/actions/workflows/{wid}/runs?{query}")
        if status != 200 or not isinstance(got, dict):
            return False
        earlier = [r for r in got.get("workflow_runs") or [] if isinstance(r, dict) and r.get("workflow_id") in (None, wid)
                   and isinstance(r.get("run_number"), int) and not isinstance(r.get("run_number"), bool)
                   and r["run_number"] < number and r.get("conclusion") in ("success", "failure")]
        return bool(earlier) and max(earlier, key=lambda r: r["run_number"]).get("conclusion") == "failure"

    def run_text(self, run):
        """The logs of a run's jobs that ran, one after the other: what a listing run printed (Door.prune_listing). A
        skipped job has no log (12 November 2026: GitHub answers 404 for it, and the first live listing failed so),
        and the log of a job that just ended can come a few seconds late."""
        status, got = self.call("GET", f"/repos/{self.repo}/actions/runs/{run}/jobs?per_page=50")
        jobs = [j for j in ((got or {}).get("jobs") or [] if status == 200 and isinstance(got, dict) else [])
                if isinstance(j, dict) and isinstance(j.get("id"), int) and not isinstance(j.get("id"), bool)
                and j.get("conclusion") != "skipped"]
        if not jobs:
            raise door_providers.Stop(f"GitHub gave no jobs of run {run} that ran ({status})")
        texts = []
        for job in jobs:
            for attempt in range(LOG_TRIES):
                try:
                    texts.append(self.job_log(job["id"]))
                    break
                except door_providers.Stop:
                    if attempt == LOG_TRIES - 1:
                        raise
                    time.sleep(LOG_PAUSE)
        return "\n".join(texts)

    def job_log(self, job):
        """The log of one job, as text, LOG_MOST bytes at most. GitHub answers with a redirect to an address that needs
        no token, and the door follows it with no token: the App's token never goes to another host."""
        status, location = http_redirect("GET", f"{self.API}/repos/{self.repo}/actions/jobs/{job}/logs", {
            "Authorization": "Bearer " + self.token(), "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"})
        if status not in (301, 302, 303, 307, 308) or not isinstance(location, str) or \
                not location.startswith("https://"):
            raise door_providers.Stop(f"GitHub gave no log of job {job} ({status})")
        status, raw = http_raw("GET", location, {}, LOG_MOST)
        if status != 200:
            raise door_providers.Stop(f"the log of job {job} could not be read ({status})")
        return raw.decode("utf-8", "replace")

    def failed_steps(self, run):
        "The jobs and steps of a run that failed, as words for the answer: ', in <job> / <step>' for three at most."
        status, got = self.call("GET", f"/repos/{self.repo}/actions/runs/{run}/jobs?per_page=50")
        found = []
        for job in ((got or {}).get("jobs") or []) if status == 200 and isinstance(got, dict) else []:
            if not isinstance(job, dict) or job.get("conclusion") in (None, "success", "skipped", "neutral"):
                continue
            steps = [s.get("name") for s in job.get("steps") or []
                     if isinstance(s, dict) and s.get("conclusion") not in (None, "success", "skipped", "neutral")]
            found.append(" / ".join(run_word(x) for x in [job.get("name")] + steps[:1] if x))
        return (", in " + "; ".join(found[:3])) if found else ""

    def image_made(self, image):
        """True when a green run of the repository that built the image made its tag: the run of that tag's push, or
        one whose head commit is the tag. That repository is the one that the access file's `images` names for the
        image, else the image's own <owner>/<name>, which GitHub reads in any case. A run it cannot read is no run."""
        name, _, tag = image.rpartition(":")
        if not name or "/" in tag or "@" in name or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", tag):
            return False
        repo = (self.access.get("images") or {}).get(name) or "/".join(name.split("/")[-2:])
        if not door_targets.REPO.fullmatch(repo) or door_targets.vendor(repo):
            return False
        built = GitHub(self.door, self.access, repo)
        try:
            if re.fullmatch(r"[0-9a-f]{7,40}", tag):
                status, runs = built.call("GET", f"/repos/{repo}/actions/runs?status=success&per_page=100")
                return status == 200 and any(str(r.get("head_sha", "")).startswith(tag)
                                             for r in (runs or {}).get("workflow_runs") or [])
            status, runs = built.call("GET", f"/repos/{repo}/actions/runs?" + urllib.parse.urlencode(
                {"branch": tag, "status": "success", "per_page": "20"}))
            return status == 200 and any(r.get("head_branch") == tag for r in (runs or {}).get("workflow_runs") or [])
        except (Refused, door_providers.Stop):
            return False

    def deploy_facts(self, repo):
        entry = None
        for a in (self.access.get("agents") or {}).values():
            entry = entry or ((a.get("repos") or {}).get(repo) or None)
        workflow = (entry or {}).get("deploy")
        status, head = self.call("GET", f"/repos/{repo}/commits/{urllib.parse.quote(self.branch(), safe='')}")
        if status != 200:
            return None
        status, runs = self.call("GET", f"/repos/{repo}/actions/workflows/{workflow}/runs?status=success&per_page=1")
        released = ((runs or {}).get("workflow_runs") or [{}])[0].get("head_sha") if status == 200 else None
        status, checks = self.call("GET", f"/repos/{repo}/commits/{head['sha']}/check-runs?per_page=100")
        green = status == 200 and all(c.get("conclusion") in ("success", "skipped", "neutral")
                                      for c in checks.get("check_runs") or [{}])
        hold = (entry or {}).get("hold")
        return {"parent": (head.get("parents") or [{}])[0].get("sha"), "released": released,
                "door_made": ((head.get("commit") or {}).get("committer") or {}).get("name", "").endswith("[bot]"),
                "green": green, "hold": bool(hold and self.file_at_head(hold) not in (None, b""))}


def github_app(access, owner):
    """The door's App of one owner (credentials github:<owner>), in whatever case the owner's name comes."""
    want = f"github:{owner}".lower()
    return next((c for k, c in (access.get("credentials") or {}).items() if k.lower() == want), None)


def sole_app(access):
    """The door's one GitHub App, when its file names one App only: an account that the owner installed it on after
    the move has no line of its own yet, and GitHub's installation of the repository decides, as it did for the hub."""
    apps = {(str(c.get("app_id")), c.get("secret")): c for k, c in (access.get("credentials") or {}).items()
            if k.lower().startswith("github:") and isinstance(c, dict) and c.get("app_id")}
    return next(iter(apps.values())) if len(apps) == 1 else None


def token_permissions(level, held):
    """The permissions of an agent's token at this level, from an installation that holds `held` (its own
    permissions, as GitHub gives them with the installation): GITHUB_ACCESS of the level, and two that an App can
    lack. For read and write also actions: read where the installation holds Actions, so that the agent can read the
    runs of GitHub Actions and show that CI passed (10 November 2026: a write token got 404 on a repository's runs).
    And issues where the installation holds Issues: read at read, so that the agent reads the issues of its
    repositories, and write at write and deploy, so that it also opens them and comments on them (12 November 2026: a
    write token got 403 on a comment to the developer that the team's policy lets it talk to in GitHub issues), but
    never more than the installation holds. GitHub refuses the whole token (422) when it asks for a permission that
    the installation does not hold, and an older App can lack both, so where the installation names neither the
    token is exactly GITHUB_ACCESS of the level."""
    asked = dict(GITHUB_ACCESS[level])
    held = held if isinstance(held, dict) else {}
    if level in ("read", "write") and held.get("actions") in ("read", "write"):
        asked["actions"] = "read"
    if held.get("issues") in ("read", "write"):
        asked["issues"] = "write" if level != "read" and held["issues"] == "write" else "read"
    return asked


class NoRedirect(urllib.request.HTTPRedirectHandler):
    "A redirect comes back as the answer, and is not followed."

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_redirect(method, url, headers, timeout=30):
    """(status, the Location of a redirect, or the answer's text): one call that never follows a redirect, so that its
    headers, a token among them, reach this host alone."""
    req = urllib.request.Request(url, method=method, headers=dict(headers, **{"User-Agent": "fleet-door"}))
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as r:
            return r.status, r.read(64 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location") if e.code in (301, 302, 303, 307, 308) else ""
    except (urllib.error.URLError, OSError) as e:
        return 599, str(e)


def http_raw(method, url, headers, limit, timeout=120):
    """(status, the bytes of the answer, at most `limit`): a tarball, or the archive of a pinned program."""
    req = urllib.request.Request(url, method=method, headers=dict(headers, **{"User-Agent": "fleet-door"}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(limit)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, OSError):
        return 599, b""


def box_call(header, blobs):
    """One request to the render box, and its answer (door_render.serve): the header as one JSON line, then the bytes
    that it names. {ok: False, skip} when the box is not there, and {ok: False, why, again} when it took the request
    and gave no answer: a render that ended early says nothing about the commit, so the commit is refused."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(RENDER_WAIT)
        s.connect(P(RENDER_SOCKET))
    except OSError as e:
        s.close()
        return {"v": 1, "ok": False, "skip": f"the render box is not there ({e.__class__.__name__})"}
    try:
        with s:
            s.sendall(json.dumps(header).encode() + b"\n")
            for blob in blobs:
                s.sendall(blob)
            s.shutdown(socket.SHUT_WR)
            got = bytearray()
            while len(got) <= RENDER_ANSWER_MAX:
                chunk = s.recv(1024 * 1024)
                if not chunk:
                    break
                got += chunk
        said = json.loads(got)
        if not isinstance(said, dict) or said.get("v") != 1:
            raise ValueError("no answer of version 1")
        return said
    except (OSError, ValueError, RecursionError) as e:
        return {"v": 1, "ok": False, "again": True,
                "why": f"the render box gave no answer ({e.__class__.__name__}): send the same call again"}


def run_program(argv, stdin, env, timeout=600, limit=None):
    """(status, output) of one program. limit: the most bytes of its output that the door reads; a program that
    writes more is stopped, with status 1 and one line in place of its output."""
    env = dict({"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}, **env)
    if limit is not None:
        return run_capped(argv, stdin, env, timeout, limit)
    try:
        r = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
                           env=env, stdin=None if stdin is not None else subprocess.DEVNULL)
    except FileNotFoundError:
        return 127, f"{argv[0]} is not on the door"
    except subprocess.TimeoutExpired:
        return 124, f"{os.path.basename(argv[0])} took longer than {timeout} seconds"
    return r.returncode, r.stdout.decode("utf-8", "replace")


def run_capped(argv, stdin, env, timeout, limit):
    """run_program with a cap on the output: one thread reads it and stops the program at the first byte over the cap,
    and one writes the input, so that neither pipe fills while the other waits."""
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    except FileNotFoundError:
        return 127, f"{argv[0]} is not on the door"
    got, over = [], []

    def read():
        size = 0
        with contextlib.suppress(OSError, ValueError):
            while True:
                chunk = p.stdout.read1(65536)
                if not chunk:
                    return
                size += len(chunk)
                if size > limit:
                    over.append(size)
                    p.kill()
                    return
                got.append(chunk)

    def write():
        with contextlib.suppress(OSError, ValueError):
            p.stdin.write(stdin)
        with contextlib.suppress(OSError, ValueError):
            p.stdin.close()
    threads = [threading.Thread(target=fn, daemon=True) for fn in ([read, write] if stdin is not None else [read])]
    for t in threads:
        t.start()
    late = False
    try:
        p.wait(timeout)
    except subprocess.TimeoutExpired:
        late = True
        p.kill()
        p.wait()
    for t in threads:
        t.join(5)
    if not threads[0].is_alive():       # a reader that still waits holds the pipe: closing it here would wait too
        with contextlib.suppress(OSError, ValueError):
            p.stdout.close()
    name = os.path.basename(argv[0])
    if late:
        return 124, f"{name} took longer than {timeout} seconds"
    if over:
        return 1, f"{name} wrote more than {limit // 1024} KiB, which the door does not read"
    return p.returncode, b"".join(got).decode("utf-8", "replace")


# ---------------------------------------------------------------- HTTP

class CallerGone(Exception):
    """The caller ended its connection while the door read its request or wrote its answer: no error of the door's."""


class Handler(BaseHTTPRequestHandler):
    server_version = "fleet-door"
    door = None                 # the Door, set by serve()

    def log_message(self, fmt, *args):
        pass

    def source(self):
        return self.client_address[0]

    def answer(self, status, data):
        raw = json.dumps(data).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            raise CallerGone() from None

    def bearer(self):
        value = self.headers.get("Authorization") or ""
        return value[7:].strip() if value.lower().startswith("bearer ") else None

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0:           # a read of a negative length would go on to the end of the stream, with no cap
            raise Refused("the Content-Length is a number, 0 or more")
        if n > BODY_MAX:
            raise Refused("the body is over 512 KiB")
        try:
            raw = self.rfile.read(n)
        except (BrokenPipeError, ConnectionResetError):
            raise CallerGone() from None
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            raise Refused("the body is not JSON") from None
        if not isinstance(data, dict):
            raise Refused("the body is a JSON object")
        return data

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/ping":
            agent = self.door.caller(self.source())
            return self.answer(200 if agent else 403, {"ok": bool(agent), "agent": agent})
        if path == "/record":
            if not self.door.hub_allowed(self.source(), self.bearer(), "record_sha256"):
                return self.answer(403, {"error": "the record is the hub's to read, with its own secret"})
            after = urllib.parse.parse_qs(query).get("after", ["0"])[0]
            return self.answer(200, {"entries": self.door.record.after(int(after) if after.isdigit() else 0),
                                     "last": self.door.record.last, "modes": self.door.modes_said()})
        if path == "/github/reach":
            if not self.door.hub_allowed(self.source(), self.bearer(), "token_sha256"):
                return self.answer(403, {"error": "what the App reaches is the hub's to read, with its token secret"})
            try:
                return self.answer(200, self.door.github_reach())
            except (Refused, door_providers.Stop) as e:
                return self.answer(502, {"error": str(e)})
        if path == "/github/repos":
            if not self.door.hub_allowed(self.source(), self.bearer(), "token_sha256"):
                return self.answer(403, {"error": "the repositories that the Apps reach are the hub's to read, with "
                                                  "its token secret"})
            try:
                return self.answer(200, self.door.github_repos())
            except (Refused, door_providers.Stop) as e:
                return self.answer(502, {"error": str(e)})
        self.answer(404, {"error": "no such route"})

    def do_POST(self):
        try:
            data = self.body()
        except Refused as e:
            return self.answer(400, {"error": str(e)})
        if self.path == "/call":
            target, op, args = data.get("target"), data.get("action"), data.get("args", [])
            content = None
            if data.get("content") is not None:
                try:
                    content = base64.b64decode(data["content"], validate=True)
                except (ValueError, TypeError):
                    return self.answer(400, {"error": "content is base64"})
            result = self.door.call(self.source(), target, op, args, content)
            return self.answer(200 if result["ok"] else 403 if result["kind"] == "refused" else 502, result)
        if self.path == "/github/token":
            if not self.door.hub_allowed(self.source(), self.bearer(), "token_sha256"):
                return self.answer(403, {"error": "a GitHub token is the hub's to ask for, with its own secret"})
            try:
                tokens, errors = self.door.github_tokens(data.get("agent"), data.get("repos"))
            except Refused as e:
                return self.answer(403, {"error": str(e)})
            return self.answer(200, {"tokens": tokens, "errors": errors})
        if self.path == "/github/key":
            if not self.door.hub_allowed(self.source(), self.bearer(), "token_sha256"):
                return self.answer(403, {"error": "an App key's state is the hub's to read, with its token secret"})
            try:
                return self.answer(200, self.door.github_key(data.get("app_id"), data.get("ref")))
            except Refused as e:
                return self.answer(403, {"error": str(e)})
            except door_providers.Stop as e:
                return self.answer(502, {"error": str(e)})
        self.answer(404, {"error": "no such route"})


class DoorServer(ThreadingHTTPServer):
    """The door's HTTP server. A caller that ended its connection is no error of the door's: the hub or an agent's
    machine that gave up before the answer (Handler.answer), in the middle of its request (Handler.body), or before it
    sent one, which is a reset while the server reads the request line. socketserver printed a traceback for each one,
    as the hub's server did 630 times in 30 days (hub.HubServer), and such lines hide the errors that are the door's
    own. Every other error prints as before, also a connection that a provider reset in the door's own work: that one
    passes through a route (do_GET, do_POST)."""
    def handle_error(self, request, client_address):
        _, error, where = sys.exc_info()
        if isinstance(error, CallerGone):
            return
        if isinstance(error, (BrokenPipeError, ConnectionResetError)) and not any(
                frame.f_code.co_name in ("do_GET", "do_POST") for frame, _ in traceback.walk_tb(where)):
            return
        super().handle_error(request, client_address)


def serve(door=None, address=None, port=None):
    door = door or Door()
    Handler.door = door
    httpd = DoorServer((address or door.conf.get("address"), port or door.conf.get("port", DOOR_PORT)), Handler)
    threading.Thread(target=vault_sweep, args=(door,), daemon=True).start()
    threading.Thread(target=host_sweep, args=(door,), daemon=True).start()
    httpd.serve_forever()


def git_raw(code, *args):
    """The bytes that git gives of the door's code folder, which root owns and the door's user reads: safe.directory
    lets the door's user read it, and nothing here writes it."""
    r = subprocess.run(["git", "-c", "safe.directory=*", "-C", code, *args], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
                       env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                            "HOME": os.environ.get("HOME", "/")})
    if r.returncode != 0:
        raise ValueError(f"git {args[0]} gave {r.returncode}: {r.stderr.decode('utf-8', 'replace').strip()[-200:]}")
    return r.stdout


def host_bundle(code, manifest, floor):
    """What self-update reads (host/ops-root, verify_bundle and descends): the signed manifest of the release that the
    door runs, its commit, its root tree and its host/ tree as raw git objects, the host files, and the commits on the
    way down to the host's own release, when it has one. The published history is one commit for each release, so
    the way down is short for a host that took the releases before."""
    revision = manifest["revision"]

    def raw(kind, name):
        return base64.b64encode(git_raw(code, "cat-file", kind, name)).decode()
    listed = git_raw(code, "ls-tree", "--name-only", f"{revision}:host").decode().split()
    history = []
    if floor:
        history = [raw("commit", sha) for sha in
                   git_raw(code, "rev-list", "--ancestry-path", f"{floor}..{revision}").decode().split()
                   if sha != revision]
    return {"manifest": manifest, "commit": raw("commit", revision), "root": raw("tree", f"{revision}^{{tree}}"),
            "host": raw("tree", f"{revision}:host"), "history": history,
            "files": {name: raw("blob", f"{revision}:host/{name}") for name in HOST_FILES if name in listed}}


def update_hosts(door):
    """Each host of the access file takes the host parts of the release that the door runs: ops-root, ops-read,
    inventory and app-release, by self-update, the one form by which ops-root takes a new version of itself, and only
    from a release that a release key signed and that descends from the release that it came from. Before, a host
    kept the copy of its install for good. The door asks each host for its release and sends the update only to a host
    of another release: once for each host and release, and again after HOST_RETRY for a host that did not answer.
    Each update that the door sends leaves a line in its record. A host on the never list is no target of the door."""
    revision, manifest = running_revision(), read_json(RELEASE_JSON, None)
    code = os.path.join(P(CODE), revision) if revision else ""
    if not revision or not isinstance(manifest, dict) or manifest.get("revision") != revision or \
            not os.path.isdir(os.path.join(code, "host")):
        return []
    access = door.access()
    never = set((access.get("never") or {}).get("hosts") or [])
    with door.lock:
        state = read_json(HOSTS_FILE, {})
    done = []
    for name, host in sorted((access.get("hosts") or {}).items()):
        last = state.get(name) or {}
        if name in never or (last.get("revision") == revision and (last.get("outcome") != "unreachable" or
                                                                   now() - (last.get("at") or 0) < HOST_RETRY)):
            continue
        with door.held(door.host_locks, name):
            outcome, said = door.update_host(host, name, manifest, code)
        if outcome != "current":
            door.record.add(caller="door", target=name, action="self-update", kind="rule",
                            outcome="done" if outcome == "done" else "refused" if outcome == "refused" else "failed",
                            why=said[:300])
        done.append((name, outcome))
        with door.lock:
            write_json(HOSTS_FILE, dict(read_json(HOSTS_FILE, {}), **{name: {
                "revision": revision, "outcome": outcome, "at": round(now())}}))
    return done


def host_sweep(door, once=False):
    """update_hosts each minute, in a thread of its own: a host that does not answer holds no yes of the owner."""
    while True:
        with contextlib.suppress(Exception):
            update_hosts(door)
        if once:
            return
        time.sleep(60)


def item_secret(text):
    """The key in one opened copy. The central vault seals the item as the owner's app saved it, one JSON object with the
    key as its "password" (and the user name, the address and the seed beside it); a copy that is no such object is the
    key itself."""
    try:
        item = json.loads(text)
    except ValueError:
        return text
    secret = item.get("password") if isinstance(item, dict) else None
    return secret if isinstance(secret, str) and secret.strip() else text


def vault_sweep(door, once=False):
    """The door's sealed copies, from the hub, each minute: the hub carries a copy that the central vault sealed to
    the door's pinned key, and only this OS user opens it, with `age` and the door's own identity. The owner's signed
    yeses come the same way."""
    while True:
        with contextlib.suppress(Exception):
            fetch_sealed(door)
        with contextlib.suppress(Exception):
            fetch_approvals(door)
        with contextlib.suppress(Exception):
            end_keys(door)
        if once:
            return
        time.sleep(60)


def kept_keys():
    """The door's file of its keys, in its two parts: what each saved key is ("kinds", by account), and the work keys
    that the door made ("work", by account). A file that is not there, or that holds anything else, is an empty one:
    the door then asks what its keys are again, and makes its work keys again."""
    held = read_json(KEYS_FILE, {})
    held = held if isinstance(held, dict) else {}
    return {part: held[part] if isinstance(held.get(part), dict) else {} for part in ("kinds", "work")}


def end_keys(door):
    """The door's work keys whose grant ended, each minute: a key of an account that left the access file, or that no
    agent holds any more, is deleted at its provider with the key that made it, and leaves the door's list and its
    secrets, with one line in the record. A key that the door cannot delete now is asked again while it lives; one
    that it can no longer delete (the key that made it is gone, or the provider refuses it) only leaves the door, and
    its provider ends it within the day (door_providers.CF_KEY_LIFE). An access file that the door could not read
    ends nothing. Returns the accounts whose key left the door."""
    access = door.access()
    if not isinstance(access.get("hub"), dict):         # no file, or a broken one: it names nobody, and ends nothing
        return []
    credentials = access.get("credentials") or {}
    used = {t for a in (access.get("agents") or {}).values() if isinstance(a, dict) for t in a.get("providers") or []}
    if set(kept_keys()["kinds"]) - set(credentials):        # what the door knew of a key that left its file
        with door.lock:
            held = kept_keys()
            held["kinds"] = {t: k for t, k in held["kinds"].items() if t in credentials}
            write_json(KEYS_FILE, held)
    ended = []
    for target in sorted(kept_keys()["work"]):
        if target in credentials and target in used:
            continue
        with contextlib.suppress(Exception):        # one account that fails holds no other account's key
            if end_key(door, target, (credentials.get(target) or {}).get("secret")):
                ended.append(target)
    return ended


def end_key(door, target, ref):
    """end_keys for one account; True when its work key left the door. ref: the saved key of the account now, if the
    access file still has one; else the one that made the work key."""
    with door.held(door.key_locks, target):
        entry = kept_keys()["work"].get(target)
        if not isinstance(entry, dict):
            door.keep_work_key(target, None)
            return False
        try:
            status = door_providers.cloudflare_end(door.secret(ref or entry.get("secret")), entry.get("account_id"),
                                                   entry.get("id"), {"http": door.http})
        except Refused:
            status = None           # the door no longer holds the key that made it
        alive = isinstance(entry.get("until"), (int, float)) and entry["until"] > now()
        if status is not None and alive and (status >= 500 or status in (408, 425, 429)):
            return False            # the provider did not answer: the next minute asks again
        door.keep_work_key(target, None)
        done = status is not None and (200 <= status < 300 or status == 404)
        door.key_said(target, "key-end", "done",
                      (f"the grant ended: the door deleted its work key (token {entry.get('id')})" if done else
                       f"the grant ended: the work key left the door, and its provider ends it within the day (token "
                       f"{entry.get('id')})"))
        return True


def hub_url(hub):
    """http://<address>:<port> of the hub of the access file, with an IPv6 address in brackets."""
    host = hub["address"] if ":" not in hub["address"] else f"[{hub['address']}]"
    return f"http://{host}:{hub.get('port', 8765)}"


def fetch_sealed(door):
    hub = door.access().get("hub") or {}
    if not hub.get("address"):
        return 0
    base = hub_url(hub)
    status, answer = door.http("GET", f"{base}/door/sealed", {"X-Fleet-Client": "door"}, None)
    if status != 200 or not isinstance(answer, dict):
        return 0
    opened = 0
    keep = answer.get("keep")
    if isinstance(keep, list):          # a grant that ended: its value leaves the door too (never a minted key's)
        kept = {hashlib.sha256(str(ref).lower().encode()).hexdigest() for ref in keep}
        for name in os.listdir(P(SECRETS_DIR)) if os.path.isdir(P(SECRETS_DIR)) else []:
            if re.fullmatch(r"[0-9a-f]{64}", name) and name not in kept:
                os.remove(os.path.join(P(SECRETS_DIR), name))
    for item in answer.get("copies") or []:
        ref, sealed = item.get("login"), item.get("sealed")
        if not REF.fullmatch(str(ref or "")) or not isinstance(sealed, str):
            continue
        status, value = run_program(["age", "--decrypt", "-i", P(VAULT_KEY)], sealed.encode(), {})
        if status != 0 or not value.strip():
            continue
        os.makedirs(P(SECRETS_DIR), mode=0o700, exist_ok=True)
        path = os.path.join(P(SECRETS_DIR), hashlib.sha256(ref.lower().encode()).hexdigest())
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(item_secret(value.strip()))
        door.http("POST", f"{base}/door/sealed/{item.get('id')}", {"Content-Type": "application/json",
                                                                    "X-Fleet-Client": "door"},
                  json.dumps({"sha256": hashlib.sha256(value.strip().encode()).hexdigest()}).encode())
        opened += 1
    return opened


def fetch_approvals(door):
    """The owner's signed yeses that the hub carries (GET /door/approvals, answered to the door's address only). The
    hub can hold one back, and nothing more: the door checks each signature itself and keeps only the good ones."""
    access = door.access()
    hub = access.get("hub") or {}
    if not hub.get("address") or not access.get("owner_keys"):
        return 0
    status, answer = door.http("GET", hub_url(hub) + "/door/approvals", {"X-Fleet-Client": "door"}, None)
    if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get("approvals"), list):
        return 0
    devices = device_keys(access, answer.get("devices") if isinstance(answer.get("devices"), list) else [])
    kept = {}
    for item in answer["approvals"][:200]:
        found = approval(access, item.get("statement"), item.get("signature"), devices) \
            if isinstance(item, dict) else None
        if found:
            kept[found[0]] = {"need": found[1], "statement": item["statement"], "signature": item["signature"]}
    # The owner's signed modes (step 4): the door keeps the newest statement of each host, so an older one cannot
    # come back, and a mode that the hub stops serving stays as it was. Only a newer statement changes it, and
    # the end of the server that it was accepted for (settle_modes): each one goes with its host's key of now,
    # and none is taken that is from before the door first saw that server under its name (mode_floor).
    #
    # The signatures are checked here, before the lock that each call of an agent takes (approved): a check is some
    # milliseconds, and a hub that serves many statements must not hold the calls. The form is read first, against
    # a copy of the kept modes, so that a statement that is not newer than the kept one, which is each one of a
    # quiet minute, costs no signature check. Under the lock, each checked statement is held to the floor again.
    given = answer.get("modes") if isinstance(answer.get("modes"), list) else []
    seen = read_json(MODES_FILE, {})
    seen = json.loads(json.dumps(seen)) if isinstance(seen, dict) else {}
    settle_modes(access, seen)
    signed, checks = [], {}
    for item in given[:MODES_READ]:
        form = mode_form(access, item.get("statement")) if isinstance(item, dict) else None
        if not form or not isinstance(seen.get(form[0]), dict) or form[2] <= mode_floor(seen[form[0]]):
            continue
        checks[form[0]] = checks.get(form[0], 0) + 1
        if checks[form[0]] > MODE_CHECKS:       # the hub serves a few of each host: more of one name are not read
            continue
        if mode_statement(access, item.get("statement"), item.get("signature")) == form:
            signed.append((form, item))
    with door.lock:
        write_json(DEVICES_FILE, devices)
        write_json(APPROVALS_FILE, kept)
        modes = read_json(MODES_FILE, {})
        modes = modes if isinstance(modes, dict) else {}
        changed = settle_modes(access, modes)
        for found, item in signed:
            if isinstance(modes.get(found[0]), dict) and found[2] > mode_floor(modes[found[0]]):
                modes[found[0]] = {"mode": found[1], "at": found[2], "statement": item["statement"],
                                   "signature": item["signature"],
                                   "host_key": access["hosts"][found[0]]["host_key"]}
                changed = True
        if changed:
            write_json(MODES_FILE, modes)
    return len(kept)


# ---------------------------------------------------------------- root commands

def cmd_access(args):
    """root: the access file, one JSON object on stdin. The owner's app sends it over its own SSH."""
    if os.geteuid() != 0 and not os.environ.get("FLEET_DOOR_ROOT"):
        sys.exit("door.py access runs as root")
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        sys.exit("the access file is over 1 MiB")
    try:
        data = validate_access(json.loads(raw))
    except ValueError as e:
        sys.exit(f"refused: {e}")
    group = None
    with contextlib.suppress(KeyError):
        import grp
        group = grp.getgrnam("door").gr_gid
    # The door's group and the mode go on the file before it takes the place of the old one: a door that read it
    # between the two steps could not open it, and named nobody.
    write_json(ACCESS_FILE, data, mode=0o640, group=group)
    print(f"access file saved: {len(data.get('agents') or {})} agents, {len(data.get('hosts') or {})} hosts")


def cmd_hub_secrets(args):
    if os.geteuid() != 0 and not os.environ.get("FLEET_DOOR_ROOT"):
        sys.exit("door.py hub-secrets runs as root")
    token, record = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    write_json(HUB_FILE, {"token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                          "record_sha256": hashlib.sha256(record.encode()).hexdigest()}, mode=0o644)
    print(json.dumps({"token": token, "record": record}))


def running_revision():
    """The revision whose code `current` points at, or "" before the first update."""
    link = os.path.join(P(CODE), "current")
    return os.path.basename(os.path.realpath(link)) if os.path.lexists(link) else ""


def ensure_follow_units():
    """The root timer that takes each signed release by itself (plan 13, item 2). Every update writes it when its text
    differs, so a door that door.sh installed before it, as worker-6's, gets it at its next update."""
    changed = False
    for name, text in ((FOLLOW_UNIT + ".service", FOLLOW_SERVICE), (FOLLOW_UNIT + ".timer", FOLLOW_TIMER)):
        path = P(os.path.join(SYSTEMD, name))
        old = None
        with contextlib.suppress(OSError):
            with open(path, encoding="utf-8") as f:
                old = f.read()
        if old != text:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path + ".new", "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(path + ".new", 0o644)
            os.replace(path + ".new", path)
            changed = True
    if changed:
        run_program(["systemctl", "daemon-reload"], None, {})
    run_program(["systemctl", "enable", "--now", FOLLOW_UNIT + ".timer"], None, {})
    return changed


def write_unit(name, text):
    "One unit file of systemd, replaced whole when its text differs. True when it changed."
    path = P(os.path.join(SYSTEMD, name))
    old = None
    with contextlib.suppress(OSError):
        with open(path, encoding="utf-8") as f:
            old = f.read()
    if old == text:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".new", "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path + ".new", 0o644)
    os.replace(path + ".new", path)
    return True


def file_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def ensure_render():
    """root: the render box of GitOps commits, put in place by the door's own update, with no step of a person. The
    two pinned programs (door_render.PINS) come from their publishers: the archive has the pinned SHA-256, and so has
    the one program that is taken out of it, which becomes root's file in TOOLS_DIR; an older version goes. The
    socket and the service of the box are written when their text differs. `take` calls it, and so does every run of
    `follow`: the release that brings this code is taken by the code before it, and a download that failed is tried
    again 10 minutes later. Returns what it could not do, one line each: the door then keeps the rules that need no
    render."""
    said = []
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    tools = P(door_render.TOOLS_DIR)
    for name, pin in sorted(door_render.PINS.items()):
        path, sums = P(door_render.tool_path(name)), pin.get(arch)
        if sums is None:
            said.append(f"no {name} is pinned for {platform.machine()}")
            continue
        if file_sha256(path) == sums["program"]:
            continue
        status, raw = http_raw("GET", pin["url"].format(arch=arch), {}, TOOL_MAX)
        if status != 200 or hashlib.sha256(raw).hexdigest() != sums["archive"]:
            said.append(f"{name} {pin['version']}: its archive did not come, or is not the pinned one ({status})")
            continue
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                data = tar.extractfile(pin["member"].format(arch=arch)).read(TOOL_MAX)
        except (tarfile.TarError, KeyError, AttributeError, OSError, EOFError):
            data = b""
        if hashlib.sha256(data).hexdigest() != sums["program"]:
            said.append(f"{name} {pin['version']}: the program in its archive is not the pinned one")
            continue
        folder = os.path.dirname(path)
        os.makedirs(folder, mode=0o755, exist_ok=True)
        with open(path + ".new", "wb") as f:
            f.write(data)
        for made, mode in ((path + ".new", 0o755), (folder, 0o755), (tools, 0o755)):
            os.chmod(made, mode)
        os.replace(path + ".new", path)
        for other in os.listdir(tools):
            if other.startswith(name + "-") and other != os.path.basename(folder):
                shutil.rmtree(os.path.join(tools, other), ignore_errors=True)
    said += ensure_tree(arch, tools)
    changed = [write_unit(RENDER_UNIT + ".socket", RENDER_SOCKET_UNIT),
               write_unit(RENDER_UNIT + "@.service", RENDER_SERVICE)]
    if any(changed):
        run_program(["systemctl", "daemon-reload"], None, {})
    if changed[0] and os.path.exists(P(RENDER_SOCKET)):
        run_program(["systemctl", "restart", RENDER_UNIT + ".socket"], None, {})
    elif any(changed) or not os.path.exists(P(RENDER_SOCKET)):
        run_program(["systemctl", "enable", "--now", RENDER_UNIT + ".socket"], None, {})
    return said


def ensure_tree(arch, tools):
    """root: each pinned folder (door_render.TREE_PINS), such as the portable Ruby that a repository's own generator
    runs in the box. Its archive has the pinned SHA-256; the door unpacks it whole into TOOLS_DIR, files and folders
    only, each on a path of the folder and no link; and the program in it has its pinned SHA-256 too. The folder
    takes the place of the one before it at once, and an older version goes. Returns what it could not do, one line
    each: a repository that generates files then waits, and the render's own programs do not."""
    said = []
    for name, pin in sorted(door_render.TREE_PINS.items()):
        path, sums = P(door_render.tree_tool_path(name)), pin.get(arch)
        if sums is None:
            said.append(f"no {name} is pinned for {platform.machine()}")
            continue
        if file_sha256(path) == sums["program"]:
            continue
        url = pin["url"].format(arch=arch, brew=(pin.get("brew") or {}).get(arch, arch))
        status, raw = http_raw("GET", url, {}, TOOL_MAX)
        if status != 200 or hashlib.sha256(raw).hexdigest() != sums["archive"]:
            said.append(f"{name} {pin['version']}: its archive did not come, or is not the pinned one ({status})")
            continue
        folder = os.path.join(tools, f"{name}-{pin['version']}")
        fresh, top = folder + ".new", pin["tree"].split("/")[0]
        shutil.rmtree(fresh, ignore_errors=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                for member in tar:
                    parts = door_render.safe(member.name.rstrip("/"))
                    if parts is None or parts[0] != top or not (member.isreg() or member.isdir()):
                        raise ValueError(f"{member.name!r} is not a file or a folder of {top}")
                    dest = os.path.join(fresh, *parts)
                    if member.isdir():
                        os.makedirs(dest, mode=0o755, exist_ok=True)
                        continue
                    os.makedirs(os.path.dirname(dest), mode=0o755, exist_ok=True)
                    with tar.extractfile(member) as src, open(dest, "wb") as f:
                        shutil.copyfileobj(src, f)
                    os.chmod(dest, 0o755 if member.mode & 0o111 else 0o644)
        except (tarfile.TarError, OSError, ValueError, EOFError) as e:
            shutil.rmtree(fresh, ignore_errors=True)
            said.append(f"{name} {pin['version']}: its archive could not be unpacked ({e})"[:300])
            continue
        if file_sha256(os.path.join(fresh, *pin["member"].split("/"))) != sums["program"]:
            shutil.rmtree(fresh, ignore_errors=True)
            said.append(f"{name} {pin['version']}: the program in its archive is not the pinned one")
            continue
        for folder_in, _dirs, _names in os.walk(fresh):
            os.chmod(folder_in, 0o755)      # whatever the umask: the box's own user reads the folder
        os.chmod(tools, 0o755)
        if os.path.lexists(folder):
            os.rename(folder, folder + ".old")
        os.rename(fresh, folder)
        shutil.rmtree(folder + ".old", ignore_errors=True)
        for other in os.listdir(tools):
            if other.startswith(name + "-") and other != os.path.basename(folder):
                shutil.rmtree(os.path.join(tools, other), ignore_errors=True)
    return said


def render_ready():
    "ensure_render, for an update: its lines are printed, and nothing that it meets stops the update."
    try:
        for line in ensure_render():
            print(f"the render box: {line}")
    except Exception as e:      # noqa: BLE001  the door's release is taken whatever the box does
        print(f"the render box: {e.__class__.__name__}: {e}")


def take(raw):
    """One signed release for the door, the same for `update` and `follow`: the release keys pinned at install, of
    either file, check the manifest (a fleet that takes releases early runs one that the early key signed); a held
    release and one that does not descend from the release the door runs are refused, as every machine refuses them
    (lifecycle.may_take); the public repository is cloned at that revision beside the code that runs, `current` points
    at it, and the service starts again. Older code folders go, but the one that ran last stays. Returns a line;
    SystemExit refuses."""
    import releases
    try:
        manifest = releases.check(raw, releases.read_keys(P(ETC), "release-key.pub")
                                  + releases.read_keys(P(ETC), "early-key.pub"))
    except (ValueError, releases.Untrusted) as e:
        sys.exit(f"refused: {e}")
    if manifest.get("hold"):
        sys.exit(f"refused: release {manifest['version']} is held")
    revision, running = manifest["revision"], running_revision()
    floor = (open(P(FLOOR_FILE)).read().strip() if os.path.exists(P(FLOOR_FILE)) else "")
    target = os.path.join(P(CODE), revision)
    fresh = not os.path.isdir(target)
    repo = target
    if fresh:
        repo = tempfile.mkdtemp(dir=P(CODE), prefix=".new-")
        os.chmod(repo, 0o755)       # mkdtemp makes it 0700, and the door's own user runs the code in it
        for argv in (["git", "init", "-q", repo], ["git", "-C", repo, "fetch", "-q", UPSTREAM, revision],
                     ["git", "-C", repo, "checkout", "-q", "--detach", "FETCH_HEAD"]):
            status, out = run_program(argv, None, {}, timeout=600)
            if status != 0:
                shutil.rmtree(repo, ignore_errors=True)
                sys.exit(f"the clone at {revision} failed: {out[-300:]}")
    if floor and floor != revision:     # also for a folder of an older release that is still on the disk
        run_program(["git", "-C", repo, "fetch", "-q", UPSTREAM, floor], None, {}, timeout=600)
        status, _ = run_program(["git", "-C", repo, "merge-base", "--is-ancestor", floor, revision], None, {})
        if status != 0:
            if fresh:
                shutil.rmtree(repo, ignore_errors=True)
            sys.exit(f"refused: {revision} does not descend from {floor}, the release the door runs")
    if fresh:
        os.rename(repo, target)
    if running == revision:
        ensure_follow_units()
        render_ready()
        keep_release(manifest)
        return f"the door runs release {manifest['version']} ({revision[:12]}) already"
    link = os.path.join(P(CODE), "current")
    with contextlib.suppress(FileNotFoundError):
        os.remove(link + ".new")
    os.symlink(target, link + ".new")
    os.replace(link + ".new", link)
    with open(P(FLOOR_FILE), "w") as f:
        f.write(revision + "\n")
    run_program(["systemctl", "restart", "fleet-door.service"], None, {})
    for name in os.listdir(P(CODE)):    # the clones of older releases: a full history each, so the disk keeps two
        if re.fullmatch(r"[0-9a-f]{40}", name) and name not in (revision, running):
            shutil.rmtree(os.path.join(P(CODE), name), ignore_errors=True)
    ensure_follow_units()
    render_ready()
    keep_release(manifest)
    return f"the door runs release {manifest['version']} ({revision[:12]})"


def keep_release(manifest):
    """The signed manifest of the release that the door runs, which its pinned keys checked, kept for its hosts'
    self-update (update_hosts) where root writes and the door's user reads. A held release is never kept, as take()
    never runs one."""
    if isinstance(manifest, dict) and not manifest.get("hold") and read_json(RELEASE_JSON, None) != manifest:
        write_json(RELEASE_JSON, manifest, mode=0o644)


def cmd_update(args):
    """root: a signed release manifest on stdin. door.sh gives the first one, and the app gives one over its own SSH
    to a door that has no follow timer yet (plan 13, item 2); the timer takes every later one (cmd_follow)."""
    if os.geteuid() != 0 and not os.environ.get("FLEET_DOOR_ROOT"):
        sys.exit("door.py update runs as root")
    try:
        raw = json.loads(sys.stdin.read(65536))
    except ValueError as e:
        sys.exit(f"refused: {e}")
    print(take(raw))


def cmd_follow(args):
    """root, from the follow timer every 10 minutes: the hub's signed release (GET /door/release on the private
    network, which the hub answers only to the door's address), taken as `update` takes one when it is not the release
    that runs. The door checks it with its own pinned keys, so the hub only carries it."""
    if os.geteuid() != 0 and not os.environ.get("FLEET_DOOR_ROOT"):
        sys.exit("door.py follow runs as root")
    # The render box and its programs, in every run: the code before this one took the release that brought them, a
    # download that failed is tried again, and neither waits for the hub.
    render_ready()
    hub = read_json(ACCESS_FILE, {}).get("hub") or {}
    if not hub.get("address"):
        print("the access file names no hub yet")
        return
    status, answer = door_providers.http("GET", hub_url(hub) + "/door/release", {"X-Fleet-Client": "door"}, None)
    if status != 200 or not isinstance(answer, dict):
        sys.exit(f"the hub gave no release ({status})")
    if answer.get("revision") == running_revision():
        # A door that took this release with the code before it has no copy of its manifest: its hosts get theirs now
        import releases
        with contextlib.suppress(ValueError, releases.Untrusted):
            keep_release(releases.check(answer, releases.read_keys(P(ETC), "release-key.pub")
                                        + releases.read_keys(P(ETC), "early-key.pub")))
        return
    print(take(answer))


PROBE_WAIT = 30         # seconds that one check of probe may take; a forward that the host took runs until then


def probe(host):
    """Test 1 of the DevOps plan, as code (new-projects plan N8 (b), the coordinator's word of 6 November 2026): through
    a host's second sshd, as ops-agent with the door's own key, a login with no request, a shell, a TTY, scp, a TCP
    forward of both kinds, a Unix-socket forward and a form outside the list all fail, and a fixed read and a rule
    form through sudo ops-root work. It reads the host's key from the access file, into a known_hosts of its own. Gives
    [[name, ok, what it saw when not ok]]."""
    port, target = str(host.get("port", SSHD_PORT)), f"ops-agent@{host['address']}"
    checks = []
    with tempfile.TemporaryDirectory(prefix="door-probe-") as folder:
        known = os.path.join(folder, "known_hosts")
        with open(known, "w") as f:
            f.write(f"[{host['address']}]:{port} {host['host_key']}\n")
        opts = ["-i", P(SSH_KEY), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", f"UserKnownHostsFile={known}",
                "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "-o", "LogLevel=ERROR"]
        ssh = ["ssh", "-p", port, *opts]

        def req(op, *args):
            return base64.b64encode(json.dumps({"v": 1, "op": op, "args": list(args)}).encode()).decode()

        def check(name, argv, good):
            status, out = run_program(argv, None, {}, timeout=PROBE_WAIT)
            ok = bool(good(status, out))
            checks.append([name, ok, "" if ok else f"{status}: {out.strip()[-200:]}"])
        refused = re.compile(r"(?i)prohibited|open failed|forwarding failed")
        check("a login with no request gets no shell", ssh + ["-T", target],
              lambda status, out: status == 3 and "requests only" in out)
        check("a shell command is refused", ssh + ["-T", target, "bash -i"], lambda status, out: status == 3)
        check("no TTY", ssh + ["-tt", target, req("uptime")], lambda status, out: "PTY allocation request failed" in out)
        check("no scp", ["scp", "-P", port, *opts, "/dev/null", f"{target}:/tmp/door-probe-scp"],
              lambda status, out: status not in (0, 124))
        check("no TCP forward", ssh + ["-W", "127.0.0.1:22", target],
              lambda status, out: status not in (0, 124) and refused.search(out))
        check("no remote TCP forward", ssh + ["-N", "-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:0:127.0.0.1:22",
                                              target], lambda status, out: status not in (0, 124))
        check("no Unix-socket forward", ssh + ["-N", "-o", "ExitOnForwardFailure=yes", "-R",
                                               "/tmp/door-probe.sock:127.0.0.1:22", target],
              lambda status, out: status not in (0, 124))
        check("a form outside the list is refused", ssh + ["-T", target, req("nonsense")],
              lambda status, out: status == 3)
        check("a fixed read works", ssh + ["-T", target, req("uptime")],
              lambda status, out: status == 0 and "load average" in out)
        check("sudo ops-root runs a rule form", ssh + ["-T", target, req("daemon-reload")],
              lambda status, out: status == 0 and "systemd read its units again" in out)
    return checks


def cmd_probe(args):
    """The door's user, as the owner's app runs it over its own SSH after a host got its parts (N8 (b)): probe, as one
    JSON line {host, passed, checks}. The status is 0 only when every check passed."""
    host = (read_json(ACCESS_FILE, {}).get("hosts") or {}).get(args.host)
    if not isinstance(host, dict) or not tailnet_address(host.get("address", "")) or \
            not HOST_KEY.fullmatch(host.get("host_key", "")):
        sys.exit(f"{args.host} is no host of the access file")
    checks = probe(host)
    passed = all(ok for _, ok, _ in checks)
    print(json.dumps({"host": args.host, "passed": passed, "checks": checks}))
    sys.exit(0 if passed else 1)


def cmd_render_check(args):
    """What the render box can reach, as one JSON line (door_render.probe, run inside the box): the families of socket
    that it can make, the network interfaces that it sees, the key paths that it can read, its user and its programs.
    The status is 0 only when the box is closed and holds both programs."""
    facts = box_call({"v": 1, "op": "probe"}, [])
    print(json.dumps(facts, sort_keys=True))
    sys.exit(0 if facts.get("ok") and facts.get("boxed") and all((facts.get("tools") or {"": False}).values()) else 1)


def cmd_status(args):
    access = read_json(ACCESS_FILE, {})
    print(f"door: {len(access.get('agents') or {})} agents, {len(access.get('hosts') or {})} hosts, record "
          f"{Record().last}, release {(open(P(FLOOR_FILE)).read().strip()[:12] if os.path.exists(P(FLOOR_FILE)) else 'none')}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="door.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve").set_defaults(fn=lambda a: serve())
    sub.add_parser("access").set_defaults(fn=cmd_access)
    sub.add_parser("update").set_defaults(fn=cmd_update)
    sub.add_parser("follow").set_defaults(fn=cmd_follow)
    sub.add_parser("hub-secrets").set_defaults(fn=cmd_hub_secrets)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("render-check").set_defaults(fn=cmd_render_check)
    probing = sub.add_parser("probe")
    probing.add_argument("host")
    probing.set_defaults(fn=cmd_probe)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
