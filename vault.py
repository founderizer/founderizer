#!/usr/bin/env python3
"""Fleet vault broker for a Linux worker: the store's key and the handover key belong to the vault, not to agents.

The broker runs as its own user (for example fleet-vault). Only that user can read the key of the fleet's own store
and the age key that opens sealed handovers. Agents run as the worker's user, so they can read neither, and no
operation of the broker gives them a login: it answers with an outcome, or with a handover that only the receiving
machine's broker can open. The helper sends only a job number; the broker takes the login, the receiving agent and
that agent's pinned handover key from the hub's confirmation of the job, never from the request.

A broker opens its logins from **the fleet's own store** (store, store_key): one age-encrypted file on this machine.
No account, no organization and no network. A value reaches it only from the central vault, sealed to this broker's
pinned key (deposit); its names are listed with  store-list , and  store-init  makes the key and the empty store. The
key is an age identity in the broker's state folder, mode 600, which only the vault user can read; an agent never
reads the store, the key or a value. It is the only store: Founderizer has no Bitwarden backend any more (11 November
2026), and load_config refuses a configuration that names a Bitwarden key, so the broker does not start on one.

A broker belongs to a machine and not to one agent: `worker_group` is the group of that machine's agent users, so an
agent the owner adds later, or one whose OS user changed, reaches it with no change to its configuration. Such a
broker has no `agent` of its own and every request to it names its caller, which is how it can be installed with the
machine, before it has its first agent (`hubsetup.vault_install`). `worker_uid`, one user, is the form of a machine
that ran one agent, and it still works.

A Linux broker does handovers. Signing in needs a browser, so it is the Mac vault helper's work (same protocol).

A Linux broker also makes a new login for a confirmed job (create_login): it makes the password, keeps a record
before its one save, and answers with the login's name. It needs nothing more, because the store writes itself.

With a curl program in its configuration, a Linux broker also sends one HTTP request for a confirmed job (call_api):
to the origin of the saved login and with its key, which stays in the broker. It keeps the identity of each request
that it started, so the same request is never sent again, and a cancel ends the requests of one task attempt.
Without that key the broker sends no request.

A Linux broker also gives a session start the API keys that the owner lets the calling agent read (read): the hub
names them, and the broker reads each value and registers its fingerprints before it gives it to the worker's user.

A Linux broker also takes a key or a login that the owner typed into Founderizer on his Mac (deposit): the central
vault seals the value to this broker's pinned key, for a grant that the owner signed, the hub carries the sealed copy,
and the broker opens it, has the hub compare the value's fingerprints with the owner's, and saves it under the same
reference.

A Linux broker also gives such a delivered secret back (withdraw) when no agent of its machine holds it any more: the
hub names the reference for one confirmed job, and the broker removes the item only when its store says that the
owner's vault delivered it, never a login that the owner saved there himself or that this vault made.

With the part "swap" in its configuration, which only a root step writes, a Linux broker also keeps such a key out
of the sessions (the key swap): the session start gets a placeholder, and a second process of this program, the swap
proxy (`vault.py swap`), which runs as a user of its own that cannot read the store, puts the real key into the
Authorization header of an HTTPS request to that key's own site. The broker gives the proxy one value for one
placeholder, one OS user and one host, after the hub said that the grant is live now.

A broker writes no key into another host: place, which wrote one into an application's .env file or a Kubernetes
Secret over SSH, left the broker (DevOps plan 0.3). It hands a login over to another machine (handover) only when the
owner's keys in its own configuration show that he signed a pin of the receiving key.

With `"central": true` in its configuration, the same program is the fleet's **central vault** on the hub's server:
one store that holds every secret of the fleet, which answers only the hub's user, never calls the hub and needs no
network. It takes a value that the owner sealed to its key in his app (intake), and it seals a copy of a value only to
a machine key that the owner signed (pin, unpin, seal), only for a grant of that value to an agent of that machine
that the owner signed, or for a value that he signed into the grantable pool (grant, ungrant, pool, unpool), and its
backup only to a recovery key that the owner signed (recovery, export). The owner signs with an ECDSA P-256 key of his Mac and the vault verifies every statement itself,
so a hub that is broken into cannot add a machine of its own and pull every secret in one call. It removes a value
that the owner took out of the fleet (remove) only while no grant or pool that he signed names it. It runs as its own
user (CENTRAL_UNIT), and only root installs or updates it (`hubsetup.py central-vault`): no release reaches it.

Run a copy that the worker's user cannot change (root-owned, outside the worker's checkout), with a root-owned
configuration and programs, because an agent can change every file in its own checkout:
    python3 /usr/local/lib/fleet-vault/vault.py serve --config /etc/fleet-vault/vault.json
    python3 vault.py unit --config /etc/fleet-vault/vault.json --user fleet-vault --group <worker group>
    python3 /usr/local/lib/fleet-vault/vault.py store-init --config /etc/fleet-vault/vault.json \\
        --user fleet-vault                                       (as root; the fleet's own store, safe to run again)
    python3 /usr/local/lib/fleet-vault/vault.py store-list --config /etc/fleet-vault/vault.json
                                                                 (as the vault user; names only, never a value)
    python3 vault.py unit --central --config /etc/fleet-vault-central/vault.json --group <the hub user's group>
    python3 /usr/local/lib/fleet-vault/vault.py swap --config /etc/fleet-vault/vault.json
                                                                 (as the swap proxy's own user; its service runs it)
    python3 vault.py unit --swap --config /etc/fleet-vault/vault.json     (the swap proxy's service)
Protocol 2: one JSON line in, one JSON line out, on a Unix socket. See UI-API.md, "Vault isolation (V3)", and for the
central vault "the central vault (central_vault)".
Standard library only; Python 3.9+.
"""
# This is the one Fleet file that a release never delivers. The broker runs a root-owned copy at
# /usr/local/lib/fleet-vault/vault.py, outside every checkout a helper updates, and `lifecycle.OWNER_ONLY` lists
# this file among the ones a helper never loads -- so a commit that changes only this file advances the revision
# every machine reports and reaches no broker. Each machine brings its own copy across instead: its server service
# compares the installed program with the vault.py of its checkout and, where they differ, runs the one root
# command the installers put there, /usr/local/sbin/fleet-vault-program (server.Service.vault_program,
# hubsetup.vault_program_script). A broker that does not come up on a new program gets back the one that was
# serving, and a broker still behind ten minutes later is what the hub's `vault_behind` warning is for.
#
# So **changing this file is the only thing that exercises that path**, and on 23 October 2026 it had never run:
# over the whole retained journal of both Linux hosts, `journalctl _UID=$(id -u fleet)` held no line "brought this
# machine's vault broker onto", and eight of "could not bring" -- the command was missing until that morning, and
# the brokers were then caught up by hand. This comment is the change that tests it for the first time.
import argparse
import base64
import codecs
import fcntl
import hashlib
import json
import grp
import os
import pwd
import re
import secrets
import select
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROTOCOL = 2
PROVENANCE = 1          # a locked copy says which handover job and source login made it
KEYS = {"hub", "age_key", "socket", "age"}                                   # every broker
# agent is the one agent whose vault this is, the form of a machine that ran one agent, and it is optional: a broker
# that serves the agents of its machine has no agent of its own, and every request of such a broker names its caller
# (caller()). It can therefore be installed before the machine has its first agent, which is when a Linux machine is
# installed. A request with no caller and no agent here is refused, because nothing would say who asked.
# Who may ask this broker, one of the two or both. worker_group is the group of every agent user of this machine
# (hubsetup.AGENT_GROUP), so an agent added later, or one whose user changed, reaches the broker with no change
# here; worker_uid is one user, the form of a machine that ran one agent. A configuration with neither is refused,
# because then nobody could ask.
CALLER_KEYS = {"worker_uid", "worker_group"}
# The owner's own keys and the fleet's ID, both or neither (DevOps plan 0.3): with them a broker hands a login over only
# to a recipient that the owner signed a pin for (handover); without them it hands over nothing. The root step of a
# machine writes them (hubsetup.py vault --owner-key ... --fleet ...), and nothing the hub sends changes them.
OWNER_PIN_KEYS = {"owner_keys", "fleet"}
GROUP_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
# The store, both keys: the fleet's own encrypted file on this machine, and the key that opens it. It is the one store
# that a configuration names.
STORE_KEYS = {"store", "store_key"}
# The keys of the Bitwarden backend, which is gone (11 November 2026): a Secrets Manager project (region, token_file,
# bws, bws_config) and its write setup (sdk, sdk_sha256, write_project). A configuration with one of them is refused,
# so a broker never opens a Bitwarden token, and its store is the fleet's own.
BITWARDEN_KEYS = {"region", "token_file", "bws", "bws_config", "sdk", "sdk_sha256", "write_project"}
NO_BITWARDEN = ("Founderizer has no Bitwarden backend any more, so this vault broker does not start: its "
                "configuration names {keys}. Give it the fleet's own store: store and store_key, made by store-init, "
                "and no Bitwarden key. Its values come from the central vault.")
AGENT_NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")
CALLER_KEY = re.compile(r"[A-Za-z0-9_-]{43}")          # an agent key (owner API 1.12): 256 bits, base64url
# The central vault's own operations, beside status: a central vault serves only these, and a machine's broker none.
CENTRAL_OPERATIONS = ("intake", "pin", "unpin", "recovery", "grant", "ungrant", "pool", "unpool", "seal", "inventory",
                      "export", "remove")
OPERATIONS = ("status", "signin", "handover", "probe", "create", "request", "cancel", "read", "deposit",
              "withdraw") + CENTRAL_OPERATIONS
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,59}")         # read: the variable name of an API key, as the hub checks it
READS = 32                  # read: the most values that one session gets
STORE = 1                           # the format of the fleet's own store
REQUEST_KEY = "curl"                # optional (call_api): the curl program that sends a request; without it, none is sent
PLACE_KEY = "ssh"                   # optional and not used: place left the broker (DevOps plan 0.3); an older
                                    # installer wrote it, so a configuration that has it still loads
JOURNAL = "creates.json"            # in the broker's private state folder, beside the store
# The fixed sentences of a save, as the Mac vault helper says them for its own store. No text repeats a value.
NOT_SET_UP = "This machine's vault is not set up to save logins."
SAVE_REFUSED = "The vault store refused this save and made nothing."
SAVE_UNKNOWN = "The vault could not confirm that its store saved the login. It is not sent again."
SAVE_UNREGISTERED = "The login is saved, but the hub did not register it."
SAVE_CHANGED = "This save was made with other values. It is not made again."
NO_RECORD = "The vault could not keep its record of this save, so it made nothing."
NOT_MADE_HERE = "This vault did not make this login for that request, so it does not use it."
REQUESTS = "requests.json"          # the requests that this broker started, in the same folder
# The fixed sentences of a request (call_api). "Nothing was sent" is said only when the broker knows it. The first
# five are this broker's own; the Mac vault helper says the other eight in the same words.
NO_REQUESTS = "This machine's vault is not set up to send requests."
SAVED_ONLY = "A request needs a login that is saved in this fleet's vault, not a handed-over copy. Nothing was sent."
BAD_ADDRESS = "This login's address is not one that the vault can send to. Nothing was sent."
NO_REQUEST_RECORD = "The vault could not keep its record of this request. Nothing was sent."
NOT_STARTED = "The vault could not start this request. Nothing was sent."
NOT_HTTPS = "This login's address is not HTTPS. Nothing was sent."
NO_HEADER = "This saved value cannot be sent as a header. Nothing was sent."
UNREACHABLE = "The service could not be reached. Nothing was sent."
STOPPED = "This task's requests were stopped. Nothing was sent."
SENT_UNKNOWN = "The request may have been sent. Its answer is not known. It is not sent again."
CANCELED = "The request was stopped before its answer. The service can have received it. It is not sent again."
REPEATED = "This request was already started. It is not sent again."
NO_PROOF = "The vault cannot prove that its request ended."
# The name that a request says at the service: an edge can refuse curl's default one (6 November 2026)
USER_AGENT = "Founderizer-Fleet/1 (vault)"
REQUEST_LIMIT = 60          # seconds that the curl child of a request gets when the agent names none; a test gives less
ANSWER_LIMIT = 65536        # bytes of an answer's body that the helper gets; the child is ended when more come
HEAD_LIMIT = 262144         # bytes of an answer before its body: the status line and the headers
PATIENCE = 5                # seconds that a cancel waits for the end of a child that it ended
SERVED = 64                 # connections that the broker serves at one time; the next ones wait
NOT_SENT = (6, 7)           # curl's exit statuses that prove that nothing went out: the host's name was not found, and
                            # no connection was made. Every other end of a child that started is unknown
API_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
API_BODY = 65536            # the most bytes of a request's body
API_PATH = re.compile(r"/(?!/)[!-\"$-\[\]-~]{0,1999}")       # one leading slash, then visible ASCII without # and \
API_HEADER = re.compile(r"header:([A-Za-z][A-Za-z0-9_-]{0,63})")
API_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
# The five the agent may not set: Host decides where the key goes, Authorization is what `auth` writes, and the other
# three are how a request is smuggled. Everything else is the agent's own (hub.py says the same, at more length).
API_FIXED = ("host", "authorization", "content-length", "transfer-encoding", "connection")
API_AUTH_FIXED = API_FIXED + ("content-type",)
API_HEADERS_MAX = 16
API_VALUE = re.compile(r"[ -~\xa0-\U0010ffff]{1,1000}")
GENERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
HEAD = re.compile(rb"HTTP/[0-9.]+ ([0-9]{3})[^\n]*\n(?:[^\r\n][^\n]*\n)*\r?\n")     # a status line, headers, an empty line
ESCAPE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))')       # one escape of a JSON string
UNDO = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
SECRET_REF = re.compile(r"bws://([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})")
SEALED_REF = re.compile(r"sealed:(\d{1,9})")
RECIPIENT = re.compile(r"age1[0-9a-z]{58}")
ARMOR = "-----BEGIN AGE ENCRYPTED FILE-----"
DELIVERED = "delivered from the owner's vault"      # a deposit's note: only an item with it is withdrawn
TAKEN = "taken from the owner"                      # an intake's note: only an item with it leaves the central store
# The central vault (`"central": true`): exactly these keys. No hub, because it never calls one; no worker_uid or
# worker_group, because only the hub's user asks it; no Bitwarden, curl, ssh or write key, because it does none of that.
CENTRAL_KEYS = {"central", "hub_uid", "fleet", "owner_keys", "age", "age_key", "store", "store_key", "socket", "state"}
FLEET_ID = re.compile(r"[0-9a-f]{16}")              # the hub's fleet_id()
OWNER_KEYS = 8                                      # the most owner keys that may sign
MACHINE = re.compile(r"[a-z][a-z0-9-]{0,62}")       # a machine of a pin
STATE = 1                                           # the format of the central vault's state file
# The fields of each statement that the owner signs: all of them, and no other.
# grant: the owner gives this secret to this agent, whose vault is on this machine, so the vault may seal it to that
# machine's pin; ungrant takes that back. pool: the owner lets the manager hand this secret out (team.json
# "resources"), so the vault may seal it to any pinned machine; unpool takes that back.
STATEMENTS = {"pin": {"v", "kind", "fleet", "machine", "recipient", "at"},
              "unpin": {"v", "kind", "fleet", "machine", "at"},
              "recovery": {"v", "kind", "fleet", "recipient", "at"},
              "grant": {"v", "kind", "fleet", "login", "agent", "machine", "at"},
              "ungrant": {"v", "kind", "fleet", "login", "agent", "at"},
              "pool": {"v", "kind", "fleet", "login", "at"},
              "unpool": {"v", "kind", "fleet", "login", "at"}}
COPY_MAX = 16384            # characters of one sealed copy that the owner gives, as the hub's DEPOSIT_COPY_MAX
CENTRAL_LINE = 65536        # bytes of one request line to the central vault: an intake carries a sealed copy
# The central vault's own user. Not a fleet-* name: the hub's user may put any fleet-* user into the agents' group
# (fleet-agent-user), and this user must never be one that the hub's user can move.
CENTRAL_USER = "founderizer-vault"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never a second request: a caller's key must not go to another place."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


class Refused(Exception):
    """A request that the broker does not serve. The text goes back to the helper; it never holds a secret."""


def log(text):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + text, file=sys.stderr, flush=True)


def unchangeable(path, what):
    """A file that the worker's user can neither change nor replace: not a link, and the file and every folder above
    it (on the given path and on the real path) are owned by root or this user and writable by no one else. A folder
    that others can write lets them put another file in its place after this check."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise SystemExit(f"{what} must be owned by root or the vault user and writable by no one else: {path}")
    folders = set()
    for start in (os.path.abspath(path), os.path.realpath(path)):
        folder = os.path.dirname(start)
        while True:
            folders.add(folder)
            if folder == os.path.dirname(folder):
                break
            folder = os.path.dirname(folder)
    for folder in sorted(folders):
        info = os.stat(folder)
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise SystemExit(f"{what} is in a folder that others can change ({folder}); every folder above it must be "
                             f"owned by root or the vault user and writable by no one else: {path}")


def load_config(path):
    unchangeable(path, "The vault configuration")
    with open(path, encoding="utf-8") as f:
        conf = json.load(f)
    if isinstance(conf, dict) and "central" in conf:        # the central vault's own form; every other one as before
        return central_config(conf)
    given = set(conf) if isinstance(conf, dict) else set()
    if given & BITWARDEN_KEYS:          # the one clear refusal of an old configuration: the broker does not start
        raise SystemExit(NO_BITWARDEN.format(keys=", ".join(sorted(given & BITWARDEN_KEYS))))
    if not isinstance(conf, dict) or given - KEYS - CALLER_KEYS - STORE_KEYS - {REQUEST_KEY, PLACE_KEY, "agent"} \
            - OWNER_PIN_KEYS - {SWAP_KEY} or (given & OWNER_PIN_KEYS) not in (set(), OWNER_PIN_KEYS) or \
            not KEYS <= given or not given & CALLER_KEYS or not STORE_KEYS <= given:
        raise SystemExit("The vault configuration needs exactly: " + ", ".join(sorted(KEYS)) + "; optionally agent, "
                         "the one agent whose vault it is; who may ask it: " +
                         " or ".join(sorted(CALLER_KEYS)) + ", or both; its one store: " +
                         " and ".join(sorted(STORE_KEYS)) + " (the fleet's own, made by store-init); optionally the "
                         "owner's keys: " + " and ".join(sorted(OWNER_PIN_KEYS)) + ", both or neither; for API "
                         "requests also: " + REQUEST_KEY + "; for the key swap also: " + SWAP_KEY + "; and " +
                         PLACE_KEY + " (read and not used), as older installers wrote it")
    # The key swap: only the form of its part is checked here, because each refusal here stops the broker. What a
    # machine can lose later (the proxy's user, the openssl program) is read at each start, and stops only the swap
    # (with_swaps).
    if SWAP_KEY in conf and not swap_shape(conf[SWAP_KEY]):
        raise SystemExit(SWAP_KEY + " must be the key swap of this machine: {\"user\": the swap proxy's OS user, "
                         "\"vault\": the vault's OS user, \"port\": the proxy's port on 127.0.0.1, \"openssl\": "
                         "the absolute path of the openssl program}")
    if "agent" in conf and (not isinstance(conf["agent"], str) or not AGENT_NAME.match(conf["agent"])):
        raise SystemExit("agent must be the Fleet name of the one agent whose vault this is, or be left out")
    if OWNER_PIN_KEYS <= given:
        owner_pin_config(conf)
    if not re.fullmatch(r"https?://[^/\s]+", str(conf["hub"])):
        raise SystemExit("hub must be the hub's address, for example http://100.80.1.2:8765")
    uid = conf.get("worker_uid")
    if "worker_uid" in conf and (not isinstance(uid, int) or isinstance(uid, bool) or uid < 0 or uid == os.getuid()):
        raise SystemExit("worker_uid must be the worker's user ID, never the vault user's")
    group = conf.get("worker_group")
    if "worker_group" in conf:
        if not isinstance(group, str) or not GROUP_NAME.match(group):
            raise SystemExit("worker_group must be the name of the group of this machine's agent users")
        try:
            members = grp.getgrnam(group)
        except KeyError:
            raise SystemExit(f"there is no group {group} on this machine") from None
        # The vault **user's** own groups, read from the passwd and group files, and never this process's gid: the
        # service runs with Group=<this very group> so that the socket is readable by the machine's agent users, so
        # the running gid is always it, and reading that refused every correctly installed broker.
        me = pwd.getpwuid(os.getuid())
        if me.pw_name in members.gr_mem or members.gr_gid == me.pw_gid:
            raise SystemExit("worker_group must be the group of the agents' users, never one the vault user is in")
    for key in ("age_key", "socket", "age", "store", "store_key"):
        if not isinstance(conf[key], str) or not os.path.isabs(conf[key]):
            raise SystemExit(f"{key} must be an absolute path")
    unchangeable(conf["age"], "The age program")                     # the agent cannot swap a program
    if REQUEST_KEY in conf:             # call_api: the program that gets the key of a request, checked as the other two
        if not isinstance(conf[REQUEST_KEY], str) or not os.path.isabs(conf[REQUEST_KEY]):
            raise SystemExit("curl must be an absolute path")
        unchangeable(conf[REQUEST_KEY], "The curl program")
    if PLACE_KEY in conf and (not isinstance(conf[PLACE_KEY], str) or not os.path.isabs(conf[PLACE_KEY])):
        raise SystemExit("ssh must be an absolute path")        # the program itself is checked when the broker starts
    return conf


def state_folder(conf):
    """The broker's private folder, which holds its store. Its journal and its record of started requests lie there,
    and only the vault user can read it."""
    return os.path.dirname(os.path.abspath(conf["store"]))


def canonical_id(value):
    """The lower-case form of a UUID, or None."""
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) and len(value) == 36 else None
    except ValueError:
        return None


def read_private(path, what):
    """A vault file, read for one request so that a removed or replaced file counts at once."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding="utf-8") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise Refused(f"the vault {what} file must belong to the vault user and have mode 600")
            text = f.read()
        folder = os.stat(os.path.dirname(os.path.abspath(path)))
    except (OSError, UnicodeError):
        raise Refused(f"the vault broker has no readable {what}") from None
    if folder.st_uid != os.getuid() or folder.st_mode & 0o077:
        raise Refused(f"the vault {what} folder must belong to the vault user and have mode 700")
    if not text.strip():
        raise Refused(f"the vault {what} file is empty")
    return text


def public_key(path, what):
    """The public half of one of this broker's keys, from the comment that age-keygen writes into the key file. The
    file is read for one request, so a removed or replaced key counts at once."""
    m = re.search(r"^# public key: (age1[0-9a-z]{58})$", read_private(path, what), re.M)
    if not m:
        raise Refused(f"the vault {what} file has no public key line")
    return m.group(1)


def recipient(conf):
    """This broker's public handover key."""
    return public_key(conf["age_key"], "handover key")


def admitted(conf, uid):
    """May this user ask the broker: the one worker user of the configuration (worker_uid), or any user of the group
    of this machine's agent users (worker_group). The socket's own mode already limits callers to that group, and
    this reads the same boundary again by user, so a renamed or added agent user reaches the broker with no change
    to the configuration and no user of another group reaches it through a group it shares with one.

    The central vault answers one user only: the hub's (hub_uid). The socket's group is the hub user's group, so this
    is what keeps out any other user of that group."""
    if conf.get("central") is True:
        return uid == conf.get("hub_uid")
    if conf.get("worker_uid") is not None and uid == conf["worker_uid"]:
        return True
    group = conf.get("worker_group")
    if not group:
        return False
    try:
        who, members = pwd.getpwuid(uid), grp.getgrnam(group)
    except KeyError:
        return False
    return who.pw_name in members.gr_mem or who.pw_gid == members.gr_gid


def peer_uid(conn):
    if hasattr(socket, "SO_PEERCRED"):          # Linux: struct ucred {pid, uid, gid}
        return struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
    return struct.unpack("2I", conn.getsockopt(0, 1, 76)[:8])[1]     # macOS LOCAL_PEERCRED: struct xucred


def hub(conf, method, path, body=None):
    """One hub call. With a caller (shared broker callers), it carries the caller's agent key, for this request only."""
    headers = {"Content-Type": "application/json"}
    if conf.get("agent_key"):
        headers["Authorization"] = "Bearer " + conf["agent_key"]
    request = urllib.request.Request(conf["hub"].rstrip("/") + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with NO_PROXY.open(request, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read() or b"{}")
        except ValueError:
            data = {}
        if e.code == 403 and isinstance(data, dict) and data.get("auth"):      # one fixed text, as the Mac vault helper
            raise Refused("the hub did not accept this agent's key") from None
        return e.code, data
    except (OSError, ValueError):
        raise Refused("the vault broker could not reach the hub") from None


def owner_pin_config(conf):
    """The owner's keys and the fleet's ID of a broker's configuration (OWNER_PIN_KEYS), checked as the central vault
    checks its own."""
    if not isinstance(conf["fleet"], str) or not FLEET_ID.fullmatch(conf["fleet"]):
        raise SystemExit("fleet must be the fleet's ID: 16 lowercase hex characters")
    keys = conf["owner_keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= OWNER_KEYS:
        raise SystemExit(f"owner_keys must list 1 to {OWNER_KEYS} public keys of the owner")
    for text in keys:
        try:
            owner_key(text)
        except ValueError:
            raise SystemExit("each of owner_keys must be the base64 of an uncompressed P-256 public key (65 bytes: "
                             "04, X, Y) that is a point of the curve") from None


def owner_pinned(conf, confirmed):
    """Refused unless the owner signed a pin of the recipient that the hub named for this handover: the pin statement
    that the hub carries beside the job, checked here with the owner's keys of this broker's own configuration. The hub
    names the receiving agent and its key, and a hub that is broken into could name a key of its own; it cannot sign
    for the owner (DevOps plan 0.3)."""
    if not OWNER_PIN_KEYS <= set(conf):
        raise Refused("this machine's vault holds no key of the owner, so it hands no login over")
    pin = confirmed.get("pin")
    if not isinstance(pin, dict):
        raise Refused("the owner has signed no pin of the receiving machine's key, so the login is not handed over")
    said = owner_statement(conf, pin, "pin")
    if said["recipient"] != confirmed["recipient"]:
        raise Refused("the owner's pin names another key than the one the login would be locked for, so it is not "
                      "handed over")


def confirm_job(conf, job, kind):
    """The hub opens a job once: an open sign-in, handover or request of this agent. It names the login, and for a
    handover the receiving agent and its pinned handover key."""
    said = {"job": job, "kind": kind, "provenance": PROVENANCE}
    if kind == "request":               # for a request, this broker says that it compares created_by (below)
        said["creation"] = 1
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}", said)
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("job") != job:
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not confirm this job" + (f": {reason}" if isinstance(reason, str) else ""))
    login = data.get("login")
    if not isinstance(login, str) or not (SECRET_REF.fullmatch(login) or SEALED_REF.fullmatch(login)):
        raise Refused("the hub named no valid login for this job")
    source = data.get("source")
    if source is not None and not (isinstance(source, str) and SECRET_REF.fullmatch(source)):
        raise Refused("the hub named no valid source login for this job")
    if kind == "handover" and not (AGENT_NAME.match(str(data.get("target"))) and
                                   RECIPIENT.fullmatch(str(data.get("recipient")))):
        raise Refused("the hub named no receiving agent with a pinned handover key")
    salts = data.get("fingerprint_salts")
    if not isinstance(salts, dict) or not all(re.fullmatch(r"[0-9a-f]{32}", str(salts.get(k))) for k in ("password", "totp")):
        raise Refused("the hub gave no fingerprint salts for this job")
    if data.get("created_by") is not None:
        # The hub allows this job only because a create job of the same task made the login. The hub has that from
        # the worker's report, so this broker's own journal must have the creation with this login.
        made, journal = data["created_by"], conf.get("_journal")
        try:
            claim = creation(dict(made, task=data.get("task")), conf["agent"]) \
                if isinstance(made, dict) and made.get("agent") == conf["agent"] else None
        except Refused:
            claim = None
        if not (claim and journal and journal.made(claim["request_id"], claim["binding"], login)):
            raise Refused(NOT_MADE_HERE)
    return data


def canonical_seed(value):
    """The base32 seed of a TOTP value: the secret of an otpauth:// URI (percent-decoded) or the value itself,
    without whitespace, "-" and "=" padding, in upper case."""
    if value.startswith("otpauth://"):
        value = urllib.parse.parse_qs(urllib.parse.urlsplit(value).query).get("secret", [""])[0]
    return re.sub(r"[\s=-]", "", value).upper()


def eligible(value):
    """A value that the hub's existing filter can find in a text: 8 or more characters and no whitespace."""
    return len(value) >= 8 and not re.search(r"\s", value)


def fingerprints(login, salts):
    """The salted fingerprints of a login's eligible secret values: its password, and its seed in both forms."""
    values = [("password", login["password"])]
    if "totp" in login:
        values.append(("totp", login["totp"]))
        seed = canonical_seed(login["totp"])
        if seed != login["totp"]:
            values.append(("totp", seed))
    return [{"kind": kind, "hash": hashlib.sha256((salts[kind] + value).encode()).hexdigest(), "len": len(value)}
            for kind, value in values if eligible(value)]


def protect(conf, confirmed, login, read=None):
    """Register salted fingerprints of the login's eligible secret values before it is used (UI-API.md,
    "Fingerprints of handled logins"). Other values are not registered and the login is still used. When a value
    is registered, the login is used only after the hub's exact receipt. read: the reference of a value that a session
    reads (owner feature secrets); the hub then takes the fingerprints for that reference and no job."""
    items = fingerprints(login, confirmed["fingerprint_salts"])
    if not items:
        return
    said, field = ({"login": read}, "login") if read else ({"job": confirmed["job"]}, "job")
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}/fingerprints", dict(said, fingerprints=items))
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get(field) != said[field] \
            or not all(isinstance(data.get(k), int) and not isinstance(data.get(k), bool) for k in ("stored", "known")) \
            or data["stored"] + data["known"] != len(items):
        raise Refused("this login could not be protected in messages, so it was not used")


def run(argv, data, env=None):
    try:
        return subprocess.run(argv, input=data, capture_output=True, text=True, timeout=30,
                              env=env or {"PATH": "/usr/local/bin:/usr/bin:/bin"})
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


PROVIDER_SITES = ("claude.ai", "claude.com", "chatgpt.com", "auth.openai.com", "x.ai")   # the providers' sign-in sites
PROVIDER_KEY_SITES = ("platform.claude.com",)   # an API console under one of them: a key read there stays allowed


def provider_site(host):
    """True for a model provider's own sign-in site, with its subdomains. Fleet holds no provider credential: the
    owner signs in to their own account in their own session, through the provider's own flow, and that is the
    condition on which Anthropic permits an operator to host the unmodified Claude Code at all. So no login of
    Fleet's may be one, and sign_in, create_login and save_key refuse these sites. An API key of a provider's paid
    API (console.anthropic.com, platform.claude.com, platform.openai.com) is another thing and stays allowed: it is
    a key the owner pays per call, not the subscription credential of a session. That is why OpenAI's entry is
    auth.openai.com, where a ChatGPT account signs in, and not all of openai.com, and why PROVIDER_KEY_SITES keeps
    the console platform.claude.com apart from claude.com."""
    host = str(host or "").lower().rstrip(".")
    if any(host == site or host.endswith("." + site) for site in PROVIDER_KEY_SITES):
        return False
    return any(host == site or host.endswith("." + site) for site in PROVIDER_SITES)


def check_login(value):
    """{username, password, url[, totp]} with an http(s) address that names a host and no user. An API key (owner
    feature secrets) is such an item with an empty user name."""
    try:
        login = json.loads(value) if isinstance(value, str) else value
        if not isinstance(login, dict) or not isinstance(login.get("username", ""), str) or \
                not all(isinstance(login.get(k), str) and login[k] for k in ("password", "url")):
            raise ValueError()
        url = urllib.parse.urlsplit(login["url"])
        if url.scheme not in ("https", "http") or not url.hostname or url.username or url.password:
            raise ValueError()
        if login.get("totp") is not None and not isinstance(login["totp"], str):
            raise ValueError()
        if provider_site(url.hostname):
            raise Refused("this login is for a model provider's own site, and Fleet uses none: the owner signs in to "
                          "their own account in their own session")
    except (ValueError, TypeError, AttributeError):
        raise Refused("the login is invalid: it needs a password and an http(s) url, an optional user name, and an "
                      "optional authenticator seed in totp") from None
    return dict({k: login[k] for k in ("password", "url", "totp") if login.get(k) is not None},
                username=login.get("username", ""))


def check_value(value):
    """{password[, totp]} of an item that a session reads (owner feature secrets): an API key, which needs no address."""
    try:
        item = json.loads(value)
        if not isinstance(item, dict) or not (isinstance(item.get("password"), str) and item["password"]) or \
                not isinstance(item.get("totp", ""), str):
            raise ValueError()
    except (ValueError, TypeError):
        raise Refused("the item is not a saved value") from None
    return {k: item[k] for k in ("password", "totp") if item.get(k)}


def provenance(text, data, sid):
    """The source login of a locked copy, after the provenance inside the copy matched the hub's record of the copy
    (its job and source login). Only the sending broker could put it there, because only that broker opened the
    login, so a copy that is sent again under another job or source is refused. A copy that says nothing carries no
    source login."""
    try:
        made = json.loads(text).get("fleet")
    except (ValueError, AttributeError):
        made = None
    if made is None:
        return None
    if made != {"v": PROVENANCE, "job": data.get("job"), "source": data.get("source")}:
        raise Refused(f"sealed:{sid} was made for another handover, so it is not used")
    return made["source"]


def open_login(conf, ref, task, store):
    """(the login, its name, its source login), inside the broker only. store: this machine's own store, which opens
    a saved login (LocalStore)."""
    m = SECRET_REF.fullmatch(ref)
    if m:
        item = store.item(m.group(1))
        return check_login(item["value"]), item["key"], ref.lower()
    sid = SEALED_REF.fullmatch(ref).group(1)
    query = urllib.parse.urlencode({"agent": conf["agent"], "task": task or ""})
    code, data = hub(conf, "GET", f"/sealed/{sid}?{query}")
    if code != 200 or ARMOR not in str(data.get("ciphertext")):
        raise Refused(f"the hub did not give sealed:{sid}" + (f": {data['error']}" if isinstance(data.get("error"), str)
                                                              else ""))
    read_private(conf["age_key"], "handover key")          # owner and mode are checked before age reads it
    r = run([conf["age"], "-d", "-i", conf["age_key"]], data["ciphertext"])
    if r is None or r.returncode != 0:
        raise Refused(f"sealed:{sid} cannot be opened with this machine's handover key")
    source = provenance(r.stdout, data, sid)
    return check_login(r.stdout), str(data.get("label") or f"sealed:{sid}"), source


def handover(conf, job):
    """Lock one login for the receiving agent's broker. The answer holds only the locked copy."""
    store = LocalStore(conf)            # a broken vault must not use up the job
    read_private(conf["age_key"], "handover key")
    confirmed = confirm_job(conf, job, "handover")
    owner_pinned(conf, confirmed)       # DevOps plan 0.3: a recipient that the owner signed, and no other
    login, label, source = open_login(conf, confirmed["login"], confirmed.get("task"), store)
    if confirmed.get("source") is not None and source != confirmed["source"]:
        raise Refused("the hub and the copy name different source logins, so the login is not handed over")
    protect(conf, confirmed, login)
    made = {"v": PROVENANCE, "job": job, "source": source}
    r = run([conf["age"], "-a", "-r", confirmed["recipient"]], json.dumps(dict(login, fleet=made)))
    if r is None or r.returncode != 0 or ARMOR not in r.stdout:
        raise Refused("the login could not be locked for the receiving agent")
    for secret in [login["password"]] + ([login["totp"]] if "totp" in login else []):
        if len(secret) >= 8 and secret in r.stdout:     # a short value can appear in any text by chance
            raise Refused("the locked copy was not locked, so it is not sent")
    return {"ok": True, "v": PROTOCOL, "job": job, "to": confirmed["target"], "label": label, "ciphertext": r.stdout}


def read(conf, purpose=None, uid=None):
    """read (owner feature secrets): the API keys that the calling agent reads in its sessions, as {variable name:
    value}. The hub names them for this agent now; the broker reads each value itself and registers its fingerprints
    before it gives it, so that the hub masks it in texts. The worker's user may read exactly these values. A value
    that the broker cannot read or protect is left out, and its name is in missing. purpose: "check" or "session", which
    the hub is told: it gives no key to a session of an agent whose Shell box is off (support plan F1).

    The key swap: on a machine whose configuration has the part "swap", a key that the hub names with a site is
    given as a placeholder, which this broker keeps for the calling OS user (uid) and that site, and never as the
    value; when it cannot be a placeholder, it is left out. The answer's `swap` then names the proxy, the folder of
    the sites' CA certificates, and each such variable with its host. On a machine without that part, each value is
    given as before."""
    store = LocalStore(conf)
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}/read",
                     {"for": purpose} if purpose in ("check", "session") else {})
    found = data.get("secrets") if isinstance(data, dict) else None
    if code != 200 or not isinstance(found, list) or data.get("ok") is not True or len(found) > READS:
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not name the secrets to read" + (f": {reason}" if isinstance(reason, str) else ""))
    env, missing, swapped, named = {}, [], {}, set()
    for x in found:
        name, ref = x.get("env") if isinstance(x, dict) else None, x.get("login") if isinstance(x, dict) else None
        salts = x.get("fingerprint_salts") if isinstance(x, dict) else None
        if not (isinstance(name, str) and ENV_NAME.fullmatch(name) and name not in env and isinstance(ref, str)
                and SECRET_REF.fullmatch(ref) and isinstance(salts, dict)
                and all(re.fullmatch(r"[0-9a-f]{32}", str(salts.get(k))) for k in ("password", "totp"))):
            raise Refused("the hub named no valid secrets to read")
        site = None
        if "_swap" in conf and (x.get("site") is not None or x.get("swap") is not None):
            # this machine swaps keys, and the hub names this key's site: a placeholder, or nothing
            named.add(ref.lower())
            site, token, form = swap_site(x.get("site")), x.get("swap"), x.get("form", SWAP_FORMS[0])
            if conf.get("_swaps") is None or type(uid) is not int or not site or form not in SWAP_FORMS \
                    or not (isinstance(token, str) and SWAP_TOKEN.fullmatch(token)):
                missing.append(name)
                continue
        try:
            value = check_value(store.item(SECRET_REF.fullmatch(ref).group(1))["value"])
            protect(conf, {"fingerprint_salts": salts}, value, read=ref.lower())
            if site:
                value = {"password": conf["_swaps"].place(uid, conf["agent"], ref.lower(), site[0], site[1], form, token)}
                swapped[name] = swap_origin(*site)
        except Refused:
            missing.append(name)
            continue
        env[name] = value["password"]
    if conf.get("_swaps") is not None and type(uid) is int:
        try:                    # the placeholders of keys that the hub names with a site no more
            conf["_swaps"].only(uid, conf["agent"], named)
        except Refused:
            pass                # the list stays as it is: each use of an entry still asks the hub
    log(f"read {len(env)} of {len(found)} value(s) for a session of {conf['agent']}"
        + (f", {len(swapped)} of them as a placeholder" if swapped else ""))
    reply = {"ok": True, "v": PROTOCOL, "env": env, "missing": missing}
    if swapped:
        reply["swap"] = {"proxy": f"http://127.0.0.1:{conf['_swap']['port']}", "ca": SWAP_RUN, "names": swapped}
    return reply


def probe(conf, job):
    """Which logins of the agent's profile this vault can open (owner API 1.9): the hub names them for one probe job.
    The answer has fixed codes only: no part of a login leaves the broker."""
    try:
        store = LocalStore(conf)
    except Refused:
        store = None                    # a vault without its key or its store opens nothing, and says so per login
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}", {"job": job, "kind": "probe"})
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("job") != job \
            or data.get("kind") != "probe":
        raise Refused("the hub did not confirm this probe job")
    logins = data.get("logins")
    if not isinstance(logins, list) or len(logins) > 32 or \
            not all(isinstance(x, str) and SECRET_REF.fullmatch(x) for x in logins):
        raise Refused("the hub named no valid logins to probe")
    results = [store.probe(ref) if store else {"login": ref, "state": "not_readable", "reason": "no_token"}
               for ref in logins]
    log(f"probe job={job}: {sum(r['state'] == 'readable' for r in results)} of {len(results)} readable")
    return {"ok": True, "v": PROTOCOL, "job": job, "results": results}


def delivered(text, item):
    """The value in a delivered copy: a login needs its address, and an API key keeps one when it has it. It refuses, and never exits, because the broker serves the next request."""
    try:
        given = json.loads(text)
    except ValueError:
        raise Refused("the delivered copy holds no item") from None
    if item == "api_key" and isinstance(given, dict) and "url" not in given:
        return check_value(text)
    return check_login(given)


def deposit(conf, number):
    """deposit (owner feature central_vault): save in this machine's own store one key or login that the central
    vault sealed to this broker's pinned key. The helper names only the delivery. The hub gives the sealed copy, the
    secret's reference, title and kind, and the salts of its fingerprints; the copy is opened here with the handover
    key, and the hub compares the value's fingerprints with the ones that the owner's vault registered under that
    reference before anything is saved. It is saved under the same reference, so `bws://<id>` names one value in every
    vault of the fleet, and the answer holds no part of it."""
    store = LocalStore(conf)            # a store that does not open refuses before the hub gives the copy
    read_private(conf["age_key"], "handover key")
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}", {"job": number, "kind": "deposit"})
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("job") != number \
            or data.get("kind") != "deposit":
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not give this delivery" + (f": {reason}" if isinstance(reason, str) else ""))
    ref, title, item, text, salts = (data.get(k) for k in ("login", "title", "item", "ciphertext", "fingerprint_salts"))
    m = SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
    if not (m and plain_line(title, 200) and item in ("login", "api_key") and isinstance(text, str) and ARMOR in text
            and isinstance(salts, dict)
            and all(re.fullmatch(r"[0-9a-f]{32}", str(salts.get(k))) for k in ("password", "totp"))):
        raise Refused("the hub gave no valid delivery")
    r = run([conf["age"], "-d", "-i", conf["age_key"]], text)
    if r is None or r.returncode != 0:
        raise Refused("the delivered copy cannot be opened with this machine's vault key")
    value = delivered(r.stdout, item)
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}/fingerprints",
                     {"deposit": number, "fingerprints": fingerprints(value, salts)})
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("deposit") != number:
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not confirm this value" + (f": {reason}" if isinstance(reason, str) else ""))
    saved = store.put(m.group(1).lower(), title, json.dumps(value, sort_keys=True, separators=(",", ":"),
                                                            ensure_ascii=False), DELIVERED)
    log(f"deposit job={number}: {ref.lower()} {saved}")
    return {"ok": True, "v": PROTOCOL, "deposit": number, "login": ref.lower(), "saved": saved}


def withdraw(conf, number):
    """withdraw (helper feature secret_withdrawals): remove from this machine's own store one secret that the owner's
    vault delivered here and that no agent of this machine holds any more. The helper names only the job; the hub
    names the reference. Only an item that a deposit saved is removed: a login that the owner saved here himself, or
    that this vault made, is refused, because the hub's catalog is not where it came from. "absent" when the store
    has no such item, so a withdrawal that is asked again ends the same way."""
    store = LocalStore(conf)            # a store that does not open refuses before the hub's job is used
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}", {"job": number, "kind": "withdraw"})
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("job") != number \
            or data.get("kind") != "withdraw":
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not confirm this withdrawal" + (f": {reason}" if isinstance(reason, str) else ""))
    ref = data.get("login")
    m = SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
    if not m:
        raise Refused("the hub named no valid login for this withdrawal")
    removed = store.remove(m.group(1).lower(), DELIVERED)
    log(f"withdraw job={number}: {ref.lower()} {removed}")
    return {"ok": True, "v": PROTOCOL, "withdrawal": number, "login": ref.lower(), "removed": removed}


# ---------------------------------------------------------------- the fleet's own store

def plain_values(value):
    """The secret values inside one stored item, for the check that the locked store holds none of them: the password
    and the authenticator seed of an item of ours, else the text itself. A value under 8 characters is left out,
    because such a text can stand in any file by chance (as a handover leaves it out)."""
    try:
        item = json.loads(value)
        found = [item[k] for k in ("password", "totp") if isinstance(item.get(k), str)] if isinstance(item, dict) else []
    except ValueError:
        found = []
    return [v for v in (found or [value]) if len(v) >= 8]


class LocalStore:
    """The fleet's own store: the owner's logins and keys in one file on this machine, which the agents' user can
    neither read nor open. No account, no organization and no network.

    The file holds {"v": 1, "items": {id: {key, value, note, made_at}}} — an item of the shape that the rest of the
    broker already reads — encrypted with the configured age program (X25519 and ChaCha20-Poly1305) to the public
    half of the store key, and opened with that key. A value goes to age on its standard input, never in an argument
    or the environment, and a locked store that still holds a value in plain is not written. The store is read again
    for every request, so a removed key or a replaced file counts at once, and a save takes the store's lock, because
    two requests of the broker can write this one file at the same time.
    """
    LIMIT = 4 * 1024 * 1024         # the most bytes of the opened store, as the journal's limit

    def __init__(self, conf):
        self.conf = conf
        self.recipient = public_key(conf["store_key"], "store key")     # owner and mode are checked before age reads it
        self.opened()               # a store that does not open counts before the hub's job is used up

    def opened(self):
        """The store's items, inside the broker only."""
        text = read_private(self.conf["store"], "store")
        if ARMOR not in text:
            raise Refused("the vault store is not a locked file")
        read_private(self.conf["store_key"], "store key")
        r = run([self.conf["age"], "-d", "-i", self.conf["store_key"]], text)
        if r is None or r.returncode != 0:
            raise Refused("the vault store cannot be opened with this machine's store key")
        try:
            if len(r.stdout) > self.LIMIT:
                raise ValueError()
            data = json.loads(r.stdout)
            items = data["items"] if isinstance(data, dict) and data.get("v") == STORE else None
            good = isinstance(items, dict) and all(
                canonical_id(i) == i and isinstance(x, dict) and set(x) == {"key", "value", "note", "made_at"}
                and plain_line(x["key"], 200) and isinstance(x["value"], str) and isinstance(x["note"], str)
                and isinstance(x["made_at"], (int, float)) and not isinstance(x["made_at"], bool)
                for i, x in items.items())
            if not good:
                raise ValueError()
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise Refused("the vault store cannot be read") from None
        return items

    def keep(self, items):
        """Lock the store and put it in the place of the old one: a new file of mode 600, made complete beside it."""
        data = json.dumps({"v": STORE, "items": items}, sort_keys=True)
        if len(data) > self.LIMIT:
            raise Refused("the vault store is full, so nothing was saved")
        r = run([self.conf["age"], "-a", "-r", self.recipient], data)
        if r is None or r.returncode != 0 or ARMOR not in r.stdout:
            raise Refused("the vault store could not be locked, so nothing was saved")
        for item in items.values():         # a store that is not locked is not written, as a copy that is not
            for value in plain_values(item["value"]):       # locked is not sent (handover)
                if value in r.stdout:
                    raise Refused("the vault store was not locked, so nothing was saved")
        path, temp = self.conf["store"], self.conf["store"] + ".new"
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(r.stdout)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, path)
        except OSError:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise Refused("the vault store could not be saved") from None
        try:
            sync_folder(os.path.dirname(os.path.abspath(path)))     # the save stays also after a loss of power
        except OSError:
            pass                    # the new store is already in its place: this is no failure of the save

    def locked(self):
        """The store's lock, as a file descriptor: one writer at a time. Closing it gives the lock back."""
        fd = os.open(self.conf["store"] + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            raise Refused("the vault store is in use, so nothing was saved") from None
        return fd

    def add(self, name, value, note=""):
        """Save one item and give its id. The store is read and written under its lock."""
        if not plain_line(name, 200) or not isinstance(value, str) or not isinstance(note, str):
            raise Refused("the vault store needs a name of 1 to 200 characters for an item")
        fd = self.locked()
        try:
            items = self.opened()
            sid = str(uuid.uuid4())
            while sid in items:
                sid = str(uuid.uuid4())
            items[sid] = {"key": name, "value": value, "note": note, "made_at": time.time()}
            self.keep(items)
        finally:
            os.close(fd)
        return sid

    def put(self, sid, name, value, note=""):
        """Save one item under the id that it has in the owner's vault (deposit): "new", or "same" when the store holds
        that value under that id already. Another value under that id is refused, because one reference names one
        value in every vault of the fleet: a delivery never changes what a name already means here."""
        if canonical_id(sid) != sid or not plain_line(name, 200) or not isinstance(value, str) or \
                not isinstance(note, str):
            raise Refused("the vault store needs an id and a name of 1 to 200 characters for an item")
        fd = self.locked()
        try:
            items = self.opened()
            if sid in items:
                try:
                    same = json.loads(items[sid]["value"]) == json.loads(value)
                except ValueError:
                    same = items[sid]["value"] == value
                if same:
                    return "same"
                raise Refused("this machine's vault store holds another value under this reference, so nothing was "
                              "saved")
            items[sid] = {"key": name, "value": value, "note": note, "made_at": time.time()}
            self.keep(items)
        finally:
            os.close(fd)
        return "new"

    def remove(self, sid, note):
        """Remove the item with this id when its note is exactly `note` (withdraw): "removed", or "absent" when the
        store holds no such item. An item with another note is refused and stays. The note is read and the item
        removed under the store's lock, so no save comes between them."""
        if canonical_id(sid) != sid:
            raise Refused("the vault store needs the id of an item")
        fd = self.locked()
        try:
            items = self.opened()
            if sid not in items:
                return "absent"
            if items[sid]["note"] != note:
                raise Refused("this login was not delivered here, so it is not removed")
            del items[sid]
            self.keep(items)
        finally:
            os.close(fd)
        return "removed"

    def item(self, sid):
        """One item of the store: {id, key (its name), value, note}."""
        found = self.opened().get(str(sid).lower())
        if not found:
            raise Refused("this machine's vault store has no such login")
        return dict(found, id=str(sid).lower())

    def probe(self, ref):
        """Can this vault open this login? The fixed codes of a probe: no part of a login leaves."""
        def result(state, reason):
            return {"login": ref, "state": state, "reason": reason}
        try:
            item = self.item(SECRET_REF.fullmatch(ref).group(1))
        except Refused as e:
            return result("not_readable", "not_found" if "no such login" in str(e) else "error")
        try:
            value = json.loads(item["value"])
            good = isinstance(value, dict) and isinstance(value.get("username", ""), str) and \
                isinstance(value.get("password"), str) and value["password"]
        except (ValueError, TypeError):
            good = False
        return result("readable", "ok") if good else result("not_readable", "bad_format")

    # What create() asks of the store for a new login: one save, and a look-up by its name and its mark.
    def named(self, name):
        """The ids of the items with exactly this name."""
        return sorted(i for i, x in self.opened().items() if x["key"] == name)

    def notes(self, ids):
        items = self.opened()
        return {i: items[i]["note"] for i in ids if i in items}

    def create(self, name, value, note):
        """Exactly one save: ("created", id), or ("refused", None) when nothing was made. The store is one file on
        this machine, which is made complete beside the old one and then takes its place, so a save that fails leaves
        the store as it was."""
        try:
            return "created", self.add(name, value, note)
        except Refused:
            return "refused", None

    def login(self, item):
        """The broker's own new item, read again: its values are fingerprinted from the store, not from memory."""
        return check_login(self.item(item)["value"])


# ---------------------------------------------------------------- new logins (create_login)

def sync_folder(path):
    """Make a new name in this folder safe against a loss of power: the file's own sync does not keep its name."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Journal:
    """This broker's record of every new login that it was asked to make, in its private state folder. A broker can
    end between its one save and the record of what came of it, and a look-up that finds nothing does not prove that
    an earlier save failed. So the journal decides: a request_id gets a create call only while it has no record, the
    record is kept before the call, and a save with an unknown outcome is only looked for by its mark. No record is
    ever dropped. One exclusive lock, held for the life of the broker, gives the journal to one process."""
    LIMIT, RESERVE = 4 * 1024 * 1024, 256
    STATES = ("creating", "created", "registered", "unknown", "failed", "discarded")
    FIELDS = {"request_id", "title", "hub", "db", "state", "login", "started_at", "updated_at", "binding", "mark"}

    def __init__(self, path, clock=time.time):
        self.path, self.clock = path, clock
        folder = os.path.dirname(os.path.abspath(path))
        info = os.stat(folder)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refused("the vault's state folder must belong to the vault user and have mode 700")
        self.lock = os.open(path + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.records = self.load()
            if any(r["state"] == "creating" for r in self.records):     # a broker that ended during its create call
                for r in self.records:
                    if r["state"] == "creating":
                        r.update(state="unknown", updated_at=self.clock())
                self.save(self.records)
        except (OSError, ValueError, Refused):
            os.close(self.lock)
            raise Refused("the vault's record of its saves cannot be read, so it makes no login") from None

    def load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return []
        with os.fdopen(fd, "rb") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > self.LIMIT:
                raise ValueError()
            records = json.loads(f.read().decode())
        good = isinstance(records, list) and all(
            isinstance(r, dict) and set(r) == self.FIELDS and canonical_id(r["request_id"]) == r["request_id"]
            and r["state"] in self.STATES and isinstance(r["binding"], str) and isinstance(r["mark"], str)
            and (r["login"] is None or (isinstance(r["login"], str) and SECRET_REF.fullmatch(r["login"]))) for r in records)
        if not good or len({r["request_id"] for r in records}) != len(records):
            raise ValueError()
        return records

    def save(self, records, reserve=0):
        """Keep the journal: a new file of mode 600, made complete beside the old one and then put in its place."""
        data = json.dumps(records, sort_keys=True).encode()
        if len(data) > self.LIMIT - reserve:
            raise Refused(NO_RECORD)
        temp = self.path + ".new"
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, self.path)
            sync_folder(os.path.dirname(os.path.abspath(self.path)))    # the record stays also after a loss of power
        except OSError:
            raise Refused(NO_RECORD) from None

    def get(self, request_id):
        return next((r for r in self.records if r["request_id"] == request_id), None)

    def begin(self, record):
        """The record of a new save, kept before its create call. A journal without room refuses, and nothing is sent."""
        self.save(self.records + [record], reserve=self.RESERVE)
        self.records.append(record)

    def change(self, record, must=False, **changes):
        """A later state of a record. `must`: a state that the next step depends on."""
        record.update(changes, updated_at=self.clock())
        try:
            self.save(self.records)
        except Refused:
            if must:
                raise

    def made(self, request_id, binding, login):
        """True when this broker made this login for this request: the hub's word alone is not enough to use it."""
        record = self.get(request_id)
        return bool(record and record["binding"] == binding and record["login"] == str(login).lower()
                    and record["state"] in ("created", "registered"))

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None


def plain_line(value, most):
    """One line of 1 to `most` characters with no space at either end and no control character, as the hub gives it."""
    return isinstance(value, str) and 1 <= len(value) <= most and value == value.strip() and \
        not re.search(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]", value)


def creation(data, agent):
    """What a new login is bound to, from the hub's fields: the request, the hub generation, the agent, the task, its
    attempt and the input. `binding` is the checksum that the journal keeps with the save, so the same request cannot
    come back with other values."""
    request = canonical_id(data.get("request_id"))
    task, attempt, db, url = (data.get(k) for k in ("task", "attempt", "db", "url"))
    try:
        parts = urllib.parse.urlsplit(url) if plain_line(url, 500) else None
        address = bool(parts) and parts.scheme in ("https", "http") and bool(parts.hostname) and \
            parts.username is None and parts.password is None
    except ValueError:
        address = False
    if not (request and isinstance(task, str) and 0 < len(task) < 64 and isinstance(attempt, int)
            and not isinstance(attempt, bool) and attempt > 0
            and isinstance(db, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", db)
            and plain_line(data.get("label"), 60) and plain_line(data.get("username"), 200) and address):
        raise Refused("The hub did not confirm this vault job.")
    if provider_site(urllib.parse.urlsplit(url).hostname):
        raise Refused("this login would be for a model provider's own site, and Fleet makes none: the owner signs in "
                      "to their own account in their own session")
    made = {"db": db, "agent": agent, "task": task, "attempt": attempt, "label": data["label"],
            "username": data["username"], "url": url}
    canonical = json.dumps(made, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return dict(made, request_id=request, binding=hashlib.sha256(canonical).hexdigest(),
                mark=f"fleet-create:{agent}:{request}")


def confirm_create(conf, job):
    """The hub's confirmation of a create job: every value of the new login comes from this answer, never from the
    request. It can be asked again while the job is open and gives the same values."""
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}", {"job": job, "kind": "create"})
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("job") != job \
            or data.get("kind") != "create":
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not confirm this job" + (f": {reason}" if isinstance(reason, str) else ""))
    made = creation(data, conf["agent"])
    if data.get("mark") != made["mark"] or data.get("selector") is not None or data.get("source_url") is not None:
        raise Refused("The hub did not confirm this vault job.")       # the mark of this agent and this request only
    return made


UPPER, LOWER, DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"


def new_password(length=24):
    """A password with a capital letter, a small letter and a digit, each character with the same probability, from
    the system's source of random numbers (the form that the Mac vault makes)."""
    alphabet = UPPER + LOWER + DIGITS
    for _ in range(64):
        text = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in part for c in text) for part in (UPPER, LOWER, DIGITS)):
            return text
    raise Refused("the vault could not make a password")


def create(conf, job):
    """create_login: one new login for a confirmed job of the calling agent, with a password that this broker makes,
    saved in this machine's own store. The answer is the login's name, or one fixed sentence. `unknown` says that the
    item can exist: the same request again only looks for it by its mark, or finishes the hub's steps, and never makes
    a second save."""
    def unknown(text):
        return {"ok": False, "v": PROTOCOL, "unknown": True, "error": text}
    journal = conf.get("_journal")
    if journal is None:                 # the machine's own setup comes first: without it, nothing is asked
        raise Refused(NOT_SET_UP)
    store = LocalStore(conf)            # a store that does not open refuses here: no job is used and nothing is made
    made = confirm_create(conf, job)
    record = journal.get(made["request_id"])
    if record is not None and record["binding"] != made["binding"]:
        raise Refused(SAVE_CHANGED)
    if record is None:
        value = json.dumps({"username": made["username"], "password": new_password(), "url": made["url"]},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        now = journal.clock()
        record = {"request_id": made["request_id"], "title": made["label"], "hub": conf["hub"], "db": made["db"],
                  "state": "creating", "login": None, "started_at": now, "updated_at": now,
                  "binding": made["binding"], "mark": made["mark"]}
        journal.begin(record)           # kept before the call
        try:
            outcome, item = store.create(made["label"], value, made["mark"])
        except Exception:               # the save can have been made: an error here proves nothing
            outcome, item = "unknown", None
        del value
        # A record that stays `creating` in the file becomes `unknown` at the next start.
        journal.change(record, state={"created": "created", "refused": "failed"}.get(outcome, "unknown"),
                       login=f"bws://{item}" if outcome == "created" else None)
    elif record["state"] == "unknown":
        # Only looked for by its mark. An item that is not found leaves the record, and the request gets no second save.
        try:
            ids = store.named(record["title"])
            notes = store.notes(ids) if ids else {}
        except Refused:
            return unknown(SAVE_UNKNOWN)
        found = next((i for i in sorted(ids) if notes.get(i) == record["mark"]), None)
        if found:
            journal.change(record, state="created", login=f"bws://{found}")
    if record["state"] in ("failed", "discarded"):
        raise Refused(SAVE_REFUSED)
    if record["state"] not in ("created", "registered") or not record["login"]:
        return unknown(SAVE_UNKNOWN)
    if record["state"] == "created":
        # The hub learns the name and gets the fingerprints before the helper gets the answer. The item exists
        # now, so every failure here stays unknown: the same request again finishes these steps.
        try:
            code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}/created", {"job": job, "login": record["login"]})
            salts = data.get("fingerprint_salts") if isinstance(data, dict) else None
            if code != 200 or data.get("ok") is not True or data.get("job") != job or data.get("login") != record["login"] \
                    or not isinstance(salts, dict) or set(salts) != {"password", "totp"} \
                    or not all(re.fullmatch(r"[0-9a-f]{32}", str(v)) for v in salts.values()):
                return unknown(SAVE_UNREGISTERED)
            protect(conf, {"job": job, "fingerprint_salts": salts}, store.login(record["login"][6:]))
            journal.change(record, must=True, state="registered")
        except Refused as e:
            return unknown(str(e) if "agent's key" in str(e) else SAVE_UNREGISTERED)
    return {"ok": True, "v": PROTOCOL, "job": job, "login": record["login"]}


# ---------------------------------------------------------------- API requests (call_api)

def request_of(data):
    """What the hub asks this broker to send, from the fields of its confirmation of a request job. Each field is
    checked again here with a full match, so that no line end and no other host comes through."""
    request = canonical_id(data.get("request_id"))
    db, task, attempt, method, path, auth, body = (data.get(k) for k in ("db", "task", "attempt", "method", "path",
                                                                         "auth", "body"))
    named = API_HEADER.fullmatch(auth) if isinstance(auth, str) else None
    headers = data.get("headers") or {}
    taken = {named.group(1).lower()} if named else set()
    if not (isinstance(headers, dict) and len(headers) <= API_HEADERS_MAX and all(
            isinstance(n, str) and API_NAME.fullmatch(n) and n.lower() not in API_FIXED and n.lower() not in taken
            and isinstance(v, str) and API_VALUE.fullmatch(v) for n, v in headers.items())
            and len({n.lower() for n in headers}) == len(headers)):
        raise Refused("The hub did not confirm this vault job.")
    try:
        size = 0 if body is None else len(body.encode()) if isinstance(body, str) else -1
    except UnicodeError:
        size = -1
    if not (data.get("kind") == "request" and request and isinstance(db, str) and GENERATION.fullmatch(db)
            and plain_line(task, 63) and isinstance(attempt, int) and not isinstance(attempt, bool) and attempt > 0
            and isinstance(method, str) and method in API_METHODS and isinstance(path, str) and API_PATH.fullmatch(path)
            and (auth in ("bearer", "basic") or (named and named.group(1).lower() not in API_AUTH_FIXED))
            and 0 <= size <= API_BODY):
        raise Refused("The hub did not confirm this vault job.")
    limit = data.get("timeout")         # plan C7: the agent's own time for the service's answer
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, (int, float)) or not 0 < limit < 1e7):
        raise Refused("The hub did not confirm this vault job.")
    return {"request_id": request, "db": db, "task": task, "attempt": attempt, "method": method, "path": path,
            "auth": auth, "headers": dict(sorted(headers.items())),
            "body": body.encode() if size else None,      # no body: absent, null or empty
            "limit": limit}


def private_host(host):
    """True for an address of the hub's private range (100.64.0.0/10) in plain dotted form: four decimal parts with
    no leading zero. It is the one place that the broker reaches without TLS."""
    parts = host.split(".")
    return len(parts) == 4 and all(re.fullmatch(r"0|[1-9][0-9]{0,2}", p) and int(p) < 256 for p in parts) \
        and parts[0] == "100" and 64 <= int(parts[1]) <= 127


def origin(url):
    """(the scheme, the host, scheme://host[:port]) of a saved login's address, written again from its parts and
    without the scheme's own port. None when that text is not visible ASCII without a quote and a backslash, or the
    port is no number."""
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        return None
    site = f"{parts.scheme}://" + (f"[{host}]" if ":" in host else host) + \
        (f":{port}" if port not in (None, {"https": 443, "http": 80}.get(parts.scheme)) else "")
    return (parts.scheme, host, site) if host and re.fullmatch(r"[!#-\[\]-~]+", site) else None


def quoted(text):
    """A value in curl's config format: in double quotes, with a backslash before each backslash and quote, and \\t
    for a tab."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\t", "\\t") + '"'


def unescaped(text):
    """The text with the JSON string escapes undone, in one pass from the left: `\\\\u00e9` stays a backslash and the
    text u00e9. The two halves of one character (a surrogate pair) are joined; a half alone stays as it is."""
    text = ESCAPE.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else UNDO.get(m.group(2), m.group(2)), text)
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "surrogatepass")


def gives_back(body, values):
    """True when an answer's body has one of the login's secret values: as it is, or as a JSON string writes it."""
    undone = unescaped(body.decode("utf-8", "replace"))
    return any(value.encode() in body or value in undone for value in values)


def curl_config(call, login, body=None):
    """(what the curl child reads on its standard input, the secret values that its answer must not show). The key is
    only in this text: no argument and no environment variable has it. The text first permits no protocol and its
    last line permits the one of the address, so a text that is cut short sends nothing. curl follows no redirect and
    tries one time. The address is the origin of the saved login only, with HTTPS; without TLS only in the hub's
    private range. The agent's own headers are written as they were confirmed, after the body's default type so that
    a type of its own wins, and before the one that carries the key, which no header of the agent's may name.
    `body`: the number of the open file that has the body. The values: the login's password and
    seed, and the Basic value that the request sends. A short value can appear in any text by chance, so it is not
    looked for (as in a locked copy)."""
    scheme, host, site = origin(login["url"]) or (None, None, None)
    if not site:
        raise Refused(BAD_ADDRESS)
    if scheme != "https" and not private_host(host):       # without TLS the key goes only to the hub's private range
        raise Refused(NOT_HTTPS)
    basic = None
    if call["auth"] == "basic":         # base64 carries every value
        basic = base64.b64encode(f"{login['username']}:{login['password']}".encode()).decode()
        header = "Authorization: Basic " + basic
    elif re.search(r"[\x00-\x08\x0a-\x1f\x7f]", login["password"]):
        raise Refused(NO_HEADER)        # a line end or another control character cannot be in a header line
    else:
        header = ("Authorization: Bearer " if call["auth"] == "bearer" else call["auth"][7:] + ": ") + login["password"]
    limit = call.get("limit") or REQUEST_LIMIT
    lines = ['proto = "-all"', "silent", "globoff", "include", "no-buffer", "http1.1", 'noproxy = "*"', "max-redirs = 0",
             f"max-time = {limit}", f"connect-timeout = {min(limit, 15)}",
             f'request = "{call["method"]}"', 'header = "Accept: application/json"',
             f'user-agent = "{USER_AGENT}"']         # an agent's own User-Agent header, below, wins
    own = call.get("headers") or {}
    if body is not None:
        if not any(n.lower() == "content-type" for n in own):   # the agent's own type wins; JSON when it named none
            lines.append('header = "Content-Type: application/json"')
        lines.append(f'data-binary = "@/dev/fd/{body}"')
    elif call["method"] in ("POST", "PUT", "PATCH"):
        lines.append('header = "Content-Length: 0"')        # a method with a body: an empty one, said so
    lines += ["header = " + quoted(f"{name}: {value}") for name, value in sorted(own.items())]
    lines += ["header = " + quoted(header), "url = " + quoted(site + call["path"]), f'proto = "={scheme}"']
    values = [v for v in (login["password"], login.get("totp")) if v and len(v) >= 8]
    if basic and len(login["password"]) >= 8:
        values.append(basic)
    return ("\n".join(lines) + "\n").encode(), values


def head(data):
    """(the status of the service's answer, where its body begins) in the output of curl with headers, or None while
    the head is not complete. An interim answer (1xx) comes before the real one and is not the answer."""
    at = 0
    while True:
        m = HEAD.match(data, at)
        if not m:
            return None
        if int(m.group(1)) >= 200:
            return int(m.group(1)), m.end()
        at = m.end()


class Child:
    """The curl child of one request, in a process group of its own, so that all of it ends at once. Its arguments are
    the same for every request and it gets no environment of the broker: the options, with the address and the key,
    come on its standard input. `body`: the number of the open file with the request's body, which the child reads."""
    def __init__(self, program, request_id, scope, body=None):
        self.request_id, self.scope, self.canceled = request_id, scope, False
        self.taking, self.gone = threading.Lock(), threading.Event()
        self.proc = subprocess.Popen([program, "-q", "--config", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
                                     start_new_session=True, pass_fds=() if body is None else (body,))

    def end(self):
        """End the child and all of its process group. Until the broker has taken the child's status (`status`), the
        pid is the child's own, also when the child has ended: the signal never goes to another process."""
        with self.taking:
            if self.proc.returncode is None:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except OSError:
                    pass

    def status(self):
        """Wait for the end of the child and take its status: curl's exit status, or a negative number for a signal.
        Only then is `gone` set: a cancel answers after it."""
        while True:
            with self.taking:
                if self.proc.poll() is not None:
                    self.gone.set()
                    return self.proc.returncode
            time.sleep(0.01)

    def answer(self, config, most, limit=None):
        """Give the child its options and read its output: (the child's status, the status of the service's answer or
        None, at most `most` bytes of its body). The broker ends the child when the body has `most` bytes, when the
        head is longer than a head can be, and at the time limit. It never reads more and never waits longer."""
        limit = threading.Timer(limit or REQUEST_LIMIT, self.end)
        limit.daemon = True
        limit.start()
        data, found = b"", None
        try:
            try:
                with self.proc.stdin as options:
                    options.write(config)
            except OSError:
                pass                    # the child ended first: its status says how
            while True:
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                data += chunk
                found = found or head(data)
                if (len(data) - found[1] >= most) if found else (len(data) > HEAD_LIMIT):
                    self.end()          # enough: the rest is not read
                    break
        except Exception:
            self.end()                  # never leave a child; its status then says that a signal ended it
        code = self.status()
        limit.cancel()
        self.proc.stdout.close()
        return (code,) + ((found[0], data[found[1]:found[1] + most]) if found else (None, b""))


class Requests:
    """This broker's requests (call_api): the identity of each request that it started, in its private state folder;
    the children that run now; and the task attempts whose requests a cancel stopped (in memory). The record decides
    that a request is sent once: a request_id gets a child only while it has no record, and the record is kept before
    the child starts. It has no answer and no body. The newest KEEP records of ended requests stay. One exclusive
    lock, held for the life of the broker, gives the record to one process. `lock`: the broker's own lock, which a
    request gives up while it waits for its child; `running` and `stopped` change only with that lock."""
    LIMIT, KEEP, GUARDS = 262144, 256, 1024
    FIELDS = {"request_id", "agent", "db", "task", "attempt", "job", "started_at"}

    def __init__(self, path, lock):
        self.path, self.lock, self.running, self.stopped = path, lock, [], []
        info = os.stat(os.path.dirname(os.path.abspath(path)))
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refused("the vault's state folder must belong to the vault user and have mode 700")
        self.file = os.open(path + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.records = self.load()
        except (OSError, ValueError, Refused):
            os.close(self.file)
            raise Refused("the vault's record of its requests cannot be read, so it sends none") from None

    def load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return []
        with os.fdopen(fd, "rb") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > self.LIMIT:
                raise ValueError()
            records = json.loads(f.read().decode())
        if not isinstance(records, list) or not all(isinstance(r, dict) and set(r) == self.FIELDS
                                                    and canonical_id(r["request_id"]) == r["request_id"] for r in records):
            raise ValueError()
        return records

    def get(self, request_id):
        return next((r for r in self.records if r["request_id"] == request_id), None)

    def begin(self, record):
        """The record of a new request, kept before its child starts: a new file of mode 600, made complete beside the
        old one and then put in its place. The oldest records of ended requests go; a request that runs keeps its
        record. Without the record, nothing is sent."""
        live = {child.request_id for child in self.running}
        ended = [r["request_id"] for r in self.records if r["request_id"] not in live]
        old = set(ended[:max(0, len(ended) - self.KEEP + 1)])
        records = [r for r in self.records if r["request_id"] not in old] + [record]
        temp = self.path + ".new"
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(records, sort_keys=True).encode())
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, self.path)
            sync_folder(os.path.dirname(os.path.abspath(self.path)))    # the record stays also after a loss of power
        except OSError:
            raise Refused(NO_REQUEST_RECORD) from None
        self.records = records

    def stop(self, scope):
        """A cancel of one task attempt: from now on no request of that scope starts, and each of its children that
        runs is ended. The count of those children, or None when the broker cannot prove that the attempt has no
        child: one did not end in time, or one of the attempt came with another key and is not ended."""
        if scope not in self.stopped:
            self.stopped = (self.stopped + [scope])[-self.GUARDS:]
        mine = [child for child in self.running if child.scope == scope]
        for child in mine:
            child.canceled = True
            child.end()
        until = time.monotonic() + PATIENCE
        # The thread of each request takes its child's status without the broker's lock, and sets `gone` after it.
        gone = all([child.gone.wait(max(0, until - time.monotonic())) for child in mine])
        other = any(child.scope != scope and child.scope[1:] == scope[1:] for child in self.running)
        return len(mine) if gone and not other else None

    def close(self):
        """End each child that runs, and give the record to the next process."""
        for child in list(self.running):
            child.end()
        if self.file is not None:
            os.close(self.file)
            self.file = None


def send(conf, job):
    """call_api: one HTTP request for a confirmed job of the calling agent, to the origin of the saved login and with
    its key, which never leaves the broker. The answer is the status of the service's answer and a bounded body. A
    refusal says that nothing went out. `unknown` says that the request can have gone out: it is never sent again,
    and the broker keeps no answer."""
    def unknown(text, **more):
        return dict({"ok": False, "v": PROTOCOL, "unknown": True, "error": text}, **more)
    calls = conf.get("_requests")
    if calls is None:                   # the machine's own setup comes first: without it, nothing is asked
        raise Refused(NO_REQUESTS)
    store = LocalStore(conf)            # a broken vault must not use up the job
    confirmed = confirm_job(conf, job, "request")
    call = request_of(confirmed)
    if not SECRET_REF.fullmatch(confirmed["login"]):
        raise Refused(SAVED_ONLY)
    # What a cancel names: the key that came with the request (its checksum only), the agent, and the hub's
    # generation, task and attempt.
    scope = (hashlib.sha256(conf["agent_key"].encode()).hexdigest(), conf["agent"], call["db"], call["task"], call["attempt"])
    # The known identity comes first: a request that was started before can have gone out, also when its task attempt
    # was stopped afterwards. Only a request that never started is refused by the guard of a cancel.
    if calls.get(call["request_id"]):   # started before, also by a broker process that has ended
        log(f"request job={job}: started before, not sent again")
        return unknown(REPEATED)
    if scope in calls.stopped:          # a cancel named this task attempt: no login is read
        raise Refused(STOPPED)
    login = open_login(conf, confirmed["login"], call["task"], store)[0]
    if not swap_call(conf, confirmed, call, login):
        raise Refused(SWAP_CALL)
    protect(conf, confirmed, login)
    body = None
    try:
        if call["body"] is not None:    # a private file without a name in the state folder, complete before the child starts
            body = tempfile.TemporaryFile(dir=os.path.dirname(os.path.abspath(calls.path)))
            body.write(call["body"])
            body.flush()
            body.seek(0)
        config, values = curl_config(call, login, body and body.fileno())
        calls.begin({"request_id": call["request_id"], "agent": conf["agent"], "db": call["db"], "task": call["task"],
                     "attempt": call["attempt"], "job": job, "started_at": time.time()})       # kept before the child
        child = Child(conf[REQUEST_KEY], call["request_id"], scope, body and body.fileno())
    except OSError:
        raise Refused(NOT_STARTED) from None
    finally:
        if body is not None:
            body.close()
    calls.running.append(child)
    # The body that is read: the part that can be shown, and enough after it that a secret value which begins in that
    # part is whole, also as JSON writes it at its longest (six bytes for each UTF-16 unit).
    most = ANSWER_LIMIT + max((3 * len(value.encode("utf-16-le")) for value in values), default=1)
    calls.lock.release()                # only here: a cancel and a status are served while the child runs
    try:
        code, status, got = child.answer(config, most, call["limit"])
    finally:
        calls.lock.acquire()
        calls.running.remove(child)
    del config, login
    if status is not None and status <= 599 and (code == 0 or len(got) >= most):
        log(f"request job={job}: HTTP {status}")
        reply = {"ok": True, "v": PROTOCOL, "job": job, "status": status}
        if gives_back(got, values):     # looked for in all that was read, before any cut: no part of the body is shown
            return dict(reply, withheld="key")
        cut = len(got) > ANSWER_LIMIT
        try:                            # a cut can be inside one character: its first bytes are then left out
            text = codecs.getincrementaldecoder("utf-8")().decode(got[:ANSWER_LIMIT], not cut)
        except UnicodeDecodeError:
            text = "\x00"
        if "\x00" in text:
            return dict(reply, withheld="binary")
        return dict(reply, body=text, truncated=cut)
    if code in NOT_SENT:
        raise Refused(UNREACHABLE)
    if child.canceled and code < 0:
        log(f"request job={job}: stopped by a cancel")
        return unknown(CANCELED, canceled=True)
    log(f"request job={job}: outcome not known")
    return unknown(SENT_UNKNOWN)


def cancel(conf, req):
    """cancel: end each request of one task attempt that came with this caller's key, and refuse a later one. The hub
    is not asked: the end of a request is always safe. `stopped` is said only after the broker took the status of
    each child that it ended."""
    calls = conf.get("_requests")
    if calls is None:
        raise Refused(NO_REQUESTS)
    db, task, attempt = req.get("db"), req.get("task"), req.get("attempt")
    if not (isinstance(db, str) and GENERATION.fullmatch(db) and plain_line(task, 63) and isinstance(attempt, int)
            and not isinstance(attempt, bool) and attempt > 0):
        raise Refused("a cancel request needs db, task and attempt")
    ended = calls.stop((hashlib.sha256(conf["agent_key"].encode()).hexdigest(), conf["agent"], db, task, attempt))
    if ended is None:
        raise Refused(NO_PROOF)
    log(f"cancel {task} attempt {attempt}: ended {ended}")
    return {"ok": True, "v": PROTOCOL, "task": task, "attempt": attempt, "stopped": True, "ended": ended}


# ---------------------------------------------------------------- the owner's signature (central vault)
#
# The central vault seals a copy only to a machine key that the owner signed, and its backup only to a recovery key
# that the owner signed, so that a hub that is broken into cannot add a machine of its own. The owner's key is an ECDSA
# P-256 key of his Mac (CryptoKit), and the standard library has no ECDSA, so its verification is here, in plain
# Python, and nothing else of it: no key is made and nothing is signed. Every value that it reads is public -- the
# statement, the signature and the owner's public key -- so it needs no protection against timing.

# NIST P-256 (FIPS 186-4 D.1.2.3; SEC 2 secp256r1): the curve y^2 = x^3 + a*x + b over the field of the prime p, and
# its base point G of the prime order n. The cofactor is 1: every point of the curve but infinity has the order n.
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def on_curve(point):
    """A point (x, y) of P-256: two numbers of the field that solve the curve's equation."""
    x, y = point
    return 0 <= x < P256_P and 0 <= y < P256_P and (y * y - x * x * x - P256_A * x - P256_B) % P256_P == 0


def point_add(one, two):
    """The sum of two points of the curve, in affine coordinates. None is the point at infinity."""
    if one is None:
        return two
    if two is None:
        return one
    (x1, y1), (x2, y2) = one, two
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:         # a point and its negative (and P-256 has no point with y = 0)
            return None
        slope = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P          # one point twice: the tangent
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P256_P, -1, P256_P) % P256_P          # two points: the line through them
    x3 = (slope * slope - x1 - x2) % P256_P
    return x3, (slope * (x1 - x3) - y1) % P256_P


def point_times(k, point):
    """k times a point of the curve: double and add, from the highest bit of k."""
    result = None
    for bit in bin(k)[2:]:
        result = point_add(result, result)
        if bit == "1":
            result = point_add(result, point)
    return result


def ecdsa_verified(point, digest, r, s):
    """True when (r, s) is an ECDSA signature by the public key `point` over this SHA-256 digest (FIPS 186-4 6.4.2).
    r and s must both be in 1..n-1. There is no low-s rule: CryptoKit makes either s, and both are valid."""
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    e = int.from_bytes(digest, "big")   # SHA-256 is exactly as long as n (256 bits), so all of it is used
    w = pow(s, -1, P256_N)
    found = point_add(point_times(e * w % P256_N, P256_G), point_times(r * w % P256_N, point))
    return found is not None and found[0] % P256_N == r


def der_signature(raw):
    """(r, s) of a signature in DER, read strictly: one SEQUENCE of two INTEGERs, each positive and in its shortest
    form, and nothing after it. None for anything else. A P-256 signature is at most 72 bytes, so every length in it
    has its one-byte form, and a longer form is refused as not the shortest."""
    if len(raw) < 2 or raw[0] != 0x30 or raw[1] >= 0x80 or raw[1] != len(raw) - 2:
        return None
    body, numbers = raw[2:], []
    for _ in range(2):
        if len(body) < 3 or body[0] != 0x02 or body[1] >= 0x80 or not 1 <= body[1] <= len(body) - 2:
            return None
        size, number = body[1], body[2:2 + body[1]]
        if number[0] & 0x80 or (size > 1 and number[0] == 0 and not number[1] & 0x80):
            return None                 # a negative number, or a zero byte in front that the number does not need
        numbers.append(int.from_bytes(number, "big"))
        body = body[2 + size:]
    if body or not all(numbers):        # more after the two numbers, or a number that is zero
        return None
    return numbers[0], numbers[1]


def owner_key(text):
    """The point of one owner key: the standard base64, padded, of 65 bytes 04 || X || Y (CryptoKit's
    x963Representation), which must be a point of the curve. ValueError for anything else. The cofactor is 1, so a
    point of the curve needs no other check of its order."""
    if not isinstance(text, str):
        raise ValueError("not an owner key")
    raw = base64.b64decode(text, validate=True)
    if base64.b64encode(raw).decode() != text or len(raw) != 65 or raw[0] != 4:
        raise ValueError("not an owner key")
    point = int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")
    if not on_curve(point):
        raise ValueError("not an owner key")
    return point


def owner_signed(conf, statement, signature):
    """True when one of the owner's keys signed exactly these statement bytes (UTF-8): signature is the standard
    base64, padded, of the DER form (CryptoKit's derRepresentation), over SHA-256 of the statement."""
    try:
        raw = base64.b64decode(signature, validate=True)
        digest = hashlib.sha256(statement.encode("utf-8")).digest()
    except ValueError:                  # also a UnicodeError: a text that is not UTF-8 was signed by nobody
        return False
    found = der_signature(raw) if base64.b64encode(raw).decode() == signature else None
    if found is None:
        return False
    for text in conf["owner_keys"]:
        try:
            if ecdsa_verified(owner_key(text), digest, *found):
                return True
        except ValueError:              # load_config refused such a key; this reads them again for one request
            continue
    return False


def canonical(value):
    """The one text of a JSON value that the vault and the owner's app both sign."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def owner_statement(conf, req, kind):
    """The owner's statement of this kind ({v, kind, fleet, at, and its machine, recipient, login and agent as
    STATEMENTS says}), after its form, its fleet and its signature. The statement must be the canonical text of what it holds, so the vault checks
    the very bytes that the app signed; and it must name this fleet, so a statement of another fleet is no use here."""
    statement, signature = req.get("statement"), req.get("signature")
    if not isinstance(statement, str) or not isinstance(signature, str):
        raise Refused("a signed statement needs its statement and its signature")
    try:
        said = json.loads(statement)
    except (ValueError, RecursionError):
        said = None
    if not isinstance(said, dict) or canonical(said) != statement:
        raise Refused("the statement is not in its canonical form")
    if set(said) != STATEMENTS[kind] or said["kind"] != kind or type(said["v"]) is not int or said["v"] != 1 \
            or type(said["at"]) is not int or said["at"] < 0 or not isinstance(said["fleet"], str) \
            or not all(isinstance(said.get(k, ""), str) for k in ("machine", "recipient", "login", "agent")) \
            or ("machine" in said and not MACHINE.fullmatch(said["machine"])) \
            or ("recipient" in said and not RECIPIENT.fullmatch(said["recipient"])) \
            or ("login" in said and not (SECRET_REF.fullmatch(said["login"]) and said["login"] == said["login"].lower())) \
            or ("agent" in said and not AGENT_NAME.match(said["agent"])):
        raise Refused(f"the statement is not a valid {kind} statement")
    if said["fleet"] != conf["fleet"]:
        raise Refused("the statement is for another fleet")
    if not owner_signed(conf, statement, signature):
        raise Refused("the statement does not carry a valid signature of the owner")
    return said


# ---------------------------------------------------------------- the central vault

def central_config(conf):
    """A central vault's configuration (load_config): its own keys and no other."""
    if conf.get("central") is not True or set(conf) != CENTRAL_KEYS:
        raise SystemExit("A central vault's configuration needs exactly: " + ", ".join(sorted(CENTRAL_KEYS)) +
                         ", with central true; no hub, no worker_uid or worker_group, no agent, no Bitwarden key and "
                         "no curl, ssh or write key")
    uid = conf["hub_uid"]
    if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0 or uid == os.getuid():
        raise SystemExit("hub_uid must be the user ID of the hub's user, never the vault user's")
    if not isinstance(conf["fleet"], str) or not FLEET_ID.fullmatch(conf["fleet"]):
        raise SystemExit("fleet must be the fleet's ID: 16 lowercase hex characters")
    keys = conf["owner_keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= OWNER_KEYS:
        raise SystemExit(f"owner_keys must list 1 to {OWNER_KEYS} public keys of the owner")
    for text in keys:
        try:
            owner_key(text)
        except ValueError:
            raise SystemExit("each of owner_keys must be the base64 of an uncompressed P-256 public key (65 bytes: "
                             "04, X, Y) that is a point of the curve") from None
    for key in ("age", "age_key", "store", "store_key", "socket", "state"):
        if not isinstance(conf[key], str) or not os.path.isabs(conf[key]):
            raise SystemExit(f"{key} must be an absolute path")
    unchangeable(conf["age"], "The age program")
    return conf


def kept_record(record, unpinned=False):
    """One record of the state: {recipient, at}. An unpin keeps its machine's record with no recipient."""
    return isinstance(record, dict) and set(record) == {"recipient", "at"} and type(record["at"]) is int and (
        isinstance(record["recipient"], str) and RECIPIENT.fullmatch(record["recipient"]) is not None
        or unpinned and record["recipient"] is None)


def kept_grant(record):
    """One grant record of the state: {machine, at}, with no machine after an ungrant."""
    return isinstance(record, dict) and set(record) == {"machine", "at"} and type(record["at"]) is int and (
        record["machine"] is None or isinstance(record["machine"], str) and MACHINE.fullmatch(record["machine"]))


def kept_pool(record):
    """One pool record of the state: {in, at}."""
    return isinstance(record, dict) and set(record) == {"in", "at"} and type(record["at"]) is int and \
        isinstance(record["in"], bool)


def central_state(conf):
    """The owner's signed records, read again for every request: {"v": 1, "pins": {machine: {recipient, at}},
    "recovery": {recipient, at} or None, "grants": {login: {agent: {machine, at}}}, "pool": {login: {in, at}},
    "removed": {login: at}}. An unpin keeps its machine's record, with no recipient, and an ungrant and an unpool keep
    theirs too, so a statement older than them, which the hub could send again, is refused as old. "removed" is not
    the owner's: it names each login that remove took out, so that no value comes in under its name again (intake).
    No file is no record, and a state of the format before grants, or before remove, has none."""
    if not os.path.lexists(conf["state"]):
        return {"v": STATE, "pins": {}, "recovery": None, "grants": {}, "pool": {}, "removed": {}}
    try:
        data = json.loads(read_private(conf["state"], "state"))
        if isinstance(data, dict):
            data.setdefault("grants", {})
            data.setdefault("pool", {})
            data.setdefault("removed", {})
        good = isinstance(data, dict) and set(data) == {"v", "pins", "recovery", "grants", "pool", "removed"} \
            and data["v"] == STATE and isinstance(data["pins"], dict) \
            and all(MACHINE.fullmatch(m) and kept_record(x, unpinned=True) for m, x in data["pins"].items()) \
            and (data["recovery"] is None or kept_record(data["recovery"])) \
            and isinstance(data["grants"], dict) and all(
                SECRET_REF.fullmatch(ref) and isinstance(held, dict) and all(
                    AGENT_NAME.match(agent) and kept_grant(x) for agent, x in held.items())
                for ref, held in data["grants"].items()) \
            and isinstance(data["pool"], dict) and all(SECRET_REF.fullmatch(ref) and kept_pool(x)
                                                       for ref, x in data["pool"].items()) \
            and isinstance(data["removed"], dict) and all(SECRET_REF.fullmatch(ref) and ref == ref.lower()
                                                          and type(at) is int for ref, at in data["removed"].items())
    except ValueError:
        good = False
    if not good:
        raise Refused("the central vault's state cannot be read")
    return data


def keep_state(conf, state):
    """Write the central vault's state whole: a new file of mode 600, made complete beside the old one and then put in
    its place, as the store is kept."""
    path, temp = conf["state"], conf["state"] + ".new"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)        # also when a file of an earlier failure was there
            f.write(json.dumps(state, sort_keys=True))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    except OSError:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise Refused("the central vault's state could not be saved, so nothing changed") from None
    try:
        sync_folder(os.path.dirname(os.path.abspath(path)))
    except OSError:
        pass                            # the new state is already in its place: this is no failure of the save


def pins(state):
    """The machines that have a key the owner signed now, and that key: the records of unpins are left out."""
    return {m: dict(x) for m, x in sorted(state["pins"].items()) if x["recipient"]}


def central_status(conf):
    """What the hub reads of the central vault: its keys, the owner's records and how many items it holds. Never a
    value and never a title."""
    state, store = central_state(conf), LocalStore(conf)
    return {"ok": True, "v": PROTOCOL, "central": True, "recipient": public_key(conf["age_key"], "key"),
            "store_recipient": store.recipient, "fleet": conf["fleet"], "owner_keys": len(conf["owner_keys"]),
            "pins": pins(state), "recovery": state["recovery"]["recipient"] if state["recovery"] else None,
            "grants": granted(state), "pool": pooled(state), "items": len(store.opened()),
            "removes": True, "source": conf.get("_source")}     # removes: this program serves remove (the hub asks)


def fingerprint_list(items):
    """The fingerprints that the owner registered under one reference, of the form that fingerprints() makes: {kind,
    hash (64 lowercase hex), len}. A reference that was registered more than once has more than one value's rows."""
    return isinstance(items, list) and len(items) <= 32 and all(
        isinstance(x, dict) and set(x) == {"kind", "hash", "len"} and x["kind"] in ("password", "totp")
        and isinstance(x["hash"], str) and re.fullmatch(r"[0-9a-f]{64}", x["hash"]) is not None
        and type(x["len"]) is int for x in items)


def intake(conf, req):
    """intake: save in the central store one value that the owner sealed to this vault's key in his app. The hub
    gives the salts and the fingerprints that the owner registered under that reference, and the value is saved only
    when each of its own fingerprints is one of those, and its password's is there when the owner registered one: the
    rule of a deposit (the hub's helper_deposit_check), so the hub cannot put another value under a name that the
    owner gave. It is saved under the same reference, and another value under it is refused, as a deposit is. A name
    that remove took out takes no value again: else a hub that is broken into could remove a value that nobody holds
    yet and put its own under the owner's name, for his next grant to send."""
    ref, title, item, text, salts, given = (req.get(k) for k in ("login", "title", "item", "ciphertext", "salts",
                                                                 "fingerprints"))
    m = SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
    if not (m and plain_line(title, 200) and item in ("login", "api_key") and isinstance(text, str)
            and ARMOR in text and len(text) <= COPY_MAX and isinstance(salts, dict)
            and all(re.fullmatch(r"[0-9a-f]{32}", str(salts.get(k))) for k in ("password", "totp"))
            and fingerprint_list(given)):
        raise Refused("the intake request is not valid")
    if ref.lower() in central_state(conf)["removed"]:
        raise Refused("this login was removed from the fleet, so no value is taken under its name again")
    store = LocalStore(conf)
    read_private(conf["age_key"], "key")            # owner and mode are checked before age reads it
    r = run([conf["age"], "-d", "-i", conf["age_key"]], text)
    if r is None or r.returncode != 0:
        raise Refused("the owner's copy cannot be opened with the central vault's key")
    value = delivered(r.stdout, item)
    mine = {(x["kind"], x["hash"], x["len"]) for x in fingerprints(value, salts)}
    registered = {(x["kind"], x["hash"], x["len"]) for x in given}
    if not (mine <= registered and (all(k[0] != "password" for k in registered)
                                    or any(k[0] == "password" for k in mine))):
        raise Refused("the value does not match what the owner registered")
    saved = store.put(m.group(1).lower(), title, canonical(value), TAKEN)
    log(f"intake: {ref.lower()} {saved}")
    return {"ok": True, "login": ref.lower(), "saved": saved}


def central_signed(conf, req, kind):
    """pin, unpin, recovery, grant, ungrant, pool and unpool: keep one statement that the owner signed. A statement must
    be newer (its `at`) than the record of its machine, of the recovery key, of its grant (one secret to one agent) or
    of its secret in the pool, so an old one cannot be sent again; the exact statement of the record answers "same",
    so a retry is no error. A pin's key is what seal locks a copy to, a grant or the pool is what lets seal lock that
    secret at all, and the recovery key is what export locks the store's key to."""
    said = owner_statement(conf, req, kind)
    state = central_state(conf)
    if kind in ("grant", "ungrant"):
        held = state["grants"].setdefault(said["login"], {})
        new, old = {"machine": said.get("machine"), "at": said["at"]}, held.get(said["agent"])
        was = old is not None and old["machine"] is not None
    elif kind in ("pool", "unpool"):
        new, old = {"in": kind == "pool", "at": said["at"]}, state["pool"].get(said["login"])
        was = old is not None and old["in"]
    else:
        new = {"recipient": said.get("recipient"), "at": said["at"]}       # an unpin keeps its time, with no recipient
        old = state["recovery"] if kind == "recovery" else state["pins"].get(said["machine"])
        was = old is not None and old["recipient"] is not None
    if old == new:          # the same record is the same statement: its v, kind, fleet and the rest are fixed
        saved = "same"
    elif old is not None and new["at"] <= old["at"]:
        raise Refused("the vault holds a statement that is as new or newer, so nothing changed")
    else:
        saved = "removed" if kind in ("unpin", "ungrant", "unpool") else "replaced" if was else "new"
        if kind == "recovery":
            state["recovery"] = new
        elif kind in ("grant", "ungrant"):
            state["grants"][said["login"]][said["agent"]] = new
        elif kind in ("pool", "unpool"):
            state["pool"][said["login"]] = new
        else:
            state["pins"][said["machine"]] = new
        keep_state(conf, state)
    log(f"{kind} statement of the owner: {saved}")
    answer = {"ok": True, "kind": kind, "saved": saved}
    answer.update({k: said[k] for k in ("machine", "recipient", "login", "agent") if k in said})
    return answer


def granted(state):
    """[{login, agent, machine}]: the grants that the owner signed and has not taken back, in a fixed order."""
    return [{"login": ref, "agent": agent, "machine": x["machine"]} for ref, held in sorted(state["grants"].items())
            for agent, x in sorted(held.items()) if x["machine"]]


def pooled(state):
    """The secrets that the owner signed into the grantable pool and has not taken out, sorted."""
    return sorted(ref for ref, x in state["pool"].items() if x["in"])


def sealable(state, ref, machine):
    """True when the owner signed that this secret may reach this machine: a grant of it to an agent there, or the
    secret in the grantable pool, which the manager may hand to an agent on any machine."""
    return any(g["login"] == ref and g["machine"] == machine for g in granted(state)) or ref in pooled(state)


def seal(conf, req):
    """seal: one stored value, locked to the key that the owner pinned for one machine, for the hub to carry to that
    machine's broker (a deposit). Nothing is sealed to a machine without a pin, nor without the owner's signed grant
    of that value to an agent of that machine or his signed word that it is in the grantable pool (sealable), and a
    copy that holds a value in plain is not given."""
    ref, machine = req.get("login"), req.get("machine")
    m = SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
    if not (m and isinstance(machine, str) and MACHINE.fullmatch(machine)):
        raise Refused("a seal request needs a login and a machine")
    state = central_state(conf)
    pin = pins(state).get(machine)
    if not pin:
        raise Refused("the owner has not pinned a key for this machine, so nothing is sealed for it")
    if not sealable(state, ref.lower(), machine):
        raise Refused("the owner has signed no grant of this secret to an agent of this machine and has not put it "
                      "into the grantable pool, so nothing is sealed for it")
    found = LocalStore(conf).opened().get(m.group(1).lower())
    if not found:
        raise Refused("the central vault has no such login")
    r = run([conf["age"], "-a", "-r", pin["recipient"]], found["value"])
    if r is None or r.returncode != 0 or ARMOR not in r.stdout:
        raise Refused("the login could not be sealed for this machine")
    if any(value in r.stdout for value in plain_values(found["value"])):
        raise Refused("the sealed copy was not locked, so it is not given")
    log(f"seal: {ref.lower()} for {machine}")
    return {"ok": True, "login": ref.lower(), "machine": machine, "recipient": pin["recipient"], "title": found["key"],
            "ciphertext": r.stdout, "sha256": hashlib.sha256(r.stdout.encode("utf-8")).hexdigest()}


def export(conf):
    """export: the backup of the central store. The store file as it is (it holds no value in plain), and the store's
    key locked to the recovery key that the owner signed, so only the owner's recovery code opens the two. Nothing is
    exported without that key."""
    recovery = central_state(conf)["recovery"]
    if not recovery:
        raise Refused("the owner has not signed a recovery key, so nothing is exported")
    store = LocalStore(conf)
    fd = store.locked()                 # the file and its count are of one store: no save comes between them
    try:
        text = read_private(conf["store"], "store")
        items = store.opened()
    finally:
        os.close(fd)
    key = read_private(conf["store_key"], "store key")
    r = run([conf["age"], "-a", "-r", recovery["recipient"]], key)
    if r is None or r.returncode != 0 or ARMOR not in r.stdout:
        raise Refused("the store's key could not be locked to the recovery key, so nothing is exported")
    secret = [line.strip() for line in key.splitlines() if line.strip() and not line.startswith("#")]
    if any(len(line) >= 8 and line in r.stdout for line in secret):
        raise Refused("the store's key was not locked, so nothing is exported")
    log(f"export: {len(items)} item(s), for the recovery key")
    return {"ok": True, "v": 1, "made_at": time.time(), "items": len(items), "store_recipient": store.recipient,
            "recovery": recovery["recipient"], "store": text, "key": r.stdout}


def remove(conf, req):
    """remove: take out of the central store one value that the owner took out of the fleet (Remove from Founderizer,
    which takes it out of the hub's catalog). The hub asks only when no machine's vault holds a copy of it any more,
    because it takes a copy back from a machine only while this vault still lists the secret (hub.py central_plan).

    It needs no statement of the owner's: a removal gives no value to anybody, so it cannot weaken what his signatures
    guard, which is where a value may go. But it is refused while a grant or the pool that he signed names the
    secret, so a hub that is broken into cannot take away a secret that the owner gives to an agent or to the door.
    And the name is kept first ("removed" of the state), so no value comes in under it again (intake). "absent" when
    the store holds no such value, so a request that is asked again ends the same way."""
    ref = req.get("login")
    m = SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
    if not m:
        raise Refused("a remove request needs a login")
    ref, state = ref.lower(), central_state(conf)
    if any(g["login"] == ref for g in granted(state)) or ref in pooled(state):
        raise Refused("a grant or the pool that the owner signed still names this login, so it is not removed")
    if ref not in state["removed"]:     # first: a removal that stops halfway still takes no new value under this name
        state["removed"][ref] = int(time.time())
        keep_state(conf, state)
    removed = LocalStore(conf).remove(m.group(1).lower(), TAKEN)
    log(f"remove: {ref} {removed}")
    return {"ok": True, "login": ref, "removed": removed}


def central(conf, req):
    """One request to the central vault (handle): its own operations and status, and nothing of a machine's broker."""
    op = req.get("op")
    if op == "status":
        return central_status(conf)
    if op == "intake":
        return intake(conf, req)
    if op in ("pin", "unpin", "recovery", "grant", "ungrant", "pool", "unpool"):
        return central_signed(conf, req, op)
    if op == "seal":
        return seal(conf, req)
    if op == "inventory":
        return {"ok": True, "logins": sorted("bws://" + sid for sid in LocalStore(conf).opened())}
    if op == "export":
        return export(conf)
    if op == "remove":
        return remove(conf, req)
    raise Refused("unknown operation")


def caller(req):
    """The calling agent and its key (shared broker callers): both or neither. The key is used for the hub calls of
    this request only: never stored, logged or answered."""
    if "agent" not in req and "agent_key" not in req:      # a field that is there, also as null, needs the other one
        return None
    agent, key = req.get("agent"), req.get("agent_key")
    if not (isinstance(agent, str) and AGENT_NAME.fullmatch(agent) and isinstance(key, str) and CALLER_KEY.fullmatch(key)):
        raise Refused("the caller fields are not valid")
    return agent, key


def handle(conf, line, uid):
    if not admitted(conf, uid):
        raise Refused("only the hub's user may ask the central vault" if conf.get("central") is True else
                      "only an agent user of this machine may ask this broker")
    try:
        req = json.loads(line)
    except ValueError:
        raise Refused("send one JSON request line") from None
    if not isinstance(req, dict) or req.get("v") != PROTOCOL:
        raise Refused("unsupported protocol version")
    op = req.get("op")
    if conf.get("central") is True:     # the central vault serves its own operations and nothing of a machine's broker,
        return central(conf, req)
    if op in CENTRAL_OPERATIONS:        # and a machine's broker none of the central vault's
        raise Refused("unknown operation")
    if op == "status":
        # backend: the store that this broker opens, which is always the fleet's own now. fleet.py's doctor and the
        # Mac app read the field, so it stays. The fleet's own store takes a secret that the owner delivers (deposits),
        # and gives it back when no agent of the machine holds it (withdrawals).
        status = {"ok": True, "v": PROTOCOL, "agent": conf.get("agent"), "store": "user", "backend": "store",
                  "user": pwd.getpwuid(os.getuid()).pw_name, "recipient": recipient(conf), "callers": True,
                  "source": conf.get("_source"), "deposits": True, "withdrawals": True}
        if conf.get("_journal") is not None:        # this broker can make a login: its record of saves is open
            status["creates"] = True
        if conf.get("_requests") is not None:       # only with a curl program: this broker can send a request
            status["requests"] = True
        if conf.get("_swaps") is not None:          # only with the part "swap": this broker keeps keys out of sessions
            status["swaps"] = True
        return status
    who = caller(req)
    if who:                             # this request acts for its caller; the store does not change
        conf = dict(conf, agent=who[0], agent_key=who[1])
    elif conf.get("agent") is None:     # a broker of a machine, not of one agent: nothing else says who asked
        raise Refused("this broker serves the agents of its machine, so a request must name its caller")
    if op == "create":
        job = req.get("job")
        if not who:
            raise Refused("a create request needs the caller fields")
        if not isinstance(job, int) or isinstance(job, bool) or job < 1:
            raise Refused("a create request needs a job number")
        return create(conf, job)
    if op in ("request", "cancel"):     # the key that comes with a request is also what a cancel of it must name
        job = req.get("job")
        if not who:
            raise Refused(f"a {op} needs the caller fields")
        if op == "cancel":
            return cancel(conf, req)
        if not isinstance(job, int) or isinstance(job, bool) or job < 1:
            raise Refused("a request needs a job number")
        return send(conf, job)
    if op == "deposit":
        job = req.get("job")
        if not who:
            raise Refused("a deposit needs the caller fields")
        if not isinstance(job, int) or isinstance(job, bool) or job < 1:
            raise Refused("a deposit needs the number of its delivery")
        return deposit(conf, job)
    if op == "withdraw":
        job = req.get("job")
        if not who:
            raise Refused("a withdrawal needs the caller fields")
        if not isinstance(job, int) or isinstance(job, bool) or job < 1:
            raise Refused("a withdrawal needs the number of its job")
        return withdraw(conf, job)
    if op == "signin":
        raise Refused("signing in needs a browser: only the Mac vault helper signs in")
    if op == "read":
        return read(conf, req.get("for"), uid)
    if op == "probe":
        job = req.get("job")
        if not isinstance(job, int) or isinstance(job, bool) or job < 1:
            raise Refused("a probe request needs a job number")
        return probe(conf, job)
    if op != "handover":
        raise Refused("unknown operation")
    job = req.get("job")
    if not isinstance(job, int) or isinstance(job, bool) or job < 1:
        raise Refused("a handover request needs a job number")
    return handover(conf, job)


def described(req):
    """The operation, the job and the caller's name for the log: known forms only, never the caller's key."""
    if not isinstance(req, dict):
        return "request"
    op, job, who = req.get("op"), req.get("job"), req.get("agent")
    text = f"{op if op in OPERATIONS else 'request'} job={job if isinstance(job, int) and not isinstance(job, bool) else None}"
    return text + (f" for {who}" if isinstance(who, str) and AGENT_NAME.fullmatch(who) else "")


def read_line(conn, limit=8192):
    data = b""
    while not data.endswith(b"\n") and len(data) < limit:
        chunk = conn.recv(limit - len(data))
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", "replace")


def with_writes(conf):
    """The configuration with the broker's journal (`_journal`), which it needs to make a login; the store writes
    itself, so nothing more is needed. Else, when the journal cannot be opened (another process has it, or it cannot
    be read), the configuration as it is, and the reason in the log: that broker reads and makes no login."""
    try:
        return dict(conf, _journal=Journal(os.path.join(state_folder(conf), JOURNAL)))
    except Refused as e:
        log(f"no new logins: {e}")
        return conf


def with_source(conf):
    """The configuration with the SHA-256 of the broker program's own file (`_source`), or without it and the reason
    in the log.

    A release never reaches this file. The broker runs a root-owned copy outside every checkout that a helper
    updates (WORKER-INSTALL.md, "Vault broker"), and `lifecycle.OWNER_ONLY` lists vault.py among the files a helper
    never loads, so a commit that changes only this program advances the revision that every machine reports and
    reaches no broker. A machine's revision therefore says nothing about its vault, and this checksum is the one
    thing that does.

    It is read once, at the start, because what the broker runs is the file as it was then: a copy installed under
    a broker that was not restarted has not reached the running code, and the status must go on saying the old one
    until the service restarts."""
    try:
        with open(os.path.realpath(__file__), "rb") as f:
            return dict(conf, _source=hashlib.sha256(f.read()).hexdigest())
    except OSError as e:
        log(f"no program checksum: {e}")         # the status then says nothing, which is not the same as current
        return conf


def with_requests(conf, lock):
    """The configuration with the broker's requests (`_requests`) when it names a curl program and the record of the
    started requests can be read; else the configuration as it is, and the reason in the log. A broker without it
    sends no request."""
    if REQUEST_KEY not in conf:
        return conf
    try:
        return dict(conf, _requests=Requests(os.path.join(state_folder(conf), REQUESTS), lock))
    except Refused as e:
        log(f"no requests: {e}")
        return conf


class Broker:
    def __init__(self, conf):
        # One request works at a time, as before. Only a request's wait for its curl child is outside this lock, so
        # that a cancel and a status are served meanwhile.
        self.lock, self.room = threading.Lock(), threading.BoundedSemaphore(SERVED)
        if conf.get("central") is True:     # the central vault makes no login, sends no request and has no target key
            self.conf = with_source(conf)
        else:
            self.conf = with_source(with_swaps(with_requests(with_writes(conf), self.lock)))
        self.conf, self.sock = dict(self.conf, _lock=self.lock), None
        self.swap_sock, self.swap_room = None, threading.BoundedSemaphore(SWAP_ROOM)

    def open(self):
        path = self.conf["socket"]
        if os.stat(os.path.dirname(path)).st_uid != os.getuid():
            raise SystemExit("The socket folder must belong to the vault user (systemd RuntimeDirectory).")
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o117)           # 0660: the vault user and the worker's group (the service Group)
        try:
            self.sock.bind(path)
        finally:
            os.umask(old)
        self.sock.listen(8)
        if self.conf.get("_swaps") is not None:
            self.open_swaps()
        return self

    def open_swaps(self):
        """The broker's second socket, for the swap proxy, only on a machine whose configuration has the part "swap".
        The proxy's user is in no group of the broker's, so the broker's runtime folder is made passable (mode 751:
        no other user lists it or makes a file in it) and the socket is open for each user (mode 666). What keeps
        each other user out is swap_served: it reads the caller's user from the kernel before it reads a byte.
        When the socket cannot be opened, the broker serves without it, and a key with a site is not given."""
        path = self.conf["_swap"]["broker"]
        try:
            os.chmod(os.path.dirname(path), 0o751)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            old = os.umask(0o111)
            try:
                sock.bind(path)
            finally:
                os.umask(old)
            sock.listen(64)
        except OSError as e:
            log(f"no key swap: the socket for the proxy could not be opened ({type(e).__name__})")
            self.conf = {k: v for k, v in self.conf.items() if k != "_swaps"}
            return
        self.swap_sock = sock
        threading.Thread(target=self.serve_swaps, daemon=True).start()

    def serve_swaps(self):
        while True:
            self.swap_room.acquire()
            try:
                conn, _ = self.swap_sock.accept()
            except OSError:
                return                  # closed
            try:
                threading.Thread(target=self.swap_served, args=(conn,), daemon=True).start()
            except RuntimeError:        # no new thread now: this question gets no answer, and the loop goes on
                conn.close()
                self.swap_room.release()

    def swap_served(self, conn):
        """One question of the swap proxy. Only the proxy's own user is answered, and nothing is read from another
        one. The broker's one lock is not taken: a swap must not wait for the hub call of another operation."""
        try:
            with conn:
                conn.settimeout(10)
                if peer_uid(conn) != self.conf["_swap"]["uid"]:
                    return
                try:
                    reply = swap_handle(self.conf, read_line(conn))
                except Refused as e:
                    reply = {"ok": False, "error": str(e)}
                except Exception as e:          # never pass details on
                    reply = {"ok": False, "error": f"the vault broker hit an error ({type(e).__name__})"}
                    log(f"swap: error {type(e).__name__}")
                if reply.get("code"):
                    log(f"swap refused: {reply['code']}")
                if self.conf.get("_source"):    # the program that this broker runs: a proxy on another one moves to it
                    reply["program"] = self.conf["_source"]
                conn.sendall((json.dumps(reply) + "\n").encode())
        except OSError:
            pass
        finally:
            self.swap_room.release()

    def serve(self):
        while True:
            self.room.acquire()         # at most SERVED connections at one time; the next ones wait, as before
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return                  # closed
            threading.Thread(target=self.served, args=(conn,), daemon=True).start()

    def served(self, conn):
        """One connection, in a thread of its own: a cancel does not wait for a request that runs."""
        try:
            with conn:
                self.answer(conn)
        finally:
            self.room.release()

    def answer(self, conn):
        conn.settimeout(10)
        what = "request"
        try:
            line = read_line(conn, CENTRAL_LINE) if self.conf.get("central") is True else read_line(conn)
            try:
                req = json.loads(line) if line.strip() else {}
            except ValueError:
                req = {}
            what = described(req)
            with self.lock:
                reply = handle(self.conf, line, peer_uid(conn))
            log(f"{what}: ok")
        except Refused as e:
            reply = {"ok": False, "v": PROTOCOL, "error": str(e)}
            log(f"{what} refused: {e}")
        except Exception as e:          # never pass details on
            reply = {"ok": False, "v": PROTOCOL, "error": f"the vault broker hit an error ({type(e).__name__})"}
            log(f"error {type(e).__name__}")
        try:
            conn.sendall((json.dumps(reply) + "\n").encode())
        except OSError:
            pass

    def close(self):
        if self.sock:
            self.sock.close()
        if self.swap_sock:
            self.swap_sock.close()
        if self.conf.get("_journal") is not None:
            self.conf["_journal"].close()
            self.conf = {k: v for k, v in self.conf.items() if k != "_journal"}
        if self.conf.get("_requests") is not None:
            self.conf["_requests"].close()
            self.conf = {k: v for k, v in self.conf.items() if k != "_requests"}


# ---------------------------------------------------------------- the key swap
#
# An API key that an agent reads can stay out of its sessions (VAULT.md, "The key swap"). The session holds a
# placeholder, and this machine's vault puts the real key into an outgoing HTTPS request: only in the Authorization
# header, and only for that key's own site. Two processes do it, as two OS users:
#
#   the broker (above, the vault user)   keeps the list of placeholders (Swaps), and gives the swap proxy the header
#                                        value of one placeholder, for one OS user and one host, after the hub said
#                                        that the grant is live now;
#   the swap proxy (`vault.py swap`)     a user of its own, which reads neither the store nor its key. A session's
#                                        HTTPS_PROXY names it. It passes a connection to any other host as it is,
#                                        unread. For a key's site it ends TLS with a certificate of a CA of its own
#                                        that is limited to that host name, reads the head of one request, replaces
#                                        the placeholders in its Authorization header, and sends it on a TLS
#                                        connection of its own to the site.
#
# Root switches it on for a machine with one part of the broker's own configuration, "swap" (SWAP_KEYS,
# hubsetup.swap_install). With that part, a key that the hub names with a site reaches a session as a placeholder or
# not at all, never as the key. Without it, nothing here runs, and each key is a variable as before. No agent can
# change the configuration. A release cannot switch it off either: a vault.py from before the swap refuses a
# configuration with a part that it does not know, so it does not start, and the machine keeps the program that was
# serving (hubsetup.vault_program_script).
#
# The proxy reads hostile bytes, so it is small and it reads strictly. It reads the CONNECT line, and for a key's
# site one request head: no byte of an answer, and no byte of a request after its head. A fault in it does not open
# the store: what it can get is the keys that swap on this machine, and the traffic to their sites.
SWAP_KEY = "swap"                           # optional, in the broker's configuration: this machine swaps keys
SWAP_USER = "founderizer-swap"              # the proxy's own user. Not a fleet-* name: the service user can change
                                            # each fleet-* user (fleet-agent-user)
SWAP_KEYS = {"user", "vault", "port", "openssl"}    # the proxy's OS user, the broker's, the proxy's port, a program
SWAP_SOCKET = "swap.sock"                   # the broker's socket for the proxy, beside its own
SWAP_STATE = "/var/lib/fleet-vault-swap"    # the keys of the proxy's CAs and certificates: the proxy's user alone
SWAP_RUN = "/run/fleet-vault-swap"          # the public certificate of each site's CA, <host>.pem, for the sessions
SWAPS = "swaps.json"                        # the broker's list of placeholders, in its state folder
PLACEHOLDER = re.compile(r"vaultswap_[0-9a-f]{40}")
PLACEHOLDER_BYTES = re.compile(rb"vaultswap_[0-9a-f]{40}")
SWAP_TOKEN = re.compile(r"[0-9a-f]{64}")    # the hub's token of one agent and key: it asks "is this grant live?" only
# The one form in which a key goes into the Authorization header, which the key's catalog entry names (the hub
# gives it with the site): the key is the whole credential, and never text beside other text of the agent's choice.
SWAP_FORMS = ("bearer", "token", "basic-user", "basic-password")
# A site's host: a DNS name of small letters, digits, dots and hyphens, at most 240 characters and never an IP
# address, so that it is safe in a file name and in openssl's files, and so that its CA has one kind of limit.
SWAP_HOST = re.compile(r"(?=.{1,240}$)(?![0-9.]+$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                       r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
SWAP_BEARER = re.compile(rb"((?i:bearer|token)) (vaultswap_[0-9a-f]{40})")
SWAP_BASIC = re.compile(rb"(?:([^:]*):(vaultswap_[0-9a-f]{40})|(vaultswap_[0-9a-f]{40}):(.*))", re.S)
SWAP_LOW_PORTS = "/proc/sys/net/ipv4/ip_unprivileged_port_start"    # the first port that each user can listen on
SWAP_HEAD = 65536                           # bytes of one request head
SWAP_HEADERS = 100
SWAP_PATIENCE = 15                          # seconds for a CONNECT line, a TLS handshake, a request head, a connect
SWAP_PER_USER = 256                         # connections of one OS user at one time. No limit for all users
                                            # together: some agents must not hold each place of the others
SWAP_CONNECT = re.compile(rb"CONNECT (?:\[([0-9A-Fa-f:.]{2,45})\]|([A-Za-z0-9.-]{1,253})):([0-9]{1,5}) HTTP/1\.[01]")
SWAP_REQUEST = re.compile(rb"([A-Z]{1,16}) (/[!-~]{0,8000}|\*) HTTP/1\.1")
SWAP_HEADER = re.compile(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}):[ \t]*"
                         rb"((?:[!-~\x80-\xff](?:[ \t!-~\x80-\xff]*[!-~\x80-\xff])?)?)[ \t]*")
# One request for each connection to a key's site, so these headers of the client are not passed: the proxy says
# `Connection: close` itself, and no upgrade to another protocol goes through it.
SWAP_NOT_PASSED = (b"connection", b"proxy-connection", b"proxy-authorization", b"keep-alive", b"upgrade")
# No key goes into a request with one of these methods: a server answers TRACE (and the older TRACK) with the request
# that it got, headers and all, and many servers have it on.
SWAP_NO_KEY_METHODS = (b"TRACE", b"TRACK", b"CONNECT")
SWAP_ASKS = 8                               # questions for a key that one OS user has open at the broker at one time
SWAP_CANDIDATE = 60                         # seconds in which the proxy of a new program says that it serves
SWAP_SERVES = b"serves\n"                   # that word, on the pipe of a hand-over
SWAP_GRACE = 5                              # seconds that the old process lives at least after that word: systemd must
                                            # know the new main process before the old one ends, or it starts the service again
SWAP_NO_UNIT = ("this process has no word for systemd (no NOTIFY_SOCKET), so it cannot give way: after the root step "
                "`hubsetup.py vault --swap`, `systemctl restart fleet-vault-swap` starts the proxy under the unit that "
                "lets it")
SWAP_MARK = b"X-Founderizer-Vault: key-swap\r\n"
# The proxy's own answers. Each one is a sentence for the agent's program, and none has a value.
SWAP_ONLY_CONNECT = "The vault's proxy takes only CONNECT for HTTPS. Plain HTTP is refused."
SWAP_BAD_TARGET = "The CONNECT line names no host and port that the vault's proxy can reach."
SWAP_UNREACHABLE = "The vault's proxy could not reach this host."
SWAP_BAD_SITE = ("The vault's proxy could not reach this key's site with a certificate that is the site's own. "
                 "Nothing was sent.")
SWAP_BAD_HEAD = "The vault's proxy does not pass this request to a key's site: {why}. Nothing was sent."
SWAP_PLACE = ("The vault puts a key only into the Authorization header of a request to the key's own site, as the "
              "whole credential and in the one form of that key: `Bearer <placeholder>`, `token <placeholder>`, or "
              "Basic with the placeholder as the user name or as the password. This request has a placeholder in "
              "another place or form. Nothing was sent.")
SWAP_REFUSED = ("The vault did not put the key into this request: this placeholder is not a key that this agent holds "
                "for this host now. Nothing was sent. If the work needs the key, ask your requester.")
SWAP_NO_HUB = ("The vault did not put the key into this request: the hub did not confirm the grant now. Nothing was "
               "sent. Try again.")
SWAP_NO_VAULT = "The vault's proxy got no answer from this machine's vault. Nothing was sent. Try again."
SWAP_BUSY = "The vault's proxy has too many connections of this user. Close some, and try again."
SWAP_CALL = ("On this machine the vault sends this key only to the key's own site, in the Authorization header and in "
             "the key's own form, as its proxy does. Nothing was sent.")
SWAP_ROOM = 256                             # questions of the proxy that the broker answers at one time


def swap_shape(part):
    """True for the part "swap" of a broker's configuration in its form: {"user", "vault", "port", "openssl"}.
    load_config asks this, so that a configuration whose part is not in this form stops the broker as each other
    wrong key does. What a machine can lose later (a user, a program) is read by swap_part, and stops only the swap."""
    return isinstance(part, dict) and set(part) == SWAP_KEYS and all(
        isinstance(part[k], str) and part[k] for k in ("user", "vault", "openssl")) \
        and os.path.isabs(part["openssl"]) and type(part["port"]) is int and 0 < part["port"] < 65536


def swap_part(conf):
    """The part "swap" of this configuration as the broker and the proxy use it: its own fields, with "uid" and
    "vault_uid" (the user IDs of the proxy and of the broker), "group" (the group of this machine's agent users) and
    "broker" (the broker's socket for the proxy). Refused when the machine does not have what it names: the proxy's
    own user, which is not root, not the broker's user and no agent user; the broker's user; the group; and an
    openssl program that no agent can change."""
    part, group = conf[SWAP_KEY], conf.get("worker_group")
    try:
        who, keeper = pwd.getpwnam(part["user"]), pwd.getpwnam(part["vault"])
        members = grp.getgrnam(group) if isinstance(group, str) else None
    except KeyError:
        who = keeper = members = None
    if not (who and keeper and members) or who.pw_uid in (0, keeper.pw_uid) or who.pw_name in members.gr_mem \
            or who.pw_gid == members.gr_gid:
        raise Refused("the key swap needs the proxy's own OS user (not root, not the vault's user and no agent "
                      "user), the vault's user, and worker_group, the group of this machine's agent users")
    try:
        unchangeable(part["openssl"], "The openssl program")       # no agent can put another program in its place
    except (SystemExit, OSError) as e:
        raise Refused(str(e) or "the openssl program is not there") from None
    return dict(part, uid=who.pw_uid, vault_uid=keeper.pw_uid, group=group,
                broker=os.path.join(os.path.dirname(conf["socket"]), SWAP_SOCKET))


def swap_site(value):
    """(host, port) of a key's site as the hub names it, an https address, or None: the host in small letters, a
    plain ASCII DNS name and no IP address; the port of the address, or 443."""
    try:
        parts = urllib.parse.urlsplit(value) if isinstance(value, str) and len(value) <= 300 else None
        host, port = (parts.hostname or "", parts.port) if parts else ("", None)
    except ValueError:
        return None
    if not parts or parts.scheme != "https" or parts.username is not None or parts.password is not None:
        return None
    host = host[:-1] if host.endswith(".") else host
    return (host, port or 443) if SWAP_HOST.fullmatch(host) else None


def swap_origin(host, port):
    """host[:port] as a session reads it: the port only when it is not 443."""
    return host if port == 443 else f"{host}:{port}"


def swap_user(uid):
    """The name of this OS user now, or None. An entry of the list of placeholders is for an OS user by number and by
    name: when a user is removed and a new user gets its number, the first user's entries open nothing for it."""
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, TypeError, OverflowError):
        return None


class Swaps:
    """The broker's list of placeholders, in its private state folder: {placeholder: {uid, user, agent, login, host,
    port, form, token}}, with "off": true in an entry that is switched off. One placeholder for one OS user, agent and
    key of this machine: it is the same in each session of that agent. It is kept on disk, so that a session that runs
    goes on after a restart of the broker. No entry has a value, and an entry opens nothing by itself: each use asks
    the hub (swap_value). An entry that is off opens no connection and gives no value (only); it keeps its name, so a
    key that the hub names again gets the same placeholder (place)."""
    FIELDS = {"uid", "user", "agent", "login", "host", "port", "form", "token"}
    LIMIT = 4 * 1024 * 1024

    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        info = os.stat(os.path.dirname(os.path.abspath(path)))
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refused("the vault's state folder must belong to the vault user and have mode 700")
        try:
            self.entries = self.load()
        except (OSError, ValueError):
            raise Refused("the vault's list of placeholders cannot be read") from None

    def load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return {}
        with os.fdopen(fd, "rb") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 \
                    or info.st_size > self.LIMIT:
                raise ValueError()
            entries = json.loads(f.read().decode())
        if not isinstance(entries, dict) or not all(
                isinstance(p, str) and PLACEHOLDER.fullmatch(p) and isinstance(e, dict)
                and set(e) - {"off"} == self.FIELDS and e.get("off", True) is True
                and type(e["uid"]) is int and isinstance(e["user"], str) and 0 < len(e["user"]) <= 64
                and isinstance(e["agent"], str) and AGENT_NAME.fullmatch(e["agent"])
                and isinstance(e["login"], str) and SECRET_REF.fullmatch(e["login"]) and isinstance(e["host"], str)
                and SWAP_HOST.fullmatch(e["host"]) and type(e["port"]) is int and 0 < e["port"] < 65536
                and e["form"] in SWAP_FORMS and isinstance(e["token"], str) and SWAP_TOKEN.fullmatch(e["token"])
                for p, e in entries.items()):
            raise ValueError()
        return entries

    def keep(self, entries):
        """Write the list whole: a new file of mode 600, made complete beside the old one and then put in its place."""
        temp = self.path + ".new"
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(entries, sort_keys=True).encode())
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, self.path)
        except OSError:
            raise Refused("the vault could not keep its list of placeholders") from None
        self.entries = entries

    def place(self, uid, agent, login, host, port, form, token):
        """The placeholder of this OS user, agent and key, with the site, the form and the token that the hub names
        now. A new one is made only when the list has none for them; one that was switched off is on again."""
        user = swap_user(uid)
        if not user:
            raise Refused("the vault does not know the OS user that asks for this key")
        entry = {"uid": uid, "user": user, "agent": agent, "login": login, "host": host, "port": port, "form": form,
                 "token": token}
        with self.lock:
            for name, old in self.entries.items():
                if (old["uid"], old["agent"], old["login"]) == (uid, agent, login):
                    if old != entry:
                        self.keep(dict(self.entries, **{name: entry}))
                    return name
            name = "vaultswap_" + secrets.token_hex(20)
            self.keep(dict(self.entries, **{name: entry}))
            return name

    def only(self, uid, agent, logins):
        """Switch off each placeholder of this OS user that is not for one of `logins`: the keys that the hub names
        with a site for this agent now. Without this, the proxy would go on opening the connections of that user to
        the site of a key that it reads no more, with a certificate that its new sessions do not trust. An entry of
        another agent name is switched off too: an OS user has one agent, so such an entry is from before the agent
        got a new name. An entry of this user number with another user name is removed: it is of a user that is
        gone, and nothing can switch it on again. (Nothing is removed while the name of this user number cannot be
        read.)"""
        user = swap_user(uid)
        with self.lock:
            kept = {name: e for name, e in self.entries.items() if e["uid"] != uid or not user or e["user"] == user}
            off = {name for name, e in kept.items()
                   if e["uid"] == uid and not e.get("off") and (e["agent"] != agent or e["login"] not in logins)}
            if off or len(kept) != len(self.entries):
                self.keep({name: dict(e, off=True) if name in off else e for name, e in kept.items()})

    def site(self, uid, host, port):
        """True when this host and port are the site of a placeholder of this OS user that is not switched off."""
        user = swap_user(uid)
        with self.lock:
            return any((e["uid"], e["user"], e["host"], e["port"]) == (uid, user, host, port) and not e.get("off")
                       for e in self.entries.values())

    def get(self, name):
        with self.lock:
            entry = self.entries.get(name)
            return dict(entry) if entry else None


def with_swaps(conf):
    """The configuration of a broker that swaps keys: `_swap`, its part "swap" as swap_part reads it, and `_swaps`,
    the list of placeholders. A configuration without the part comes back as it is: each key is given as before.
    When the machine does not have what the part names, or the list cannot be read, `_swap` is {} and `_swaps` is
    not there: the broker serves each other operation, and a key that the hub names with a site is not given (read)."""
    if SWAP_KEY not in conf:
        return conf
    try:
        swap = swap_part(conf)
        if swap["vault_uid"] != os.getuid():
            raise Refused("the part swap names another vault user than the one that this broker runs as")
        return dict(conf, _swap=swap, _swaps=Swaps(os.path.join(state_folder(conf), SWAPS)))
    except Refused as e:
        log(f"no key swap: {e}")
        return dict(conf, _swap={})


def swap_value(conf, uid, host, port, name, form):
    """The header value of this placeholder, for the swap proxy: it must be a placeholder of this OS user (by number
    and by name) and of this host that is not switched off, the proxy must have found it in the form of that key, and
    the hub must say now that its agent still reads its key at this site. A hub that does not answer is a refusal. Then the value is read from the store. No lock of
    the broker is held here: the hub call must not wait for another operation, and the store is one file that a save
    puts in place whole. A refusal has one fixed code and no value: "refused" or "hub"."""
    entry = conf["_swaps"].get(name) if isinstance(name, str) and PLACEHOLDER.fullmatch(name) else None
    if not entry or entry.get("off") or (entry["uid"], entry["user"], entry["host"], entry["port"], entry["form"]) != (
            uid, swap_user(uid), host, port, form):
        return {"ok": False, "code": "refused"}
    try:        # with no agent key: the token is what the hub knows this question by
        code, data = hub(dict(conf, agent=entry["agent"], agent_key=None), "POST",
                         f"/helper/vault/{entry['agent']}/swap",
                         {"login": entry["login"], "site": "https://" + swap_origin(host, port), "form": form,
                          "swap": entry["token"]})
    except Refused:
        return {"ok": False, "code": "hub"}
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("login") != entry["login"]:
        return {"ok": False, "code": "refused" if code in (403, 404, 409) else "hub"}
    try:
        value = check_value(LocalStore(conf).item(SECRET_REF.fullmatch(entry["login"]).group(1))["value"])["password"]
    except Refused:
        # Also when the store has the item no more: at the end of the last grant of a machine the hub takes the value
        # back (withdraw), and a grant that is given again brings it back (deposit). In between, there is no key.
        return {"ok": False, "code": "refused"}
    if re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value):      # a line end or another control character: no header value
        return {"ok": False, "code": "refused"}
    if form == "basic-user" and ":" in value:       # a site cuts the user name at the first colon: not the whole key
        return {"ok": False, "code": "refused"}
    return {"ok": True, "value": value}


def swap_call(conf, confirmed, call, login):
    """May this broker send this call_api request with this key? On a machine that swaps keys, a key that the hub
    names with a site goes into a request only as the proxy puts it there: to that site, in the Authorization header,
    and in the key's own form. So call_api is no second road with looser rules (a header of the agent's choice, the
    address of the saved item). `bearer` is call_api's bearer, and `basic-password` its basic, whose user name is the
    saved item's own. A key of another form goes through the proxy only. True on a machine that does not swap, and for
    a key that the hub names no site for: as before."""
    if "_swap" not in conf or confirmed.get("site") is None:
        return True
    site, where = swap_site(confirmed.get("site")), origin(login.get("url") or "")
    return bool(site and where and where[2] == "https://" + swap_origin(*site)
                and {"bearer": "bearer", "basic-password": "basic"}.get(confirmed.get("form")) == call["auth"])


def swap_handle(conf, line):
    """One request of the swap proxy on the broker's second socket: site (is this host a site of a placeholder of
    this OS user?) and swap (the header value of one placeholder). The caller is the proxy's user, which
    Broker.swap_served read from the kernel before this."""
    try:
        req = json.loads(line)
    except ValueError:
        raise Refused("send one JSON request line") from None
    if not isinstance(req, dict):
        raise Refused("send one JSON request line")
    uid, host, port = req.get("uid"), req.get("host"), req.get("port")
    if not (type(uid) is int and uid > 0 and isinstance(host, str) and SWAP_HOST.fullmatch(host)
            and type(port) is int and 0 < port < 65536):
        raise Refused("a swap request needs uid, host and port")
    if req.get("op") == "site":
        return {"ok": True, "site": conf["_swaps"].site(uid, host, port)}
    if req.get("op") == "swap":
        return swap_value(conf, uid, host, port, req.get("name"), req.get("form"))
    raise Refused("unknown operation")


# ---- the swap proxy's own code: nothing below reads the store, and the proxy's user cannot

# The kernel's tables of TCP sockets, and whether a row has an IPv4 address in its form of IPv6.
SWAP_TABLES = (("/proc/net/tcp", False), ("/proc/net/tcp6", True))


def swap_peer(conn):
    """The user ID that owns the other end of this TCP connection on this machine, from the kernel's table of sockets,
    or None. The row must have exactly this connection's two addresses and ports: while this process holds the
    connection, no other socket has them. A program with one socket for both IP versions (.NET, Java) is in the IPv6
    table, with the IPv4 address in its mapped form."""
    try:
        (peer_ip, peer_port), (own_ip, own_port) = conn.getpeername()[:2], conn.getsockname()[:2]
        one, two = socket.inet_aton(peer_ip), socket.inet_aton(own_ip)
    except (OSError, ValueError):
        return None

    def form(raw, port, mapped):
        four = "%08X" % int.from_bytes(raw, sys.byteorder)
        return ("0000000000000000" + ("FFFF0000" if sys.byteorder == "little" else "0000FFFF") + four
                if mapped else four) + ":%04X" % port
    for table, mapped in SWAP_TABLES:
        local, remote = form(one, peer_port, mapped), form(two, own_port, mapped)
        try:
            with open(table, encoding="ascii") as f:
                for row in f:
                    parts = row.split()
                    if len(parts) > 7 and parts[1] == local and parts[2] == remote and parts[7].isdigit():
                        return int(parts[7])
        except OSError:
            continue
    return None


def swap_head(sock, limit):
    """(the bytes before the first empty line, the bytes that came after it), or (None, b"") for a head that is longer
    than `limit` or that ends early."""
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > limit:
            return None, b""
        chunk = sock.recv(8192)
        if not chunk:
            return None, b""
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return (head, rest) if len(head) <= limit else (None, b"")


def swap_request(head, host, port):
    """(method, target, [(name, value)]) of one request head for this host, read strictly, or the words of why it is
    not passed. Strict, so that the line that this proxy reads as the Authorization header is that header for the site
    too, and not a part of another header that the site gives back: each line ends with CR LF and has no other CR, LF
    or NUL; the request line is `METHOD /path HTTP/1.1`; a header is `name: value` with no space before the colon and
    no fold; and exactly one Host header, which is this host."""
    lines = head.split(b"\r\n")
    if any(b"\r" in x or b"\n" in x or b"\0" in x for x in lines):
        return "a line does not end with CR LF"
    found = SWAP_REQUEST.fullmatch(lines[0])
    if not found:
        return "its first line is not `METHOD /path HTTP/1.1`"
    headers = []
    for line in lines[1:]:
        h = SWAP_HEADER.fullmatch(line)
        if not h:
            return "a header line is not `name: value`"
        headers.append((h.group(1), h.group(2)))
    if len(headers) > SWAP_HEADERS:
        return "it has too many headers"
    hosts = [v.lower() for n, v in headers if n.lower() == b"host"]
    own = [b"%s:%d" % (host.encode(), port)] + ([host.encode()] if port == 443 else [])
    if len(hosts) != 1 or hosts[0] not in own:
        return "its Host header is not this host"
    return found.group(1), found.group(2), headers


def swap_basic(value):
    """The text of Basic credentials in an Authorization value, or None for another form."""
    if value[:6].lower() != b"basic ":
        return None
    try:
        return base64.b64decode(value[6:].strip(), validate=True)
    except ValueError:
        return None


def swap_found(target, headers):
    """(the placeholder that this request head asks a key for, or None; the form in which it stands, one of
    SWAP_FORMS; True when the head has a placeholder in a place or a form where no key goes). A key goes into the one
    Authorization header only, and as the whole credential: `Bearer <placeholder>`, `token <placeholder>`, or Basic
    credentials that are exactly `<placeholder>:<text>` (basic-user) or `<text>:<placeholder>` (basic-password). The
    broker gives the value only for the one form of that key (swap_value): with other text beside the placeholder, or
    with the key on the wrong side of a Basic credential, an agent could make the key a refused credential on purpose,
    and a site that writes one into its error would give it back. The request line, each other header, a header name
    and a second Authorization header are no place for one."""
    grants = [v for n, v in headers if n.lower() == b"authorization"]
    elsewhere = bool(PLACEHOLDER_BYTES.search(target)) or any(
        PLACEHOLDER_BYTES.search(n) or (n.lower() != b"authorization" and PLACEHOLDER_BYTES.search(v))
        for n, v in headers)
    found = []
    for value in grants:
        plain = swap_basic(value)
        word = SWAP_BEARER.fullmatch(value)
        basic = SWAP_BASIC.fullmatch(plain) if plain is not None else None
        if word:
            found.append((word.group(2).decode(), word.group(1).decode().lower()))
        elif basic and len(PLACEHOLDER_BYTES.findall(plain)) == 1:
            found.append((basic.group(3).decode(), "basic-user") if basic.group(3) else
                         (basic.group(2).decode(), "basic-password"))
        elif PLACEHOLDER_BYTES.search(value) or (plain is not None and PLACEHOLDER_BYTES.search(plain)):
            elsewhere = True
    if (found or elsewhere) and len(grants) > 1:
        elsewhere = True
    name, form = found[0] if len(found) == 1 else (None, None)
    return name, form, elsewhere


def swap_put(headers, name, value):
    """The headers with the placeholder `name` of the Authorization header replaced by `value`, in the form that
    swap_found accepted."""
    old, new = name.encode(), value.encode()
    out = []
    for header, text in headers:
        if header.lower() == b"authorization":
            plain = swap_basic(text)
            text = b"Basic " + base64.b64encode(plain.replace(old, new)) if plain is not None else text.replace(old, new)
        out.append((header, text))
    return out


def swap_relay(source, target):
    """Pass the bytes of one direction until its end, unread, then say the end to the other side."""
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except (OSError, ValueError):
        pass
    try:
        target.shutdown(socket.SHUT_WR)
    except (OSError, ValueError):
        pass


def swap_both(client, site, first=b""):
    """Pass the bytes of both directions until both ended. first: bytes of the client that came with its request
    head."""
    def up():
        try:
            if first:
                site.sendall(first)
        except (OSError, ValueError):
            return
        swap_relay(client, site)
    back = threading.Thread(target=up, daemon=True)
    back.start()
    swap_relay(site, client)
    for sock in (client, site):         # the answer ended: the other direction ends with it
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass
    back.join()


def swap_say(sock, status, text):
    """One answer of the proxy's own: a status, one sentence as JSON, and the header that says who answers."""
    body = (json.dumps({"error": text}) + "\n").encode()
    try:
        sock.sendall(b"HTTP/1.1 " + status.encode() + b"\r\nContent-Type: application/json\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\nConnection: close\r\n" + SWAP_MARK + b"\r\n" + body)
    except (OSError, ValueError):
        pass


def swap_reach(host, port):
    """A TCP connection to this host and port, or None."""
    try:
        sock = socket.create_connection((host, port), timeout=SWAP_PATIENCE)
    except (OSError, UnicodeError):
        return None
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return sock


class SwapAuthority:
    """The proxy's certificates. For each host that is a key's site: one CA that critical X.509 name constraints limit
    to that one DNS name (permitted: the name; excluded: each name under it, and each IPv4 and IPv6 address), and that
    host's certificate, which the CA signs. A session trusts only the CAs of its own keys' sites, so nothing here can
    speak for another host to it. The openssl program makes them: the standard library makes no certificate. The keys
    are in the proxy's state folder, which only its user reads. The public certificate of each CA goes to
    `public`/<host>.pem, where a session's start reads it. A host name has only small letters, digits, dots and
    hyphens (SWAP_HOST), so it is safe in a file name and in openssl's files. The same commands run with OpenSSL 3
    and with LibreSSL."""
    DAYS, LEAF_DAYS, AGAIN = 3650, 90, 30 * 86400

    def __init__(self, folder, public, openssl):
        self.folder, self.public, self.openssl = folder, public, openssl
        self.lock, self.made, self.held = threading.Lock(), {}, None
        self.leaf_key = os.path.join(folder, "leaf.key")
        if not os.path.exists(self.leaf_key):
            self.run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.leaf_key)

    def run(self, *args):
        r = subprocess.run([self.openssl, *args], capture_output=True, timeout=60, cwd=self.folder,
                           env={"PATH": "/usr/bin:/bin"})
        if r.returncode != 0:
            raise OSError("openssl " + args[0] + " failed")

    def authority(self, host):
        """(the key, the certificate) of this host's own CA, made at the first use and kept."""
        key, cert, conf = (os.path.join(self.folder, f"{host}.ca.{end}") for end in ("key", "pem", "cnf"))
        if not (os.path.exists(key) and os.path.exists(cert)):
            with open(conf, "w", encoding="ascii") as f:
                f.write("[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\n"
                        f"CN=Founderizer key swap, {host[:40]}\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"
                        "keyUsage=critical,keyCertSign\nsubjectKeyIdentifier=hash\n"
                        f"nameConstraints=critical,permitted;DNS:{host},excluded;DNS:.{host},"
                        "excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0\n")
            self.run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key + ".new")
            self.run("req", "-x509", "-new", "-key", key + ".new", "-sha256", "-days", str(self.DAYS), "-config", conf,
                     "-out", cert + ".new")
            os.replace(key + ".new", key)
            os.replace(cert + ".new", cert)
        return key, cert

    def context(self, host):
        """The TLS server context for this host name: its certificate, made at the first use in this process and
        again when it is 30 days old. HTTP/1.1 only. The public certificate of its CA is in place before this
        returns."""
        with self.lock:
            have = self.made.get(host)
            if have and time.time() - have[0] < self.AGAIN:
                return have[1]
            # Two processes of the proxy run for as long as the old one has connections (a hand-over to a new
            # program): one at a time makes the files of a site. The lock ends with this process.
            if self.held is None:
                self.held = open(os.path.join(self.folder, "making"), "a")
            fcntl.flock(self.held, fcntl.LOCK_EX)
            try:
                return self.context_made(host)
            finally:
                fcntl.flock(self.held, fcntl.LOCK_UN)

    def context_made(self, host):
        """context, with this process's lock and the lock between processes held."""
        key, cert = self.authority(host)
        ext, csr, leaf = (os.path.join(self.folder, f"{host}.leaf.{end}") for end in ("cnf", "csr", "pem"))
        with open(ext, "w", encoding="ascii") as f:
            # the two key identifiers by name: a client that checks strictly asks for them, and an openssl
            # before 3.2 does not add them by itself
            f.write(f"subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\n"
                    "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
                    "authorityKeyIdentifier=keyid:always\n")
        self.run("req", "-new", "-key", self.leaf_key, "-subj", "/CN=Founderizer key swap", "-out", csr)
        self.run("x509", "-req", "-in", csr, "-CA", cert, "-CAkey", key, "-set_serial",
                 "0x" + secrets.token_hex(16), "-days", str(self.LEAF_DAYS), "-sha256", "-extfile", ext, "-out", leaf)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(leaf, self.leaf_key)
        ctx.set_alpn_protocols(["http/1.1"])
        with open(cert, "rb") as f:
            text = f.read()
        shown = os.path.join(self.public, host + ".pem")
        try:
            with open(shown, "rb") as f:
                same = f.read() == text
        except OSError:
            same = False
        if not same:                # readable by each user: it is the public half
            with open(shown + ".new", "wb") as f:
                f.write(text)
            os.chmod(shown + ".new", 0o644)
            os.replace(shown + ".new", shown)
        self.made[host] = (time.time(), ctx)
        return ctx


def swap_ask(swap, request):
    """One question to the broker on its socket for the proxy: the answer, or None when the broker gives none. The
    other end must be the vault's own user, so that no other program answers in its place."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            s.connect(swap["broker"])
            if peer_uid(s) != swap["vault_uid"]:
                return None
            s.sendall((json.dumps(request) + "\n").encode())
            data = b""
            while not data.endswith(b"\n") and len(data) < 65536:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        reply = json.loads(data)
    except (OSError, ValueError):
        return None
    return reply if isinstance(reply, dict) else None


class SwapProxy:
    """The swap proxy: one listener on 127.0.0.1, and two threads for each connection.

    swap: the part "swap" of the configuration (swap_part). authority: a SwapAuthority. ask: one question to the
    broker, a dict in and a dict or None out (swap_ask). site: the TLS client context for the connection to a key's
    site, which checks the site's certificate against the system's CAs. peer: the OS user of a connection
    (swap_peer). reach: a connection to a host (swap_reach). A test gives its own of the last four, and a port."""
    def __init__(self, swap, authority, ask=None, site=None, peer=swap_peer, reach=swap_reach, port=None, sock=None,
                 program=None, spawn=None, parent=None):
        """sock: a listener that another process of the proxy made (a hand-over), in the place of a new one.
        program: the SHA-256 of the program file that this process runs. spawn(program, sock): start the installed
        program as the process that takes over (swap_candidate); it gives that process when it serves, None when it
        is not the time, else the reason as text. Without the last two, this process never gives way. parent: the
        process that this one took over from, or None."""
        self.swap, self.authority, self.peer, self.reach = swap, authority, peer, reach
        self.asked = ask or (lambda request: swap_ask(swap, request))
        self.site = site or ssl.create_default_context()
        self.site.set_alpn_protocols(["http/1.1"])
        self.lock, self.open, self.asking = threading.Lock(), {}, {}
        self.program, self.spawn, self.parent = program, spawn, parent
        # each connection of this process: False while it waits, True when it passes bytes, None when this process
        # closed it at a hand-over
        self.conns = {}
        self.tls = {}                           # and the TLS socket that took it over, for a key's site
        self.ending, self.heir = False, None    # a new process serves, and that process
        self.trying, self.failed = False, None  # a candidate runs; (the program that failed, its tries, answers to skip)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", swap["port"] if port is None else port))
            sock.listen(128)
        self.sock = sock
        self.port = self.sock.getsockname()[1]

    def ask(self, request):
        """One question to the broker. Its answer also says which program the broker runs: when that is not this
        process's own, the installed program gets its try to take over (consider)."""
        said = self.asked(request)
        if said and self.program and said.get("program") != self.program:
            self.consider(said.get("program"))
        return said

    def consider(self, program):
        """The broker runs another program than this process. Start that program as a candidate: one at a time, and
        never from a process that ends. A program that failed gets its next try only after more answers of the broker
        (4, then 16, 64, 256 and then each 1024): a fault of one moment does not keep the old program for ever, and
        a fault that stays does not start a process at each connection."""
        if not (self.spawn and isinstance(program, str) and re.fullmatch(r"[0-9a-f]{64}", program)):
            return
        with self.lock:
            if self.ending or self.trying:
                return
            if self.failed and self.failed[0] == program and self.failed[2] > 0:
                self.failed = (program, self.failed[1], self.failed[2] - 1)
                return
            self.trying = True
        try:
            threading.Thread(target=self.candidate, args=(program,), daemon=True).start()
        except RuntimeError:
            with self.lock:
                self.trying = False

    def candidate(self, program):
        """Let the installed program take over. When it serves, this process takes no new connection and ends with
        the connections that it has (serve). When it does not, nothing changes here: this process goes on with the
        program that it runs."""
        try:
            taken = self.spawn(program, self.sock)
        except Exception as e:              # never a detail
            taken = f"the try failed ({type(e).__name__})"
        with self.lock:
            self.trying = False
            if taken is None:
                return                      # not the time: the installed file is not what the broker runs
            if isinstance(taken, str):
                tries = self.failed[1] + 1 if self.failed and self.failed[0] == program else 1
                self.failed = (program, tries, min(4 ** tries, 1024))
            else:
                self.heir, self.ending = taken, True
        if isinstance(taken, str):
            log(f"swap: the proxy of the new vault program did not start ({taken}): this proxy goes on with the "
                f"program that it runs, and tries that program again later (try {tries})")
            return
        log("swap: the proxy of a new vault program serves now")
        # At most one old process: the one that this process took over from ends now, with what it still holds.
        if self.parent and self.parent > 1 and os.getppid() == self.parent:
            try:
                os.kill(self.parent, signal.SIGTERM)
            except OSError:
                pass

    def reads_users(self):
        """True when this process reads the OS user of a connection on this machine: its own, for a connection to a
        listener of its own. A machine where it cannot (a /proc that it does not read) must not serve, because then
        it knows no caller. Not on the proxy's own listener: in a hand-over another process accepts there too."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as own:
                own.bind(("127.0.0.1", 0))
                own.listen(8)
                own.settimeout(5)
                with socket.create_connection(own.getsockname(), timeout=5) as client:
                    for _ in range(8):      # another program of this machine can connect here too: only this one counts
                        conn, _ = own.accept()
                        with conn:
                            if conn.getpeername() == client.getsockname():
                                return self.peer(conn) == os.getuid()
        except OSError:
            pass
        return False

    def serve(self):
        """Accept until the listener closes, or until a new process serves (ending). Then this process takes no new
        connection, and this returns when its last connection ended (gives_way)."""
        try:
            self.sock.settimeout(1)     # a look at `ending` each second: for that second both processes accept
        except OSError:
            return                      # closed
        while not self.ending:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.sock.fileno() < 0:
                    return              # closed
                time.sleep(0.2)         # no free file or no memory now: no new connection, and the proxy goes on
                continue
            conn.settimeout(SWAP_PATIENCE)
            with self.lock:
                self.conns[conn] = False
            try:
                threading.Thread(target=self.served, args=(conn,), daemon=True).start()
            except RuntimeError:        # no new thread now: this connection is not served
                conn.close()
                self.ended(conn)
        try:
            self.sock.close()           # this process's copy: the new process has its own
        except OSError:
            pass
        self.gives_way()

    def gives_way(self):
        """The end of a process that a new one took over from. It goes on with each connection that passes bytes, to
        that connection's own end. A connection that did not get that far in SWAP_PATIENCE seconds is closed: the
        old program does no new work for it, and its thread sends nothing to a site after that (passes). This
        returns after the last connection, and not before SWAP_GRACE seconds: systemd must know the new main process
        first, or it would start the service again.

        The new process is this one's child, so systemd does not see its end while this process lives. When it
        ends with a fault, this process ends too (fails): with no process left, systemd starts the service again."""
        with self.lock:
            has = len(self.conns)
        log(f"swap: this process takes no new connection, and ends with the {has} that it has")
        since = time.monotonic()
        while True:
            code = self.heir.poll() if hasattr(self.heir, "poll") else None
            if code not in (None, 0):
                log(f"swap: the process that took over ended with a fault ({code}): this one ends too, so that the "
                    f"service starts again")
                return self.fails()
            waited = time.monotonic() - since
            with self.lock:
                if not self.conns and waited >= SWAP_GRACE:
                    return
                waiting = []
                if waited >= SWAP_PATIENCE:
                    # The mark is made in the lock that passes() takes: a connection is closed here or it passes
                    # bytes, never both. At each turn, not one time: a connection can get its TLS socket between
                    # two turns.
                    for conn, passes in self.conns.items():
                        if not passes:
                            self.conns[conn] = None
                            waiting.append(self.tls.get(conn, conn))
            for sock in waiting:
                try:
                    # the socket's own end, not the TLS socket's shutdown: that one takes the TLS state away from
                    # the connection's thread, which still reads it
                    socket.socket.shutdown(sock, socket.SHUT_RDWR)
                except (OSError, ValueError):
                    pass
            time.sleep(0.5)

    def fails(self):
        os._exit(1)

    def wrapped(self, conn, client):
        """This connection is to a key's site: `client` is the TLS socket that took it over."""
        with self.lock:
            if conn in self.conns:
                self.tls[conn] = client

    def passes(self, conn):
        """This connection passes bytes from now on (a tunnel, or a request to a key's site and its answer), and
        this process keeps it to its end: True. False when this process closed it at a hand-over (gives_way): its
        thread then sends nothing to a site, so no request and no key go there for a caller that hears no answer."""
        with self.lock:
            if self.conns.get(conn) is None:
                return False
            self.conns[conn] = True
            return True

    def ended(self, conn):
        """One connection of this process ended."""
        with self.lock:
            self.conns.pop(conn, None)
            self.tls.pop(conn, None)

    def close(self):
        self.sock.close()

    def agent_user(self, uid):
        """True for a user of the group of this machine's agent users, as the broker reads it (admitted)."""
        try:
            who, members = pwd.getpwuid(uid), grp.getgrnam(self.swap["group"])
        except KeyError:
            return False
        return who.pw_name in members.gr_mem or who.pw_gid == members.gr_gid

    def served(self, conn):
        uid = None
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            who = self.peer(conn)
            if who is None or not self.agent_user(who):
                return                  # no agent user of this machine: no answer
            with self.lock:
                if self.open.get(who, 0) >= SWAP_PER_USER:
                    return swap_say(conn, "503 Service Unavailable", SWAP_BUSY)
                self.open[who] = self.open.get(who, 0) + 1
                uid = who
            self.one(conn, uid)
        except (OSError, ValueError):       # a connection that ended, a TLS error: this connection only
            pass
        except Exception as e:              # never a detail of a request
            log(f"swap: error {type(e).__name__}")
        finally:
            if uid is not None:
                with self.lock:
                    self.open[uid] -= 1
                    if not self.open[uid]:
                        del self.open[uid]
            try:
                conn.close()
            except OSError:
                pass
            self.ended(conn)

    def one(self, conn, uid):
        head, rest = swap_head(conn, 8192)
        found = SWAP_CONNECT.fullmatch(head.split(b"\r\n")[0]) if head is not None else None
        if not found:
            return swap_say(conn, "405 Method Not Allowed", SWAP_ONLY_CONNECT) if head is not None else None
        literal = found.group(1) is not None            # an IPv6 address in brackets: a tunnel only
        host = (found.group(1) or found.group(2)).decode().lower()
        host, port = (host[:-1] if host.endswith(".") and not literal else host), int(found.group(3))
        if rest or not 0 < port < 65536 or not host:
            return swap_say(conn, "400 Bad Request", SWAP_BAD_TARGET)
        if not literal and SWAP_HOST.fullmatch(host):
            # No answer of the broker (it starts again): a tunnel. The site then gets the placeholder, and nothing
            # else of the session fails.
            said = self.ask({"op": "site", "uid": uid, "host": host, "port": port})
            if said and said.get("site") is True:
                return self.opened(conn, uid, host, port)
        site = self.reach(host, port)
        if site is None:
            return swap_say(conn, "502 Bad Gateway", SWAP_UNREACHABLE)
        with site:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            conn.settimeout(None)
            site.settimeout(None)
            if self.passes(conn):
                swap_both(conn, site)   # not read, and no line in the log

    def opened(self, conn, uid, host, port):
        """A connection to a key's site: TLS ends here, the head of one request is read, and the placeholder of its
        Authorization header is replaced. The request goes to the site on a TLS connection that checks the site's
        own certificate. A connection that ends before its TLS (a session's start asks for the site's CA in this way)
        ends here with no line in the log."""
        context = self.authority.context(host)          # the CA's public certificate is in place before the answer
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        # The TLS socket takes the connection over, and `conn` itself is then no socket any more: so this process
        # keeps the TLS socket too, to end the connection at a hand-over while it waits here (gives_way).
        client = context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
        self.wrapped(conn, client)
        try:
            client.do_handshake()
            head, rest = swap_head(client, SWAP_HEAD)
            if head is None:
                return swap_say(client, "431 Request Header Fields Too Large",
                                SWAP_BAD_HEAD.format(why="its head is too long, or it ended early"))
            where = swap_origin(host, port)
            request = swap_request(head, host, port)
            if isinstance(request, str):
                log(f"swap: uid {uid} to {where}: not passed ({request})")
                return swap_say(client, "400 Bad Request", SWAP_BAD_HEAD.format(why=request))
            method, target, headers = request
            name, form, elsewhere = swap_found(target, headers)
            if elsewhere:
                log(f"swap: uid {uid} to {where}: not passed (a placeholder where no key goes)")
                return swap_say(client, "400 Bad Request", SWAP_PLACE)
            if name and method in SWAP_NO_KEY_METHODS:
                log(f"swap: uid {uid} to {where}: not passed (a {method.decode()} request with a placeholder)")
                return swap_say(client, "400 Bad Request", SWAP_BAD_HEAD.format(
                    why="a server sends a " + method.decode() + " request back, so no key goes into one"))
            kept = [(n, v) for n, v in headers if n.lower() not in SWAP_NOT_PASSED] + [(b"Connection", b"close")]
            if name:
                with self.lock:         # a few questions of one user at one time: the others keep their places
                    room = self.asking.get(uid, 0) < SWAP_ASKS
                    if room:
                        self.asking[uid] = self.asking.get(uid, 0) + 1
                if not room:
                    return swap_say(client, "503 Service Unavailable", SWAP_BUSY)
                try:
                    said = self.ask({"op": "swap", "uid": uid, "host": host, "port": port, "name": name, "form": form})
                finally:
                    with self.lock:
                        self.asking[uid] -= 1
                        if not self.asking[uid]:
                            del self.asking[uid]
                value = said.get("value") if said and said.get("ok") is True else None
                if not (isinstance(value, str) and value and not re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value)):
                    code = said.get("code") if said else None
                    log(f"swap: uid {uid} to {where}: no key "
                        f"({code if code in ('refused', 'hub') else 'no answer of the vault'})")
                    if code == "refused":
                        return swap_say(client, "403 Forbidden", SWAP_REFUSED)
                    return swap_say(client, "503 Service Unavailable", SWAP_NO_HUB if code == "hub" else SWAP_NO_VAULT)
                kept = swap_put(kept, name, value)
                del value, said
            out = method + b" " + target + b" HTTP/1.1\r\n" + b"".join(n + b": " + v + b"\r\n" for n, v in kept) + b"\r\n"
            del kept
            if not self.passes(conn):   # closed at a hand-over while it waited: nothing goes to the site
                return
            raw = self.reach(host, port)
            if raw is None:
                return swap_say(client, "502 Bad Gateway", SWAP_BAD_SITE)
            with raw:
                try:
                    site = self.site.wrap_socket(raw, server_hostname=host)
                except (OSError, ValueError):
                    return swap_say(client, "502 Bad Gateway", SWAP_BAD_SITE)
                with site:
                    site.sendall(out)
                    del out
                    if name:
                        log(f"swap: uid {uid} to {where}: the key of one placeholder in a {method.decode()} request")
                    client.settimeout(None)
                    site.settimeout(None)
                    swap_both(client, site, rest)
        finally:
            try:
                client.close()
            except (OSError, ValueError):
                pass


def swap_notify(text):
    """Tell systemd about this service (sd_notify). True when the words went out. The unit has NotifyAccess=all, so
    that the process that takes over can say that it is the main process now."""
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(text.encode(), "\0" + path[1:] if path.startswith("@") else path)
    except OSError:
        return False
    return True


def swap_program():
    """The SHA-256 of this program's file as it is now, or None."""
    try:
        with open(os.path.realpath(__file__), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def swap_candidate(config, program, sock):
    """Start the installed program as the proxy that takes over from this process (SwapProxy.candidate): a child with
    the listener and one pipe. It makes each check of a normal start, tells systemd that it is the main process, and
    writes one line into the pipe. The child (a Popen) when that line came. None when the installed file is not the
    program that the broker runs (an update is in the middle): no try now. Else the reason as text, and then the
    child has ended on each path, and systemd hears again that this process is the main one.

    Under a unit without NotifyAccess (the unit of the first version) there is no hand-over: systemd would start
    the service a second time when this process ends.

    The two processes run two versions of this program, so these are a contract that a later version keeps: the
    arguments `swap --config <file> --take <listener>,<pipe>`; the word SWAP_SERVES on the pipe, and only after
    systemd has MAINPID; exit code 0 for a process that gave way and ended with its connections, and another code
    for a fault; and SIGTERM as the end of the process before (SwapProxy.candidate). A version that changes one of
    them cannot take over from an older process: that one then goes on and writes a line at each try."""
    if swap_program() != program:
        return None
    if not os.environ.get("NOTIFY_SOCKET"):
        return SWAP_NO_UNIT
    mine = theirs = child = None
    try:
        mine, theirs = os.pipe()
        child = subprocess.Popen([sys.executable, os.path.realpath(__file__), "swap", "--config", config,
                                  "--take", f"{sock.fileno()},{theirs}"],
                                 pass_fds=(sock.fileno(), theirs), stdin=subprocess.DEVNULL)
        os.close(theirs)
        theirs = None
        look = select.poll()            # not select.select: this process can have more than 1024 open files
        look.register(mine, select.POLLIN)
        ready = look.poll(SWAP_CANDIDATE * 1000)
        if ready and os.read(mine, 16) == SWAP_SERVES:
            return child
        if ready:                       # the pipe closed, or another word came: the child ends by itself in a moment
            try:
                reason = f"exit {child.wait(timeout=5)}"
            except subprocess.TimeoutExpired:
                reason = "it did not say that it serves"
        else:
            reason = f"no word in {SWAP_CANDIDATE} seconds"
    except Exception as e:              # never a detail
        reason = f"the try failed ({type(e).__name__})"
    finally:
        for end in (mine, theirs):
            if end is not None:
                try:
                    os.close(end)
                except OSError:
                    pass
    if child is not None and child.poll() is None:      # no child that could serve beside this process
        child.kill()
        child.wait()
        reason += ", and it was ended"
    if child is not None:
        swap_notify(f"MAINPID={os.getpid()}")           # the child can have said that it is the main process
    return reason


def swap_main(config, take=None):
    """`vault.py swap`: the swap proxy of this machine, as its own user. It reads the broker's configuration, which is
    root's and holds no secret, for its part "swap". take: (the listener, a pipe), two file numbers that the process
    that serves now gave this one: after each check of a normal start, this process takes over (swap_candidate)."""
    unchangeable(os.path.realpath(__file__), "The vault broker program")       # never a checkout that an agent can change
    program, parent = swap_program(), os.getppid()
    if take and not os.environ.get("NOTIFY_SOCKET"):
        raise SystemExit("The swap proxy cannot take over under this unit: systemd gave it no NOTIFY_SOCKET.")
    conf = load_config(config)
    if conf.get("central") is True or SWAP_KEY not in conf:
        raise SystemExit(f"{config} has no part swap: this machine does not swap keys.")
    try:
        swap = swap_part(conf)
    except Refused as e:
        raise SystemExit(f"The swap proxy does not start: {e}.") from None
    if os.getuid() != swap["uid"]:
        raise SystemExit(f"The swap proxy runs as {swap['user']}, and as no other user.")
    try:                    # a machine that lets each user listen on the proxy's port: an agent could take its place
        with open(SWAP_LOW_PORTS, encoding="ascii") as f:
            low = int(f.read().strip())
    except (OSError, ValueError):
        low = None
    if low is not None and low <= swap["port"]:
        raise SystemExit(f"The swap proxy does not start: on this machine each user can listen on port "
                         f"{swap['port']} (net.ipv4.ip_unprivileged_port_start is {low}), so an agent could take "
                         f"the proxy's place.")
    state, public = os.environ.get("STATE_DIRECTORY") or SWAP_STATE, os.environ.get("RUNTIME_DIRECTORY") or SWAP_RUN
    info = os.stat(state)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SystemExit("The swap proxy's state folder must belong to its user and have mode 700.")
    sock = None
    if take:                    # the listener of the process that serves now: the proxy's own, and no other socket
        try:
            sock = socket.socket(fileno=take[0])
            mine = sock.type == socket.SOCK_STREAM and sock.getsockname() == ("127.0.0.1", swap["port"])
        except OSError:
            mine = False
        try:                    # and it listens (Linux says so; a system that cannot say is no server of the fleet)
            mine = mine and sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0
        except OSError:
            pass
        if not mine:
            raise SystemExit("The swap proxy cannot take over: it did not get the proxy's listener.")
    proxy = SwapProxy(swap, SwapAuthority(state, public, swap["openssl"]), sock=sock, program=program,
                      spawn=lambda new, listener: swap_candidate(config, new, listener),
                      parent=parent if take else None)
    if not proxy.reads_users():
        raise SystemExit("The swap proxy does not start: it cannot read the user of a connection from /proc/net/tcp "
                         "on this machine, so it would know no caller.")
    if take:
        if not swap_notify(f"MAINPID={os.getpid()}\nREADY=1"):
            raise SystemExit("The swap proxy cannot take over: systemd did not take its word.")
        try:                    # the process that served takes no new connection from this line on
            os.write(take[1], SWAP_SERVES)
            os.close(take[1])
        except OSError:
            if os.getppid() == parent:      # it lives and does not listen for the word: it gave this try up
                raise SystemExit("The swap proxy does not take over: the process that serves did not take its word.") \
                    from None
            # else it has ended: this process serves alone
        log(f"swap proxy for the agents of this machine on 127.0.0.1:{proxy.port}, in the place of the process that "
            f"served before")
    else:
        swap_notify("READY=1")
        log(f"swap proxy for the agents of this machine on 127.0.0.1:{proxy.port}")
    proxy.serve()
    return 0


# The swap proxy's service (`unit --swap`): its own user, the right to its one low port and no other, and no part of
# the store. A restart of the broker does not touch it: when the broker runs a new program, the proxy lets that
# program take over as a new process, with no cut of the open connections (SwapProxy.candidate), and NotifyAccess=all
# lets that process tell systemd that it is the main process now. No ProtectProc, no ProcSubset and no
# RestrictAddressFamilies: it reads /proc/net/tcp, and it connects to any address.
SWAP_UNIT = """[Unit]
Description=Fleet vault key swap proxy (puts an API key into a request to the key's own site; it cannot read the store)
After=network-online.target fleet-vault.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
User={user}
Group={user}
ExecStart=/usr/bin/python3 {script} swap --config {config}
NotifyAccess=all
StateDirectory=fleet-vault-swap
StateDirectoryMode=0700
RuntimeDirectory=fleet-vault-swap
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
LimitCORE=0
LimitNOFILE=65536
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------- the fleet's own store: its operations

def owned_by(path, info, mode):
    """A file of the store that belongs to the vault user and that no one else can read."""
    os.chmod(path, mode)
    if os.geteuid() == 0:
        os.chown(path, info.pw_uid, info.pw_gid)


def store_init(config, user=None, keygen="age-keygen"):
    """The fleet's own store, in one operation (as root): the store key and an empty store in the broker's state
    folder, owned by the vault user and readable by no one else. **Safe to run again**: a key or a store that is
    there is kept, because a new key would leave every saved value unreadable. It reads no value and writes no
    configuration: the configuration already names both files. Returns what it made.

    For a central vault it also makes the vault's own key (age_key), to which the owner seals a new value, and keeps
    that one too when it is there. With no user named, the user is the one that the service runs as: fleet-vault, or
    founderizer-vault (CENTRAL_USER) for a central vault."""
    conf = load_config(config)          # it names the store: load_config refuses one that does not
    user = user or (CENTRAL_USER if conf.get("central") is True else "fleet-vault")
    try:
        info = pwd.getpwnam(user)
    except KeyError:
        raise SystemExit(f"There is no user {user}. Make the vault user first.") from None
    if info.pw_uid == 0 or admitted(conf, info.pw_uid):
        raise SystemExit("The store belongs to the vault user, never to root and never to a user that may ask the "
                         "broker.")
    folder, key, store = state_folder(conf), conf["store_key"], conf["store"]
    if os.path.dirname(os.path.abspath(key)) != folder:
        raise SystemExit(f"store_key must be in the broker's state folder ({folder}).")
    central = conf.get("central") is True
    if central and any(os.path.dirname(os.path.abspath(conf[k])) != folder for k in ("age_key", "state")):
        raise SystemExit(f"age_key and state must be in the central vault's state folder ({folder}).")
    made = []
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700)
        made.append("folder")
    os.chmod(folder, 0o700)
    if os.geteuid() == 0:
        os.chown(folder, info.pw_uid, info.pw_gid)
    if not os.path.exists(key):
        r = run([keygen, "-o", key], None)
        if r is None or r.returncode != 0 or not os.path.exists(key):
            raise SystemExit("The store key could not be made. Is age-keygen installed?")
        made.append("key")
    owned_by(key, info, 0o600)
    with open(key, encoding="utf-8") as f:              # as root, before the store is written for the vault user
        m = re.search(r"^# public key: (age1[0-9a-z]{58})$", f.read(), re.M)
    if not m:
        raise SystemExit(f"The store key file has no public key line: {key}")
    own = None
    if central:
        if not os.path.exists(conf["age_key"]):
            r = run([keygen, "-o", conf["age_key"]], None)
            if r is None or r.returncode != 0 or not os.path.exists(conf["age_key"]):
                raise SystemExit("The central vault's key could not be made. Is age-keygen installed?")
            made.append("age_key")
        owned_by(conf["age_key"], info, 0o600)
        with open(conf["age_key"], encoding="utf-8") as f:
            own = re.search(r"^# public key: (age1[0-9a-z]{58})$", f.read(), re.M)
        if not own:
            raise SystemExit(f"The central vault's key file has no public key line: {conf['age_key']}")
    if not os.path.exists(store):
        r = run([conf["age"], "-a", "-r", m.group(1)], json.dumps({"v": STORE, "items": {}}, sort_keys=True))
        if r is None or r.returncode != 0 or ARMOR not in r.stdout:
            raise SystemExit("The empty store could not be locked. Is age installed?")
        fd = os.open(store, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(r.stdout)
            f.flush()
            os.fsync(f.fileno())
        made.append("store")
    owned_by(store, info, 0o600)
    return dict({"store": store, "store_key": key, "user": user, "made": made, "public_key": m.group(1)},
                **({"age_key": conf["age_key"], "recipient": own.group(1)} if central else {}))


def store_list(config):
    """The names in the fleet's own store: its items' references, titles and when they were saved. Never a value.
    Run it as the vault user."""
    conf = load_config(config)
    try:
        items = LocalStore(conf).opened()
    except Refused as e:
        raise SystemExit(str(e)) from None
    return [{"login": f"bws://{i}", "title": x["key"],
             "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(x["made_at"]))}
            for i, x in sorted(items.items(), key=lambda kv: kv[1]["made_at"])]


UNIT = """[Unit]
Description=Fleet vault broker for {agent} (keeps the store's key and the handover key away from agents)
After=network-online.target
Wants=network-online.target

[Service]
User={user}
Group={group}
ExecStart=/usr/bin/python3 {script} serve --config {config}
RuntimeDirectory=fleet-vault
RuntimeDirectoryMode=0750
StateDirectory=fleet-vault
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""

# The central vault's service (`unit --central`): its own user, the hub user's group for the socket, and no network
# at all. The program is the root-owned copy that `hubsetup.py central-vault` installs, wherever this one runs from.
CENTRAL_UNIT = """[Unit]
Description=Fleet central vault (seals a secret only to a key that the owner signed)

[Service]
User={user}
Group={group}
ExecStart=/usr/bin/python3 /usr/local/lib/fleet-vault-central/vault.py serve --config {config}
RuntimeDirectory=fleet-vault-central
RuntimeDirectoryMode=0750
StateDirectory=fleet-vault-central
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
LimitCORE=0
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("serve", help="Serve the worker's helper on the configured socket")
    p.add_argument("--config", required=True)
    p = sub.add_parser("unit", help="Print the systemd unit for this broker")
    p.add_argument("--config", required=True)
    p.add_argument("--user", help="the vault user; default: fleet-vault, and always " + CENTRAL_USER + " for --central")
    p.add_argument("--group", help="the worker's group, or with --central the hub user's group: it may open the "
                                   "socket. Not for --swap")
    p.add_argument("--central", action="store_true", help="the unit of the central vault on the hub's server")
    p.add_argument("--swap", action="store_true", help="the unit of this machine's key swap proxy; --user is its own "
                                                       "user, default: " + SWAP_USER)
    p = sub.add_parser("swap", help="Run this machine's key swap proxy, as its own user: it puts an API key into a "
                                    "request to the key's own site, and it cannot read the store")
    p.add_argument("--config", required=True, help="the broker's configuration, which has the part swap")
    p.add_argument("--take", help=argparse.SUPPRESS)       # LISTENER,PIPE: from the process that serves now (a hand-over)
    p = sub.add_parser("store-init", help="The fleet's own store, as root: make the store key and an empty store "
                                          "that only the vault user can read. Safe to run again")
    p.add_argument("--config", required=True)
    p.add_argument("--user", help="the vault user: it owns the key and the store; default: fleet-vault, and "
                                  + CENTRAL_USER + " for a central vault")
    p.add_argument("--keygen", default="age-keygen", help="the age-keygen program; default: the one on the PATH")
    p = sub.add_parser("store-list", help="The references and titles in the fleet's own store, as the vault user. "
                                          "Never a value")
    p.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    if args.cmd in ("store-init", "store-list"):
        unchangeable(os.path.realpath(__file__), "The vault broker program")     # the installed copy, not a checkout
        if args.cmd == "store-init":
            if os.geteuid() != 0:
                raise SystemExit("Run store-init as root: the key and the store belong to the vault user.")
            print(json.dumps(dict(store_init(args.config, args.user, args.keygen), ok=True)))
        else:
            print(json.dumps(store_list(args.config), indent=2))
        return 0
    if args.cmd == "swap":
        take = re.fullmatch(r"([0-9]{1,6}),([0-9]{1,6})", args.take or "")
        if args.take and not take:
            raise SystemExit("--take is for the swap proxy's own hand-over.")
        return swap_main(args.config, take=(int(take.group(1)), int(take.group(2))) if take else None)
    if args.cmd == "unit" and args.swap:        # the same program file as the broker's, and its own user
        if args.central or args.group:
            raise SystemExit("unit --swap takes --config and --user, and no other option.")
        user = args.user or SWAP_USER
        if not GROUP_NAME.match(user) or user.startswith("fleet-"):
            raise SystemExit("The swap proxy's user is a user of its own, with no fleet- name.")
        print(SWAP_UNIT.format(user=user, config=args.config, script=os.path.abspath(__file__)), end="")
        return 0
    if args.cmd == "unit":
        if not args.group:
            raise SystemExit("unit needs --group: the worker's group, or with --central the hub user's group.")
        with open(args.config, encoding="utf-8") as f:
            said = json.load(f)
        if args.central != (said.get("central") is True):      # the unit and the configuration are of one kind
            raise SystemExit("unit --central is for a central vault's configuration, and only for one.")
        if args.central:
            if args.user not in (None, CENTRAL_USER):
                raise SystemExit(f"The central vault runs as {CENTRAL_USER}.")
            print(CENTRAL_UNIT.format(user=CENTRAL_USER, group=args.group, config=args.config), end="")
            return 0
        agent = said.get("agent") or "the agents of this machine"
        print(UNIT.format(agent=agent, user=args.user or "fleet-vault", group=args.group, config=args.config,
                          script=os.path.abspath(__file__)), end="")
        return 0
    unchangeable(os.path.realpath(__file__), "The vault broker program")     # never the worker's checkout
    conf = load_config(args.config)
    broker = Broker(conf).open()
    log(f"central vault on {conf['socket']}" if conf.get("central") is True else
        f"vault broker for {conf.get('agent') or 'the agents of this machine'} on {conf['socket']}")
    broker.serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
