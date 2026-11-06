#!/usr/bin/env python3
"""Fleet vault broker for a Linux worker: the store's key and the handover key belong to the vault, not to agents.

The broker runs as its own user (for example fleet-vault). Only that user can read the key of the fleet's own store
(or the Bitwarden access token) and the age key that opens sealed handovers. Agents run as the worker's user, so they can read neither, and no operation of
the broker gives them a login: it answers with an outcome, or with a handover that only the receiving machine's
broker can open. The helper sends only a job number; the broker takes the login, the receiving agent and that
agent's pinned handover key from the hub's confirmation of the job, never from the request.

A broker opens its logins from one of two stores, which its configuration chooses:

  - **the fleet's own store** (store, store_key): one age-encrypted file on this machine. No Bitwarden account, no
    organization and no network. A value reaches it only from the central vault, sealed to this broker's pinned key
    (deposit); its names are listed with  store-list , and  store-init  makes the key and the empty store. The key is
    an age identity in the broker's state folder, mode 600, which only the vault user can read; an agent never reads
    the store, the key or a value.
  - **a Bitwarden Secrets Manager project** (region, token_file, bws, bws_config): what the pilot used. Since the
    DevOps plan's track B (2 November 2026) no server keeps a Bitwarden token: load_config refuses such a
    configuration, so an installed program that has one keeps running the old program (fleet-vault-program), and the
    central vault is the one way a value reaches a server.

A broker belongs to a machine and not to one agent: `worker_group` is the group of that machine's agent users, so an
agent the owner adds later, or one whose OS user changed, reaches it with no change to its configuration. Such a
broker has no `agent` of its own and every request to it names its caller, which is how it can be installed with the
machine, before it has its first agent (`hubsetup.vault_install`). `worker_uid`, one user, is the form of a machine
that ran one agent, and it still works.

A Linux broker does handovers. Signing in needs a browser, so it is the Mac vault helper's work (same protocol).

A Linux broker also makes a new login for a confirmed job (create_login): it makes the password, keeps a record
before its one create call, and answers with the login's name. With the fleet's own store it needs nothing more,
because that store writes itself. With a Bitwarden project it needs the write setup, which uses the pinned Bitwarden
SDK library in the broker's own process, because the Bitwarden program takes a new value as a command argument;
without that setup such a broker only reads, as before.

With a curl program in its configuration, a Linux broker also sends one HTTP request for a confirmed job (call_api):
to the origin of the saved login and with its key, which stays in the broker. It keeps the identity of each request
that it started, so the same request is never sent again, and a cancel ends the requests of one task attempt.
Without that key the broker sends no request.

A Linux broker also gives a session start the API keys that the owner lets the calling agent read (read): the hub
names them, and the broker reads each value and registers its fingerprints before it gives it to the worker's user.

With the fleet's own store, a Linux broker also takes a key or a login that the owner typed into Founderizer on his
Mac (deposit): the central vault seals the value to this broker's pinned key, for a grant that the owner signed, the
hub carries the sealed copy, and the broker opens it, has the hub compare the value's fingerprints with the owner's,
and saves it under the same reference.

With the fleet's own store, a Linux broker also gives such a delivered secret back (withdraw) when no agent of its
machine holds it any more: the hub names the reference for one confirmed job, and the broker removes the item only when
its store says that the owner's vault delivered it, never a login that the owner saved there himself or that this
vault made.

A broker writes no key into another host: place, which wrote one into an application's .env file or a Kubernetes
Secret over SSH, left the broker (DevOps plan 0.3). It hands a login over to another machine (handover) only when the
owner's keys in its own configuration show that he signed a pin of the receiving key.

With `"central": true` in its configuration, the same program is the fleet's **central vault** on the hub's server:
one store that holds every secret of the fleet, which answers only the hub's user, never calls the hub and needs no
network. It takes a value that the owner sealed to its key in his app (intake), and it seals a copy of a value only to
a machine key that the owner signed (pin, unpin, seal), only for a grant of that value to an agent of that machine
that the owner signed, or for a value that he signed into the grantable pool (grant, ungrant, pool, unpool), and its
backup only to a recovery key that the owner signed (recovery, export). The owner signs with an ECDSA P-256 key of his Mac and the vault verifies every statement itself,
so a hub that is broken into cannot add a machine of its own and pull every secret in one call. It runs as its own
user (CENTRAL_UNIT), and only root installs or updates it (`hubsetup.py central-vault`): no release reaches it.

Run a copy that the worker's user cannot change (root-owned, outside the worker's checkout), with a root-owned
configuration, Bitwarden settings and programs, because an agent can change every file in its own checkout:
    python3 /usr/local/lib/fleet-vault/vault.py serve --config /etc/fleet-vault/vault.json
    python3 vault.py unit --config /etc/fleet-vault/vault.json --user fleet-vault --group <worker group>
    python3 /usr/local/lib/fleet-vault/vault.py store-init --config /etc/fleet-vault/vault.json \\
        --user fleet-vault                                       (as root; the fleet's own store, safe to run again)
    python3 /usr/local/lib/fleet-vault/vault.py sdk-install --config /etc/fleet-vault/vault.json \\
        --manifest <folder>/vault-sdk.json --project <Bitwarden project UUID>   (as root; Bitwarden's write setup)
    python3 vault.py unit --central --config /etc/fleet-vault-central/vault.json --group <the hub user's group>
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
import platform
import pwd
import re
import secrets
import shutil
import signal
import socket
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
KEYS = {"hub", "age_key", "socket", "age"}                                   # every broker, whatever its store
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
# The store, all of one group or all of the other: the fleet's own encrypted file on this machine, or a Bitwarden
# Secrets Manager project. A configuration with both is refused, because then no answer says which one holds a login.
STORE_KEYS = {"store", "store_key"}
BITWARDEN_KEYS = {"region", "token_file", "bws", "bws_config"}
AGENT_NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")
CALLER_KEY = re.compile(r"[A-Za-z0-9_-]{43}")          # an agent key (owner API 1.12): 256 bits, base64url
# The central vault's own operations, beside status: a central vault serves only these, and a machine's broker none.
CENTRAL_OPERATIONS = ("intake", "pin", "unpin", "recovery", "grant", "ungrant", "pool", "unpool", "seal", "inventory",
                      "export")
OPERATIONS = ("status", "signin", "handover", "probe", "create", "request", "cancel", "read", "deposit",
              "withdraw") + CENTRAL_OPERATIONS
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,59}")         # read: the variable name of an API key, as the hub checks it
READS = 32                  # read: the most values that one session gets
# The write setup (create_login): all three keys or none. sdk: the installed library; sdk_sha256: its checksum;
# write_project: the Bitwarden project of new items (an ID, no secret).
WRITE_KEYS = {"sdk", "sdk_sha256", "write_project"}
STORE = 1                           # the format of the fleet's own store
LOCAL = "local"                     # where an item of that store is: it holds one place and names no project
REQUEST_KEY = "curl"                # optional (call_api): the curl program that sends a request; without it, none is sent
PLACE_KEY = "ssh"                   # optional and not used: place left the broker (DevOps plan 0.3); an older
                                    # installer wrote it, so a configuration that has it still loads
# What ssh says when it failed before the server ran any command: only these prove that nothing was written.
# What the manifest of an installed library must say: the pinned recipe (vault_sdk_build.py), nothing else.
SDK_PIN = {"v": 1, "sdk": "2.1.0", "rev": "0520690b9710af7a8b1e47aad776f002f369688f", "crate": "bitwarden-c",
           "addition_sha256": "43d0eb44d44fd18bdeba6ea9631a25a03bdc07ff2359430c19843aff0b8ace2f",
           "library": "libbitwarden_c.so", "system": "Linux", "self_test": "passed",
           "symbols": ["init", "run_command", "free_mem", "fleet_free_string"]}
JOURNAL = "creates.json"            # beside the token, in the broker's private state folder
# The fixed sentences of a save, as the Mac vault helper says them. No text repeats a value.
NOT_SET_UP = "This machine's vault is not set up to save logins."
SAVE_REFUSED = "Bitwarden refused this save and made nothing."
SAVE_UNKNOWN = "The vault could not confirm that Bitwarden saved the login. It is not sent again."
SAVE_UNREGISTERED = "The login is saved, but the hub did not register it."
SAVE_CHANGED = "This save was made with other values. It is not made again."
NO_RECORD = "The vault could not keep its record of this save, so it made nothing."
NO_WRITE_ACCESS = "Bitwarden refused the write token or its project. Nothing was made."
NOT_MADE_HERE = "This vault did not make this login for that request, so it does not use it."
# The same outcomes in the words of the fleet's own store, which names no Bitwarden (says()).
STORE_REFUSED = "The vault store refused this save and made nothing."
STORE_UNKNOWN = "The vault could not confirm that its store saved the login. It is not sent again."
NO_STORE_WRITE = "The vault store could not be opened for a save. Nothing was made."
STORE_SAVED_ONLY = "A request needs a login that is saved in this fleet's vault, not a handed-over copy. Nothing was sent."
REQUESTS = "requests.json"          # the requests that this broker started, beside the token too
# The fixed sentences of a request (call_api). "Nothing was sent" is said only when the broker knows it. The first
# five are this broker's own; the Mac vault helper says the other eight in the same words.
NO_REQUESTS = "This machine's vault is not set up to send requests."
SAVED_ONLY = "A request needs a login that is saved in Bitwarden, not a handed-over copy. Nothing was sent."
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
    if given & (BITWARDEN_KEYS | WRITE_KEYS):
        raise SystemExit("A server keeps no Bitwarden token: this broker's configuration names a Bitwarden project ("
                         + ", ".join(sorted(given & (BITWARDEN_KEYS | WRITE_KEYS))) + "). Give it the fleet's own "
                         "store (store, store_key, made by store-init); its values come from the central vault.")
    stores = [group for group in (STORE_KEYS, BITWARDEN_KEYS) if given & group]
    if not isinstance(conf, dict) or given - KEYS - CALLER_KEYS - STORE_KEYS - BITWARDEN_KEYS - WRITE_KEYS \
            - {REQUEST_KEY, PLACE_KEY, "agent"} - OWNER_PIN_KEYS or \
            (given & OWNER_PIN_KEYS) not in (set(), OWNER_PIN_KEYS) or \
            not KEYS <= given or not given & CALLER_KEYS or len(stores) != 1 or not stores[0] <= given or \
            (given & WRITE_KEYS) not in (set(), WRITE_KEYS) or (given & WRITE_KEYS and stores[0] is STORE_KEYS):
        raise SystemExit("The vault configuration needs exactly: " + ", ".join(sorted(KEYS)) + "; optionally agent, "
                         "the one agent whose vault it is; who may ask it: " +
                         " or ".join(sorted(CALLER_KEYS)) + ", or both; and one store: all of " +
                         ", ".join(sorted(STORE_KEYS)) + " (the fleet's own) or all of " +
                         ", ".join(sorted(BITWARDEN_KEYS)) + " (a Bitwarden project), never both; for new logins in "
                         "Bitwarden also all of: " + ", ".join(sorted(WRITE_KEYS)) + "; and for API requests also: "
                         + REQUEST_KEY + "; and " + PLACE_KEY + " (read and not used), as older installers wrote it")
    if "agent" in conf and (not isinstance(conf["agent"], str) or not AGENT_NAME.match(conf["agent"])):
        raise SystemExit("agent must be the Fleet name of the one agent whose vault this is, or be left out")
    if OWNER_PIN_KEYS <= given:
        owner_pin_config(conf)
    if "region" in conf and conf["region"] not in ("eu", "us"):
        raise SystemExit("region must be eu or us")
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
    for key in ["age_key", "socket", "age"] + sorted((STORE_KEYS | BITWARDEN_KEYS - {"region"}) & given):
        if not isinstance(conf[key], str) or not os.path.isabs(conf[key]):
            raise SystemExit(f"{key} must be an absolute path")
    if BITWARDEN_KEYS <= given:
        unchangeable(conf["bws"], "The Bitwarden CLI")               # the agent cannot swap a program
        unchangeable(conf["bws_config"], "The Bitwarden settings")   # or point the token at another server
    unchangeable(conf["age"], "The age program")
    if REQUEST_KEY in conf:             # call_api: the program that gets the key of a request, checked as the other two
        if not isinstance(conf[REQUEST_KEY], str) or not os.path.isabs(conf[REQUEST_KEY]):
            raise SystemExit("curl must be an absolute path")
        unchangeable(conf[REQUEST_KEY], "The curl program")
    if PLACE_KEY in conf and (not isinstance(conf[PLACE_KEY], str) or not os.path.isabs(conf[PLACE_KEY])):
        raise SystemExit("ssh must be an absolute path")        # the program itself is checked when the broker starts
    if WRITE_KEYS <= set(conf):         # the write setup: its form here; the library itself is checked at the start
        if not isinstance(conf["sdk"], str) or not os.path.isabs(conf["sdk"]):
            raise SystemExit("sdk must be an absolute path")
        if not isinstance(conf["sdk_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", conf["sdk_sha256"]):
            raise SystemExit("sdk_sha256 must be the SHA-256 of the library: 64 lowercase hex characters")
        if not isinstance(conf["write_project"], str) or canonical_id(conf["write_project"]) != conf["write_project"]:
            raise SystemExit("write_project must be the Bitwarden project's UUID, in lower case")
    return conf


def backend(conf):
    """Which store this broker opens: "store", the fleet's own encrypted file on this machine, or "bitwarden"."""
    return "store" if STORE_KEYS <= set(conf) else "bitwarden"


def says(conf, bitwarden, store):
    """One fixed outcome in the words of the store that this broker uses."""
    return store if backend(conf) == "store" else bitwarden


def state_folder(conf):
    """The broker's private folder: of its store, or of its Bitwarden token. Its journal and its record of started
    requests lie there, and only the vault user can read it."""
    return os.path.dirname(os.path.abspath(conf["store" if backend(conf) == "store" else "token_file"]))


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


def bws_item(conf, sid, token):
    """One Bitwarden item, inside the broker only: {id, key (its name), value}."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": pwd.getpwuid(os.getuid()).pw_dir, "BWS_ACCESS_TOKEN": token}
    r = run([conf["bws"], "--config-file", conf["bws_config"], "--profile", conf["region"], "--output", "json",
             "secret", "get", sid], None, env)
    if r is None or r.returncode != 0:
        # CLI errors can contain its response or the token. Never return either stream.
        raise Refused("Bitwarden refused this login; check the vault token, project access, region and secret ID")
    try:
        item = json.loads(r.stdout)
        if str(item["id"]).lower() != sid.lower() or not isinstance(item["key"], str) or not item["key"] or \
                not isinstance(item["value"], str):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise Refused("Bitwarden gave no valid item for this login") from None
    return item


def open_login(conf, ref, task, store):
    """(the login, its name, its source login), inside the broker only. store: what opens a saved login here (the
    fleet's own store, or Bitwarden)."""
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
    store = opened_store(conf)          # a broken vault must not use up the job
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


def read(conf, purpose=None):
    """read (owner feature secrets): the API keys that the calling agent reads in its sessions, as {variable name:
    value}. The hub names them for this agent now; the broker reads each value itself and registers its fingerprints
    before it gives it, so that the hub masks it in texts. The worker's user may read exactly these values. A value
    that the broker cannot read or protect is left out, and its name is in missing. purpose: "check" or "session", which
    the hub is told: it gives no key to a session of an agent whose Shell box is off (support plan F1)."""
    store = opened_store(conf)
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}/read",
                     {"for": purpose} if purpose in ("check", "session") else {})
    found = data.get("secrets") if isinstance(data, dict) else None
    if code != 200 or not isinstance(found, list) or data.get("ok") is not True or len(found) > READS:
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not name the secrets to read" + (f": {reason}" if isinstance(reason, str) else ""))
    env, missing = {}, []
    for x in found:
        name, ref = x.get("env") if isinstance(x, dict) else None, x.get("login") if isinstance(x, dict) else None
        salts = x.get("fingerprint_salts") if isinstance(x, dict) else None
        if not (isinstance(name, str) and ENV_NAME.fullmatch(name) and name not in env and isinstance(ref, str)
                and SECRET_REF.fullmatch(ref) and isinstance(salts, dict)
                and all(re.fullmatch(r"[0-9a-f]{32}", str(salts.get(k))) for k in ("password", "totp"))):
            raise Refused("the hub named no valid secrets to read")
        try:
            value = check_value(store.item(SECRET_REF.fullmatch(ref).group(1))["value"])
            protect(conf, {"fingerprint_salts": salts}, value, read=ref.lower())
        except Refused:
            missing.append(name)
            continue
        env[name] = value["password"]
    log(f"read {len(env)} of {len(found)} value(s) for a session of {conf['agent']}")
    return {"ok": True, "v": PROTOCOL, "env": env, "missing": missing}


def probe(conf, job):
    """Which logins of the agent's profile this vault can open (owner API 1.9): the hub names them for one probe job.
    The answer has fixed codes only: no part of a login leaves the broker."""
    try:
        store = opened_store(conf)
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
    if backend(conf) != "store":
        raise Refused("this machine's vault opens a Bitwarden project, so it takes no delivered secret")
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
    if backend(conf) != "store":
        raise Refused("this machine's vault opens a Bitwarden project, so it holds no delivered secret")
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


def probe_one(conf, ref, token):
    def result(state, reason):
        return {"login": ref, "state": state, "reason": reason}
    if not token:
        return result("not_readable", "no_token")
    m = SECRET_REF.fullmatch(ref)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": pwd.getpwuid(os.getuid()).pw_dir, "BWS_ACCESS_TOKEN": token}
    try:
        r = subprocess.run([conf["bws"], "--config-file", conf["bws_config"], "--profile", conf["region"], "--output",
                            "json", "secret", "get", m.group(1)], capture_output=True, text=True, timeout=30, env=env)
    except subprocess.TimeoutExpired:
        return result("not_readable", "timeout")
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return result("not_readable", "error")
    if r.returncode != 0:               # the CLI's text is only searched, never kept or shown
        text = (r.stdout + r.stderr).lower()
        return result("not_readable", "not_found" if "404" in text or "not found" in text else
                      "no_access" if any(w in text for w in ("401", "403", "unauthorized", "forbidden")) else "error")
    try:
        item = json.loads(r.stdout)
        value = json.loads(item["value"])
        good = str(item["id"]).lower() == m.group(1).lower() and isinstance(value, dict) and \
            isinstance(value.get("username", ""), str) and isinstance(value.get("password"), str) and value["password"]
    except (ValueError, KeyError, TypeError):
        good = False
    return result("readable", "ok") if good else result("not_readable", "bad_format")


# ---------------------------------------------------------------- the two stores

class BitwardenStore:
    """A Bitwarden Secrets Manager project, read with the CLI and this broker's own access token. The token is read
    for one request and stays in this process and its children."""

    def __init__(self, conf):
        self.conf = conf
        self.token = read_private(conf["token_file"], "token").strip()

    def item(self, sid):
        return bws_item(self.conf, sid, self.token)

    def probe(self, ref):
        return probe_one(self.conf, ref, self.token)

    def writer(self, refusal):
        return reach(self.conf, self.token, refusal)


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
    neither read nor open. No Bitwarden account, no organization and no network.

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
        """Can this vault open this login? The fixed codes of a probe, as Bitwarden's: no part of a login leaves."""
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

    # What create() asks of a store that writes. This store is one place, so it takes a project and names none.
    def writer(self, refusal):
        return self, LOCAL

    def named(self, name, project, organization):
        """The ids of the items with exactly this name."""
        return sorted(i for i, x in self.opened().items() if x["key"] == name)

    def notes(self, ids):
        items = self.opened()
        return {i: items[i]["note"] for i in ids if i in items}

    def create(self, name, value, note, project, organization):
        """Exactly one save: ("created", id), or ("refused", None) when nothing was made. The store is one file on
        this machine, which is made complete beside the old one and then takes its place, so a save that fails leaves
        the store as it was and no outcome is unknown."""
        try:
            return "created", self.add(name, value, note)
        except Refused:
            return "refused", None

    def login(self, item):
        """The broker's own new item, read again: its values are fingerprinted from the store, not from memory."""
        return check_login(self.item(item)["value"])

    def close(self):
        """Nothing is held open: every read and every save opens the file itself."""


def opened_store(conf):
    """What opens this broker's logins, read for one request: the fleet's own store, or the Bitwarden project of this
    broker's token. A store that does not open refuses here, before the hub's job is used up."""
    return LocalStore(conf) if backend(conf) == "store" else BitwardenStore(conf)


# ---------------------------------------------------------------- new logins (create_login)

class Provider(Exception):
    """Bitwarden, or its library, gave no good answer. The text of an answer is never kept or passed on."""


def sync_folder(path):
    """Make a new name in this folder safe against a loss of power: the file's own sync does not keep its name."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def library_problem(conf):
    """None when the configured library is the installed one: on a path that the worker cannot change, and with the
    checksum that the configuration names. Else the reason in one sentence."""
    try:
        unchangeable(conf["sdk"], "The Bitwarden library")
        if sha256_file(conf["sdk"]) != conf["sdk_sha256"]:
            return "the Bitwarden library is not the one that the configuration names"
    except SystemExit as e:
        return str(e)
    except OSError:
        return "the Bitwarden library cannot be read"
    return None


class Sdk:
    """The Bitwarden SDK in this process: the pinned library from its protected path. The token and a new value go to
    it in memory only; no program argument, no environment variable and no file has them. `library`: a stand-in with
    the same four functions, for tests."""
    def __init__(self, path, region, library=None):
        import ctypes
        self.ctypes, self.client = ctypes, None
        lib = library
        if lib is None:
            lib = ctypes.CDLL(path)
            lib.init.restype, lib.init.argtypes = ctypes.c_void_p, [ctypes.c_char_p]
            lib.run_command.restype, lib.run_command.argtypes = ctypes.c_void_p, [ctypes.c_char_p, ctypes.c_void_p]
            lib.free_mem.restype, lib.free_mem.argtypes = None, [ctypes.c_void_p]
            lib.fleet_free_string.restype, lib.fleet_free_string.argtypes = None, [ctypes.c_void_p]
        self.lib = lib
        domain = "bitwarden.eu" if region == "eu" else "bitwarden.com"
        self.client = lib.init(json.dumps({"apiUrl": f"https://api.{domain}", "identityUrl": f"https://identity.{domain}",
                                           "userAgent": "Fleet Vault", "deviceType": "SDK"}).encode())
        if not self.client:
            raise Provider()

    def answer(self, command):
        """The SDK's answer to one command as an object, or None: no answer, or one that cannot be read. The
        answer's memory is cleared and freed by the library's own function."""
        raw = self.lib.run_command(json.dumps(command).encode(), self.client)
        if not raw:
            return None
        try:
            data = self.ctypes.string_at(raw)
            reply = json.loads(data.decode()) if len(data) <= 1 << 20 else None
        except (ValueError, UnicodeError):
            reply = None
        finally:
            self.lib.fleet_free_string(raw)
        return reply if isinstance(reply, dict) else None

    def close(self):
        if self.client:
            self.lib.free_mem(self.client)
            self.client = None


class Items:
    """The Bitwarden calls of a new login, after sign-in with this broker's token (the calls of the Mac vault)."""
    def __init__(self, sdk, token):
        self.sdk = sdk
        try:
            self.command({"loginAccessToken": {"accessToken": token}})
        except Provider:
            sdk.close()
            raise

    def command(self, command):
        reply = self.sdk.answer(command)
        if not reply or reply.get("success") is not True or not isinstance(reply.get("data"), dict):
            raise Provider()
        return reply["data"]

    def organization(self, project):
        """The organization of the project, which also proves that the token reaches the project."""
        data = self.command({"projects": {"get": {"id": project}}})
        if canonical_id(str(data.get("id")).lower()) != project or not canonical_id(str(data.get("organizationId")).lower()):
            raise Provider()
        return str(data["organizationId"]).lower()

    def named(self, name, project, organization):
        """The IDs of the project's items with exactly this name."""
        rows = self.command({"secrets": {"list": {"organizationId": organization}}}).get("data")
        if not isinstance(rows, list):
            raise Provider()
        found = []
        for row in rows:
            if not isinstance(row, dict) or not canonical_id(str(row.get("id")).lower()) or \
                    not isinstance(row.get("key"), str) or not isinstance(row.get("projectIds"), list):
                raise Provider()
            if row["key"] == name and project in [str(x).lower() for x in row["projectIds"]]:
                found.append(str(row["id"]).lower())
        return found

    def notes(self, ids):
        rows = self.command({"secrets": {"getByIds": {"ids": ids}}}).get("data")
        if not isinstance(rows, list) or not all(isinstance(r, dict) and isinstance(r.get("id"), str)
                                                 and isinstance(r.get("note"), str) for r in rows):
            raise Provider()
        return {r["id"].lower(): r["note"] for r in rows}

    def create(self, name, value, note, project, organization):
        """Exactly one create call: ("created", id), ("refused", None) or ("unknown", None). Only an answer of the
        server with a 4xx status proves that nothing was made; no answer, an answer that cannot be read and every
        other error leave the outcome unknown. The error text is never passed on."""
        reply = self.sdk.answer({"secrets": {"create": {"organizationId": organization, "key": name, "value": value,
                                                        "note": note, "projectIds": [project]}}})
        if not reply:
            return "unknown", None
        if reply.get("success") is True:
            made = canonical_id(str((reply.get("data") or {}).get("id")).lower()) if isinstance(reply.get("data"), dict) else None
            return ("created", made) if made else ("unknown", None)
        refused = re.match(r"Received error message from server: \[4[0-9]{2}[ \]]", str(reply.get("errorMessage") or ""))
        return ("refused", None) if refused else ("unknown", None)

    def login(self, item):
        """The broker's own new item, read again: its values are fingerprinted from Bitwarden, not from memory."""
        data = self.command({"secrets": {"get": {"id": item}}})
        if str(data.get("id")).lower() != item or not isinstance(data.get("value"), str):
            raise Provider()
        return check_login(data["value"])

    def close(self):
        self.sdk.close()


def open_items(conf, token):
    """Sign in with the broker's token through the pinned library. Raises Provider when that fails."""
    return Items(Sdk(conf["sdk"], conf["region"]), token)


class Journal:
    """This broker's record of every new login that it was asked to make, in its private state folder. Bitwarden has
    no create that is safe to repeat, and a look-up that finds nothing does not prove that an earlier create failed.
    So the journal decides: a request_id gets a create call only while it has no record, the record is kept before
    the call, and a save with an unknown outcome is only looked for by its mark. No record is ever dropped. One
    exclusive lock, held for the life of the broker, gives the journal to one process."""
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


def reach(conf, token, refusal):
    """(the Bitwarden calls, the project's organization): sign-in with the token, and the project that it must
    reach. Nothing is made here."""
    try:
        items = open_items(conf, token)
    except (Provider, OSError, AttributeError):
        raise Refused(refusal) from None
    try:
        return items, items.organization(conf["write_project"])
    except Provider:
        items.close()
        raise Refused(refusal) from None


def create(conf, job):
    """create_login: one new login for a confirmed job of the calling agent, with a password that this broker makes.
    The answer is the login's name, or one fixed sentence. `unknown` says that the item can exist: the same request
    again only looks for it by its mark, or finishes the hub's steps, and never sends a second create call."""
    def unknown(text):
        return {"ok": False, "v": PROTOCOL, "unknown": True, "error": text}
    journal = conf.get("_journal")
    if journal is None:                 # the machine's own setup comes first: without it, nothing is asked
        raise Refused(NOT_SET_UP)
    store = opened_store(conf)
    made = confirm_create(conf, job)
    project = conf.get("write_project", LOCAL)
    record, items = journal.get(made["request_id"]), None
    try:
        if record is not None and record["binding"] != made["binding"]:
            raise Refused(SAVE_CHANGED)
        if record is None:
            # Sign-in and the project come before the password and the record: a failure here made nothing.
            items, organization = store.writer(says(conf, NO_WRITE_ACCESS, NO_STORE_WRITE))
            value = json.dumps({"username": made["username"], "password": new_password(), "url": made["url"]},
                               sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            now = journal.clock()
            record = {"request_id": made["request_id"], "title": made["label"], "hub": conf["hub"], "db": made["db"],
                      "state": "creating", "login": None, "started_at": now, "updated_at": now,
                      "binding": made["binding"], "mark": made["mark"]}
            journal.begin(record)       # kept before the call
            try:
                outcome, item = items.create(made["label"], value, made["mark"], project, organization)
            except Exception:           # the call can have gone out: an error here proves nothing
                outcome, item = "unknown", None
            del value
            # A record that stays `creating` in the file becomes `unknown` at the next start.
            journal.change(record, state={"created": "created", "refused": "failed"}.get(outcome, "unknown"),
                           login=f"bws://{item}" if outcome == "created" else None)
        elif record["state"] == "unknown":
            # Only looked for by its mark. An item that is not found leaves the record: the first call can still arrive.
            try:
                items, organization = store.writer(says(conf, SAVE_UNKNOWN, STORE_UNKNOWN))
                ids = items.named(record["title"], project, organization)
                notes = items.notes(ids) if ids else {}
            except (Refused, Provider):
                return unknown(says(conf, SAVE_UNKNOWN, STORE_UNKNOWN))
            found = next((i for i in sorted(ids) if notes.get(i) == record["mark"]), None)
            if found:
                journal.change(record, state="created", login=f"bws://{found}")
        if record["state"] in ("failed", "discarded"):
            raise Refused(says(conf, SAVE_REFUSED, STORE_REFUSED))
        if record["state"] not in ("created", "registered") or not record["login"]:
            return unknown(says(conf, SAVE_UNKNOWN, STORE_UNKNOWN))
        if record["state"] == "created":
            # The hub learns the name and gets the fingerprints before the helper gets the answer. The item exists
            # now, so every failure here stays unknown: the same request again finishes these steps.
            try:
                if items is None:
                    items, _ = store.writer(SAVE_UNREGISTERED)
                code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}/created", {"job": job, "login": record["login"]})
                salts = data.get("fingerprint_salts") if isinstance(data, dict) else None
                if code != 200 or data.get("ok") is not True or data.get("job") != job or data.get("login") != record["login"] \
                        or not isinstance(salts, dict) or set(salts) != {"password", "totp"} \
                        or not all(re.fullmatch(r"[0-9a-f]{32}", str(v)) for v in salts.values()):
                    return unknown(SAVE_UNREGISTERED)
                protect(conf, {"job": job, "fingerprint_salts": salts}, items.login(record["login"][6:]))
                journal.change(record, must=True, state="registered")
            except Refused as e:
                return unknown(str(e) if "agent's key" in str(e) else SAVE_UNREGISTERED)
            except Provider:
                return unknown(SAVE_UNREGISTERED)
        return {"ok": True, "v": PROTOCOL, "job": job, "login": record["login"]}
    finally:
        if items is not None:
            items.close()


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
             f'request = "{call["method"]}"', 'header = "Accept: application/json"']
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
    store = opened_store(conf)          # a broken vault must not use up the job
    confirmed = confirm_job(conf, job, "request")
    call = request_of(confirmed)
    if not SECRET_REF.fullmatch(confirmed["login"]):
        raise Refused(says(conf, SAVED_ONLY, STORE_SAVED_ONLY))
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
    "recovery": {recipient, at} or None, "grants": {login: {agent: {machine, at}}}, "pool": {login: {in, at}}}. An
    unpin keeps its machine's record, with no recipient, and an ungrant and an unpool keep theirs too, so a statement
    older than them, which the hub could send again, is refused as old. No file is no record, and a state of the
    format before grants has none."""
    if not os.path.lexists(conf["state"]):
        return {"v": STATE, "pins": {}, "recovery": None, "grants": {}, "pool": {}}
    try:
        data = json.loads(read_private(conf["state"], "state"))
        if isinstance(data, dict):
            data.setdefault("grants", {})
            data.setdefault("pool", {})
        good = isinstance(data, dict) and set(data) == {"v", "pins", "recovery", "grants", "pool"} \
            and data["v"] == STATE and isinstance(data["pins"], dict) \
            and all(MACHINE.fullmatch(m) and kept_record(x, unpinned=True) for m, x in data["pins"].items()) \
            and (data["recovery"] is None or kept_record(data["recovery"])) \
            and isinstance(data["grants"], dict) and all(
                SECRET_REF.fullmatch(ref) and isinstance(held, dict) and all(
                    AGENT_NAME.match(agent) and kept_grant(x) for agent, x in held.items())
                for ref, held in data["grants"].items()) \
            and isinstance(data["pool"], dict) and all(SECRET_REF.fullmatch(ref) and kept_pool(x)
                                                       for ref, x in data["pool"].items())
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
            "source": conf.get("_source")}


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
    owner gave. It is saved under the same reference, and another value under it is refused, as a deposit is."""
    ref, title, item, text, salts, given = (req.get(k) for k in ("login", "title", "item", "ciphertext", "salts",
                                                                 "fingerprints"))
    m = SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
    if not (m and plain_line(title, 200) and item in ("login", "api_key") and isinstance(text, str)
            and ARMOR in text and len(text) <= COPY_MAX and isinstance(salts, dict)
            and all(re.fullmatch(r"[0-9a-f]{32}", str(salts.get(k))) for k in ("password", "totp"))
            and fingerprint_list(given)):
        raise Refused("the intake request is not valid")
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
    saved = store.put(m.group(1).lower(), title, canonical(value), "taken from the owner")
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
        status = {"ok": True, "v": PROTOCOL, "agent": conf.get("agent"), "store": "user", "backend": backend(conf),
                  "user": pwd.getpwuid(os.getuid()).pw_name, "recipient": recipient(conf), "callers": True,
                  "source": conf.get("_source")}
        if conf.get("_journal") is not None:        # this broker can make a login: its own store, or the write setup
            status["creates"] = True
        if conf.get("_requests") is not None:       # only with a curl program: this broker can send a request
            status["requests"] = True
        if backend(conf) == "store":                # the fleet's own store takes a secret the owner delivers,
            status["deposits"] = True
            status["withdrawals"] = True            # and gives it back when no agent of the machine holds it
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
        return read(conf, req.get("for"))
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
    """The configuration with the broker's journal (`_journal`), which it needs to make a login: with the fleet's own
    store always, because the store writes itself; with Bitwarden only when the write setup is there and good. Else
    the configuration as it is, and the reason in the log: that broker reads and makes no login."""
    reason = None
    if backend(conf) == "store" or WRITE_KEYS <= set(conf):
        reason = None if backend(conf) == "store" else library_problem(conf)
        if reason is None:
            try:
                return dict(conf, _journal=Journal(os.path.join(state_folder(conf), JOURNAL)))
            except Refused as e:
                reason = str(e)
    if reason is not None:
        log(f"no new logins: {reason}")
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
            self.conf = with_source(with_requests(with_writes(conf), self.lock))
        self.conf, self.sock = dict(self.conf, _lock=self.lock), None

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
        return self

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
        if self.conf.get("_journal") is not None:
            self.conf["_journal"].close()
            self.conf = {k: v for k, v in self.conf.items() if k != "_journal"}
        if self.conf.get("_requests") is not None:
            self.conf["_requests"].close()
            self.conf = {k: v for k, v in self.conf.items() if k != "_requests"}


# ---------------------------------------------------------------- the write setup: one operation (sdk-install)

SELF_TEST = {"fleetSelfTest": {}}       # a command that the SDK does not have: it answers an error by itself


def sdk_test(library):
    """Load the library and ask it one command that it refuses by itself: the four functions are there, an answer
    comes back, and the library frees it. No token, no secret and no network. Never as root."""
    if os.geteuid() == 0:
        raise SystemExit("The load test runs as the vault user, never as root.")
    sdk = Sdk(library, "eu")
    try:
        reply = sdk.answer(SELF_TEST)
    finally:
        sdk.close()
    if not reply or reply.get("success") is not False or not isinstance(reply.get("errorMessage"), str):
        raise SystemExit("The library did not pass its load test.")
    return True


def run_sdk_test(library, uid, gid):
    """sdk_test in a process of its own, as the vault user. True when it passed."""
    if uid == 0:
        return False
    change = {} if (uid, gid) == (os.geteuid(), os.getegid()) else {"user": uid, "group": gid, "extra_groups": []}
    try:
        done = subprocess.run([sys.executable, "-B", os.path.abspath(__file__), "sdk-test", "--library", library],
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              env={"PATH": "/usr/local/bin:/usr/bin:/bin"}, **change)
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return done.returncode == 0 and done.stdout.strip() == "ok"


def glibc(text):
    """(2, 31) from "glibc 2.31"; None for another C library."""
    m = re.fullmatch(r"glibc (\d+)\.(\d+)(?:\.\d+)?", str(text or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def sdk_install(config, manifest, project, library=None, system=None, machine=None, libc=None, test=run_sdk_test,
                folder=None):
    """The write setup of a broker, in one operation: check the built library against its manifest and the pinned
    recipe, check that this machine can run it, put a copy that the worker cannot change beside this program, test
    that the vault user can load it (no token), and name it with the project in the broker's configuration. It
    reads no token and changes none. The broker uses the setup after its next start. Returns the new keys.
    system, machine, libc, test and folder have other values only in tests."""
    system, machine = system or platform.system(), machine or platform.machine()
    libc = libc if libc is not None else (os.confstr("CS_GNU_LIBC_VERSION") if "CS_GNU_LIBC_VERSION" in os.confstr_names else "")
    conf = load_config(config)
    if backend(conf) != "bitwarden":
        raise SystemExit("This broker opens the fleet's own store, which makes a login by itself. The Bitwarden "
                         "library belongs to a broker with a Bitwarden project.")
    project = canonical_id(project)
    if not project:
        raise SystemExit("--project must be the UUID of the Bitwarden project for new logins.")
    try:
        with open(manifest, encoding="utf-8") as f:
            said = json.load(f)
    except (OSError, ValueError):
        raise SystemExit("The manifest cannot be read.") from None
    if not isinstance(said, dict) or any(said.get(k) != v for k, v in SDK_PIN.items()):
        raise SystemExit("The manifest is not of the pinned recipe: another source, another addition, another system "
                         "or no passed self-test.")
    if system != "Linux" or said.get("machine") != machine:
        raise SystemExit(f"The library is for Linux on {said.get('machine')}; this machine is {system} on {machine}.")
    need, have = glibc(said.get("libc")), glibc(libc)
    if not need or not have or have < need:
        raise SystemExit(f"The library was built with {said.get('libc')}; this machine has {libc or 'no glibc'}.")
    source = library or os.path.join(os.path.dirname(os.path.abspath(manifest)), SDK_PIN["library"])
    digest = said.get("library_sha256")
    if os.path.islink(source) or not os.path.isfile(source) or not isinstance(digest, str) \
            or not re.fullmatch(r"[0-9a-f]{64}", digest) or os.path.getsize(source) != said.get("library_bytes") \
            or sha256_file(source) != digest:
        raise SystemExit("The library is not the one of the manifest.")
    folder = folder or os.path.dirname(os.path.realpath(__file__))     # beside the broker program, on no other path
    dest, staged = os.path.join(folder, SDK_PIN["library"]), os.path.join(folder, "." + SDK_PIN["library"] + ".new")
    new, next_config = {"sdk": dest, "sdk_sha256": digest, "write_project": project}, config + ".new"
    try:
        owner = os.stat(os.path.dirname(os.path.abspath(conf["token_file"])))   # the vault user owns the state folder
    except OSError:
        raise SystemExit("The vault's state folder (the folder of token_file) is not there.") from None
    try:
        # The new copy and the new configuration are made complete beside the installed ones, and the copy is tested
        # there. Only then do they take the places. A setup that fails leaves the old library and configuration.
        try:
            with open(source, "rb") as src, \
                    os.fdopen(os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644), "wb") as out:
                for block in iter(lambda: src.read(1 << 20), b""):
                    out.write(block)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(staged, 0o644)
        except OSError:
            raise SystemExit(f"The library could not be put in {folder}.") from None
        unchangeable(staged, "The Bitwarden library")
        if sha256_file(staged) != digest:
            raise SystemExit("The copy of the library is not the one of the manifest.")
        if owner.st_uid == 0 or not test(staged, owner.st_uid, owner.st_gid):
            raise SystemExit("The vault user could not load the library, so it is not set up. The load test never runs "
                             "as root.")
        try:
            with open(config, encoding="utf-8") as f:
                current = json.load(f)
            with os.fdopen(os.open(next_config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644), "w",
                           encoding="utf-8") as f:
                json.dump(dict(current, **new), f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(next_config, stat.S_IMODE(os.stat(config).st_mode))
        except (OSError, ValueError):
            raise SystemExit("The new configuration could not be written.") from None
        load_config(next_config)        # the form that the broker reads at its next start
        try:
            os.replace(staged, dest)
            os.replace(next_config, config)
            sync_folder(folder)
            sync_folder(os.path.dirname(os.path.abspath(config)))
        except OSError:
            raise SystemExit("The setup could not be put in place. Run it again.") from None
    finally:
        for left in (staged, next_config):
            try:
                os.unlink(left)
            except OSError:
                pass
    return new


# ---------------------------------------------------------------- the fleet's own store: three operations

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
    conf = load_config(config)
    if backend(conf) != "store":
        raise SystemExit("This broker's configuration names a Bitwarden project. Name store and store_key instead, "
                         "and no Bitwarden key, to use the fleet's own store.")
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
    if backend(conf) != "store":
        raise SystemExit("This broker opens a Bitwarden project, so its items are listed there.")
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
    p.add_argument("--group", required=True, help="the worker's group, or with --central the hub user's group: it may "
                                                  "open the socket")
    p.add_argument("--central", action="store_true", help="the unit of the central vault on the hub's server")
    p = sub.add_parser("store-init", help="The fleet's own store, as root: make the store key and an empty store "
                                          "that only the vault user can read. Safe to run again")
    p.add_argument("--config", required=True)
    p.add_argument("--user", help="the vault user: it owns the key and the store; default: fleet-vault, and "
                                  + CENTRAL_USER + " for a central vault")
    p.add_argument("--keygen", default="age-keygen", help="the age-keygen program; default: the one on the PATH")
    p = sub.add_parser("store-list", help="The references and titles in the fleet's own store, as the vault user. "
                                          "Never a value")
    p.add_argument("--config", required=True)
    p = sub.add_parser("sdk-install", help="The write setup, as root: install the pinned Bitwarden library and name it "
                                           "and the project for new logins in the configuration")
    p.add_argument("--config", required=True)
    p.add_argument("--manifest", required=True, help="vault-sdk.json of a build of vault_sdk_build.py")
    p.add_argument("--project", required=True, help="the UUID of the Bitwarden project for new logins (no secret)")
    p.add_argument("--library", help="the built library; default: beside the manifest")
    p = sub.add_parser("sdk-test", help="Load a library and ask it one command without a token; never as root")
    p.add_argument("--library", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "sdk-test":
        sdk_test(args.library)
        print("ok")
        return 0
    if args.cmd in ("store-init", "store-list"):
        unchangeable(os.path.realpath(__file__), "The vault broker program")     # the installed copy, not a checkout
        if args.cmd == "store-init":
            if os.geteuid() != 0:
                raise SystemExit("Run store-init as root: the key and the store belong to the vault user.")
            print(json.dumps(dict(store_init(args.config, args.user, args.keygen), ok=True)))
        else:
            print(json.dumps(store_list(args.config), indent=2))
        return 0
    if args.cmd == "sdk-install":
        if os.geteuid() != 0:
            raise SystemExit("Run sdk-install as root: the library and the configuration must belong to root.")
        unchangeable(os.path.realpath(__file__), "The vault broker program")     # the installed copy, not a checkout
        print(json.dumps(dict(sdk_install(args.config, args.manifest, args.project, args.library), ok=True,
                              next="restart the broker service to use the setup")))
        return 0
    if args.cmd == "unit":
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
