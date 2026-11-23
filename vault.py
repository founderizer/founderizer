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

A Linux broker does handovers. It signs an agent in in the agent's own browser on that server (plan 04, S5), as the
Mac vault helper does in the owner's Chrome (same protocol).

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
reference. When the owner replaced the value of that reference (the central vault's signed replace), the hub says so
with the delivery, and the broker puts the new value in the place of the one that an earlier delivery saved.

A Linux broker also gives such a delivered secret back (withdraw) when no agent of its machine holds it any more: the
hub names the reference for one confirmed job, and the broker removes the item only when its store says that the
owner's vault delivered it, never a login that the owner saved there himself or that this vault made.

With the part "swap" in its configuration, which only a root step writes, a Linux broker also keeps such a key out
of the sessions (the key swap): the session start gets a placeholder, and a second process of this program, the swap
proxy (`vault.py swap`), which runs as a user of its own that cannot read the store, puts the real key into the
Authorization header, or into the one header that the key's form names, of an HTTPS request to that key's own site.
The broker gives the proxy one value for one
placeholder, one OS user and one host, after the hub said that the grant is live now.

A broker writes no key into another host: place, which wrote one into an application's .env file or a Kubernetes
Secret over SSH, left the broker (DevOps plan 0.3). It hands a login over to another machine (handover) only when the
owner's keys in its own configuration show that he signed a pin of the receiving key.

With `"central": true` in its configuration, the same program is the fleet's **central vault** on the hub's server:
one store that holds every secret of the fleet, which answers only the hub's user, never calls the hub and needs no
network. It takes a value that the owner sealed to its key in his app (intake), and a new value under a reference
that it holds only with the owner's signed statement about that very copy (replace). It seals a copy of a value only to
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
import errno
import fcntl
import hashlib
import hmac
import ipaddress
import json
import grp
import queue
import os
import pwd
import re
import secrets
import select
import shlex
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
                      "export", "remove", "key_addresses", "hub_key")
# The hub's own files whose key the central vault keeps for it (hub_key; UI-API.md 1.202): its Google file, which the
# hub seals so that a copy of the hub user's files does not open it.
HUB_KEYS = ("google",)
# The addresses that select each row of the hub's table of well-known services (lifecycle.KEY_TABLE: the API hosts,
# and the pages as (host, path)), for the central vault's key_addresses. A copy, because the central vault runs this
# file alone and takes no host from the hub: test_key_table holds it equal to the hub's table.
KEY_TABLE_PLACES = {
    "openai": {"hosts": ("api.openai.com",),
               "pages": (("platform.openai.com", "/api-keys"), ("platform.openai.com", "/settings/organization/api-keys"))},
    "replicate": {"hosts": ("api.replicate.com",), "pages": (("replicate.com", "/account/api-tokens"),)},
    "cloudflare": {"hosts": ("api.cloudflare.com",), "pages": ()},
}
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
# The lifetime of the owner's pin of a handover's recipient (package 4 of the vault's gates, C2): a pin locks a handover
# for 90 days from the time that it names, by this machine's clock. This broker keeps no record of an unpin, so an old pin
# of a key that the owner took back ends here within that time, and the owner's app signs each pin again after 7 days.
# A pin dated more than a day after this machine's clock is not taken either, so a clock ahead on the owner's Mac cannot
# make a pin live longer. The central vault keeps no statement of the owner's from that far ahead, of any kind that
# central_signed takes (choice C50): one from ahead would stay its record's newest until its time, and no statement
# dated right could end it. A replace (intake) is not checked so.
PIN_LIFE = 90 * 86400
PIN_AHEAD = 86400
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
              "unpool": {"v", "kind", "fleet", "login", "at"},
              # replace: the owner puts a new value under a reference that the vault holds. sha256 is of the sealed
              # copy that his app made, so the statement is about that one copy and no other (intake).
              "replace": {"v", "kind", "fleet", "login", "sha256", "at"}}
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


class HubSilent(Refused):
    """hub(): no answer of the hub came. The connection was refused, was reset, closed before the answer began or timed
    out: what a vault gets while the hub restarts, because the hub's own process listens on its port and binds it
    again only near the end of its start. A Refused, so each caller that catches Refused is as before; the key swap
    tells it from each answer of the hub (swap_asks). A connection that closes in the middle of an answer is
    http.client's IncompleteRead, which hub() lets through as before: an error of the broker, and no yes."""


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
    if conf.get("caller_user"):         # one OS user for each agent: whom the request came from, by the socket
        headers["X-Fleet-Caller-User"] = conf["caller_user"]
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
        if e.code == 403 and isinstance(data, dict) and data.get("auth") in ("os_user", "os_user_shared"):
            raise Refused("the hub gives this agent's vault nothing now: its key came from another user account, or "
                          "it shares its user account with another agent") from None
        if e.code == 403 and isinstance(data, dict) and data.get("auth"):      # one fixed text, as the Mac vault helper
            raise Refused("the hub did not accept this agent's key") from None
        return e.code, data
    except OSError:                     # no answer came (HubSilent)
        raise HubSilent("the vault broker could not reach the hub") from None
    except ValueError:                  # an answer came, and it is not JSON
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


def owner_keys_held(conf):
    """Refused when this broker's configuration has no owner keys: such a vault hands no login over. `handover` asks
    this before it confirms the hub's one-use job, so such a vault uses up no job."""
    if not OWNER_PIN_KEYS <= set(conf):
        raise Refused("this machine's vault holds no key of the owner, so it hands no login over")


def owner_pinned(conf, confirmed):
    """Refused unless the owner signed a pin of the recipient that the hub named for this handover: the pin statement
    that the hub carries beside the job, checked here with the owner's keys of this broker's own configuration. The hub
    names the receiving agent and its key, and a hub that is broken into could name a key of its own; it cannot sign
    for the owner (DevOps plan 0.3). The pin must also be from the last PIN_LIFE, and not from more than PIN_AHEAD after
    now: this broker keeps no record of an unpin, so an old pin of a key that the owner took back would otherwise lock a
    login for it for ever (C2)."""
    owner_keys_held(conf)
    pin = confirmed.get("pin")
    if not isinstance(pin, dict):
        raise Refused("the owner has signed no pin of the receiving machine's key, so the login is not handed over")
    said = owner_statement(conf, pin, "pin")
    if said["recipient"] != confirmed["recipient"]:
        raise Refused("the owner's pin names another key than the one the login would be locked for, so it is not "
                      "handed over")
    age = time.time() - said["at"]
    if age > PIN_LIFE:
        raise Refused("the owner's pin of the receiving machine's key is more than 90 days old, so the login is not "
                      "handed over")
    if age < -PIN_AHEAD:
        raise Refused("the owner's pin of the receiving machine's key is dated after now, so the login is not handed "
                      "over")


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
PROVIDER_KEY_SITES = ("platform.claude.com", "api.x.ai")   # an API console or a paid API under one of them: a key
                                                            # read there stays allowed (api.x.ai: the AI providers build)


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


def login_shaped(value):
    """True for a stored item with a user name or an authenticator seed, of any type: the shape of a login. The owner's
    choice C11 of 13 November 2026 keeps such an item out of a session (`read`, and the proxy's `swap_value`). A field
    that is there and not empty counts, whatever its type, so that no later writer opens a gap with a user name that is
    not a string. A login that was saved with no user name and no seed has the shape of a key, and this cannot tell."""
    try:
        item = json.loads(value)
    except (ValueError, TypeError):
        return False
    return isinstance(item, dict) and any(item.get(k) not in (None, "") for k in ("username", "totp"))


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
    owner_keys_held(conf)               # a vault that hands nothing over must not use up the job either
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
    logins = []             # C11: (variable, reference) of each value that has the shape of a login: none is given
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
            if conf.get("_swaps") is None or type(uid) is not int or not site or not swap_form(form, full=True) \
                    or not (isinstance(token, str) and SWAP_TOKEN.fullmatch(token)):
                missing.append(name)
                continue
        try:
            stored = store.item(SECRET_REF.fullmatch(ref).group(1))["value"]
            if login_shaped(stored):
                # C11: a login's value never reaches a session, as itself or as a placeholder. Its reference leaves
                # `named`, so `Swaps.only` drops a placeholder that an earlier read made. This rule is for a session's
                # read and the swap way only: a login that an agent holds as "Uses it" goes through `send` (call_api)
                # as before.
                named.discard(ref.lower())
                logins.append((name, ref.lower()))
                missing.append(name)
                continue
            value = check_value(stored)
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
    log(f"a session read of {conf['agent']} left out {len(logins)} value(s) with a user name or an authenticator seed"
        + (f": {', '.join(ref for _, ref in logins)}" if logins else ""))   # a reference opens nothing
    # `missing` names each variable that the session does not get, as before; `logins`, only when there is one, names
    # those of them that C11 left out, so an answer with no login keeps its shape for an older helper
    reply = {"ok": True, "v": PROTOCOL, "env": env, "missing": missing}
    if logins:
        reply["logins"] = [name for name, _ in logins]
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
    vault of the fleet, and the answer holds no part of it.

    replaces: the hub's word, in its answer for this delivery and never in the helper's request, that the owner
    replaced the value of this reference. Then the value goes into the place of the one that an earlier delivery
    saved here (LocalStore.put), and the answer says "replaced". The key swap needs nothing more: its proxy reads the
    store at each use, so the next request of a session carries the new value under the same placeholder."""
    store = LocalStore(conf)            # a store that does not open refuses before the hub gives the copy
    read_private(conf["age_key"], "handover key")
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}", {"job": number, "kind": "deposit"})
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("job") != number \
            or data.get("kind") != "deposit":
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not give this delivery" + (f": {reason}" if isinstance(reason, str) else ""))
    ref, title, item, text, salts = (data.get(k) for k in ("login", "title", "item", "ciphertext", "fingerprint_salts"))
    replaces = data.get("replaces") is True     # the hub's word in this answer: the owner replaced this value
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
                                                            ensure_ascii=False), DELIVERED, replace=replaces)
    log(f"deposit job={number}: {ref.lower()} {saved}")
    swap_given(conf, ref.lower())
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
    swap_taken(conf, ref.lower())
    return {"ok": True, "v": PROTOCOL, "withdrawal": number, "login": ref.lower(), "removed": removed}


# ---------------------------------------------------------------- the sign-in on a Linux server (plan 04, S5)
# On a Linux server an agent's browser is its own Chrome (plan 04, S2). It listens for DevTools on 127.0.0.1 and the
# agent's port of root's ports file, where the fleet's table (D11) lets in only the agent's user, this broker's user and
# root. The broker fills a sign-in form there as the Mac's vault helper fills one in the owner's Chrome
# (VaultBrowser.swift): the page's origin and the form's action are checked in the page, in the same script that fills.
# Its scripts run in a world of their own and reach the DOM only through that world's prototypes, so neither a script
# nor the markup of the page changes what they read. The agent gets only the outcome. The broker records the origins of
# the sign-in's top-level pages and the cookies of other sites that the sign-in created (their names, never a value);
# the hub keeps them with the agent's use of the login, and when that use ends it has the agent's helper clear them in
# that browser (S2's clear, hub signin_clear_sweep). What an agent's own programs can still reach in its own browser is
# in VAULT.md (item 26).

SIGNIN_PORTS = "/etc/fleet-browser/ports"       # root's file: one line <user> <DevTools port> <screen-sharing port>
SIGNIN_STEP = 20.0          # seconds that one step of a sign-in (a submit, a code) waits for its page at most
SIGNIN_TICK = 1.0           # seconds between two looks at a page that changes with no event (a page of scripts)
SIGNIN_QUIET = 2.0          # seconds with no new top-level page, document request or load before a page's state counts
SIGNIN_FIRST_LOOK = 3.0     # seconds after a submit before the first look, which wipes the fields: as the Mac's one look
SIGNIN_TOTAL = 60.0         # seconds for the whole fill in the browser: below the helper's wait for the broker (90)
SIGNIN_TABS = 3             # the most tabs of the login's origin that a fill tries
SIGNIN_CLEANUP = 5.0        # seconds that the clean-up of a fill has, also after the whole fill's time ran out
SIGNIN_OTP = ("input[autocomplete=one-time-code],input[name*=otp i],input[id*=otp i],input[name=code],"
              "input[id=code]")             # VaultBrowser.otpSelector
SIGNIN_ORIGINS, SIGNIN_COOKIES = 50, 200    # the most that one record names (lifecycle.browser_clear_valid)
# lifecycle.BROWSER_HOST: a host that a clear can name (a DNS name or an IPv4 address, in lower case)
SIGNIN_HOST = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*")
SIGNIN_EVENTS = ("Page.frameNavigated", "Page.loadEventFired", "Page.navigatedWithinDocument",
                 "Network.requestWillBeSent")       # the events that signin_settle reads; no other is kept
SIGNIN_KEPT = 1 << 22       # bytes of such events that a connection keeps between two waits, each 1 KiB at least
SIGNIN_EVENT = 1 << 10      # what one kept event counts at least: a flood of small events holds 4096 at most
SIGNING = set()             # the uids whose sign-in runs now, while the broker's lock is free (signin)


def signin_port(user, path=None):
    """The DevTools port of this OS user by root's ports file (D11), or a refusal: the file must be a plain file of
    root's that only root writes, and the user's line of the contract's form."""
    try:
        fd = os.open(SIGNIN_PORTS if path is None else path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused("this server has no browser of an agent (no ports file)") from None
    with os.fdopen(fd, encoding="ascii", errors="replace") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("the browsers' ports file is not root's own, so it names no port")
        text = f.read(1 << 20)
    for line in text.split("\n"):
        parts = line.split(" ")
        if len(parts) == 3 and parts[0] == user and re.fullmatch(r"93[0-9]{2}", parts[1]):
            return int(parts[1])
    raise Refused("this agent has no browser port on this server")


def signin_sockets(match, tables=None):
    """The uids of the sockets of the kernel's own whole lists (IPv4 and IPv6) whose row `match` takes. A list that
    cannot be read adds a uid of -1, which no agent has; a kernel with no IPv6 has no such socket either."""
    uids = set()
    for path, _six in SWAP_TABLES if tables is None else tables:
        try:
            with open(path, encoding="ascii") as f:
                next(f, None)               # its head line
                for line in f:
                    row = line.split()
                    if len(row) > 7 and match(row):
                        uids.add(int(row[7]))
        except FileNotFoundError:
            continue
        except (OSError, ValueError, UnicodeDecodeError):
            uids.add(-1)
    return uids


def signin_listeners(port, tables=None):
    """The uids of every socket that listens on this TCP port, on any address (a dual-stack socket on [::] takes
    connections to 127.0.0.1 too)."""
    return signin_sockets(lambda row: row[3] == "0A" and row[1].rpartition(":")[2] == f"{port:04X}", tables)


def signin_peer(port, local, tables=None):
    """The uids of the sockets whose own port is `port` and whose other end is this broker's port `local`: on
    loopback, the far end of the broker's own connection (in the IPv4 list, or in the IPv6 one as a mapped address)."""
    return signin_sockets(lambda row: row[1].rpartition(":")[2] == f"{port:04X}" and
                          row[2].rpartition(":")[2] == f"{local:04X}", tables)


class SigninCdp:
    """**A DevTools connection to one agent's own Chrome** on 127.0.0.1:<port>, only where each socket that listens on
    that port is of the agent's uid, and only where the far end of the connection is of it too (D11: another user's
    answer proves nothing and gets no fill). One call at a time; the events that signin_settle reads, up to SIGNIN_KEPT
    bytes, are kept for `wait`. Every read has an end, and `limit` (monotonic) ends them all: a peer that sends a byte
    now and then holds nobody past it. Raises Refused. (fleet.Cdp is the helper's copy of this client.)"""

    MOST = 1 << 23          # the largest message that it reads, 8 MiB

    def __init__(self, port, uid, timeout=10.0, tables=None, limit=None):
        self.timeout, self.limit, self.last, self.rest, self.events, self.kept, self.size = \
            timeout, limit, 0, b"", [], 0, 0
        if signin_listeners(port, tables) != {uid}:
            raise Refused(f"no browser of this agent alone listens on its port {port}: start its browser task first")
        end = self.end(timeout)
        try:
            path = urllib.parse.urlsplit(self.version(port, end)["webSocketDebuggerUrl"]).path
        except (KeyError, TypeError, ValueError, AttributeError, OSError) as e:
            raise Refused(f"the agent's browser gave no DevTools address ({type(e).__name__})") from None
        if not re.fullmatch(r"/devtools/browser/[A-Za-z0-9-]{1,64}", path):
            raise Refused("the agent's browser gave no DevTools address of Chrome's own form")
        try:
            self.sock = socket.create_connection(("127.0.0.1", port), timeout=max(0.1, end - time.monotonic()))
        except OSError as e:
            raise Refused(f"the agent's browser took no DevTools connection: {e}") from None
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
                               ).encode())
            while b"\r\n\r\n" not in self.rest:
                part = self.recv(end)
                if not part or len(self.rest) > 65536:
                    raise Refused("the agent's browser ended the DevTools connection at its start")
                self.rest += part
            head, self.rest = self.rest.split(b"\r\n\r\n", 1)
            if b" 101 " not in head.split(b"\r\n", 1)[0]:
                raise Refused("the agent's browser refused the DevTools connection")
            if signin_peer(port, self.sock.getsockname()[1], tables) != {uid}:
                raise Refused(f"the far end of the connection to port {port} is not this agent's browser")
        except BaseException:
            self.sock.close()
            raise

    def end(self, seconds):
        """When a read that may take `seconds` ends: never after the whole fill's limit."""
        end = time.monotonic() + seconds
        return end if self.limit is None else min(end, self.limit)

    @staticmethod
    def version(port, end):
        """Chrome's /json/version, by HTTP on a socket of its own and before `end`, at most 64 KiB."""
        with socket.create_connection(("127.0.0.1", port), timeout=max(0.1, end - time.monotonic())) as sock:
            sock.sendall(f"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
            said, length = b"", None
            while length is None or len(said.partition(b"\r\n\r\n")[2]) < length:
                left = end - time.monotonic()
                if left <= 0:
                    raise OSError("no answer in time")
                sock.settimeout(left)
                part = sock.recv(1 << 16)
                if not part:
                    break
                said += part
                if len(said) > 1 << 16:
                    raise ValueError("an answer above 64 KiB")
                head, cut, _ = said.partition(b"\r\n\r\n")
                found = re.search(rb"(?im)^content-length:[ \t]*([0-9]{1,6})[ \t]*\r?$", head) if cut else None
                length = int(found.group(1)) if found else length
        head, cut, body = said.partition(b"\r\n\r\n")
        if not cut or not re.match(rb"HTTP/1\.[01] 200 ", head):
            raise ValueError("no address")
        return json.loads(body[:length] if length is not None else body)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.sock.close()

    def recv(self, end):
        left = end - time.monotonic()
        if left <= 0:
            raise Refused("the sign-in ran out of its time in the agent's browser"
                          if self.limit is not None and time.monotonic() >= self.limit else
                          "the agent's browser did not answer in time")
        self.sock.settimeout(left)
        try:
            return self.sock.recv(1 << 16)
        except (TimeoutError, socket.timeout):
            raise Refused("the agent's browser did not answer in time") from None
        except OSError as e:
            raise Refused(f"the DevTools connection to the agent's browser failed: {e}") from None

    def send(self, message, opcode=0x1):
        data = message if isinstance(message, bytes) else json.dumps(message).encode()
        size, mask = len(data), os.urandom(4)
        length = bytes([0x80 | size]) if size < 126 else bytes([0x80 | 126]) + size.to_bytes(2, "big") \
            if size < 65536 else bytes([0x80 | 127]) + size.to_bytes(8, "big")
        try:
            self.sock.sendall(bytes([0x80 | opcode]) + length + mask +
                              bytes(b ^ mask[i % 4] for i, b in enumerate(data)))
        except OSError as e:
            raise Refused(f"the DevTools connection to the agent's browser failed: {e}") from None

    def take(self, n, end):
        while len(self.rest) < n:
            part = self.recv(end)
            if not part:
                raise Refused("the agent's browser ended the DevTools connection")
            self.rest += part
        data, self.rest = self.rest[:n], self.rest[n:]
        return data

    def message(self, end):
        """Chrome's next whole message; its first bytes before `end`, and a message that began is read whole within a
        call's own time, so that the connection never stops in the middle of one. A ping gets its pong."""
        parts = []
        while True:
            first, second = self.take(2, end)
            end = max(end, self.end(self.timeout))
            size = second & 0x7F
            if size >= 126:
                size = int.from_bytes(self.take(2 if size == 126 else 8, end), "big")
            if size + sum(map(len, parts)) > self.MOST:
                raise Refused("a DevTools message above 8 MiB")
            mask = self.take(4, end) if second & 0x80 else None
            data = self.take(size, end)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            opcode = first & 0x0F
            if opcode == 0x8:
                raise Refused("the agent's browser ended the DevTools connection")
            if opcode == 0x9:
                self.send(data, 0xA)
            elif opcode != 0xA:
                parts.append(data)
                if first & 0x80:
                    self.size = sum(map(len, parts))
                    try:
                        return json.loads(b"".join(parts))
                    except ValueError:
                        raise Refused("the agent's browser sent a DevTools message that is not JSON") from None

    def keep(self, event):
        """An event that signin_settle reads (a document request of a frame, a navigation, a load), with only the
        fields that it reads, while the kept events stay under SIGNIN_KEPT bytes on the connection; every other
        message goes."""
        params = event.get("params") if isinstance(event, dict) and isinstance(event.get("params"), dict) else {}
        size = max(self.size, SIGNIN_EVENT)
        if not isinstance(event, dict) or event.get("method") not in SIGNIN_EVENTS or \
                self.kept + size > SIGNIN_KEPT or \
                event["method"] == "Network.requestWillBeSent" and params.get("type") != "Document":
            return
        frame = params.get("frame") if isinstance(params.get("frame"), dict) else {}
        request = params.get("request") if isinstance(params.get("request"), dict) else {}
        text = lambda v: v[:8192] if isinstance(v, str) else None
        self.events.append({"method": event["method"], "sessionId": text(event.get("sessionId")),
                            "params": {"type": text(params.get("type")), "frameId": text(params.get("frameId")),
                                       "request": {"url": text(request.get("url"))},
                                       "frame": {"id": text(frame.get("id")), "url": text(frame.get("url")),
                                                 "parentId": text(frame.get("parentId"))}}})
        self.kept += size

    def call(self, method, params=None, session=None):
        """The result of one DevTools call; Refused for an error of Chrome's, and with nothing sent once the whole
        fill's time ran out."""
        if self.limit is not None and time.monotonic() >= self.limit:
            raise Refused("the sign-in ran out of its time in the agent's browser")
        self.last += 1
        end = self.end(self.timeout)
        self.send({"id": self.last, "method": method, "params": params or {},
                   **({"sessionId": session} if session else {})})
        while True:
            answer = self.message(end)
            if isinstance(answer, dict) and answer.get("id") == self.last:
                if "error" in answer:
                    raise Refused(f"the agent's browser refused {method}: "
                                  f"{str((answer['error'] or {}).get('message'))[:200]}")
                result = answer.get("result")
                return result if isinstance(result, dict) else {}
            self.keep(answer)

    def wait(self, end):
        """The events that came since the last wait, and then each new one until `end`, as they come: an iterator."""
        end = end if self.limit is None else min(end, self.limit)
        while True:
            while self.events:
                event = self.events.pop(0)
                self.kept = 0 if not self.events else self.kept
                yield event
            try:
                if end - time.monotonic() <= 0:
                    return
                self.keep(self.message(end))
            except Refused:
                if time.monotonic() >= end:
                    return
                raise


class signin_free:
    """`with signin_free(conf):` the broker's lock is free while the agent's browser works (as a request's curl child
    runs with it free), so that every other agent's vault calls go on meanwhile."""

    def __init__(self, conf):
        self.lock = conf.get("_lock")

    def __enter__(self):
        if self.lock is not None:
            self.lock.release()

    def __exit__(self, *_):
        if self.lock is not None:
            self.lock.acquire()


def signin_origin(url):
    """The origin of a login's address as a page's location.origin says it: scheme://host[:port], with no default
    port."""
    parts = urllib.parse.urlsplit(url)
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    port = parts.port
    return f"{scheme}://{host}" + (f":{port}" if port and port != {"http": 80, "https": 443}.get(scheme) else "")


# The scripts' helpers are VaultBrowser.dom of the Mac's Fleet Vault, byte for byte (test_vault_signin holds it, and
# the Mac's VaultBrowserFlowTests run them in a stand-in page): each reaches the DOM only through the prototypes of its
# own world, which a page's markup cannot shadow by a name (<input name="action">, <img name="querySelector">). `read` a
# getter, `$` and `$$` a query, `form` the form of an HTML field (none for an `input` inside `<svg>`), `own` the first
# field of the form itself (through its elements, also one that form= ties to it), `away` a form's action off the
# page's origin, `post` a GET form and its buttons made to send by POST (a formaction to another origin goes), `send`
# the submit with the vault's own submitter, a GET submit that only the page could make held, and the secret wiped
# after it (at pagehide when the page sends it itself), `set` a value with the events that a framework listens to,
# `secret` a secret only into a field of a kind that takes one, with no pattern, min, max, step or dir, made readonly
# (no validity, so no `:valid` or `:user-valid` rule matches it) and with a fixed style, which it reads back from the
# computed style with a throwaway value in the field before it types (a shadow root's `::slotted` rule with
# `!important` beats an inline style: Fleet Vault 0.3.17, b9dfa593), and `wipe` the emptying of such a field, which
# takes readonly away again. `valid` reads each field's validity through the prototypes, so that `send` submits no
# form that checks its fields (no `novalidate`) while one of them is not valid: the browser would lay the page out
# and focus that field while the secret is in its own field. `closes` reads whether the nearest HTML dialog around a
# dialog form is open, the only case that sends (Fleet Vault 0.3.18, 12553a04). The gaps that the Mac's `dom`
# comment names as not closed hold here too: a `::slotted` rule whose condition comes true after the look, while the
# secret stays in the page (a handler of the page took the submit, or a dialog form), can still give a password's
# length or a code's digits.
SIGNIN_DOM = ("const D=Document.prototype,E=Element.prototype,F=HTMLFormElement.prototype,I=HTMLInputElement.prototyp"
              "e,N=Node.prototype,T=EventTarget.prototype,V=Event.prototype;const read=(P,n,o)=>Object.getOwnProperty"
              "Descriptor(P,n).get.call(o),$=(n,s)=>(n===document?D:E).querySelector.call(n,s),$$=s=>D.querySelectorA"
              "ll.call(document,s),form=e=>e instanceof HTMLInputElement?read(I,'form',e):null,own=(f,s)"
              "=>{const c=read(F,'elements',f);for(let i=0;i<c.length;i++)if(E.matches.call(c[i],s))return c[i];"
              "return null},away=f=>{try{return new URL(read(F,'action',f)).origin!==location.origin}catch("
              "x){return true}},post=f=>{const g=read(F,'method',f)==='get';if(g)E.setAttribute.call(f,"
              "'method','post');const c=$$('button,input');for(let i=0;i<c.length;i++){const b=c[i],P=b instanceof HT"
              "MLButtonElement?HTMLButtonElement.prototype:b instanceof HTMLInputElement?I:null;if(!P||read("
              "P,'form',b)!==f)continue;if(E.hasAttribute.call(b,'formmethod')&&read(P,'formMethod',b)==='get')"
              "E.setAttribute.call(b,'formmethod','post');if(E.hasAttribute.call(b,'formaction')){let o=null;"
              "try{o=new URL(read(P,'formAction',b)).origin}catch(x){}if(o!==location.origin)E.removeAttribute.call("
              "b,'formaction')}}return g},closes=f=>{for(let a=read(N,'parentElement',f);a;a=read(N,'parentElement',"
              "a))if(a instanceof HTMLDialogElement)return read(HTMLDialogElement.prototype,'open',a);return false}"
              ",valid=f=>{const c=read(F,'elements',f);for(let i=0;i<c.length;i++){const x=c[i],P=x instanceof HTMLIn"
              "putElement?I:x instanceof HTMLSelectElement?HTMLSelectElement.prototype:x instanceof HTMLTextAreaEleme"
              "nt?HTMLTextAreaElement.prototype:x instanceof HTMLButtonElement?HTMLButtonElement.prototype:null;"
              "if(P&&read(P,'willValidate',x)&&!read(ValidityState.prototype,'valid',read(P,'validity',"
              "x)))return false}return true},send=(f,e,get)=>{if(!read(F,'noValidate',f)&&!valid(f)){wipe("
              "e);return false}const open=closes(f);let b=null,ev=null,held=false;if(get){b=D.createElement.call("
              "document,'button');E.setAttribute.call(b,'type','submit');E.setAttribute.call(b,'formmethod',"
              "'post');E.setAttribute.call(b,'hidden','');N.appendChild.call(f,b)}const c=x=>{if(read(V,"
              "'target',x)===f)ev=x},h=x=>{if(read(V,'target',x)===f&&!read(V,'defaultPrevented',x)&&get)"
              "{V.preventDefault.call(x);held=true}};T.addEventListener.call(window,'submit',c,true);T.addEventListen"
              "er.call(window,'submit',h);try{F.requestSubmit.call(f,b)}catch(x){ev=null}finally{T.removeEventListene"
              "r.call(window,'submit',c,true);T.removeEventListener.call(window,'submit',h);if(b)E.remove.call("
              "b)}const took=!!ev&&read(V,'defaultPrevented',ev),dialog=read(F,'method',f)==='dialog',went=!!ev&&!hel"
              "d&&(took||!dialog||open),page=went&&(took||dialog);if(page)T.addEventListener.call(window,"
              "'pagehide',()=>wipe(e),{once:true});else wipe(e);return went},set=(e,v)=>{Object.getOwnPropertyDescrip"
              "tor(I,'value').set.call(e,v);const q=x=>{V.preventDefault.call(x);V.stopImmediatePropagation.call("
              "x)};T.addEventListener.call(window,'submit',q,true);try{T.dispatchEvent.call(e,new Event("
              "'input',{bubbles:true}));T.dispatchEvent.call(e,new Event('change',{bubbles:true}))}finally{"
              "T.removeEventListener.call(window,'submit',q,true)}},fits=e=>e instanceof HTMLInputElement&&['text',"
              "'tel','password','number'].includes(read(I,'type',e)),secret=(e,v)=>{if(!fits(e))return false;"
              "['pattern','min','max','step','dir'].forEach(n=>E.removeAttribute.call(e,n));E.setAttribute.call("
              "e,'readonly','');const s=read(HTMLElement.prototype,'style',e),C=CSSStyleDeclaration.prototype,"
              "u=Object.getOwnPropertyDescriptor(I,'value').set,w=[['field-sizing','fixed'],['-webkit-text-security',"
              "'disc'],['transition','none'],['animation','none']];w.forEach(([n,x])=>C.setProperty.call("
              "s,n,x,'important'));u.call(e,'1');const k=getComputedStyle(e),beaten=[['field-sizing','fixed'],"
              "['-webkit-text-security','disc'],['transition-property','none'],['animation-name','none']].some("
              "([n,x])=>{const y=C.getPropertyValue.call(k,n);return y!==''&&y!==x});u.call(e,'');if(beaten)"
              "{E.removeAttribute.call(e,'readonly');return false}set(e,v);return true},wipe=e=>{if(fits("
              "e)){set(e,'');E.removeAttribute.call(e,'readonly')}};")


def signin_fill(origin, login):
    """VaultBrowser.fillScript: the user name and the password into the form of the page's password field, and its
    submit, only on the login's origin and only for a form whose answer goes to that origin. The user name goes into
    the first user field of that form itself (`own`). The origin and the action are read again just before the submit,
    because the page's own listeners of the input events run between."""
    return ("(()=>{" + SIGNIN_DOM + "if(location.origin!==%s)return 'wrong-origin';"
            "const p=$(document,'input[type=password]');const f=p&&form(p);if(!f)return 'no-form';"
            "if(away(f))return 'wrong-action';const g=post(f),u=own(f,'input[type=email],input[type=text],"
            "input:not([type])');if(u)set(u,%s);if(!secret(p,%s))return 'bad-field';"
            "if(away(f)||location.origin!==%s){wipe(p);return 'moved';}return send(f,p,g)?'filled':'not-sent';})()"
            % (json.dumps(origin), json.dumps(login.get("username", "")), json.dumps(login["password"]),
               json.dumps(origin)))


def signin_check(origin):
    """VaultBrowser.checkScript: `form` while a password field is there, `otp` on a code page, `loading` before the
    page has its fields, `none` when the sign-in went through. A password or a code that is still in the page after
    its submit (a page that did not go) is wiped, so that no later click of the page sends it."""
    return ("(()=>{" + SIGNIN_DOM + "if(location.origin!==%s)return 'wrong-origin';"
            "const p=$(document,'input[type=password]'),k=$(document,%s);wipe(p);wipe(k);"
            "return p?'form':k?'otp':read(D,'readyState',document)==='loading'?'loading':'none';})()"
            % (json.dumps(origin), json.dumps(SIGNIN_OTP)))


def signin_code(origin, code):
    """VaultBrowser.otpScript: the authenticator code into the code field's form, and its submit, with the same checks
    as the fill."""
    return ("(()=>{" + SIGNIN_DOM + "if(location.origin!==%s)return 'wrong-origin';"
            "const e=$(document,%s);const f=e&&form(e);if(!f)return 'no-form';"
            "if(away(f))return 'wrong-action';const g=post(f);if(!secret(e,%s))return 'bad-field';"
            "if(away(f)||location.origin!==%s){wipe(e);return 'moved';}return send(f,e,g)?'filled':'not-sent';})()"
            % (json.dumps(origin), json.dumps(SIGNIN_OTP), json.dumps(code), json.dumps(origin)))


# A sign-in that is not confirmed: each password and code field of the page is emptied, with the events that a page's
# framework listens to, so that no field and no state of the page keeps what the vault typed for the agent's tools
SIGNIN_EMPTY = ("(()=>{" + SIGNIN_DOM + "$$(%s).forEach(x=>wipe(x));return 'emptied';})()"
                % json.dumps("input[type=password]," + SIGNIN_OTP))


def totp_now(seed, at=None):
    """An RFC 6238 authenticator code from a base32 seed or an otpauth:// URI (fleet.totp_code's rule)."""
    digits, period, algorithm = 6, 30, "sha1"
    if seed.startswith("otpauth://"):
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(seed).query))
        seed = params.get("secret", "")
        try:
            digits, period = int(params.get("digits", 6)), int(params.get("period", 30))
        except ValueError:
            raise Refused("the login's authenticator settings are not supported") from None
        algorithm = params.get("algorithm", "SHA1").lower()
    if algorithm not in ("sha1", "sha256", "sha512") or not 6 <= digits <= 8 or not 1 <= period <= 300:
        raise Refused("the login's authenticator settings are not supported")
    seed = re.sub(r"[\s=-]", "", seed).upper()
    try:
        key = base64.b32decode(seed + "=" * (-len(seed) % 8))
    except ValueError:
        key = b""
    if not key:
        raise Refused("the login's authenticator seed is not base32")
    mac = hmac.new(key, struct.pack(">Q", int((time.time() if at is None else at) // period)),
                   getattr(hashlib, algorithm)).digest()
    offset = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def signin_run(cdp, session, script):
    """One script in the page's main frame, in a world of the vault's own: its answer, or None where the page went
    away under it (a navigation in between). A new world for each run: a navigation ends the old one."""
    try:
        frame = (((cdp.call("Page.getFrameTree", session=session).get("frameTree") or {}).get("frame")) or {}).get("id")
        world = cdp.call("Page.createIsolatedWorld", {"frameId": frame, "worldName": "fleet-vault"},
                         session=session).get("executionContextId")
        said = cdp.call("Runtime.evaluate", {"expression": script, "contextId": world, "returnByValue": True},
                        session=session)
    except Refused:
        return None
    value = (said.get("result") or {}).get("value") if not said.get("exceptionDetails") else None
    return value if isinstance(value, str) else None


def signin_saw(seen, url):
    """The origin of a top-level page's address into `seen`: http and https only, at most SIGNIN_ORIGINS."""
    if isinstance(url, str) and url.split(":", 1)[0].lower() in ("http", "https") and len(seen) < SIGNIN_ORIGINS:
        try:
            seen.add(signin_origin(url))
        except ValueError:
            pass


def signin_settle(cdp, session, frame, origin, seen, step=SIGNIN_STEP, tick=SIGNIN_TICK, quiet=SIGNIN_QUIET,
                  first=SIGNIN_FIRST_LOOK, watch=None):
    """After a submit: the page's state by signin_check once the tab has been quiet for `quiet` seconds (no new
    top-level page, no document request of its main frame, no load, no same-page navigation of its main frame):
    `none`, `otp`, `wrong-origin` (a sign-in that ends on another site), or `form` on a page that loaded after a new
    top-level page (the site gave its form back). Else the last state when `step` runs out, or the whole fill's
    limit. It reads the tab's events as they come and looks at the page once each `tick`, but not before `first`
    seconds after the submit: each look wipes a password or a code that is still in the page (signin_check), and a
    page's own handler may still read its field until then, as the Mac's one look comes 3 s after the submit. Each
    top-level page that the tab goes to, each redirect on the way too, goes into `seen`: a single sign-on page that
    comes after the landing page also, while the tab is not quiet yet. `watch`, a dict, gets `navigated`: whether a
    new top-level page came after the submit (the form went), also one that has not loaded yet."""
    end, last, navigated, loaded = time.monotonic() + step, time.monotonic(), False, False
    look = time.monotonic() + first
    if getattr(cdp, "limit", None) is not None:
        end = min(end, cdp.limit)           # the whole fill's time: no look that would only meet the limit
    while True:
        for event in cdp.wait(min(end, time.monotonic() + tick)):
            params = event.get("params") if isinstance(event.get("params"), dict) else {}
            if event.get("sessionId") != session:
                continue
            method = event.get("method")
            if method == "Page.frameNavigated" and not (params.get("frame") or {}).get("parentId"):
                signin_saw(seen, (params.get("frame") or {}).get("url"))
                navigated, last = True, time.monotonic()
            elif method == "Network.requestWillBeSent" and params.get("type") == "Document" and \
                    params.get("frameId") == frame:
                signin_saw(seen, (params.get("request") or {}).get("url"))
                last = time.monotonic()
            elif method == "Page.loadEventFired":
                loaded, last = loaded or navigated, time.monotonic()
            elif method == "Page.navigatedWithinDocument" and params.get("frameId") == frame:
                last = time.monotonic()     # the main frame's own history; a widget's frame keeps nothing open
        if time.monotonic() < min(look, end):
            continue
        state = signin_run(cdp, session, signin_check(origin))
        settled = state in ("none", "otp", "wrong-origin") or state == "form" and loaded
        if settled and time.monotonic() - last >= quiet or time.monotonic() >= end:
            if watch is not None:
                watch["navigated"] = navigated
            return state


def signin_cookies(cdp):
    """Every cookie of the agent's browser, as Chrome lists them (S2: Storage.getCookies answers on the browser)."""
    cookies = cdp.call("Storage.getCookies").get("cookies")
    return [c for c in cookies if isinstance(c, dict)] if isinstance(cookies, list) else []


def signin_host(host):
    """A host that a clear can name (lifecycle.browser_clear_valid): not an IPv6 address, no dot at its end."""
    return isinstance(host, str) and bool(SIGNIN_HOST.fullmatch(host))


def signin_record(seen, before, after):
    """What the hub keeps for the clear at the end of the login's use (lifecycle.browser_clear_valid): the origins of
    the sign-in's top-level pages, and each cookie that the sign-in created on a domain of none of them (embedded
    content), by its name, its domain, its path and its partition; never a value. A cookie that was there before stays
    out, also with a new value: it is of another session of that site (plan 04, round 11). A domain of a top-level page
    loses all its cookies at the clear anyway. An entry that the rule would refuse stays out, so that the rest gets
    through: an IPv6 host, a host with a dot at its end, a cookie with no name."""
    key = lambda c: (c.get("name"), c.get("domain"), c.get("path"), json.dumps(c.get("partitionKey"), sort_keys=True))
    old = {key(c) for c in before}
    origins = sorted(o for o in seen if signin_host(urllib.parse.urlsplit(o).hostname or ""))
    hosts = {urllib.parse.urlsplit(o).hostname for o in origins}
    made = []
    for c in after:
        name, domain = c.get("name"), str(c.get("domain") or "").lower()
        path, part = c.get("path"), c.get("partitionKey")
        bare = domain.removeprefix(".")
        site = part.get("topLevelSite") if isinstance(part, dict) else None
        if key(c) in old or not (isinstance(name, str) and 0 < len(name) <= 4096) or not signin_host(bare) or \
                any(h == bare or h.endswith("." + bare) for h in hosts) or \
                not (path is None or isinstance(path, str) and path.startswith("/") and len(path) <= 4096) or \
                not (site is None or isinstance(site, str) and 0 < len(site) <= 4096):
            continue
        made.append(dict({"name": name, "domain": domain}, **({"path": path} if path is not None else {}),
                         **({"partitionKey": {"topLevelSite": site}} if site is not None else {})))
    return {"origins": origins[:SIGNIN_ORIGINS], "cookies": made[:SIGNIN_COOKIES]}


def signin_page(cdp, login, code=None, keep=None, step=SIGNIN_STEP, tick=SIGNIN_TICK, quiet=SIGNIN_QUIET,
                first=SIGNIN_FIRST_LOOK):
    """**The fill in the agent's own Chrome**, as VaultBrowser.signIn fills in the owner's: in the first of at most
    SIGNIN_TABS tabs of the login's origin whose page takes the fill (a `not-sent` or a fill with no answer ends the
    search: no later tab gets the secret), the user name and the password and their submit;
    then, where the site asks for one and the login has a seed, the authenticator code (`code()` makes it now). Once it
    typed: a sign-in that is not confirmed, also one that an error ends, empties each password and code field of its
    page, and `keep` gets the record (signin_record) in each case. A tab whose fill stopped after it may have typed is
    emptied too. After a fill or a code that answered `not-sent` (a listener of the page can hide a submit that went)
    or nothing (the fill can still run in the page), the broker watches that tab as after a submit, so that a sign-in
    that went is taken and its record kept, and types into no other tab; a watch that ends on a code page or on
    another site, or after a new page came, shows that the form went, and ends as a fill that went. Returns (signed
    in, with a code)."""
    origin = signin_origin(login["url"])
    before = signin_cookies(cdp)
    tabs = [t for t in cdp.call("Target.getTargets").get("targetInfos") or []
            if isinstance(t, dict) and t.get("type") == "page" and str(t.get("url") or "").startswith(origin + "/")]
    if not tabs:
        raise Refused(f"no tab of the agent's browser shows {origin}: open the site's sign-in page there first, then "
                      f"ask again")
    session = frame = state = said = None
    seen, with_code, said_all, coded = {origin}, False, set(), ""
    try:
        for tab in tabs[:SIGNIN_TABS]:
            session = cdp.call("Target.attachToTarget", {"targetId": tab.get("targetId"), "flatten": True}).get(
                "sessionId")
            cdp.call("Page.enable", session=session)
            cdp.call("Network.enable", session=session)
            frame = (((cdp.call("Page.getFrameTree", session=session).get("frameTree") or {}).get("frame")) or {}).get(
                "id")
            said = signin_run(cdp, session, signin_fill(origin, login))
            said_all.add(said)
            if said in ("filled", "not-sent", None):
                break       # a submit that a page's listener hid, or a fill with no answer, can still send the
                #             password: the broker watches this tab, and no second tab gets it
            if said not in ("wrong-origin", "no-form", "wrong-action"):
                signin_run(cdp, session, SIGNIN_EMPTY)          # it may have typed before it stopped
            cdp.call("Target.detachFromTarget", {"sessionId": session})
            session = None
        if session is None:
            if "bad-field" in said_all:
                raise Refused(f"the sign-in form on {origin} has a password field that the vault types no secret "
                              f"into: the page's style takes back its size or its glyphs, or puts a transition or an "
                              f"animation on it")
            raise Refused(f"no tab on {origin} shows a sign-in form whose answer goes to {origin}")
        watch = {}
        state = signin_settle(cdp, session, frame, origin, seen, step, tick, quiet, first, watch)
        if state == "otp" and code is not None:
            coded = signin_run(cdp, session, signin_code(origin, code()))
            if coded == "bad-field":
                raise Refused(f"the code page on {origin} has a code field that the vault types no code into: it takes "
                              f"no code, or the page's style takes back its size or its glyphs, or puts a transition "
                              f"or an animation on it")
            if coded in ("filled", "not-sent", None):       # as at the fill: a code that can have gone is watched
                with_code = coded in ("filled", "not-sent")
                state = signin_settle(cdp, session, frame, origin, seen, step, tick, quiet, first)
        if state != "none" and state != "wrong-origin":    # on another site the form went: signin's own words
            if coded == "not-sent":
                raise Refused(f"the code form on {origin} sent nothing that the vault saw: it sends by GET in the "
                              f"page's address, a field of it is not valid, it is a dialog form with no HTML dialog "
                              f"around it or whose nearest one is not open, or a listener of the page stopped its "
                              f"submit or hid it from the vault, and then the code can have gone to {origin}")
            if coded is None:
                raise Refused(f"the code page on {origin} gave the vault no answer, and the page did not sign in after "
                              f"it")
            went = state == "otp" or watch.get("navigated")   # a code page, or a new page: the form went
            if coded == "" and said == "not-sent" and not went:
                raise Refused(f"the sign-in form on {origin} sent nothing that the vault saw: it sends by GET in the "
                              f"page's address, a field of it is not valid (required and empty, or refused by its type "
                              f"or pattern), it is a dialog form with no HTML dialog around it or whose nearest one "
                              f"is not open, or a listener of the page stopped its submit or hid it from the vault, "
                              f"and then the form can have gone to {origin}. "
                              f"The vault typed into no other tab: close this page and ask again to use another one")
            if coded == "" and said is None and not went:
                raise Refused(f"the sign-in form on {origin} gave the vault no answer, and the page did not sign in "
                              f"after it; the vault typed into no other tab")
    finally:
        if session is not None:
            if getattr(cdp, "limit", None) is not None:     # the clean-up has its own seconds, also after the limit
                cdp.limit = max(cdp.limit, time.monotonic() + SIGNIN_CLEANUP)
            if state != "none":
                signin_run(cdp, session, SIGNIN_EMPTY)
            if keep is not None:
                try:
                    after = signin_cookies(cdp)
                except Refused:
                    after = before                  # the cookies cannot be read now: the record keeps its origins
                keep(signin_record(seen, before, after))
            try:
                cdp.call("Target.detachFromTarget", {"sessionId": session})
            except Refused:
                pass
    return state == "none", with_code


def signin_keep(conf, job, record):
    """The hub keeps a sign-in's record with the agent's use of the login (POST /helper/vault/<agent>/signed). Refused
    where it did not say that it kept it."""
    code, data = hub(conf, "POST", f"/helper/vault/{conf['agent']}/signed", dict(record, job=job))
    if code != 200 or not isinstance(data, dict) or data.get("ok") is not True or data.get("job") != job:
        reason = data.get("error") if isinstance(data, dict) else None
        raise Refused("the hub did not keep the record of this sign-in" +
                      (f": {reason}" if isinstance(reason, str) else ""))


def signin(conf, job, uid, ports=None, tables=None):
    """sign_in on a Linux server (plan 04, S5): the job's login, opened inside the broker, filled in the calling
    agent's own Chrome. The caller's OS user names the port (root's ports file), and the connection to that agent's
    browser comes first, so that an agent with no browser running uses up no job. Then the hub confirms the job and
    the grant and checks that the request came from the agent's own user (confirm_job, with the caller fields that
    `handle` requires). Before the fill the hub keeps the login's own origin, so that the end of the login's use clears
    at least that site, and a seed that makes no code refuses before anything is typed; after the fill, the whole
    record, also after an error. The broker's lock is free while the browser works (signin_free), one sign-in of an
    agent at a time, and the whole fill has SIGNIN_TOTAL seconds. The answer has the origin, the login's name and
    whether a code was used, as the Mac's vault helper answers: never a value."""
    if not isinstance(job, int) or isinstance(job, bool) or job < 1:
        raise Refused("a sign-in needs a job number")
    if uid in SIGNING:
        raise Refused("a sign-in of this agent runs already")
    store = LocalStore(conf)            # a store that does not open refuses before the hub's job is used
    port = signin_port(caller_user(uid), ports)
    SIGNING.add(uid)
    try:
        with signin_free(conf):
            cdp = SigninCdp(port, uid, tables=tables, limit=time.monotonic() + SIGNIN_TOTAL)
        with cdp:
            confirmed = confirm_job(conf, job, "signin")
            login, label, source = open_login(conf, confirmed["login"], confirmed.get("task"), store)
            if confirmed.get("source") is not None and source != confirmed["source"]:
                raise Refused("the hub and the copy name different source logins, so the login is not used")
            protect(conf, confirmed, login)
            if login.get("totp"):
                totp_now(login["totp"])
            origin = signin_origin(login["url"])
            signin_keep(conf, job, {"origins": [origin], "cookies": []})

            def keep(record):
                try:
                    signin_keep(conf, job, record)
                except Refused as e:            # the login's own origin is kept already
                    log(f"sign-in job {job}: {e}")
            with signin_free(conf):
                signed, with_code = signin_page(cdp, login, (lambda: totp_now(login["totp"])) if login.get("totp")
                                                else None, keep)
    finally:
        SIGNING.discard(uid)
    if not signed:
        raise Refused(f"the sign-in on {origin} could not be confirmed: the page still asks for the login, or it went "
                      f"to another site" + (", after the authenticator code" if with_code else "") +
                      ". The password was never shown to you.")
    log(f"signed {conf['agent']} in on {origin} with {label!r} for job {job}" + (" and a code" if with_code else ""))
    return {"ok": True, "v": PROTOCOL, "job": job, "origin": origin, "label": label, "authenticator": with_code}


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

    def put(self, sid, name, value, note="", replace=False):
        """Save one item under the id that it has in the owner's vault (deposit): "new", or "same" when the store holds
        that value under that id already. Another value under that id is refused, because one reference names one
        value in every vault of the fleet: a delivery never changes what a name already means here.

        replace: the owner replaced the value of this reference (the central vault's signed replace, and the hub's
        word with a delivery of it). Then another value goes into the place of the stored one, "replaced", but only
        over an item with this same note: a delivery replaces what a delivery saved, never a login that this vault
        made or that the owner saved here himself. The store is one file that is made whole beside the old one and
        then takes its place (keep), so a replace that fails leaves the old value whole."""
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
                if not replace:
                    raise Refused("this machine's vault store holds another value under this reference, so nothing "
                                  "was saved")
                if items[sid]["note"] != note:
                    raise Refused("the value under this reference did not come here from the owner's vault, so it is "
                                  "not replaced")
            saved = "replaced" if sid in items else "new"
            items[sid] = {"key": name, "value": value, "note": note, "made_at": time.time()}
            self.keep(items)
        finally:
            os.close(fd)
        return saved

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


# A second opinion on the owner's signature (the owner's "OpenSSL as a second check" of 20 November 2026, for "each
# release and the vault's owner signatures"): a statement that the central vault or a machine broker takes
# (owner_statement: the central vault's pin, unpin, recovery, grant, ungrant, pool, unpool and replace, and a broker's
# handover pin) counts only when our ECDSA above and this machine's OpenSSL both take its signature
# (owner_signed_twice), wherever the machine has an OpenSSL that passes the probe: RFC 6979 A.2.5's signature of
# "sample", and the same signature with one bit changed. Every supported Linux
# system has OpenSSL (its ca-certificates depends on it). The door (door.owner_signed, since c7ca3a0e2) and the hub
# (hub.phone_signed, since 20 November 2026) take owner_signed_twice too, and each keeps a statement's answer for
# its process, because the door checks each of the owner's yeses again at each fetch, and the hub asks before it
# takes its one lock for a phone's yes; owner_signed alone is our ECDSA, which the apps' test vectors and the tests
# call.
# releases.py makes a second check of the same kind for each release; this file stands alone, so it has its own, made
# for a check that must end within its caller's wait.
# Our own code decides alone where no OpenSSL place holds a program that passes the probe: no program there, one that
# cannot be started, or one that runs and does not take the probe's signature or takes its changed copy. So a forged
# statement that our ECDSA took would still pass where OpenSSL breaks in that way on the fixed probe: twice in one
# check while a program is kept (after its no, and in the new probe), and once in a check that has none kept (the
# first check of a process, or the one after a check that found none). That is the price of a vault that keeps
# working with a broken OpenSSL, as on a machine with none. An OpenSSL that is there and could not be asked (it ran
# out of time, a signal ended it, its files could not be written, no process could be started for it) refuses that
# one statement with its own words (owner_statement) and a line in the log, and the kept program stays kept, so the
# next check asks it again: nobody turns the second check off, or opens a probe, by loading the machine.
# All the runs of one check share OPENSSL_WAIT seconds, and a run that is not done when they end is ended, so one
# check stays within the hub's 10-second wait for the central vault's answer (hub.CENTRAL_WAIT).
OPENSSL_PLACES = ("/usr/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl",
                  "/usr/local/opt/openssl@3/bin/openssl")
OPENSSL_WAIT = 5                    # seconds for all the runs of one check (about 15 ms each run): the central vault
#                                     makes them under its one request lock
ABSENT = "absent"                   # what a run says when no program can be started at that place
UNKNOWN = "unknown"                 # what the probe says when a run of it could not be asked
OPENSSL_SAYS = "Verified OK"        # what `openssl dgst -verify` says of a good signature, beside its status 0
_P256_HEAD = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")   # the DER head of a P-256 key
_OWNER_PROBE = ((0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
                 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299), b"sample",
                (0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
                 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8))
_openssl = []                       # [the program] once one is found in this process; empty before, or with none


def der_of(r, s):
    """(r, s) as a DER signature in its shortest form: what der_signature reads back."""
    def number(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        raw = b"\0" + raw if raw[0] & 0x80 else raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = number(r) + number(s)
    return b"\x30" + bytes([len(body)]) + body


def openssl_verify_p256(program, point, message, signature, until=None):
    """What the OpenSSL program at this path says of `signature` (DER) as an ECDSA signature of `message` (over its
    SHA-256) by the P-256 key `point`: True for its status 0 with its line, False when it ran and did not take it,
    ABSENT when no program can be started at this path, None when it could not be asked otherwise (its files could not
    be written, it ran out of time, a signal ended it). The run ends by `until`, a time.monotonic() value, else
    OPENSSL_WAIT seconds from now. Its files go to the service's own runtime directory where systemd gives one (a
    tmpfs), else to the temporary folder."""
    folder = None
    try:
        folder = tempfile.mkdtemp(prefix="fleet-p256-",
                                  dir=(os.environ.get("RUNTIME_DIRECTORY") or "").split(":")[0] or None)
        x, y = point
        key = base64.b64encode(_P256_HEAD + b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"))
        pem = b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(key[i:i + 64] for i in range(0, len(key), 64)) + \
            b"\n-----END PUBLIC KEY-----\n"
        names = ("key.pem", "message", "signature")
        for name, data in zip(names, (pem, bytes(message), bytes(signature))):
            with open(os.path.join(folder, name), "wb") as f:
                f.write(data)
        key_file, text_file, signature_file = (os.path.join(folder, name) for name in names)
        wait = OPENSSL_WAIT if until is None else until - time.monotonic()
        if wait <= 0:
            return None             # the check's time is gone: OpenSSL could not be asked
        try:
            done = subprocess.run([program, "dgst", "-sha256", "-verify", key_file, "-signature", signature_file,
                                   text_file], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=wait)
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.EACCES, errno.ENOEXEC):
                return ABSENT       # no program can be started here
            return None             # it could not be started now (no process, no memory)
    except (TypeError, ValueError, AttributeError, OverflowError):
        return False                # a value that no key or signature is
    except (OSError, subprocess.SubprocessError):
        return None                 # no folder or file of ours, no time: OpenSSL could not be asked
    finally:
        if folder:
            shutil.rmtree(folder, ignore_errors=True)
    if done.returncode < 0:
        return None                 # a signal ended it
    return done.returncode == 0 and done.stdout.decode("utf-8", "replace").strip() == OPENSSL_SAYS


def owner_verifier(again=False, until=None):
    """The first OpenSSL of OPENSSL_PLACES that takes RFC 6979's P-256 signature of "sample" and refuses it with one
    bit changed; None when no place has such a program (then our own ECDSA decides alone); UNKNOWN when a run of the
    probe could not be asked (then this check refuses). The kept program changes only at a definite end: a program
    that it found is kept for the process, with none found it looks again at the next check, and UNKNOWN leaves what
    was kept as it was. `again` probes anew in any case; `until` is the end of the check's time
    (openssl_verify_p256)."""
    held = _openssl[:1]             # one read: another thread can empty the list between a test and an index
    if held and not again:
        return held[0]
    point, message, (r, s) = _OWNER_PROBE
    good = der_of(r, s)
    forged = good[:-1] + bytes([good[-1] ^ 1])
    for program in OPENSSL_PLACES:
        if not (os.path.isfile(program) and os.access(program, os.X_OK)):
            continue
        takes = openssl_verify_p256(program, point, message, good, until)
        if takes is None:
            return UNKNOWN
        if takes is not True:       # no program here after all, or one that does not verify P-256
            continue
        refuses = openssl_verify_p256(program, point, message, forged, until)
        if refuses is None:
            return UNKNOWN
        if refuses is False:
            _openssl[:] = [program]
            return program
    _openssl[:] = []                # none: the next check looks again
    return None


def _unasked():
    """What a check says when OpenSSL could not be asked: None, which refuses this one statement with its own words
    (owner_statement), with a line in the log. The kept program stays kept: the next check asks it again, and only its
    definite no on the probe's good signature, or its absence, starts a new probe."""
    log("owner statement refused once: this machine's OpenSSL could not be asked (the next check asks it again)")
    return None


def openssl_takes(point, message, signature):
    """True when this machine has no OpenSSL that passes the probe, or when its OpenSSL takes this signature too;
    False when it refuses it; None when OpenSSL could not be asked (_unasked). After OpenSSL's no, the same program is
    given the probe's good signature: when it takes it, the program works and its no stands; when it does not, or the
    program is gone, every place is probed anew, so a program that stopped working refuses nothing by itself, and with
    none left our own ECDSA decides, as on a machine with none. All its runs share OPENSSL_WAIT seconds."""
    until = time.monotonic() + OPENSSL_WAIT
    program = owner_verifier(until=until)
    if program is None:
        return True
    if program == UNKNOWN:
        return _unasked()
    said = openssl_verify_p256(program, point, message, signature, until)
    if said is True:
        return True
    if said is None:
        return _unasked()
    if said is False:
        probe_point, probe_message, (r, s) = _OWNER_PROBE
        still = openssl_verify_p256(program, probe_point, probe_message, der_of(r, s), until)
        if still is True:
            return False            # a program that works refused this signature
        if still is None:
            return _unasked()
    program = owner_verifier(again=True, until=until)      # the program no longer works, or is gone
    if program is None:
        return True
    if program == UNKNOWN:
        return _unasked()
    said = openssl_verify_p256(program, point, message, signature, until)
    if said is True or said is False:
        return said
    return _unasked()               # it could not be asked, or it went away within this check


def owner_signer(conf, statement, signature):
    """The first of the owner's keys that signed exactly these statement bytes (UTF-8), by our own ECDSA, as its point
    with the signature's DER bytes; None when none did. signature is the standard base64, padded, of the DER form
    (CryptoKit's derRepresentation), over SHA-256 of the statement."""
    try:
        raw = base64.b64decode(signature, validate=True)
        digest = hashlib.sha256(statement.encode("utf-8")).digest()
    except ValueError:                  # also a UnicodeError: a text that is not UTF-8 was signed by nobody
        return None
    found = der_signature(raw) if base64.b64encode(raw).decode() == signature else None
    if found is None:
        return None
    for text in conf["owner_keys"]:
        try:
            point = owner_key(text)
            if ecdsa_verified(point, digest, *found):
                return point, raw
        except ValueError:              # load_config refused such a key; this reads them again for one request
            continue
    return None


def owner_signed(conf, statement, signature):
    """True when one of the owner's keys signed exactly these statement bytes, by our own ECDSA alone (owner_signer):
    the first of owner_signed_twice's two checks, which the door and the hub take since 20 November 2026."""
    return owner_signer(conf, statement, signature) is not None


def owner_signed_twice(conf, statement, signature):
    """owner_signed with this machine's OpenSSL as a second check (openssl_takes): True when both take the signature,
    False when one of them refuses it, None when OpenSSL could not be asked. The first key that our ECDSA takes
    decides, so one call makes one check of OpenSSL, however often a key is listed."""
    found = owner_signer(conf, statement, signature)
    return False if found is None else openssl_takes(found[0], statement.encode("utf-8"), found[1])


def canonical(value):
    """The one text of a JSON value that the vault and the owner's app both sign."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def owner_statement(conf, req, kind):
    """The owner's statement of this kind ({v, kind, fleet, at, and its machine, recipient, login, agent and sha256 as
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
            or not all(isinstance(said.get(k, ""), str) for k in ("machine", "recipient", "login", "agent", "sha256")) \
            or ("sha256" in said and not re.fullmatch(r"[0-9a-f]{64}", said["sha256"])) \
            or ("machine" in said and not MACHINE.fullmatch(said["machine"])) \
            or ("recipient" in said and not RECIPIENT.fullmatch(said["recipient"])) \
            or ("login" in said and not (SECRET_REF.fullmatch(said["login"]) and said["login"] == said["login"].lower())) \
            or ("agent" in said and not AGENT_NAME.match(said["agent"])):
        raise Refused(f"the statement is not a valid {kind} statement")
    if said["fleet"] != conf["fleet"]:
        raise Refused("the statement is for another fleet")
    signed = owner_signed_twice(conf, statement, signature)
    if signed is None:
        raise Refused("the vault could not check the owner's signature this time, so the statement is not taken; it "
                      "can be sent again")
    if not signed:
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
    "removed": {login: at}, "values": {login: {sha256, at}}}. An unpin keeps its machine's record, with no recipient,
    and an ungrant and an unpool keep theirs too, so a statement older than them, which the hub could send again, is
    refused as old. "removed" is not the owner's: it names each login that remove took out, so that no value comes in
    under its name again (intake). "values" has the owner's newest replace statement of each login: the checksum of
    the copy that it is about, and its time, so an older copy cannot come back (intake). No file is no record, and a
    state of the format before grants, before remove or before replace has none."""
    if not os.path.lexists(conf["state"]):
        return {"v": STATE, "pins": {}, "recovery": None, "grants": {}, "pool": {}, "removed": {}, "values": {}}
    try:
        data = json.loads(read_private(conf["state"], "state"))
        if isinstance(data, dict):
            data.setdefault("grants", {})
            data.setdefault("pool", {})
            data.setdefault("removed", {})
            data.setdefault("values", {})
        good = isinstance(data, dict) and set(data) == {"v", "pins", "recovery", "grants", "pool", "removed", "values"} \
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
                                                          and type(at) is int for ref, at in data["removed"].items()) \
            and isinstance(data["values"], dict) and all(
                SECRET_REF.fullmatch(ref) and ref == ref.lower() and isinstance(x, dict) and set(x) == {"sha256", "at"}
                and isinstance(x["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", x["sha256"]) is not None
                and type(x["at"]) is int for ref, x in data["values"].items())
    except ValueError:
        good = False
    if not good:
        raise Refused("the central vault's state cannot be read")
    return data


def keep_state(conf, state):
    """Write the central vault's state whole: a new file of mode 600, made complete beside the old one and then put in
    its place, as the store is kept. "values" is written only when it has a record: until the owner's first replace,
    the file is one that the program from before replace reads."""
    state = {k: v for k, v in state.items() if k != "values" or v}
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
            "removes": True, "replaces": True,      # this program serves remove, and replace in intake (the hub asks)
            "key_addresses": True,                  # and key_addresses: the hub asks it only when this says so
            "hub_keys": True,                       # and hub_key, the key of the hub's Google file: the same rule
            "hub_key_ids": hub_key_ids(conf),       # the id of each key that hub_key gave: the hub asks again on news
            # the checksum of the copy of the newest replace of each login: no secret. A hub that stopped between
            # this vault's write and its own record of a replace reads here that a value changed.
            "values": {ref: x["sha256"] for ref, x in sorted(state["values"].items())},
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
    owner gave. It is saved under the same reference, and another value under it is refused, as a deposit is. A name
    that remove took out takes no value again: else a hub that is broken into could remove a value that nobody holds
    yet and put its own under the owner's name, for his next grant to send.

    replace: with a statement that the owner signed (STATEMENTS "replace") about this login and this very copy (the
    SHA-256 of the sealed text), another value goes into the place of the one that the store holds: "replaced". Only
    the owner's key can say that, so the rule above stands: no hub puts a value of its own under his name. The
    statement must be newer than the newest one of this login, so that an older copy, which a hub can keep, cannot
    come back; the very same statement again is a retry. Its record is kept first and the store is written after it,
    one file that takes the place of the old one whole: a replace that stops between the two leaves the old value
    whole, and the same statement again ends it. With a statement, a login that the store does not hold is saved as
    new. A new value that names no address keeps the address of the stored one (kept_address). The answer names the
    fingerprints of the value that the store holds now, which are no secret: the hub compares a delivered copy with
    them (its helper_deposit_check)."""
    ref, title, item, text, salts, given = (req.get(k) for k in ("login", "title", "item", "ciphertext", "salts",
                                                                 "fingerprints"))
    m = SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
    if not (m and plain_line(title, 200) and item in ("login", "api_key") and isinstance(text, str)
            and ARMOR in text and len(text) <= COPY_MAX and isinstance(salts, dict)
            and all(re.fullmatch(r"[0-9a-f]{32}", str(salts.get(k))) for k in ("password", "totp"))
            and fingerprint_list(given)):
        raise Refused("the intake request is not valid")
    state = central_state(conf)
    if ref.lower() in state["removed"]:
        raise Refused("this login was removed from the fleet, so no value is taken under its name again")
    said = None
    if "statement" in req or "signature" in req:
        said = owner_statement(conf, req, "replace")
        if said["login"] != ref.lower():
            raise Refused("the statement is about another login")
        if said["sha256"] != hashlib.sha256(text.encode("utf-8")).hexdigest():
            raise Refused("the statement is about another copy than this one")
        record, last = {"sha256": said["sha256"], "at": said["at"]}, state["values"].get(ref.lower())
        if last is not None and last != record and said["at"] <= last["at"]:
            raise Refused("the vault holds a statement that is as new or newer, so nothing changed")
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
    if said is not None:
        value = kept_address(value, store.opened().get(m.group(1).lower()))     # the key changes, its address stays
        if state["values"].get(ref.lower()) != record:
            state["values"][ref.lower()] = record   # first: from here no older statement of this login is taken
            keep_state(conf, state)
    saved = store.put(m.group(1).lower(), title, canonical(value), TAKEN, replace=said is not None)
    log(f"intake: {ref.lower()} {saved}" + (", with the owner's replace statement" if said is not None else ""))
    return {"ok": True, "login": ref.lower(), "saved": saved,
            "fingerprints": [{"kind": k, "hash": h, "len": n} for k, h, n in sorted(mine)]}


def kept_address(value, held):
    """The value that a replace saves: the new one, with the address of the stored one when the new one names no
    address. A replace puts a new key in the place of the old one, and the address of the key's service is no part of
    the key: an API key that the owner saved with an address keeps it when his new save names none, so that an agent
    whose vault sends the key for it (call_api) still has the place to send it to. An address in the new value takes
    the place of the old one. The user name and the seed come from the new value only (C11): a replace by Add secret,
    which saves an API key with no user name and no seed, so repairs a key whose stored item had a login's user name,
    and that key reaches a session again. held: the stored item, or None."""
    try:
        old = json.loads(held["value"]) if held else None
    except ValueError:
        old = None
    if "url" in value or not isinstance(old, dict) or not isinstance(old.get("url"), str):
        return value
    try:
        return check_login(dict(value, url=old["url"]))
    except Refused:
        return value                    # an address that is no address any more: the new value as it came


def central_signed(conf, req, kind):
    """pin, unpin, recovery, grant, ungrant, pool and unpool: keep one statement that the owner signed. A statement must
    be newer (its `at`) than the record of its machine, of the recovery key, of its grant (one secret to one agent) or
    of its secret in the pool, so an old one cannot be sent again; the exact statement of the record answers "same",
    so a retry is no error. A statement dated more than PIN_AHEAD after this vault's clock is not kept, of any of
    these kinds, and the record before it stays. A pin's key is what seal locks a copy to, a grant or the pool is what lets seal lock
    that secret at all, and the recovery key is what export locks the store's key to."""
    said = owner_statement(conf, req, kind)
    if said["at"] - time.time() > PIN_AHEAD:     # package 4 and C50: no statement of these kinds kept from the future
        raise Refused(f"the owner's {kind} is dated more than a day after this vault's clock, so it is not kept")
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


KEY_TABLE_HOST = re.compile(r"(?=.{1,240}$)(?![0-9.]+$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")      # lifecycle.KEY_SITE_HOST


def key_table_row(address):
    """The name of the one row of KEY_TABLE_PLACES that this address selects, or None, by the rule of
    lifecycle.key_table_row (test_key_table gives both the same addresses): an https address of at most 300
    characters with no space and no user part, a plain ASCII host in any case with or without one dot at its end, no
    port or 443; an API host with any path; a page by its exact host and its exact path, with or without one slash at
    its end."""
    if not isinstance(address, str) or len(address) > 300 or any(c.isspace() for c in address):
        return None
    try:
        parts = urllib.parse.urlsplit(address)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or parts.username is not None or parts.password is not None or port not in (None, 443):
        return None
    host = host[:-1] if host.endswith(".") else host
    if not KEY_TABLE_HOST.fullmatch(host):
        return None
    path = parts.path[:-1] if parts.path.endswith("/") and parts.path != "/" else parts.path
    found = {name for name, row in KEY_TABLE_PLACES.items()
             if host in row["hosts"] or any(host == page_host and path == page_path for page_host, page_path in row["pages"])}
    return found.pop() if len(found) == 1 else None


def key_addresses(conf):
    """key_addresses (the changed key swap, Part C): for each stored item (not a login, login_shaped) whose value has an
    address (its `url`) that selects one row of this vault's own copy of the table (key_table_row), that row's name.
    No value, no address, no path and no host goes out, and no host comes in: so a hub that is broken into learns
    from it only which stored keys have an address of a row, and which row."""
    rows = {}
    for sid, item in sorted(LocalStore(conf).opened().items()):
        try:
            url = json.loads(item.get("value") or "").get("url")
        except (ValueError, TypeError, AttributeError):
            continue
        if login_shaped(item.get("value")):
            continue                    # a login never swaps (C11): its address is not the table's to know
        row = key_table_row(url)
        if row:
            rows["bws://" + sid] = row
    log(f"key_addresses: {len(rows)} stored item(s) with an address of a row")
    return {"ok": True, "rows": rows}


def hub_key_path(conf, name):
    """The key file of one of the hub's files: `hub-<name>.key` in this vault's state folder."""
    return os.path.join(os.path.dirname(os.path.abspath(conf["state"])), f"hub-{name}.key")


def hub_key_ids(conf):
    """{name: the id of the key that hub_key keeps}, for each key file that is there and holds one key: 16 hex
    characters of a SHA-256 of the key, as the hub's atrest.key_id makes them, which open nothing. The hub reads them
    with each status, and asks hub_key again when the key that it holds has another id: a running hub then seals its
    file with the key that this vault keeps now. A status makes no key."""
    ids = {}
    for name in HUB_KEYS:
        try:
            text = read_private(hub_key_path(conf, name), f"{name} key").strip()
        except Refused:
            continue
        if re.fullmatch(r"[0-9a-f]{64}", text):
            ids[name] = hashlib.sha256(b"founderizer key id\x00" + bytes.fromhex(text)).hexdigest()[:16]
    return ids


def hub_key(conf, req):
    """hub_key: the key of one of the hub's own files (HUB_KEYS), which this vault keeps for the hub (UI-API.md 1.202):
    32 random bytes in `hub-<name>.key` of this vault's state folder, which only this vault's user reads, made at the
    hub's first request and never replaced. The hub seals its Google file with it, so a copy of the hub user's files
    does not open that file. It is no value of the owner's and opens nothing of the store, and no export carries it.
    The socket's rule gives it to the hub's user alone (admitted), and each request is a line of this vault's log."""
    name = req.get("name")
    if name not in HUB_KEYS:
        raise Refused("name must be one of: " + ", ".join(HUB_KEYS))
    path = hub_key_path(conf, name)
    if not os.path.lexists(path):
        hub_key_make(path)
    text = read_private(path, f"{name} key").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise Refused(f"the vault {name} key file does not hold one key")
    log(f"hub_key: the key of the hub's {name} file")
    return {"ok": True, "key": text}


def hub_key_make(path):
    """A new key file that nothing replaces: written whole beside it and synced, then linked to its name, which fails
    over a file that is there (another request made it first, and that one is the key), and the folder synced, so the
    key is on the disk before the hub seals anything with it."""
    temp = f"{path}.{secrets.token_hex(8)}.new"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(secrets.token_hex(32) + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            pass
        sync_folder(os.path.dirname(path))
    except OSError:
        raise Refused("the key of the hub's file could not be made") from None
    finally:
        try:
            os.unlink(temp)
        except OSError:
            pass


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
    if op == "key_addresses":
        return key_addresses(conf)
    if op == "hub_key":
        return hub_key(conf, req)
    if op == "export":
        return export(conf)
    if op == "remove":
        return remove(conf, req)
    raise Refused("unknown operation")


def caller_user(uid):
    """The OS user of the process at the other end of the socket, by its uid (peer_uid), as the hub reads it in
    X-Fleet-Caller-User; the uid in digits where the system has no name for it."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


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
        # and gives it back when no agent of the machine holds it (withdrawals). A delivery that the hub marks so
        # replaces the value that an earlier one saved (replaces): the hub sends such a delivery only to a broker
        # that says this word.
        status = {"ok": True, "v": PROTOCOL, "agent": conf.get("agent"), "store": "user", "backend": "store",
                  "user": pwd.getpwuid(os.getuid()).pw_name, "recipient": recipient(conf), "callers": True,
                  "source": conf.get("_source"), "deposits": True, "withdrawals": True, "replaces": True}
        if conf.get("_journal") is not None:        # this broker can make a login: its record of saves is open
            status["creates"] = True
        if conf.get("_requests") is not None:       # only with a curl program: this broker can send a request
            status["requests"] = True
        if conf.get("_swaps") is not None:          # only with the part "swap": this broker keeps keys out of sessions
            status["swaps"] = True
        return status
    who = caller(req)
    if who:                             # this request acts for its caller; the store does not change
        # One OS user for each agent: every hub call of this request names the user that it came from, read from
        # the socket, so that a key that another agent's user read from a shared home opens nothing (hub
        # Handler.broker_allowed).
        conf = dict(conf, agent=who[0], agent_key=who[1], caller_user=caller_user(uid))
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
    if op == "signin":                  # plan 04, S5: the agent's own Chrome on this Linux server
        if not who:                     # the hub checks the caller's OS user only with them (Handler.broker_allowed)
            raise Refused("a sign-in needs the caller fields")
        return signin(conf, req.get("job"), uid)
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
#                                        the placeholder in its Authorization header or in the one header that the
#                                        key's form names, and sends it on a TLS
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
# The one form in which a key goes into a request, which the key's catalog entry names (the hub gives it with the
# site): the key is the whole credential, and never text beside other text of the agent's choice. These are forms of
# the Authorization header (key: `Key <key>`); header:<name> is the whole value of the one request header of that
# name. The same rule as lifecycle.key_form, in this program's own code (it stands alone as a root-owned program);
# test_key_swap holds the two equal.
SWAP_FORMS = ("bearer", "token", "basic-user", "basic-password", "key")
SWAP_HEADER_FORM = "header:"
SWAP_HEADER_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SWAP_FORM_WORD = re.compile(r"[a-z][a-z0-9-]{0,39}")       # the shape of a word form, also of a later release's
SWAP_HEADER_WORDS = ("key", "token", "secret", "auth")
SWAP_HEADER_NEVER = ("authorization", "proxy-authorization", "connection", "proxy-connection", "keep-alive", "upgrade")
SWAP_HEADER_NEVER_PARTS = ("idempoten", "csrf", "xsrf", "authenticat")
# A site's host: a DNS name of small letters, digits, dots and hyphens, at most 240 characters and never an IP
# address, so that it is safe in a file name and in openssl's files, and so that its CA has one kind of limit.
SWAP_HOST = re.compile(r"(?=.{1,240}$)(?![0-9.]+$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                       r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
SWAP_BEARER = re.compile(rb"((?i:bearer|token|key)) (vaultswap_[0-9a-f]{40})")
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
SWAP_PLACE = ("The vault puts a key only into a request to the key's own site, as the whole credential and in the one "
              "form of that key: in the Authorization header as `Bearer <placeholder>`, `token <placeholder>`, "
              "`Key <placeholder>`, or Basic with the placeholder as the user name or as the password, or as the whole "
              "value of the one header that the key's form names, in one header of that name. This request has a "
              "placeholder in another place or form. Nothing was sent.")
SWAP_REFUSED = ("The vault did not put the key into this request: this placeholder is not a key that this agent holds "
                "for this host now, or this is not the key's own form. Nothing was sent. If the work needs the key, "
                "ask your requester.")
SWAP_NO_HUB = ("The vault did not put the key into this request: the hub did not confirm the grant now. Nothing was "
               "sent. Try again.")
SWAP_NO_VAULT = "The vault's proxy got no answer from this machine's vault. Nothing was sent. Try again."
SWAP_BUSY = "The vault's proxy has too many connections of this user. Close some, and try again."
SWAP_CALL = ("On this machine the vault sends this key only to the key's own site, in the key's own form, as its proxy "
             "does. Nothing was sent.")
SWAP_ROOM = 256                             # questions of the proxy that the broker answers at one time
SWAP_KEPT = 60                              # seconds: the hub's yes to a use of a placeholder counts while the hub
                                            # does not answer, from the moment that its question left (Swaps.said)


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


def swap_form(form, full=False):
    """True for a form of a key (SWAP_FORMS, or header:<name>), for any value and with no exception: lifecycle.key_form
    in this program's own code. full: the whole rule, which the read of a session's keys and the proxy keep (a header's
    name holds a word of SWAP_HEADER_WORDS, and is no name of SWAP_HEADER_NEVER, no sec-* name and holds no part of
    SWAP_HEADER_NEVER_PARTS). Without full, its shape only, which the load of the list of placeholders keeps
    (Swaps.load), so that a later release that refuses one more name, or that adds a word of the Authorization header
    (any plain word is a shape), never makes a broker refuse its whole list."""
    if not isinstance(form, str):
        return False
    if form in SWAP_FORMS or not full and SWAP_FORM_WORD.fullmatch(form):
        return True
    name = form[len(SWAP_HEADER_FORM):] if form.startswith(SWAP_HEADER_FORM) else None
    if name is None or not SWAP_HEADER_NAME.fullmatch(name):
        return False
    return not full or (any(w in name for w in SWAP_HEADER_WORDS) and name not in SWAP_HEADER_NEVER and
                        not name.startswith("sec-") and not any(p in name for p in SWAP_HEADER_NEVER_PARTS))


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
    the hub (swap_value). An entry that is off opens no connection and gives no value; it keeps its name, so a key
    that the hub names again gets the same placeholder (place).

    The hub's answers to the uses of each placeholder are in memory only (`answers`; said, kept_yes): its last yes,
    and the time of its newest no. When no answer of the hub comes, that yes counts for SWAP_KEPT seconds from the
    moment that its question left, for the entry as a whole and while the entry stays on and the same. Nothing of it
    goes to disk, so a new broker process has no yes.

    Each switch is the hub's own word, and none is the agent's. Off: a read of the agent's keys that names the key
    with a site no more (only); the hub's no to a use (refused); the hub's take-back of the value from this machine
    (taken). On: the agent's next read that names the key with a site (place); a delivery of the value, for an entry
    that the hub then calls live for the entry's own OS user (waiting, on). "off" has one form, true, so a list that
    this version wrote is one that the first version reads."""
    FIELDS = {"uid", "user", "agent", "login", "host", "port", "form", "token"}
    LIMIT = 4 * 1024 * 1024

    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        self.answers = {}       # {placeholder: ((the entry of the kept yes, when its question left) or None,
                                #                when the question of the newest no left, or None)}
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
                and swap_form(e["form"]) and isinstance(e["token"], str) and SWAP_TOKEN.fullmatch(e["token"])
                for p, e in entries.items()):
            raise ValueError()
        return entries

    def keep(self, entries):
        """Write the list whole: a new file of mode 600, made complete beside the old one and then put in its place.
        A kept yes ends here when its entry changes or goes off: the hub's no to a use, a take-back of the value, a
        read that names the key with a site no more and a read that gives a new token are each the hub's own word.
        It ends before the write, so a list that cannot be written keeps no yes: each change of an entry counts as a
        no at this moment, so a slow yes to a question from before the change is not kept either (said). A new
        placeholder gets no such no: no question can be out for it yet."""
        now = time.monotonic()
        self.answers = {n: (None, now) if self.entries.get(n) != entries[n] else a
                        for n, a in self.answers.items() if n in entries}
        self.answers.update((n, (None, now)) for n, e in entries.items()
                            if n not in self.answers and n in self.entries and self.entries[n] != e)
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

    def refused(self, name, entry):
        """The hub said no to a use of this placeholder: its agent does not read its key at its site now. Off, with
        no read of the agent: an agent with no read grant left makes none. Only when the entry is still the one
        that the hub was asked about: a read can give it another token in between."""
        with self.lock:
            if self.entries.get(name) == entry and not entry.get("off"):
                self.keep(dict(self.entries, **{name: dict(entry, off=True)}))

    def taken(self, login):
        """The hub took the value of this key back from this machine, because no agent here holds it: each
        placeholder of the key is off, of each user."""
        with self.lock:
            off = {name: dict(e, off=True) for name, e in self.entries.items()
                   if e["login"] == login and not e.get("off")}
            if off:
                self.keep(dict(self.entries, **off))

    def waiting(self, login):
        """The placeholders of this key that are off, as copies: {placeholder: entry}."""
        with self.lock:
            return {name: dict(e) for name, e in self.entries.items() if e["login"] == login and e.get("off")}

    def on(self, name, entry):
        """Switch this placeholder on again, when it is still the entry that the hub was asked about. That opens
        nothing by itself: each use still asks the hub."""
        with self.lock:
            if self.entries.get(name) == entry and entry.get("off"):
                self.keep(dict(self.entries, **{name: {k: v for k, v in entry.items() if k != "off"}}))

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

    def said(self, name, entry, asked, yes):
        """The hub's answer to a use of this placeholder, whose question left at `asked` (time.monotonic()). Each
        answer that is not a yes ends the kept yes, whatever the age of its question. A yes is kept for the entry as
        it was asked about, when the list still has it so, and only when its question left after the question of each
        no to this placeholder: so a slow yes does not come back after the hub's no to a newer question."""
        with self.lock:
            kept, no = self.answers.get(name, (None, None))
            if not yes:
                self.answers[name] = (None, asked if no is None else max(no, asked))
            elif (no is None or asked > no) and (kept is None or asked >= kept[1]) and self.entries.get(name) == entry:
                self.answers[name] = ((dict(entry), asked), no)

    def kept_yes(self, name, entry):
        """The seconds since the question of the hub's kept yes for this placeholder left, when that yes counts now: it
        is for this entry as a whole (uid, user, agent, login, host, port, form, token), the list has the entry so and
        on, and it is less than SWAP_KEPT seconds old. Else None. A use of it does not renew it."""
        with self.lock:
            kept, now = self.answers.get(name, (None, None))[0], time.monotonic()
            if kept and kept[0] == entry == self.entries.get(name) and 0 <= now - kept[1] < SWAP_KEPT:
                return now - kept[1]
            return None


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


def swap_asks(conf, entry, use=True):
    """Ask the hub now whether the agent of this placeholder reads its key at its site and in its form: (the code,
    whether the hub named the agent's OS user). 200 for the hub's exact yes, the hub's code for each other answer (0
    for a yes that is not exact, a body that is not JSON, and the hub's refusal of an agent key), None only when no
    answer of the hub came (HubSilent: a refused connection, a reset, a timeout). Only None lets a kept yes count
    (swap_value). With no agent key: the token is what the hub knows this question by. use=False says that no request
    of a session waits for the answer (swap_given), so the hub writes no line about a refused use.

    The hub knows an agent by its name, and this list knows an entry by its OS user. A name can change hands on one
    machine (the owner renames an agent, and then gives its old name to another one), and then the hub's yes for
    the name is a yes for the new holder. So a yes that names another OS user than the entry's is the hub's no for
    this entry (409). A hub from before this answer names none."""
    asked = {"login": entry["login"], "site": "https://" + swap_origin(entry["host"], entry["port"]),
             "form": entry["form"], "swap": entry["token"]}
    if not use:
        asked["use"] = False
    try:
        code, data = hub(dict(conf, agent=entry["agent"], agent_key=None), "POST",
                         f"/helper/vault/{entry['agent']}/swap", asked)
    except HubSilent:
        return None, False
    except Refused:                     # an answer that is not a yes: hub() raises it for a 403 with "auth" and for a
        return 0, False                 # body that is not JSON
    if code != 200:
        return code, False
    if not (isinstance(data, dict) and data.get("ok") is True and data.get("login") == entry["login"]):
        return 0, False
    if data.get("user") is None:
        return 200, False
    if data["user"] == entry["user"]:
        return 200, True
    # the hub's log has no line for this (it said yes), so this one says why the placeholder gets nothing
    log(f"swap: the hub names another OS user for the agent {entry['agent']} than {entry['user']}, whose "
        f"placeholder this is: the name is another agent's now")
    return 409, True


def swap_given(conf, login):
    """The key swap's part of a delivery of this key's value to this machine (deposit): each placeholder of the key
    that is off comes on again when the hub says now that its agent reads the key at its site, and names the
    entry's own OS user as that agent's. So a session that still runs gets the key again with no new start, and the
    placeholder of an agent that does not hold the key stays off, also when its name is another agent's now. A hub
    that names no OS user switches nothing on: the agent's next read does. Nothing on a broker that does not swap,
    and nothing here stops the delivery: the value is saved, and the broker holds its lock, so the first question
    with no answer of the hub is the last one. No kept yes is used or written here: a placeholder that is off has
    none (Swaps.keep), and one that comes on again gets its next yes from the hub at its next use."""
    swaps = conf.get("_swaps")
    if swaps is None:
        return
    try:
        for name, entry in sorted(swaps.waiting(login).items()):
            code, named = swap_asks(conf, entry, use=False)
            if code is None:
                return                  # the hub does not answer now: the agent's next read switches it on
            if code == 200 and named:
                try:
                    swaps.on(name, entry)
                except Refused:
                    pass                # the list could not be written: the agent's next read switches it on
    except Exception as e:              # never a fault of this part in the answer of a delivery that is saved
        log(f"deposit: the placeholders of {login} stay as they are ({type(e).__name__})")


def swap_taken(conf, login):
    """The key swap's part of a take-back of this key's value from this machine (withdraw): each placeholder of the
    key is off, with no read of an agent. Nothing on a broker that does not swap."""
    swaps = conf.get("_swaps")
    if swaps is None:
        return
    try:
        swaps.taken(login)
    except Refused:
        pass                            # the list could not be written: each use still asks the hub


def swap_value(conf, uid, host, port, name, form):
    """The header value of this placeholder, for the swap proxy: it must be a placeholder of this OS user (by number
    and by name) and of this host that is not switched off, the proxy must have found it in the form of that key, and
    the hub must say now that its agent still reads its key at this site. When no answer of the hub comes (a hub that
    restarts for a release is silent for 2 to 3.4 seconds), its yes to an earlier use of this placeholder counts for
    SWAP_KEPT seconds from the moment that the question of that yes left, for this entry as a whole and while the
    entry stays on and the same (Swaps.said, kept_yes). A use of it does not renew it, and each answer of the hub that
    is not a yes ends it. With no such yes, a hub that does not answer is a refusal. Then the value is read from the
    store. No lock of the broker is held here: the hub call must not wait for another operation, and the store is one
    file that a save puts in place whole. A refusal has one fixed code and no value: "refused" or "hub"."""
    entry = conf["_swaps"].get(name) if isinstance(name, str) and PLACEHOLDER.fullmatch(name) else None
    if not entry or entry.get("off") or (entry["uid"], entry["user"], entry["host"], entry["port"], entry["form"]) != (
            uid, swap_user(uid), host, port, form):
        return {"ok": False, "code": "refused"}
    swaps, asked = conf["_swaps"], time.monotonic()
    code, _named = swap_asks(conf, entry)   # the entry's host, port and form are the ones of this request (above)
    if code is None:
        age = swaps.kept_yes(name, entry)
        if age is None:
            return {"ok": False, "code": "hub"}
        # the proof at a release reads this line: the agent, the key's reference and the age, and no value, no token
        # and no placeholder
        log(f"swap: the hub did not answer, so its yes of {age:.1f} seconds ago counts for the agent {entry['agent']} "
            f"and the key {entry['login']}")
    else:
        swaps.said(name, entry, asked, code == 200)     # in memory, before the list is written: the no always ends it
        if code != 200:
            # Only the hub's 409 switches off: this agent does not read this key so now, or its name is another OS
            # user's agent now. Not a 404: a hub that does not know the route gives one too, and so would switch off
            # each placeholder that is used.
            if code == 409:
                try:
                    swaps.refused(name, entry)
                except Refused:
                    pass                # the list could not be written: each use still asks the hub
            return {"ok": False, "code": "refused" if code in (403, 404, 409) else "hub"}
    try:
        stored = LocalStore(conf).item(SECRET_REF.fullmatch(entry["login"]).group(1))["value"]
        if login_shaped(stored):
            # C11, the second wall of `read`: the proxy puts no login's value into a request. This is the swap way of
            # a session only; call_api with a login ("Uses it") goes through `send` as before.
            return {"ok": False, "code": "refused"}
        value = check_value(stored)["password"]
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
    names with a site goes into a request only as the proxy puts it there: to that site, and in the key's own form. So
    call_api is no second road with looser rules (a header of the agent's choice, the address of the saved item).
    `bearer` is call_api's bearer, `basic-password` its basic, whose user name is the saved item's own, and a header
    form its `header:<Name>` of the same name in any case (the form's name has no `_`, so `xi_api_key` is not
    `header:xi-api-key`), by the whole rule as the read and the proxy keep it (a stored form that only its shape lets
    through goes nowhere), and with no header of the agent's that a site reads as the key's own (`_` read as `-`), which
    it could join to the key. A key of another form goes through the proxy only. True on a machine that does not swap,
    and for a key that the hub names no site for: as before."""
    if "_swap" not in conf or confirmed.get("site") is None:
        return True
    site, where = swap_site(confirmed.get("site")), origin(login.get("url") or "")
    form, auth = confirmed.get("form"), call["auth"]
    named = form[len(SWAP_HEADER_FORM):] if isinstance(form, str) and form.startswith(SWAP_HEADER_FORM) else None
    fits = ({"bearer": "bearer", "basic-password": "basic"}.get(form) == auth or
            named is not None and swap_form(form, full=True) and isinstance(auth, str) and auth.lower() == form and
            not any(str(n).lower().replace("_", "-") == named for n in (call.get("headers") or {})))
    return bool(site and where and where[2] == "https://" + swap_origin(*site) and fits)


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
    """The user ID that owns the other end of this TCP connection on this machine, from the kernel's own lookup or
    its table of sockets, or None. The socket must have exactly this connection's two addresses and ports: while this
    process holds the connection, no other socket has them. A program with one socket for both IP versions (.NET,
    Java) is in the IPv6 table, with the IPv4 address in its mapped form."""
    try:
        (peer_ip, peer_port), (own_ip, own_port) = conn.getpeername()[:2], conn.getsockname()[:2]
        one, two = socket.inet_aton(peer_ip), socket.inet_aton(own_ip)
    except (OSError, ValueError):
        return None
    # the kernel's exact lookup first (egress_diag): a scan of /proc for each connection would let an agent with many
    # idle sockets slow every other agent's (the fourth review round); /proc only where that lookup cannot run
    found = egress_diag(socket.AF_INET, socket.IPPROTO_TCP, (peer_ip, peer_port), (own_ip, own_port))
    if found is not False:
        return found

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
    SWAP_FORMS or header:<name>; True when the head has a placeholder in a place or a form where no key goes). A key
    goes in as the whole credential only: in the one Authorization header as `Bearer <placeholder>`,
    `token <placeholder>`, `Key <placeholder>`, or Basic credentials that are exactly `<placeholder>:<text>`
    (basic-user) or `<text>:<placeholder>` (basic-password); or as the whole value of one other header whose name a
    header form can have (swap_form, full), in the one header of that name. The broker gives the value only for the one
    form of that key (swap_value): with other text beside the placeholder, or with the key on the wrong side of a Basic
    credential, an agent could make the key a refused credential on purpose, and a site that writes one into its error
    would give it back. The request line, a header name, any other header, a second header of a named header's name
    with any value (also one with _ for -, which CGI and WSGI sites read as the same header, and which a site can join
    to the first), a second Authorization header, and two placeholders that each could be a key are no place for one
    (design key-swap-two-more-forms.md, version 2)."""
    grants = [v for n, v in headers if n.lower() == b"authorization"]
    elsewhere = bool(PLACEHOLDER_BYTES.search(target)) or any(PLACEHOLDER_BYTES.search(n) for n, _v in headers)
    same = {}               # each header's name as a site may read it: in small letters, with _ as -
    for n, _v in headers:
        read_as = n.lower().replace(b"_", b"-")
        same[read_as] = same.get(read_as, 0) + 1
    found = []
    for n, v in headers:
        low = n.lower()
        if low == b"authorization" or not PLACEHOLDER_BYTES.search(v):
            continue
        form = SWAP_HEADER_FORM + low.decode("ascii")       # SWAP_HEADER takes only ASCII token characters
        if PLACEHOLDER_BYTES.fullmatch(v) and swap_form(form, full=True) and same[low] == 1:
            found.append((v.decode(), form))
        else:
            elsewhere = True
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
    if (found or elsewhere) and len(grants) > 1 or len(found) > 1:
        elsewhere = True
    name, form = found[0] if len(found) == 1 else (None, None)
    return name, form, elsewhere


def swap_put(headers, name, value, form=None):
    """The headers with the placeholder `name` replaced by `value` in the one place of the form that swap_found
    accepted: the Authorization header for a form of SWAP_FORMS (form None is one of them), else the whole value of
    the one header that the form header:<name> names, and no other header."""
    old, new = name.encode(), value.encode()
    named = form[len(SWAP_HEADER_FORM):].encode() if isinstance(form, str) and form.startswith(SWAP_HEADER_FORM) \
        else None
    out = []
    for header, text in headers:
        if named is None and header.lower() == b"authorization":
            plain = swap_basic(text)
            text = b"Basic " + base64.b64encode(plain.replace(old, new)) if plain is not None else text.replace(old, new)
        elif named is not None and header.lower() == named and text == old:
            text = new
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


def swap_reach(host, port, uid=None, rules=None, gate=None):
    """A TCP connection to this host and port, or None. On a machine with the outgoing gate (its root-owned rules
    file, EGRESS_RULES), through the gate's relay port, with the UID of the agent user whose connection this is: the
    kernel lets this proxy's user reach nothing else, and the gate decides and counts as for the agent itself (the
    proposal's section 5.9). The gate looks the host up, so this proxy asks no DNS question there. Elsewhere it
    connects by itself, as before. rules, gate: a test's own path and address."""
    if os.path.exists(rules or EGRESS_RULES):
        return swap_through_gate(host, port, uid, gate or ("127.0.0.1", EGRESS_PORTS["relay"]))
    try:
        sock = socket.create_connection((host, port), timeout=SWAP_PATIENCE)
    except (OSError, UnicodeError):
        return None
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return sock


def swap_through_gate(host, port, uid, gate):
    """One tunnel through the gate's relay port: a CONNECT head with the agent user's UID, and the gate's 200. None
    when the gate refuses or does not answer: the proxy then says that it could not reach the host."""
    if not isinstance(uid, int) or isinstance(uid, bool):
        return None
    try:
        sock = socket.create_connection(gate, timeout=SWAP_PATIENCE)
    except OSError:
        return None
    try:
        target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{EGRESS_UID_HEADER}: {uid}\r\n\r\n"
                     .encode("ascii"))
        head, rest = swap_head(sock, 4096)
    except (OSError, UnicodeError):
        sock.close()
        return None
    if not head or not re.match(rb"HTTP/1\.[01] 200 ", head) or rest:
        sock.close()
        return None
    sock.settimeout(None)
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
        if os.path.exists(EGRESS_RULES):
            # The outgoing gate's table lets this user reach the gate's relay port and nothing else: so the check is
            # the row of its own connection to that port, which no listener of its own needs. With no gate running,
            # the check fails, and the unit starts the proxy again in 2 seconds: it could reach no host anyway.
            try:
                with socket.create_connection(("127.0.0.1", EGRESS_PORTS["relay"]), timeout=5) as client:
                    return egress_tcp_uid(client.getsockname()[:2], ("127.0.0.1", EGRESS_PORTS["relay"])) == \
                        os.getuid()
            except OSError:
                return False
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
        site = self.reach(host, port, uid)
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
        Authorization header, or of the one header that the key's form names, is replaced. The request goes to the
        site on a TLS connection that checks the site's
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
                kept = swap_put(kept, name, value, form)
                del value, said
            out = method + b" " + target + b" HTTP/1.1\r\n" + b"".join(n + b": " + v + b"\r\n" for n, v in kept) + b"\r\n"
            del kept
            if not self.passes(conn):   # closed at a hand-over while it waited: nothing goes to the site
                return
            raw = self.reach(host, port, uid)
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
    lookup = egress_lookup_check(("127.0.0.1", EGRESS_PORTS["relay"]) if os.path.exists(EGRESS_RULES) else None)
    if lookup["tcp"] is False:
        log("swap proxy: the kernel's lookup of a socket does not work on this machine: the proxy reads the user of "
            "each connection from /proc/net/tcp, which is slow when the machine has many sockets")
    if not proxy.reads_users():
        raise SystemExit("The swap proxy does not start: it cannot read the user of a connection on this machine, so "
                         "it would know no caller.")
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
# lets that process tell systemd that it is the main process now. The type stays simple: a program of the first
# version tells systemd nothing, and with Type=notify its proxy would never count as started. No ProtectProc, no
# ProcSubset and no RestrictAddressFamilies: it reads /proc/net/tcp, and it connects to any address.
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


# ---------------------------------------------------------------- the outgoing gate (egress)
#
# Step 1 of `agent-outgoing-connections-proposal.md` (the owner's "Yes, all nine" of 17 November 2026). On a Linux
# server where root ran `configure --egress on`, the kernel sends each TCP connection and each DNS question of an
# agent user to this program, the gate, which runs as a user of its own (EGRESS_USER): root's nftables table matches
# each packet by the UID of the socket that made it (meta skuid), so it holds for each process of an agent user, also
# one that reads no proxy variable, a cron job, or a program that the service user starts as that user. The gate
# reads the original destination and the agent's UID from the kernel, reads the host's name from the first bytes (a
# TLS ClientHello or an HTTP request head) or from what its own resolver gave this agent, connects for it, and counts.
#
# In this step the gate refuses no host: it records ("records only"). The kernel refuses UDP other than DNS and ICMP
# (the owner's decision 5), and root's closures keep an agent from asking systemd-resolved, tailscaled or snapd to
# connect for it. Every root-owned part of the whole design comes now (the table, its sets and its version, the
# units, the launcher and its safe copy, the closures), so that the later steps are releases only.
#
# The table stays while the gate does not run (the proposal's section 5.4): an agent's DNS and TCP then fail at once,
# and the hub still answers. Nothing falls back to a direct connection, because a gate that an agent could make fail
# would otherwise open everything, also for a connection that the agent keeps open after the gate is back. The
# restart, the hand-over, the take-back and the launcher keep the gate up; the hub's server watch tells the manager of
# a gate that does not answer (hub.py, egress_troubles). Root's file EGRESS_LOADED says which table the kernel has
# now, for the gate's state.
#
# The gate's standing rule: it reads the first bytes of a connection (one TLS ClientHello or one HTTP request head)
# and no byte after them, and it never ends TLS. The swap proxy (`vault.py swap`) keeps its own rule, and they stay
# two programs with two users: on a machine with the gate, the swap proxy's outgoing connection goes to the gate's
# relay port with the agent's UID (swap_reach), and the kernel lets the swap proxy's user reach nothing else.
#
# Its parts, all root's: the configuration (EGRESS_CONF), the table's text (EGRESS_RULES, which names its version in
# its first line, and whose existence tells the swap proxy to use the gate), the safe copy of this program and the
# launcher (EGRESS_LIB), the gate's unit, the unit that loads the table with its sets (`egress-rules`, at boot and at
# each change of /etc/group, /etc/subuid or the browsers' ports: a path unit for each), the drop-in that loads the
# table again after nftables.service flushes the kernel's rules, and the drop-ins that put the closures back at each
# start of systemd-resolved, tailscaled and snapd's socket. `configure --egress on` writes them all, in the order of
# the proposal's section 8.

EGRESS_KEY = 1                              # the format of EGRESS_CONF
EGRESS_TABLE = 1                            # the version of the table's text that this program writes and reads: a
# new version when the gate must serve a table in a new way. The direct lines of the Tailscale range (19 November
# 2026) changed no port and no set of the gate, so they kept version 1: the root step finds the new text by its
# file's hash, and a version 2 would also have made it restart a swap proxy that started before its program changed
# (swap_again), which cuts that proxy's tunnels.
EGRESS_POLICY = 1                           # the version of the policy that this program takes
EGRESS_LIB = "/usr/local/lib/founderizer-egress"
EGRESS_SAFE = EGRESS_LIB + "/vault.py"      # this program as it was at the last root step: what the launcher runs
EGRESS_LAUNCH = EGRESS_LIB + "/launch"      # when the installed program does not start the gate
EGRESS_DIR = "/etc/founderizer-egress"
EGRESS_CONF = EGRESS_DIR + "/egress.json"   # root's, mode 644, no secret
EGRESS_RULES = EGRESS_DIR + "/rules.nft"
EGRESS_LOADED = "/run/founderizer-egress-table"     # root's, mode 644: the version of the table in the kernel now
EGRESS_LOCK = "/run/founderizer-egress-rules.lock"  # one rules step at a time: boot, the path units, nftables
EGRESS_BROWSER = "/etc/fleet-browser/ports"     # the agents' browser parts (build plan 04, whose contract is devops's
# scripts/fleet-browser/README.md): `<user> <DevTools port> <screen port>` on each line. Root's table of those parts
# lets a DevTools port reach only its own agent's user, by the socket's UID, so that agent's own connection to it
# goes direct and never through the gate, whose own user that table refuses (a review of 17 November 2026)
EGRESS_DEVTOOLS = range(9300, 9400)             # the contract's DevTools ports
EGRESS_SUBUID = "/etc/subuid"                   # the sub-uids of each user, which newuidmap maps into a namespace
EGRESS_USER = "founderizer-egress"          # not a fleet-* name: the service user can make and change those
EGRESS_SERVICE = "fleet-egress"
EGRESS_RULES_SERVICE = "fleet-egress-rules"
EGRESS_SUBUID_PATH = "fleet-egress-subuid"       # the path unit of /etc/subuid
EGRESS_BROWSER_PATH = "fleet-egress-browser"     # the path unit of the browsers' ports
EGRESS_UNITS = "/etc/systemd/system"
EGRESS_RUN = "/run/founderizer-egress"      # the gate's RuntimeDirectory: its control socket
EGRESS_CONTROL = EGRESS_RUN + "/control.sock"
EGRESS_RUNNING = EGRESS_RUN + "/running"    # the SHA-256 of the program that the gate's process runs now
EGRESS_CRASHES = EGRESS_RUN + "/crashes"    # `<SHA-256 of its program> <seconds since boot>` for each end of the
EGRESS_CRASHES_MOST = 3                     # gate's process that nobody asked for (a crash, a kill), in the last
EGRESS_CRASHES_HOUR = 3600                  # EGRESS_CRASHES_HOUR: at this many, neither the launcher nor a hand-over
                                            # runs that program while they are that recent, so for up to an hour
                                            # after its third end; and a safe copy that does not take the stored policy
                                            # does not serve in its place (egress_policy_taken), so no fallback drops a
                                            # later step's refusals (a review of 17 November 2026)
EGRESS_STATE = "/var/lib/founderizer-egress"    # the gate's StateDirectory: its last policy
EGRESS_SERVICE_USER = "fleet"               # the machine's Founderizer service: join.sh WORKER, hub.sh HUB_USER
EGRESS_GROUP = "fleet-agents"               # hubsetup.AGENT_GROUP: every agent user of this machine, and nobody else
EGRESS_PORTS = {"out": 877, "local": 878, "relay": 879, "dns": 880}     # below 1024: see EGRESS_LOW_PORT
EGRESS_LOW_PORT = 880                       # each user can listen on a port below ip_unprivileged_port_start only
EGRESS_GIT_PORT = 9418                      # the hub's git daemon, direct in the table like the hub's own port
EGRESS_NFT = "/usr/sbin/nft"
EGRESS_CONTAINER_GROUPS = ("docker", "lxd", "incus", "libvirt")     # each one makes a daemon run a container for
# its members, whose traffic is forwarded and is no socket of theirs (the proposal's A6): no agent user is in one
EGRESS_PER_USER = 512                       # connections of one agent user that the gate relays at one time
EGRESS_DNS_PER_USER = 64                    # DNS questions of one agent user that wait for an answer at one time
EGRESS_NAMES = 1000                         # different names of one agent user in one batch of counts; past it a
                                            # new name counts under its last two labels (egress_fold)
EGRESS_ROWS = 4000                          # rows of one agent user in one batch; past it a new row counts on port 0
EGRESS_ADDRESSES = 4096                     # addresses that the resolver keeps a name for, for one agent user
EGRESS_STALL = 5                            # seconds of no answer after which the name's addresses of the same family
                                            # join (a first address that answers in time is never raced by them)
EGRESS_FALLBACK = 0.25                      # seconds before the gate also tries the name's other addresses (RFC 8305):
# the kernel gives the client the gate's handshake at once, so the client's own fallback from a broken IPv6 path to
# IPv4 cannot run, and the gate runs it (measured on 17 November 2026: without it an agent's request hung where root's
# went on over IPv4 in 0.25 s)
EGRESS_PATIENCE = 15                        # seconds for a connection to a host, a CONNECT head, one DNS answer
EGRESS_FIRST = 16384 + 64                   # bytes of a connection's first record that the gate reads for its name
EGRESS_HEAD = 8192                          # bytes of the relay port's CONNECT head
EGRESS_CANDIDATE = 60                       # seconds in which the gate of a new program says that it serves
EGRESS_SERVES = b"serves\n"
EGRESS_LINE = 4 * 1024 * 1024               # bytes of one line on the control socket (a merge of counts)
EGRESS_ASK = 65536                          # bytes of one request of the service user
EGRESS_CONTROLS = 16                        # requests on the control socket at one time
EGRESS_THREADS = 8192                       # threads of the gate's connections and questions at one time; past it a
                                            # new connection gets a reset, so that the gate never fails to start one
EGRESS_STREAM = 120                         # seconds of one connection of DNS over TCP
EGRESS_NEW_RATE = "200/second burst 2000 packets"     # new TCP connections of one agent user, in the kernel
EGRESS_DNS_RATE = "200/second burst 2000 packets"     # DNS questions over UDP of one agent user, in the kernel
EGRESS_MODPROBE = "/etc/modprobe.d/founderizer-egress.conf"
EGRESS_FAMILIES = ("rxrpc", "smc", "rds", "tipc")       # socket families whose transport is a kernel socket, which
# an unprivileged user can open where the module loads (AF_RXRPC did on Ubuntu 24.04 on 17 November 2026): the kernel
# then sends the agent's bytes from a socket of no user, which the table cannot read as the agent's (the second
# review round). The step keeps their modules from loading and unloads one that no socket holds; the gate's state
# names each one that is loaded.
EGRESS_FOLDED = 1000                        # different folded names of one agent user in one batch; past them, and
                                            # past EGRESS_ROWS rows, a new host counts as EGRESS_MORE
EGRESS_UID_HEADER = "X-Founderizer-Agent-Uid"
EGRESS_MORE = "(more hosts)"                # the one row of a batch past the limits, for each verdict and kind
EGRESS_NAME = re.compile(r"(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}"
                         r"[a-z0-9_])?)*\.?")
EGRESS_CLOSED = {                           # the local services that connect or resolve for any local user (A1, A2)
    "resolved": {"default": "/run/systemd/resolve", "sockets": ("/run/systemd/resolve/io.systemd.Resolve",
                                                                 "/run/systemd/resolve/io.systemd.Resolve.Monitor")},
    "tailscaled": {"folder": "/run/tailscale", "sockets": ("/run/tailscale/tailscaled.sock",)},
    "snapd": {"sockets": ("/run/snapd.socket", "/run/snapd-snap.socket")},
}
EGRESS_DROPINS = {                          # unit -> (section, key): where each closure goes back at a start
    "systemd-resolved.service": ("Service", "ExecStartPre", "resolved"),
    "tailscaled.service": ("Service", "ExecStartPre", "tailscaled"),
    "snapd.socket": ("Socket", "ExecStartPost", "snapd"),
    "docker.socket": ("Socket", "ExecStartPost", "daemons"),
    "incus.socket": ("Socket", "ExecStartPost", "daemons"),
    "libvirtd.socket": ("Socket", "ExecStartPost", "daemons"),
    "snap.lxd.daemon.unix.socket": ("Socket", "ExecStartPost", "daemons"),
}
EGRESS_DBUS = "/etc/dbus-1/system.d/founderizer-egress.conf"
EGRESS_DAEMONS = ("/run/docker.sock", "/var/snap/lxd/common/lxd/unix.socket", "/var/lib/lxd/unix.socket",
                  "/var/lib/incus/unix.socket", "/run/libvirt/libvirt-sock")    # each container group's own socket:
# a process of an agent user that still has the group (its user manager, a tmux) loses it only at its next login, so
# a named user's entry with no right on the socket ends its use at once (a named user's entry decides before a
# group's)
# Tailscale's interface, its IPv4 range, and its own address on this machine (tailscaled's resolver and web
# interface), for the one direct line of the Tailscale range (egress_table)
EGRESS_TAILSCALE = {"interface": "tailscale0", "range": "100.64.0.0/10", "own": "100.100.100.100"}
EGRESS_CLASSES = (                          # for the records: the kinds of address that are never the open internet
    ("metadata", ("169.254.169.254/32", "fd00:ec2::254/128")),
    ("link-local", ("169.254.0.0/16", "fe80::/10")),
    ("fleet", ("100.64.0.0/10", "fd7a:115c:a1e0::/48")),
    ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")),
    ("reserved", ("0.0.0.0/8", "240.0.0.0/4", "224.0.0.0/4", "ff00::/8", "::/128")),
)


def egress_config(path=EGRESS_CONF, read=None):
    """The gate's root-owned configuration, checked: a dict with the users and the hub's direct address and ports.
    Raises Refused with the reason."""
    if read is None:
        unchangeable(path, "The gate's configuration")
        with open(path, encoding="utf-8") as f:
            text = f.read()
    else:
        text = read(path)
    try:
        conf = json.loads(text)
    except ValueError:
        raise Refused("the gate's configuration is no JSON") from None
    if not isinstance(conf, dict) or conf.get("egress") != EGRESS_KEY:
        raise Refused(f"the gate's configuration is not of format {EGRESS_KEY}")
    for key in ("user", "service_user", "swap_user", "group"):
        if not isinstance(conf.get(key), str) or not GROUP_NAME.fullmatch(conf[key]):
            raise Refused(f"the gate's configuration has no valid {key}")
    hub = conf.get("hub")
    try:
        hub_ip = str(ipaddress.ip_address(hub)) if hub is not None else None
    except ValueError:
        raise Refused("the hub in the gate's configuration is not an address") from None
    ports = conf.get("hub_ports") or []
    if not isinstance(ports, list) or not all(isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536
                                              for p in ports):
        raise Refused("the hub's ports in the gate's configuration are not ports")
    return dict(conf, hub=hub_ip, hub_ports=ports)


def egress_table(conf=None):
    """The kernel rules, as root's text with no elements (EGRESS_RULES). Its first line names its version. One table
    for IPv4 and IPv6; its chains are fixed and only its sets change (egress_elements). What they do:

    Each chain jumps to the rules of a user only when the packet's socket names that user (meta skuid matches the
    set). A packet that no socket of a user makes (the kernel's own: IPv6 neighbour discovery, an ICMP error, an NFS
    or CIFS mount) cannot be read as a user's, so it never meets those rules; a rule "skuid != @agents" would not
    match it either, and would send it on to the last refusal (a review of 17 November 2026: that cut IPv6 for the
    whole probe server, as its neighbour entries ran out).

    - agent_nat: a packet of an agent user that goes to the hub's address and port, to the swap proxy on 127.0.0.1,
      or to its own browser's DevTools port on the loopback address (the set browser, of each agent user and its port:
      the browsers' own table lets that port reach only its own agent's user, so the connection must keep that user's
      UID, and another agent's connection to it goes through the gate, which records it) goes on as it is; each DNS
      question (UDP or TCP to port 53, to any name server) goes to the gate's resolver; a TCP connection to another
      Tailscale machine goes on as it is (below); each TCP connection to an address of this machine goes to the
      gate's local port, and every other one to its port. The chain's priority is one before dstnat, so that a NAT
      rule of another table (Docker's published ports) does not take an agent's connection first.
    - agent_out: a flow that is open goes on (the first install cuts nothing, and an agent's listener answers).
      Every other first packet of an agent user is refused, but those that the kernel sent to the gate and those that
      go direct: so UDP other than DNS, ICMP and each other protocol are refused, with words that the program sees.
    - sub_out: a packet of a sub-uid of an agent user (the set subagents, from /etc/subuid) is refused. A process of
      the agent that newuidmap gave such a UID in a user namespace of its own, in this machine's network, would
      otherwise meet none of the agent's rules (a review of 17 November 2026).
    - relay_out: the swap proxy's user reaches the gate's relay port, and nothing else, also no name server.

    Two limits for each agent user, in the kernel, so that one agent's flood of new connections or DNS questions
    never reaches the gate as more than its share: past them a new TCP connection gets a reset and a question is
    dropped (EGRESS_NEW_RATE, EGRESS_DNS_RATE).

    A TCP connection to another Tailscale machine goes direct (EGRESS_TAILSCALE), because the gate cannot answer for
    it. Tailscale's own rule (its chain ts-input, at the input hook) drops each packet from its IPv4 range that does
    not come in on tailscale0, but this machine's own address on the loopback interface; and the kernel gives an
    agent each packet of the gate from the address that the agent asked for, on the loopback interface. So an
    agent's connection to another Tailscale machine did not open: each answer of the gate was dropped, and the
    program waited until its own time limit (19 November 2026: from the first table on, no agent reached the door,
    and the counter of that rule rose with each try). The line takes only an address of that range whose route
    leaves through tailscale0: not this machine's own address (its route is the loopback interface, and the gate's
    local port keeps it), not an address of that range on another network (a cloud's own services), and not
    tailscaled's own IPv4 address, whose services are tailscaled's as its socket is (the closures): a connection
    there still goes to the gate, and waits until the program's own time limit, as the door's did. The gate does not
    record a direct connection. A DNS question to a name server in that range still goes to the gate's resolver, whose
    answer that rule drops: so a machine whose resolv.conf names one (tailscaled's 100.100.100.100, or a cloud's)
    loses its agents' DNS, an open hole that the proposal's section 16.9 names; a server that asks 127.0.0.53 does
    not. Tailscale 1.104 has no such rule for IPv6, so the gate records an agent's connections to Tailscale's IPv6
    range as to any other host."""
    p = EGRESS_PORTS
    ts = EGRESS_TAILSCALE
    tailscale = f'ip daddr {ts["range"]} ip daddr != {ts["own"]} oifname "{ts["interface"]}"'
    return f"""# founderizer-egress table {EGRESS_TABLE}
# The outgoing gate's kernel rules (vault.py, "the outgoing gate"). Root's: `vault.py configure --egress on` writes
# this file, and the unit {EGRESS_RULES_SERVICE} loads it with the elements of its sets. Do not edit it.
table inet founderizer_egress
delete table inet founderizer_egress
table inet founderizer_egress {{
  comment "founderizer-egress {EGRESS_TABLE}"
  set agents {{ type uid; }}
  set relays {{ type uid; }}
  set subagents {{ type uid; flags interval; }}
  set direct4 {{ type ipv4_addr . inet_service; }}
  set direct6 {{ type ipv6_addr . inet_service; }}
  set browser {{ type uid . inet_service; }}
  set new_rate {{ type uid; flags dynamic; timeout 1m; size 65536; }}
  set dns_rate {{ type uid; flags dynamic; timeout 1m; size 65536; }}
  chain nat_out {{
    type nat hook output priority -101; policy accept;
    meta skuid @agents jump agent_nat
  }}
  chain agent_nat {{
    ip daddr . tcp dport @direct4 return
    ip6 daddr . tcp dport @direct6 return
    ip daddr 127.0.0.1 tcp dport {SWAP_PORT} return
    ip daddr 127.0.0.1 meta skuid . tcp dport @browser return
    ip6 daddr ::1 meta skuid . tcp dport @browser return
    meta l4proto {{ udp, tcp }} th dport 53 redirect to :{p["dns"]}
    {tailscale} meta l4proto tcp return
    fib daddr type local meta l4proto tcp redirect to :{p["local"]}
    meta l4proto tcp redirect to :{p["out"]}
  }}
  chain filter_out {{
    type filter hook output priority 0; policy accept;
    meta skuid @agents jump agent_out
    meta skuid @subagents jump sub_out
    meta skuid @relays jump relay_out
  }}
  chain agent_out {{
    ct status dnat ip daddr 127.0.0.1 udp dport {p["dns"]} update @dns_rate {{ meta skuid limit rate over {EGRESS_DNS_RATE} }} drop
    ct status dnat ip6 daddr ::1 udp dport {p["dns"]} update @dns_rate {{ meta skuid limit rate over {EGRESS_DNS_RATE} }} drop
    ct state established accept
    ct state new meta l4proto tcp update @new_rate {{ meta skuid limit rate over {EGRESS_NEW_RATE} }} reject with tcp reset
    ip daddr . tcp dport @direct4 accept
    ip6 daddr . tcp dport @direct6 accept
    ip daddr 127.0.0.1 tcp dport {SWAP_PORT} accept
    ip daddr 127.0.0.1 meta skuid . tcp dport @browser accept
    ip6 daddr ::1 meta skuid . tcp dport @browser accept
    {tailscale} meta l4proto tcp accept
    ct status dnat ip daddr 127.0.0.1 meta l4proto {{ tcp, udp }} th dport {{ {p["out"]}, {p["local"]}, {p["dns"]} }} accept
    ct status dnat ip6 daddr ::1 meta l4proto {{ tcp, udp }} th dport {{ {p["out"]}, {p["local"]}, {p["dns"]} }} accept
    meta l4proto tcp reject with tcp reset
    reject with icmpx admin-prohibited
  }}
  chain sub_out {{
    ct state established accept
    meta l4proto tcp reject with tcp reset
    reject with icmpx admin-prohibited
  }}
  chain relay_out {{
    ct state established accept
    ip daddr 127.0.0.1 tcp dport {p["relay"]} accept
    meta l4proto tcp reject with tcp reset
    reject with icmpx admin-prohibited
  }}
}}
"""


def egress_rules_version(text):
    """The version that a rules file names in its first line, or None."""
    found = re.match(r"# founderizer-egress table ([0-9]{1,6})\n", text or "")
    return int(found.group(1)) if found else None


def egress_agents(group=EGRESS_GROUP, never=()):
    """The UIDs of this machine's agent users: each member of the group, and each user whose own group it is. Never
    root, and never a user that `never` names (the gate's, the service user's, the swap proxy's)."""
    try:
        g = grp.getgrnam(group)
    except KeyError:
        return []
    names = set(g.gr_mem) | {p.pw_name for p in pwd.getpwall() if p.pw_gid == g.gr_gid}
    out = set()
    for name in names - set(never):
        try:
            uid = pwd.getpwnam(name).pw_uid
        except KeyError:
            continue
        if uid != 0:
            out.add(uid)
    return sorted(out)


def egress_uid_of(name):
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def egress_browser_ports(agents, path=None):
    """Each agent user's own DevTools port of the agents' browsers (EGRESS_BROWSER), as nft text `<uid> . <port>`:
    from each whole line of the contract, `<user> <DevTools port> <screen port>`, with a DevTools port of 9300 to 9399
    and a screen port of 5910 to 5999, whose user is an agent user. A line of another form is left out, so a line
    that a later contract adds costs no agent its browser."""
    try:
        with open(path or EGRESS_BROWSER, encoding="utf-8") as f:
            text = f.read(65536)
    except (OSError, UnicodeDecodeError):
        return []
    rows = set()
    for line in text.split("\n")[:-1]:             # only lines with their new line: never half of one in writing
        found = re.fullmatch(r"(\S+) ([0-9]{4}) ([0-9]{4})", line)
        if not found or int(found.group(2)) not in EGRESS_DEVTOOLS or not 5910 <= int(found.group(3)) <= 5999:
            continue
        uid = egress_uid_of(found.group(1))
        if uid in agents:
            rows.add((uid, int(found.group(2))))
    return [f"{uid} . {port}" for uid, port in sorted(rows)]


def egress_subids(agents, path=None, users=None, held=None):
    """The sub-uid ranges of the agent users in /etc/subuid (a line `<user or UID>:<first>:<count>`), as nft
    intervals with no overlap. The UID of each user of this machine (root, the gate's, an agent's) is cut out of a
    range that holds it, so that no user's own packets are ever refused for it, and the rest of the range stays; such
    a range goes into `held`, as words, because a process of that agent can take that user's UID. users: the UIDs of
    this machine's users (a test's own)."""
    try:
        with open(path or EGRESS_SUBUID, encoding="utf-8") as f:
            lines = f.read(1 << 20).splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    owners = {str(uid) for uid in agents}
    for uid in agents:
        try:
            owners.add(pwd.getpwuid(uid).pw_name)
        except KeyError:
            pass
    users = ({p.pw_uid for p in pwd.getpwall()} if users is None else set(users)) | {0}
    spans = []
    for line in lines:
        found = re.fullmatch(r"([^:\s]+):([0-9]{1,10}):([0-9]{1,10})", line.strip())
        if not found or found.group(1) not in owners:
            continue
        first, count = int(found.group(2)), int(found.group(3))
        if count < 1:
            continue
        # a range past the UIDs that a socket can have is cut to them, and never left with no rule (a review of 17
        # November 2026); root's UID 0, as each user's, is cut out below and named
        first, last = min(first, 0xFFFFFFFE), min(first + count - 1, 0xFFFFFFFE)
        inside = sorted(u for u in users if first <= u <= last)
        if inside and held is not None:
            held.append(f"the sub-uids {first}-{last} of {found.group(1)} hold the UID of a user of this machine "
                        f"({', '.join(map(str, inside))}), which a process of that agent can take")
        for user in inside:
            if user > first:
                spans.append([first, user - 1])
            first = user + 1
        if first <= last:
            spans.append([first, last])
    merged = []
    for first, last in sorted(spans):
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], last)
        else:
            merged.append([first, last])
    return [f"{first}-{last}" if last > first else str(first) for first, last in merged]


def egress_elements(conf, agents=None):
    """{set: [elements as nft text]} of the table's six sets, from the machine as it is now."""
    never = (conf["user"], conf["service_user"], conf["swap_user"])
    agents = egress_agents(conf["group"], never) if agents is None else agents
    swap = egress_uid_of(conf["swap_user"])
    out = {"agents": [str(u) for u in agents], "relays": [str(swap)] if swap is not None else [],
           "subagents": egress_subids(agents), "direct4": [], "direct6": [], "browser": egress_browser_ports(agents)}
    if conf.get("hub"):
        kind = "direct6" if ":" in conf["hub"] else "direct4"
        out[kind] = [f"{conf['hub']} . {port}" for port in conf["hub_ports"]]
    return out


def egress_load_text(rules, elements):
    """One nft transaction: the whole table, then the elements of its sets. nft applies a file in one atomic step, so
    no packet sees half of it (the proposal's F52)."""
    text = rules
    for name, items in elements.items():
        if items:
            text += f"add element inet founderizer_egress {name} {{ {', '.join(items)} }}\n"
    return text


def egress_loaded(run):
    """The version of the table that the kernel has now, or None: its comment, read as JSON."""
    code, out, _ = run(f"{EGRESS_NFT} -j list table inet founderizer_egress 2>/dev/null || true")
    try:
        for item in json.loads(out or "{}").get("nftables", []):
            comment = (item.get("table") or {}).get("comment") if isinstance(item, dict) else None
            if isinstance(comment, str):
                found = re.fullmatch(r"founderizer-egress ([0-9]{1,6})", comment)
                return int(found.group(1)) if found else None
    except (ValueError, AttributeError):
        pass
    return None


# POSIX ACLs as the kernel keeps them (system.posix_acl_access and system.posix_acl_default): a version word, then
# entries of a tag, a permission and an ID, in order of tag and ID. No program of the acl package is needed.
ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = 1, 2, 4, 8, 16, 32
ACL_NO_ID = 0xFFFFFFFF


def acl_read(path, default=False):
    """[(tag, perm, id)] of a file's ACL, or None when it has none."""
    try:
        raw = os.getxattr(path, "system.posix_acl_default" if default else "system.posix_acl_access",
                          follow_symlinks=False)
    except OSError:
        return None
    if len(raw) < 4 or struct.unpack_from("<I", raw)[0] != 2 or (len(raw) - 4) % 8:
        return None
    return [struct.unpack_from("<HHI", raw, i) for i in range(4, len(raw), 8)]


def acl_bytes(entries):
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, p, i) for t, p, i in sorted(entries))


def acl_with(entries, gid, perm, tag=ACL_GROUP):
    """The entries with the named group's (or with tag ACL_USER the named user's) entry set to `perm`, and a mask
    that keeps each other entry's effect: the union of the group class, as setfacl -m makes it."""
    out = [e for e in entries if not (e[0] == tag and e[2] == gid) and e[0] != ACL_MASK]
    out.append((tag, perm, gid))
    mask = 0
    for t, p, _ in out:
        if t in (ACL_GROUP_OBJ, ACL_GROUP, ACL_USER):
            mask |= p
    out.append((ACL_MASK, mask, ACL_NO_ID))
    return out


def acl_close(path, gid, perm, default=False, tag=ACL_GROUP):
    """One entry of the agents' group on a file or a folder, so that the kernel refuses them what `perm` leaves out:
    no write on a socket is no connection to it (unix(7)), no search on a folder is no path through it, and a named
    group's entry decides before the entry of others (acl(5)). True when it changed the file. A socket that others
    and the group cannot write needs none. The default ACL of a folder gives each new file of it the entry: each other
    entry is rwx there, so that the mode of a new file decides as it did before (an entry narrower than rwx would take
    a right from every user: proved on 17 November 2026, when a default of r-x shut each user out of resolved's new
    socket)."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return False
    if default:
        if not stat.S_ISDIR(info.st_mode):
            return False
        have = acl_read(path, default=True)
        want = acl_with([(ACL_USER_OBJ, 7, ACL_NO_ID), (ACL_GROUP_OBJ, 7, ACL_NO_ID), (ACL_OTHER, 7, ACL_NO_ID)],
                        gid, perm)
        if have is not None and sorted(have) == sorted(want):
            return False
        os.setxattr(path, "system.posix_acl_default", acl_bytes(want), follow_symlinks=False)
        return True
    if stat.S_ISSOCK(info.st_mode) and not info.st_mode & 0o022 and tag == ACL_GROUP:
        return False
    have = acl_read(path)
    base = have or [(ACL_USER_OBJ, (info.st_mode >> 6) & 7, ACL_NO_ID),
                    (ACL_GROUP_OBJ, (info.st_mode >> 3) & 7, ACL_NO_ID), (ACL_OTHER, info.st_mode & 7, ACL_NO_ID)]
    want = acl_with(base, gid, perm, tag)
    if have is not None and sorted(have) == sorted(want):
        return False
    os.setxattr(path, "system.posix_acl_access", acl_bytes(want), follow_symlinks=False)
    return True


def acl_open(path, gid, default=False, tag=ACL_GROUP):
    """The agents' group's entry out again (configure --egress off). True when it changed the file. With no named
    entry left, the ACL goes, and the group bits of the mode are the group's own again."""
    have = acl_read(path, default=default)
    if have is None or not any(t == tag and i == gid for t, _, i in have):
        return False
    name = "system.posix_acl_default" if default else "system.posix_acl_access"
    rest = [e for e in have if not (e[0] == tag and e[2] == gid) and e[0] != ACL_MASK]
    if any(t in (ACL_USER, ACL_GROUP) for t, _, _ in rest):
        mask = 0
        for t, p, _ in rest:
            if t in (ACL_GROUP_OBJ, ACL_GROUP, ACL_USER):
                mask |= p
        os.setxattr(path, name, acl_bytes(rest + [(ACL_MASK, mask, ACL_NO_ID)]), follow_symlinks=False)
        return True
    os.removexattr(path, name, follow_symlinks=False)
    group = next((p for t, p, _ in rest if t == ACL_GROUP_OBJ), None)
    if not default and group is not None:
        os.chmod(path, (stat.S_IMODE(os.lstat(path).st_mode) & ~0o070) | (group << 3))
    return True


def egress_close(conf, which=None):
    """The closures of A1 and A2 for each service (or one): (what changed, what could not be closed), as texts. Root
    runs this at the root step, at each run of the rules' unit, and in each drop-in at a start of the service, before
    it opens its socket. A file system that keeps no ACL (a tmpfs of a kernel with no POSIX ACLs) cannot hold a
    closure: that is said, and nothing else of the gate stops for it."""
    try:
        gid = grp.getgrnam(conf["group"]).gr_gid
    except KeyError:
        return [], []
    done, failed = [], []
    for name, parts in EGRESS_CLOSED.items():
        if which and name != which:
            continue
        steps = ([(parts["default"], 4, True, "each new socket of")] if parts.get("default") else []) + \
            ([(parts["folder"], 0, False, "")] if parts.get("folder") else []) + \
            [(sock, 4, False, "") for sock in parts["sockets"]]
        for path, perm, default, words in steps:
            try:
                if acl_close(path, gid, perm, default=default):
                    done.append(f"{name}: {words + ' ' if words else ''}{path} refuses the agents")
            except OSError as e:
                failed.append(f"{name}: {path} ({e.strerror or type(e).__name__})")
    if failed:
        log(f"egress: no closure on {', '.join(failed)}: an agent there can still ask that service")
    return done, failed


def egress_open(conf):
    """The closures out again (configure --egress off)."""
    try:
        gid = grp.getgrnam(conf["group"]).gr_gid
    except KeyError:
        return
    for parts in EGRESS_CLOSED.values():
        for path, default in ([(parts["default"], True)] if parts.get("default") else []) + \
                [(p, False) for p in ([parts["folder"]] if parts.get("folder") else []) + list(parts["sockets"])]:
            try:
                acl_open(path, gid, default=default)
            except OSError:
                continue
    never = (conf["user"], conf["service_user"], conf["swap_user"])
    for sock in EGRESS_DAEMONS:
        for uid in egress_agents(conf["group"], never):
            try:
                acl_open(sock, uid, tag=ACL_USER)
            except OSError:
                continue


def egress_dbus(conf, agents):
    """The D-Bus policy of the closure of systemd-resolved: no agent user asks it for a name over D-Bus. The group's
    policy takes a supplementary group (proved with dbus-daemon 1.14 on 17 November 2026); one policy for each agent
    user too, for a bus that reads only a user's own group."""
    users = []
    for uid in agents:
        try:
            users.append(pwd.getpwuid(uid).pw_name)
        except KeyError:
            continue
    deny = '<deny send_destination="org.freedesktop.resolve1"/>'
    lines = [f'  <policy group="{conf["group"]}">{deny}</policy>'] + \
        [f'  <policy user="{u}">{deny}</policy>' for u in sorted(users) if GROUP_NAME.fullmatch(u)]
    return ('<?xml version="1.0"?>\n<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"\n'
            ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
            "<!-- Founderizer's outgoing gate: no agent user asks systemd-resolved for a name over D-Bus. Root's:\n"
            "     vault.py egress-rules writes it. -->\n<busconfig>\n" + "\n".join(lines) + "\n</busconfig>\n")


def egress_inputs():
    """One hash of the files that the table's sets come from."""
    digest = hashlib.sha256()
    for path in ("/etc/passwd", "/etc/group", EGRESS_SUBUID, EGRESS_BROWSER):
        try:
            with open(path, "rb") as f:
                digest.update(f.read(1 << 22))
        except OSError:
            digest.update(b"-")
        digest.update(b"\0")
    return digest.hexdigest()


def egress_table_step(conf, run, agents):
    """The table, inside EGRESS_LOCK: the whole table with its sets, in one nft transaction, whenever root's rules file
    is there, also while the gate does not run (the proposal's section 5.4); no table with no rules file (before the
    root step's gate serves, and after `--egress off`). The whole table each time: no refresh of a set depends on how
    a version of nft takes a flush and an add of an interval in one transaction. Root's file EGRESS_LOADED names the
    version that the kernel has: written after a load, removed with the table."""
    try:
        with open(EGRESS_RULES, encoding="utf-8") as f:
            rules = f.read()
    except FileNotFoundError:
        rules = None
    if rules is None:
        run(f"{EGRESS_NFT} delete table inet founderizer_egress >/dev/null 2>&1 || true")
        if egress_loaded(run) is not None:
            return {"ok": False, "reason": "the table did not go"}
        try:
            os.unlink(EGRESS_LOADED)
        except FileNotFoundError:
            pass
        return {"ok": True, "table": "none"}
    loaded = egress_loaded(run)
    code, out, err = run(f"{EGRESS_NFT} -f - <<'FOUNDERIZER_EGRESS'\n"
                         f"{egress_load_text(rules, egress_elements(conf, agents))}FOUNDERIZER_EGRESS\n")
    if code != 0:
        if loaded is None:              # nft applies a file whole or not at all: still no table
            try:
                os.unlink(EGRESS_LOADED)
            except FileNotFoundError:
                pass
        return {"ok": False, "reason": f"the table did not load: {(err or out).strip()[-300:]}"}
    try:
        egress_write_root(EGRESS_LOADED, f"{egress_rules_version(rules)}\n", 0o644)
    except OSError:
        pass                        # the table is there; only the gate's state misses it until the next step
    return {"ok": True, "table": "loaded"}


def egress_rules(conf, run=None, write=None, agents=None, families=None, table_only=False):
    """The rules' step (root, from the safe copy): at boot and at each change of /etc/group, /etc/subuid or the
    browsers' ports (the rules' units), and after nftables.service loads or flushes the kernel's rules (its drop-in).
    The table (egress_table_step); then, unless table_only, the closures, the D-Bus policy and no agent user in a
    container group. One table step at a time (EGRESS_LOCK). A path unit's event while its step runs starts no second
    run (the start joins the one that runs), and useradd writes /etc/group and /etc/subuid one after the other: so the
    step runs again while what it read changed under it. Returns the answer of one JSON line. families: the families
    of EGRESS_FAMILIES that a socket is made of here (a test's own)."""
    run = run or root_shell
    write = write or egress_write_root
    families = families or egress_open_families
    never = (conf["user"], conf["service_user"], conf["swap_user"])
    for _ in range(5):
        before = egress_inputs()
        answer = egress_rules_once(conf, run, write, agents, families, table_only, never)
        if not answer["ok"] or egress_inputs() == before:
            break
    return answer


def egress_rules_once(conf, run, write, agents, families, table_only, never):
    """One run of the rules' step (egress_rules)."""
    lock = os.open(EGRESS_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        agents = egress_agents(conf["group"], never) if agents is None else agents
        table = egress_table_step(conf, run, agents)
    finally:
        os.close(lock)
    if not table["ok"] or table_only:
        return table
    removed = []
    for uid in agents:
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            continue
        for group in EGRESS_CONTAINER_GROUPS:
            try:
                members = grp.getgrnam(group).gr_mem
            except KeyError:
                continue
            if user in members and run(f"gpasswd -d {shlex.quote(user)} {group} >/dev/null")[0] == 0:
                removed.append(f"{user}:{group}")
    if removed:
        log(f"egress: agent users out of the container groups: {', '.join(removed)}")
    closed, unclosed = egress_close(conf)
    for module in egress_open_families(tries=False):    # loaded before the step: out again, when no socket holds it
        if run(f"modprobe -r {module} >/dev/null 2>&1")[0] == 0:
            closed.append(f"the module {module} is out")
    # Then a socket of each family, here: root's unit has no list of families, and the gate's has one, so only this
    # step can find a family that is built into the kernel (the fourth review round). Only while the modprobe file
    # keeps each module from loading: without it a try would load the module that it looks for (the fifth round).
    if egress_modprobe_kept():
        for family in families():
            unclosed.append(f"the socket family {family} is open to the agents (built into this kernel, or its "
                            f"module is in use)")
    else:
        unclosed.append(f"{EGRESS_MODPROBE} is missing or changed, so the modules of the socket families of "
                        f"{', '.join(EGRESS_FAMILIES)} can load: run `vault.py configure --egress on` again")
    more_closed, more_unclosed = egress_daemons(conf, agents)
    closed += more_closed
    unclosed += more_unclosed
    egress_subids(agents, held=unclosed)
    try:
        dbus = write(EGRESS_DBUS, egress_dbus(conf, agents), 0o644)
    except OSError as e:
        dbus = False
        unclosed.append(f"dbus: {EGRESS_DBUS} ({e.strerror or type(e).__name__})")
    if dbus:
        run("systemctl reload dbus.service >/dev/null 2>&1 || true")
    return dict(table, agents=len(agents), groups_removed=removed, closed=closed, unclosed=unclosed, dbus=bool(dbus))


def egress_daemons(conf, agents=None):
    """A named user's entry with no right for each agent user on each container daemon's socket (EGRESS_DAEMONS): at
    each run of the rules' unit, and at each start of docker.socket (its drop-in)."""
    if agents is None:
        agents = egress_agents(conf["group"], (conf["user"], conf["service_user"], conf["swap_user"]))
    closed, unclosed = [], []
    for sock in EGRESS_DAEMONS:
        for uid in agents:
            try:
                if acl_close(sock, uid, 0, tag=ACL_USER):
                    closed.append(f"{sock} refuses the agent user {uid}")
            except OSError as e:
                unclosed.append(f"{sock} for {uid} ({e.strerror or type(e).__name__})")
    return closed, unclosed


EGRESS_FAMILY_SOCKETS = {"rxrpc": (33, socket.SOCK_DGRAM, socket.AF_INET), "smc": (43, socket.SOCK_STREAM, 0),
                         "rds": (21, socket.SOCK_SEQPACKET, 0), "tipc": (30, socket.SOCK_RDM, 0)}


def egress_modprobe_kept(path=None):
    """Whether the modprobe file keeps each module of EGRESS_FAMILIES from loading (an `install <module> /bin/false`
    line for each)."""
    try:
        with open(path or EGRESS_MODPROBE, encoding="utf-8") as f:
            lines = {line.strip() for line in f}
    except OSError:
        return False
    return all(f"install {module} /bin/false" in lines for module in EGRESS_FAMILIES)


def egress_open_families(path="/proc/modules", tries=True):
    """The families of EGRESS_FAMILIES that are open on this machine now: a loaded module, or (tries) a socket of it
    that this process can make, which also finds one that is built into the kernel and so in no list of modules. A
    try cannot load a module that the step keeps from loading."""
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            loaded = {line.split()[0] for line in f if line.strip()}
    except OSError:
        loaded = set()
    out = []
    for name in EGRESS_FAMILIES:
        opened = name in loaded
        if not opened and tries and sys.platform.startswith("linux"):
            try:
                socket.socket(*EGRESS_FAMILY_SOCKETS[name]).close()
                opened = True
            except OSError:
                pass
        if opened:
            out.append(name)
    return out


def egress_write_root(path, text, mode):
    """Write a root file only when its text changed: True when it did. Through a file beside it and a rename, so no
    reader sees half of it."""
    try:
        with open(path, encoding="utf-8") as f:
            if f.read() == text:
                return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def egress_hex(ip, port, mapped=False):
    """An address and a port as /proc/net/tcp, tcp6, udp and udp6 write them: each 32-bit word of the address in
    this machine's byte order, then the port. mapped: an IPv4 address in its IPv6 form (::ffff:a.b.c.d), as a program
    with one socket for both IP versions (Java, .NET) has it in the IPv6 table."""
    raw = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
    if mapped:
        raw = b"\0" * 10 + b"\xff\xff" + raw
    return "".join("%08X" % int.from_bytes(raw[i:i + 4], sys.byteorder) for i in range(0, len(raw), 4)) + \
        ":%04X" % port


EGRESS_WILD = {False: "00000000", True: "0" * 32}


def egress_rows(table):
    """(local, remote, state, uid) of each row of a table of the kernel's sockets."""
    try:
        with open(table, encoding="ascii") as f:
            next(f, None)
            for row in f:
                parts = row.split()
                if len(parts) > 7 and parts[7].isdigit():
                    yield parts[1], parts[2], parts[3], int(parts[7])
    except OSError:
        return


# The kernel's own lookup of one socket (NETLINK_SOCK_DIAG, inet_diag): no scan of /proc/net, which an agent could
# make as large as its open files allow with sockets that send nothing, and then each lookup of each agent would wait
# behind it (the third and fourth review rounds). The gate's unit allows AF_NETLINK; the swap proxy's has no list.
NETLINK_SOCK_DIAG, SOCK_DIAG_BY_FAMILY = 4, 20
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_DUMP = 1, 0x300
EGRESS_PORT_ROWS = 4096         # the sockets of one UDP port that the gate reads to place one DNS question, at most

# Whether the kernel's lookup works in this process, for TCP and for UDP: egress_lookup_check sets it at each start.
# A kernel with no inet_diag handler for a protocol (a container with no module to load) answers "no such socket"
# for each one, as it does for a socket that is not there, so only a check with a socket of the process's own tells
# the two apart. False: the lookups of that protocol read /proc. True until a check says otherwise.
EGRESS_LOOKUP = {socket.IPPROTO_TCP: True, socket.IPPROTO_UDP: True}


def egress_lookup_check(tcp_to=None):
    """At a process's start: does the kernel's exact lookup find a TCP connection and a UDP socket of this process's
    own? Sets EGRESS_LOOKUP, and returns {"tcp": ..., "udp": ...}: True when the lookup finds them, False when it
    runs and does not, and None when there was nothing to look up (no connection to `tcp_to`, as while the gate starts
    at boot). None keeps that lookup on: a moment with no listener must not send a process to /proc for its whole
    life (the fifth review round). tcp_to: the listener that the connection goes to, for a user whose table lets it
    reach no listener of its own (the swap proxy's: the gate's relay port)."""
    me = os.getuid()
    EGRESS_LOOKUP[socket.IPPROTO_TCP] = EGRESS_LOOKUP[socket.IPPROTO_UDP] = True
    tcp = udp = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as own:
            if not tcp_to:
                own.bind(("127.0.0.1", 0))
                own.listen(1)
            with socket.create_connection(tcp_to or own.getsockname(), timeout=5) as client:
                tcp = egress_diag(socket.AF_INET, socket.IPPROTO_TCP, client.getsockname()[:2],
                                  client.getpeername()[:2]) == me
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as own:
            own.bind(("127.0.0.1", 0))
            udp = egress_diag(socket.AF_INET, socket.IPPROTO_UDP, own.getsockname()[:2], ("0.0.0.0", 0)) == me
    except OSError:
        pass
    EGRESS_LOOKUP[socket.IPPROTO_TCP], EGRESS_LOOKUP[socket.IPPROTO_UDP] = tcp is not False, udp is not False
    return {"tcp": tcp, "udp": udp}


def egress_diag(family, protocol, local, remote):
    """The UID of the one socket of this protocol whose local end is `local` and whose remote end is `remote` (an
    exact lookup of the kernel, inet_diag), None when the kernel has no such socket, or False when the lookup itself
    cannot run here (no netlink, or the start check found that it does not work). An IPv4 lookup also finds a socket
    of both IP versions (Java, .NET)."""
    if not EGRESS_LOOKUP.get(protocol, True):
        return False

    def packed(ip):
        return socket.inet_pton(family, ip).ljust(16, b"\0")
    try:
        if protocol == socket.IPPROTO_UDP:          # udp_diag looks the socket up with its two ends swapped
            sockid = struct.pack("!HH", remote[1], local[1]) + packed(remote[0]) + packed(local[0])
        else:
            sockid = struct.pack("!HH", local[1], remote[1]) + packed(local[0]) + packed(remote[0])
    except (OSError, ValueError):
        return False
    sockid += struct.pack("=III", 0, 0xFFFFFFFF, 0xFFFFFFFF)          # any interface, no cookie
    req = struct.pack("=BBBBI", family, protocol, 0, 0, 0xFFFFFFFF) + sockid
    msg = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST, 1, 0) + req     # one socket
    try:
        with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_SOCK_DIAG) as nl:
            nl.settimeout(2)
            nl.sendto(msg, (0, 0))
            data = nl.recv(65536)
    except (OSError, AttributeError):
        return False
    i = 0
    while i + 16 <= len(data):
        size, kind = struct.unpack_from("=IH", data, i)
        if kind == SOCK_DIAG_BY_FAMILY and size >= 16 + 72 and i + 16 + 72 <= len(data):
            return struct.unpack_from("=I", data, i + 16 + 64)[0]            # inet_diag_msg idiag_uid
        if kind in (NLMSG_ERROR, NLMSG_DONE) or size < 16:
            return None
        i += (size + 3) & ~3
    return None


def egress_udp_port(family, port, most=EGRESS_PORT_ROWS):
    """(packed local address, uid) of each UDP socket of this family whose local port is `port`: one dump of the
    kernel's own table, in which the kernel keeps that port alone (udp_dump compares it), with no text of /proc. None
    when the port has more than `most` sockets (a question from it is not placed), False when the dump cannot run."""
    if not EGRESS_LOOKUP.get(socket.IPPROTO_UDP, True):
        return False
    sockid = struct.pack("!HH", port, 0) + bytes(32) + struct.pack("=III", 0, 0xFFFFFFFF, 0xFFFFFFFF)
    req = struct.pack("=BBBBI", family, socket.IPPROTO_UDP, 0, 0, 0xFFFFFFFF) + sockid
    msg = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, 1, 0) + req
    rows = []
    try:
        with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_SOCK_DIAG) as nl:
            nl.settimeout(2)
            nl.sendto(msg, (0, 0))
            while True:
                data, i = nl.recv(65536), 0
                if not data:
                    return False
                while i + 16 <= len(data):
                    size, kind = struct.unpack_from("=IH", data, i)
                    if kind == NLMSG_DONE:
                        return rows
                    if kind == NLMSG_ERROR or size < 16:
                        return False
                    if kind == SOCK_DIAG_BY_FAMILY and size >= 16 + 72 and i + 16 + 72 <= len(data):
                        wide = 16 if data[i + 16] == socket.AF_INET6 else 4      # idiag_family, then id.idiag_src
                        rows.append((data[i + 24:i + 24 + wide], struct.unpack_from("=I", data, i + 16 + 64)[0]))
                        if len(rows) > most:
                            return None
                    i += (size + 3) & ~3
    except (OSError, AttributeError, struct.error):
        return False


def egress_tcp_uid(peer, dest):
    """The UID of the program's own socket of a connection that the kernel sent to the gate: the socket whose local
    end is the peer that the gate sees and whose remote end is the ORIGINAL destination (the NAT is hidden from the
    program's socket; proved on 13 November 2026, P2). The kernel's exact lookup; the table of /proc only where that
    lookup does not work (egress_lookup_check). None when no socket has both: no caller, no service."""
    six = ":" in peer[0]
    found = egress_diag(socket.AF_INET6 if six else socket.AF_INET, socket.IPPROTO_TCP, peer[:2], dest[:2])
    if found is not False:
        return found
    forms = [("/proc/net/tcp6" if six else "/proc/net/tcp", False)] + ([] if six else [("/proc/net/tcp6", True)])
    for table, mapped in forms:
        local, remote = egress_hex(peer[0], peer[1], mapped), egress_hex(dest[0], dest[1], mapped)
        for loc, rem, _, uid in egress_rows(table):
            if loc == local and rem == remote:
                return uid
    return None


def egress_udp_fast(peer, servers):
    """The UID of the socket that sent a DNS question from `peer`, by the kernel's exact lookup: a socket that did not
    connect (any remote end), or one that connected to one of this machine's name servers, as glibc's resolver does.
    None when neither is so (a program that asked another name server: the slow way, egress_udp_uid), False with no
    netlink."""
    six = ":" in peer[0]
    family = socket.AF_INET6 if six else socket.AF_INET
    wild = "::" if six else "0.0.0.0"
    for remote in [(wild, 0)] + [(ip, 53) for ip in servers if (":" in ip) == six]:
        found = egress_diag(family, socket.IPPROTO_UDP, peer[:2], remote)
        if found is not None:
            return found
    return None


def egress_udp_uid(peer):
    """The UID of the socket that sent a DNS question from this address and port, when the exact lookups did not find
    it (egress_udp_fast: a socket that connected to a name server that is not this machine's): the kernel's own dump
    of the sockets of that port (egress_udp_port), or its table in /proc where the dump cannot run. A socket on the
    exact address decides before one of the same port on no address, and the question's own family before the IPv6
    form of an IPv4 address: a socket that another agent user binds on no address cannot make a question of a
    connected socket its own, or no one's. None when no socket, or two users at the first level that has one."""
    six = ":" in peer[0]
    try:
        raw = socket.inet_pton(socket.AF_INET6 if six else socket.AF_INET, peer[0])
    except (OSError, ValueError):
        return None
    if six:
        levels = [(socket.AF_INET6, raw), (socket.AF_INET6, bytes(16))]
    else:
        levels = [(socket.AF_INET, raw), (socket.AF_INET6, bytes(10) + b"\xff\xff" + raw),
                  (socket.AF_INET, bytes(4)), (socket.AF_INET6, bytes(16))]
    tables = {}
    for family, want in levels:
        if family not in tables:
            tables[family] = egress_udp_port(family, peer[1])
            if tables[family] is False:
                return egress_udp_proc(peer)
            if tables[family] is None:
                return None
        found = {uid for local, uid in tables[family] if local == want}
        if found:
            return found.pop() if len(found) == 1 else None
    return None


def egress_udp_proc(peer):
    """egress_udp_uid from the kernel's table of UDP sockets in /proc, with the same levels: where the kernel's own
    lookup does not work (egress_lookup_check)."""
    six = ":" in peer[0]
    if six:
        exact = egress_hex(peer[0], peer[1])
        levels = [("/proc/net/udp6", exact), ("/proc/net/udp6", EGRESS_WILD[True] + exact[-5:])]
    else:
        exact, mapped = egress_hex(peer[0], peer[1]), egress_hex(peer[0], peer[1], mapped=True)
        levels = [("/proc/net/udp", exact), ("/proc/net/udp6", mapped),
                  ("/proc/net/udp", EGRESS_WILD[False] + exact[-5:]), ("/proc/net/udp6", EGRESS_WILD[True] + exact[-5:])]
    for table, want in levels:
        found = {uid for loc, _, _, uid in egress_rows(table) if loc == want}
        if found:
            return found.pop() if len(found) == 1 else None
    return None


def egress_direct_uid(conn):
    """The UID of the other end of a connection that came to the gate directly (its relay port): the socket whose
    local end is the peer and whose remote end is the gate's own address, by the kernel's lookup (egress_tcp_uid)."""
    try:
        peer, own = conn.getpeername()[:2], conn.getsockname()[:2]
    except OSError:
        return None
    return egress_tcp_uid(peer, own)


def egress_original(conn, six):
    """(address, port) that the program connected to, before the kernel sent the connection to the gate."""
    if six:
        raw = conn.getsockopt(socket.IPPROTO_IPV6, 80, 28)      # IP6T_SO_ORIGINAL_DST
        return socket.inet_ntop(socket.AF_INET6, raw[8:24]), struct.unpack_from("!H", raw, 2)[0]
    raw = conn.getsockopt(socket.SOL_IP, 80, 16)                 # SO_ORIGINAL_DST
    return socket.inet_ntoa(raw[4:8]), struct.unpack_from("!H", raw, 2)[0]


def egress_host(value):
    """A host name as the records keep it (as the program wrote it, no dot at the end: a name can carry data in its
    labels, and the hub's check of a login's value is exact), or None for one that is not a name."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".")
    if not value or not EGRESS_NAME.fullmatch(value.lower()) or re.fullmatch(r"[0-9.]+", value):
        return None
    return value


def egress_sni(data):
    """("more", None) while the first TLS handshake message is not whole, else ("done", the server name or None).
    The message can lie in more than one record. A first byte that is no TLS handshake: ("done", None)."""
    if not data:
        return "more", None
    if data[0] != 0x16:
        return "done", None
    body, i = b"", 0
    while i + 5 <= len(data) and data[i] == 0x16 and len(body) < EGRESS_FIRST:
        size = struct.unpack_from("!H", data, i + 3)[0]
        if i + 5 + size > len(data):
            body += data[i + 5:]
            break
        body += data[i + 5:i + 5 + size]
        i += 5 + size
        if len(body) >= 4 and len(body) >= 4 + int.from_bytes(body[1:4], "big"):
            break
    if len(body) < 4:
        return ("more", None) if len(data) < EGRESS_FIRST else ("done", None)
    if body[0] != 0x01:
        return "done", None
    need = 4 + int.from_bytes(body[1:4], "big")
    if len(body) < need:
        return ("more", None) if len(data) < EGRESS_FIRST else ("done", None)
    hello = body[4:need]
    try:
        j = 2 + 32
        j += 1 + hello[j]                                       # session id
        j += 2 + struct.unpack_from("!H", hello, j)[0]          # cipher suites
        j += 1 + hello[j]                                       # compression methods
        end = j + 2 + struct.unpack_from("!H", hello, j)[0]
        j += 2
        while j + 4 <= end:
            kind, size = struct.unpack_from("!HH", hello, j)
            j += 4
            if kind == 0:                                       # server_name
                k, last = j + 2, j + size
                while k + 3 <= last:
                    form, length = hello[k], struct.unpack_from("!H", hello, k + 1)[0]
                    if form == 0:
                        return "done", egress_host(hello[k + 3:k + 3 + length].decode("ascii"))
                    k += 3 + length
                return "done", None
            j += size
    except (IndexError, struct.error, UnicodeError):
        pass
    return "done", None


EGRESS_METHOD = re.compile(rb"[A-Z]{1,16} (\S{1,8000}) HTTP/1\.[01]\r?\n")


def egress_http_host(data):
    """("more", None) while an HTTP/1 request head is not whole, else ("done", its host or None): the Host line, or
    the host of a request line in absolute form."""
    if not data:
        return "more", None
    line = EGRESS_METHOD.match(data)
    if not line:
        if re.match(rb"[A-Z]{1,16}( |$)", data[:17]) and b"\n" not in data and len(data) < EGRESS_FIRST:
            return "more", None
        return "done", None
    end = data.find(b"\r\n\r\n")
    if end < 0:
        end = data.find(b"\n\n")
    if end < 0:
        return ("more", None) if len(data) < EGRESS_FIRST else ("done", None)
    target = line.group(1).decode("latin-1")
    if "://" in target:
        try:
            return "done", egress_host(urllib.parse.urlsplit(target).hostname)
        except ValueError:
            return "done", None
    for raw in data[line.end():end].split(b"\n"):
        name, _, value = raw.decode("latin-1").partition(":")
        if name.strip().lower() == "host":
            value = value.strip()
            if value.startswith("["):
                return "done", None                             # an address, not a name
            return "done", egress_host(value.rsplit(":", 1)[0] if value.count(":") == 1 else value)
    return "done", None


def egress_first(data):
    """What the first bytes of a connection say: ("more", None, None), or ("done", name or None, how)."""
    state, name = egress_sni(data)
    if state == "more":
        return "more", None, None
    if data[:1] == b"\x16":
        return "done", name, "sni" if name else None
    state, name = egress_http_host(data)
    if state == "more":
        return "more", None, None
    return "done", name, "host" if name else None


def egress_dns_name(msg, i, depth=0):
    """(name, the index after it) of a DNS name at `i`, with its compression pointers."""
    labels, jumped, after = [], False, None
    for _ in range(128):
        size = msg[i]
        if size == 0:
            return ".".join(labels), (after if jumped else i + 1)
        if size & 0xC0 == 0xC0:
            if not jumped:
                after = i + 2
            jumped, i = True, ((size & 0x3F) << 8) | msg[i + 1]
            continue
        labels.append("".join(chr(b) if chr(b).isalnum() and b < 128 or b in b"-_" else "\\%03d" % b
                              for b in msg[i + 1:i + 1 + size]))      # DNS's own form: \DDD for each other byte
        i += 1 + size
    raise ValueError("a name with too many labels")


def egress_dns_question(msg):
    """(name, type) of a DNS question, or None."""
    try:
        if len(msg) < 12 or struct.unpack_from("!H", msg, 4)[0] < 1:
            return None
        name, i = egress_dns_name(msg, 12)
        return name.rstrip("."), struct.unpack_from("!H", msg, i)[0]
    except (IndexError, ValueError, struct.error):
        return None


def egress_dns_answers(msg):
    """The addresses of the A and AAAA records of a DNS answer, of every name in it (a CNAME chain ends at one)."""
    out = []
    try:
        count_q, count_a = struct.unpack_from("!HH", msg, 4)
        i = 12
        for _ in range(count_q):
            _, i = egress_dns_name(msg, i)
            i += 4
        for _ in range(count_a):
            _, i = egress_dns_name(msg, i)
            kind, _, _, size = struct.unpack_from("!HHIH", msg, i)
            i += 10
            if kind == 1 and size == 4:
                out.append(socket.inet_ntop(socket.AF_INET, msg[i:i + 4]))
            elif kind == 28 and size == 16:
                out.append(socket.inet_ntop(socket.AF_INET6, msg[i:i + 16]))
            i += size
    except (IndexError, ValueError, struct.error):
        pass
    return out


def egress_servfail(msg):
    """A DNS answer that says that the server failed, for a question that got no answer from this machine's name
    servers; None for bytes that are no question."""
    if egress_dns_question(msg) is None:
        return None
    _, i = egress_dns_name(msg, 12)
    flags = struct.unpack_from("!H", msg, 2)[0]
    return msg[:2] + struct.pack("!HHHHH", 0x8000 | (flags & 0x7900) | 0x0080 | 2, 1, 0, 0, 0) + msg[12:i + 4]


def egress_class(ip):
    """The kind of an address for the records: one of EGRESS_CLASSES, "local" for an address of this machine (the
    caller knows it), or "public"."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "public"
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.is_loopback:
        return "local"
    for kind, nets in EGRESS_CLASSES:
        if any(a in ipaddress.ip_network(n) for n in nets if ipaddress.ip_network(n).version == a.version):
            return kind
    return "public"


def egress_fold(name):
    """A name past the limit of names counts under its last two labels."""
    return ".".join(name.split(".")[-2:])


class EgressCounts:
    """What the gate counts, in memory: one row for each agent user, host (a name, or an address), port, verdict, how
    the name was read and the kind of address, with DNS questions, connections and bytes in each direction, and the
    first and the last time. The service user takes them (take), and they go to the hub with its readings. A count
    limit for each agent user, and never a clock: past EGRESS_NAMES names a new name counts under its last two labels,
    and past EGRESS_ROWS rows a new row counts on port 0."""

    FIELDS = ("dns", "conns", "up", "down")

    def __init__(self, clock=time.time):
        self.lock, self.clock, self.rows, self.names, self.per_user = threading.Lock(), clock, {}, {}, {}

    def key(self, uid, host, port, verdict, how, cls):
        """The row of one event. Each host is a name or an address: past EGRESS_NAMES of them a new one counts under
        its last two labels (an address under itself), past EGRESS_FOLDED of those and past EGRESS_ROWS rows as
        EGRESS_MORE on port 0. So one agent user's rows of a batch stay under EGRESS_ROWS and a few of EGRESS_MORE,
        whatever names or addresses it makes up."""
        names = self.names.setdefault(uid, {})
        if host not in names:
            if len(names) >= EGRESS_NAMES:
                folded = host if ":" in host or re.fullmatch(r"[0-9.]+", host) else egress_fold(host)
                host = folded if folded in names or len(names) < EGRESS_NAMES + EGRESS_FOLDED else EGRESS_MORE
            names.setdefault(host, True)
        key = (uid, host, port, verdict, how or "address", cls)
        if key not in self.rows and self.per_user.get(uid, 0) >= EGRESS_ROWS:
            key = (uid, EGRESS_MORE, 0, verdict, how or "address", cls)
        return key

    def add(self, uid, host, port, verdict, how, cls, **counts):
        """Count one event; returns its row's key, to which a connection adds its bytes."""
        with self.lock:
            key = self.key(uid, host, port, verdict, how, cls)
            self.add_key(key, counts)
            return key

    def add_key(self, key, counts, first=None, last=None):
        t = self.clock()
        if key not in self.rows:
            self.per_user[key[0]] = self.per_user.get(key[0], 0) + 1
        row = self.rows.setdefault(key, {"dns": 0, "conns": 0, "up": 0, "down": 0, "first": first or t, "last": t})
        for field in self.FIELDS:
            row[field] += int(counts.get(field) or 0)
        row["first"] = min(row["first"], first or t)
        row["last"] = max(row["last"], last or t)

    def take(self):
        """Each row, and the counts start again from zero."""
        with self.lock:
            rows, self.rows, self.names, self.per_user = self.rows, {}, {}, {}
        out = []
        for (uid, host, port, verdict, how, cls), row in rows.items():
            try:
                user = pwd.getpwuid(uid).pw_name
            except KeyError:
                user = None
            out.append(dict(row, uid=uid, user=user, host=host, port=port, verdict=verdict, how=how, cls=cls))
        return out

    def merge(self, rows):
        """Rows of another process of the gate (the one before a hand-over), added to these."""
        with self.lock:
            for r in rows if isinstance(rows, list) else []:
                try:
                    key = self.key(int(r["uid"]), str(r["host"]), int(r["port"]), str(r["verdict"]), str(r["how"]),
                                   str(r["cls"]))
                    self.add_key(key, r, first=float(r["first"]), last=float(r["last"]))
                except (KeyError, TypeError, ValueError):
                    continue


class EgressNames:
    """For each agent user, which name its DNS answer gave for which address: the name of a connection whose first
    bytes carry none (SSH, a database, a server that speaks first). A count limit for each user, never a clock."""

    def __init__(self):
        self.lock, self.by_user = threading.Lock(), {}

    def learn(self, uid, name, addresses):
        with self.lock:
            seen = self.by_user.setdefault(uid, {})
            for address in addresses:
                seen.pop(address, None)
                seen[address] = name
            while len(seen) > EGRESS_ADDRESSES:
                seen.pop(next(iter(seen)))

    def name(self, uid, address):
        with self.lock:
            return self.by_user.get(uid, {}).get(address)


def egress_six(address):
    """True for an IPv6 address, but not for an IPv4 address in its IPv6 form (::ffff:a.b.c.d), which reaches its
    host over IPv4: the dial's families (the fourth review round)."""
    if ":" not in address:
        return False
    try:
        return ipaddress.IPv6Address(address.split("%")[0]).ipv4_mapped is None
    except ValueError:
        return True


def egress_dial(port, first=None, name=None, resolve=None, connect=None, fallback=EGRESS_FALLBACK,
                patience=EGRESS_PATIENCE, stall=EGRESS_STALL):
    """A TCP connection for an agent, or None. To `first`, the address that the program chose, as it chose it; when
    that does not connect in `fallback` seconds and the gate knows the name, also to the name's other addresses, one
    each `fallback` seconds (RFC 8305): the program's own fallback cannot run, because the kernel gave it the gate's
    handshake at once. With no first address (the relay port), to the name's addresses in that order."""
    resolve = resolve or (lambda host: [a[4][0] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)])
    connect = connect or (lambda address: socket.create_connection((address, port), timeout=patience))
    cond, made, failed, started, over, refused = threading.Condition(), [], [], [], [], []

    def one(address):
        try:
            sock = connect(address)
        except ConnectionRefusedError:
            with cond:
                failed.append(address)
                if address == first:
                    refused.append(address)
                cond.notify_all()
            return
        except (OSError, UnicodeError, ValueError):
            with cond:
                failed.append(address)
                cond.notify_all()
            return
        with cond:
            late = bool(over)               # the dial ended: no one takes this connection
            if not late:
                made.append(sock)
                cond.notify_all()
        if late:
            sock.close()

    def start(address):
        started.append(address)
        threading.Thread(target=one, args=(address,), daemon=True).start()

    deadline = time.monotonic() + patience
    more, found, same_taken = None, None, False
    if first:
        start(first)
    with cond:
        while not made and time.monotonic() < deadline:
            # A refusal is the host's own answer: the program would have had it too. The fallback is for a path that
            # does not answer, or that has no route, to the name's other addresses, as a program's own fallback
            # (RFC 8305) goes: the other family after `fallback` seconds with no answer; the same family only after
            # the first address failed or gave no answer for `stall` seconds, so that a pinned address that answers
            # in time races no other host of its family.
            if found is None and name and (not first or (not refused and (failed or
                                           time.monotonic() - (deadline - patience) >= fallback))):
                cond.release()
                try:
                    found = [a for a in dict.fromkeys(resolve(name)) if a != first][:8]
                except (OSError, UnicodeError):
                    found = []
                finally:
                    cond.acquire()
                more = [a for a in found if first and egress_six(a) != egress_six(first)][:4]
            stalled = time.monotonic() - (deadline - patience) >= stall
            if found is not None and not same_taken and (not first or ((failed or stalled) and not refused)):
                same_taken = True
                same = [a for a in found if not first or egress_six(a) == egress_six(first)]
                other = list(more or [])
                more = []                       # the other family first, then in turn
                while other or same:
                    more += other[:1] + same[:1]
                    other, same = other[1:], same[1:]
                more = [a for a in more if a not in started][:4]
            if more:
                start(more.pop(0))
                cond.wait(fallback)
                continue
            if len(failed) >= len(started) and (not name or refused or (found is not None and same_taken)):
                break
            cond.wait(min(fallback, max(0.0, deadline - time.monotonic())))
        winner = made[0] if made else None
        over.append(True)
    for sock in made[1:]:
        sock.close()
    if winner is not None:
        for opt in ((socket.IPPROTO_TCP, socket.TCP_NODELAY), (socket.SOL_SOCKET, socket.SO_KEEPALIVE)):
            try:
                winner.setsockopt(*opt, 1)
            except OSError:
                pass
        winner.settimeout(None)
    return winner


def egress_reset(sock):
    """Close a connection with a reset, so that the program hears at once that it failed."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def egress_resolvers(path="/etc/resolv.conf"):
    """The name servers of this machine, as glibc reads them; 127.0.0.1 when there is none."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        out.append(str(ipaddress.ip_address(parts[1].split("%")[0])))
                    except ValueError:
                        continue
    except OSError:
        pass
    return out[:3] or ["127.0.0.1"]


class EgressFlow:
    """One connection that the gate relays: its agent user, its row once its name is read, and its bytes. Each
    direction's own thread writes its own count; take() reads them and adds what is new."""

    def __init__(self, uid, socks):
        self.uid, self.socks, self.key, self.lock = uid, socks, None, threading.Lock()
        self.up = self.down = self.told_up = self.told_down = 0
        self.first, self.named = b"", threading.Event()


class Egress:
    """The gate: its listeners, one thread for each connection's direction, its resolver, its control socket and its
    counts. In this step it refuses no host ("records only"); it refuses a caller that is no agent user, and an
    agent user past its limit of connections, and it never relays a connection to one of its own ports."""

    LISTENERS = (("out4", "out", False), ("out6", "out", True), ("local4", "local", False),
                 ("local6", "local", True), ("relay4", "relay", False), ("dns4", "dns", False),
                 ("dns6", "dns", True), ("dnst4", "dnst", False), ("dnst6", "dnst", True))

    def __init__(self, conf, socks=None, program=None, spawn=None, parent=None, state=EGRESS_STATE,
                 clock=time.time, dial=egress_dial, resolvers=egress_resolvers, ports=None):
        self.conf, self.state, self.clock, self.dial, self.resolvers = conf, state, clock, dial, resolvers
        self.ports = dict(EGRESS_PORTS, **(ports or {}))
        self.counts, self.names = EgressCounts(clock), EgressNames()
        self.lock, self.cond = threading.Lock(), threading.Condition()
        self.flows, self.open, self.asking = set(), {}, {}
        self.program, self.spawn, self.parent = program, spawn, parent
        self.ending, self.heir, self.trying, self.failed = False, None, False, None
        self.threads = threading.BoundedSemaphore(EGRESS_THREADS)     # each handler's thread holds one
        self.handlers = 0                       # handlers that run now: a hand-over waits for them too
        self.slow = queue.Queue(maxsize=256)    # DNS questions that the kernel's exact lookup did not place
        self.controls = threading.BoundedSemaphore(EGRESS_CONTROLS)
        self.loops = []
        self.since, self.agents_at, self.agents = clock(), None, set()
        self.policy = self.load_policy()
        self.socks = socks if socks is not None else self.listen()
        self.installed_at = self.installed = None

    # ---- listeners
    def listen(self):
        socks = {}
        for name, kind, six in self.LISTENERS:
            port = self.ports[kind if kind != "dnst" else "dns"]
            family = socket.AF_INET6 if six else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM if kind == "dns" else socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if six:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(("::1" if six else "127.0.0.1", port))
                if kind != "dns":
                    sock.listen(1024)
            except OSError:
                sock.close()
                if six:
                    continue                # a machine with no IPv6 sends the gate no IPv6
                raise
            socks[name] = sock
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = self.conf.get("control") or EGRESS_CONTROL
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        control.bind(path)
        os.chmod(path, 0o666)               # SO_PEERCRED decides who it answers (control)
        control.listen(64)
        socks["control"] = control
        return socks

    def is_agent(self, uid):
        """An agent user of this machine now: a member of its group, read again when /etc/group changes."""
        try:
            at = os.stat("/etc/group").st_mtime_ns
        except OSError:
            at = None
        if at != self.agents_at:
            never = (self.conf["user"], self.conf["service_user"], self.conf["swap_user"])
            self.agents, self.agents_at = set(egress_agents(self.conf["group"], never)), at
        return uid in self.agents

    # ---- the policy (step 1: "records" only)
    def load_policy(self):
        try:
            with open(os.path.join(self.state, "policy.json"), encoding="utf-8") as f:
                return egress_policy(json.load(f))
        except (OSError, ValueError, Refused):
            return None

    def set_policy(self, value):
        policy = egress_policy(value)       # Refused: the last policy stays
        tmp = os.path.join(self.state, "policy.json.new")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(policy, f)
        os.replace(tmp, os.path.join(self.state, "policy.json"))
        self.policy = policy

    # ---- one connection
    def begin_flow(self, uid, socks):
        """A flow of this agent user, or None past its limit of connections."""
        with self.lock:
            if self.open.get(uid, 0) >= EGRESS_PER_USER:
                return None
            self.open[uid] = self.open.get(uid, 0) + 1
            flow = EgressFlow(uid, socks)
            self.flows.add(flow)
            return flow

    def end(self, flow):
        self.told(flow)
        with self.lock:
            self.flows.discard(flow)
            self.open[flow.uid] = self.open.get(flow.uid, 1) - 1
            if self.open[flow.uid] <= 0:
                self.open.pop(flow.uid, None)
        with self.cond:
            self.cond.notify_all()

    def told(self, flow):
        """A flow's new bytes into its row."""
        with flow.lock:
            if not flow.key:
                return
            now_up, now_down = flow.up, flow.down          # each read once: a pump adds while this runs
            up, down = now_up - flow.told_up, now_down - flow.told_down
            flow.told_up, flow.told_down = now_up, now_down
        if up or down:
            with self.counts.lock:
                self.counts.add_key(flow.key, {"up": up, "down": down})

    def name_flow(self, flow, host, port, how, cls, verdict="pass"):
        with flow.lock:
            if flow.key is not None:
                return
            flow.key = self.counts.add(flow.uid, host, port, verdict, how, cls, conns=1)
        flow.named.set()

    def outbound(self, conn, six, local):
        """A TCP connection of an agent user, from the kernel's redirect: to another host (port out) or to an address
        of this machine (port local)."""
        try:
            peer = conn.getpeername()[:2]
            dst, dport = egress_original(conn, six)
        except OSError:
            return egress_reset(conn)
        uid = egress_tcp_uid(peer, (dst, dport))
        if uid is None or not self.is_agent(uid):
            return egress_reset(conn)       # only the kernel's redirect of an agent user's socket comes here
        if local and dport in self.ports.values():
            return egress_reset(conn)       # never one of the gate's own ports: that would be a loop
        flow = self.begin_flow(uid, [conn])
        if flow is None:
            self.counts.add(uid, dst, dport, "busy", "address", "local" if local else egress_class(dst), conns=1)
            return egress_reset(conn)
        try:
            known = self.names.name(uid, dst)
            up = self.dial(dport, first=dst, name=known)
            cls = "local" if local else egress_class(dst)
            if up is None:
                self.name_flow(flow, known or dst, dport, "dns" if known else "address", cls)
                return egress_reset(conn)
            flow.socks.append(up)
            self.relay(flow, conn, up, dport, cls, known or dst, "dns" if known else "address")
        finally:
            self.end(flow)

    def relay(self, flow, client, site, port, cls, plain, plain_how, first=b"", host=None):
        """Both directions until both ended. The client's first bytes are read for a name as they pass, never held
        back, and no byte after them; then the kernel moves the rest (os.splice) with no copy in this process.
        plain, plain_how: the row's host when no first byte names one (the name that the resolver gave this agent for
        the address, or the address). host: the relay port's CONNECT host, which names the row."""
        for sock in (client, site):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

        def name_seen(data, done):
            if flow.named.is_set():
                return
            state, name, found = egress_first(data)
            if state == "more" and not done:
                return
            if host:
                self.name_flow(flow, host, port, "relay", cls)
                if name and name != host:           # the inner name of a tunnel, as the swap proxy sent it
                    self.counts.add(flow.uid, name, port, "pass", "relay-sni", cls, conns=1)
            elif name:
                self.name_flow(flow, name, port, found, cls)
            else:
                self.name_flow(flow, plain, port, plain_how, cls)

        back = threading.Thread(target=self.pump, args=(site, client, flow, "down", lambda data: name_seen(b"", True)),
                                daemon=True)
        back.start()
        self.pump(client, site, flow, "up", lambda data: name_seen(data, False), first=first)
        name_seen(b"", True)
        back.join()
        for sock in (client, site):
            try:
                sock.close()
            except OSError:
                pass

    def pump(self, source, target, flow, direction, look, first=b""):
        """One direction until its end. `look` sees the first bytes (up) or hears that the server spoke first
        (down). Then the end goes to the other side."""
        seen = first
        try:
            if first:
                look(seen)
                target.sendall(first)
                setattr(flow, direction, getattr(flow, direction) + len(first))
            while not flow.named.is_set() and len(seen) < EGRESS_FIRST:
                data = source.recv(65536)
                if not data:
                    break
                seen += data
                look(seen)                  # before the bytes go on: the answer they bring cannot name it first
                target.sendall(data)
                setattr(flow, direction, getattr(flow, direction) + len(data))
            else:
                self.splice(source, target, flow, direction)
        except (OSError, ValueError):
            pass
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def splice(self, source, target, flow, direction):
        """The rest of one direction: os.splice through a pipe where the kernel has it (measured on 17 November
        2026: 3.8 to 4.5 GB/s for the relay alone, a quarter of the CPU of a copy), else recv and sendall."""
        if hasattr(os, "splice"):
            r, w = os.pipe()
            moved = 0
            try:
                while True:
                    try:
                        n = os.splice(source.fileno(), w, 65536, flags=os.SPLICE_F_MOVE)
                    except OSError as e:
                        if e.errno == errno.EINVAL and not moved:
                            break                       # no splice for this pair: the copy below
                        raise
                    if n == 0:
                        return
                    left = n
                    while left:
                        left -= os.splice(r, target.fileno(), left, flags=os.SPLICE_F_MOVE)
                    moved += n
                    setattr(flow, direction, getattr(flow, direction) + n)
            finally:
                os.close(r)
                os.close(w)
        while True:
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)
            setattr(flow, direction, getattr(flow, direction) + len(data))

    def relayed(self, conn):
        """The relay port: the swap proxy's connection for an agent user (the key swap with the gate), and nobody
        else's. One CONNECT head with the agent's UID; the gate looks the host up, connects, answers 200, and relays
        as for the agent itself."""
        try:
            self.relay_port(conn)
        except OSError:
            egress_reset(conn)

    def relay_port(self, conn):
        uid = egress_direct_uid(conn)
        if uid is None or uid != egress_uid_of(self.conf["swap_user"]):
            return egress_reset(conn)
        conn.settimeout(EGRESS_PATIENCE)
        head, rest = swap_head(conn, EGRESS_HEAD)
        conn.settimeout(None)
        found = SWAP_CONNECT.match(head or b"")
        agent = None
        for line in (head or b"").split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == EGRESS_UID_HEADER.lower().encode() and value.strip().isdigit():
                agent = int(value.strip())
        port = int(found.group(3)) if found else 0
        host = (found.group(1) or found.group(2)).decode("ascii").lower() if found else None
        if not found or not 0 < port < 65536 or agent is None or not self.is_agent(agent):
            swap_say(conn, "400 Bad Request", "The gate's relay port takes CONNECT host:port with the agent user's "
                                              "UID, from the swap proxy only.")
            conn.close()
            return
        flow = self.begin_flow(agent, [conn])
        if flow is None:
            self.counts.add(agent, host, port, "busy", "relay", "public", conns=1)
            swap_say(conn, "503 Service Unavailable", "This agent user has too many connections.")
            conn.close()
            return
        try:
            literal = None
            try:
                literal = str(ipaddress.ip_address(host))
            except ValueError:
                pass
            up = self.dial(port, first=literal, name=None if literal else host)
            cls = egress_class(up.getpeername()[0]) if up is not None else "public"
            if up is None:
                self.name_flow(flow, host, port, "relay", cls)
                swap_say(conn, "502 Bad Gateway", "The gate could not reach this host.")
                return conn.close()
            flow.socks.append(up)
            try:
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except OSError:
                up.close()
                return conn.close()
            self.relay(flow, conn, up, port, cls, host, "relay", first=rest, host=host)
        finally:
            self.end(flow)

    # ---- DNS
    def asked(self, data, peer, uid=None):
        """(uid, question) of a DNS question over UDP that the gate takes, counted in its user's limit; None for one
        that it drops. uid: from the kernel's exact lookup, or else the slow lookup here."""
        if uid is None:
            uid = egress_udp_uid(peer[:2])
        asked = egress_dns_question(data)
        if uid is None or asked is None or not self.is_agent(uid):
            return None
        with self.lock:
            if self.asking.get(uid, 0) >= EGRESS_DNS_PER_USER:
                return None
            self.asking[uid] = self.asking.get(uid, 0) + 1
        return uid, asked

    def question(self, sock, data, peer, uid, asked):
        """One DNS question over UDP that `asked` took, from its own thread."""
        try:
            answer = self.upstream(data)
            self.counts.add(uid, asked[0] or ".", 53, "pass", "dns", "", dns=1)
            if answer is not None:
                self.names.learn(uid, asked[0], egress_dns_answers(answer))
            reply = answer if answer is not None else egress_servfail(data)
            if reply:
                try:
                    sock.sendto(reply, peer)
                except OSError:
                    pass
        finally:
            self.done_asking(uid)

    def done_asking(self, uid):
        with self.lock:
            self.asking[uid] = self.asking.get(uid, 1) - 1
            if self.asking[uid] <= 0:
                self.asking.pop(uid, None)
        with self.cond:
            self.cond.notify_all()

    def held(self, target, *args):
        """A handler in a thread that holds one of EGRESS_THREADS, counted from before its thread starts (start_held),
        so that a process that gives way ends only after it (a connection that its loop took last is not cut before
        its flow begins)."""
        try:
            target(*args)
        finally:
            self.threads.release()
            with self.lock:
                self.handlers -= 1
            with self.cond:
                self.cond.notify_all()

    def upstream(self, data):
        """The answer of this machine's own name servers, asked as the gate's user, or None."""
        for server in self.resolvers():
            with socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.settimeout(4)
                try:
                    u.connect((server, 53))
                    u.send(data)
                    for _ in range(4):
                        answer = u.recv(65535)
                        if answer[:2] == data[:2]:
                            return answer
                except OSError:
                    continue
        return None

    def stream_dns(self, conn, six):
        """DNS over TCP (a long answer, or a program that asks so): each question as it comes, to the first name
        server over TCP."""
        try:
            peer = conn.getpeername()[:2]
            dst = egress_original(conn, six)
        except OSError:
            return egress_reset(conn)
        uid = egress_tcp_uid(peer, dst)
        if uid is None or not self.is_agent(uid):
            return egress_reset(conn)
        flow = self.begin_flow(uid, [conn])          # in the agent user's own limit, as each of its connections
        if flow is None:
            return egress_reset(conn)
        flow.key = ()                           # no row of its own: each question counts as DNS
        up, deadline = None, time.monotonic() + EGRESS_STREAM
        try:
            conn.settimeout(EGRESS_PATIENCE)
            for _ in range(256):
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                conn.settimeout(min(EGRESS_PATIENCE, left))
                size = self.exactly(conn, 2, deadline)
                if size is None:
                    return
                data = self.exactly(conn, struct.unpack("!H", size)[0], deadline)
                if data is None:
                    return
                asked = egress_dns_question(data)
                if up is None:
                    server = self.resolvers()[0]
                    up = socket.create_connection((server, 53), timeout=EGRESS_PATIENCE)
                up.sendall(size + data)
                head = self.exactly(up, 2)
                answer = self.exactly(up, struct.unpack("!H", head)[0]) if head else None
                if answer is None:
                    return
                if asked:
                    self.counts.add(uid, asked[0] or ".", 53, "pass", "dns", "", dns=1)
                    self.names.learn(uid, asked[0], egress_dns_answers(answer))
                conn.sendall(head + answer)
        except (OSError, struct.error):
            pass
        finally:
            for s in (conn, up):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self.end(flow)

    @staticmethod
    def exactly(sock, size, deadline=None):
        """`size` bytes, or None; with a deadline, each read waits no longer than the time that is left."""
        data = b""
        while len(data) < size:
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                sock.settimeout(min(EGRESS_PATIENCE, left))
            try:
                part = sock.recv(size - len(data))
            except socket.timeout:
                return None
            if not part:
                return None
            data += part
        return data

    # ---- the control socket: the service user's word, and the gate's own counts at a hand-over
    def control(self, conn):
        """One request on the control socket. The caller's UID first (SO_PEERCRED): a caller that is neither the
        service user nor the gate's own user is closed before one byte is read. Then one line, with a deadline for
        the whole of it, and at most EGRESS_CONTROLS requests at one time."""
        try:
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", cred)
        except OSError:
            conn.close()
            return
        own = uid == os.getuid()
        if not own and uid != egress_uid_of(self.conf["service_user"]):
            conn.close()
            return
        if not self.controls.acquire(blocking=False):
            conn.close()
            return
        try:
            line = egress_line(conn, EGRESS_LINE if own else EGRESS_ASK, 30)
            try:
                request = json.loads(line) if line else None
            except ValueError:
                request = None
            answer = self.control_answer(uid, request if isinstance(request, dict) else {})
            conn.sendall((json.dumps(answer) + "\n").encode())
        except OSError:
            pass
        finally:
            self.controls.release()
            conn.close()

    def control_answer(self, uid, request):
        op = request.get("op")
        if uid == os.getuid() and op == "merge":
            if self.ending:                 # a process that gives way takes no counts: the one that serves does
                return {"ok": False, "reason": "this gate gives way"}
            self.counts.merge(request.get("rows"))
            return {"ok": True}
        if uid != egress_uid_of(self.conf["service_user"]):
            return {"ok": False, "reason": "the gate answers this machine's Founderizer service only"}
        if op == "status":
            self.consider()
            return self.gate_state()
        if op == "counts":
            with self.lock:
                flows = list(self.flows)
            for flow in flows:
                self.told(flow)
            return {"ok": True, "rows": self.counts.take(), "since": self.since}
        if op == "policy":
            try:
                self.set_policy(request.get("policy"))
            except (Refused, OSError) as e:
                return {"ok": False, "reason": str(e)}
            return {"ok": True}
        return {"ok": False, "reason": "op is status, counts or policy"}

    @staticmethod
    def crashed(program):
        """How often the gate's process ended, with no stop that anybody asked for, while this program served, in the
        last EGRESS_CRASHES_HOUR (EGRESS_CRASHES, which the launcher writes from the unit's ExecStopPost)."""
        since = egress_uptime() - EGRESS_CRASHES_HOUR
        try:
            with open(EGRESS_CRASHES, encoding="ascii") as f:
                lines = f.read(1 << 20).splitlines()
        except (OSError, UnicodeDecodeError):
            return 0
        count = 0
        for line in lines:
            parts = line.split()
            try:
                count += len(parts) == 2 and parts[0] == program and float(parts[1]) > since
            except ValueError:
                pass
        return count

    def gate_state(self):
        """table: the version of the table that the kernel has now, by root's word (EGRESS_LOADED), or None."""
        try:
            with open(EGRESS_LOADED, encoding="ascii") as f:
                text = f.read(16)
            table = int(text) if re.fullmatch(r"[0-9]{1,6}\n", text) else None
        except (OSError, UnicodeDecodeError):
            table = None
        with self.lock:
            open_now = sum(self.open.values())
        return {"ok": True, "program": self.program, "table": table, "knows_table": EGRESS_TABLE,
                "lookup": {"tcp": EGRESS_LOOKUP[socket.IPPROTO_TCP], "udp": EGRESS_LOOKUP[socket.IPPROTO_UDP]},
                "policy": self.policy, "mode": "records", "since": self.since,
                "open": open_now, "handover": "trying" if self.trying else None,
                "failed": {"program": self.failed[0], "tries": self.failed[1]} if self.failed else None}

    # ---- a new program: the hand-over with no cut (the swap proxy's, SwapProxy.consider and candidate)
    def consider(self):
        """At the service user's word: when the installed program is another than this process's own, it gets its
        try to take over. A program that failed gets its next try only after more words (4, then 16, 64, 256 and
        then each 1024)."""
        program = self.installed_program()
        if not (self.spawn and program and program != self.program):
            return
        with self.lock:
            if self.ending or self.trying:
                return
            if self.failed and self.failed[0] == program and self.failed[2] > 0:
                self.failed = (program, self.failed[1], self.failed[2] - 1)
                return
            if self.crashed(program) >= EGRESS_CRASHES_MOST:     # it ended that often after it took over
                return
            self.trying = True
        threading.Thread(target=self.candidate, args=(program,), daemon=True).start()

    def installed_program(self):
        """The SHA-256 of the installed vault program, read again only when the file changed."""
        try:
            info = os.stat(INSTALLED)
        except OSError:
            return None
        at = (info.st_mtime_ns, info.st_size, info.st_ino)
        if at != self.installed_at:
            try:
                with open(INSTALLED, "rb") as f:
                    self.installed = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                return None
            self.installed_at = at
        return self.installed

    def candidate(self, program):
        try:
            taken = self.spawn(program, self.socks)
        except Exception as e:              # never a detail
            taken = f"the try failed ({type(e).__name__})"
        with self.lock:
            self.trying = False
            if taken is None:
                return
            if isinstance(taken, str):
                tries = self.failed[1] + 1 if self.failed and self.failed[0] == program else 1
                self.failed = (program, tries, min(4 ** tries, 1024))
            else:
                self.heir, self.ending = taken, True
        if isinstance(taken, str):
            log(f"egress: the gate of the new vault program did not start ({taken}): this gate goes on with the "
                f"program that it runs, and tries that program again later (try {tries})")
            return
        log("egress: the gate of a new vault program serves now")
        with self.cond:
            self.cond.notify_all()
        if self.parent and self.parent > 1 and os.getppid() == self.parent:
            try:
                os.kill(self.parent, signal.SIGTERM)
            except OSError:
                pass

    # ---- the loops
    def accept(self, name, kind, six):
        sock = self.socks[name]
        sock.settimeout(1)
        while not self.ending:
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.ending:
                    return
                time.sleep(0.05)
                continue
            conn.settimeout(None)
            target = {"out": lambda c: self.outbound(c, six, False), "local": lambda c: self.outbound(c, six, True),
                      "relay": self.relayed, "dnst": lambda c: self.stream_dns(c, six),
                      "control": self.control}[kind]
            if not self.start_held(target, conn):
                egress_reset(conn)

    def datagrams(self, name):
        sock = self.socks[name]
        sock.settimeout(1)
        while not self.ending:
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self.ending:
                    return
                continue
            uid = egress_udp_fast(peer[:2], self.resolvers())
            if uid is None or uid is False:         # a socket that the exact lookup does not find: the slow way
                try:
                    self.slow.put_nowait((sock, data, peer))
                except queue.Full:
                    pass                            # the program asks again; no other agent waits behind it
                continue
            self.take_question(sock, data, peer, uid)

    def take_question(self, sock, data, peer, uid=None):
        took = self.asked(data, peer, uid)
        if took is None:
            return
        if not self.start_held(self.question, sock, data, peer, *took):
            self.done_asking(took[0])

    def start_held(self, target, *args):
        """Start one handler's thread, holding one of EGRESS_THREADS and counted in `handlers` before it starts. False
        when there is no room or no thread."""
        if not self.threads.acquire(blocking=False):
            return False
        with self.lock:
            self.handlers += 1
        try:
            threading.Thread(target=self.held, args=(target,) + args, daemon=True).start()
        except RuntimeError:
            self.threads.release()
            with self.lock:
                self.handlers -= 1
            return False
        return True

    def slow_questions(self):
        """The one worker of the questions that the exact lookups did not place: a dump of the sockets of the
        question's port for each (egress_udp_uid), and it holds back no other question."""
        while not self.ending:
            try:
                sock, data, peer = self.slow.get(timeout=1)
            except queue.Empty:
                continue
            self.take_question(sock, data, peer)

    def serve_gate(self):
        """Serve until a new process serves; then end with the connections that this one holds, and give the new one
        the counts."""
        threads = []
        for name, kind, six in self.LISTENERS + (("control", "control", False),):
            if name in self.socks:
                loop = self.datagrams if kind == "dns" else self.accept
                args = (name,) if kind == "dns" else (name, kind, six)
                threads.append(threading.Thread(target=loop, args=args, daemon=True))
        threads.append(threading.Thread(target=self.slow_questions, daemon=True))
        for t in threads:
            t.start()
        self.loops = threads
        with self.cond:
            while not self.ending:
                self.cond.wait()
        for t in threads:                       # each loop sees `ending` within a second: no new connection after it
            t.join()
        with self.cond:
            while self.flows or self.asking or self.handlers:   # its connections, questions and handlers
                self.cond.wait()
        for flow in list(self.flows):
            self.told(flow)
        egress_merge(self.counts.take(), self.conf.get("control") or EGRESS_CONTROL)


def egress_line(conn, limit, seconds):
    """One line of at most `limit` bytes, within `seconds` for the whole of it (a caller that sends one byte at a
    time does not hold the gate's thread), or "" when it does not come."""
    deadline, data = time.monotonic() + seconds, b""
    while not data.endswith(b"\n") and len(data) < limit:
        left = deadline - time.monotonic()
        if left <= 0:
            return ""
        conn.settimeout(left)
        try:
            part = conn.recv(min(65536, limit - len(data)))
        except socket.timeout:
            return ""
        if not part:
            break
        data += part
    return data.decode("utf-8", "replace") if data.endswith(b"\n") else ""


def egress_merge(rows, path=EGRESS_CONTROL, tries=5):
    """The counts of a gate that gave way, to the gate that serves now (its own user: Egress.control_answer, merge). A gate
    that gives way answers no: then the next one in a moment."""
    if not rows:
        return True
    line = (json.dumps({"op": "merge", "rows": rows}) + "\n").encode()
    for _ in range(tries):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(path)
                s.sendall(line)
                if json.loads(egress_line(s, 4096, 10) or "{}").get("ok") is True:
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(1)
    log(f"egress: {len(rows)} rows of counts did not reach the gate that serves now")
    return False


def egress_policy(value):
    """The policy that the hub gives through the service user, checked. Step 1 knows version 1 with the mode
    "records" (pass each connection, and count it); a policy of another version or mode is refused, and the gate keeps
    the last one."""
    if not isinstance(value, dict) or value.get("version") != EGRESS_POLICY:
        raise Refused(f"this gate takes a policy of version {EGRESS_POLICY}")
    if value.get("mode") != "records":
        raise Refused("this gate takes the mode records only")
    return {"version": EGRESS_POLICY, "mode": "records"}


def egress_uptime():
    """Seconds since this machine's boot (/proc/uptime): the clock of EGRESS_CRASHES, which lasts one boot in /run, as
    the launcher reads it too. No step of the wall clock moves it."""
    try:
        with open("/proc/uptime", encoding="ascii") as f:
            return float(f.read(64).split()[0])
    except (OSError, ValueError, IndexError):
        return time.monotonic()


def egress_policy_taken(state=None):
    """Whether this program takes the policy that a gate stored here (no policy is taken too). A policy of a version
    or a mode that this program does not know was stored by a later program, so this one must not serve in its place:
    it would refuse less than that policy says. So the launcher's fallback to the safe copy of an earlier root step
    never drops a later step's refusals (a review of 17 November 2026); the table stays while no gate serves. Two
    rules follow for each later program: it takes every older policy, and it stores an older one that the hub gives
    (a release that goes back); else a server can be left with no program that starts."""
    try:
        with open(os.path.join(state or EGRESS_STATE, "policy.json"), encoding="utf-8") as f:
            value = json.load(f)
    except (OSError, ValueError):
        return True
    try:
        egress_policy(value)
    except Refused:
        return False
    return True


def egress_take_spec(socks, pipe):
    """The --take argument of a hand-over: name=fd for each listener, and the pipe."""
    return ",".join(f"{name}={sock.fileno()}" for name, sock in sorted(socks.items())) + f",pipe={pipe}"


def egress_candidate(config, program, socks):
    """Start the installed program as the gate that takes over from this process (Egress.candidate): a child with
    each listener and one pipe, as swap_candidate does for the swap proxy. The child (a Popen) when it says that it
    serves; None when the installed file changed again (an update is in the middle); else the reason as text.

    The contract that a later version keeps: the arguments `egress --config <file> --take name=fd,...,pipe=fd`, the
    word EGRESS_SERVES on the pipe only after systemd has MAINPID, the counts of a gate that gave way through its
    own user's op "merge", and SIGTERM as the end of the process before."""
    try:
        with open(INSTALLED, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != program:
                return None
    except OSError:
        return None
    if not os.environ.get("NOTIFY_SOCKET"):
        return SWAP_NO_UNIT
    mine = theirs = child = None
    try:
        mine, theirs = os.pipe()
        fds = tuple(s.fileno() for s in socks.values()) + (theirs,)
        child = subprocess.Popen([sys.executable, "-I", INSTALLED, "egress", "--config", config, "--take",
                                  egress_take_spec(socks, theirs)], pass_fds=fds, stdin=subprocess.DEVNULL)
        os.close(theirs)
        theirs = None
        look = select.poll()
        look.register(mine, select.POLLIN)
        ready = look.poll(EGRESS_CANDIDATE * 1000)
        if ready and os.read(mine, 16) == EGRESS_SERVES:
            return child
        if ready:
            try:
                reason = f"exit {child.wait(timeout=5)}"
            except subprocess.TimeoutExpired:
                reason = "it did not say that it serves"
        else:
            reason = f"no word in {EGRESS_CANDIDATE} seconds"
    except Exception as e:              # never a detail
        reason = f"the try failed ({type(e).__name__})"
    finally:
        for end in (mine, theirs):
            if end is not None:
                try:
                    os.close(end)
                except OSError:
                    pass
    if child is not None and child.poll() is None:
        child.kill()
        child.wait()
        reason += ", and it was ended"
    if child is not None:
        swap_notify(f"MAINPID={os.getpid()}")
    return reason


def egress_taken(spec, ports=None):
    """{name: socket} and the pipe from a --take argument, each checked: the gate's own listener at its own address
    and port, and no other socket. Raises SystemExit."""
    ports = dict(EGRESS_PORTS, **(ports or {}))
    want = {name: (socket.AF_INET6 if six else socket.AF_INET,
                   socket.SOCK_DGRAM if kind == "dns" else socket.SOCK_STREAM,
                   ("::1" if six else "127.0.0.1", ports[kind if kind != "dnst" else "dns"]))
            for name, kind, six in Egress.LISTENERS}
    socks, pipe = {}, None
    for part in spec.split(","):
        name, _, number = part.partition("=")
        if not number.isdigit():
            raise SystemExit("--take is for the gate's own hand-over.")
        if name == "pipe":
            pipe = int(number)
            continue
        try:
            sock = socket.socket(fileno=int(number))
        except OSError:
            raise SystemExit(f"The gate cannot take over: {name} is no socket.") from None
        if name == "control":
            ok = sock.family == socket.AF_UNIX and sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0
        elif name in want:
            family, kind, address = want[name]
            here = sock.getsockname()[:2]
            ok = sock.family == family and sock.type == kind and here == address and \
                (kind == socket.SOCK_DGRAM or sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0)
        else:
            ok = False
        if not ok:
            raise SystemExit(f"The gate cannot take over: it did not get its own {name}.")
        socks[name] = sock
    if pipe is None or "control" not in socks or "out4" not in socks:
        raise SystemExit("The gate cannot take over: its listeners or its pipe are missing.")
    return socks, pipe


def egress_selftest():
    """The readers on fixed bytes: a program that cannot read a name must not serve (the launcher then starts the
    safe copy)."""
    name = b"example.test"
    sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" + struct.pack("!H", len(sni)) + sni
    hello = b"\x16\x03\x01" + struct.pack("!H", len(body) + 4) + b"\x01" + struct.pack("!I", len(body))[1:] + body
    question = bytes.fromhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001")
    return egress_sni(hello) == ("done", "example.test") and \
        egress_sni(hello[:20]) == ("more", None) and \
        egress_http_host(b"GET / HTTP/1.1\r\nHost: example.test:8080\r\n\r\n") == ("done", "example.test") and \
        egress_dns_question(question) == ("www.example.com", 1)


def egress_main(config, take=None, check=False):
    """`vault.py egress`: the gate, as its own user, from the launcher (EGRESS_LAUNCH). With check: the start check
    alone (the launcher's), and nothing listens. take: the listeners and the pipe of a hand-over."""
    unchangeable(os.path.realpath(__file__), "The vault program")
    try:
        conf = egress_config(config)
    except Refused as e:
        raise SystemExit(f"The gate does not start: {e}.") from None
    if os.getuid() != egress_uid_of(conf["user"]):
        raise SystemExit(f"The gate runs as {conf['user']}, and as no other user.")
    try:
        with open(SWAP_LOW_PORTS, encoding="ascii") as f:
            low = int(f.read().strip())
    except (OSError, ValueError):
        low = None
    if low is not None and low <= EGRESS_LOW_PORT:
        raise SystemExit(f"The gate does not start: on this machine each user can listen on its ports "
                         f"(net.ipv4.ip_unprivileged_port_start is {low}).")
    try:
        with open(EGRESS_RULES, encoding="utf-8") as f:
            table = egress_rules_version(f.readline() + "\n")
    except OSError:
        table = None
    if table is not None and table > EGRESS_TABLE:      # none yet: the root step writes it after the gate serves
        raise SystemExit(f"The gate of this program knows the table up to version {EGRESS_TABLE}, and the table is "
                         f"{table}: the safe copy, which matches it, serves.")
    if not egress_policy_taken():
        raise SystemExit(f"The gate does not start: a later program stored a policy that this program does not take "
                         f"(it takes version {EGRESS_POLICY}), and it would refuse less than that policy says. The "
                         f"table stays, so each agent reaches the hub and nothing else until a program that takes the "
                         f"policy serves. To go back to this program on purpose, remove "
                         f"{os.path.join(EGRESS_STATE, 'policy.json')} as root: the gate then takes the hub's policy "
                         f"at the service's next reading.")
    if not os.access("/proc/net/tcp", os.R_OK) or not egress_selftest():
        raise SystemExit("The gate does not start: it cannot read the kernel's table of sockets, or its own readers "
                         "fail their check.")
    lookup = egress_lookup_check()
    for protocol, works in lookup.items():
        if works is False and not check:
            log(f"egress: the kernel's lookup of a {protocol} socket does not work on this machine: the gate reads "
                f"/proc for it, which is slow when the machine has many sockets")
    if check:
        return 0
    if take and not os.environ.get("NOTIFY_SOCKET"):
        raise SystemExit("The gate cannot take over under this unit: systemd gave it no NOTIFY_SOCKET.")
    socks, pipe, parent = None, None, os.getppid()
    if take:
        socks, pipe = egress_taken(take)
    gate = Egress(conf, socks=socks, program=swap_program(),
                  spawn=lambda new, listeners: egress_candidate(config, new, listeners),
                  parent=parent if take else None)

    def gave_way(signum, frame):
        """SIGTERM: a process that gave way gives the one that serves its counts first."""
        if gate.ending:
            with gate.lock:
                flows = list(gate.flows)
            for flow in flows:
                gate.told(flow)
            egress_merge(gate.counts.take())
        os._exit(0)
    signal.signal(signal.SIGTERM, gave_way)
    if take:
        if not swap_notify(f"MAINPID={os.getpid()}\nREADY=1"):
            raise SystemExit("The gate cannot take over: systemd did not take its word.")
        try:                        # an end of this process now counts against its own program (the launcher)
            egress_write_root(EGRESS_RUNNING, f"{gate.program}\n", 0o644)
        except OSError:
            pass
        try:
            os.write(pipe, EGRESS_SERVES)
            os.close(pipe)
        except OSError:
            if os.getppid() == parent:
                raise SystemExit("The gate does not take over: the process that serves did not take its word.") \
                    from None
        log("egress: the outgoing gate serves, in the place of the process that served before")
    else:
        swap_notify("READY=1")
        log(f"egress: the outgoing gate serves the agent users of this machine (records only), table {table}")
    gate.serve_gate()
    return 0


# The gate's own service: its own user, the right to its low ports and no other, and nothing of the store. A new
# vault program takes over as a new process with no cut (Egress.consider, at the service user's word), and
# NotifyAccess=all lets that process tell systemd that it is the main process now. Its launcher, not the program,
# is ExecStart: it starts the installed program when that program passes its own start check, else the safe copy;
# and ExecStopPost, as the gate's own user, counts an end of the gate that nobody asked for against its program.
EGRESS_UNIT = """[Unit]
Description=Founderizer's outgoing gate (each connection and DNS question of an agent user, recorded)
Before=systemd-user-sessions.service cron.service
StartLimitIntervalSec=0

[Service]
User={user}
Group={user}
ExecStart={launch}
ExecStopPost={launch} --stopped
NotifyAccess=all
RuntimeDirectory=founderizer-egress
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
StateDirectory=founderizer-egress
StateDirectoryMode=0700
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LimitCORE=0
LimitNOFILE=65536
TasksMax=16384
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
"""

# The kernel rules at boot, before a user's services and cron, and again at each change of the machine's groups (a
# new agent user, the swap proxy's user), of the agents' sub-uids and of the browsers' ports (a path unit for each).
# Root runs the safe copy, which only a root step changes, as it does the table: the two always match.
EGRESS_RULES_UNIT = """[Unit]
Description=Founderizer's outgoing gate: the kernel rules, their sets and the closures
DefaultDependencies=no
StartLimitIntervalSec=0
Wants=network-pre.target
After=local-fs.target
Before=network-pre.target shutdown.target systemd-user-sessions.service cron.service
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I {safe} egress-rules --config {conf}

[Install]
WantedBy=sysinit.target
"""

# One path unit for each file that the step reads. systemd watches the folder above a file that is not there (/etc
# for /etc/fleet-browser/ports, before the browsers' parts come), at each new file there sets every watch of the same
# path unit up again, and loses the events that its other watches had waiting: under systemd 255 a new agent user and
# a change of the group docker then started no step at all (17 November 2026).
EGRESS_PATH_UNIT = """[Unit]
Description=Founderizer's outgoing gate: the kernel rules again at each change of {watched}

[Path]
PathChanged={watched}
Unit={rules}.service

[Install]
WantedBy=paths.target
"""

EGRESS_LAUNCHER = """#!/bin/sh
# Founderizer's outgoing gate (vault.py, "the outgoing gate"). Root's: `vault.py configure --egress on` writes it.
# It starts the gate of the installed vault program, or, when that program does not start it, the gate of the safe
# copy that the last root step kept, which always matches the kernel rules. With --stopped (the unit's ExecStopPost)
# it counts an end of the gate that nobody asked for (a crash, a kill, a start that failed) against the program that
# ran ({running}); while the installed program has {most} such ends in the last {hour} seconds since boot, the safe copy
# serves, so a program that passes its check and stops later does not keep the gate down. The file keeps that hour.
conf={conf}
installed={installed}
if [ "$1" = "--stopped" ]; then
    if [ "$SERVICE_RESULT" != "success" ] && [ -f {running} ] && read -r hash < {running}; then
        now=$(cut -d. -f1 /proc/uptime)
        {{ if [ -f {crashes} ]; then awk -v since=$((now - {hour})) '$2 > since' {crashes}; fi
          echo "$hash $now"; }} > {crashes}.new && mv -f {crashes}.new {crashes} || true
    fi
    exit 0
fi
rm -f {running}
hash=$(sha256sum "$installed" 2>/dev/null | cut -d' ' -f1)
ended=0
if [ -n "$hash" ] && [ -f {crashes} ]; then
    since=$(($(cut -d. -f1 /proc/uptime) - {hour}))
    ended=$(awk -v h="$hash" -v since="$since" '$1 == h && $2 > since' {crashes} | wc -l)
fi
for program in "$installed" {safe}; do
    if [ "$program" = "$installed" ] && [ "${{ended:-0}}" -ge {most} ]; then
        echo "founderizer-egress: $program ended $ended times with no stop asked for, so the safe copy serves" >&2
        continue
    fi
    if /usr/bin/python3 -I "$program" egress --config "$conf" --check; then
        sha256sum "$program" 2>/dev/null | cut -d' ' -f1 > {running} || true
        exec /usr/bin/python3 -I "$program" egress --config "$conf"
    fi
    echo "founderizer-egress: $program does not start the gate" >&2
done
exit 1
"""


# The rules' step again every 5 minutes: it loads the table again after a flush that no unit saw (`nft flush ruleset`
# or `nft -f /etc/nftables.conf` by hand), and tries again a load that failed, or a set whose change no path unit saw.
EGRESS_TIMER_UNIT = """[Unit]
Description=Founderizer's outgoing gate: the kernel rules again every 5 minutes

[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min
Unit={rules}.service

[Install]
WantedBy=timers.target
"""

# nftables.service loads /etc/nftables.conf at its start and its reload, and the stock text of that file begins with
# `flush ruleset`; its stop runs `nft flush ruleset`. Each one takes the gate's table away with every other table, so
# root's rules step runs after each of them and loads the table again (a review of 17 November 2026). Its own file
# name: the browsers' parts have a drop-in of their own for the same unit.
EGRESS_NFT_UNIT = "nftables.service"
EGRESS_NFT_DROPIN = """# Founderizer's outgoing gate: its kernel rules again after this unit loads or flushes the
# kernel's rules (vault.py, egress_rules). Root's: `vault.py configure --egress on` writes it.
[Service]
ExecStartPost=-+/usr/bin/python3 -I {safe} egress-rules --config {conf} --table
ExecReload=-+/usr/bin/python3 -I {safe} egress-rules --config {conf} --table
ExecStopPost=-+/usr/bin/python3 -I {safe} egress-rules --config {conf} --table
"""


def egress_paths():
    """{path unit: the file that it watches}: the groups (a new agent user), the sub-uids and the browsers' ports."""
    return {EGRESS_RULES_SERVICE: "/etc/group", EGRESS_SUBUID_PATH: EGRESS_SUBUID, EGRESS_BROWSER_PATH: EGRESS_BROWSER}


def egress_watch_units():
    """The units that start the rules' step, for one systemctl command: a path unit for each file, and the timer."""
    return " ".join([f"{unit}.path" for unit in egress_paths()] + [f"{EGRESS_RULES_SERVICE}.timer"])


def egress_unload():
    """The shell that takes the table and the rules file away, under the rules' step's lock, so that no step that read
    the rules file before loads the table after its delete. The table first, and root's files only once it is gone:
    each agent then connects as before, and the swap proxy by itself."""
    return (f"flock {EGRESS_LOCK} sh -c 'if {EGRESS_NFT} list table inet founderizer_egress >/dev/null 2>&1; then "
            f"{EGRESS_NFT} delete table inet founderizer_egress || exit 1; fi; rm -f {EGRESS_LOADED}; "
            f"rm -f {EGRESS_RULES}' || true\n")


def egress_dropin(section, key, which):
    return (f"# Founderizer's outgoing gate: the closure of this service for the agent users, at each start, before\n"
            f"# the service opens its socket (vault.py, egress_close). Root's: `vault.py configure --egress on`.\n"
            f"[{section}]\n{key}=-{'+' if section == 'Service' else ''}/usr/bin/python3 -I {EGRESS_SAFE} egress-close "
            f"--config {EGRESS_CONF} {which}\n")


def egress_files(conf_text):
    """{path: (text, mode)} of each root-owned file of the gate but the safe copy and the D-Bus policy."""
    files = {EGRESS_CONF: (conf_text, 0o644), EGRESS_RULES: (egress_table(None), 0o644),
             EGRESS_LAUNCH: (EGRESS_LAUNCHER.format(conf=EGRESS_CONF, installed=INSTALLED, safe=EGRESS_SAFE,
                                                    running=EGRESS_RUNNING, crashes=EGRESS_CRASHES,
                                                    most=EGRESS_CRASHES_MOST, hour=EGRESS_CRASHES_HOUR), 0o755),
             f"{EGRESS_UNITS}/{EGRESS_SERVICE}.service":
                 (EGRESS_UNIT.format(user=EGRESS_USER, launch=EGRESS_LAUNCH), 0o644),
             f"{EGRESS_UNITS}/{EGRESS_RULES_SERVICE}.service":
                 (EGRESS_RULES_UNIT.format(safe=EGRESS_SAFE, conf=EGRESS_CONF), 0o644),
             **{f"{EGRESS_UNITS}/{unit}.path": (EGRESS_PATH_UNIT.format(watched=watched, rules=EGRESS_RULES_SERVICE),
                                                0o644) for unit, watched in egress_paths().items()},
             f"{EGRESS_UNITS}/{EGRESS_RULES_SERVICE}.timer": (EGRESS_TIMER_UNIT.format(rules=EGRESS_RULES_SERVICE),
                                                             0o644),
             f"{EGRESS_UNITS}/{EGRESS_NFT_UNIT}.d/founderizer-egress.conf":
                 (EGRESS_NFT_DROPIN.format(safe=EGRESS_SAFE, conf=EGRESS_CONF), 0o644)}
    for unit, (section, key, which) in EGRESS_DROPINS.items():
        files[f"{EGRESS_UNITS}/{unit}.d/founderizer-egress.conf"] = (egress_dropin(section, key, which), 0o644)
    files[EGRESS_MODPROBE] = ("# Founderizer's outgoing gate: the socket families whose transport is a kernel socket, "
                              "which the kernel rules\n# cannot read as an agent's (vault.py, EGRESS_FAMILIES). Root's: "
                              "`vault.py configure --egress on` writes it.\n" +
                              "".join(f"install {m} /bin/false\n" for m in EGRESS_FAMILIES), 0o644)
    return files


def egress_reading():
    """The shell that reads the gate's state for the root step. It changes nothing."""
    files = " ".join(shlex.quote(p) for p in sorted(egress_files("").keys()) + [EGRESS_SAFE])
    return ("id -u %(u)s >/dev/null 2>&1 && echo euser=yes || echo euser=no\n"
            "echo elow=$(cat %(low)s 2>/dev/null)\n"
            "test -x %(nft)s && echo enft=yes || echo enft=no\n"
            "echo eactive=$(systemctl is-active %(gate)s 2>/dev/null || true)\n"
            "echo eenabled=$(systemctl is-enabled %(gate)s 2>/dev/null || true)\n"
            "echo erestarts=$(systemctl show -p NRestarts --value %(gate)s 2>/dev/null || echo unknown)\n"
            "echo epath=$(for u in %(watch)s; do systemctl is-active $u 2>/dev/null || true; done | sort -u | "
            "paste -sd, -)\n"
            "echo erules=$(systemctl is-enabled %(rules)s.service 2>/dev/null || true)\n"
            "echo eswap=$(systemctl is-active %(swap)s 2>/dev/null || true)\n"
            "echo eswap_at=$(date -d \"$(systemctl show -p ExecMainStartTimestamp --value %(swap)s 2>/dev/null)\" +%%s "
            "2>/dev/null)\n"
            "echo eprogram_at=$(stat -c %%Y %(installed)s 2>/dev/null)\n"
            "echo elisten=$(ss -Hltn 'sport = :%(out)d' 2>/dev/null | wc -l)\n"
            "echo eports=$(ss -Hltnu 2>/dev/null | awk '{print $5}' | grep -oE ':(877|878|879|880)$' | tr -d : | "
            "sort -u | tr '\\n' ' ')\n"
            "for f in %(files)s; do echo \"hash $(sha256sum \"$f\" 2>/dev/null | cut -d' ' -f1) $f\"; done\n") % {
                "u": EGRESS_USER, "low": SWAP_LOW_PORTS, "nft": EGRESS_NFT, "gate": EGRESS_SERVICE,
                "rules": EGRESS_RULES_SERVICE, "swap": SWAP_SERVICE, "installed": INSTALLED,
                "watch": egress_watch_units(),
                "out": EGRESS_PORTS["out"], "files": files}


def egress_conf_text(broker, service_user=EGRESS_SERVICE_USER):
    """The gate's configuration, from the broker's (its hub, the address that the join line gave)."""
    hub = urllib.parse.urlsplit(str(broker.get("hub") or ""))
    try:
        address = str(ipaddress.ip_address(hub.hostname or ""))
    except ValueError:
        raise ConfigureStop("The hub's address in this machine's vault configuration is no IP address, so the gate "
                            "cannot let its connections go direct. Nothing changed.") from None
    ports = sorted({hub.port or 80, EGRESS_GIT_PORT})
    return json.dumps({"egress": EGRESS_KEY, "user": EGRESS_USER, "service_user": service_user,
                       "swap_user": SWAP_USER, "group": str(broker.get("worker_group") or EGRESS_GROUP),
                       "hub": address, "hub_ports": ports}, indent=2) + "\n"


def configure_egress(egress, check, run, broker, settle, rules=None, close=None):
    """The gate's part of the root step (`configure --egress on|off|keep`): the parts of the proposal's section 8 in
    its order. Returns (changes, {the answer's egress fields}) or raises ConfigureStop. rules: the rules' step
    (egress_rules), which a test gives."""
    rules = rules or (lambda conf: egress_rules(conf, run))
    before = readings(run(egress_reading())[1])
    hashes = {}
    for line in run(egress_reading())[1].splitlines():
        if line.startswith("hash "):
            parts = line.split(" ", 2)
            if len(parts) == 3:
                hashes[parts[2]] = parts[1]
    loaded = egress_loaded(run)
    state = {"egress": before.get("eactive") == "active" and loaded is not None, "egress_table": loaded}
    if egress == "keep":
        return [], state
    # Each agent user in a container group, which the step takes out: said first, so that a person who put an agent
    # into the group docker by hand learns it before the table loads (the proposal's section 8)
    members, agents = [], set(egress_agents(str(broker.get("worker_group") or EGRESS_GROUP),
                                            (EGRESS_USER, EGRESS_SERVICE_USER, SWAP_USER)))
    for group in EGRESS_CONTAINER_GROUPS:
        try:
            g = grp.getgrnam(group)
        except KeyError:
            continue
        members += [f"{u}:{group}" for u in g.gr_mem if egress_uid_of(u) in agents]
    if members:
        state["groups_to_leave"] = members
    if egress == "off":
        on_disk = any(hashes.get(p) for p in egress_files("").keys())
        if not on_disk and loaded is None and before.get("eactive") in ("", "inactive", "failed", "unknown"):
            return [], state
        if check:
            return ["the gate"], state
        try:
            conf = egress_config(EGRESS_CONF)
        except (Refused, OSError, SystemExit):
            conf = None
        # The order of the way back: the table first (each agent connects as before, and the swap proxy's own way
        # goes on through the gate that still runs), then the rules file (the swap proxy connects by itself), then the
        # gate, the units, the drop-ins and the closures.
        run(egress_unload(), timeout=300)
        if egress_loaded(run) is not None:      # the gate still runs, and the agents still connect through it
            raise ConfigureStop("The gate's kernel rules did not go, so nothing else of the gate changed. Run this "
                                "step again.")
        script = (f"systemctl disable --now {egress_watch_units()} >/dev/null 2>&1 || true\n"
                  f"systemctl disable {EGRESS_RULES_SERVICE}.service >/dev/null 2>&1 || true\n"
                  f"systemctl disable --now {EGRESS_SERVICE} >/dev/null 2>&1 || true\nrm -rf {EGRESS_RUN}\n"
                  f"systemctl reset-failed {EGRESS_SERVICE} {EGRESS_RULES_SERVICE}.service >/dev/null 2>&1 || true\n"
                  + "".join(f"rm -f {shlex.quote(p)}\n" for p in egress_files("").keys() if p not in (EGRESS_CONF,))
                  + f"rm -f {EGRESS_DBUS}\nsystemctl daemon-reload\n"
                  "systemctl reload dbus.service >/dev/null 2>&1 || true\n")
        code, out, err = run(script, timeout=300)
        if conf is not None:
            (close or egress_open)(conf)
        if code != 0:
            raise ConfigureStop(f"The gate could not be taken away: {(err or out).strip()[-300:]}")
        return ["the gate"], {"egress": False, "egress_table": None}
    # on
    if before.get("enft") != "yes":
        raise ConfigureStop(f"This machine has no {EGRESS_NFT} (the package nftables), so the gate's kernel rules "
                            f"cannot load. Nothing of the gate changed.")
    low = before.get("elow", "")
    if low.isdigit() and int(low) <= EGRESS_LOW_PORT:
        raise ConfigureStop(f"On this machine each user can listen on the gate's ports "
                            f"(net.ipv4.ip_unprivileged_port_start is {low}), so an agent could take the gate's place. "
                            f"The gate is not switched on. Set net.ipv4.ip_unprivileged_port_start to 1024, its "
                            f"default, and run this step again.")
    if egress_uid_of(EGRESS_SERVICE_USER) is None:
        raise ConfigureStop(f"This machine has no user {EGRESS_SERVICE_USER}, the user of its Founderizer service, "
                            f"which gives the gate its policy. Nothing of the gate changed.")
    try:
        with open(INSTALLED, "rb") as f:
            program = f.read()
    except OSError:
        raise ConfigureStop(f"{INSTALLED} is not readable. Nothing of the gate changed.") from None
    files = egress_files(egress_conf_text(broker))
    want = {path: hashlib.sha256(text.encode()).hexdigest() for path, (text, _) in files.items()}
    want[EGRESS_SAFE] = hashlib.sha256(program).hexdigest()
    new_files = sorted(p for p, h in want.items() if hashes.get(p) != h)
    gate_again = before.get("eactive") != "active"
    if gate_again and before.get("eports"):
        raise ConfigureStop(f"Another program listens on the gate's port {before['eports'].split()[0]} of this "
                            f"machine, so the gate cannot start. Nothing of the gate changed.")
    table_new = loaded != EGRESS_TABLE
    installed_before = bool(hashes.get(EGRESS_RULES))      # root's rules file: a gate that this machine had already
    path_again = before.get("epath") != "active" or before.get("erules") != "enabled"
    swap_again = table_new and before.get("eswap") == "active" and \
        (before.get("eswap_at") or "0").isdigit() and (before.get("eprogram_at") or "0").isdigit() and \
        int(before.get("eswap_at") or 0) < int(before.get("eprogram_at") or 0)
    changes = [name for name, needed in (("the gate's user", before.get("euser") != "yes"),
                                         ("the gate's files", bool(new_files)), ("the gate", gate_again),
                                         ("the kernel rules", table_new or EGRESS_RULES in new_files),
                                         ("the rules' unit", path_again),
                                         ("the swap proxy", swap_again)) if needed]
    if check or not changes:
        return changes, dict(state, egress_state="would make" if changes else "there")
    if before.get("euser") != "yes":
        code, out, err = run(f"id -u {EGRESS_USER} >/dev/null 2>&1 || useradd --system --user-group --home-dir "
                             f"{EGRESS_STATE} --no-create-home --shell /usr/sbin/nologin {EGRESS_USER}\n")
        if code != 0:
            raise ConfigureStop(f"The user {EGRESS_USER} of the gate could not be made: {(err or out).strip()[-300:]}")
    folder = tempfile.mkdtemp(prefix="fleet-egress-configure-")

    def put(paths):
        script = f"install -d -o root -g root -m 755 {EGRESS_DIR} {EGRESS_LIB}\n"
        for i, path in enumerate(paths):
            local = os.path.join(folder, str(i))
            if path == EGRESS_SAFE:
                with open(local, "wb") as f:
                    f.write(program)
                mode = 0o644
            else:
                text, mode = files[path]
                with open(local, "w", encoding="utf-8") as f:
                    f.write(text)
            script += (f"install -d -o root -g root -m 755 {shlex.quote(os.path.dirname(path))}\n"
                       f"install -o root -g root -m {mode:o} {shlex.quote(local)} {shlex.quote(path + '.new')}\n"
                       f"mv -f {shlex.quote(path + '.new')} {shlex.quote(path)}\n")
        code, out, err = run(script + "systemctl daemon-reload\n", timeout=300)
        if code != 0:
            raise ConfigureStop(f"The gate's files could not be put in place: {(err or out).strip()[-300:]}")

    try:
        # 1. Every file but the rules file, whose existence tells the swap proxy to use the gate: it comes only after
        # the gate serves. A gate that runs keeps running: a new unit or launcher counts from its next start, and a
        # new program comes by the hand-over, which cuts nothing.
        put([p for p in new_files if p != EGRESS_RULES or installed_before])
        if gate_again:
            run(f"systemctl enable {EGRESS_SERVICE} >/dev/null 2>&1\nsystemctl reset-failed {EGRESS_SERVICE} "
                f">/dev/null 2>&1 || true\nsystemctl restart {EGRESS_SERVICE}\nsleep {settle}\n", timeout=300)
        now = readings(run(egress_reading())[1])
        if now.get("eactive") != "active" or now.get("elisten") in ("", "0"):
            if installed_before or loaded is not None:
                # A gate that this machine had already: its table stays, as while any gate does not run (the
                # proposal's section 5.4), with the new rules file, and the hub's server watch tells the manager
                raise ConfigureStop(f"The gate of this machine is {now.get('eactive') or 'not running'} {settle} "
                                    f"seconds after its start. Its kernel rules stay, so each agent reaches the hub "
                                    f"and nothing else until the gate serves. Read `journalctl -u {EGRESS_SERVICE} "
                                    f"-n 30` on this machine: the gate says why on its first line.")
            # A first install whose gate does not start: the table, the rules file and the rules' units go, so that
            # each agent and the swap proxy connect as before, with no record.
            run(egress_unload()
                + f"systemctl disable --now {egress_watch_units()} >/dev/null 2>&1 || true\n"
                f"systemctl disable {EGRESS_RULES_SERVICE}.service >/dev/null 2>&1 || true\n", timeout=300)
            raise ConfigureStop(f"The gate of this machine is {now.get('eactive') or 'not running'} {settle} seconds "
                                f"after its start, so the kernel rules are not loaded and each agent connects as "
                                f"before. Read `journalctl -u {EGRESS_SERVICE} -n 30` on this machine: the gate says "
                                f"why on its first line.")
        # 2. The rules file, now that the gate serves; then the swap proxy of an older program starts again, so that
        # it uses the gate's relay port before the table keeps its user to that port.
        if EGRESS_RULES in new_files and not installed_before:
            put([EGRESS_RULES])
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    if swap_again:
        run(f"systemctl restart {SWAP_SERVICE}\nsleep {settle}\n", timeout=300)
    # 3. The table, its sets, the closures, the D-Bus policy and the container groups; then its unit and the path
    # unit, for each boot and each change of the groups.
    try:
        done = rules(egress_config(EGRESS_CONF))
    except (Refused, OSError, SystemExit) as e:
        done = {"ok": False, "reason": str(e)}
    if not done.get("ok"):
        raise ConfigureStop(f"The gate runs, and its kernel rules did not load: {done.get('reason')}. Each agent "
                            f"connects as before, with no record.")
    run(f"systemctl enable {EGRESS_RULES_SERVICE}.service >/dev/null 2>&1\n"
        f"systemctl enable --now {egress_watch_units()} >/dev/null 2>&1\n", timeout=300)
    after = readings(run(egress_reading())[1])
    loaded = egress_loaded(run)
    if loaded != EGRESS_TABLE or after.get("epath") != "active":
        raise ConfigureStop(f"The gate's kernel rules are {'not loaded' if loaded is None else f'of version {loaded}'}"
                            f", or their path unit does not run ({after.get('epath') or 'not there'}). Read "
                            f"`journalctl -u {EGRESS_RULES_SERVICE} -n 30` on this machine.")
    return changes, {"egress": True, "egress_table": loaded, "egress_state": "made",
                     "groups_removed": done.get("groups_removed") or [], "closed": done.get("closed") or [],
                     "unclosed": done.get("unclosed") or []}


def egress_root_main(args, euid=None):
    """`vault.py egress-rules` and `vault.py egress-close`: as root, from a root-owned copy, with root's own
    configuration of the gate. One JSON line."""
    if (os.geteuid() if euid is None else euid) != 0:
        raise SystemExit(f"Run {args.cmd} as root.")
    unchangeable(os.path.realpath(__file__), "The vault program")
    try:
        conf = egress_config(args.config)
    except Refused as e:
        print(json.dumps({"ok": False, "reason": str(e)}))
        return 1
    if args.cmd == "egress-close" and args.which == "daemons":
        closed, unclosed = egress_daemons(conf)
        print(json.dumps({"ok": True, "closed": closed, "unclosed": unclosed}))
        return 0
    if args.cmd == "egress-close":
        closed, unclosed = egress_close(conf, args.which)
        print(json.dumps({"ok": True, "closed": closed, "unclosed": unclosed}))
        return 0
    answer = egress_rules(conf, table_only=args.table)
    print(json.dumps(answer))
    return 0 if answer.get("ok") else 1


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


# ---------------------------------------------------------------- this machine's own root step (configure)
#
# Part B of the changed key swap (the manager's choice C43, 15 November 2026): the one command that changes this
# machine's vault configuration after its install. It adds the owner's keys and never takes one away, so that the step
# of one Mac of the owner does not take the handovers of another; only its remove form (`--remove-owner-key`, F8 piece
# E1) takes a key out, for a Mac that the owner removed, and never the last one; it sets the fleet's ID where the vault
# has none; and it switches the key swap on or off. It runs only as root and only as the installed program
# (configure_main), as store-init does, so the code that root runs here is root's own: the program that the install put
# in place, or the one that fleet-vault-program took from a signed release above its floor
# (hubsetup.vault_program_script). Nothing of a checkout runs, and the hub names nothing. The owner's Mac runs it over
# SSH; join.sh and hub.sh run it at an install (`hubsetup.py key-swap`); `hubsetup.py vault --swap` calls it. No rule of
# the machine's sudoers file reaches it: the service user's two root commands are other programs, and its third right is
# to run commands as an agent user, which this command refuses (hubsetup.sudoers_text; test_key_swap.Configure holds
# both).
#
# Its last line on standard output is one JSON object, which the owner's app reads: {"ok": true, "state", "swaps",
# "swaps_from", "owner_keys", "fleet", "changed"}, or {"ok": false, "reason"} with exit 1.

INSTALLED = "/usr/local/lib/fleet-vault/vault.py"   # hubsetup.VAULT_LIB + "/vault.py": the one copy that configures
VAULT_CONF_PATH = "/etc/fleet-vault/vault.json"     # hubsetup.VAULT_CONF
VAULT_USER = "fleet-vault"                          # hubsetup.VAULT_USER: the broker's own user
SWAP_SERVICE = "fleet-vault-swap"                   # hubsetup.SWAP_SERVICE
SWAP_UNIT_PATH = "/etc/systemd/system/fleet-vault-swap.service"     # hubsetup.SWAP_UNIT
SWAP_PORT = 876                                     # hubsetup.SWAP_PORT: below 1024, where no user without the right
                                                    # can listen
SWAP_OPENSSL = "/usr/bin/openssl"
CONFIGURE_LOCK = "/run/fleet-vault-configure.lock"  # root's: two steps never change one vault at the same time
CONFIGURE_SETTLE = 3                                # hubsetup.VAULT_SETTLE: seconds before a service is read
ROOT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"   # hubsetup.ROOT_PATH
# What `swaps` is read from. Root cannot ask the broker itself: its socket admits the agents' users only (admitted).
# The broker makes its socket for the proxy only after it loaded the part "swap" (Broker.open_swaps), in its runtime
# folder, which systemd removes at each stop of the broker (RuntimeDirectory, with no Preserve): so a socket of the
# vault user there is the word of the broker that runs now, and not of a file that a step wrote.
SWAPS_FROM = "the socket for the proxy of the broker that runs now, and the proxy's service"


class ConfigureStop(Exception):
    """Why configure changed nothing more: one sentence, which the owner's app shows on the server's row. `undone`:
    this step put the configuration of before back (a broker that did not stay up on the new one, or a switch to on
    that ended badly), and its JSON line says so (`"undone": true`). Each such try restarts the broker two times and
    ends in the same way while the machine runs the same program, so the owner's app makes no try of its own again
    on that server until the program changes, the owner presses Try again or the owner's wish changes (app patch 2)."""

    def __init__(self, reason, undone=False):
        super().__init__(reason)
        self.undone = undone


def root_shell(script, timeout=120):
    """(code, out, err) of a shell script, run with root's own PATH and nothing of the caller's environment."""
    try:
        r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=timeout,
                           env={"PATH": ROOT_PATH, "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError, UnicodeError) as e:
        return 1, "", f"the command did not run ({type(e).__name__})"
    return r.returncode, r.stdout, r.stderr


def configure_reading(conf):
    """The shell that reads what runs, so that a second run changes nothing and the answer says what is so: the proxy's
    user, the kernel's first port that each user can listen on, the hash of the proxy's unit, the broker's and the
    proxy's services, and the owner of the broker's socket for the proxy (SWAPS_FROM). It changes nothing."""
    sock = os.path.join(os.path.dirname(str(conf.get("socket") or "/run/fleet-vault/vault.sock")), SWAP_SOCKET)
    return ("id -u %(u)s >/dev/null 2>&1 && echo user=yes || echo user=no\n"
            "echo low=$(cat %(low)s 2>/dev/null)\n"
            "echo unit=$(sha256sum %(unit)s 2>/dev/null | cut -d' ' -f1)\n"
            "echo broker=$(systemctl is-active fleet-vault 2>/dev/null || true)\n"
            "echo broker_restarts=$(systemctl show -p NRestarts --value fleet-vault 2>/dev/null || echo unknown)\n"
            "echo active=$(systemctl is-active %(service)s 2>/dev/null || true)\n"
            "echo restarts=$(systemctl show -p NRestarts --value %(service)s 2>/dev/null || echo unknown)\n"
            "echo enabled=$(systemctl is-enabled %(service)s 2>/dev/null || true)\n"
            "echo socket=$(test -S %(sock)s && stat -c %%U %(sock)s 2>/dev/null)\n") % {
                "u": SWAP_USER, "low": SWAP_LOW_PORTS, "unit": SWAP_UNIT_PATH, "service": SWAP_SERVICE,
                "sock": shlex.quote(sock)}


def readings(text):
    """{name: value} of the lines name=value of a reading."""
    return dict(line.split("=", 1) for line in (text or "").splitlines() if "=" in line)


def configure_swaps(reading):
    """True when the broker that runs now swaps keys (SWAPS_FROM) and the proxy runs."""
    return reading.get("broker") == "active" and reading.get("socket") == VAULT_USER and \
        reading.get("active") == "active"


def configure_lock(path=CONFIGURE_LOCK):
    """The lock of this machine's root step: a file of root's, held until the process closes it or ends. A second step
    that finds it held stops and changes nothing."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise ConfigureStop("Another step changes this machine's vault now, so this one changed nothing. Try again in "
                            "a minute.") from None
    return fd


def configure_answer(state, conf, reading, changes):
    return {"ok": True, "state": state, "swaps": configure_swaps(reading), "swaps_from": SWAPS_FROM,
            "owner_keys": len(conf.get("owner_keys") or []), "fleet": bool(conf.get("fleet")), "changed": changes}


def configure(config=VAULT_CONF_PATH, owner_keys=(), fleet=None, swap="keep", check=False, run=None, read=None,
              settle=CONFIGURE_SETTLE, lock=CONFIGURE_LOCK, egress="keep", egress_rules_step=None, remove_owner_keys=()):
    """This machine's own root step (the section above). `owner_keys` are added to the vault's list, `fleet` is set
    where the vault has none, and `swap` is "on", "off" or "keep". With `check` it reads and changes nothing.
    `remove_owner_keys` (the remove form) are taken out of the vault's list, in a run that adds none, and never the
    last key: the broker then starts again, because a running broker reads its keys only at its start. A key that is
    not in the list changes no key, and the broker still starts again, so the same remove again finishes a run that
    a lost connection cut after its write. A key that is no point of the curve can be taken out too. The broker's
    state stays as it is (VAULT.md, "The owner's keys of the central vault").

    The order of the install's swap step stays: it reads first; it refuses before anything changes (a vault of another
    fleet, a key that is not in the owner's form, a machine where each user can listen on the proxy's port); it makes
    the proxy's user; it writes the configuration and restarts the broker once, only when the configuration changes or
    the broker runs without its socket for the proxy, and a broker that does not stay up gets the old configuration
    back; then it installs, starts or stops the proxy, and starts it again only when its unit changed or it does not
    run. A second run with the same arguments changes nothing and restarts nothing. Returns the answer of the section
    above, or raises ConfigureStop."""
    run = run or root_shell
    read = read or (lambda path: open(path, encoding="utf-8").read())
    if swap not in ("on", "off", "keep") or egress not in ("on", "off", "keep"):
        raise ConfigureStop("swap and egress are on, off or keep. Nothing changed.")
    held = configure_lock(lock) if lock and not check else None
    try:
        answer = configure_locked(config, list(owner_keys), fleet, swap, check, run, read, settle,
                                  list(remove_owner_keys))
        # The outgoing gate (configure_egress): read where the machine has it, changed only on its own word.
        if egress != "keep" or os.path.exists(EGRESS_CONF):
            changes, part = configure_egress(egress, check, run, json.loads(read(config)), settle,
                                             rules=egress_rules_step)
            state = part.pop("egress_state", None)
            answer.update(part, changed=answer["changed"] + changes)
            if changes:
                answer["state"] = "would make" if check else "made"
            elif state and answer["state"] == "there":
                answer["state"] = state
        return answer
    finally:
        if held is not None:
            os.close(held)


def configure_locked(config, owner_keys, fleet, swap, check, run, read, settle, removed=()):
    try:
        current = json.loads(read(config))
        current = current if isinstance(current, dict) else None
    except (OSError, ValueError):
        current = None
    if current is None or not current.get("worker_group") or current.get("central") is True:
        raise ConfigureStop("This machine has no vault broker of its own to configure: run `hubsetup.py vault` first.")
    for text in owner_keys:             # a key that is taken out needs no check: one that is no point of the curve
        try:                            # keeps the broker from its start, and its removal is the repair
            owner_key(text)
        except ValueError:
            raise ConfigureStop("Each owner key is the base64 of an uncompressed P-256 public key (65 bytes), as the "
                                "app shows it. Nothing changed.") from None
    if owner_keys and removed:
        raise ConfigureStop("One run adds owner keys or removes them, not both. Nothing changed.")
    if fleet is not None and not FLEET_ID.fullmatch(str(fleet)):
        raise ConfigureStop("fleet is the fleet's ID: 16 lowercase hex characters. Nothing changed.")
    if fleet and current.get("fleet") and current["fleet"] != fleet:
        raise ConfigureStop(f"This vault is of another fleet ({current['fleet']}), so nothing changed.")
    conf, had = dict(current), list(current.get("owner_keys") or [])
    added = [k for k in dict.fromkeys(owner_keys) if k not in had]
    kept = [k for k in had if k not in removed]
    if added and not (current.get("fleet") or fleet):
        raise ConfigureStop("The owner's keys go with the fleet's ID: give --fleet. Nothing changed.")
    if len(had) + len(added) > OWNER_KEYS:
        raise ConfigureStop(f"A vault takes at most {OWNER_KEYS} owner keys, and this one would have "
                            f"{len(had) + len(added)}. Nothing changed.")
    if had and not kept:
        raise ConfigureStop("A vault keeps at least one owner key, and this run would take away each one that it has. "
                            "Nothing changed.")
    if added:
        conf["owner_keys"] = had + added
    if kept != had:                     # the remove form: the broker starts again below, as for each new configuration
        conf["owner_keys"] = kept
    if fleet and not current.get("fleet"):
        if not conf.get("owner_keys"):
            raise ConfigureStop("The fleet's ID goes with the owner's keys: give --add-owner-key. Nothing changed.")
        conf["fleet"] = fleet
    if swap == "on":
        conf[SWAP_KEY] = {"user": SWAP_USER, "vault": VAULT_USER, "port": SWAP_PORT, "openssl": SWAP_OPENSSL}
    elif swap == "off":
        conf.pop(SWAP_KEY, None)
    swaps = SWAP_KEY in conf
    before = readings(run(configure_reading(current))[1])
    low = before.get("low", "")
    if swap == "on" and low.isdigit() and int(low) <= SWAP_PORT:
        raise ConfigureStop(f"On this machine each user can listen on port {SWAP_PORT} "
                            f"(net.ipv4.ip_unprivileged_port_start is {low}), so an agent could take the place of the "
                            f"vault's proxy. The key swap is not switched on. Set net.ipv4.ip_unprivileged_port_start "
                            f"to 1024, its default, and run this step again.")
    unit = SWAP_UNIT.format(user=SWAP_USER, config=config, script=INSTALLED)
    user_new = swaps and before.get("user") != "yes"
    conf_new = conf != current
    # A broker that started while the part could not be read (no proxy's user yet) serves without its socket for the
    # proxy, and gives no key that has a site until it starts again; a broker that does not run starts.
    # A remove form starts the broker again also when the key is gone from the file already: a run that a lost
    # connection cut after its write and before the restart leaves the running broker on the keys of before.
    broker_again = conf_new or bool(removed) or \
        (swaps and (before.get("broker") != "active" or before.get("socket") != VAULT_USER))
    unit_new = swaps and before.get("unit") != hashlib.sha256(unit.encode()).hexdigest()
    proxy_again = swaps and (unit_new or before.get("active") != "active")
    proxy_enable = swaps and (unit_new or before.get("enabled") != "enabled")
    proxy_off = not swaps and swap == "off" and (before.get("active") not in ("", "inactive", "failed", "unknown")
                                                 or before.get("enabled") == "enabled")
    changes = [name for name, needed in (("the proxy's user", user_new), ("the configuration", conf_new),
                                         ("the broker", broker_again and not conf_new),
                                         ("the proxy", proxy_again or proxy_enable or proxy_off)) if needed]
    if check or not changes:
        return configure_answer("would make" if changes else "there", conf, before, changes)
    if user_new:
        code, out, err = run("id -u %(u)s >/dev/null 2>&1 || useradd --system --user-group --home-dir %(state)s "
                             "--shell /usr/sbin/nologin %(u)s\n" % {"u": SWAP_USER, "state": SWAP_STATE})
        if code != 0:
            raise ConfigureStop(f"The user {SWAP_USER} of the vault's proxy could not be made: "
                                f"{(err or out).strip()[-300:]}")
    folder = tempfile.mkdtemp(prefix="fleet-vault-configure-")
    try:
        new, old, service = (os.path.join(folder, name) for name in ("vault.json", "vault.json.before", "unit"))
        for path, text in ((new, json.dumps(conf, indent=2) + "\n"), (old, json.dumps(current, indent=2) + "\n"),
                           (service, unit)):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        restart = ("systemctl reset-failed fleet-vault >/dev/null 2>&1 || true\n"
                   "systemctl restart fleet-vault\nsleep %d\n" % settle)
        if broker_again:
            code, out, err = run(("install -o root -g root -m 644 %s %s\n" % (shlex.quote(new), shlex.quote(config))
                                  if conf_new else "") + restart, timeout=300)
            now = readings(run(configure_reading(conf))[1])
            if code != 0 or now.get("broker") != "active" or now.get("broker_restarts") not in ("0", "unknown"):
                if conf_new:
                    run("install -o root -g root -m 644 %s %s\n" % (shlex.quote(old), shlex.quote(config)) + restart,
                        timeout=300)
                raise ConfigureStop("The vault broker of this machine did not stay up with the new configuration, so "
                                    "the configuration is as it was. Read `journalctl -u fleet-vault -n 30` on this "
                                    "machine." if conf_new else
                                    "The vault broker of this machine did not stay up after its start. Read "
                                    "`journalctl -u fleet-vault -n 30` on this machine.", undone=conf_new)
        if proxy_again or proxy_enable:
            script = ("install -o root -g root -m 644 %s %s\nsystemctl daemon-reload\n"
                      % (shlex.quote(service), SWAP_UNIT_PATH)) if unit_new else ""
            script += "systemctl enable %s >/dev/null 2>&1\n" % SWAP_SERVICE
            if proxy_again:
                script += ("systemctl reset-failed %s >/dev/null 2>&1 || true\nsystemctl restart %s\nsleep %d\n"
                           % (SWAP_SERVICE, SWAP_SERVICE, settle))
            code, out, err = run(script, timeout=300)
            if code != 0:
                raise ConfigureStop(f"The service of the vault's proxy could not be started: "
                                    f"{(err or out).strip()[-300:]}")
        if proxy_off:
            run("systemctl disable --now %s >/dev/null 2>&1 || true\nsystemctl reset-failed %s >/dev/null 2>&1 || "
                "true\n" % (SWAP_SERVICE, SWAP_SERVICE), timeout=300)
        after = readings(run(configure_reading(conf))[1])
        fault = None
        if swaps and (after.get("active") != "active" or proxy_again and after.get("restarts") not in ("0", "unknown")):
            fault = (f"The vault's proxy of this machine is {after.get('active') or 'not running'} {settle} seconds "
                     f"after its start. Read `journalctl -u {SWAP_SERVICE} -n 30` on this machine: a proxy that does "
                     f"not start says why on its first line.")
        elif swaps and not configure_swaps(after):
            fault = ("The vault broker of this machine runs without its socket for the proxy. Read `journalctl -u "
                     "fleet-vault -n 30` on this machine: the broker says why on its line \"no key swap\".")
        if fault and SWAP_KEY not in current:
            # This step put the part in, and the switch did not end well: nothing that worked before may stop (the
            # brief's rules 1 and 4), so the old configuration goes back, the broker starts on it again, and the proxy
            # stops. Each key then reaches a session as a value, as before this step.
            run("install -o root -g root -m 644 %s %s\n" % (shlex.quote(old), shlex.quote(config)) + restart +
                "systemctl disable --now %s >/dev/null 2>&1 || true\nsystemctl reset-failed %s >/dev/null 2>&1 || "
                "true\n" % (SWAP_SERVICE, SWAP_SERVICE), timeout=300)
            back = readings(run(configure_reading(current))[1])
            raise ConfigureStop(fault + " So this step put the configuration back as it was and stopped the proxy: "
                                "the key swap is not switched on, and each key reaches a session as a value, as "
                                "before." + ("" if back.get("broker") == "active" else
                                             " The vault broker did not come up again on it: read `journalctl -u "
                                             "fleet-vault -n 30` on this machine."), undone=True)
        if fault:
            raise ConfigureStop(fault + " The configuration keeps the part, which it had before this step, so a key "
                                        "that has a site is not given to a session until this is repaired.")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    if swap == "off" and after.get("active") == "active":
        raise ConfigureStop(f"The vault's proxy of this machine still runs. Read `journalctl -u {SWAP_SERVICE} -n 30` "
                            f"on this machine.")
    return configure_answer("made", conf, after, changes)


def configure_main(args, euid=None, program=None):
    """`vault.py configure`: as root and only as the installed program (INSTALLED, which no user can change), and its
    one JSON line. A program that a checkout holds is the user's, and root runs none of it."""
    try:
        if (os.geteuid() if euid is None else euid) != 0:
            raise ConfigureStop("Run configure as root: it changes this machine's vault configuration and its services.")
        if args.config != VAULT_CONF_PATH:      # a root step never needs another file: the unit and install name it
            raise ConfigureStop(f"configure takes only this machine's own configuration, {VAULT_CONF_PATH}.")
        here = os.path.realpath(program or __file__)
        if here != INSTALLED:
            raise ConfigureStop(f"configure runs only as the installed program ({INSTALLED}), never from a checkout. "
                                f"This one is {here}.")
        try:
            unchangeable(here, "The vault broker program")
        except SystemExit as e:
            raise ConfigureStop(str(e)) from None
        answer = configure(args.config, args.add_owner_key, args.fleet, args.swap, args.check,
                           egress=getattr(args, "egress", "keep"),
                           remove_owner_keys=getattr(args, "remove_owner_key", None) or [])
    except ConfigureStop as e:
        print(json.dumps(dict({"ok": False, "reason": str(e)}, **({"undone": True} if e.undone else {}))))
        return 1
    print(json.dumps(answer))
    return 0


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
    p = sub.add_parser("configure", help="This machine's own root step, as root and only as the installed program: "
                                         "add the owner's keys or remove one, set the fleet's ID, and switch the "
                                         "key swap on or off. Its last line is one JSON object")
    p.add_argument("--config", default=VAULT_CONF_PATH)
    p.add_argument("--add-owner-key", action="append", default=[], metavar="KEY",
                   help="one public key of the owner (base64 of 65 bytes): added to the vault's keys, never in their "
                        "place")
    p.add_argument("--remove-owner-key", action="append", default=[], metavar="KEY",
                   help="one public key of the owner (base64 of 65 bytes) that is taken out of the vault's keys, in a "
                        "run that adds none; the last key is never taken out")
    p.add_argument("--fleet", help="the fleet's ID, 16 lowercase hex characters: set where the vault has none")
    p.add_argument("--swap", choices=("on", "off", "keep"), default="keep",
                   help="the key swap: on, off, or as it is (the default)")
    p.add_argument("--egress", choices=("on", "off", "keep"), default="keep",
                   help="the outgoing gate (its kernel rules, its units and the closures): on, off, or as it is")
    p.add_argument("--check", action="store_true", help="read, and change nothing")
    p = sub.add_parser("egress", help="Run this machine's outgoing gate, as its own user, from its launcher: each "
                                      "connection and DNS question of an agent user, recorded")
    p.add_argument("--config", default=EGRESS_CONF)
    p.add_argument("--check", action="store_true", help="the start check alone: nothing listens")
    p.add_argument("--take", help=argparse.SUPPRESS)       # name=fd,...,pipe=fd: a hand-over
    p = sub.add_parser("egress-rules", help="As root: load the gate's kernel rules with their sets (none without "
                                            "root's rules file), close the local services that resolve or connect "
                                            "for any user, and take each agent user out of the container groups")
    p.add_argument("--config", default=EGRESS_CONF)
    p.add_argument("--table", action="store_true", help="the kernel rules alone (the drop-in of nftables.service)")
    p = sub.add_parser("egress-close", help="As root: close one local service for the agent users (a drop-in runs "
                                            "it at the service's start)")
    p.add_argument("--config", default=EGRESS_CONF)
    p.add_argument("which", choices=sorted(EGRESS_CLOSED) + ["daemons"])
    args = parser.parse_args(argv)
    if args.cmd == "configure":
        return configure_main(args)
    if args.cmd == "egress":
        return egress_main(args.config, take=args.take, check=args.check)
    if args.cmd in ("egress-rules", "egress-close"):
        return egress_root_main(args)
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
