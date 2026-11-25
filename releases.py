#!/usr/bin/env python3
"""The release channel: how a Founderizer fleet takes a new revision, and how it keeps the old one when the new one
is bad. PRODUCT.md 4.2 and 4.3, package P6.

The fleet already moves between revisions: its configuration lives on the branch `config`, the hub commits the
owner's own changes there, and code arrives by a merge (COORDINATION.md "The configuration ref"). This module adds
the three things that a customer's machine needs and the owner's own fleet never had: where the code comes from
(the git remote `upstream`), which revision is released (a signed manifest), and the safety that a bad release
costs nothing.

    manifest = check(raw, key)                      a manifest we may act on, or Untrusted
    Update(kit, manifest, origin=url).apply()       the update, with its own roll-back

**The signature is the whole trust.** A manifest that no public key in the repository verifies is not read, not
recorded and not applied. The private keys live only on the owner's Mac and in the owner's own vault (PRODUCT.md
4.3, "Who signs a release"), so a hub can check a release and can never make one. The key file holds a set, so a key
can be replaced without stranding a fleet that skipped the release which brought the new one (4.3, "How a signing
key is replaced").

**Two tracks.** A fleet takes from the channel only a release that a key of KEY_FILE signed, which the owner's Mac
signs once the owner's own fleet runs that release, unless the fleet takes releases early (the hub's setting `releases.early`, the owner's own fleet):
then it asks the channel for the early track and trusts the keys of EARLY_KEY_FILE too, which sign each release as
it is published. A release that a fleet already took is checked against both files (every_key).

**Nothing happens in the hub's own checkout until every check passed.** The merge, the released code's schema
against a copy of this fleet's own database, `selftest.py` and `fleet.py verify` all run in a temporary clone,
exactly as `hub.commit_kit_file` commits the owner's files. So the pinned revision is not a revision the fleet
goes back to: it is the revision the fleet never left. A broken release costs the time it took to find out, and
nothing else.

The schema check is there because the other two cannot see it: both start hubs on *fresh* databases, so a
migration step that only the customer's own rows refuse passes them and meets real data for the first time at the
restart, after the ref has moved. `Update.schema_check` says the rest.

**The `hold` flag is the stop button.** The manifest can say that no fleet should take this release, whatever a
fleet's own settings say. It is signed with everything else, so it cannot be stripped on the way.

**The entitlement is carried, never enforced.** A hub that holds one sends it as a bearer to the channel and keeps
what comes back. Nothing here refuses work when it expires. A hub with none asks with no Authorization header, and
the channel answers every fleet (the website's docs/CONTRACTS.md, "A call with no token"). Founderizer for Teams
reads the kept token in the hub (hub.teams_on), and only one signed word turns it off there (read_ended).

No dependency: a hub is a bare Ubuntu server with python3, git and curl (hub.sh PACKAGES), so the Ed25519
verification below is the reference implementation of RFC 8032. Where the machine has an OpenSSL that verifies Ed25519
(every supported Linux system has one), that proven implementation checks each signature too, and a release is taken
only when both say yes (openssl_agrees).
"""
import base64
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

# The configuration ref and the baseline of selftest.py belong to other packages; this module reads them and
# changes neither, so the three can never disagree about what "up to date" or "a pass" means. It reads them where it
# uses them and not at the top, so that the check of a release (check and what it calls) imports nothing but the
# standard library: the root-owned copy that a machine's vault program checks a release with is this file alone
# (hubsetup.vault_program_script), and `lifecycle.may_take` imports this module from inside lifecycle.

# Where a release comes from, and where the manifest is asked for. Both are defaults: the hub overrides them from
# its own configuration (hub.releases region), because P7 settles the host of the channel and the address of the
# published repository. The channel is the platform: founderizer.com is the marketing site, and no program reads from
# it (the owner, 21 November 2026).
DEFAULT_CHANNEL = "https://platform.founderizer.com"
DEFAULT_UPSTREAM = "https://github.com/founderizer/founderizer.git"
REMOTE = "upstream"                 # PRODUCT.md 4.3: "every hub carries [it] as the git remote `upstream`"
MOVED = "refs/founderizer/moved"    # where the clone keeps the ref's own tip when a push lost to it
KEY_FILE = "release-key.pub"        # the release public keys, shipped in the repository beside this file
EARLY_KEY_FILE = "early-key.pub"    # the keys of the early track, which a fleet that takes releases early trusts too
ENTITLEMENT_KEY_FILE = "entitlement-key.pub"    # the entitlement public keys: another key, and its own file (4.2)

CHANNEL_TIMEOUT = 10        # seconds for GET /releases/latest: a channel that does not answer changes nothing
SELFTEST_WAIT = 300         # seconds for selftest.py, as verify.py gives it
VERIFY_WAIT = 420           # seconds for fleet.py verify; the run's own selftest.py comes before it, and it runs none
SCHEMA_WAIT = 120           # seconds for the released code's schema against a copy of this fleet's database
PIECES_WAIT = 120           # seconds for the clone's hubpieces.py, which compiles hub.py in pieces in about a second
GIT_WAIT = 300              # seconds for one git step; a fetch of the whole repository is the slow one
PUSH_TRIES = 4              # the push of the configuration ref, and three more when the hub moved the ref under it

REVISION = re.compile(r"[0-9a-f]{40}")                          # a full commit id, never a short one
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,40}")      # the name the owner reads, "2026.10.2"
NOTES = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,400}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{1,2000}\.[A-Za-z0-9_-]{1,200}")      # the entitlement, as 4.2 is carried


class Untrusted(Exception):
    """A manifest, a signature or an entitlement that this fleet will not act on. Its text is one line for the
    owner, and it never carries what it refused."""


# ---------------------------------------------------------------- Ed25519 (RFC 8032, the reference implementation)
#
# Kept as close to the RFC's own appendix as the house style allows, so that it can be read against it. The hub
# only ever verifies; sign() is here because our own publishing step and the tests need the other half, and because
# a signature scheme with no reachable signer cannot be tested at all. No private key is ever kept on a hub.

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(point, other):
    """Two points in extended coordinates (X, Y, Z, T)."""
    a = (point[1] - point[0]) * (other[1] - other[0]) % _P
    b = (point[1] + point[0]) * (other[1] + other[0]) % _P
    c = 2 * point[3] * other[3] * _D % _P
    d = 2 * point[2] * other[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar, point):
    found = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            found = _add(found, point)
        point = _add(point, point)
        scalar >>= 1
    return found


_IDENTITY = (0, 1, 1, 0)


def _same(point, other):
    return ((point[0] * other[2] - other[0] * point[2]) % _P == 0
            and (point[1] * other[2] - other[1] * point[2]) % _P == 0)


def _usable_key(point):
    """A public key of the prime-order subgroup, and not the identity or the one point of order two.

    RFC 8032 does not ask for this, and many implementations leave it out, which is how a signature of a
    small-order key verifies against messages nobody signed. Our key is our own and is none of them, so this costs
    one scalar multiplication on a poll and closes the one shape in which a wrong key could verify at all."""
    return point[0] % _P != 0 and _same(_mul(_Q, point), _IDENTITY)


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(point):
    zinv = _inv(point[2])
    x, y = point[0] * zinv % _P, point[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(blob):
    if len(blob) != 32:
        return None
    y = int.from_bytes(blob, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _modq(blob):
    return int.from_bytes(hashlib.sha512(blob).digest(), "little") % _Q


def _expand(secret):
    digest = hashlib.sha512(secret).digest()
    scalar = int.from_bytes(digest[:32], "little")
    return (scalar & ((1 << 254) - 8)) | (1 << 254), digest[32:]


def public_key(secret):
    """The 32-byte public key of a 32-byte Ed25519 seed."""
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    return _compress(_mul(_expand(secret)[0], _G))


def sign(secret, message):
    """The 64-byte detached signature of `message`. Never called on a hub: no hub holds a private key."""
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    scalar, prefix = _expand(secret)
    pub = _compress(_mul(scalar, _G))
    r = _modq(prefix + message)
    rs = _compress(_mul(r, _G))
    return rs + int.to_bytes((r + _modq(rs + pub + message) * scalar) % _Q, 32, "little")


def verify_signature(public, message, signature):
    """True when `signature` is this public key's signature of `message`. Every wrong shape is False, never a
    crash: a manifest from the outside must not be able to raise out of a check."""
    if not (isinstance(public, bytes) and len(public) == 32
            and isinstance(signature, bytes) and len(signature) == 64 and isinstance(message, bytes)):
        return False
    try:
        point = _decompress(public)
        given = _decompress(signature[:32])
        scalar = int.from_bytes(signature[32:], "little")
        if point is None or given is None or scalar >= _Q or not _usable_key(point):
            return False
        h = _modq(signature[:32] + public + message)
        return _same(_mul(scalar, _G), _add(given, _mul(h, point)))
    except (ValueError, TypeError, OverflowError):
        return False


# ---------------------------------------------------------------- a second opinion: OpenSSL's Ed25519
#
# Since 20 November 2026 a release is taken only when this machine's OpenSSL says yes too, where the machine has one
# that verifies Ed25519 (the owner's "OpenSSL as a second check"). So one wrong line of our own code above cannot let a
# forged release into a fleet, and a machine with no such OpenSSL checks as before. No package comes in: every supported
# Linux system has OpenSSL 3, because its ca-certificates depends on it, and a Mac's Homebrew Python brings Homebrew's;
# macOS's own /usr/bin/openssl (LibreSSL 3.3) has no Ed25519, and the probe below passes it over. A program is looked
# for only at these places, never on the PATH, and is used only once it took RFC 8032's test vector and refused it with
# one bit changed.
OPENSSL_PLACES = ("/usr/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl",
                  "/usr/local/opt/openssl@3/bin/openssl")
OPENSSL_WAIT = 30                   # seconds for one check by OpenSSL
OPENSSL_SAYS = "Signature Verified Successfully"    # pkeyutl's line for a good signature, beside its status 0
_ED25519_HEAD = bytes.fromhex("302a300506032b6570032100")      # the DER head of an Ed25519 public key (RFC 8410)
# RFC 8032's TEST 2 (section 7.1): OpenSSL's pkeyutl reads no message of zero bytes, so not TEST 1. No manifest is
# empty, and a message of zero bytes is refused wherever OpenSSL checks.
_PROBE = (bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), b"\x72",
          bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"))
_openssl = []                       # [the program] once one is found in this process; empty before, or with none


def openssl_verify(program, public, message, signature):
    """True when the OpenSSL program at this path says that `signature` is the Ed25519 signature of `message` by the
    32-byte key `public`: both its status 0 and its line. Every failure to ask it is False."""
    folder = None
    try:
        folder = tempfile.mkdtemp(prefix="fleet-ed25519-")
        names = ("key.pem", "message", "signature")
        pem = (b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(_ED25519_HEAD + bytes(public))
               + b"\n-----END PUBLIC KEY-----\n")
        for name, data in zip(names, (pem, bytes(message), bytes(signature))):
            with open(os.path.join(folder, name), "wb") as f:
                f.write(data)
        key, text, sig = (os.path.join(folder, name) for name in names)
        done = subprocess.run([program, "pkeyutl", "-verify", "-pubin", "-inkey", key, "-rawin", "-in", text,
                               "-sigfile", sig], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=OPENSSL_WAIT)
        return done.returncode == 0 and done.stdout.decode("utf-8", "replace").strip() == OPENSSL_SAYS
    except (OSError, TypeError, ValueError, subprocess.SubprocessError):
        return False
    finally:
        if folder:
            shutil.rmtree(folder, ignore_errors=True)


def openssl_verifier(again=False):
    """The first OpenSSL of OPENSSL_PLACES that takes RFC 8032's test vector and refuses it with one bit changed, or
    None: then our own Ed25519 decides alone. A program that it found is kept for the process; when it found none, it
    looks again at the next check, so a short fault of a probe (a time-out under load, a full /tmp) does not turn the
    second check off for the life of a hub. `again` probes anew in any case."""
    held = _openssl[:1]             # one read: another thread of the hub can empty the list between a test and an index
    if held and not again:
        return held[0]
    public, message, signature = _PROBE
    forged = bytes([signature[0] ^ 1]) + signature[1:]
    found = next((program for program in OPENSSL_PLACES
                  if os.path.isfile(program) and os.access(program, os.X_OK)
                  and openssl_verify(program, public, message, signature)
                  and not openssl_verify(program, public, message, forged)), None)
    _openssl[:] = [found] if found else []
    return found


def openssl_agrees(public, message, signature):
    """True when this machine has no OpenSSL that verifies Ed25519, or when its OpenSSL takes this signature too.
    OpenSSL's no is asked once more after a new probe: a program that stopped working since its probe then refuses
    nothing by itself, and our own Ed25519 decides, as on a machine with none, while an OpenSSL that works refuses a
    forged signature both times."""
    program = openssl_verifier()
    if program is None or openssl_verify(program, public, message, signature):
        return True
    program = openssl_verifier(again=True)
    return program is None or openssl_verify(program, public, message, signature)


# ---------------------------------------------------------------- the public keys, shipped in the repository

MAX_KEYS = 4            # how many keys one file may hold: two while a key is being replaced, and room for a mistake


def read_keys(kit, name=KEY_FILE):
    """The public keys of this checkout, a tuple in the file's own order, and empty when it carries none yet
    (parse_keys says how the file is read).

    The file holds one base64 line for each 32-byte Ed25519 public key; lines that start with # are for the reader.
    **It is a set, and every key in it is trusted.** That is the whole of a rotation: the release that brings the
    next key is signed with the key it replaces, every release after it is signed with the new one, and a fleet
    that skipped the release in between still carries a key that checks both (PRODUCT.md 4.3, "How a signing key
    is replaced"). One line is the ordinary state and asks nothing of a reader.

    A line that is not a 32-byte key, or more lines than MAX_KEYS, makes the whole file carry nothing: a key file
    that is half read is a mistake, and a fleet that cannot say which keys it trusts takes no release. No key means
    that every manifest is refused, which is the right answer until P7 publishes the first ones."""
    path = os.path.join(kit, name)
    try:
        with open(path, encoding="utf-8") as f:
            return parse_keys(f.read())
    except (OSError, ValueError):
        return ()


def parse_keys(text):
    """The keys of one key file's text, as read_keys reads the file: a tuple, empty when the text carries none or
    cannot be read whole. `lifecycle.may_take` reads the text out of a commit, never from a working tree."""
    lines = [line.strip() for line in (text or "").split("\n") if line.strip() and not line.strip().startswith("#")]
    if not lines or len(lines) > MAX_KEYS:
        return ()
    keys = []
    for line in lines:
        try:
            key = base64.b64decode(line, validate=True)
        except (ValueError, TypeError):
            return ()
        if len(key) != 32:
            return ()
        keys.append(key)
    return tuple(keys)


def every_key(kit):
    """The keys of both files, KEY_FILE and EARLY_KEY_FILE: what checks a release that a fleet already took
    (lifecycle.may_take and the root copies of the check), because a fleet that takes releases early took one that
    the early key signed. Which releases a fleet takes from the channel is the hub's own setting (hub.release_keys)."""
    return read_keys(kit) + read_keys(kit, EARLY_KEY_FILE)


def trusted(keys):
    """The keys a check may use, from the tuple `read_keys` gives, from one key, or from None. One key is still one
    key: nothing that holds a key has to know that the file became a set."""
    held = (keys,) if isinstance(keys, (bytes, bytearray)) else tuple(keys or ())
    return tuple(bytes(key) for key in held if isinstance(key, (bytes, bytearray)) and len(key) == 32)


def signed_by_any(keys, message, signature):
    """True when one of these keys signed `message`: our own Ed25519 says so, and so does this machine's OpenSSL
    where it has one that verifies Ed25519 (openssl_agrees). Every key the checkout carries is trusted, so the fleet
    that is a release behind and the fleet that is up to date check the same release, each with a key it has."""
    return any(verify_signature(key, message, signature) and openssl_agrees(key, message, signature)
               for key in trusted(keys))


def self_check():
    """None when this machine checks a release as it must: a manifest that a test key signed passes signed_by_any,
    and the same manifest with one bit of its signature changed does not. Else the one line that says which. The hub
    runs it through selftest.py on the code of a release before it takes it, so a release whose check would refuse
    every later release on the hub's machine is not taken there. A helper, the door and a root copy of this file run
    no selftest.py: each one asks the probe in each process, and with no OpenSSL that passes it, our own Ed25519
    decides, as before."""
    seed = hashlib.sha256(b"Founderizer: the self-check of a release").digest()
    key = public_key(seed)
    text = signed_text({"revision": "0123456789abcdef" * 2 + "01234567", "version": "2026.11.1",
                        "notes": DEFAULT_CHANNEL + "/notes", "minimum": "", "hold": False})
    good = sign(seed, text)
    if not signed_by_any([key], text, good):
        return "this machine's check refuses a release that a trusted key signed"
    if signed_by_any([key], text, bytes([good[0] ^ 1]) + good[1:]):
        return "this machine's check takes a release whose signature was changed"
    return None


# ---------------------------------------------------------------- the manifest

# What the signature covers, which PRODUCT.md 4.3 leaves open. One line for each field, in this order, so that a
# signer in any language produces the same bytes and no field can be dropped on the way: `hold` is in here, so the
# stop button cannot be stripped. A later version numbers itself in the first line and is not taken by this one.
SIGNED_PREFIX = b"founderizer-release-1"


def signed_text(manifest):
    """The exact bytes that a release signature covers."""
    return b"\n".join([SIGNED_PREFIX,
                       manifest["revision"].encode(),
                       manifest["version"].encode(),
                       (manifest["notes"] or "").encode(),
                       (manifest["minimum"] or "").encode(),
                       b"true" if manifest["hold"] else b"false"]) + b"\n"


def read_manifest(raw):
    """The manifest of PRODUCT.md 4.3, checked field by field before anything is done with it. `hold` is optional
    and false when it is absent, so a channel that never holds a release writes nothing extra.

    It raises Untrusted on anything it does not recognise. This runs before the signature check, so it must not
    trust a single character of what it reads."""
    if not isinstance(raw, dict):
        raise Untrusted("the release channel did not answer with a manifest")
    revision, version = raw.get("revision"), raw.get("version")
    notes, minimum, hold = raw.get("notes"), raw.get("minimum"), raw.get("hold", False)
    if not (isinstance(revision, str) and REVISION.fullmatch(revision)):
        raise Untrusted("the manifest names no revision")
    if not (isinstance(version, str) and VERSION.fullmatch(version)):
        raise Untrusted("the manifest has no version name")
    if notes is not None and not (isinstance(notes, str) and (notes == "" or NOTES.fullmatch(notes))):
        raise Untrusted("the manifest's notes are not an https address")
    if minimum is not None and minimum != "" and not (isinstance(minimum, str) and REVISION.fullmatch(minimum)):
        raise Untrusted("the manifest's minimum is not a commit")
    if not isinstance(hold, bool):
        raise Untrusted("the manifest's hold is not true or false")
    signature = raw.get("signature")
    if not (isinstance(signature, str) and 0 < len(signature) <= 200):
        raise Untrusted("the manifest carries no signature")
    return {"revision": revision, "version": version, "notes": notes or None, "minimum": minimum or None,
            "hold": hold, "signature": signature}


def check(raw, keys):
    """The manifest this fleet may act on, or Untrusted. Nothing else in this module reads an unchecked manifest.

    `keys` is what `read_keys` gave this fleet, and any one of them may have signed the release."""
    manifest = read_manifest(raw)
    keys = trusted(keys)
    if not keys:
        raise Untrusted(f"this checkout carries no release key ({KEY_FILE}), so no release can be checked")
    try:
        signature = base64.b64decode(manifest["signature"] + "=" * (-len(manifest["signature"]) % 4), validate=False)
    except (ValueError, TypeError):
        raise Untrusted("the manifest's signature is not base64") from None
    if not signed_by_any(keys, signed_text(manifest), signature):
        if any(verify_signature(key, signed_text(manifest), signature) for key in keys):
            raise Untrusted("the manifest's signature passes this checkout's own check, and this machine's OpenSSL "
                            "refuses it")
        raise Untrusted("the manifest's signature is not a signature of it by a release key this checkout carries")
    return manifest


# ---------------------------------------------------------------- the entitlement (PRODUCT.md 4.2)

def new_fleet_id():
    """Sixteen random hex characters: it identifies a fleet to us and says nothing about its owner (4.2)."""
    return os.urandom(8).hex()


def read_entitlement(token, keys=None):
    """The claims of an entitlement token, as given. `verified` says whether one of our own keys signed it.

    The keys are the **entitlement** keys, `ENTITLEMENT_KEY_FILE`, and not the release keys: the website signs a
    release with one and an entitlement with the other, and publishes both (PRODUCT.md 4.2). A hub that checked an
    entitlement with its release key would mark every real entitlement unverified.

    The hub carries this token and never acts on it: an expired entitlement changes nothing here, because only our
    side refuses (4.2). So an unverifiable token is still kept and still shown; it is marked, not refused.

    The counts are read as the token gives them, each None when it has none: `machines`; `users`, the users that a
    licence of Founderizer for Teams pays for (the coordinator's D81 and D85, 25 November 2026: the owner, and each
    person of the fleet's People list who can write to an agent, by the gate that each of their messages passes;
    hub.licence_users); and `agents`, the count of a token that our side signed before D81. Neither name is needed,
    so a token of either form keeps its licence: since its release for D81 the platform signs only `users`, and it
    still verifies a token with `agents` that it signed before that release."""
    if not (isinstance(token, str) and TOKEN.fullmatch(token)):
        raise Untrusted("an entitlement is <claims>.<signature>, both base64url")
    body, _, signature = token.partition(".")
    try:
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8"))
        raw_signature = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except (ValueError, TypeError, UnicodeDecodeError):
        raise Untrusted("the entitlement's claims are not base64url JSON") from None
    if not isinstance(claims, dict):
        raise Untrusted("the entitlement's claims are not an object")
    fleet, plan, until = claims.get("fleet"), claims.get("plan"), claims.get("until")
    counts = {name: claims.get(name) for name in ("machines", "agents", "users")}
    if not (isinstance(fleet, str) and re.fullmatch(r"[0-9a-f]{16}", fleet)):
        raise Untrusted("the entitlement names no fleet")
    if not (isinstance(plan, str) and VERSION.fullmatch(plan)):
        raise Untrusted("the entitlement names no plan")
    if isinstance(until, bool) or not isinstance(until, (int, float)) or not 0 < until < 2 ** 40:
        raise Untrusted("the entitlement has no until date")
    for name, number in counts.items():
        if number is not None and (isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 10000):
            raise Untrusted(f"the entitlement's {name} is not a count")
    return {"fleet": fleet, "plan": plan, "until": float(until), **counts,
            "verified": signed_by_any(keys, body.encode(), raw_signature)}


def sign_entitlement(secret, claims):
    """The other half of read_entitlement, for our own side and for the tests. Never called on a hub."""
    body = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=")
    return (body + b"." + base64.urlsafe_b64encode(sign(secret, body)).rstrip(b"=")).decode()


# The word that a licence of Founderizer for Teams ended (teams-design-1-shop-and-licence.md, 3.9): the one signed
# message that turns Teams off in a hub, because silence, a date or a refusal of one of our services changes nothing.
# The entitlement key signs it, as it signs the token. One line for each field, in this order, with a first line of
# its own, so that no release text and no other message of ours can be taken for it.
LICENCE_PREFIX = b"founderizer-licence-1"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def ended_text(word):
    """The exact bytes that the signature of the word "ended" covers."""
    return b"\n".join([LICENCE_PREFIX, b"ended", word["fleet"].encode(), word["token_sha256"].encode(),
                       str(word["at"]).encode()]) + b"\n"


def read_ended(raw, fleet, token, keys):
    """The word that the licence of `token` ended, checked field by field: {"state": "ended", "fleet",
    "token_sha256", "at", "signature"}. It must name `fleet` (this fleet's id) and the SHA-256 of `token` (the token
    that the hub holds now), and one of `keys` (the **entitlement** keys) must have signed ended_text of it. `at` is
    the time, in whole epoch seconds, at which our records say that the licence ended.

    It raises Untrusted on anything else, so that a word which a hub cannot check changes nothing. A word names one
    token: a new token is not ended by an old word."""
    if not isinstance(raw, dict) or raw.get("state") != "ended":
        raise Untrusted("the answer is not the word that a licence ended")
    word_fleet, digest, at, signature = raw.get("fleet"), raw.get("token_sha256"), raw.get("at"), raw.get("signature")
    if not (isinstance(word_fleet, str) and re.fullmatch(r"[0-9a-f]{16}", word_fleet)):
        raise Untrusted("the word names no fleet")
    if not (isinstance(digest, str) and SHA256_HEX.fullmatch(digest)):
        raise Untrusted("the word names no token")
    if isinstance(at, bool) or not isinstance(at, int) or not 0 < at < 2 ** 40:
        raise Untrusted("the word has no time")
    if not (isinstance(signature, str) and 0 < len(signature) <= 200):
        raise Untrusted("the word carries no signature")
    if word_fleet != fleet:
        raise Untrusted("the word is for another fleet")
    if not (isinstance(token, str) and digest == hashlib.sha256(token.encode()).hexdigest()):
        raise Untrusted("the word names another token than the one this fleet holds")
    if not trusted(keys):
        raise Untrusted(f"this checkout carries no entitlement key ({ENTITLEMENT_KEY_FILE}), so no word can be checked")
    try:
        raw_signature = base64.b64decode(signature + "=" * (-len(signature) % 4), validate=True)
    except (ValueError, TypeError):
        raise Untrusted("the word's signature is not base64") from None
    word = {"state": "ended", "fleet": word_fleet, "token_sha256": digest, "at": at, "signature": signature}
    if not signed_by_any(keys, ended_text(word), raw_signature):
        raise Untrusted("the word is not signed by an entitlement key that this checkout carries")
    return word


# ---------------------------------------------------------------- POST /api/entitlement/renew: the licence's poll
#
# teams-design-1-shop-and-licence.md, 3.10 (J6). A hub that holds a licence of Founderizer for Teams asks the
# channel for it one time each hour, with the count of its users (D81 and D85: the owner and each person who can write
# to an agent, hub.licence_users; no agent is counted), and keeps what comes back only by its
# signature (hub.licence_take): a token that our key signed, or the signed word "ended". The licence goes only to our
# own site over HTTPS, by the rule of errorreports.endpoint, and never to the address of a redirect.
LICENCE_PATH = "/api/entitlement/renew"
OUR_HOST = re.compile(r"(?:[a-z0-9-]+\.)*founderizer\.com")
CHANNEL_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")
# The `error` codes of the route's answers (the platform's docs/CONTRACTS.md, "The licence poll"): the only word of
# an answer that the hub's log keeps, and only one of these, so that no sender writes a word of its own there.
ERROR_CODES = frozenset(("ended", "lapsed", "unbound", "no_licence", "unavailable", "too_many"))
COUNT_MOST = 10000                               # the users that one count may name, as a token's `users`
ANSWER_MOST = 65536                              # bytes of an answer that the poll reads; a token is far less


def licence_endpoint(channel, path=LICENCE_PATH):
    """The address of the licence's poll on the fleet's release channel, which must be HTTPS at founderizer.com or a
    host below it (each label letters, digits and hyphens), with no user name, query, fragment or odd path: never
    `xfounderizer.com`. Untrusted for any other channel, so that a hub whose channel names another site sends its
    licence nowhere. `path`: LICENCE_PATH, or CLAIM_PATH for the claim (claim), whose key goes by the same rule."""
    refused = Untrusted("the fleet's channel is not founderizer.com, so the licence's poll goes nowhere")
    try:
        parts = urllib.parse.urlsplit(str(channel or "").strip())
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        raise refused from None
    if parts.scheme.lower() != "https" or not OUR_HOST.fullmatch(host) or parts.username is not None \
            or parts.password is not None or parts.query or parts.fragment \
            or not CHANNEL_PATH.fullmatch(parts.path.rstrip("/")):
        raise refused
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit(("https", netloc, parts.path.rstrip("/") + path, "", ""))


def _loopback(host):
    """True for a literal address of this machine's loopback (127.0.0.0/8, ::1): the one host that _post asks over
    http, a test's stand-in of the channel. A name is no such address."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except (TypeError, ValueError):
        return False


def _connect(host, port, deadline, timeout):
    """A socket connected to `host`: each address that the system's lookup gives, in its order, with a part of the time
    that remains before `deadline` (a third of `timeout` at most, and the last address all that remains), and not each
    address with the whole limit, as socket.create_connection gives it. So a host whose first address drops every
    packet (IPv6 on many servers) is reached on its next one inside the limit, and N dead addresses do not last N
    limits. The lookup itself is the system's own, with the system's limits. The OSError of the last address that
    failed, or TimeoutError when no time remained. Its twin is teamspack.connect, for the package's GET: that module
    imports no module of the hub, so the two are kept alike by hand."""
    found = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    error = None
    for n, (family, kind, proto, _name, where) in enumerate(found):
        rest = deadline - time.monotonic()
        if rest <= 0:
            break
        sock = None
        try:                        # a family that the kernel does not have (IPv6 off) raises here: the next address
            sock = socket.socket(family, kind, proto)
            sock.settimeout(rest if n == len(found) - 1 else min(rest, timeout / 3))
            sock.connect(where)
        except OSError as e:
            if sock is not None:
                sock.close()
            error = e
            continue
        sock.settimeout(timeout)
        return sock
    raise error or TimeoutError("timed out")


def _post(url, token, body, timeout=CHANNEL_TIMEOUT):
    """(status, text) of one POST of `body` as JSON, with the token as the bearer, or none when it is None (the claim,
    `claim`, carries its key in the body). status 0 and the reason when no whole answer came: also a body that ends
    before its Content-Length ("IncompleteRead"), which is the start of an answer and not an answer.

    - **No proxy and no redirect.** http.client reads no proxy that the environment names and follows nothing, so the
      licence goes only to the address that licence_endpoint checked. A 3xx is its own status.
    - **`timeout` seconds for the whole call**: the connection, the TLS handshake, the request, the head and the body
      together, and not only each read of the socket (its own timeout). The connection gives each address of the
      host a part of the time that remains (_connect). From the connection on, a timer shuts the socket down at the
      limit, and the body is read in pieces (`read1`) with the clock read before each one, so a channel that sends
      one byte at a time holds the licence's poll no longer than that: until 22 November 2026 it held it for as long
      as the channel sent, and hub.licence_sweep starts no poll while one runs. This code makes the TLS socket
      itself, before its handshake, so that the timer reaches it. Only the lookup of the host's name is the system's
      own, with the system's limits.
    - At most ANSWER_MOST bytes of the body are read.
    - **https**, with the certificate and the name checked, and http only to a literal loopback address (a test's
      stand-in), so that the bearer never goes in clear over a network. licence_endpoint gives an https address
      only."""
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port         # .port: ValueError for a port that is no number
        if not (parts.scheme == "https" and host or parts.scheme == "http" and _loopback(host)):
            return 0, "the licence's poll goes only over https, and over http only to this machine's loopback address"
        if parts.scheme == "https":
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port or 443, timeout=timeout, context=context)
        else:
            context, conn = None, http.client.HTTPConnection(host, port or 80, timeout=timeout)
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    except ValueError as e:
        return 0, type(e).__name__
    except OSError as e:            # this machine's certificates for TLS
        return 0, str(e)[:300]
    payload = json.dumps(body, separators=(",", ":")).encode()
    headers = {"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "founderizer-hub"}
    if token is not None:       # the claim (claim) carries its key in the body and sends no bearer
        headers["Authorization"] = "Bearer " + token
    ended, late = threading.Event(), f"it did not answer whole in {timeout:g} seconds"

    def cut():
        """The limit of the whole call: a read or a write that waits on the socket ends at once."""
        ended.set()
        sock = conn.sock
        if sock is not None:
            with contextlib.suppress(OSError):
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
    deadline = time.monotonic() + timeout
    timer = threading.Timer(timeout, cut)
    timer.daemon = True
    timer.start()
    try:
        conn.sock = _connect(conn.host, conn.port, deadline, timeout)
        if ended.is_set():          # the timer came at the end of the connection, when no socket was there to shut
            return 0, late
        if context is not None:
            conn.sock = context.wrap_socket(conn.sock, server_hostname=host, do_handshake_on_connect=False)
            if ended.is_set():      # the timer came while the socket changed hands: the handshake has no limit
                return 0, late
            conn.sock.do_handshake()
        conn.request("POST", target, body=payload, headers=headers)
        answer = conn.getresponse()
        status, text = answer.status, b""
        while len(text) < ANSWER_MOST:
            if time.monotonic() >= deadline:
                return 0, late
            piece = answer.read1(ANSWER_MOST - len(text))       # what one receive brings
            if not piece and answer.length:     # read1 gives b"" for a body that ends before its Content-Length
                raise http.client.IncompleteRead(text, answer.length)
            if not piece:
                break
            text += piece
        if ended.is_set():          # the timer's cut reads as the end of the head or of the body: not a whole answer
            return 0, late
        return status, text.decode("utf-8", "replace")
    except (OSError, http.client.HTTPException, ValueError) as e:
        if ended.is_set() or time.monotonic() >= deadline:      # the timer's cut, or a socket's own end at the limit
            return 0, late
        if isinstance(e, ssl.SSLError) or not isinstance(e, (http.client.HTTPException, ValueError)):
            return 0, str(e)[:300]          # this machine's reason: no route, no name, no TLS, a certificate
        return 0, type(e).__name__          # a status line or a header that is not HTTP, or a header that no request
                                            # carries: its class only, because its text is the server's or the token's
    finally:
        timer.cancel()
        conn.close()


def renew(url, token, users=None, *, timeout=CHANNEL_TIMEOUT):
    """One licence's poll: POST `url` (licence_endpoint of the channel) with `token` as the bearer and the body
    {"users": <the count of the fleet's users, hub.licence_users>}, or {} with `users` None (the asks after the word
    "ended"), and nothing else of the fleet. Until D81 (25 November 2026) the body was {"agents": <the count of the
    fleet's active agents>}; the platform still answers such a body, with a token, and records no count from it.

    Returns {"status", "token", "renews", "ended", "says"}, and no answer makes it raise. `token`: the token of a 200,
    unchecked (the hub keeps it only if our key signed it for this fleet), with `renews`, what the platform says of it
    (None when the answer does not say it). The answer's own count, `users` or the `agents` of before D81, is read by
    nobody: no signature covers it, and the token that does carries the same count (read_entitlement). `ended`: the
    word of a 410 `ended`, unchecked (hub.take_ended_word checks it). `says`: one line for the hub's log, which holds
    the status and the answer's `error` code, never other words of the answer. A status or a body that is none of
    these gives only `says`, and the hub changes nothing for it."""
    if users is not None and (isinstance(users, bool) or not isinstance(users, int)
                              or not 0 <= users <= COUNT_MOST):
        raise ValueError("a count of users is a whole number from 0 to 10000")
    status, text = _post(url, token, {} if users is None else {"users": users}, timeout)
    answer = {"status": status, "token": None, "renews": None, "ended": None, "says": None}
    if status == 0:
        return dict(answer, says="the licence's poll got no answer from the release channel: " + text)
    try:
        raw = json.loads(text)
    except (ValueError, RecursionError):        # RecursionError: JSON nested deeper than Python's stack takes
        raw = None
    raw = raw if isinstance(raw, dict) else {}
    fresh, renews = raw.get("token"), raw.get("renews")
    if status == 200 and isinstance(fresh, str) and TOKEN.fullmatch(fresh):
        return dict(answer, token=fresh, renews=renews if isinstance(renews, bool) else None)
    if status == 410 and raw.get("error") == "ended" and isinstance(raw.get("ended"), dict):
        return dict(answer, ended=raw["ended"])
    error = raw.get("error")
    code = f" ({error})" if isinstance(error, str) and error in ERROR_CODES else ""
    return dict(answer, says=f"the licence's poll got {status}{code} from the release channel")



# ---------------------------------------------------------------- POST /api/entitlement/claim: the claim
#
# teams-design-1-shop-and-licence.md, 3.11. The owner's app gives the hub the key of a purchase (POST
# /ui/teams/claim), and the hub trades it here, with its own fleet id, for the licence's token. The key goes only to
# the address that licence_endpoint checked (HTTPS at founderizer.com), in the body, with no bearer, no proxy and no
# redirect, and the whole call ends within CLAIM_WAIT seconds, because the owner's app waits for its answer.
CLAIM_PATH = "/api/entitlement/claim"
CLAIM_WAIT = 30         # seconds for the whole claim, from the connection to the last byte of the answer
# The `error` codes of the claim's refusals (the platform's docs/CONTRACTS.md, "The claim"), and `gone`, the answer of
# a shop that is closed: only with one of these is the answer's `says` line passed on, for the app's words of a
# refused claim (E2); each other answer gets the hub's own line.
CLAIM_ERRORS = frozenset(("unknown_key", "expired_key", "not_live", "test_shop", "used_key", "fleet_taken",
                          "too_many", "unavailable", "gone", "incomplete", "unreadable"))
SAYS_MOST = 300         # characters of a `says` line, as the platform writes it at most


def claim(url, key, fleet, *, timeout=CLAIM_WAIT):
    """One claim: POST `url` (licence_endpoint of the channel with CLAIM_PATH) with {"claim_key": key, "fleet":
    fleet} and nothing else of the fleet.

    Returns {"status", "token", "renews", "error", "says"}, and no answer makes it raise. `token`: the token of a 200,
    unchecked (the hub keeps it only if our key signed it for this fleet with plan `teams`), with `renews` (None when
    the answer does not say it). Else `error`, the answer's code when it is one of CLAIM_ERRORS, and `says`: that
    refusal's own line, on one line and cut to SAYS_MOST characters, or the hub's line with the status alone. status 0:
    no answer, also when the whole call took more than `timeout` seconds (CLAIM_WAIT: _post's limit for the whole
    call, from the connection to the last byte); a claim again with the same key gets the same token (the platform's
    "A hub that lost the answer asks again"). Until 22 November 2026 the claim gave _post min(10, 30) seconds, so a
    platform that answered after 10 seconds was no answer."""
    status, text = _post(url, None, {"claim_key": key, "fleet": fleet}, timeout)
    answer = {"status": status, "token": None, "renews": None, "error": None, "says": None}
    if status == 0:
        return dict(answer, says="the claim got no answer from the release channel: " + text)
    try:
        raw = json.loads(text)
    except (ValueError, RecursionError):        # RecursionError: JSON nested deeper than Python's stack takes
        raw = None
    raw = raw if isinstance(raw, dict) else {}
    fresh, renews, error, says = raw.get("token"), raw.get("renews"), raw.get("error"), raw.get("says")
    if status == 200 and isinstance(fresh, str) and TOKEN.fullmatch(fresh):
        return dict(answer, token=fresh, renews=renews if isinstance(renews, bool) else None)
    if status != 200 and isinstance(error, str) and error in CLAIM_ERRORS:
        line = " ".join(says.split()) if isinstance(says, str) else ""
        line = line if len(line) <= SAYS_MOST else line[:SAYS_MOST - 1] + "\u2026"
        return dict(answer, error=error, says=line or f"the claim got {status} ({error}) from the release channel")
    return dict(answer, says=f"the claim got {status} from the release channel")

# ---------------------------------------------------------------- GET /releases/latest

def _fetch(url, token=None, timeout=CHANNEL_TIMEOUT):
    """(status, body, headers). status 0 and the reason in the body when the channel did not answer. The
    entitlement goes as a bearer when this fleet holds one, and nothing else of this fleet goes with it; a fleet with
    none sends no Authorization header.

    The bearer goes to the channel's own address only, never to the address of a redirect: urllib copies each header
    of a request into the request that follows a redirect, so until 22 November 2026 a channel that answered 302 sent
    the licence to wherever it pointed. The release still follows a redirect, without the bearer, because the
    channel answers every fleet with no token and the signature is the whole trust of a release: a fleet that holds
    a token keeps its releases if the channel ever moves to another address."""
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "founderizer-hub"})
    if token:
        request.add_unredirected_header("Authorization", "Bearer " + token)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as answer:
            return answer.status, answer.read(65536).decode("utf-8", "replace"), dict(answer.headers)
    except urllib.error.HTTPError as answer:
        with answer:
            return answer.code, answer.read(65536).decode("utf-8", "replace"), dict(answer.headers)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, str(getattr(e, "reason", e))[:300], {}


def latest(channel, keys, token=None, *, fetch=_fetch, timeout=CHANNEL_TIMEOUT, revision=None, early=False):
    """Poll the release channel once.

    Returns {"status", "manifest", "says", "entitlement"}: the manifest when one verified, else None with the one
    line that says why. `entitlement` is a fresh token the channel sent along, kept whatever the manifest did
    (4.5: "Near expiry the hub asks for a fresh one with the old one"). It never raises.

    With `revision` it asks for that one release, `GET /releases/<revision>`: the release that a newer one names as
    its minimum (hub.poll_release). A manifest of any other revision is not taken.

    With `early` it asks for the early track (`?track=early`), whose releases the early key signs as they are
    published; `keys` must then hold the early keys too, or every early release is refused."""
    url = (channel or DEFAULT_CHANNEL).rstrip("/") + "/releases/" + (revision or "latest") + ("?track=early" if early else "")
    status, body, _headers = fetch(url, token, timeout)
    if status == 0:
        return {"status": 0, "manifest": None, "entitlement": None, "says": "the release channel did not answer: " + body}
    if status in (401, 403):        # the channel asks for no account: only an older channel or a filter answers so
        return {"status": status, "manifest": None, "entitlement": None,
                "says": f"the release channel refused this fleet ({status})"}
    if status != 200:
        return {"status": status, "manifest": None, "entitlement": None,
                "says": f"the release channel answered {status}"}
    try:
        raw = json.loads(body)
    except (ValueError, RecursionError):        # RecursionError: JSON nested deeper than Python's stack takes
        return {"status": status, "manifest": None, "entitlement": None,
                "says": "the release channel did not answer with JSON"}
    fresh = raw.get("entitlement") if isinstance(raw, dict) else None
    fresh = fresh if isinstance(fresh, str) and TOKEN.fullmatch(fresh) else None
    try:
        manifest = check(raw, keys)
    except Untrusted as e:
        return {"status": status, "manifest": None, "entitlement": fresh, "says": str(e)}
    if revision and manifest["revision"] != revision:
        return {"status": status, "manifest": None, "entitlement": fresh,
                "says": f"the release channel answered with another release than {revision[:12]}"}
    return {"status": status, "manifest": manifest, "entitlement": fresh, "says": None}


# ---------------------------------------------------------------- the update

TIMED_OUT = "ended at the hub's time limit of"    # the words of _run for a step that its limit ended (timed_out)


def _run(argv, timeout=GIT_WAIT, cwd=None, input=None, env=None):
    """One command, with `input` as its standard input when given, and `env` added to this process's environment. It
    never raises: a step that cannot run is a step that failed, with its reason.

    The command runs in a process group of its own, and at its `timeout` the whole group is ended, not only the
    command: a git fetch or `ls-remote` leaves git-remote-https behind it, and a check run under the scope's shell
    (SCOPE_SCRIPT) leaves the check, and either would hold the step's output open, and so the step, past its limit.
    Such a step says TIMED_OUT, which `timed_out` reads, and which no program's own words say (a check's own
    "timed out after 30 seconds" is the check's answer)."""
    try:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                                env=dict(os.environ, **env) if env else None, start_new_session=True)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)[:300]
    try:
        out, err = proc.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass                    # a process that left the group holds the output: the step ends all the same
        return 1, "", f"{os.path.basename(str(argv[0]))} {TIMED_OUT} {timeout} seconds"
    return proc.returncode, (out or "").strip(), (err or "").strip()


def timed_out(err):
    """True when `_run` ended the step at its own limit: its whole words, and no other."""
    return re.fullmatch(r"\S+ " + re.escape(TIMED_OUT) + r" [0-9.]+ seconds", str(err or "")) is not None


def _line(text):
    return " ".join(str(text or "").split())[:400]


def _ended(code, out, err):
    """What a check of a release said, for the owner's line: its own words; and when the system ended it with a signal,
    that first, in plain words, and then the end of what it printed on its standard output, where it stopped (a
    self-test that is ended part way prints a line for each check that passed there; a warning on its error output
    would hide that). Until 19 November 2026 such a line said only "no output". SIGKILL
    is what the kernel sends when memory runs out: the case of a small server whose compile of a release takes more
    memory than it has free."""
    if not isinstance(code, int) or code >= 0:
        return _line(err or out) or "no output"
    try:
        name = signal.Signals(-code).name
    except ValueError:
        name = f"signal {-code}"
    ended = "the system ended it" + (", for example for lack of memory" if -code == signal.SIGKILL else "") + \
        f" ({name})"
    tail = " ".join(str(out or err or "").split())[-120:]   # its progress, not a warning; short: _said cuts at 400
    return f"{ended}; the end of what it printed: {tail}" if tail else ended


def ipv4_default_route(path="/proc/net/route"):
    """True when this machine has an IPv4 default route that is up, False when it has none, None when that cannot be
    read (a machine with no /proc, such as a Mac). The kernel's own table, which `ip -4 route show default` reads too
    and which needs no root: a row whose destination and mask are 00000000 and whose flags carry RTF_UP (1)."""
    try:
        with open(path) as table:
            rows = [line.split() for line in table.read().splitlines()[1:]]
    except OSError:
        return None
    try:
        return any(len(row) >= 8 and row[1] == "00000000" and row[7] == "00000000" and int(row[3], 16) & 1
                   for row in rows)
    except ValueError:
        return None


def ipv6_address(host):
    """True when `host` has an IPv6 address, False when the resolver answers that it has none, None when the resolver
    gives no answer (it cannot be read)."""
    try:
        return bool(socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM))
    except socket.gaierror as e:
        none = {getattr(socket, name) for name in ("EAI_NONAME", "EAI_NODATA", "EAI_ADDRFAMILY") if hasattr(socket, name)}
        return False if e.errno in none else None
    except (OSError, UnicodeError):
        return None


# git's own words, as curl and ssh write them, for each network cause: read in this order, so that a connection that
# timed out is `timeout` and not `connect`, and a TLS or HTTP failure says that a connection was made.
NETWORK_WORDS = (
    ("dns", r"could not resolve host|could not resolve hostname|name or service not known|temporary failure in name "
            r"resolution|nodename nor servname"),
    ("tls", r"\bssl\b|\btls\b|certificate|gnutls|openssl"),
    ("timeout", r"timed out|\btimeout\b|hub's time limit"),
    ("connect", r"failed to connect|could(?:n't| not) connect|connection refused|network is unreachable|no route to "
                r"host|connection reset|connect to host"),
    ("http", r"the requested url returned error|\bhttp/\d|rpc failed|remote end hung up|early eof|unexpected "
             r"disconnect"),
)


def network_cause(err, host, route=None, ipv6=None):
    """The network cause of a git step that failed, from git's own words `err`, or None when they name none.

    A connection that failed or timed out is `no_ipv4_route` when the machine says so at that moment: `host` has no
    IPv6 address, and this server has no IPv4 default route. That was the owner's test hub from 15 to 21 November
    2026: its server lost its IPv4 route, and github.com answers over IPv4 only. A reading that cannot be made (no
    /proc, a resolver that does not answer) leaves git's own word."""
    text = str(err or "").lower()
    cause = next((name for name, words in NETWORK_WORDS if re.search(words, text)), None)
    if cause in ("connect", "timeout") and host and (route or ipv4_default_route)() is False \
            and (ipv6 or ipv6_address)(host) is False:
        return "no_ipv4_route"
    return cause


def room_cause(code, *texts):
    """`memory` when the system ended the step with SIGKILL, as the kernel does when memory runs out (`_ended` says
    it too), or when the check's scope says that the system ended one of its processes for lack of memory (OOM_MARK);
    `disk` when its words say that the disk is full; else None."""
    said = " ".join(str(text or "") for text in texts)
    if isinstance(code, int) and code == -signal.SIGKILL or OOM_MARK in said:
        return MEMORY
    said = said.lower()
    if re.search(r"no space left on device|disk quota exceeded|database or disk is full", said):
        return DISK
    return None


def check_cause(code, out, err, said="check"):
    """The cause of a check of a release that did not pass: the room's (room_cause) when the system ended it or one of
    its processes, or the disk was full; none when `_run` ended it at its own limit, which says nothing of the release
    and nothing that can be read of the machine; else `said`, the check said no."""
    return room_cause(code, err, out) or (None if timed_out(err) else said)


def _host(url):
    """The host of a git address, `https://github.com/…` or `git@github.com:…`, or None for a path."""
    found = re.match(r"[a-z][a-z0-9+.-]*://(?:[^@/]*@)?([^/:?#]+)", url or "", re.I) or \
        re.match(r"[^@/:]+@([^/:]+):", url or "")
    return found.group(1).lower() if found else None


def _said(text):
    """One line the owner reads on the app's Updates page, so it starts with a capital (the owner, 19 October 2026).
    A line that starts with a name this fleet itself uses keeps it: a revision, a branch or a version."""
    line = _line(text)
    head = line.split(" ", 1)[0]
    if head[:1].islower() and head.isalpha() and not re.fullmatch(r"[0-9a-f]{7,}", head):
        return line[0].upper() + line[1:]
    return line


def selftest_summary(out):
    """(passed, of, everything it failed, the failures that are not in the baseline) from selftest.py's own last
    line, or None when it printed no summary. The baseline is COORDINATION.md rule 5, read from verify.py so that
    the release check and `fleet.py verify` cannot drift apart about what a pass is."""
    from verify import SELFTEST_BASELINE
    for line in reversed([one for one in (out or "").split("\n") if one.strip()]):
        found = re.search(r"(\d+) of (\d+) checks passed\.(?:\s*FAILED:\s*(\[.*\]))?\s*$", line)
        if not found:
            continue
        failed = re.findall(r"'([^']*)'", found.group(3) or "")
        return (int(found.group(1)), int(found.group(2)), failed,
                [n for n in failed if n not in SELFTEST_BASELINE])
    return None


def schema_summary(out):
    """(how many steps the database refused, the lines that say which) from `hub.py --check-schema`'s own last
    line, or None when it printed none. The released code writes that line; `hub.check_schema` is the other half
    of this contract and says so."""
    lines = [one.strip() for one in (out or "").split("\n") if one.strip()]
    for line in reversed(lines):
        found = re.search(r"schema check: (\d+) steps? refused\.$", line)
        if found:
            return int(found.group(1)), [one[len("refused: "):] for one in lines if one.startswith("refused: ")]
    return None


# The fleet's own data, which a release never moves: `lifecycle.data_path`, the owner's files that the hub writes
# (`lifecycle.CONFIG_FILES`: team.json, profiles, knowledge and skills) and the files of a task's output. The published
# repository carries a `team.json`, profiles and a `knowledge/services.md` of its own, and a customer's fleet carries
# theirs, so without this a release would replace the fleet it was meant to update. An install still seeds them, the
# way it seeds the manager's profile; only an update leaves them alone. Every other path is the release's own, byte
# for byte (Update.merge), which is what lets each machine prove what it takes (`lifecycle.may_take`).


# What an update run says about itself. The app shows the state and the line; nothing else reads them.
KEPT, ROLLED_BACK, DONE, FAILED = "kept", "rolled_back", "done", "failed"
STATES = (KEPT, ROLLED_BACK, DONE, FAILED)
# `room` is the hub's own step before a run (hub.release_work): the machine had too little memory for the checks.
STEPS = ("room", "hold", "branch", "clean", "pinned", "fetch", "have", "already", "minimum", "clone", "merge", "keep",
         "schema", "selftest", "verify", "take", "push", "follow")

# **The cause of a run that did not end done** (the reliability plan of 21 November 2026, 3.2): one code of this fixed
# list, read from git's own words and the machine's state at that moment, or None when nothing says which, never a
# guess. The hub keeps it in the release's row and acts on its kind (hub.release_work): a network cause rests not at
# all, and the hub probes the published repository at each poll until it answers (reaches); a lack of room rests the
# rest of the day; a release that did not pass rests as before; the fleet's own causes are as before.
MEMORY, DISK = "memory", "disk"
KINDS = {"network": ("no_ipv4_route", "dns", "connect", "tls", "http", "timeout"), "room": (MEMORY, DISK),
         "release": ("conflict", "check"), "fleet": ("busy", "hold", "branch", "own_changes")}
CAUSES = tuple(cause for causes in KINDS.values() for cause in causes)


def kind(cause):
    """`network`, `room`, `release` or `fleet` for a cause of CAUSES, else None."""
    return next((name for name, causes in KINDS.items() if cause in causes), None)


# **What a release's checks need** (W2 of that plan). The peak of the memory that the self-test of a release took,
# summed over its own process and the hubs it starts, was 497 MiB and 444 MiB in two runs on the owner's Mac on 21
# November 2026 (macOS 27, Python 3.12, the code of commit 89eb5eddd, 214 of 214 checks passed in 47 s and 42 s): the
# code exported into a folder of its own, its hub.py compiled in pieces first (`python3 -B -m hubpieces`), as a
# release's run does, then `python3 selftest.py` there, with `ps -axo pid=,ppid=,rss=` read every 0.1 s and the RSS of
# the process tree summed. `fleet.py verify --no-selftest --json` took 118 MiB, and the schema check is one hub. A
# sum of RSS counts the pages that processes share once for each of them, so it is above what a Linux memory cgroup
# counts. With a fifth more for a release that grows, CHECK_NEED: a hub whose server has less free memory and swap
# than this starts no run (hub.release_work), and records `memory` as the cause.
CHECK_NEED = 600 * 2 ** 20
PROBE_WAIT = 20             # seconds for `git ls-remote` of the published repository (reaches)
_SCOPE = {}                 # the memory scope that this machine gives, read once (check_prefix)


def memory_room(path="/proc/meminfo"):
    """{free, ram, swap, total, ram_total} in bytes from /proc/meminfo: the memory that can be given now with free swap
    (MemAvailable + SwapFree), the memory that can be given now without swapping anything out (MemAvailable), the free
    swap (SwapFree), all of it (MemTotal + SwapTotal), and the server's memory (MemTotal). None where it cannot be read
    (no /proc, a kernel with no MemAvailable)."""
    try:
        with open(path) as info:
            fields = {line.split(":")[0]: int(line.split()[1]) * 1024 for line in info if line.count(":") == 1
                      and len(line.split()) >= 2 and line.split()[1].isdigit()}
    except (OSError, ValueError):
        return None
    if "MemAvailable" not in fields or "MemTotal" not in fields:
        return None
    return {"free": fields["MemAvailable"] + fields.get("SwapFree", 0), "ram": fields["MemAvailable"],
            "swap": fields.get("SwapFree", 0), "total": fields["MemTotal"] + fields.get("SwapTotal", 0),
            "ram_total": fields["MemTotal"]}


# The shell that each check runs under inside its scope. It runs the check, then reads `oom_kill` in the scope's own
# memory.events, which a fresh scope starts at 0: where systemd cannot end the whole scope when the system ends one
# of its processes (OOMPolicy, systemd before 253), a hub that the self-test starts can be the one that is ended,
# and the self-test then fails as if the release were at fault. A count above 0 adds OOM_MARK to the check's error
# output (room_cause reads it). A check that a signal ended ends this shell with the same signal, so that _ended and
# room_cause read it as before.
OOM_MARK = "founderizer-oom-kill"
SCOPE_SCRIPT = ('"$@"; s=$?; k=$(sed -n "s/^oom_kill //p" "/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup '
                '2>/dev/null)/memory.events" 2>/dev/null); if [ "${k:-0}" -gt 0 ] 2>/dev/null; then echo '
                '"' + OOM_MARK + ': the system ended $k process(es) of this check for lack of memory" >&2; fi; '
                'if [ "$s" -gt 128 ]; then kill -$((s - 128)) $$ 2>/dev/null; fi; exit "$s"')


def check_prefix(room=None, run=_run, which=shutil.which):
    """(the words that each check of a release runs under, a sentence when they hold no memory limit, else None).

    The checks run at the lowest CPU priority (`nice -n 19`) and at the lowest disk priority of the best-effort class
    where `ionice` is there (`-c 2 -n 7`; the idle class could starve a check behind the hub's own steady writes), and,
    where systemd's user manager gives it to this user, in a scope of their own with a memory limit and a bounded swap.
    So a check that does not fit ends in seconds with SIGKILL (`memory`), and not after 300 s in which the server swaps
    and the hub answers nothing (15 November 2026). The limit is the memory free now without swap (`ram`), and
    CHECK_NEED where that is less. The swap is the free swap, and half of CHECK_NEED at most: the need was measured as
    a sum of RSS on a Mac and never on Linux, and a check of a server with 1 GB that passed slowly with some swap must
    not fail at every release. The scope ends whole when the system ends one of its processes, where systemd can say
    so (OOMPolicy=kill), so that the check's own process reads SIGKILL too; where it cannot, SCOPE_SCRIPT reads the
    scope's own count of such ends.

    Whether a scope can be made is read once for each process, by a scope that prints its own limit: a machine with
    no systemd, no user manager, or no memory controller for this user gives none, and the checks then run under nice
    and ionice alone."""
    words = ["nice", "-n", "19"] if which("nice") else []
    words += ["ionice", "-c", "2", "-n", "7"] if which("ionice") else []
    if "scope" not in _SCOPE:
        _SCOPE["scope"], _SCOPE["says"] = None, "no systemd-run on this machine"
        for extra in (["-p", "OOMPolicy=kill"], []) if which("systemd-run") else ():
            code, out, err = run(["systemd-run", "--user", "--scope", "--quiet", "--collect", "-p",
                                  "MemoryMax=536870912", "-p", "MemorySwapMax=0", *extra, "--", "sh", "-c",
                                  'cat "/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)/memory.max"'], timeout=30)
            if code == 0 and out.strip().isdigit():
                _SCOPE["scope"], _SCOPE["says"] = extra, None
                break
            _SCOPE["says"] = _line(err or out) or f"systemd-run ended with {code}"
    if _SCOPE["scope"] is None:
        return words, (f"The checks of a release run with no memory limit, because this machine gives no scope "
                       f"with one: {_SCOPE['says']}.")
    limit = max(CHECK_NEED, (room or {}).get("ram") or 0)
    swap = min((room or {}).get("swap") or 0, CHECK_NEED // 2)
    return ["systemd-run", "--user", "--scope", "--quiet", "--collect", "-p", f"MemoryMax={limit}", "-p",
            f"MemorySwapMax={swap}", *_SCOPE["scope"], "--", "sh", "-c", SCOPE_SCRIPT, "founderizer-check",
            *words], None


def reaches(kit, url, run=_run):
    """True when the published repository answers now: `git ls-remote` of it, PROBE_WAIT seconds at most, with no
    prompt (GIT_TERMINAL_PROMPT=0, no standard input). It reads the address the fetch reads, with the checkout's own
    configuration, and changes nothing: ls-remote writes no object and no ref. `_run` starts it in a process group of
    its own and ends the whole group at PROBE_WAIT, so git-remote-https cannot hold the probe past it."""
    code, _, _ = run(["git", "-C", kit, "ls-remote", "-q", url, "HEAD"], timeout=PROBE_WAIT,
                     env={"GIT_TERMINAL_PROMPT": "0"})
    return code == 0


# ---------------------------------------------------------------- the second route of a release's code (W12)

# **A second route for a release's code** (the reliability plan of 21 November 2026, 3.2 and W12). The owner's test
# hub lost its IPv4 route for six days, and github.com, its only upstream, answers over IPv4 only; the channel's host
# answers over IPv4 and IPv6. So the publisher makes one git bundle of the published repository at each release
# (autopublish.make_bundle), and it is served at one fixed address of the channel (BUNDLE_PATH, step 2 of W12). A hub
# whose fetch failed for the network, while the probe of the published repository fails too, takes the release's
# commit from that file (take_bundle, hub.release_bundle_work). The file needs no trust: the signed manifest names
# the commit, a commit id is the hash of its content, the hub fetches that one commit by its id, and the run refuses a
# checkout that does not hold it (Update.before, the step `have`). Until step 2 the channel answers 404 there, and the
# row stays as the network left it.
BUNDLE_PATH = "/releases/latest.bundle"
# The file is a bundle of the whole published main, about 6 to 29 MiB on 22 November 2026 (autopublish.BUNDLE says
# how that was measured), and it grows by about 13 KiB for each release: BUNDLE_MOST leaves room for more than a year.
BUNDLE_MOST = 256 << 20     # bytes: a larger file is refused, before its first byte when it says its length
BUNDLE_WAIT = 300           # seconds for the whole download; the hub's probe thread waits for it, and holds nothing
BUNDLE_READ = 30            # seconds that one read of it waits at most, so that the download ends near BUNDLE_WAIT
BUNDLE_REF = "refs/founderizer/bundle"      # where the hub's checkout keeps the commit that it took from the file
BUNDLE_HEADS = (b"# v2 git bundle\n", b"# v3 git bundle\n")      # the first line of a git bundle, and of nothing else


def bundle_address(channel):
    """The one address of the release file on the release channel `channel`."""
    return (channel or DEFAULT_CHANNEL).rstrip("/") + BUNDLE_PATH


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The file is at one fixed address of the channel: a redirect is an answer that is not the file."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download(url, path, *, most=BUNDLE_MOST, wait=BUNDLE_WAIT, read_wait=BUNDLE_READ, opener=None,
             clock=time.monotonic):
    """The file at `url` into `path`: None when it is there whole, else the one line that says why, and then no file
    is left at `path`. It never raises.

    Over HTTPS only, with no proxy and no redirect, and inside two limits. `most` bytes: a Content-Length above it is
    refused before a byte is read, and a body that grows past it is cut and refused. `wait` seconds: each read is one
    `read1`, which gives what the next receive brings, up to 64 KiB, and waits `read_wait` seconds at most for it (the
    socket's timeout); the clock, which starts before the connection, is read again before each read, so a server
    that sends a byte of the body now and then ends the download `wait` + `read_wait` seconds after it began. Before
    the body, the connection, the TLS handshake and the headers wait `read_wait` seconds at most for each receive,
    and nothing limits them as a whole; the name lookup is the system's own, with the resolver's limits."""
    if not str(url).lower().startswith("https://"):
        return f"the address of the release file is not an https address: {str(url)[:100]}"
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    deadline, got, why = clock() + wait, 0, None
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "founderizer-hub"})
        with opener.open(request, timeout=min(read_wait, wait)) as answer, open(path, "wb") as out:
            length = str(answer.headers.get("Content-Length") or "").strip()
            if length.isdigit() and int(length) > most:
                why = f"the release file is {length} bytes, more than the {most} that this hub takes"
            while why is None:
                if clock() > deadline:
                    why = f"the release file did not come whole in {wait} seconds"
                    break
                chunk = answer.read1(1 << 16)       # what one receive brings: read() waits for all 64 KiB
                if not chunk:
                    break
                got += len(chunk)
                if got > most:
                    why = f"the release file is more than the {most} bytes that this hub takes"
                    break
                out.write(chunk)
            if why is None and length.isdigit() and got != int(length):
                why = f"the release file came with {got} of its {length} bytes"
    except urllib.error.HTTPError as answer:
        with contextlib.suppress(Exception):
            answer.close()
        why = f"the release channel answered {answer.code} for the release file"
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
        why = "the release file could not be downloaded: " + _line(getattr(e, "reason", None) or e)[:200]
    if why is not None:
        with contextlib.suppress(OSError):
            os.remove(path)
    return why


def take_bundle(kit, channel, revision, *, run=None, fetch=None):
    """The second route: the release file of the channel `channel` (download), and from it the one commit `revision`,
    by its id, into the checkout `kit` at BUNDLE_REF. None when `kit` holds that commit now, else the one line that
    says why, and then nothing of the file reaches `kit`.

    Everything of the file stays in a folder of its own, which is gone when this returns. A file whose first line is
    not a git bundle's (BUNDLE_HEADS) is refused before git reads it: git reads a file that says `gitdir: <path>` as
    a pointer to another repository of this machine. git then unpacks the file into a bare repository of that folder,
    never into `kit`, and asks it for that one commit, with no tag: a file that does not hold it fails there ("bad
    object"), as does a file of a range whose start that repository lacks. Only then does `kit` fetch BUNDLE_REF from
    that repository, which sends the objects that `kit` lacks and nothing else, and checks that they are whole: a
    file filtered of its blobs (`--filter`) gives a commit that cannot be sent whole, and fails there. `kit` then holds
    that commit, which `cat-file` reads again, as the run reads it at its step `have`."""
    run, fetch = run or _run, fetch or download
    if not REVISION.fullmatch(str(revision or "")):
        return "the release names no full commit id"
    folder = tempfile.mkdtemp(prefix="founderizer-bundle-")
    try:
        path, own = os.path.join(folder, "release.bundle"), os.path.join(folder, "taken.git")
        why = fetch(bundle_address(channel), path)
        if why:
            return why
        try:
            with open(path, "rb") as file:
                first = file.readline(64)
        except OSError as e:
            return f"the release file could not be read: {_line(e)}"
        if first not in BUNDLE_HEADS:
            return "the release file is not a git bundle"
        quiet = {"GIT_TERMINAL_PROMPT": "0"}
        code, _, err = run(["git", "init", "-q", "--bare", own], timeout=60, env=quiet)
        if code != 0:
            return f"no repository could be made for the release file: {_line(err)[-200:] or 'git said nothing'}"
        for into, source, wanted in ((own, path, revision), (kit, own, BUNDLE_REF)):
            code, _, err = run(["git", "-C", into, "fetch", "-q", "--no-write-fetch-head", "--no-tags", source,
                                f"+{wanted}:{BUNDLE_REF}"], timeout=GIT_WAIT, env=quiet)
            if code != 0:
                said = _line(str(err or "").replace(path, "the file").replace(own, "its repository"))[-200:]
                return f"the release file does not give release {revision[:12]}: {said or 'git said nothing'}"
        if run(["git", "-C", kit, "cat-file", "-e", revision + "^{commit}"], timeout=60)[0] != 0:
            return f"this checkout does not hold release {revision[:12]} after the fetch from the release file"
        return None
    finally:
        shutil.rmtree(folder, ignore_errors=True)


class Update:
    """One update run of one fleet.

    The hub's own checkout is read until the last step: the merge and all three checks happen in a temporary
    clone of it, and the merge reaches the configuration ref only when the schema check, `selftest.py` and
    `fleet.py verify` have all passed in that clone. So `pinned` is the revision the fleet keeps, not a revision
    it returns to, and a failure leaves the checkout, the ref and every machine exactly as they were.

    `origin` is the address the configuration ref is pushed to, as the hub pushes the owner's own commits. With no
    origin the run stops before the push and says so, which is what a test of the merge and the checks wants.

    `database` is a copy of this fleet's own database, which the released code's schema is run against inside the
    clone before anything moves (the `schema` check). Without one that check is skipped, which is what a test of
    the merge wants and what a hub with no records to risk would get anyway.

    `floor` is the hub user's release floor (`lifecycle.floor_path`): the run checks what it would push with the
    same `lifecycle.may_take` that every machine runs before it moves, and the hub's checkout follows under it.

    `pushed` is called with the revision the moment the push has landed, before this checkout follows it: from then
    on every machine of this fleet takes the release at its next sync, so the hub records it at once, and a run that
    an error or a stop of the hub cuts off before its answer still asks each machine for its idle update. An error
    in it is printed and stops nothing.

    `own` is called with a tip that the ref moved to under the push: true for a write of the hub's own whose push
    landed while the rest of it never ran (hub.KIT_PUSHED). The run does not merge onto that tip, which the hub
    takes back; it ends rolled back at the push, and the next run takes the release.

    `limit` is the words that each of the four checks runs under (check_prefix): its priority and its memory scope.

    `bundled` is true for a run whose release commit the second route took already, from the release file of the
    channel, while the published repository did not answer (take_bundle, hub.release_bundle_work): the run then
    fetches nothing from the network, and the step `have` still refuses a checkout that does not hold that commit.

    Each answer carries `cause`: one code of CAUSES for a run that did not end done, read from git's words, the
    signal that ended a check and the machine's state, or None where nothing says which."""

    def __init__(self, kit, manifest, *, origin=None, upstream=None, branch=None, remote=REMOTE,
                 run=_run, python=None, database=None, selftest_wait=SELFTEST_WAIT, verify_wait=VERIFY_WAIT,
                 schema_wait=SCHEMA_WAIT, floor=None, pushed=None, own=None, limit=(), bundled=False):
        from lifecycle import CONFIG_BRANCH
        self.kit, self.manifest, self.origin, self.upstream = kit, manifest, origin, upstream
        self.branch, self.remote, self.run, self.database = branch or CONFIG_BRANCH, remote, run, database
        self.floor, self.pushed, self.own, self.limit = floor, pushed, own, list(limit or ())
        self.bundled = bool(bundled)
        self.python = python or sys.executable
        self.selftest_wait, self.verify_wait, self.schema_wait = selftest_wait, verify_wait, schema_wait
        # pinned: the revision this fleet runs and keeps. reached: the revision that got onto the configuration
        # ref, which only a run that published one has.
        self.pinned, self.reached, self.clone = None, None, None

    # ---- the readings

    def git(self, *args, cwd=None, timeout=GIT_WAIT):
        return self.run(["git", "-C", cwd or self.kit, *args], timeout=timeout)

    def answer(self, state, step, says, cause=None):
        return {"state": state, "step": step, "says": _said(says), "pinned": self.pinned, "reached": self.reached,
                "revision": self.manifest["revision"], "version": self.manifest["version"],
                "cause": cause if state != DONE and cause in CAUSES else None}

    def check_run(self, argv, timeout):
        """One of the four checks, under `limit`, in the clone."""
        return self.run([*self.limit, *argv], timeout=timeout, cwd=self.clone)

    # ---- the run

    def apply(self):
        """Do the update. One of KEPT (nothing was touched), ROLLED_BACK (the merge or a check failed and the fleet
        keeps the pinned revision), DONE, or FAILED (the ref moved and this hub did not follow it: the one state a
        person must look at)."""
        ready = self.before()
        if ready:
            return ready
        folder = tempfile.mkdtemp(prefix="founderizer-release-")
        self.clone = os.path.join(folder, "kit")
        try:
            return self.in_clone()
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def before(self):
        """Everything that is read before a single object is written: the answer when the run stops here."""
        manifest = self.manifest
        if manifest["hold"]:
            return self.answer(KEPT, "hold", f"release {manifest['version']} is held: no fleet takes it", "hold")
        code, branch, _ = self.git("symbolic-ref", "--short", "--quiet", "HEAD", timeout=60)
        if code != 0 or branch != self.branch:
            return self.answer(KEPT, "branch", f"this checkout is on {branch or 'no branch'}, not the configuration "
                                               f"ref {self.branch}, so a release cannot be merged into it", "branch")
        if self.git("status", "--porcelain", "--untracked-files=no", timeout=60)[1]:
            return self.answer(KEPT, "clean", "this checkout has its own changes; nothing is merged over them",
                               "own_changes")
        code, head, _ = self.git("rev-parse", "HEAD", timeout=60)
        if code != 0 or not REVISION.fullmatch(head):
            return self.answer(KEPT, "pinned", "this checkout has no revision to pin")
        self.pinned = head
        answer = self.fetch()
        if answer:
            return answer
        if self.git("cat-file", "-e", manifest["revision"] + "^{commit}", timeout=60)[0] != 0:
            return self.answer(KEPT, "have", f"the released revision {manifest['revision'][:12]} is not in "
                                             f"{self.remote} after the fetch")
        if self.git("merge-base", "--is-ancestor", manifest["revision"], head, timeout=60)[0] == 0:
            return self.answer(KEPT, "already", f"this fleet already runs release {manifest['version']}")
        least = manifest["minimum"]
        if least and self.git("merge-base", "--is-ancestor", least, head, timeout=60)[0] != 0:
            return self.answer(KEPT, "minimum", f"release {manifest['version']} needs a fleet at {least[:12]} or "
                                                f"later; this one is at {head[:12]}")
        return None

    def fetch(self):
        """`git fetch upstream`, with the remote added when the repository does not carry it yet. A `bundled` run
        fetches nothing."""
        code, url, _ = self.git("remote", "get-url", self.remote, timeout=60)
        if code != 0:
            if not self.upstream:
                return self.answer(KEPT, "fetch", f"this checkout has no remote {self.remote} and no address was "
                                                  f"configured for it")
            code, _, err = self.git("remote", "add", self.remote, self.upstream, timeout=60)
            if code != 0:
                return self.answer(KEPT, "fetch", f"the remote {self.remote} could not be added", room_cause(code, err))
        elif self.upstream and url != self.upstream:
            code, _, err = self.git("remote", "set-url", self.remote, self.upstream, timeout=60)
            if code != 0:
                return self.answer(KEPT, "fetch", f"the remote {self.remote} could not be pointed at the published "
                                                  f"repository", room_cause(code, err))
        if self.bundled:
            return None             # the second route holds the commit already: the step `have` reads it
        code, _, err = self.git("fetch", "-q", "--no-write-fetch-head", self.remote)
        if code != 0:
            # First what a person reads in one go, then git's own line: a server with no route to github.com (the
            # owner's test fleet, 21 November 2026) said only "The fetch of upstream failed: fatal: unable to access…".
            where = _host(self.upstream or url)
            return self.answer(KEPT, "fetch", f"This server could not download release {self.manifest['version']} "
                                              f"from {where or 'the published repository'}, so this fleet did not "
                                              f"take it. The fetch of {self.remote} failed: {err[-200:]}",
                               room_cause(code, err) or network_cause(err, where))
        return None

    def in_clone(self):
        """The merge and the three checks, in a clone, then the push and this checkout's own fast-forward."""
        code, _, err = self.run(["git", "clone", "-q", "--shared", self.kit, self.clone])
        if code == 0:
            code, _, err = self.git("checkout", "-q", self.pinned, cwd=self.clone, timeout=60)
        if code != 0:
            return self.answer(ROLLED_BACK, "clone", f"the update could not be prepared: {err[-200:]}",
                               room_cause(code, err))
        answer = self.merge()
        if answer:
            return answer
        code, merged, _ = self.git("rev-parse", "HEAD", cwd=self.clone, timeout=60)
        if code != 0 or not REVISION.fullmatch(merged):
            return self.answer(ROLLED_BACK, "merge", "the merge left no commit")
        answer = self.checks() or self.take(self.pinned, merged)
        if answer:
            return answer
        return self.publish(merged)

    def clone_git(self, *args, timeout=60):
        return self.git(*args, cwd=self.clone, timeout=timeout)

    def merge(self, base=None):
        """The release onto this fleet's configuration ref, in the clone: one commit whose parents are `base` and the
        released revision, and whose tree is the release's own outside the fleet's data, the data as `base` has it,
        and the signed manifest as `release.json` (lifecycle.RELEASE_FILE).

        The data is configuration, not code (`lifecycle.data_path`). The published repository carries a `team.json`,
        profiles and owner knowledge of its own, and the fleet being updated carries the owner's: taking ours would
        replace the team, the agents and their instructions with a stranger's. Every other path is the release's own,
        byte for byte, so a line of code that reached the ref without a release does not survive one, and every
        machine can prove what it takes: `lifecycle.may_take` finds the signed manifest and that revision's own
        tree. So there is nothing to conflict, and a release fits every fleet.

        `base` is the commit the release goes onto: the pinned revision, or the configuration ref's own new tip when
        the ref moved under the push and this run follows it (`catch_up`)."""
        import lifecycle
        base = base or self.pinned
        version, revision = self.manifest["version"], self.manifest["revision"]
        author = ["-c", "user.name=Founderizer", "-c", "user.email=releases@founderizer.invalid"]
        entries = []
        for rev, data in ((revision, False), (base, True)):
            code, out, err = self.clone_git("ls-tree", "-r", "-z", "--full-tree", rev)
            if code != 0:
                return self.answer(ROLLED_BACK, "merge", f"release {version} could not be read: {_line(err)}. The "
                                                         f"fleet stays at {self.pinned[:12]}.", room_cause(code, err))
            for line in out.split("\0"):
                path = line.partition("\t")[2]
                if path and path != lifecycle.RELEASE_FILE and lifecycle.data_path(path) == data:
                    entries.append(line)
        for args, given in ((["hash-object", "-w", "--stdin"], self.release_text()), (["read-tree", "--empty"], None)):
            code, out, err = self.run(["git", "-C", self.clone, *args], timeout=60, input=given)
            if code != 0:
                return self.answer(ROLLED_BACK, "merge", f"release {version} could not be put together: "
                                                         f"{_line(err or out)}. The fleet stays at {self.pinned[:12]}.",
                                   room_cause(code, err, out))
            if given is not None:
                entries.append(f"{lifecycle.DATA_MODE} blob {out}\t{lifecycle.RELEASE_FILE}")
        code, out, err = self.run(["git", "-C", self.clone, "update-index", "-z", "--index-info"], timeout=60,
                                  input="".join(one + "\0" for one in entries))
        tree = self.clone_git("write-tree")[1] if code == 0 else ""
        commit = self.run(["git", "-C", self.clone, *author, "commit-tree", tree, "-p", base, "-p", revision, "-m",
                           f"Take release {version} ({revision[:12]})"], timeout=60)[1] if REVISION.fullmatch(tree) \
            else ""
        reset = self.clone_git("reset", "-q", "--hard", commit) if REVISION.fullmatch(commit) else (1, "", "")
        if reset[0] != 0:
            return self.answer(ROLLED_BACK, "merge", f"release {version} could not be committed onto this fleet: "
                                                     f"{_line(err or out) or 'git made no commit'}. The fleet stays "
                                                     f"at {self.pinned[:12]}.", room_cause(code, err, out, reset[2]))
        code, names, _ = self.clone_git("diff", "--no-renames", "--name-only", "-z", base, "HEAD")
        if code != 0 or any(lifecycle.data_path(one) for one in names.split("\0") if one):
            return self.answer(ROLLED_BACK, "keep", f"release {version} changes this fleet's own configuration, which "
                                                    f"a release never does. The fleet stays at {self.pinned[:12]}.",
                               "conflict" if code == 0 else None)
        return None

    def release_text(self):
        """`release.json`: the signed manifest, field for field as the channel gave it, so that every machine checks
        the very signature this hub checked."""
        return json.dumps({key: self.manifest[key] for key in ("revision", "version", "notes", "minimum", "hold",
                                                                "signature")}, indent=2, sort_keys=True) + "\n"

    def take(self, base, merged):
        """`lifecycle.may_take` on what this run would push, read from the revision it goes onto, under the hub
        user's floor: every machine of this fleet runs that check before it moves, so a commit that the check would
        refuse never reaches the ref, where no machine could take it."""
        import lifecycle
        problem = lifecycle.may_take(self.clone, merged, self.run, self.floor, head=base)
        if problem:
            return self.answer(ROLLED_BACK, "take", f"release {self.manifest['version']} passed every check, and the "
                                                    f"check of each machine refuses it: {_line(problem)}. The fleet "
                                                    f"stays at {self.pinned[:12]}.", "check")
        return None

    def pieces(self):
        """The clone's compiled hub.py, compiled in pieces (hubpieces.py), before the first check that imports hub:
        the schema check, the hubs of selftest.py and fleet.py verify then read that file, where the first of them
        would otherwise compile the whole file, about 270 MB for a moment on a server with 1 GB, against about 85 MB
        in pieces (measured on 20 November 2026). It runs the clone's own hubpieces.py, so each release brings the
        writer of its own hub.py, with -B, so that Python writes no compiled file of the writer itself. Its answer is
        not read, and it stops nothing: when it writes no file (a clone of a release from before it, a process that
        the system ended), the first check compiles the whole file, as before."""
        self.check_run([self.python, "-B", "-m", "hubpieces"], PIECES_WAIT)

    def schema_check(self):
        """The released code's own schema against a copy of this fleet's database, in the clone.

        `selftest.py` starts real hubs, and every one of them on a *fresh* database. So the one thing it cannot
        see is the customer's own rows: a unique index over a table that already holds a duplicate, or a NOT NULL
        column with no default on a table that has rows. Those passed every check there is and then met real data
        for the first time at the restart — which `hub.finish_release` does after the push, when the ref has moved
        and every machine has followed it. This is that meeting, brought forward to where a failure still costs
        nothing: the fleet is kept, exactly as a failed selftest keeps it.

        The copy is a copy of a copy: the hub already hands over a throwaway, and this makes its own inside the
        folder `apply()` deletes, so the released code can only ever open a file this run wrote. That costs the
        database's size in the tempdir for the length of the run, which is the right price for the invariant.

        The released hub runs as a module from the clone (`python3 -m hub`), not by its path. Python then reads the
        compiled hub.py that `pieces` wrote in the clone just before (or, when it wrote none, compiles the whole file
        here and keeps it in the clone's __pycache__), and the hubs that selftest.py starts next in that clone, also
        as a module, read the same file: hub.py is compiled one time in a run, before the first check that imports
        it, and not again beside the self-test and its hubs."""
        if not self.database:
            return None
        version, pinned = self.manifest["version"], self.pinned[:12]
        copy = os.path.join(os.path.dirname(self.clone), "database.sqlite3")
        try:
            shutil.copyfile(self.database, copy)
        except OSError as e:
            return self.answer(ROLLED_BACK, "schema", f"this fleet's database could not be copied for the schema "
                                                      f"check of release {version}: {e}. The fleet stays at {pinned}.",
                               room_cause(None, os.strerror(e.errno) if e.errno else ""))
        code, out, err = self.check_run([self.python, "-m", "hub", "--check-schema", copy], self.schema_wait)
        summary = schema_summary(out)
        if summary is None:
            return self.answer(ROLLED_BACK, "schema", f"release {version} could not read this fleet's database: "
                                                      f"{_ended(code, out, err)}. The fleet stays at "
                                                      f"{pinned}.", check_cause(code, out, err))
        refused, says = summary
        if refused:
            return self.answer(ROLLED_BACK, "schema", f"release {version} needs {refused} schema step(s) that this "
                                                      f"fleet's own records refuse ({_line('; '.join(says[:2]))}). "
                                                      f"The fleet stays at {pinned}.", check_cause(code, out, err))
        if code != 0:
            return self.answer(ROLLED_BACK, "schema", f"the schema check of release {version} ended with {code} "
                                                      f"and named nothing. The fleet stays at {pinned}.",
                               check_cause(code, out, err))
        return None

    def checks(self):
        """The schema against a copy of this fleet's records, then `selftest.py` and `fleet.py verify`, all three
        in the clone, so they read the released code and not this hub's. Any one failing keeps the fleet where it
        is. The schema goes first because it takes a second and selftest.py about a minute."""
        from verify import OWNER_STEPS
        self.pieces()
        answer = self.schema_check()
        if answer:
            return answer
        version, pinned = self.manifest["version"], self.pinned[:12]
        code, out, err = self.check_run([self.python, os.path.join(self.clone, "selftest.py")], self.selftest_wait)
        summary = selftest_summary(out)
        if summary is None:
            return self.answer(ROLLED_BACK, "selftest", f"selftest.py did not answer for release {version}: "
                                                        f"{_ended(code, out, err)}. The fleet stays at "
                                                        f"{pinned}.", check_cause(code, out, err))
        passed, total, failed, new = summary
        if new:
            return self.answer(ROLLED_BACK, "selftest", f"release {version} fails {len(new)} check(s) that the "
                                                        f"baseline does not have ({', '.join(new[:4])}); "
                                                        f"{passed} of {total} passed. The fleet stays at {pinned}.",
                               check_cause(code, out, err))
        if code != 0 and not failed:
            return self.answer(ROLLED_BACK, "selftest", f"selftest.py ended with {code} for release {version} and "
                                                        f"named no failure; {passed} of {total} passed. The fleet "
                                                        f"stays at {pinned}.", check_cause(code, out, err))
        # **Without its own self-test** (verify.WITHOUT): selftest.py has just passed on this clone, and fleet.py verify
        # ran the same file in the same clone a second time. Each run waits for the hub's timers, so that second run
        # was a minute of the two that the owner waited on Updates for every release (14 November 2026: "clicked on
        # Update fleet, seems stuck, not a great ux"). The released fleet.py always knows the option: a release
        # comes after the code that runs this, which already has it.
        code, out, err = self.check_run([self.python, os.path.join(self.clone, "fleet.py"), "verify", "--no-selftest",
                                         "--json"], self.verify_wait)
        try:
            results = json.loads(out)
            # A check the owner alone can pass says nothing about the release (verify.OWNER_STEPS): a fleet that has
            # never been signed in would otherwise be held at its first revision for ever.
            bad = [one["check"] for one in results
                   if one.get("state") == "fail" and one.get("check") not in OWNER_STEPS]
        except (ValueError, TypeError, KeyError):
            return self.answer(ROLLED_BACK, "verify", f"fleet.py verify did not answer for release {version}: "
                                                      f"{_ended(code, out, err)}. The fleet stays at "
                                                      f"{pinned}.", check_cause(code, out, err))
        if bad:
            return self.answer(ROLLED_BACK, "verify", f"release {version} is not healthy: verify failed "
                                                      f"{', '.join(bad)}. The fleet stays at {pinned}.",
                               check_cause(code, out, err, DISK if "disk" in bad else "check"))     # verify's disk check
        return None

    def publish(self, merged):
        """The push to the configuration ref, and this checkout's fast-forward onto it. Nothing before this point
        left the clone.

        **The ref moves under this push.** The hub commits the owner's own files to the same ref
        (`hub.commit_kit_file`) and the checks above take minutes, so a release that passed every one of them
        can reach a tip that is no longer the one it was merged onto, and git refuses the push as a
        non-fast-forward. That is what happened to the owner's own fleet on 19 October 2026, and the release was
        thrown away over it. It is not a verdict on the release: it is two writers of one ref, and the owner's
        files and the released code touch different paths by design. So a refused push is followed, not given
        up: merge the released revision onto the new tip and push that (`catch_up`), up to PUSH_TRIES times.
        What is given up is the fleet whose ref moves faster than a push takes, and the line says so."""
        version = self.manifest["version"]
        if not self.origin:
            return self.answer(ROLLED_BACK, "push", f"release {version} passed every check, and this fleet has no "
                                                    f"address for its configuration ref, so nothing was pushed")
        for left in range(PUSH_TRIES - 1, -1, -1):
            code, _, err = self.run(["git", "-C", self.clone, "push", "-q", self.origin, f"HEAD:{self.branch}"])
            if code == 0:
                break
            # The push is the step that leaves this machine, so what it did is read from the ref and not from
            # git's exit code (RULES.md rule 9). A ref that carries exactly what was pushed means the push landed
            # and something after it failed: the fleet has moved, and saying it was rolled back would be a lie
            # the owner acts on.
            tip = self.ref_now()
            if tip == merged:
                break
            if tip is None or not self.may_follow(tip, merged):
                return self.answer(ROLLED_BACK, "push", f"release {version} passed every check and the push to "
                                                        f"{self.branch} was refused: {_line(err)}. The fleet stays "
                                                        f"at {self.pinned[:12]}.",
                                   room_cause(code, err) or network_cause(err, _host(self.origin)))
            if not left:
                return self.answer(ROLLED_BACK, "push", f"release {version} passed every check, and {self.branch} "
                                                        f"moved under it {PUSH_TRIES} times while it was pushed, "
                                                        f"so the fleet stays at {self.pinned[:12]}. Press Update "
                                                        f"again when this fleet is writing less.", "busy")
            answer, merged = self.catch_up(tip, merged)
            if answer:
                return answer
        self.reached = merged           # it is on the ref now, so every machine of this fleet follows it
        if self.pushed:
            try:
                self.pushed(merged)
            except Exception:           # a record only: the answer carries `reached` too, and the follow must happen
                traceback.print_exc()
        import lifecycle
        # The hub's own checkout moves as every other does: under lifecycle.may_take, with its floor raised after.
        if self.git("fetch", "-q", "origin")[0] != 0 or lifecycle.take(self.kit, merged, self.run, self.floor):
            return self.answer(FAILED, "follow", f"release {version} is on {self.branch} as {merged[:12]}, and this "
                                                 f"hub's own checkout did not move onto it. Bring it up to date by "
                                                 f"hand: git -C {self.kit} merge --ff-only {merged[:12]}, then "
                                                 f"restart the hub's service, which runs the code it started with")
        return self.answer(DONE, "follow", f"release {version} is on {self.branch} as {merged[:12]}; this fleet "
                                           f"moved from {self.pinned[:12]}")

    def ref_now(self):
        """The configuration ref's own tip in the repository this fleet pushes to, or None when it cannot be
        read. The ref is read, never the text git printed: "non-fast-forward" is English from a program whose
        wording is not ours to depend on, and the ref itself says the same thing exactly."""
        if self.run(["git", "-C", self.clone, "fetch", "-q", self.origin, f"+{self.branch}:{MOVED}"])[0] != 0:
            return None
        code, tip, _ = self.clone_git("rev-parse", MOVED)
        return tip if code == 0 and REVISION.fullmatch(tip) else None

    def may_follow(self, tip, merged):
        """Is this tip one that a refused push may be merged onto and pushed again? It must hold the revision
        this fleet runs, and what was just pushed must not already hold it — a ref that is behind this merge did
        not refuse it for moving, and a second merge would meet whatever did. Nor may it be a write of the hub's own
        that the hub takes back (`own`)."""
        return (self.clone_git("merge-base", "--is-ancestor", tip, merged)[0] != 0
                and self.clone_git("merge-base", "--is-ancestor", self.pinned, tip)[0] == 0
                and not (self.own and self.own(tip)))

    def catch_up(self, tip, checked):
        """The released revision merged again, onto the tip the configuration ref moved to, with the proof that
        this is still the code the checks passed. Gives (the answer that ends the run, the revision to push).

        **The checks are not run a second time, and this is the one place where "it passed" and "it is what will
        run" could come apart, so the sameness is proved and not argued.** The second merge is compared with the
        one the checks read: every path that differs must be the fleet's own data (`lifecycle.data_path`). If that
        holds, the tree that will run is the tree `selftest.py`, `fleet.py verify` and the schema check read, file
        for file, and running them again would answer a question already answered while the ref moves once more.

        It holds by construction: a merge takes every other path from the release and the data from its base, so
        what reached the ref meanwhile — the owner's files that `hub.commit_kit_file` writes, a task's output, or
        code that some commit put there by hand — changes nothing the checks read, and code that came without a
        release does not survive this one. The data itself is not re-checked and does not need to be: the fleet
        already runs it, whether this release is taken or not. The comparison stays as the proof, and so does the
        check of each machine (`take`) on the commit that is pushed."""
        version, pinned = self.manifest["version"], self.pinned[:12]
        if self.clone_git("reset", "-q", "--hard", tip)[0] != 0:
            return self.answer(ROLLED_BACK, "push", f"release {version} passed every check, and {self.branch} "
                                                    f"moved to {tip[:12]} while it was pushed, which this update "
                                                    f"could not follow. The fleet stays at {pinned}."), checked
        answer = self.merge(base=tip)
        if answer:
            return answer, checked
        code, again, _ = self.clone_git("rev-parse", "HEAD")
        if code != 0 or not REVISION.fullmatch(again):
            return self.answer(ROLLED_BACK, "merge", "the second merge left no commit"), checked
        code, names, _ = self.clone_git("diff", "--no-renames", "--name-only", checked, again)
        if code != 0:
            return self.answer(ROLLED_BACK, "push", f"release {version} passed every check, and what the second "
                                                    f"merge of it holds could not be read. The fleet stays at "
                                                    f"{pinned}."), checked
        import lifecycle
        changed = sorted(one for one in names.split("\n") if one and not lifecycle.data_path(one))
        if changed:
            return self.answer(ROLLED_BACK, "push", f"release {version} passed every check, and while it was "
                                                    f"pushed {self.branch} gained a commit that changes "
                                                    f"{', '.join(changed[:4])}, which is not this fleet's own "
                                                    f"configuration, so what passed the checks is no longer what "
                                                    f"would run. The fleet stays at {pinned}. Press Update again "
                                                    f"to check the release against it.", "own_changes"), checked
        return self.take(tip, again), again
