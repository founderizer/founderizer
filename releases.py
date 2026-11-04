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

**Two tracks.** A fleet takes from the channel only a release that a key of KEY_FILE signed, which the owner signs
with Touch ID, unless the fleet takes releases early (the hub's setting `releases.early`, the owner's own fleet):
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

**The entitlement is carried, never enforced.** The hub sends it as a bearer to the channel and keeps what comes
back. Nothing here refuses work when it expires; only our side refuses (PRODUCT.md 4.2).

No dependency: a hub is a bare Ubuntu server with python3, git and curl (hub.sh PACKAGES), so the Ed25519
verification below is the reference implementation of RFC 8032 and nothing else.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

# The configuration ref and the baseline of selftest.py belong to other packages; this module reads them and
# changes neither, so the three can never disagree about what "up to date" or "a pass" means. It reads them where it
# uses them and not at the top, so that the check of a release (check and what it calls) imports nothing but the
# standard library: the root-owned copy that a machine's vault program checks a release with is this file alone
# (hubsetup.vault_program_script), and `lifecycle.may_take` imports this module from inside lifecycle.

# Where a release comes from, and where the manifest is asked for. Both are defaults: the hub overrides them from
# its own configuration (hub.releases region), because P7 settles the host of the channel and the address of the
# published repository.
DEFAULT_CHANNEL = "https://founderizer.com"
DEFAULT_UPSTREAM = "https://github.com/miguelpieras/founderizer-fleet.git"
REMOTE = "upstream"                 # PRODUCT.md 4.3: "every hub carries [it] as the git remote `upstream`"
MOVED = "refs/founderizer/moved"    # where the clone keeps the ref's own tip when a push lost to it
KEY_FILE = "release-key.pub"        # the release public keys, shipped in the repository beside this file
EARLY_KEY_FILE = "early-key.pub"    # the keys of the early track, which a fleet that takes releases early trusts too
ENTITLEMENT_KEY_FILE = "entitlement-key.pub"    # the entitlement public keys: another key, and its own file (4.2)

CHANNEL_TIMEOUT = 10        # seconds for GET /releases/latest: a channel that does not answer changes nothing
SELFTEST_WAIT = 300         # seconds for selftest.py, as verify.py gives it
VERIFY_WAIT = 420           # seconds for fleet.py verify, which runs selftest.py again inside itself
SCHEMA_WAIT = 120           # seconds for the released code's schema against a copy of this fleet's database
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
    """True when one of these keys signed `message`. Every key the checkout carries is trusted, so the fleet that
    is a release behind and the fleet that is up to date check the same release, each with a key it has."""
    return any(verify_signature(key, message, signature) for key in trusted(keys))


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
    side refuses (4.2). So an unverifiable token is still kept and still shown; it is marked, not refused."""
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
    machines, agents = claims.get("machines"), claims.get("agents")
    if not (isinstance(fleet, str) and re.fullmatch(r"[0-9a-f]{16}", fleet)):
        raise Untrusted("the entitlement names no fleet")
    if not (isinstance(plan, str) and VERSION.fullmatch(plan)):
        raise Untrusted("the entitlement names no plan")
    if isinstance(until, bool) or not isinstance(until, (int, float)) or not 0 < until < 2 ** 40:
        raise Untrusted("the entitlement has no until date")
    for name, number in (("machines", machines), ("agents", agents)):
        if number is not None and (isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 10000):
            raise Untrusted(f"the entitlement's {name} is not a count")
    return {"fleet": fleet, "plan": plan, "until": float(until), "machines": machines, "agents": agents,
            "verified": signed_by_any(keys, body.encode(), raw_signature)}


def sign_entitlement(secret, claims):
    """The other half of read_entitlement, for our own side and for the tests. Never called on a hub."""
    body = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=")
    return (body + b"." + base64.urlsafe_b64encode(sign(secret, body)).rstrip(b"=")).decode()


# ---------------------------------------------------------------- GET /releases/latest

def _fetch(url, token=None, timeout=CHANNEL_TIMEOUT):
    """(status, body, headers). status 0 and the reason in the body when the channel did not answer. The
    entitlement goes as a bearer and nothing else of this fleet goes with it."""
    headers = {"Accept": "application/json", "User-Agent": "founderizer-hub"}
    if token:
        headers["Authorization"] = "Bearer " + token
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=timeout) as answer:
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
    if status in (401, 403):
        return {"status": status, "manifest": None, "entitlement": None,
                "says": "the release channel refused this fleet's entitlement"}
    if status != 200:
        return {"status": status, "manifest": None, "entitlement": None,
                "says": f"the release channel answered {status}"}
    try:
        raw = json.loads(body)
    except ValueError:
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

def _run(argv, timeout=GIT_WAIT, cwd=None, input=None):
    """One command, with `input` as its standard input when given. It never raises: a step that cannot run is a step
    that failed, with its reason."""
    try:
        done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                              **({"input": input} if input is not None else {"stdin": subprocess.DEVNULL}))
        return done.returncode, done.stdout.strip(), done.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)[:300]


def _line(text):
    return " ".join(str(text or "").split())[:400]


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
STEPS = ("hold", "branch", "clean", "pinned", "fetch", "have", "already", "minimum", "clone", "merge", "keep",
         "schema", "selftest", "verify", "take", "push", "follow")


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
    same `lifecycle.may_take` that every machine runs before it moves, and the hub's checkout follows under it."""

    def __init__(self, kit, manifest, *, origin=None, upstream=None, branch=None, remote=REMOTE,
                 run=_run, python=None, database=None, selftest_wait=SELFTEST_WAIT, verify_wait=VERIFY_WAIT,
                 schema_wait=SCHEMA_WAIT, floor=None):
        from lifecycle import CONFIG_BRANCH
        self.kit, self.manifest, self.origin, self.upstream = kit, manifest, origin, upstream
        self.branch, self.remote, self.run, self.database = branch or CONFIG_BRANCH, remote, run, database
        self.floor = floor
        self.python = python or sys.executable
        self.selftest_wait, self.verify_wait, self.schema_wait = selftest_wait, verify_wait, schema_wait
        # pinned: the revision this fleet runs and keeps. reached: the revision that got onto the configuration
        # ref, which only a run that published one has.
        self.pinned, self.reached, self.clone = None, None, None

    # ---- the readings

    def git(self, *args, cwd=None, timeout=GIT_WAIT):
        return self.run(["git", "-C", cwd or self.kit, *args], timeout=timeout)

    def answer(self, state, step, says):
        return {"state": state, "step": step, "says": _said(says), "pinned": self.pinned, "reached": self.reached,
                "revision": self.manifest["revision"], "version": self.manifest["version"]}

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
            return self.answer(KEPT, "hold", f"release {manifest['version']} is held: no fleet takes it")
        code, branch, _ = self.git("symbolic-ref", "--short", "--quiet", "HEAD", timeout=60)
        if code != 0 or branch != self.branch:
            return self.answer(KEPT, "branch", f"this checkout is on {branch or 'no branch'}, not the configuration "
                                               f"ref {self.branch}, so a release cannot be merged into it")
        if self.git("status", "--porcelain", "--untracked-files=no", timeout=60)[1]:
            return self.answer(KEPT, "clean", "this checkout has its own changes; nothing is merged over them")
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
        """`git fetch upstream`, with the remote added when the repository does not carry it yet."""
        code, url, _ = self.git("remote", "get-url", self.remote, timeout=60)
        if code != 0:
            if not self.upstream:
                return self.answer(KEPT, "fetch", f"this checkout has no remote {self.remote} and no address was "
                                                  f"configured for it")
            if self.git("remote", "add", self.remote, self.upstream, timeout=60)[0] != 0:
                return self.answer(KEPT, "fetch", f"the remote {self.remote} could not be added")
        elif self.upstream and url != self.upstream:
            if self.git("remote", "set-url", self.remote, self.upstream, timeout=60)[0] != 0:
                return self.answer(KEPT, "fetch", f"the remote {self.remote} could not be pointed at the published "
                                                  f"repository")
        code, _, err = self.git("fetch", "-q", "--no-write-fetch-head", self.remote)
        if code != 0:
            return self.answer(KEPT, "fetch", f"the fetch of {self.remote} failed: {err[-200:]}")
        return None

    def in_clone(self):
        """The merge and the three checks, in a clone, then the push and this checkout's own fast-forward."""
        code, _, err = self.run(["git", "clone", "-q", "--shared", self.kit, self.clone])
        if code != 0 or self.git("checkout", "-q", self.pinned, cwd=self.clone, timeout=60)[0] != 0:
            return self.answer(ROLLED_BACK, "clone", f"the update could not be prepared: {err[-200:]}")
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
                                                         f"fleet stays at {self.pinned[:12]}.")
            for line in out.split("\0"):
                path = line.partition("\t")[2]
                if path and path != lifecycle.RELEASE_FILE and lifecycle.data_path(path) == data:
                    entries.append(line)
        for args, given in ((["hash-object", "-w", "--stdin"], self.release_text()), (["read-tree", "--empty"], None)):
            code, out, err = self.run(["git", "-C", self.clone, *args], timeout=60, input=given)
            if code != 0:
                return self.answer(ROLLED_BACK, "merge", f"release {version} could not be put together: "
                                                         f"{_line(err or out)}. The fleet stays at {self.pinned[:12]}.")
            if given is not None:
                entries.append(f"{lifecycle.DATA_MODE} blob {out}\t{lifecycle.RELEASE_FILE}")
        code, out, err = self.run(["git", "-C", self.clone, "update-index", "-z", "--index-info"], timeout=60,
                                  input="".join(one + "\0" for one in entries))
        tree = self.clone_git("write-tree")[1] if code == 0 else ""
        commit = self.run(["git", "-C", self.clone, *author, "commit-tree", tree, "-p", base, "-p", revision, "-m",
                           f"Take release {version} ({revision[:12]})"], timeout=60)[1] if REVISION.fullmatch(tree) \
            else ""
        if not REVISION.fullmatch(commit) or self.clone_git("reset", "-q", "--hard", commit)[0] != 0:
            return self.answer(ROLLED_BACK, "merge", f"release {version} could not be committed onto this fleet: "
                                                     f"{_line(err or out) or 'git made no commit'}. The fleet stays "
                                                     f"at {self.pinned[:12]}.")
        code, names, _ = self.clone_git("diff", "--no-renames", "--name-only", "-z", base, "HEAD")
        if code != 0 or any(lifecycle.data_path(one) for one in names.split("\0") if one):
            return self.answer(ROLLED_BACK, "keep", f"release {version} changes this fleet's own configuration, which "
                                                    f"a release never does. The fleet stays at {self.pinned[:12]}.")
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
                                                    f"stays at {self.pinned[:12]}.")
        return None

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
        database's size in the tempdir for the length of the run, which is the right price for the invariant."""
        if not self.database:
            return None
        version, pinned = self.manifest["version"], self.pinned[:12]
        copy = os.path.join(os.path.dirname(self.clone), "database.sqlite3")
        try:
            shutil.copyfile(self.database, copy)
        except OSError as e:
            return self.answer(ROLLED_BACK, "schema", f"this fleet's database could not be copied for the schema "
                                                      f"check of release {version}: {e}. The fleet stays at {pinned}.")
        code, out, err = self.run([self.python, os.path.join(self.clone, "hub.py"), "--check-schema", copy],
                                  timeout=self.schema_wait, cwd=self.clone)
        summary = schema_summary(out)
        if summary is None:
            return self.answer(ROLLED_BACK, "schema", f"release {version} could not read this fleet's database: "
                                                      f"{_line(err or out) or 'no output'}. The fleet stays at "
                                                      f"{pinned}.")
        refused, says = summary
        if refused:
            return self.answer(ROLLED_BACK, "schema", f"release {version} needs {refused} schema step(s) that this "
                                                      f"fleet's own records refuse ({_line('; '.join(says[:2]))}). "
                                                      f"The fleet stays at {pinned}.")
        if code != 0:
            return self.answer(ROLLED_BACK, "schema", f"the schema check of release {version} ended with {code} "
                                                      f"and named nothing. The fleet stays at {pinned}.")
        return None

    def checks(self):
        """The schema against a copy of this fleet's records, then `selftest.py` and `fleet.py verify`, all three
        in the clone, so they read the released code and not this hub's. Any one failing keeps the fleet where it
        is. The schema goes first because it takes a second and the other two take minutes."""
        from verify import OWNER_STEPS
        answer = self.schema_check()
        if answer:
            return answer
        version, pinned = self.manifest["version"], self.pinned[:12]
        code, out, err = self.run([self.python, os.path.join(self.clone, "selftest.py")],
                                  timeout=self.selftest_wait, cwd=self.clone)
        summary = selftest_summary(out)
        if summary is None:
            return self.answer(ROLLED_BACK, "selftest", f"selftest.py did not answer for release {version}: "
                                                        f"{_line(err or out) or 'no output'}. The fleet stays at "
                                                        f"{pinned}.")
        passed, total, failed, new = summary
        if new:
            return self.answer(ROLLED_BACK, "selftest", f"release {version} fails {len(new)} check(s) that the "
                                                        f"baseline does not have ({', '.join(new[:4])}); "
                                                        f"{passed} of {total} passed. The fleet stays at {pinned}.")
        if code != 0 and not failed:
            return self.answer(ROLLED_BACK, "selftest", f"selftest.py ended with {code} for release {version} and "
                                                        f"named no failure; {passed} of {total} passed. The fleet "
                                                        f"stays at {pinned}.")
        code, out, err = self.run([self.python, os.path.join(self.clone, "fleet.py"), "verify", "--json"],
                                  timeout=self.verify_wait, cwd=self.clone)
        try:
            results = json.loads(out)
            # A check the owner alone can pass says nothing about the release (verify.OWNER_STEPS): a fleet that has
            # never been signed in would otherwise be held at its first revision for ever.
            bad = [one["check"] for one in results
                   if one.get("state") == "fail" and one.get("check") not in OWNER_STEPS]
        except (ValueError, TypeError, KeyError):
            return self.answer(ROLLED_BACK, "verify", f"fleet.py verify did not answer for release {version}: "
                                                      f"{_line(err or out) or 'no output'}. The fleet stays at "
                                                      f"{pinned}.")
        if bad:
            return self.answer(ROLLED_BACK, "verify", f"release {version} is not healthy: verify failed "
                                                      f"{', '.join(bad)}. The fleet stays at {pinned}.")
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
                                                        f"at {self.pinned[:12]}.")
            if not left:
                return self.answer(ROLLED_BACK, "push", f"release {version} passed every check, and {self.branch} "
                                                        f"moved under it {PUSH_TRIES} times while it was pushed, "
                                                        f"so the fleet stays at {self.pinned[:12]}. Press Update "
                                                        f"again when this fleet is writing less.")
            answer, merged = self.catch_up(tip, merged)
            if answer:
                return answer
        self.reached = merged           # it is on the ref now, so every machine of this fleet follows it
        import lifecycle
        # The hub's own checkout moves as every other does: under lifecycle.may_take, with its floor raised after.
        if self.git("fetch", "-q", "origin")[0] != 0 or lifecycle.take(self.kit, merged, self.run, self.floor):
            return self.answer(FAILED, "follow", f"release {version} is on {self.branch} as {merged[:12]}, and this "
                                                 f"hub's own checkout did not move onto it. Bring it up to date by "
                                                 f"hand: git -C {self.kit} merge --ff-only {merged[:12]}")
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
        not refuse it for moving, and a second merge would meet whatever did."""
        return (self.clone_git("merge-base", "--is-ancestor", tip, merged)[0] != 0
                and self.clone_git("merge-base", "--is-ancestor", self.pinned, tip)[0] == 0)

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
                                                    f"to check the release against it."), checked
        return self.take(tip, again), again
