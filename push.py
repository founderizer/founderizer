#!/usr/bin/env python3
"""Pings to the owner's phone (MOBILE-APP.md 9, owner feature push). Python standard library only.

Apple takes a push for the iPhone app only from a holder of an APNs key of the app's team, and such a key pushes to the
app on every phone, so no hub holds one: every hub, the owner's own too, hands its pings to our side's push route
(`POST <channel>/api/push`, the release channel's address), and our side sends them to Apple. The route asks for no
account (the website's docs/CONTRACTS.md, "A call with no token"): a fleet with no entitlement sends its pings with no
Authorization header, and a fleet that holds one still sends it as the bearer, which the route does not read.

What a ping says goes sealed. The phone gives the hub a key of its own with its push token, and the hub seals the
agent's name, the item's title and its options with it (ChaCha20-Poly1305, RFC 8439, which the phone opens with
CryptoKit). Our side and Apple carry the item's number and the sealed bytes, and never a word of the item. The cipher
is atrest.py's, the one copy of it in the hub (its own copy here went on 20 November 2026).

**A ping to a member's phone** (Founderizer for Teams, B9: the iPhone app of a company's people) goes by a route of its
own, `POST <channel>/api/push/member` (send_member), with the fleet's licence as the bearer and its own counts at our
side, so that the pings of a company's people never take the room of the owner's, and a 429 there names the count that
is full (PushError.full). The Teams part person_links calls it from a thread of its own; the owner's pings never do.
"""
import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request

import atrest

ENVIRONMENTS = ("production", "development")    # the app's own build: production from TestFlight, development from Xcode
DEVICE_TOKEN = re.compile(r"[0-9a-f]{64,200}")
SEAL_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")    # 32 bytes in base64
TIMEOUT = 45            # seconds for one ping: our side waits up to 15 for Apple's connection and 15 for its answer
RETRY_DEFAULT = 60      # seconds before a ping that our side held back (429) goes again, when it named no time
RETRY_MOST = 1200       # the longest wait for one, whatever our side said: two of its windows of 10 minutes
MEMBER_ROUTE = "/api/push/member"       # B9: the route of a member ping (the website's docs/CONTRACTS.md)
FULL_COUNTS = ("fleet", "phone", "members")     # the counts that a 429 of that route names in `full`


class PushError(Exception):
    """Nothing was sent. The message is safe to show and to log: it never holds a key, a token or a payload.

    `retry_after` is set when our side held the ping back because a count of its is full (429, the website's
    docs/CONTRACTS.md, "The limits"): the seconds after which the same ping may go again. Our side sent nothing to
    Apple, so the ping still reaches Apple once at most. Its count of each caller counts the refused requests too, so
    the hub sends no ping before that time.

    `status` is our side's own HTTP status when it answered with a refusal (400 for a shape that it does not take),
    and None when it could not be reached.

    `full` is the count that is full, for a 429 of the member route (send_member): "fleet" (the requests of this
    fleet's licence), "phone" (the member pings to that device token, of all fleets) or "members" (all member pings).
    A value that the hub does not know, or none, is "fleet", as the website's docs/CONTRACTS.md says. None for each
    other answer, and for each answer of the owner's route, whose 429 names no count. On the member route a 503 with a
    Retry-After gives `retry_after` too (the switch is off, the shop is closed, a fault of our side): the same ping
    may go again after it."""

    def __init__(self, says, retry_after=None, status=None, full=None):
        super().__init__(says)
        self.retry_after = retry_after
        self.status = status
        self.full = full


def _retry_after(headers):
    """The seconds of a 429's Retry-After, from 1 to RETRY_MOST. Our side writes a whole number of seconds; a date,
    or no header, is RETRY_DEFAULT."""
    try:
        seconds = int(str(headers.get("Retry-After") or "").strip())
    except ValueError:
        return RETRY_DEFAULT
    return min(max(seconds, 1), RETRY_MOST)


# ---------------------------------------------------------------- the seal (RFC 8439, atrest.py's cipher)

def seal(key, plaintext, nonce=None):
    """The nonce, the sealed bytes and the tag in one, as CryptoKit's `ChaChaPoly.SealedBox(combined:)` reads them:
    AEAD_CHACHA20_POLY1305 with no additional data, and a new random nonce for each seal unless a test gives one."""
    if len(key) != 32:
        raise ValueError("a seal key is 32 bytes")
    return atrest.encrypt(key, plaintext, b"", nonce)


def open_sealed(key, combined):
    """The other half of seal, for the tests: the plaintext, or ValueError when the tag does not stand."""
    if len(key) != 32 or len(combined) < 28:
        raise ValueError("not a sealed ping")
    try:
        return atrest.decrypt(key, combined, b"")
    except atrest.Unopened:
        raise ValueError("the tag does not stand") from None


def seal_key(text):
    """The 32 bytes of a seal key as the phone sends it, in base64, or ValueError."""
    if not isinstance(text, str) or not SEAL_KEY.fullmatch(text):
        raise ValueError("seal must be the phone's 32-byte key, in base64")
    return base64.b64decode(text)


# ---------------------------------------------------------------- the send

def _side(channel):
    """The name of our side in a ping's words: the host of the release channel that the ping went to (the hub's
    release_channel(), platform.founderizer.com for every client since 21 November 2026), so that the words name the
    server that answered and never one that the channel left."""
    return urllib.parse.urlsplit(str(channel)).hostname or "our side"


def _refusal(status, text, side):
    try:
        says = json.loads(text).get("says")
    except (ValueError, AttributeError):
        says = None
    if status in (401, 402):        # only a route that still asks for an account answers these
        return f"{side} refused this fleet ({status}), so it sends no pings for it"
    if status == 502:
        return f"{side} could not reach Apple's push service"
    if status == 503:
        return f"{side} sends no pings yet"
    return f"{side} answered {status}" + (f": {str(says)[:200]}" if says else "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A ping follows no redirect: urllib's own handler took a 301, 302 or 303 of our side's push route to the host that
    it named, as a GET, with the entitlement's bearer in its Authorization, and took that host's answer for Apple's (the
    review of 22 November 2026). The redirect stays an answer of its own, refused with its status (_refusal)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _full(text):
    """The count that a 429 of the member route names: one of FULL_COUNTS, and "fleet" for any other value or none."""
    try:
        full = json.loads(text).get("full")
    except (ValueError, AttributeError):
        full = None
    return full if full in FULL_COUNTS else "fleet"


def send(channel, entitlement, device_token, payload, environment, collapse=None, expires=None, timeout=None):
    """One ping through our side. (status, reason): Apple's HTTP status and its reason, or (0, why) when no answer
    came, so that the ping may or may not have arrived. PushError when nothing left: our side refused the ping or
    could not be reached. `entitlement` goes as the bearer when this fleet holds one, as before; with none, the ping
    goes with no Authorization header."""
    return _post(channel, "/api/push", entitlement, device_token, payload, environment, collapse, expires, timeout)


def send_member(channel, licence, device_token, payload, environment, collapse=None, expires=None, timeout=None):
    """One member ping (B9) through our side's member route, with the fleet's licence as the bearer: as send, and a 429
    names its full count (PushError.full), and a 503 with a Retry-After gives its time. With no licence nothing goes:
    the route takes no ping without one."""
    if not licence:
        raise PushError("a member ping goes only with the fleet's licence")
    return _post(channel, MEMBER_ROUTE, licence, device_token, payload, environment, collapse, expires, timeout,
                 member=True)


def _post(channel, path, bearer, device_token, payload, environment, collapse, expires, timeout, member=False):
    if not isinstance(device_token, str) or not DEVICE_TOKEN.fullmatch(device_token):
        raise PushError("that is not a device token")
    if environment not in ENVIRONMENTS:
        raise PushError("the environment is production or development")
    body = {"token": device_token, "environment": environment, "payload": payload}
    if collapse:
        body["collapse"] = collapse
    if expires is not None:
        body["expires"] = int(expires)
    headers = {"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "founderizer-hub"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    request = urllib.request.Request(channel.rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
                                     headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout or TIMEOUT) as answer:
            text = answer.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as answer:
        with answer:
            said = answer.read(65536).decode("utf-8", "replace")
            says = _refusal(answer.code, said, _side(channel))
            held = answer.code == 429 or (member and answer.code == 503 and answer.headers.get("Retry-After"))
            raise PushError(says, retry_after=_retry_after(answer.headers) if held else None, status=answer.code,
                            full=_full(said) if member and answer.code == 429 else None) from None
    except urllib.error.URLError as e:          # the request did not get out: no connection, no name, no TLS
        raise PushError(f"{_side(channel)} cannot be reached: {str(e.reason)[:200]}") from None
    except (OSError, ValueError):               # it went, and the answer did not come back
        return 0, f"{_side(channel)} gave no answer in time"
    try:
        got = json.loads(text)
        status, reason = got["status"], got.get("reason") or ""
    except (ValueError, KeyError, TypeError, AttributeError):
        return 0, f"{_side(channel)} answered with something other than Apple's answer"
    if isinstance(status, bool) or not isinstance(status, int):
        return 0, f"{_side(channel)} answered with something other than Apple's answer"
    return status, str(reason)[:100]
