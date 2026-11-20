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
"""
import base64
import json
import re
import urllib.error
import urllib.request

import atrest

ENVIRONMENTS = ("production", "development")    # the app's own build: production from TestFlight, development from Xcode
DEVICE_TOKEN = re.compile(r"[0-9a-f]{64,200}")
SEAL_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")    # 32 bytes in base64
TIMEOUT = 45            # seconds for one ping: our side waits up to 15 for Apple's connection and 15 for its answer
RETRY_DEFAULT = 60      # seconds before a ping that our side held back (429) goes again, when it named no time
RETRY_MOST = 1200       # the longest wait for one, whatever our side said: two of its windows of 10 minutes


class PushError(Exception):
    """Nothing was sent. The message is safe to show and to log: it never holds a key, a token or a payload.

    `retry_after` is set when our side held the ping back because a count of its is full (429, the website's
    docs/CONTRACTS.md, "The limits"): the seconds after which the same ping may go again. Our side sent nothing to
    Apple, so the ping still reaches Apple once at most. Its count of each caller counts the refused requests too, so
    the hub sends no ping before that time.

    `status` is our side's own HTTP status when it answered with a refusal (400 for a shape that it does not take),
    and None when it could not be reached."""

    def __init__(self, says, retry_after=None, status=None):
        super().__init__(says)
        self.retry_after = retry_after
        self.status = status


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

def _refusal(status, text):
    try:
        says = json.loads(text).get("says")
    except (ValueError, AttributeError):
        says = None
    if status in (401, 402):        # only a route that still asks for an account answers these
        return f"founderizer.com refused this fleet ({status}), so it sends no pings for it"
    if status == 502:
        return "founderizer.com could not reach Apple's push service"
    if status == 503:
        return "founderizer.com sends no pings yet"
    return f"founderizer.com answered {status}" + (f": {str(says)[:200]}" if says else "")


def send(channel, entitlement, device_token, payload, environment, collapse=None, expires=None, timeout=None):
    """One ping through our side. (status, reason): Apple's HTTP status and its reason, or (0, why) when no answer
    came, so that the ping may or may not have arrived. PushError when nothing left: our side refused the ping or
    could not be reached. `entitlement` goes as the bearer when this fleet holds one, as before; with none, the ping
    goes with no Authorization header."""
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
    if entitlement:
        headers["Authorization"] = "Bearer " + entitlement
    request = urllib.request.Request(channel.rstrip("/") + "/api/push", data=json.dumps(body).encode(), method="POST",
                                     headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout or TIMEOUT) as answer:
            text = answer.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as answer:
        with answer:
            says = _refusal(answer.code, answer.read(65536).decode("utf-8", "replace"))
            raise PushError(says, retry_after=_retry_after(answer.headers) if answer.code == 429 else None,
                            status=answer.code) from None
    except urllib.error.URLError as e:          # the request did not get out: no connection, no name, no TLS
        raise PushError(f"founderizer.com cannot be reached: {str(e.reason)[:200]}") from None
    except (OSError, ValueError):               # it went, and the answer did not come back
        return 0, "founderizer.com gave no answer in time"
    try:
        got = json.loads(text)
        status, reason = got["status"], got.get("reason") or ""
    except (ValueError, KeyError, TypeError, AttributeError):
        return 0, "founderizer.com answered with something other than Apple's answer"
    if isinstance(status, bool) or not isinstance(status, int):
        return 0, "founderizer.com answered with something other than Apple's answer"
    return status, str(reason)[:100]
