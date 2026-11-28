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
import collections
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request

import atrest

ENVIRONMENTS = ("production", "development")    # the app's own build: production from TestFlight, development from Xcode
DEVICE_TOKEN = re.compile(r"[0-9a-f]{64,200}")
BEARER = re.compile(r"[A-Za-z0-9._~+/=-]{1,8192}")     # a bearer that goes into a header whole: no space, no control
SEAL_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")    # 32 bytes in base64
TIMEOUT = 45            # seconds for one ping: our side waits up to 15 for Apple's connection and 15 for its answer
RETRY_DEFAULT = 60      # seconds before a ping that our side held back (429) goes again, when it named no time
RETRY_MOST = 1200       # the longest wait for one, whatever our side said: two of its windows of 10 minutes
LICENCE_HOLD = 900      # seconds that a refusal of the licence holds pings, unless a new licence token ends it first
MEMBER_ROUTE = "/api/push/member"       # B9: the route of a member ping (the website's docs/CONTRACTS.md)
# B9 (b9-phone-members.md 10.7): a member's phone seals its kind, the fleet's id and its push token for our side alone
# (HPKE, app/vectors/member-token-vectors.json), so a company's hub never holds or sends a token in the clear: "v1.",
# a key id of 8, ".", and 448 characters of base64url with no padding (enc and the sealed bytes, 336 bytes).
MEMBER_PUSH = re.compile(r"v1\.[a-z0-9]{8}\.[A-Za-z0-9_-]{448}")
MEMBER_PUSH_BYTES = 336
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
    other answer, and for each answer of the owner's route, whose 429 names no count. A 503 with a Retry-After gives
    `retry_after` too, on both routes (the switch is off, the shop is closed, a fault of our side): the same ping may
    go again after it, and a long 503 does not bring each fleet's call back each minute.

    `local` is True when this file's own checks refused the ping's own token, environment or sealed value (a member
    ping's `push`, member_push) before anything went out: the same ping has them again each time.

    `setting` names a setting of the fleet that this file refused before anything went out: "channel" (an address
    that no request can go to) or "bearer" (a licence that cannot go into a header). It is no fault of the ping, and a
    later setting can end it.

    `word` is the `error` of our side's own body ("unreachable" for its own 502: Apple could not be reached), or None:
    a 502 with another body is a proxy's, which may come after our side gave the ping to Apple. `gone` is True for our
    side's 410 {"gone": true} of the member route: the link's value does not belong (another fleet, a value that does
    not open, an old key, a development build), so the link's token goes.

    What a sender does with each refusal, and with each answer of Apple's, is outcome's one table, for the owner's
    route and the members' alike."""

    def __init__(self, says, retry_after=None, status=None, full=None, local=False, setting=None, word=None,
                 gone=False):
        super().__init__(says)
        self.gone = gone
        self.retry_after = retry_after
        self.status = status
        self.full = full
        self.local = local
        self.setting = setting
        self.word = word


# ---------------------------------------------------------------- one table for each answer (both routes)
#
# Our side's answer is Apple's (the website's docs/CONTRACTS.md): 200 {"status": <Apple's HTTP status>, "reason"}, so
# Apple's own refusals come inside a 200. outcome() classes each answer once, for the owner's pings (hub.send_ping)
# and the members' (the Teams part person_links):
#   HELD     nothing went to Apple, by a cause of the fleet or of a service: every ping waits `wait` seconds, and this
#            one waits first (the owner's row is queued again while inside PUSH_KEEP). Our side's own 502 (its body
#            {"error": "unreachable"}: Apple could not be reached), and on the owner's route any 502 (hub.send_ping
#            holds a proxy's 502 one time for each ping: one second send, which can ring twice, and the second such 502
#            of that ping makes it unknown); our side's 503 (its Retry-After, or RETRY_DEFAULT), 401 and 402
#            (`licence`: LICENCE_HOLD, which a new licence token ends), 429 by its count, no connection, a setting (a
#            channel or a bearer that cannot go out, a 3xx, 403, 404 or 405 of a channel that moved or a route that is
#            not live, a 408, 421, 425, 426 or 431); Apple's 5xx; Apple's 403 of a production ping (its reasons are
#            about our side's own key); Apple's 429 TooManyProviderTokenUpdates (our side's own).
#   PHONE    Apple's other 429: too many pings to that phone; its pings wait RETRY_DEFAULT, this one first.
#   MAYBE    the ping may have gone: it never goes again, and every ping waits RETRY_DEFAULT (the owner's row is
#            unknown). Status 0, by any cause, on the member route a 502 that is not our side's own, and our side's
#            500, 504 or any other 5xx: a proxy may answer after our side gave the ping to Apple.
#   REFUSED  the ping's own fault: that ping goes (the owner's row failed). Our side's 400 and 413, and each other
#            4xx; this file's own refusal of the token or the environment (`token_gone`); Apple's 410 and 400
#            BadDeviceToken or DeviceTokenNotForTopic (`token_gone`); on the owner's route, Apple's 403 of a development
#            ping: our side's key is a production key for the app alone (UI-API 1.76), so such a ping never arrives, and
#            a hold would send it again for a day; our side's 410 {"gone": true} on the member route (`token_gone`: a
#            development build's value gets it too, as the member route sends no environment); Apple's other 4xx.
#   SENT     Apple took it.
# A development ping of the owner's (a build from Xcode) takes the same table. The words are Apple's reason alone for
# Apple's refusal, and "Apple: <status> <reason>" for each other answer of Apple's that is no 200, and for its 403 of a
# development ping.

HELD, PHONE, MAYBE, REFUSED, SENT = "held", "phone", "maybe", "refused", "sent"
GONE_REASONS = ("BadDeviceToken", "DeviceTokenNotForTopic")     # Apple's 400 reasons of a token that is not the app's
Outcome = collections.namedtuple("Outcome", "kind wait licence token_gone words")


def outcome(status=None, reason=None, error=None, environment=None, member=False):
    """The class of one answer: (status, reason) as send gives them, or the PushError that it raised, for a ping of
    `environment` ("production" or "development"), on the member route when `member`. An Outcome: `kind` of the table
    above, `wait` in seconds (HELD, PHONE, MAYBE), `licence` for a hold that a new licence token ends, `token_gone`
    when the stored token goes too, and `words` for the log and the owner's row."""
    if error is not None:
        e, words = error, str(error)
        if e.local:
            return Outcome(REFUSED, None, False, True, words)
        if e.setting is not None:
            bearer = e.setting == "bearer"
            return Outcome(HELD, LICENCE_HOLD if bearer else RETRY_DEFAULT, bearer, False, words)
        code = e.status
        if code == 502:             # our side's own 502 says that Apple could not be reached: nothing went; on the
            if e.word == "unreachable" or not member:   # owner's route a second send only replaces his banner
                return Outcome(HELD, e.retry_after or RETRY_DEFAULT, False, False, words)
            return Outcome(MAYBE, RETRY_DEFAULT, False, False, words)
        if code == 410 and member and e.gone:   # the link's value does not belong: that link's token goes
            return Outcome(REFUSED, None, False, True, words)
        if code is None or code in (403, 404, 405, 408, 421, 425, 426, 431, 503) or 300 <= code < 400:
            return Outcome(HELD, e.retry_after or RETRY_DEFAULT, False, False, words)
        if code in (401, 402):
            return Outcome(HELD, LICENCE_HOLD, True, False, words)
        if code == 429:
            return Outcome(PHONE if e.full == "phone" else HELD, e.retry_after or RETRY_DEFAULT, False, False, words)
        if code >= 500:
            return Outcome(MAYBE, RETRY_DEFAULT, False, False, words)
        return Outcome(REFUSED, None, False, False, words)          # 400, 413 and each other 4xx
    words = str(reason or "")
    if status == 200:
        return Outcome(SENT, None, False, False, words)
    if status == 0:
        return Outcome(MAYBE, RETRY_DEFAULT, False, False, words)
    apple = f"Apple: {status} {words}".strip()
    if status == 429:               # too many pings to that phone; or too many updates of our side's own key
        return Outcome(HELD if words == "TooManyProviderTokenUpdates" else PHONE, RETRY_DEFAULT, False, False, apple)
    if status == 403 and environment == "development" and not member:     # our side's production key sends none
        return Outcome(REFUSED, None, False, False, apple)
    if status >= 500 or status == 403:      # Apple's 403 reasons are about our side's own key
        return Outcome(HELD, RETRY_DEFAULT, False, False, apple)
    return Outcome(REFUSED, None, False, status == 410 or (status == 400 and words in GONE_REASONS), words)


def member_push(value):
    """True for a phone's sealed push token of the exact form (MEMBER_PUSH) whose base64url decodes strictly to
    MEMBER_PUSH_BYTES: one spelling for each value. The hub never opens it."""
    if not isinstance(value, str) or not MEMBER_PUSH.fullmatch(value):
        return False
    body = value.rsplit(".", 1)[1]
    try:
        raw = base64.urlsafe_b64decode(body)
    except ValueError:
        return False
    return len(raw) == MEMBER_PUSH_BYTES and base64.urlsafe_b64encode(raw).decode("ascii") == body


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
    except (ValueError, AttributeError, RecursionError):
        says = None
    if status in (401, 402):        # only a route that still asks for an account answers these
        return f"{side} refused this fleet ({status}), so it sends no pings for it"
    if status == 502 and _word(text) == "unreachable":
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


def _word(text):
    """The `error` word of our side's body, or None."""
    try:
        word = json.loads(text).get("error")
    except (ValueError, AttributeError, RecursionError):
        word = None
    return word if isinstance(word, str) else None


def _gone(text):
    """True for our side's body {"gone": true}."""
    try:
        return json.loads(text).get("gone") is True
    except (ValueError, AttributeError, RecursionError):
        return False


def _full(text):
    """The count that a 429 of the member route names: one of FULL_COUNTS, and "fleet" for any other value or none."""
    try:
        full = json.loads(text).get("full")
    except (ValueError, AttributeError, RecursionError):
        full = None
    return full if full in FULL_COUNTS else "fleet"


def _goes_out(url, bearer):
    """PushError(setting=...) for an address or a bearer that cannot go into a request, which http.client or urllib
    would refuse before anything went out: no http or https, no host, a host that IDNA does not take (an empty label),
    a user or a password, a % in the host, a port that is no number, a character that is not ASCII, a space or a
    control character, or a bearer with a line break. A setting of the fleet, not of the ping."""
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port                                      # ValueError for a port that is no number
        good = url.isascii() and parts.scheme in ("http", "https") and bool(parts.hostname) and \
            parts.username is None and parts.password is None and "%" not in parts.netloc and \
            not any(ord(ch) <= 0x20 or ord(ch) == 0x7f for ch in url)
        if good:
            parts.hostname.encode("idna")               # UnicodeError (a ValueError) for an empty or long label
    except ValueError:
        good = False
    if not good:
        raise PushError("the channel is no address that a request can go to", setting="channel")
    if bearer and not BEARER.fullmatch(bearer):
        raise PushError("the bearer cannot go into a request", setting="bearer")


def send(channel, entitlement, device_token, payload, environment, collapse=None, expires=None, timeout=None):
    """One ping through our side. (status, reason): Apple's HTTP status and its reason, or (0, why) when no answer
    came, so that the ping may or may not have arrived. PushError when nothing left: our side refused the ping or
    could not be reached. `entitlement` goes as the bearer when this fleet holds one, as before; with none, the ping
    goes with no Authorization header. A 429, and a 503 with a Retry-After, give their time (PushError.retry_after)."""
    if not isinstance(device_token, str) or not DEVICE_TOKEN.fullmatch(device_token):
        raise PushError("that is not a device token", local=True)
    if environment not in ENVIRONMENTS:
        raise PushError("the environment is production or development", local=True)
    return _post(channel, "/api/push", entitlement, {"token": device_token, "environment": environment}, payload,
                 collapse, expires, timeout)


def send_member(channel, licence, sealed, payload, collapse=None, expires=None, timeout=None):
    """One member ping (B9) through our side's member route, with the fleet's licence as the bearer: as send, and a 429
    names its full count (PushError.full). It carries the phone's sealed push token (`push`, member_push) and no token
    or environment in the clear: our side opens it, and refuses a token in the clear with 400. With no licence nothing
    goes: the route takes no ping without one."""
    if not licence:
        raise PushError("a member ping goes only with the fleet's licence")
    if not member_push(sealed):
        raise PushError("that is not a sealed push token of a member's phone", local=True)
    return _post(channel, MEMBER_ROUTE, licence, {"push": sealed}, payload, collapse, expires, timeout, member=True)


def _post(channel, path, bearer, to, payload, collapse, expires, timeout, member=False):
    """`to` is what names the phone in the body: {"token", "environment"} on the owner's route, {"push"} on the
    member route."""
    body = dict(to, payload=payload)
    if collapse:
        body["collapse"] = collapse
    if expires is not None:
        body["expires"] = int(expires)
    headers = {"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "founderizer-hub"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    url = str(channel).rstrip("/") + path
    _goes_out(url, bearer)
    request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout or TIMEOUT) as answer:
            text = answer.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as answer:
        with answer:
            try:                    # the refusal's own words; its status and Retry-After are in its head
                said = answer.read(65536).decode("utf-8", "replace")
            except (OSError, ValueError, http.client.HTTPException):
                said = ""
            says = _refusal(answer.code, said, _side(channel))
            held = answer.code == 429 or (answer.code == 503 and answer.headers.get("Retry-After"))
            raise PushError(says, retry_after=_retry_after(answer.headers) if held else None, status=answer.code,
                            full=_full(said) if member and answer.code == 429 else None, word=_word(said),
                            gone=member and answer.code == 410 and _gone(said)) from None
    except urllib.error.URLError as e:          # no connection, no name, no TLS: a state of the network, never local
        raise PushError(f"{_side(channel)} cannot be reached: {str(e.reason)[:200]}") from None
    except (OSError, ValueError, http.client.HTTPException):
        # The request went, and its answer did not come back whole: a time-out, a cut answer, a status line that is no
        # HTTP. What http.client and urllib refuse before anything goes out (the address, the bearer) _goes_out
        # refused first, as a setting of the fleet.
        return 0, f"{_side(channel)} gave no answer in time"
    try:
        got = json.loads(text)
        status, reason = got["status"], got.get("reason") or ""
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return 0, f"{_side(channel)} answered with something other than Apple's answer"
    if isinstance(status, bool) or not isinstance(status, int):
        return 0, f"{_side(channel)} answered with something other than Apple's answer"
    return status, str(reason)[:100]
