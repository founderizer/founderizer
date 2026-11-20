#!/usr/bin/env python3
"""The day's error report: what a hub sends to our side, once a day, while the owner has turned error reports on.

The owner, 16 November 2026, to the picture of Settings › General with a section "Error reports" and one switch,
"Send to Founderizer's developers", off until he turns it on: "Yes, as drawn". The plan is
~/dev/founderizer-plans/feedback-diagnostics-plan.md, Phase 3, and its contract is the one of `POST
<channel>/api/errors`, which the Mac app and the website follow too.

**What goes is what he was told goes, and nothing else:** the hub's errors as diagnostics.view gives them (a class
from the fixed list, files and lines of this code tree, numbers and times, never a word of an error), the refused
calls in the same shape, and facts: the fleet's random id, the version of the release that runs (from its signed
manifest, never a commit of the configuration ref, which is this fleet's own), the code's id, the operating system's
name and version, and how many agents and servers the fleet has. Every value is checked again here against the
contract's own patterns, and a value out of shape is left out, so that nothing else can ride along. Only what
happened after the report before it, and after the owner turned reports on, goes.

**Where it goes:** only to our own site, over HTTPS, at founderizer.com or a host below it (a staging fleet reports to
staging), and no redirect is followed. It carries no Authorization header: the route asks for no account, and the
report needs nothing that names the subscription.

Python standard library only.
"""
import http.client
import json
import platform
import re
import urllib.error
import urllib.parse
import urllib.request

import diagnostics

PATH = "/api/errors"
MANIFEST = "release.json"   # lifecycle.RELEASE_FILE: the signed manifest of the release on the configuration ref
DAY = 86400             # seconds between two reports, and the hold after an answer that is not 2xx or 429
RETRY = 3600            # seconds before a report that could not reach our side is tried again
RETRY_MOST = 6 * 3600   # the longest wait that our side's Retry-After may set
TIMEOUT = 30            # seconds for one send
MOST = 20               # faults, and refused calls, in one report (diagnostics.MAX_SHOWN)
LIMIT = 65536           # bytes of one report, as our side takes it
COUNT_MOST = 100_000    # agents, and servers
EPOCH = (1.6e9, 4e9)    # the times that a report may carry

HOST = re.compile(r"(?:[a-z0-9-]+\.)*founderizer\.com")
CHANNEL_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")
FLEET = re.compile(r"[0-9a-f]{16}")
# The version and the system are numbers and one word, never words that a sentence could be made of (the owner, 20
# November 2026: "Yes, tighten them"), as our side checks them: a release's version ("2026.11.538") or "unknown", and
# one word of letters with its version number ("ubuntu 24.04", "macOS 26.6", "arch").
VERSION = re.compile(r"unknown|[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,6}")
SYSTEM = re.compile(r"[A-Za-z]{1,16}(?: [0-9]{1,4}(?:\.[0-9]{1,4}){0,3})?")
SYSTEM_WORD = re.compile(r"[A-Za-z]{1,16}")
SYSTEM_NUMBER = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}(?![0-9])")
CODE = re.compile(r"[0-9a-f]{1,64}")
CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
COMMIT = re.compile(r"[0-9a-f]{40}")


class ReportError(Exception):
    """Nothing was sent, or our side refused it. The message is safe to log: it never holds a value of the report.

    `retry_after`: the seconds after which a report may go again: our side's Retry-After for a 429, DAY for any other
    answer that is not 2xx (the same report would only be refused again) and for a channel that is not ours, and None
    when our side was not reached."""

    def __init__(self, says, retry_after=None, status=None):
        super().__init__(says)
        self.retry_after = retry_after
        self.status = status


def endpoint(channel):
    """The report's address on the fleet's release channel, which must be HTTPS at founderizer.com or a host below
    it (each label letters, digits and hyphens): never `xfounderizer.com`, never a user name, a query or an odd path.
    ReportError for any other channel, so that no hub whose channel names another site sends anything there."""
    refused = ReportError("the fleet's channel is not founderizer.com, so no error report goes", retry_after=DAY)
    try:
        parts = urllib.parse.urlsplit(str(channel or "").strip())
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        raise refused from None
    if parts.scheme.lower() != "https" or not HOST.fullmatch(host) or parts.username is not None \
            or parts.password is not None or parts.query or parts.fragment \
            or not CHANNEL_PATH.fullmatch(parts.path.rstrip("/")):
        raise refused
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit(("https", netloc, parts.path.rstrip("/") + PATH, "", ""))


def version_of(manifest):
    """The version that a release's signed manifest names ("2026.11.538"), or "unknown". The manifest must name a
    release revision too, as lifecycle.released reads it."""
    try:
        said = json.loads(manifest)
    except (TypeError, ValueError, RecursionError):
        return "unknown"
    if not isinstance(said, dict) or not isinstance(said.get("revision"), str) \
            or not COMMIT.fullmatch(said["revision"]):
        return "unknown"
    version = said.get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        return "unknown"            # never a commit's id either: it could be one fleet's own
    return version


def system_words():
    """The operating system as SYSTEM has it: one word and its version number ("ubuntu 24.04", "macOS 26.6"), or ""
    when the system gives no word that fits. On Linux the word is os-release's ID, the one word that names a
    distribution ("rhel", where NAME is "Red Hat Enterprise Linux"), up to its first character that is not a letter
    ("opensuse" of "opensuse-leap"); the number is the start of VERSION_ID, and a system with none (Arch) gives its
    word alone."""
    try:
        release = platform.freedesktop_os_release()
        word, number = release.get("ID", ""), release.get("VERSION_ID", "")
    except (OSError, ValueError, AttributeError):
        mac = platform.mac_ver()[0]
        word, number = ("macOS", mac) if mac else (platform.system(), platform.release())
    word, number = SYSTEM_WORD.match(str(word)), SYSTEM_NUMBER.match(str(number))
    if word is None:
        return ""
    text = f"{word.group()} {number.group()}" if number else word.group()
    return text if SYSTEM.fullmatch(text) else ""


def _number(value, low, high):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def _time(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not EPOCH[0] <= value <= EPOCH[1]:
        return None
    return round(float(value), 3)


def _times(entry):
    """The count and the two times of a fault or a refused call, or None when one of them is out of shape."""
    count = _number(entry.get("count"), 1, diagnostics.COUNT_MOST)
    first, last = _time(entry.get("first")), _time(entry.get("last"))
    if count is None or first is None or last is None:
        return None
    return {"count": count, "first": first, "last": last}


def _frame(value):
    """A file of this code tree with its line (0 when Python gave none: diagnostics.place), or exactly ("lib", 0): a
    frame outside the tree, as diagnostics.py keeps it. Anything else is None."""
    if not isinstance(value, dict) or set(value) != {"file", "line"}:
        return None
    file, line = value.get("file"), value.get("line")
    if file == "lib" and _number(line, 0, 0) == 0:
        return {"file": "lib", "line": 0}
    line = _number(line, 0, diagnostics.LINE_MOST)
    if line is None or not isinstance(file, str) or not diagnostics.FILE.fullmatch(file):
        return None
    return {"file": file, "line": line}


def _fault(entry):
    """One fault of diagnostics.view in the contract's shape, checked again, or None. Its class is one of the
    recorder's list, or "other": a name that code chose never goes."""
    frames = entry.get("frames")
    if not isinstance(frames, list) or not frames or len(frames) > diagnostics.MAX_FRAMES:
        return None
    frames = [_frame(f) for f in frames]
    times = _times(entry)
    name = entry.get("class")
    if None in frames or times is None or entry.get("program") not in diagnostics.PROGRAMS \
            or not isinstance(name, str) or not (name in diagnostics.CLASSES or name == "other"):
        return None
    errno, http = entry.get("errno"), entry.get("http")
    if errno is not None and _number(errno, 0, 100_000) is None or http is not None and _number(http, 100, 599) is None:
        return None
    return dict({"program": entry["program"], "class": name, "frames": frames, "errno": errno, "http": http}, **times)


def _refusal(entry):
    """One refused call of diagnostics.view in the contract's shape, checked again, or None."""
    frame = _frame({"file": entry.get("file"), "line": entry.get("line")})
    times = _times(entry)
    tool = entry.get("tool")
    if frame is None or times is None or not isinstance(tool, str) or not CLASS.fullmatch(tool):
        return None
    return dict({"tool": tool, "file": frame["file"], "line": frame["line"]}, **times)


def _size(body):
    return len(json.dumps(body, separators=(",", ":")).encode())


def report(fleet, version, system, code, agents, servers, view, since=0):
    """The day's report: the facts and the faults and refused calls of `view` (diagnostics.view) whose last time is
    after `since`, at most MOST of each, and the oldest of them left out until the report is LIMIT bytes or less. None
    when a required fact is out of shape: then nothing goes."""
    if not isinstance(fleet, str) or not FLEET.fullmatch(fleet) or not isinstance(version, str) \
            or not VERSION.fullmatch(version):
        return None
    body = {"fleet": fleet, "from": "hub", "version": version}
    if isinstance(system, str) and SYSTEM.fullmatch(system):
        body["system"] = system
    if isinstance(code, str) and CODE.fullmatch(code):
        body["code"] = code
    for key, value in (("agents", agents), ("servers", servers)):
        if _number(value, 0, COUNT_MOST) is not None:
            body[key] = value
    view = view if isinstance(view, dict) else {}
    for key, check in (("faults", _fault), ("refusals", _refusal)):
        given = view.get(key)
        given = given if isinstance(given, list) else []
        newer = [e for e in given if isinstance(e, dict) and (_time(e.get("last")) or 0) > since]
        body[key] = [x for x in map(check, newer) if x is not None][:MOST]
    while _size(body) > LIMIT and (body["faults"] or body["refusals"]):
        oldest = min((x["last"], key, i) for key in ("faults", "refusals") for i, x in enumerate(body[key]))
        del body[oldest[1]][oldest[2]]
    return body


def due(on, sent, tried, hold, t):
    """Whether the day's report goes now: error reports are on, our side holds nothing back, no try failed in the
    last RETRY seconds, and the last report that went is a DAY old or there was none. A time more than a DAY after
    `t` was written while the clock was ahead, and counts as none, so that it cannot stop the reports for long."""
    sent, tried, hold = (s if s and s <= t + DAY else None for s in (sent, tried, hold))
    if not on or (hold and t < hold) or (tried and sent != tried and t - tried < RETRY):
        return False
    return not sent or t - sent >= DAY


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never a second request: the report goes to the one address that endpoint checked."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(url, body, timeout=None):
    """POST the report to `url` (endpoint(channel), or a test server's). Nothing when our side took it; ReportError
    when it refused it (retry_after: Retry-After for a 429, DAY for any other answer), could not be reached or gave
    no answer (retry_after None)."""
    request = urllib.request.Request(url, data=json.dumps(body, separators=(",", ":")).encode(), method="POST",
                                     headers={"Accept": "application/json", "Content-Type": "application/json",
                                              "User-Agent": "founderizer-hub"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout or TIMEOUT):
            pass                    # a 2xx: our side took it (a 3xx is an HTTPError here, because no redirect is followed)
    except urllib.error.HTTPError as answer:
        with answer:
            retry = DAY
            if answer.code == 429:
                try:
                    retry = min(max(int(str(answer.headers.get("Retry-After") or "").strip()), 1), RETRY_MOST)
                except ValueError:
                    retry = RETRY
            raise ReportError(f"founderizer.com answered {answer.code}", retry_after=retry, status=answer.code) \
                from None
    except urllib.error.URLError as e:          # the request did not get out: no connection, no name, no TLS
        raise ReportError(f"founderizer.com cannot be reached: {str(e.reason)[:200]}") from None
    except (OSError, ValueError, http.client.HTTPException):    # it went, and no answer that HTTP reads came back
        raise ReportError("founderizer.com gave no answer in time") from None
