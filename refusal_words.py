"""The hub's refusal words: one table of the sentences that a person reads in an app, each with a code.

A refusal answers `{"error": <the hub's English>}`. A refusal that has a code answers `code` and, when its words hold a
value, `names` beside it (UI-API.md, "A refusal's code and its names"). The English stays as the hub writes it: old apps,
the owner's own AI and the logs read `error`. An app that knows the code shows its own words in the device's language and
puts the names in them; any other app shows `error`, as it always did.

WORDS holds `code -> the English, with {name} holes`. The sentence is the unit: two sentences are two codes, also when
they mean the same, and a code is never used again for another sentence. A hole is a plain name (`{server}`), and the
call that refuses gives each name, so the English, the code and the names cannot drift apart.

At a raise site (hub.py):

    raise Refusal(404, code="no_such_agent")
    raise Refusal(409, code="server_silent", names={"server": server})
    raise Conflict(code="team_changed", sha256=current)
    raise refusal_words.Coded("some_code", agent=name)                     # a check that raises ValueError
    return self.json(409, refusal_words.answer("hub_changed"))             # an answer written by hand

and each route that turns an exception into `error` writes `refusal_body(e)`, so that `code`, `names` and the other
fields of the exception reach the answer.

This module imports nothing of the hub, so that app/vectors/make_vectors.py can write WORDS as `refusal-codes.json`
(the file that the apps' tests read) and every file of the hub can import it. A new code is a new key here, in the
commit that raises it: test_refusal_words.py fails for a code that a raise site names and this table does not hold.
"""
import re
import string

NAME_MOST = 200         # a name is a text of at most this many characters, or a whole number
CODE = re.compile(r"[a-z0-9_]{2,40}")           # the letters of a code: small letters, digits and _, 2 to 40
HOLE = re.compile(r"[a-z][a-z0-9_]*")           # the letters of a hole's name

WORDS = {
    # the app's state is of an older generation of the hub's database than the hub's own (a restore, a new hub)
    "hub_changed": "hub generation changed; refresh state",
    "hub_changed_sending": "hub generation changed; refresh state before sending",
    # another change to team.json came first
    "team_changed": "team.json changed meanwhile; reload it",
    "team_changed_lines": "team.json changed meanwhile; reload the reporting lines",
    # a name that the hub does not hold
    "no_such_agent": "no such agent",
    "no_such_server": "no such server",
    "no_such_task": "no such task",
    # a registered login in words, in a file, or on its way to a page
    "login_as_text": "a registered login cannot be sent as text",
    "login_as_file": "a registered login cannot be sent as a file",
    "login_not_shown": "registered login text cannot be displayed",
    # a request_id that came back with another command, message, file or content
    "command_reused": "request_id was already used for a different command",
    "command_reused_message": "request_id was already used for an owner message; send the answer with a new one",
    "command_reused_file": "request_id was already used for another file",
    "command_reused_content": "request_id was already used for different content or recipient",
    # a command that the hub claimed and did not finish
    "command_interrupted": "this command was interrupted and the hub does not know what came of it. Read the thing it "
                           "was about, and send the command again with a new request_id if it did not take effect",
    # the hub's own checkout
    "revision_unreadable": "the hub cannot read its own revision",
    # a server and its service
    "server_silent": "{server} sent no reading in the last 10 minutes: check that it is on",
    "server_no_service": "{server} has no server service: it did not join with a join code",
    # an owner request (a Needs-you item)
    "request_answered": "owner request is already answered",
    "request_unknown": "owner request does not exist",
    "request_unknown_ended": "owner request does not exist: a request whose task ended is gone with it",
    # a phone that calls from an address that no owner device has
    "not_owner_device": '{address} is not an owner device. See "owner_devices" in team.json.',
    "not_owner_device_no_code": "{address} is not an owner device, and that is not a code for a new one",
    # an agent that is busy
    "agent_mid_turn": "{agent} is in the middle of a turn. Move it when the turn ends.",
    "agent_open_signin": "{agent} has an open sign-in. Finish it or let it run out, then try again.",
    # a one-time rule of "On a schedule" whose time has passed: its Resume (WAKEUPS-INTERFACE.md 8)
    "time_passed": "this time has passed; change the time first",
}


def holes(words):
    """The names that the English holds, in the order that they first come: "{a} and {b} and {a}" gives ("a", "b")."""
    return tuple(dict.fromkeys(field for _, field, _, _ in string.Formatter().parse(words) if field is not None))


def shown(names):
    """`names` as an answer carries them: each value a text of at most NAME_MOST characters, or a whole number. A name
    is written in the words as the app shows it (an agent by its role); only a longer text is cut, in `names` alone."""
    out = {}
    for key, value in names.items():
        if isinstance(value, int) and not isinstance(value, bool):
            out[key] = value
            continue
        value = str(value)
        out[key] = value if len(value) <= NAME_MOST else value[:NAME_MOST - 1] + "…"
    return out


def words(code, names=None, table=None):
    """The English of `code` with `names` in its holes. A KeyError names the code or the hole that is wrong: a call that
    gives the wrong names is a mistake of the code, and test_refusal_words.py finds it before a release."""
    return (WORDS if table is None else table)[code].format(**(names or {}))


def fields(code, names=None, extra=None):
    """The fields of an answer beside `error`, in the order that every refusal gives them: `extra` (a Conflict's current
    value, the `why` of a shared refusal), then `code`, then `names`. names None: the words hold no name, and the answer
    has no `names`."""
    out = dict(extra or {}, code=code)
    if names is not None:
        out["names"] = names
    return out


def answer(code, **names):
    """The whole body of a refusal that a route writes by hand (`self.json(409, answer("hub_changed"))`): what
    refusal_body gives for a Refusal of the same code and names."""
    return dict(fields(code, shown(names) or None), error=words(code, names))


class Coded(ValueError):
    """A check that says no with a code. It is a ValueError, so each route that turns a ValueError into a 400 takes it
    as before, and its words come from the table. `extra` holds `code` and `names` (none when there is no name), which
    refusal_body writes into the answer."""

    def __init__(self, code, **names):
        super().__init__(words(code, names))
        self.code, self.names = code, shown(names)
        self.extra = fields(code, self.names or None)


def refusal_body(e):
    """The answer of an exception that a route turns into `error`: its words, and each field of its `extra` (the code
    and the names of a coded refusal, the current value of a Conflict). An exception with no `extra` answers `error`
    alone, as every route did before a refusal had a code."""
    return dict(getattr(e, "extra", {}), error=str(e))
