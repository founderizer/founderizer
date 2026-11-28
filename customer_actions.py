"""A customer action (D143; customer-keyed-tools design v5 of 26 November 2026): the pure parts of the Vault area.

An action is one fixed request, or one checked read and then one fixed write, that a support agent makes to a service
with a key of the vault, for the customer who writes to it on a chat app, and only about that customer's own record.
It lives on the agent's entry in team.json (`agents.<agent>.customer_actions`), and it works only while the owner's yes
row holds its hash.

Here are three things that the hub and its tests import, and nothing that reads a grant, git, the database or the
network:
- action_form: the static form check of one action (validate_team may call it). It reads only the action and the
  entry of its login in the team that is checked.
- the hub's own pattern parser and matcher. A customer's value and a service's value are never matched by Python's
  `re`: the parser takes a small subset (a sequence of literal characters and character classes, each with a bounded
  count), and the matcher does one pass over the value for each element, so its work is the number of elements times
  the value's length, also for a hostile value under the hub's LOCK.
- action_hash: the one hash of an action and its login's recorded site and form, which the owner's yes binds.
pattern_words gives the plain words of a pattern for the owner's card.

And the pure parts of one run (design v5, 3.2), which the hub calls under its LOCK: e164 and whatsapp_e164 (the one
rule of a phone number), action_request (the request of one call), check_answer (the check and the cut of the
service's answer) and run_hashes (the salted hashes of the folded runs of a customer's own words)."""

import hashlib
import hmac
import json
import math
import unicodedata
import re
import urllib.parse

# What an action may hold, and nothing else: a field that a later release adds makes the action inactive in this one
FIELDS = ("login", "auth", "headers", "read", "write", "fills", "binds", "owner", "also", "returns", "per_day",
          "fleet_day", "says")
ACTION_NAME = re.compile(r"[a-z][a-z0-9_]{0,39}")
ACTIONS_MOST = 8                    # actions of one agent
NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")           # a path segment, a query key, a body key, a fill or a bind
FIELD_PART = re.compile(r"0|[1-9][0-9]{0,5}|[A-Za-z_][A-Za-z0-9_-]{0,63}")     # a list index, or a key
FIELD_MOST = 8                      # parts of a field of the service's answer, `customer.phone` or `items.0.state`
LOGIN_REF = re.compile(r"bws://[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|sealed:[0-9]{1,12}")
# call_api's forms of `auth` (hub.py API_HEADER and API_AUTH_FIXED; test_customer_actions holds the copies equal)
AUTH_HEADER = re.compile(r"header:([A-Za-z][A-Za-z0-9_-]{0,63})")
AUTH_FIXED = ("host", "authorization", "content-length", "transfer-encoding", "connection", "content-type")
HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")
HEADERS_MOST = 4
HEADER_VALUE = re.compile(r"[ -z|~]{1,200}")        # fixed visible ASCII, never a `{` or a `}`
READ_METHODS, WRITE_METHODS = ("GET",), ("POST", "PUT", "PATCH", "DELETE")
PATH_MOST, BODY_MOST, BODY_DEPTH, FIXED_MOST = 300, 2000, 4, 200
KINDS = ("whatsapp_phone", "telegram_id", "chat_id")
KIND_WORDS = {"whatsapp_phone": "WhatsApp number", "telegram_id": "Telegram account", "chat_id": "account in {app}"}
# The only body keys that take a customer's own words, and the words that never hold a fill on the way to it
TEXT_KEYS = ("message", "comment", "body", "description", "note", "reason", "subject", "text")
ADDRESS_WORDS = ("email", "mail", "phone", "mobile", "cell", "msisdn", "whatsapp", "sms", "fax", "recipient", "address",
                 "url", "uri")
# An address word only as a key's first or last word (`to_list`, `reply_to`)
EDGE_ADDRESS_WORDS = ("to", "cc", "bcc")
# Address words also inside a longer word (`phonenumber`, `emailaddress`), and whole words that name a place to send to
ADDRESS_PARTS = ("email", "phone", "recipient", "address", "msisdn", "whatsapp", "telegram")
SEND_WORDS = ("chat", "tel", "destination", "receiver", "webhook", "callback")    # an address word only as a key's first or last word (`to_list`, `reply_to`)
TEXT_FILL = re.compile(r"text:([1-9][0-9]{0,3})")
TEXT_MOST = 1000
PER_DAY, FLEET_DAY = (3, 20), (100, 1000)           # (the default, the most)
SAYS_MOST = 160
SETTING = re.compile(r"[A-Za-z][A-Za-z0-9_ -]{0,39}")    # a setting's word: a letter first
HASH_VERSION = b"customer-action v1\n"      # a new reading of a field or a pattern takes a new version
FILLS_MOST, RETURNS_MOST = 8, 8
# The hub's pattern subset, and the lengths that a caller checks before any match (design v5, 3.1)
PATTERN_CHARS, PATTERN_ELEMENTS, COUNT_MOST = 300, 16, 200
FILL_MOST, VALUE_MOST = 200, 500    # a customer's fill, and a value of the service's answer
TEMPLATE = re.compile(r"\{([A-Za-z0-9_-]{1,64})\}")
LITERAL_PART = re.compile(r"[A-Za-z0-9_-]{1,64}")
QUERY_VALUE = re.compile(r"[A-Za-z0-9_-]{0,64}")

PRINTABLE = frozenset(chr(c) for c in range(0x20, 0x7f))
META = frozenset("^$()[]{}|*+?.\\")
ESCAPABLE = META | frozenset("-/")
DIGITS = frozenset("0123456789")
UPPER = frozenset(chr(c) for c in range(ord("A"), ord("Z") + 1))
LOWER = frozenset(chr(c) for c in range(ord("a"), ord("z") + 1))


class PatternError(ValueError):
    """A pattern outside the hub's subset; its words say why, in one sentence."""


def _count(text, i):
    """The count after an element at i: (m, n, the next index). No count is {1}."""
    if i >= len(text) or text[i] != "{":
        return 1, 1, i
    end = text.find("}", i)
    if end < 0:
        raise PatternError("A { must close with }.")
    parts = text[i + 1:end].split(",")
    if len(parts) not in (1, 2) or not all(p.isascii() and p.isdigit() and (p == "0" or p[0] != "0") for p in parts):
        raise PatternError("A count is {n} or {m,n}, with whole numbers.")
    m, n = int(parts[0]), int(parts[-1])
    if not m <= n or not 1 <= n <= COUNT_MOST:
        raise PatternError(f"A count {{m,n}} needs m at most n, and n from 1 to {COUNT_MOST}.")
    return m, n, end + 1


def _class(text, i):
    """The characters of a class that opens at i, and the index after its `]`."""
    i += 1
    if i < len(text) and text[i] == "^":
        raise PatternError("A class with ^ (all characters but some) is not allowed.")
    items = []                          # each a character; "-" between two of them makes a range
    while True:
        if i >= len(text):
            raise PatternError("A [ must close with ].")
        c = text[i]
        if c == "]":
            break
        if c == "\\":
            if i + 1 >= len(text) or text[i + 1] not in ESCAPABLE:
                raise PatternError("In a class, \\ comes only before one of ^ $ ( ) [ ] { } | * + ? . \\ - /.")
            items.append(("char", text[i + 1]))
            i += 2
            continue
        if c == "[":
            raise PatternError("A [ inside a class must be written \\[.")
        if c not in PRINTABLE:
            raise PatternError("A pattern holds visible ASCII characters and spaces only.")
        items.append(("dash", c) if c == "-" else ("char", c))
        i += 1
    chars = set()
    k = 0
    while k < len(items):
        kind, c = items[k]
        if kind == "char" and k + 2 < len(items) and items[k + 1][0] == "dash" and items[k + 2][0] == "char":
            hi = items[k + 2][1]
            if ord(c) > ord(hi):
                raise PatternError(f"The range {c}-{hi} goes backwards.")
            chars.update(chr(x) for x in range(ord(c), ord(hi) + 1))
            k += 3
            continue
        if kind == "dash" and 0 < k < len(items) - 1:
            raise PatternError("A - in a class stands between two characters of a range, or first or last: write \\-.")
        chars.add(c)                    # a character, or a - at the start or the end
        k += 1
    if not chars:
        raise PatternError("A class needs at least one character.")
    return frozenset(chars), i + 1


def parse_pattern(text):
    """The elements of a pattern of the hub's subset, as a tuple of (characters, m, n), or PatternError. A pattern is
    ^...$ around at most 16 elements, each a literal character (a meta character after \\) or a class [...] of
    characters and ranges, each with no count, {n} or {m,n} (n at most 200); at most 300 characters. No group,
    alternation, `.`, `*`, `+`, `?`, shorthand class, back-reference or look-around: the parser takes only what it
    knows, so a later Python's regex syntax adds nothing here."""
    if not isinstance(text, str) or not text.isascii() or not 3 <= len(text) <= PATTERN_CHARS:
        raise PatternError(f"A pattern is ASCII text of 3 to {PATTERN_CHARS} characters.")
    if text[0] != "^":
        raise PatternError("A pattern starts with ^.")
    elements, i, ended = [], 1, False
    while i < len(text):
        c = text[i]
        if c == "$":
            if i != len(text) - 1:
                raise PatternError("A $ comes only at the end of a pattern.")
            ended = True
            break
        if c == "[":
            chars, i = _class(text, i)
        elif c == "\\":
            if i + 1 >= len(text) or text[i + 1] not in ESCAPABLE:
                raise PatternError("\\ comes only before one of ^ $ ( ) [ ] { } | * + ? . \\ - /.")
            chars, i = frozenset(text[i + 1]), i + 2
        elif c in META:
            raise PatternError(f"{c} is not allowed in a pattern (write \\{c} for the character itself).")
        elif c in PRINTABLE:
            chars, i = frozenset(c), i + 1
        else:
            raise PatternError("A pattern holds visible ASCII characters and spaces only.")
        m, n, i = _count(text, i)
        elements.append((chars, m, n))
        if len(elements) > PATTERN_ELEMENTS:
            raise PatternError(f"A pattern has at most {PATTERN_ELEMENTS} elements.")
    if not ended:
        raise PatternError("A pattern ends with $.")
    if not elements:
        raise PatternError("A pattern needs at least one element.")
    return tuple(elements)


def pattern_match(elements, value):
    """True when the whole value matches the parsed pattern. The set of end positions that the elements so far can
    reach is a bit for each position; for each element one pass over the value keeps, at each position q, the first
    position from which every character up to q is in the element's class, and a running count of reachable
    positions, so the element's test at q is one subtraction. Each element reads each character of the value once,
    never times its count. The caller checks the value's length first (FILL_MOST, VALUE_MOST)."""
    if not isinstance(value, str) or len(value) > VALUE_MOST:
        return False
    size = len(value)
    reach = bytearray(size + 1)
    reach[0] = 1
    for chars, m, n in elements:
        new = bytearray(size + 1)
        before = [0] * (size + 2)       # before[x]: how many reachable positions are below x
        first, found = 0, False         # first: the lowest p with value[p:q] all in chars
        for q in range(size + 1):
            before[q + 1] = before[q] + reach[q]
            if q and value[q - 1] not in chars:
                first = q
            low, high = max(q - n, first), q - m
            if high >= low and before[high + 1] - before[low]:
                new[q] = 1
                found = True
        if not found:
            return False
        reach = new
    return bool(reach[size])


def pattern_ok(pattern, value, most):
    """True when a value of at most `most` characters matches the pattern; its length first, then the matcher. A
    pattern that does not parse matches nothing."""
    if not isinstance(value, str) or len(value) > most:
        return False
    try:
        return pattern_match(parse_pattern(pattern), value)
    except PatternError:
        return False


# Which strings a pattern can accept, for the form check: a small automaton for each kind of string that a pattern
# must never accept, run over the pattern's elements (never over a value). A step of an element moves the
# automaton's states on any character that the element's class and a transition share.

class _Probe:
    def __init__(self):
        self.moves, self.free, self.final = [], [], set()

    def state(self):
        self.moves.append([])
        self.free.append([])
        return len(self.moves) - 1

    def closure(self, states):
        out, todo = set(states), list(states)
        while todo:
            for t in self.free[todo.pop()]:
                if t not in out:
                    out.add(t)
                    todo.append(t)
        return frozenset(out)

    def step(self, states, chars):
        return self.closure({t for s in states for on, t in self.moves[s] if not chars.isdisjoint(on)})

    def accepts_some(self, elements):
        """True when some string that the elements accept is a string of this probe."""
        now = self.closure({0})
        for chars, m, n in elements:
            got, cur, seen = set(now) if m == 0 else set(), now, set()
            for t in range(1, n + 1):
                cur = self.step(cur, chars)
                if not cur:
                    break
                if t >= m:
                    if cur in seen:     # the sets repeat from here: every later one is in `got` already
                        break
                    seen.add(cur)
                    got |= cur
            now = frozenset(got)
            if not now:
                return False
        return bool(now & self.final)


def _sequence(parts, inside=False):
    """A probe for a sequence of (characters, m, n); n None is no upper count. inside: the sequence may stand
    anywhere in the string, with any characters around it."""
    p = _Probe()
    cur = p.state()
    if inside:
        p.moves[cur].append((PRINTABLE, cur))
    for chars, m, n in parts:
        for _ in range(m):
            nxt = p.state()
            p.moves[cur].append((chars, nxt))
            cur = nxt
        if n is None:
            p.moves[cur].append((chars, cur))
            continue
        ends = [cur]
        for _ in range(n - m):
            nxt = p.state()
            p.moves[cur].append((chars, nxt))
            cur = nxt
            ends.append(cur)
        end = p.state()
        for e in ends:
            p.free[e].append(end)
        cur = end
    if inside:
        p.moves[cur].append((PRINTABLE, cur))
    p.final.add(cur)
    return p


def _letters(least=20):
    """A probe for free words: `least` letters or more in all, whatever stands between them (CamelCase, dots, digits
    or spaces)."""
    p = _Probe()
    letters = UPPER | LOWER
    states = [p.state() for _ in range(least + 1)]
    for k in range(least + 1):
        p.moves[states[k]].append((PRINTABLE - letters, states[k]))
        p.moves[states[k]].append((letters, states[min(k + 1, least)]))
    p.final.add(states[least])
    return p


PHONE_GAPS = frozenset(" -.()/[]~")     # what the E.164 rule of design 3.2.7 and phone libraries remove


def _phone(least=7, plus_first=False):
    """A probe for a phone number as the E.164 rule reads one: an optional + first (a required one with plus_first),
    then `least` digits or more, with PHONE_GAPS anywhere."""
    p = _Probe()
    digits = [p.state() for _ in range(least + 1)]
    plus = p.state()
    p.moves[digits[0]] += [(PHONE_GAPS, digits[0]), (frozenset("+"), plus)] + \
        ([] if plus_first else [(DIGITS, digits[1])])
    p.moves[plus] += [(PHONE_GAPS, plus), (DIGITS, digits[1])]
    for k in range(1, least + 1):
        p.moves[digits[k]] += [(DIGITS, digits[min(k + 1, least)]), (PHONE_GAPS, digits[k])]
    p.final.add(digits[least])
    return p


ALSO_LEAST = 100        # values that an also fill accepts at least, so that a guess rarely opens a record


def _value_count(elements, cap):
    """A lower bound of how many values the parsed pattern accepts, up to `cap`: the values in which each element
    takes its highest count, which all have one length, so no two of them are one string."""
    total = 1
    for chars, m, n in elements:
        total = min(cap, total * len(chars) ** min(n, 16))
    return total


# The strings that a pattern fill never accepts (design v5, 3.1), each with its words
FILL_NEVER = (
    (_sequence([(frozenset("@"), 1, 1)], inside=True), "an email address or a WhatsApp hidden id (an @)"),
    (_phone(), "a phone number (7 or more digits, with or without + and separators)"),
    (_sequence([(frozenset(":"), 1, 1), (frozenset("/"), 2, 2)], inside=True), "a web address (://)"),
    (_sequence([(UPPER | LOWER | DIGITS, 1, 1), (frozenset("."), 1, 1), (UPPER | LOWER, 2, 2)], inside=True),
     "a web address (a name with a dot)"),
)
FREE_WORDS = _letters()
DOTS = _sequence([(frozenset("."), 1, 2)])     # a path part "." or ".."
PATH_NEVER = frozenset("/\\%?#;")       # what a server can read as more than one path part after it decodes
PLUS_PHONE = _phone(plus_first=True)


def recipient_key(key):
    """True when the key names whom the service sends to (to, cc, bcc as its first or last word; recipient,
    destination, receiver, webhook, callback; a key that is only an address word, `email`; a last word url or uri):
    it holds no fixed value at all, only a bind."""
    words = _key_words(key)
    return any(_word_in(w, ("recipient",) + SEND_WORDS[2:]) for w in words) or \
        bool(words) and (_word_in(words[0], EDGE_ADDRESS_WORDS) or _word_in(words[-1], EDGE_ADDRESS_WORDS)
                         or len(words) == 1 and (_word_in(words[0], ADDRESS_WORDS + SEND_WORDS)
                                                 or any(part in words[0] for part in ADDRESS_PARTS))
                         or _word_in(words[-1], ("url", "uri")))


def message_key(key):
    """True when the key's last word is a message word (`email_subject`, `sms_text`): its fixed value is message
    text with a letter in it, which the address shapes of fixed_address still check, never a setting or an
    address."""
    words = _key_words(key)
    return bool(words) and words[-1] in TEXT_KEYS


def setting_value(value):
    """True for a fixed value that is a setting and no address, the only fixed value that an address key may hold:
    true, false, null, a whole number from -99 to 99 (also as one or two digits of a query), or a word that starts
    with a letter and has at most two digits (`off`, `html`, `cancel_v2`)."""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -100 < value < 100
    return isinstance(value, str) and (bool(SETTING.fullmatch(value)) and sum(c.isdigit() for c in value) <= 2
                                       or value.isascii() and value.isdigit() and len(value) <= 2)


def _literal(text):
    """A fixed text as the elements of a pattern, in the form that a service that folds Unicode (NFKC) reads; a letter
    outside ASCII reads as a letter (`a`), so that `пример.рф` is a dotted name too, and a digit as a digit (`0`).
    """
    folded = unicodedata.normalize("NFKC", text).translate({0x3002: ".", 0xFF61: "."})
    return tuple((frozenset(c if c in PRINTABLE else "a" if c.isalpha() else "0"), 1, 1) for c in folded
                 if c in PRINTABLE or c.isalpha() or c.isdecimal())


def fixed_address(text):
    """True when a fixed text of a body is an address: an @, ://, a dotted name, or a + and 7 digits or more, also in
    full-width forms. Bare digits stay open under a key that is no address word: help desks name a fixed group by its
    number."""
    elements = _literal(text)
    return any(probe.accepts_some(elements) for probe, _ in FILL_NEVER[:1] + FILL_NEVER[2:]) or \
        PLUS_PHONE.accepts_some(elements)


def field_parts(field):
    """The parts of a field of the service's answer (`customer.phone`, `items.0.state`), or None. A part of digits only
    is an index into a list (no sign, no leading zero); any other part starts with a letter or _, so that no reading of
    it as a number goes around the list rules."""
    if not isinstance(field, str) or len(field) > 200:
        return None
    parts = field.split(".")
    return parts if len(parts) <= FIELD_MOST and all(FIELD_PART.fullmatch(p) for p in parts) else None


def _key_words(key):
    """The words of a key: split at _ and - and before a capital after a small letter."""
    return [w.lower() for w in re.split(r"[_-]+|(?<=[a-z0-9])(?=[A-Z])", key) if w]


def _word_in(word, words):
    return word in words or word.endswith("s") and word[:-1] in words or word.endswith("es") and word[:-2] in words


def address_key(key):
    """True when a word of the key is an address word or its plural (`phone_number`, `replyEmail`, `recipients`,
    `e_mail`, `redirect_uri`), or its first or last word is to, cc or bcc (`to_list`, `reply_to`, `ccs`): such a key
    never holds a fill or a fixed value, and never leads to one; only a bind, the customer's own handle, stands there."""
    words = _key_words(key)
    return any(_word_in(w, ADDRESS_WORDS + SEND_WORDS) or any(part in w for part in ADDRESS_PARTS) for w in words) \
        or bool(words) and (_word_in(words[0], EDGE_ADDRESS_WORDS) or _word_in(words[-1], EDGE_ADDRESS_WORDS))


def _path(path):
    """{"segments", "slash", "query"} of a request's path, or a problem's words. slash: the path ends with a /, which
    some services need; no other part is empty."""
    if not isinstance(path, str) or not path.isascii() or not 2 <= len(path) <= PATH_MOST or path[0] != "/":
        return f"A path starts with / and has at most {PATH_MOST} ASCII characters."
    part, _, query = path.partition("?")
    segments = part[1:].split("/")
    slash = len(segments) > 1 and segments[-1] == ""
    if slash:
        segments.pop()
    for s in segments:
        if not (LITERAL_PART.fullmatch(s) or TEMPLATE.fullmatch(s)):
            return ("Each part of a path between / is letters, digits, _ or -, or one whole {name}: never empty, "
                    "never a . and never a {name} with more around it.")
    pairs = []
    if "?" in path:
        for item in query.split("&"):
            key, eq, value = item.partition("=")
            if not eq or not NAME.fullmatch(key) or not (QUERY_VALUE.fullmatch(value) or TEMPLATE.fullmatch(value)):
                return "A query is key=value pairs of letters, digits, _ or -, or a value that is one whole {name}."
            if key.lower() == "_method" or key.lower() in (k.lower() for k, _ in pairs):
                return "A query never holds _method, and each key comes once."
            pairs.append((key, value))
    return {"segments": segments, "slash": slash, "query": pairs}


def _uses(body, keys=(), depth=0, out=None):
    """Each {name} of a body template, as (name, the keys from the root to it, True when a dict's value holds it
    directly), or a problem's words."""
    out = [] if out is None else out
    if depth > BODY_DEPTH:
        return f"A body is at most {BODY_DEPTH} levels deep."
    if isinstance(body, dict):
        for k, v in body.items():
            if not (isinstance(k, str) and NAME.fullmatch(k)):
                return "A body's keys are letters, digits, _ or -."
            if k.lower() == "_method":
                return "A body never holds _method: the method is the write's own."
            got = _uses(v, keys + (k,), depth + 1, out)
            if isinstance(got, str):
                return got
    elif isinstance(body, list):
        for v in body:
            got = _uses(v, keys + (None,), depth + 1, out)
            if isinstance(got, str):
                return got
    elif isinstance(body, str):
        whole = TEMPLATE.fullmatch(body)
        if whole:
            out.append((whole.group(1), keys, bool(keys) and keys[-1] is not None))
        elif "{" in body or "}" in body or len(body) > FIXED_MOST:
            return (f"A text of a body is one whole \"{{name}}\" or fixed text of at most {FIXED_MOST} characters "
                    "with no { or }.")
        elif any(k is not None and address_key(k) for k in keys) and not (
                (setting_value(body) or keys[-1] is not None and message_key(keys[-1])
                 and any(c.isalpha() for c in body))
                and not any(k is not None and recipient_key(k) for k in keys)):
            return "An address key of a body holds only a bind, the customer's own handle: never a fixed address."
        elif fixed_address(body):
            return "A fixed text of a body is never an address (an @, ://, a dotted name or a + and a number)."
    elif not (body is None or isinstance(body, (bool, int)) or isinstance(body, float) and math.isfinite(body)):
        return "A body holds objects, lists, texts, numbers, true, false and null only."
    elif isinstance(body, (int, float)) and not isinstance(body, bool) and any(k is not None and address_key(k)
                                                                                for k in keys) \
            and not (setting_value(body) and not any(k is not None and recipient_key(k) for k in keys)):
        return "An address key of a body holds only a bind, the customer's own handle: never a fixed address."
    return out


def _request(r, methods, name, role):
    """The parsed read or write ({"method", "segments", "slash", "query", "body", "uses", "in_path", "in_query"}), or a
    problem's words."""
    if not isinstance(r, dict) or not set(r) <= {"method", "path", "body"} or "method" not in r or "path" not in r:
        return f"The {role} of action {name} is an object with method and path" + \
            (", and a body if it needs one." if role == "write" else ".")
    if r["method"] not in methods:
        return f"The {role} of action {name} has the method " + " or ".join(methods) + "."
    got = _path(r["path"])
    if isinstance(got, str):
        return f"Action {name}, {role}: {got}"
    got.update(method=r["method"], body=None, uses=[])
    if "body" in r:
        if role != "write" or not isinstance(r["body"], dict):
            return f"Only a write of action {name} has a body, and it is a JSON object."
        try:
            size = len(json.dumps(r["body"], ensure_ascii=False))
        except (TypeError, ValueError, RecursionError):
            size = BODY_MOST + 1
        if size > BODY_MOST:
            return f"The write's body of action {name} has at most {BODY_MOST} characters."
        uses = _uses(r["body"])
        if isinstance(uses, str):
            return f"Action {name}, write: {uses}"
        got.update(body=r["body"], uses=uses)
    got["in_path"] = [m.group(1) for m in map(TEMPLATE.fullmatch, got["segments"]) if m]
    got["in_query"] = [m.group(1) for m in (TEMPLATE.fullmatch(v) for _, v in got["query"]) if m]
    return got


def action_form(name, action, login):
    """None when the action keeps the form of design v5, 3.1, or one sentence that says the first thing that breaks it
    (action_parts' first item)."""
    return action_parts(name, action, login)[0]


def action_parts(name, action, login):
    """(None, the parsed action) when the action keeps the form of design v5, 3.1, else (one sentence that says the
    first thing that breaks it, None). login: the team's entry of the action's login (team.json "logins"), or None when
    the team has none. Static: no grant, git or database read, so validate_team can call it for each load; an action
    that fails is inactive and reported, never a refusal of the team. The grant check (the login is the agent's, and
    call_api takes it) is the hub's, at a save, at each run and when the vault asks. The parsed action is what the
    run, the card and the check of the answer read, so that no later piece parses a path in its own way: {"read",
    "write" (each _request's dict, or None), "patterns" {fill: elements}, "texts" {fill: most characters}, "binds"
    {name: kind}, "owner" (field parts), "kind", "sent" (the fills and binds that a request carries: no other value
    goes to the service), "also" ((field parts, fill) or None), "returns" {key: (field parts,
    elements)}, "per_day", "fleet_day"}."""
    problem = _parts(name, action, login)
    return (problem, None) if isinstance(problem, str) else (None, problem)


def _parts(name, action, login):
    if not (isinstance(name, str) and ACTION_NAME.fullmatch(name)):
        return "An action's name is a small letter and then small letters, digits or _, at most 40 characters."
    if not isinstance(action, dict):
        return f"Action {name} is an object."
    extra = sorted(set(action) - set(FIELDS), key=str)
    if extra:
        return f"Action {name} has a field that an action does not take: {str(extra[0])[:40]}."
    if not (isinstance(action.get("login"), str) and LOGIN_REF.fullmatch(action["login"])):
        return f"Action {name} names its login by its reference, bws://<id> or sealed:<number>."
    if not isinstance(login, dict):
        return f"The login of action {name} is not in the team's logins."
    if not login_site_ok(login.get("site")):
        return f"The login of action {name} needs its site, an https address: the owner's card shows it."
    auth = action.get("auth")
    named = AUTH_HEADER.fullmatch(auth) if isinstance(auth, str) else None
    if auth not in ("bearer", "basic") and not (named and named.group(1).lower() not in AUTH_FIXED):
        return f"The auth of action {name} is bearer, basic or header:<Name>, as call_api takes it."
    headers = action.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > HEADERS_MOST:
        return f"The headers of action {name} are an object of at most {HEADERS_MOST}."
    seen = set()
    for k, v in headers.items():
        low = k.lower() if isinstance(k, str) else ""
        if not (low and HEADER_NAME.fullmatch(k) and (low == "accept" or low.endswith("-version"))):
            return f"Action {name} sets only Accept and a header whose name ends in -Version: the hub sends the rest."
        if low in seen:         # Accept and accept are one header, which the vault would send two times
            return (f"Action {name} sets the header {k} two times: a header's name is the same in small and capital "
                    "letters.")
        seen.add(low)
        if not (isinstance(v, str) and HEADER_VALUE.fullmatch(v)):
            return f"Each header of action {name} is fixed visible text of at most 200 characters, with no {{ or }}."
    fills, binds = action.get("fills", {}), action.get("binds", {})
    if not isinstance(fills, dict) or len(fills) > FILLS_MOST:
        return f"The fills of action {name} are an object of at most {FILLS_MOST}."
    if not isinstance(binds, dict) or len(binds) > len(KINDS):
        return f"The binds of action {name} are an object of at most {len(KINDS)}, one for each kind."
    texts, patterns = {}, {}
    for f, p in fills.items():
        if not (isinstance(f, str) and NAME.fullmatch(f)):
            return f"A fill's name in action {name} is letters, digits, _ or -."
        text = TEXT_FILL.fullmatch(p) if isinstance(p, str) else None
        if text:
            if int(text.group(1)) > TEXT_MOST:
                return f"A text fill of action {name} has at most {TEXT_MOST} characters."
            texts[f] = int(text.group(1))
            continue
        try:
            elements = parse_pattern(p)
        except PatternError as e:
            return f"The pattern of fill {f} of action {name} is not one that the hub matches: {e}"
        if sum(e[1] for e in elements) < 1:
            return f"The pattern of fill {f} of action {name} accepts an empty value: a fill is never empty."
        patterns[f] = elements
    for b, kind in binds.items():
        if not (isinstance(b, str) and NAME.fullmatch(b)) or kind not in KINDS:
            return f"A bind of action {name} names a kind: " + ", ".join(KINDS) + "."
        if b in fills:
            return f"{b} of action {name} is a fill and a bind: a name is one of them."
    if len(set(binds.values())) != len(binds):
        return f"Action {name} binds each kind once."
    owner = action.get("owner")
    if not (isinstance(owner, dict) and set(owner) == {"field", "kind"} and field_parts(owner["field"])
            and owner["kind"] in KINDS):
        return f"Action {name} has owner: the field of the service's answer that is the customer's own, and its kind."
    owner_parts = field_parts(owner["field"])
    if owner_parts[0].isdigit():
        return f"The owner field of action {name} starts with a field of the answer's object, not a list index."
    also = action.get("also")
    if also is not None and not (isinstance(also, dict) and set(also) == {"field", "fill"}
                                 and field_parts(also["field"]) and isinstance(also["fill"], str)
                                 and also["fill"] in patterns):
        return f"The also of action {name} is a field of the answer and a pattern fill that it must equal."
    returns = action.get("returns", {})
    if not isinstance(returns, dict) or len(returns) > RETURNS_MOST:
        return f"The returns of action {name} are an object of at most {RETURNS_MOST}."
    kept = {}
    for k, p in returns.items():
        if not field_parts(k):
            return f"Each returns key of action {name} is a field of the answer: parts of letters, digits, _ or -."
        try:
            elements = parse_pattern(p)
        except PatternError as e:
            return f"The pattern of returns {k[:64]} of action {name} is not one that the hub matches: {e}"
        if FREE_WORDS.accepts_some(elements):
            return (f"The pattern of returns {k[:64]} of action {name} accepts 20 letters or more: no free words come "
                    "back.")
        kept[k] = (field_parts(k), elements)
    for f in ([also["field"]] if also else []) + list(returns):
        parts = field_parts(f)
        for i, part in enumerate(parts):
            if part.isdigit() and parts[:i + 1] != owner_parts[:i + 1]:
                return (f"{f[:64]} of action {name} goes into a list: only through the same list and index as the "
                        "owner field.")
    read = write = None
    if "read" in action:
        read = _request(action["read"], READ_METHODS, name, "read")
        if isinstance(read, str):
            return read
    if "write" in action:
        write = _request(action["write"], WRITE_METHODS, name, "write")
        if isinstance(write, str):
            return write
    if not read and not write:
        return f"Action {name} has a read, a write or both."
    sent = set()                        # the names that go to the service
    for r, role in ((read, "read"), (write, "write")):
        if not r:
            continue
        for n in r["in_path"] + r["in_query"] + [u[0] for u in r["uses"]]:
            if n not in fills and n not in binds:
                return f"{{{n}}} in the {role} of action {name} is neither a fill nor a bind."
            sent.add(n)
        for n in r["in_path"] + r["in_query"]:
            if n in texts:
                return f"Text fill {n} of action {name} goes only into a body key: " + ", ".join(TEXT_KEYS) + "."
        for k, v in r["query"]:
            m = TEMPLATE.fullmatch(v)
            if address_key(k) and (m and m.group(1) not in binds or not m and (recipient_key(k)
                                                                              or not setting_value(v))):
                return (f"The query key {k} of action {name} is an address word: it holds only a bind, the customer's "
                        "own handle, or a setting that is no address.")
        for n, keys, direct in r["uses"]:
            if n in fills and any(k is not None and address_key(k) for k in keys):
                return (f"A key on the way to fill {n} of action {name} is an address word: an address is only a "
                        "bind, the customer's own handle.")
            if n in texts and not (direct and keys[-1].lower() in TEXT_KEYS):
                return f"Text fill {n} of action {name} goes only into a body key: " + ", ".join(TEXT_KEYS) + "."
    if also and _value_count(patterns[also["fill"]], ALSO_LEAST) < ALSO_LEAST:
        return (f"The also fill of action {name} accepts fewer than {ALSO_LEAST} values: it is a second fact that the "
                "customer knows.")
    unused = sorted((set(fills) | set(binds)) - sent - ({also["fill"]} if also else set()))
    if unused:
        return f"{unused[0]} of action {name} is used nowhere."
    # A fill that only also reads is compared with the answer and never sent, so it may be an email (the order's
    # email and its number); a fill that goes to the service never carries an address
    for f in sorted(sent & set(patterns)):
        problem = fill_pattern_problem(patterns[f])
        if problem:
            return f"The pattern of fill {f} of action {name} {problem}"
    for r in (read, write):
        for n in (r["in_path"] if r else []):
            if n in patterns and DOTS.accepts_some(patterns[n]):
                return f"The pattern of fill {n} of action {name} accepts . or .., which a path part never is."
            if n in patterns and any(chars & PATH_NEVER for chars, _, _ in patterns[n]):
                return (f"The pattern of fill {n} of action {name} accepts /, \\, %, ? or #, which a path part never "
                        "holds.")
    if write and read:
        if read["in_query"] or not read["in_path"]:
            return (f"The read of a write in action {name} names its record by a {{name}} in its path and by none in "
                    "its query: the write repeats only the path.")
        if write["segments"][:len(read["segments"])] != read["segments"]:
            return f"The write's path of action {name} must start with its read's path, part by part."
        for n in write["in_path"] + write["in_query"] + [u[0] for u in write["uses"]]:
            if n in patterns and n not in read["in_path"]:
                return (f"Fill {n} of the write of action {name} must also be a whole part of its read's path, so "
                        "that the read checks that record first.")
        if any(p.isdigit() for p in owner_parts):
            return f"The owner field of a write's read in action {name} goes through no list."
        if not also:
            return f"A write of action {name} on an existing record has also: a number alone does not open a write."
    elif write:
        if patterns:
            return (f"A write of action {name} with no read (a create) has no pattern fill: only the customer's own "
                    "words and binds.")
        if also:
            return f"A write of action {name} with no read has no also."
        if owner["kind"] not in binds.values():
            return f"A write of action {name} with no read binds the kind that its owner names."
    counts = {}
    for key, (default, most) in (("per_day", PER_DAY), ("fleet_day", FLEET_DAY)):
        v = action.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= most:
            return f"The {key} of action {name} is a whole number from 1 to {most}."
        counts[key] = v
    says = action.get("says")
    if not (isinstance(says, str) and 1 <= len(says) <= SAYS_MOST and says.isprintable()):
        return f"Action {name} says in at most {SAYS_MOST} characters what it does: the agent and the owner read it."
    for r in (read, write):
        if r and r["body"] is not None:
            r["body"] = json.loads(json.dumps(r["body"]))      # the run fills a copy, never the team's own action
    return dict(read=read, write=write, patterns=patterns, texts=texts, binds=dict(binds), owner=owner_parts, sent=sent,
                kind=owner["kind"], also=(field_parts(also["field"]), also["fill"]) if also else None, returns=kept,
                **counts)


def fill_ok(spec, value):
    """True when a customer's value fits a fill's spec: a text fill (`text:<n>`) is text of 1 to n characters; a
    pattern fill passes pattern_ok with FILL_MOST."""
    text = TEXT_FILL.fullmatch(spec) if isinstance(spec, str) else None
    if text:
        return isinstance(value, str) and 1 <= len(value) <= int(text.group(1))
    return pattern_ok(spec, value, FILL_MOST)


def login_site_ok(site):
    """True for a login's site that an action can show and bind: an https address with a host and no user part."""
    if not isinstance(site, str) or len(site) > 300 or any(c.isspace() for c in site):
        return False
    try:
        parts = urllib.parse.urlsplit(site)
        return parts.scheme == "https" and bool(parts.hostname) and parts.username is None and parts.password is None
    except ValueError:
        return False


def fill_pattern_problem(elements):
    """None, or the words that end "The pattern of fill X ..." when the parsed pattern can accept an address, a phone
    number or a web address (design v5, 3.1)."""
    for probe, words in FILL_NEVER:
        if probe.accepts_some(elements):
            return f"accepts {words}: a fill never carries an address."
    return None


def agent_actions_form(actions, logins):
    """{name: None or a problem's words} for an agent's customer_actions; past the first ACTIONS_MOST names (sorted),
    each is refused for the count."""
    if not isinstance(actions, dict):
        return {}
    logins = logins if isinstance(logins, dict) else {}
    out = {}
    for i, name in enumerate(sorted(actions, key=str)):
        action = actions[name]
        if i >= ACTIONS_MOST:
            out[name] = f"An agent has at most {ACTIONS_MOST} actions."
            continue
        ref = action.get("login") if isinstance(action, dict) else None
        out[name] = action_form(name, action, logins.get(ref) if isinstance(ref, str) else None)
    return out


def action_hash(name, action, login):
    """The hash that the owner's yes binds: the action's name, every field with the counts in effect, and its login's
    recorded site, kind, form and title. Any change of one of them, by a tool, by a hand edit or of the login's site,
    gives another hash, so the action is inactive until a new yes; so does a later release that reads a pattern in
    another way, which changes HASH_VERSION. 64 hex characters. The action and the login are JSON values."""
    login = login if isinstance(login, dict) else {}
    action = dict(action, per_day=action.get("per_day", PER_DAY[0]), fleet_day=action.get("fleet_day", FLEET_DAY[0])) \
        if isinstance(action, dict) else action
    whole = {"name": name, "action": action, "site": login.get("site"), "kind": login.get("kind"),
             "form": login.get("form"), "title": login.get("title")}
    text = json.dumps(whole, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(HASH_VERSION + text.encode()).hexdigest()


# The plain words of a pattern, for the owner's card (card-words.md)

def _char_words(c):
    """One character for the card: _ and - as they are, a double quotation mark in words, any other in quotes."""
    return c if c in "_-" else "double quotation mark" if c == '"' else f'"{c}"'


def _class_words(chars, plural):
    left, words = set(chars), []
    for group, many, one in ((DIGITS, "digits", "digit"),):
        if group <= left:
            left -= group
            words.append(many if plural else one)
    if UPPER | LOWER <= left:
        left -= UPPER | LOWER
        words.insert(0, "letters" if plural else "letter")
    else:
        for group, many, one in ((UPPER, "capital letters", "capital letter"), (LOWER, "small letters", "small letter")):
            if group <= left:
                left -= group
                words.insert(0, many if plural else one)
    if " " in left:
        left.discard(" ")
        words.append("spaces" if plural else "space")
    rest = sorted(left)
    i = 0
    while i < len(rest):
        j = i
        while j + 1 < len(rest) and ord(rest[j + 1]) == ord(rest[j]) + 1:
            j += 1
        if j - i >= 2:
            words.append(("characters" if plural else "character") + f' from "{rest[i]}" to "{rest[j]}"')
        else:
            words.extend(_char_words(c) for c in rest[i:j + 1])
        i = j + 1
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " or " + words[-1]


def pattern_words(pattern):
    """The plain words of a fill or a returns pattern: `[0-9]{1,6}` is "1 to 6 digits", `[a-z_]{1,19}` is "1 to 19
    characters, each a small letter or _", `text:300` is "their own words, at most 300 characters", a literal is itself
    in quotes. None for a pattern that does not parse."""
    text = TEXT_FILL.fullmatch(pattern) if isinstance(pattern, str) else None
    if text:
        return f"their own words, at most {text.group(1)} characters"
    try:
        elements = parse_pattern(pattern)
    except PatternError:
        return None
    parts = []
    for chars, m, n in elements:
        count = str(n) if m == n else (f"up to {n}" if m == 0 else f"{m} to {n}")
        if len(chars) == 1:
            c = next(iter(chars))
            c = f'"{c}"' if c in "_-" else _char_words(c)       # a literal _ or - stands alone: in quotes
            parts.append(c if m == n == 1 else f"{c} {count} times")
        elif m == n == 1:
            parts.append(f"1 {_class_words(chars, False)}")
        elif _class_words(chars, False).count(" or ") or _class_words(chars, False).count(","):
            parts.append(f"{count} characters, each a {_class_words(chars, False)}")
        else:
            parts.append(f"{count} {_class_words(chars, True)}")
    return ", then ".join(parts)


# ---- One run (design v5, 3.2): the request of one call, and the check and the cut of the service's answer. The hub
# calls these under its LOCK, so each one reads what it gets once: never a value against a pattern of Python's `re`.

PHASES = ("read", "write", "create")
E164 = re.compile(r"\+[1-9][0-9]{6,14}")
WHATSAPP_JID = re.compile(r"([1-9][0-9]{6,14})@s\.whatsapp\.net")
PHONE_DROPS = frozenset("-.()")             # with every whitespace character: what the E.164 rule removes
REQUEST_PATH_MOST, REQUEST_BODY_MOST = 2000, 65536      # call_api's bounds of a path and of a body
RUN = 12                                    # characters of a run that a value shares with a customer's own words
RUN_DROPS = frozenset("_-.")                # with every whitespace character: what a folded run ignores
_MISSING = object()


class ActionError(ValueError):
    """A call that a request cannot carry: its words say why, in one sentence that the session may read."""


def e164(value):
    """The E.164 form ("+" and digits) of a phone number of a service's answer, or None (design v5, 3.2.7). The value
    is a JSON string, not empty. Remove all whitespace, dashes, dots and parentheses; then only ASCII digits may
    follow a leading + or 00, and the result matches \\+[1-9][0-9]{6,14}. Bare digits and a JSON number never match:
    a service that writes a number with no + or 00 does not say which country it is in."""
    if not isinstance(value, str) or not value or len(value) > VALUE_MOST:
        return None
    text = "".join(c for c in value if not (c.isspace() or c in PHONE_DROPS))
    if text.startswith("+"):
        digits = text[1:]
    elif text.startswith("00"):
        digits = text[2:]
    else:
        return None
    if not (digits.isascii() and digits.isdigit()):
        return None
    return "+" + digits if E164.fullmatch("+" + digits) else None


def whatsapp_e164(handle):
    """The E.164 form of a WhatsApp handle or alias, made only from a full match of [1-9][0-9]{6,14}@s.whatsapp.net;
    None for a hidden id (@lid), a group or any other text."""
    if not isinstance(handle, str):
        return None
    match = WHATSAPP_JID.fullmatch(handle)
    return "+" + match.group(1) if match else None


def _segment(value, name):
    """A value of a path part or of a query, encoded: ASCII text, never empty, `.` or `..`."""
    if not isinstance(value, str) or not value or not value.isascii() or value in (".", ".."):
        raise ActionError(f"The value of {name} cannot go in the request: it is ASCII text, never empty, . or ...")
    return urllib.parse.quote(value, safe="")


def _filled(body, value):
    """A new copy of a body template with each whole "{name}" replaced by its value, in one pass: a value that holds
    a {name} of its own is never read again."""
    if isinstance(body, dict):
        return {k: _filled(v, value) for k, v in body.items()}
    if isinstance(body, list):
        return [_filled(v, value) for v in body]
    whole = TEMPLATE.fullmatch(body) if isinstance(body, str) else None
    if whole:
        got = value(whole.group(1))
        if not isinstance(got, str):
            raise ActionError(f"The value of {whole.group(1)} is text: a fill goes into the body as a JSON string.")
        return got
    return body


def action_request(parts, phase, values, bound):
    """(method, path, body text or None, extra headers) of one call of a parsed action (action_parts' dict). phase:
    read, write or create; values: {fill: value} of the call; bound: {bind name: value} that the hub bound. Only the
    names of parts["sent"] go to the service. Each value of a path part or of a query is ASCII, never `.` or `..`, and
    encoded with quote(value, safe=""); a trailing / of the action stays. The body is the action's template, filled
    in one pass, each fill as a JSON string; the one extra header, Content-Type: application/json, comes only with a
    body. ActionError when the call cannot be carried."""
    if phase not in PHASES:
        raise ActionError("A phase is read, write or create.")
    r = parts["read"] if phase == "read" else parts["write"]
    if r is None or (phase == "create") != (parts["read"] is None and parts["write"] is not None):
        raise ActionError(f"This action has no {phase}.")
    # A fill's value comes only from the call's values, and a bind's only from the hub's bound: an address of the
    # body is only the hub's own bind, also when a caller puts a bind's name among the values
    fills = set(parts["patterns"]) | set(parts["texts"])
    given = {k: v for k, v in (values or {}).items() if k in fills and k in parts["sent"]}
    given.update((k, v) for k, v in (bound or {}).items() if k in parts["binds"] and k in parts["sent"])

    def value(name):
        if name not in given:
            raise ActionError(f"The call gives no value of {name}.")
        return given[name]

    def part(text):
        whole = TEMPLATE.fullmatch(text)
        return _segment(value(whole.group(1)), whole.group(1)) if whole else text

    path = "/" + "/".join(part(s) for s in r["segments"]) + ("/" if r["slash"] else "")
    if r["query"]:
        path += "?" + "&".join(f"{k}={part(v)}" for k, v in r["query"])
    body = None
    if r["body"] is not None:
        body = json.dumps(_filled(r["body"], value), ensure_ascii=True, separators=(",", ":"))
    if len(path) > REQUEST_PATH_MOST or body is not None and len(body) > REQUEST_BODY_MOST:
        raise ActionError("The values of this call make the request too long.")
    return r["method"], path, body, ({"Content-Type": "application/json"} if body is not None else {})


def _field(doc, parts):
    """The value at a field of a parsed answer, or _MISSING. A part of digits indexes a list, and any other part is a
    key of an object; nothing else reads a part, so no number goes into an object and no name into a list."""
    for p in parts:
        if p.isdigit():
            if not isinstance(doc, list) or int(p) >= len(doc):
                return _MISSING
            doc = doc[int(p)]
        elif isinstance(doc, dict) and p in doc:
            doc = doc[p]
        else:
            return _MISSING
    return doc


def _text(value):
    """A value of the answer as text: a JSON string, or a JSON integer (never true or false) as its decimal text;
    else None."""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _folded_equal(service, customer):
    """True when the service's value and the customer's fill are the same text with case and whitespace folded. An
    empty text never matches."""
    a = "".join(service.casefold().split()) if isinstance(service, str) else ""
    b = "".join(customer.casefold().split()) if isinstance(customer, str) else ""
    return bool(a) and a == b


def _returns(parts, doc):
    """{returns key: text} of each returns value of the answer that passes its own pattern, its length first."""
    out = {}
    for key, (fparts, elements) in parts["returns"].items():
        got = _text(_field(doc, fparts))
        if got is not None and len(got) <= VALUE_MOST and pattern_match(elements, got):
            out[key] = got
    return out


def _once(pairs):
    """An object of a JSON text whose keys each come once; a key that comes two times is a ValueError, because two
    readers of the text can then read two other values (the first key or the last one)."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("a key comes two times in one object")
        out[k] = v
    return out


def check_answer(parts, phase, text, bound_kind, bound, also_value):
    """(passed, returns) of the body of the service's answer to one call (design v5, 3.2.7 and 3.2.8). One json.loads
    of the whole text (a RecursionError, a ValueError or a key that comes two times in one object is a failure), and
    it is one JSON object. A read: the owner
    field is the customer's own (for whatsapp_phone a JSON string whose e164 equals the bound value; for telegram_id
    and chat_id the same text exactly, never compared with a phone), and with also, the also field equals the
    customer's fill, case and whitespace folded (empty never matches). A create: the owner check against the bound
    handle. A write: no owner check, only the returns cut, so it passes here (the hub reads the status). returns: only
    the values that pass their patterns, each a JSON string or a JSON integer; the read of a write gives none, because
    its pass only opens the write. The status, a body that the vault cut or held back, and the shared-run drop are
    the caller's."""
    try:
        doc = json.loads(text, object_pairs_hook=_once) if isinstance(text, str) else None
    except (ValueError, RecursionError):
        doc = None
    if phase == "write":
        return True, _returns(parts, doc) if isinstance(doc, dict) else {}
    if phase not in ("read", "create") or not isinstance(doc, dict):
        return False, {}
    if bound_kind != parts["kind"] or not isinstance(bound, str) or not bound:
        return False, {}
    owner = _field(doc, parts["owner"])
    if (e164(owner) if bound_kind == "whatsapp_phone" else _text(owner)) != bound:
        return False, {}
    if phase == "read" and parts["also"] and not _folded_equal(_text(_field(doc, parts["also"][0])), also_value):
        return False, {}
    if phase == "read" and parts["write"] is not None:
        return True, {}
    return True, _returns(parts, doc)


def folded(text):
    """A text as a run reads it: case folded, with every whitespace character, _, - and . removed."""
    return "".join(c for c in text.casefold() if not (c.isspace() or c in RUN_DROPS)) if isinstance(text, str) else ""


def run_hashes(text, salt):
    """The salted hashes of every run of RUN characters of the folded text (each window of 12 characters): the hub
    keeps only these of a customer's own words, never the words, and a returns value that shares one with them is
    dropped (design v5, 3.2.7). salt: the hub's own secret, text or bytes. A text of fewer than RUN characters after
    the fold has none."""
    f = folded(text)
    key = salt.encode() if isinstance(salt, str) else bytes(salt)
    return {hmac.new(key, f[i:i + RUN].encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:32]
            for i in range(len(f) - RUN + 1)}


def shares_run(value, salt, known):
    """True when the value shares a run of RUN characters, folded, with a text whose run_hashes are in `known`."""
    return not run_hashes(value, salt).isdisjoint(known)
