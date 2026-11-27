"""The Fleet Manager's own CLI (F6-8 of the owner's feedback of 22 November 2026): the table `hub.MANAGER_OPS`, which
gives each operation of the owner API one class, alone, told or owner.

The manager's tool `admin` (piece M1 of ~/dev/founderizer-plans/owner-feedback-2026-11-22/F6-manager-cli-design.md,
which the area "Needs-you and the manager" builds) runs only what this table lets it run. So a gap in the table is a
gap in what the manager can do, and a wrong class is a power that the owner did not give. These tests read the owner
API from hub.py itself and the pages of fleet_read from owner_mcp.py: the hub is the list, and nothing here is kept by
hand. No hub runs, no database, no network.
"""
import ast
import functools
import inspect
import itertools
import pathlib
import re
import tempfile
import unittest
from unittest.mock import patch

import hub
import owner_mcp
from test_ui_api import own_files

# The whole source of the hub: so ship.py runs this module for each change of hub.py (WHOLE_SOURCE), and a new owner
# route fails its push until somebody gives it its class.
SOURCE = pathlib.Path(hub.__file__).read_text()

# The one ui_command label that is not its path (test_owner_mcp.Shape.LABEL_PATHS).
LABEL_PATHS = {"/ui/attachment_keep": "/ui/attachments/{}/keep"}
# The fields that name a request and the state that it is made on, never a part of what it does.
NOT_PARTS = {"request_id", "db", "base_sha256", "base_revision"}
CLASSES = ("alone", "told", "owner")


def norm(route):
    return re.sub(r"\{[^}]*\}", "{}", route).rstrip("/")


def fields_of(body):
    """The fields that one route's own code takes: as test_owner_mcp.Shape.hub_routes reads them, and each field that
    it reads by data.get("x"), data["x"] or "x" in data (`take` of /ui/releases/check is read only so)."""
    fields = set()
    for pattern in (r"self\.only\(data,\s*\(([^)]*)\)", r"self\.integration_base\(data,\s*\(([^)]*)\)",
                    r"set\(data\)\s*-\s*\{([^}]*)\}"):
        for got in re.finditer(pattern, body):
            fields |= {x.strip().strip("\"'") for x in got.group(1).split(",") if x.strip()}
    for pattern in (r'data\.get\(\s*"(\w+)"', r'data\[\s*"(\w+)"\s*\]', r'"(\w+)" in data\b'):
        fields |= set(re.findall(pattern, body))
    return {f for f in fields - NOT_PARTS if f and " " not in f}


@functools.lru_cache(maxsize=1)
def readers():
    """{name: source} of each module-level function of the hub whose name ends in _read and that takes `data`: a
    route's read of its body that left Handler (task_control_read, task_steer_read, chat_stop_read)."""
    return {m.group(1): m.group(3) for m in re.finditer(r"\ndef (\w+_read)\(([^)]*)\):(.*?)(?=\n\S)", SOURCE, re.S)
            if re.search(r"\bdata\b", m.group(2))}


def route_fields(body):
    """The fields of one route's method (fields_of), with those of each *_read function of the hub that it calls."""
    fields = fields_of(body)
    for name in set(re.findall(r"\b(\w+_read)\(", body)) & set(readers()):
        fields |= fields_of(readers()[name])
    return fields


@functools.lru_cache(maxsize=1)
def methods():
    """{name: source} of each method of the hub's classes whose name starts with ui_."""
    return {m.group(1): m.group(2)
            for m in re.finditer(r"\n    def (ui_\w+)\(self[^)]*\):(.*?)(?=\n    def |\Z)", SOURCE, re.S)}


def labelled():
    """{route: (method, fields)} of each owner command, by the label of its own ui_command call."""
    found = {}
    for name, body in methods().items():
        label = re.search(r'ui_command\(\s*f?"([^"]+)"', body)
        if label:
            route = norm("/ui/" + label.group(1))
            found[LABEL_PATHS.get(route, route)] = (name, route_fields(body))
    return found


def strings(node):
    if isinstance(node, (ast.List, ast.Tuple)) and \
            all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts):
        return [e.value for e in node.elts]
    return None


def route_shape(test):
    """(length, {index: [its values]}) of one condition of the dispatch on `parts`, or None when it is no /ui/ route."""
    length, fixed = None, {}
    for term in test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) else [test]:
        if not (isinstance(term, ast.Compare) and len(term.ops) == 1):
            continue
        left, op, right = term.left, term.ops[0], term.comparators[0]
        if isinstance(op, ast.Eq) and isinstance(left, ast.Name) and left.id == "parts" and strings(right):
            length = len(strings(right))
            fixed.update({i: [v] for i, v in enumerate(strings(right))})
        elif isinstance(op, ast.Eq) and isinstance(left, ast.Call) and getattr(left.func, "id", "") == "len" \
                and getattr(left.args[0], "id", "") == "parts" and isinstance(right, ast.Constant):
            length = right.value
        elif isinstance(left, ast.Subscript) and getattr(left.value, "id", "") == "parts":
            index = left.slice
            if isinstance(index, ast.Slice) and isinstance(op, ast.Eq) and strings(right):
                start = index.lower.value if index.lower else 0
                fixed.update({start + i: [v] for i, v in enumerate(strings(right))})
            elif isinstance(index, ast.Constant) and isinstance(op, ast.Eq) and isinstance(right, ast.Constant):
                fixed[index.value] = [right.value]
            elif isinstance(index, ast.Constant) and isinstance(op, ast.In) and strings(right):
                fixed[index.value] = strings(right)
    if length is None or fixed.get(0) != ["ui"]:
        return None
    return length, fixed


def handler_of(body):
    """The Handler method that the body of one dispatch condition returns, or None (two methods, or no method):
    self.ui_x(...), and getattr(self, "ui_mcp_" + parts[2])() as its prefix."""
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
            call = node.value.func
            if isinstance(call, ast.Attribute) and getattr(call.value, "id", "") == "self":
                return call.attr
            if isinstance(call, ast.Call) and getattr(call.func, "id", "") == "getattr":
                return call.args[1].left.value
    return None


def names_ui(test):
    """True for a condition that compares `parts` with a list or tuple that holds "ui": a route of the owner API."""
    return any(isinstance(node, (ast.List, ast.Tuple)) and any(isinstance(e, ast.Constant) and e.value == "ui"
                                                               for e in node.elts)
               for node in ast.walk(test)) and any(isinstance(node, ast.Name) and node.id == "parts"
                                                   for node in ast.walk(test))


@functools.lru_cache(maxsize=2)
def unread(verb):
    """The lines of each `if` of Handler.get or Handler.post whose condition names "ui" and gives no shape that
    route_shape reads (a slice with no length, a length of at least n): a route that the table would miss."""
    tree = ast.parse(SOURCE)
    handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Handler")
    method = next(f for f in handler.body if isinstance(f, ast.FunctionDef) and f.name == verb)
    return [node.lineno for node in method.body
            if isinstance(node, ast.If) and names_ui(node.test) and not route_shape(node.test)]


@functools.lru_cache(maxsize=2)
def dispatch(verb):
    """[(route, method)] of each /ui/ route of Handler.get or Handler.post: its parts from the condition of its `if`
    (each value of `parts[i] in (...)` is a route of its own), and the method that its body returns. An `if` that names
    "ui" with no shape that this reads is in unread(verb), which a test holds empty."""
    tree = ast.parse(SOURCE)
    handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Handler")
    method = next(f for f in handler.body if isinstance(f, ast.FunctionDef) and f.name == verb)
    found = []
    for node in method.body:
        shape = route_shape(node.test) if isinstance(node, ast.If) else None
        if not shape:
            continue
        length, fixed = shape
        name = handler_of(node.body)
        for parts in itertools.product(*[fixed.get(i, ["{}"]) for i in range(length)]):
            found.append(("/" + "/".join(parts), name + parts[-1] if name and name.endswith("_") else name))
    return found


@functools.lru_cache(maxsize=1)
def owner_writes():
    """{name: fields} of each owner write: each route of a ui_command; each POST route under /ui/ whose method gives
    no ui_command label (/ui/messages, /ui/needs/<id>, /ui/team/logins, ...); and "GET <route>" for each GET route
    under /ui/ that writes (hub.get_writes)."""
    labels = labelled()
    found = {route: fields for route, (_method, fields) in labels.items()}
    commands = {method for method, _fields in labels.values()}
    for route, method in dispatch("post"):
        if route not in found and method not in commands:
            found[route] = route_fields(methods().get(method, "")) if method else set()
    for route, _method in dispatch("get"):
        if hub.get_writes([p if p != "{}" else "1" for p in route.strip("/").split("/")]):
            found["GET " + route] = set()
    return found


# A read of the owner CLI that reaches the hub and is not one of owner_mcp.SWIFT_READS: read_attachment reads GET
# /ui/attachments/<id>, and writes only a file of the owner's own Mac.
MORE_READS = ("read_attachment",)


def owner_reads():
    """{read: its pages, or None}: each read of the owner CLI that reaches the hub (owner_mcp.SWIFT_READS and those of
    MORE_READS that are tools of it now), and for fleet_read the pages that owner_mcp.PAGES gives it."""
    tools = {t["name"] for t in owner_mcp.tools()}
    return {name: set(owner_mcp.PAGES) if name == "fleet_read" else None
            for name in (*owner_mcp.SWIFT_READS, *(n for n in MORE_READS if n in tools))}


def listed(function):
    """The words of the one `not in ("a", "b")` of a function of the hub: the values that its route takes."""
    tuples = re.findall(r"not in \(((?:\s*\"[^\"]*\",?)+)\)", inspect.getsource(function))
    assert len(tuples) == 1, f"{function.__name__} has {len(tuples)} lists of values"
    return set(re.findall(r"\"([^\"]*)\"", tuples[0]))


def taken(op, field):
    """The values that the hub takes for one field of one operation, read from the hub, or None where this test does
    not know where the hub keeps them."""
    known = {("fleet_read", "page"): lambda: set(owner_mcp.PAGES),
             ("/ui/triggers/{}/state", "action"): lambda: set(hub.TRIGGER_ACTIONS),
             ("/ui/settings", "settings"): lambda: set(hub.SETTINGS),
             ("/ui/tasks/{}/control", "action"): lambda: listed(hub.task_control_read),
             ("/ui/conversations/{}", "action"): lambda: listed(hub.Handler.ui_conversation_control),
             ("/ui/chat-apps/pause", "paused"):
                 lambda: {"true", "false"} if 'isinstance(data.get("paused"), bool)' in methods()["ui_chat_pause"]
                 else set(),
             ("/ui/team/agents/{}", "active"):
                 lambda: {"true", "false"} if 'isinstance(data["active"], bool)' in methods()["ui_team_agent"]
                 else set()}
    return known[(op, field)]() if (op, field) in known else None


def parsed(name):
    """(operation, field or None, value or None) of one name of the table."""
    words = name.split(" ")
    op = " ".join(words[:2]) if words[0] == "GET" else words[0]
    rest = words[2:] if words[0] == "GET" else words[1:]
    if not rest:
        return op, None, None
    assert len(rest) == 1, f"{name!r}: a name is an operation and at most one part"
    field, _, value = rest[0].partition("=")
    return op, field, value or None


class ManagerOps(unittest.TestCase):
    """hub.MANAGER_OPS, the class of each owner operation for the manager's tool admin (claim 5 of the design)."""

    @classmethod
    def setUpClass(cls):
        cls.classes = {name: of for of in CLASSES for name in hub.MANAGER_OPS.get(of, ())}
        cls.operations = dict(owner_writes(), **{read: None for read in owner_reads()})

    def setUp(self):
        # The class reads hub.Handler's source and serves no request, but its hub still gets files of its own
        # (test_ui_api.OwnFiles): no test's hub reads a file of the machine that runs it.
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        own_files(self, folder.name)

    def test_each_name_has_exactly_one_class(self):
        """A name in two lists has two classes: the tool would run as alone what the owner keeps as the owner's, or the
        other way round, by the order in which it reads them. So each name is in one list, once, and there are no
        other lists."""
        self.assertEqual(sorted(hub.MANAGER_OPS), sorted(CLASSES))
        every = [name for of in CLASSES for name in hub.MANAGER_OPS[of]]
        twice = sorted({name for name in every if every.count(name) > 1})
        self.assertEqual(twice, [], f"names in two lists, or twice in one: {twice}")

    def test_each_owner_route_and_each_page_has_its_class(self):
        """Claim 5 of the design: the table is whole. Each owner write route (each ui_command route, each POST route
        under /ui/ outside it, and each GET route under /ui/ that writes), each read of the owner CLI and each page of
        fleet_read has its class, read from hub.py and owner_mcp.py and never from a list kept by hand. A route that a
        release adds with no class makes this fail, so it cannot go out unclassed. A route with parts (a field, or the
        values of a field) has each part classed: each field that the route takes, and each value of a field that the
        hub takes, so a new power of /ui/team/agents/<name> or a new action of a wake-up rule fails here too. Such a
        route can also have a class of its own, for a call that gives none of its parts (a check of the release
        channel with no take): a call takes the strictest class of the names that it matches (hub.MANAGER_OPS). And
        each field of a route that is alone or told has a name of its own, or is one of hub.MANAGER_MODIFIERS: the
        table's rule makes a field in no list the owner's, so a new field of an open route must be classed, and the
        test no longer passes a field that the table would refuse (the validation of f191b35c0, R1)."""
        writes, reads = owner_writes(), owner_reads()
        self.assertGreater(len(labelled()), 80, "too few ui_command routes: check the pattern")
        self.assertTrue({"/ui/messages", "/ui/needs/{}", "/ui/team/logins", "GET /ui/backup"} <= set(writes),
                        "the owner writes outside ui_command are not found: check the dispatch's parse")
        names = [parsed(name) for name in self.classes]
        gaps = []
        for op in sorted(set(writes) | set(reads)):
            mine = [(field, value) for of, field, value in names if of == op]
            if not mine:
                gaps.append(f"{op}: no class")
                continue
            if (None, None) in mine and op in reads and reads[op] is not None:
                gaps.append(f"{op}: a class for each page, not one for all of them")
            if mine == [(None, None)] and self.classes.get(op) == "owner":
                continue                # closed: a field of it changes nothing
            split = {field for field, _value in mine if field is not None}
            if op in writes:
                left = writes[op] - split - {field for route, field in hub.MANAGER_MODIFIERS if route == op}
                gaps += [f"{op}: the field {field} has no class" for field in sorted(left)]
            for field in sorted(split):
                given = {value for f, value in mine if f == field}
                if given == {None}:
                    continue
                if None in given:
                    gaps.append(f"{op}: a class for the field {field} and for its values")
                    continue
                values = taken(op, field)
                if values is None:
                    gaps.append(f"{op}: this test does not know where the hub keeps the values of {field}: add them "
                                f"to taken()")
                    continue
                gaps += [f"{op}: {field}={value} has no class" for value in sorted(values - given)]
        self.assertEqual(gaps, [], "owner operations that the manager's table does not class:\n" + "\n".join(gaps))

    def test_each_if_of_the_dispatch_that_names_ui_is_read(self):
        """The table is whole only for the routes that this test reads. A route of Handler.post or Handler.get whose
        condition gives no shape that route_shape reads (only a slice, or a length of at least n) would have no class,
        and nothing would fail. So each `if` of the two dispatches that compares `parts` with a list that holds "ui"
        must give one (the validation of 23 November 2026, finding 7)."""
        self.assertEqual({verb: unread(verb) for verb in ("post", "get")}, {"post": [], "get": []},
                         "routes of the dispatch that this test cannot read: give each a length, as the others do")

    def test_the_owners_voice_is_the_owners_and_the_managers_hand_has_its_own_mark(self):
        """Claim 9 of the design: nothing that the manager does through admin has the owner's force. The owner's
        message, steer, Stop in the chat box and goal control put words into an agent's thread as the owner's; with
        the manager's hand they would read as the owner's own, so they are the owner's. And words with the manager's
        hand carry the whole mark "[fleet manager]" (request_via), with no "owner" in it: before 23 November 2026
        request_via gave None for it, the owner's own hand, so a later change that opened one of these rows would have
        written the manager's words as the owner's (the validation, finding 9); and "[owner via ...]" is what RULES.md
        tells an agent to do as the owner's request (R2)."""
        voice = ("/ui/messages", "/ui/tasks/{}/steer", "/ui/chats/{}/stop", "/ui/goals/{}/state")
        self.assertEqual({name: self.classes.get(name) for name in voice}, dict.fromkeys(voice, "owner"))
        self.assertEqual(hub.request_via(hub.MANAGER_HAND), "[fleet manager]")
        self.assertNotIn("owner", hub.request_via(hub.MANAGER_HAND))
        self.assertNotIn(hub.MANAGER_HAND, hub.OWNER_FORCE_HANDS)
        self.assertFalse(hub.owner_force(hub.MANAGER_HAND))

    def test_each_name_is_an_owner_operation(self):
        """A name that is no route, no field of its route or no value that its route takes classes nothing: the route
        that it meant is in no list after a rename, and a reader of the table believes a class that the tool never
        finds. So each name is an operation of the owner API as hub.py and owner_mcp.py have it now."""
        writes, reads = owner_writes(), owner_reads()
        stale = []
        for name in self.classes:
            op, field, value = parsed(name)
            if op not in writes and op not in reads:
                stale.append(f"{name}: {op} is no owner route and no read of the owner CLI")
            elif field is None:
                continue
            elif op in writes and field not in writes[op] and taken(op, field) is None:
                stale.append(f"{name}: {op} takes no field {field}")
            elif op in reads and (field != "page" or reads[op] is None):
                stale.append(f"{name}: {op} has no pages")
            elif value is not None and value not in (taken(op, field) or ()):
                stale.append(f"{name}: {op} takes no {field} {value}")
        self.assertEqual(stale, [], "names of the manager's table that are no owner operation:\n" + "\n".join(stale))
        loose = [f"{route} {field}" for route, field in hub.MANAGER_MODIFIERS
                 if route not in writes or field not in writes[route]]
        self.assertEqual(loose, [], "modifiers of the table that their route does not take")

    def test_the_reads_of_peoples_words_the_owners_chats_and_files_stay_the_owners(self):
        """Claim 12 of the design, with the Door and security area's read (ADDENDA.md, F6): the manager's admin reads
        no page that holds a person's words, the owner's own chat with an agent, an agent's notes and lessons, the
        whole snapshot, a QR, or the owner's knowledge files. Design section 3 had two of them as alone. The page
        people gives the first words of each message of an unknown sender, a stranger's text that no agent reads
        today. For the owner GET /ui/knowledge gives each file of knowledge/owner/, more than the manager's profile
        lists, and the Door area keeps the page out of shape A (KnowledgeReader holds the filter for an agent's read).
        search_history searches every chat and conversation; the manager has its own tool, with its own filters."""
        own = ("state", "owner_chat", "conversation", "conversations", "events", "notes", "lessons", "chat_link",
               "agent_messages", "artifacts", "knowledge", "people")
        self.assertEqual({f"fleet_read page={page}": self.classes.get(f"fleet_read page={page}") for page in own},
                         {f"fleet_read page={page}": "owner" for page in own})
        self.assertEqual(self.classes.get("search_history"), "owner")

    def test_no_card_device_vault_secret_or_door_route_is_the_managers(self):
        """Claims 6 and 8: no row gives the manager an approval of its own, a device of the owner's, the vault, a
        secret or the door. Each route under /ui/needs/ (an answer to a card), /ui/owner/ (the owner's phones and
        computer), /ui/vault/, /ui/secrets/ and /ui/door, and each route that owner_mcp.NOT_TOOLS keeps from the
        owner's own tools (each carries a credential or a statement that the owner's Mac signs), is the owner's, and
        so is each part of it: a new route there that a builder classes as alone or told fails here. And each row of
        FIXED, which an edit of the table could open with no other test that fails."""
        prefixes = ("/ui/needs/", "/ui/owner/", "/ui/vault/", "/ui/secrets/", "/ui/door")
        wrong = sorted(name for name, of in self.classes.items() if of != "owner" and
                       (parsed(name)[0].startswith(prefixes) or parsed(name)[0] in owner_mcp.NOT_TOOLS))
        self.assertEqual(wrong, [], f"routes of cards, devices, the vault, secrets or the door, not owner: {wrong}")
        self.assertEqual({name: self.classes.get(name) for name in self.FIXED}, dict.fromkeys(self.FIXED, "owner"))

    # Claims 7, 8 and 10 of the design, and the security reads of this table (23 November 2026): rows that give a
    # release, the hub's checkout, a backup, a key, a grant outside the pool, the Tools boxes or the owner's own voice;
    # an agent's model, effort and screen model (the owner's route has none of the rules of the manager's own
    # set_agent_model: model_changes off, a lead's team, its own model); the digest of the snapshot with each agent's
    # newest reports; an agent turned on, a conversation let run again and the end of a hold (no rule yet refuses the
    # owner's own for the manager's hand); an MCP server at an address that the caller gives.
    FIXED = ("/ui/releases/update", "/ui/releases/auto", "/ui/team/reload", "GET /ui/backup", "/ui/team/agents/{}/key",
             "/ui/servers/{}/key-swap", "/ui/team/repos", "/ui/team/agents/{} can", "/ui/messages",
             "/ui/team/agents/{} model", "/ui/team/agents/{} effort", "/ui/team/agents/{} screen", "fleet_overview",
             "/ui/team/agents/{} active=true", "/ui/conversations/{} action=resume", "/ui/resources/take",
             "/ui/mcp/check server")


class KnowledgeReader(unittest.TestCase):
    """Claim 12 of the design, the filter: an agent that reads the owner's knowledge page under its own name
    (phone_knowledge's reader) gets only the owner files that the Knowledge files section of its own profile lists.

    The fault of claim 12 stays OPEN, and the owner's knowledge files are a rule in words, not a limit of access: this
    filter is one part only. No caller gives `reader` yet (piece M1 will); the manager reads every owner file through
    its own read_knowledge and search_knowledge (knowledge_usable gives a manager each of them, for its summaries);
    and each machine's checkout of the configuration ref holds knowledge/owner/ (lifecycle.CONFIG_FILES), which any
    agent with a shell can read. The Door area gave the change of knowledge_usable to the area "Needs-you and the
    manager"."""

    FILES = [{"path": "knowledge/owner/listed.md", "scope": "owner", "title": "Listed", "commit": "c1"},
             {"path": "knowledge/owner/other.md", "scope": "owner", "title": "Other", "commit": "c1"},
             {"path": "knowledge/services.md", "scope": "internal", "title": "Services", "commit": "c1"}]
    PROFILE = {"sections": [{"key": "knowledge_files", "text": "- knowledge/owner/listed.md"}]}

    def profile_view(self, agent, rev, strict=False):
        """As hub.profile_view: a profile that git gives no answer for now is KitUnread with strict, and with no text
        without it."""
        if agent == "unread" and strict:
            raise hub.KitUnread(f"profiles/{agent}.md")
        return self.PROFILE if agent == "manager" else {"sections": []}

    def read(self, path, revision="r1", **how):
        """(status, the paths whose text git gave) of one read of the page, on a catalog of three files."""
        texts = []

        def text(entry):
            texts.append(entry["path"])
            return f"The words of {entry['path']}."
        with patch.object(hub, "kv_get", lambda key: "g1" if key == "db_id" else None), \
                patch.object(hub, "knowledge_entries", lambda: self.FILES), \
                patch.object(hub, "knowledge_text", text), \
                patch.object(hub, "kit_revision", lambda fresh=False: revision), \
                patch.object(hub, "profile_view", self.profile_view), \
                patch.object(hub, "scrub", lambda value: value), patch.object(hub, "mask_secrets", lambda t: t):
            status, _body, _headers = hub.phone_knowledge({"db": "g1", "path": path}, **how)
        return status, texts

    def test_a_file_that_the_profile_does_not_list_is_not_read(self):
        """The bug that the Door and security area found (ADDENDA.md, F6, claim 12): GET /ui/knowledge gives each file
        of knowledge/owner/, and the manager's profile lists fewer. Through the page with its own name, the manager
        reads a file of its profile; a file that its profile does not list, or an internal file, is the 404 of a file
        that is not there, and git gives no text of it. When the revision or the profile cannot be read, the list is
        not known: 503, and no text (a profile that failed to read is not a profile with no files). The owner's own
        reads stay as they were."""
        listed = "knowledge/owner/listed.md"
        self.assertEqual(self.read(listed, reader="manager"), (200, [listed]))
        self.assertEqual(self.read("knowledge/owner/other.md", reader="manager"), (404, []))
        self.assertEqual(self.read("knowledge/services.md", internal=True, reader="manager"), (404, []))
        self.assertEqual(self.read(listed, reader="worker-2"), (404, []))
        self.assertEqual(self.read(listed, revision=None, reader="manager"), (503, []))
        self.assertEqual(self.read(listed, reader="unread"), (503, []))
        self.assertEqual(self.read("knowledge/owner/other.md"), (200, ["knowledge/owner/other.md"]))
        self.assertEqual(self.read("knowledge/services.md", internal=True), (200, ["knowledge/services.md"]))


if __name__ == "__main__":
    unittest.main()
