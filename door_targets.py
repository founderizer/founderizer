"""What the door may do: one table for each kind of target (DevOps plan, section 2, "The door"). Standard library only.

Every call is one of four kinds: a rule call, which code passes at once; the agent's own call, which code does not list
as a rule but which the agent's grant covers, so that it runs and the agent answers for it (the owner, 11 November 2026:
"it needs to be the agent itself"); a call that the next mode allows, which runs only with the owner's signed yes to
that exact call (door-modes proposal, step 3: a host's `run`, a root script with no box); or a refusal. A call that no
table lists is refused, reads too. A refusal names its route: the agent that holds the grant, the owner's window, or a
check that failed now. decide() gives the kind of one call and the reason, and never acts: door.py acts on what it
gives.

    host                a managed host, through its second sshd: the fixed reads of host/ops-read, the rule forms
                        of host/ops-root, its own forms (the agent's own calls) on a host whose mode is fix, and its
                        run there with the owner's yes
    <provider>:<name>   one provider account of the access file (door_providers.py)
    commit:<owner/repo> a commit that the door makes on a repository the access file gives the agent
    deploy:<owner/repo> that repository's documented deploy
    gitops:<owner/repo> the GitOps repository: a read at HEAD through a filter, a listing and a search of what that
                        read gives, commits of the listed forms, a sync, and an uncordon of a node through the
                        repository's one fixed workflow
    door:self           the door's own server: fixed reads that the door runs as its own user (DOOR_SELF_READS)

The host forms come from host/ops-root and host/ops-read themselves, so the door and the host check each form with
the same code, and the host refuses on its own what the door should never have sent.
"""
import base64
import calendar
import collections
import copy
import difflib
import fnmatch
import importlib.machinery
import importlib.util
import json
import os
import posixpath
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


OPS_ROOT = load("ops_root", os.path.join(HERE, "host", "ops-root"))
OPS_READ = load("ops_read", os.path.join(HERE, "host", "ops-read"))

# The product's own repositories: no customer's door ever touches them (DevOps plan, "Always refused"). GitHub sends
# the old name of a moved repository to its new one, so an old name stays here: the hub's public repository moved from
# miguelpieras/founderizer-fleet to founderizer/founderizer on 11 November 2026.
VENDOR_REPOS = ("founderizer/founderizer", "founderizer/founderizer-apps", "miguelpieras/founderizer-fleet",
                "miguelpieras/founderizer-web", "miguelpieras/agents", "miguelpieras/founderizer-control",
                "miguelpieras/founderizer-verdicts-reviewer-1", "miguelpieras/founderizer-verdicts-reviewer-2",
                "miguelpieras/founderizer-verdicts-security")
# The words with which a refusal of a root script with no box (the form run) begins, when only the owner's word is
# missing: Run it once, or Full access on its server. The hub knows such a refusal in the door's record by them
# (hub.door_full_waiting), so they are one constant.
NO_BOX = "is a root script with no box"
# Host forms that only the door sends, with a value of its own on stdin: never an agent's call.
DOOR_ONLY = {"self-update", "place", "pro-attach", "runner-register"}
# Host forms whose content goes to the host on stdin, with its sha256, and the forms whose value the door itself sends
# there (new-projects plan N4): never the caller's.
HOST_CONTENT = ("file", "unit-new", "vhost-new", "script", "run", "look")
DOOR_VALUE = ("env-new", "env-add")
# Host forms that arm the rollback timer before they run, whatever they do: a host that answers the door after one of
# them did not lock the door out, so the door ends the countdown then (door.py, Door.timer_off).
TIMED_FORMS = ("script", "run")
TARGET = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}|[a-z]+:[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
CONTENT_MAX = 256 * 1024     # bytes of content in one call
PATH_MOST = 1000            # characters of a path of a repository: the commit rules read each path from each folder on
FOLDERS_MOST = 64           # and folders of a path: 200 paths of 1000 characters in 500 folders took 1.9 s

# The commit rules (DevOps plan section 2): these paths, at any depth, never pass in any commit.
NEVER_PATHS = (".claude/**", ".codex/**", ".mcp.json", "AGENTS.md", "CLAUDE.md", ".github/**", ".husky/**",
               ".vscode/**", "policy.hujson", "scripts/security/check-tailnet-policy.mjs",
               # the other files that an agent's runtime reads as its instructions or its settings: Claude Code's and
               # Codex's local ones, and those of the other runtimes that a person of the repository may run in it
               "CLAUDE.local.md", "AGENTS.override.md", ".agents/**", "GEMINI.md", ".gemini/**", ".cursorrules",
               ".cursor/**", ".windsurfrules", ".windsurf/**", ".clinerules", ".clinerules/**", ".roo/**",
               ".roorules", ".continue/**", ".aider.conf.yml", ".opencode/**", "opencode.json", ".kiro/**",
               ".junie/**")
# Manifest forms that code refuses in rendered output: a new one of these is never committed. Each pattern reads one
# line of block style: a key at any depth, after the dashes of a list too, its value quoted or not and in any case,
# with a comment after it. Block style is all that the door reads by lines: a file that it reads as it is (unread),
# and the objects of a render and of a file that the real parser read, written out in it (objects_text).
ITEM = r"^[ \t]*(?:-[ \t]+)*"                 # the start of a line: its indentation and the dashes of its lists
END = r"[\"']?[ \t\r]*(?:#.*)?$"              # the end of a value: its closing quote, a comment, and the CR of a CRLF
TRUE = r"\s*[\"']?(?i:true|yes|on|y)\b"       # the words that YAML 1.1 reads as true, which a cluster's readers take


def kind_line(names):
    # also the kind's List, whose items with no kind of their own are of that kind in Kubernetes' reading
    return ITEM + r"(?i:kind)[ \t]*:\s*[\"']?(?i:(?:" + names + ")(?:List)?)" + END


# The three reference forms take each key that ENDS in secretKeyRef, secretRef or secretName, in any case (a CSI
# volume's nodePublishSecretRef, a store's tokenSecretRef), and the operator's kinds each group of external-secrets.io
# (generators.external-secrets.io too). A key's word is read from its start: \w* from each place of a long word would
# take a time that grows with the square of its length.
MANIFEST_REFUSED = {
    "a new secretKeyRef": r"(?<!\w)(?i:\w*secretKeyRef)\s*:", "a new secretRef": r"(?<!\w)(?i:\w*secretRef)\s*:",
    "a new secret volume": ITEM + r"(?i:secret)[ \t]*:[ \t\r]*(?:#.*)?$|(?<!\w)(?i:\w*secretName)\s*:",
    "a hostPath": r"\bhostPath\s*:",
    "privileged": r"\bprivileged\s*:" + TRUE, "a host namespace": r"\bhost(Network|PID|IPC)\s*:" + TRUE,
    "an Application": kind_line("Application|ApplicationSet|AppProject"),
    # the group with its version, or alone with no version (no object of the cluster, but a reading of the door's)
    "an external-secrets kind": ITEM + r"apiVersion[ \t]*:\s*[\"']?(?i:(?:[\w-]+\.)*external-secrets\.io)(?:/|" + END + ")",
    "a CRD": kind_line("CustomResourceDefinition"),
    "a webhook": kind_line("(?:Mutating|Validating)WebhookConfiguration"),
    "a new LoadBalancer": r"\btype\s*:\s*[\"']?LoadBalancer\b", "a Secret object": kind_line("Secret"),
    "RBAC": kind_line("Role|ClusterRole|RoleBinding|ClusterRoleBinding"),
    "a Tailscale operator setting": r"tailscale\.com/tags\s*:|" + kind_line("ProxyClass"),
}
SECRET_KIND = re.compile(MANIFEST_REFUSED["a Secret object"], re.M)
SECRET_TOP = re.compile(r"^(?i:kind)[ \t]*:\s*[\"']?(?i:Secret(?:List)?)" + END, re.M)
SECRET_DATA = re.compile(ITEM + r"(?i:data|stringData)[ \t]*:", re.M)
LIST_TOP = re.compile(kind_line(r"\w*List"), re.M)        # a List of objects, at any depth of a JSON array of them
KEY_AT = re.compile(r"^([ \t]*(?:-[ \t]+)*)(?i:(kind)[ \t]*:\s*[\"']?(?i:Secret(?:List)?)" + END +
                    r"|(apiVersion)[ \t]*:)", re.M)


def secret_object(text):
    """True when a block-style text holds a Secret object: the kind at the top level of a document; or the kind at
    any depth with an apiVersion key at its own depth, which makes it an object (an extra object of a chart), or in
    a List, or in a text that has a data or a stringData key. A text that only names the kind, as an Application's
    ignoreDifferences and a patch's target do, holds none."""
    if SECRET_TOP.search(text):
        return True
    if not SECRET_KIND.search(text):
        return False
    if SECRET_DATA.search(text) or LIST_TOP.search(text):
        return True
    found = [(len(m.group(1)), bool(m.group(2))) for m in KEY_AT.finditer(text)]
    kinds, versions = {d for d, kind in found if kind}, {d for d, kind in found if not kind}
    return bool(kinds & versions)


# The keys whose value a pattern reads: it stands on the key's own line, with no escape and as no block scalar.
READ_VALUES = ("kind", "apiVersion", "type", "channel", "serviceAccountName", "storage")
DQ, SQ = r'"(?:[^"\\]|\\.)*"', r"'(?:[^']|'')*'"
PLAIN = (r"(?:[\w./~+=$^(]|-(?=[\w.$-]))"       # a plain value of a flow sequence: no `: `, no comma, bracket or brace
         r"(?:[^\s,\[\]{}#:]|:(?=[^\s,\[\]{}])|[ \t]+(?=[^\s,\[\]{}#:]))*")
NOT_PLAIN = "\"'{[|>&*!%@`"                    # what a plain key or a plain value never starts with
FLOW_ONE = f"(?:{DQ}|{SQ}|{PLAIN})"
FLOW_LIST = re.compile(rf"\[[ \t]*(?:{FLOW_ONE}[ \t]*(?:,[ \t]*{FLOW_ONE}[ \t]*)*(?:,[ \t]*)?)?\]")
NPM_AGE = 7 * 86400          # min-release-age=7, which npm ci does not check on a lockfile: the door does


class Decision:
    """kind: read | rule | own (the agent's own call) | full (what the next mode allows: it runs only with the owner's
    signed yes to that exact call) | refused. why: one line for the agent and the record. form, args: what the door
    runs. host, window, reboot: what the door's order needs. route: what the caller of a refusal can do next, when it is
    not "none" (door.py ROUTES): holder, with needs (the needs_access name of what it lacks, server:<host>) and level."""

    def __init__(self, kind, why, **more):
        self.kind, self.why = kind, why
        self.target = more.get("target")
        self.form, self.args = more.get("form"), more.get("args") or []
        self.host, self.window, self.reboot = more.get("host"), more.get("window"), more.get("reboot", False)
        self.business = more.get("business")
        self.write = more.get("write", kind in ("rule", "own", "full"))
        self.route, self.needs, self.level = more.get("route"), more.get("needs"), more.get("level")
        self.plan = more.get("plan")            # what the door runs: a provider's requests, a commit, a deploy
        # what the door sends on the host's stdin: (random, None) or (key, app:<app>:<NAME>) for a setting (N4), and
        # (runner, <owner>/<repo>, <runner name>) for a runner (N6)
        self.value = more.get("value")
        # what a call hash covers besides the call's own content: a prune's list, which the door made (X3)
        self.hash_content = more.get("hash_content")

    def __repr__(self):
        return f"Decision({self.kind}, {self.why!r})"


def refused(why, **more):
    return Decision("refused", why, **more)


def vendor(repo):
    """One of the product's own repositories, in whatever case its name comes: GitHub reads names in any case."""
    return isinstance(repo, str) and repo.lower() in {r.lower() for r in VENDOR_REPOS}


def glob_match(path, pattern):
    """A pattern of the commit rules at any depth: "x/**" covers everything under any folder x."""
    parts = path.split("/")
    if pattern.endswith("/**"):
        head = pattern[:-3]
        return any("/".join(parts[i:i + head.count("/") + 1]) == head for i in range(len(parts)))
    return any(fnmatch.fnmatchcase("/".join(parts[i:]), pattern) for i in range(len(parts)))


def never_path(path):
    """The commit rule that covers this path, in whatever case its name comes: a checkout on a disk that does not
    tell the cases apart, as a Mac's, reads claude.md as CLAUDE.md."""
    low = path.casefold()
    return next((p for p in NEVER_PATHS if glob_match(low, p.casefold())), None)


# ---------------------------------------------------------------- one call

def decide(access, agent, target, op, args, content=None, lookups=None):
    """The decision on one call of one agent. `access` is the access file, `content` the bytes that came with the
    call, and `lookups` the facts some checks need from outside (the npm registry, a release run), which door.py
    fills and the tests stub. Never raises for a caller's mistake: it refuses."""
    me = (access.get("agents") or {}).get(agent)
    if me is None:
        return refused("this caller is not in the door's access file")
    if not isinstance(target, str) or not TARGET.fullmatch(target):
        return refused("the target is a host, or <kind>:<name>")
    if not isinstance(op, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,40}", op):
        return refused("the action is a word like restart or dns-cname")
    if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
        return refused("the arguments are text")
    if content is not None and len(content) > CONTENT_MAX:
        return refused(f"the content is over {CONTENT_MAX // 1024} KiB: it is refused, never cut")
    never = access.get("never") or {}
    kind, _, name = target.partition(":")
    if not name:
        return decide_host(access, agent, me, target, op, args, never, content, lookups or {})
    if kind in ("commit", "deploy", "gitops"):
        if vendor(name) or name.lower() in {r.lower() for r in never.get("repos") or []}:
            return refused(f"{name} is never a target of the door")
        if not REPO.fullmatch(name):        # the door reads the head of no other name (door.Door.lookups)
            return refused(f"{name} is no repository's name, owner/repository")
        if kind == "commit":
            return decide_commit(access, agent, me, name, op, args, content, lookups or {})
        if kind == "deploy":
            return decide_deploy(access, me, name, op, args, lookups or {})
        return decide_gitops(access, me, name, op, args, content, lookups or {})
    if kind == "db":
        return decide_db(access, agent, me, name, op, args, never, content)
    if kind == "door":
        return decide_door(access, me, name, op, args, content)
    import door_providers
    if kind not in door_providers.PROVIDERS:
        return refused(f"{kind} is no kind of target")
    if f"{kind}:{name}" in (never.get("accounts") or []):
        return refused(f"{target} is never a target of the door")
    missing = None if target in (access.get("credentials") or {}) else door_providers.no_key(target)
    if missing:
        return refused(missing[0], route=missing[1])
    if target not in (me.get("providers") or []):
        return refused(f"{agent} holds no grant on {target}", route="holder")
    return door_providers.decide(access, agent, kind, name, op, args, content, lookups or {})


# ---------------------------------------------------------------- the door's own server

# What the agent that holds the fleet's own servers reads of the door's own server, which no host form reaches: the
# door patches itself, and no agent has root there. The door runs each read as its own user, with no root, no argument
# of the caller's, no file's content and no journal, whose lines name every business's calls: the argv reads of
# host/ops-read, the same programs that the holder reads on each host.
DOOR_SELF_READS = ("uptime", "df", "free", "swap", "ps", "listen", "packages", "upgradable", "failed", "units",
                   "timers", "lsblk", "findmnt")


def decide_door(access, me, name, op, args, content=None):
    """The decision on one call to door:self (the review rounds of 19 November 2026 could not read the door's own
    server). Only for an agent that holds a host of kind fleet, which the owner's app gives to the one agent that holds
    the fleet's own servers."""
    target = f"door:{name}"
    if name != "self":
        return refused("the door's own server is door:self", target=target)
    if not any(level == "fix" and ((access.get("hosts") or {}).get(host) or {}).get("kind") == "fleet"
               for host, level in (me.get("servers") or {}).items()):
        return refused(f"{target} is for the agent that holds the fleet's own servers", target=target, route="holder")
    if op not in DOOR_SELF_READS:
        return refused(f"{target} takes the reads {', '.join(DOOR_SELF_READS)}", target=target)
    if args or content:
        return refused(f"{op} of {target} takes no argument and no content", target=target)
    return Decision("read", f"the fixed read {op} of the door's own server, as the door's own user", target=target,
                    plan={"self_read": op}, write=False)


# ---------------------------------------------------------------- databases

# Incident intake, part 4: a database through the door. The agent sends SQL and gets rows, or the count of changed
# rows; the door holds the logins, and no password enters a session. The database refuses, not the door: the door
# parses no SQL to decide. `query` runs with a login that can only read, `change` and `dry` with one that reads and
# writes rows and can create, alter and drop nothing.
DB_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")     # as the hub names a provider's account (hub.DOOR_CREDENTIAL)
DB_ENGINES = ("postgresql", "sqlserver")
DB_LEVELS = ("read", "data")
DB_OPS = {"query": "read", "change": "data", "dry": "data"}     # the level that each action needs
DB_SECONDS, DB_SECONDS_MAX = 30, 300        # how long one statement may run: the default, and the most


def decide_db(access, agent, me, name, op, args, never, content=None):
    """The decision on one call to db:<name>. A read is a read. A change is the agent's own call, which it answers
    for: no yes of the owner and no window, because the grant is the authorization (the owner: an agent that owns a
    product's data may change all of it). `dry` is a change that the door rolls back; it needs the level of a
    change, because SQL can end its transaction itself and the locks are the same. The plan is what the door's
    database helper runs: {db, engine, op, seconds}."""
    target = f"db:{name}"
    db = (access.get("databases") or {}).get(name)
    # One answer for a name that is no database and for a database of another business, before every other check:
    # an agent of one business does not learn from the door's words which databases another business has.
    if db is None or db.get("business") != me.get("business"):
        return refused(f"{target} is no database of this agent's business at the door", target=target)
    if target in (never.get("accounts") or []):
        return refused(f"{target} is never a target of the door", target=target)
    if op not in DB_OPS:
        return refused("a database takes query, change and dry, each with its SQL as content", target=target)
    level = (me.get("databases") or {}).get(name)
    if level not in DB_LEVELS:
        return refused(f"{agent} holds no grant on {target}", target=target, route="holder", needs=target,
                       level=DB_OPS[op])
    if DB_OPS[op] == "data" and level != "data":
        return refused(f"{op} writes rows, and {agent} holds {target} at read", target=target, route="holder",
                       needs=target, level="data")
    try:
        sql = (content or b"").decode("utf-8")
    except UnicodeDecodeError:
        return refused("the SQL is text in UTF-8", target=target)
    if not sql.strip() or "\0" in sql:
        return refused(f"{op} takes its SQL as content, as text", target=target)
    seconds = DB_SECONDS
    if args:
        if len(args) != 1 or not re.fullmatch(r"[1-9][0-9]{0,2}", args[0]) or int(args[0]) > DB_SECONDS_MAX:
            return refused(f"the one argument is the seconds that a statement may run, 1 to {DB_SECONDS_MAX}",
                           target=target)
        seconds = int(args[0])
    plan = {"db": name, "engine": db["engine"], "op": op, "seconds": seconds}
    if op == "query":
        return Decision("read", f"a query with the read login of {target}", target=target, plan=plan,
                        business=db["business"])
    return Decision("own", f"rows of {target} change" if op == "change" else
                    f"a change of {target} that the door rolls back", target=target, plan=plan,
                    business=db["business"])


# ---------------------------------------------------------------- hosts

def rule_only_refusal(access, name, h, lookups, what, **more):
    """The refusal of `what` (what a rule-only host does not take) on rule-only host `name`, with its true cause as far
    as the door's file says it. Root on the hub's server, on the door's own and on a machine of the fleet opens keys of
    the whole fleet (door.own_server), and on a host that agents of two businesses hold at Fix it opens each one's:
    code keeps both rule-only, so no route is left. For any other rule-only host the file does not say why: the
    manager's hold, the host's own install, or a second business tag on the server, which the owner's app reads from
    Tailscale and the file does not keep (DoorAccess.plan keeps one business). The hub knows the hold, so the route is
    to ask (on 17 November 2026 the words of the first kind, said for a held server of one business, sent its holder
    and the manager to "only Founderizer code" for two days, while one call of the manager ended the hold)."""
    own = (lookups or {}).get("own_server")
    keys = own(h) if own else ("fleet" if h.get("kind") == "fleet" or
                               h.get("address") == (access.get("hub") or {}).get("address") else None)
    if keys:
        return refused(f"{name} is rule-only: it holds the fleet's own keys, so {what}", **more)
    # every agent that holds a server has a business in a file that door.validate_access took
    held_by = {a.get("business") for a in (access.get("agents") or {}).values()
               if isinstance(a, dict) and (a.get("servers") or {}).get(name) == "fix"}
    if len(held_by) > 1:
        return refused(f"{name} is rule-only: agents of two businesses hold it at Fix, so {what}", **more)
    return refused(f"{name} is rule-only at the door, so {what}. The door's file does not say why: the manager's "
                   f"hold, the server's own install or a second business on the server made it rule-only",
                   **dict(more, route="ask", needs=f"server:{name}"))


def decide_host(access, agent, me, host, op, args, never, content=None, lookups=None):
    h = (access.get("hosts") or {}).get(host)
    if h is None or host in (never.get("hosts") or []):
        return refused(f"{host} is no host of the door" if h is None else f"{host} is never a target of the door")
    level = (me.get("servers") or {}).get(host)
    # what the agent lacks, by the name that ask_my_requester's needs_access takes: the hub names the agent that holds it
    lacks = {"route": "holder", "needs": f"server:{host}", "level": "read" if op in OPS_READ.READS else "fix"}
    if level not in ("read", "fix"):
        return refused(f"{agent} holds no grant on {host}", **lacks)
    common = {"target": host, "host": host, "business": h.get("business")}
    if op in OPS_READ.READS:
        try:
            OPS_READ.check_read(op, args)
        except OPS_READ.Refused as e:
            return refused(str(e), **common)
        return Decision("read", f"the fixed read {op}", form=op, args=args, write=False, **common)
    if op in DOOR_ONLY:
        return refused(f"{op} is the door's own form", **common)
    if op not in OPS_ROOT.FORMS:
        return refused(f"{op} is not listed for a host: `help` lists the forms", **common)
    if level != "fix":
        if op == "look":            # incident intake, part 3: the wide read is the Fix holder's, who can write there
            return refused(f"{agent} holds Read on {host}: look reads a host's files for the agent that holds it at "
                           f"Fix", **dict(common, **lacks))
        return refused(f"{agent} holds Read on {host}: no write", **dict(common, **lacks))
    try:
        checked = OPS_ROOT.check_args(op, list(args))
    except OPS_ROOT.Refused as e:
        return refused(str(e), **common)
    # A machine of the fleet, a server that runs agents or the hub: ops-root runs no form there that compares or
    # deletes a file (FLEET_REFUSED), and the door says so first, with the host's own reason
    if h.get("kind") == "fleet" and op in OPS_ROOT.FLEET_REFUSED:
        return refused(f"{host} is a machine of the fleet, where agents run and their keys are: {op} "
                       f"{OPS_ROOT.FLEET_REFUSED[op]} there", **common)
    value = None
    if op in DOOR_VALUE:            # N4: 32 random bytes of the door, or the key that the owner saved for this setting
        if content:
            return refused(f"{op} takes no content: the door makes the value, or sends the owner's key", **common)
        value = ("random", None)
        if checked[2] == "key":
            name = f"app:{checked[0]}:{checked[1]}"
            if name not in (me.get("providers") or []) or name not in (access.get("credentials") or {}):
                return refused(f"no key of yours is saved for the door as {name}: ask the owner for it with "
                               f"request_secret, with door {name}", **common)
            value = ("key", name)
    elif op == "runner-new":        # N6: only the repository that the door made for this app, by its own record
        if content:
            return refused("runner-new takes no content: the door sends its tokens", **common)
        mine = [r for r in ((lookups or {}).get("made_app") or (lambda app: []))(checked[0])
                if isinstance(r, dict) and r.get("agent") == agent and REPO.fullmatch(str(r.get("repo")))]
        if len(mine) != 1:
            return refused(f"the door made no repository {checked[0]} for this agent, so it makes no runner for it",
                           **common)
        value = ("runner", mine[0]["repo"], re.sub(r"[^a-z0-9-]", "-", f"{host}-{checked[0]}")[:64])
    elif op in HOST_CONTENT and not content:
        return refused(f"{op} takes its bytes as the call's content", **common)
    f = OPS_ROOT.FORMS[op]
    more = dict(common, form=op, args=checked, window=f["window"], reboot=f["reboot"], write=f["write"], value=value)
    if f["kind"] == "look":
        # The holder's wide read (incident intake, part 3): a script that reads the host's files in a box with no
        # write and no network, which the host builds and proves itself (ops-root, look_box and look_proved). It is
        # a read: no yes of the owner, no hash for one, no window, no host lock and no rollback timer.
        if h.get("mode") != "fix":
            return rule_only_refusal(access, host, h, lookups, "no look runs there", **more)
        if me.get("business") != h.get("business"):     # as Full access asks it (door.Door.full_access)
            return refused(f"{host} is a server of another business than {agent}'s: no look there", **more)
        return Decision("read", "the holder's wide read: a script in a box with no write and no network", **more)
    if f["kind"] in ("own", "full"):
        if h.get("mode") != "fix":          # Patch only is code's: no yes of the owner lifts it, so no hash asks for it
            return rule_only_refusal(access, host, h, lookups, "only rule forms run there, and no file install",
                                     **more)
        if f["kind"] == "full":             # door-modes proposal, step 3: the owner's yes runs that exact call once
            return Decision("full", f"{op} {NO_BOX}, which no grant on {host} covers", **more)
        return Decision("own", f"the host form {op}", **more)
    # N4: a new app lives on a fix host only. ops-root refuses it there too, but the door refuses it first, before it
    # makes a value or a runner's tokens for a call that the host will not run.
    if op in OPS_ROOT.PLAN_WRITES and h.get("mode") != "fix":
        return rule_only_refusal(access, host, h, lookups, "no form of a new app writes there", **more)
    return Decision("rule" if f["write"] else "read", f"{op} is a rule call", **more)


# ---------------------------------------------------------------- workflow files (new-projects plan N5)
#
# The developer of a repository that the door made holds write, and GitHub refuses a push with write that changes
# .github/workflows on any branch. So those files come only through the door, for the Operator that made the
# repository, by the door's own record and not by the hub's grants. The door reads each workflow as JSON, which GitHub
# reads as YAML too, so that its checks see what GitHub runs, and it commits its own serialization of what it checked.
# The deploy workflow is the product's template with the app's name and the artifact's name. Every other job runs on
# GitHub's runners, with no job-level uses, no secret but GITHUB_TOKEN, no id-token write, and no trigger
# pull_request_target or workflow_run. With these checks, such a commit is a rule call.

WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.ya?ml")
# The file name alone, as a dispatch names it: a GitOps target's caller workflow (`sync`, DevOps plan X3)
WORKFLOW_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.ya?ml")
DEPLOY_PATH = ".github/workflows/deploy.yml"
ARTIFACT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
GITHUB_RUNNERS = ("ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04")
WORKFLOW_KEYS = {"name", "run-name", "on", "permissions", "env", "defaults", "concurrency", "jobs"}
REFUSED_TRIGGERS = ("pull_request_target", "workflow_run")
DEPLOY_CONTRACT = (
    "The deploy workflow runs after each green run of the workflow named CI for a push to the default branch. That "
    "run uploads one artifact named <artifact> that holds <artifact>.tar.gz, the tree of the release, and "
    "<artifact>.tar.gz.sha256, the output of sha256sum for it. The deploy job runs on the app's own runner, downloads "
    "that artifact and gives it to the release helper, which checks its SHA-256, unpacks it as current and restarts "
    "the app's unit. The app listens on 127.0.0.1 at the port in PORT, reads its settings from its environment, and "
    "its health path answers 200 with APP_RELEASE_SHA, the commit's sha, in its body. Every other job runs on GitHub's "
    "runners (ubuntu-latest), with no job-level uses, no secret but GITHUB_TOKEN, no id-token write, and no trigger "
    "pull_request_target or workflow_run. The door commits each workflow as JSON, which GitHub reads as YAML.")
DOWNLOAD = (
    'set -euo pipefail\n'
    'dir="$RUNNER_TEMP/release-$RUN_ID"\n'
    'rm -rf "$dir" && mkdir -p "$dir"\n'
    'list="$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/actions/runs/$RUN_ID/artifacts?name=$ARTIFACT"\n'
    'url=$(curl -fsS -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" "$list" | '
    'python3 -c \'import json, sys; a = [x for x in json.load(sys.stdin)["artifacts"] if not x["expired"]]; '
    'print(a[0]["archive_download_url"] if len(a) == 1 else "")\')\n'
    'test -n "$url"\n'
    'curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -o "$dir/artifact.zip" "$url"\n'
    'python3 -c \'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])\' "$dir/artifact.zip" '
    '"$dir"\n')


def deploy_workflow(app, artifact):
    """The product's deploy workflow: after a green CI run of a push to the default branch, it downloads that run's
    artifact on the app's own runner and gives it to the release helper. It checks out nothing and runs no action."""
    run = "${{ github.event.workflow_run.id }}"
    folder = "$RUNNER_TEMP/release-$RUN_ID/$ARTIFACT.tar.gz"
    return {
        "name": "Deploy",
        "on": {"workflow_run": {"workflows": ["CI"], "types": ["completed"]}},
        "permissions": {"actions": "read"},
        "concurrency": {"group": "deploy", "cancel-in-progress": False},
        "env": {"APP": app, "ARTIFACT": artifact},
        "jobs": {"deploy": {
            "if": "github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push' && "
                  "github.event.workflow_run.head_branch == github.event.repository.default_branch && "
                  "github.event.workflow_run.head_repository.full_name == github.repository",
            "runs-on": ["self-hosted", app],
            "timeout-minutes": 30,
            "steps": [
                {"name": "Download the artifact of the CI run",
                 "env": {"GH_TOKEN": "${{ github.token }}", "RUN_ID": run}, "run": DOWNLOAD},
                {"name": "Release it",
                 "env": {"RUN_ID": run, "SHA": "${{ github.event.workflow_run.head_sha }}"},
                 "run": f'sudo -n "/usr/local/sbin/$APP-deploy" deploy "{folder}" "{folder}.sha256" "$SHA"\n'}]}}}


def canonical(workflow):
    "The bytes that the door commits for a workflow that it checked: JSON, which GitHub reads as YAML."
    return (json.dumps(workflow, indent=2, ensure_ascii=False) + "\n").encode()


EXPRESSION_MARK = re.compile(r"'|\}\}")     # in a ${{ }} expression: a quoted text's quote, or the expression's end


def expressions(text):
    """The texts of the ${{ }} expressions of one text of a workflow, as GitHub reads them: a }} inside a quoted text
    ('...', with '' for a quote in it) ends nothing, and an expression with no end runs to the end of the text. Each
    text holds the text up to the first }} after each ${{ inside it, so a reading that ends at the first }} finds
    nothing more. One pass over the text (a search for an end from each ${{ read the rest again)."""
    out, at = [], 0
    while True:
        start = text.find("${{", at)
        if start < 0:
            break
        mark = EXPRESSION_MARK.search(text, start + 3)
        while mark is not None and mark.group() == "'":
            close = text.find("'", mark.end())
            mark = None if close < 0 else EXPRESSION_MARK.search(text, close + 1)
        end = len(text) if mark is None else mark.start()
        out.append(text[start + 3:end])
        at = end + 2
    return out


def secret_use(node, key=None):
    """The first use of a secret other than GITHUB_TOKEN: in a ${{ }} expression, in an if (an expression with no
    marks), or a secrets key (a called workflow's or a trigger's)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "secrets":
                return "a secrets key"
            found = secret_use(v, k)
            if found:
                return found
    elif isinstance(node, list):
        for v in node:
            found = secret_use(v, key)
            if found:
                return found
    elif isinstance(node, str):
        for text in expressions(node) + ([node] if key == "if" else []):
            if re.search(r"\bsecrets\b", re.sub(r"\bsecrets\s*\.\s*GITHUB_TOKEN\b", "", text, flags=re.I), re.I):
                return f"the secret in {text.strip()[:80]!r}"
    return None


def workflow_problem(path, workflow, app):
    """What code refuses in one workflow file of a repository that the door made, or None."""
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict) or not jobs or not all(isinstance(j, dict) for j in jobs.values()):
        return f"{path} is a workflow: an object with its jobs, each an object"
    if path == DEPLOY_PATH:
        env = workflow.get("env") if isinstance(workflow.get("env"), dict) else {}
        artifact = env.get("ARTIFACT")
        if not isinstance(artifact, str) or not ARTIFACT.fullmatch(artifact) or \
                workflow != deploy_workflow(app, artifact):
            return (f"{DEPLOY_PATH} is the product's deploy workflow, with only the app's name and the artifact's "
                    f"name filled in: `ops commit:<owner>/{app} deploy-template <artifact>` gives its text")
        return None
    if set(workflow) - WORKFLOW_KEYS:
        return f"{path}: {sorted(set(workflow) - WORKFLOW_KEYS)[0]} is not a key of a workflow"
    on = workflow.get("on")
    triggers = [on] if isinstance(on, str) else list(on) if isinstance(on, (list, dict)) else None
    if not triggers or not all(isinstance(t, str) for t in triggers):
        return f"{path}: on names the workflow's triggers"
    for trigger in triggers:
        if trigger in REFUSED_TRIGGERS:
            return f"{path}: no workflow of a repository that the door made has the trigger {trigger}"
    asks = [("the workflow", workflow.get("permissions"))] + [(f"the job {k}", j.get("permissions"))
                                                              for k, j in jobs.items()]
    for where, permissions in asks:
        if permissions == "write-all" or (isinstance(permissions, dict) and permissions.get("id-token") == "write"):
            return f"{path}: {where} asks for id-token write, which no workflow of a repository that the door made has"
    for name, job in jobs.items():
        if "uses" in job:
            return f"{path}: the job {name} calls a workflow with uses, which the door does not read"
        if job.get("runs-on") not in GITHUB_RUNNERS and job.get("runs-on") not in [[r] for r in GITHUB_RUNNERS]:
            return (f"{path}: the job {name} runs on one of GitHub's runners ({', '.join(GITHUB_RUNNERS)}): only "
                    f"the deploy workflow runs on the app's own runner")
    found = secret_use(workflow)
    if found:
        return f"{path}: {found}: a repository that the door made has no secret but GITHUB_TOKEN"
    return None


def decide_workflows(repo, made, files, message, branch=None):
    """A commit of workflow files only, for the Operator that made the repository through the door, on the branch that
    the decision read (branch)."""
    app, target, out = made.get("app") or repo.split("/", 1)[1], f"commit:{repo}", []
    for path, data, mode in files:
        if data is None:
            out.append((path, None, mode))
            continue
        try:
            workflow = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return refused(f"{path}: the door reads a workflow as JSON, which GitHub reads as YAML too. Write it as "
                           f"JSON, with the same keys", target=target)
        why = workflow_problem(path, workflow, app)
        if why:
            return refused(why, target=target)
        out.append((path, canonical(workflow), "100644"))
    return Decision("rule", "workflow files of a repository that the door made, checked by code", target=target,
                    plan={"repo": repo, "files": out, "message": message, "branch": branch})


def decide_template(repo, made, args):
    if len(args) != 1 or not ARTIFACT.fullmatch(args[0]):
        return refused("deploy-template takes the artifact's name: letters, digits, dots, hyphens and underscores")
    app = made.get("app") or repo.split("/", 1)[1]
    text = canonical(deploy_workflow(app, args[0])).decode()
    return Decision("read", "the product's deploy workflow", target=f"commit:{repo}", write=False,
                    plan={"text": json.dumps({"path": DEPLOY_PATH, "text": text, "contract": DEPLOY_CONTRACT},
                                             indent=2)})


# ---------------------------------------------------------------- commits

def repo_entry(me, name, kinds):
    entry = (me.get("repos") or {}).get(name)
    return entry if isinstance(entry, dict) and entry.get("kind") in kinds else None


def commit_files(content):
    """[(path, bytes or None for a delete, mode)] and the message of a commit's content, or a reason."""
    try:
        body = json.loads(content or b"")
        message, files = body["message"], body["files"]
        if not isinstance(message, str) or not 0 < len(message) <= 2000 or not isinstance(files, list) or \
                not 0 < len(files) <= 200:
            raise ValueError
        out = []
        for f in files:
            path, mode = f["path"], f.get("mode", "100644")
            if isinstance(path, str) and len(path) > PATH_MOST:
                return None, f"a path of the commit has more than {PATH_MOST} characters"
            if isinstance(path, str) and path.count("/") > FOLDERS_MOST:
                return None, f"a path of the commit has more than {FOLDERS_MOST} folders"
            # no empty part, ".", ".." (a leading or trailing "/", "//"): never_path reads each path as it is written
            if not isinstance(path, str) or any(part in ("", ".", "..") for part in path.split("/")) or \
                    "\\" in path or "\0" in path:
                raise ValueError
            data = None if f.get("delete") is True else base64.b64decode(f["content"], validate=True)
            out.append((path, data, mode))
        return out, message
    except (ValueError, KeyError, TypeError):
        return None, "the content of a commit is {message, files: [{path, content (base64)} or {path, delete}]}"


def paths_clash(files):
    """Why a commit's paths are refused among themselves, or None: a path twice, or a path and a path under it (x and
    x/y), of which GitHub's tree keeps one; and two that differ only in case (a.txt and A.txt, Foo/x and foo), which a
    checkout that reads names in any case reads as one, as never_path does. No lookup."""
    paths = [path for path, _data, _mode in files]
    if len(set(paths)) != len(paths) or any(a.startswith(b + "/") for a in paths for b in paths):
        return "a path of the commit comes twice, or is a folder of another of its paths"
    folded = [path.casefold() for path in paths]
    if len(set(folded)) != len(folded) or any(a.startswith(b + "/") for a in folded for b in folded):
        return "two paths of the commit differ only in case, which some checkouts read as one name; a rename by case " \
               "only (README to Readme) is made outside the door"
    return None


def head_refused(files, lookups):
    """Why a commit is refused by what its paths are at the head of the branch (head_tree: {path: "file" | "folder" |
    "link"} of the whole tree there, one read of GitHub), or None (Reader A of 24 November 2026). A file written at a
    path that is a folder there replaces the whole folder (GitHub's tree API: "Entries defined in the tree parameter
    will overwrite items from base_tree with the same path"), and the rules of the paths under it (never_path) never
    see them go, as scripts/security in a devops repository; a file written at a link's path, or under a file or a link,
    replaces it. A delete of a path that is no file there (a folder, a link, or nothing) is refused: GitHub takes a
    null sha at a folder's path too. A path that differs from one there only in case is refused, as never_path reads
    names in any case (claude.md/x beside CLAUDE.md, scripts/Security). Without the lookup, every commit is refused."""
    tree = lookups.get("head_tree")
    if not tree:                # fail closed: a decision that cannot read the head commits nothing
        return "the door cannot read what the commit's paths are at the head of the branch, so it commits nothing"
    kinds = tree()
    folded = {}
    for known in kinds:
        folded.setdefault(known.casefold(), known)
    for path, data, _mode in files:
        parts = path.split("/")
        at = None
        for n in range(1, len(parts) + 1):
            here = "/".join(parts[:n])
            at = kinds.get(here)
            if at is None:
                other = folded.get(here.casefold())
                if other is not None:
                    return f"{here} differs only in case from {other} at the head of the branch, which some checkouts " \
                           f"read as one name; a rename by case only is made outside the door"
                break                   # nothing there: the rest of the path is new
            if n < len(parts) and at != "folder":
                return f"{here} is a file or a link at the head of the branch, and a file written under it would " \
                       f"replace it"
        if data is None and at != "file":
            return f"{path} is no file at the head of the branch (a folder, a link, or no file), so the commit deletes " \
                   f"nothing there"
        if data is not None and at == "folder":
            return f"{path} is a folder at the head of the branch, and a file written at its path would replace the " \
                   f"whole folder"
        if data is not None and at == "link":
            return f"{path} is a link or a submodule at the head of the branch, which the door does not replace"
    return None


def set_parent(plan, lookups):
    """The commit at the head that the decision read (head_sha) as its commit's one parent: GitHub.commit makes the
    commit on it, and reads the branch again before it moves it, so a branch that moved meanwhile is no commit."""
    sha = lookups.get("head_sha")
    if sha and not plan.get("parent"):
        plan["parent"] = sha()


def with_parent(d, lookups):
    """The decision with its commit's parent (set_parent)."""
    if d.kind != "refused" and isinstance(d.plan, dict):
        set_parent(d.plan, lookups)
    return d


def decide_commit(access, agent, me, repo, op, args, content, lookups):
    """A commit that the door makes. devops: any file outside the commit rules and scripts/ is a rule call, and
    scripts/ is the agent's own call. app: a checked lockfile fix, a checked image, a replica count or a dated scan
    exception is a rule call, and other paths are the agent's own call. gitops goes through gitops:<repo>. The workflow
    files of a repository that the door made go only through decide_workflows, for the agent that made it (N5)."""
    made = (lookups.get("made_repo") or (lambda name: None))(repo)
    mine = isinstance(made, dict) and made.get("agent") == agent
    if op == "deploy-template":
        return decide_template(repo, made, args) if mine else \
            refused(f"{repo} is no repository that the door made for this agent", target=f"commit:{repo}")
    if op != "push":
        return refused("a commit target takes push, with the files as content")
    if mine:
        files, message = commit_files(content)
        if files is not None and any(WORKFLOW.fullmatch(p) for p, _, _ in files):
            if not all(WORKFLOW.fullmatch(p) and m == "100644" for p, _, m in files):
                return refused("a commit of workflow files holds only workflow files (.github/workflows/<name>.yml, "
                               "mode 100644), with no other file", target=f"commit:{repo}")
            why = paths_clash(files) or head_refused(files, lookups)
            if why:
                return refused(why, target=f"commit:{repo}")
            d = decide_workflows(repo, made, files, message, (lookups.get("branch") or (lambda: None))())
            return with_parent(d, lookups)
    entry = repo_entry(me, repo, ("devops", "app"))
    if entry is None:
        return refused(f"the door commits nothing on {repo} for this agent", route="holder")
    files, message = commit_files(content)
    if files is None:
        return refused(message)
    for path, data, mode in files:
        if mode in ("120000", "160000"):
            return refused(f"{path} is a symlink or a gitlink, which no commit of the door makes")
        if mode not in ("100644", "100755"):
            return refused(f"{path} has the mode {mode}")
        hit = never_path(path)
        if hit:
            return refused(f"{path} is under the commit rules ({hit}), which no commit passes")
    why = paths_clash(files) or head_refused(files, lookups)
    if why:
        return refused(why, target=f"commit:{repo}")
    plan = {"repo": repo, "files": files, "message": message, "branch": entry.get("branch")}
    set_parent(plan, lookups)
    if entry["kind"] == "devops":
        if any(p == "scripts" or p.startswith("scripts/") for p, _, _ in files):
            return Decision("own", "a commit under scripts/", target=f"commit:{repo}", plan=plan)
        return Decision("rule", "a commit outside the commit rules and scripts/", target=f"commit:{repo}", plan=plan)
    reasons = []
    for path, data, _mode in files:
        why = app_path_rule(path, data, lookups, repo)
        if why is True:
            continue
        if isinstance(why, str) and why.startswith("refused:"):
            return refused(why[len("refused:"):].strip(), target=f"commit:{repo}")
        reasons.append(why or f"{path} is not a form of the rule calls")
    if reasons:
        return Decision("own", reasons[0], target=f"commit:{repo}", plan=plan)
    return Decision("rule", "a checked change of the listed forms", target=f"commit:{repo}", plan=plan)


def app_path_rule(path, data, lookups, repo):
    """True for a rule form, "refused: ..." for a refusal, else the reason that it is the agent's own call."""
    base = os.path.basename(path)
    if data is None:
        return f"{path} is deleted"
    if base == "package-lock.json":
        return lockfile_rule(path, data, lookups)
    if re.search(r"(^|/)scan-exceptions?/[^/]+\.(json|ya?ml)$", path):
        return exception_rule(data)
    old = (lookups.get("base_file") or (lambda p: None))(path)
    if old is None:
        return f"{path} is a new file"
    changed = changed_lines(old, data)
    if changed is None:
        return f"{path} changes more than its values"
    if all(REPLICAS_LINE.fullmatch(line) for line in changed):
        return True
    if all(IMAGE_LINE.fullmatch(line) for line in changed):
        return image_rule(old, data, lookups)
    return f"{path}: {changed[0].strip()[:80]} is not a listed form"


def changed_lines(old, new):
    """The new lines of a change that keeps the line count and changes lines in place, or None."""
    a, b = old.decode("utf-8", "replace").splitlines(), new.decode("utf-8", "replace").splitlines()
    if len(a) != len(b):
        return None
    return [y for x, y in zip(a, b) if x != y]


def same_keys(old, new):
    """True when each line that a change of equal line count changes keeps its key, with its indentation and its
    dash: only its value changes. Without it, a line of another key (privileged: false) could become a listed one
    (replicas: 2), which takes the first one out."""
    def key(line):
        found = re.match(r"\s*(?:-\s*)?[^:#\s]+\s*:", line)
        return found.group(0) if found else None
    a, b = old.decode("utf-8", "replace").splitlines(), new.decode("utf-8", "replace").splitlines()
    return len(a) == len(b) and all(key(x) is not None and key(x) == key(y) for x, y in zip(a, b) if x != y)


def listed_before(old, new):
    """True when each line that a change changes was a listed line at HEAD too. In a file that is not block style a
    line can hold more than its first key (a flow mapping over several lines, an include of a template), and a new
    listed line in its place takes the rest of it out."""
    a, b = old.decode("utf-8", "replace").splitlines(), new.decode("utf-8", "replace").splitlines()
    return len(a) == len(b) and all(LISTED_LINE.fullmatch(x) for x, y in zip(a, b) if x != y)


IMAGE_KEYS = ("image", "tag", "digest", "newTag", "newName")
# The start of a key line of a block mapping: its indentation with a list's dash, its key, and its colon, with a blank
# or the line's end after it (tag:1 is a text). One run of blanks at each place, so that no line takes a square time.
KEY_HEAD = re.compile(r"([ \t]*(?:-[ \t]+)?)([\w./-]+)[ \t]*:(?=[ \t]|$)")
BLOCK_MARK = re.compile(r"[|>][-+0-9]{0,2}")
BLOCK_TEXT = "\n|"       # the value of a key whose value is a block scalar's text: no value of one line is it
REGISTRY_WORD = re.compile(r"(?i)registry")
MOVES_IMAGES = re.compile(r"(?i)registry|parameters")      # also Argo CD's Helm parameters and fileParameters


def registry_line(line):
    """True when a line may give a key that names a registry (Bitnami's global.imageRegistry, which a chart reads
    before an image's own registry): a key line whose key holds the word; and any other line that holds it anywhere
    (an explicit key, an anchor that an alias takes as a key, a flow mapping) or that has a backslash and a double
    quote (an escape in a quoted key); and so for a key that holds parameters (an Argo CD Application's Helm parameters
    and fileParameters set any value of the chart, global.imageRegistry and image.repository too). A value of a key
    line that holds the word (https://registry...) is none. A known limit: a chart that moves its images under another
    key (Istio's global.hub) is not seen, nor what a later values file, an Argo CD Application's parameters or values in
    another file, or the chart's own default registry does to the image."""
    found = key_line(line)
    if found:
        return bool(MOVES_IMAGES.search(found[1]))
    return bool(MOVES_IMAGES.search(line)) or "\\" in line and "\"" in line
DOC_MARK = re.compile(r"(?:---|\.\.\.)(?=[ \t]|$)")
# a quoted text to its end, or to the line's end where it stays open (no closing group); a flow bracket; a comment
OPEN_MARKS = re.compile(r"\"(?:[^\"\\]|\\.)*(\")?|'(?:[^']|'')*(')?|[\[\]{}]|(?:^|[ \t])#")


def line_value(text):
    """A value of one line as YAML reads it, where this text says it, with its comment taken out: without its quotes,
    "" for none, and BLOCK_TEXT for a block scalar's mark; or None for an anchor, an alias, a tag, a flow collection
    other than {} and [], a list's dash, a quoted text that does not end on its line or that has an escape, and a
    key in it."""
    value = re.split(r"[ \t]#", text, 1)[0].strip(" \t")
    if value[:1] in ("\"", "'"):
        closed = len(value) > 1 and value[-1] == value[0] and value[0] not in value[1:-1] and "\\" not in value
        return value[1:-1] if closed else None
    if BLOCK_MARK.fullmatch(value):
        return BLOCK_TEXT
    if value and (value[0] in "&*!|>{}[]%@`,#?:" and value not in ("{}", "[]") and not FLOW_LIST.fullmatch(value)
                  or value[:2] in ("- ", "-") or ": " in value):
        return None
    return value


def left_open(text):
    """True when a value of one line leaves a quoted text or a flow collection open: YAML reads the lines after it as
    part of that value, and no reading by lines can say where it ends. One pass over the line's marks. A quote counts
    as the start of a quoted text only at the text's start, after a [, a { or a , (blanks between them), or after a :
    and a blank; any other (it's, [a 's, a:'s) is a letter for YAML, and this pass cannot tell where its quoted text
    would end, so it counts as open too."""
    depth, last, end = 0, "", 0
    for mark in OPEN_MARKS.finditer(text):
        token, gap = mark.group(0), text[end:mark.start()]
        between = gap.rstrip(" \t")
        last = between[-1] if between else last
        starts = last in ("", "[", "{", ",") or last == ":" and len(between) < len(gap)
        if token[0] in "\"'" and not starts:
            return True
        if token[0] == "\"" and mark.group(1) is None or token[0] == "'" and mark.group(2) is None:
            return True
        if token[-1] == "#":
            break
        depth += 1 if token in "[{" else -1 if token in "]}" else 0
        last, end = token[-1], mark.end()
    return depth != 0


def key_line(line):
    """(prefix, key, value) of a key line of a block mapping whose key and value YAML reads as this text says
    (line_value), or None for any other line: also a quoted key, a merge key (<<) and an explicit key (?)."""
    head = KEY_HEAD.match(line)
    value = head and line_value(line[head.end():])
    return None if value is None else (head.group(1), head.group(2), value)


def image_repo(ref):
    "An image's reference without its tag and its digest: a registry's port stays (host:5000/name:tag)."
    ref = ref.split("@", 1)[0]
    colon = ref.rfind(":")
    return ref[:colon] if colon > ref.rfind("/") else ref


def line_maps(lines):
    """For each line, the block mapping that it is a line of (an id, or None for a blank line, a comment or a document
    mark), the keys of each mapping with their values, and whether this reading of each mapping is sure, as the lines'
    indentation and list dashes say: a key at the column of an open mapping is one of its keys, a deeper key opens a
    mapping, a list's dash opens its item's mapping, a line further left closes each deeper one, and a document mark
    closes them all. A block scalar's text is read as a text of its own (an Argo CD Application's Helm values). Not
    sure: a mapping with a line that key_line cannot read (a tag, an anchor, a merge key, a quoted key); one that opens
    under a key with a value, with each mapping around it; and, after a quoted text or a flow collection that a line
    leaves open, each mapping of the rest of its document. One pass, so that each changed tag of a commit reads its own
    mapping in it."""
    ids, keys, sure, saved = [], [], [], []
    stack, opens, over, lost = [], True, None, False     # over: the column that a block scalar's text is deeper than
    for line in lines:
        rest = line.lstrip(" \t")
        indent = len(line) - len(rest)
        if not rest or rest.startswith("#"):
            ids.append(None)
            continue
        while over is not None and indent <= over:
            stack, opens, over, lost = saved.pop()
        if indent == 0 and DOC_MARK.match(rest):
            stack, opens, lost = [], True, False
            ids.append(None)
            continue
        dash = re.match(r"-(?:[ \t]+|$)", rest)
        while stack and stack[-1][0] > indent:
            stack.pop()
        if dash or not stack or stack[-1][0] < indent:
            stack.append((indent + (dash.end() if dash else 0), len(keys)))
            keys.append({})
            sure.append(not lost)
            if not (dash or len(stack) == 1 or opens):
                for _column, held in stack:
                    sure[held] = False
        mapping = stack[-1][1]
        ids.append(mapping)
        found = key_line(line)
        value = found[2] if found else line_value(rest[dash.end():]) if dash else None
        if found:
            keys[mapping].setdefault(found[1], []).append(value)
        if value == BLOCK_TEXT:
            saved.append((stack, False, over, lost))
            stack, opens, over = [], True, len(found[0]) if found else indent     # a text that is lost stays lost
        elif value is not None:
            opens = value == ""
        else:
            opens, sure[mapping] = False, False
            head = KEY_HEAD.match(line)
            if left_open(line[head.end():].lstrip(" \t") if head else rest[dash.end():] if dash else rest):
                lost = True
                for _column, held in stack:
                    sure[held] = False
    return ids, keys, sure


def image_name(keys, kustomize=False):
    """The one image that a mapping's keys name for its tag: for a tag, Helm's registry and repository (an empty
    registry is none) and an image key's own repository; for a newTag (kustomize), Kustomize's newName, else its name,
    in a mapping with none of Helm's keys. None where they name more than one or none, where such a key stands twice
    or has no value, or where another key holds registry (imageRegistryOverride)."""
    def one(key):
        values = keys.get(key) or []
        return values[0] if len(values) == 1 and values[0] != BLOCK_TEXT else None
    if any(REGISTRY_WORD.search(key) for key in keys if key != "registry"):
        return None             # a chart's own key that can move the image (imageRegistryOverride)
    if kustomize:
        if keys.keys() & {"registry", "repository", "image"}:
            return None
        return one("newName" if "newName" in keys else "name") or None
    names = set()
    if "repository" in keys:
        registry, repository = one("registry") if "registry" in keys else "", one("repository")
        if registry is None or not repository:
            return None
        names.add(f"{registry}/{repository}" if registry else repository)
    if "image" in keys:
        if not one("image"):
            return None
        names.add(image_repo(one("image")))
    return names.pop() if len(names) == 1 else None


def image_rule(old, new, lookups):
    """A checked change of image lines, each line by itself (decide_gitops and the listed forms of a repository of
    code give it only a change that keeps its lines in place and changes only these keys' values): an image keeps its
    repository, and a green release run of that repository made its new tag; a tag or a newTag is one of the image
    that its own mapping names (image_name: Helm's values, Kustomize's images), where this reading of the mapping is
    sure (line_maps), where no line outside that mapping may give a key of a registry (a chart's global.imageRegistry
    comes first), and a green release run made it; a newName is another repository; and no release run says that
    it made a digest. Each image is asked once: each ask is a call to GitHub. Before 23 November 2026 the rule read
    only the image lines, and in Helm's values it took the line after image: as the image, so a changed tag there was
    no check at all (the validator of the review of stage A)."""
    asked = {}

    def made(image):
        if image not in asked:
            asked[image] = (lookups.get("image_made") or (lambda image: False))(image)
        return asked[image]
    a, b = old.decode("utf-8", "replace").splitlines(), new.decode("utf-8", "replace").splitlines()
    if len(a) != len(b):
        return "the change does not keep its lines in place"
    maps = registries = None
    for i, (x, y) in enumerate(zip(a, b)):
        if x == y:
            continue
        before, after = key_line(x), key_line(y)
        if not before or not after or before[:2] != after[:2] or after[1] not in IMAGE_KEYS:
            return f"{y.strip()[:80]} is not a listed form"
        key, was, now = after[1], before[2], after[2]
        if key == "image":
            if image_repo(was) != image_repo(now):
                return f"the image changes its repository: {image_repo(was)} to {image_repo(now)}"
            if not made(now):
                return f"no green release run made {now}"
        elif key == "newName":
            return f"the image changes its repository: {was} to {now}"
        elif key == "digest":
            return f"no release run says that it made the digest {now[:80]}"
        else:
            ids, keys, sure = maps = maps or line_maps(b)
            registries = registries if registries is not None else \
                {ids[j] for j, line in enumerate(b) if ids[j] is not None and registry_line(line)}
            name = image_name(keys[ids[i]], key == "newTag") if ids[i] is not None and sure[ids[i]] else None
            if not name:
                return f"no image of its own mapping names the tag {now[:80]}"
            quoted = y[KEY_HEAD.match(y).end():].lstrip(" \t")[:1] in ("\"", "'")
            if not quoted and yaml_other(now):     # tag: 1.10 is deployed as 1.1, 010 as 8, yes as true
                return f"YAML reads the tag {now[:80]} as a number or a bool, so a chart may deploy another tag"
            if registries - {ids[i]}:
                return f"a registry outside the mapping of the tag {now[:80]} can move its image (global.imageRegistry)"
            if not made(f"{name}:{now}"):
                return f"no green release run made {name}:{now}"
    return True


def exception_rule(data):
    """A dated scan exception: one CVE, one version, at most 30 days, and extended once at most."""
    try:
        e = json.loads(data)
        until = calendar.timegm(time.strptime(e["until"], "%Y-%m-%d"))
        ok = re.fullmatch(r"(CVE-\d{4}-\d{4,}|GHSA(-[a-z0-9]{4}){3})", e["id"]) and isinstance(e["version"], str) \
            and 0 < until - time.time() <= 31 * 86400 and int(e.get("extended", 0)) <= 1
    except (ValueError, KeyError, TypeError, OverflowError):
        ok = False
    return True if ok else "the exception is not one dated CVE of one version for 30 days at most"


def lockfile_rule(path, data, lookups):
    """A checked lockfile fix (DevOps plan section 2). For each changed entry: `resolved` is on the registry,
    `integrity` equals the registry's, the version is 7 days old, the name exists already or the registry names it
    as a dependency, and no new install script appears. Too young is refused; any other failure makes the commit the
    agent's own call."""
    registry = lookups.get("npm") or (lambda name: None)
    old_text = (lookups.get("base_file") or (lambda p: None))(path)
    try:
        new = json.loads(data).get("packages") or {}
        old = json.loads(old_text).get("packages") or {} if old_text else {}
    except (ValueError, AttributeError):
        return "the lockfile is not JSON with packages"
    names_before = {key.rsplit("node_modules/", 1)[-1] for key in old if key}
    wanted = set()
    for key, e in new.items():
        if key and isinstance(e, dict):
            wanted.update((e.get("dependencies") or {}).keys())
            wanted.update((e.get("optionalDependencies") or {}).keys())
            wanted.update((e.get("peerDependencies") or {}).keys())
    root = new.get("") or {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        wanted.update((root.get(field) or {}).keys())
    for key, e in new.items():
        if not key or not isinstance(e, dict) or old.get(key) == e or e.get("link"):
            continue
        name = e.get("name") or key.rsplit("node_modules/", 1)[-1]
        doc = registry(name)
        version = e.get("version")
        if not isinstance(doc, dict) or version not in (doc.get("versions") or {}):
            return f"{name}@{version} is not on the registry"
        dist = doc["versions"][version].get("dist") or {}
        if e.get("resolved") != dist.get("tarball"):
            return f"{name}@{version} resolves somewhere else than the registry says"
        if e.get("integrity") != dist.get("integrity"):
            return f"{name}@{version} has another integrity than the registry's"
        published = (doc.get("time") or {}).get(version)
        try:
            age = time.time() - calendar.timegm(time.strptime(published[:19], "%Y-%m-%dT%H:%M:%S"))
        except (TypeError, ValueError):
            return f"{name}@{version} has no publish time"
        if age < NPM_AGE:
            return f"refused: {name}@{version} is younger than 7 days (min-release-age=7)"
        if name not in names_before and name not in wanted:
            return f"{name} is a new name that nothing names as a dependency"
        if e.get("hasInstallScript") and not (old.get(key) or {}).get("hasInstallScript"):
            return f"{name}@{version} brings an install script"
    return True


# ---------------------------------------------------------------- reading a manifest
#
# Code reads a manifest with patterns, line by line, and the standard library has no YAML parser. YAML can write the
# same manifest in forms that no line pattern reads: as JSON or in flow style ({"kind": "Pod", "spec": {"hostPID":
# true}}), with a quoted key ("privileged": true), through an anchor, an alias, a merge key or a tag, with its value on
# the next line, or in a text with an escape. So the door does not try to parse YAML: it refuses a YAML file that is
# not block style, where each line outside a block scalar is one plain key with its value, one item of a list, a
# document mark or a comment. A JSON file is parsed, and read as the block style lines that say the same.

def after_value(tail):
    "True when nothing but a comment follows a value on its line."
    return not tail.strip(" \t") or re.match(r"[ \t]+#", tail) is not None


def value_problem(value, key):
    """(why code cannot read the value of one line, whether it opens a block scalar). key is its key, or None for an
    item of a list. An empty flow mapping or sequence ({} and []) and a flow sequence of plain or quoted values on
    one line (args: ["a", "b"]) are read; a flow mapping is not, and neither is an expression of a template ({{ }})."""
    first = value[0]
    if first in "\"'":
        quoted = re.match(DQ if first == '"' else SQ, value)
        if not quoted or not after_value(value[quoted.end():]):
            return "a quoted text that does not end on its line", False
        if key in READ_VALUES and "\\" in quoted.group():
            return f"an escape in the value of {key}", False
    elif first in "{[":
        flow = re.match(r"\{\}" if first == "{" else FLOW_LIST, value)
        if not flow or not after_value(value[flow.end():]):
            return ("a flow mapping ({...}) or an expression of a template" if first == "{" else
                    "a flow sequence ([...]) that is not one line of plain values"), False
    elif first in "|>":
        head = re.match(r"[|>](?:[+-][1-9]?|[1-9][+-]?)?", value)
        if not after_value(value[head.end():]):
            return "text on the line that opens a block scalar", False
        if key in READ_VALUES:
            return f"a block scalar as the value of {key}", False
        return None, True
    elif first in NOT_PLAIN:
        return {"&": "an anchor", "*": "an alias", "!": "a tag"}.get(first, f"a value that starts with {first}"), False
    return None, False


def unread(text):
    """Why code cannot read this YAML text line by line, or None: the first form in it that is not block style. The
    lines of a block scalar (key: | and key: >) are text, and code reads only that they stand to the right of their
    key, as YAML asks; the patterns still read them, so a text that looks like a refused form is refused too."""
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85\u2028\u2029\ufeff]|\r(?!\n)", text):
        return "a character that ends a line or hides one, other than a line feed"
    # inside a block scalar, and after a plain text that can go on: the column that the next lines stand to the right of
    under = more = None
    for line in text.replace("\r\n", "\n").split("\n"):
        rest = line.lstrip(" ")
        indent = len(line) - len(rest)
        if not rest.strip(" \t"):
            continue
        if under is not None:
            if indent > under:
                continue
            under = None
        on, more = more, None
        if rest[0] == "\t":
            return "a tab in the indentation"
        if rest[0] == "#":
            continue
        if indent == 0 and re.match(r"(?:---|\.\.\.)(?=[ \t]|$)", rest):
            if not re.fullmatch(r"(?:---|\.\.\.)[ \t]*(?:#.*)?", rest):
                return "content on the line of a document mark"
            continue
        if indent == 0 and rest[0] == "%":
            return "a directive"
        dashes = re.match(r"(?:-(?:[ \t]+|$))*", rest)
        item, key = rest[dashes.end():].rstrip(" \t"), None
        if not item or item[0] == "#":          # dashes alone: the item is in the lines below
            continue
        if item[0] in "\"'":
            quoted = re.match(DQ if item[0] == '"' else SQ, item)
            if quoted and re.match(r"[ \t]*:", item[quoted.end():]):
                return "a quoted key"
        elif item[0] in "?:" and item[1:2] in ("", " ", "\t"):
            return "a key or a value with a mark of its own (? or :)"
        elif item[0] not in NOT_PLAIN:
            colon, comment = re.search(r":(?=[ \t]|$)", item), re.search(r"[ \t]#", item)
            if colon and not (comment and comment.start() < colon.start()):
                key, item = item[:colon.start()].rstrip(" \t"), item[colon.end():].strip(" \t")
                if key == "<<":
                    return "a merge key"
        why, opens = value_problem(item, key) if item and item[0] != "#" else (None, False)
        if why:
            return why
        plain = bool(item) and item[0] not in NOT_PLAIN + "#"
        if key is None and not dashes.end():
            # A line with no key and no dash. To the right of the key of a plain text, YAML reads it as the next line
            # of that text, as a tool writes a long one. Anywhere else it is the value of the key above, which code
            # would not read with its key.
            if on is None or indent <= on or not plain:
                return "a value on a line of its own, with no key and no dash"
            more = None if re.search(r"[ \t]#", item) else on
            continue
        column = indent + (dashes.end() if key is not None else rest.rindex("-", 0, dashes.end()))
        if opens:
            under = column
        elif plain and not re.search(r"[ \t]#", item):
            more = column
    return None


# The most that as_block and as_lines write out of parsed documents. A line starts with two spaces for each of its
# levels, and each level copies the lines in it: a JSON file of 41 KB with 900 levels took 17 s and 2.5 GB. The levels:
# the deepest real manifest known is the schema of a custom resource, about 35 levels (Argo CD's ApplicationSet,
# counted by hand along its path). The text: one limit for all that a commit and its render write out, after the
# commit and at HEAD, so that the patterns read it in about a second; a commit over it goes in parts.
TREE_LEVELS, TREE_TEXT = 64, 2 * 1024 * 1024


class TreeLimit(ValueError):
    "Parsed documents over the limits of tree_limit, which no code writes out as lines."


def tree_limit(docs):
    """Why code does not write these parsed documents out as lines (as_block, as_lines), or None: more than TREE_LEVELS
    levels of mappings and lists, or more than TREE_TEXT characters of lines (tree_size)."""
    size, why = tree_size(docs, TREE_TEXT)
    return why or (f"more than {TREE_TEXT // 2 ** 20} MB of lines, as code writes its keys and items out"
                   if size > TREE_TEXT else None)


def scalar_size(v):
    """The characters of a value that is no text, a mapping or a list, as as_block writes it (json.dumps), with no
    writing: a number of 4299 digits is about 0.302 of its bits, and a float is 24 at most."""
    if isinstance(v, bool) or v is None:
        return 5
    if isinstance(v, int):
        return int(v.bit_length() * 0.302) + 2
    return 24 if isinstance(v, float) else 0


def tree_size(docs, most):
    """(the characters of lines that as_lines writes of these parsed documents, with the spaces of each line's level
    and each line of a text on its own, counted up to a little more than most; why there are more than TREE_LEVELS
    levels of mappings and lists, or None). It is measured level by level, before any line is written."""
    size, level = 0, [doc for doc in docs if isinstance(doc, (dict, list))]
    for n in range(TREE_LEVELS):
        below = []
        for node in level:
            for key, v in node.items() if isinstance(node, dict) else ((None, v) for v in node):
                text = v if isinstance(v, str) else ""
                lines = len(text.splitlines())
                size += (2 * n + 4) * (1 + (lines if lines > 1 else 0)) + len(str(key or "")) + \
                    (len(text) if isinstance(v, str) else scalar_size(v))
                if isinstance(v, (dict, list)):
                    below.append(v)
            if size > most:
                return size, None
        if not below:
            return size, None
        level = below
    return size, f"more than {TREE_LEVELS} levels of mappings and lists"


def commit_tree_refusal(files, head_of, report):
    """Why the documents that code writes out as lines in a GitOps commit are too many, or None: of each file of the
    commit, after it and at HEAD (a JSON file as the door parses it, a YAML file as the render box's parser read it),
    and of each object that its render changes, before and after. Measured all at once, before any rule reads one of
    them, against one limit for them all: a limit for each file let a rule read a file before a later file was found
    over it, and many files at the limit took minutes. A deleted file counts only in a commit with a file that the
    rules read: its objects at HEAD are known to those rules. A YAML file with no render report counts nothing here,
    as code reads its text by lines and writes no lines of it."""
    read = any(data is not None for _path, data, _mode in files)

    def written():
        for path, data, _mode in files:
            old, info = head_of(path)
            if data is None and not read:
                continue
            if path.lower().endswith(".json"):
                yield False, path, json_docs(path, data)
                yield False, path, json_docs(path, old)
            else:
                yield False, path, info.get("after")
                yield False, path, info.get("before")
        for _uid, unit in sorted(((report or {}).get("units") or {}).items()):
            for group in unit.get("changed") or [] if unit.get("ok") else []:
                where = f"{unit_name(unit)}, rendered with {group['set']}: {group['object']}"
                yield True, where, group["before"]
                yield True, where, group["after"]
    used, most = 0, TREE_TEXT // 2 ** 20
    for render, where, docs in written():
        if not isinstance(docs, list):
            continue
        size, why = tree_size(docs, TREE_TEXT - used)
        if why:
            return f"{where} has {why}, after the commit or at HEAD, which the door does not read"
        used += size
        if used > TREE_TEXT and render:
            return (f"the objects that the commit's render changes have, with its files, more than {most} MB of lines "
                    f"as code writes their keys and items out, before and after the commit, which the door does not "
                    f"read at once: a person makes this commit outside the door")
        if used > TREE_TEXT:
            return (f"the commit's files have more than {most} MB of lines as code writes their keys and items out, "
                    f"after the commit and at HEAD, which the door does not read at once: commit fewer files at a "
                    f"time")
    return None


def as_block(value, depth=0):
    """A JSON value as the block style lines that say the same, for the patterns: one key or one item on each line."""
    def flat(v):
        return re.sub(r"\s+", " ", v) if isinstance(v, str) else json.dumps(v)
    pad, out = "  " * depth, []
    for key, v in value.items() if isinstance(value, dict) else [(None, v) for v in value]:
        out.append(pad + ("-" if key is None else flat(key) + ":"))
        out.append("\n" + as_block(v, depth + 1) if isinstance(v, (dict, list)) else " " + flat(v) + "\n")
    return "".join(out)


def as_lines(value, depth=0):
    """A JSON value as as_block writes it, but with each line of a text on a line of its own, below its key: a form
    inside a text value or a block scalar (an Application's helm.values) stands at the start of a line, where the
    patterns read it."""
    def flat(v):
        return re.sub(r"\s+", " ", v) if isinstance(v, str) else json.dumps(v)

    def text(v, pad):
        lines = v.splitlines() if isinstance(v, str) else []
        if len(lines) < 2:
            return " " + flat(v) + "\n"
        return " |\n" + "".join(f"{pad}  {flat(line)}\n" for line in lines)
    pad, out = "  " * depth, []
    for key, v in value.items() if isinstance(value, dict) else [(None, v) for v in value]:
        out.append(pad + ("-" if key is None else flat(key) + ":"))
        out.append("\n" + as_lines(v, depth + 1) if isinstance(v, (dict, list)) else text(v, pad))
    return "".join(out)


def lines_text(docs):
    "Documents as as_lines writes them, one document each: the second text of the count. TreeLimit: tree_limit."
    why = tree_limit(docs)
    if why:
        raise TreeLimit(why)
    return "---\n".join(as_lines(doc) for doc in docs if isinstance(doc, (dict, list)))


def no_key_twice(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("a key is there twice")
    return dict(pairs)


def manifest_text(path, data):
    """(the text of one file of the GitOps repository as the patterns read it, None), or (None, why code cannot read
    it). A YAML file is block style (unread); a JSON file, which a cluster's tools apply as they apply YAML, is read
    as block style lines; a file with another name is read as it is (a commit reads it loosely too: loose_read)."""
    name = path.lower()
    if not name.endswith((".yaml", ".yml", ".json")):
        return data.decode("utf-8", "replace"), None
    try:
        text = data.decode("utf-8")
        if not name.endswith(".json"):
            why = unread(text)
            return (None, why) if why else (text, None)
        value = json.loads(text, object_pairs_hook=no_key_twice)
        why = tree_limit([value])
        return (None, why) if why else ((as_block(value) if isinstance(value, (dict, list)) else text), None)
    except UnicodeDecodeError:
        return None, "bytes that are not UTF-8"
    except (ValueError, RecursionError):
        return None, "a JSON file that is not JSON with each key once"


def manifest_name(path):
    "True for a name that the block reader or the JSON parser reads: .yaml, .yml or .json, in any case."
    return path.lower().endswith((".yaml", ".yml", ".json"))


# The loose reading, for a text that the block reader does not read: a file of the GitOps repository with another name
# than .yaml, .yml or .json, which Kustomize takes as a resource and Helm renders as a template all the same, and a
# YAML file that its own people wrote in another style. It finds a word wherever it stands, and never says what the
# text means. LOOSE_WORDS are the words of every form that MANIFEST_REFUSED and the checks beside it refuse, the tag
# by which YAML reads a key from base64, and the directive that names a tag's handle. Role, Application and a secret
# volume are words of plain speech too, so LOOSE_KEYS takes them with their key, in the text with its quotes, spaces,
# tabs and braces taken out (the bare text).
# A key in a text that no parser reads, as go-yaml and Helm read one: the key and its own closing quote, then its colon
# (also after spaces and line breaks: a flow mapping's key), where a colon ends a key: before a space, a line break,
# the text's end or a flow mark, or after a quoted key ("k":v). A colon inside a word is no key's: secret-db:5432 and
# external-secrets:v0.9.1 name none. go-yaml and Helm refuse a key whose colon stands on a later line than the key,
# but an explicit key's (? key): after a ?, the word alone counts as the key (EXPLICIT), whatever comment lines stand
# before its colon. The bare text has no spaces, so there any colon ends a key (BARE_END). No quantifier stands inside
# another, and a pattern that reads a word starts only at the word's start, so no text makes the door's reading slow.
KEY_END = r"(?:[\"']\s*:|\s*:(?=[\s,\[\]{}]|$))"
BARE_END = r"\s*:"
# an explicit key's ? where a node starts, and the key's opening quote; after a colon and a list's dash too, for the
# bare text, which has no braces and no spaces ({? k} after a key's colon, - ? k)
EXPLICIT = r"(?<![^\s\[{,:-])\?\s*[\"']?"
# What may stand after a held key's colon before its value on a later line: a block scalar's mark, and comment lines
# (kind: # Deployment or Role, then the value). One line at a time, so that no text has two ways to be read.
BREAK = r"[\n\r\x85\u2028\u2029]"
AFTER = r"[ \t]*(?:[|>][-+0-9]{0,2}[ \t]*)?(?:(?:#[^\n\r\x85\u2028\u2029]*)?" + BREAK + r"[ \t]*)*"
AFTER_BARE = r"(?:[|>][-+0-9]{0,2})?(?:(?:#[^\n\r\x85\u2028\u2029]*)?" + BREAK + r")*"


def key_value(value, bare=False):
    """The rest of a held key's pattern after its name: its colon (KEY_END, or BARE_END in the bare text), what may
    stand before its value (AFTER), and the value's pattern, also after an anchor (&a Role); or a tag, which can make
    any value (!!binary); or an alias, whose anchor can hold any value: its name is the group alias, and it counts only
    where the text holds an anchor of that name (aliased), so that a * of Markdown (**Kind:**, a * list after "of this
    kind:") counts for nothing."""
    if bare:
        return BARE_END + AFTER_BARE + r"(?:!|\*(?P<alias>[\w-]+)|(?:&[\w-]*?\s*)?" + value + ")"
    return KEY_END + AFTER + r"(?:!|\*(?P<alias>[\w-]+)|(?:&[\w-]+\s+)?[\"']?" + value + ")"


def keyed(word, end=KEY_END, explicit=None):
    """A pattern of word as a key: with its end (KEY_END, BARE_END, key_value), or after the ? of an explicit key
    (EXPLICIT), where explicit, if given, is the whole key's pattern (a key that ends in the word), with no colon after
    it on its line, where the key's colon and its value say what it is (? kind: supplier is a key of a mapping, and a
    script's ternary)."""
    return r"(?:" + word + end + "|" + EXPLICIT + (explicit or word) + r"(?![\w.-])(?![ \t]*:))"


ANCHOR = re.compile(r"&([\w-]+)")


def aliased(pattern, text, anchors=None):
    """The matches of a held key's pattern (key_value) in a text, but one whose value is an alias that names no anchor
    of the text (ANCHOR, or anchors if given)."""
    anchors = set(ANCHOR.findall(text)) if anchors is None else anchors
    return [m for m in pattern.finditer(text) if not m.groupdict().get("alias") or m.group("alias") in anchors]


LOOSE_WORDS = ("secretkeyref", "secretref", "secretname", "hostpath", "privileged", "hostnetwork", "hostpid", "hostipc",
               "applicationset", "appproject", "external-secrets.io", "secrets-store.csi.x-k8s.io",
               "customresourcedefinition", "mutatingwebhookconfiguration", "validatingwebhookconfiguration",
               "loadbalancer", "clusterrole",
               "rolebinding", "clusterrolebinding", "tailscale.com/tags", "proxyclass", "upgrade.cattle.io",
               "serviceaccountname", "!!binary", "tag:yaml.org,2002:binary", "%tag")


TRUE_WORD = r"(?:true|yes|on|y)(?![a-z0-9])"
LOOSE_KEYS = {"kind: role": keyed("kind", key_value(r"role(?:list)?(?![a-z0-9])", bare=True)),
              "kind: application": keyed("kind", key_value(r"application(?:list)?(?![a-z0-9])", bare=True)),
              "secret:": keyed(r"(?<![a-z0-9_./-])secret", BARE_END),
              # each key that ends so, as MANIFEST_REFUSED reads them: a word of LOOSE_WORDS is a whole word only
              "*secretkeyref:": keyed("secretkeyref", BARE_END, explicit=r"[\w.-]*?secretkeyref"),
              "*secretref:": keyed("secretref", BARE_END, explicit=r"[\w.-]*?secretref"),
              "*secretname:": keyed("secretname", BARE_END, explicit=r"[\w.-]*?secretname"),
              # and the two that a text can turn on with no new word, from false to true
              "privileged: true": keyed("privileged", key_value(TRUE_WORD, bare=True)),
              "a host namespace: true": keyed(r"host(?:network|pid|ipc)", key_value(TRUE_WORD, bare=True)),
              # an explicit key that starts with an anchor, a tag, a comment or a block scalar, before which EXPLICIT
              # does not read the key's word (EXPLICIT_MARK)
              "an explicit key's mark": r"(?<![^\s\[{,:-])\?\s*(?:&[\w-]|!!|!<|[#|>])"}
LOOSE_KEYS = {word: re.compile(pattern) for word, pattern in LOOSE_KEYS.items()}


# A backslash and what it escapes, in a double-quoted text of YAML: a line break (with the next line's indentation),
# a number of 2, 4 or 8 hex digits, or one character
ESCAPE = re.compile(r"\\(?:(\r\n|[\r\n\x85\u2028\u2029])[ \t]*|x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|"
                    r"U([0-9a-fA-F]{8})|(.))", re.S)
DQ_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r",
              "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": "\u2028",
              "P": "\u2029"}


def loose_texts(text):
    """The four readings of a text in the loose reading, in lower case, so that no word hides in an escape of YAML or
    JSON: with each number escape written out (a backslash with x50, u0050 or U00000050), (1) with each line that
    ends in a backslash joined with the next one, as a double-quoted text goes on (a line break of YAML is a CR LF, a
    CR, a LF, a NEL, an LS or a PS, as go-yaml reads them), and (2) with no join, as a comment that ends in a backslash
    ends at its line's end (joined, its last word would glue to the next line's first); and (3, 4) the same two with
    each other escape of a double-quoted text written out too (\\" and \\n: JSON in a quoted text). A word that one of
    them shows counts. A text with no backslash has one reading, four times."""
    if "\\" not in text:
        return [text.lower()] * 4
    # one pass for the four: (joined, as is), (as is, as is), (joined, every escape), (as is, every escape)
    pieces, last = [[], [], [], []], 0
    for found in ESCAPE.finditer(text):
        whole = found.group(0)
        if found.group(1):
            outs = ("", whole, "", whole)
        elif found.group(5) is None:
            try:
                outs = (chr(int(found.group(2) or found.group(3) or found.group(4), 16)),) * 4
            except (ValueError, OverflowError):
                outs = ("",) * 4
        else:
            outs = (whole, whole) + (DQ_ESCAPES.get(found.group(5), whole),) * 2
        for piece, out in zip(pieces, outs):
            piece += (text[last:found.start()], out)
        last = found.end()
    return ["".join(piece + [text[last:]]).lower() for piece in pieces]


def loose_views(text):
    "Each distinct reading of a text (loose_texts), as it stands and without its comments (uncommented)."
    return list(dict.fromkeys(view for low in loose_texts(text) for view in (low, uncommented(low))))


def loose_counts(text):
    """How many of each word of LOOSE_WORDS and key of LOOSE_KEYS a text holds, the most that one of its readings
    (loose_texts) shows, and the bare text of each of the four readings: in lower case, with its quotes, spaces, tabs
    and braces taken out. An alias after a held key's colon counts where an anchor of its name stands (aliased)."""
    counts, bares, seen = {}, [], {}
    for low in loose_texts(text):
        if low not in seen:
            bare = re.sub(r"[\"'{} \t]", "", low)
            anchors = set(ANCHOR.findall(low))
            # a word with list after it too: a kind's List holds that kind (ClusterRoleList, ApplicationSetList)
            one = {w: len(re.findall(r"(?<![a-z0-9])" + re.escape(w) + r"(?:list)?(?![a-z0-9])", low))
                   for w in LOOSE_WORDS}
            one.update({w: len(aliased(pattern, bare, anchors)) for w, pattern in LOOSE_KEYS.items()})
            seen[low] = bare
            counts = {w: max(n, counts.get(w, 0)) for w, n in one.items()}
        bares.append(seen[low])
    return counts, bares


def loose_danger(old_text, new_text):
    """The first refused form that the loose reading finds more of in the new text than in the old, or None: a word of
    LOOSE_WORDS or a key of LOOSE_KEYS, another service account, or a bigger volume claim, in any reading
    (loose_counts). With no old text, one word is enough: a README that says hostPath is refused too, and the refusal
    names the word."""
    (old, old_bare), (new, new_bare) = loose_counts(old_text), loose_counts(new_text)
    word = next((w for w in new if new[w] > old[w]), None)
    if word:
        return f"the word {word}"
    # serviceAccount, the old name of the pod's field, too: a pattern, as a loose word would take kind: ServiceAccount
    accounts, sizes = (lambda bare: re.findall(r"serviceaccount(?:name)?:([^,\s\]]*)", bare)), \
        (lambda bare: [quantity(x) for x in re.findall(r"storage:([0-9.]+[kmgtp]i?)", bare)])
    if any(accounts(a) != accounts(b) for a, b in zip(old_bare, new_bare)):
        return "a changed serviceAccountName"
    for a, b in ((sizes(a), sizes(b)) for a, b in zip(old_bare, new_bare)):
        if len(b) > len(a) or any(n > o for o, n in zip(a, b)):
            return "a bigger volume claim"
    return None


MANIFEST_KEY = re.compile(keyed(r"(?<![a-z0-9_./-])(?:kind|apiversion)", BARE_END))


def manifest_keys(text):
    """How many kind and apiVersion keys a text holds, in the loose reading (the most of its readings): what makes a
    text a manifest."""
    return max(len(MANIFEST_KEY.findall(bare)) for bare in loose_counts(text)[1])


KIND_SECRET = re.compile(keyed("kind", key_value(r"secret(?:list)?(?![a-z0-9])", bare=True)))
STRING_DATA = re.compile(keyed("stringdata", BARE_END))


def loose_secret(text):
    """True when the loose reading says that a text may hold a Secret object. A reading of the text (loose_texts) in
    lower case, with its quotes, spaces, tabs and braces taken out, names the kind Secret or has a stringData key; or
    the text is JSON and an object in it has that kind, in any case. The filter of a read asks it of a file that the
    block reader cannot read, where the repository's own people wrote the text, and a commit of a file that gets the
    loose reading."""
    for low in set(loose_texts(text)):
        bare = re.sub(r"[\"'{} \t]", "", low)
        if aliased(KIND_SECRET, bare, set(ANCHOR.findall(low))) or STRING_DATA.search(bare):
            return True
    try:
        left = [json.loads(text)]
    except (ValueError, RecursionError):
        return False
    while left:
        value = left.pop()
        if isinstance(value, dict):
            if any(k.lower() == "kind" and isinstance(v, str) and v.lower() in ("secret", "secretlist")
                   for k, v in value.items()):
                return True
            left.extend(value.values())
        elif isinstance(value, list):
            left.extend(value)
    return False


# The C0 control characters but a tab and the line breaks, as bytes: UTF-8 writes none of them in another way
CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def kept_back(path, data, read=None):
    """Why the filter of a read keeps one file of a GitOps repository back from every agent, or None: no Secret
    object leaves the door. The file as the patterns read it holds a Secret or a private key; or it is not block
    style, or has another name than .yaml, .yml or .json, and a loose reading of its text says that it may hold one;
    or it is not UTF-8 text, where the filter sees nothing, or it holds a control character (CONTROL), between whose
    letters no pattern reads a word. The render box asks nothing of what a file holds: a unit
    that can read a path that the door gives no agent is closed, by its paths alone (door_render.closed). read:
    manifest_text(path, data), when the caller has it."""
    text, why = manifest_text(path, data) if read is None else read
    if why:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return "is not UTF-8 text, so it may hold a Secret that the filter cannot see: the filter keeps it back"
    if CONTROL.search(data):        # UTF-16 with no mark is UTF-8 too, with a NUL between the letters of each word
        return ("holds a control character other than a tab or a line break, which can hide a Secret from the filter: "
                "the filter keeps it back")
    if not why and (secret_object(text) or any("-----begin" in low for low in loose_texts(text))):     # with an escape
        return "holds a Secret, which the filter keeps back"
    # the loose reading too for a file with another name than .yaml, .yml or .json, which no reader reads by lines
    if (why or not manifest_name(path)) and \
            (loose_secret(text) or any("-----begin" in low for low in loose_texts(text))):
        return "may hold a Secret, which the filter keeps back"
    return None


# The lines that a commit changes in a YAML file that code reads only loosely: the values of decide_gitops's rule calls
# (one run of spaces before a list's dash and one after it: \s*-?\s* splits a long run of spaces in each place)
REPLICAS_LINE = re.compile(r"\s*(?:-\s*)?replicas\s*:\s*\d{1,2}\s*")
IMAGE_LINE = re.compile(r"\s*(?:-\s*)?(image|tag|digest|newTag|newName)\s*:\s*\S+\s*")
LISTED_LINE = re.compile(r"\s*(?:-\s*)?replicas\s*:\s*\d{1,2}\s*|"
                         r"\s*[\w./-]*restartedAt['\"]?\s*:\s*['\"]?[0-9T:.Z+-]{10,40}['\"]?\s*|"
                         r"\s*(?:-\s*)?(?:image|tag|digest|newTag|newName)\s*:\s*[\w./:@-]+\s*")
# What makes a file that no parser of the door reads one that changes only on listed lines (the rule of references to
# Secrets, A8): a key that contains secret, with its spaces kept, so that "the secrets of an application:" in a README
# is no key; an apiVersion of the operator's groups, of the Secrets Store CSI driver, of Argo CD or of RBAC; and, where
# the door reads no object in the file (a values file, a file of another name), a key that contains serviceaccount.
# In a manifest of objects the count reads serviceAccountName and serviceAccount by their values (sa_changed).
# imagePullSecrets names a Secret that only the node reads, to pull an image: no key of this rule. A group stands with
# its version or alone: an apiVersion of external-secrets.io with no version makes no object of the cluster, but the
# store route of the door would read such a decoy as a store.
HELD_GROUPS = (r"(?:(?:[\w-]+\.)*external-secrets\.io|argoproj\.io|secrets-store\.csi\.x-k8s\.io|"
               r"rbac\.authorization\.k8s\.io)(?:/|(?![\w./-]))")
# A key's colon may stand on the next line: in a flow mapping ({"secretKeyRef"\n: ...}) and after YAML's explicit key
# (? secretKeyRef\n: ...).
# A key's whole word, at its start, with the word that it must hold looked for ahead: [\w.-]*secret[\w.-]* would try
# each split of one long word, a time that grows with the square of its length.
NAMES_SECRET = re.compile(keyed(r"(?<![\w.-])(?!imagepullsecrets(?![\w.-]))(?=[\w.-]*secret)[\w.-]+"))
NAMES_HELD = re.compile(keyed("apiversion", key_value(HELD_GROUPS)))
NAMES_ACCOUNT = re.compile(keyed(r"(?<![\w.-])(?=[\w.-]*serviceaccount)[\w.-]+"))
# RBAC, as sensitive_key and rbac_rule read it: a key with rbac (but an RBAC proxy's) or clusterrole, and a rule's verbs
RBAC_WORD = r"rbac(?![-_]?proxy)"       # but an RBAC proxy's: kubeRBACProxy, kube-rbac-proxy, rbac_proxy
NAMES_RBAC = re.compile(keyed(r"(?<![\w.-])(?=[\w.-]*(?:" + RBAC_WORD + r"|clusterrole))[\w.-]+") + "|" +
                        keyed(r"(?<![\w.-])verbs"))
# The two keys of a Secret's name and key (name_and_key), each as a key itself, where a node starts (at a line's start,
# after a flow mark, a list's dash or an explicit key's ?, and after a node's anchor and tag there, in either order:
# {!x name: admin}), so that "the api key: ..." in an alert's text is no such key. At most two of them: a loop over
# them would read each run of tags from each dash before it ({!x- !x- ...).
PROPERTIES = r"(?:(?:&[\w-]+|![^\s,\[\]{}]*)[ \t]+){0,2}"
NAMES_PAIR = [re.compile(r"(?:^|[\r\x85\u2028\u2029\[{,]|[?\-][ \t])[ \t]*" + PROPERTIES + r"[\"']?" + word + KEY_END +
                         r"|(?<![^\s\[{,:-])\?\s*" + PROPERTIES + r"[\"']?" + word + r"(?![\w.-])", re.M)
              for word in ("key", "name")]


def uncommented(text):
    """A text with each YAML comment taken out: a # at a line's start or after a space, a tab or a line break, to the
    line's end, which each line break of YAML makes (a LF, a CR, a NEL, an LS or a PS, as go-yaml reads them; re's
    lines end at a LF only)."""
    return re.sub(r"(^|[ \t\r\x85\u2028\u2029])#[^\n\r\x85\u2028\u2029]*", r"\1", text, flags=re.M)


def names_secret(text, accounts=True, rbac=True, views=None):
    """True when a text names a Secret, a held kind, with rbac RBAC, or, with accounts, a service account, in the loose
    reading (NAMES_SECRET, NAMES_HELD, NAMES_RBAC, NAMES_ACCOUNT), in each of its readings, as it stands and without
    its comments (loose_views)."""
    views = loose_views(text) if views is None else views
    return any(NAMES_SECRET.search(t) or aliased(NAMES_HELD, t) or rbac and NAMES_RBAC.search(t) or
               accounts and NAMES_ACCOUNT.search(t) for t in views)


# What makes a key of a text that its words never spell, as go-yaml and Helm read YAML: a tag that changes a node
# (!!binary c2VjcmV0UmVm: is secretRef; a verbatim !<...>; and, with a %TAG directive, any tag), where a node starts:
# at a line's start, after a colon, a dash or a ? and a space, after a flow mark, after a quoted key's colon, and after
# an anchor there; an explicit key that starts with an anchor, a tag, a comment or a block scalar, before which
# EXPLICIT does not read its word (in a flow, a ? with no space after it is an explicit key's too, but a comment and a
# block scalar need a space before them and an anchor its name, so a regex's [?&] is none); and an alias as a key (*k :
# and ? *k, ?*k) whose anchor (&k) the text holds. The
# name of an anchor and of an alias is letters, digits, _ and - (go-yaml refuses &a.b), so a long run of other marks
# takes one try, not one for each. A ! with a space after it, a ! after a word or a ? with no space ("what?!", a
# regex's (?!api)), a local tag (- !x, which go-yaml reads as the text), an anchor alone, an alias as a value, and a
# * with no anchor of its name (Markdown's *Alert:*, a host *.example.com:443) make no key.
NODE = r"(?:^[ \t]*|[?:\-][ \t]+|[\[{,][ \t]*|[\"']:[ \t]*)(?:&[\w-]+[ \t]+)?"
CHANGING_TAG = re.compile(NODE + r"!(?:!|<)", re.M)
ANY_TAG = re.compile(NODE + r"!(?=\S)", re.M)
DIRECTIVE = re.compile(r"^%", re.M)
EXPLICIT_MARK = re.compile(r"(?<![^\s\[{,])\?(?:\s*(?:&[\w-]|!!|!<)|\s+[#|>])")
ALIAS_KEY = re.compile(r"(?<![^\s,\[\]{}?])\*([\w-]+)\s*:|(?<![^\s,\[\]{}])\?\s*\*([\w-]+)")


def yaml_key(views):
    "True when a reading of a text (loose_views) has what makes a key that its words never spell."
    for view in views:
        text = yaml_breaks(view)
        if (ANY_TAG if DIRECTIVE.search(text) else CHANGING_TAG).search(text) or EXPLICIT_MARK.search(text):
            return True
        anchors = set(ANCHOR.findall(text))
        if anchors and any((m.group(1) or m.group(2)) in anchors for m in ALIAS_KEY.finditer(text)):
            return True
    return False


ONE_WORD = re.compile(r"[\w./:@-]*")


def text_holds(text, rbac=True):
    """True when a text may hold a mapping that names a Secret, a service account, a held kind or, with rbac, RBAC, as
    a chart reads a text that it renders (tpl, extraObjects: - |) or a values text that is not block style: in its
    readings (loose_views) it names one (names_secret), it has a name key and a key key (NAMES_PAIR: a mapping of a
    name and a key, as basicAuth.password: {name, key}, names a key of a Secret under any key's name; a key key alone,
    as a toleration's or an affinity's, names none), or it has a tag, an explicit key or an alias that can make any
    key of the text (yaml_key: !!binary c2VjcmV0S2V5UmVm, *k : {name: db1, key: k} after &k secretKeyRef). An anchor
    alone holds none, nor does a text of one word with no space, as an image with its tag or a URL, nor a colon in a
    word (KEY_END): external-secrets:v1+k3s1 names no key. The known limit: a template's action ({{ "secretRef" }}:,
    printf) can make any key of a text that a chart gives to tpl, and no reading of the text sees it."""
    if ONE_WORD.fullmatch(text):
        return False
    views = loose_views(text)
    return names_secret(text, rbac=rbac, views=views) or yaml_key(views) or \
        all(any(pair.search(view) for view in views) for pair in NAMES_PAIR)


# The value of a key that a rule call changes, as LISTED_LINE reads it (an image, a tag, a digest, a replica count)
# (the value's own quotes, if any, around a plain value: a quote that opens another scalar cannot be taken for a value)
# (on the key's own line: a value that a line break would take could be the next key)
LISTED_VALUE = re.compile(r"(?i)(?<![\w.-])((?:image|tag|digest|newtag|newname|replicas)[\"']?[ \t]*:[ \t]*)"
                          r"([\"']?)[\w./:@-]*\2")


def rbac_changed(old, new):
    """True when a change of a values text that code does not read by lines can change what the text says of RBAC. A
    text with no key of RBAC (NAMES_RBAC) in any reading, before or after, says none. Else only the value of a listed
    key (an image, a tag, a digest, a replica count) may change: an image bump in a text that also has rbac: is free.
    A count of the keys of RBAC would also free rbac: {create: false} turned to {create: true}, which no reading of
    such a text can tell from a bump."""
    if not any(NAMES_RBAC.search(view) for text in (old, new) for view in loose_views(text)):
        return False
    # the texts as written: a key's case is Helm's (rbac.Create is another key, and create keeps the chart's default)
    return LISTED_VALUE.sub(r"\1", old) != LISTED_VALUE.sub(r"\1", new)


def sensitive_key(key):
    """True for a key that names a Secret, an account or RBAC: it contains secret, serviceaccount, clusterrole or rbac
    (a chart's rbac.create, rbac.extraRules, createClusterRoles); but imagePullSecrets, and rbac in a key of an RBAC
    proxy (kubeRBACProxy, kube-rbac-proxy, an image beside a server)."""
    low = key.lower() if isinstance(key, str) else ""
    named = "secret" in low or "serviceaccount" in low or "clusterrole" in low or re.search(RBAC_WORD, low)
    return bool(named) and low != "imagepullsecrets"


def rbac_rule(node):
    """True for a mapping that is a rule of a Role (verbs, with resources, apiGroups, resourceNames or
    nonResourceURLs), under a key of any name: a chart's clusterRoleRules or additionalPermissions. No key with the
    word rules is read alone: a monitoring chart's defaultRules and alerting rules are ordinary values."""
    return isinstance(node, dict) and "verbs" in node and \
        bool({"resources", "apiGroups", "resourceNames", "nonResourceURLs"} & set(node))


def name_and_key(node, parent):
    """True for a mapping of exactly a name and a key (and optional), outside a ConfigMap's (a parent configMap,
    configMapKeyRef or configMapRef, by its whole name: a chart may read a key such as dbConfigMap as a Secret's) and a
    selector: how the Prometheus operator and many charts name a key of a Secret (basicAuth.password,
    authorization.credentials)."""
    low = parent.lower() if isinstance(parent, str) else ""
    return isinstance(node, dict) and {"name", "key"} <= set(node) <= {"name", "key", "optional"} and \
        low not in ("configmap", "configmapkeyref", "configmapref") and low != "matchlabels" and \
        "selector" not in low


def sensitive(docs):
    """What of parsed documents names a Secret, a service account, RBAC or a held kind, with its place, in their
    order: each value under a key that sensitive_key reads, each mapping of a name and a key (name_and_key), each rule
    of a Role (rbac_rule), each mapping with an apiVersion of a held group, and each text that may hold a mapping
    that names one of these (text_holds: a manifest that a chart takes as a text, as extraObjects: - |). Check 1 of a
    file that the parser reads compares it at HEAD and after the commit, and nothing else. An item of a list is placed by its name, where
    it has one (an env item before another moves no reference), else by its index (a reference that moves to another
    container, as a sidecar, changes its place)."""
    out = []

    def walk(node, at, parent):
        if isinstance(node, dict):
            if isinstance(node.get("apiVersion"), str) and re.match(HELD_GROUPS, node["apiVersion"], re.I) or \
                    name_and_key(node, parent) or rbac_rule(node):
                out.append((at, json.dumps(node, sort_keys=True, default=str)))
                return
            for k, v in node.items():
                if sensitive_key(k):
                    out.append((at + (str(k),), json.dumps(v, sort_keys=True, default=str)))
                else:
                    walk(v, at + (str(k),), k)
        elif isinstance(node, list):
            for n, v in enumerate(node):
                named = isinstance(v, dict) and isinstance(v.get("name"), str)
                walk(v, at + (("name", v["name"]) if named else n,), parent)
        elif isinstance(node, str) and text_holds(node):        # a text with a line break or none (one-line JSON)
            out.append((at, json.dumps(node)))
    for n, doc in enumerate(docs or []):
        walk(doc, (n,), None)
    return out


BLOCK_DASH = re.compile(r"-(?:[ \t]+|$)")      # the dash of a list item, with the blanks after it


class Plain(str):
    """A value that a line of block style gives with no quotes (block_tree's strict reading, for the door's store
    route): YAML may read it as no text (yaml_other)."""


# YAML 1.1's bools and nulls, which go-yaml (a cluster's reader) reads as no text when they stand with no quotes
YAML_WORDS = frozenset(("y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "true", "True", "TRUE", "false",
                        "False", "FALSE", "on", "On", "ON", "off", "Off", "OFF", "~", "null", "Null", "NULL", ""))
# YAML 1.1's and 1.2's numbers: an integer (also 0b, 0o, 0x, an old octal, with _, of base 60) or a float
YAML_NUMBER = re.compile(r"[-+]?(?:0[bB][-+]?[01_]+|0[oO][-+]?[0-7_]+|0[0-7_]+|0[xX][0-9a-fA-F_]+"
                         r"|(?:[0-9][0-9_]*(?::[0-5]?[0-9])*(?:\.[0-9_]*)?|[0-9_]*\.[0-9_]+)(?:[eE][-+]?[0-9]+)?)"
                         r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")


def yaml_other(text):
    """True when YAML 1.1 or 1.2 may read a plain value as no text: a bool, a null or a number. go-yaml takes each _
    out of a value that starts as a number does before it reads one (0_x1f is 31, 1e_3 is 1000)."""
    bare = text.replace("_", "") if text[:1] in "0123456789+-." else text
    return text in YAML_WORDS or bool(YAML_NUMBER.fullmatch(bare))


def block_tree(text, strict=False):
    """A text that unread reads as block style, as the tree of mappings, lists and texts that it says, for sensitive:
    a value is the text of its line with no comment and no quotes, and a block scalar's value its lines. Each
    document of the text is one item of the list that it gives. strict (door.store_docs): a form that this reader
    reads in another way than a cluster's reader is a ValueError. That is a key twice in one mapping (this reader
    takes its last value, and a cluster's reader may take another or refuse the file, as in no_key_twice); a \\ in
    double quotes, a '' in single quotes, and a # with space before it in either (this reader takes no escape, and it
    cuts a comment inside the quotes too, so "ma\\x69n" is another name for it than for a cluster); a block scalar as
    the value of a name or a namespace (its lines keep their spaces here, and not in YAML); .inf or .nan, which this
    reader reads as a text and YAML as a number that no JSON of a cluster holds; a tab after a list's dash, which a
    cluster's reader (go-yaml, as libyaml) refuses (it takes one after a key's colon); and a document mark or an
    end mark with space before it, outside a block scalar (this reader skips it, and YAML reads a text). A comment
    starts at a # at the start of a text or after one space or tab, and strip takes the spaces before it: a pattern with
    a run of spaces before its # reads a long run again from each of its places (a line of 1 MB took over an hour).
    In the strict reading a value with no quotes is a Plain text: YAML may read it as no text (yaml_other)."""
    def split(text):
        colon = re.search(r":(?=[ \t]|$)", text)
        return (text[:colon.start()].rstrip(" \t"), text[colon.end():].strip(" \t")) if colon else (None, text)

    def value(text):
        if strict and text[:1] in ("\"", "'"):
            quoted = re.match(DQ if text[0] == '"' else SQ, text)
            if not quoted or re.search(r"\\|[ \t]#" if text[0] == '"' else r"''|[ \t]#", quoted.group()[1:-1]):
                raise ValueError("a quoted text that the block reader reads in another way than YAML")
        text = re.sub(r"(?:^|[ \t])#.*$", "", text).strip(" \t")
        if strict and re.fullmatch(r"[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)", text):
            raise ValueError("YAML's infinity or not-a-number, which no object of a cluster holds")
        if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
            return text[1:-1]
        return Plain(text) if strict else text
    rows = []                   # [column, text, the lines of its block scalar or None]
    scalar = None               # (the column that its lines stand to the right of, its lines)
    for line in text.replace("\r\n", "\n").split("\n"):
        rest = line.lstrip(" ")
        col = len(line) - len(rest)
        if scalar is not None:
            if not rest.strip(" \t") or col > scalar[0]:
                scalar[1].append(line)
                continue
            scalar = None
        mark = re.fullmatch(r"(?:---|\.\.\.)[ \t]*(?:#.*)?", rest)
        if strict and mark and col > 0:
            raise ValueError("a document mark or an end mark with space before it")
        if not rest.strip(" \t") or rest.startswith("#") or mark:
            continue
        owner = col             # col walks the line past its dashes: a copy of the rest at each dash took seconds
        dash = BLOCK_DASH.match(line, col)
        while dash:
            if strict and "\t" in dash.group():
                raise ValueError("a tab after a list's dash: a cluster's YAML reader takes no tab there")
            rows.append([col, "-", None])
            owner, col = col, dash.end()
            dash = BLOCK_DASH.match(line, col)
        rest = line[col:].rstrip(" \t")
        if not rest:
            continue
        rows.append([col, rest, None])
        # a block scalar: the value after its key, with no comment, or the text after a dash, is | or > alone
        key, said = split(rest)
        if re.fullmatch(r"[|>][-+0-9]*", re.sub(r"(?:^|[ \t])#.*$", "", said).strip(" \t")):
            rows[-1][2] = []
            scalar = (col if key is not None else owner, rows[-1][2])

    def node(i, col):
        "(the node whose rows start at row i in column col, the row after it)"
        if rows[i][1] == "-":
            items = []
            while i < len(rows) and rows[i][0] == col and rows[i][1] == "-":
                i += 1
                item = None
                if i < len(rows) and rows[i][0] > col:
                    item, i = node(i, rows[i][0])
                items.append(item)
            return items, i
        key, said = split(rows[i][1])
        if key is None:         # a text, and the lines that go on with it (joined once: a join at each took seconds)
            parts, lines, i = [rows[i][1]], rows[i][2], i + 1
            while i < len(rows) and rows[i][0] > col and rows[i][1] != "-":
                parts.append(rows[i][1])
                i += 1
            return ("\n".join(lines) if lines is not None else value(" ".join(parts))), i
        out = {}
        while i < len(rows) and rows[i][0] == col and rows[i][1] != "-":
            key, said = split(rows[i][1])
            if strict and key in out:
                raise ValueError("a key is there twice")
            lines, i = rows[i][2], i + 1
            if lines is not None:
                if strict and key in ("name", "namespace"):
                    raise ValueError("a block scalar as a name: its lines keep their spaces here, and YAML's do not")
                out[key] = "\n".join(lines)
            elif said and not said.startswith("#"):
                parts = [said]
                while i < len(rows) and rows[i][0] > col and rows[i][1] != "-":
                    parts.append(rows[i][1])
                    i += 1
                out[key] = value(" ".join(parts))
            elif i < len(rows) and (rows[i][0] > col or rows[i][0] == col and rows[i][1] == "-"):
                out[key], i = node(i, rows[i][0])
            else:
                out[key] = None
        return out, i
    docs, i = [], 0
    while i < len(rows):
        found, i = node(i, rows[i][0])
        docs.append(found)
    return docs


def sensitive_lines(text):
    """What of a block style text names a Secret, a service account or a held kind (sensitive of its block_tree), or
    None for a text that is not block style (unread)."""
    if unread(text):
        return None
    return sensitive(block_tree(text))


def loose_read(path, data, old):
    """True when a commit's file gets the loose reading and not the block reader's: a file with another name than
    .yaml, .yml or .json; and a YAML file that the block reader cannot read and could not read at HEAD either, which
    the people of the repository wrote that way (a flow list of mappings, an expression of a template, a quoted
    key). A new YAML file, and one that was block style at HEAD, stay with the block reader, which refuses them."""
    if not manifest_name(path):
        return True
    if path.lower().endswith(".json") or old is None:
        return False
    try:
        return bool(unread(data.decode("utf-8"))) and bool(manifest_text(path, old)[1])
    except UnicodeDecodeError:
        return False


def manifest_refusal(old_text, new_text):
    """The first refused manifest form that the new rendered output has more of than the old, or None."""
    for what, pattern in MANIFEST_REFUSED.items():
        if what == "a Secret object" and not secret_object(new_text):
            continue                    # the kind's name alone, as a reference to it, is no Secret
        if len(re.findall(pattern, new_text, re.M)) > len(re.findall(pattern, old_text, re.M)):
            return what
    if plan_channels(new_text) > plan_channels(old_text):
        return "a k3s upgrade channel"
    if sa_changed(old_text, new_text):
        return "a changed serviceAccountName"
    if storage_grew(old_text, new_text):
        return "a bigger volume claim"
    return None


def plan_channels(text):
    """The channel lines of k3s upgrade Plans. A Plan names one version, so each k3s upgrade is one commit, the agent's
    own call (DevOps plan 5.5), and a channel, which upgrades with no commit, is never the door's."""
    return sum(len(re.findall(ITEM + r"channel\s*:\s*\S", doc, re.M))
               for doc in re.split(r"^---(?:[ \t\r].*)?$", text, flags=re.M)
               if re.search(ITEM + r"apiVersion[ \t]*:\s*[\"']?(?i:upgrade\.cattle\.io)/", doc, re.M))


SERVICE_ACCOUNT = re.compile(r"serviceAccount(?:Name)?\s*:\s*(\S+)")      # the pod's field and its old name


def sa_changed(old_text, new_text):
    return SERVICE_ACCOUNT.findall(old_text) != SERVICE_ACCOUNT.findall(new_text)


def storage_grew(old_text, new_text):
    def sizes(text):
        return [quantity(x) for x in re.findall(r"storage\s*:\s*['\"]?([0-9.]+[KMGTP]i?)", text)]
    return any(n > o for o, n in zip(sizes(old_text), sizes(new_text))) or len(sizes(new_text)) > len(sizes(old_text))


def quantity(text):
    m = re.fullmatch(r"([0-9.]+)([KMGTP])(i?)", text, re.I)        # in lower case too, for the loose reading
    if not m or not re.fullmatch(r"[0-9]+(?:[.][0-9]*)?|[.][0-9]+", m.group(1)):     # not [.]?: two runs side by side
        return 0
    return float(m.group(1)) * (1024 if m.group(3) else 1000) ** ("KMGTP".index(m.group(2).upper()) + 1)


# ---------------------------------------------------------------- the GitOps repository

def gitops_path_refused(path, access):
    if re.search(r"(^|/)Secrets/", path) or path.startswith("_config/") or "/_config/" in path:
        return f"{path} is a secret path of the GitOps repository"
    if any(glob_match(path, p) for p in (access.get("exposure") or [])):
        return f"{path} is in the exposure register"
    return None


def read_path_refused(path, access):
    """Why a read of the GitOps repository refuses a path by its form or its place, or None: decide_gitops for read,
    and for each file that a listing or a search reads (door.GitHub.head_files), so that they give the same files."""
    if not path or path.startswith("/") or any(p in ("", ".", "..") for p in path.split("/")):
        return "read takes one path of the repository"      # GitHub reads a/./b and a//b as a/b
    if len(path) > PATH_MOST:
        return f"the path has more than {PATH_MOST} characters"
    if path.count("/") > FOLDERS_MOST:
        return f"the path has more than {FOLDERS_MOST} folders"
    return gitops_path_refused(path, access)


def read_text(path, data):
    """(the text that a read of the GitOps repository gives of one file's bytes at HEAD, None), or (None, why the
    filter keeps the file back): door.GitHub.read, and each file of a listing and of a search, which so name and
    search only what a read gives, and only in the text that it gives."""
    read = manifest_text(path, data)        # once: a file at the limit takes a moment to read
    kept = kept_back(path, data, read)
    if kept:
        return None, kept
    return (data.decode("utf-8") if read[1] else data.decode("utf-8", "replace")), None


# What each form of the GitOps repository takes: the answer to any other word, help too
GITOPS_FORMS = ('the GitOps repository takes read <path>, list [<folder>], find "<words>" [<folder>] (words of more '
                'than one part in quotes), push and rollback with a commit as content, sync <app> [prune], and '
                'uncordon <node>')
# What list and find of the GitOps repository take (the owner's yes of 25 November 2026: a search over the files that
# a read gives already, and no new access)
LIST_FORM = "list takes one folder of the repository at most: with none, it lists the whole repository"
FIND_FORM = ("find takes the words to look for, 2 to 200 characters on one line, and after them one folder of the "
             "repository at most: with none, it searches the whole repository")
FIND_WORDS = (2, 200)


def folder_refused(folder, access):
    """Why list or find refuses a folder, or None: the rules of a read's path (read_path_refused), and a folder that
    is a secret path itself or that holds only paths that no read gives (Secrets, _config, a folder of the exposure
    register). A NUL stands for any name below it: no path of a repository holds one, and only a pattern's wildcard
    takes it."""
    if not folder or folder.startswith("/") or any(p in ("", ".", "..") for p in folder.split("/")) or \
            not folder.isprintable():
        return ("the folder is a path of the repository, with no / at its start, no empty, . or .. part, and only "
                "printable characters")
    if len(folder) > PATH_MOST:
        return f"the folder has more than {PATH_MOST} characters"
    if folder.count("/") > FOLDERS_MOST:
        return f"the folder has more than {FOLDERS_MOST} folders"
    if gitops_path_refused(folder, access):
        return gitops_path_refused(folder, access)
    if gitops_path_refused(folder + "/\0", access):
        return f"each path below {folder} is a secret path of the GitOps repository or in the exposure register"
    return None


# ---------------------------------------------------------------- uncordon a node
#
# The owner's yes, 22 November 2026: "a narrow route to uncordon cordoned app nodes" of a business's k3s cluster, for
# the agent that holds its GitOps target. No host of the door reaches the cluster's API, but a self-hosted runner of
# the GitOps repository does. So the door dispatches one fixed workflow file of that repository, which a person commits
# (no commit through the door writes .github/** of a GitOps repository: NEVER_PATHS), with one input, the node's name,
# and waits for its run, as a sync does. A rule call: the owner's yes covers this one route. In a repository without
# that file, GitHub refuses the dispatch, and the call fails with GitHub's answer. The ref of the dispatch is the one
# of a sync: door.GitHub.dispatch takes the repository's default branch, as GitHub names it (door.GitHub.branch). The
# plan holds no ref, and no word of the call reaches one, so the agent never chooses the version of the workflow that
# runs.
UNCORDON_WORKFLOW = "uncordon-node.yml"       # .github/workflows/uncordon-node.yml of the GitOps repository
UNCORDON_INPUT = "node"                       # its one input
NODE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")      # a Kubernetes node's name of one label


def gitattributes_refused(files):
    """Why a GitOps commit of these files is refused for a .gitattributes, at any depth and in any case, or None: the
    commit's own files, and its final ones, with those that the door writes again (with_generated). The render box, and
    list and find, read the repository as git exports it (export-ignore, export-subst, working-tree-encoding): in a
    GitOps repository .gitattributes is a person's file. In an app or a devops repository an attribute needs git
    configuration that the repository does not hold to do more than change how a checkout looks, and the blob hash
    guards list and find (door.GitHub.head_files)."""
    for path, _data, _mode in files:
        if path.casefold().rsplit("/", 1)[-1] == ".gitattributes":
            return (f"{path} says how git exports the files of the GitOps repository: a person changes it, outside "
                    f"the door")
    return None


def decide_gitops(access, me, repo, op, args, content, lookups):
    """read <path> at HEAD through the filter; list [<folder>] the files that such a read gives; find <words>
    [<folder>] in their text; commit an image tag or digest, a replica count or a restart annotation as rule calls;
    rollback to the last good digest after a schema check; sync through the listed caller workflow; uncordon <node>
    through UNCORDON_WORKFLOW. Other manifests are the agent's own call."""
    entry = repo_entry(me, repo, ("gitops",))
    if entry is None:
        return refused(f"the door gives this agent nothing on {repo}", route="holder")
    target = f"gitops:{repo}"
    if op == "read":
        why = read_path_refused(args[0], access) if len(args) == 1 else "read takes one path of the repository"
        if why:
            return refused(why, target=target)
        return Decision("read", "a read at HEAD through the filter", target=target, write=False,
                        plan={"repo": repo, "read": args[0], "filter": True})
    if op in ("list", "find"):
        # The files that a read gives, and nothing else (door.GitHub.head_files). The words of a search never go into
        # the door's record (a person may search for a name): the decision's words name the folder alone, and the
        # door hashes a search's call with no argument (door.recorded_args).
        if content is not None:
            return refused(f"{op} takes no content: only its arguments", target=target)
        words = None
        if op == "find":
            if len(args) not in (1, 2):
                return refused(FIND_FORM, target=target)
            words, args = args[0], args[1:]
            if not FIND_WORDS[0] <= len(words) <= FIND_WORDS[1] or "".join(words.splitlines()) != words:
                return refused(FIND_FORM, target=target)
        elif len(args) > 1:
            return refused(LIST_FORM, target=target)
        folder = args[0] if args else ""
        why = folder_refused(folder, access) if args else None
        if why:
            return refused(why, target=target)
        where = f"below {folder}" if folder else "in the whole repository"
        if op == "list":
            return Decision("read", f"a listing at HEAD through the filter, {where}", target=target, write=False,
                            plan={"repo": repo, "list": folder, "filter": True})
        return Decision("read", f"a search at HEAD through the filter, {where}", target=target, write=False,
                        plan={"repo": repo, "find": words, "folder": folder, "filter": True})
    if op == "sync":
        caller = entry.get("sync")
        if len(args) not in (1, 2) or not APP_NAME.fullmatch(str(args[0])) or not caller or \
                args[1:] not in ([], ["prune"]):
            return refused("sync takes one app name, and prune after it to prune too, through the repository's listed "
                           "caller workflow", target=target)
        if args[1:]:
            return decide_prune(lookups, repo, target, caller, args[0])
        # the call waits for the run and answers with how it ended (door.GitHub.dispatch), so a failed sync fails
        return Decision("rule", "a sync through the listed caller", target=target, window="deploy",
                        plan={"repo": repo, "workflow": caller, "inputs": {"app": args[0]}, "wait": True})
    if op == "uncordon":
        if content is not None:
            return refused("uncordon takes no content: only the name of the node", target=target)
        if len(args) != 1 or not NODE_NAME.fullmatch(args[0]):
            return refused("uncordon takes one argument, the name of the node: lower-case letters, digits and -, at "
                           "most 63, with a letter or a digit at each end", target=target)
        # as a sync: the call waits for the run and answers with how it ended, so an uncordon that fails fails
        return Decision("rule", f"an uncordon of the node {args[0]} through {UNCORDON_WORKFLOW}", target=target,
                        window="deploy", plan={"repo": repo, "workflow": UNCORDON_WORKFLOW,
                                               "inputs": {UNCORDON_INPUT: args[0]}, "wait": True})
    if op not in ("push", "rollback"):
        return refused(GITOPS_FORMS, target=target)
    files, message = commit_files(content)
    if files is None:
        return refused(message, target=target)
    base = lookups.get("base_file")
    if base:                    # each file at HEAD is one read of GitHub for the whole decision
        at_base = {}
        lookups = dict(lookups, base_file=lambda p: at_base[p] if p in at_base else at_base.setdefault(p, base(p)))
    # checks: the call waits for the runs that the commit's push starts, and the agent learns how they ended
    plan = {"repo": repo, "files": files, "message": message, "branch": entry.get("branch"), "checks": True}
    for path, data, mode in files:
        if mode in ("120000", "160000") or never_path(path):
            return refused(f"{path} is under the commit rules", target=target)
        if mode not in ("100644", "100755"):        # 040000 too: a tree entry at a file's path
            return refused(f"{path} has the mode {mode}", target=target)
        why = gitattributes_refused([(path, data, mode)])
        if why:
            return refused(why, target=target)
        if path.casefold() == DOOR_DECLARATION:
            return refused(f"{path} names the files that the door writes itself: a person changes it, outside the "
                           f"door", target=target)
        why = gitops_path_refused(path, access)
        if why:
            return refused(why, target=target)
    why = paths_clash(files) or head_refused(files, lookups) or tag_text_refusal(files)   # before the box
    if why:
        return refused(why, target=target)
    set_parent(plan, lookups)
    # What the commit makes a cluster apply (door_render.py): the door gives the lookup only where its render box is.
    # With no report, every file keeps the rules that need no render, as before the box.
    report = (lookups.get("render") or (lambda files: None))(files)
    if report is not None and not isinstance(report, dict):
        return refused("the door could not read the render of this commit", target=target, route="again")
    if report is not None and not report.get("ok"):
        if "skip" not in report:
            return refused(f"the door could not render this commit: {report.get('why')}", target=target,
                           route="again" if report.get("again") else None)
        report = None
    try:
        why = tag_scan_refusal(report) or declared_refusal(report, files)   # before the rules of the files
        if why:
            return refused(why, target=target)
        d = gitops_files(lookups, op, target, plan, files, report)
        if d.kind != "refused":
            plan["objects"] = commit_objects(files, report, lookups)     # door.py keeps them once the commit is made
            d = with_owner(d, report, files, plan, target)
        d = with_generated(d, report, lookups, files, plan, target)
        # the files that the commit holds in the end, with those that the door writes again (with_generated)
        why = (paths_clash(d.plan["files"]) or head_refused(d.plan["files"], lookups) or
               gitattributes_refused(d.plan["files"])) \
            if d.kind != "refused" and isinstance(d.plan, dict) and d.plan.get("files") else None
        return refused(why, target=target) if why else d
    except (KeyError, TypeError, AttributeError, ValueError, RecursionError):
        return refused("the door could not read the render of this commit", target=target, route="again")


# ---------------------------------------------------------------- the files that a repository generates (X3)
#
# A GitOps repository can name, in DOOR_DECLARATION at HEAD, files that its own generator writes from the rest of the
# tree, such as an inventory of what the cluster exposes, which its own checks compare with the tree. A commit through
# the door that changes what such a file says must carry it, or those checks fail (11 November 2026: for about 31
# hours). The render box writes each file again on the tree after the commit, with the generator as it is at HEAD
# (door_render.generated). The owner, 12 November 2026, "Me, one card each time (Recommended)": a file that only loses
# lines (an entry leaves it) goes with the commit, which keeps its kind; any other change of it makes the commit the
# owner's, as the door's card (kind full) with the exact change, and after the owner's yes the door makes that commit
# once, with the file. A commit through the door changes neither the declaration, nor a file that it names, nor a
# rule of one.

DOOR_DECLARATION = ".founderizer/door.json"     # door_render.DECLARATION
GEN_LINE = 160              # characters of one line of a change in the decision's words


def declared_refusal(report, files):
    "Why a commit refuses because it changes a file that the repository generates, or a rule of one, or None."
    paths = {path for path, _data, _mode in files}
    for g in (report or {}).get("generated") or []:
        for path in [g["path"]] + list(g["rules"]):
            if path in paths:
                return (f"{path} is named in {DOOR_DECLARATION}: the door writes {g['path']} itself, with the generator "
                        f"as it is at HEAD, so a commit through the door changes neither the file nor its rules")
    return None


def with_generated(d, report, lookups, files, plan, target):
    """The decision on a GitOps commit with the files that its repository generates. d: the decision on the commit's
    own files. Each written file joins the commit, and its bytes join what the call hash covers, so that the owner's yes
    is to those bytes too."""
    if d.kind == "refused":
        return d
    if report is None:
        if (lookups.get("declared") or (lambda: False))():
            return refused(f"the repository names, in {DOOR_DECLARATION}, files that its generator writes or whose "
                           f"changes are the owner's, and the door has no render of this commit that writes them "
                           f"again or reads them", target=target)
        return d
    entries = report.get("generated") or []
    written, changes = [], []
    for g in entries:
        if g["status"] == "same":
            continue
        if g["status"] == "failed" and g["path"] == DOOR_DECLARATION:
            return refused(f"{g.get('why')}: the door refuses each commit of this repository until a person writes "
                           f"it again, outside the door", target=target)
        if g["status"] == "failed":
            return refused(f"the door could not write {g['path']} again ({g.get('why')}), and a commit without it "
                           f"fails the repository's checks", target=target)
        written.append((g["path"], base64.b64decode(g["content"]), "100644"))
        if g["status"] != "removes":
            lines = " | ".join(line.strip()[:GEN_LINE] for line in g["added"])
            more = g["gained"] - len(g["added"])
            changes.append(f"{g['path']} gains {g['gained']} lines and loses {g['removed']}; it gains: {lines}"
                           + (f" | and {more} lines more" if more > 0 else "") if g["gained"] else
                           f"{g['path']} loses {g['removed']} lines, and lines of it move")
    if not written:
        return d
    plan["files"] = list(files) + written
    plan["message"] = f"{(plan.get('message') or '').rstrip()}\n\nThe door wrote " \
                      f"{', '.join(path for path, _data, _mode in written)} again, with the generator at HEAD."
    covered = b"".join(path.encode() + b"\0" + data + b"\0" for path, data, _mode in written)
    if changes:
        return Decision("full", f"{d.why}; and the commit changes what the repository generates, which is the "
                        f"owner's (12 November 2026: \"Me, one card each time (Recommended)\"): {'; '.join(changes)}",
                        target=target, plan=plan, window="deploy", hash_content=covered)
    d.why = f"{d.why}; with {', '.join(path for path, _data, _mode in written)} written again, from which entries leave"
    d.hash_content = covered
    return d


# ---------------------------------------------------------------- YAML tags
#
# The coordinator of the DevOps plan, 16 November 2026, after the generator of a declaration was found to read the
# commit's manifests with Ruby's YAML.load_stream: a YAML tag outside the core schema can make a reader build an object
# of its own program (Psych's !ruby/object, PyYAML's !!python/object/apply), and the render box's generator, the
# repository's checks and its people's tools are such readers. No manifest needs one, so a GitOps commit through the
# door holds none in a YAML or JSON file: refused also where the same text is at HEAD. Two readings, each enough to
# refuse: the forms below in the text, before the box (a local !ruby/ or !python/ tag, the !! shorthand outside the
# core schema, a verbatim tag, an escaped character in a tag, a %TAG directive), and every tag outside the core schema
# as the box's own YAML parser resolves it (door_render.yaml_tags). The text check reads a ! only where a YAML node can
# start (NODE_AT), so a shebang, a ! in a word, in a quote or after "echo ", and ! before a space are no tag; a
# script line that starts with such a form, or with "- " before it, is refused. In a repository with a declaration
# the box's parser must have read the commit: where it could not, the commit is refused (the coordinator, 16 November
# 2026, after the review of the YAML tags).

TAG_CHAR = r"[0-9A-Za-z\-#;/?:@&=+$_.~*'()%]"      # what a tag holds after its !: YAML's ns-tag-char
# Where a YAML node, and so a tag, can start: at the start of a line, after a document mark, after ": ", "- " or "? ",
# and after [, { or , in a flow, each also after an anchor (&name). A ! inside a plain or a quoted text is none.
NODE_AT = r"(?:^[ \t]*|^---[ \t]+|[:?\-][ \t]+|[\[{,][ \t]*)(?:&[^\s,\[\]{}]+[ \t]+)?"
CORE_TAGS = r"(?:str|int|float|bool|null|seq|map)"
TAG_FORMS = (
    ("a %TAG directive", re.compile(r"^(%TAG)(?=[ \t])", re.M)),
    ("a verbatim tag (!<...>)", re.compile(NODE_AT + r"(!<)", re.M)),
    ("a tag of the !! shorthand outside the core schema",
     re.compile(NODE_AT + r"(!!(?!" + CORE_TAGS + r"(?!" + TAG_CHAR + r"))(?=" + TAG_CHAR + r"))", re.M)),
    ("a tag that names Ruby or Python", re.compile(NODE_AT + r"(!" + TAG_CHAR + r"*?(?:ruby|python))", re.M | re.I)),
    ("a tag with an escaped character", re.compile(NODE_AT + r"(!" + TAG_CHAR + r"*?%[0-9A-Fa-f]{2})", re.M)),
)
TAG_WHY = ", which no GitOps commit through the door holds: a YAML reader can build an object of its own program from it"


def tag_text_refusal(files):
    "Why a commit refuses for a form of a YAML tag in the text of one of its YAML or JSON files (TAG_FORMS), or None."
    for path, data, _mode in files:
        if data is None or not path.lower().endswith((".yaml", ".yml", ".json")):
            continue
        text = data.decode("utf-8", "replace")
        for what, pattern in TAG_FORMS:
            found = pattern.search(text)
            if found:
                line = text.count("\n", 0, found.start(1)) + 1
                return f"{path} holds {what} on line {line}{TAG_WHY}"
    return None


def tag_scan_refusal(report):
    """Why a commit refuses for a YAML tag outside the core schema that the box's parser found in one of its files
    (door_render.yaml_tags), or for no reading of the parser in a repository with a declaration, or None."""
    if report and report.get("tags") is None and (report.get("generated") or report.get("owner")):
        return (f"the door could not read the YAML tags of this commit with the box's own parser (no pinned Ruby on "
                f"the door, or a run that failed), and the repository has {DOOR_DECLARATION}: send the commit again")
    for path, found in sorted(((report or {}).get("tags") or {}).items()):
        tags = found.get("tags") if isinstance(found, dict) else None
        if tags:
            shown = re.sub(r"[^\w.:/%!<>-]", "?", str(tags[0]))[:80]
            return f"{path} holds the YAML tag {shown}, outside the core schema{TAG_WHY}"
    return None


# ---------------------------------------------------------------- the files whose changes are the owner's
#
# The coordinator of the DevOps plan, 16 November 2026, under D25 ("a weaker control is the owner's") and the owner's
# answer of 12 November 2026 for exposure, "Me, one card each time (Recommended)": an agent could change the controls
# of a GitOps repository as its own call (the script of a cluster's exposure check, its CronJob, its RBAC, admission
# policies, their alerts), and a door sync then took the change to the cluster with no card. Now the repository's
# declaration names such files (owner, door_render.owned), and a commit through the door that changes, adds or
# deletes one of them, or that writes or takes away one of their objects in another file or in a chart or a Kustomize
# folder that it renders, is the owner's: the door's existing card (kind full), with the exact change in its words,
# and the door makes that commit once, after the owner's signed yes to its call hash. A refusal stays a refusal, and
# a path that is also a generated file or a rule of one stays refused (declared_refusal), because the box takes those
# from HEAD.

OWNER_SHOWN = 40            # lines of a change of the owner's files that the decision's words show


def listed_objects(doc, depth=0):
    """The objects of one document as Kubernetes reads it (apimachinery's Unstructured.IsList, which kubectl and Argo
    CD use): any document whose items is a list is a list, whatever its kind, and only its items are applied; an item
    with no kind or apiVersion of its own takes the list's kind, less "List", and the list's apiVersion. At any depth
    (door_render.objects). A ConfigMap with items, or a List whose items have no kind, hid a held object from the
    door (the review of 22 November 2026)."""
    items = doc.get("items")
    if isinstance(items, list) and depth < 40:
        return [o for item in items if isinstance(item, dict)
                for o in listed_objects(list_item(doc, item), depth + 1)]
    return [doc]


def list_item(doc, item):
    "One item of a list with the kind and the apiVersion that Kubernetes gives it where it names none."
    kind, version = doc.get("kind"), doc.get("apiVersion")
    if not item.get("kind") and isinstance(kind, str) and kind:
        item = dict(item, kind=kind[:-4] if kind.endswith("List") else kind)
    if not item.get("apiVersion") and isinstance(version, str) and version:
        item = dict(item, apiVersion=version)
    return item


DIFF_LINES = 2000            # changed lines of a side that change_words compares line by line


def change_words(path, old, new):
    """The exact change of one file as the owner's card shows it: the lines that it loses (-) and gains (+), in their
    order, OWNER_SHOWN of them at most, each cut to GEN_LINE characters, with the count of the others. Between the
    lines that the two sides share at their start and their end, difflib compares the rest; with more than DIFF_LINES
    lines on a side it compares nothing (it took 1.7 s on 8000 changed lines, and much longer on a file of 256 KB),
    and the words give the first OWNER_SHOWN lines of each side with the counts."""
    if new is None:
        return f"{path} is deleted ({len((old or b'').splitlines())} lines at HEAD)"
    a = [] if old is None else old.decode("utf-8", "replace").splitlines()
    b = new.decode("utf-8", "replace").splitlines()
    start = next((n for n, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    end = next((n for n, (x, y) in enumerate(zip(reversed(a[start:]), reversed(b[start:]))) if x != y),
               min(len(a), len(b)) - start)
    a, b, size = a[start:len(a) - end], b[start:len(b) - end], len(a)

    def said(line):
        return line.strip()[:GEN_LINE] if line[1:].strip() else line[0]
    if old is not None and max(len(a), len(b)) > DIFF_LINES:
        shown = " | ".join(said(sign + line) for sign, side in (("-", a), ("+", b)) for line in side[:OWNER_SHOWN])
        more = len(a) + len(b) - min(len(a), OWNER_SHOWN) - min(len(b), OWNER_SHOWN)
        return (f"{path} changes {len(a)} of its {size} lines at HEAD into {len(b)} lines, too many to compare one "
                f"by one; the first of each side: {shown} | and {more} lines more")
    lines = [line for line in list(difflib.unified_diff(a, b, n=0, lineterm=""))[2:] if not line.startswith("@@")]
    gained = sum(1 for line in lines if line.startswith("+"))
    shown = " | ".join(said(line) for line in lines[:OWNER_SHOWN])
    more = len(lines) - OWNER_SHOWN
    return (f"{path} is new ({gained} lines)" if old is None else
            f"{path} loses {len(lines) - gained} lines and gains {gained}") + \
        f": {shown}" + (f" | and {more} lines more" if more > 0 else "")


def owner_objects(owned):
    "[(group, kind, namespace, name, path)] of each object that a file of the owner holds at HEAD (door_render.owned)."
    out = []
    for o in owned:
        for key in o.get("objects") or []:
            group, kind, rest = key.split(":", 2)
            namespace, _, name = rest.partition("/")
            out.append((group, kind, namespace, name, o["path"]))
    return out


def owner_keys_in(keys, objects):
    """[(key, path)]: each key of keys (object_key) that is an object of the owner's: the same group, kind and name,
    and the same namespace, or none on one side, where an app's own namespace can make them the same object."""
    out = []
    for key in sorted(k for k in keys if k):
        group, kind, rest = key.split(":", 2)
        namespace, _, name = rest.partition("/")
        out += [(key, path) for g, k, ns, n, path in objects
                if (g, k, n) == (group, kind, name) and (ns == namespace or not ns or not namespace)]
    return out


def file_objects(path, info, old, new):
    """The keys of the objects that a file of a commit holds at HEAD and after it, as the box's parser and the door's
    readers read them, or None when the door cannot read which objects it makes: a Jsonnet file, which a cluster's
    tools run. A file that is no manifest makes none."""
    name = path.lower()
    if name.endswith((".jsonnet", ".libsonnet")):
        return None
    found = set()
    for docs in (info.get("before"), info.get("after")):
        if isinstance(docs, list):
            found |= {object_key(o) for doc in docs if isinstance(doc, dict) for o in listed_objects(doc)}
    for data in (old, new):
        found |= object_keys(path, data) or set()
        if name.endswith(".json") and data is not None:
            try:
                doc = json.loads(data)
            except (ValueError, RecursionError):
                continue            # gitops_files refuses a JSON file that is no JSON
            found |= {object_key(o) for o in listed_objects(doc)} if isinstance(doc, dict) else set()
    return found


# The chain around the owner's files (the coordinator of the DevOps plan, 16 November 2026, after two reviews: "the
# control is the whole chain"). What stops a control or hides its result without touching its files is the owner's
# too, decided by what an object does and not by its kind alone, so that the routine alerts and monitors of an agent
# stay its own work:
# - a new manifest or a kustomization in a folder that an Application applies and that holds an owner's file (a
#   cluster's tools read such a folder whole, and a kustomization or a chart changes how), and a file whose name
#   differs from an owner's file only in case or in the ending that those tools read;
# - in a namespace where a workload of the owner's files runs (RUNS): a NetworkPolicy, a ResourceQuota, a LimitRange,
#   every kind of monitoring.coreos.com, an Endpoints or an EndpointSlice, a workload whose pods an owner's Service
#   selects, and that Namespace object; an object with no namespace takes the destination of the Application that
#   applies its file, and with none it is in no namespace of the owner's;
# - anywhere: an admission policy or its binding; a Prometheus, an Alertmanager, a ThanosRuler or an
#   AlertmanagerConfig (an Alertmanager that selects every config lets one in an app's namespace route or mute the
#   alerts about that namespace); a PriorityClass; a workload whose pods a NetworkPolicy of the owner's admits; and,
#   new or changed by the commit, a PrometheusRule that records a metric name that an owner's rule reads, or whose
#   labels or label functions write __name__, and a ServiceMonitor, a PodMonitor, a Probe or a ScrapeConfig that can
#   give a series a source label (SOURCE_LABELS): honorLabels, target labels or a relabeling that write one of them,
#   a labelmap, or static labels. A job label or name of its own writes job alone, and the owner's alerts read the
#   source's service and namespace too, so it fakes no result.
# Routine lines in other files (an image, a replica count, a restart time) stay the rule calls that they were.
RUNS = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "CronJob", "Job", "Pod",
        "Service")                          # the kinds whose namespace is where a control runs or answers
GUARD_KINDS = ("NetworkPolicy", "ResourceQuota", "LimitRange")
ADMISSION_GROUPS = ("admissionregistration.k8s.io", "kyverno.io", "policies.kyverno.io", "templates.gatekeeper.sh",
                    "constraints.gatekeeper.sh")
MONITORING = "monitoring.coreos.com"
SERVERS = ("Prometheus", "PrometheusAgent", "Alertmanager", "ThanosRuler", "AlertmanagerConfig")
SCRAPES = ("ServiceMonitor", "PodMonitor", "Probe", "ScrapeConfig")
SOURCE_LABELS = ("__name__", "namespace", "service", "job", "pod", "instance")
PODS = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "CronJob", "Job", "Pod")
READ_ENDS = (".yaml", ".yml", ".json")      # the endings that a cluster's tools read as manifests, in any case
MANIFEST_ENDS = READ_ENDS + (".jsonnet", ".libsonnet")
KUSTOMIZATIONS = ("kustomization.yaml", "kustomization.yml", "kustomization")


def name_variant(path):
    "A path as a cluster's tools may read the same file: in lower case, with no ending that they read as a manifest."
    name = path.casefold()
    return next((name[:-len(end)] for end in READ_ENDS if name.endswith(end)), name)


def applies(root, path):
    "True when the folder of an Application (app_roots: {root, recurse}) applies this path of the repository."
    folder, rest = root["root"], path
    if folder:
        if not path.startswith(folder + "/"):
            return False
        rest = path[len(folder) + 1:]
    return root["recurse"] or "/" not in rest


def split_key(key):
    "(group, kind, namespace, name) of an object_key."
    group, kind, rest = key.split(":", 2)
    namespace, _, name = rest.partition("/")
    return group, kind, namespace, name


def chain_words(keys, namespaces, where, default=""):
    """The words for each key (object_key) that is part of the owner's chain by its kind, before or after the commit:
    see the list above. default: the namespace of an object that names none, or '' when no Application gives one,
    and then the object is in no namespace of the owner's."""
    out = []
    for key in sorted(k for k in keys if k):
        group, kind, namespace, name = split_key(key)
        inside = (namespace or default) in namespaces
        if group in ADMISSION_GROUPS:
            out.append(f"{where} {key}, an admission policy")
        elif group == MONITORING and kind in SERVERS:
            out.append(f"{where} {key}, which runs the checks or routes their alerts")
        elif (group, kind) == ("scheduling.k8s.io", "PriorityClass"):
            out.append(f"{where} {key}, a PriorityClass, which decides which pods a full node stops")
        elif inside and (kind in GUARD_KINDS or group == MONITORING or (group, kind) in (("", "Endpoints"),
                                                                                         ("discovery.k8s.io",
                                                                                          "EndpointSlice"))):
            out.append(f"{where} {key}, in the namespace where the owner's controls run")
        elif (group, kind) == ("", "Namespace") and name in namespaces:
            out.append(f"{where} {key}, the namespace where the owner's controls run")
    return out


def source_labels(spec, depth=0):
    "What in a scrape object's spec can give a series another source's labels (SOURCE_LABELS), or None."
    if depth > 40:
        return "a spec too deep to read"
    for key, value in spec.items() if isinstance(spec, dict) else enumerate(spec if isinstance(spec, list) else []):
        if key == "honorLabels" and value is True:
            return "honorLabels: true"
        if key in ("targetLabels", "podTargetLabels") and isinstance(value, list) and \
                set(map(str, value)) & set(SOURCE_LABELS):
            return f"{key} that write {sorted(set(map(str, value)) & set(SOURCE_LABELS))[0]}"
        if key == "targetLabel" and isinstance(value, str) and (value in SOURCE_LABELS or "$" in value):
            return f"a relabeling that writes {value}"
        if key == "action" and isinstance(value, str) and value.lower() == "labelmap":
            return "a relabeling of action labelmap, which writes the names that it maps"
        if key == "labels" and isinstance(value, dict) and set(map(str, value)) & set(SOURCE_LABELS):
            return "static labels that name a source"
        if isinstance(value, (dict, list)):
            found = source_labels(value, depth + 1)
            if found:
                return found
    return None


def pod_labels(o):
    "The labels of the pods of a workload (PODS), or {}."
    spec = o.get("spec") if isinstance(o.get("spec"), dict) else {}
    if o.get("kind") == "Pod":
        meta = o.get("metadata")
    else:
        if o.get("kind") == "CronJob":
            job = spec.get("jobTemplate") if isinstance(spec.get("jobTemplate"), dict) else {}
            spec = job.get("spec") if isinstance(job.get("spec"), dict) else {}
        template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
        meta = template.get("metadata")
    labels = meta.get("labels") if isinstance(meta, dict) else None
    return {str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {}


def names_name(rule):
    "True when a rule of a PrometheusRule writes __name__: a key of its labels, or a quoted __name__ in its expression."
    labels = rule.get("labels") if isinstance(rule.get("labels"), dict) else {}
    return "__name__" in labels or bool(re.search(r"""["'`]__name__["'`]""", str(rule.get("expr") or "")))


def content_words(objs, before, namespaces, where, default, reads, selectors, admits):
    """The words for each object after the commit that is part of the owner's chain by what it does, of those that the
    commit adds or changes (before: the objects at HEAD): a PrometheusRule that records a metric name that an owner's
    rule reads (reads) or that writes __name__, a scrape object that can give a series a source label, a workload in
    the owner's namespace whose pods an owner's Service selects, and a workload whose pods an owner's NetworkPolicy
    admits."""
    known = {object_key(o): o for o in before if object_key(o)}
    out = []
    for o in objs:
        key = object_key(o)
        if not key or known.get(key) == o:
            continue                # the commit leaves this object as it is at HEAD
        group, kind, namespace, _name = split_key(key)
        namespace = namespace or default
        spec = o.get("spec")
        if (group, kind) == (MONITORING, "PrometheusRule"):
            groups = spec.get("groups") if isinstance(spec, dict) and isinstance(spec.get("groups"), list) else []
            rules = [r for g in groups if isinstance(g, dict)
                     for r in (g.get("rules") if isinstance(g.get("rules"), list) else []) if isinstance(r, dict)]
            records = {str(r["record"]) for r in rules if r.get("record")}
            if records & reads:
                out.append(f"{where} {key}, which records {sorted(records & reads)[0]}, a metric that a rule of the "
                           f"owner's reads")
            elif any(names_name(r) for r in rules):
                out.append(f"{where} {key}, which writes __name__")
        elif group == MONITORING and kind in SCRAPES:
            why = source_labels(spec)
            if why:
                out.append(f"{where} {key}, a {kind} with {why}, which can give a series a source's labels")
        elif kind in PODS and group in ("", "apps", "batch"):
            labels = pod_labels(o)
            if any(sel["selector"] and (sel["namespace"] or default) == namespace
                   and all(labels.get(k) == v for k, v in sel["selector"].items()) for sel in selectors):
                out.append(f"{where} {key}, whose pods a Service of the owner's selects")
            elif any(adm["namespace"] in ("*", namespace) and namespace
                     and all(labels.get(k) == v for k, v in adm["labels"].items()) for adm in admits):
                out.append(f"{where} {key}, whose pods a NetworkPolicy of the owner's admits")
    return out


def owner_change(report, files):
    """What of a commit is the owner's by DOOR_DECLARATION at HEAD (the report's owner, door_render.owned), as words,
    or []: each of its files that the declaration names, or a name of it that differs only in case or ending, and that
    it changes, with the exact change; each object of such a file at HEAD that the commit writes or takes away in
    another file, or in a chart or a Kustomize folder that the box rendered for it (the same object in a second place,
    which a cluster may take in its stead); each new manifest and each kustomization in a folder that an Application
    applies and that holds such a file; each object of the owner's chain (chain_words, content_words); and each file of
    the commit whose objects the door cannot read, which could hold one."""
    if not report:
        return []
    owned = report.get("owner") or []
    if not owned:
        return []
    paths = {o["path"] for o in owned}
    variants = {name_variant(p): p for p in paths}
    apps = report.get("apps")

    def destination(path):
        "The namespace of the Application that applies a path, or '' when the door does not know one."
        return next((r["namespace"] for r in apps or [] if applies(r, path) and r["namespace"]), "")
    if isinstance(apps, list):
        roots = [r for r in apps if any(applies(r, p) for p in paths)]
    else:                       # the box could not read the Applications: each folder of the owner's files, and below
        roots = [{"root": p.rpartition("/")[0], "recurse": True, "namespace": ""} for p in paths]
    objects = owner_objects(owned)
    namespaces = {ns or destination(path) for _g, kind, ns, _n, path in objects if kind in RUNS} - {""}
    reads = {r for o in owned for r in o.get("reads") or []}
    selectors = [dict(sel, namespace=sel.get("namespace") or destination(o["path"]))
                 for o in owned for sel in o.get("selectors") or [] if isinstance(sel, dict)]
    admits = [dict(adm, namespace=adm.get("namespace") or destination(o["path"]))
              for o in owned for adm in o.get("admits") or [] if isinstance(adm, dict)]
    out = []
    for path, data, _mode in files:
        info = (report.get("files") or {}).get(path) or {}
        old = None if info.get("head") is None else base64.b64decode(info["head"])
        if old == data:
            continue                # the commit leaves this file as it is at HEAD
        if path in paths or name_variant(path) in variants:
            named = variants.get(name_variant(path), path)
            out.append(change_words(path, old, data) + ("" if path in paths else f" (a name of {named})"))
            continue
        root = next((r for r in roots if applies(r, path)), None)
        folder = (root["root"] or "the top of the repository") if root else None
        if folder and path.rpartition("/")[2].casefold() in KUSTOMIZATIONS:
            out.append(f"{path} is a kustomization in {folder}, a folder of the owner's files")
        elif folder and old is None and path.casefold().endswith(MANIFEST_ENDS):
            out.append(f"{path} is a new file in {folder}, a folder of the owner's files")
        units = [report["units"][u] for u in info.get("units") or []]
        if units and all(u.get("ok") and not u.get("closed") for u in units):
            continue                # the render of each of its units says what it makes: the units, below
        found = None if units else file_objects(path, info, old, data)
        if found is None:
            out.append(f"the door cannot read which objects {path} makes, and the repository gives the owner objects")
            continue
        default = destination(path)
        out += [f"{path} holds {key}, an object of {owner}" for key, owner in owner_keys_in(found, objects)]
        out += chain_words(found, namespaces, f"{path} holds", default)
        after = docs_of(path, info.get("after"), data)
        if after is None:
            out += [f"the door cannot read what {path} holds, and its {split_key(k)[1]} can be part of the owner's "
                    f"chain" for k in sorted(k for k in found if k) if split_key(k)[0] == MONITORING
                    or split_key(k)[1] in PODS]
            continue
        before = docs_of(path, info.get("before"), old) or []
        out += content_words(after, before, namespaces, f"{path} holds", default, reads, selectors, admits)
    for _uid, unit in sorted((report.get("units") or {}).items()):
        if not unit.get("ok") or unit.get("closed"):
            continue                # its files are above: the door cannot read what it makes
        default = next((r["namespace"] for r in apps or [] if r["root"] == unit.get("root") and r["namespace"]), "")
        for group in unit.get("changed") or []:
            before = [o for o in group.get("before") or [] if isinstance(o, dict)]
            after = [o for o in group.get("after") or [] if isinstance(o, dict)]
            found = {object_key(o) for o in before + after}
            where = f"{unit_name(unit)} renders"
            out += [f"{where} {key}, an object of {owner}" for key, owner in owner_keys_in(found, objects)]
            out += chain_words(found, namespaces, where, default)
            out += content_words(after, before, namespaces, where, default, reads, selectors, admits)
    return list(dict.fromkeys(out))


def docs_of(path, docs, data):
    """The objects of one file after the commit, each as a dict (the items of a List too): the box's reading of a YAML
    file, the door's of a JSON file, [] for a file that is gone or no manifest, or None when the door cannot read them
    whole."""
    if data is None or not path.lower().endswith(READ_ENDS):
        return []
    if path.lower().endswith(".json"):
        try:
            value = json.loads(data)
        except (ValueError, RecursionError):
            return None
        return listed_objects(value) if isinstance(value, dict) else []
    if not isinstance(docs, list):
        return None                 # a stream that no reader splits
    return [o for d in docs if isinstance(d, dict) for o in listed_objects(d)]


def with_owner(d, report, files, plan, target):
    """The decision on a GitOps commit, d, with the files whose changes are the owner's: the owner's card when the
    commit touches what they hold (owner_change), with the exact change in its words. Without a report the door
    cannot tell, and with_generated refuses every commit of a repository that has a declaration."""
    said = owner_change(report, files) if report else []
    if not said:
        return d
    return Decision("full", f"{d.why}; and the commit changes what {DOOR_DECLARATION} gives the owner, which is "
                    f"the owner's to decide, once for each change: {'; '.join(said)}", target=target, plan=plan,
                    window="deploy", hash_content=d.hash_content)


# ---------------------------------------------------------------- the door's prune (DevOps plan X3)
#
# A door sync with prune deletes from the cluster what Argo CD wants to prune in one app, as Argo CD lists it in a
# listing run of the repository's caller. The owner, 12 November 2026, "The agent (Recommended)": an object that the
# agent's own commit through the door removed prunes as the agent's own call, like its other changes, also when people
# made it before the door; Git keeps the object, so a revert brings it back. Data volumes, Secrets, namespaces and
# load balancers never prune that way: those, and every object that the door cannot tie to its own commit, take the
# whole list to the owner as the door's card (kind full, his signed yes to the exact list, once). An object that a
# commit through the door added and then removed is a rule call.

APP_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
PRUNE_KEY = re.compile(r"[a-z0-9.-]{0,253}:[A-Za-z][A-Za-z0-9]{0,62}:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?/"
                       r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")     # GROUP:KIND:NAMESPACE/NAME, as argocd takes it
PRUNE_OWNER_KINDS = ("Namespace", "CustomResourceDefinition", "PersistentVolume", "PersistentVolumeClaim", "Secret")
PRUNE_MOST = 20              # objects in one prune that is no card
PRUNE_LISTED = 200           # objects that a listing may name
LISTING_MARK = "DOOR-PRUNE-LIST"
# The one line of a job's log that is the listing: GitHub's time, the mark and base64, and nothing else. The log also
# shows the step's script, and a script line that names the mark is no listing (12 November 2026, the first live run).
LISTING_LINE = re.compile(r"(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z )?" + LISTING_MARK + r" ([A-Za-z0-9+/]+={0,2})")


def object_key(doc):
    """GROUP:KIND:NAMESPACE/NAME of one object as a dict, as a prune names it, or None when it is not one."""
    meta = doc.get("metadata") if isinstance(doc, dict) else None
    api, kind = (doc.get("apiVersion"), doc.get("kind")) if isinstance(doc, dict) else (None, None)
    if not isinstance(meta, dict) or not isinstance(api, str) or not isinstance(kind, str) or kind == "List":
        return None
    group = api.rpartition("/")[0] if "/" in api else ""
    key = f"{group}:{kind}:{meta.get('namespace') or ''}/{meta.get('name')}"
    return key if isinstance(meta.get("name"), str) and PRUNE_KEY.fullmatch(key) else None


def plain_value(value):
    "The value of one block style line as text, with no comment and no quotes, or None when it is not a plain one."
    value = re.sub(r"[ \t]#.*$", "", value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value if value and not value.startswith(("{", "[", "|", ">", "&", "*", "!")) else None


def object_keys(path, data):
    """The objects of one file as a prune names them, as a set of keys, or None when code cannot read them all: a
    manifest that is not block style or JSON (manifest_text), or a document whose kind, name or namespace the door
    cannot read. A file that is no manifest holds no object for a cluster, and gives the empty set."""
    if data is None:
        return set()
    if not manifest_name(path):
        return set()
    text, why = manifest_text(path, data)
    if why or text is None:
        return None
    keys = set()
    for doc in re.split(r"^---[^\n]*\n?", text.replace("\r\n", "\n"), flags=re.M):
        top, meta, child = {}, {}, None
        within = False
        for line in doc.split("\n"):
            if not line.strip() or line.lstrip().startswith("#") or line.startswith("..."):
                continue
            if not line.startswith((" ", "\t")):
                within = False
                found = re.match(r"([A-Za-z]+):(.*)$", line)
                if found:
                    top[found.group(1)] = found.group(2)
                    within = found.group(1) == "metadata" and not found.group(2).strip()
                continue
            if within:
                indent = len(line) - len(line.lstrip(" "))
                child = indent if child is None else child
                found = re.match(r" +(name|namespace):(.*)$", line)
                if indent == child and found:
                    meta[found.group(1)] = found.group(2)
        if not top:
            continue
        api, kind = plain_value(top.get("apiVersion", "")), plain_value(top.get("kind", ""))
        name = plain_value(meta.get("name", ""))
        namespace = plain_value(meta["namespace"]) if "namespace" in meta else ""
        if not api or not kind or not name or namespace is None:
            return None
        key = object_key({"apiVersion": api, "kind": kind,
                          "metadata": {"name": name, **({"namespace": namespace} if namespace else {})}})
        if key is None:
            return None
        keys.add(key)
    return keys


def commit_objects(files, report, lookups):
    """{removed, added}: what a GitOps commit takes from the cluster and gives it, as a prune names objects. From the
    door's render of each chart and Kustomize folder that the commit touches (an object at HEAD and none after is
    removed), and from the before and after of each other file of the commit that the door reads: a plain YAML or JSON
    manifest, a deleted one too. A file that the door cannot read, at HEAD or after, gives nothing, so no object of it
    is the door's own."""
    removed, added, rendered = set(), set(), set()
    for unit in (report or {}).get("units", {}).values():
        if not unit.get("ok") or unit.get("closed"):
            continue
        for group in unit.get("changed") or []:
            before = {k for k in (object_key(o) for o in group.get("before") or []) if k}
            after = {k for k in (object_key(o) for o in group.get("after") or []) if k}
            removed |= before - after
            added |= after - before
    for path, info in ((report or {}).get("files") or {}).items():
        if info.get("units"):
            rendered.add(path)
    for path, data, _mode in files:
        if path in rendered:
            continue
        if report:
            head = (report.get("files") or {}).get(path) or {}
            old = None if head.get("head") is None else base64.b64decode(head["head"])
        else:
            old = (lookups.get("base_file") or (lambda p: None))(path)
        before, after = object_keys(path, old), object_keys(path, data)
        if before is None or after is None:
            continue
        removed |= before - after
        added |= after - before
    return {"removed": sorted(removed - added), "added": sorted(added - removed)}


def listing(text, app):
    """The objects that Argo CD wants to prune in one app, from the line LISTING_MARK of a listing run: {prune: [key],
    lb: [key of a Service of type LoadBalancer]}, or why the line is no listing. The run is on a shared runner, so the
    line is only a list to check: each key must have the form, the app must be this one, and the door decides with its
    own record."""
    found = [m.group(1) for m in (LISTING_LINE.fullmatch(line.strip()) for line in (text or "").splitlines()) if m]
    if len(found) != 1:
        return f"the listing run printed {len(found)} lines {LISTING_MARK}, not one"
    try:
        body = json.loads(base64.b64decode(found[0], validate=True))
    except (ValueError, TypeError):
        return f"the line {LISTING_MARK} is not base64 JSON"
    if not isinstance(body, dict) or body.get("app") != app or not isinstance(body.get("prune"), list) or \
            not isinstance(body.get("lb"), list):
        return f"the line {LISTING_MARK} is not the listing of {app}"
    keys = body["prune"]
    if len(keys) > PRUNE_LISTED or not all(isinstance(k, str) and PRUNE_KEY.fullmatch(k) for k in keys) or \
            len(set(keys)) != len(keys) or not all(isinstance(k, str) for k in body["lb"]):
        return f"the line {LISTING_MARK} names objects that are not GROUP:KIND:NAMESPACE/NAME, or names one twice"
    return {"prune": sorted(keys), "lb": sorted(set(body["lb"]) & set(keys))}


def decide_prune(lookups, repo, target, caller, app):
    """A sync with prune: the caller syncs the app, then prunes exactly the listed objects, each of which Argo CD must
    still want to prune in that run (its prune=yes). The list is the listing run's, never the agent's.
    rule: each object was added and then removed by commits through the door. own: each was removed by the agent's
    own commit through the door (the owner, 12 November 2026). full: anything else, the whole list to the owner."""
    found = lookups.get("prune_listing")
    if not isinstance(found, dict):
        return refused(f"the door could not read what Argo CD wants to prune in {app}: "
                       f"{found or 'no listing run'}", target=target, route="again")
    keys, lbs = found["prune"], set(found["lb"])
    base = {"repo": repo, "workflow": caller, "wait": True}
    if not keys:
        return Decision("rule", f"a sync through the listed caller: Argo CD wants to prune nothing in {app}",
                        target=target, window="deploy", plan=dict(base, inputs={"app": app}))
    removed = lookups.get("removed_object") or (lambda key: False)
    made = lookups.get("made_object") or (lambda key: False)
    owner = []
    for key in keys:
        _group, kind, rest = key.split(":", 2)
        if kind in PRUNE_OWNER_KINDS:
            owner.append(f"{key} is a {kind}")
        elif not rest.split("/", 1)[0]:
            owner.append(f"{key} has no namespace")
        elif key in lbs:
            owner.append(f"{key} is a Service of type LoadBalancer")
        elif not removed(key):
            owner.append(f"no commit through the door removed {key}")
    if len(keys) > PRUNE_MOST:
        owner.append(f"it prunes {len(keys)} objects, more than {PRUNE_MOST}")
    listed = "\n".join(keys)
    plan = dict(base, pruned=keys, inputs={"app": app, "prune": "yes", "prune_objects": listed,
                                           "prune_owner_yes": "true" if owner else "false"})
    every = ", ".join(keys)
    if owner:
        return Decision("full", f"a prune in {app} that is the owner's: {'; '.join(owner[:5])}. The whole list goes "
                        f"to the owner, because a part of it would leave the app OutOfSync: {every}", target=target,
                        window="deploy", plan=plan, hash_content=listed.encode())
    if all(made(key) for key in keys):
        return Decision("rule", f"a prune in {app} of what commits through the door made and then removed: {every}",
                        target=target, window="deploy", plan=plan, hash_content=listed.encode())
    return Decision("own", f"a prune in {app} of what its own commits through the door removed (the owner, 12 "
                    f"November 2026: \"The agent (Recommended)\"): {every}", target=target, window="deploy",
                    plan=plan, hash_content=listed.encode())


# ---------------------------------------------------------------- references to Secrets (stage A)
#
# The owner, 21 November 2026, "Yes, send it", to the door's rule for a reference to a Secret in a GitOps commit (its
# design of that day, version 3): a new reference of a pod to a Secret that exists is the door's existing card (kind
# full), with the exact change and one press; a new Secret that the commit makes for a key that the owner gave on a
# key card is to pass by itself, which is the next stage and no code here yet. One rule for every fleet. Until then:
# - each NEW reference of a pod (env[].valueFrom.secretKeyRef, envFrom[].secretRef, volumes[].secret,
#   volumes[].projected.sources[].secret, and a CSI volume's SecretProviderClass, below a mapping that has
#   containers) is the owner's card, which names it. New: the object at HEAD, looked up by its name (or its
#   generateName) in every file of the commit, in the same place, holds no reference of the same form, Secret, key
#   and namespace. The place is the Application of HEAD that applies the file, with its namespace or the object's
#   own; with no such Application, the file's folder (namespace_token): so the same namespace of two clusters'
#   folders, or of two folders that no Application names, is no same place, and only a moved object is new;
# - each other new reference (a key that ends in secretKeyRef, secretRef or secretName, in any case, a secret:
#   mapping, and, in an object of the Prometheus operator, a mapping of a name and a key and the secrets of its
#   servers) is refused, unless an object of its kind in the same place holds it at HEAD and is gone after the commit
#   (a renamed one), or holds it at all for an Ingress and a Certificate (a moved one); and so is a new object of the
#   operator's groups, of the Secrets
#   Store CSI driver, of Argo CD's Application kinds or of RBAC, and a change of one at HEAD outside the fields that
#   are free (held_change);
# - the count of MANIFEST_REFUSED reads copies of the objects in which each reference is renamed to a key that no form
#   reads, as as_block and as as_lines write them (each line of a text value at the start of a line), and the text
#   that it read before, for each form but the three of a reference;
# - check 1: a file that no parser of the door reads as objects alone (a values file), with no unit that rendered it
#   whole, and a file that a chart's source of HEAD takes as its values (whatever it holds), keeps what of it names a
#   Secret, a service account or a held kind (sensitive), where the parser read it; where no parser did, it changes
#   only on listed lines when it names one (names_secret: a service account only where the door reads no object);
#   text that no tool of a cluster reads, by the render box's word, is no such file (a README, a runbook);
# - a unit that can read a path that the door gives no agent (closed) gets the same rule, and a refusal in the place
#   of each card;
# - the words of a commit's new references fit the door's record (REFERENCES_MOST). A render's names are a template's
#   words, and a template can write there what it read: a unit's card names its chart or Kustomize folder, never an
#   object, and a Secret or a key only where that very word stands in a file of the commit.
# The holes that stay open: a workload's own Secrets (the agent can change the command or the image of a workload
# that reads a Secret already and read its log, and it builds the image); the value of its job's own key in a log;
# the words of a card are the agent's line's words, and the hub checks only the hash, the target and the action; a
# file that no parser reads and that names a Secret by a key with neither secret nor serviceaccount in it
# (auth.existing: db); a chart upgrade that changes RBAC rules or the spec of an ExternalSecret has no route (a person
# makes that commit outside the door); a folder that only an ApplicationSet's template names is in no namespace that
# the door knows apart; another operator (Argo Events, KEDA) reads a Secret by fields of its own, and can make or copy
# a Secret from an object that is the agent's own call; in a manifest that no parser reads, the count reads a
# serviceAccount: whose name: stands on the next line by that next line, not by the account; with no render box, or
# with Applications of HEAD that the box cannot read, the door knows no file that a chart takes as its values, so one
# that looks like an object (apiVersion and kind atop the values) is read as an object; an operator or an Application
# field newer than these lists is refused; a store that the Vault area cannot write has no next stage; an
# Application that is not in this repository, and a plugin that Argo CD finds by its own discover rule with no
# plugin word in the source, can read a file that the box takes as text, as they can read what no render of the door
# shows; an aggregationRule that selects ClusterRoles by a label of a chart's version (VERSION_LABELS), which is free.

REFERENCE_FORMS = ("a new secretKeyRef", "a new secretRef", "a new secret volume")
SECRET_ENDS = ("secretkeyref", "secretref", "secretname")      # the endings of a key of another reference
OPERATOR_GROUP = re.compile(r"(?:[a-z0-9-]+\.)*external-secrets\.io")
STORE_GROUP = "secrets-store.csi.x-k8s.io"      # the Secrets Store CSI driver: a SecretProviderClass reads a store
# An annotation that the operator copies to the Secret is read there by a reflector or a replicator, and one of an
# Application by a tool beside Argo CD (the image updater's pull secret): only these change
FREE_ANNOTATIONS = ("argocd.argoproj.io/", "app.kubernetes.io/", "helm.sh/", "reloader.stakater.com/")
APP_ANNOTATIONS = FREE_ANNOTATIONS + ("notifications.argoproj.io/subscribe", "link.argocd.argoproj.io/")
APP_KINDS = ("application", "applicationset", "appproject")
# The kinds whose other reference is known when an object of the kind in the same place holds it at HEAD (a renamed or
# moved Ingress): never the Prometheus operator's, whose name and key can read any Secret of the namespace.
KNOWN_OTHERS = (("networking.k8s.io", "ingress"), ("cert-manager.io", "certificate"))
RBAC_KINDS = ("role", "clusterrole", "rolebinding", "clusterrolebinding")
# The names of the kinds that held_kind holds, and of Secret, a CRD and the webhook configurations, which the commit
# rules refuse as kinds (MANIFEST_REFUSED), each also as its List: what a helm parameter's value can name (a chart's
# extraObjects[0].kind=Secret). The operator's kinds stand here by name, its group by HELD_GROUPS: a new kind of the
# operator that this list lacks is held by its group alone.
HELD_KIND_NAMES = frozenset(name + end for name in (
    ("secret", "secretproviderclass", "customresourcedefinition", "mutatingwebhookconfiguration",
     "validatingwebhookconfiguration", "externalsecret", "clusterexternalsecret", "secretstore", "clustersecretstore",
     "pushsecret", "clusterpushsecret") + RBAC_KINDS + APP_KINDS) for end in ("", "list"))
AGGREGATION = "rbac.authorization.k8s.io/"      # a ClusterRole's label of this prefix adds its rules to another's
# The labels of a chart's version, which a version bump changes on each object of the chart: Helm's, and the older
# chart: <name>-<version> that kube-prometheus-stack sets, and a plain version: 1.2.3 (Kustomize's commonLabels). Every
# other label of a ClusterRole is held: an aggregationRule in the cluster can select by any label, also one that no
# file of this repository holds (another repository's, an operator's, Kubernetes' own), so the tree's selectors say
# too little. The known limit: an aggregationRule that selects by one of these free labels, which a bump can change.
VERSION_LABELS = ("helm.sh/chart", "app.kubernetes.io/version", "chart", "version")
# What a commit may change in an Application's spec; every other field is refused, so one that the door does not know
# is closed. A source's targetRevision is free only with a chart: in a git source it can name a commit that never went
# through the door. The helm values of a source of this repository whose chart a unit rendered whole are the
# render's to decide (rendered_by); of each other source (a chart of a helm repository or of another git repository,
# which the door does not render) they are free where they name no Secret, service account or held kind (sensitive,
# sensitive_lines: also a mapping of a name and a key), and its valueFiles not at all.
APP_FREE = ("syncPolicy", "ignoreDifferences", "info")
HELM_FREE = ("values", "valuesObject", "parameters", "valueFiles")
KUSTOMIZE_FREE = ("images", "replicas")
SERVER_KINDS = ("prometheus", "prometheusagent", "alertmanager", "thanosruler")     # their spec.secrets are mounted
REFERENCES_MOST = 300       # characters of the words of a commit's new references: what door.py's record keeps
ARGOCD_SOURCE = re.compile(r"\.argocd-source(?:-[^/]*)?\.ya?ml", re.I)      # Argo CD's overrides of a source
RENDER_ONLY = "only the render names"       # a Secret or a key of a card that is no word of the commit's files
NAME_SHOWN = 63             # characters of one name in those words


def is_object(doc):
    "True for a document that a cluster applies as an object: a mapping with an apiVersion and a kind."
    return isinstance(doc, dict) and isinstance(doc.get("apiVersion"), str) and isinstance(doc.get("kind"), str)


def objects_in(docs):
    "The objects of documents, the items of a List too, at any depth."
    return [o for d in docs or [] if isinstance(d, dict) for o in listed_objects(d) if is_object(o)]


def shown(value):
    "A name out of the agent's own file as the words print it: its letters, digits and a few marks."
    return re.sub(r"[^\w.:/-]", "?", value)[:NAME_SHOWN] if isinstance(value, str) and value else "?"


def plain(value):
    "True for a name that is plain text: a text with no line break and no other control character."
    return isinstance(value, str) and re.fullmatch(r"[^\x00-\x1f\x7f\x85\u2028\u2029]+", value) is not None


def namespace_token(o, given, place, alone):
    """What stands for an object's namespace in the rule: (its own namespace, or given, the destination of the
    Application that applies it, and place, that Application's root or the unit), so that the same namespace of two
    clusters' folders is no same place; or (None, alone, its file or unit) when no Application gives one."""
    meta = o.get("metadata") if isinstance(o.get("metadata"), dict) else {}
    own = meta.get("namespace")
    if isinstance(own, str) and own:
        return own, place
    if own in (None, "") and given:
        return given, place
    return None, alone


def secret_facts(obj, namespace, strip=False):
    """Each reference to a Secret in one object (A3), as a dict: form (the form of MANIFEST_REFUSED of a pod's
    reference, or another's key as written), pod, name and key (of the Secret, as the object writes them), what (a
    Secret, or a SecretProviderClass) and ns. A pod's references stand below a mapping that has containers:
    env[].valueFrom.secretKeyRef, envFrom[].secretRef, volumes[].secret, volumes[].projected.sources[].secret and
    volumes[].csi.volumeAttributes.secretProviderClass. Each other key at any depth that ends in secretKeyRef,
    secretRef or secretName, in any case, and each other secret: mapping, is another reference; in an object of the
    Prometheus operator also each mapping of exactly a name and a key (and optional) outside a configMap and a
    selector, and the spec.secrets of its servers. strip: rename each reference's key, in place, to one that no form
    reads, for the count (A7)."""
    facts, spots, holders = [], set(), []
    group = obj.get("apiVersion", "").rpartition("/")[0].lower() if isinstance(obj.get("apiVersion"), str) else ""
    kind = obj.get("kind", "").lower() if isinstance(obj.get("kind"), str) else ""

    def field(node, name, kind):
        value = node.get(name) if isinstance(node, dict) else None
        return value if isinstance(value, kind) else kind()

    def items(node, name):
        return [x for x in field(node, name, list) if isinstance(x, dict)]

    def hold(holder, name):
        spots.add((id(holder), name))
        holders.append((holder, name))

    def pod(holder, name, form, ref, of="name", key=False, what="Secret"):
        hold(holder, name)
        found = ref if isinstance(ref, dict) else {}
        facts.append({"form": form, "pod": True, "name": found.get(of) if isinstance(ref, dict) else
                      (ref if what != "Secret" else None), "key": found.get("key") if key else None, "what": what,
                      "ns": namespace})

    def pod_spec(spec):
        for box in items(spec, "containers") + items(spec, "initContainers") + items(spec, "ephemeralContainers"):
            for env in items(box, "env"):
                held = field(env, "valueFrom", dict)
                if "secretKeyRef" in held:
                    pod(held, "secretKeyRef", "a new secretKeyRef", held["secretKeyRef"], key=True)
            for env in items(box, "envFrom"):
                if "secretRef" in env:
                    pod(env, "secretRef", "a new secretRef", env["secretRef"])
        for volume in items(spec, "volumes"):
            if "secret" in volume:
                ref = volume["secret"]
                if isinstance(ref, dict) and "secretName" in ref:
                    hold(ref, "secretName")
                pod(volume, "secret", "a new secret volume", ref, of="secretName")
            for source in items(field(volume, "projected", dict), "sources"):
                if "secret" in source:
                    pod(source, "secret", "a new secret volume", source["secret"])
            attributes = field(field(volume, "csi", dict), "volumeAttributes", dict)
            if "secretProviderClass" in attributes:
                pod(attributes, "secretProviderClass", "a new secret volume", attributes["secretProviderClass"],
                    what="SecretProviderClass")

    def other(holder, name, value):
        hold(holder, name)
        facts.append({"form": name, "pod": False, "name": value, "key": None, "what": "Secret", "ns": namespace})

    def walk(node, parent=None, above=None):
        if isinstance(node, dict):
            if "containers" in node:
                pod_spec(node)
            if group == MONITORING and above is not None and isinstance(parent, str) and \
                    name_and_key(node, parent) and (id(above), parent) not in spots:
                other(above, parent, node)
            for name, value in list(node.items()):
                low = name.lower() if isinstance(name, str) else ""
                if (id(node), name) not in spots and (low.endswith(SECRET_ENDS) or
                                                       low == "secret" and isinstance(value, dict)):
                    other(node, name, value)
                walk(value, name, node)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
    if group == MONITORING and kind in SERVER_KINDS and isinstance(spec.get("secrets"), list):
        hold(spec, "secrets")
        for name in spec["secrets"]:
            facts.append({"form": "secrets", "pod": False, "name": name, "key": None, "what": "Secret",
                          "ns": namespace})
    walk(obj)
    if strip:
        for holder, name in holders:
            if name in holder:
                n = 0
                while f"ref{n}" in holder:
                    n += 1
                holder[f"ref{n}"] = holder.pop(name)
    return facts


def stripped(docs):
    "Copies of documents with each reference to a Secret of their objects renamed to a key that no form reads (A7)."
    out = copy.deepcopy([d for d in docs or [] if isinstance(d, (dict, list))])
    for o in objects_in(out):
        secret_facts(o, None, strip=True)
    return out


def yaml_breaks(text):
    "A text with each line break that YAML reads (CR LF, CR, NEL, LS and PS) as a line feed."
    return re.sub(r"\r\n?|[\x85\u2028\u2029]", "\n", text)


def argo_set(value):
    """A value of a helm parameter as Argo CD gives it to helm's --set (cleanSetParameters): a list in braces as it is,
    and else with a backslash before each comma that has none (door_render.value_set does the same)."""
    return value if value.startswith("{") and value.endswith("}") else re.sub(r"(?<!\\),", r"\\,", value)


def neutral(text):
    "A text without the three forms of a reference, which the rule decides on the objects: what the count reads."
    for form in REFERENCE_FORMS:
        text = re.sub(MANIFEST_REFUSED[form], "", text, flags=re.M)
    return text


def fact_id(fact):
    "What makes two references the same: their form, Secret, key and namespace."
    return (fact["form"], json.dumps(fact["name"], sort_keys=True, default=str),
            json.dumps(fact["key"], sort_keys=True, default=str), fact["ns"])


def held_kind(obj):
    """The form of an object whose change the door refuses (A4): of the operator's groups, of the Secrets Store CSI
    driver, an Application, an ApplicationSet or an AppProject of Argo CD, a Role, a ClusterRole or a binding; or
    None."""
    # an apiVersion with no "/" is held by its whole text: "external-secrets.io" alone makes no object of the
    # cluster, but the door's other readers (the store route) must never take such a decoy for a store
    version = obj["apiVersion"]
    group, kind = (version.rpartition("/")[0] if "/" in version else version).lower(), obj["kind"].lower()
    if OPERATOR_GROUP.fullmatch(group):
        return "an external-secrets kind"
    if group == STORE_GROUP:
        return "a SecretProviderClass"
    if group == "argoproj.io" and kind in APP_KINDS:
        return "an Application"
    if group == "rbac.authorization.k8s.io" and kind in RBAC_KINDS:
        return "RBAC"
    return None


def notes_changed(old, new, free=FREE_ANNOTATIONS):
    "True when an object's annotations gain or change one whose key has no prefix of free."
    a, b = ((o.get("metadata") if isinstance(o.get("metadata"), dict) else {}).get("annotations") or {}
            for o in (old, new))
    if not isinstance(a, dict) or not isinstance(b, dict):
        return a != b
    return any(not (isinstance(k, str) and k.startswith(free)) for k, v in b.items() if k not in a or a[k] != v)


def helm_unescape(text):
    "A text of a helm parameter as Helm's --set reads it: a backslash keeps the character after it, and goes."
    return re.sub(r"\\(.)", r"\1", text, flags=re.S)


def helm_path(name):
    """The parts of a helm parameter's name as Helm's --set reads them: a key between dots (a backslash keeps a dot in
    it) and an index in brackets, as a number."""
    return [int(index) if index else helm_unescape(key)
            for key, index in re.findall(r"((?:\\.|[^.\[\]\\])+)|\[(\d+)\]", name, re.S)]


# A list in braces as one parameter's value: Helm reads its commas as the list's, up to its first closing brace, so a
# value with more after that brace sets more (argo_set gives it to Helm as it is)
HELM_LIST = re.compile(r"\{[^}]*\}")
# The names of held kinds that are words of plain speech too: such a value is held only as a kind's (x.kind=Secret)
PLAIN_KINDS = ("secret", "role", "application")


def helm_values(helm):
    """The values that a source's helm block gives a chart, as far as the door reads them, with each of its parameters
    set at its path as Helm's --set sets it: valuesObject, which Argo CD takes over values, else a values text in block
    style (block_tree); and whether a values text that is not block style may hold a mapping of a name and a key (the
    door then reads no tree of it)."""
    tree, loose = {}, False
    if isinstance(helm.get("valuesObject"), dict):
        tree = copy.deepcopy(helm["valuesObject"])
    elif isinstance(helm.get("values"), str) and helm["values"].strip():
        docs = None if unread(helm["values"]) else block_tree(helm["values"])
        if docs and isinstance(docs[0], dict):
            tree = docs[0]
        loose = docs is None and text_holds(helm["values"])
    for p in helm.get("parameters") if isinstance(helm.get("parameters"), list) else []:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str):
            continue
        parts, node = helm_path(p["name"]), tree
        if not parts or any(isinstance(part, int) and part > 255 for part in parts):
            continue
        for part, after in zip(parts, parts[1:] + [None]):
            new = {} if isinstance(after, str) else [] if isinstance(after, int) else str(p.get("value"))
            if isinstance(part, int) and isinstance(node, list):
                node.extend([None] * (part + 1 - len(node)))
                if after is None or not isinstance(node[part], (dict, list)):
                    node[part] = new
            elif isinstance(part, str) and isinstance(node, dict):
                if after is None or not isinstance(node.get(part), (dict, list)):
                    node[part] = new
            else:
                break
            node = node[part]
    return tree, loose


def helm_changed(key, x, y, helm=None):
    """True when a free helm field of an Application's source changes what names a Secret, a service account, RBAC or
    a held kind (sensitive): in values, valuesObject and parameters (a values text that is not block style, when it
    may hold a mapping that names one: text_holds; RBAC there changes only by the value of a listed key: rbac_changed;
    a parameter by its name as Helm reads it, with no backslash, a name with a comma or an =, which sets more than one
    value, a list of a rule of a Role, and by its value as Helm reads it where that names a held kind, its group or a
    Secret; and, given the source's two helm blocks, a mapping of a name and a key that a parameter sets a part of in
    the values that the door reads, or in a values text that it cannot read and that may hold one);
    and each change of its valueFiles, which name files whatever they hold. source_changed asks it of each source
    that no unit of the door rendered whole."""
    if key == "values" and isinstance(x or "", str) and isinstance(y or "", str):
        a, b = sensitive_lines(x or ""), sensitive_lines(y or "")
        if a is None or b is None:
            return any(text_holds(t, rbac=False) for t in (x or "", y or "")) or rbac_changed(x or "", y or "")
        return a != b
    if key == "valuesObject":
        return sensitive([x]) != sensitive([y])
    lists = (x or [], y or [])
    if key == "parameters" and all(isinstance(v, list) and all(isinstance(p, dict) for p in v) for v in lists):
        def held(p, loose):
            raw, value = (p.get("name") if isinstance(p.get("name"), str) else ""), p.get("value")
            name = helm_unescape(raw)           # Helm's --set reads a\b as ab
            value = value if isinstance(value, str) else ""
            said = helm_unescape(value).strip()
            last = next((part for part in reversed(helm_path(raw)) if isinstance(part, str)), "")
            # Argo CD writes the name as it is and the value with a backslash before each comma (argo_set): a comma or
            # an = in the name, and a comma in the value that has none, start another parameter in Helm, but in a list
            # in braces that the value is whole
            more = bool(re.search(r"[,=]", raw)) or "=" in value and not HELM_LIST.fullmatch(value) and \
                argo_set(value).replace("\\\\", "").replace("\\,", "").count(",") > 0
            # a value that is the group of a held kind or the name of one (extraDeploy[0].kind=ClusterRoleBinding),
            # or that holds a manifest that names a Secret, an account or RBAC, makes an object that no name shows
            kind = said.lower() in HELD_KIND_NAMES and (said.lower() not in PLAIN_KINDS or last.lower() == "kind")
            return sensitive_key(name) or more or text_holds(value) or text_holds(said) or kind or \
                re.match(HELD_GROUPS, said, re.I) or loose and last in ("name", "key", "optional") or re.search(
                r"(?<![a-z0-9_])(?:verbs|resources|apigroups|resourcenames|nonresourceurls)(?:[\[=]|$)", name.lower())
        blocks = helm if helm is not None else ({}, {})
        trees = [helm_values(block) if isinstance(block, dict) else ({}, False) for block in blocks]
        a, b = ([p for p in v if held(p, trees[0][1] or trees[1][1])] for v in lists)
        return a != b or helm is not None and sensitive([trees[0][0]]) != sensitive([trees[1][0]])
    return True


def source_changed(a, b, rendered=None):
    """True when a source of an Application changes outside what is free: its helm values (a source that a unit of
    the door rendered whole with this Application's own values, rendered(source), is decided by the render; for each
    other one, only what names no
    Secret, service account or held kind: helm_changed), a chart's version, and its Kustomize images and replicas."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return a != b
    seen = rendered is not None and rendered(a) and rendered(b)
    for key in set(a) | set(b):
        if key == "targetRevision" and "chart" in a and "chart" in b:
            continue
        x, y = a.get(key, {} if key in ("helm", "kustomize") else None), \
            b.get(key, {} if key in ("helm", "kustomize") else None)
        free = HELM_FREE if key == "helm" else KUSTOMIZE_FREE if key == "kustomize" else None
        if free and isinstance(x, dict) and isinstance(y, dict):      # such a block may come or go
            for k in set(x) | set(y):
                if x.get(k) == y.get(k):
                    continue
                if k not in free or key == "helm" and not seen and helm_changed(k, x.get(k), y.get(k)):
                    return True
            # the values that the parameters set a part of, whichever field of them changed (helm_values)
            if key == "helm" and not seen and x != y and helm_changed("parameters", x.get("parameters"),
                                                                    y.get("parameters"), (x, y)):
                return True
        elif x != y:
            return True
    return False


def app_spec_changed(old, new, rendered=None):
    "True when an Application's spec changes outside APP_FREE and the free fields of its sources (source_changed)."
    if not isinstance(old, dict) or not isinstance(new, dict):
        return old != new
    for key in set(old) | set(new):
        a, b = old.get(key), new.get(key)
        if key in APP_FREE:
            continue
        if key == "source":
            if source_changed(a, b, rendered):
                return True
        elif key == "sources" and isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            if any(source_changed(x, y, rendered) for x, y in zip(a, b)):
                return True
        elif a != b:               # destination, project, a source added or taken away, and each other field
            return True
    return False


def without(value, *keys):
    return {k: v for k, v in value.items() if k not in keys} if isinstance(value, dict) else value


def held_change(old, new, rendered=None):
    """True when an object that the door holds (held_kind) changes, from old at HEAD to new, outside what is free (A4).
    The operator's groups and the Secrets Store driver: the spec, the name and the namespace are compared; labels are
    free, and a new or changed annotation only with a prefix of FREE_ANNOTATIONS; apiVersion between v1beta1 and v1
    is free for the operator's kinds only. Argo CD's kinds: an Application's spec outside its free fields
    (app_spec_changed), an ApplicationSet's spec outside the free fields of its template's spec, an AppProject's spec,
    each field beside metadata and spec (an operation), and an annotation as above. RBAC: all but labels and
    annotations, and a label of the prefix AGGREGATION is no free label, nor any label of a ClusterRole but
    VERSION_LABELS: an aggregationRule can select ClusterRoles by a label of any name, and adds their rules to its
    own."""
    form = held_kind(new)
    if form in ("an external-secrets kind", "a SecretProviderClass"):
        versions = {old["apiVersion"].rpartition("/")[2], new["apiVersion"].rpartition("/")[2]}
        if len(versions) > 1 and (form != "an external-secrets kind" or versions != {"v1beta1", "v1"}):
            return True
        meta_old, meta_new = (o.get("metadata") if isinstance(o.get("metadata"), dict) else {} for o in (old, new))
        if old.get("spec") != new.get("spec") or any(meta_old.get(k) != meta_new.get(k) for k in ("name", "namespace")):
            return True
        return notes_changed(old, new)
    if form == "an Application":
        if without(old, "metadata", "spec", "status") != without(new, "metadata", "spec", "status") or \
                notes_changed(old, new, APP_ANNOTATIONS):
            return True
        a, b, kind = old.get("spec"), new.get("spec"), new["kind"].lower()
        own = rendered and (lambda source: rendered(source, new))     # this object's own values
        if kind == "application":
            return app_spec_changed(a, b, own)
        if kind == "applicationset" and isinstance(a, dict) and isinstance(b, dict):
            x, y = a.get("template"), b.get("template")
            if without(a, "template") != without(b, "template") or without(x, "spec") != without(y, "spec"):
                return True         # the generators, the templatePatch and each other field of the spec
            return isinstance(x, dict) and isinstance(y, dict) and \
                app_spec_changed(x.get("spec"), y.get("spec"), own)
        return a != b

    def bare(o):
        meta = o.get("metadata")
        if not isinstance(meta, dict):
            return without(o, "status")
        labels = meta.get("labels") or {}          # no labels, as no label of AGGREGATION: a first label is free
        if not isinstance(labels, dict):
            kept = labels
        elif o["kind"].lower() == "clusterrole":
            # a version label's value changes freely, but adding or removing one is a change (an aggregationRule can
            # select by a key's presence alone)
            kept = {k: (None if k in VERSION_LABELS else v) for k, v in labels.items()}
        else:
            kept = {k: v for k, v in labels.items() if str(k).startswith(AGGREGATION)}
        return dict(without(o, "status", "metadata"), metadata=dict(without(meta, "labels", "annotations"),
                                                                     labels=kept))
    return bare(old) != bare(new)


def head_key(o):
    """What finds an object at HEAD, with its namespace: its group, its kind, its own namespace and its name, any
    name (a ClusterRole's system:x too, which no prune names), or its generateName; None for one with neither."""
    meta = o.get("metadata") if isinstance(o.get("metadata"), dict) else {}
    name, stem = meta.get("name"), meta.get("generateName")
    if not (isinstance(name, str) and name) and not (isinstance(stem, str) and stem):
        return None
    return o["apiVersion"].rpartition("/")[0], o["kind"], str(meta.get("namespace") or ""), \
        name if isinstance(name, str) and name else ("generateName", stem)


VERSIONS_MOST = 16          # versions at HEAD of one object in one place that the rule reads (at_head)


def at_head(before):
    """{(key, namespace): [object]} of the objects at HEAD, [(object, namespace)], each version once (an object equal
    to one before it adds nothing), and VERSIONS_MOST + 1 of them at most: the rule reads each object after the commit
    against each version of it at HEAD, and 2000 versions of one name took 7.5 s, so secret_rule refuses more than
    VERSIONS_MOST. Each object is compared with the kept versions of its own key only, and nothing is written out."""
    out = {}
    for o, ns in before:
        key = head_key(o)
        if key:
            versions = out.setdefault((key, ns), [])
            if len(versions) <= VERSIONS_MOST and all(v != o for v in versions):
                versions.append(o)
    return out


def held_objects(before, after, rendered=None, heads=None):
    """[(form, object, new)]: each object after the commit that the door holds (held_kind) and that is new, or that
    changes from a version at HEAD outside what is free (held_change). before, after: [(object, namespace)]; heads:
    at_head(before), when the caller has it."""
    heads, out = at_head(before) if heads is None else heads, []
    for o, ns in after:
        form = held_kind(o)
        if form:
            old = heads.get((head_key(o), ns), []) if head_key(o) else []
            if not old or any(held_change(h, o, rendered) for h in old):
                out.append((form, o, not old))
    return out


def object_words(o):
    "One object of the agent's own file as the words name it: its kind, its own namespace and its name."
    meta = o.get("metadata") if isinstance(o.get("metadata"), dict) else {}
    name = meta.get("name") if isinstance(meta.get("name"), str) else None
    namespace = meta.get("namespace")
    return f"{shown(o['kind'])} " + (f"{shown(namespace)}/" if isinstance(namespace, str) and namespace else "") + \
        (shown(name) if name else f"{shown(meta.get('generateName'))}*")


def rule_known(pool, present):
    """The references that an object of a kind in a namespace holds at HEAD, by which another one is known
    (secret_rule's pool and after_all): for KNOWN_OTHERS, and for every kind whose object is gone after the commit.
    present: the (head_key, namespace) of each object after the commit."""
    return {(kind_of(h), ns, f["form"], json.dumps(f["name"], sort_keys=True, default=str))
            for h, ns in pool if kind_of(h) in KNOWN_OTHERS or (head_key(h), ns) not in present
            for f in secret_facts(h, ns) if not f["pod"]}


def kind_of(o):
    return o["apiVersion"].rpartition("/")[0].lower(), o["kind"].lower()


def rule_basis(before, pool=None, after_all=None):
    """What secret_rule reads of the objects at HEAD of a whole commit, once for it: their versions (at_head) and the
    references known by kind and namespace (rule_known). Read again for each file of a commit, the objects at HEAD of
    200 files took 7.7 s, and 18 s with a copy of each written out."""
    present = {(head_key(o), ns) for o, ns in after_all or [] if head_key(o)}
    return {"heads": at_head(before), "known": rule_known(before if pool is None else pool, present)}


def secret_rule(before, after, where, named=True, pool=None, words=None, card_at=None, after_all=None,
                rendered=None, basis=None):
    """The rule of references to Secrets on the objects of one place (A2 to A6). before: [(object, namespace)] at HEAD;
    after: [(object, namespace)] after the commit. where: the place, as the words name it. named: False for a render,
    whose objects the words never name, and whose Secret and key they name only where it is one of words, the words
    of the commit's own files; card_at names the place in its cards. pool: the objects at HEAD by whose kind and
    namespace another reference is known (before, when None): for an Ingress and a Certificate, when one of that kind
    in the same place holds it at HEAD; for every kind, when the one that holds it at HEAD is gone from after_all, the
    commit's objects after it (after, when None): a renamed object, and no copy. rendered(source, object): the test
    of an Application's source whose chart a unit rendered whole with that object's own values (rendered_by), for the
    objects of a file of the commit only. basis: rule_basis(before, pool, after_all), when the caller has it. (why or
    None, [(form, words)] of each new reference of a pod, which is the owner's to decide)."""
    if basis is None:
        basis = rule_basis(before, pool, after if after_all is None else after_all)
    heads = basis["heads"]
    if any(len(versions) > VERSIONS_MOST for versions in heads.values()):
        return (f"{where}: an object of the same kind, namespace and name is there in more than {VERSIONS_MOST} "
                f"versions at HEAD, which the door does not read: a person changes those files outside the door"), []
    for form, o, new in held_objects(before, after, rendered, heads):
        if new:
            return f"{where}: {form}" + ("" if named else ", more than at HEAD") + ", which no commit passes", []
        return (f"{where}: {form}: a change of {object_words(o) if named else 'the object'} at HEAD, which no commit "
                f"passes", [])
    known_others, cards, words = basis["known"], [], words or set()
    for o, ns in after:
        old = heads.get((head_key(o), ns), []) if head_key(o) else []
        if old and all(h == o for h in old):
            continue                # the commit leaves the object as it is at HEAD
        known = None                # the references that each version of it at HEAD holds, and how often
        for h in old:
            found = collections.Counter(fact_id(f) for f in secret_facts(h, ns))
            known = found if known is None else known & found
        known, seen = known or collections.Counter(), collections.Counter()
        for fact in secret_facts(o, ns):
            same = fact_id(fact)
            seen[same] += 1
            if seen[same] <= known[same]:
                continue            # a reference that the object holds at HEAD
            if not fact["pod"]:
                if (kind_of(o), ns, fact["form"],
                        json.dumps(fact["name"], sort_keys=True, default=str)) in known_others:
                    continue        # an object of its kind in its namespace holds it at HEAD: renamed or moved
                return (f"{where}: a new {shown(fact['form'])}" if named else
                        f"{where}: a new reference to a Secret outside a pod's places") + ", which no commit passes", []
            if not plain(fact["name"]) or fact["form"] == "a new secretKeyRef" and not plain(fact["key"]):
                return f"{where}: {fact['form']} to a Secret by a name that is no plain text, which no commit " \
                       f"passes", []
            name, key = fact["name"], fact["key"]
            if named:
                said = f"{object_words(o)} reads {fact['what']} {shown(name)}" + \
                    (f" key {shown(key)}" if key is not None else "")
            else:
                said = f"{card_at or where} reads " + (f"{fact['what']} {shown(name)}" if name in words else
                                                       f"a {fact['what']} that {RENDER_ONLY}") + \
                    ("" if key is None else f" key {shown(key)}" if key in words else
                     f", by a key that {RENDER_ONLY}")
            cards.append((fact["form"], f"{fact['form']}: {said}"))
    return None, cards


def same_repository(url, repo):
    """True when an Application's repoURL names this repository (owner/name on GitHub), in any of git's forms. The
    host is GitHub's own and stands first, after an optional scheme of git's network (https, http, ssh, git) and
    user: another host with the same owner and name (or one such as evilgithub.com, github.com.example.com,
    example.com/github.com, file://github.com or evil.com\\@github.com) is another repository, whose chart the door
    never read."""
    found = re.match(r"(?:(?:https?|ssh|git)://)?(?:[^@/\\\s]+@)?github\.com[:/]([^/:\s]+/[^/:\s]+?)(?:\.git)?/?$",
                     url.strip(), re.I) if isinstance(url, str) else None
    return bool(found) and found.group(1).lower() == repo.lower()


def app_key(path, o):
    """An Application or an ApplicationSet of a file as the box names the one whose values a unit rendered (the
    unit's apps, door_render.value_sets): its file, kind, name and namespace."""
    meta = o.get("metadata") if isinstance(o.get("metadata"), dict) else {}
    return [path] + [v if isinstance(v, str) else None for v in (o.get("kind"), meta.get("name"),
                                                                  meta.get("namespace"))]


def rendered_by(report, repo, revisions=lambda: {None, "", "HEAD"}):
    """The test of an Application's source whose chart a unit of the door rendered whole, test(source, app): of this
    repository, at the revision that the door rendered (one of revisions()), with no chart of a helm repository, and
    the path of such a unit's root, where that unit rendered this Application's own values (app_key: a box with no
    word of them renders no Application's). The render decides its helm values; every other source's are held where
    they name a Secret (helm_changed)."""
    units = [u for u in ((report or {}).get("units") or {}).values()
             if u.get("kind") == "helm" and u.get("ok") and not u.get("closed")]
    accepted = []

    def test(source, app):
        path, revision = source.get("path"), source.get("targetRevision")
        if "chart" in source or not isinstance(path, str) or not same_repository(source.get("repoURL"), repo):
            return False
        if not accepted:
            accepted.append(revisions())
        if not (revision is None or isinstance(revision, str)) or revision not in accepted[0]:
            return False        # the cluster renders the chart of another revision than the door's
        root = posixpath.normpath(path).strip("/")
        root = root if root not in ("", ".") else "."
        return any(u.get("root") == root and app in (u.get("apps") or []) for u in units)
    return test


def reference_card(cards, target, plan):
    """The owner's card for a commit's new references of pods (A10), the references first, or a refusal when their
    words pass what the door's record keeps."""
    counted = collections.Counter(cards)
    said = "; ".join(card + (f" ({n} times)" if n > 1 else "") for card, n in counted.items())
    if len(said) > REFERENCES_MOST:
        return refused(f"the commit makes {len(cards)} new references to Secrets, more than the door's record names "
                       f"in {REFERENCES_MOST} characters: commit fewer new references at a time", target=target)
    return Decision("full", f"{said}: a reference to a Secret, which is the owner's to decide, once for each change "
                    f"(the owner, 21 November 2026)", target=target, plan=plan, window="deploy")


def objects_text(docs):
    """Objects as the block style lines that say the same, one document each: what the patterns read of a render,
    and of a file that the real parser read. TreeLimit: tree_limit."""
    why = tree_limit(docs)
    if why:
        raise TreeLimit(why)
    return "---\n".join(as_block(doc) for doc in docs)


def unit_name(unit):
    return f"the {'chart' if unit['kind'] == 'helm' else 'Kustomize folder'} {unit['root']}"


def render_broken(report):
    "The words for the first unit that rendered at HEAD and does not render after the commit, or None."
    return next((f"{unit_name(unit)} renders at HEAD and not after this commit ({unit.get('why')})"
                 for _uid, unit in sorted(report["units"].items()) if unit.get("broke")), None)


def render_refusal(report, words=None):
    """(why the render of a commit refuses it, or None; the cards of its new references to Secrets). For each chart
    and each Kustomize folder that the door rendered, with each value set: an object that the cluster gets after the
    commit has no more of a refused form than the same object at HEAD, a new object has none, and no Secret object is
    new or changed. The rule of references to Secrets reads the objects first (secret_rule), with the objects of the
    same value set at HEAD as those that make another reference known by kind and namespace: a new reference of a pod
    is a card, and in a closed unit a refusal; the count reads the objects with each reference renamed. words: the
    words of the commit's own files, the only names out of a render that a card prints. The same reference in each
    value set of a unit is one card, and in several units one card that names each of them, where the commit's words
    name its Secret and its key (else each unit's card stays its own: a Secret that only a render names can be another
    one in each unit).
    An Application that a render makes has its helm values held where they name a Secret (helm_changed): no unit
    rendered with them."""
    apps, most = report.get("apps"), {}
    for uid, unit in sorted(report["units"].items()):
        where = unit_name(unit)
        if not unit.get("ok"):
            continue                # the door did not render it: its files kept the rules that need no render
        given = next((r["namespace"] for r in apps or [] if r["root"] == unit.get("root") and r["namespace"]), None)

        def token(o):
            return namespace_token(o, given, uid, uid)
        pools, afters, known = {}, {}, {}
        for group in unit["changed"]:
            pools.setdefault(group["set"], []).extend((o, token(o)) for o in objects_in(group["before"]))
            afters.setdefault(group["set"], []).extend((o, token(o)) for o in objects_in(group["after"]))
        for group in unit["changed"]:
            before, after = group["before"], group["after"]
            if not after:
                continue            # an object that the commit takes away adds nothing
            what = f"{where}, rendered with {group['set']}: {group['object']}"
            why = tree_limit(after) or tree_limit(before)
            if why:
                return f"{what} has {why}, after the commit or at HEAD, which the door does not read", []
            if any(isinstance(o.get("kind"), str) and o["kind"].lower() == "secret" and o not in before
                   for o in after):
                return f"{what} is a new or a changed Secret object, which no commit passes", []
            closed = unit.get("closed")
            if group["set"] not in known:       # once for each value set: for each group, 4000 of them took 13.7 s
                known[group["set"]] = rule_known(pools[group["set"]], {
                    (head_key(o), ns) for o, ns in afters[group["set"]] if head_key(o)})
            olds = [(o, token(o)) for o in objects_in(before)]
            why, found = secret_rule(olds, [(o, token(o)) for o in objects_in(after)], what, named=False,
                                     words=None if closed else words, card_at=where,
                                     basis={"heads": at_head(olds), "known": known[group["set"]]})
            if why:
                return why, []
            if found and closed:    # the door widens nothing in a unit that can read what it gives no agent
                return f"{what}: {found[0][0]}, more than at HEAD, which no commit passes", []
            # each card without the unit's name, which begins its words (card_at)
            most.setdefault((uid, group["set"]), collections.Counter()).update(
                (form, card[len(f"{form}: {where}"):]) for form, card in found)
            free_before, free_after = stripped(before), stripped(after)
            hit = manifest_refusal(objects_text(free_before), objects_text(free_after)) or \
                manifest_refusal(lines_text(free_before), lines_text(free_after))
            if hit:
                return f"{what}: {hit}, more than at HEAD, which no commit passes", []
    units = {}
    for (uid, _set), found in most.items():     # in each value set its own, and the most of any set
        units[uid] = units.get(uid, collections.Counter()) | found
    places = {}                                 # (form, the words after the unit's name): [(unit, how often)]
    for uid, found in sorted(units.items()):
        for said, n in found.items():
            places.setdefault(said, []).append((report["units"][uid], n))
    cards = []
    for (form, rest), at in places.items():
        if len(at) == 1 or RENDER_ONLY in rest:     # one unit, or Secrets that may differ in each unit: a card each
            cards += [f"{form}: {unit_name(unit)}{rest}" for unit, n in at for _ in range(n)]
        else:               # a Kustomize base that three overlays read: one card that names each of them
            cards += [f"{form}: {units_words([unit for unit, _n in at])}{rest.replace(' reads ', ' read ', 1)}"] * \
                max(n for _unit, n in at)
    return None, cards


def units_words(units):
    "Several units as one card names them: the charts a and b, and the Kustomize folders c, d and e."
    def joined(roots):
        return roots[0] if len(roots) == 1 else ", ".join(roots[:-1]) + " and " + roots[-1]
    parts = []
    for kind, one, many in (("helm", "chart", "charts"), ("kustomize", "Kustomize folder", "Kustomize folders")):
        roots = sorted(unit["root"] for unit in units if unit["kind"] == kind)
        if roots:
            parts.append(f"the {one if len(roots) == 1 else many} {joined(roots)}")
    return ", and ".join(parts)


def json_docs(path, data):
    "The one document of a JSON file as the door parses it, in a list, or None for no JSON file or no JSON."
    if data is None or not path.lower().endswith(".json"):
        return None
    try:
        return [json.loads(data)]
    except (ValueError, RecursionError):
        return None


def gitops_files(lookups, op, target, plan, files, report):
    """The decision on the files of a GitOps commit, after the path rules. report: the render of the commit, or None.
    A refusal comes before the owner's card for new references to Secrets, the card before the agent's own call, and
    that before a rule call."""
    if report:
        plan["parent"] = report.get("head")         # the commit that the door rendered: the commit's only parent
        why = render_broken(report)
        if why:
            return refused(why, target=target)
    apps = report.get("apps") if report else None
    def revisions():
        """The targetRevision words of the branch that the commit goes to, whose head the door rendered: its name, and
        no word, "" and HEAD too where it is the repository's default branch, which Argo CD reads for them."""
        try:
            default = (lookups.get("default_branch") or (lambda name: None))(target.partition(":")[2])
        except Exception:       # GitHub gave no default branch: only a branch that the door's file names is known
            default = None
        branch = plan.get("branch") or default
        names = {branch, "refs/heads/" + branch} if isinstance(branch, str) and branch else set()
        return names | ({None, "", "HEAD"} if not plan.get("branch") or plan["branch"] == default else set())
    rendered = rendered_by(report, target.partition(":")[2], revisions)

    heads_read = {}

    def head_of(path):
        "(the file at HEAD or None, its entry in the report), read once for each commit (each is a read of GitHub)"
        if path not in heads_read:
            info = report["files"].get(path) or {} if report else {}
            heads_read[path] = ((None if info.get("head") is None else base64.b64decode(info["head"])), info) \
                if report else ((lookups.get("base_file") or (lambda p: None))(path), info)
        return heads_read[path]

    def namespaced(docs, path):
        """[(object, namespace token)] of documents of one path (namespace_token): the place is the root of the
        Application of HEAD that applies the path, or the path's folder when none does or the box could not read the
        Applications of HEAD; so an object is "at HEAD" only in the same folder or under the same Application."""
        app = next((r for r in apps or [] if applies(r, path) and r["namespace"]), None) or \
            next((r for r in apps or [] if applies(r, path)), None)
        folder = path.rpartition("/")[0]
        given, place = (app["namespace"] or None, app["root"]) if app else (None, folder)
        return [(o, namespace_token(o, given, place, folder)) for o in objects_in(docs)]

    def trusted(info):
        "True when the documents of the box's reading of a YAML file are what a cluster applies, as parsed below."
        units = [report["units"][u] for u in info.get("units") or []]
        return not units or all(u.get("ok") and not u.get("closed") for u in units)
    why = commit_tree_refusal(files, head_of, report)
    if why:
        return refused(why, target=target)
    # The objects at HEAD of every file of the commit, so that an object that moves from one file to another is found
    # (A2), and one that moves to a folder of another namespace is a new object there.
    before_all, after_all = [], []
    for path, data, _mode in files:
        old, info = head_of(path)
        head = info.get("before")
        docs = json_docs(path, old) if path.lower().endswith(".json") else \
            head if isinstance(head, list) and trusted(info) and all(isinstance(d, dict) for d in head) else None
        before_all += namespaced(docs, path)
        if data is not None:            # an object of a file that the parser does not read after it is not gone
            after = info.get("after")
            read = json_docs(path, data) if path.lower().endswith(".json") else \
                after if isinstance(after, list) and trusted(info) and all(isinstance(d, dict) for d in after) else None
            after_all += namespaced(docs if read is None else read, path)
    own, cards, basis = None, [], None
    for path, data, mode in files:
        if data is None:
            own = own or f"{path} is deleted"
            continue
        old, info = head_of(path)
        units = [report["units"][u] for u in info.get("units") or []]
        # whole: every chart and Kustomize folder that reads this file rendered, so the render says what the file
        # does. A unit that can read a path that the door gives no agent (closed) is rendered and decided, and the
        # door widens nothing there: its files keep the rules that need no render.
        whole = bool(units) and all(u.get("ok") and not u.get("closed") for u in units)
        # docs: each document of a YAML file as the real parser reads it, or None for one that it does not read (a
        # template, or no object). parsed: the parser reads them all. A file of a unit that did not render is a
        # template that nobody read, whatever its text parses to.
        yaml_name = path.lower().endswith((".yaml", ".yml"))
        docs = info.get("after") if yaml_name and isinstance(info.get("after"), list) else None
        parsed = docs if docs is not None and (whole or not units) and all(isinstance(d, dict) for d in docs) else None
        unrendered = next((f". The door could not render {u['root']} ({u.get('why')}), so its files keep the rules "
                           f"that need no render" if not u.get("ok") else
                           f". {u['root']} can read a path that the door gives no agent, so its files "
                           f"keep the rules that need no render" for u in units if not u.get("ok") or u.get("closed")),
                          "")
        # ArgoCD runs a jsonnet file of a folder that it applies file by file, and no render of a chart shows it
        runs = path.lower().endswith((".jsonnet", ".libsonnet"))
        loose_yaml = block = lines = False
        text = None                 # None: nothing applies this file as it is, and only its render says what it does
        if loose_read(path, data, old) and parsed is None and (not whole or runs or (yaml_name and docs is None)):
            loose_yaml = manifest_name(path)
            # Read as it is, and then decided as the code before the block reader decided it, so that a tag or a
            # replica count in such a file stays a rule call. Such a file holds no more of each of the loose reading's
            # words than it holds at HEAD, where its own people wrote it: a new file with another name holds none.
            text, before = data.decode("utf-8", "replace"), (old or b"").decode("utf-8", "replace")
            hit = loose_danger(before, text)
            if not hit and loose_secret(text) and not loose_secret(before):
                hit = "what may be a Secret object"
            if not hit and not manifest_name(path) and manifest_keys(text) > manifest_keys(before):
                hit = "a kind or an apiVersion key"     # a text that becomes a manifest with the words it had
            if hit:
                return refused(f"{path}: {hit}, more than the file holds at HEAD, which no commit passes in a file "
                               f"that code reads only loosely: one with another name than .yaml, .yml or .json, or "
                               f"a YAML file that is not block style at HEAD{unrendered}", target=target)
            lines = True
        elif manifest_name(path):
            text, why = manifest_text(path, data)
            if not why:
                # the file at HEAD as the patterns read it; one that is not block style is counted as it is
                before = manifest_text(path, old)[0] if old else ""
                before = (old or b"").decode("utf-8", "replace") if before is None else before
                block = lines = True
            elif parsed is not None:
                # no block style, and the real parser reads every document of it: the same lines, from its reading
                head = info.get("before")
                text = objects_text(parsed)
                before = objects_text(head) if isinstance(head, list) else (old or b"").decode("utf-8", "replace")
                block = True
            elif not whole or docs is None:
                # Also in a unit that rendered: a JSON file that is no JSON with each key once, and a YAML stream
                # that the door does not split, are read by a cluster's tools in a way that the door does not know.
                return refused(f"{path} has {why}. Code reads a manifest line by line, so the door takes it only in "
                               f"block style: one plain key with its value, or one item of a list, on each line"
                               f"{unrendered}", target=target)
            elif any(isinstance(d, dict) for d in docs):
                # a template with documents that the parser reads: those are read as they are, beside the render
                head = info.get("before") if isinstance(info.get("before"), list) else []
                text = objects_text([d for d in docs if isinstance(d, dict)])
                before = objects_text([d for d in head if isinstance(d, dict)])
                block = True
        # The object reading (A1): a YAML file that the box's parser read whole, and a JSON file, which the door parses.
        # (the documents after the commit, at HEAD or None), or None for a file that no parser reads.
        reading = (json_docs(path, data), json_docs(path, old)) if path.lower().endswith(".json") and \
            text is not None else \
            (parsed, info["before"] if isinstance(info.get("before"), list) else None) if parsed is not None else None
        if text is not None:
            if secret_object(text) if block else SECRET_KIND.search(text):
                return refused(f"{path} holds a Secret object", target=target)
            if reading and reading[0] is not None:
                basis = basis or rule_basis(before_all, None, after_all)       # once for the commit
                why, found = secret_rule(before_all, namespaced(reading[0], path), path, after_all=after_all,
                                         rendered=lambda source, o, path=path: rendered(source, app_key(path, o)),
                                         basis=basis)
                if why:
                    return refused(why, target=target)
                cards += [card for _form, card in found]
                # The references are the rule's: today's text without their three forms, and the objects with each
                # reference renamed, as as_block and as as_lines write them (a text value line by line, A7)
                head = None if reading[1] is None else stripped(reading[1])
                free = stripped(reading[0])
                hit = manifest_refusal(neutral(before), neutral(text)) or \
                    manifest_refusal(neutral(before) if head is None else objects_text(head), objects_text(free)) or \
                    manifest_refusal(neutral(before) if head is None else lines_text(head), lines_text(free))
            else:
                hit = manifest_refusal(before, text)
            if hit:
                return refused(f"{path}: {hit}, which no commit passes", target=target)
        # Check 1 (A8), after the checks above: a file that no parser of the door reads as objects alone (a document
        # that is no object: a values file), with no unit that rendered it whole, and a file that a source of HEAD
        # takes as its values from another source, unless a unit rendered that source whole (the box's values: a chart
        # that the door does not render reads it as values, whatever it holds). Where the parser read it at HEAD and
        # after, what of it names a Secret, a service account or a held kind stays as it is (sensitive); else, when it
        # names one, only its listed lines change. The render decides a file that each unit reading it rendered whole,
        # so that a chart's template stays free to edit, but for a jsonnet file, which ArgoCD runs. A service account
        # counts only where the door reads no object in it.
        # Argo CD merges .argocd-source.yaml, and .argocd-source-<app>.yaml, of a source's folder into that source
        # (the image updater writes one), and no render of the door reads it: its helm and kustomize fields change
        # as those of a source that no unit rendered (source_changed), and it holds nothing else.
        if ARGOCD_SOURCE.fullmatch(path.rpartition("/")[2]):
            def overrides(docs):
                docs = [d for d in docs or [] if d is not None]
                return {} if not docs else docs[0] if len(docs) == 1 and isinstance(docs[0], dict) else None
            if reading is not None:
                now, was = overrides(reading[0]), overrides(reading[1])
            else:               # the door's own reading of block style, at HEAD and after, or none
                texts = [(b or b"").decode("utf-8", "replace") for b in (data, old)]
                now, was = (None if unread(t) else overrides(block_tree(t)) for t in texts)
            if now is None or was is None or source_changed(was, now):
                return refused(f"{path} changes what Argo CD merges into the source of an Application beyond the "
                               f"source's free fields, which no commit passes", target=target)
        held = f"{path} names a Secret, a service account or a held kind, and no parser of the door reads it: only " \
               f"an image, a tag, a replica count and a restart time change in it{unrendered}"
        # (a box that names no source's targetRevision renders none of them as the cluster does)
        named = report is not None and any(fnmatch.fnmatchcase(path, v["path"]) and not (
            "targetRevision" in v["source"] and rendered(v["source"], v.get("app")))
            for v in report.get("values") or [])
        read = reading[0] if reading and reading[0] is not None else None
        # Text that no tool of a cluster reads (a README, a runbook) is no file of check 1: a file whose name ends in
        # none of MANIFEST_ENDS, which no unit reads and no source takes as its values, where the box's any_file says
        # that no reader of the tree takes a file by any name (door_render.any_file: a jsonnet file, a plugin, a
        # templatePatch, a folder with no filter of endings, a git files generator, value files that the box cannot
        # follow, a link of a manifest's name to such a file). A folder of an Application applies the files of
        # MANIFEST_ENDS alone, a chart reads the files of its own folder, and a Kustomize folder what its
        # kustomization names, which the box follows (its units). A door with no box, and an older box, know none of
        # that: check 1 holds every file there.
        prose = report is not None and report.get("any_file") is False and info.get("units") == [] and \
            isinstance(report.get("values"), list) and not path.lower().endswith(MANIFEST_ENDS) and \
            not any(fnmatch.fnmatchcase(path, v["path"]) for v in report["values"])
        check = not prose and (named or not (whole and not runs) and
                               not (read is not None and all(is_object(d) for d in read)))
        unparsed = False
        if check and read is not None and (old is None or reading[1] is not None):
            def pick(docs):
                return [d for d in docs or [] if named or not is_object(d)]
            if sensitive(pick(read)) != sensitive(pick(reading[1])):
                return refused(held, target=target)
        elif check:
            accounts = not (object_keys(path, data) or object_keys(path, old))
            unparsed = names_secret(data.decode("utf-8", "replace"), accounts) or \
                names_secret((old or b"").decode("utf-8", "replace"), accounts)
        if old is None:
            if unparsed:
                return refused(held, target=target)
            own = own or f"{path} is a new manifest"
            continue
        changed = changed_lines(old, data)
        kept = same_keys(old, data)
        listed = changed is not None and kept and listed_before(old, data) and \
            all(LISTED_LINE.fullmatch(line) for line in changed)
        if loose_yaml and not listed:
            # A count of words cannot say what such a change does: a key that a template builds, a tag before a value
            # and a word that moves out of a comment add none. So only the listed values change in such a file.
            return refused(f"{path} is not block style, so code cannot read what this change of it does: only an "
                           f"image, a tag, a replica count and a restart time change in such a file. Write a "
                           f"manifest in block style first, as a commit of its own; a template has no such commit"
                           f"{unrendered}", target=target)
        if unparsed and not listed:
            return refused(held, target=target)
        if changed is None or not kept or not (lines or listed):
            # in a file that code does not read by lines, a line can hold more than its first key: a rule call
            # there is a change of listed lines only
            own = own or f"{path} changes more than its values"
        elif all(REPLICAS_LINE.fullmatch(line) for line in changed):
            continue
        elif all(re.fullmatch(r"\s*[\w./-]*restartedAt['\"]?\s*:\s*['\"]?[0-9T:.Z+-]{10,40}['\"]?\s*", line)
                 for line in changed):
            continue
        elif all(IMAGE_LINE.fullmatch(line) for line in changed):
            ok = image_rule(old, data, lookups)
            if ok is not True:
                own = own or ok
            elif op == "rollback" and not (lookups.get("schema_ok") or (lambda p, d: False))(path, data):
                return refused(f"the schema check of {path} failed: no rollback", target=target)
        else:
            own = own or f"{path}: other manifest lines"
    if report:
        said = {w for _path, data, _mode in files if data is not None
                for w in re.findall(r"[A-Za-z0-9._-]+", data.decode("utf-8", "replace"))}
        why, found = render_refusal(report, said)
        if why:
            return refused(why, target=target)
        cards += found
    if cards:
        return reference_card(cards, target, plan)
    if own:
        return Decision("own", own, target=target, plan=plan, window="deploy")
    return Decision("rule", "a listed GitOps change", target=target, plan=plan, window="deploy")


# ---------------------------------------------------------------- deploys

def decide_deploy(access, me, repo, op, args, lookups):
    """The repository's documented deploy, when its default branch is the last released commit plus the agent's own
    commit (one the door made), with green CI and audit, and no hold line."""
    entry = repo_entry(me, repo, ("app",))
    if entry is None or not entry.get("deploy"):
        return refused(f"{repo} has no deploy that the door runs for this agent", route="holder")
    if op != "run" or args:
        return refused("a deploy target takes run, with no arguments")
    facts = (lookups.get("deploy_facts") or (lambda r: None))(repo)
    target = f"deploy:{repo}"
    if not isinstance(facts, dict):
        return refused("the door could not read the repository's state", target=target)
    if facts.get("parent") != facts.get("released"):
        return refused("the default branch is not the last released commit plus one commit", target=target)
    if not facts.get("door_made"):
        return refused("the newest commit of the default branch is not one that the door made", target=target)
    if not facts.get("green"):
        return refused("CI and the audit are not green on the default branch", target=target)
    if facts.get("hold"):
        return refused("the repository holds its deploys now", target=target)
    return Decision("rule", "the documented deploy", target=target, window="deploy",
                    plan={"repo": repo, "workflow": entry["deploy"], "inputs": {}})
