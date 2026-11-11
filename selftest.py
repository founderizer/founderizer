#!/usr/bin/env python3
"""Self-test for the pilot hub: starts a temporary hub and exercises it the way agents and helpers would.

    python3 selftest.py        # prints failures and a summary
    python3 selftest.py -v     # prints every check

Needs nothing but Python. The sealed-handover checks are skipped when `age` is not installed.
Takes about a minute because it waits for the hub's timers. It tests hub.py only: fleet.py needs
tmux and real sessions, which is what the pilot itself is for.
"""
import ast, atexit, base64, hashlib, json, os, re, shlex, shutil, signal, socket, subprocess, sys, tempfile, threading
import time, uuid
import urllib.error, urllib.parse, urllib.request


def guard(folder, fd):
    """The guard of one run (see GONE below): it waits until every process of that run has ended, which the end of
    `fd` says, and then removes the run's folder."""
    while os.read(fd, 4096):
        pass
    shutil.rmtree(folder, ignore_errors=True)


if sys.argv[1:2] == ["--guard"]:
    guard(sys.argv[2], int(sys.argv[3]))
    sys.exit(0)

VERBOSE = "-v" in sys.argv
KIT = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="fleet-selftest-")

# No hub of this run and no file of it outlives the run, however it ends (AGENTS.md: a test stops the servers and
# removes the folders that it made). On 11 November 2026 ten hubs of ended runs still served on this Mac, the oldest
# for eight days: a run that ended early ("the hub did not start", an exception, a signal) stopped none of its hubs,
# and a caller that gives up on a run kills it with SIGKILL at its time-out (autopublish.py, releases.py, verify.py,
# test_publish.py), which no cleanup inside the run survives. So, besides finish() below:
# - every hub reads LIFE, whose write end only this process holds, and stops itself when that read ends, because
#   this process is gone (hub.py --parent-pipe);
# - a guard process reads GONE, whose write ends this process and every hub hold, so that read ends when all of
#   them have ended, and then it removes TMP. A session of its own keeps a Ctrl-C or a kill of this process group
#   from reaching it.
LIFE, LIFE_W = os.pipe()
GONE, GONE_W = os.pipe()
subprocess.Popen([sys.executable, os.path.abspath(__file__), "--guard", TMP, str(GONE)], pass_fds=(GONE,),
                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                 start_new_session=True)
os.close(GONE)
HUBS = []           # every hub this run started


def finish():
    """Every hub of this run stopped and ended, and its folder removed: at its last line, and at every early end --
    "the hub did not start", an exception, a Ctrl-C, a SIGTERM or a SIGHUP. A hub that SIGTERM has not ended in ten
    seconds gets SIGKILL. A second signal does not cut it short."""
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, signal.SIG_IGN)
    for proc in HUBS:
        if proc.poll() is None:
            proc.terminate()
    for proc in HUBS:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    shutil.rmtree(TMP, ignore_errors=True)


atexit.register(finish)
for number in (signal.SIGTERM, signal.SIGHUP):          # the default action of both ends the process with no atexit
    signal.signal(number, lambda got, frame: sys.exit(128 + got))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# The three agents these checks need, and the whole team of every hub they start: no team.json of the machine is
# read. A fleet whose owner called his agents manager, vps or studio would otherwise be checked with his own entries,
# and his studio without a browser fails checks that are about the hub's code (PRODUCT.md 4.1: a self-test that fails
# for a reason that is not the code's keeps that machine on old code). These three carry no vault and no grant
# either, so the tool sets below are the hub's own: test_create_login.py, test_call_api.py and test_google_api.py
# check the tools a grant adds, and test_vault.py broker mode, which this file's file-mode login flow is not.
REFERENCE = {
    "manager": {"role": "manager", "machine": "hub", "runtime": "claude", "can": ["shell", "web"],
                "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"},
    "vps": {"role": "worker", "machine": "vps", "runtime": "codex", "can": ["shell", "web"],
            "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"},
    "studio": {"role": "worker", "machine": "mac-studio", "runtime": "claude",
               "can": ["shell", "web", "browser", "screen"],
               "screen_command": "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex",
               "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}"},
}


def start_hub(name, addresses, *flags, agents=None, extra=None):
    port = free_port()
    team = {"hub": {"machine": "hub", "port": 8765}, "addresses": addresses,
            "agents": json.loads(json.dumps(REFERENCE))}
    if agents:          # agents of the check's own
        team["agents"].update(json.loads(json.dumps(agents)))
    team.update(json.loads(json.dumps(extra or {})))        # other entries of the check's own, a catalog of secrets
    path = os.path.join(TMP, f"{name}.json")
    json.dump(team, open(path, "w"))
    proc = subprocess.Popen([sys.executable, os.path.join(KIT, "hub.py"), "--host", "127.0.0.1", "--port", str(port),
                             "--db", os.path.join(TMP, f"{name}.db"), "--team", path, "--parent-pipe", str(LIFE),
                             *flags],
                            pass_fds=(LIFE, GONE_W), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            # a home of this run's own: ~/.fleet holds the owner's Google, MCP and GitHub App files,
                            # which are the machine's and not these checks'
                            env=dict(os.environ, HOME=TMP))
    HUBS.append(proc)
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(base + "/health", timeout=1).read()
            return proc, base
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    print("the hub did not start")
    sys.exit(1)


# The tools of each role, by name, in RULES.md's own groups: the ones every agent has, then the manager's own with
# its two duty writes, or the ones of a worker's task. set_reminder is in the first group since asking_and_waiting,
# because "come back to this at this time" was the manager's alone and belongs to every agent that has to wait.
# message_owner left it on 29 October 2026 (the owner: only the manager and his chats message him directly): a
# worker's or a lead's owner chat has it, and its task sessions do not.
# A count says only that something moved; a set says which tool moved, and RULES.md names every one of these.
# The tools a grant adds are not here: start_hub drops the grants.
EVERY_AGENT = ["read_messages", "search_knowledge", "read_knowledge", "write_knowledge", "see_responsibilities",
               "open_case", "record_step", "close_case", "attach_watch", "see_notes", "write_notes", "remember",
               "recall",
               "forget", "see_triggers", "save_trigger", "change_trigger", "set_reminder",
               "message_agent",
               # AUTONOMY.md P3: standing instructions and targets, in every session with the agent's tools
               "keep_instruction", "set_target", "end_standing", "see_standing",
               # AUTONOMY.md P6: everything an agent took part in, searched and read back
               "search_history", "read_history",
               # design v4 D2: an agent's own skills
               "write_skill",
               # support plan F4: a typed report that reached a duty of the agent joins one of its cases
               "join_report"]
MANAGER_TOOLS = EVERY_AGENT + ["create_task", "cancel_task", "restart_task", "answer", "check_result",
                               "decide_permission", "see_team", "see_capacity", "see_goals",
                               "update_goal", "record_spend", "raise_needs_you", "withdraw_need", "discuss_need", "request_secret",
                               # new-projects plan N8 (b): the door's parts on the servers after the first one
                               "door_rollout", "door_hold",
                               # DevOps plan X3: a GitOps repository through the door
                               "door_gitops",
                               "tell_owner",
                               "message_owner", "grant_access",
                               "set_duty", "change_duty", "see_history", "decide_report",
                               # AUTONOMY.md P8: the one changer of the agents with no lead
                               "set_agent_model",
                               # the owner, 5 November 2026: the summary of each knowledge file
                               "summarize_knowledge"]
WORKER_TOOLS = EVERY_AGENT + ["list_my_tasks", "report_progress", "read_attachment", "ask_my_requester",
                              "deliver_result", "sign_in", "hand_over", "resolve_outcome", "see_earlier_work",
                              "report_up",
                              # plan C17 (the owner, 26 October 2026): a worker writes its own duties
                              "set_duty", "change_duty",
                              # AUTONOMY.md P8: its own costs, and a lead its team's
                              "see_history",
                              # the owner, 29 October 2026: it asks him itself for a secret that its task needs
                              "request_secret"]
# A lead: its own task's worker tools, and the eleven team tools of RULES.md -- the first nine limited to that
# task's subtasks, the two duty writes to its own team. No check ever listed a lead's tools, because the hub these
# checks start has no lead -- which is how LEAD_TEAM_TOOLS came to hold nine where RULES.md named eight, for weeks.
# Section 1b starts a lead of its own for this one line.
LEAD_TOOLS = WORKER_TOOLS + ["create_task", "cancel_task", "restart_task", "answer", "check_result",
                             "decide_permission", "see_team", "see_capacity", "decide_report",
                             # the owner, 20 October 2026: a lead writes the duties of its own team
                             "set_duty", "change_duty",
                             # AUTONOMY.md P8: a lead is the one changer of its team's models
                             "set_agent_model"]


def tool_set(got, want):
    """Empty when the names are the same set, else which names are missing and which are extra."""
    missing, extra = sorted(set(want) - set(got)), sorted(set(got) - set(want))
    return "" if not missing and not extra else f"missing {missing}, extra {extra}"


# ---------------------------------------------------------------- every tool is named where an agent reads it
# The two checks above prove that RULES.md names every tool. That is the catalog test, and it is not enough: an
# agent reads RULES.md once, at the start of a session, before it knows which tool the work will need. In one day
# four capabilities shipped complete, tested and inert -- an agent's own notes, folding duplicate lessons, the whole
# needs_access grant route, and the manager's own reason for a task -- because nothing in an agent's own path ever
# named them. Each was found by a person noticing, which is not a process.
#
# So the stronger rule: every tool is named somewhere an agent is read to IN THE MOMENT it would reach for it. In
# this codebase that corpus is the hub's own prose -- a session's start text, the details the hub writes into a
# task, what a tool answers, a refusal, a [hub] message, a wake-up's words -- which is the string literals of
# hub.py and wakeups.py, plus one real start text read off a running hub below.
#
# What does not count, and why:
#   * a tool's own description in TOOLS and wakeups.TOOL_SPECS: that is the catalog again, the thing under test. A
#     tool only a conscientious agent finds there is a tool that ships inert, and "conscientious under pressure" is
#     not a design.
#   * RULES.md and profiles/: RULES.md is the check above, and a profile is the owner's own prose, which the fleet's
#     code can neither rely on nor keep current.
#   * docstrings: notes to whoever reads the code. No session ever sees one.
#   * the hub's own log: the owner reads it; no agent does.
#   * SQL: a column named like a tool says nothing to anybody.
#   * comments: the tree leaves them out by itself, which is the point -- hub.py explains itself in comments that
#     name tools no agent is ever told about, and they must not let a tool pass.
SQL_VERB = re.compile(r"(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|PRAGMA|BEGIN|COMMIT|VACUUM)\b", re.I)
SQL_CALLS = ("q", "q1", "ins", "read_row", "read_rows", "execute", "executemany", "executescript", "sql_step")
# Five tools are named with ordinary English words, so finding "answer" or "remember" in a sentence proves nothing
# at all. For those five the name must read as a call: "call answer", "with recall", "answer(" or "forget=".
AMBIGUOUS = ("answer", "reply", "recall", "remember", "forget")
# Tools with no honest place to be named in the moment, one line each for why. It is empty today: of the sixty-three
# every one has a moment, and the five that had none got a sentence in text that already existed (the Google levels
# now name their tools, rule 4's other half is in every task's start text, see_capacity's "wait for it" says what
# waiting is made of, a goal's spending line names the tool that writes it, and tell_owner's refusal in a chat
# points at message_owner). Anything put here must be written down deliberately, with its reason, rather than the
# rule being bent until it passes.
NO_PROMPT = {}


def tool_table(path, which, at):
    """The names in one tool table, as the source has it: TOOLS in hub.py, TOOL_SPECS in wakeups.py."""
    names = []
    for node in ast.parse(open(path).read()).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == which for t in node.targets):
            names += [e.elts[at].value for e in node.value.elts
                      if isinstance(e, ast.Tuple) and len(e.elts) > at and isinstance(e.elts[at], ast.Constant)]
    return names


def prose(path):
    """The strings of one module that an agent can end up reading: every string literal except the tool table, the
    docstrings, the log's own words and the SQL. A literal with no space in it is a name in code, not a sentence."""
    tree = ast.parse(open(path).read())
    out, skip = [], set()

    def mark(node):
        skip.update(id(n) for n in ast.walk(node))

    for node in tree.body:          # the catalog: the tool table itself
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") in ("TOOLS", "TOOL_SPECS") for t in node.targets):
            mark(node.value)
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = n.body[0] if n.body else None       # a docstring
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                skip.add(id(first.value))
        elif isinstance(n, ast.Call):
            called = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
            if called == "log":
                for arg in n.args:
                    mark(arg)
            elif called in SQL_CALLS and n.args:
                mark(n.args[0])

    def walk(node, dead):
        for child in ast.iter_child_nodes(node):
            gone = dead or id(child) in skip
            if not gone and isinstance(child, ast.Constant) and isinstance(child.value, str):
                out.append(child.value)
            elif not gone and isinstance(child, ast.JoinedStr):
                # an f-string: its own text, with each {...} standing in as a space, so no name is read across one
                out.append(" ".join(v.value for v in child.values
                                    if isinstance(v, ast.Constant) and isinstance(v.value, str)))
                for v in child.values:
                    if not isinstance(v, ast.Constant):
                        walk(v, gone)
                continue
            walk(child, gone)

    walk(tree, False)
    return [t for t in out if " " in t.strip() and not SQL_VERB.match(t.strip())]


def named_in_the_moment(name, corpus):
    """True when some text an agent reads names this tool."""
    shape = (r"(?:[Cc]all|[Uu]se|[Ww]ith|and)\s+" + name + r"\b|\b" + name + r"\s*[(=]" if name in AMBIGUOUS
             else r"(?<![\w.])" + name + r"(?![\w])")
    return any(re.search(shape, text) for text in corpus)


# studio holds the one login that vps hands over to it below: a handover goes only to an agent that holds its login
# already (DevOps plan V1). A grant adds no tool, so the tool sets of these checks stay the hub's own.
HUB_PROC, HUB = start_hub("main", {"vps": "", "mac-studio": "", "owner": ""},
                          "--silence", "6", "--question-wait", "60", "--manager-silence", "12", "--stop-after", "3",
                          "--tick", "1", "--hook-wait", "4", "--job-wait", "3",
                          agents={"studio": dict(REFERENCE["studio"],
                                                 secrets={"bws://22222222-2222-4222-8222-222222222222": "use"})})
fails, count = [], [0]


def check(name, cond, detail=""):
    count[0] += 1
    if VERBOSE or not cond:
        print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def raw(method, path, body=None, headers=None, form=None, base=None):
    if path.startswith("/hook/") and body is not None and base is None:
        task = path.rsplit("/",1)[1]
        rows = json.loads(raw("GET", "/records")[2])
        t = next((t for t in rows["tasks"] if "T-"+str(t["id"]) == task), None)
        if t:
            body = dict(body, generation=rows["db"], attempt=t["attempt"])
    h = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    req = urllib.request.Request((base or HUB) + path, data=data, method=method, headers=h)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    try:
        with op.open(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

rid = [0]
def rpc(agent, method, params=None, notify=False, base=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None: msg["params"] = params
    if not notify:
        rid[0] += 1; msg["id"] = rid[0]
    path = f"/mcp/{agent}"
    if agent in ("vps", "studio") and method == "tools/call" and (params or {}).get("arguments",{}).get("task_id") and base is None:
        records = json.loads(raw("GET", "/records")[2])
        task = params["arguments"]["task_id"]
        t = next((t for t in records["tasks"] if "T-"+str(t["id"]) == task), None)
        path += f"/{records['db']}/{task}/{t['attempt'] if t else 1}"
    code, headers, text = raw("POST", path, msg, {"Accept": "application/json, text/event-stream"}, base=base)
    try:
        return code, headers, (json.loads(text) if text else None)
    except ValueError:
        return code, headers, None

def tool(agent, name, base=None, **args):
    code, headers, resp = rpc(agent, "tools/call", {"name": name, "arguments": args}, base=base)
    res = resp["result"]
    return res["content"][0]["text"], res["isError"]

def events(agent, after=0, wait=0, alive=None):
    path = f"/events/{agent}?after={after}&wait={wait}" + (f"&alive={urllib.parse.quote(alive)}" if alive is not None else "")
    return json.loads(raw("GET", path)[2])["events"]

def later(fn, delay):
    threading.Thread(target=lambda: (time.sleep(delay), fn()), daemon=True).start()

def board():
    return raw("GET", "/board")[2]

# 0 the owner's own MCP server against the owner API it wraps (OWNER-MCP.md, OWNER-MCP-BOUNDARY.md)
# owner_mcp.py is the owner's admin server: every tool is one route of the hub's owner API. It runs on his Mac with
# the standard library alone, so it cannot import a single name from here -- it repeats the routes, the fields and
# the enums as text. These checks are the whole of the upkeep, and they are here and not only in test_owner_mcp.py
# because selftest.py is what a release runs: a lane that adds an owner route, a field or a value fails the release
# until it has decided whether the owner's own agent can reach it. Source only: no hub, no network, nothing started.

def constants(path, name):
    """One tuple, list or dict constant of a module, as the source has it (its keys, for a dict)."""
    for node in ast.parse(open(path).read()).body:
        if isinstance(node, ast.Assign) and any(getattr(x, "id", "") == name for x in node.targets):
            value = node.value
            if isinstance(value, ast.Dict):
                return tuple(k.value for k in value.keys if isinstance(k, ast.Constant))
            if isinstance(value, (ast.Tuple, ast.List)):
                return tuple(e.value for e in value.elts if isinstance(e, ast.Constant))
    return None

def owner_api_routes():
    """Every owner command route of hub.py, by the label its own ui_command call gives, with the fields it takes."""
    src, found = open(os.path.join(KIT, "hub.py")).read(), {}
    for m in re.finditer(r"\n    def (ui_\w+)\(self[^)]*\):(.*?)(?=\n    def |\Z)", src, re.S):
        name, body = m.group(1), m.group(2)
        label = re.search(r'ui_command\(\s*f?"([^"]+)"', body)
        if not label:
            continue
        fields = set()
        for pattern in (r"self\.only\(data,\s*\(([^)]*)\)", r"self\.integration_base\(data,\s*\(([^)]*)\)",
                        r"set\(data\)\s*-\s*\{([^}]*)\}"):
            for got in re.finditer(pattern, body):
                fields |= {x.strip().strip("\"'") for x in got.group(1).split(",") if x.strip()}
        route = re.sub(r"\{[^}]*\}", "{}", "/ui/" + label.group(1)).rstrip("/")
        route = {"/ui/attachment_keep": "/ui/attachments/{}/keep"}.get(route, route)
        found[route] = (name, {f for f in fields - {"request_id", "db", "base_sha256"} if f and " " not in f})
    return found

try:
    import lifecycle, owner_mcp
    OWNER_MCP = open(os.path.join(KIT, "owner_mcp.py")).read()
    API = owner_api_routes()
    check("the owner API has routes to compare at all", len(API) > 50, f"{len(API)} found")

    named = {re.sub(r"\{[^}]*\}", "{}", m.group(1)).rstrip("/") for m in re.finditer(r'"(/ui/[^"]*)"', OWNER_MCP)}
    loose = sorted(set(API) - named - set(owner_mcp.NOT_TOOLS))
    check("every owner command route is a tool of the owner's MCP server, or in its NOT_TOOLS with a reason",
          not loose, f"neither a tool nor excluded: {loose}")
    gone = sorted(r for r in owner_mcp.NOT_TOOLS if r not in API and not re.search(
        r"parts(?:\[:\d\])?\s*==\s*\[" + re.escape(", ".join(f'"{s}"' for s in r.strip("/").split("/")
                                                                  if s != "{}")) + r"\]",
        open(os.path.join(KIT, "hub.py")).read()))
    check("every route the owner's MCP server leaves out is still a route of the owner API", not gone,
          f"NOT_TOOLS names routes the hub no longer has: {gone}")

    sends = {}
    for m in re.finditer(r'(?:plain|with_base)\(\s*"(/ui/[^"]*)",\s*\(([^)]*)\)', OWNER_MCP):
        route = re.sub(r"\{[^}]*\}", "{}", m.group(1)).rstrip("/")
        sends.setdefault(route, set()).update({x.strip().strip("\"'") for x in m.group(2).split(",") if x.strip()})
        sends[route] |= set(re.findall(r"\{(\w+)\}", m.group(1)))      # a path variable rides in the path
    dropped = {}
    for route, (name, fields) in sorted(API.items()):
        if route in owner_mcp.NOT_TOOLS:
            continue
        missing = (fields - sends[route]) if route in sends else {f for f in fields if f'"{f}"' not in OWNER_MCP}
        if missing:
            dropped[route] = sorted(missing)
    check("every field an owner route takes can be sent by one of its tools",
          not dropped, f"a tool would drop these in silence: {dropped}")

    stale = []
    for name, repeated in owner_mcp.FROM_THE_HUB.items():
        module, _, attribute = name.partition(".")
        real = getattr(lifecycle, attribute, None) if module == "lifecycle" else \
            constants(os.path.join(KIT, "hub.py"), attribute)
        if real is None or tuple(real) != tuple(repeated):
            stale.append(f"{name}: it says {tuple(repeated)}, the hub says {real and tuple(real)}")
    check("what the owner's MCP server repeats from the hub is what the hub says", not stale, "; ".join(stale))

    # And the document the owner reads: a tool nobody wrote down is a tool he will not know he has.
    owner_mcp.TOOLS.update({x["name"]: x for x in owner_mcp.tools()})
    written = open(os.path.join(KIT, "OWNER-MCP.md")).read()
    unwritten = sorted(n for n in owner_mcp.TOOLS if f"`{n}`" not in written)
    check("every tool of the owner's MCP server is named in OWNER-MCP.md", not unwritten,
          f"not in the document: {unwritten}")
    table = {m for m in re.findall(r"^\| `(\w+)`", written, re.M)} | \
        {w for line in written.splitlines() if line.startswith("| `")
         for w in re.findall(r"`(\w+)`", line.split("|")[1])}
    check("every tool OWNER-MCP.md's table names is a tool the server has", not (table - set(owner_mcp.TOOLS)),
          f"the document names tools that are gone: {sorted(table - set(owner_mcp.TOOLS))}")
except Exception as owner_mcp_problem:       # a missing file or a changed shape is a failure, never a silent pass
    check("the owner's MCP server can be checked against the owner API", False, repr(owner_mcp_problem))

# 0b what a root command of a machine may be given (hubsetup.sudoers_text and the scripts it names)
#
# A machine's service user holds a few rights with root, and each one is meant to be a single mechanical act. The
# privilege in such a right is not the command, it is the argument: a root command that takes a path the caller
# chooses installs whatever that caller wrote, and the caller here is a user that runs the fleet's own code. Both of
# the fleet's instances of that shipped before anybody looked -- the repair line that read vault.py out of an
# agent's own checkout, and a rule naming a command with no argument list, which sudoers reads as "with any
# arguments the caller chooses" (sudoers(5)).
#
# So: every root right either takes no argument at all, or the command it names checks the one argument it takes
# against a closed pattern before it does anything. test_agent_users.Sudoers pins the two rules this fleet has
# today as text; this is the rule for a root right nobody has written yet, and it is here because selftest.py is
# what a release runs -- a lane that adds one fails the release until it has decided whether the caller can steer
# it. Source only: no hub, no network, nothing started, and no file of this machine is read.
#
# A guard that cannot fail is no guard, so each branch below was made to fail once before it shipped, by running
# this block against a mutated `sudoers_text` and mutated scripts: a root command the table does not know, a
# wildcard argument, a rule with no argument list at all (which sudoers reads as "any"), that rule together with a
# script that installs `$1`, a helper with its pattern check deleted, a pattern that matches a path, an effect
# before the check, and a `""` rule whose script no longer refuses an argument. All eight were caught. The last
# two shapes are this fleet's own history: the repair line that read `vault.py` out of an agent's checkout, and
# the rule that named the vault command with no argument list.

try:
    import hubsetup

    # Each root command of a machine, with the text that installs it. A `(root)` rule naming a command this table
    # does not know fails below: a new root right must be looked at, never skipped.
    ROOT_SCRIPTS = {hubsetup.HELPER: hubsetup.helper_script(),
                    hubsetup.VAULT_UPDATE: hubsetup.vault_program_script("git://100.64.0.1/fleet-pilot.git")}
    # What a line may do before the argument has been checked: say something, refuse, or set the shell up.
    PRELUDE = ("#", "set", "test", "exit", "echo", "printf", "umask", "trap", ":")

    def root_grants(user="fleet"):
        """Every `(root)` right of `sudoers_text`, as (the command's path, its argument list as sudoers has it)."""
        out = []
        for line in hubsetup.sudoers_text(user).splitlines():
            if not line or line.startswith("#") or "(root)" not in line:
                continue
            spec = line.split("NOPASSWD:", 1)[1].strip().split(None, 1)
            out.append((spec[0], spec[1].strip() if len(spec) > 1 else ""))
        return out

    def argument_check(script):
        """The line of a script that matches its one argument against a closed pattern, with that pattern: a
        whole-line `grep -qx`, which is the only form the fleet uses. (None, None) when there is none."""
        for line in script.splitlines():
            if "$1" not in line or not re.search(r"grep -qxE?\s", line):
                continue
            pattern = re.search(r"""grep -qxE?\s+(['"])(.*?)\1""", line)
            return line, pattern.group(2) if pattern else None
        return None, None

    grants = root_grants()
    check("every root right of a machine is a command this check knows",
          {path for path, _ in grants} == set(ROOT_SCRIPTS),
          f"the sudoers file grants {sorted(path for path, _ in grants)}, this check knows "
          f"{sorted(ROOT_SCRIPTS)}")
    check("no root right of a machine takes a wildcard argument",
          not [path for path, args in grants if "*" in args],
          f"a wildcard lets the caller choose: {[p for p, a in grants if '*' in a]}")

    steerable, unchecked, late, pathlike, reads_one = [], [], [], [], []
    for path, args in grants:
        script = ROOT_SCRIPTS.get(path)
        if script is None:
            continue                                    # the first check above is the one that says so
        if args == '""':
            # sudoers lets it be run with no arguments at all; the script must say the same, and read none.
            if 'test "$#" = 0' not in script:
                steerable.append(f"{path}: the rule pins no argument and the script does not refuse one")
            if "$1" in script:
                reads_one.append(f"{path}: the rule pins no argument and the script reads one")
            continue
        if args:
            continue                # an enumerated literal argument list: sudoers itself closes the set
        line, pattern = argument_check(script)
        if line is None:
            unchecked.append(f"{path}: any argument the caller chooses, and the script checks none")
            continue
        if pattern is None or "/" in pattern:
            pathlike.append(f"{path}: its argument may be a path ({pattern!r})")
        before = script.splitlines()[:script.splitlines().index(line)]
        if any("$1" in one for one in before):
            late.append(f"{path}: it reads its argument before it checks it")
        if [one for one in before if one.strip() and not one.strip().startswith(PRELUDE)]:
            late.append(f"{path}: it acts before it checks its argument "
                        f"({[o.strip()[:40] for o in before if o.strip() and not o.strip().startswith(PRELUDE)]})")

    check("a root right that takes an argument checks it against a closed pattern", not unchecked,
          "; ".join(unchecked))
    check("a root right that takes no argument refuses one", not (steerable + reads_one),
          "; ".join(steerable + reads_one))
    check("a root command checks its argument before it does anything", not late, "; ".join(late))
    check("no root command takes a path from its caller", not pathlike, "; ".join(pathlike))
except Exception as root_rights_problem:     # a changed shape is a failure, never a silent pass
    check("the root rights of a machine can be checked", False, repr(root_rights_problem))

# 1 handshake and roles
code, headers, resp = rpc("manager", "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "sim-cli", "version": "9.9"}})
check("initialize answers with the requested version", code == 200 and resp["result"]["protocolVersion"] == "2025-06-18")
check("initialize gives a session id header", any(k.lower() == "mcp-session-id" for k in headers))
code, headers, resp = rpc("manager", "initialize", {"protocolVersion": "2099-01-01", "capabilities": {}, "clientInfo": {"name": "sim-cli", "version": "9.9"}})
check("unknown protocol version falls back to a known one", resp["result"]["protocolVersion"] == "2025-06-18")
code, _, resp = rpc("manager", "notifications/initialized", notify=True)
check("a notification gets 202 and no body", code == 202 and resp is None)
check("GET on the MCP endpoint is 405", raw("GET", "/mcp/manager")[0] == 405)
check("unknown agent is 404", rpc("nobody", "ping")[0] == 404)
mt = [t["name"] for t in rpc("manager", "tools/list")[2]["result"]["tools"]]
wt = [t["name"] for t in rpc("studio", "tools/list")[2]["result"]["tools"]]
mdiff, wdiff = tool_set(mt, MANAGER_TOOLS), tool_set(wt, WORKER_TOOLS)
check("the manager's tools are the ones RULES.md names", not mdiff, mdiff)
check("a worker's tools are the ones RULES.md names", not wdiff, wdiff)

# 1b a lead, and every tool named where an agent reads it. A hub of its own: the main hub's team stays the three
# agents the rest of these checks are written for, and this one carries the two agents those checks cannot have --
# a lead, whose tools nothing ever listed, and a worker with Google, whose start text names the tools its levels
# give (the clause renders them from GOOGLE_TOOLS, so only the real text proves they are there).
MOMENT = {"pa": {"role": "lead", "machine": "pa", "runtime": "claude", "can": ["shell", "web"],
                 "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"},
          "gw": {"role": "worker", "machine": "gw", "runtime": "claude", "can": ["shell", "web"],
                 "google": {"gmail": {"account": "a@b.com", "level": "send"},
                            "drive": {"account": "a@b.com", "level": "write"}},
                 "start": "claude --permission-mode bypassPermissions --tools default {settings} {prompt}"}}
procL, hubL = start_hub("moment", {"vps": "", "mac-studio": "", "owner": ""}, "--tick", "1", agents=MOMENT)
lt = [t["name"] for t in rpc("pa", "tools/list", base=hubL)[2]["result"]["tools"]]
ldiff = tool_set(lt, LEAD_TOOLS)
check("a lead's tools are the ones RULES.md names", not ldiff, ldiff)
text, err = tool("manager", "create_task", base=hubL, owner="gw", title="Read the mail",
                 done_when="nothing; this task is only here for the words its session starts with")
check("create_task for the agent with Google", not err and "T-1" in text, text)
told = json.loads(raw("GET", "/events/gw?after=0&wait=0", base=hubL)[2])["events"]
opening = "\n".join(e["text"] for e in told)
check("a session is told the tools its Google levels give, by name and not by the name of the level",
      all(t in opening for t in ("drive_search", "drive_write", "drive_move", "gmail_read", "gmail_send")),
      opening[:500])
# The check below reads one audience's own text, because the corpus of the next one is audience-blind: every prose
# string of hub.py, whoever reads it. message_agent passed that check on seven strings and was named in no worker's
# start text -- the one text read at the moment a worker needs a colleague.
check("a worker's own start text names the other agents and the tool that reaches them",
      "YOUR TEAM" in opening and "message_agent" in opening and "pa [lead" in opening, opening[:800])
check("a start text has RULES.md read only by a session that does not hold it yet",
      "only if your context does not hold it yet" in opening, opening[:300])
# A quiet message (a release notice): never typed for, so it wakes nobody; it comes with the next read. One that waits
# for a decision (LATER_SAY) is typed for once it has waited its hour unread. The hub has no route that writes one on
# demand, so this check writes the rows the way emit() does.
import sqlite3
with sqlite3.connect(os.path.join(TMP, "moment.db"), timeout=10) as db:
    for said, created, extra in (("[hub] This fleet took release 9.9.9.", time.time(), {"quiet": True}),
                                 ("[hub] Duty sweep. The hour is up.", time.time() - 3610,
                                  {"quiet": True, "wake_after": 3600}),
                                 ("[hub] Duty sweep. Just now.", time.time(), {"quiet": True, "wake_after": 3600})):
        db.execute("INSERT INTO events(agent,kind,task,text,created,extra) VALUES(?,?,?,?,?,?)",
                   ("manager", "say", None, said, created, json.dumps(extra)))
db.close()
delivered = json.loads(raw("GET", "/events/manager?delivery=1&after=0&wait=0", base=hubL)[2])["events"]
check("a quiet message is not delivered for a signal", not any("9.9.9" in e["text"] for e in delivered), str(delivered))
check("a quiet message that waits for a decision is delivered for a signal after its hour and not before",
      any("The hour is up" in e["text"] for e in delivered) and not any("Just now" in e["text"] for e in delivered),
      str(delivered))
text, err = tool("manager", "read_messages", base=hubL)
check("a quiet message comes with the next read, and the hub's own words carry no owner-chat guidance",
      not err and "9.9.9" in text and "Just now" in text and "Owner-chat guidance" not in text, text[:300])
raw("POST", "/say", form={"text": "Morning"}, base=hubL)
text, err = tool("manager", "read_messages", base=hubL)
check("the owner's own words come with the owner-chat guidance", not err and "[owner] Morning" in text
      and "Owner-chat guidance" in text, text[:300])
procL.terminate()

# The universe this check reads: the tool tables as the source has them. Tied to the three tool lists above, so a
# tool added in a shape the parser cannot see, that an agent can nevertheless call, fails here instead of hiding.
TOOL_UNIVERSE = sorted(set(tool_table(os.path.join(KIT, "hub.py"), "TOOLS", 1))
                       | set(tool_table(os.path.join(KIT, "wakeups.py"), "TOOL_SPECS", 0)))
check("the tool tables this check reads hold every tool a session is offered",
      set(mt) | set(wt) | set(lt) <= set(TOOL_UNIVERSE),
      str(sorted((set(mt) | set(wt) | set(lt)) - set(TOOL_UNIVERSE))))
CORPUS = prose(os.path.join(KIT, "hub.py")) + prose(os.path.join(KIT, "wakeups.py")) + [opening]
unnamed = [t for t in TOOL_UNIVERSE if t not in NO_PROMPT and not named_in_the_moment(t, CORPUS)]
check("every tool is named in text an agent reads in the moment, not only in the catalog", not unnamed,
      f"named nowhere a session reads: {unnamed}. Name each one where it belongs, in the prompt of the moment it "
      f"is for, or write it into NO_PROMPT with the reason it needs none.")
check("the check itself reports a tool that nothing names",
      named_in_the_moment("deliver_result", CORPUS) and not named_in_the_moment("bottle_the_moon", CORPUS))
check("every tool excused from a prompt carries its reason",
      all(t in TOOL_UNIVERSE and str(NO_PROMPT[t]).strip() for t in NO_PROMPT), str(NO_PROMPT))
text, err = tool("studio", "raise_needs_you", title="x", why="y")
check("a worker cannot reach the owner", err and "no tool" in text, text)
check("ping", rpc("studio", "ping")[2]["result"] == {})
check("unknown method is an error", "error" in rpc("studio", "nope/nope")[2])
code, _, resp = raw("POST", "/mcp/studio", [{"jsonrpc": "2.0", "id": 91, "method": "ping"}, {"jsonrpc": "2.0", "method": "notifications/x"}], {"Accept": "application/json"})
check("a batch is answered as a list", code == 200 and isinstance(json.loads(resp), list) and len(json.loads(resp)) == 1)
b = board()
check("the board names the client that connected as the manager, and none for studio yet",
      "sim-cli 9.9" in b and "nothing yet" in b)

# 2 tasks and routing
text, err = tool("manager", "create_task", owner="vps", title="shot", done_when="file exists", needs="browser")
check("hub refuses a browser task for a machine without one", err and "studio" in text, text)
text, err = tool("manager", "create_task", owner="studio", title="Take a screenshot of example.com", done_when="outputs/example.png is pushed", needs="browser", details="Save it to outputs/example.png")
check("create_task", not err and "T-1" in text, text)
data = json.loads(raw("GET", "/events/studio?after=0&wait=0")[2])
ev = data["events"]
check("the worker's helper gets a task event with needs=browser", ev and ev[-1]["kind"] == "task" and ev[-1]["task"] == "T-1" and ev[-1]["extra"]["needs"] == "browser", str(ev))
check("the hub names its database, so a helper can tell a new one", bool(data.get("db")))
fresh = json.loads(raw("GET", "/events/studio?after=0&wait=0&fresh=1")[2])
check("a helper new to this hub is handed the task still waiting to start", [e["task"] for e in fresh["events"]] == ["T-1"] and fresh["last"] >= ev[-1]["id"], str(fresh))
text, err = tool("vps", "list_my_tasks", task_id="T-1")
check("another worker cannot open the task", err, text)
text, err = tool("studio", "list_my_tasks", task_id="T-1")
check("list_my_tasks shows the task and marks it working", not err and "[submitted]" not in text and "Done when" in text, text)
fresh = json.loads(raw("GET", "/events/studio?after=0&wait=0&fresh=1")[2])
check("a helper new to this hub is not handed a task that already started", fresh["events"] == [], str(fresh))
text, err = tool("studio", "report_progress", task_id="T-1", note="Opened the page")
check("report_progress", not err)

# Delivery is durable until the agent reads, even after a helper changes its cursor.
pending = lambda: json.loads(raw("GET", "/events/studio?delivery=1&after=999999&wait=0")[2])["events"]
check("a sent task stays pending without a read receipt", any(e["task"] == "T-1" for e in pending()))
text, err = tool("studio", "read_messages", task_id="T-1")
check("agent read returns the message and removes it from delivery", not err and "Message M-" in text and not pending())
check("the read names the start of the attempt instead of giving its text a second time",
      "list_my_tasks gives the task again" in text and "You are agent" not in text, text[:300])
records = json.loads(raw("GET", "/records")[2])
msg = {"jsonrpc":"2.0","id":900,"method":"tools/call","params":{"name":"report_progress","arguments":{"task_id":"T-1","note":"stale"}}}
resp = json.loads(raw("POST", f"/mcp/studio/{records['db']}/T-1/0", msg)[2])["result"]
check("an old attempt cannot report progress", resp["isError"] and "STOP" in resp["content"][0]["text"])
msg["params"]["name"] = "deliver_result"
msg["params"]["arguments"] = {"task_id":"T-1","what_was_done":"old","where_output_is":"old","how_checked":"old"}
resp = json.loads(raw("POST", f"/mcp/studio/{records['db']}/T-1/0", msg)[2])["result"]
check("an old attempt cannot deliver a result", resp["isError"] and "STOP" in resp["content"][0]["text"])
# 3 a question returns at once, and its answer comes as a message
t0 = time.time(); text, err = tool("studio", "ask_my_requester", task_id="T-1", question="Which\x03 colour;\x1b?")
check("a question returns at once and says the task is paused", not err and "Q-1" in text and "paused" in text and time.time() - t0 < 2, text)
mev = events("manager")
check("the manager was told about the question", any("Q-1" in e["text"] for e in mev), str(mev)[:300])
check("the inbox retains question text without typing it into a terminal", any("\x03" in e["text"] for e in mev))
check("task shows input-required", "[input-required]" in tool("manager", "see_team")[0])
# 4 the answer, and a wait that an older session asks for
text, err = tool("studio", "ask_my_requester", task_id="T-1", question="Which size?", wait_seconds=900)
check("a wait that an older session asks for is refused, and nothing is asked", err and "wait_seconds" in text, text)
before = events("studio")[-1]["id"]
text, err = tool("manager", "answer", question_id="Q-1", text="teal")
ev = events("studio", after=before)
check("the answer arrives as a message for that task's session", ev and ev[0]["kind"] == "say" and ev[0]["task"] == "T-1" and "teal" in ev[0]["text"], str(ev))
check("task is working again", "T-1 [working]" in tool("manager", "see_team")[0])
text, err = tool("manager", "answer", question_id="Q-1", text="again")
check("a question cannot be answered twice", err)

# 5 result, check, follow-up
text, err = tool("studio", "deliver_result", task_id="T-1", outcome="completed", what_was_done="Took the screenshot")
check("a completed result needs where and how", err, text)
text, err = tool("studio", "deliver_result", task_id="T-1", outcome="completed", what_was_done="Took the screenshot", where_output_is="outputs/example.png", how_checked="Opened the file")
check("deliver_result", not err and "stop now" in text, text)
text, err = tool("studio", "report_progress", task_id="T-1", note="more")
check("a finished task takes no more notes", err)
check("the manager was told about the result", any("Result for T-1" in e["text"] for e in events("manager")))
text, err = tool("manager", "check_result", task_id="T-1", accepted=False, note="The page was still loading")
check("check_result refused points to a follow-up", "follow-up" in text, text)
text, err = tool("manager", "create_task", owner="studio", title="Retake the screenshot", done_when="outputs/example.png shows the full page", needs="browser", follows="T-1")
check("follow-up task created", "T-2" in text, text)
text, err = tool("studio", "list_my_tasks", task_id="T-2")
check("the follow-up shows what it follows and why", "Follows: T-1" in text and "still loading" in text, text)
check("the first task stayed completed", "T-1" not in tool("manager", "see_team")[0].split("OPEN TASKS")[1].split("RESULTS")[0])

# 6 permission prompts through the hook
hook_body = {"hook_event_name": "PermissionRequest", "tool_name": "Bash", "tool_input": {"command": "curl -X POST http://hub/outbox -d key=k", "description": "Post to the outbox"}, "session_id": "s", "cwd": "/x"}
later(lambda: tool("manager", "decide_permission", prompt_id="P-1", decision="allow", always=True), 1.0)
t0 = time.time(); code, _, text = raw("POST", "/hook/permission/studio/T-2", hook_body)
out = json.loads(text)
check("the hook waits and returns the manager's decision", code == 200 and out["hookSpecificOutput"]["decision"]["behavior"] == "allow" and 0.8 < time.time() - t0 < 3.5, text)
hook_body["tool_input"]["description"] = "The same command, described differently"
t0 = time.time(); code, _, text = raw("POST", "/hook/permission/studio/T-2", hook_body)
check("the same command is answered from memory at once, whatever its description", json.loads(text)["hookSpecificOutput"]["decision"]["behavior"] == "allow" and time.time() - t0 < 0.5)
long_a = "echo " + "a" * 900 + " && true"
long_b = "echo " + "a" * 900 + " && rm -rf /"
later(lambda: tool("manager", "decide_permission", prompt_id="P-2", decision="allow", always=True), 0.8)
raw("POST", "/hook/permission/studio/T-2", dict(hook_body, tool_input={"command": long_a}))
later(lambda: tool("manager", "decide_permission", prompt_id="P-3", decision="deny", reason="never"), 0.8)
t0 = time.time(); code, _, text = raw("POST", "/hook/permission/studio/T-2", dict(hook_body, tool_input={"command": long_b}))
d = json.loads(text)["hookSpecificOutput"]["decision"]
check("a long command that differs only at its end is a new question", d["behavior"] == "deny" and time.time() - t0 > 0.5, text)
check("permission messages contain the full command", any(long_b in e["text"] for e in events("manager")))
check("a denial comes back with the reason", "never" in d.get("message", ""), text)
before = events("manager")[-1]["id"]
mine = events("studio")[-1]["id"]
t0 = time.time(); code, _, text = raw("POST", "/hook/permission/studio/T-2", dict(hook_body, tool_input={"command": "sudo reboot"}))
d = json.loads(text)["hookSpecificOutput"]["decision"]
check("no decision in time: the answer is no, with the way forward", d["behavior"] == "deny" and "ask your requester" in d["message"] and "run the same thing again" in d["message"] and 3.5 < time.time() - t0 < 7, text)
check("the worker's own session is told that an expiry forbids nothing",
      any("P-4 expired" in e["text"] and "run the same thing again" in e["text"] for e in events("studio", after=mine)))
mine = events("studio")[-1]["id"]
text, err = tool("manager", "decide_permission", prompt_id="P-4", decision="allow")
check("a decision that comes too late is refused, not lost", err and "expired" in text, text)
check("a late word reaches the session that holds the work and decides nothing",
      "told in its own task session" in text and
      any("manager says allow on P-4" in e["text"] for e in events("studio", after=mine)), text)
check("the requester is told the prompt expired", any("P-4" in e["text"] and "expired" in e["text"] for e in events("manager", after=before)))
check("the task is working again after the prompt", "T-2 [working]" in tool("manager", "see_team")[0])
before = events("manager")[-1]["id"]
def answer_later():
    time.sleep(0.5)
    raw("POST", "/helper/dialog/studio/T-2", {})        # the helper sees that same question on the worker's screen
    time.sleep(0.5)
    pending = [e for e in events("manager", after=before) if "Permission prompt" in e["text"]][-1]["text"]
    tool("manager", "decide_permission", prompt_id=pending.split("Permission prompt ")[1].split()[0], decision="deny")
threading.Thread(target=answer_later, daemon=True).start()
raw("POST", "/hook/permission/studio/T-2", dict(hook_body, tool_input={"command": "make install"}))
check("a prompt the hub is carrying is not reported as a question nobody can answer",
      not any("own screen" in e["text"] for e in events("manager", after=before)), str(events("manager", after=before))[:300])
raw("POST", "/helper/dialog/studio/T-2", {})
check("a question on a worker's screen with no prompt behind it is reported to the requester",
      any("own screen" in e["text"] for e in events("manager", after=before)))
tool("studio", "report_progress", task_id="T-2", note="someone answered it at the machine")
check("...and the mark clears when the session moves again", "its screen" not in tool("manager", "see_team")[0])
code, _, text = raw("POST", "/hook/activity/studio/T-2", {"tool_name": "Read"})
check("activity hook", code == 200)

# 7 needs you
text, err = tool("manager", "raise_needs_you", title="Allowance may run out", why="70% used",
                 what_to_do="Nothing is needed if you can wait until 20:00 UTC.")
check("a Needs-you item that says nothing is needed is refused", err and "tell_owner" in text, text)
text, err = tool("manager", "raise_needs_you", title="A release went out", why="It shipped")
check("a Needs-you item with nothing for the owner to do is refused", err and "what_to_do" in text, text)
text, err = tool("manager", "raise_needs_you", title="FYI: a release went out", why="It shipped", what_to_do="Read it")
check("an FYI is refused as a Needs-you item", err and "tell_owner" in text, text)
text, err = tool("manager", "raise_needs_you", title="Allowance may run out", why="70% used", what_to_do="Choose one",
                 options=["Fine, no action needed", "Add capacity"])
check("...also when only an option says nothing is needed", err and "tell_owner" in text, text)
text, err = tool("manager", "raise_needs_you", title="Pick", why="Naming", what_to_do="Choose", options=[1, 2])
check("options that are not texts are refused, not a crash", err and "options is a list" in text, text)
check("...and a refused item pages nobody", not any(e["kind"] == "notify" and "Needs you" in e["text"] for e in events("owner")))
text, err = tool("manager", "raise_needs_you", title="Pick the codename", why="Naming is the owner's choice",
                 what_to_do="Type a name. Nothing else is needed from you.")
check("raise_needs_you, also when it says nothing else is needed", "N-1" in text, text)
check("the owner gets a notification event", any(e["kind"] == "notify" and e["text"] == "Needs you: Pick the codename"
                                                 for e in events("owner")))
before = events("manager")[-1]["id"]
code, headers, _ = raw("POST", "/needs/1", form={"answer": "Tide"})
check("answering on the board redirects back", code == 303)
ev = events("manager", after=before)
check("the owner's answer reaches the manager", ev and "Tide" in ev[0]["text"], str(ev))
code, _, _ = raw("POST", "/say", form={"text": "Status please"})
check("owner message reaches the manager", any("[owner] Status please" in e["text"] for e in events("manager", after=before)))
text, err = tool("manager", "raise_needs_you", title="Stripe", why="Billing needs the key",
                 what_to_do="Please paste the Stripe secret key here.")
check("a Needs-you item that asks for a key in words is refused, naming request_secret",
      err and "request_secret" in text, text)

# 7b secret requests (owner feature secret_requests): the manager asks for a key, the owner's app answers with its
# secure form, and no value passes the manager or the hub. A hub of its own, because the answer is an owner route,
# which needs the owner's address, and the main hub has none; the catalog is in its team.json from the start, as the
# app's own step (POST /ui/secrets/add) would have left it, because that step commits team.json through git.
STRIPE = "bws://11111111-2222-4333-8444-555555555555"
procS, hubS = start_hub("secrets", {"vps": "", "mac-studio": "", "owner": "127.0.0.1"}, "--tick", "1",
                        agents={"studio": dict(REFERENCE["studio"], secrets={STRIPE: "read"})},
                        extra={"logins": {STRIPE: {"title": "STRIPE_SECRET_KEY", "kind": "api_key",
                                                   "env": "STRIPE_SECRET_KEY"}}})


def owner_ui(path, body, base=None):
    db = json.loads(raw("GET", "/ui/state", base=base)[2])["db"]
    return raw("POST", path, dict({"request_id": str(uuid.uuid4()), "db": db}, **body),
               {"X-Fleet-Client": "selftest"}, base=base)


text, err = tool("manager", "request_secret", base=hubS, why="Charge customers")
check("request_secret: an API key needs its variable name", err and "needs env" in text, text)
text, err = tool("manager", "request_secret", base=hubS, kind="login", why="Read the payouts")
check("request_secret: a login needs its sign-in page", err and "needs site" in text, text)
text, err = tool("manager", "request_secret", base=hubS, kind="login", site="https://dash.example.com", why="x",
                 give_to={"vps": "read"})
check("request_secret: nobody reads a login", err and '"use"' in text, text)
text, err = tool("manager", "request_secret", base=hubS, env="STRIPE_SECRET_KEY", why="Billing")
check("request_secret: a key the catalog has is refused, with its reference", err and STRIPE in text, text)
text, err = tool("manager", "request_secret", base=hubS, env="OPENAI_API_KEY", site="https://api.openai.com",
                 why="studio writes the product copy", give_to={"studio": "read"})
check("request_secret raises a Needs-you item and says the value never passes the manager",
      not err and "N-1" in text and "never its value" in text, text)
text, err = tool("manager", "request_secret", base=hubS, env="OPENAI_API_KEY", why="again")
check("...and the same request again raises nothing", not err and "N-1 already asks" in text, text)
need = json.loads(raw("GET", "/ui/state", base=hubS)[2])["needs"][0]
check("the owner's app reads what the item asks for", need["kind"] == "secret" and need["secret"] == {
    "kind": "api_key", "env": "OPENAI_API_KEY", "site": "https://api.openai.com", "give": {"studio": "read"}}, need)
code, _, text = owner_ui("/ui/needs/1", {"answer": "sk-proj-abcdef0123456789"}, base=hubS)
check("a secret request takes no answer in words", code == 409 and "no answer in words" in text, text)
code, _, _ = raw("POST", "/needs/1", form={"answer": "sk-proj-abcdef0123456789"}, base=hubS)
check("...not on the board either", code == 303 and "This page takes no secret" in raw("GET", "/board", base=hubS)[2]
      and not json.loads(raw("GET", "/ui/state", base=hubS)[2])["needs"][0]["answer"])
said = "\n".join(e["text"] for e in json.loads(raw("GET", "/events/manager?after=0&wait=0", base=hubS)[2])["events"])
check("...and no word of it reached the manager", "sk-proj" not in said, said[-300:])
code, _, text = owner_ui("/ui/needs/1/secret", {"login": "bws://99999999-2222-4333-8444-555555555555"}, base=hubS)
check("the secure answer names a secret of the catalog", code == 404, text)
code, _, text = owner_ui("/ui/needs/1/secret", {"login": STRIPE, "value": "x"}, base=hubS)
check("the secure answer takes no value", code == 400 and "unknown field" in text, text)
answer_id = str(uuid.uuid4())
code, _, text = owner_ui("/ui/needs/1/secret", {"login": STRIPE, "request_id": answer_id}, base=hubS)
check("the secure answer is accepted", code == 200 and json.loads(text)["login"] == STRIPE, text)
said = json.loads(raw("GET", "/events/manager?after=0&wait=0", base=hubS)[2])["events"][-1]["text"]
check("the manager reads the secret's name, its reference and who holds it, in the hub's words",
      "Answer to Needs-you N-1" in said and STRIPE in said and "studio (reads it as $STRIPE_SECRET_KEY)" in said
      and "Its variable is STRIPE_SECRET_KEY, not OPENAI_API_KEY" in said, said)
code, _, text = owner_ui("/ui/needs/1/secret", {"login": STRIPE, "request_id": answer_id}, base=hubS)
check("the same answer again is a replay", code == 200 and json.loads(text)["replayed"], text)
code, _, text = owner_ui("/ui/needs/1/secret", {"decline": "no"}, base=hubS)
check("an answered secret request takes no second answer", code == 409, text)
text, err = tool("manager", "request_secret", base=hubS, kind="login", site="https://dash.example.com/login",
                 why="vps reads the payouts", give_to={"vps": "use"})
check("request_secret asks for a login", not err and "a login for dash.example.com" in text, text)
code, _, text = owner_ui("/ui/needs/2/secret", {"decline": "Use the test account first"}, base=hubS)
said = json.loads(raw("GET", "/events/manager?after=0&wait=0", base=hubS)[2])["events"][-1]["text"]
check("a declined secret request reaches the manager in the owner's words",
      code == 200 and "Not given: Use the test account first" in said, text + said)
text, err = tool("manager", "raise_needs_you", base=hubS, title="Shop key", why="Fleet Vault has none",
                 what_to_do="Paste the shop's API key into Fleet Vault on your Mac.")
check("a Needs-you item that sends the owner to their own app passes", not err and "N-3" in text, text)
code, _, text = owner_ui("/ui/needs/3/secret", {"decline": ""}, base=hubS)
check("an item that asks for no secret takes no secure answer", code == 409, text)
# DevOps plan V1: the central vault is the one way a value reaches a server. The owner's own sealed copies to each
# machine are gone (secret_deliveries), the app signs each grant (signed_grants), and no secret comes in while no
# central vault answers: this hub has none.
state = json.loads(raw("GET", "/ui/state", base=hubS)[2])
check("the hub offers signed_grants and no longer secret_deliveries",
      "signed_grants" in state["ui_features"] and "secret_deliveries" not in state["ui_features"], state["ui_features"])
code, _, text = raw("GET", f"/ui/secrets/machines?db={state['db']}&login={urllib.parse.quote(STRIPE)}", base=hubS)
check("the owner's copies to each machine are gone", code == 404, text)
code, _, text = owner_ui("/ui/secrets/deliver", {"login": STRIPE, "copies": []}, base=hubS)
check("...and so is the route that took them", code == 404, text)
code, _, text = owner_ui("/ui/secrets/add", {"login": "bws://99999999-2222-4333-8444-555555555555", "title": "NEW_KEY",
                                             "kind": "api_key", "env": "NEW_KEY"}, base=hubS)
check("no secret is added while no central vault answers", code == 503 and "central vault" in text, text)
# Owner feature live_changes: the apps wait on GET /ui/wait and read the moment something they show changes (the owner,
# 25 October 2026: "it needs to be immediate"). Last on this hub, so the write it makes moves no later check.
state = json.loads(raw("GET", "/ui/state", base=hubS)[2])
check("the hub offers live_changes, and /ui/state carries its token",
      "live_changes" in state["ui_features"] and isinstance(state.get("token"), str), state.get("token"))
started = time.monotonic()
code, _, text = raw("GET", f"/ui/wait?db={state['db']}&since=another-boot.0.0&wait=10", base=hubS)
check("a wait that names another boot answers at once", code == 200 and time.monotonic() - started < 5, text)
woke = {}
waiter = threading.Thread(target=lambda: woke.update(answer=raw(
    "GET", f"/ui/wait?db={state['db']}&since={state['token']}&wait=20", base=hubS)))
started = time.monotonic()
waiter.start()
time.sleep(0.5)
tool("manager", "raise_needs_you", base=hubS, title="Live", why="a selftest check",
     what_to_do="Nothing: this item is a selftest check.")
waiter.join(25)
answer = json.loads((woke.get("answer") or (0, {}, "{}"))[2] or "{}")
check("a change the owner sees wakes a waiting app before its wait ends",
      answer.get("token") not in (None, state["token"]) and time.monotonic() - started < 15, woke.get("answer"))
procS.terminate()

# 8 outbox, practice site, fingerprints, seatbelt
check("outbox starts empty", json.loads(raw("GET", "/outbox?key=launch")[2])["count"] == 0)
raw("POST", "/outbox", form={"key": "launch", "text": "hello"})
check("outbox counts one send", json.loads(raw("GET", "/outbox?key=launch")[2])["count"] == 1)
check("the manager can see the outbox count without a shell", "launch: 1" in tool("manager", "see_team")[0])
password = "Zq7Lm2Xc9Vb4Nn8K"
salt = "ab12"
raw("POST", "/secrets", {"label": "pilot-site", "salt": salt, "len": len(password), "hash": hashlib.sha256((salt + password).encode()).hexdigest(), "username": "pilot"})
code, _, text = raw("POST", "/site/login", form={"username": "pilot", "password": "wrong"})
check("wrong login is refused", code == 200 and "Wrong login" in text)
code, headers, text = raw("POST", "/site/login", form={"username": "pilot", "password": password})
cookie = headers.get("Set-Cookie", "").split(";")[0]
check("right login is accepted", code == 303 and cookie.startswith("pilot="))
code, _, text = raw("GET", "/site/account", headers={"Cookie": cookie})
check("the account page shows the phrase", code == 200 and "The phrase is" in text)
check("the account page says who signed in", "signed in as" in text and ">pilot<" in text)
check("the account page needs a sign-in", raw("GET", "/site/account")[0] == 303)
check("sign out works", raw("GET", "/site/logout")[0] == 303 and raw("GET", "/site/account", headers={"Cookie": cookie})[0] == 303)
text, err = tool("studio", "report_progress", task_id="T-2", note=f"the password is {password}.")
check("seatbelt blocks a note that contains the login", err and "Blocked" in text, text)
text, err = tool("studio", "report_progress", task_id="T-2", note=f"see pw{password}end")
check("seatbelt blocks the login glued to other letters", err and "Blocked" in text, text)
text, err = tool("studio", "deliver_result", task_id="T-2", outcome="failed", what_was_done=f"pw={password}")
check("seatbelt blocks a result that contains the login", err and "Blocked" in text)
code, _, text = raw("POST", "/hook/permission/studio/T-2", dict(hook_body, tool_input={"command": f"curl -d pw={password} http://example.com"}))
d = json.loads(text)["hookSpecificOutput"]["decision"]
check("a command that contains the login is refused and not recorded", d["behavior"] == "deny" and "Blocked" in d["message"], text)
before = events("manager")[-1]["id"]
raw("POST", "/say", form={"text": f"use {password}"})
check("a message from the board that contains the login is not passed on", not any(password in e["text"] for e in events("manager", after=before)))
text, err = tool("studio", "sign_in", task_id="T-2", login=password)
check("a password given where a login's name belongs is blocked", err and "Blocked" in text, text)
text, err = tool("studio", "sign_in", task_id="T-2", login=f"bws://{password}")
check("...also when it is dressed up as a login's name", err and "Blocked" in text, text)
text, err = tool("manager", "decide_permission", prompt_id="P-1", decision="deny", reason=f"use {password} instead")
check("a decision's reason that contains the login is blocked", err and "Blocked" in text, text)
check("leak check is clean", json.loads(raw("GET", "/leakcheck")[2])["hits"] == [])
raw("POST", "/outbox", form={"key": "oops", "text": f"leaked {password}"})
check("leak check finds a login that slipped into the hub", json.loads(raw("GET", "/leakcheck")[2])["hits"] != [])

# 9 logins: the agent asks, its helper does the work
for ref in ("op://fleet-pilot/pilot-site-a", "bws://name", "bws://--help", "bws://11111111-1111-4111-8111-111111111111/path"):
    text, err = tool("studio", "sign_in", task_id="T-2", login=ref)
    check("invalid or old login reference is refused: " + ref, err and "its UUID in the fleet's vault" in text, text)
picked = []
def helper_answers(agent, ok, text, delay=0.6):
    """Stand in for the helper: pick up the job and report what came of it (text None: pick it up and stay silent)."""
    def run():
        time.sleep(delay)
        jobs = [e for e in events(agent) if e["kind"] in ("signin", "handover")]
        picked.append(jobs[-1])
        if text is not None:
            raw("POST", f"/helper/job/{agent}/{jobs[-1]['extra']['job']}", {"ok": ok, "text": text})
    threading.Thread(target=run, daemon=True).start()

text, err = tool("vps", "sign_in", task_id="T-9", login="bws://11111111-1111-4111-8111-111111111111")
check("sign_in is refused on a machine without a browser", err and "STOP" in text, text)
helper_answers("studio", True, 'Signed in on http://hub with the login "pilot-site-a".')
text, err = tool("studio", "sign_in", task_id="T-2", login="bws://11111111-1111-4111-8111-111111111111")
check("sign_in returns the helper's word", not err and "Signed in" in text, text)
job = picked[-1]
check("the helper is handed the login's name, and a task", job["extra"]["login"] == "bws://11111111-1111-4111-8111-111111111111" and job["task"] == "T-2", str(job))
helper_answers("studio", False, "the vault refused: this machine's token cannot open that login, or the name is wrong")
text, err = tool("studio", "sign_in", task_id="T-2", login="bws://22222222-2222-4222-8222-222222222222")
check("a refusal from the vault comes back as an error", err and "vault refused" in text, text)
helper_answers("studio", True, None)
t0 = time.time(); text, err = tool("studio", "sign_in", task_id="T-2", login="bws://11111111-1111-4111-8111-111111111111")
check("no helper: sign_in gives up and says so", err and "did not answer" in text and time.time() - t0 < 6, text)
late = picked[-1]["extra"]["job"]
check("a helper report that comes too late is refused", raw("POST", f"/helper/job/studio/{late}", {"ok": True, "text": "late"})[0] == 409)
check("a sign-in whose asker has stopped waiting is not handed to a helper later", not any(e["kind"] in ("signin", "handover") for e in events("studio")))
helper_answers("studio", True, f"oops {password}")
text, err = tool("studio", "sign_in", task_id="T-2", login="bws://11111111-1111-4111-8111-111111111111")
check("a helper report that contains the login is blocked", err and "blocked" in text and password not in text, text)
text, err = tool("studio", "hand_over", task_id="T-2", login="bws://11111111-1111-4111-8111-111111111111", to="nobody")
check("hand_over needs a real agent", err and "not another agent" in text, text)
text, err = tool("studio", "hand_over", task_id="T-2", login="bws://11111111-1111-4111-8111-111111111111", to="vps")
check("hand_over needs the receiver's key", err and "no key" in text, text)
KEYFILE = os.path.join(TMP, 'studio.key')
if shutil.which('age') and shutil.which('age-keygen'):
    subprocess.run(["age-keygen", "-o", KEYFILE], capture_output=True)
    pub = subprocess.run(["age-keygen", "-y", KEYFILE], capture_output=True, text=True).stdout.strip()
    check("register key", raw("POST", "/keys/studio", {"pubkey": pub})[0] == 200)
    check("bad key refused", raw("POST", "/keys/studio", {"pubkey": "hello"})[0] == 400)
    text, err = tool("manager", "create_task", owner="vps", title="Hand over a login", done_when="studio has it")
    tid = text.split()[1]
    tool("vps", "list_my_tasks", task_id=tid)
    sealed = subprocess.run(["age", "-a", "-r", pub], input=json.dumps({"username": "pilot", "password": password, "url": HUB + "/site/login"}), capture_output=True, text=True).stdout
    def vps_helper():
        time.sleep(0.6)
        job = [e for e in events("vps") if e["kind"] == "handover"][-1]
        code, _, text = raw("POST", "/sealed", {"sender": "vps", "recipient": job["extra"]["to"], "task": job["task"], "label": "pilot-site", "ciphertext": sealed, "job": job["extra"]["job"]})
        raw("POST", f"/helper/job/vps/{job['extra']['job']}", {"ok": True, "text": f"{json.loads(text)['ref']} is the name of the locked copy. Only studio can open it."})
    threading.Thread(target=vps_helper, daemon=True).start()
    text, err = tool("vps", "hand_over", task_id=tid, login="bws://22222222-2222-4222-8222-222222222222", to="studio")
    check("hand_over returns the name of the locked copy", not err and "sealed:1" in text, text)
    check("another machine cannot fetch it", raw("GET", "/sealed/1?agent=vps")[0] == 403)
    code, _, text = raw("GET", f"/sealed/1?agent=studio&task={tid}")      # a handover is opened for one task
    plain = subprocess.run(["age", "-d", "-i", KEYFILE], input=json.loads(text)["ciphertext"], capture_output=True, text=True).stdout
    check("the receiver can open it", json.loads(plain)["password"] == password)
    check("the hub's copy does not contain the password", password not in text)
    tool("vps", "deliver_result", task_id=tid, outcome="completed", what_was_done="Handed over", where_output_is="sealed:1", how_checked="The tool said so")
else:
    print('note: age is not installed, sealed-handover checks skipped')
raw("GET", "/site/price", headers={"User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"})
raw("GET", "/api/price", headers={"User-Agent": "curl/8.7.1"})
b = board()
check("board renders", "Retake the screenshot" in b and "read by Chrome" in b and "read by curl" in b and "Pick the codename" in b)
check("board does not show the password", password not in b)
check("text board", "OPEN TASKS" in raw("GET", "/board.txt")[2])

# 9b the names the hub answers to (devops task 1.1), on the port that it really bound: a page in a browser on an allowed
# machine reads nothing under a name of its own (DNS rebinding) and writes nothing from another site
own_port = int(HUB.rsplit(":", 1)[1])
other_port = own_port + 1 if own_port < 65535 else own_port - 1
check("the hub answers 127.0.0.1 with its own port", raw("GET", "/board.txt", headers={"Host": f"127.0.0.1:{own_port}"})[0] == 200)
check("the hub answers localhost with its own port", raw("GET", "/board.txt", headers={"Host": f"localhost:{own_port}"})[0] == 200)
code, _, text = raw("GET", "/board.txt", headers={"Host": f"127.0.0.1:{other_port}"})
check("a Host with another port gets 421 and no body", (code, text) == (421, ""), f"{code} {text[:80]}")
code, _, text = raw("POST", "/say", form={"text": ""}, headers={"Origin": "https://attacker.example"})
check("a foreign Origin gets 403 foreign origin", (code, text) == (403, '{"error": "foreign origin"}'), f"{code} {text[:80]}")
check("the hub's own Origin is answered on /say", raw("POST", "/say", form={"text": ""}, headers={"Origin": HUB})[0] == 303)
check("no Origin is answered on /say", raw("POST", "/say", form={"text": ""})[0] == 303)
code, _, text = raw("GET", "/events/owner?wait=0", headers={"Sec-Fetch-Site": "cross-site"})
check("a cross-site GET of /events/owner gets 403 foreign origin", (code, text) == (403, '{"error": "foreign origin"}'),
      f"{code} {text[:80]}")

# 10 timers (this hub runs with short timers)
text, err = tool("manager", "set_reminder", minutes=0.03, note="look at T-2")
before = events("manager")[-1]["id"]
time.sleep(4)
check("reminder fires", any("Reminder" in e["text"] and "look at T-2" in e["text"] for e in events("manager", after=before)))
tool("studio", "report_progress", task_id="T-2", note="working on it")
before_s = events("studio")[-1]["id"]; before_m = events("manager")[-1]["id"]
# plan C9: no clock nudges a task. A turn of its session that ends with nothing waiting is asked about once, and the
# second in a row tells the requester with the session's last words.
records_now = json.loads(raw("GET", "/records")[2])
t2 = next(t for t in records_now["tasks"] if t["id"] == 2)
def turn_of_t2(seq, said):
    tool("studio", "read_messages", task_id="T-2")          # the session reads what came, then its turn ends
    return raw("POST", "/helper/events/studio", {"generation": records_now["db"], "task": "T-2", "attempt": t2["attempt"],
                                                  "session": "33333333-2222-4333-8444-555555555555", "events": [
        {"seq": seq, "type": "user_message", "text": "Go on."}, {"seq": seq + 1, "type": "agent_message", "text": said},
        {"seq": seq + 2, "type": "result", "stop_reason": "end_turn"}]})[0]
check("a turn's records reach the hub", turn_of_t2(1, "I checked the queue.") == 200)
check("turn end: the owner of the task is asked first",
      any("T-2 is open and nothing is waiting" in e["text"] for e in events("studio", after=before_s)))
turn_of_t2(10, "Still checking the queue.")
check("turn end: then the requester is told, with the last words",
      any("T-2" in e["text"] and "two turns in a row" in e["text"] and "Still checking the queue." in e["text"]
          for e in events("manager", after=before_m)))
check("board marks the stall", "STALLED" in board())
# plan C10: silence is a fact, a line that the manager's helper told it twice and that it took neither time
raw("POST", "/helper/dialog/manager/manager", {"kind": "untaken"})
time.sleep(4)
check("manager silence: the hub tells the owner itself", any("Fleet hub" in e["text"] for e in events("owner")), str(events("owner")))
check("board shows the banner", "telling you itself" in board())
tool("manager", "read_messages")
time.sleep(3)
check("banner clears once the manager acts", "telling you itself" not in board())
text, err = tool("manager", "cancel_task", task_id="T-2", reason="not needed")
check("cancel_task", not err)
check("a canceled task is no longer marked as stalled", "STALLED" not in board())
check("worker session is told to stop", any("canceled" in e["text"] for e in events("studio", after=before_s)))
time.sleep(5)
check("stop event closes finished sessions", any(e["kind"] == "stop" and e["task"] in ("T-1", "T-2") for e in events("studio")))
text, err = tool("manager", "create_task", owner="vps", title="Never mind", done_when="x")
tid = text.split()[1]
before = events("vps")[-1]["id"] - 1 if events("vps") else 0
tool("manager", "cancel_task", task_id=tid, reason="changed my mind")
data = json.loads(raw("GET", f"/events/vps?after={before}&wait=0")[2])
check("a task canceled before its session started is not started later",
      not any(e["kind"] == "task" and e["task"] == tid for e in data["events"]) and data["last"] > before, str(data)[:300])
before_o = (events("owner") or [{"id": 0}])[-1]["id"]
raw("POST", "/helper/dialog/manager/manager", {})
time.sleep(3)
check("a manager stuck at a question on its own screen: the hub tells the owner itself",
      any("own screen" in e["text"] for e in events("owner", after=before_o)) and "own screen" in board())
HUB_PROC.terminate()

# 11 who is calling: a second hub that knows its machines by address. One address for each machine, as owner API 1.12
# asks of every fixture, and every call below comes from 127.0.0.1: so the manager, alone on the hub machine's own
# address, is the one name this hub accepts. "stray" is an agent whose machine is in no address at all, which
# validate_team refuses but a team.json the hub was started with can hold.
STRAY = {"stray": {"role": "worker", "machine": "nowhere", "runtime": "claude", "can": ["shell"]}}
proc2, hub2 = start_hub("strict", {"hub": "127.0.0.1", "vps": "127.0.0.2", "mac-studio": "127.0.0.77",
                                   "owner": "127.0.0.78"}, "--tick", "1", agents=STRAY)
wrong_machine = []


def refused(code):
    """A call the machine rule must refuse. The board's row below counts exactly these, so they are counted here and
    not written down as a number that goes stale."""
    wrong_machine.append(code)
    return code == 403


check("a name is accepted from its own machine", rpc("manager", "tools/list", base=hub2)[0] == 200)
check("a name whose machine has no address is refused, not taken from anybody",      # all: every call is counted
      all([refused(rpc("stray", "ping", base=hub2)[0]), refused(rpc("stray", "tools/list", base=hub2)[0]),
           refused(raw("GET", "/events/stray?after=0&wait=0", base=hub2)[0])]))
# PRODUCT.md 4.8: this hub is the case, so it is also the proof. It started on the file, it answered /health above,
# and it says the rule it breaks. The rule itself is not asserted here: which one comes first depends on the
# team.json this checkout has (test_servers.py TeamAtStartup pins the line on a fixture of its own).
check("a hub started with a team.json that validate_team refuses starts, and its board answers the owner's machine only",
      refused(raw("GET", "/board", base=hub2)[0]))      # TeamAtStartup reads the rule on the owner's board
check("another worker's name is refused from a machine that is not its own", refused(rpc("vps", "ping", base=hub2)[0]))
check("team tools under another machine's name are refused", refused(rpc("studio", "tools/list", base=hub2)[0]))
check("another machine's messages cannot be read", refused(raw("GET", "/events/studio?after=0&wait=0", base=hub2)[0]))
check("only the owner's machine can message the manager", refused(raw("POST", "/say", form={"text": "I am the owner"}, base=hub2)[0]))
check("only the owner's machine can read the owner's notifications", refused(raw("GET", "/events/owner?after=0&wait=0", base=hub2)[0]))
check("only the owner's machine can say which logins to watch for", refused(raw("POST", "/secrets", {"label": "x", "salt": "s", "hash": "0" * 64}, base=hub2)[0]))
check("a key cannot be registered under another machine's name", refused(raw("POST", "/keys/studio", {"pubkey": "age1" + "q" * 58}, base=hub2)[0]))
check("a permission prompt cannot be raised under another machine's name", refused(raw("POST", "/hook/permission/studio/T-1", {"tool_name": "Bash", "tool_input": {"command": "ls"}}, base=hub2)[0]))
check("a handover cannot be sent under another machine's name", refused(raw("POST", "/sealed", {"sender": "studio", "recipient": "vps", "ciphertext": "-----BEGIN AGE ENCRYPTED FILE-----"}, base=hub2)[0]))
import http.client
conn = http.client.HTTPConnection("127.0.0.1", int(hub2.rsplit(":", 1)[1]), timeout=10)
ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
conn.request("POST", "/mcp/studio", body=ping, headers={"Content-Type": "application/json"})
first = conn.getresponse(); first.read()
conn.request("POST", "/mcp/manager", body=ping, headers={"Content-Type": "application/json"})
second = conn.getresponse(); answer = second.read()
# the body too: a connection that kept half a request would answer the next one from the wrong bytes
check("a refusal leaves a kept-alive connection usable",
      first.status == 403 and second.status == 200 and json.loads(answer).get("result") == {},
      f"{first.status} {second.status} {answer[:120]}")
proc2.terminate()

# 12 two agents on one address: the address alone names nobody, so a session sends its own credential (owner API 1.12)
proc3, hub3 = start_hub("shared", {"hub": "127.0.0.1", "vps": "127.0.0.1", "mac-studio": "127.0.0.77",
                                   "owner": "127.0.0.1"}, "--tick", "1")        # the owner reads this hub's board
code, _, resp = rpc("manager", "tools/list", base=hub3)
check("on a shared address a name alone is refused, with the reason",
      code == 403 and (resp or {}).get("auth") == "credential_required", f"{code} {resp}")
check("the other agent of that address is refused as well", rpc("vps", "ping", base=hub3)[0] == 403)
b3 = raw("GET", "/board", base=hub3)[2]
check("a refusal on a credential is not counted as a wrong machine",
      "from the wrong machine</td><td>0<" in b3 and "credential did not match</td><td>2<" in b3, b3[-900:])
wrong_machine.clear()
check("a name is refused from a machine that is not its own", refused(rpc("studio", "ping", base=hub3)[0]))
b3 = raw("GET", "/board", base=hub3)[2]
check("the board counts the calls the machine rule refused, and nothing else",
      f"from the wrong machine</td><td>{len(wrong_machine)}<" in b3 and "credential did not match</td><td>2<" in b3,
      b3[-900:])
proc3.terminate()

finish()
print(f"{count[0] - len(fails)} of {count[0]} checks passed." + ("" if not fails else f" FAILED: {fails}"))
sys.exit(1 if fails else 0)
