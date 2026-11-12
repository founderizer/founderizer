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
    gitops:<owner/repo> the GitOps repository: a read at HEAD through a filter, and commits of the listed forms

The host forms come from host/ops-root and host/ops-read themselves, so the door and the host check each form with
the same code, and the host refuses on its own what the door should never have sent.
"""
import base64
import calendar
import fnmatch
import importlib.machinery
import importlib.util
import json
import os
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
                "miguelpieras/founderizer-web", "miguelpieras/agents")
# Host forms that only the door sends, with a value of its own on stdin: never an agent's call.
DOOR_ONLY = {"self-update", "place", "pro-attach", "runner-register"}
# Host forms whose content goes to the host on stdin, with its sha256, and the forms whose value the door itself sends
# there (new-projects plan N4): never the caller's.
HOST_CONTENT = ("file", "unit-new", "vhost-new", "script", "run")
DOOR_VALUE = ("env-new", "env-add")
# Host forms that arm the rollback timer before they run, whatever they do: a host that answers the door after one of
# them did not lock the door out, so the door ends the countdown then (door.py, Door.timer_off).
TIMED_FORMS = ("script", "run")
TARGET = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}|[a-z]+:[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
CONTENT_MAX = 256 * 1024     # bytes of content in one call

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
    return ITEM + r"(?i:kind)[ \t]*:\s*[\"']?(?i:" + names + ")" + END


MANIFEST_REFUSED = {
    "a new secretKeyRef": r"\bsecretKeyRef\s*:", "a new secretRef": r"\bsecretRef\s*:",
    "a new secret volume": ITEM + r"secret[ \t]*:[ \t\r]*(?:#.*)?$|\bsecretName\s*:", "a hostPath": r"\bhostPath\s*:",
    "privileged": r"\bprivileged\s*:" + TRUE, "a host namespace": r"\bhost(Network|PID|IPC)\s*:" + TRUE,
    "an Application": kind_line("Application|ApplicationSet|AppProject"),
    "an external-secrets kind": ITEM + r"apiVersion[ \t]*:\s*[\"']?(?i:external-secrets\.io)/",
    "a CRD": kind_line("CustomResourceDefinition"),
    "a webhook": kind_line("(?:Mutating|Validating)WebhookConfiguration"),
    "a new LoadBalancer": r"\btype\s*:\s*[\"']?LoadBalancer\b", "a Secret object": kind_line("Secret"),
    "RBAC": kind_line("Role|ClusterRole|RoleBinding|ClusterRoleBinding"),
    "a Tailscale operator setting": r"tailscale\.com/tags\s*:|" + kind_line("ProxyClass"),
}
SECRET_KIND = re.compile(MANIFEST_REFUSED["a Secret object"], re.M)
SECRET_TOP = re.compile(r"^(?i:kind)[ \t]*:\s*[\"']?(?i:Secret)" + END, re.M)
SECRET_DATA = re.compile(ITEM + r"(?i:data|stringData)[ \t]*:", re.M)
LIST_TOP = re.compile(kind_line(r"\w*List"), re.M)        # a List of objects, at any depth of a JSON array of them
KEY_AT = re.compile(r"^([ \t]*(?:-[ \t]+)*)(?i:(kind)[ \t]*:\s*[\"']?(?i:Secret)" + END +
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
FLOW_LIST = re.compile(rf"\[[ \t]*(?:{FLOW_ONE}[ \t]*(?:,[ \t]*{FLOW_ONE}[ \t]*)*,?[ \t]*)?\]")
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
        if kind == "commit":
            return decide_commit(access, agent, me, name, op, args, content, lookups or {})
        if kind == "deploy":
            return decide_deploy(access, me, name, op, args, lookups or {})
        return decide_gitops(access, me, name, op, args, content, lookups or {})
    import door_providers
    if kind not in door_providers.PROVIDERS:
        return refused(f"{kind} is no kind of target")
    if f"{kind}:{name}" in (never.get("accounts") or []):
        return refused(f"{target} is never a target of the door")
    if target not in (me.get("providers") or []):
        return refused(f"{agent} holds no grant on {target}", route="holder")
    return door_providers.decide(access, agent, kind, name, op, args, content, lookups or {})


# ---------------------------------------------------------------- hosts

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
        return refused(f"{agent} holds Read on {host}: no write", **dict(common, **lacks))
    try:
        checked = OPS_ROOT.check_args(op, list(args))
    except OPS_ROOT.Refused as e:
        return refused(str(e), **common)
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
    if f["kind"] in ("own", "full"):
        if h.get("mode") != "fix":          # Patch only is code's: no yes of the owner lifts it, so no hash asks for it
            return refused(f"{host} is rule-only: only rule forms run there, and no file install", **more)
        if f["kind"] == "full":             # door-modes proposal, step 3: the owner's yes runs that exact call once
            return Decision("full", f"{op} is a root script with no box, which no grant on {host} covers", **more)
        return Decision("own", f"the host form {op}", **more)
    # N4: a new app lives on a fix host only. ops-root refuses it there too, but the door refuses it first, before it
    # makes a value or a runner's tokens for a call that the host will not run.
    if op in OPS_ROOT.PLAN_WRITES and h.get("mode") != "fix":
        return refused(f"{host} is rule-only: no form of a new app writes there", **more)
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
        for text in re.findall(r"\$\{\{(.*?)\}\}", node, re.S) + ([node] if key == "if" else []):
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


def decide_workflows(repo, made, files, message):
    """A commit of workflow files only, for the Operator that made the repository through the door."""
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
                    plan={"repo": repo, "files": out, "message": message, "branch": None})


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
            if not isinstance(path, str) or path.startswith("/") or ".." in path.split("/") or not path or \
                    "\\" in path or "\0" in path:
                raise ValueError
            data = None if f.get("delete") is True else base64.b64decode(f["content"], validate=True)
            out.append((path, data, mode))
        return out, message
    except (ValueError, KeyError, TypeError):
        return None, "the content of a commit is {message, files: [{path, content (base64)} or {path, delete}]}"


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
            return decide_workflows(repo, made, files, message)
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
    plan = {"repo": repo, "files": files, "message": message, "branch": entry.get("branch")}
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
    if all(re.fullmatch(r"\s*-?\s*replicas\s*:\s*\d{1,2}\s*", line) for line in changed):
        return True
    if all(re.fullmatch(r"\s*-?\s*(image|tag|digest|newTag|newName)\s*:\s*\S+\s*", line) for line in changed):
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


def image_rule(old, new, lookups):
    """A checked image: the same repository name, and a green release run of that repository made this tag or
    digest."""
    def refs(data):
        return re.findall(r"^\s*-?\s*image\s*:\s*['\"]?([^\s'\"]+)", data.decode("utf-8", "replace"), re.M)
    before, after = refs(old), refs(new)
    made = lookups.get("image_made") or (lambda image: False)
    for x, y in zip(before, after):
        if x == y:
            continue
        name_x, name_y = re.split(r"[:@]", x, 1)[0], re.split(r"[:@]", y, 1)[0]
        if name_x != name_y:
            return f"the image changes its repository: {name_x} to {name_y}"
        if not made(y):
            return f"no green release run made {y}"
    if not before:      # a tag or digest field on its own line: the run check reads it as the chart's values
        tags = [line.split(":", 1)[1].strip() for line in changed_lines(old, new) or []]
        if not all(made(t) for t in tags):
            return "no green release run made this tag"
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


def as_block(value, depth=0):
    """A JSON value as the block style lines that say the same, for the patterns: one key or one item on each line."""
    def flat(v):
        return re.sub(r"\s+", " ", v) if isinstance(v, str) else json.dumps(v)
    pad, out = "  " * depth, []
    for key, v in value.items() if isinstance(value, dict) else [(None, v) for v in value]:
        out.append(pad + ("-" if key is None else flat(key) + ":"))
        out.append("\n" + as_block(v, depth + 1) if isinstance(v, (dict, list)) else " " + flat(v) + "\n")
    return "".join(out)


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
        return (as_block(value) if isinstance(value, (dict, list)) else text), None
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
# text means. LOOSE_WORDS are the words of every form that MANIFEST_REFUSED and the checks beside it refuse, and the
# tag by which YAML reads a key from base64. Role, Application and a secret volume are words of plain speech too, so
# LOOSE_KEYS takes them with their key, in the text with its quotes, spaces, tabs and braces taken out.
LOOSE_WORDS = ("secretkeyref", "secretref", "secretname", "hostpath", "privileged", "hostnetwork", "hostpid", "hostipc",
               "applicationset", "appproject", "external-secrets.io", "customresourcedefinition",
               "mutatingwebhookconfiguration", "validatingwebhookconfiguration", "loadbalancer", "clusterrole",
               "rolebinding", "clusterrolebinding", "tailscale.com/tags", "proxyclass", "upgrade.cattle.io",
               "serviceaccountname", "!!binary", "tag:yaml.org,2002:binary")
LOOSE_KEYS = {"kind: role": r"kind:\s*role(?![a-z0-9])", "kind: application": r"kind:\s*application(?![a-z0-9])",
              "secret:": r"(?<![a-z0-9_./-])secret:",
              # and the two that a text can turn on with no new word, from false to true
              "privileged: true": r"privileged:\s*(?:true|yes|on|y)(?![a-z0-9])",
              "a host namespace: true": r"host(?:network|pid|ipc):\s*(?:true|yes|on|y)(?![a-z0-9])"}


def loose_text(text):
    """A text in lower case, with the escapes that YAML and JSON read in a quoted text written out (a backslash with
    x50 or u0050, and a line that ends in a backslash, which goes on in the next one), so that no word hides in one."""
    def char(found):
        try:
            return chr(int(next(g for g in found.groups() if g), 16))
        except (ValueError, OverflowError):
            return ""
    text = re.sub(r"\\\r?\n[ \t]*", "", text)
    return re.sub(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))", char, text).lower()


def loose_counts(text):
    low = loose_text(text)
    bare = re.sub(r"[\"'{} \t]", "", low)
    counts = {w: len(re.findall(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", low)) for w in LOOSE_WORDS}
    counts.update({w: len(re.findall(pattern, bare)) for w, pattern in LOOSE_KEYS.items()})
    return counts, bare


def loose_danger(old_text, new_text):
    """The first refused form that the loose reading finds more of in the new text than in the old, or None: a word of
    LOOSE_WORDS or a key of LOOSE_KEYS, another service account, or a bigger volume claim. With no old text, one
    word is enough: a README that says hostPath is refused too, and the refusal names the word."""
    (old, old_bare), (new, new_bare) = loose_counts(old_text), loose_counts(new_text)
    word = next((w for w in new if new[w] > old[w]), None)
    if word:
        return f"the word {word}"
    accounts, sizes = (lambda bare: re.findall(r"serviceaccountname:([^,\s\]]*)", bare)), \
        (lambda bare: [quantity(x) for x in re.findall(r"storage:([0-9.]+[kmgtp]i?)", bare)])
    if accounts(old_bare) != accounts(new_bare):
        return "a changed serviceAccountName"
    a, b = sizes(old_bare), sizes(new_bare)
    return "a bigger volume claim" if len(b) > len(a) or any(n > o for o, n in zip(a, b)) else None


def manifest_keys(text):
    """How many kind and apiVersion keys a text holds, in the loose reading: what makes a text a manifest."""
    return len(re.findall(r"(?<![a-z0-9_./-])(?:kind|apiversion):", loose_counts(text)[1]))


def loose_secret(text):
    """True when the loose reading says that a text may hold a Secret object. The text in lower case, with its quotes,
    spaces, tabs and braces taken out, names the kind Secret or has a stringData key; or the text is JSON and an
    object in it has that kind, in any case. The filter of a read asks it of a file that the block reader cannot
    read, where the repository's own people wrote the text, and a commit of a file that gets the loose reading."""
    bare = re.sub(r"[\"'{} \t]", "", loose_text(text))
    if re.search(r"kind:\s*secret(?![a-z0-9])", bare) or "stringdata:" in bare:
        return True
    try:
        left = [json.loads(text)]
    except (ValueError, RecursionError):
        return False
    while left:
        value = left.pop()
        if isinstance(value, dict):
            if any(k.lower() == "kind" and isinstance(v, str) and v.lower() == "secret" for k, v in value.items()):
                return True
            left.extend(value.values())
        elif isinstance(value, list):
            left.extend(value)
    return False


def kept_back(path, data):
    """Why the filter of a read keeps one file of a GitOps repository back from every agent, or None: no Secret
    object leaves the door. The file as the patterns read it holds a Secret or a private key; or it is not block
    style, or has another name than .yaml, .yml or .json, and a loose reading of its text says that it may hold one;
    or it is not UTF-8 text, where the filter sees nothing. The render box asks the same of each file that a chart
    or a Kustomize folder can read (door_render.closed)."""
    text, why = manifest_text(path, data)
    if why:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return "is not UTF-8 text, so it may hold a Secret that the filter cannot see: the filter keeps it back"
    elif secret_object(text) or "-----BEGIN" in text:
        return "holds a Secret, which the filter keeps back"
    # the loose reading too for a file with another name than .yaml, .yml or .json, which no reader reads by lines
    if (why or not manifest_name(path)) and (loose_secret(text) or "-----BEGIN" in text):
        return "may hold a Secret, which the filter keeps back"
    return None


# The lines that a commit changes in a YAML file that code reads only loosely: the values of decide_gitops's rule calls
LISTED_LINE = re.compile(r"\s*-?\s*replicas\s*:\s*\d{1,2}\s*|"
                         r"\s*[\w./-]*restartedAt['\"]?\s*:\s*['\"]?[0-9T:.Z+-]{10,40}['\"]?\s*|"
                         r"\s*-?\s*(?:image|tag|digest|newTag|newName)\s*:\s*[\w./:@-]+\s*")


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


def sa_changed(old_text, new_text):
    a = re.findall(r"serviceAccountName\s*:\s*(\S+)", old_text)
    b = re.findall(r"serviceAccountName\s*:\s*(\S+)", new_text)
    return a != b


def storage_grew(old_text, new_text):
    def sizes(text):
        return [quantity(x) for x in re.findall(r"storage\s*:\s*['\"]?([0-9.]+[KMGTP]i?)", text)]
    return any(n > o for o, n in zip(sizes(old_text), sizes(new_text))) or len(sizes(new_text)) > len(sizes(old_text))


def quantity(text):
    m = re.fullmatch(r"([0-9.]+)([KMGTP])(i?)", text, re.I)        # in lower case too, for the loose reading
    if not m or not re.fullmatch(r"[0-9]+[.]?[0-9]*|[.][0-9]+", m.group(1)):
        return 0
    return float(m.group(1)) * (1024 if m.group(3) else 1000) ** ("KMGTP".index(m.group(2).upper()) + 1)


# ---------------------------------------------------------------- the GitOps repository

def gitops_path_refused(path, access):
    if re.search(r"(^|/)Secrets/", path) or path.startswith("_config/") or "/_config/" in path:
        return f"{path} is a secret path of the GitOps repository"
    if any(glob_match(path, p) for p in (access.get("exposure") or [])):
        return f"{path} is in the exposure register"
    return None


def decide_gitops(access, me, repo, op, args, content, lookups):
    """read <path> at HEAD through the filter; commit an image tag or digest, a replica count or a restart
    annotation as rule calls; rollback to the last good digest after a schema check; sync through the listed caller
    workflow. Other manifests are the agent's own call."""
    entry = repo_entry(me, repo, ("gitops",))
    if entry is None:
        return refused(f"the door gives this agent nothing on {repo}", route="holder")
    target = f"gitops:{repo}"
    if op == "read":
        if len(args) != 1 or not args[0] or args[0].startswith("/") or ".." in args[0].split("/"):
            return refused("read takes one path of the repository", target=target)
        why = gitops_path_refused(args[0], access)
        if why:
            return refused(why, target=target)
        return Decision("read", "a read at HEAD through the filter", target=target, write=False,
                        plan={"repo": repo, "read": args[0], "filter": True})
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
    if op not in ("push", "rollback"):
        return refused("the GitOps repository takes read, push, rollback and sync", target=target)
    files, message = commit_files(content)
    if files is None:
        return refused(message, target=target)
    # checks: the call waits for the runs that the commit's push starts, and the agent learns how they ended
    plan = {"repo": repo, "files": files, "message": message, "branch": entry.get("branch"), "checks": True}
    for path, data, mode in files:
        if mode in ("120000", "160000") or never_path(path):
            return refused(f"{path} is under the commit rules", target=target)
        why = gitops_path_refused(path, access)
        if why:
            return refused(why, target=target)
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
        d = gitops_files(lookups, op, target, plan, files, report)
    except (KeyError, TypeError, AttributeError, ValueError, RecursionError):
        return refused("the door could not read the render of this commit", target=target, route="again")
    if d.kind != "refused":
        plan["objects"] = commit_objects(files, report, lookups)     # door.py keeps them once the commit is made
    return d


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
    value = re.sub(r"[ \t]+#.*$", "", value).strip()
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
    found = [line.split(LISTING_MARK + " ", 1)[1].strip() for line in (text or "").splitlines()
             if LISTING_MARK + " " in line]
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
                        f"to him, because a part of it would leave the app OutOfSync: {every}", target=target,
                        window="deploy", plan=plan, hash_content=listed.encode())
    if all(made(key) for key in keys):
        return Decision("rule", f"a prune in {app} of what commits through the door made and then removed: {every}",
                        target=target, window="deploy", plan=plan, hash_content=listed.encode())
    return Decision("own", f"a prune in {app} of what its own commits through the door removed (the owner, 12 "
                    f"November 2026: \"The agent (Recommended)\"): {every}", target=target, window="deploy",
                    plan=plan, hash_content=listed.encode())


def objects_text(docs):
    """Objects as the block style lines that say the same, one document each: what the patterns read of a render,
    and of a file that the real parser read."""
    return "---\n".join(as_block(doc) for doc in docs)


def unit_name(unit):
    return f"the {'chart' if unit['kind'] == 'helm' else 'Kustomize folder'} {unit['root']}"


def render_broken(report):
    "The words for the first unit that rendered at HEAD and does not render after the commit, or None."
    return next((f"{unit_name(unit)} renders at HEAD and not after this commit ({unit.get('why')})"
                 for _uid, unit in sorted(report["units"].items()) if unit.get("broke")), None)


def render_refusal(report):
    """Why the render of a commit refuses it, or None. For each chart and each Kustomize folder that the door
    rendered, with each value set: an object that the cluster gets after the commit has no more of a refused form
    than the same object at HEAD, a new object has none, and no Secret object is new or changed."""
    for _uid, unit in sorted(report["units"].items()):
        where = unit_name(unit)
        if not unit.get("ok"):
            continue                # the door did not render it: its files kept the rules that need no render
        for group in unit["changed"]:
            before, after = group["before"], group["after"]
            if not after:
                continue            # an object that the commit takes away adds nothing
            what = f"{where}, rendered with {group['set']}: {group['object']}"
            if any(isinstance(o.get("kind"), str) and o["kind"].lower() == "secret" and o not in before
                   for o in after):
                return f"{what} is a new or a changed Secret object, which no commit passes"
            hit = manifest_refusal(objects_text(before), objects_text(after))
            if hit:
                return f"{what}: {hit}, more than at HEAD, which no commit passes"
    return None


def gitops_files(lookups, op, target, plan, files, report):
    """The decision on the files of a GitOps commit, after the path rules. report: the render of the commit, or None."""
    if report:
        plan["parent"] = report.get("head")         # the commit that the door rendered: the commit's only parent
        why = render_broken(report)
        if why:
            return refused(why, target=target)
    own = None
    for path, data, mode in files:
        if data is None:
            own = own or f"{path} is deleted"
            continue
        info = report["files"].get(path) or {} if report else {}
        if report:
            old = None if info.get("head") is None else base64.b64decode(info["head"])
        else:
            old = (lookups.get("base_file") or (lambda p: None))(path)
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
        if text is not None:
            if secret_object(text) if block else SECRET_KIND.search(text):
                return refused(f"{path} holds a Secret object", target=target)
            hit = manifest_refusal(before, text)
            if hit:
                return refused(f"{path}: {hit}, which no commit passes", target=target)
        if old is None:
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
        if changed is None or not kept or not (lines or listed):
            # in a file that code does not read by lines, a line can hold more than its first key: a rule call
            # there is a change of listed lines only
            own = own or f"{path} changes more than its values"
        elif all(re.fullmatch(r"\s*-?\s*replicas\s*:\s*\d{1,2}\s*", line) for line in changed):
            continue
        elif all(re.fullmatch(r"\s*[\w./-]*restartedAt['\"]?\s*:\s*['\"]?[0-9T:.Z+-]{10,40}['\"]?\s*", line)
                 for line in changed):
            continue
        elif all(re.fullmatch(r"\s*-?\s*(image|tag|digest|newTag|newName)\s*:\s*\S+\s*", line) for line in changed):
            ok = image_rule(old, data, lookups)
            if ok is not True:
                own = own or ok
            elif op == "rollback" and not (lookups.get("schema_ok") or (lambda p, d: False))(path, data):
                return refused(f"the schema check of {path} failed: no rollback", target=target)
        else:
            own = own or f"{path}: other manifest lines"
    if report:
        why = render_refusal(report)
        if why:
            return refused(why, target=target)
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
