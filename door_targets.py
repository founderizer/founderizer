"""What the door may do: one table for each kind of target (DevOps plan, section 2, "The door"). Standard library only.

Every call is one of three kinds: a rule call, which code passes at once with no model, so that it works when the model
is down; a judged call, which one model call allows or refuses; or a refusal. A call that no table lists is refused,
reads too. decide() gives the kind of one call and the reason, and never acts: door.py acts on what it gives.

    host                a managed host, through its second sshd: the fixed reads of host/ops-read, the rule forms
                        of host/ops-root, and its judged forms on a host whose mode is fix
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

# The product's own repositories: no customer's door ever touches them (DevOps plan, "Always refused").
VENDOR_REPOS = ("miguelpieras/founderizer-fleet", "miguelpieras/founderizer-web", "miguelpieras/agents")
# Host forms that only the door sends, with a value of its own on stdin: never an agent's call.
DOOR_ONLY = {"self-update", "place", "pro-attach", "runner-register"}
# Host forms whose content goes to the host on stdin, with its sha256 (the judge reads it first), and the forms whose
# value the door itself sends there (new-projects plan N4): never the caller's.
HOST_CONTENT = ("file", "unit-new", "vhost-new")
DOOR_VALUE = ("env-new", "env-add")
TARGET = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}|[a-z]+:[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
CONTENT_MAX = 256 * 1024     # bytes of content in one call; the judge's own cap is the door's (door.JUDGE_MAX)

# The commit rules (DevOps plan section 2): these paths, at any depth, never pass in any commit.
NEVER_PATHS = (".claude/**", ".codex/**", ".mcp.json", "AGENTS.md", "CLAUDE.md", ".github/**", ".husky/**",
               ".vscode/**", "policy.hujson", "scripts/security/check-tailnet-policy.mjs")
# Manifest forms that code refuses in rendered output: a new one of these is never committed.
MANIFEST_REFUSED = {
    "a new secretKeyRef": r"\bsecretKeyRef\s*:", "a new secretRef": r"\bsecretRef\s*:",
    "a new secret volume": r"^\s*secret\s*:\s*$|\bsecretName\s*:", "a hostPath": r"\bhostPath\s*:",
    "privileged": r"\bprivileged\s*:\s*true", "a host namespace": r"\bhost(Network|PID|IPC)\s*:\s*true",
    "an Application": r"^kind\s*:\s*(Application|ApplicationSet|AppProject)\s*$",
    "an external-secrets kind": r"^apiVersion\s*:\s*external-secrets\.io/",
    "a CRD": r"^kind\s*:\s*CustomResourceDefinition\s*$",
    "a webhook": r"^kind\s*:\s*(Mutating|Validating)WebhookConfiguration\s*$",
    "a new LoadBalancer": r"\btype\s*:\s*LoadBalancer\b", "a Secret object": r"^kind\s*:\s*Secret\s*$",
    "RBAC": r"^kind\s*:\s*(Role|ClusterRole|RoleBinding|ClusterRoleBinding)\s*$",
    "a Tailscale operator setting": r"tailscale\.com/tags\s*:|^kind\s*:\s*ProxyClass\s*$",
}
NPM_AGE = 7 * 86400          # min-release-age=7, which npm ci does not check on a lockfile: the door does


class Decision:
    """kind: read | rule | judged | refused. why: one line for the agent and the record. form, args: what the door
    runs. host, window, reboot: what the door's order needs."""

    def __init__(self, kind, why, **more):
        self.kind, self.why = kind, why
        self.target = more.get("target")
        self.form, self.args = more.get("form"), more.get("args") or []
        self.host, self.window, self.reboot = more.get("host"), more.get("window"), more.get("reboot", False)
        self.business = more.get("business")
        self.write = more.get("write", kind in ("rule", "judged"))
        self.plan = more.get("plan")            # what the door runs: a provider's requests, a commit, a deploy
        # what the door sends on the host's stdin: (random, None) or (key, app:<app>:<NAME>) for a setting (N4), and
        # (runner, <owner>/<repo>, <runner name>) for a runner (N6)
        self.value = more.get("value")

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
    return next((p for p in NEVER_PATHS if glob_match(path, p)), None)


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
        return refused(f"{agent} holds no grant on {target}")
    return door_providers.decide(access, agent, kind, name, op, args, content, lookups or {})


# ---------------------------------------------------------------- hosts

def decide_host(access, agent, me, host, op, args, never, content=None, lookups=None):
    h = (access.get("hosts") or {}).get(host)
    if h is None or host in (never.get("hosts") or []):
        return refused(f"{host} is no host of the door" if h is None else f"{host} is never a target of the door")
    level = (me.get("servers") or {}).get(host)
    if level not in ("read", "fix"):
        return refused(f"{agent} holds no grant on {host}")
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
        return refused(f"{agent} holds Read on {host}: no write", **common)
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
    if f["kind"] == "judged":
        if h.get("mode") != "fix":
            return refused(f"{host} is rule-only: no judged form and no file install", **more)
        return Decision("judged", f"{op} is judged", **more)
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
    scripts/ is judged. app: a checked lockfile fix, a checked image, a replica count or a dated scan exception is a
    rule call, and other paths are judged. gitops goes through gitops:<repo>. The workflow files of a repository that
    the door made go only through decide_workflows, for the agent that made it (N5)."""
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
        return refused(f"the door commits nothing on {repo} for this agent")
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
            return Decision("judged", "a commit under scripts/ is judged", target=f"commit:{repo}", plan=plan)
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
        return Decision("judged", reasons[0], target=f"commit:{repo}", plan=plan)
    return Decision("rule", "a checked change of the listed forms", target=f"commit:{repo}", plan=plan)


def app_path_rule(path, data, lookups, repo):
    """True for a rule form, "refused: ..." for a refusal, else the reason the judge reads it."""
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
    as a dependency, and no new install script appears. Too young is refused; any other failure goes to the judge."""
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


def manifest_refusal(old_text, new_text):
    """The first refused manifest form that the new rendered output has more of than the old, or None."""
    for what, pattern in MANIFEST_REFUSED.items():
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
    """The channel lines of k3s upgrade Plans. A Plan names one version, so each k3s upgrade is one judged commit
    (DevOps plan 5.5), and a channel, which upgrades with no commit, is never the door's."""
    return sum(len(re.findall(r"^\s*channel\s*:\s*\S", doc, re.M)) for doc in re.split(r"^---\s*$", text, flags=re.M)
               if re.search(r"^apiVersion\s*:\s*upgrade\.cattle\.io/", doc, re.M))


def sa_changed(old_text, new_text):
    a = re.findall(r"serviceAccountName\s*:\s*(\S+)", old_text)
    b = re.findall(r"serviceAccountName\s*:\s*(\S+)", new_text)
    return a != b


def storage_grew(old_text, new_text):
    def sizes(text):
        return [quantity(x) for x in re.findall(r"storage\s*:\s*['\"]?([0-9.]+[KMGTP]i?)", text)]
    return any(n > o for o, n in zip(sizes(old_text), sizes(new_text))) or len(sizes(new_text)) > len(sizes(old_text))


def quantity(text):
    m = re.fullmatch(r"([0-9.]+)([KMGTP])(i?)", text)
    if not m:
        return 0
    return float(m.group(1)) * (1024 if m.group(3) else 1000) ** ("KMGTP".index(m.group(2)) + 1)


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
    workflow. Other manifests are judged."""
    entry = repo_entry(me, repo, ("gitops",))
    if entry is None:
        return refused(f"the door gives this agent nothing on {repo}")
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
        if len(args) != 1 or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args[0]) or not caller:
            return refused("sync takes one app name, through the repository's listed caller workflow", target=target)
        return Decision("rule", "a sync through the listed caller", target=target,
                        plan={"repo": repo, "workflow": caller, "inputs": {"app": args[0]}}, window="deploy")
    if op not in ("push", "rollback"):
        return refused("the GitOps repository takes read, push, rollback and sync", target=target)
    files, message = commit_files(content)
    if files is None:
        return refused(message, target=target)
    plan = {"repo": repo, "files": files, "message": message, "branch": entry.get("branch")}
    judged = None
    for path, data, mode in files:
        if mode in ("120000", "160000") or never_path(path):
            return refused(f"{path} is under the commit rules", target=target)
        why = gitops_path_refused(path, access)
        if why:
            return refused(why, target=target)
        if data is None:
            judged = judged or f"{path} is deleted"
            continue
        text = data.decode("utf-8", "replace")
        old = (lookups.get("base_file") or (lambda p: None))(path)
        if re.search(r"^kind\s*:\s*Secret\s*$", text, re.M):
            return refused(f"{path} holds a Secret object", target=target)
        rendered = lookups.get("render") or (lambda p, before, after: (before, after))
        before, after = rendered(path, (old or b"").decode("utf-8", "replace"), text)
        hit = manifest_refusal(before, after)
        if hit:
            return refused(f"{path}: {hit}, which no commit passes", target=target)
        if old is None:
            judged = judged or f"{path} is a new manifest"
            continue
        changed = changed_lines(old, data)
        if changed is None:
            judged = judged or f"{path} changes more than its values"
        elif all(re.fullmatch(r"\s*-?\s*replicas\s*:\s*\d{1,2}\s*", line) for line in changed):
            continue
        elif all(re.fullmatch(r"\s*[\w./-]*restartedAt['\"]?\s*:\s*['\"]?[0-9T:.Z+-]{10,40}['\"]?\s*", line)
                 for line in changed):
            continue
        elif all(re.fullmatch(r"\s*-?\s*(image|tag|digest|newTag|newName)\s*:\s*\S+\s*", line) for line in changed):
            ok = image_rule(old, data, lookups)
            if ok is not True:
                judged = judged or ok
            elif op == "rollback" and not (lookups.get("schema_ok") or (lambda p, d: False))(path, data):
                return refused(f"the schema check of {path} failed: no rollback", target=target)
        else:
            judged = judged or f"{path}: other manifest lines"
    if judged:
        return Decision("judged", judged, target=target, plan=plan, window="deploy")
    return Decision("rule", "a listed GitOps change", target=target, plan=plan, window="deploy")


# ---------------------------------------------------------------- deploys

def decide_deploy(access, me, repo, op, args, lookups):
    """The repository's documented deploy, when its default branch is the last released commit plus the agent's own
    commit (one the door made), with green CI and audit, and no hold line."""
    entry = repo_entry(me, repo, ("app",))
    if entry is None or not entry.get("deploy"):
        return refused(f"{repo} has no deploy that the door runs for this agent")
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
