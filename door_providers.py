"""The door's provider targets (DevOps plan, section 2 and step C6), in the plan's order: Backblaze, Cloudflare,
GitHub, Hetzner, then AWS, Azure and Tailscale. Standard library only.

Each provider has its listed reads (no path on the list returns a token), its rule calls, which code passes, and the
agent's own calls, which run on the agent's grant and for which the agent answers; anything else is refused. decide()
turns one call into a plan of steps, and execute() runs a plan with the token that the door holds for that account. A
token never leaves the door: no answer carries one, and a key that the door mints stays on the door until it places it
on a host itself, through that host's ops-root (`place`), where the old value is, found by its hash. An AWS account
holds no key at all: the door assumes that account's role with its own bot's web identity token. The key that the
owner saves for a Cloudflare account can be one that only makes tokens: the door then makes its own work key from it,
with the rights that these forms need, which Cloudflare ends after a day, and no call is sent with the saved key
(cloudflare_work_key).

    ops backblaze:<account> buckets | keys | files <bucket-id> [prefix]
    ops backblaze:<account> key-mint <host> <bucket-id>            rule: a key for one host, its name as the prefix,
                                                                   no delete right
    ops backblaze:<account> key-place <host> <file> <key-id> <NAME>=id:<sha256> <NAME>=key:<sha256>
    ops backblaze:<account> key-revoke <key-id>                    rule for a key that the door minted, else the
                                                                   owner's (a delete of what no agent made)
    ops backblaze:<account> change <b2 call>                       own call (D25), its body as content
    ops cloudflare:<account> zones | records <zone> | tunnels | rulesets <zone>
    ops cloudflare:<account> cname <zone> <name> <tunnel-id>       rule: a new CNAME to a tunnel of that account
    ops cloudflare:<account> tunnel-route <tunnel-id> <hostname> <port>   rule: a new hostname, the host's own origin
    ops cloudflare:<account> purge <zone> <host or url> ...        rule
    ops cloudflare:<account> change <METHOD> <path>                own call (D25), its body as content
    ops github:<owner> runs|failed|alerts|code-alerts|secret-alerts|runners <repo>
    ops github:<owner> workflow <repo> <workflow> [name=value ...] rule for a health workflow, own call for bootstrap
    ops github:<owner> secret <repo> <NAME> <key-id> id|key        rule: a value that the door rotated
    ops github:<owner> pull-request <repo> <head> <base> <title>   rule
    ops hetzner:<project> servers | server <name> | firewalls | volumes | ips
    ops hetzner:<project> power-cycle <server>                     rule, for a server that the agent holds
    ops hetzner:<project> change <METHOD> <path> <server>          own call: a held server's firewall, protection, label
    ops hetzner:<project> change <METHOD> <path>                   own call (D25); a write that names a server only
                                                                   for a server that the agent holds at Fix
    ops aws:<account> instances | groups | stacks | identity
    ops aws:<account> start|stop|reboot <instance-id>              rule, for a tagged instance
    ops aws:<account> ingress|change-set|key-off ...               own call
    ops aws:<account> eks-allowlist <cluster> <ipv4-range> ...     own call: the EKS public endpoint's new list
    ops aws:<account> call <service> <Action> [<region>]           own call: any other call inside the role's rights,
                                                                   its parameters as JSON content
    ops aws:<account> call eks <METHOD> <path> [<region>]          own call, the same for a REST API
    ops azure:<subscription> get <path>                            listed reads and metrics
    ops azure:<subscription> sql-firewall|app-setting ...          own call
    ops azure:<subscription> change <METHOD> <path> <api-version>  own call (D25)
    ops tailscale:<tailnet> devices | device <id>
    ops tailscale:<tailnet> key-expiry-off <id> | rename <id> <name>   rule, for a device of the fleet
    ops tailscale:<tailnet> delete <id> | oauth-client <tag>       own call
    ops tailscale:<tailnet> change <METHOD> <path>                 own call (D25): a device's name, key expiry, delete

A delete in an agent's own call runs only when the door's own record shows that an agent made its target through the
door (made_keys, deletes); any other delete, and every AWS delete, goes to the owner as a Needs-you item with the exact
call.
"""
import base64
import contextlib
import datetime
import hashlib
import hmac
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from door_targets import Decision, refused, vendor

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
SHA = re.compile(r"[0-9a-f]{64}")
HOSTNAME = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
INPUT = re.compile(r"[A-Za-z0-9._/:@+-]{1,200}")
BODY_MAX = 64 * 1024
B2_AUTHORIZE = "https://api.backblazeb2.com/b2api/v3/b2_authorize_account"


def plan(kind, why, account, steps, **more):
    """A decision whose plan is a list of steps for execute()."""
    return Decision(kind, why, target=f"{more.pop('provider')}:{account}",
                    plan={"provider": more.get("provider_name"), "account": account, "steps": steps}, **more)


def read_plan(provider, account, steps, why, repo=None):
    plan = {"provider": provider, "account": account, "steps": steps}
    if repo:                    # GitHub: the repository whose installation gives the token (github_token)
        plan["repo"] = repo
    return Decision("read", why, target=f"{provider}:{account}", write=False, plan=plan)


def step(method, path, body=None, keep=None, need=None, query=None):
    """One request. keep: what the door keeps from the answer instead of passing it on. need: a condition on an
    earlier answer, which execute() checks before it sends this one."""
    return {"method": method, "path": path, "body": body, "keep": keep, "need": need, "query": query}


def held_servers(access, agent):
    return set(((access.get("agents") or {}).get(agent) or {}).get("servers") or {})


def account_of(access, provider, account):
    return (access.get("credentials") or {}).get(f"{provider}:{account}") or {}


# ---------------------------------------------------------------- Backblaze B2

def backblaze(access, agent, account, op, args, content, lookups):
    p = {"provider": "backblaze"}
    if op == "buckets" and not args:
        return read_plan("backblaze", account, [step("POST", "b2_list_buckets", {"accountId": "{account_id}"})],
                         "a listed read")
    if op == "keys" and not args:
        return read_plan("backblaze", account, [step("POST", "b2_list_keys", {"accountId": "{account_id}",
                                                                              "maxKeyCount": 1000})], "a listed read")
    if op == "files" and len(args) in (1, 2) and ID.fullmatch(args[0]):
        body = {"bucketId": args[0], "maxFileCount": 1000}
        if len(args) == 2:
            body["prefix"] = args[1]
        return read_plan("backblaze", account, [step("POST", "b2_list_file_names", body)], "a listed read")
    if op == "key-mint":
        if len(args) != 2 or args[0] not in held_servers(access, agent) or not ID.fullmatch(args[1]):
            return refused("key-mint takes a host that this agent holds and the bucket's id")
        host = args[0]
        return Decision("rule", "a key for one host: its name as the prefix, no delete right",
                        target=f"backblaze:{account}", plan={"provider": "backblaze", "account": account, "steps": [
                            step("POST", "b2_create_key", {
                                "accountId": "{account_id}", "keyName": host, "bucketId": args[1],
                                "namePrefix": f"{host}/",
                                "capabilities": ["listBuckets", "listFiles", "readFiles", "writeFiles"]},
                                keep="minted")]})
    if op == "key-revoke":
        if len(args) != 1 or not ID.fullmatch(args[0]):
            return refused("key-revoke takes the key's id")
        mine = (lookups.get("minted") or (lambda k: False))(args[0])
        return Decision("rule" if mine else "own", "a key that the door minted" if mine else
                        "revoking a key that the door did not mint", target=f"backblaze:{account}",
                        plan={"provider": "backblaze", "account": account,
                              "steps": [dict(step("POST", "b2_delete_key", {"applicationKeyId": args[0]},
                                                  keep="revoked"), key_id=args[0])]})
    if op == "key-place":
        return key_place(access, agent, "backblaze", account, args, lookups)
    if op == "change":                            # D25: a write of the key's own rights, the agent's own call
        name = args[0] if len(args) == 1 else ""
        if not re.fullmatch(r"b2_[a-z_]{3,40}", name):
            return refused("change takes one call of the B2 API, such as b2_update_bucket, with its body as content")
        if re.match(r"b2_(list|get|download|authorize)_", name):
            return refused(f"{name} is a read, or its answer is a token: a read that is not listed stays refused")
        if name == "b2_create_key":
            return refused("a new key's answer is its secret: the door's key-mint makes one for a host and keeps it")
        body = json_body(content) if content else {}
        if body is False or not isinstance(body, dict):
            return refused("the body is one JSON object of at most 64 KiB")
        copies = body.get("replicationConfiguration")
        if body.get("bucketType") not in (None, "allPrivate") or \
                (copies.get("asReplicationSource") if isinstance(copies, dict) else copies):
            return refused("a public bucket gives each file in it to anybody, and a bucket that copies itself gives "
                           "them to another account; no read of the door gives a file, so this is never the door's")
        return Decision("own", f"a call of {name} inside the key's rights", target=f"backblaze:{account}",
                        plan={"provider": "backblaze", "account": account, "steps": [step("POST", name, body)]})
    return refused(f"{op} is not listed for Backblaze")


def key_place(access, agent, provider, account, args, lookups):
    """The two parts of a key that the door minted, each where its old value is on a host the agent holds at Fix,
    through that host's ops-root: <host> <file> <key-id> <NAME>=id:<sha256> [<NAME>=key:<sha256>]."""
    if len(args) < 4:
        return refused("key-place takes the host, the file, the key's id and NAME=id:<sha256> or NAME=key:<sha256>")
    host, path, key_id, pairs = args[0], args[1], args[2], args[3:]
    me = (access.get("agents") or {}).get(agent) or {}
    if (me.get("servers") or {}).get(host) != "fix":
        return refused(f"{agent} holds no Fix on {host}")
    if (access.get("hosts") or {}).get(host, {}).get("kind") == "fleet":
        return refused("a key is never placed on a Fleet machine")
    if not (lookups.get("minted") or (lambda k: False))(key_id):
        return refused(f"{key_id} is no key that the door minted")
    places = []
    for pair in pairs:
        m = re.fullmatch(r"([A-Z][A-Z0-9_]{0,63})=(id|key):([0-9a-f]{64})", pair)
        if not m:
            return refused(f"{pair!r} is not NAME=id:<sha256> or NAME=key:<sha256>")
        places.append({"host": host, "file": path, "name": m.group(1), "part": m.group(2), "old": m.group(3)})
    return Decision("rule", "a minted key where the old value is", target=f"{provider}:{account}", host=host,
                    plan={"provider": provider, "account": account, "place": places, "key": key_id})


# ---------------------------------------------------------------- Cloudflare

def cloudflare(access, agent, account, op, args, content, lookups):
    zone = args[0] if args else ""
    if op == "zones" and not args:
        return read_plan("cloudflare", account, [step("GET", "/zones", query={"per_page": "50"})], "a listed read")
    if op == "records" and len(args) == 1 and re.fullmatch(r"[0-9a-f]{32}", zone):
        return read_plan("cloudflare", account, [step("GET", f"/zones/{zone}/dns_records",
                                                      query={"per_page": "500"})], "a listed read")
    if op == "tunnels" and not args:
        return read_plan("cloudflare", account, [step("GET", "/accounts/{account_id}/cfd_tunnel",
                                                      query={"is_deleted": "false"})], "a listed read")
    if op == "rulesets" and len(args) == 1 and re.fullmatch(r"[0-9a-f]{32}", zone):
        return read_plan("cloudflare", account, [step("GET", f"/zones/{zone}/rulesets")], "a listed read")
    if op == "cname":
        if len(args) != 3 or not re.fullmatch(r"[0-9a-f]{32}", zone) or not HOSTNAME.fullmatch(args[1]) or \
                not re.fullmatch(r"[0-9a-f-]{36}", args[2]):
            return refused("cname takes the zone's id, the full name and the tunnel's id")
        if args[2] in (account_of(access, "cloudflare", account).get("change_tunnels") or []):
            return refused("that tunnel's names go through change")
        return Decision("rule", "a new CNAME to a tunnel of this account", target=f"cloudflare:{account}",
                        plan={"provider": "cloudflare", "account": account, "steps": [
                            step("GET", "/accounts/{account_id}/cfd_tunnel/" + args[2], keep="tunnel"),
                            step("GET", f"/zones/{zone}/dns_records", query={"name": args[1]}, need="none"),
                            step("POST", f"/zones/{zone}/dns_records", {
                                "type": "CNAME", "name": args[1], "content": f"{args[2]}.cfargotunnel.com",
                                "proxied": True, "comment": "the door"})]})
    if op == "tunnel-route":
        if len(args) != 3 or not re.fullmatch(r"[0-9a-f-]{36}", args[0]) or not HOSTNAME.fullmatch(args[1]) or \
                not re.fullmatch(r"[1-9][0-9]{0,4}", args[2]):
            return refused("tunnel-route takes the tunnel's id, the full name and the host's own port")
        if args[0] in (account_of(access, "cloudflare", account).get("change_tunnels") or []):
            return refused("that tunnel's names go through change")
        return Decision("rule", "a new tunnel hostname with the host's own origin", target=f"cloudflare:{account}",
                        plan={"provider": "cloudflare", "account": account, "tunnel": args[0], "steps": [
                            step("GET", f"/accounts/{{account_id}}/cfd_tunnel/{args[0]}/configurations",
                                 keep="ingress"),
                            step("PUT", f"/accounts/{{account_id}}/cfd_tunnel/{args[0]}/configurations",
                                 {"add": {"hostname": args[1], "service": f"http://localhost:{args[2]}"}},
                                 need="new_hostname")]})
    if op == "purge":
        if len(args) < 2 or len(args) > 31 or not re.fullmatch(r"[0-9a-f]{32}", zone):
            return refused("purge takes the zone's id and 1 to 30 names or addresses")
        urls = [a for a in args[1:] if a.startswith("https://")]
        hosts = [a for a in args[1:] if HOSTNAME.fullmatch(a)]
        if len(urls) + len(hosts) != len(args) - 1:
            return refused("purge takes full names or https addresses")
        return Decision("rule", "a cache purge", target=f"cloudflare:{account}",
                        plan={"provider": "cloudflare", "account": account, "steps": [
                            step("POST", f"/zones/{zone}/purge_cache",
                                 {"files": urls} if urls and not hosts else {"hosts": hosts} if hosts and not urls
                                 else {"files": urls, "hosts": hosts})]})
    if op == "change":
        return own_write("cloudflare", account, args, content, CF_PATH, CF_NEVER,
                         lambda method, path: f"a change of {path.split('/')[3] if path.count('/') > 2 else path}",
                         check=lambda body: "a tunnel to ssh://, tcp://, rdp://, smb:// or a socket is never the door's"
                         if re.search(r'"service"\s*:\s*"(ssh|tcp|rdp|smb|unix|unix\+tls)://', json.dumps(body or {}))
                         else None)
    return refused(f"{op} is not listed for Cloudflare")


# The owner, 6 November 2026 (DevOps D25: "Yes, as for AWS"): for every provider account, a write that is not listed
# is one write inside the key's own rights, as AWS's `call` is. Since the owner's word of 11 November 2026 ("it needs
# to be the agent itself") it runs as the agent's own call, for which the agent answers; a delete of what no agent made
# through the door comes to the owner as a Needs-you item with the exact call, which his signed yes lets through once
# (deletes). An unlisted read stays refused, so that no read returns a key, and a write whose answer is a secret is
# never sent: the door gives the agent the provider's answer.
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
CF_PATH = re.compile(r"/(zones|accounts)/([0-9a-f]{32}|\{account_id\})(/[A-Za-z0-9._~:@-]+){1,10}")
CF_NEVER = ((r"/tokens(/|$)", "an API token's answer is its secret: never the door's"),
            (r"/cfd_tunnel/[^/]+/token$", "a tunnel's token is a secret: never the door's"),
            (r"^POST \S*/(cfd_tunnel|warp_connector)$", "a new tunnel's answer carries its token: never the door's"),
            (r"/(stream|images/v1)/keys(/|$)", "a signing key's answer is its private part: never the door's"),
            (r"/temp-access-credentials", "R2 credentials are secrets: never the door's"),
            (r"/service_tokens", "a service token's answer is its secret: never the door's"))


def own_write(provider, account, args, content, path, never, why, host=None, first=(), methods=WRITE_METHODS,
              query=None, check=None):
    """D25's form `change <METHOD> <path>`, with the body as content: one write of the key's own rights, as the agent's
    own call. A read
    is not one, so an unlisted read stays refused. check(body): the words of a refusal of this provider's own, or
    None, on the body as the door parsed it."""
    if len(args) < 2 or args[0] not in methods:
        return refused(f"change takes {', '.join(methods)} and the path, with the body as content; a read that is not "
                       f"listed stays refused")
    method, where = args[0], args[1]
    if ".." in where or not path.fullmatch(where):
        return refused(f"{where} is not a path of this {provider} account that the door changes")
    for pattern, words in never:                # each pattern reads "<METHOD> <path>"
        if re.search(pattern, f"{method} {where}"):
            return refused(words)
    body = None
    if content and method != "DELETE":
        body = json_body(content)
        if body is False:
            return refused("the body is JSON of at most 64 KiB")
    words = check(body) if check else None
    if words:
        return refused(words)
    last = step(method, where, body, **({"query": query} if query else {}))
    return Decision("own", why(method, where), target=f"{provider}:{account}", host=host,
                    plan={"provider": provider, "account": account, "steps": [*first, last]})


def json_body(content):
    if not content or len(content) > BODY_MAX:
        return False
    try:
        return json.loads(content)
    except ValueError:
        return False


# ---------------------------------------------------------------- GitHub

def github(access, agent, owner, op, args, content, lookups):
    repo = args[0] if args else ""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", repo or "-"):
        return refused("the repository is its name under this owner")
    full = f"{owner}/{repo}"
    if vendor(full):
        return refused(f"{full} is never a target of the door")
    reads = {"runs": f"/repos/{full}/actions/runs", "failed": f"/repos/{full}/actions/runs",
             "alerts": f"/repos/{full}/dependabot/alerts", "code-alerts": f"/repos/{full}/code-scanning/alerts",
             "secret-alerts": f"/repos/{full}/secret-scanning/alerts", "runners": f"/repos/{full}/actions/runners"}
    if op in reads and len(args) == 1:
        query = {"per_page": "50"}
        if op == "failed":
            query["status"] = "failure"
        if op == "secret-alerts":
            query["hide_secret"] = "true"           # the alert, never the secret it found
        return read_plan("github", owner, [step("GET", reads[op], query=query)], "a listed read", repo=full)
    if op == "jobs" and len(args) == 2 and args[1].isdigit():
        return read_plan("github", owner, [step("GET", f"/repos/{full}/actions/runs/{args[1]}/jobs")],
                         "a listed read", repo=full)
    if op in ("workflow", "secret", "pull-request") and not holds(access, agent, full):
        return refused(f"{full} is no repository that this agent holds: a GitHub write of the door reaches only those "
                       f"(new-projects plan N2)")
    if op == "workflow":
        if len(args) < 2 or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}\.ya?ml", args[1]):
            return refused("workflow takes the repository, the workflow's file name and name=value inputs")
        lists = (access.get("workflows") or {}).get(full) or {}
        inputs = {}
        for pair in args[2:]:
            key, sep, value = pair.partition("=")
            if not sep or not re.fullmatch(r"[a-z][a-z0-9_-]{0,40}", key) or not INPUT.fullmatch(value):
                return refused(f"{pair!r} is not an input that code can check")
            inputs[key] = value
        kind = "rule" if args[1] in (lists.get("health") or []) else \
            "own" if args[1] in (lists.get("bootstrap") or []) else None
        if kind is None:
            return refused(f"{args[1]} is not a listed workflow of {full}")
        ref = lists.get("ref") or (lookups.get("default_branch") or (lambda name: None))(full)
        if not ref:
            return refused(f"the door could not read the default branch of {full}")
        return Decision(kind, f"a {'health' if kind == 'rule' else 'bootstrap'} workflow", target=f"github:{owner}",
                        plan={"provider": "github", "account": owner, "repo": full, "steps": [
                            step("POST", f"/repos/{full}/actions/workflows/{args[1]}/dispatches",
                                 {"ref": ref, "inputs": inputs})]})
    if op == "secret":
        if len(args) != 4 or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", args[1]) or args[3] not in ("id", "key") or \
                not (lookups.get("minted") or (lambda k: False))(args[2]):
            return refused("secret takes the repository, the secret's name, the id of a key the door rotated, and id "
                           "or key: which part of it")
        return Decision("rule", "a new value of a secret that the door rotated", target=f"github:{owner}",
                        plan={"provider": "github", "account": owner, "secret": {"repo": full, "name": args[1],
                                                                                 "key": args[2], "part": args[3]}})
    if op == "pull-request":
        if len(args) < 4 or not all(re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", b) for b in args[1:3]):
            return refused("pull-request takes the repository, the head branch, the base branch and the title")
        return Decision("rule", "a pull request", target=f"github:{owner}",
                        plan={"provider": "github", "account": owner, "repo": full, "steps": [
                            step("POST", f"/repos/{full}/pulls", {"head": args[1], "base": args[2],
                                                                   "title": " ".join(args[3:])[:200]})]})
    if op == "repo-new":
        if len(args) != 1 or not APP_NAME.fullmatch(args[0]):
            return refused("repo-new takes the app's name: a lowercase letter, then lowercase letters, digits and "
                           "hyphens, 24 characters at most")
        if full.lower() in [r.lower() for r in (access.get("never") or {}).get("repos") or []]:
            return refused(f"{full} is on the never list")
        via = sorted(r for r in ((access.get("agents") or {}).get(agent) or {}).get("github") or {}
                     if r.lower().startswith(owner.lower() + "/"))
        if not via:
            return refused(f"the door makes a repository only in an account where this agent holds one already, and "
                           f"it holds none of {owner}")
        return Decision("rule", "a new private repository with its first commit", target=f"github:{owner}",
                        plan={"provider": "github", "account": owner, "repo": via[0],
                              "repo_new": {"name": full, "agent": agent}})
    if op == "repo-delete":
        if len(args) != 1 or not APP_NAME.fullmatch(args[0]):
            return refused("repo-delete takes the app's name")
        made = (lookups.get("made_repo") or (lambda name: None))(full)
        if not made or made.get("agent") != agent:
            return refused(f"{full} is no repository that the door made for this agent: deleting another one is the "
                           f"owner's, through a Needs-you item")
        return Decision("own", "deleting a repository that the door made, which has no runner",
                        target=f"github:{owner}", plan={"provider": "github", "account": owner, "repo": full,
                                                         "repo_delete": {"name": full, "id": made.get("id")}})
    return refused(f"{op} is not listed for GitHub")


APP_NAME = re.compile(r"[a-z][a-z0-9-]{0,23}")  # new-projects plan N4: the name of an app, its users and its repository
REPO_NEW = {"administration": "write", "repository_creation": "write", "metadata": "read"}   # plan N2: one call
REPO_DELETE = {"administration": "write", "metadata": "read"}
RUNNER_TOKENS = {"administration": "write", "metadata": "read"}    # plan N6: a runner's registration and remove tokens
RUNNER_RELEASE = "https://api.github.com/repos/actions/runner/releases/latest"


def runner_release(answer):
    """(version, {x64, arm64: sha256}) of the runner's release, from GitHub's answer: each archive's own digest, and
    the SHA lines of the release's notes, which must agree when both are there (new-projects plan N6)."""
    tag, body = answer.get("tag_name"), answer.get("body") if isinstance(answer.get("body"), str) else ""
    if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]{1,3}\.[0-9]{1,4}\.[0-9]{1,4}", tag):
        raise Stop("the runner's latest release has no version")
    version, sums = tag[1:], {}
    for arch in ("x64", "arm64"):
        name = f"actions-runner-linux-{arch}-{version}.tar.gz"
        asset = next((a for a in answer.get("assets") or [] if isinstance(a, dict) and a.get("name") == name), None)
        digest = str((asset or {}).get("digest") or "")
        listed = digest[7:] if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) else None
        noted = re.search(rf"<!-- BEGIN SHA linux-{arch} -->([0-9a-f]{{64}})<!-- END SHA linux-{arch} -->", body)
        noted = noted.group(1) if noted else None
        if asset is None or not (listed or noted) or (listed and noted and listed != noted):
            raise Stop(f"GitHub publishes no one SHA-256 for {name}")
        sums[arch] = listed or noted
    return version, sums


def holds(access, agent, repo):
    """True when the access file gives this agent the repository: a grant of the hub (`github`) or a target of its
    own (`repos`), in whatever case the names come."""
    me = (access.get("agents") or {}).get(agent) or {}
    want = repo.lower()
    return any(name.lower() == want for name in list(me.get("github") or {}) + list(me.get("repos") or {}))


# ---------------------------------------------------------------- Hetzner Cloud

HZ_HELD = (r"/firewalls/[0-9]{1,12}/actions/(set_rules|apply_to_resources|remove_from_resources)",
             r"/servers/[0-9]{1,12}/actions/change_protection", r"/servers/[0-9]{1,12}")


def hz_held(access, agent):
    """The servers that this agent holds at Fix through the door, by name: the one set for every Hetzner write that
    names a server. Never a server on the never list, and never a rule-only host: the hub's server, the door's own
    and each machine of the agents hold the keys of the whole fleet, and a copy of such a disk is every one of them."""
    never, hosts = (access.get("never") or {}).get("hosts") or [], access.get("hosts") or {}
    mine = ((access.get("agents") or {}).get(agent) or {}).get("servers") or {}
    return sorted(name for name, level in mine.items() if level == "fix" and name not in never and
                  (hosts.get(name) or {}).get("mode") == "fix")


def hetzner(access, agent, project, op, args, content, lookups):
    reads = {"servers": "/servers", "firewalls": "/firewalls", "volumes": "/volumes", "ips": "/primary_ips"}
    if op in reads and not args:
        return read_plan("hetzner", project, [step("GET", reads[op], query={"per_page": "50"})], "a listed read")
    if op == "server" and len(args) == 1 and NAME.fullmatch(args[0]):
        return read_plan("hetzner", project, [step("GET", "/servers", query={"name": args[0]})], "a listed read")
    if op == "power-cycle":
        if len(args) != 1 or args[0] not in hz_held(access, agent):
            return refused("power-cycle takes a server that this agent holds at Fix")
        return Decision("rule", "a power cycle of a server that the agent holds", target=f"hetzner:{project}",
                        host=args[0], reboot=True, window="reboot",
                        plan={"provider": "hetzner", "account": project, "steps": [
                            step("GET", "/servers", query={"name": args[0]}, keep="server_id", need="one_server"),
                            step("POST", "/servers/{server_id}/actions/reset")]})
    if op == "change" and len(args) == 3:
        if args[0] not in ("POST", "PUT") or args[2] not in hz_held(access, agent):
            return refused("change takes the method, the path and the server it is for, which this agent holds at Fix")
        if "rescue" in args[1]:
            return refused("Rescue is never booted")
        if not any(re.fullmatch(p, args[1]) for p in HZ_HELD):
            return refused(f"{args[1]} is not a firewall, protection or label change")
        body = json_body(content)
        if body is False:
            return refused("the body is JSON of at most 64 KiB")
        words, first = hz_reads(args[1], body)
        if words:
            return refused(words)
        # the named server binds a path of a server (server_path); a firewall has the reads of the two-argument form
        return Decision("own", "a firewall, protection or labels of a held server", target=f"hetzner:{project}",
                        host=args[2], plan={"provider": "hetzner", "account": project,
                                            "held": hz_held(access, agent), "steps": [
                            step("GET", "/servers", query={"name": args[2]}, keep="server_id", need="one_server"),
                            *(first if args[1].startswith("/firewalls/") else []),
                            step(args[0], args[1], body, need="server_path")]})
    if op == "change" and len(args) == 2:         # D25: a write of the project's own rights, the agent's own call
        server_made = args[0] == "POST" and args[1] == "/servers"
        d = own_write("hetzner", project, args, content, HZ_PATH, HZ_NEVER,
                      lambda method, path: f"a change of {path.split('/')[1]}", methods=("POST", "PUT", "DELETE"),
                      check=lambda body: "a server with no SSH key gives its root password in the answer: name an "
                      "SSH key" if server_made and not (body or {}).get("ssh_keys") else None)
        return hz_disks(access, agent, d) if d.kind == "own" else d
    return refused(f"{op} is not listed for Hetzner")


HZ_PATH = re.compile(r"/(servers|firewalls|volumes|primary_ips|floating_ips|networks|load_balancers|certificates|"
                     r"ssh_keys|placement_groups|images)(/[0-9]{1,12})?(/actions/[a-z_]{2,40})?")
HZ_NEVER = ((r"rescue", "Rescue is never booted"),
            (r"/actions/(reset_password|request_console|rebuild)$",
             "its answer is a password or a console: never the door's"))
HZ_KEYS = {"name", "image", "volumes", "networks", "public_net", "ipv4", "ipv6", "server", "assignee", "assignee_id",
           "apply_to", "remove_from", "targets", "type", "id"}      # the body keys that hz_reads looks at
HZ_SYSTEM = re.compile(r"[a-z][a-z0-9._-]{0,62}")      # a system image has a name; a snapshot or a backup has none
# What sits on one server at a time: its name in an answer, the action that puts it on a server, the action that
# takes it off, and the field that names the server, in its own answer and in a body.
HZ_ON = {"volumes": ("volume", "attach", "detach", "server"),
         "floating_ips": ("floating_ip", "assign", "unassign", "server"),
         "primary_ips": ("primary_ip", "assign", "unassign", "assignee_id")}


def hz_disks(access, agent, d):
    """The two-argument change that own_write let through. A server's disk holds its keys, and whoever starts a copy
    of it with an SSH key of their own is root there. So a write that names a server by its id passes only for a
    server of hz_held: the door reads what hz_reads says first, and sends the write when each need holds. A delete
    keeps its own rule (deletes)."""
    if deletes(d.plan, {}):
        return d
    last = d.plan["steps"][-1]
    words, first = hz_reads(last["path"], last["body"])
    if words:
        return refused(words)
    if first:
        d.plan["held"] = hz_held(access, agent)
        if not d.plan["held"]:
            return refused("a write on a server, its disk, its volume, its address or its firewall takes a server "
                           "that this agent holds at Fix, and it holds none")
        d.plan["steps"][:0] = first
    return d


def hz_reads(path, body):
    """(the words of a refusal or None, the reads that the door sends first) for one Hetzner write that is no delete.
    A write on a server reads that server's name (held_server), and so no write changes a server's name. A new server
    starts from a system image, with no volume, network or address of the project: the agent's own SSH key is root on
    it, and no agent holds it yet. A snapshot or a backup is a copy of a disk, so no write changes one. A volume or
    an address leaves a held server, and joins a held server when it is on none. A firewall goes on and off held
    servers, and its rules change when each server that it is on is held."""
    kind, one, action = re.fullmatch(r"/([a-z_]+)(?:/([0-9]+))?(?:/actions/([a-z_]+))?", path).groups()
    body = body if isinstance(body, dict) else {}
    # The checks below read a key as the provider's documents spell it. A key in another case, at any depth, and a
    # key with a letter outside ASCII are refused, so that no check depends on how the provider reads one.
    todo = [body]
    while todo:
        part = todo.pop()
        for k, v in part.items() if isinstance(part, dict) else ():
            if not isinstance(k, str) or not k.isascii():
                return "each key of the body is plain ASCII text", []
            if k != k.lower() and k.lower() in HZ_KEYS:
                return f"the body's key {k} is written {k.lower()}", []
            if k != "labels":       # a label's name is the owner's own word, in any case: no check reads one
                todo.append(v)
        todo.extend(part if isinstance(part, list) else ())

    def held(server):
        return step("GET", f"/servers/{server}", keep="check", need="held_server")
    if kind == "servers" and one:
        if "name" in body:
            return "a server's name at the provider is how the door knows which server it is: no write of the door " \
                   "changes it", []
        return None, [held(one)]
    if kind == "servers":
        image, net = body.get("image"), body.get("public_net")
        if image is not None and not (isinstance(image, str) and HZ_SYSTEM.fullmatch(image)):
            return "a new server starts from a system image by its name, such as ubuntu-24.04: a snapshot or a " \
                   "backup is a copy of a server's disk, and is never the door's", []
        if body.get("volumes"):
            return "a new server takes no volume: a volume joins a server through its own attach action, for a " \
                   "server that this agent holds", []
        if body.get("networks"):
            return "a new server joins no private network of the project: the agent's own SSH key is root on it, and " \
                   "attach_to_network takes a server that this agent holds", []
        if isinstance(net, dict) and (net.get("ipv4") is not None or net.get("ipv6") is not None):
            return "a new server takes no address of the project: an address joins a server through its own assign " \
                   "action, for a server that this agent holds", []
    if kind == "images" and one:
        return "an image is a copy of a server's disk: a change of one is never the door's", []
    if kind in HZ_ON:
        thing, join, leave, field = HZ_ON[kind]
        if action == leave:
            return None, [step("GET", f"/{kind}/{one}", keep="check", need=f"on:{thing}"), held("{server_id}")]
        if action == join or (not one and body.get(field) is not None):
            if type(body.get(field)) is not int:
                return f"the body names the server by its id, a number, as {field}", []
            return None, ([step("GET", f"/{kind}/{one}", keep="check", need=f"free:{thing}")] if one else []) + \
                [held(body[field])]
    if kind == "load_balancers":        # a target is a server whose ports the load balancer shows to the internet
        if not one and body.get("targets"):
            return "a new load balancer has no target: add_target adds each one, a server that this agent holds", []
        if action in ("add_target", "remove_target"):
            server = body.get("server")
            if body.get("type") != "server" or not isinstance(server, dict) or type(server.get("id")) is not int:
                return "a load balancer's target is a server that the body names by its id, never a label or an " \
                       "address", []
            return None, [held(server["id"])]
    if kind == "firewalls" and action == "set_rules":
        return None, [step("GET", "/servers", query={"per_page": "50"}, keep="check", need="server_names"),
                      step("GET", f"/firewalls/{one}", keep="check", need="held_firewall")]
    if kind == "firewalls":
        named = body.get({"apply_to_resources": "apply_to", "remove_from_resources": "remove_from"}.get(
            action, "apply_to" if not one else ""))
        if named:
            if not isinstance(named, list) or len(named) > 10 or any(
                    not isinstance(r, dict) or r.get("type") != "server" or not isinstance(r.get("server"), dict) or
                    type(r["server"].get("id")) is not int for r in named):
                return "a firewall goes on and off the servers that the body names by their ids, 10 at most, and " \
                       "never by a label", []
            return None, [held(r["server"]["id"]) for r in named]
    return None, []


# ---------------------------------------------------------------- AWS
#
# The door's rights in an AWS account are a role there that only the door's own Teleport bot assumes (plan 5.4): the
# bot writes a short JWT-SVID, the door trades it at STS for an hour's session, and no AWS key is stored anywhere.

# service: (protocol, host, API version or JSON target prefix). A service that is not here is not listed; the role's
# own policy decides which calls of a listed service work.
AWS_SERVICES = {
    "ec2": ("query", "ec2.{region}.amazonaws.com", "2016-11-15"),
    "iam": ("query", "iam.amazonaws.com", "2010-05-08"),
    "sts": ("query", "sts.{region}.amazonaws.com", "2011-06-15"),
    "cloudformation": ("query", "cloudformation.{region}.amazonaws.com", "2010-05-15"),
    "rds": ("query", "rds.{region}.amazonaws.com", "2014-10-31"),
    "elasticache": ("query", "elasticache.{region}.amazonaws.com", "2015-02-02"),
    "monitoring": ("query", "monitoring.{region}.amazonaws.com", "2010-08-01"),
    "ecr": ("json", "api.ecr.{region}.amazonaws.com", "AmazonEC2ContainerRegistry_V20150921"),
    "logs": ("json", "logs.{region}.amazonaws.com", "Logs_20140328"),
    "eks": ("rest", "eks.{region}.amazonaws.com", None),
}
# Never, whoever asks (plan section 2, "Always refused"): an answer that is a secret or a credential, a shell or code
# on a host, a person's or a program's access, IAM beyond the listed key form, and the account itself. A disk's copy
# that goes to another account or to a bucket is access too: a shared image or snapshot, and an export.
AWS_NEVER = re.compile(
    r"(sts|iam|organizations|account|secretsmanager|kms|lambda|ec2-instance-connect):.*"
    r"|ssm:(Get|Send|Start|Resume).*|ecr:(GetAuthorizationToken|GetDownloadUrlForLayer|InitiateLayerUpload"
    r"|UploadLayerPart|CompleteLayerUpload)"
    r"|ec2:(GetPasswordData|DescribeInstanceAttribute|ModifyInstanceAttribute|GetLaunchTemplateData"
    r"|DescribeLaunchTemplateVersions|CreateLaunchTemplate.*|GetConsoleOutput|GetConsoleScreenshot"
    r"|CreateKeyPair|ImportKeyPair|ModifyImageAttribute|ModifySnapshotAttribute|ExportImage"
    r"|CreateInstanceExportTask|CreateStoreImageTask)"
    r"|rds:(ModifyDBSnapshotAttribute|ModifyDBClusterSnapshotAttribute|StartExportTask)", re.I)
CALL_SERVICES = [name for name in AWS_SERVICES if not AWS_NEVER.fullmatch(f"{name}:Any")]
AWS_NEVER_PATH = re.compile(r"/(access-entries|access-policies|pod-identity-associations|identity-provider-configs)"
                            r"(/|$)")
REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]")
CIDR4 = re.compile(r"(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}/([0-9]|[12][0-9]|3[0-2])")


def aws(access, agent, account, op, args, content, lookups):
    tag = account_of(access, "aws", account).get("tag", "door")
    reads = {"instances": ("ec2", "DescribeInstances"), "groups": ("ec2", "DescribeSecurityGroups"),
             "stacks": ("cloudformation", "DescribeStacks"), "identity": ("sts", "GetCallerIdentity")}
    if op in reads and not args:
        return read_plan("aws", account, [{"aws": reads[op], "params": {}}], "a listed read")
    if op in ("start", "stop", "reboot"):
        if len(args) != 1 or not re.fullmatch(r"i-[0-9a-f]{8,17}", args[0]):
            return refused(f"{op} takes one instance id")
        action = {"start": "StartInstances", "stop": "StopInstances", "reboot": "RebootInstances"}[op]
        return Decision("rule", f"{op} of a tagged instance", target=f"aws:{account}", reboot=True, window="reboot",
                        plan={"provider": "aws", "account": account, "steps": [
                            {"aws": ("ec2", "DescribeInstances"), "params": {
                                "InstanceId.1": args[0], "Filter.1.Name": "tag-key", "Filter.1.Value.1": tag},
                             "need": "tagged"},
                            {"aws": ("ec2", action), "params": {"InstanceId.1": args[0]}}]})
    if op == "ingress":
        if len(args) != 5 or args[0] not in ("add", "remove") or not re.fullmatch(r"sg-[0-9a-f]{8,17}", args[1]) or \
                args[2] not in ("tcp", "udp") or not re.fullmatch(r"[0-9]{1,5}", args[3]) or \
                not re.fullmatch(r"[0-9.]{7,15}/[0-9]{1,2}", args[4]):
            return refused("ingress takes add or remove, the group, tcp or udp, the port and an IPv4 range")
        action = "AuthorizeSecurityGroupIngress" if args[0] == "add" else "RevokeSecurityGroupIngress"
        return Decision("own", "a security group of a tagged instance", target=f"aws:{account}",
                        plan={"provider": "aws", "account": account, "steps": [
                            {"aws": ("ec2", "DescribeInstances"), "params": {
                                "Filter.1.Name": "instance.group-id", "Filter.1.Value.1": args[1],
                                "Filter.2.Name": "tag-key", "Filter.2.Value.1": tag}, "need": "tagged"},
                            {"aws": ("ec2", action), "params": {
                                "GroupId": args[1], "IpPermissions.1.IpProtocol": args[2],
                                "IpPermissions.1.FromPort": args[3], "IpPermissions.1.ToPort": args[3],
                                "IpPermissions.1.IpRanges.1.CidrIp": args[4]}}]})
    if op == "change-set":
        if len(args) != 2 or not NAME.fullmatch(args[0]) or not NAME.fullmatch(args[1]) or not content:
            return refused("change-set takes the stack, the change set's name and the template as content")
        return Decision("own", "a CloudFormation change set", target=f"aws:{account}",
                        plan={"provider": "aws", "account": account, "steps": [
                            {"aws": ("cloudformation", "CreateChangeSet"), "params": {
                                "StackName": args[0], "ChangeSetName": args[1],
                                "TemplateBody": content.decode("utf-8", "replace")}}]})
    if op == "key-off":
        if len(args) != 2 or not NAME.fullmatch(args[0]) or not re.fullmatch(r"AKIA[0-9A-Z]{16}", args[1]):
            return refused("key-off takes the user and the access key id")
        return Decision("own", "deactivating an IAM key that shows no use", target=f"aws:{account}",
                        plan={"provider": "aws", "account": account, "steps": [
                            {"aws": ("iam", "GetAccessKeyLastUsed"), "params": {"AccessKeyId": args[1]},
                             "need": "unused"},
                            {"aws": ("iam", "UpdateAccessKey"), "params": {
                                "UserName": args[0], "AccessKeyId": args[1], "Status": "Inactive"}}]})
    if op == "eks-allowlist":
        if not 2 <= len(args) <= 41 or not NAME.fullmatch(args[0]) or not all(CIDR4.fullmatch(a) for a in args[1:]):
            return refused("eks-allowlist takes the cluster and its new list: one to 40 IPv4 ranges")
        if any(a.endswith("/0") for a in args[1:]):
            return refused("an EKS endpoint open to every address is never the door's to set")
        return Decision("own", "a change of the EKS public endpoint allowlist", target=f"aws:{account}",
                        plan={"provider": "aws", "account": account, "steps": [
                            {"aws": ("eks", "DescribeCluster"), "method": "GET", "path": f"/clusters/{args[0]}"},
                            {"aws": ("eks", "UpdateClusterConfig"), "method": "POST",
                             "path": f"/clusters/{args[0]}/update-config",
                             "params": {"resourcesVpcConfig": {"publicAccessCidrs": args[1:]}}}]})
    if op == "call":
        return aws_any(account, args, content)
    return refused(f"{op} is not listed for AWS")


def aws_held(service, action, params):
    """The words of a refusal for a call that is right only for a server that the agent holds, or None. The door has
    no record of which instance of an AWS account an agent holds, so it sends none of them: a copy of a disk, a disk
    on another instance, code that runs at start-up, and a new master password."""
    names = {name.lower() for name in params}
    if service == "ec2" and re.fullmatch(r"(?i)CreateImage|CreateSnapshots?", action):
        return "it makes a copy of an instance's disk, and the door does not know which instances an agent holds"
    if service == "ec2" and re.fullmatch(r"(?i)AttachVolume|CreateReplaceRootVolumeTask", action):
        return "it puts a disk on another instance, and the door does not know which instances an agent holds"
    if service == "ec2" and any(name.endswith("userdata") for name in names):
        return "UserData is code that runs as root when an instance starts"
    if service == "rds" and action.lower().startswith("modify") and "masteruserpassword" in names:
        return "a new master password is a login to a database that is there"
    return None


def aws_any(account, args, content):
    """Any other call inside the role's rights, as the agent's own call (the plan's AWS row): `call <service> <Action>
    [<region>]` with its parameters as one JSON object of content (flat for a query service), or `call eks <METHOD>
    <path> [<region>]` with an optional JSON body. AWS_NEVER, aws_held and the role's own deny list hold the rest, and
    every AWS delete is the owner's (deletes)."""
    service = args[0] if args else ""
    protocol = (AWS_SERVICES.get(service) or ("",))[0]
    rest = protocol == "rest"
    region = args[3 if rest else 2] if len(args) == (4 if rest else 3) else None
    if service not in CALL_SERVICES or len(args) not in ((3, 4) if rest else (2, 3)) or \
            (region and not REGION.fullmatch(region)):
        return refused(f"call takes a service of {', '.join(CALL_SERVICES)}, its action (for eks a method and a "
                       f"path) and a region")
    try:
        params = json.loads(content) if content else None
    except ValueError:
        return refused("the parameters are one JSON object")
    if params is not None and not isinstance(params, dict):
        return refused("the parameters are one JSON object")
    if rest:
        method, path = args[1], args[2]
        if method not in ("GET", "POST", "PUT", "DELETE") or \
                not re.fullmatch(r"/[A-Za-z0-9._~/-]{1,300}(\?[A-Za-z0-9._~=&-]{1,500})?", path) or ".." in path:
            return refused("the call takes GET, POST, PUT or DELETE and a path")
        if AWS_NEVER_PATH.search(path.partition("?")[0]):
            return refused("a person's or a program's access to a cluster is never the door's")
        if re.fullmatch(r"/clusters/[^/]+/update-config", path.partition("?")[0]) and \
                "resourcesvpcconfig" in keys_in(params):
            return refused("the cluster's endpoint and the addresses that reach it change through eks-allowlist, "
                           "which never opens it to every address")
        s = {"aws": (service, f"{method} {path.partition('?')[0]}"), "method": method, "path": path, "params": params}
    else:
        action = args[1]
        if not re.fullmatch(r"[A-Z][A-Za-z0-9]{1,80}", action):
            return refused("the action is a name like DescribeVolumes")
        if AWS_NEVER.fullmatch(f"{service}:{action}"):
            return refused(f"{service}:{action} is never the door's: its answer is a secret, it opens a shell or "
                           f"code on a host, or it gives access")
        why = aws_held(service, action, params or {})
        if why:
            return refused(f"{service}:{action} is never the door's here: {why}")
        if protocol == "query" and params and (len(params) > 200 or any(
                not re.fullmatch(r"[A-Za-z0-9.]{1,100}", k) or not isinstance(v, (str, int, bool))
                for k, v in params.items())):
            return refused("a query service's parameters are flat: names like Filter.1.Name, and text values")
        s = {"aws": (service, action), "params": {k: str(v).lower() if isinstance(v, bool) else str(v)
                                                  for k, v in params.items()} if protocol == "query" and params
             else params or {}}
    if region:
        s["region"] = region
    return Decision("own", f"a call of {service} inside the role's rights", target=f"aws:{account}",
                    plan={"provider": "aws", "account": account, "steps": [s], "call": True})


# ---------------------------------------------------------------- Azure

AZ_READS = (r"/subscriptions/[0-9a-f-]{36}/resourceGroups(/[A-Za-z0-9._()-]+)?",
            r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Za-z0-9._()-]+/providers/Microsoft\.(Sql|Web)/"
            r"[A-Za-z/]+(/[A-Za-z0-9._-]+)?",
            r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Za-z0-9._()-]+/providers/[A-Za-z.]+/[A-Za-z]+/"
            r"[A-Za-z0-9._-]+/providers/Microsoft\.Insights/metrics")


def azure(access, agent, account, op, args, content, lookups):
    conf = account_of(access, "azure", account)
    if op == "get" and len(args) == 1:
        if not any(re.fullmatch(p, args[0]) for p in AZ_READS) or re.search(r"/(config|listKeys|publishxml)", args[0],
                                                                            re.I):
            return refused(f"{args[0]} is not a listed read")
        return read_plan("azure", account, [step("GET", args[0])], "a listed read")
    if op == "sql-firewall":
        if len(args) != 4 or args[0] not in (conf.get("sql_servers") or []) or not NAME.fullmatch(args[1]) or \
                not all(re.fullmatch(r"[0-9.]{7,15}", ip) for ip in args[2:]):
            return refused("sql-firewall takes a listed SQL server, the rule's name and the first and last address")
        return Decision("own", "a firewall rule on a listed SQL server", target=f"azure:{account}",
                        plan={"provider": "azure", "account": account, "steps": [step(
                            "PUT", f"{args[0]}/firewallRules/{args[1]}",
                            {"properties": {"startIpAddress": args[2], "endIpAddress": args[3]}})]})
    if op == "app-setting":
        if len(args) != 3 or args[0] not in (conf.get("sites") or []) or \
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", args[1]) or len(args[2]) > 2000:
            return refused("app-setting takes a listed site, the setting's name and its value")
        return Decision("own", "an App Service setting", target=f"azure:{account}",
                        plan={"provider": "azure", "account": account, "app_setting": {
                            "site": args[0], "name": args[1], "value": args[2]}})
    if op == "change":                            # D25: a write of the service principal's own rights, an own call
        if len(args) != 3 or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?", args[2]):
            return refused("change takes the method, the path and the API version of its resource provider, with the "
                           "body as content")
        return own_write("azure", account, args[:2], content, AZ_PATH, AZ_NEVER,
                         lambda method, path: "a change of " + (path.split("/providers/")[-1].split("/")[0]
                                                                if "/providers/" in path else "a resource group"),
                         query={"api-version": args[2]},
                         check=lambda body: "a machine's osProfile, customData, userData and extensionProfile set its "
                         "login or run code on it at start-up: never the door's"
                         if re.search(r"(?i)/Microsoft\.Compute/", args[1]) and AZ_LOGIN & set(keys_in(body)) else None)
    return refused(f"{op} is not listed for Azure")


AZ_PATH = re.compile(r"/subscriptions/[0-9a-f-]{36}(/[A-Za-z0-9._()~-]+){1,16}")
AZ_NEVER = ((r"(?i)^POST \S*/(list[a-z]*|regenerate[a-z]*|generate[a-z]*|get[a-z]*|reset[a-z]*|rotate[a-z]*|"
             r"begingetaccess|createquerykey/[^/]+|publishxml|[a-z]*(token|credentials?|sas|password|secrets?|keys?))$",
             "its answer can be a key, a password, a token, a connection string or a setting, which ARM gives only "
             "to an action like this one: never the door's"),
            (r"(?i)/(keys|functionkeys|hostkeys|systemkeys|secrets)(/[^/]+)?$",
             "a key or a secret of a resource is never the door's"),
            (r"(?i)/runcommands?(/|$)", "a command on a machine or in a cluster is a shell there: never the door's"),
            (r"(?i)/Microsoft\.(Compute|HybridCompute)/\S+/extensions(/|$)",
             "an extension runs code as root on a machine, and one of them sets its login: never the door's"),
            (r"(?i)/Microsoft\.Resources/(deployments|deploymentScripts|deploymentStacks)(/|$)",
             "a deployment makes whatever its template says, and a deployment script runs code, with all of the "
             "door's rights: never the door's. change takes one resource at a time"),
            (r"(?i)/Microsoft\.Authorization(/|$)", "a person's or a program's access is never the door's"))
AZ_LOGIN = {"osprofile", "customdata", "userdata", "extensionprofile"}      # ARM reads a name in any case


def keys_in(value):
    """Each name in a JSON value, at any depth, in lower case."""
    if isinstance(value, dict):
        for name, inner in value.items():
            yield name.lower()
            yield from keys_in(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from keys_in(inner)


# ---------------------------------------------------------------- Tailscale

def tailscale(access, agent, tailnet, op, args, content, lookups):
    fleet_tags = account_of(access, "tailscale", tailnet).get("fleet_tags") or []
    if op == "devices" and not args:
        return read_plan("tailscale", tailnet, [step("GET", "/tailnet/-/devices")], "a listed read")
    if op == "device" and len(args) == 1 and ID.fullmatch(args[0]):
        return read_plan("tailscale", tailnet, [step("GET", f"/device/{args[0]}")], "a listed read")
    if op in ("key-expiry-off", "rename"):
        if not args or not ID.fullmatch(args[0]) or (op == "rename" and (len(args) != 2 or not re.fullmatch(
                r"[a-z0-9][a-z0-9-]{0,62}", args[1]))) or (op != "rename" and len(args) != 1):
            return refused("key-expiry-off takes a device id; rename takes a device id and a name")
        last = step("POST", f"/device/{args[0]}/key", {"keyExpiryDisabled": True}) if op == "key-expiry-off" else \
            step("POST", f"/device/{args[0]}/name", {"name": args[1]})
        return Decision("rule", "a device of the fleet", target=f"tailscale:{tailnet}",
                        plan={"provider": "tailscale", "account": tailnet, "steps": [
                            step("GET", f"/device/{args[0]}", need="fleet_device"), last],
                              "fleet_tags": fleet_tags})
    if op == "delete" and len(args) == 1 and ID.fullmatch(args[0]):
        return Decision("own", "deleting a device", target=f"tailscale:{tailnet}",
                        plan={"provider": "tailscale", "account": tailnet,
                              "steps": [step("DELETE", f"/device/{args[0]}")]})
    if op == "oauth-client" and len(args) == 2 and args[0] in ("make", "revoke") and \
            re.fullmatch(r"tag:[a-z0-9-]{1,50}|[A-Za-z0-9]{6,40}", args[1]):
        steps = [step("POST", "/tailnet/-/keys", {"keyType": "client", "scopes": ["devices:core"],
                                                   "tags": [args[1]]}, keep="minted")] if args[0] == "make" else \
            [dict(step("DELETE", f"/tailnet/-/keys/{args[1]}", keep="revoked"), key_id=args[1])]
        return Decision("own", f"{args[0]} an OAuth client for one tag", target=f"tailscale:{tailnet}",
                        plan={"provider": "tailscale", "account": tailnet, "steps": steps})
    if op in ("tags", "acl", "policy"):
        return refused("a device's tags and the policy file are never the door's")
    if op == "change":                            # D25: a write of the client's own rights, an own call
        return own_write("tailscale", tailnet, args, content, TS_PATH, TS_NEVER,
                         lambda method, path: f"a change of {path.split('/')[-1]}")
    return refused(f"{op} is not listed for Tailscale")


TS_PATH = re.compile(r"/(tailnet/-|device/[0-9A-Za-z]{6,40})(/[A-Za-z0-9._-]+){0,4}")
# The door knows a caller by its Tailscale address and by nothing else, so whoever moves a device's address, routes
# or approval, or the tailnet's own settings, can become another agent to the door. `change` passes the three writes
# of TS_OWN, which the listed forms make too, and no other write of a device or of the tailnet.
TS_OWN = r"POST /device/[^/]+/(name|key)|DELETE /device/[^/]+"
TS_NEVER = ((r"/keys(/|$)", "a key's answer is its secret: the door's oauth-client makes one and keeps it"),
            (r"/(acl|tags)(/|$)", "a device's tags and the policy file are never the door's"),
            (r"/webhooks(/|$)", "a webhook's answer is its secret: never the door's"),
            (r"-invites(/|$)", "an invite's answer is a link that lets anybody in: never the door's"),
            (rf"^(?!({TS_OWN})$)\S+ /device/",
             "a device's address, routes, approval and attributes decide who a caller is on the private network: "
             "never the door's. change takes a device's name, its key expiry and its delete"),
            (r"^\S+ /tailnet/",
             "the tailnet's settings, its DNS, its posture rules and its users decide who reaches what and who is who "
             "on the private network: never the door's"))


PROVIDERS = {"backblaze": backblaze, "cloudflare": cloudflare, "github": github, "hetzner": hetzner, "aws": aws,
             "azure": azure, "tailscale": tailscale}


def decide(access, agent, kind, name, op, args, content, lookups):
    for a in args:
        if len(a) > 2000 or "\n" in a or "\0" in a:
            return refused("each argument is one line of text")
    d = PROVIDERS[kind](access, agent, name, op, args, content, lookups)
    d.target = d.target or f"{kind}:{name}"
    return d


# ---------------------------------------------------------------- what an agent made, and what a delete removes
#
# The coordinator's change to D25 (6 November 2026): "a delete of what no agent made" is a code check. The door keeps
# the names of what writes through it made (made_keys, from the provider's answer); an agent's own call that deletes
# anything else (deletes) goes to the owner as a Needs-you item with the exact call, and his signed yes lets it through
# once.

HZ_ONE = {"servers": "server", "firewalls": "firewall", "volumes": "volume", "primary_ips": "primary_ip",
          "floating_ips": "floating_ip", "networks": "network", "load_balancers": "load_balancer",
          "certificates": "certificate", "ssh_keys": "ssh_key", "placement_groups": "placement_group"}
MADE_NAME = re.compile(r"[A-Za-z0-9._:@~-]{1,200}")
B2_MADE = ("b2_copy_file", "b2_start_large_file", "b2_finish_large_file")
B2_DELETE = {"b2_delete_bucket": ("bucket", "bucketId"), "b2_delete_file_version": ("file", "fileId"),
             "b2_cancel_large_file": ("file", "fileId"), "b2_delete_key": ("key", "applicationKeyId")}
AZ_DELETE_ACTION = re.compile(r"(?i)(delete|purge|remove|reimage|wipe|clear|truncate|empty)[a-z]*")
# The coordinator's word of 6 November 2026 on D25: every AWS delete through the generic `call` is the owner's, decided
# by the action's name, with no record of what an agent made there (an AWS answer names the resources that a call read,
# too, so a record would take them for made). Delete, Terminate, Remove, Deregister, Revoke and Purge, as he named them,
# and the ones of the listed services that remove something under another name: BatchDelete (ECR's images), Release (an
# Elastic IP or a dedicated host), Cancel (a spot fleet's cancel can end its instances), and three that delete by a
# rule. The listed form `ingress remove` stays the agent's own call, as before D25: it closes access and deletes
# nothing, and the exposure duty needs it fast to close an open port.
AWS_DELETE = re.compile(r"(Delete|BatchDelete|Terminate|Remove|Deregister|Revoke|Purge|Release|Cancel)[A-Z][A-Za-z0-9]*")
AWS_DELETE_OTHER = ("logs:PutRetentionPolicy",          # a shorter retention deletes the older logs
                    "ecr:PutLifecyclePolicy",           # its rules delete images
                    "cloudformation:ExecuteChangeSet")  # it runs a change set, whose removals the call does not show


def made_keys(provider, method, path, status, answer):
    """The names of what one write made, from the provider's own answer: a new object of a collection (its id, or its
    name for an R2 bucket), a new Hetzner object or image, an Azure resource that a PUT created (201), a B2 bucket or
    file. A write that changed something that was there makes nothing."""
    if status >= 300 or not isinstance(answer, dict):
        return []
    if provider == "cloudflare" and method == "POST":
        result = answer.get("result")
        if path.endswith("/dns_records/batch") and isinstance(result, dict):
            return [f"{path.removesuffix('/batch')}/{r['id']}" for r in result.get("posts") or []
                    if isinstance(r, dict) and isinstance(r.get("id"), str) and MADE_NAME.fullmatch(r["id"])]
        if isinstance(result, dict):
            return [f"{path}/{result[k]}" for k in ("id", "uuid", "name")
                    if isinstance(result.get(k), str) and MADE_NAME.fullmatch(result[k])]
    if provider == "hetzner" and method == "POST":
        if path.strip("/") in HZ_ONE:
            one, where = answer.get(HZ_ONE[path.strip("/")]), path
        elif re.fullmatch(r"/servers/[0-9]{1,12}/actions/create_image", path):
            one, where = answer.get("image"), "/images"
        else:
            one, where = None, ""
        if isinstance(one, dict) and isinstance(one.get("id"), int):
            return [f"{where}/{one['id']}"]
    if provider == "azure" and method == "PUT" and status == 201:
        return [path.lower()]
    if provider == "backblaze":
        if path == "b2_create_bucket" and isinstance(answer.get("bucketId"), str):
            return [f"bucket:{answer['bucketId']}"]
        if path in B2_MADE:
            return ([f"file:{answer['fileId']}"] if isinstance(answer.get("fileId"), str) else []) + \
                ([f"name:{answer['bucketId']}/{answer['fileName']}"]
                 if isinstance(answer.get("bucketId"), str) and isinstance(answer.get("fileName"), str) else [])
    return []


def deletes(plan, conf):
    """The names of what a plan deletes, as made_keys names them, or [] when it deletes nothing: the DELETE method,
    and each provider's delete calls that use another method (B2's b2_delete_*, b2_hide_file and b2_cancel_large_file,
    Cloudflare's batch and bulk deletes, Hetzner's disable_backup, which deletes the server's backups, and Azure's
    delete, purge and reimage actions). A key is made when the door minted it. A delete whose target the door cannot
    name gets a name that nothing made, so it goes to the owner, and so does every AWS delete of the generic `call`
    (AWS_DELETE), by its action's name or the REST API's DELETE method."""
    provider, out = (plan or {}).get("provider"), []
    for s in (plan or {}).get("steps") or []:
        method, path = s.get("method"), s.get("path") or ""
        body = s.get("body") if isinstance(s.get("body"), dict) else {}
        if provider == "aws":
            service, action = s.get("aws") or ("", "")
            if plan.get("call") and (method == "DELETE" or AWS_DELETE.fullmatch(action) or
                                     f"{service}:{action}" in AWS_DELETE_OTHER):
                out.append(f"aws:{service}:{action}")
            continue
        if provider == "backblaze":
            if path == "b2_hide_file":
                out.append(f"name:{body.get('bucketId')}/{body.get('fileName')}")
            elif path in B2_DELETE:
                out.append(f"{B2_DELETE[path][0]}:{body.get(B2_DELETE[path][1])}")
            elif re.match(r"b2_(delete|hide|cancel)_", path):
                out.append(f"{path}:?")
            continue
        if provider not in ("cloudflare", "hetzner", "azure", "tailscale"):
            continue
        if provider == "cloudflare":
            path = path.replace("{account_id}", str(conf.get("account_id") or ""))
        if provider == "azure":
            path = path.lower()
        if method == "DELETE":
            key = re.fullmatch(r"/tailnet/-/keys/([A-Za-z0-9]{1,100})", path) if provider == "tailscale" else None
            out.append(f"key:{key.group(1)}" if key else path)
        elif method != "POST":
            continue
        elif provider == "hetzner" and re.fullmatch(r"/servers/[0-9]{1,12}/actions/disable_backup", path):
            out.append(path.partition("/actions/")[0])
        elif provider == "azure" and AZ_DELETE_ACTION.fullmatch(path.rsplit("/", 1)[-1]):
            out.append(path.rsplit("/", 1)[0])
        elif provider == "cloudflare" and path.endswith("/dns_records/batch"):
            base = path.removesuffix("/batch")
            out += [f"{base}/{d['id']}" if isinstance(d, dict) and isinstance(d.get("id"), str) else f"{base}/?"
                    for d in body.get("deletes") or []]
        elif provider == "cloudflare" and re.search(r"/(bulk/)?delete$", path):
            out.append(re.sub(r"/(bulk/)?delete$", "", path))
    return out


def named(key):
    """A name of deletes() in words."""
    kind, _, rest = key.partition(":")
    words = {"bucket": "the bucket", "file": "the file version", "name": "the file", "key": "the key",
             "aws": "the AWS call"}
    return f"{words[kind]} {rest}" if kind in words and not key.startswith("/") else key


def delete_refusal(key):
    """The door's words for a delete that is the owner's, for the first name that deletes() gave."""
    if key.startswith("aws:"):
        return f"this call is an AWS delete ({key[4:]}), and every AWS delete is the owner's."
    return f"this call deletes {named(key)}, which no agent made through the door, and such a delete is the owner's."


# ---------------------------------------------------------------- execute a plan
#
# ctx gives what a plan needs: http(method, url, headers, body) -> (status, answer), the secret of this account
# (credentials), keep(kind, value) for what the door keeps (a minted key's secret) and forgets (the id of a key that
# it revoked), minted_secret(key_id), and
# host(host, op, args, stdin) for a call through a host's ops-root. Tests give a stub ctx.

BASES = {"cloudflare": "https://api.cloudflare.com/client/v4", "github": "https://api.github.com",
         "hetzner": "https://api.hetzner.cloud/v1", "tailscale": "https://api.tailscale.com/api/v2",
         "azure": "https://management.azure.com"}


class Stop(Exception):
    """A step that cannot go on: its condition failed, or the provider refused."""


def execute(plan, ctx):
    """Run one plan and give the text the agent reads: the provider's answers, with what the door keeps taken out."""
    provider, conf = plan["provider"], ctx["credentials"]
    if "place" in plan:
        return place(plan, ctx)
    if "secret" in plan:
        return github_secret(plan, ctx)
    if "repo_new" in plan:
        return repo_new(plan, ctx)
    if "repo_delete" in plan:
        return repo_delete(plan, ctx)
    if "app_setting" in plan:
        return azure_setting(plan, ctx)
    session = open_session(provider, conf, ctx, plan)
    said, kept = [], {}
    for s in plan["steps"]:
        if provider == "aws":
            status, answer = aws_call(s, conf, ctx)
        else:
            path = s["path"].format(**dict(session.get("fill", {}), **kept))
            status, answer = send(provider, s, path, session, ctx, kept, plan)
        if status >= 400:
            if provider == "cloudflare" and session.get("work") and status in (401, 403):
                raise cloudflare_refused(session, status, answer, ctx)
            raise Stop(f"{provider} answered {status}: {short(answer)}")
        if provider != "aws" and ctx.get("made"):
            for key in made_keys(provider, s["method"], path, status, answer):
                ctx["made"](key)
        need = s.get("need")
        if need:
            check_need(need, answer, plan, kept)
        if s.get("keep") == "minted":
            ctx["keep"]("minted", answer)
            if provider == "backblaze":
                key_works(answer, ctx)
            said.append(f"minted {answer.get('applicationKeyId') or answer.get('id')}: the door keeps its secret" +
                        (", and the new key works" if provider == "backblaze" else ""))
            continue
        if s.get("keep") == "revoked":          # a key that the provider ended leaves the door's list and secrets
            ctx["keep"]("revoked", s["key_id"])
        if s.get("keep") == "server_id":
            kept["server_id"] = answer["servers"][0]["id"]
            continue
        if s.get("keep") in ("tunnel", "ingress", "check"):     # check: a read that only a need looks at
            kept[s["keep"]] = answer
            continue
        said.append(short(answer, 4000))
    return "\n".join(said) or "done"


def check_need(need, answer, plan, kept):
    if need == "none" and (answer.get("result") or []):
        raise Stop("a record of that name exists: a change of it goes through change")
    if need == "one_server" and len(answer.get("servers") or []) != 1:
        raise Stop("no one server has that name in this project")
    if need == "held_server" and (answer.get("server") or {}).get("name") not in (plan.get("held") or []):
        raise Stop("that server is none that this agent holds at Fix: a write on a server, its disk or its volume "
                   "passes only for one that it holds")
    how, _, thing = need.partition(":")
    if how in ("free", "on"):       # Hetzner: the server that a volume or an address is on, before it moves (HZ_ON)
        one, name = answer.get(thing), thing.replace("_", " ")
        on = one.get("assignee_id" if thing == "primary_ip" else "server") if isinstance(one, dict) else False
        if how == "free" and on is not None:
            raise Stop(f"that {name} is on a server, or the project did not say: take it off first, from a server "
                       f"that this agent holds")
        if how == "on" and type(on) is not int:
            raise Stop(f"that {name} is on no server")
        kept["server_id"] = on                      # the next step reads that server's name (held_server)
    if need == "server_names":      # Hetzner: the project's servers, for the firewall that the next step reads
        kept["names"] = {one.get("id"): one.get("name") for one in answer.get("servers") or []
                         if isinstance(one, dict)}
    if need == "held_firewall":
        firewall = answer.get("firewall")
        on = firewall.get("applied_to") if isinstance(firewall, dict) else None
        if not isinstance(on, list) or any(
                not isinstance(r, dict) or r.get("type") != "server" or not isinstance(r.get("server"), dict) or
                kept["names"].get(r["server"].get("id")) not in (plan.get("held") or []) for r in on):
            raise Stop("that firewall is on a server that this agent does not hold at Fix, or on servers by a label, "
                       "or on one beyond the project's first 50: its rules are not this agent's to set")
    if need == "tagged" and not any(r.get("instancesSet") for r in answer.get("reservations", [{}])) and \
            not answer.get("tagged"):
        raise Stop("that instance or group has no instance with the door's tag")
    if need == "unused" and (answer.get("AccessKeyLastUsed") or {}).get("LastUsedDate"):
        raise Stop("that key shows use: it stays active")
    if need == "fleet_device" and not set(answer.get("tags") or []) & set(plan.get("fleet_tags") or []):
        raise Stop("that device has no tag of the fleet")


def short(answer, limit=2000):
    text = answer if isinstance(answer, str) else json.dumps(answer, sort_keys=True)
    return text[:limit]


def open_session(provider, conf, ctx, plan=None):
    """What every request of this plan carries: its base and its authorization. AWS has no secret: each call is
    signed with the session of the account's role (aws_session)."""
    if provider == "aws":
        return {}
    secret = ctx["secret"](conf.get("secret"))
    if provider == "backblaze":
        key_id, _, key = secret.partition(":")
        status, answer = ctx["http"]("GET", B2_AUTHORIZE,
                                     {"Authorization": "Basic " + base64.b64encode(f"{key_id}:{key}".encode())
                                      .decode()}, None)
        if status != 200:
            raise Stop(f"Backblaze refused the door's key ({status})")
        return {"base": answer["apiInfo"]["storageApi"]["apiUrl"] + "/b2api/v3/",
                "headers": {"Authorization": answer["authorizationToken"]},
                "fill": {"account_id": answer["accountId"]}}
    if provider == "github":
        return {"base": BASES["github"], "headers": {"Authorization": "Bearer " + github_token(conf, ctx, plan["repo"]),
                                                     "Accept": "application/vnd.github+json",
                                                     "X-GitHub-Api-Version": "2022-11-28"}}
    if provider == "azure":
        status, answer = ctx["http"]("POST", f"https://login.microsoftonline.com/{conf['tenant']}/oauth2/v2.0/token",
                                     {"Content-Type": "application/x-www-form-urlencoded"},
                                     urllib.parse.urlencode({"grant_type": "client_credentials",
                                                             "client_id": conf["client_id"], "client_secret": secret,
                                                             "scope": "https://management.azure.com/.default"}).encode())
        if status != 200:
            raise Stop(f"Azure refused the door's principal ({status})")
        return {"base": BASES["azure"], "headers": {"Authorization": "Bearer " + answer["access_token"]},
                "query": {"api-version": conf.get("api_version", "2023-08-01")}}
    if provider == "tailscale":
        # an OAuth client: its secret buys an access token of an hour, which the calls carry (client credentials)
        client = conf.get("client_id") or (secret.split("-")[2] if secret.startswith("tskey-client-") else "")
        status, answer = ctx["http"]("POST", BASES["tailscale"] + "/oauth/token",
                                     {"Content-Type": "application/x-www-form-urlencoded"},
                                     urllib.parse.urlencode({"client_id": client, "client_secret": secret}).encode())
        if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get("access_token"), str):
            raise Stop(f"Tailscale refused the door's OAuth client ({status})")
        return {"base": BASES["tailscale"], "headers": {"Authorization": "Bearer " + answer["access_token"]}}
    if provider == "cloudflare":
        return cloudflare_session(conf, secret, ctx)
    return {"base": BASES[provider], "headers": {"Authorization": "Bearer " + secret},
            "fill": {"account_id": conf.get("account_id") or ""}}


# ---- Cloudflare: a key that makes tokens, and the door's work key
#
# The owner, 12 November 2026, to the key card that listed seven rights for one agent's need: "why do I have to do
# that?". Since then the key that he saves for a Cloudflare account can be one that only makes tokens (a token with
# Account API Tokens Edit for that one account), given once. The door asks Cloudflare what a saved key is
# (cloudflare_key). A key that makes tokens is never sent with a call: the door makes its own work key from it, with
# the rights of CF_KEY_RIGHTS for that one account, which Cloudflare ends after CF_KEY_LIFE, and sends each call with
# that one (cloudflare_work_key). A key that makes no tokens is the hand-made narrow key of before, and is used as
# before. A token that the first key makes can hold any right of the account, so this code is the only limit on what
# the door makes: the rights are a constant, each is taken from the account's own list by its exact name and scope,
# and a new key whose answer shows another right, or another account, is deleted before any call uses it.

# What the listed forms need. An agent's `change` reaches no more than these, whatever the saved key could make.
CF_KEY_RIGHTS = (("Zone Read", "zone"), ("DNS Read", "zone"), ("DNS Write", "zone"), ("Cache Purge", "zone"),
                 ("Zone WAF Read", "zone"), ("Cloudflare Tunnel Read", "account"),
                 ("Cloudflare Tunnel Write", "account"))
CF_SCOPES = {"zone": "com.cloudflare.api.account.zone", "account": "com.cloudflare.api.account"}
CF_KEY_LIFE = 24 * 3600     # seconds until Cloudflare ends a work key by itself, whatever becomes of the door
CF_KEY_FRESH = 3600         # a work key with less than this left is replaced before the call
CF_KEY_TRIES = 4            # times that the door asks whether a new work key signs in, CF_KEY_PAUSE seconds apart
CF_KEY_PAUSE = 2
CF_KEY_SETTLE = 300         # seconds in which a new work key that Cloudflare refuses is not yet taken for a dead one
CF_KEY_NAME = "Founderizer door: {target}"      # the name of a work key in Cloudflare's own list of tokens
CF_KIND_LIFE = 24 * 3600    # seconds until the door asks again what a saved key is: its rights can change at Cloudflare
CF_ACCOUNTS_ASKED = 8       # accounts of one key that the door asks about: a key that reaches more is no key of the door
CF_ID = re.compile(r"[0-9a-f]{32}")


class Unsaid(Stop):
    """Cloudflare did not say: a time-out, a limit or a fault. It says nothing about a key."""


def cloudflare_session(conf, saved, ctx):
    """What every Cloudflare request of a plan carries. `saved` is the key that the owner saved for this account. When
    it makes tokens, the requests carry the door's work key and never that one; else they carry it, as before. No
    request of a plan goes out before the door knows what the saved key is and which one account it is for."""
    key = cloudflare_key(conf, saved, ctx)
    session = {"base": BASES["cloudflare"], "headers": {"Authorization": "Bearer " + saved},
               "fill": {"account_id": key["account_id"]}}
    if key["kind"] == "maker":
        if key["named"] and key["named"] != key["account_id"]:
            raise Stop("the door's file names another Cloudflare account than the one that this key makes tokens for")
        work = cloudflare_work_key(conf, saved, key["account_id"], ctx)
        session.update(headers={"Authorization": "Bearer " + work}, work=work, maker=saved)
    elif ctx.get("keep_work_key"):      # the key before made tokens, and this one makes none: its work key goes
        with ctx.get("key_lock") or contextlib.nullcontext():
            left = (ctx.get("work_key") or (lambda: None))()
            if isinstance(left, dict):
                # the saved key deletes it if it can, which a key that makes no tokens cannot: then its day ends it
                ended = cloudflare_end(saved, left.get("account_id"), left.get("id"), ctx)
                ctx["keep_work_key"](None)
                (ctx.get("said") or (lambda action, outcome, why: None))(
                    "key-end", "done", f"the saved key makes no tokens, so the work key of the key before left the "
                                       f"door" + ("" if 200 <= ended < 300 or ended == 404 else
                                                  ", and Cloudflare ends it within the day") +
                                       f" (token {left.get('id')})")
    return session


def key_mark(value):
    """The name by which the door knows one key's value in its own files, never the value: a new value under the same
    reference is another key."""
    return hashlib.sha256(b"door key\0" + value.encode()).hexdigest()


def cf_get(ctx, token, path):
    return ctx["http"]("GET", BASES["cloudflare"] + path, {"Authorization": "Bearer " + token}, None)


def cf_errors(answer):
    """Cloudflare's own words for a call that failed. Never the answer itself: a new token's answer is its value."""
    errors = answer.get("errors") if isinstance(answer, dict) else None
    said = "; ".join(str(e.get("message"))[:200] for e in errors if isinstance(e, dict) and e.get("message")) \
        if isinstance(errors, list) else ""
    return said[:300]


def cf_listed(what, status, answer):
    """The list that Cloudflare gave, or None for its clear no (the key may not read it: a 4xx that is no 401).
    Anything else stops the call: a time-out, a limit, a fault and a 401 say nothing about what a key is, and no key
    is taken for a kind that it may not be."""
    if status == 200 and isinstance(answer, dict) and answer.get("success") is not False and \
            isinstance(answer.get("result"), list):
        return answer["result"]
    if status == 401:
        # Cloudflare does not know the key (now): a new key gets this for a minute, also after its verify said
        # active, and a deleted key gets it for good. It is no "the key may not read this".
        raise Unsaid(f"Cloudflare does not take the door's key now (401, when the door asked {what}). A new key can "
                     f"need a minute: send the same call again. If it stays so, Cloudflare no longer takes the key, "
                     f"and the owner makes a new one")
    if 400 <= status < 500 and status not in (408, 425, 429):
        return None
    raise Unsaid(f"Cloudflare did not say {what} ({status}), so the door cannot tell what its key is: send the same "
                 f"call again")


def cf_active(what, status, answer):
    """True when Cloudflare's own verify says that a token is active, False for its clear no; a time-out, a limit or
    a fault stops the call. Here a 401 is a clear no: the verify of a user's token gives it to the token of an
    account, and each verify gives it to a token that Cloudflare does not take."""
    if status == 200 and isinstance(answer, dict) and isinstance(answer.get("result"), dict):
        return answer["result"].get("status") == "active"
    if 400 <= status < 500 and status not in (408, 425, 429):
        return False
    raise Unsaid(f"Cloudflare did not say {what} ({status}), so the door cannot tell what its key is: send the same "
                 f"call again")


def cloudflare_key(conf, saved, ctx):
    """What a saved Cloudflare key is: {"kind": "maker" for a key that makes tokens for one account, or "plain",
    "account_id": the one account that it is for}. The door asks Cloudflare once for each value and each account that
    its file names, and again after CF_KIND_LIFE, because a token's rights can change at Cloudflare while its value
    stays. It keeps the answer by the value's mark (ctx key_kind). When Cloudflare does not say at the later asking,
    the answer before stands, until it is two times CF_KIND_LIFE old."""
    mark, now = key_mark(saved), (ctx.get("now") or time.time)()
    # the account that the door's file names: never the door's own reading of the key before (Door.credential)
    named = conf.get("account_id") if isinstance(conf.get("account_id"), str) and \
        CF_ID.fullmatch(conf["account_id"]) and not conf.get("account_kept") else None
    known = (ctx.get("key_kind") or (lambda mark: None))(mark)
    known = known if isinstance(known, dict) and known.get("kind") in ("maker", "plain") and \
        CF_ID.fullmatch(str(known.get("account_id"))) and known.get("named") == named and \
        isinstance(known.get("at"), (int, float)) and not isinstance(known.get("at"), bool) else None
    if known and 0 <= now - known["at"] < CF_KIND_LIFE:
        return known
    try:
        key = dict(cloudflare_asked(saved, named, ctx), named=named, at=int(now))
    except Unsaid:
        if known and 0 <= now - known["at"] < 2 * CF_KIND_LIFE:
            return known
        raise
    if ctx.get("keep_key_kind"):
        ctx["keep_key_kind"](mark, key)
    if not named and ctx.get("account"):        # with the credential too: what a call makes is named by its account
        ctx["account"](key["account_id"])
    return key


def cloudflare_asked(saved, named, ctx):
    """cloudflare_key's questions to Cloudflare, with the saved key: {kind, account_id}, or a Stop.

    The accounts are the one that the door's file names and those that Cloudflare lists for the key (plan N1: a key
    card gives the door the key only). With none, or with more than CF_ACCOUNTS_ASKED, the call stops: a key of the
    door is for one business's account. Then the key must work: Cloudflare's verify takes it as a token of its user,
    or as the token of one of those accounts. Only a key that works is asked what it is, and only its answer is kept:
    a new key that Cloudflare does not know yet is no hand-made key.

    A key makes tokens when it lists permission groups, which Cloudflare gives only to a key with a right on API
    tokens. One that lists the groups of its user makes tokens in each account that its user reaches: refused. One
    that lists the groups of an account makes tokens there: it is for that one account, and for no other."""
    status, answer = cf_get(ctx, saved, "/accounts?per_page=50")
    ids = [a.get("id") if isinstance(a, dict) else None
           for a in cf_listed("which accounts its key reaches", status, answer) or []]
    if any(not isinstance(i, str) or not CF_ID.fullmatch(i) for i in ids):
        raise Stop("Cloudflare gave no account id that the door can use")
    asked = list(dict.fromkeys(([named] if named else []) + ids))
    if not asked:
        raise Stop(f"the token reaches no Cloudflare account that Cloudflare lists for it ({status}), so the door "
                   f"cannot tell what it is, and uses no key whose one account it does not know. A new key can need "
                   f"a minute: send the same call again. If it stays so, Cloudflare no longer takes the key, or the "
                   f"key may not read its account: a key that makes tokens needs Account Settings: Read beside "
                   f"Account API Tokens: Edit, and a hand-made key needs a right of its account")
    if len(asked) > CF_ACCOUNTS_ASKED:
        raise Stop(f"the token reaches more than {CF_ACCOUNTS_ASKED} Cloudflare accounts: a key of the door is for "
                   f"one account")
    user = cf_active("whether it takes its key", *cf_get(ctx, saved, "/user/tokens/verify"))
    if not user and not any(cf_active("whether it takes its key", *cf_get(ctx, saved, f"/accounts/{a}/tokens/verify"))
                            for a in asked):
        raise Stop("Cloudflare does not take the door's key, as a token of its user or of its account: a new key "
                   "can need a minute, so send the same call again. If it stays so, the owner makes a new key")
    if user and cf_listed("whether its key makes tokens for a user",
                          *cf_get(ctx, saved, "/user/tokens/permission_groups")):
        raise Stop("this Cloudflare key makes tokens for its user, in each account that the user reaches: the door "
                   "takes a key that makes tokens for one account (Manage Account, Account API Tokens)")
    makes = [a for a in asked if cf_listed("whether its key makes tokens",
                                           *cf_get(ctx, saved, f"/accounts/{a}/tokens/permission_groups"))]
    if makes and (len(makes) > 1 or len(ids) > 1):
        raise Stop("this Cloudflare key makes tokens and reaches more than one account: a key that makes tokens is "
                   "for one account")
    if not makes and not named and len(ids) > 1:
        raise Stop("the token reaches more than one Cloudflare account: a key of the door is for one account")
    return {"kind": "maker" if makes else "plain", "account_id": makes[0] if makes else named or ids[0]}


def cloudflare_work_key(conf, maker, account, ctx):
    """The door's work key of one Cloudflare account, from the key that makes tokens: the one that the door holds,
    while it has more than CF_KEY_FRESH left, the same key made it and the code's rights are the same; else a new one.
    A new key signs in before anything uses it, and only then the door keeps it and deletes the one before, so a new
    key that fails costs no key that works: while the one before still has a minute left, with the same rights and
    from the same key, the call goes with it. One call of an account at a time comes here (ctx key_lock)."""
    with ctx.get("key_lock") or contextlib.nullcontext():
        now = (ctx.get("now") or time.time)()
        mark = key_mark(maker)
        rights = hashlib.sha256(json.dumps([CF_KEY_RIGHTS, account]).encode()).hexdigest()[:16]
        held = (ctx.get("work_key") or (lambda: None))()
        held = held if isinstance(held, dict) else {}
        same = held.get("maker") == mark and held.get("rights") == rights and isinstance(held.get("value"), str) and \
            bool(held["value"]) and isinstance(held.get("until"), (int, float)) and \
            not isinstance(held.get("until"), bool)
        if same and held["until"] - now > CF_KEY_FRESH:
            return held["value"]
        said = ctx.get("said") or (lambda action, outcome, why: None)
        try:
            made = cloudflare_mint(maker, account, CF_KEY_NAME.format(target=f"cloudflare:{conf.get('owner')}"), ctx,
                                   now, held.get("groups") if held.get("account_id") == account else None)
            try:
                cloudflare_signs_in(made["value"], account, ctx)
                if ctx.get("keep_work_key"):
                    try:
                        ctx["keep_work_key"](dict(made, maker=mark, rights=rights, account_id=account,
                                                  secret=conf.get("secret"), value_mark=key_mark(made["value"])))
                    except OSError as e:
                        raise Stop(f"the door could not keep its new work key ({e.__class__.__name__}), and deleted "
                                   f"it") from None
            except Stop:
                cloudflare_end(maker, account, made["id"], ctx)
                raise
        except Stop as e:
            said("key-new", "failed", str(e))
            if same and held["until"] - now > 60:
                return held["value"]
            raise
        if isinstance(held.get("id"), str) and held["id"] != made["id"]:
            cloudflare_end(maker, held.get("account_id") or account, held["id"], ctx)
        ends = datetime.datetime.fromtimestamp(made["until"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        said("key-new", "done", f"a work key of {len(CF_KEY_RIGHTS)} rights for one Cloudflare account, which "
                                f"Cloudflare ends at {ends} (token {made['id']})")
        return made["value"]


def cloudflare_mint(maker, account, name, ctx, now, kept=None):
    """One new token of the account, made with the key that makes tokens: {id, value, until, groups}. Its rights are
    CF_KEY_RIGHTS, each taken from the account's own list by its exact name and scope, for this one account and its
    zones, and it ends CF_KEY_LIFE from now. Cloudflare's documents call a group's name subject to change: for a
    right whose name the list no longer has, the door takes the id that the same name gave it for the work key before
    (kept), and for a door that never had one, the call stops. The answer must show those rights and that account and
    nothing else: a key that shows anything else is deleted, and the call stops."""
    head = {"Authorization": "Bearer " + maker, "Content-Type": "application/json"}
    kept = kept if isinstance(kept, dict) else {}
    groups = {}
    for right, scope in CF_KEY_RIGHTS:
        # the list by the documented filters: the whole list has no documented page size
        status, answer = cf_get(ctx, maker, f"/accounts/{account}/tokens/permission_groups?" + urllib.parse.urlencode(
            {"name": right, "scope": CF_SCOPES[scope]}))
        listed = answer.get("result") if status == 200 and isinstance(answer, dict) else None
        if not isinstance(listed, list):
            raise Stop(f"Cloudflare no longer takes the key that makes tokens ({status}): the owner makes a new one, "
                       f"which request_secret asks for with this door name" if status == 401 else
                       f"Cloudflare gave the door no list of the account's permission groups ({status}): the key "
                       f"that makes tokens needs Account API Tokens: Edit")
        found = [g["id"] for g in listed if isinstance(g, dict) and g.get("name") == right and
                 isinstance(g.get("scopes"), list) and CF_SCOPES[scope] in g["scopes"] and
                 isinstance(g.get("id"), str) and CF_ID.fullmatch(g["id"])]
        if not found and isinstance(kept.get(right), str) and CF_ID.fullmatch(kept[right]):
            found = [kept[right]]
        if len(found) != 1:
            raise Stop(f"Cloudflare lists {'no' if not found else 'more than one'} permission group {right!r} for "
                       f"{'a zone' if scope == 'zone' else 'an account'}: the door makes no key whose rights it cannot "
                       f"name")
        groups[right] = found[0]
    want = {scope: [groups[right] for right, s in CF_KEY_RIGHTS if s == scope] for scope in CF_SCOPES}
    resource = f"com.cloudflare.api.account.{account}"
    until = round(now) + CF_KEY_LIFE
    body = {"name": name[:120],
            "expires_on": datetime.datetime.fromtimestamp(until, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policies": [{"effect": "allow", "resources": {resource: "*"},
                          "permission_groups": [{"id": i} for i in want["account"]]},
                         {"effect": "allow", "resources": {resource: {"com.cloudflare.api.account.zone.*": "*"}},
                          "permission_groups": [{"id": i} for i in want["zone"]]}]}
    status, answer = ctx["http"]("POST", f"{BASES['cloudflare']}/accounts/{account}/tokens", head,
                                 json.dumps(body).encode())
    made = answer.get("result") if status == 200 and isinstance(answer, dict) else None
    new = made.get("id") if isinstance(made, dict) and isinstance(made.get("id"), str) and \
        CF_ID.fullmatch(made["id"]) else None
    if new is None or not isinstance(made.get("value"), str) or not 20 <= len(made["value"]) <= 400:
        if new:
            cloudflare_end(maker, account, new, ctx)
        raise Stop(f"Cloudflare made the door no work key ({status}): {cf_errors(answer) or 'no id and value'}")
    # Whatever stands under the account's own key is inside that account, so the answer's resources are read by
    # their key alone, and the answer's rights one by one.
    asked, policies = set(groups.values()), made.get("policies")
    shown = isinstance(policies, list) and bool(policies) and all(
        isinstance(p, dict) and p.get("effect") == "allow" and isinstance(p.get("resources"), dict) and
        set(p["resources"]) == {resource} and isinstance(p.get("permission_groups"), list) and
        all(isinstance(g, dict) and isinstance(g.get("id"), str) for g in p["permission_groups"]) for p in policies)
    if not shown or {g["id"] for p in policies for g in p["permission_groups"]} != asked:
        cloudflare_end(maker, account, new, ctx)
        raise Stop("Cloudflare's answer does not show the rights and the one account that the door asked for: the "
                   "door deleted the new key, and no call uses a key that it could not check")
    return {"id": new, "value": made["value"], "until": until, "groups": groups}


def cloudflare_signs_in(value, account, ctx):
    """A work key that the door just made signs in, before anything uses it and before the door keeps it."""
    status = None
    for attempt in range(CF_KEY_TRIES):
        if attempt:
            (ctx.get("sleep") or time.sleep)(CF_KEY_PAUSE)
        status, answer = cf_get(ctx, value, f"/accounts/{account}/tokens/verify")
        result = answer.get("result") if isinstance(answer, dict) else None
        if status == 200 and isinstance(result, dict) and result.get("status") == "active":
            return
    raise Stop(f"the new work key does not sign in at Cloudflare ({status}): the door deleted it")


def cloudflare_end(maker, account, token_id, ctx):
    """Delete one token that the door made, with the key that makes tokens: the status of Cloudflare's answer. A key
    that the door could not delete ends by itself, CF_KEY_LIFE after it was made."""
    if not isinstance(token_id, str) or not CF_ID.fullmatch(token_id) or not CF_ID.fullmatch(str(account)):
        return 400
    status, _ = ctx["http"]("DELETE", f"{BASES['cloudflare']}/accounts/{account}/tokens/{token_id}",
                            {"Authorization": "Bearer " + maker}, None)
    return status


def cloudflare_refused(session, status, answer, ctx):
    """The Stop for a step that Cloudflare refused (401 or 403) with the door's work key. A work key that Cloudflare
    no longer takes (somebody deleted it there) is deleted at Cloudflare, and leaves the door only when that delete
    says that it is gone: then the next call makes a new one, and no refused call leaves a live token behind. A key
    that the door made less than CF_KEY_SETTLE ago stays: Cloudflare can need a minute for a new token. For
    a key that is active, the words name its rights: a call outside them is what Cloudflare refused, and no wider key
    of the owner's is the answer to that."""
    work, account = session["work"], session["fill"]["account_id"]
    try:
        active = cf_active("whether it takes the door's work key",
                           *cf_get(ctx, work, f"/accounts/{account}/tokens/verify"))
    except Stop:
        active = None
    if active is False:
        with ctx.get("key_lock") or contextlib.nullcontext():
            held = (ctx.get("work_key") or (lambda: None))()
            if isinstance(held, dict) and held.get("value") == work and ctx.get("keep_work_key"):
                made = held.get("at")
                if isinstance(made, (int, float)) and (ctx.get("now") or time.time)() - made < CF_KEY_SETTLE:
                    return Stop(f"Cloudflare does not take the door's new work key yet ({status}): send the same "
                                f"call again in a minute")
                ended = cloudflare_end(session["maker"], account, held.get("id"), ctx)
                if not (200 <= ended < 300 or ended == 404):    # it may be live: the door makes no key beside it
                    return Stop(f"Cloudflare does not take the door's work key ({status}), and the door could not "
                                f"delete it there now ({ended}): send the same call again")
                ctx["keep_work_key"](None)
                (ctx.get("said") or (lambda action, outcome, why: None))(
                    "key-end", "done", f"Cloudflare no longer takes the work key, so it left the door (token "
                                       f"{held.get('id')}): the next call makes a new one")
        return Stop(f"Cloudflare no longer takes the door's work key ({status}): the door makes a new one, so send "
                    f"the same call again")
    return Stop(f"cloudflare answered {status}: {short(answer)}. The door's work key for this account holds these "
                f"rights and no other: {', '.join(right for right, _ in CF_KEY_RIGHTS)}. A call outside them is not "
                f"the door's to make")


def send(provider, s, path, session, ctx, kept, plan):
    headers = dict(session["headers"])
    query = dict(session.get("query") or {}, **(s.get("query") or {}))
    body = s.get("body")
    if provider == "backblaze":
        body = json.loads(json.dumps(body).replace("{account_id}", session["fill"]["account_id"]))
        url = session["base"] + path
    else:
        url = session["base"] + path
    if s.get("need") == "new_hostname":        # Cloudflare: the tunnel's ingress with one new hostname before the end
        ingress = ((kept.get("ingress") or {}).get("result") or {}).get("config", {}).get("ingress") or []
        add = body["add"]
        if any(rule.get("hostname") == add["hostname"] for rule in ingress):
            raise Stop("that hostname is in the tunnel already: a change of it goes through change")
        body = {"config": dict(((kept.get("ingress") or {}).get("result") or {}).get("config") or {},
                               ingress=[r for r in ingress if r.get("hostname")] + [add] +
                               [r for r in ingress if not r.get("hostname")] or [add, {"service": "http_status:404"}])}
    if s.get("need") == "server_path" and not re.match(rf"/servers/{kept.get('server_id')}(/|$)", path) and \
            not path.startswith("/firewalls/"):
        raise Stop("that path is not the named server's")
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    return ctx["http"](s["method"], url, headers, data)


# New-projects plan N2 (the owner's "Yes, as written", 6 November 2026): every token of the door asks for its
# permissions by name. Its own work needs these: its commits and pull requests, the runs and dispatches of workflows,
# the secrets that it sets to a key it rotated, and its reads of runners (Administration at read) and of alerts.
# Administration at write goes only into a token of its own for one call (repo-new, repo-delete, a runner's
# registration), which the door never keeps. GitHub refuses a token that asks for more than the installation holds, so
# a token asks for each of these only as far as the installation holds it.
DOOR_PERMISSIONS = {"metadata": "read", "contents": "write", "pull_requests": "write", "actions": "write",
                    "workflows": "write", "administration": "read", "security_events": "read",
                    "vulnerability_alerts": "read", "secret_scanning_alerts": "read", "secrets": "write"}


def named_permissions(want, held):
    """want, as far as the installation holds it: a permission that it lacks is left out, and one that it holds at
    read only is asked at read. An installation that names no permissions gets want as it is."""
    if not isinstance(held, dict):
        return dict(want)
    out = {}
    for name, level in want.items():
        has = held.get(name)
        if has in ("write", "admin") or (has == "read" and level == "read"):
            out[name] = level
        elif has == "read":
            out[name] = "read"
    return out


def github_token(conf, ctx, repo, permissions=None):
    """An installation token of the door's App for this owner, from the App's key, signed by openssl, with its
    permissions by name (plan N2). The App's installation is the one of the call's repository, which GitHub gives for a
    personal account and an organization alike (plan N1), as for the hub's tokens (door.py, github_tokens)."""
    jwt = app_jwt(conf["app_id"], ctx["secret"](conf["secret"]), ctx.get("sign"))
    status, answer = ctx["http"]("GET", f"{BASES['github']}/repos/{repo}/installation",
                                 {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json"}, None)
    if status != 200:
        raise Stop(f"GitHub gave no installation of the door's App ({status})")
    asked = named_permissions(permissions or DOOR_PERMISSIONS, answer.get("permissions"))
    short = sorted(name for name, level in (permissions or {}).items() if asked.get(name) != level)
    if short:                       # a one-call token needs each of its permissions as it asks them
        raise Stop(permission_pages(answer, short))
    status, answer = ctx["http"]("POST", f"{BASES['github']}/app/installations/{answer['id']}/access_tokens",
                                 {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json",
                                  "Content-Type": "application/json"}, json.dumps({"permissions": asked}).encode())
    if status != 201:
        raise Stop(f"GitHub gave the door no token ({status})")
    return answer["token"]


def permission_pages(installation, short):
    """The words of a one-call token that the installation cannot give (plan N2): what it lacks, and GitHub's two
    pages where the owner gives it, the App's permissions and the installation's acceptance. GitHub has no API that
    changes an App's permissions, so the Operator reports it and the manager raises one Needs-you item with both."""
    account = installation.get("account") if isinstance(installation.get("account"), dict) else {}
    login, slug, iid = account.get("login"), installation.get("app_slug"), installation.get("id")
    words = f"the App's installation does not hold {', '.join(short)} as this call needs"
    if not (isinstance(login, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", login) and isinstance(slug, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", slug) and isinstance(iid, int)):
        return words + ": the owner gives it on the App's page on GitHub, and then accepts it on its installation"
    org = account.get("type") == "Organization"
    where = f"organizations/{login}/settings" if org else "settings"
    return (f"{words}. The owner gives it on GitHub's two pages: the App's permissions, "
            f"https://github.com/{where}/apps/{slug}/permissions, and then the installation's acceptance, "
            f"https://github.com/{where}/installations/{iid}")


def app_pem(value):
    """The PEM of a GitHub App key, as the door holds it: the app gives the central vault "pem:" and the PEM in
    standard base64, on one line, because a vault fingerprints only a value with no white space and the central vault
    takes no value without a fingerprint. A value that is a PEM already stays as it is."""
    if isinstance(value, str) and value.startswith("pem:"):
        try:
            return base64.b64decode(value[4:], validate=True).decode()
        except ValueError:
            raise Stop("the door's App key is not one PEM in base64") from None
    return value


def app_jwt(app_id, key_pem, sign=None):
    key_pem = app_pem(key_pem)

    def part(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    t0 = int(time.time())
    signed = part(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + "." + \
        part(json.dumps({"iat": t0 - 60, "exp": t0 + 540, "iss": int(app_id)}).encode())
    if sign is None:
        def sign(text, pem):
            import tempfile
            with tempfile.NamedTemporaryFile("w", delete=True) as f:
                f.write(pem)
                f.flush()
                r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", f.name], input=text.encode(),
                                   capture_output=True, timeout=20)
            if r.returncode != 0:
                raise Stop("openssl could not sign with the door's App key")
            return r.stdout
    return signed + "." + part(sign(signed, key_pem))


def one_call(conf, ctx, via, permissions, repositories=None):
    """(installation, token) of a token for one call (plan N2), with exactly these permissions, which the door never
    keeps; GitHub's two pages when the installation does not hold them. The installation is that of `via`."""
    jwt = app_jwt(conf["app_id"], ctx["secret"](conf["secret"]), ctx.get("sign"))
    head = {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json"}
    status, inst = ctx["http"]("GET", f"{BASES['github']}/repos/{via}/installation", head, None)
    if status != 200 or not isinstance(inst, dict):
        raise Stop(f"GitHub gave no installation of the door's App ({status})")
    asked = named_permissions(permissions, inst.get("permissions"))
    short = sorted(name for name, level in permissions.items() if asked.get(name) != level)
    if short:
        raise Stop(permission_pages(inst, short))
    body = {"permissions": permissions}
    if repositories:
        body["repositories"] = repositories
    status, got = ctx["http"]("POST", f"{BASES['github']}/app/installations/{inst['id']}/access_tokens",
                              dict(head, **{"Content-Type": "application/json"}), json.dumps(body).encode())
    if status != 201 or not isinstance(got, dict) or not isinstance(got.get("token"), str):
        raise Stop(f"GitHub gave the door no token for this call ({status})")
    return inst, got["token"]


def gh(ctx, token, method, path, body=None):
    return ctx["http"](method, f"{BASES['github']}{path}", {"Authorization": "Bearer " + token,
                                                           "Accept": "application/vnd.github+json",
                                                           "X-GitHub-Api-Version": "2022-11-28",
                                                           **({"Content-Type": "application/json"} if body else {})},
                       json.dumps(body).encode() if body is not None else None)


def repo_new(plan, ctx):
    """New-projects plan N3: one private repository with a first commit, in the account of the door's App, with a
    token of its own for this call. The door's record keeps the call pending before it is sent and, once GitHub
    answers, the repository by its id with the agent and the app (ctx["repos"]). A retry finds a repository of that
    name: it completes the record only when the App reads it, its one commit is the App's and GitHub made it within a
    minute of the pending record, and refuses otherwise. A repository that the record shows made for this agent, by
    its id, gets the App's reach check again: a retry after that check failed finishes there."""
    conf, want = ctx["credentials"], plan["repo_new"]
    full, agent, record = want["name"], want["agent"], ctx["repos"]
    owner, app = full.split("/", 1)
    inst, token = one_call(conf, ctx, plan["repo"], REPO_NEW)
    status, there = gh(ctx, token, "GET", f"/repos/{full}")
    if status == 200:
        known = record("made", full)
        if isinstance(there, dict) and known and known.get("agent") == agent and known.get("id") == there.get("id"):
            return app_reaches(conf, ctx, plan["repo"], full)
        pending = record("pending", full)
        made = isinstance(there, dict) and pending and pending.get("agent") == agent and \
            created_within(there.get("created_at"), pending.get("at"), 60) and app_commit_only(ctx, token, full, inst)
        if not made:
            raise Stop(f"{full} exists, and the door's record does not show that the door made it for this agent")
        record("made", full, id=there["id"], agent=agent, app=app)
        return f"{full} was made by the door for {agent}, and the record now says so"
    if status != 404:
        raise Stop(f"GitHub did not say whether {full} exists ({status})")
    record("pending", full, agent=agent, app=app)
    org = ((inst.get("account") or {}).get("type") == "Organization")
    status, answer = gh(ctx, token, "POST", f"/orgs/{owner}/repos" if org else "/user/repos",
                        {"name": app, "private": True, "auto_init": True,
                         "description": f"made by the door for {agent}"})
    if status != 201 or not isinstance(answer, dict) or answer.get("full_name", "").lower() != full.lower():
        raise Stop(f"GitHub made no repository {full} ({status}): {short(answer, 300)}")
    record("made", full, id=answer.get("id"), agent=agent, app=app)
    return app_reaches(conf, ctx, plan["repo"], full)


def app_reaches(conf, ctx, via, full):
    """The App's installation reaches a repository that the door made, or the call stops with GitHub's answer."""
    status, _ = gh(ctx, one_call(conf, ctx, via, {"metadata": "read"})[1], "GET", f"/repos/{full}")
    if status != 200:
        raise Stop(f"GitHub made {full}, and the App's installation does not reach it ({status}): the new-projects plan "
                   f"stops here and goes back to the owner with this answer")
    return f"made {full}: private, with its first commit, and the App reaches it"


def created_within(created, at, seconds):
    try:
        made = datetime.datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return False
    return isinstance(at, (int, float)) and abs(made.timestamp() - at) <= seconds


def app_commit_only(ctx, token, full, inst):
    """True when the repository has one commit, and the App's own bot made it (GitHub's first commit)."""
    status, commits = gh(ctx, token, "GET", f"/repos/{full}/commits?per_page=2")
    bot = f"{inst.get('app_slug')}[bot]"
    return status == 200 and isinstance(commits, list) and len(commits) == 1 and \
        ((commits[0].get("author") or {}).get("login") == bot or (commits[0].get("committer") or {}).get("login") == bot)


def repo_delete(plan, ctx):
    """New-projects plan N3: delete a repository that the door made, which has no runner, with a token of its own for
    that one repository (plan N2)."""
    conf, want = ctx["credentials"], plan["repo_delete"]
    full = want["name"]
    _, token = one_call(conf, ctx, full, REPO_DELETE, repositories=[full.split("/", 1)[1]])
    status, answer = gh(ctx, token, "GET", f"/repos/{full}")
    if status != 200 or not isinstance(answer, dict) or answer.get("id") != want.get("id"):
        raise Stop(f"{full} is not the repository that the door made ({status})")
    status, runners = gh(ctx, token, "GET", f"/repos/{full}/actions/runners")
    if status != 200 or not isinstance(runners, dict) or runners.get("total_count") != 0:
        raise Stop(f"{full} has a runner, or GitHub did not say ({status}): the door deletes it only with none")
    status, answer = gh(ctx, token, "DELETE", f"/repos/{full}")
    if status != 204:
        raise Stop(f"GitHub did not delete {full} ({status}): {short(answer, 300)}")
    ctx["repos"]("deleted", full)
    return f"deleted {full}, which the door made"


def github_secret(plan, ctx):
    """A secret of a repository, set to the value of a key that the door rotated, with gh's own sealing. The value
    goes on gh's stdin and never into an argument or an answer."""
    s = plan["secret"]
    token = github_token(ctx["credentials"], ctx, s["repo"])
    value = minted_part(ctx, s["key"], s["part"])
    status, out = ctx["run"](["gh", "secret", "set", s["name"], "--repo", s["repo"]], value.encode(),
                             {"GH_TOKEN": token})
    if status != 0:
        raise Stop(f"gh could not set {s['name']}: {out[-300:]}")
    return f"{s['name']} of {s['repo']} has the rotated value"


def minted_part(ctx, key_id, part):
    """One part of a key that the door minted: its id, or the key itself."""
    minted_id, _, key = ctx["minted_secret"](key_id).partition(":")
    return minted_id if part == "id" else key


def key_works(answer, ctx):
    """A Backblaze key that the door just minted signs in, before anything uses it. One that does not is kept, so
    that key-revoke can end it."""
    status, _ = ctx["http"]("GET", B2_AUTHORIZE, {"Authorization": "Basic " + base64.b64encode(
        f"{answer.get('applicationKeyId')}:{answer.get('applicationKey')}".encode()).decode()}, None)
    if status != 200:
        raise Stop(f"the new key {answer.get('applicationKeyId')} does not sign in ({status}): end it with key-revoke")


def azure_setting(plan, ctx):
    """One App Service setting: the site's settings are read, one changed, and written back whole."""
    s, conf = plan["app_setting"], ctx["credentials"]
    session = open_session("azure", conf, ctx)
    q = "?" + urllib.parse.urlencode(session["query"])
    status, answer = ctx["http"]("POST", f"{session['base']}{s['site']}/config/appsettings/list{q}",
                                 session["headers"], None)
    if status != 200:
        raise Stop(f"Azure answered {status}")
    props = dict(answer.get("properties") or {}, **{s["name"]: s["value"]})
    status, answer = ctx["http"]("PUT", f"{session['base']}{s['site']}/config/appsettings{q}",
                                 dict(session["headers"], **{"Content-Type": "application/json"}),
                                 json.dumps({"properties": props}).encode())
    if status >= 400:
        raise Stop(f"Azure answered {status}")
    return f"{s['name']} is set on {s['site'].rsplit('/', 1)[-1]}"


def place(plan, ctx):
    """Each part of a minted key where its old value is, through the host's ops-root, which finds that line by the
    old value's hash. The new value goes on stdin only."""
    minted = ctx["minted_secret"](plan["key"])
    key_id, _, key = minted.partition(":")
    said = []
    for p in plan["place"]:
        value = key_id if p["part"] == "id" else key
        status, out = ctx["host"](p["host"], "place", [p["file"], p["name"], p["old"]], value.encode())
        if status != 0:
            raise Stop(f"{p['name']} in {p['file']} on {p['host']}: {out.strip()[-300:]}")
        said.append(out.strip())
    return "\n".join(said)


# ---- AWS: the role's session, and signature version 4

def aws_session(conf, ctx):
    """(key id, key, session token) of the role that this account names: STS AssumeRoleWithWebIdentity with the
    JWT-SVID that the door's own bot writes. The session lasts an hour and stays in the door's memory only; a new one
    comes five minutes before it ends."""
    role = conf.get("role", "")
    cache = ctx.get("aws_sessions")
    held = (cache or {}).get(role)
    if held and held[3] - time.time() > 300:
        return held[:3]
    region = conf.get("region", "us-east-1")
    body = urllib.parse.urlencode({"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15", "RoleArn": role,
                                   "RoleSessionName": "fleet-door", "WebIdentityToken": ctx["aws_token"]()}).encode()
    status, answer = ctx["http"]("POST", f"https://sts.{region}.amazonaws.com/",
                                 {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, body)
    text = answer if isinstance(answer, str) else json.dumps(answer)
    got = {k: re.search(f"<{k}>([^<]+)</{k}>", text) for k in ("AccessKeyId", "SecretAccessKey", "SessionToken",
                                                                 "Expiration", "Code", "Message")}
    if status != 200 or not all(got[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")):
        said = ": ".join(got[k].group(1)[:200] for k in ("Code", "Message") if got[k])
        raise Stop(f"AWS STS gave the door no session of {role} ({status}{', ' + said if said else ''})")
    ends = datetime.datetime.strptime(got["Expiration"].group(1)[:19], "%Y-%m-%dT%H:%M:%S")
    held = tuple(got[k].group(1) for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")) + \
        (ends.replace(tzinfo=datetime.timezone.utc).timestamp(),)
    if cache is not None:
        cache[role] = held
    return held[:3]


def aws_sign(method, host, path, query, headers, body, service, region, session, now=None):
    """The headers of one request, signed with SigV4 by the role's session, its token among the signed headers."""
    key_id, key, token = session
    t = now or datetime.datetime.now(datetime.timezone.utc)
    amz, day = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
    headers = dict(headers, **{"Host": host, "X-Amz-Date": amz, "X-Amz-Security-Token": token})
    lines = sorted((name.lower(), str(value).strip()) for name, value in headers.items())
    signed = ";".join(name for name, _ in lines)
    canonical = "\n".join([method, path, query, "".join(f"{n}:{v}\n" for n, v in lines), signed,
                           hashlib.sha256(body).hexdigest()])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = hmac.new(("AWS4" + key).encode(), day.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed}, " \
                               f"Signature={hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()}"
    return headers


def aws_call(s, conf, ctx, now=None):
    """One call of a plan's step, in its service's protocol: a query API (the answer is XML, which the door gives on
    as text, and the conditions read it as text too), a JSON API, or a REST API with a path."""
    service, action = s["aws"]
    protocol, host, version = AWS_SERVICES[service]
    region = "us-east-1" if service == "iam" else s.get("region") or conf.get("region", "us-east-1")
    host = host.format(region=region)
    method, path, query, params = s.get("method", "POST"), "/", "", s.get("params")
    if protocol == "query":
        body = urllib.parse.urlencode(sorted(dict(params or {}, Action=action, Version=version).items())).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    elif protocol == "json":
        body, headers = json.dumps(params or {}).encode(), {"Content-Type": "application/x-amz-json-1.1",
                                                            "X-Amz-Target": f"{version}.{action}"}
    else:
        path, _, query = s["path"].partition("?")
        query = "&".join(sorted(query.split("&"))) if query else ""
        body = b"" if params is None else json.dumps(params).encode()
        headers = {"Content-Type": "application/json"} if params is not None else {}
    headers = aws_sign(method, host, path, query, headers, body, service, region, aws_session(conf, ctx), now)
    status, answer = ctx["http"](method, f"https://{host}{path}" + (f"?{query}" if query else ""), headers,
                                 body if method != "GET" else None)
    text = answer if isinstance(answer, str) else json.dumps(answer)
    if action == "DescribeInstances" and status == 200:
        return status, {"tagged": "<instanceId>" in text, "text": text}
    if action == "GetAccessKeyLastUsed" and status == 200:
        return status, {"AccessKeyLastUsed": {"LastUsedDate": "<LastUsedDate>" in text or None}}
    return status, text


def http(method, url, headers, data, timeout=30):
    """The door's own HTTPS call: (status, the answer as JSON, or text when it is not JSON)."""
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers, **{"User-Agent": "fleet-door"}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status = r.read(4 * 1024 * 1024), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(64 * 1024), e.code
    except (urllib.error.URLError, OSError) as e:
        return 599, f"cannot reach {urllib.parse.urlsplit(url).hostname}: {e}"
    try:
        return status, json.loads(raw or b"{}")
    except ValueError:
        return status, raw.decode("utf-8", "replace")
