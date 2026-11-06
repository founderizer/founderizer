"""The door's provider targets (DevOps plan, section 2 and step C6), in the plan's order: Backblaze, Cloudflare,
GitHub, Hetzner, then AWS, Azure and Tailscale. Standard library only.

Each provider has its listed reads (no path on the list returns a token), its rule calls, which code passes, and its
judged calls; anything else is refused. decide() turns one call into a plan of steps, and execute() runs a plan with
the token that the door holds for that account. A token never leaves the door: no answer carries one, and a key that
the door mints stays on the door until it places it on a host itself, through that host's ops-root (`place`), where
the old value is, found by its hash. An AWS account holds no key at all: the door assumes that account's role with
its own bot's web identity token.

    ops backblaze:<account> buckets | keys | files <bucket-id> [prefix]
    ops backblaze:<account> key-mint <host> <bucket-id>            rule: a key for one host, its name as the prefix,
                                                                   no delete right
    ops backblaze:<account> key-place <host> <file> <key-id> <NAME>=id:<sha256> <NAME>=key:<sha256>
    ops backblaze:<account> key-revoke <key-id>                    rule for a key that the door minted, else the
                                                                   owner's (a delete of what no agent made)
    ops backblaze:<account> change <b2 call>                       judged (D25), its body as content
    ops cloudflare:<account> zones | records <zone> | tunnels | rulesets <zone>
    ops cloudflare:<account> cname <zone> <name> <tunnel-id>       rule: a new CNAME to a tunnel of that account
    ops cloudflare:<account> tunnel-route <tunnel-id> <hostname> <port>   rule: a new hostname, the host's own origin
    ops cloudflare:<account> purge <zone> <host or url> ...        rule
    ops cloudflare:<account> change <METHOD> <path>                judged (D25), its body as content
    ops github:<owner> runs|failed|alerts|code-alerts|secret-alerts|runners <repo>
    ops github:<owner> workflow <repo> <workflow> [name=value ...] rule for a health workflow, judged for bootstrap
    ops github:<owner> secret <repo> <NAME> <key-id> id|key        rule: a value that the door rotated
    ops github:<owner> pull-request <repo> <head> <base> <title>   rule
    ops hetzner:<project> servers | server <name> | firewalls | volumes | ips
    ops hetzner:<project> power-cycle <server>                     rule, for a server that the agent holds
    ops hetzner:<project> change <METHOD> <path> <server>          judged: a held server's firewall, protection, name
    ops hetzner:<project> change <METHOD> <path>                   judged (D25)
    ops aws:<account> instances | groups | stacks | identity
    ops aws:<account> start|stop|reboot <instance-id>              rule, for a tagged instance
    ops aws:<account> ingress|change-set|key-off ...               judged
    ops aws:<account> eks-allowlist <cluster> <ipv4-range> ...     judged: the EKS public endpoint's new list
    ops aws:<account> call <service> <Action> [<region>]           judged: any other call inside the role's rights,
                                                                   its parameters as JSON content
    ops aws:<account> call eks <METHOD> <path> [<region>]          judged, the same for a REST API
    ops azure:<subscription> get <path>                            listed reads and metrics
    ops azure:<subscription> sql-firewall|app-setting ...          judged
    ops azure:<subscription> change <METHOD> <path> <api-version>  judged (D25)
    ops tailscale:<tailnet> devices | device <id>
    ops tailscale:<tailnet> key-expiry-off <id> | rename <id> <name>   rule, for a device of the fleet
    ops tailscale:<tailnet> delete <id> | oauth-client <tag>       judged
    ops tailscale:<tailnet> change <METHOD> <path>                 judged (D25)

A judged delete passes to the judge only when the door's own record shows that an agent made its target through the
door (made_keys, deletes); any other delete goes to the owner as a Needs-you item with the exact call.
"""
import base64
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


def read_plan(provider, account, steps, why):
    return Decision("read", why, target=f"{provider}:{account}", write=False,
                    plan={"provider": provider, "account": account, "steps": steps})


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
        return Decision("rule" if mine else "judged", "a key that the door minted" if mine else
                        "revoking a key that the door did not mint", target=f"backblaze:{account}",
                        plan={"provider": "backblaze", "account": account,
                              "steps": [step("POST", "b2_delete_key", {"applicationKeyId": args[0]},
                                             keep="revoked")]})
    if op == "key-place":
        return key_place(access, agent, "backblaze", account, args, lookups)
    if op == "change":                            # D25: a write of the key's own rights, judged
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
        return Decision("judged", f"a call of {name} inside the key's rights", target=f"backblaze:{account}",
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
        if args[2] in (account_of(access, "cloudflare", account).get("judged_tunnels") or []):
            return refused("that tunnel's names are judged: use change")
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
        if args[0] in (account_of(access, "cloudflare", account).get("judged_tunnels") or []):
            return refused("that tunnel is judged: use change")
        return Decision("rule", "a new tunnel hostname with the host's own origin", target=f"cloudflare:{account}",
                        plan={"provider": "cloudflare", "account": account, "steps": [
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
        return judged_write("cloudflare", account, args, content, CF_PATH, CF_NEVER,
                            lambda method, path: f"a change of {path.split('/')[3] if path.count('/') > 2 else path}",
                            check=lambda body: "a tunnel to ssh://, tcp://, rdp://, smb:// or a socket is never the door's"
                            if re.search(r'"service"\s*:\s*"(ssh|tcp|rdp|smb|unix|unix\+tls)://', json.dumps(body or {}))
                            else None)
    return refused(f"{op} is not listed for Cloudflare")


# The owner, 6 November 2026 (DevOps D25: "Yes, as for AWS"): for every provider account, a write that is not listed
# goes to the judge inside the key's own rights, as AWS's `call` does; the judge refuses what spends money, deletes what
# no agent made, gives a person access or weakens a control, and such a call comes to the owner as a Needs-you item
# with the exact call, which his signed yes lets through once. An unlisted read stays refused, so that no read returns
# a key, and a write whose answer is a secret is never sent: the door gives the agent the provider's answer.
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
CF_PATH = re.compile(r"/(zones|accounts)/([0-9a-f]{32}|\{account_id\})(/[A-Za-z0-9._~:@-]+){1,10}")
CF_NEVER = ((r"/tokens(/|$)", "an API token's answer is its secret: never the door's"),
            (r"/cfd_tunnel/[^/]+/token$", "a tunnel's token is a secret: never the door's"),
            (r"^POST \S*/(cfd_tunnel|warp_connector)$", "a new tunnel's answer carries its token: never the door's"),
            (r"/(stream|images/v1)/keys(/|$)", "a signing key's answer is its private part: never the door's"),
            (r"/temp-access-credentials", "R2 credentials are secrets: never the door's"),
            (r"/service_tokens", "a service token's answer is its secret: never the door's"))


def judged_write(provider, account, args, content, path, never, why, host=None, first=(), methods=WRITE_METHODS,
                 query=None, check=None):
    """D25's form `change <METHOD> <path>`, with the body as content: one write of the key's own rights, judged. A read
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
    return Decision("judged", why(method, where), target=f"{provider}:{account}", host=host,
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
        return read_plan("github", owner, [step("GET", reads[op], query=query)], "a listed read")
    if op == "jobs" and len(args) == 2 and args[1].isdigit():
        return read_plan("github", owner, [step("GET", f"/repos/{full}/actions/runs/{args[1]}/jobs")],
                         "a listed read")
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
            "judged" if args[1] in (lists.get("bootstrap") or []) else None
        if kind is None:
            return refused(f"{args[1]} is not a listed workflow of {full}")
        ref = lists.get("ref") or (lookups.get("default_branch") or (lambda name: None))(full)
        if not ref:
            return refused(f"the door could not read the default branch of {full}")
        return Decision(kind, f"a {'health' if kind == 'rule' else 'bootstrap'} workflow", target=f"github:{owner}",
                        plan={"provider": "github", "account": owner, "steps": [
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
                        plan={"provider": "github", "account": owner, "steps": [
                            step("POST", f"/repos/{full}/pulls", {"head": args[1], "base": args[2],
                                                                   "title": " ".join(args[3:])[:200]})]})
    return refused(f"{op} is not listed for GitHub")


# ---------------------------------------------------------------- Hetzner Cloud

HZ_JUDGED = (r"/firewalls/[0-9]{1,12}/actions/(set_rules|apply_to_resources|remove_from_resources)",
             r"/servers/[0-9]{1,12}/actions/change_protection", r"/servers/[0-9]{1,12}")


def hetzner(access, agent, project, op, args, content, lookups):
    reads = {"servers": "/servers", "firewalls": "/firewalls", "volumes": "/volumes", "ips": "/primary_ips"}
    if op in reads and not args:
        return read_plan("hetzner", project, [step("GET", reads[op], query={"per_page": "50"})], "a listed read")
    if op == "server" and len(args) == 1 and NAME.fullmatch(args[0]):
        return read_plan("hetzner", project, [step("GET", "/servers", query={"name": args[0]})], "a listed read")
    if op == "power-cycle":
        if len(args) != 1 or args[0] not in held_servers(access, agent):
            return refused("power-cycle takes a server that this agent holds")
        return Decision("rule", "a power cycle of a server that the agent holds", target=f"hetzner:{project}",
                        host=args[0], reboot=True, window="reboot",
                        plan={"provider": "hetzner", "account": project, "steps": [
                            step("GET", "/servers", query={"name": args[0]}, keep="server_id", need="one_server"),
                            step("POST", "/servers/{server_id}/actions/reset")]})
    if op == "change" and len(args) == 3:
        if args[0] not in ("POST", "PUT") or args[2] not in held_servers(access, agent):
            return refused("change takes the method, the path and the server it is for, which this agent holds")
        if "rescue" in args[1]:
            return refused("Rescue is never booted")
        if not any(re.fullmatch(p, args[1]) for p in HZ_JUDGED):
            return refused(f"{args[1]} is not a firewall, protection or name change")
        body = json_body(content)
        if body is False:
            return refused("the body is JSON of at most 64 KiB")
        return Decision("judged", "a firewall, protection or name of a held server", target=f"hetzner:{project}",
                        host=args[2], plan={"provider": "hetzner", "account": project, "steps": [
                            step("GET", "/servers", query={"name": args[2]}, keep="server_id", need="one_server"),
                            step(args[0], args[1], body, need="server_path")]})
    if op == "change" and len(args) == 2:         # D25: a write of the project's own rights, judged
        server_made = args[0] == "POST" and args[1] == "/servers"
        return judged_write("hetzner", project, args, content, HZ_PATH, HZ_NEVER,
                            lambda method, path: f"a change of {path.split('/')[1]}", methods=("POST", "PUT", "DELETE"),
                            check=lambda body: "a server with no SSH key gives its root password in the answer: name an "
                            "SSH key" if server_made and not (body or {}).get("ssh_keys") else None)
    return refused(f"{op} is not listed for Hetzner")


HZ_PATH = re.compile(r"/(servers|firewalls|volumes|primary_ips|floating_ips|networks|load_balancers|certificates|"
                     r"ssh_keys|placement_groups|images)(/[0-9]{1,12})?(/actions/[a-z_]{2,40})?")
HZ_NEVER = ((r"rescue", "Rescue is never booted"),
            (r"/actions/(reset_password|request_console|rebuild)$",
             "its answer is a password or a console: never the door's"))


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
# Never, judged or not (plan section 2, "Always refused"): an answer that is a secret or a credential, a shell or code
# on a host, a person's or a program's access, IAM beyond the listed key form, and the account itself.
AWS_NEVER = re.compile(
    r"(sts|iam|organizations|account|secretsmanager|kms|lambda|ec2-instance-connect):.*"
    r"|ssm:(Get|Send|Start|Resume).*|ecr:(GetAuthorizationToken|GetDownloadUrlForLayer|InitiateLayerUpload"
    r"|UploadLayerPart|CompleteLayerUpload)"
    r"|ec2:(GetPasswordData|DescribeInstanceAttribute|ModifyInstanceAttribute|GetLaunchTemplateData"
    r"|DescribeLaunchTemplateVersions|CreateLaunchTemplate.*|GetConsoleOutput|GetConsoleScreenshot"
    r"|CreateKeyPair|ImportKeyPair)", re.I)
CALL_SERVICES = [name for name in AWS_SERVICES if not AWS_NEVER.fullmatch(f"{name}:Any")]
AWS_NEVER_PATH = re.compile(r"/(access-entries|access-policies|pod-identity-associations|identity-provider-configs)"
                            r"(/|$)")
REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]")
CIDR4 = re.compile(r"(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}/([0-9]|[12][0-9]|3[0-2])")
AWS_COST = ". A call that adds cost goes to the owner through your line, as a Needs-you item with the exact command (D11)."


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
        return Decision("judged", "a security group of a tagged instance", target=f"aws:{account}",
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
        return Decision("judged", "a CloudFormation change set", target=f"aws:{account}",
                        plan={"provider": "aws", "account": account, "steps": [
                            {"aws": ("cloudformation", "CreateChangeSet"), "params": {
                                "StackName": args[0], "ChangeSetName": args[1],
                                "TemplateBody": content.decode("utf-8", "replace")}}]})
    if op == "key-off":
        if len(args) != 2 or not NAME.fullmatch(args[0]) or not re.fullmatch(r"AKIA[0-9A-Z]{16}", args[1]):
            return refused("key-off takes the user and the access key id")
        return Decision("judged", "deactivating an IAM key that shows no use", target=f"aws:{account}",
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
        return Decision("judged", "a change of the EKS public endpoint allowlist", target=f"aws:{account}",
                        plan={"provider": "aws", "account": account, "steps": [
                            {"aws": ("eks", "DescribeCluster"), "method": "GET", "path": f"/clusters/{args[0]}"},
                            {"aws": ("eks", "UpdateClusterConfig"), "method": "POST",
                             "path": f"/clusters/{args[0]}/update-config",
                             "params": {"resourcesVpcConfig": {"publicAccessCidrs": args[1:]}}}]})
    if op == "call":
        return aws_any(account, args, content)
    return refused(f"{op} is not listed for AWS")


def aws_any(account, args, content):
    """Any other call inside the role's rights, judged (the plan's AWS row): `call <service> <Action> [<region>]` with
    its parameters as one JSON object of content (flat for a query service), or `call eks <METHOD> <path> [<region>]`
    with an optional JSON body. The role's own deny list and the judge hold the rest."""
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
        s = {"aws": (service, f"{method} {path.partition('?')[0]}"), "method": method, "path": path, "params": params}
    else:
        action = args[1]
        if not re.fullmatch(r"[A-Z][A-Za-z0-9]{1,80}", action):
            return refused("the action is a name like DescribeVolumes")
        if AWS_NEVER.fullmatch(f"{service}:{action}"):
            return refused(f"{service}:{action} is never the door's: its answer is a secret, it opens a shell or "
                           f"code on a host, or it gives access")
        if protocol == "query" and params and (len(params) > 200 or any(
                not re.fullmatch(r"[A-Za-z0-9.]{1,100}", k) or not isinstance(v, (str, int, bool))
                for k, v in params.items())):
            return refused("a query service's parameters are flat: names like Filter.1.Name, and text values")
        s = {"aws": (service, action), "params": {k: str(v).lower() if isinstance(v, bool) else str(v)
                                                  for k, v in params.items()} if protocol == "query" and params
             else params or {}}
    if region:
        s["region"] = region
    return Decision("judged", f"a call of {service} inside the role's rights", target=f"aws:{account}",
                    plan={"provider": "aws", "account": account, "steps": [s]})


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
        return Decision("judged", "a firewall rule on a listed SQL server", target=f"azure:{account}",
                        plan={"provider": "azure", "account": account, "steps": [step(
                            "PUT", f"{args[0]}/firewallRules/{args[1]}",
                            {"properties": {"startIpAddress": args[2], "endIpAddress": args[3]}})]})
    if op == "app-setting":
        if len(args) != 3 or args[0] not in (conf.get("sites") or []) or \
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", args[1]) or len(args[2]) > 2000:
            return refused("app-setting takes a listed site, the setting's name and its value")
        return Decision("judged", "an App Service setting", target=f"azure:{account}",
                        plan={"provider": "azure", "account": account, "app_setting": {
                            "site": args[0], "name": args[1], "value": args[2]}})
    if op == "change":                            # D25: a write of the service principal's own rights, judged
        if len(args) != 3 or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?", args[2]):
            return refused("change takes the method, the path and the API version of its resource provider, with the "
                           "body as content")
        return judged_write("azure", account, args[:2], content, AZ_PATH, AZ_NEVER,
                            lambda method, path: "a change of " + (path.split("/providers/")[-1].split("/")[0]
                                                                   if "/providers/" in path else "a resource group"),
                            query={"api-version": args[2]})
    return refused(f"{op} is not listed for Azure")


AZ_PATH = re.compile(r"/subscriptions/[0-9a-f-]{36}(/[A-Za-z0-9._()~-]+){1,16}")
AZ_NEVER = ((r"(?i)^POST \S*/(list[a-z]*|regenerate[a-z]*|generate[a-z]*|get[a-z]*|reset[a-z]*|rotate[a-z]*|"
             r"begingetaccess|createquerykey/[^/]+|publishxml|[a-z]*(token|credentials?|sas|password|secrets?|keys?))$",
             "its answer can be a key, a password, a token, a connection string or a setting, which ARM gives only "
             "to an action like this one: never the door's"),
            (r"(?i)/(keys|functionkeys|hostkeys|systemkeys|secrets)(/[^/]+)?$",
             "a key or a secret of a resource is never the door's"))


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
        return Decision("judged", "deleting a device", target=f"tailscale:{tailnet}",
                        plan={"provider": "tailscale", "account": tailnet,
                              "steps": [step("DELETE", f"/device/{args[0]}")]})
    if op == "oauth-client" and len(args) == 2 and args[0] in ("make", "revoke") and \
            re.fullmatch(r"tag:[a-z0-9-]{1,50}|[A-Za-z0-9]{6,40}", args[1]):
        steps = [step("POST", "/tailnet/-/keys", {"keyType": "client", "scopes": ["devices:core"],
                                                   "tags": [args[1]]}, keep="minted")] if args[0] == "make" else \
            [step("DELETE", f"/tailnet/-/keys/{args[1]}")]
        return Decision("judged", f"{args[0]} an OAuth client for one tag", target=f"tailscale:{tailnet}",
                        plan={"provider": "tailscale", "account": tailnet, "steps": steps})
    if op in ("tags", "acl", "policy"):
        return refused("a device's tags and the policy file are never the door's")
    if op == "change":                            # D25: a write of the client's own rights, judged
        return judged_write("tailscale", tailnet, args, content, TS_PATH, TS_NEVER,
                            lambda method, path: f"a change of {path.split('/')[-1]}")
    return refused(f"{op} is not listed for Tailscale")


TS_PATH = re.compile(r"/(tailnet/-|device/[0-9A-Za-z]{6,40})(/[A-Za-z0-9._-]+){0,4}")
TS_NEVER = ((r"/keys(/|$)", "a key's answer is its secret: the door's oauth-client makes one and keeps it"),
            (r"/(acl|tags)(/|$)", "a device's tags and the policy file are never the door's"),
            (r"/webhooks(/|$)", "a webhook's answer is its secret: never the door's"),
            (r"-invites(/|$)", "an invite's answer is a link that lets anybody in: never the door's"))


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
# The coordinator's change to D25 (6 November 2026): "a delete of what no agent made" is a code check, and not only a
# rule of the judge, because the judge can miss a crafted call. The door keeps the names of what writes through it
# made (made_keys, from the provider's answer); a judged call that deletes anything else (deletes) goes to the owner as
# a Needs-you item with the exact call, as a refusal of the judge does, and his signed yes lets it through once.

HZ_ONE = {"servers": "server", "firewalls": "firewall", "volumes": "volume", "primary_ips": "primary_ip",
          "floating_ips": "floating_ip", "networks": "network", "load_balancers": "load_balancer",
          "certificates": "certificate", "ssh_keys": "ssh_key", "placement_groups": "placement_group"}
MADE_NAME = re.compile(r"[A-Za-z0-9._:@~-]{1,200}")
B2_MADE = ("b2_copy_file", "b2_start_large_file", "b2_finish_large_file")
B2_DELETE = {"b2_delete_bucket": ("bucket", "bucketId"), "b2_delete_file_version": ("file", "fileId"),
             "b2_cancel_large_file": ("file", "fileId"), "b2_delete_key": ("key", "applicationKeyId")}
AZ_DELETE_ACTION = re.compile(r"(?i)(delete|purge|remove|reimage|wipe|clear|truncate|empty)[a-z]*")


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
    name gets a name that nothing made, so it goes to the owner."""
    provider, out = (plan or {}).get("provider"), []
    for s in (plan or {}).get("steps") or []:
        method, path = s.get("method"), s.get("path") or ""
        body = s.get("body") if isinstance(s.get("body"), dict) else {}
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
    words = {"bucket": "the bucket", "file": "the file version", "name": "the file", "key": "the key"}
    return f"{words[kind]} {rest}" if kind in words and not key.startswith("/") else key


# ---------------------------------------------------------------- execute a plan
#
# ctx gives what a plan needs: http(method, url, headers, body) -> (status, answer), the secret of this account
# (credentials), keep(kind, value) for what the door keeps (a minted key's secret), minted_secret(key_id), and
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
    if "app_setting" in plan:
        return azure_setting(plan, ctx)
    session = open_session(provider, conf, ctx)
    said, kept = [], {}
    for s in plan["steps"]:
        if provider == "aws":
            status, answer = aws_call(s, conf, ctx)
        else:
            path = s["path"].format(**dict(session.get("fill", {}), **kept))
            status, answer = send(provider, s, path, session, ctx, kept, plan)
        if status >= 400:
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
        if s.get("keep") == "server_id":
            kept["server_id"] = answer["servers"][0]["id"]
            continue
        if s.get("keep") in ("tunnel", "ingress"):
            kept[s["keep"]] = answer
            continue
        said.append(short(answer, 4000))
    return "\n".join(said) or "done"


def check_need(need, answer, plan, kept):
    if need == "none" and (answer.get("result") or []):
        raise Stop("a record of that name exists: a change of it is judged")
    if need == "one_server" and len(answer.get("servers") or []) != 1:
        raise Stop("no one server has that name in this project")
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


def open_session(provider, conf, ctx):
    """What every request of this provider carries: its base and its authorization. AWS has no secret: each call is
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
        return {"base": BASES["github"], "headers": {"Authorization": "Bearer " + github_token(conf, ctx),
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
    return {"base": BASES[provider], "headers": {"Authorization": "Bearer " + secret},
            "fill": {"account_id": conf.get("account_id", "")}}


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
            raise Stop("that hostname is in the tunnel already: a change of it is judged")
        body = {"config": dict(((kept.get("ingress") or {}).get("result") or {}).get("config") or {},
                               ingress=[r for r in ingress if r.get("hostname")] + [add] +
                               [r for r in ingress if not r.get("hostname")] or [add, {"service": "http_status:404"}])}
    if s.get("need") == "server_path" and not path.startswith(f"/servers/{kept.get('server_id')}") and \
            not path.startswith("/firewalls/"):
        raise Stop("that path is not the named server's")
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    return ctx["http"](s["method"], url, headers, data)


def github_token(conf, ctx):
    """An installation token of the door's App for this owner, from the App's key, signed by openssl."""
    jwt = app_jwt(conf["app_id"], ctx["secret"](conf["secret"]), ctx.get("sign"))
    status, answer = ctx["http"]("GET", f"{BASES['github']}/orgs/{conf['owner']}/installation" if conf.get("org", True)
                                 else f"{BASES['github']}/users/{conf['owner']}/installation",
                                 {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json"}, None)
    if status != 200:
        raise Stop(f"GitHub gave no installation of the door's App ({status})")
    status, answer = ctx["http"]("POST", f"{BASES['github']}/app/installations/{answer['id']}/access_tokens",
                                 {"Authorization": "Bearer " + jwt, "Accept": "application/vnd.github+json"}, b"{}")
    if status != 201:
        raise Stop(f"GitHub gave the door no token ({status})")
    return answer["token"]


def app_jwt(app_id, key_pem, sign=None):
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


def github_secret(plan, ctx):
    """A secret of a repository, set to the value of a key that the door rotated, with gh's own sealing. The value
    goes on gh's stdin and never into an argument or an answer."""
    s = plan["secret"]
    token = github_token(ctx["credentials"], ctx)
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
