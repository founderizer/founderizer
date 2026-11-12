# The owner's own MCP server

`owner_mcp.py` is the third face of Founderizer. The first is the Mac app. The second is
`INSTALL-PROMPT.md`, a prompt the customer pastes into the agent they already run. This is the
one that works unattended: **an MCP server that an agent connects to, and then sets a fleet up
and runs it** — it installs a hub, claims it, adds machines and agents, adds MCP servers, hands out
access from the pool, says a goal, reads every check, takes releases and backups, and answers a
Needs-you item.
No person clicks anything.

It is for the owner's own agent: their Claude, or any MCP client. It is not for the fleet's agents —
they have their own server, the `fleet` tools of `hub.py` (RULES.md). This one is the owner's side.
**OWNER-MCP-BOUNDARY.md** is why that sentence holds in the code and not only here: what stops this
server becoming a tool the manager can grant, why nothing refuses it by name, and where the
confirmation of a destructive call goes when there is no window to put it in.

## Give it to an agent

One grant, once. In the agent's MCP configuration, for Claude Code or any client that starts a
local server:

```json
{"mcpServers": {"founderizer": {
  "command": "python3",
  "args": ["/Users/<you>/fleet-pilot/owner_mcp.py"],
  "env": {"FOUNDERIZER_HUB": "http://100.64.0.1:8765"}
}}}
```

`FOUNDERIZER_HUB` can be left out: then the agent calls `use_hub` once with the address, or
`install_hub` and `claim_hub` when there is no hub yet, and the server writes the address into
`~/.founderizer/hub`. That file is no credential.

The install's firewall lets SSH in over the fleet's private network only. So `install_hub` puts the
server on that network itself, before the install starts, and keeps the public keys of the server's
SSH, and the port of its SSH, in `~/.founderizer/known_hosts`, for its address on that network. It
reads them over the owner's own SSH to the address that the owner gave. The owner's own
`known_hosts` knows the key of that address, or the first SSH there keeps the key that the server
gives (`StrictHostKeyChecking=accept-new`), as the Mac app's install does: then SSH refuses a key
that changed. The first read of `install_hub` and `install_log` goes to the address that the
owner gave; when SSH gets no connection there, the read and the later steps go to the private
address, and SSH checks the server there against those keys only. In BatchMode, SSH refuses a server
whose key it does not know, and the owner's `known_hosts` does not know the private address. Each
line has the name `<host>@<address>`, so the keys that one server gave count for the commands of its
own host. They count for a command whose host is that private address itself only when each host
that found the address gave the same keys and port, because a server can say that it has the
address of another server. That file is no credential either. The owner's own
`~/.ssh/known_hosts` changes only at the first SSH to an address that it does not know: then SSH
adds the key of that address.

The server runs the code of that folder, as it was when the agent's session started it. So a tool that a later
release adds reaches the agent only when the folder holds that release and a new session starts.

Nothing else is needed. There is no token to issue, no key to copy and nothing to rotate.

`install_hub` and `add_machine` can run for a long time: the first updates of a new server hold
apt's lock for about 9 minutes, and a join can wait for that lock more than once. While a tool
call runs, the server sends a progress notification for it every 30 seconds, when the
request of the call gave a `progressToken`. Claude Code gives one with each tool call. It ends a
call to a local server that sends no answer and no progress for 30 minutes
(`CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT`), and then the agent gets Claude Code's error, not the words
of this server. A client that gives no token gets no progress. Such a client ends a call at its own
time limit for a call, if it has one, and the steps still run on the server. So give it a limit for
this server that is longer than the longest call. That is about 10800 seconds, for the join of a
Linux server that must go on the private network first: in Codex, `tool_timeout_sec = 12000` in
the `[mcp_servers.founderizer]` table of its configuration.

The server runs one tool call at a time, and it reads its input also while a call runs. Claude Code
moves a call that runs longer than 2 minutes to the background, and then the agent can send another
call. That call waits in the server, with progress, and runs when the first one ends. A request
that is not a tool call, such as a ping, gets its answer at once. When the client ends a call (the
user's Esc, or the client's own time limit), it sends a cancel. A cancelled call that waits never
runs. A cancelled call that runs gets no more progress and no answer, but its command over SSH goes
on to its end: a join line works once, and a step that stops part way leaves the server in a state
that no step expects. Then the call starts no other step, so a cancelled `add_machine` does not go
on to its join line. A call that waits needs the time of the call before it too: a client that ends
a call at its own time limit, such as Codex, needs a limit of two times the longest call. So the
long tools tell the agent to wait for their answer before it calls a tool of this server again.
Until 11 November 2026 the server read one message at a time. So a call that waited behind a long
call got no progress, Claude Code ended it after 30 minutes, and the server still ran it later.

## How it authenticates to the hub, and why that is the whole of it

**It does not.** The hub knows the owner by the address the call comes from.

`hub.py` `ui_allowed` is the gate on every owner route: the call must come from the address that
`team.json` holds as `addresses.owner`, it must carry **no** bearer token, and it must carry no
browser `Origin`. The Mac app is authorized by exactly that and by nothing else — "The native app
uses the existing owner machine identity." So an MCP server that runs on the owner's Mac inherits
that identity as it stands. It holds no credential of its own, and there is no second credential
path to secure, leak or revoke. (The hub's remote MCP address for the owner's Claude or ChatGPT app,
when a later release turns it on, is another server with its own OAuth tokens at the phone's level
or less; those tokens never reach an owner route: OWNER-MCP-BOUNDARY.md, section 7a.)

That address is proved once, by the install's **claim** (`hubsetup.py`, "Why the claim exists"):
the installer on the new hub makes a one-time code, the owner's Mac sends it back, and the address
of that call becomes the hub's owner. The server's `claim_hub` tool makes exactly that call —
`POST /claim` with the code in the request body, from this Mac — so the server can take a fleet
from nothing and end up holding the authority, without a second mechanism being invented for it.

What follows from this is the whole security model, and it is the owner's own:

- **The grant is the authorization.** A grant of a repository, a database, a system or a server makes
  the agent that holds it fully responsible for it. So after the owner has put this server in their
  agent's configuration, it acts. It asks for no per-call confirmation, and it builds no second
  approval in front of a hub route.
- **Its authority is what it holds, not what it is told.** It holds the owner's Mac. That is the
  boundary, and it is the same boundary the Mac app has. A prompt, a web page or a machine's log
  cannot widen it: text that comes back from the hub, from an install log or from a server is
  data, and the server never runs any of it.
- **Revoking it is one step, and it is the Mac.** Take the server out of the agent's
  configuration, or change `addresses.owner` on the hub. There is nothing else to withdraw.

Because the address is the credential, the server is only the owner **on the owner's Mac**. On any
other machine every owner route answers 403, and the server says so in those words.

## No secret through a tool

In or out: no password, no API key, no provider token, no entitlement, no Tailscale auth key.
`test_owner_mcp.NoSecret` holds the server to it two ways: no tool takes an argument whose name is
one of those things, and the owner routes that do carry a credential are **not tools of this
server at all** — the subscription token, the GitHub App's private key, a chat bot token, Google's
client secret, the secret catalog's fingerprints and the restore of a copy. Those stay the app's,
because this server would be the thing that carried the value.

Two kinds of short text do pass, and both are allowed by RULES.md, "Logins":

- **The Tailscale auth key is named, never carried.** `install_hub` takes the *path* of a file on
  this Mac, refuses it unless only its owner can read it (mode 600), never reads it in Python, and
  gives it on `ssh`'s standard input to the step that puts the server on the private network, as
  `INSTALL-PROMPT.md` A2 does, with a time limit and `--reset` for `tailscale up`, and only for a
  server that is not on that network yet.
  `add_machine` does the same with its `authkey_file` (B2). That step removes the server's copy of
  the key after `tailscale up`, and the install itself reads no key.
- **A one-time code that dies in minutes** — the install's claim code, a machine's join code, the
  device code a provider shows the owner. "A one-time code that dies within minutes is the only
  thing you may pass on as plain text." The hub keeps each of them only as a SHA-256.

## One owner API, not two

Every tool is one route of `hub.py`'s owner API, with that route's own body, its own command rules
and its own refusals:

- a `request_id` of its own on every command, so a lost answer is sent again and lands once (a tool
  takes the owner's agent's own `request_id` for exactly that);
- the hub's generation (`db`) on every read and command, read again once when the hub says it
  moved;
- `base_sha256` of `team.json` on every command that moves it, read from `GET /ui/team`
  immediately before the command, so a change that arrived meanwhile is the hub's own 409 and not
  a silent overwrite;
- the hub's refusal, given back whole — not only the reason but what came with it, because a
  refusal often carries what is still missing, and that is the part the agent must act on.

This file validates nothing the hub validates. It passes the fields through and gives the hub's
own words back, so the two cannot drift apart. It validates only what no hub sees: the SSH host
and user it puts in a command line, and the mode of the auth key file.

`fleet_read` is the reads. Each of its pages is one `GET` route, and
`test_owner_mcp.Shape.test_every_page_of_fleet_read_is_a_get_route_the_hub_really_serves` reads
`hub.py`'s own dispatch to prove it, because a page that named a route the hub does not serve
would read as an empty fleet instead of as a mistake.

## The tools

| Tool | Route | What it does |
| --- | --- | --- |
| `fleet_overview` | `/ui/state`, `/ui/health`, `/ui/releases`, `/ui/servers` | What is my fleet doing. Start here. |
| `fleet_read` | every owner `GET` route, by page name | Every check the app reads. |
| `search_history` | `/ui/history` | Search what one agent, or every agent, took part in, by words, dates, person, task and kind; with `ref`, one record in full. |
| `see_costs` | `/ui/costs` | What every agent's work cost, against the period before: list dollars, the four kinds of tokens, results without rework by kind of work, checks, each account's window and the model changes. |
| `which_hub` / `use_hub` | `/ui/state` | Which hub, on what authority; and point at one. |
| `install_hub` | SSH, `hub.sh` (INSTALL-PROMPT.md A1–A5) | Install a hub on a server the owner names. It puts the server on the private network first (A2), with `authkey_file`, and starts the install at the server's address there. It changes nothing on a server where an install runs. |
| `install_log` | SSH, `tail` | The install's own log, with the claim code read out of it. When SSH gets no connection to the host, because of the install's firewall, it reads the log at the server's address on the private network. |
| `claim_hub` | `POST /claim` | Prove this Mac's address. This is what grants the authority. |
| `add_machine` | `/ui/servers/join` | The one-time join line, and with `host` it runs it over SSH: as root on Linux, as the Mac user on a Mac. A Linux server that is not on the private network goes on it first, with `authkey_file` (B2); without that file, it stops before the hub makes a code. |
| `add_agent` | `/ui/servers/<s>/agents` | An agent on an available server, with its install job. |
| `remove_machine` | `/ui/servers/<s>/remove` | A server with no agent leaves. |
| `activate_agent` / `agent_settings` | `/ui/team/agents/<a>` | Turn an agent on or off; its model, effort, capabilities. |
| `agent_key` | `/ui/team/agents/<a>/key` | Register, replace or remove an agent's key, by its SHA-256. Never a key. A key that a server service registered is replaced, never removed. |
| `rename_agent` | `/ui/team/agents/<a>/rename` | A new name for an agent: everything it has moves with it, and nobody signs in again. |
| `move_agent` | `/ui/team/agents/<a>/move` | An agent onto an empty server of its own kind: the install job there, and its old session ends. A new fleet's manager onto its first server, with `runtime` its AI provider. |
| `remove_agent` | `/ui/team/agents/<a>/remove` | Delete an agent: what is its own goes, on the hub and on its server (its service, files and own OS user), and nothing of another agent. Its tasks stay as history. |
| `switch_runtime` | `/ui/team/agents/<a>` | Switch one agent to its other runtime. A command of its own. |
| `vault_access` | `/ui/team/agents/<a>` | Give one agent its machine's vault broker, or take it away. |
| `login_creation` | `/ui/team/agents/<a>` | Let one agent make new logins in the vault, or stop it. |
| `set_reporting_lines` | `/ui/team/lines` | The whole shape of the team: each agent's role and who it reports to. |
| `save_profile` | `/ui/profiles/<a>` | Write one agent's profile — the owner's own words, which the agent cannot change. |
| `prepare_runtime` | `/ui/servers/<s>/prepare` | Prepare an agent's other runtime before its switch. |
| `start_manager_session` | `/ui/machines/<a>/manager` | Ask the manager's machine to start the standing session. |
| `sign_in_machine` / `sign_in_code` | `/ui/machines/<a>/signin[/code]` | Start a machine's own provider sign-in, and carry the code back. |
| `check_machine` / `update_machine` | `/ui/machines/<a>/check`, `/update` | Take a reading now; update Fleet when idle. |
| `check_mcp_server` | `/ui/mcp/check` | Does this MCP server answer? Asked before it is saved, and of a machine for a `command` server. Writes nothing. |
| `save_mcp_server` | `/ui/team/mcp` | Add one of the owner's own MCP servers, change it, or remove it. An agent loads it only once it also holds `tool:<name>`. |
| `grant_access` | `/ui/team/repos`, `/ui/team/tools`, `/ui/team/google`, `/ui/secrets/grant` | One agent's hold of one resource, as `<kind>:<what>` and a level. |
| `share_resource` / `take_resource` | `/ui/resources`, `/ui/resources/take` | The pool's standing; and end one hold. |
| `save_account` | `/ui/team/accounts` | One runtime account: its provider and the owner's title for it. |
| `save_login` | `/ui/team/logins` | The owner's title for one vault login, by its `bws://` reference. The label only. |
| `machine_access` | `/ui/team/access` | How the fleet reaches a machine: its SSH user, port, Screen Sharing. |
| `save_knowledge` | `/ui/knowledge` | The owner's own knowledge files: text, new text in place, a page the hub fetches, a kept file, a delete. |
| `remove_skill` | `/ui/skills/remove` | Remove one agent's own skill in one commit. The agents write their skills; `fleet_read(page="skills")` lists them. |
| `save_person` / `person_handle` | `/ui/people`, `/ui/people/<id>/handles` | The people who may write to an agent, and their chat handles. `scopes` gives a person All of an agent, or only some of its repositories and secrets (the person access plan). |
| `save_role` | `/ui/roles` | The roles those people hold: a name, a prompt in the owner's words, tools on or off, a daily limit for a closed role. A held role is not deleted. |
| `save_settings` | `/ui/settings` | The fleet's settings in `team.json`, such as `contacts.v2`, and the runtime facts the owner changes (`cache_seconds`, `compact_tokens`, `token_weights`, `routine`); null gives each its default. |
| `person_code` / `remove_owner_handle` | `/ui/people/codes`, `/ui/people/handles` | Link the owner's own chat account; remove one of their handles. |
| `control_conversation` | `/ui/conversations/<id>` | Pause one conversation with a person, or let it run again. |
| `save_chat_account` | `/ui/team/chat-apps` | One chat app account. The account, never its bot token. |
| `pause_chat_apps` | `/ui/chat-apps/pause` | Pause all: every inbound message and every outbound item at once. |
| `link_chat_app` | `/ui/chat-apps/<id>/link`, `/unlink` | Link or unlink a WhatsApp account. The QR is a read. |
| `send_again` | `/ui/outbound/<id>/again` | Send one chat message again, for an unknown or failed one. |
| `disconnect_google` / `disconnect_mcp_server` | `/ui/google/disconnect`, `/ui/mcp/disconnect` | End a saved connection. The grants stay. |
| `attach_file` / `read_attachment` / `keep_attachment` | `/ui/attachments*` | A file to the hub, a file back to this Mac, and keeping one. |
| `owner_device` / `device_code` | `/ui/owner/devices[/<d>/code]` | The owner's phones, and one enrollment code. Its key is the phone's. |
| `reload_team` | `/ui/team/reload` | Apply `team.json` from a pushed revision without restarting the hub. |
| `send_message` | `/ui/messages` | Say something to an agent. **This is how a goal or a duty is set.** |
| `answer_needs_you` | `/ui/needs/<id>` | Answer a Needs-you item, in words, by choosing an option, or by ticking the options of an item that lets them combine (`choices`). A secret request takes neither: the app's secure form answers it. |
| `discuss_need` | `/ui/needs/<id>/talk` | Ask about an open Needs-you item before deciding it. The manager replies under the item; the item stays open. |
| `decline_secret_request` | `/ui/needs/<id>/secret` | Decline a secret request, with a reason or none. A decline carries no value, so this server sends it; an answer with a value stays the app's secure form. |
| `control_task` / `steer_task` | `/ui/tasks/<id>/control`, `/steer` | Pause, stop, resume; steer an open task. |
| `goal_state` / `duty_state` / `trigger_state` | `/ui/goals/<id>/state` and the two beside it | Pause, resume, finish, drop. |
| `end_standing` | `/ui/standing/<id>/end` | End one standing instruction or target of any agent. `fleet_read(page="standing")` lists them. |
| `settle_outcome` | `/ui/outcomes/<id>` | Record whether an unknown outcome took effect. |
| `check_releases` / `take_release` / `automatic_releases` | `/ui/releases/*` | Ask the channel; take the release; turn automatic updates off or on (on by default). |
| `take_backup` | `/ui/backup`, `/ui/backups/confirm` | A copy of the fleet into a file on this Mac, checked. |

**A goal and a duty have no form.** UI-API.md version 1.20 took the owner's own writers out of the
hub on the owner's direction: they say in chat what they want the fleet to reach, and the manager
writes it down with `update_goal`, or a duty with `set_duty`. So this server sets a goal with
`send_message` and nothing else, and `goal_state` and `duty_state` are the state changes that
stayed.

## The three things it cannot do without the owner

Not because a rule forbids it, but because each one is the owner's own hands on something this
server is not allowed to carry.

1. **Bring a new credential into the fleet.** The subscription token the shop issues for this
   fleet (`POST /ui/releases/entitlement`), the GitHub App's private key, a chat app's bot token,
   Google's Connect, a vault login (also the one an agent asks for with `request_secret`, whose
   answer, `POST /ui/needs/<id>/secret`, only the app's secure form gives, once the value is in the
   vault; its decline carries no value, so `decline_secret_request` sends that one) and the
   Tailscale auth key itself. Each is the owner's account,
   the owner's money and the owner's liability (RULES.md, "Access that the fleet already holds"),
   and the value would have to pass through a tool. So the owner does these in the app, and this
   server hands out only what the fleet already holds. The Tailscale key is the one it touches,
   and only as the path of a file it never opens.
2. **Finish a provider sign-in.** `sign_in_machine` starts it and `sign_in_code` carries the code,
   but the page in between is the provider's own, in the owner's own browser, under the terms on
   which Founderizer may host the unmodified runtime at all: each end user signs in through the
   vendor's flow, and the operator never collects or intermediates the credential. The agent gives
   the owner the link and waits for the code.
3. **Be the owner on another machine.** The authority *is* the owner's Mac. An agent that runs in
   the cloud, on a worker or on anyone else's computer gets 403 from every owner route, and no
   argument to any tool changes that. The claim can only be made from the Mac that will own the
   fleet, so this server cannot grant itself the fleet from somewhere else — which is the point.

Two smaller ones worth knowing: a server has to exist and be paid for before `install_hub` can
reach it, and turning a new agent on waits for that machine's own setup check — the hub refuses
`activate_agent` until then and says exactly what is missing, which the agent can read and act on.

## Keeping it in step with the hub

This server is a client of the owner API, and the hub is built by several threads at once. So the one thing that
can go wrong is **drift**: the hub grows a route, a field or a value, and this file does not. It cannot be caught by
reading the file, because the failure is silent in three different ways, and each has a check of its own.

`owner_mcp.py` runs on the owner's Mac with the standard library alone, and the hub is on another machine, so it
**cannot import one name from the hub**. It repeats the routes, the fields and the enums as text. Two constants in
the file are where that repetition lives — `NOT_TOOLS` (the routes left out, each with its reason) and
`FROM_THE_HUB` (every value copied from `hub.py` or `lifecycle.py`) — and the checks below hold both to the hub.

| What drifts | How it fails if nothing checks | The check |
| --- | --- | --- |
| A **new owner route** | The owner asks for it, the agent has no tool, and nobody knows the route exists | Every `ui_command` route of `hub.py` must be a tool here or named in `NOT_TOOLS` |
| A **new field** on a route that is already a tool | The worst one: `plain` and `with_base` send exactly the fields their own tuple names, so the call still succeeds and the setting is simply **not there** | Every field a route takes must be sendable by one of its tools |
| A **new value** of an enum | The agent is told the old values and refuses a good one, or sends a stale one | Every entry of `FROM_THE_HUB` must equal the hub's own constant |
| **New words** of a shell text that both run (`TAILSCALE_INSTALL`, Tailscale's install with its wait for apt's lock) | `add_machine` installs Tailscale in another way than the hub's join line and INSTALL-PROMPT.md B2 | The same check: the text is an entry of `FROM_THE_HUB` |
| A **tool nobody wrote down** | The owner never learns they have it, and the table below goes stale both ways | Every tool must be named in this file, and every tool the table names must exist |

**All of them run in `selftest.py`**, section 0, from the source alone — no hub, no network, nothing started. That is
the point: `selftest.py` is what a release runs, and nothing excuses a failure in it (COORDINATION.md rule 5). So a
thread that adds an owner route or a field **fails the release** until it has decided whether the owner's own agent
can reach it. `test_owner_mcp.py` has the same drift checks with their reasoning. Neither keeps a list by hand: both read
`hub.py`.

The second check is not hypothetical. It found four powers on `POST /ui/team/agents/<a>` that `agent_settings`
**named in its own description** and could not send — `screen`, `runtime`, `vault` and `vault_create` — which are
now `agent_settings`'s `screen` field and the tools `switch_runtime`, `vault_access` and `login_creation`. The third
found `repo: read|write` after the hub had gained a third level, `deploy`.

Each check is proved to fail: a route, a field and an enum value were each added to a copy of `hub.py`,
and a tool was taken out of this file's own table, and every check failed naming exactly what drifted.

## Checks

`test_owner_mcp.py`, 43 checks, against a fixture hub and never against a real fleet:

- **`Boundary`** — OWNER-MCP-BOUNDARY.md, held to the code that enforces it: no agent can be put on
  the owner's address, no owner device can take a machine's address, the owner's own computer cannot
  join as a machine, `grant_access` does **not** refuse this server by name (asserted on purpose, so
  the address gate cannot be quietly replaced by a blocklist of one file name), and the grant it
  makes is inert — the dangerous tools, called from an address that names no owner, all refuse.
- **`McpServers`** — the owner's own MCP servers through this server: a `command` server checked
  against a machine before anything is saved, then saved, renamed and removed; an entry the hub
  refuses given back in the hub's own words with nothing saved; and an entry that moved under the
  command as the hub's own 409 instead of an overwrite.
- **`FromNothing`** — the whole claim, end to end, with a real MCP client over standard input and
  output, the real claim listener of `hubsetup.py`, the real owner API of `hub.py` in process and
  the real `POST /join` for the machine that joins: claim a hub, read the fleet, add a machine,
  put an agent on it with its install job, and then read every page of the owner API. Also a goal
  said in chat, a Needs-you item answered, access granted and taken back with every other hold
  left as it stands, the pool's standing, and a copy of the fleet written to this Mac and checked.
- **`Install`** — the install's commands in the order `INSTALL-PROMPT.md` gives them, with a
  stand-in `ssh` that answers from a table, because no test provisions a server: the auth key on
  standard input exactly once and in no argument, the network step before the start, the read and
  the start at the server's private address and the port of its SSH, which the keys that the network
  step read check, a key file other users can read refused before
  any command, a host or user that would not be one argument refused, the claim code read out of
  the log, and an install that stopped given to the owner instead of worked around. While a call
  runs, a client that gave a `progressToken` gets a progress notification for the call at regular
  times, all before the answer; a client that gave none gets none. Each SSH asks the server for a
  sign of life every 30 seconds (`ServerAliveInterval`), as the Mac app's install SSH does. A call
  that the agent sends while another runs waits with progress and runs after it, and a ping gets
  its answer at once. A cancel drops a call that waits, so that it never runs, and it ends the
  progress and the answer of the call that runs, but not its command: that call starts no other step.
- **`Progress`** — `Calls` in this process: only a string or an integer token of a tool call asks
  for progress; a call has progress from its reading to its answer and none after it; the calls
  run one at a time, in the order of reading, while a ping gets its answer at once; a cancel drops
  a call that waits and silences the call that runs, which finishes its step and starts no other
  command over SSH and no call to the hub; a claim that went through keeps the hub address also
  after a cancel; the type of an id counts; a batch gets one list of
  answers, and a cancel in a batch can name a request of the same batch; a client that closed its
  end stops the progress and not the call, and no other call starts; and `serve` returns at the end
  of its input only after the calls that it read. And `install_hub` and `add_machine` tell the
  agent that this server runs one call at a time, and to wait for their answer.
- **`RootThroughSudo`** — `install_hub` (twice), `install_log` and `add_machine` run on the stand-in
  server of `test_hub_install.py`, as root and as a user who is not root: each root step is one
  `sudo -n -i -- /bin/sh -c '…'`, and `/bin/sh` (and dash) gets each program unchanged. A program
  that `sudo -i` would change goes as `eval` of a `printf` (`through_sudo`, the idea of the app's
  `InstallPlan.throughSudo`). Until 11 November 2026 root's login shell expanded take_line's "$t"
  to nothing, so on a server that had the code already the code did not move. The same server
  says no, too: a `sudo` that does not let the user in stops `install_hub` at its first root step
  with sudo's own words and nothing changed (`become_root`; `add_machine` stops the same way for a
  Linux server before the hub makes a code, and `install_log` instead of a read for ever), a step
  of the code that fails (git that apt-get cannot install, a fetch that git cannot make, a move
  that `may-take` refuses) stops it with that step's words before the install starts, and a Mac's
  join line runs whole as the Mac user that SSH reaches, never through sudo. Root on a Mac, and a
  kind that is not the machine's (`uname -s`), are refused before a code is made, and the answer
  says when a join did not run (a line that printed nothing) or ended with a failure. Until that
  day the agent read a sudo refusal as a missing repository credential, the install started with
  the old code after a refused move, and join.sh stopped each Mac line that this server ran as root.
  On a new server whose first updates hold apt's lock, the git step waits for the lock, as A3,
  `hub.sh` and `join.sh` do: the stand-in's `apt-get` holds the lock of dpkg as apt does. The git
  step's `apt-get update`, which tries the lock of the package lists once, gets up to 10 tries, 15
  seconds apart (since 11 November 2026). The step's SSH
  time-out is longer than that wait, and shorter than the 30 minutes after which Claude Code ends a
  call to a stdio MCP server that gave no answer and no progress. A Linux join line has the time of
  each wait of the join for apt's lock, one after the other, and of its work: join.sh's apt-gets
  that install, and the age install of the vault broker. A Mac's join line has 3600 seconds. A step
  that can change the server and that SSH loses (status 255) is said as a command that did not
  finish, not in the step's own words for a failure. A network step or a start step that fails stops
  the install with its own words. A command that does not finish in its time says what to do in the
  words of its tool: a join line, which writes no install log, does not send the agent to
  `install_log`. A Linux server that is not on the private network goes on it before the hub makes
  a code (B2): the owner's key file on the standard input of one root step and in no argument,
  `tailscale up` with the file that the step writes, the file removed after it, and a wait for
  apt's lock before each try of Tailscale's installer. The step starts tailscaled when it does not
  run. Its `tailscale up` has a time limit, and `--reset`: a server that an earlier join line left
  waiting for a sign-in keeps the settings of that line, which Tailscale does not let a `tailscale
  up` drop without `--reset`. On a server that is on the network already, the key stays on this
  Mac. Without a key file, `add_machine` stops in the words of B2, and a key that Tailscale refuses
  stops it in Tailscale's words; no code is made. Until 11 November 2026 the hub's line ran
  `tailscale up` with no key on such a server, and it waited for a sign-in that nobody saw.
  After the firewall step of the install, the stand-in SSH refuses a new session to the public
  address, and it knows the private address only by the keys that `install_hub` kept: `install_log`
  and a second `install_hub` still reach the server, at its private address, also when the agent
  gives the public address, and `hub.sh` reads no key. The first read goes to the private address
  only when SSH gets no connection to the public one, so a server that the owner replaced, and that
  still runs at the kept address, gets no install. When this Mac does not reach the private address,
  `install_hub` starts nothing; when neither address answers, `install_log` gives SSH's words at
  each. The kept keys are the ones that `sshd -T` names, with its port, and they count for the host
  that read them: a server cannot write a marker or the name of another host, and it cannot change
  the lines of another host. A server that says that it has another server's address makes those
  keys count for that address no more. A server where an install runs gets no second one, but a
  plan that still runs does not stop the install. Until 11 November 2026
  `install_hub` gave the key to `hub.sh`, and after its firewall step no `install_log` could
  connect, so the agent could not read the claim code.
- **`Refusals`** — a Mac that is not the owner's, a generation that moved, a `team.json` that
  moved under a command, the same `request_id` twice, and a field the hub refuses.
- **`NoSecret`** — no tool takes a secret, the credential-carrying routes are not tools here, a
  registered login in a message is refused and stored nowhere, and the sign-in code is in no row
  and no log line.
- **`Admin`** — the admin actions beside the ones `FromNothing` walks: a profile written as the owner and the
  agent's own notes read but never written; the reporting lines, so a worker reports to a lead; the entries of
  `team.json` (an account, a login's title, how a machine is reached) and one of the owner's own knowledge files
  added and removed; a person added with a handle, blocked and removed; a file sent to the hub, read back whole and
  kept; and the small switches — Pause all, the manager session, and a reload the hub refuses.
- **`Shape`** — an MCP client lists the tools, every page is a `GET` route `hub.py` really serves, and without a hub
  every tool says how to get one. And the three drift checks of "Keeping it in step with the hub" above, which are
  what answers "does it have all the admin actions" and keeps answering it: every owner route is a tool or is in
  `NOT_TOOLS` with its reason, every field of a route can be sent, and every value in `FROM_THE_HUB` is the hub's
  own. All three read `hub.py` and keep no list by hand, and all three also run in `selftest.py`, which a release
  runs.

**Live, 20 October 2026,** against a real fleet's own hub from its owner's Mac, with a real MCP client over standard input and output. `which_hub` said
`reads_owner_api: true`. Every read answered with that owner's own fleet: four machines, each agent's
repositories, the people, the chat apps, capacity, health (`ok: true`), the checks, the duties, the
owner's phone and the four profiles. `check_mcp_server` asked `mac-studio` about a program and **the
Studio answered for itself** (`missing`, "no notes-mcp on its PATH or in ~/.local/bin"), so the machine
half of that check is live on that fleet, which UI-API.md still calls not deployed. Three writes were
made and each was undone: an MCP server added (`f053582`) and removed (`bb07f77`); Pause all on and
off again; and a knowledge file added (`b2f3e8b`) and removed (`fb208c7`). The owner's catalog, Pause
all and knowledge files are exactly as they were, and nothing else on that fleet was changed.

**Not proved:** no Linux server was provisioned and no provider was signed in to, so the install's
`apt`, `git clone`, `hub.sh` and `verify` steps are proved as the commands the server sends and
not as a real install; and the claim is proved against `hubsetup.py`'s own listener on loopback,
not over a tailnet.

It adds no route to `hub.py`, no table, no feature name and no change to `team.json`, so it needs
no deployment: it is one file on the owner's Mac.
