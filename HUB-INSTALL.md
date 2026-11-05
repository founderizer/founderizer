# Install a Founderizer hub

`hub.sh` turns a bare server into a working Founderizer hub: the one the Mac app and the
iPhone app connect to, and the one every worker and joined server then fetches its
code from. It is the counterpart of `join.sh`, which adds a *server* to a hub that
already runs (WORKER-INSTALL.md, UI-API.md "Servers"). One line. The hub answers in under
ten minutes; the security updates at the end can take some minutes more, and by then the
hub is already yours.

A customer never types any of this in a console: the Mac app installs over SSH from
their own Mac, or they paste `INSTALL-PROMPT.md` into the agent they already run and it
takes the steps below for them. This file is the description of the installer itself.

It needs root on a fresh Ubuntu 22.04, 24.04 or 26.04, or Debian 12 or 13 server. It
does not create a model provider account, does not sign in to one, does not write, copy or
refresh a provider credential, does not make a vault entry, and opens no public
port. Every step checks first, so the line is safe to run again after a failure and
a second run on a working hub changes nothing.

**The owner signs in to Claude themselves, from the app.** That is not a convenience,
it is the condition on which an operator may host the unmodified Claude Code at all:
each end user signs in through Anthropic's own flow, and the operator never collects,
stores or intermediates the credential. So the installer signs in to nothing, and
`"vault": "none"` in the first `team.json` says that the manager holds no credential of
Founderizer's. See "The sign-in, and renewing it" below.

**It makes the fleet, and no agent.** No agent runs on the hub's server: an agent has a
shell, and the central vault on that server holds every key. The manager is the first
agent, and its own setup page in the app gives it a server of its own (a VPS that joins
with one line, or a Mac), then its AI provider and the sign-in (UI-API.md 1.82). Each
agent installs only its own AI, on its own server.

## Before you run it

1. **A server.** Ubuntu 22.04, 24.04 or 26.04, or Debian 12 or 13, with systemd, and
   root. A €5 VPS is enough to start. Nothing else may be using port 8765.
2. **A Tailscale auth key** for the fleet's own tailnet, from its Tailscale admin
   console. One use is enough; a pre-authorized key saves a sign-in. The key goes to
   the installer on **standard input**, so run the line in a terminal on the server,
   not through a pipe. It never becomes a command argument or part of a URL.
3. **A copy of this repository on the server**, with its history. The hub's own
   repository is made from that copy, so a folder of loose files is not enough:

   ```sh
   rsync -a --exclude .claude ~/fleet-pilot/ root@<server>:/root/fleet-kit/
   ```

   A `git clone`, a `git bundle` or `--source` (below) does the same. Uncommitted
   changes in the copy are not installed: the installer takes its commit.
4. **The owner's Mac on the same tailnet**, with the Mac app, because the owner
   proves that Mac's address while the install runs.

## The install

One line on the server, as root:

```sh
sh /root/fleet-kit/hub.sh
```

With `--source` it clones the repository into `/root/fleet-kit` first, which replaces
step 3 above when the server can reach that address:

```sh
sh hub.sh --source https://github.com/miguelpieras/founderizer-fleet.git
```

The installer asks for the Tailscale auth key and does not show what you type. To give it
without a prompt, pipe it in — that still keeps the key out of the command line and out of
the process list:

```sh
printf '%s\n' 'tskey-auth-...' | sh /root/fleet-kit/hub.sh
```

`--check` prints the plan and changes nothing. Run it first on an unfamiliar server:

```sh
sh /root/fleet-kit/hub.sh --check
```

Other options: `--port N` (default 8765), `--timezone Z` (default the server's own),
`--runtime claude|codex` for the manager's first AI provider, which its setup page may change, `--hostname NAME` for the Tailscale name
(default: the name its provider gave the machine, which becomes its name in Fleet), `--claim-wait SECONDS`
(default 1800) and `--reclaim`.

### What the fifteen steps do

1. **This server and this copy of Founderizer.** Root, the system, systemd, and that the
   copy is a Founderizer checkout with a commit.
2. **Base packages:** `git tmux python3 curl ca-certificates ufw unattended-upgrades`.
3. **The user `fleet`:** created, password locked, out of `sudo`, `admin` and `wheel`,
   home mode 700, and lingering on, so its services run after logout and after a
   restart. It runs the hub and the git daemon, and no agent's session: each agent has
   its own user (step 9). Nothing of Founderizer runs as root.
4. **The private network.** Tailscale from its own installer when the server has none
   (`curl -fsSL https://tailscale.com/install.sh | sh`, the vendor's own script, which is what
   `join.sh` uses for a server too),
   then `tailscale up --auth-key=file:<a root-only file> --accept-dns=false` (with
   `--hostname NAME` only when it is given). This hub's address is what `tailscale ip -4` then gives.
5. **The firewall** (`ufw`, `hubsetup.py firewall`): incoming traffic on `tailscale0` only,
   SSH included, outgoing allowed. SSH is open to the internet no more, so after this step SSH
   reaches the server at its Tailscale address only. A firewall that was off keeps open each
   port that answered from the internet before the install (a website on that server stays up),
   with the comment `fleet kept`. It comes before the claim, because the
   owner's Mac must reach port 8765 while the install still runs. A firewall that is already
   active keeps its own rules, and loses only the public SSH rule (`fleet ssh`) that an
   installer before 2 November 2026 added.
6. **The Founderizer repository on this hub.** `~fleet/fleet-pilot.git` is the bare
   repository and the origin of the whole fleet: `fleet-git` serves it read-only over
   `git://`, and every worker and joined server fetches its code from it.
   `~fleet/fleet-pilot` is the hub's own checkout and it stands on `config`, the
   configuration ref — the branch the hub writes and nothing else writes (PILOT.md,
   "The configuration ref"). Both refs start at the commit of the copy you ran, so the
   code the hub serves is the code it runs.
7. **The first `team.json`, and the owner's own Mac.** One manager on this machine, or,
   when the app that starts the install gives the manager its own server
   (`FLEET_MANAGER_SERVER=later`, Founderizer 0.1.112 and later), one manager with no
   server yet (`"placed": false`: its `machine` names this machine only until its setup
   gives it one); this machine's address, `"vault": "none"`, and no credential of any kind.
   Then the claim, below. The file is committed on `config` and pushed to the hub's own
   repository, so the record starts at the first minute.
8. **The two root commands of this machine**, below:
   `/usr/local/sbin/fleet-agent-user`, `/usr/local/sbin/fleet-vault-program` and
   `/etc/sudoers.d/fleet-agents`.
9. **One OS user for each agent of this machine**, below.
10. **The services** `fleet-hub` and `fleet-git`, as systemd user services of `fleet`,
    enabled and started. No agent's service is here any more: each one belongs to its
    own user, in the next step.
11. **Each agent of this machine, under its own OS user**, below: its checkout cloned
    over `git://` on the configuration ref, its runtime in its own `~/.local/bin`, and
    its service in its own systemd manager. A new hub has none, and says so: the manager
    runs on a server of its own. A hub from before keeps its manager on this machine,
    and a second run of the line installs it there as before.
12. **The checks** the owner can act on, below.
13. **This fleet's own id**, below: sixteen hex characters in the hub's key store, made
    once and never again.
14. **Security updates:** unattended security updates on, and the pending ones once.
    It never restarts the server; it says when a restart is needed.
15. **`verify`**, below: the last step says whether this machine is healthy, and the
    line ends in failure when a check failed.

### One OS user for each agent

`join.sh` and `hub.sh` make one OS user for each agent the fleet's `team.json` gives
this machine: `fleet-<agent>`, with a locked password, out of `sudo`, `admin` and
`wheel`, lingering on, and the home `/home/fleet-<agent>` of mode 700 that belongs to
it alone. A new hub has no agent, and `verify` names the agents of a machine, so a
second run of the line makes the user of an agent that was added since.

It is the step that gives each agent's own files somewhere no other agent's user can
read: a runtime credential, a vault token, a session record. The one command behind
both installers is

```sh
python3 hubsetup.py agent-users --team <team.json> --machine <name> [--check]
```

and it is safe to run again: a user that is already as Founderizer needs it is left exactly as
it is, and a home that somebody opened to other users is closed again.

**And the agent's session runs there.** Its checkout, its runtime, the credential the
vendor's client writes, its vault token and its systemd user service are all in that
home at mode 700, so one agent cannot read another agent's credential. On the hub the
manager moved with the rest: one rule for every Linux agent is smaller than two. The
installer's own step for it is step 11, and three things follow from it:

- **The runtime is installed once for each agent**, in that user's own `~/.local/bin`,
  because the credential lives beside it and a home of mode 700 cannot be shared. A
  machine with several agents carries one copy of the runtime for each.
- **An agent's checkout is a clone over `git://`**, like every worker's, into
  `/home/fleet-<agent>/fleet-<agent>` on the configuration ref. So no agent pushes to
  the hub's bare repository through the filesystem any more — the manager could while it
  shared the hub's own user, and it is now in the same position as every other agent of
  a fleet these installers make: fetch only. The hub itself commits the owner's own
  files, and each task's output, which the agent's helper sends to it when the agent
  delivers (RULES.md, "Where work goes").
- **`verify` reads each agent as its own user** (PRODUCT.md 4.1 keeps its check ids; a
  reading it cannot take warns), which is why the root helper of step 8 exists.

A Mac keeps one user for its agents: a Mac agent's service is a LaunchAgent of a desktop
session, so a second user would have to be logged in at the screen.

### The two root commands of this machine

An agent the owner adds later from the app is installed by the server service, which runs
as that machine's service user without root, so it cannot make a user by itself, and it
cannot bring that machine's vault broker onto the `vault.py` of a release either. Both
installers therefore put three files in place, with `visudo -c` on the last before it is
moved in:

- `/usr/local/sbin/fleet-agent-user` — one root command that takes one argument,
  `fleet-<agent>`, checks it against the agent names the hub allows, and makes that user.
- `/usr/local/sbin/fleet-vault-program` — one root command that takes **no** argument and
  brings this machine's vault broker onto the `vault.py` of the fleet's configuration ref
  (WORKER-INSTALL.md, "When a release changes vault.py"). It fetches that program itself,
  from the address this machine already takes all of its code from, so the caller passes
  no bytes and names no path.
- `/etc/sudoers.d/fleet-agents` — it gives the service user three rights and nothing else:
  those two commands as root, and any command as a member of the group `fleet-agents`,
  which holds the agent users and nobody else.

The service user needs the last right to install an agent under its own user, and
`verify` needs it to read one. That user is not an agent and runs no AI session, so it is
not a way from one agent to another. Neither root command takes a path, a value or a
command from its caller, so neither is a way for that user to run code of its own as
root, which is the one thing a root right of it must not become.

### The claim: the owner's own Mac

In Founderizer the owner is a private-network address and no token (`hub.py`,
`allowed("owner")`). A hub with the wrong `addresses.owner` would serve the owner's
pages to the wrong machine, and one with none would serve them to nobody and could not
start at all. So the installer proves the address before it finishes, with the same
one-time code `join.sh` uses, the other way round.

The installer prints a line like this and waits up to 30 minutes:

```
FLEET_CLAIM=XXXX-XXXX-XXXX sh -c "$(curl -fsS http://100.80.1.2:8765/claim)"
```

Paste it in Terminal **on the Mac that will own this fleet**. It sends the code back on
standard input, and the address of that call becomes `addresses.owner`. Then it waits
for the hub itself on the same port, and prints the address to paste into the app.

The code is made on the server, kept there only as its SHA-256, and never written to a
log, a file or a URL. It works once. Five wrong codes from one address and that address
waits. The hub's own address cannot claim it. If nothing claims it in time, nothing is
written and the line can be run again for a new code.

Because the claim listens on the hub's own address and port, it also proves the fleet's
Tailscale access rules for port 8765 before the hub exists. A claim that never arrives
is nearly always those rules.

### The checks at the end

- **`python3 selftest.py`** in the hub's checkout. On a clean hub every check passes:
  `127 of 127 checks passed` and no `FAILED:` line (the total grows when a lane adds a
  check; what counts is that nothing failed). Since 18 October 2026 the suite carries no
  standing failures, so **any** failure is real: send the line to the operator.
- **`GET /health`** from the server, which the installer makes: it names the agents the
  hub runs.
- **`GET /ui/state`** from the owner's Mac, which the claim line makes on that Mac. 200
  there is the real proof: that route answers the owner's address and no other.
- **The address line**, printed last. Paste it into the Founderizer window that waits for it: the app
  connects to the hub at once.

### This fleet's own id

`python3 hubsetup.py fleet-id` keeps sixteen random hex characters in the hub's key
store, under `fleet_id` — the same key and the same store the hub's own `fleet_id()`
reads and the app reads over `GET /ui/releases`. It identifies this fleet to us and says
nothing about its owner: no address, no name, no account (PRODUCT.md 4.2).

It is made **once and never again**, because a second id would orphan the fleet's
subscription, and a second run of the installer finds the one that is there. The step
comes after the end checks, because the hub writes its records when it starts.

**The installer claims no entitlement with it.** A claim key works once, so the claim has
exactly one caller and that is the app (PRODUCT.md 4.5): it reads the id from the hub,
calls the website, and posts the token back to `POST /ui/releases/entitlement`. Had both
claimed, the second would be refused and the customer would need a new key. So the
install ends at `verify`, and nothing of a subscription is in it.

### The last step: `verify`

`python3 fleet.py verify` (PRODUCT.md 4.1) runs as `fleet` from the hub's own checkout,
and the installer prints every line it answers:

```
  ok    services: The hub and the git service are running.
  ok    hub_answers: The hub answers at http://100.80.1.2:8765 for Manager.
  ok    owner_claimed: The owner of this hub is the Mac at 100.80.1.3
  ...
READY
```

An install that half worked therefore says which check failed and what fixes it, instead
of looking finished, and the line itself ends in failure, so the agent or the app that
ran it knows. A `warn` is not a failure. A new hub has no agent, so no check of it waits
for a sign-in: the manager's own server answers for the manager, and until the owner
signs it in there, that server's `runtime_signed_in` fails on purpose, because that is
the one step only they can take.

The same command is the right first question at any later moment, and the app shows the
same array as the owner's checklist.

## The sign-in, and renewing it

One thing is left after the install, and it is done in the app: **set up the manager
and sign in to your own Claude account.** The manager's page asks for its server first,
then its AI provider, and then for the sign-in, which happens on that server.

What happens, in order (UI-API.md, "Sign a machine in"):

1. The app asks the hub, which starts Claude Code's own sign-in in a window of its own
   on that machine.
2. Claude prints its sign-in link; the hub passes that link to the app.
3. You open it **in your own browser**, on your own Mac, and authenticate with
   Anthropic.
4. Anthropic gives you a code. You paste it into the app.
5. The hub hands it to that machine, which types it into the waiting sign-in. Claude's
   own client writes the credential there, on the machine it belongs to.

Nothing of that is stored by Founderizer. The link, the code and anything derived from them
live in the hub's memory only, for one reader, and are gone when they are used. No
long-lived token ever passes through Founderizer: `claude setup-token` and anything like it
is out of the question, because holding such a token is exactly what the operator may
not do.

**When the login expires you use the same button.** Expiry is recurring and only you
can answer it; nobody can renew it for you, and no part of Founderizer stores, copies or
refreshes it.

Codex works the same way, with its own device sign-in: the app shows you a link and a
code, you open the link and type that code into OpenAI's page, and nothing comes back
through the app. **Grok has no sign-in path at all**, in the app or anywhere else in
Founderizer: xAI's terms do not let a third party run it this way, and Founderizer refuses it in
code rather than leaving it to a rule nobody reads.

Then add your agents in the app: the + at the top of the sidebar, Add agent. Each one is
signed in the same way, on the server it runs on.

## Run it again, update, remove

The line is safe to run again. Each step checks first: a package that is installed is
left, the service user and the agents' own users are left as they are, a Tailscale
connection that is up is left, the repositories are left as they are, a `team.json` that
already names an owner makes no new code and is not touched, and the services are
written again and restarted. Nothing is destroyed. A second run also makes the user,
the checkout and the service of an agent that was added since.

- **The owner's Mac changed address.** Run the line with `--reclaim`: it makes a new
  code, waits for the new Mac, and changes only `addresses.owner`.
- **New code for the fleet.** This is a deployment, not an install: fetch, merge `main`
  into `config`, check `import hub`, push `config`, restart `fleet-hub` (COORDINATION.md,
  "The configuration ref"). The hub serves the new code to every machine from its own
  bare repository.
- **Remove the services** and keep everything else:

  ```sh
  runuser -u fleet -- systemctl --user disable --now fleet-hub fleet-git
  rm -f ~fleet/.config/systemd/user/fleet-hub.service ~fleet/.config/systemd/user/fleet-git.service
  runuser -u fleet -- systemctl --user daemon-reload
  ```

  Each agent's service belongs to that agent's own user, so it is stopped there, once for
  each agent of this machine:

  ```sh
  runuser -u fleet-manager -- systemctl --user disable --now fleet-manager
  rm -f ~fleet-manager/.config/systemd/user/fleet-manager.service
  runuser -u fleet-manager -- systemctl --user daemon-reload
  ```

  This keeps the repository, the records (`~fleet/.fleet/pilot.db`), the outputs, each
  agent's own checkout and its runtime sign-in.

## The central vault

One vault on the hub's machine holds every secret of the fleet, and each server's vault gets
only the secrets its agents hold and the owner signed for it (UI-API.md, versions 1.44 and
1.73). It is the one way a value reaches a server. It is not a step of the line above. It is
two root commands on the hub's machine, which the owner's app runs over the owner's own SSH:

```sh
sudo python3 /usr/local/lib/founderizer-kit/hubsetup.py kit-clone
sudo python3 /usr/local/lib/founderizer-kit/hubsetup.py central-vault --owner-key <the key the app gives>
```

**Root's own clone first.** The vault is installed as root, so it is never installed from a
folder that the hub's user can change, such as the hub's own checkout `~fleet/fleet-pilot`,
or from a path that the hub names. `kit-clone` keeps root's own clone of the published
repository in `/usr/local/lib/founderizer-kit`, owned by root and writable by nobody else,
at the revision of the release that the hub runs: the hub's `release.json` is that release's
signed manifest, and one of the release keys of the clone itself must have signed it. A
release that does not descend from the clone's own revision is refused, so no older release
comes back, and a second run with nothing new changes nothing. `--source` names another
copy of the published repository (default: `https://github.com/miguelpieras/founderizer-fleet.git`);
the signature names the commit, so it is the same commit from any copy. The first clone is
made once, as root, from the hub's own checkout (`sudo python3 ~fleet/fleet-pilot/hubsetup.py
kit-clone`), on the day the hub is trusted with its first signed release; every later run is
the clone's own. `central-vault` refuses to run from anywhere else.

`--hub-user` names the user the hub runs as (default `fleet`), and `--fleet` the fleet's id
(default: the one in the hub's own records, read and never written). `central-vault` makes:

- the user `founderizer-vault`: a system user with no login and no shell, and not a
  `fleet-*` name, because the hub's user can put a `fleet-*` user into the agents' group;
- `/usr/local/lib/fleet-vault-central/vault.py`: the clone's `vault.py`, owned by root,
  mode 644;
- `/etc/fleet-vault-central/vault.json`: its configuration, owned by root, mode 644, with
  no secret in it: the hub's uid, the fleet's id and the owner's public key;
- in `/var/lib/fleet-vault-central/` (mode 700, its user alone): its own key, which the
  owner's app seals new values to, the store's key, the store, and the owner's signed
  pins and grants that it keeps;
- `fleet-vault-central.service`, which runs it as its own user with the hub user's group,
  so the socket `/run/fleet-vault-central/vault.sock` (mode 660) opens to the hub and to
  nobody else, and the vault answers the hub's uid alone. It has no network.

Then it asks the vault for its status as the hub's user, and its last line is one JSON
object: `{"ok": true, "recipient", "store_recipient", "fleet"}`, or `{"ok": false,
"error"}` with a non-zero exit. It never prints a key file.

**Running the two again is how it is updated**: `kit-clone` takes the newer signed release,
and `central-vault` reads first in each step, starts the service again only when something
changed, and never replaces a key, the store or the owner's statements that are there. The
owner's key is the one exception: each run writes the key it is given as the only one, so a
run from a new Mac replaces the key of a lost one. Root on this machine is the owner's own
authority, and that is why this is a root step.

**The hub's user can neither read it nor replace its code.** Its files belong to root or
to its own user, and there is no sudoers line and no root helper for it: the hub asks its
socket, and that is all it can do. The vault seals a copy only to a machine key the owner
signed, only for a grant to an agent of that machine or a place in the grantable pool that
the owner signed, and its backup only to a recovery key the owner signed. So a hub that is
broken into can neither add a machine of its own nor send a secret to a machine that the
owner did not give it to.

## Not part of this installer

- **Worker push keys.** None. The separate push listener (`fleet-git-push`, port 9419)
  was retired on 25 October 2026 at the owner's word, and the tailnet no longer admits
  that port to the hub. A worker fetches but cannot push: its helper sends a delivered
  task's output to the hub on its usual port, and the hub commits it.
- **A vault broker**, which an agent needs before it can use a saved login
  (WORKER-INSTALL.md, "Vault broker"). The hub itself needs none: the manager holds no
  credential. A joined machine's broker is installed by its own join line and brought onto
  each release by its own server service, through the root command of step 8; `/ui/health`
  raises `vault_behind` only for a machine where that could not happen
  (WORKER-INSTALL.md, "When a release changes vault.py").
- **The apps.** The Mac app and the iPhone app are installed on the owner's own
  machines, not here.
- **Backups.** The records are `~fleet/.fleet/pilot.db` and the repository is
  `~fleet/fleet-pilot.git`; the owner decides how they are kept.

## The test

`python3 -m unittest test_hub_install.py test_join_install.py` proves both installers
— with `test_agent_users.py` for the per-agent user, the root helper and the agent-add
path — without touching a machine: the first `team.json` is one the hub can run and holds no
credential, the claim takes one code once and refuses the rest, the hub's own repository
is made for real in a temporary folder with both refs at the right commit, `hub.sh
--check` names its fifteen steps in order and changes nothing, this fleet's id is made
once and never twice and the installers claim no entitlement, the per-agent user is
made for the agents of the right machine and for no other and a second run changes
nothing, both installers end in `verify` and end in failure when a check failed,
`INSTALL-PROMPT.md` carries its refusals in writing and names no command the installers
do not take, and `create_login`, `save_key` and `sign_in` refuse a model provider's own
site.

What a test cannot reach, a container can. On 17 October 2026 this was run on a real
Ubuntu 24.04 with systemd: `hub.sh --check` named all its steps; `hubsetup.py
agent-users` made the users of two agents for real, with locked passwords, no sudo,
lingering, and homes of mode 700 that one agent could not read from the other's user; a
second run changed nothing, and a home that had been opened to other users was closed
again; and `verify`, run through `runuser` as the service user, printed its lines and
made the installer's own line end in failure. The move of each agent's session into its
own user was proved the same way, by the lane that made it (PRODUCT.md, "What the move to
per-agent users decided"). What stays unproved until a real server runs it: `apt-get`,
`tailscale up`, `ufw`, the systemd user services and the claim, because a container has
no tailnet and makes no `/run/user/<uid>` — which step 11 waits for, so the whole line
has still never run to its end on a machine.

On 5 November 2026 it did, on new servers, from the published tree and with the app's own
steps: `hub.sh` ended READY on Debian 13 (Python 3.13) and on Ubuntu 26.04 (Python 3.14,
sudo-rs, chrony), each claimed from another machine of the network, and a Debian 13 server
joined the Debian 13 hub with the hub's own line, ended READY, and then installed the
manager as its own user, up to the owner's sign-in. The network was Tailscale with a test
control server, not the owner's tailnet.
