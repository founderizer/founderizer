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
with one line, or a Mac) and the sign-in (UI-API.md 1.82). The app's first run asks for
its AI provider before the servers, and the setup gives the server and that provider in
one command. With two servers or one for each agent, the first run's one press makes the
manager's server too, right after the hub's server is on the private network, and the
setup installs that server with no second press. Each agent installs only its own AI, on
its own server.

**One server for all is one word.** With `FLEET_HUB_SERVER=shared` in the installer's
environment, the manager runs on the hub's server (with `--runtime codex` it runs Codex
there; the default is Claude Code), and the owner can add each later agent
on that server too, each under its own OS user. The first `team.json` then says
`"hub": {"shared": true}` (UI-API.md 1.168 and 1.171), and two more steps give this server
what a joined server gets from its join:

- After "One OS user for each agent", **this server's own vault broker**
  (`fleet-vault.service` of the user `fleet-vault`, `hubsetup.py vault`), before the first
  agent of this server starts. The hub gives each worker there its vault by itself when
  the broker has reported, as on a joined server.
- After "This fleet's own id", **this server's own server service**:
  `fleet-server.service` of the user `fleet`, from its own clone
  `/home/fleet/fleet-server`, with the SHA-256 of its key in the hub's records
  (`hubsetup.py hub-server`). That service installs each later agent as a joined
  server's service does.

An agent that breaks out of its account there can reach every key of the fleet. The word
counts at a hub's first install, and it does not go with `FLEET_MANAGER_SERVER=later`.
Without it the steps are the seventeen below, and no new agent goes onto the hub's server.
Founderizer gives the word since version 0.1.249, when the owner chooses "1 server" on the
first run's page "Your fleet's servers" (the owner approved this layout on 14 November
2026). With `FLEET_SHAPE_STEP=one`, `two` or `each` the first `team.json` also keeps the
step that the owner chose on that slider (`"shape": {"step"}`, UI-API.md 1.176);
`FLEET_SHAPE_STEP=one` is `FLEET_HUB_SERVER=shared`, and that word alone keeps the step
`one`. Both are words of a hub's first install. A fleet that runs changes to one server
by the owner's command and one root step on the hub's server, from root's own clone, which
`hubsetup.py kit-clone` brings to the hub's release first: `python3
/usr/local/lib/founderizer-kit/hubsetup.py one-server`. It makes this server's vault broker
and its server service and restarts no service of the hub. Founderizer does both from the
manager's setup of a fleet that exists, on a hub that has them.

What such a fleet does not have: **a door**. The hub knows the door's own calls by the
door's address alone, and each agent on the hub's server calls from the hub's address. So
a fleet whose hub's server takes agents has its door on a server of its own or has none,
and with no door no agent of it holds a server for apps, a deploy key or a GitOps
repository through the door. A restore of a copy keeps this server's own records: of its
server service, of the keys of the agents that the server has, and of its vault's store
(UI-API.md 1.171). So after a restore on the server that the copy came from, the same line
does not have to run again. On another server, an agent that only the lost server had is
not installed: the same line again installs it, and UI-API.md 1.171 says what its key then
needs. A real server ran the install on 15 November 2026 (Ubuntu 24.04, 2
vCPU, 4 GB): UI-API.md 1.171 says what it proved.

## Before you run it

1. **A server.** Ubuntu 22.04, 24.04 or 26.04, or Debian 12 or 13, with systemd, and
   root. A €5 VPS is enough to start. Nothing else may be using port 8765. It must
   reach github.com over HTTPS, where the hub takes its releases. GitHub answers over
   IPv4 only, so a server with IPv6 only needs a public IPv4 address. The install's
   first step checks it, and a first install stops on a server that cannot reach it.
   A server can also lose the IPv4 address that its provider gives it, when systemd-networkd
   cannot renew it (a hub did, on 16 November 2026). Then the first step sets each link that
   systemd-networkd marks failed up again, and reads the route for up to 60 seconds. When the
   route comes back, the step asks github.com again. When it does not come back, the stop
   tells you to restart the server first, not to add an address. The app's install stops
   earlier on any server with no IPv4 route, because it checks the server first. On a new
   server, the install prompt also stops earlier, because it clones the code first. So this
   repair runs when a person runs the line on the server, from a copy that is there already:
   a second run, `--reclaim`, or a first run from a copy.
2. **A Tailscale auth key** for the fleet's own tailnet, from its Tailscale admin
   console. One use is enough; a pre-authorized key saves a sign-in. The key goes to
   the installer on **standard input**, so run the line in a terminal on the server,
   not through a pipe. It never becomes a command argument or part of a URL.
3. **A copy of this repository on the server**, with its history. The hub's own
   repository is made from that copy, so a folder of loose files is not enough:

   ```sh
   rsync -a --exclude .claude ~/founderizer/ root@<server>:/root/fleet-kit/
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
sh hub.sh --source https://github.com/founderizer/founderizer.git
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
(default 1800), `--manager-name NAME` for the manager's own name in a new fleet, and `--reclaim`, for a hub that
has an owner ("The owner's Mac is lost, or it has a new address", below).

`--manager-name`: without it the manager is named `manager`. A name has 2 to 26 characters a-z 0-9 -, starts
with a letter, and is none of the names that the fleet uses itself (owner, hub, agents, channels, chats, checks,
git, pilot, server, vault, watch, work, and each name that starts with login- or vault-). A hub that is there
keeps the name that its manager has, and nobody can rename the manager afterwards. **Use it only with an app that finds the manager by its role.** The Founderizer apps of
14 November 2026 (Founderizer for Mac 0.1.227) find the manager by the name `manager` in some places (the
notification of a Needs-you item, the chat that opens first), so with those apps leave the option out.

### What the seventeen steps do

1. **This server and this copy of Founderizer.** Root, the system, systemd, that the
   copy is a Founderizer checkout with a commit, and that the server reaches the address
   that the hub takes its releases from (github.com) over HTTPS. When it does not, the address
   is on github.com, and the server has no IPv4 route, the step sets each link that
   systemd-networkd marks failed up again (`networkctl reconfigure`), reads the route at 10, 30
   and 60 seconds, and asks github.com again when the route is back.
2. **Base packages:** `git tmux python3 curl ca-certificates ufw unattended-upgrades sudo tzdata libatomic1`.
3. **The user `fleet`:** created, password locked, out of `sudo`, `admin` and `wheel`,
   home mode 700, and lingering on, so its services run after logout and after a
   restart. It runs the hub and the git daemon, and no agent's session: each agent has
   its own user (step 9). Nothing of Founderizer runs as root.
4. **The private network.** Tailscale from its own installer when the server has none
   (`curl -fsSL https://tailscale.com/install.sh | sh`, the vendor's own script, which is what
   the hub's join line uses for a server too). That script does not wait for apt's lock, which
   the first updates of a new server hold, so the step waits up to 20 minutes for the lock before
   each try of the script, and tries three times at most;
   then `tailscale up --reset --auth-key=file:<a root-only file> --accept-dns=false --timeout=300s`
   (with `--hostname NAME` only when it is given). `--reset` removes the settings that an earlier
   `tailscale up` left, for example a join line that waited for a sign-in: Tailscale refuses each
   new try that does not name them again. With no `--timeout`, `tailscale up` waits for ever on a
   tailnet that approves each new machine by hand. This hub's address is what `tailscale ip -4`
   then gives.
5. **The firewall** (`ufw`, `hubsetup.py firewall`): incoming traffic on `tailscale0` only,
   SSH included, outgoing allowed. SSH is open to the internet no more, so after this step SSH
   reaches the server at its Tailscale address only. A firewall that was off keeps open each
   port that answered from the internet before the install (a website on that server stays up),
   with the comment `fleet kept`. It comes before the claim, because the
   owner's Mac must reach port 8765 while the install still runs. A firewall that is already
   active keeps its own rules, and loses only the public SSH rule (`fleet ssh`) that an
   installer before 2 November 2026 added. The step changes nothing on a server that is not
   on the private network: `tailscale ip -4` must give an address, and `tailscale status` must
   succeed. A server that waits for an admin to approve it in Tailscale has an address
   already, but nothing on the private network reaches it. On such a server the step stops,
   and the server keeps its public SSH.
6. **The Founderizer repository on this hub.** `~fleet/founderizer.git` is the bare
   repository and the origin of the whole fleet: `fleet-git` serves it read-only over
   `git://`, and every worker and joined server fetches its code from it.
   `~fleet/founderizer` is the hub's own checkout and it stands on `config`, the
   configuration ref — the branch the hub writes and nothing else writes (`config-ref.sh`,
   its first lines). Both refs start at the commit of the copy you ran, so the
   code the hub serves is the code it runs. For a hub that this install makes (step 3
   made the user `fleet` itself), the step also makes root's own clone of that code in
   `/usr/local/lib/founderizer-kit` (`hubsetup.py kit-clone --first`, from the copy you
   ran; below, "Who makes the first clone"): the steps that Founderizer runs as root on
   this server run from it. It needs a copy that root alone can write, as
   `/root/fleet-kit` is. From any other copy the step says so and the install goes on,
   because the hub works without the clone. On any other hub the step runs `kit-clone`
   with no `--first`, which takes the hub's signed release and makes no clone without
   one. **A hub made before the name `founderizer`** has the name `fleet-pilot` for its
   repository and its checkout, and a second run of the installer keeps that name: on such
   a hub, read `fleet-pilot` wherever this document names `~fleet/founderizer`. Nothing else
   holds the name: the hub gives its machines the address of its repository (the join
   answer, the join script and `GET /ui/state`), and `fleet-git` serves the origin of the
   hub's checkout.
7. **The first `team.json`, and the owner's own Mac.** One manager on this machine, or,
   when the app that starts the install gives the manager its own server
   (`FLEET_MANAGER_SERVER=later`, Founderizer 0.1.112 and later), one manager with no
   server yet (`"placed": false`: its `machine` names this machine only until its setup
   gives it one); this machine's address, `"vault": "none"`, and no credential of any kind.
   Then the claim, below. The file is committed on `config` and pushed to the hub's own
   repository, so the record starts at the first minute. With `--manager-name NAME` the
   manager's entry has that name, and the same commit moves the published profile
   `profiles/manager.md` to `profiles/NAME.md` with that name in its title line: the hub
   and the manager's own helper read an agent's profile by the agent's name. The name is
   also in the manager's OS user, its checkout and its service (`fleet-NAME`).
8. **The two root commands of this machine**, below:
   `/usr/local/sbin/fleet-agent-user`, `/usr/local/sbin/fleet-vault-program` and
   `/etc/sudoers.d/fleet-agents`.
9. **One OS user for each agent of this machine**, below.
10. **The services** `fleet-hub`, `fleet-git` and `fleet-channels` (the chat apps
    bridge), as systemd user services of `fleet`,
    enabled and started. No agent's service is here any more: each one belongs to its
    own user, in the next step.

    The hub's unit starts the hub as a module in the folder of its code
    (`python3 -m hub`). A hub that starts so holds about 135 MB less memory than a hub
    that starts by its path. The unit also has `OOMPolicy=continue`: the hub keeps
    running when the system ends a check of a release for lack of memory. The code
    writes the unit's text (`lifecycle.hub_unit`).

    A hub that an earlier release installed needs no second run of this installer. At
    its start, the hub looks at its unit's file. If the file still has the text of an
    earlier release, the hub first tests the new start line. If the test passes, the hub
    writes the unit again, and its service starts one more time. If the test fails, the
    hub does not change the file.

    The hub does not change a unit that you changed: a file with a text of your own, a
    unit with a drop-in file of its own (for example in
    `~/.config/systemd/user/fleet-hub.service.d/`), a unit that is a link, and a unit
    that systemd reads from another file. The hub's log says so at each start. Such a
    hub keeps its unit until you write the unit again. The command replaces the unit's
    file, so keep a setting of your own in a drop-in file. Run these two lines as root
    (the hub's own line in its log gives them, as one line, with this server's values):

    ```
    runuser -u fleet -- env XDG_RUNTIME_DIR=/run/user/$(id -u fleet) python3 /home/fleet/founderizer/fleet.py service hub
    runuser -u fleet -- env XDG_RUNTIME_DIR=/run/user/$(id -u fleet) systemctl --user restart fleet-hub
    ```

    Do this again after a release that changes the unit: with a drop-in file, the hub
    does not write its unit by itself.
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
15. **This server's own hardening** (`hubsetup.py harden`), the same as each server that joins
    gets from its join line. SSH takes keys only, with no X11 forwarding: one file in sshd's own
    folder, which sshd checks before it reloads. It is not written where no account of the server
    has an SSH key, because that server would then let nobody in, and not where OpenSSH does not
    run. It is not written either when the session that runs the step logged in over SSH with a
    password, as sshd's own line for that session in the journal says: the key that the server
    holds can be one that this person does not hold, such as the provider's key of the server's
    creation, and the step's line then says to log in with an SSH key and run it again. Where
    sshd's own files take keys only already, the line says so instead, and tells that person to
    add a key of their own to `authorized_keys` before they log out. A session that logged in
    with a key, and the server's console, take the step. sshd also checks its files once before
    the write: a server whose own files already fail that check gets no file, and the step's line
    gives sshd's words. npm takes no package version newer than seven days, for every user and
    for `fleet`, each where no such rule is. Tailscale updates itself. The server's memory gets
    a reserve and a limit: a swap file (`/swapfile`, as large as the memory, 4 GiB at most)
    where the server has no swap, and one limit for all users' processes together, of 85% of
    the memory and of swap as much as half of the memory
    (`/etc/systemd/system/user.slice.d/00-fleet-memory.conf`). The agents' sessions, the hub
    and the fleet's other services and each login are in that group; when it is full, the
    kernel ends the largest process of an agent's session first (from the helper's start,
    each helper gives the sessions that it starts a higher score than the fleet's own
    services), and SSH and Tailscale, which are not in it, keep the rest, so the server
    still takes a login. A server that has swap, or a limit of its own, keeps it. The server
    also restarts by itself when it stops: 10 seconds after a kernel panic
    (`/etc/sysctl.d/60-fleet-restart.conf`, `kernel.panic = 10`, where Ubuntu waits forever),
    and when systemd stops for 10 minutes, by the kernel's software watchdog
    (`/etc/systemd/system/fleet-watchdog.service` loads `softdog` at each start, because
    Ubuntu keeps it from loading by itself, and `/etc/systemd/system.conf.d/00-fleet-watchdog.conf`
    has systemd ping it). A server that sets `kernel.panic` or `RuntimeWatchdogSec` itself (in a
    file, as a link at one of these files, or at its boot), or that has a watchdog of its own,
    keeps that, and a container gets neither part. Each part
    says what it did, a part that cannot be done leaves the server as it was, and none of
    them stops the install. Until 14 November 2026 only the join had this step. A second
    claim (`--reclaim`) leaves it out.
16. **A kept connection keeps its speed** (`hubsetup.py tcp`). The Mac app reads the hub's
    state every 3 seconds on one kept connection, and after a pause Linux starts each answer
    from a window of 10 packets again: a state of 474 KB took 6 round trips (0.29 s at a round
    trip of 56 ms). `/etc/sysctl.d/60-fleet-hub-tcp.conf` sets
    `net.ipv4.tcp_slow_start_after_idle = 0`, and the step sets that value at once too, so an
    answer takes one round trip (0.06 s). A file of the server's own that sets the value keeps
    it, and the step then writes nothing. It never stops the install.
17. **`verify`**, below: the last step says whether this machine is healthy, and the
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
  delivers (RULES.md, "Where work goes", for a task's output).
- **`verify` reads each agent as its own user** (PRODUCT.md 4.1 keeps its check ids; a
  reading it cannot take warns), which is why the root helper of step 8 exists.

A Mac runs one agent (10 November 2026): a Mac agent's service is a LaunchAgent of the desktop
session, so every agent there would run as the desktop account, and each could act as the others.
The desktop account of a Mac that joins the fleet belongs to that one agent: no person keeps files
or logins in it. More agents go to Linux servers, where each has its own user.

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

In Founderizer the owner is one computer: its private-network address and, after that
computer registered its key with the hub, that key too (`hub.py`, `allowed("owner")`;
SECURITY.md, "How the hub knows the owner's computer"). A hub that holds no key of the
owner's computer yet keeps the address rule alone. A hub with the wrong
`addresses.owner` would serve the owner's
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
waits. The hub's own address cannot claim it. One connection gets 20 seconds in all, so a
machine that sends nothing, or a byte now and then, cannot hold the claim open. If nothing claims it in time, nothing is
written and the line can be run again for a new code.

Because the claim listens on the hub's own address and port, it also proves the fleet's
Tailscale access rules for port 8765 before the hub exists. A claim that never arrives
is nearly always those rules.

A second claim finds a hub that runs, and that hub holds the address and port. The claim
then stops the hub's service for its own time and starts it again in every case: "The
owner's Mac is lost, or it has a new address", below.

### The checks at the end

- **`python3 selftest.py`** in the hub's checkout. On a clean hub every check passes:
  `127 of 127 checks passed` and no `FAILED:` line (the total grows when a lane adds a
  check; what counts is that nothing failed). Since 18 October 2026 the suite carries no
  standing failures, so **any** failure is real: send the line to the operator.
- **`GET /health`** from the server, which the installer makes: it names the agents the
  hub runs. A hub listens only at the end of its start, so the installer reads it until the
  hub's first answer: up to 120 times, a second apart.
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
and sign in to your own account.** The app's first run asked for the manager's AI provider
already. With two servers or one for each agent, the manager's page installs the server
that the first run made for it (or asks for one, when there is none), and then asks for
the sign-in, which happens on that server; with one server, it asks for the sign-in alone.

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

- **A hub installed before step 16 existed** (10 November 2026) gets it as root, from root's
  own clone of the release (below, "The central vault"), never from the hub user's checkout:

  ```sh
  sudo python3 /usr/local/lib/founderizer-kit/hubsetup.py kit-clone
  sudo python3 /usr/local/lib/founderizer-kit/hubsetup.py tcp
  ```

  The first takes the hub's signed release into that clone, and `tcp --check` says what the
  second would do. A release runs no root code, so no release does it. To undo it: delete
  `/etc/sysctl.d/60-fleet-hub-tcp.conf`, then `sysctl -w net.ipv4.tcp_slow_start_after_idle=1`.
  Both act on the next answer of a connection that is open; nothing restarts.
- **A hub installed before step 15 existed** (14 November 2026) gets it the same way, as root:

  ```sh
  sudo python3 /usr/local/lib/founderizer-kit/hubsetup.py kit-clone
  sudo python3 /usr/local/lib/founderizer-kit/hubsetup.py harden --user fleet
  ```

  `harden --check` says what the second would do. It prints one line for SSH, one for npm, one
  for Tailscale, one for swap, one for the memory limit, one for the restart after a kernel
  panic and one for the watchdog. A session that is open keeps going. Run them from an SSH session that logged
  in with a key, or in the provider's console: from a session that logged in with a password, SSH
  keeps password login, and its line says so; where SSH takes keys only already, the line tells
  you to add a key of your own before you log out. To undo the SSH part: delete
  `/etc/ssh/sshd_config.d/10-fleet-hardening.conf`, then `systemctl reload ssh`. To undo the
  memory limit: delete `/etc/systemd/system/user.slice.d/00-fleet-memory.conf`, then
  `systemctl daemon-reload`. To undo the swap file: `swapoff /swapfile`, delete `/swapfile`,
  its line in `/etc/fstab` and `/etc/sysctl.d/60-fleet-swap.conf`, then
  `sysctl -w vm.swappiness=60`. To undo the restart after a panic: delete
  `/etc/sysctl.d/60-fleet-restart.conf`, then `sysctl -w kernel.panic=0`. To undo the
  watchdog: `systemctl disable fleet-watchdog.service`, delete its file and
  `/etc/systemd/system.conf.d/00-fleet-watchdog.conf`, then `systemctl daemon-reload`.
- **The owner's Mac is lost, or it has a new address.** Run the line with `--reclaim`: it
  makes a new code, waits for the new Mac, and changes only `addresses.owner` and the key
  of the owner's Mac. The hub is away for the time of the claim; the part below says what
  happens.
- **The owner's Mac has no key for the hub, or lost it.** The hub knows the owner's Mac by
  its address and by a key that the Mac made (`owner-key.json` beside the hub's records
  holds its SHA-256; SECURITY.md, "How the hub knows the owner's computer"). Founderizer
  registers the key by itself over its SSH connection to this server. A Mac that has no
  such connection gets its key with the same line, `--reclaim`: the Mac that sends the code
  back makes a new key and sends its SHA-256 with the code.
- **New code for the fleet.** This is a release, not an install, and never a merge by
  hand: new code comes only as a signed release. The hub asks the release channel and
  checks the release against its release keys. It merges and tests the release in a
  temporary clone, moves `config` to the result (`releases.py`) and, when the release
  changed the code, restarts itself. It does so by itself, or when the owner takes the
  release (the tool `take_release` of the owner MCP server). Each machine
  refuses a commit that changes the code and carries no signed release (`lifecycle.py`,
  `may_take`). The hub serves the new code to every machine from its own bare repository.
- **Remove the services** and keep everything else:

  ```sh
  runuser -u fleet -- systemctl --user disable --now fleet-hub fleet-git fleet-channels
  rm -f ~fleet/.config/systemd/user/fleet-hub.service ~fleet/.config/systemd/user/fleet-git.service ~fleet/.config/systemd/user/fleet-channels.service
  runuser -u fleet -- systemctl --user daemon-reload
  ```

  Each agent's service belongs to that agent's own user, so it is stopped there, once for
  each agent of this machine. These lines are for a manager named `manager`; a manager with
  another name has that name in its place (`fleet-<name>`):

  ```sh
  runuser -u fleet-manager -- systemctl --user disable --now fleet-manager
  rm -f ~fleet-manager/.config/systemd/user/fleet-manager.service
  runuser -u fleet-manager -- systemctl --user daemon-reload
  ```

  This keeps the repository, the records (`~fleet/.fleet/pilot.db`), the outputs, each
  agent's own checkout and its runtime sign-in.

### The owner's Mac is lost, or it has a new address

The hub serves the owner's pages to one address, `addresses.owner`. A new Mac, or the same
Mac with a new address, gets `403` from each of them, and only root on the hub's server
changes that address: with a second claim.

**A lost Mac comes off the fleet's Tailscale network first**, in the network's admin console.
Until the claim, that Mac is the owner for the hub, and like every machine of the network it
reaches the hub's port.

Then run the line with `--reclaim`, as root, and with the `--port` of the install when the
hub does not listen on 8765. A hub whose SSH takes keys only (step 15) lets nobody in with a
password: reach root with an SSH key that the server holds, or in the console of its provider.
A second claim leaves step 15 out, so it never turns password login off on a hub from before:

```sh
sh /root/fleet-kit/hub.sh --reclaim
```

It prints a claim line, as the first install did. Run that line in Terminal on the Mac that
owns the fleet from now on. The address of that call becomes `addresses.owner`, nothing else
in `team.json` changes, and the change is one commit on `config`, "The owner of this hub is
another Mac".

**The hub is away for the time of the claim**, so have the new Mac ready before you run the
line. The claim listens on the hub's own address and port, and the hub that runs holds them.
So the claim stops the service `fleet-hub`, waits for the Mac, writes and commits
`team.json`, and starts `fleet-hub` again. The hub reads `team.json` at its start: from then
on it serves the owner's pages to the new address and refuses the address from before. While
the hub is away, every other call to its port gets `503` from the claim, as from a hub that
does not answer: each server's helper tries again by itself, and work that needs the hub in
that time waits or fails with its reason. The records stay. Until 10 November 2026 a second
claim on a hub that runs ended with "Address already in use" before it printed its line.

**The hub starts again in every case:** when the Mac claimed it; when no Mac claimed it in
time, and then nothing is written, the address from before keeps the hub, and the line can be
run again for a new code; when a step failed; when the claim was ended from outside (Ctrl-C,
a terminal that closed, a kill); and when the claim's own program was killed with no warning,
because a small guard of the claim then starts the hub. The claim says so when the hub
answers again. Should `fleet-hub` ever stay stopped all the same, start it:

```sh
runuser -u fleet -- env XDG_RUNTIME_DIR=/run/user/$(id -u fleet) systemctl --user start fleet-hub
```

A hub that somebody stopped before the claim is not started by it: the claim then finds the
port free, as a first claim does, and whoever stopped the hub starts it.

**What the claim refuses.** In each of these cases it prints no claim line, stops nothing
and changes nothing:

- `team.json` is not the file of a hub at this address and port that has an owner: it names
  another port or address, or the hub cannot run it. A claim would write a new first
  `team.json` over the team of a fleet. Give the `--port` of the install;
- the port is in use and the `fleet-hub` of the hub's own user does not run, so another
  program holds the port;
- the hub is in the middle of a write or a release of its own, so its configuration ref holds
  a commit that its checkout does not have yet. Run the line again in a few minutes.

A claim that cannot commit or push its change takes it back: `team.json` is as it was, and
the hub starts on what it ran before.

**It changes the owner's address and the key of the owner's Mac, and nothing else.** The Mac
that sends the code back makes a new key and sends its SHA-256 with the code, and the claim
writes it beside the hub's records (`~fleet/.fleet/owner-key.json`) in place of the key of the
Mac from before. A Mac whose program is from before the key sends none: the claim then takes
the old key away, and the hub knows the new Mac by its address until Founderizer on it
registers a key. A claim that fails and takes `team.json` back leaves the key as it found it
too. An enrolled phone keeps its access,
because it has an address and a key of its own. The central vault keeps the owner key of the
Mac from before until a `central-vault` run from the new Mac replaces it ("The central
vault", below).

**The claim always runs from the hub's own checkout** (`~fleet/founderizer/hubsetup.py`),
which follows the fleet's releases, so an old copy in `/root/fleet-kit` gets all of the above
too. The other steps of the line run from that copy, as in every second run, so bring it up
to date first when it is old.

**The claim alone**, with no other step of the installer, as root:

```sh
cd /home/fleet && runuser -u fleet -- env HOME=/home/fleet python3 founderizer/hubsetup.py claim \
    --reclaim --commit --address "$(tailscale ip -4 | head -n 1)" --out /home/fleet/founderizer/team.json
```

On a hub made before the name `founderizer`, write `fleet-pilot` in place of it in both places.

It needs nothing afterwards, and no restart of `fleet-hub`: the claim starts the hub itself,
after its commit. Three things it does need:

- **the hub's own user**, as `runuser` gives it here: `fleet-hub` is a service of that user,
  and the checkout is that user's. As root without `runuser`, the claim finds a port that is
  in use and no service of root's that holds it, and says so;
- **`--commit`**: a hub refuses every write while its checkout has a change that is not
  committed, so on a hub that runs the claim refuses to go on without it;
- **the hub's own address and port** (`--port N` when it is not 8765), as `team.json` has
  them: they are how the claim knows that the file is this hub's own.

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
folder that the hub's user can change, such as the hub's own checkout `~fleet/founderizer`,
or from a path that the hub names. `kit-clone` keeps root's own clone of the published
repository in `/usr/local/lib/founderizer-kit`, owned by root and writable by nobody else,
at the revision of the release that the hub runs: the hub's `release.json` is that release's
signed manifest, and one of the release keys of the clone itself must have signed it. A
release that does not descend from the clone's own revision is refused, so no older release
comes back, and a second run with nothing new changes nothing. `--source` names another
copy of the published repository (default: `https://github.com/founderizer/founderizer.git`);
the signature names the commit, so it is the same commit from any copy. `kit-clone` reads
the hub's `release.json` in the hub's checkout, which it finds as `~fleet/founderizer` or as
`~fleet/fleet-pilot`, and it follows no link to it. `central-vault` refuses to run from
anywhere else.

**Who makes the first clone** (since 15 November 2026; before that day nothing made it, and
each root step of the app stopped on a new hub at its first command). A new hub runs the
code of its installer and has no `release.json`: the hub writes one with the first release
that it takes, and the public source gives a new hub code that its channel offers only
later. So the first clone comes from the installer's own tree, `/root/fleet-kit`, and
never from the hub's checkout:

- **The installer makes it, for a hub that it makes itself and for no other**, in its
  step of the repository: `python3 /root/fleet-kit/hubsetup.py kit-clone --first`. It
  gives `--first` only when its own step made the user `fleet` in this install, and
  neither the hub's repository nor its checkout is there yet. A mark in root's own folder
  (`/root/.founderizer-new-hub`) says the first: the step of the user writes it when it
  makes the user with a new home folder, and the step of the repository takes it away
  before the installer runs anything as that user. So the installer has run nothing as
  the hub's user then, and that user has no file of its own that could run: "this hub has
  no release" is what root itself knows, not something that the hub's user shows. The two
  folders alone would not say it: they are that user's, which can move them away. With
  the word, and with no
  `release.json` and no clone, `kit-clone` puts the clone at the commit of the tree that
  it runs from. It does that only from a tree that is root's alone: root owns it,
  everything in it and each folder above it, no group or other user can write any of
  them, and nothing in it is a link. It takes nothing from the network and nothing from
  the hub's user, and that commit is the code that root runs as root in that same run.
- **Without the word, a run with no `release.json` makes no first clone.** A command by
  hand, a later run of the installer and the app's own steps stop there, as before, with
  "the hub's checkout ... carries no release.json that can be read".
- **While the hub has taken no release, a clone that is there stays at its commit**:
  `kit-clone` from the clone ends well, so the app's steps run. On a new hub that commit
  is the hub's own code. A clone whose files are not its commit's gets them again from
  its own objects.
- **From the hub's first release on, the rule above holds with no exception**: the clone
  moves only to a release that a key of its own files signed, and only forward. A hub's
  user that takes its `release.json` away gets a clone that stays where it is, as it gets
  today with the manifest of the release that the clone is at. It never gets an older
  revision, and it never gets its own code run. A `release.json` that is there and that no
  release key signed, or that is not a plain file, stops `kit-clone` as before.
- **A hub that was installed before that day** has no clone. One command makes it, as
  root, from the installer's tree and never from the hub's checkout: `python3
  /root/fleet-kit/hubsetup.py kit-clone`. It makes the clone only when the hub has a
  `release.json`, at that signed release, and with the release keys of root's own tree.
  Until such a hub takes its first release, the command stops with the words above. A
  real server proved both on 15 November 2026, with the installer of 2026.11.493. A hub
  with no `/root/fleet-kit` either gets its installer's copy again with the install's own
  first lines (INSTALL-PROMPT.md, A2). Founderizer runs that command by itself, as the
  first command of each root step, where the clone has no `hubsetup.py` and
  `/root/fleet-kit` has one (the Mac app after version 0.1.261). An app from before stops
  there at its first command: "python3: can't open file".

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
owner's app runs them again by itself when the program that the vault runs is not the
`vault.py` of the hub's release (UI-API.md, version 1.87). In root's clone of a hub installed
before the key change of 4 November 2026, which has no `early-key.pub`, it first writes its own
release keys into `release-key.pub`, so that the clone's own `kit-clone` can check the release. The
owner's key is the one exception: each run writes the key it is given as the only one, so a
run from a new Mac replaces the key of a lost one. Root on this machine is the owner's own
authority, and that is why this is a root step.

**The hub's user can neither read it nor replace its code.** Its files belong to root or
to its own user, and there is no sudoers line and no root helper for it: the hub asks its
socket, and that is all it can do. The vault seals a copy only to a machine key the owner
signed, only for a grant to an agent of that machine or a place in the grantable pool that
the owner signed, and its backup only to a recovery key the owner signed. So a hub that is
broken into cannot add a machine of its own, and it can send a secret only to a machine whose
key the owner pinned: the machine of a grant is the one that the hub names for the agent at
the moment of the Give (VAULT.md, limit 23). It removes a value that the owner took out of the fleet only
while no grant or pool that the owner signed names it, so the hub cannot take away a secret
that the owner gives, and it takes no value under a removed name again (UI-API.md, version 1.86).

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
  `~fleet/founderizer.git`; the owner decides how they are kept. The hub puts the
  records in WAL mode when it starts: the newest commits can be in `pilot.db-wal`
  beside them, so a copy of `pilot.db` alone can lack them. The app's copy of the
  fleet has them all, and so does `sqlite3 ~fleet/.fleet/pilot.db ".backup <file>"`.

## The test

`python3 -m unittest discover -s tests -p test_hub_install.py`, and the same with
`test_join_install.py`, from the top folder of this repository, prove both installers
— with `test_agent_users.py` for the per-agent user, the root helper and the agent-add
path — without touching a machine: the first `team.json` is one the hub can run and holds no
credential, the claim takes one code once and refuses the rest, a second claim on a hub
that runs stops the hub for its time and starts it again in every case (on the new owner,
when no Mac claimed, and when the claim was ended from outside) and stops nothing that it
must not, the hub's own repository
is made for real in a temporary folder with both refs at the right commit, `hub.sh
--check` names its seventeen steps in order and changes nothing, this fleet's id is made
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

On 10 November 2026 the second claim was run in a Linux container without a network (Debian
12, Python 3.11, git 2.39), from a copy of the tree with one line of `fleet.py` changed (the
next paragraph says why). That container has no systemd, so a
stand-in ran `fleet-hub` from the unit file that `fleet.py service hub` wrote, with the
unit's own stop rule. Everything else was the installer's own: the steps `preflight`,
`hub_user`, `repository`, `first_team` and `services` of `hub.sh` as root, the hub as
`fleet`, `runuser`, and git. One address claimed the new hub. Then `first_team` and
`services` ran again with `--reclaim` while the hub ran, and a second address claimed it:
before, `GET /ui/state` answered 200 to the first address and 403 to the second; after the
`services` step, 403 to the first and 200 to the second, with one commit on `config`. The
claim alone gave the same with no restart after it. A claim that no Mac answered, a kill of
the claim and of its `runuser`, a `kill -9` of the claim, Ctrl-C, and a terminal that closed
each left the hub running for the owner from before, with nothing written. On the code from
before, the same container showed the fault: `OSError: [Errno 98] Address already in use`.
What that run did not reach: systemd itself (`systemctl --user` of a real user manager), Tailscale, and a real Mac.

The changed line: from 20 October to 16 November 2026 `fleet.py` did not parse on a Python
before 3.12, because one f-string had a backslash inside its braces. In that container the
step `services` stopped there with a SyntaxError, so the run went on with a copy that had
the line with no backslash. The tree itself has it so since 16 November 2026. On that day
each published Python file compiled, and `selftest.py` passed, with the `python3` of Debian
12 (3.11) and of Ubuntu 22.04 (3.10), each in a container; the Ubuntu container needed the
package `tzdata` first, because its image has no time zone data and the hub reads the zone
UTC. Since then each release is checked, before it goes out, for the forms of an f-string
and of a statement that Python 3.10 does not take, the installers install `tzdata`, and a
hub with no zone data still reads UTC.
