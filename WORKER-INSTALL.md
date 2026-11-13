# Install a Founderizer worker

The same installer supports Mac Studio, Mac mini, and Linux VPS workers. It uses
a macOS user LaunchAgent or a Linux systemd user service. Run it as the worker's
normal OS user. It does not create accounts, copy credentials, change sleep or
login settings, or enable public access. For a Codex worker, it adds one table to
`~/.codex/config.toml` so that Codex trusts exactly this checkout
(`[projects."<checkout>"]`, `trust_level = "trusted"`); other settings and an
existing entry for this checkout stay as they are.

For a new VPS (Ubuntu or Debian) or a Mac, the usual way is Founderizer → Settings → Servers →
Add server: one line on the new machine joins it (UI-API.md, "Servers"), and Add agent on that
server's page then installs an agent on it. This page is the manual way.

## Register the machine first

In the shared `team.json`, add the worker under `agents`, with a unique name,
`role: "worker"`, its `machine`, `runtime`, command and capabilities. Add that
machine's private-network address under `addresses` and add
`profiles/<worker-name>.md`. Use the existing Studio or VPS entry as the example.
Commit and push these changes and reload the hub before installing the worker.
This step is explicit: an installer cannot grant a new machine hub access.

Each worker identity must belong to one machine. Do not install `studio` on a
second Mac. The installer checks that the outgoing private-network address is the
registered one, that the hub knows the worker, and that it has no active tasks.
It refuses to replace a service for another checkout.

## Requirements

- All workers: Python 3.10 or later, Git, tmux, a connection to the hub's private
  network, access to the shared Git repository, and the configured Codex or
  Claude CLI. Runtime login is checked without an AI turn. A signed-out runtime is
  reported and needs sign-in before tasks; it does not prevent service installation.
- macOS screen workers: macOS 14 or later, the ChatGPT app with Codex Computer Use
  configured, Xcode Command Line Tools, and the desktop user signed in and unlocked.
  Use the installed Codex binary path as `screen_command` in `team.json`.
- Linux VPS: systemd with user services. Enable linger for the worker user so it
  runs after SSH logout: `loginctl enable-linger "$USER"`. An administrator may be
  required. Linux installation does not provide a macOS desktop or Computer Use.

Install missing requirements with the OS package manager. The installer stops
with the missing command's name; it does not run downloaded code or use sudo.

## macOS

Clone the shared repository, then double-click **Install Founderizer Worker.command**.
Enter the registered worker name. The installer builds and signs **Founderizer Worker**,
installs the LaunchAgent, and starts it. It opens the macOS screen permission flow
for a screen worker. In System Settings → Privacy & Security → Screen & System
Audio Recording, allow **Founderizer Worker**. No audio is captured. Rebuilding the app
can require this permission again.

From Terminal, the same installation is:

```sh
python3 worker_install.py --agent studio --start --authorize-screen
```

The Mac service starts after the user signs in. It does not bypass FileVault or
the lock screen. Leave a dedicated screen worker unlocked while it works.

A Mac's join also leaves the file that makes Chrome take Claude's extension from its
Web Store (`server.py join`), unless the owner chose ChatGPT alone for that Mac. Chrome fetches it at its next start and asks
once, on that Mac's screen, to enable it. It asks on the page only on a profile that has
started before the file arrived; on a newer one the question waits in no menu at all.
Then sign the extension in, in that Chrome, to the Claude account of the Mac's agents.
Until a Chrome profile has it on and Chrome answers that account, the setup check fails
the `browser` item of an agent on Claude. A Chrome profile that is removed takes the
extension with it, and the next start of Chrome fetches it again.

## A new Mac: one sitting

A bare Mac needs no Terminal. Open the Founderizer installer on it, and type the address
and the link code it shows in Founderizer on your own Mac: Add server, A Mac that stays
on. In Apple's own setup, say no to FileVault: with FileVault on, macOS offers no
automatic login, and a person must unlock the Mac after each power cut.

macOS's own dialog asks for the password once, and the installer's one root step
(`Installer/setup.sh` in the app's repository) then installs Apple's developer tools,
Homebrew, Tailscale, Chrome and the ChatGPT app, turns on the firewall, Remote Login,
Screen Sharing, no sleep and the restart after a power cut, and runs the hub's join line.
The password never reaches Founderizer. The rest is one page at a time: automatic login,
the Lock Screen, Claude's extension and the sign-in in Chrome, one Chrome menu item, and
for computer use the ChatGPT sign-in and two macOS pages. A power cut does not lose the
page. Finish restarts the Mac, and the hub then proves the browser with a real task, with
nobody at the Mac. The manager tells you in one line.

Keep that Mac behind a locked door: it stays signed in, and anyone who touches it acts
as your agents. Sign accounts in that Chrome that are made for the agents. Give each Mac
a Claude account of its own, and never sign that account in on your own Chrome: the
extension's link is account-wide, so an agent could reach the Chrome of another Mac or
your own browser. The sitting goes on only when that Mac's own Chrome has opened a page
that only that Mac can reach.

## Linux VPS or a new checkout

Copy `install-worker.sh` to the machine, then run:

```sh
sh install-worker.sh --repo '<private-repo-url>' --agent vps --directory "$HOME/fleet-pilot"
```

Use the real registered name and repository URL. This clones the repository,
checks requirements and identity, installs the service, and starts the helper.
It refuses an existing target directory. For an existing checkout on either OS:

```sh
python3 worker_install.py --agent <worker-name> --check
python3 worker_install.py --agent <worker-name> --start
```

Open Founderizer → Team to check the worker's fresh helper reading. A running helper
does not prove a browser or desktop task; check one real task after onboarding.

## Update and remove

Finish the worker's tasks, run `git pull --rebase` in its existing checkout, and
run the installer there again. Do not create a second checkout for the same worker.

To stop automatic startup, unload the service and remove only its definition:

```sh
# macOS: replace studio with the worker name.
launchctl bootout "gui/$(id -u)/com.agentfleet.studio"
rm "$HOME/Library/LaunchAgents/com.agentfleet.studio.plist"

# Linux: replace vps with the worker name.
systemctl --user disable --now fleet-vps.service
rm "$HOME/.config/systemd/user/fleet-vps.service"
systemctl --user daemon-reload
```

These commands keep the repository, outputs, usage records and runtime login.

## SSH over the private network only (Linux)

Both installers and the setup executor let incoming traffic in on `tailscale0` only,
SSH included, and open no new port to the internet (`hubsetup.py firewall`). A server whose
firewall was off keeps open each port that answered from the internet before the install, with
the comment `fleet kept`, so a website on it stays up; SSH moves to the private network. After the
install, reach a machine at its Tailscale address: the address `team.json` gives it,
which is the one the app uses too. The provider's own firewall stays the outer layer.

**A machine installed before 2 November 2026 keeps the public SSH rule** that those
installers added (`22/tcp ALLOW IN Anywhere`, comment `fleet ssh`), because a
release reaches no root-owned file. As root in that machine's own checkout, once:

```bash
python3 hubsetup.py firewall --check
python3 hubsetup.py firewall
```

It runs only on a machine that is on the private network, removes only the rules
with that comment (IPv4 and IPv6), and keeps every other rule and the defaults. Run
it over the private network: a session that came in over the public address keeps
going, and a new one does not.

## Vault broker (Linux, V3)

**The join line installs it.** `join.sh` runs `python3 hubsetup.py vault --hub <hub>`
as root on a Linux machine, beside the root helpers and the agent users, so a machine
that joins the fleet ends with a working broker and the owner runs nothing by hand.
It is safe to run again: every step reads first, and the service is restarted only
when something changed. Run the join line again to repair a machine.

The join line also puts `/usr/local/sbin/fleet-vault-program` in place, the one root
command that brings this broker onto the `vault.py` of a release; the machine's own
server service runs it. See "When a release changes vault.py".

The broker holds the key of the store and the key that opens sealed handovers, as
its own user `fleet-vault`, so that no agent of the machine can read either and no
broker answer gives a login (UI-API.md, "Vault isolation (V3)"). What the install
puts in place, all of it mechanical and none of it a credential of the owner's: the
user; `/usr/local/lib/fleet-vault/vault.py` and `/etc/fleet-vault`, owned by root;
`age`; the handover key in `/var/lib/fleet-vault/age.key`;
`/etc/fleet-vault/vault.json`; the store; and the service.

**It belongs to the machine, not to one agent.** A machine joins before it has its
first agent, so the configuration it gets has no `agent` and every request to such a
broker names its caller, which every current helper does. Who may ask it is
`worker_group`, the group of this machine's agent users (`fleet-agents`): an agent
the owner adds later, or one whose OS user changed, reaches the broker with no change
to its configuration. That is the one thing to get right, because a broker that
admits one user ID was left unreachable by the move to one OS user for each agent --
running, current, and serving nobody.

**A machine's broker opens the fleet's own store, and no other**: one `age` file on that
machine (`store`, `store_key`), made by `vault.py store-init`, with no account, no
organization and no token. So installing a machine needs nothing of the owner's, and the
one thing that cannot be automatic does not arise. **Founderizer has no Bitwarden backend
any more** (11 November 2026; since 2 November 2026 no server kept a Bitwarden token): a
broker does not start on a configuration that names a Bitwarden key (`region`,
`token_file`, `bws`, `bws_config`, `sdk`, `sdk_sha256` or `write_project`), and the first
line of its log says to give it the fleet's own store. So a broker installed with one keeps
running its old program, and the hub says that its vault is behind, until its
configuration names the fleet's own store. `python3 fleet.py check <agent>` shows the store
that the broker opens (`backend` in its status).

**The owner's keys reach that store from the central vault only** (HUB-INSTALL.md, "The
central vault"). It seals a value to a machine's pinned vault key, only for a grant of it to
an agent of that machine, or a place in the grantable pool, that the owner signed. The hub
carries the sealed copy, which it cannot open, and the broker opens it, has the hub compare
the value's fingerprints with the ones the owner's vault registered, and saves it in its own
store under the same `bws://` reference. It takes a broker whose `vault.py` has the `deposit`
operation (its status says `"deposits": true`) and a helper that reports the feature
`secret_deposits`. `vault.py store-put` is gone: no value reaches a server's store by hand.

**The configuration is root with mode 644 and holds no secret.** Do not make it
`root:fleet-vault` 640: the service sets `Group=`, so the vault user's own group is
not among the service's groups, the broker fails on its own configuration, and the
unit restarts for ever.

**Then the fleet is told, by the owner's own click.** The hub records a machine's
store key when the owner first gives an agent of that machine its vault, on the
Secrets page or in the agent's Knowledge & access step; `hub.offered_store` takes the
key the machine's own broker reports when Fleet has recorded none, because the only
writer of `vault_stores` is a grant and the first grant would otherwise be refused
for ever (`no_vault_store`). After that, a reported key that differs is refused
(`vault_store_mismatch`). Until that click the agent holds its secrets and cannot use
them, and the Secrets page says so on the secret itself.

Check, as the worker: `sudo -u <worker> sudo -n true` must fail ("a password is
required"), because a worker user with passwordless sudo can read the vault as root
and the broker is then no boundary for it; `sudo -u <worker> cat
/var/lib/fleet-vault/age.key` must fail with "Permission denied"; `python3 fleet.py
check <agent>` must show "vault broker answers (kept by fleet-vault)", which store it
opens, "vault broker key is the one pinned in team.json" and "vault broker runs the
vault.py of this checkout"; and the machine row must show `security.vault`
`{"mode": "broker", "isolated": true}`.

To undo on one machine: `systemctl disable --now fleet-vault`, and set `"vault":
"none"` for its agents in the app. The store and both keys stay in
`/var/lib/fleet-vault`, so the same machine's broker can be started again; a new key
would leave every value it holds unreadable.

A Mac has no `vault.py` broker. Its vault is the signed `Fleet Vault.app`, started by
the LaunchAgent `com.agentfleet.vault` in the user's login session. The app
repository's `Vault/install.py` installs it once as root, with a root updater that
puts each newer signed vault in place by itself. It holds the fleet's own store too;
see the next section.

## Vault broker (macOS)

The Mac helper opens **the fleet's own store** on that Mac, as a Linux broker does, so
a fleet of Macs needs no account of a vault vendor either. The configuration at
`/Library/Application Support/Fleet Vault/config.json`, root with mode 644, names it
(`"store": "fleet"`), and `status` answers that word, so `python3 fleet.py check
<agent>` prints "vault broker opens the fleet's own store".

The store is `~/Library/Application Support/Fleet Vault/store.age`, mode 600, with
the same format as a Linux store (`{"v": 1, "items": {...}}`, one item for each
`bws://<uuid>`), encrypted to the public half of a store key of its own. That key is
one item of the helper's Keychain group, not a file: on a Mac the agents of the
machine run as the vault's own user, so only the helper's signature keeps the store
shut, and the ciphertext alone opens nothing. The handover key is a separate key, so
rotating one does not orphan the other's values.

**The owner's keys** (Fleet Vault 0.3.9, build 12): with `owner_keys` (the owner's public
keys) and `fleet` (the fleet's id) in that configuration, the helper hands a login over only
to a key that the owner signed a pin of, as a Linux broker does with the keys that
`hubsetup.py vault --owner-key` gives it. Only root adds them, on the Mac itself, with programs
that macOS protects. Copy the key list exactly as the central vault's configuration holds it,
read as root on the hub's server (`/etc/fleet-vault-central/vault.json`), and after a change of
the owner's Mac add the earlier key too, until the pins are signed again. The first two lines
only read: the build must be 12 or more, and the second prints the fleet id that goes in.

```sh
/usr/bin/plutil -extract CFBundleVersion raw "/Applications/Fleet Vault.app/Contents/Info.plist"
/usr/bin/plutil -extract fleet raw "/Library/Application Support/Fleet Vault/update.json"
f="/Library/Application Support/Fleet Vault/config.json"
/usr/bin/sudo /bin/cp -p "$f" "$f.old"
/usr/bin/sudo /bin/cp -p "$f" "$f.new"
/usr/bin/sudo /usr/bin/plutil -replace owner_keys -json '["<the owner public key>"]' "$f.new"
/usr/bin/sudo /usr/bin/plutil -replace fleet -string "$(/usr/bin/plutil -extract fleet raw \
    "/Library/Application Support/Fleet Vault/update.json")" "$f.new"
/usr/bin/sudo /bin/mv "$f.new" "$f"
/usr/bin/sudo /bin/launchctl kickstart -k gui/<worker uid>/com.agentfleet.vault
```

The copy keeps root's ownership and mode, and the one `mv` puts both keys in place at once.
Wait a few seconds; then the helper must answer its worker's user (try again before you undo):

```sh
printf '{"v":2,"op":"status"}\n' | /usr/bin/sudo -u <worker> /usr/bin/nc -w 10 -U \
    "/Users/<worker>/Library/Application Support/AgentFleet/vault.sock"
```

If it does not, this and the same `kickstart` undo the step:

```sh
/usr/bin/sudo /bin/mv "/Library/Application Support/Fleet Vault/config.json.old" \
    "/Library/Application Support/Fleet Vault/config.json"
```

Nothing of `/Applications` runs as root here, because an admin user can rename an app there.
Type the password in an admin account that no agent uses where the Mac has one: what the agents'
user's shell starts can read what is typed in its sessions. Without the keys the helper checks
no pin, so nothing changes on a Mac until root gives them.

**A Mac's join line installs it** (since 28 October 2026, `join.sh` `mac_vault`): it takes the
signed vault of the release channel's newest Mac build of the fleet's track (see "The track"
below), checks it against our Developer ID, and runs the `install.py` that the vault carries
as root, named after the Mac, with the fleet's own store. macOS asks for the Mac user's
password once, at that step. A Mac that joined before then, or one whose step failed, gets
it from the join line run again, or by hand from a clone of the app repository
(`founderizer/founderizer-apps`), with the signed build:

```sh
sudo python3 Vault/install.py --app "<build>/Fleet Vault.app" --user <mac user> --agent <agent> --hub http://100.80.1.2:8765 --store --fleet <fleet id>
```

**It updates itself.** The install also puts the vault's updater there: the root daemon
`com.agentfleet.vault.update` runs `/Library/Application Support/Fleet Vault/update.zsh`
at load and every hour. Each app release carries the signed vault inside the app, and
the updater takes it from the release channel (with the fleet's id, `entitlement.fleet`
of `GET /ui/releases`), checks it as the installer checks a build, puts it in place only
when its build number is higher, and starts the vault again; its log is `update.log`
beside it. A Mac whose vault was installed before the updater gets it alone, with no
change to the app or its configuration:

```sh
sudo python3 Vault/install.py --updater-only --fleet <fleet id>
```

**The track.** The updater reads the fleet's track from the root-owned `update.json` beside
it, which only `install.py` writes: the early track only when the install was given
`--track early`, and the approved track otherwise. A fleet whose setting `releases.early` is
on (`early` of `GET /ui/releases`) takes the early track: its join line asks the channel for
that track's build and gives `install.py` `--track early`, and both commands above take
`--track early` too. On a Mac of such a fleet whose updater takes the approved track, the
`--updater-only` command with `--track early` moves it to the early track. Every other
fleet gives no `--track`, because the `install.py` of an approved build may be older than
that flag and refuses it.

Nothing else is needed: the helper makes the store key, the handover key and an empty
store at its first request, and `create_login` works on that store with no project and
no setup. A configuration that still names a `region` is of the Bitwarden backend, which
the vault does not open any more: the install stops on it and changes nothing. The owner
removes that configuration as root and installs again, which **moves no value**: they add
each secret again.

The owner saves one item into a Mac's store with the helper's own commands, the Mac
equivalents of `store-put` and `store-list`. The value is on standard input, so it
stands in no argument, and no answer repeats it:

```sh
"/Applications/Fleet Vault.app/Contents/MacOS/FleetVault" store-put --title "<name>" < item.json
"/Applications/Fleet Vault.app/Contents/MacOS/FleetVault" store-list
```

Then register the reference it gives with the hub and grant it, as for any secret.
Because the agents of a Mac run as the vault's own user, an agent of that machine can
run those two commands: it can add an item and read the names in the store, and no
value and no other machine's store.

### When a release changes vault.py

**A release reaches no checkout's copy of the broker.** It updates each agent's
own checkout and its own user service; the broker runs the root-owned copy at
`/usr/local/lib/fleet-vault/vault.py` as a system service, and nothing in the
fleet may touch that without root. `lifecycle.OWNER_ONLY` also lists `vault.py`
among the files a helper never loads, so a commit that changes only that file
advances the revision every machine reports.

**So the machine brings its own broker along.** The server service of a joined
machine reads the installed program, which is root-owned and world-readable, and
where it differs from the `vault.py` of its own checkout it runs the second root
command the installers put in place:

```bash
/usr/local/sbin/fleet-vault-program
```

It takes **no argument**. It fetches `vault.py` from the fleet's configuration ref
itself, as root, into a bare repository under `/usr/local/lib/fleet-vault` that only
root can write, installs it `root:root` 644 and restarts `fleet-vault`; a broker
that does not come up gets back the program that was serving. So the service user
passes no bytes and names no path, source, destination or service: what it may ask
for is this one act and nothing else. That is narrower than the command this
replaced, which installed from a checkout a user can write.

Nothing else of the broker is touched. Its user, its store, its store key and its
handover key are never read, and the handover key is never remade — a new one would
leave every value the store holds unreadable and turn every agent's access into
`vault_store_mismatch`.

**What root's own clone proves, and what it does not.** It proves that nobody
below root on that machine wrote those bytes. It does not prove they are the
bytes the owner meant: whoever can push the configuration ref can put a program
there, and this one runs as the vault's own user, which holds the store key. The
agents' code already comes from that ref, so the ref could always run code as
every agent — but never as the vault user, and that is the step this adds. What
closes it is a signature over the released revision, verified on the machine
before the blob becomes the program, with the public half pinned root-owned at
install. `release-key.pub` already carries the release key and its private half
is on the website host and never on a hub, so the key exists; what is missing is
a signature this program can check with a stock tool. Until then the trust in
this command is the trust in that ref.

Each machine does this within ten minutes of taking a release, so after a release
that changed `vault.py` the owner runs nothing.

**A machine installed before this needs one installer step run once.** The root
command is written by the installers, and nothing in the fleet can put a new
root-owned file in place by itself. So on a machine whose broker was installed
earlier, as root in that machine's checkout:

```bash
python3 hubsetup.py agent-helper --user <the service user> --repo <the hub's config ref>
```

`--check` first says what it would write. That is the step both installers already
run; it writes nothing when the three files are already the ones that version writes,
and the machine's own server service brings the broker across within ten minutes of
it. Every release after that is automatic.

**Not the join line.** A machine already in the fleet can get no fresh one: the hub
refuses a join code for a name it already has, and the script would redo apt, the
firewall and `POST /join`, with `set -eu` stopping it before the two steps that
matter.

**The warning is now about the machine that could not.** The broker's `status`
answers `source`, the SHA-256 of the program it runs, the helper sends it to the hub
as `security.vault.broker_source`, and `/ui/health` raises one `vault_behind`
warning for each machine whose broker differs from the hub's own `vault.py`. A
warning that stays is one of four things: the machine has a broker and no server
service, its installers are older than that root command, it cannot reach the hub's
configuration ref, or the broker did not come up on the new program and kept the one
that was serving. The warning says it in the owner's words, with no command ("The
vault on vps-2 has not taken the last update." and "It updates itself within ten
minutes; tell us if it does not."): the command above, and the `agent-helper` step for
a machine that does not have it, are this page's, for whoever the owner asks.
`journalctl -u fleet-vault -n 30` says which of the four it is.

The checksum is read once, when the broker starts, so a copy installed under a
broker that was not restarted does not clear the warning — the running code is
still the old one. Then `python3 fleet.py check <agent>` as the worker shows "vault
broker runs the vault.py of this checkout", and the warning goes at that machine's
next status report (within ten minutes). A broker that says nothing about its
program — one older than this, or a Mac's signed helper, which the app updates
itself — raises no warning, because unknown is not behind.

### New logins on a Linux broker (`create_login`)

A broker makes a new login in its own store, with no setup: the store writes itself, and
the broker's record of its saves, `/var/lib/fleet-vault/creates.json`, decides that one
request gets one save (UI-API.md, "`create_login` on a Linux worker"). The machine row
shows `security.vault.creates: true` while that record is open; when it cannot be opened,
`journalctl -u fleet-vault` has a line "no new logins", and the broker still reads. The
owner then allows the agent in Founderizer (`vault_create`), and a project with its own
permission. The write setup of a Bitwarden project (`vault.py sdk-install`, the pinned
library and `vault_sdk_build.py`) is gone with the Bitwarden backend.


### API requests on a Linux broker (`call_api`): the curl program

A broker sends no API request until its configuration names a curl program. **The
install names it**: `hubsetup.py vault` adds `"curl": "/usr/bin/curl"` to
`/etc/fleet-vault/vault.json`, where the base packages of `join.sh` put curl, so a
machine that joins can send requests and nobody runs a step by hand. A curl path
that is there already is kept. This adds no token and no grant: a request uses a
login that the agent already has (UI-API.md, "`call_api`", part 7).

**A broker set up by an older installer has no curl key**, and no release adds one: a
release changes the broker program and never its configuration, so an update of the
program alone leaves requests off. Add the one key once, as root, with the path of a
curl program that root owns and that the worker cannot change, and restart:

```bash
ls -l /usr/bin/curl                                  # owner root, not writable by others
# add:  "curl": "/usr/bin/curl"   to /etc/fleet-vault/vault.json
systemctl show fleet-vault -p KillMode               # must be control-group
systemctl restart fleet-vault
```

Check: the machine row shows `security.vault.requests: true`, and the broker made
`/var/lib/fleet-vault/requests.json.lock` at its start. `requests.json`, its record
of started requests (no answer and no key), comes with the first request.
`KillMode=control-group` is the default of the unit that
`vault.py unit` prints: with it, a restart of the broker also ends a curl child that
runs, so no request goes on without its broker. To undo: remove the key and
restart; the broker then sends no requests, and `requests.json` stays. A later run
of `hubsetup.py vault` adds the key again.

### The key swap on a Linux broker (`hubsetup.py vault --swap`)

An API key that an agent reads is a variable in its sessions. With the key swap, a key
that has a site stays out of them: the session holds a placeholder, and the vault's
swap proxy puts the key into the `Authorization` header of an HTTPS request to that
site only (VAULT.md, "The key swap"). **No install switches it on.** Root does, for one
machine, in a checkout at the release:

```bash
python3 hubsetup.py vault --hub http://100.80.1.2:8765 --kit "$PWD" --swap --check   # says what it would make
python3 hubsetup.py vault --hub http://100.80.1.2:8765 --kit "$PWD" --swap
```

What the step makes, after the broker's own step:

- The user `founderizer-swap`, with a group of its own. It is in no group of the agents
  or of the broker, so it reads neither the store nor its key.
- The part `"swap"` of `/etc/fleet-vault/vault.json`: `{"user", "vault", "port",
  "openssl"}`. The file stays root's with mode 644 and holds no secret. This part is the
  switch: with it, the broker gives a key that has a site as a placeholder or not at
  all, never as the key. A `vault.py` from before the key swap does not start on a
  configuration with this part, so a release with an older program is not taken on such
  a machine: the machine keeps the program that was serving.
- The service `fleet-vault-swap`: the same program file as the broker's
  (`vault.py swap`), on `127.0.0.1:876`. A restart of the broker does not touch it. When
  the broker runs a new `vault.py`, the proxy starts that program as a new process that
  takes over its listener, and the old process ends with its last open connection, or
  at the next hand-over (`NotifyAccess=all` lets the new process tell systemd that it
  is the main one).

The step stops, and changes nothing, on a machine whose kernel setting
`net.ipv4.ip_unprivileged_port_start` is 876 or lower: there each user can listen on
the proxy's port, and an agent could take its place. It changes no line of
`fleet-agent-user`, of `fleet-vault-program` or of the sudoers file. A second run
changes nothing while the proxy runs with the unit that the installed program prints,
and it starts a proxy that is down again. A later
run of `hubsetup.py vault` without `--swap` keeps the part. On a machine that is not a
Linux server, `--swap` switches nothing on and says so.

Check: `systemctl is-active fleet-vault fleet-vault-swap` says `active` two times; the
first line of `journalctl -u fleet-vault-swap -n 5` names the port; `/run/fleet-vault`
has mode 751, `vault.sock` 660 and `swap.sock` 666 (the broker answers on `swap.sock`
only the proxy's user, which it reads from the kernel).

After the step, a key swaps when the owner gave it a site (`POST /ui/team/logins` with
`site`, and `form` when the key does not go as `Bearer`), an agent of this machine
reads it, and the agent's program is Claude Code or Codex. Its next session then gets
the placeholder. On such a machine the vault also sends that key in a `call_api`
request only to that site, in the `Authorization` header and in the key's own form.

The hub does not know that this machine swaps keys, and it reads no report of a machine
for that. So after the step, the owner tells the hub: the tool `server_key_swap` of the
owner MCP server with `on: true` (`POST /ui/servers/<server>/key-swap`). From then on
the settings check does not count a key that swaps here as a key in the agent's
sessions, and the start text of an agent whose sessions get the variable says that it
holds a placeholder. The word opens nothing. Without it the key swap works the same:
the settings check then counts such a key as a key in the sessions, which is more than
is so, and the start text says "when its value begins with vaultswap_".

What a machine that swaps costs: the HTTPS programs of a session that holds a
placeholder go through the proxy. A new `vault.py` does not cut a connection of theirs
that passes bytes; the second new `vault.py` after a connection opened does cut it (so
do two hand-overs in a row, when the installer puts an older program back).
`systemctl restart fleet-vault-swap` does, and so does this step when it writes another
unit. A server whose unit has the line `PartOf=fleet-vault.service`
(`systemctl cat fleet-vault-swap`) got the key swap from the first version: there each
restart of the broker still restarts the proxy, until this step runs one time again.
A new `vault.py` whose proxy does not start is not taken: the proxy that runs writes one
line into its log, goes on with its own program, and tries the new one again later.
`systemctl restart fleet-vault-swap` makes the proxy start from the installed program
at once. A session that holds no placeholder does not use the proxy.

To undo: first the owner takes the word back (`server_key_swap` with `on: false`), or
the hub goes on saying that the keys of this machine's agents are placeholders. Then,
as root: `systemctl disable --now fleet-vault-swap`, take the part `"swap"` out of
`/etc/fleet-vault/vault.json`, `systemctl restart fleet-vault`. The next sessions get
each key as a variable again. A session that holds a placeholder must start again.
