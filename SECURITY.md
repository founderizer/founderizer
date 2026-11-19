# Security

Founderizer keeps the logins and the API keys of your agents. A security problem in it can let another person use
them. If you find one, please tell us privately first, so that we can fix it before other people know about it.

## Report a problem privately

Do not open a public issue, pull request or discussion about a security problem.

Report it with GitHub's private vulnerability reporting:

1. Open the **Security** tab of this repository.
2. Select **Report a vulnerability**.
3. Complete the form, and send it.

The form is also at <https://github.com/founderizer/founderizer/security/advisories/new>. Only you and the
maintainers of this repository can see the report.

Put this information in the report:

- The release or the commit of this repository that you tested.
- The steps that show the problem.
- What an attacker can do with the problem.
- A proof of concept, if you have one.

Do not put a real password, key or token in a report, also not one of your own. Use an example value.

## What happens after a report

1. We read the report, and we answer you in the report.
2. We examine the problem. If we need more information, we ask you in the report.
3. If it is a security problem, we make the fix in our own repository, we test it, and we publish it in a new
   release. This repository is a copy of our own repository (`README.md`, "Changes from outside").
4. After the release, we publish a security advisory in this repository. The advisory tells what the problem was,
   which releases have it, and which release fixes it. If you agree, the advisory gives your name.
5. If it is not a security problem, we tell you why in the report.

Please keep the problem private until we publish the advisory.

## Which versions get fixes

We fix only the newest release. A hub takes a new release from this repository, and only a release whose manifest
has a valid signature (`releases.py`). A fleet gets a fix when it takes the release that has it. [VAULT.md](VAULT.md),
"How the vault's code is updated", tells how a release reaches the vault on each server.

## What this policy covers

- The code in this repository: the hub, the helper on each machine, the vault brokers and the central vault, the
  door, the installers and the owner's MCP server.
- The Mac and iPhone apps, and Fleet Vault for Mac, are in <https://github.com/founderizer/founderizer-apps>. Report
  a problem in them there.
- If you do not know which repository a problem belongs to, report it in either one.
- A problem in a service that a fleet uses, for example an AI provider, Tailscale or GitHub, goes to that service. A
  problem in how Founderizer uses the service goes to us.

## How the hub knows the owner's computer

The hub serves the owner's routes to one computer: the one that claimed the hub. It knows that computer by two
things, and a call needs both (`hub.py`, `owner_allowed`):

- **Its address** on the fleet's private network, which the claim proved with a one-time code of the hub's own server.
- **A key that the computer made** for that hub: 32 random bytes. The hub keeps only the SHA-256. The computer keeps
  the key in a file that only the owner's user reads, `~/.founderizer/owner-keys/<address>_<port>`, with the hub's
  numeric address in its name. The key only ever goes to that number: a program that calls its hub by a name looks
  the name up once, and sends the call that carries the key to the number that it got, never to the name again,
  and it follows no redirect with the key. Before a computer registers a key for a hub that it calls by a name, it
  checks that the name's number is an address of the fleet's private network that the hub's own server has, which
  it reaches over SSH with a known host key: whoever answers a name's lookup chooses its number.

**What the key guards against.** A VM or a container on the owner's computer sends its traffic out through that
computer, so the hub sees the computer's address. Such a guest has the address and not the key, and the hub refuses
it.

**What the key does not guard against.** A program that runs on the owner's computer as the owner's user can read the
file, as it can read the owner's SSH keys. A guest to which the owner gives the folder `~/.founderizer`, or the whole
home folder, can read it too. To the hub, each of these is the owner.

**How a computer gets its key.** At the claim of a new hub, the computer sends the SHA-256 with the one-time code, and
the claim keeps it before it names the owner. On a fleet from before the key, Founderizer registers one by itself: the
hub writes a one-time value into a file of its own server, and the computer reads that file over its own SSH
connection to that server, as the user that owns the file and never as root. No call that has only the address
registers, replaces or removes a key. Until a computer has registered a key, its hub knows it by the address
alone: Founderizer says so in System status when it cannot register one, and a second claim on the hub's server
(`sh hub.sh --reclaim`) makes one.

## How the vault keeps secrets

[VAULT.md](VAULT.md) tells what the vault protects, how it protects it, what it does not protect, and what the owner
of a fleet must do.

## An agent's own browser on a Linux server

Each agent with its Shell box and its Browser box on a Linux server has a Chrome of its own (build plan 04). The
fleet's own nftables table lets only the agent's user, the vault's broker and root reach its DevTools port on that
server, and closes each port of both ranges that no agent holds; after a flush of the ruleset by hand, that rule has
a gap of one reading of the server (at most five minutes). The vault signs the agent in there, and the end of the
agent's use of a login clears the sites of that sign-in in that browser within a minute while it runs, else at its
next start. What the agent's own programs
can still reach in its own browser (a filled field, the vault's script, the browser's cookies) is item 26 of
[VAULT.md](VAULT.md), "What the vault does not protect": a copied session works until the site ends it, so after a
grant's end the owner's step is the site's "sign out everywhere" or a new password.

At the owner's Take over (UI-API.md 1.225), the agent's helper shares that browser's screen with `x11vnc` on loopback
and the agent's screen-sharing port, for one viewer, with no shared clipboard, and with a new one-time password at each
press; only root and the server's worker user reach that port, so the owner's Mac opens it through its own SSH tunnel
as root. The password is in no row and no log line of the hub, it goes to the owner's Mac app only (never to a phone),
and the app keeps it nowhere. The helper refuses while a page of that browser is an AI provider's site.

What this does not protect: `x11vnc` runs as the agent's own user, so those settings hold for an agent that does not
interfere. An agent that turns against the owner (a page that took over its session, for example) can replace that
server with a program of its own on the same port, and then it decides what the owner sees, and it reads what the
owner's viewer sends: what the owner types, and the clipboard of the owner's Mac where Screen Sharing sends it to such
a server (not yet measured). The address of that screen names a user of its own (`takeover-<agent>`), so that Screen
Sharing should not take the sign-in that it keeps for 127.0.0.1, which can be another Mac's, when such a server asks
for an Apple sign-in (not yet measured either: the live check of the take-over measures it). On a Mac the other end is
Apple's own server, but its shared clipboard reaches the agent's Mac too (an open point of the take-over). So a
take-over is for a CAPTCHA only: the owner types nothing there that they would not type into the agent's own browser,
and copies no password before it. The agent's session gets the owner's answer only after the sharing has stopped,
which holds for an agent that reads its messages with `read_messages`.

## What an agent's read of a server shows, and what it does not

The agent that holds a server at Fix through the door can read that server's files with `ops <server> look`: a bash
script that the server runs in a box (`host/ops-root`, `look_box`). No person approves a look. The box is the
boundary, so this section says what it stops and what it does not.

**What the box stops, for a script of any content.**

- **A write.** The whole file system is read-only for the script, the folders of the server's accounts and the
  server's own temporary folders included. The script has 64 MiB of memory for files of its own, which go when it
  ends.
- **The network.** The box has no network device, the calls that make or use a socket are refused, and so is
  io_uring. A script reaches no address, no local database and no Docker socket.
- **Other processes.** The script sees only its own processes: no other process's environment, command line or
  memory, no shared memory, no terminal of a person, and none of the kernel's own folders for root (its debug and
  tracing folders).
- **A hidden folder.** The key stores of a server (the accounts' password files, the SSH host keys, certificates'
  private keys, VPN and backup settings, the vault's and the door's own folders), the stores of databases and of
  containers, the folders of code libraries, and each folder that the server's own list names. A hidden folder is
  an empty folder for the script.
- **A folder that a look cannot search,** with all that is in it. A look makes its list of hidden files for each
  call, and a folder whose names it does not read to the end is hidden whole: a folder with more than 4,000
  folders or 250,000 entries right in it, a folder more than 48 levels down or with a path of more than 1,024
  characters, and a folder that the server could not read. A folder at least two levels down with more than 50
  names of secrets or of stores right in it is hidden whole too, and one with more than 12 such files of one
  ending (a folder of migrations or of certificates). On a server with more than 600 paths to hide that are
  there, the folders that hold the most of them are hidden whole, because a box starts more slowly with each
  path; no folder that the box itself runs from is one of them. And the list ends at 1,000,000 entries read, at about
  100,000 paths held or after 20 seconds: then each folder that it did not reach is hidden whole, which is the
  level of the server's folders that the list was at and all below it, and that can be an app's own folders. The
  look's answer names the first ten of the folders that it hid whole, and says how many more there are. No look
  runs on a server whose top folder cannot be read or holds more than 250,000 entries, or whose paths to hide
  that are there are more than 600 with no folders of its apps that can be hidden whole in their place.
- **A hidden file,** while no program puts a new file in its place: a file that a systemd unit names as its
  settings or its credentials, a unit file written on the server that holds a value itself, a file with one of the
  usual names of a file with secrets (`.env`, a private key, a database's settings file of a common framework),
  and the dot entries of each account's home. A hidden file is an empty file for the script. A form of the door
  that puts a file in its place waits until no look runs. So does a form that runs the agent's own command or
  script, an account's tool or a package's tool, and no look starts while one of those runs, or while a program
  that one of them started still runs. The door's other forms run fixed commands of the system (a restart, a
  certificate's renewal, a log's rotation), which replace no file that a look hides by itself.
- **Time, memory and processes** have limits: 120 seconds, 512 MiB, 64 processes.

Each server proves its box itself before the first look, and again after a new version of the host program, a
restart or a new systemd. One script in the box tries the main ways: a read of a file in a hidden folder and of two
hidden files, a write in seven places and in four other forms, a socket of five kinds, four of the system calls
that the box refuses, the kernel's debug folder, and another process. A server whose box fails the test runs no look. The script
does not try each line above: `test_host_parts.LookBoxLive` tries the others (a unit's settings file, a home's dot
entries, Docker's folder, other processes' environments, the limits) on a real Ubuntu 24.04 and 26.04.

**What the box does not stop.**

- **A secret in a file whose name is in no rule:** source code, a settings file with another name, a value in a
  Compose file or a crontab, a log line, a copy in a backup or an archive, a hard link under another name. A link
  is never searched by its own name: a link named `.env` to a file with another name leaves that file readable, and
  so does a dot entry of a home that is a link. What the system's packages installed (`/usr` except `/usr/local`,
  `/usr/src` and `/usr/share/nginx`; `/boot`; `/snap`), and `/lost+found`, are not searched for names. The names are a list, and a list
  can miss a file. The agent that holds the server adds a path to the server's own list with
  `ops <server> hide <path>`.
- **A compiled copy of a hidden Python file in another place.** Beside a hidden `.py` file, a look hides its
  folder's cache (`__pycache__`) and an old `.pyc` or `.pyo`. It does not find the cache beside a link to that
  file, a cache folder that Python's own settings name (`PYTHONPYCACHEPREFIX`), or a copy that Python writes
  during the look.
- **A hidden file that another program writes during a look:** an app's own deploy, a package's own timer, a
  command of a person on the server, and the door's rollback timer when a look still runs after the timer's wait
  of about two minutes. A rename puts a new file in the place of the hidden one, and the look that runs can read
  the new file until it ends.
- **Data that is no key:** logs with customers' data, uploaded files, a mail queue.
- **What a key is worth.** The agent's session has the network. A key that a look does read can be used from there:
  where an app's key is in a file that no rule hides, a look is worth that app's own rights.
- **A lock.** A script can hold a read lock on a file that it can read, for the time that it runs.
- **Text that steers.** A server's files hold what strangers wrote: a log line has a customer's address, name and
  words. The agent that reads them can be steered by them, and only its own judgement stops that. So `ops` says with
  each look's answer that it is data, the door records each look (the agent, its task, the server, the call's hash
  and the count of bytes that went back, never the script and never the bytes), and an agent that reads strangers'
  text all day and has its Shell box off holds no server.

A look runs only on a server that the door holds at `fix`, for the agent that holds it at Fix. The hub's own machine,
a machine of the fleet's agents and a CI host that two businesses share hold the fleet's own keys: no look runs
there.

## What the holder of the fleet's own servers can do there

Each Linux server of a fleet, a server that runs agents or the hub's server, is a host of the door at `rule-only`.
One agent holds all of them: the fleet's DevOps agent, or, in a fleet with none, the manager when it runs alone on a
server that is not the hub's. This section says what that agent can do on such a server and what it cannot.

**What it can do.** Run the fixed root forms of `host/ops-root`: restart or reload a service, enable a unit, restart
the server, run the security upgrades, upgrade Tailscale, empty the journal and the package cache. Read why the
server failed or is slow with `ops <server> health`. Read the server's logs and its units with the fixed reads, as the
user `ops-agent`, which has no root. A restart or a reboot can end the work that runs on that server: the holder
answers for the time.

**What it cannot do, whatever the door's file says.** Run a command, a script or a file install of its own, or the
wide read `look`: the server's own `ops-root` refuses each of them by its mode and by the mark of a machine of the
fleet, which only root on that server can take away. Compare or delete a file as root (`same`, `covers`, `drop`), or
have a key placed there. Restart, reload or enable `nftables.service`: such a server keeps its firewall in ufw, and
each start, reload or stop of that unit removes every firewall rule, ufw's too. No statement of the owner lifts this,
and no mode of the server does.

**What `health` and the fixed reads show.** `health` reads counters of `/proc` and of the memory groups, the name of
a process (the kernel's 15 characters), and the lines of the journal that the kernel, journald and systemd-oomd
wrote. It reads no process's arguments or environment and no file's content. A process chooses its own name and the
name of its group, so a line of `health` can hold up to 300 characters that an agent of that server wrote: it is
data, as every answer of a server is. The fixed read `status <unit>` prints
the arguments of that unit's processes, as `ps` shows them to every user of the server, and `journal` prints what the
journal holds: a key that a program writes into its arguments or its log is visible there.

**What the hub decides, and what it does not.** The hub proposes the fleet's servers and the agent that holds them.
The owner's app takes a server only when its own Tailscale and the server itself say that it is one, and an agent
only when its own server says that it runs alone there. So a fault of the hub can make another agent that runs alone
on its server the holder, with the fixed forms above. It cannot add another device as a host, it cannot give more
than the fixed forms, and it cannot move to another address an entry of the door's file that holds a business's
servers, a database, a commit target or an account that a Mac session wrote.

