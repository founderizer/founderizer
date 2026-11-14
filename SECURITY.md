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

## How the vault keeps secrets

[VAULT.md](VAULT.md) tells what the vault protects, how it protects it, what it does not protect, and what the owner
of a fleet must do.

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
