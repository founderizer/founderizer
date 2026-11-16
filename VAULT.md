# How the vault keeps secrets

The agents of a Founderizer fleet use logins and API keys that belong to the owner of the fleet. The vault is the part
of Founderizer that keeps them. This document tells what the vault protects, how it protects it, what it does not
protect, and what the owner must do.

Each statement names the file that does it. A path that starts with `Sources/`, `Vault/` or `ios/` is in the apps
repository, <https://github.com/founderizer/founderizer-apps>. Every other path is in this repository. The statements
are true for the code of the same commit as this file. If the code and this document do not agree, the code is
correct, and the document has a bug: please report it.

To report a security problem, read [SECURITY.md](SECURITY.md).

## Words

- **Secret**: a login or an API key. A login has an address, a user name, a password and, if the site uses one, an
  authenticator seed. An API key is the same item with no user name (`vault.py`).
- **Hub**: the program on the fleet's server that keeps the agents, their tasks and their records (`hub.py`).
- **Central vault**: the program on the hub's server that keeps every secret that the owner adds (`vault.py` with
  `"central": true`).
- **Broker**: the vault program on each machine where agents run. On a Linux server it is `vault.py`. On a Mac it is
  Fleet Vault (`Sources/FleetVaultCore/`).
- **Swap proxy**: a second process of the vault program on a Linux server that swaps keys (`vault.py swap`). It
  puts an API key into a request to the key's own site. See "The key swap".
- **Door**: the service, on a server of its own, through which agents change and read the fleet's servers
  (`door.py`).
- **Owner key**: the key on the owner's Mac that signs the owner's decisions (`Sources/FleetCore/OwnerKey.swift`).
- **Sealed copy**: a value that [age](https://age-encryption.org) encrypted to one public key. Only the holder of the
  private key can open it.

## What the vault protects, and against whom

The vault protects the value of each secret. The design gives these results:

- **An agent uses a login, but it does not read the password.** The broker signs in, makes a new login, or sends an
  API request for the agent, and the agent gets only the outcome (`vault.py`,
  `Sources/FleetVaultCore/VaultBroker.swift`, `rules/logins.md`). The exception is an API key that the owner lets an
  agent read (see "What an agent gets"). On a Linux server that swaps keys, such a key can stay out of the agent's
  sessions too (see "The key swap").
- **The hub does not have the value of a secret that the owner adds.** It carries sealed copies that it cannot open,
  and it keeps only fingerprints of each value (`hub.py`).
- **A hub that is broken into cannot get every secret with one call.** The central vault seals a value only to a
  machine key that the owner signed. It seals it only for a grant that the owner signed, or for a value that the owner
  put into the pool (`vault.py`).
- **A value travels only as a sealed copy.** It goes from the owner's Mac to the central vault, from the central vault
  to a machine, and from one machine to another, only sealed to one key (`Sources/FleetCore/AgeSeal.swift`,
  `vault.py`).
- **An agent cannot open the store of its broker.** On Linux, the store's key belongs to another OS user. On a Mac, it
  is in a Keychain group that only Fleet Vault's signed code can read (`vault.py`,
  `Sources/FleetVaultCore/VaultLocalStore.swift`).
- **A copy of the central vault's backup is of no use without the owner's recovery code** (`vault.py`,
  `Sources/FleetCore/RecoveryCode.swift`).

"What the vault does not protect", below, tells where these results stop.

## Where a value goes

### On the owner's Mac

- The owner adds a secret in Founderizer for Mac, with **Settings › Secrets › Add secret** or **Import**. The app seals
  the value to the central vault's key in its own process. It uses age's format: X25519, HKDF-SHA-256 and
  ChaCha20-Poly1305 (`Sources/FleetCore/AgeSeal.swift`, `Sources/Founderizer/SecretEntryView.swift`).
- The value is only in the memory of the form. The app clears it when the hub has the reference, at Cancel, and when
  the form closes. No draft and no log gets it (`Sources/Founderizer/SecretEntryView.swift`).
- The app seals only to the key that the central vault's install printed on the machine that the hub names as its own.
  That key comes to the Mac over the owner's SSH connection, which accepts only a known host key. The machine's name,
  and its address when the Mac has no saved connection to it, come from the hub. The app seals only while the hub names
  the same key (`Sources/FleetCore/CentralVault.swift`, `Sources/Founderizer/CentralVaultSection.swift`).
- With the sealed copy, the hub gets the secret's name, its catalog entry and salted SHA-256 fingerprints of the value
  (`Sources/Founderizer/SecretEntryView.swift`). An import sends these for all its items in one command, and the hub
  puts them into the catalog with one commit (`Sources/Founderizer/SecretImportView.swift`, `hub.py`). A title that
  holds a value, of the catalog or of the same import, is refused before the hub keeps the command (`hub.py`).
- The catalog takes no second API key with the variable name of another one, also not from one import (`hub.py`).
  When the owner saves a key under a variable name that one key of the catalog has, the app replaces the value of
  that key: the new value goes
  under the same reference, with a `replace` statement that the owner key signs about that one sealed copy (see "The
  owner's signatures"). The catalog entry, its site and each grant stay as they are
  (`Sources/Founderizer/SecretEntryView.swift`, `Sources/FleetCore/Secrets.swift`,
  `Sources/Founderizer/GrantSigning.swift`). The import leaves out a key whose variable name a key of the catalog has
  (`Sources/Founderizer/SecretImportView.swift`).

### On the hub

- The hub cannot open a sealed copy, and it does not try (`hub.py`).
- For each value, it keeps a salt, a hash and a length. Each salt is an HMAC of the secret's name under a key of 32
  random bytes in the hub's own database (`hub.py`).
- It uses the fingerprints to find a value in a text. It refuses a text with a registered value when an agent writes
  it. It removes the value from each tool answer before the answer reaches a session. It masks each text of a
  session's record when it stores it (`hub.py`).
- After the owner replaced a value, the hub keeps the fingerprints of the new value as the central vault named them,
  the time, and the number of the newest delivery of then. It ends each sealed copy that still waits, and it sends a
  new sealed copy to each machine whose store holds the old value, and to the door. From its record of the replace
  on, it gives no machine's vault and no door a copy that was sealed before, and it confirms a delivered copy only
  when its fingerprints are those of the new value. A vault that took an old copy in the moment before that record
  gets the new one with the next delivery. It keeps the fingerprints of the old value too, so it goes on masking
  the old value in texts (`hub.py`).
- The central vault's status names the checksum of the copy of the newest replace of each reference. When the hub
  has no record of such a replace, because it stopped between the central vault's write and its own record, it makes
  the record at its next read of the status, and the new value goes to each machine as above (`vault.py`, `hub.py`).
- It confirms a sign-in, a handover, a probe and a request of a broker only once. For each of these except a probe, it
  first checks again that the task belongs to the agent, that the task is open, and that the agent still holds the
  login. It gives a delivery, a withdrawal and a new login again while they wait (`hub.py`).

### In the central vault

- The central vault runs on the hub's server as its own OS user, `founderizer-vault`. It answers only the hub's OS
  user, on the Unix socket `/run/fleet-vault-central/vault.sock`, and it never calls the hub (`vault.py`,
  `hubsetup.py`, `hub.py`).
- Its service cannot use the network. It can open only Unix sockets, and every IP address is denied (`vault.py`).
- It keeps one store with every secret that the owner added. A login that a broker made is only in that broker's
  store (`vault.py`, `hub.py`).
- It opens a sealed copy from the owner with its own age key, which only its user can read (`vault.py`,
  `hubsetup.py`). It keeps the value only when its own fingerprints of the value are among the fingerprints that the
  hub gives as the owner's (`vault.py`).
- It refuses another value under a reference that it holds. The one exception is a copy that comes with the owner's
  `replace` statement: the statement names the reference and the SHA-256 of that sealed copy, so the hub cannot put
  a copy of its own under it. The central vault keeps the newest statement of each reference and refuses an older
  one, so an earlier copy cannot come back. It writes the record of the statement first and then the store, which
  is one file that takes the place of the old one whole. A replace that stops between the two leaves the old value
  whole, and the same statement again ends it (`vault.py`).
- A replace changes the key and not the address of its service. When the stored value has an address and the new
  value names none, the central vault keeps the address and the user name of the stored value, so a vault can still
  send the key for an agent that uses it. An address in the new value takes the place of the old one (`vault.py`).
- It seals a copy of a value for a machine only when the owner signed a pin of that machine's key, and also signed a
  grant of the value to an agent on that machine, or put the value into the pool. It seals a value of the pool to
  each machine whose key the owner pinned (`vault.py`, `Sources/FleetCore/OwnerKey.swift`).
- It removes a value only while no grant and no pool entry that the owner signed names it (`vault.py`).
- It keeps one key for the hub: the key that seals the hub's Google file, with each account's Google refresh token.
  It makes the key at the hub's first request, as 32 random bytes in `hub-google.key` of its state folder, mode 600,
  and never replaces it. It gives the key to the hub's OS user alone, and each request is a line of its log. The key
  is no value of the owner's, it opens nothing of the store, and no export carries it (`vault.py` `hub_key`). Its
  status names the key's id, a hash that opens nothing, so that a running hub knows when the key changed. The hub
  keeps the key in memory, so a copy of the hub user's files does not open the Google file (`hub.py`).

### In a broker on a Linux server

- The broker runs as its own OS user, `fleet-vault`. Only that user can read its store key and its handover key
  (`vault.py`, `hubsetup.py`).
- Each agent runs as its own OS user, `fleet-<agent>`, with a locked password, no sudo and a home folder of mode 700
  (`hubsetup.py`). So an agent can read neither key.
- The broker's socket, `/run/fleet-vault/vault.sock`, has mode 0660 for the vault user and the group of the machine's
  agent users. For each connection, the broker gets the caller's user from the kernel (`SO_PEERCRED`), and it serves
  only an agent user of its machine (`vault.py`).
- A request carries a job number, and the agent's name and hub key. The broker takes the login, the receiving agent
  and that agent's key from the hub's confirmation of the job, never from the request (`vault.py`).
- A value comes into the broker's store only as a copy that is sealed to this machine's key and that the hub delivers
  and confirms (the central vault's copies come this way), or from the broker itself when it makes a new login
  (`vault.py`).
- The broker refuses another value under a reference that its store holds. The one exception is a delivery for
  which the hub's answer says that the owner replaced the value: the broker then puts the new value in the place of
  the old one, and only over a value that an earlier delivery saved, never over a login that the broker made. The
  helper's request cannot say this. The store is one file that takes the place of the old one whole, so a replace
  that fails leaves the old value whole (`vault.py`, `hub.py`).
- The broker gives a delivered value back when no agent of its machine holds it any more (`vault.py`).

### In Fleet Vault on a Mac

- Fleet Vault runs as the OS user of the Mac's agents, so file modes do not keep the store from the agents. What
  keeps the store shut is its key: an item of Fleet Vault's own Keychain access group, which macOS gives only to code
  with Fleet Vault's signature (`Sources/FleetVaultCore/VaultLocalStore.swift`).
- Each build of Fleet Vault has that signature, an older one too, and an agent of the Mac can stop Fleet Vault and
  start an older signed build. So the keys are under the Keychain names of a key generation: `local.agent-fleet.vault`
  for generation 1, and that name with the generation's number for each later one. A build reads only the names of
  its own generation: builds 1 to 14 generation 1, build 15 generation 2, and build 16 and later generation 3, which
  keeps a value with the shape of a login out of each session (see "Never a login's password in a session").
  The name of each generation is a constant of each build's code, so no older build can be told to read another
  (`Sources/FleetVaultCore/VaultKeychain.swift`).
- The first start of a build of a newer generation moves the keys. It copies the four items of the newest lower
  generation that has its marker, or else of generation 1, so a copy that an earlier move left unfinished is never its
  source. A marked generation ends that search, also with no item in it: after a marker, nothing lower is read. It proves each copy by its bytes, writes a marker, and only then deletes the old items. Each process moves under a lock of the vault's own
  folder and reads the marker again inside it, so two processes never move at once. A move that stops goes on at the
  next start, and loses no key. Until the move is done, the build reads and makes no key of its own generation
  (`VaultKeyMove.swift`).
- The lock is a file of the agents' user. An agent that holds it stops the move. One that removes or renames it can
  make two moves run at once, but no move deletes a key of its generation or writes other bytes over one, no move takes
  back a key, and a move takes back only a journal that it added itself, and nothing once the marker is there. So the worst case is a stop, or a journal
  that goes back to older bytes: a loss that is smaller than the one that the agent can cause today by deleting the
  store file. No key leaves the vault's Keychain group (`VaultKeyMove.swift`).
- After the move, an older build finds no key. It makes new keys under its own names, cannot open the store, and
  answers with another key, so the hub sends that Mac nothing until the newer build runs again (limit 6). The way back
  after a bad release is a newer build with the fix, never an older build. The root updater installs only a newer
  build (`Vault/update.zsh`).
- Its items are in the data-protection Keychain, in the group `6EBZ756H9Q.local.agent-fleet.vault`. They can be read
  after the first unlock since a restart, only on this Mac, and they are never synchronized
  (`Sources/FleetVaultCore/VaultKeychain.swift`).
- When it starts, Fleet Vault checks its own code signature: Apple's anchor, the team `6EBZ756H9Q` and the identifier
  `local.agent-fleet.vault` (`Sources/FleetVaultCore/VaultBroker.swift`).
- Its socket is in a folder of the vault's user that the group and other users cannot use. It serves only the user ID
  of its configuration, and each part of that configuration's path must belong to root
  (`Sources/FleetVaultCore/VaultProtocol.swift`, `Sources/FleetVaultCore/VaultBroker.swift`).
- It confirms each job with the hub, and it takes the job's fields from the hub's answer. It sends the calling agent's
  hub key when the request names its caller, and else no key. The hub takes a call with no key only from an agent that
  is alone on its machine's address (`Sources/FleetVaultCore/VaultBroker.swift`,
  `Sources/FleetVaultCore/VaultHub.swift`, `hub.py`).
- It takes a delivery, and gives a delivered value back, as a Linux broker does. It also puts a new value in the
  place of a delivered one only when the hub's answer for the delivery says that the owner replaced the value
  (`Sources/FleetVaultCore/VaultBroker.swift`, `Sources/FleetVaultCore/VaultLocalStore.swift`,
  `Sources/FleetVaultCore/VaultProtocol.swift`).

### In the door

- The central vault seals each secret that the owner signed for the door to the door's pinned key (`hub.py`).
- The door opens the copy and keeps the value in a file of mode 600 of its own OS user, `door`. The hub keeps an
  SHA-256 of the value, with no salt (`door.py`, `hub.py`).
- For a Cloudflare account, the owner can save a key that only makes tokens. The door uses that key only to ask
  Cloudflare what the key is, and to make and delete a work key of its own. Each call for an agent goes out with the
  work key, which has only the rights that the door's code names, for that one account. Cloudflare ends a work key
  after one day (`door_providers.py`). The door keeps the work key in a file of mode 600, in the folder of the values
  that it opened (`door.py`).

## The keys

| Key | Kind | Where it is | Who uses it |
| --- | --- | --- | --- |
| Owner key | ECDSA P-256 | The owner's Mac. In the Secure Enclave when the Mac has one, else a software key. One item of the login Keychain for each fleet: "when unlocked, this device only", not synchronized. | Founderizer for Mac, to sign the owner's statements (`Sources/FleetCore/OwnerKey.swift`) |
| Central vault key | age (X25519) | `/var/lib/fleet-vault-central/age.key`, mode 600, user `founderizer-vault` | The central vault, to open what the owner sealed (`hubsetup.py`, `vault.py`) |
| Central store key | age (X25519) | `/var/lib/fleet-vault-central/store.key` | The central vault (`hubsetup.py`) |
| Broker store key | age (X25519) | Linux: `/var/lib/fleet-vault/store.key`, mode 600, user `fleet-vault`. Mac: the Keychain item `store`. | The broker (`hubsetup.py`, `Sources/FleetVaultCore/VaultLocalStore.swift`) |
| Broker handover key | age (X25519) | Linux: `/var/lib/fleet-vault/age.key`, mode 600. Mac: the Keychain item `age`. Made one time and never replaced. The hub pins its public half. | The broker, to open copies that are sealed to its machine (`hubsetup.py`, `Sources/FleetVaultCore/VaultPrograms.swift`) |
| Recovery code | 26 symbols of Crockford's base32 (130 random bits) | The owner's Mac, in the login Keychain, and a phone that enrolled after the Mac had the code | The central vault seals its backup to an age key that comes from this code with HKDF-SHA-256 (`Sources/FleetCore/RecoveryCode.swift`, `Sources/Founderizer/RecoveryCopy.swift`) |
| Fingerprint key | 32 random bytes | The hub's database | The hub, to make the salt of each fingerprint (`hub.py`) |
| Google file key | 32 random bytes | `/var/lib/fleet-vault-central/hub-google.key`, mode 600, user `founderizer-vault`. On a hub with no central vault of this program yet, and on a Mac: `~/.config/founderizer/google-file.key` of the hub's user, outside `~/.fleet`. | The hub, to seal its Google file with ChaCha20-Poly1305 (`vault.py` `hub_key`, `hub.py`, `atrest.py`) |

## The stores

- The central vault and each broker keep their secrets in one file that age locks. The file holds
  `{"v": 1, "items": {...}}` in ASCII armor, encrypted to the public half of the store key with X25519 and
  ChaCha20-Poly1305 (`vault.py`, `Sources/FleetVaultCore/VaultLocalStore.swift`).
- A value goes to age on its standard input or on a pipe, never in an argument or in the environment. A locked store
  in which a value of 8 or more characters is still in clear text is not written (`vault.py`,
  `Sources/FleetVaultCore/VaultLocalStore.swift`).
- On Linux, the store and each key file must belong to the vault user with mode 600, in a folder of mode 700, or the
  broker refuses them. It reads them again for each request (`vault.py`). The program is `/usr/bin/age`
  (`hubsetup.py`).
- On a Mac, the store is `~/Library/Application Support/Fleet Vault/store.age`. A save writes a new file of mode 600
  and renames it into place. A read refuses a file that is not a regular file of this user, or that the group or
  other users can write (`Sources/FleetVaultCore/VaultLocalStore.swift`). Fleet Vault has its own copy of age 1.3.2,
  which the build checks against a SHA-256 (`Vault/build.py`).
- The central vault's backup is its locked store, and its store key sealed to the recovery key that the owner
  signed. So only the owner's recovery code opens the backup (`vault.py`).

## The owner's signatures

- The central vault reads eight kinds of statement that the owner key signs: `pin` and `unpin` (the key of a
  machine), `recovery` (the key of the backup), `grant` and `ungrant` (a secret for an agent on a machine), `pool`
  and `unpool` (a secret that the fleet manager can give to an agent on any machine), and `replace` (a new value
  under a reference that the vault holds, for one sealed copy) (`vault.py`, `Sources/FleetCore/OwnerKey.swift`).
- Each statement is the canonical JSON text of exactly its own fields, and it names the fleet and a time. The
  signature is ECDSA over SHA-256 of the statement's bytes (`vault.py`, `Sources/FleetCore/OwnerKey.swift`).
- The central vault checks each statement itself, with the owner's public key. It refuses a statement of another
  fleet. It keeps a dated record of each machine, recovery key, grant and pool entry, also after its end, and of the
  newest replace of each reference, and it refuses a statement that is not newer than that record. So the hub cannot
  send an old statement again (`vault.py`).
- The app signs a grant before the hub records it, and it signs the end of a grant after the hub records the end. So
  the central vault's signed grants always include the hub's grants. The app sends each statement through the hub
  (`Sources/Founderizer/GrantSigning.swift`). A `replace` statement goes with the sealed copy that it is about, in
  the same request (`Sources/FleetCore/CentralVault.swift`).
- The app pins a server's key only when the Mac's own Tailscale names the SSH address as that server, and when the key
  that it reads there over SSH is the key that the hub reports (`Sources/Founderizer/CentralVaultSection.swift`).
  It reads the key of a Linux server as root, from the key file that the broker's configuration names. It reads the
  key of a Mac from the answer on Fleet Vault's socket, as the OS user of that Mac's agents
  (`Sources/FleetCore/CentralVault.swift`).
- Before a Linux broker hands a login to another machine, it checks that the owner signed a pin of the receiving key.
  It uses the owner's public keys in its own configuration. Only a root step writes them there, and nothing that the
  hub sends changes them. A Linux broker without these keys hands no login over (`vault.py`, `hubsetup.py`).
- The hub hands a login over to an agent only for the key that the owner's kept pin of the agent's machine names
  (`hub.py`). The app signs the pin of each trusted machine again when the pin that the hub keeps is 7 days old, or
  when the hub keeps none (`Sources/FleetCore/CentralVaultPlan.swift`). It signs the pins of the machines that have a
  worker or a lead, so the hub hands no login over to an agent on another machine.
- **A pin lives 90 days.** A broker, on Linux or on a Mac, and the hub each lock a handover only with a pin whose time
  is not more than 90 days before their own clock, and not more than one day after it (`vault.py`,
  `Sources/FleetVaultCore/VaultOwnerPin.swift`, `hub.py`). The central vault keeps no pin and no unpin dated more than
  one day after its own clock (`vault.py`), and the app signs no pin while the Mac's clock and the hub's clock differ by more
  than an hour (`Sources/FleetCore/CentralVaultPlan.swift`). The hub warns on the System status
  page 30 days before the trust in a server's vault ends, for a server whose vault takes copies, and it tells the fleet
  manager each 7 days, so that the manager asks the owner to open Founderizer on the Mac (`hub.py`). So when the
  owner's Mac stops, the fleet still hands logins over for at least 83 days: a pin lives 90 days, and the app signed
  each one again at most 7 days before.
- **A server that the owner removes on the Mac gets no pin again.** Remove server writes the machine into a record of
  that Mac, and the app then signs an unpin of it and sends it until the central vault takes it. The app signs no pin
  of a machine in that record, by a re-sign or by a first trust, until Add server for that machine on the same Mac
  (`Sources/FleetCore/VaultRemovals.swift`, `Sources/Founderizer/CentralVaultSection.swift`). The record holds no key,
  so a lost record, or the empty record of a new Mac, ends no pin: each trusted machine gets the trust step again.
- Fleet Vault on a Mac makes the same check, with the owner's public keys and the id of the fleet in its
  configuration. Only root writes that configuration, and no install adds the keys: a root step of its own does
  (`Sources/FleetVaultCore/VaultOwnerPin.swift`, `Sources/FleetVaultCore/VaultHub.swift`, `Vault/install.py`,
  `WORKER-INSTALL.md`, "Vault broker (macOS)"). Without the keys, Fleet Vault hands no login over, as a Linux broker
  without them does. So that root step turns handovers on for a Mac.

## What an agent gets

- **A sign-in.** On a Mac, Fleet Vault types the user name, the password and the authenticator code into the page in
  Chrome. First it checks the origin of the page and the origin where the form sends its data. The agent gets only
  the outcome (`Sources/FleetVaultCore/VaultBrowser.swift`, `Sources/FleetVaultCore/VaultBroker.swift`). A Linux
  broker does not sign in (`vault.py`).
- **An API request** (`call_api`). The broker sends the request with the key only to the origin of the saved login,
  over HTTPS. It uses plain HTTP only inside the private range 100.64.0.0/10. The request follows no redirect. The
  agent gets the status and the body, but not a body that holds a key of 8 or more characters (`vault.py`,
  `Sources/FleetVaultCore/VaultProtocol.swift`, `Sources/FleetVaultCore/VaultAnswer.swift`).
- **A new login** (`create_login`). The broker makes a password of 24 characters from the system's random source.
  The agent gets only the name of the new login (`vault.py`, `Sources/FleetVaultCore/VaultGenerator.swift`). The
  owner must first let the agent make logins: this permission is off by default (`hub.py`). A login or a key that a
  task makes works in that task with no grant. Each other task needs the owner's grant (`hub.py`,
  `rules/logins.md`).
- **A handover to another agent** (`hand_over`). The agent gets only the name of a sealed copy, `sealed:<number>`,
  that only the receiving machine can open (`fleet.py`). The copy works for the one task that opens it first, and
  the hub deletes it when that task ends, or after one day if no task opened it (`hub.py`).
- **An API key that the owner lets it read** ("Reads it" in the app). The value is in the agent's sessions as an
  environment variable, except a key that swaps (see the next item) (`hub.py`,
  `Sources/Founderizer/SecretEntryView.swift`). The broker registers its fingerprints with the hub before it gives the
  value, and leaves the key out when the hub does not answer (`vault.py`). The hub does not answer for some seconds
  when it starts again for a release, so the helper reads again at a session's start, 5 seconds later and at most 3
  more times, while the read leaves out a key that the agent's session read before did not leave out, or fails as a
  whole; a fault that stays makes one slow start, no read starts again once 30 seconds passed since the first read
  began, so a hub that answers slowly gets no more calls, and a session keeps what its start got (`fleet.py`). The
  helper writes the values into a file of mode 600, and the session's command reads the file and deletes it before the
  program starts, so no value is in a command line (`fleet.py`). A session of an agent whose Shell box is off gets no
  key. The checks of such an agent still get its keys when the broker tells the hub that the read is for a check,
  which a Linux broker does (`hub.py`, `vault.py`). Fleet Vault on a Mac does not tell the hub what a read is for, so
  the hub gives it no key for such an agent (`Sources/FleetVaultCore/VaultHub.swift`, `hub.py`).
- **An API key that it reads, as a placeholder.** On a Linux server that swaps keys, a key that the hub names with
  a site is not in the sessions (see "The key swap"). The variable holds a placeholder in each session of the
  agent, the owner chat included, and in the agent's checks, because each of them gets its keys by the same read
  (`fleet.py`). The swap proxy puts the key into requests to the key's site (`vault.py`).
- **Never a login's password in a session.** The hub names only API keys with a read grant for a session (`hub.py`).
  The hub knows a key by its kind in the catalog, and nothing ties that kind to the value under its reference, so the
  broker checks the value itself. It gives a session no value that has a user name or an authenticator seed: not as
  itself, and not as a placeholder of the key swap. The swap proxy gives none of it either (`vault.py`,
  `Sources/FleetVaultCore/VaultBroker.swift`). A login that an agent holds as "Uses it" still goes out in `call_api`.
  - **The manager hears of it.** The broker's answer names each key that this rule left out. The helper reports what
    its agent's last read did not give, and the hub tells the manager in a quiet message when a key starts to be
    missing, with the reason and the repair, at most once a day for each key (`fleet.py`, `hub.py`). The start texts name such a key apart, from
    the last read, so the first session after a key goes missing still lists it.
  - **The repair** is to save the key again under the same name in Settings › Secrets. A replace keeps the stored
    address when the new value names none, and it takes the user name and the seed from the new value only (`vault.py`).
  - **What this rule cannot see:** a login that was saved with no user name and no seed has the shape of a key
    (limit 5).

## The key swap

An API key that an agent reads is a variable in its sessions, so an agent with a shell can print it. The key swap
keeps such a key out of the sessions. It is for Linux servers. A new Linux server swaps keys from its install; on a
server that joined before, it is off until root switches it on.

- **The switch.** Root runs the vault program's own step on a server: `vault.py configure --swap on`
  (`vault.py`). It runs only as root and only as the installed program, `/usr/local/lib/fleet-vault/vault.py`,
  which no user can change: never from a checkout. So the code that root runs is the program that the install put
  in place, or the one that `fleet-vault-program` took from a signed release. The step makes the OS user
  `founderizer-swap` and the service `fleet-vault-swap`, and it writes the part `swap` into the broker's
  configuration, which belongs to root. With that part, the broker gives a key that the hub names with a site as a
  placeholder or not at all, never as the key. No agent can change the configuration. A broker that does not stay
  up gets the old configuration back. The step stops where each user can listen on the proxy's port. A second run
  changes nothing and restarts nothing. A lock lets only one step change a vault at one time.
- **Who runs the step.** A new server's install runs it after the vault step (`join.sh`, and `hub.sh` for a hub's
  own server that takes agents, through `hubsetup.py key-swap`). An install goes on when the step stops: it says
  why, and the server then gives each key as a value. `hubsetup.py vault --swap` runs it too. No rule of a server's
  sudoers file reaches it: the service user's two root commands are other programs, and its third right is to run
  a command as an agent user, which the step refuses (`hubsetup.py`).
- **Off.** `vault.py configure --swap off` takes the part away, restarts the broker and stops the proxy. Each session
  that runs on that server with a placeholder then gets no key until its next start, because the proxy stops with
  the switch.
- **The owner's keys and the fleet.** The same step adds owner keys to a vault (`--add-owner-key`) and never takes
  one away, so the step of one Mac of the owner does not take the handovers of another Mac. It sets the fleet's ID
  (`--fleet`) where the vault has none, and it refuses a vault of another fleet.
- **What the step reads.** Its last line is one JSON object, with `swaps`: the broker that runs now swaps keys. Root
  cannot ask the broker itself, because the broker's socket admits only the agents' users. So the step reads the
  broker's socket for the proxy, which the broker makes only after it loads the part `swap`, in its runtime folder,
  which systemd removes at each stop of the broker; and it reads that the proxy's service runs (`vault.py`,
  `SWAPS_FROM`). When the step put the configuration of before back (a broker that did not stay up on the new one,
  or a switch to on that ended badly), its line says `"undone": true` beside `ok` and `reason`: a try again restarts
  the broker two times and ends in the same way while the machine runs the same program.
- **A broker that starts again.** The step restarts the broker when it changes the configuration, and so does
  each release that changes `vault.py`. The broker's socket is gone for that moment: for less than 0.4 seconds on a
  test server. On a Linux machine whose broker is installed, each call to the broker (a session's read of its keys,
  a sign-in, a handover, a new login, an API request, a delivery, the doctor) looks for the socket again for up to
  2 seconds, so a restart is not a refusal. Nothing goes to the broker before the connection, so no request goes two
  times (`fleet.py`, `broker_wait`). The machine report does not wait for a missing socket, because its next round
  reads again.
- **An older program.** A vault program from before the key swap does not start on a configuration with that part
  (`vault.py`). The root command that brings the program of a release, `fleet-vault-program`, puts back the program
  that was serving when the new one does not start. The root step `hubsetup.py vault` with an older program leaves
  the broker stopped (`hubsetup.py`). So an older program does not switch the key swap off. A program from before
  the step does not know `configure`, and an install with it says so and goes on.
- **Which key swaps.** The hub names the site of a key when all of these hold: the agent's grant is "Reads it"; the
  key's catalog entry has a site, an `https` address with a host name, which the owner sets with the tool
  `save_login` of the owner's MCP server (`owner_mcp.py`) or which the table of well-known services gives it (the
  next item); the agent's program is Claude Code or Codex; the key is not the key of a model account; no MCP server
  names the key; the site is not a host of the provider of the agent's own program (`lifecycle.py`, `hub.py`). Each
  part comes from `team.json`, where the owner writes it, and where the hub's step at a key's birth and the fleet
  manager's switch write only a site that the table made, and from a fixed table of each program's hosts
  (`lifecycle.py`). The site is also the address that a check of the
  key must keep to, so a key that has a site already swaps when root switches its server on (`hub.py`). The hub
  does not decide by a report from an agent's machine. Each broker decides by its own configuration whether its
  server swaps keys (`hub.py`, `vault.py`).
- **A site from the table of well-known services.** A key of a well-known service gets its site with no person who
  types it (the owner's choices of 14 November 2026). The signed code has a table: for each service its API host,
  the form in which the service's own SDK and CLI send the key, and the addresses that select it. Today the table
  has OpenAI, Replicate and Cloudflare, each read in the service's own reference and SDK source (`lifecycle.py`
  `KEY_TABLE`, with its sources). When the owner adds a key whose address selects a row (Add secret's "Service
  address", the site of an agent's request on its card, an import row), the hub writes the row's site and form into
  the key's catalog entry, with a mark that the table made them. The hub takes that address from a version of the
  app that sends it; an app from before sends none, and its keys get no site from the table. The app sends only the
  address's scheme, host and port, because a path can be a secret, so the table's key pages never match from the app
  (the manager's choice C40). It does this only at the key's birth, and only when
  nothing holds the key: no grant of an agent at any level, no profile, no account, and no MCP server or saved check
  that names its variable (`hub.py`). The hub keeps nothing of the address but the row. An API host selects its row
  with any path; a web page selects it only by its exact host and the exact path of the key page (one slash at the
  end, a query and a fragment change nothing; another case of the path, a port other than 443, a user part, a
  subdomain or a longer name select nothing). Cloudflare's tokens page selects nothing, because the same page shows
  the Global API Key, which goes in another header (`lifecycle.py` `key_table_row`). For the keys that are stored
  already, the central vault answers one question of the hub: which stored keys (not logins) have an address that
  selects a row of its own copy of the table, and which row; the hub then reads its own catalog for them. It gives no value, no address and no host, and it takes no host
  from the hub (`vault.py` `key_addresses`). The hub counts once with it: one line of the hub's log with numbers, and
  nothing written (`hub.py` `key_table_count`); no pass writes the sites of today's keys (the owner's choice C39).
- **A table-made site is a default, not a lock.** The fleet manager switches such a site off, with no approval and
  a one-line why that goes into the commit of `team.json` and the hub's log, and on again (`switch_key_site`). Off,
  the key is a value in the sessions of the agents that read it, from their next start. From the moment of the
  switch, a session that runs with a placeholder of the key gets no key any more, for each agent that reads it,
  until its next start: the hub's answer to its use is no (`hub.py` `helper_vault_swap`), and the proxy refuses the
  request. That holds also for an agent whose program worked with the placeholder. An agent that persuades the
  fleet manager gets the key as a value. A site that the owner sets with `save_login` ends the mark: that site is
  the owner's lock, which no table and no tool of an agent changes. A later release can change a row or take it out:
  an entry that the table made keeps its own site and form, and only the manager's "on" reads the row again, which a
  row that is gone refuses (`hub.py`).
- **What the hub says about a server.** The hub keeps two records of each Linux server, apart (`hub.py`). The word,
  `key_swap`: the owner's Mac app read as root that the server's vault swaps keys, after its step there. Only the
  route of that reading writes it, and it says only what the reading found. The owner's wish, `key_swap_wish`: the
  owner's own yes or no for the server, with the tool `server_key_swap` of the owner's MCP server (`owner_mcp.py`),
  or with the answer of a Needs-you item. A server where an agent reads a key that has a site waits for the owner's
  yes: the hub asks the fleet manager for one item about it, whose title and two answers are the hub's words. An
  agent whose Shell box is off waits too: its sessions get no key, but its checks read its keys and get the
  placeholder there. A key that an agent only uses (`call_api`) makes no wait, because the vault sends it as before
  (`hub.py`, `key_swap_waits`; `vault.py`, `swap_call`). The
  hub reads no report of a machine for these records. It uses the word only for what it says. The settings check
  does not count a key that swaps there as a key in the agent's sessions. The start text of an agent whose sessions
  get the variable says that the variable holds a placeholder, which begins with `vaultswap_`, and not the key
  (`hub.py`). The word opens nothing, and no vault reads it. A wrong word makes the settings check and the start
  text say a thing that is not so.
- **The placeholder.** The broker makes one placeholder for each agent and key: `vaultswap_` and 160 random bits.
  It keeps a list of them with the OS user, the agent, the name of the key, the site and the form, and no value
  (`vault.py`). A placeholder is no secret: it is of use only on that server, to that OS user, for that site. At
  each read of an agent's keys, the broker switches off the placeholders of that OS user for keys that the hub
  names with a site no more. The broker gives no value for a placeholder that is off, and the proxy does not read
  a connection to a site that only such a placeholder names. An entry is for its OS user by number and by name
  (`vault.py`).
- **A placeholder with no read.** When the agent has no read grant left, its helper asks for no read (`fleet.py`).
  So the broker also switches a placeholder off on the hub's own word. When the hub says no to a use, the broker
  switches that placeholder off. When the hub takes the value of a key back from the server, the broker switches
  off each placeholder of that key (`vault.py`, `hub.py`). A placeholder comes on again at the agent's next read
  that gives the key as a placeholder. It also comes on when the hub delivers the value to the server again and
  then says that the agent reads the key now. The hub's answer names the OS user that the agent has on a Linux
  server, and the broker takes the answer only for a placeholder of that OS user: a name that the owner gave to
  another agent of the same server opens nothing for the OS user that had the name before (`vault.py`, `hub.py`).
  So after the hub's no, a grant
  that comes back with no new delivery reaches a session that still runs only at the agent's next read, which is
  the start of its next session or check. Some placeholders stay on with no use: the one of an agent that lost its
  grant and does not use it again, on a server where another agent still holds the key or where no helper carries
  the hub's take-back; the one of an agent that moved to another server, because the hub answers the old
  server's vault with a refusal that says nothing of the grant; and the one that an agent got under its old name,
  when it has a new name and makes no read, because the hub knows no agent of the old name. The hub refuses each
  use of such a placeholder, and a use that gets the hub's no for the grant switches it off (`vault.py`,
  `hub.py`).
- **The swap proxy.** A session that holds a placeholder gets the variables that make its HTTPS programs use the
  proxy on `127.0.0.1` (`fleet.py`, `lifecycle.py`). The proxy runs as `founderizer-swap`, which can read neither
  the store nor its key (`vault.py`, `hubsetup.py`). It reads the OS user of each connection from the kernel's
  table of sockets, and it serves only an agent user of its server (`vault.py`).
- **Other hosts are not read.** The proxy passes a connection to a host that is no site of a key of that OS user
  on as it is, and it does not read it (`vault.py`). It also cannot open the TLS of such a connection: the helper
  adds only the CAs of an agent's own keys' sites to the lists of CAs that the agent's sessions use, and each of
  these CAs is limited to one host name (`fleet.py`, `vault.py`).
- **A key's site.** For a connection to a key's site, the proxy reads the head of one HTTP request. It puts the
  key in the place of the placeholder only in the `Authorization` header, only as the whole credential, and only
  in the one form of that key: `Bearer`, `token`, or the user name or the password of `Basic`. The form is
  `Bearer` when the key's catalog entry names no other (`vault.py`, `lifecycle.py`). The proxy refuses a request
  whose head has a placeholder in another place or in another form, and a `TRACE` request with a placeholder,
  because a server sends such a request back. It sends the request on a TLS connection of its own, which checks
  the site's certificate against the system's list of CAs (`vault.py`). It reads no byte of a request after its
  head, and no byte of an answer.
- **One CA for each site.** The proxy makes one CA for each site. X.509 name constraints limit it to that one host
  name: a program that checks the constraints refuses a certificate that this CA signs for a name under it, for
  another name or for an IP address (`vault.py`). The helper writes two CA files for an agent: the system's list of
  CAs with the CAs of the agent's own keys' sites, and those CAs alone (`fleet.py`).
- **The grant, at each use.** Before the broker gives the proxy a value, it asks the hub: does this agent still
  read this key at this site and in this form? Each answer that is not an exact yes is a refusal (`vault.py`,
  `hub.py`). So the end of a grant stops the next request of a session that runs. When no answer comes (a refused
  connection, a reset or a timeout: the hub does not answer for 2 to 3.4 seconds when it starts again for a
  release), the hub's yes to an earlier use of the same placeholder counts for 60 seconds from the moment that the
  question of that yes left. It counts only for the same entry (OS user, agent, key, site, form and token) while
  the entry stays on. A use does not renew it, each answer of the hub that is not a yes ends it, a yes counts only
  when its question left after the question of each no, and the broker keeps it in its memory only, so a new broker
  process has none. The broker writes one line for each use of such a yes, with the agent, the key's reference and
  the age in seconds (`vault.py`). With no such yes, a hub that does not answer is a refusal. The hub's answer does
  not look at the agent's Shell box: a session that started before that box went off still gets the key in its
  requests while the grant holds (`hub.py`).
- **`call_api` on such a server.** The broker can also send a request itself (`call_api`). On a server that swaps
  keys, it sends a key that the hub names with a site only as the proxy does: to that site, in the `Authorization`
  header, and in the key's own form. A key whose form is `token` or the user name of `Basic` goes through the
  proxy only (`vault.py`, `hub.py`).
- **The model's own calls.** The variable `NO_PROXY` names the hosts of the provider of the agent's own program,
  the hub and the machine itself, so the calls to them do not go through the proxy (`lifecycle.py`, `fleet.py`).
  For a check, it names only the hub and the machine itself (`fleet.py`).

## How the vault's code is updated

- A hub takes a release only when the release's manifest has a valid signature (`releases.py`).
- A root step brings each Linux broker to the `vault.py` of the release. The server's own service starts it, and it
  installs the new program only when root-owned copies of the release check accept the release's signature, and
  only a release that comes after the floor of the releases that this broker took (`server.py`, `hubsetup.py`). A
  limit: a server with no floor yet takes any signed release at its first update. The program that its install put
  in place serves until then.
- The owner's Mac app brings the central vault to the `vault.py` of the hub's release by itself. It runs the root step
  of the install over the owner's SSH connection. That step takes only a release that a key in root's own clone
  accepts, and that comes after the clone's revision (`hub.py`, `hubsetup.py`, `Sources/FleetCore/CentralVaultPlan.swift`).
- On a Mac, a root updater installs a newer Fleet Vault only when its manifest came over HTTPS, the SHA-256 of the
  file is the one in the manifest, and the new build passes the check of the team's signature (`Vault/update.zsh`).

## What the vault does not protect

1. **An API key that an agent reads, and that does not swap.** The key is in the agent's sessions, so an agent with
   a shell can print it or send it to another place. The rules forbid this (`rules/logins.md`), and the hub masks
   the key in the texts that it sees, but nothing else stops it (`fleet.py`,
   `Sources/Founderizer/SecretEntryView.swift`). A key does not swap on a server that did not get the root step,
   on a Mac, when its catalog entry has no site, when the agent's program is not Claude Code or Codex, when it is
   the key of a model account, when an MCP server names it, or when its site is a host of the provider of the
   agent's own program (`lifecycle.py`, `vault.py`). A session that started before the key swapped keeps the key
   until it ends.
   **A key that swaps is not in the sessions, with these limits:**
   - The agent can use the key for each thing that the key can do at its site, also to make a second key there if
     the service has such a call.
   - A grant that ended still puts the key into requests for up to 60 seconds after the hub's last yes to a use of
     its placeholder, counted from the question of that yes, while the hub does not answer the vault. An agent of
     the server can make the hub slow or silent for its vault, for example with requests that keep the hub busy or
     when it takes each free local port, but no yes counts for longer: a use does not renew it, and each answer of
     the hub that is not a yes ends it (`vault.py`).
   - A placeholder works only in a request through the proxy. An agent that writes the key's variable into an
     application's configuration, on a server or in a file, writes the placeholder there, and the application fails
     later, with no sign at that moment. The fleet manager switches the table's site off first for such work, or the
     door does it (`rules/manager.md`). A task's start text says so, with each key's form, and asks the agent to
     ask its requester when a program cannot use a placeholder (`hub.py` `key_words`).
   - An owner chat holds the placeholders, as each session of its agent does, but its start text names no key and
     says nothing of a placeholder (`fleet.py` `chat_instructions`): an agent that runs a program in its owner chat
     and gets the proxy's refusal has no words for it. A chat sends its work to a task (`start_task`, with the
     agent's line as its requester), whose start text has the words, and it reaches its line with `message_agent`,
     with no step of the owner. To name the keys in a chat's start text would change that text, and so start a new
     conversation of each owner chat.
   - A hub of a release before the table refuses a `team.json` with a mark, whose field `table` it does not know. So
     the app's part, which sends the address that makes the first marks, comes only after the hub's part is live and
     proved, and a fleet with marks does not go back to a hub from before it.
   - Replicate's API also takes the word `Token`, which its older clients and documents use, and an agent can write
     it from memory. The row's form is `bearer`, and the proxy takes a placeholder only in the entry's own form, so a
     request with `Token` and the placeholder gets the proxy's refusal (403).
   - A site from the table is only as right as the address that the owner gave. A request that names a host of the
     table for a key of another service gives a placeholder that does not work; the fleet manager switches it off.
     A site from the table also does not serve: a websocket (the proxy passes no `Upgrade`, so OpenAI's realtime API
     gets no key), another host of the same service (a project with OpenAI's data residency sends its key to its
     region's host, for example `eu.api.openai.com`; an account in Cloudflare's FedRAMP uses
     `api.fed.cloudflare.com`), and an agent whose program's own provider has that host (an OpenAI key stays a value
     for an agent of Codex) (`lifecycle.py`).
   - A site that sends the key back gives it to the session: an answer that repeats the `Authorization` header.
     The proxy does not look for the key in an answer (`vault.py`).
   - The key goes only in the `Authorization` header, as `Bearer`, `token` or `Basic`. A program that needs the
     key in another place gets no key. When the placeholder is in another header or in the address of a request to
     the key's site, the proxy refuses the request. When a program puts the placeholder in a body, makes a
     signature from it, sends it to another host, or does not use HTTPS, the placeholder goes out as it is
     (`vault.py`).
   - A person who breaks into the swap proxy can get the keys that swap on that server, of each agent user, and can
     read the traffic to those keys' sites. That person also sees the names of the other hosts to which the
     sessions connect through the proxy. That person does not get the store, a login's password, or a key that
     does not swap (`vault.py`).
   - On a server whose proxy service has no `PartOf=fleet-vault.service` line (the root step of this version
     writes it so), a new vault program does not cut a connection that passes bytes: the proxy that runs lets the
     new program take over as a new process, and ends with its own connections. A connection that is open for
     two new programs is cut at the second one, and so is a connection that only waited at the hand-over
     (`vault.py`). These cut each open HTTPS connection of the sessions that hold a placeholder, except to the
     hosts that `NO_PROXY` names: a restart of the proxy's own service, by root or by the root step when it
     changes the service (`hubsetup.py`); the end of the new process by a fault while the old one still has
     connections; and, on a server with the `PartOf` line, each restart of the broker (`vault.py`).
   - A new vault program whose proxy does not start is not taken by a proxy that runs, which tries it again
     later. After a start of the server, or of the proxy's service, that program's proxy stays down, and a session
     that holds a placeholder has no HTTPS until a later program (`vault.py`).
   - An agent of the server can make each such try fail, for example when it takes each free local port at that
     moment. The proxy then goes on with the older program for as long as the agent does that. The proxy's log has
     a line for each failed try, and the broker's status does not say which program the proxy runs. A restart of
     the proxy's service by root starts the installed program (`vault.py`).
2. **Short and simple values.** The hub finds only a value of 8 or more characters with no space in it. The vault uses
   a shorter value, but the hub cannot mask it, and `call_api` can give it back in a body (`vault.py`,
   `Sources/FleetVaultCore/VaultProtocol.swift`, `Sources/FleetVaultCore/VaultAnswer.swift`). Also, the hub's database
   keeps a hash and the length of each value, and the key of the salts is in the same database (`hub.py`). So a
   person with a copy of that database can find a short or simple value by guessing.
3. **A key that the owner types into a chat.** It is in the chat's records before anything can mask it (`RULES.md`).
   The Mac app asks before it pastes a key into a chat message, but the owner can paste it anyway
   (`Sources/Founderizer/FleetView.swift`).
4. **Root, and the vault's own OS user.** On a Linux server, only file owners and modes protect the keys and the
   stores, so root and the vault user can read them (`vault.py`, `hubsetup.py`). On a Mac, root installs and replaces
   Fleet Vault (`Vault/install.py`).
5. **A hub that is broken into, inside one machine.** For an API key that a session reads, an API request and a new
   login, a broker has only the hub's word. So a hub that is broken into can make a broker give any value of that
   broker's store to the agent users of its machine, or send it to the saved site of that value. It can also put a
   value of its own into a broker's store (`vault.py`). On a server that swaps keys, the hub's word also says which
   key swaps and what its site is. When the hub names no site for a key, the broker gives the key itself to the
   session (`vault.py`, `hub.py`). A broker gives a session no value with a user name or an authenticator seed. But a
   login that was saved with no user name and no seed has the shape of a key, so the hub's word can still bring such a
   login's password into a session, and an older Fleet Vault build on a Mac has no such check (limit 6).
6. **A Mac that does not have the owner's keys.** Fleet Vault on a Mac checks the owner's pin of the receiving key
   with the owner's public keys and the id of the fleet that root gave its configuration. No install gives them
   (`Sources/FleetVaultCore/VaultOwnerPin.swift`, `Vault/install.py`). Without them, Fleet Vault refuses each handover,
   as a Linux broker without them does, so such a Mac hands no login over. The root step of
   `WORKER-INSTALL.md`, "Vault broker (macOS)", turns handovers on. A sign-in, a session's read, `call_api`, a delivery
   and a withdrawal do not need the keys (`Sources/FleetVaultCore/VaultHub.swift`,
   `Sources/FleetVaultCore/VaultBroker.swift`). The agents of a Mac run as the OS user of its Fleet Vault, so an agent can
   start an older signed build in its place. Since build 15, no older build opens the store of a Mac that made its
   move to the newest key generation (see "In Fleet Vault on a Mac"). What stays:
   - **The time before the move ends.** The move ends when the old items are deleted, and until then an older build
     still opens that Mac's store. An agent can keep the new build from its first start, or keep the move from its
     end: it can stop Fleet Vault, hold the move's lock, or keep the disk full so that the deletes fail. Then a build
     before 14 hands a login over without the owner's keys, and a build before 12 checks no pin.
   - **A check that comes with no new generation.** An older build of the same generation can undo it
     (`Sources/FleetVaultCore/VaultKeychain.swift`, `Vault/update.zsh`).
7. **An old pin, and an old owner key.** A broker that checks the owner's pin of the receiving key, on Linux or on a
   Mac, keeps no record of an unpin. So a hub that is broken into can hold an unpin back, and send the last pin of a
   key that the owner removed, until that pin is 90 days old (`vault.py`, `Sources/FleetVaultCore/VaultOwnerPin.swift`).
   Each broker reads that age with its own clock. A broker whose clock is days behind takes an old pin for that much
   longer, and it refuses a new pin as dated after now until the pin is less than a day ahead of its clock. A broker
   more than 8 days behind refuses each handover, because the app signs each pin again after 7 days. On 14 November
   2026 the clock of each machine of the fleet was within a second of the hub's. While the owner adds a server on a
   Mac, a hub that is broken into can name a removed machine as the server that joined with that Mac's join code, and
   that clears its mark (`Sources/Founderizer/AddMachineView.swift`, `Sources/Founderizer/MachineInstallView.swift`).
   The record of removed servers is only on the Mac that removed them: a removal by another Mac, or
   by the owner's MCP tool `remove_machine`, signs no unpin and writes no record, and a new Mac does not know a removal
   of the old one. The app of such a Mac signs the pin of that machine again while the hub's reading names it as
   trusted (`Sources/FleetCore/VaultRemovals.swift`). The other way round, a server that the owner removed on a Mac and
   then adds again by another way (another Mac, or the MCP tool `add_machine`) keeps its mark on that Mac. That Mac
   then signs no pin of it by itself: the server's row on the Secrets page says that the owner removed it on this Mac,
   and Try again on that row clears the mark and runs the trust step (`Sources/FleetCore/CentralVaultPlan.swift`).
   Until then the central vault seals nothing to it, and its agents get no login by handover. A hub that is broken
   into can make that row show, but only the owner's Try again clears the mark. An agent of a Mac whose agents run as the SSH user can make each
   re-sign of that Mac fail: then its server row shows after six tries, the warning shows at day 60, and at day 90 that
   Mac's agents get no login by handover (`Sources/FleetCore/CentralVaultPlan.swift`). On a Mac, Fleet Vault before
   build 17 checks no age of a pin. Build 17 keeps key generation 3, so an agent of a Mac can start build 16 in its
   place, which opens the same store and checks no age (limit 6, "A check that comes with no new generation"), until
   a later build raises the generation (`Sources/FleetVaultCore/VaultKeychain.swift`). A pin that the central vault
   took with a time more than a day ahead, before it refused such a pin, cannot be put right before its time: each
   broker refuses it until it is less than a day ahead, and a new pin is not newer than it (`vault.py`). The live fleet had none on 14 November 2026. A broker also keeps the owner keys that its root step gave it after the owner changes
   Macs, until a root step on that machine changes them, and it refuses a pin that another key signed (`hubsetup.py`,
   `Vault/install.py`). The app signs each kept pin again with the new Mac's owner key, so such a broker then refuses
   handovers until that root step (`Sources/FleetCore/CentralVaultPlan.swift`).
8. **The end of a grant.** The end of a grant, of a pin and of a pool entry reaches the central vault only through
   the hub. A hub that is broken into can hold it back, and the central vault then still seals that secret
   (`Sources/Founderizer/GrantSigning.swift`).
9. **The pool.** A value in the pool needs no grant. The fleet manager can give it to an agent on any machine, and the
   central vault seals it to each machine whose key the owner pinned (`Sources/FleetCore/OwnerKey.swift`, `vault.py`).
10. **Agents of one Mac.** All agents of a Mac run as one OS user, and the hub key of each agent is a file of that user
    (`fleet.py`). So an agent can use the grants of another agent of the same Mac.
11. **The release key.** Releases change the vault's code on each server and in the central vault without a step from
    the owner (see "How the vault's code is updated"). So the holder of a release key can change every broker and the
    central vault (`hubsetup.py`, `hub.py`). On a Mac, a build with the team's Apple signature can replace Fleet Vault
    (`Vault/update.zsh`).
12. **A page in the browser.** On a Mac, Fleet Vault types the password and the code into the page in the Chrome that
    the agent uses (`Sources/FleetVaultCore/VaultBrowser.swift`, `rules/logins.md`). A program that can run a script
    in that page can read them, and it can use the session's cookies after the sign-in. The code says that it protects
    the vault's keys, not the browser's session (`Sources/FleetVaultCore/VaultBrowser.swift`).
13. **The owner's Mac while it is unlocked.** The app signs with the owner key with no Touch ID or password prompt
    (`Sources/FleetCore/OwnerKey.swift`). So a person or a program that controls the Mac as the owner can sign
    statements: with the app's own controls, or through the app's link, where the tool `grant_secret` of the
    app's own program makes the app sign a grant of a secret to an agent, or its end, with no question to the
    owner (`Sources/FleetOwnerAPI/OwnerGrantSecret.swift`; OWNER-MCP-BOUNDARY.md, section 7b). A copy of the app
    with a different signature must first get the owner's login password from macOS to read the key's item
    (`Sources/FleetCore/OwnerKey.swift`). The hub takes each call from the Mac's address that
    carries the Mac's own key for the hub, which is a file of the owner's user (`hub.py`, SECURITY.md, "How the hub
    knows the owner's computer"). So a program that runs on the Mac as the owner uses every owner route. A VM or a
    container on the Mac has the Mac's address and not that file, and the hub refuses it, unless the owner gives it
    the folder `~/.founderizer`.
14. **The hub's own sign-ins.** The Google refresh tokens and their client secret, the GitHub App private key, the
    credentials of the MCP servers and the Discord bot tokens are not in the vault. They are files of the hub's OS user
    on the hub's server, so a person who controls that user has them (`hub.py`, `channels.py`). The Google file is
    sealed with ChaCha20-Poly1305 under a key that the central vault keeps and gives to the hub's user, so a copy of
    the hub user's files does not open it (`hub.py`, `atrest.py`, `vault.py` `hub_key`). Until a central vault serves
    that key, and on a Mac, the key is in a second file of the hub's user outside the hub's data folder, so only a copy
    of that folder alone does not open it. Neither protects the file from that user, who can ask the vault, or from a
    copy of the whole disk.
15. **The door's secrets.** The door keeps each secret that it opened, and each key that it made itself, in a file of
    its own OS user, not in an age store. The hub keeps an SHA-256 of each secret that the door opened, with no salt
    (`door.py`, `hub.py`).
16. **The links between the machines.** The hub serves HTTP, not HTTPS (`hub.py`). It depends on the fleet's private
    network, Tailscale, to protect these links (`HUB-INSTALL.md`, "The private network" and "The firewall"). Agent keys
    and job numbers go over them. A value of a secret goes over them only as a sealed copy, except a key that
    `call_api` sends with plain HTTP to a service inside the private range (`vault.py`).
17. **A broker that is lost.** No copy of the fleet has a broker's store key. If a machine's broker is lost, the
    logins that it made are lost too, also the passwords of accounts that `create_login` opened, which the owner never
    saw (`hub.py`).
18. **An export file.** After an import, the export file stays on the disk until the owner deletes it
    (`Sources/Founderizer/SecretImportView.swift`).
19. **The connections of an agent's shell.** Founderizer has no list of the hosts to which the shell of a session can
    connect. The helper starts each session as a program of the agent's OS user (`fleet.py`). A task session
    in a terminal, and the manager's session, start with full access: Codex with `--sandbox danger-full-access`, and
    Claude Code with its shell tool allowed (`lifecycle.py`, `fleet.py`). These sessions do not start with full
    access. An owner chat of Claude Code, a session of an agent whose Shell box is off, and a locked conversation with
    a person have no shell (`fleet.py`). An owner chat of Codex starts in Codex's `read-only` sandbox (`fleet.py`). A
    task in the Codex app-server runner, which each screen task is, starts in Codex's `workspace-write` sandbox
    (`screen_runner.py`, `lifecycle.py`). A task of an ACP program runs in a runner that allows each permission
    request of the program itself, or asks the hub, which waits for the answer of the task's requester
    (`acp_runner.py`, `hub.py`). Where a session has a shell, the only limits on its connections are the sandbox of
    its own program and, for an ACP program that asks the hub, its requester's answer to each request. On a Linux
    server, the firewall step of the install closes incoming connections only: when it turns the firewall on, it
    allows each outgoing connection (`hubsetup.py`). So a value that a session with full access can read (see
    limit 1) can go from its machine to any host, and the hub does not see that connection. Only two services of a
    fleet run with no IP network, and no session of an agent runs in them: the central vault,
    `fleet-vault-central.service` (`vault.py`, `hubsetup.py`), and the door's render service,
    `fleet-door-render@.service` (`door.py`). The unit of a third service, the gate of the connected apps,
    `founderizer-connect.service`, lets it use only Unix sockets and the address 127.0.0.1, and no session of an agent
    runs in it (`hubsetup.py`). The Web box of an agent's Tools row does not change this. For an agent with a shell,
    the helper removes no tool when that box is off (`fleet.py`), and a shell needs no web tool to connect. The one
    host list that Founderizer has is for the page reads of a task session of an agent whose Shell box is off, and
    such a session has no shell (`fleet.py`, `lifecycle.py`). The swap proxy of "The key swap" is no such list
    either: it passes a connection to each host that is not a key's site on as it is (`vault.py`).
20. **The end of "Reads it" in a session that runs.** When the owner changes "Reads it" to "Uses it", or takes the key
    back, the hub records the change and asks the agent's helper to update when it is idle (`hub.py`,
    `lifecycle.py`). Nothing stops a session. A session that started before the change keeps the value in its
    environment until the session ends (`fleet.py`). A session that starts after the change gets no value, because
    the hub names the keys of a session again at each start (`hub.py`, `vault.py`,
    `Sources/FleetVaultCore/VaultHub.swift`). The helper keeps the keys for the agent's checks in its memory. It reads
    them again only after a check failed, after it took the update, or after its machine's vault took a new delivery
    of a key that the agent reads, so until then a check still runs with the key (`fleet.py`, `hub.py`). With "Uses it", the value stays in the broker's store, and the broker still sends API requests with
    it for the agent. When no agent of the machine holds the secret any more, and the central vault holds it, the hub
    asks a broker that takes withdrawals to give the value back (`hub.py`, `vault.py`). The agent could also copy the
    key while it had the grant (see limit 1). So the end of a read grant does not take the key from the agent.
    A key that swaps is the exception. Its value is in no session, in no owner chat and in no check of the agent:
    each one holds only the placeholder, also the checks' copy in the helper's memory (`fleet.py`). The broker asks
    the hub at each use, so the end of the grant stops the next request, also of a session and of a check that
    started before (`vault.py`, `hub.py`; see "The key swap"). Two things stay: what the agent did with the key at
    its site while it had the grant (limit 1), and the value in a session that started before the key swapped.
21. **The first vault key of a machine.** While no agent of a machine has had a session, the hub keeps the vault key
    that the reports of that machine's helpers agree on. The last of these keys is the machine's first key. The
    first grant binds that key, and a machine that then reports another key gets no grant (`vault_store_mismatch`)
    (`hub.py`). The hub knows a session by its session credential, which each session of an agent with an agent key
    gets before it starts, and by its runtime's first call to the hub (`hub.py`, `fleet.py`). The hub writes down the
    end of that keep before the first sign of a session, so the end stays when the sign goes, for example with an
    agent that the owner removes. A machine that is bound at that moment keeps its bound key the same way. Only the
    removal of the machine from the fleet opens the keep again (`hub.py`). The app
    pins a machine's key by itself when it reads on the machine the key that the hub has bound. On a Linux server, it
    reads the key as root from the broker's key file. On a Mac, it asks Fleet Vault on its socket, as the OS user of
    that Mac's agents (`Sources/FleetCore/CentralVaultPlan.swift`, `Sources/Founderizer/CentralVaultSection.swift`,
    `Sources/FleetCore/CentralVault.swift`). A program of that OS user can answer on that socket in the vault's
    place. So on a Mac, the pin shows only what that OS user said, and the first key from before any session is what
    makes it true. The case that is left has three ways. In the first two, the machine's helpers named no key in a
    report before the first session of one of its agents: a broker that first answered after that session, or an
    agent that had sessions on another machine before it moved here (the hub cannot tell where a session ran). For
    such a machine the hub takes the first key from the report at the first grant, and keeps it until the owner
    removes the machine from the fleet. The third is a session of an agent without an agent key, which has no
    credential: the hub sees it only at its runtime's first call to the hub, so a report that comes before that call
    is still kept as the first key, also through a whole session whose runtime does not reach the hub. In each way, an agent that reports a key of its own in time, and answers with
    it on a Mac's socket, can get that key pinned. The central vault then seals the secrets of that Mac to a key that
    the agent holds. The hub also locks each handover to an agent of that Mac for that
    key, and the owner's pin of it lets a broker that checks pins hand the login over (`hub.py`). On a Linux server,
    an agent that reports a key of its own before the first grant gets no pin: the app reads another key as root,
    so it pins nothing for that server, and the central vault seals nothing to the false key. The hub then hands no
    login over to an agent of that server, because it keeps no pin of the owner for it (`hub.py`). A hub that is broken
    into can still name the false key: a broker that checks pins refuses it, because the owner signed no pin of it, and
    a broker without the owner's keys hands no login over at all (limit 6) (`vault.py`,
    `Sources/FleetVaultCore/VaultOwnerPin.swift`).
22. **The old value after a replace.** When the owner replaces the value of a key, the central vault holds the new
    value at once, and the old value is in no store of the central vault after that (`vault.py`). The store of a
    machine holds the old value until the machine took its new delivery: the hub makes that delivery at once, and the
    machine's helper carries it at its next question to the hub. A machine that is off, and a machine whose vault
    program is from before the replace, keep the old value until they are back and current (`hub.py`). Until then
    that machine's vault gives the old value to a new session, to a check and to the swap proxy. After the machine's
    vault took the new value, it gives only the new one. A session that started before keeps the old value in its
    environment until it ends, on a machine that does not swap keys (`fleet.py`). A delivery that fails leaves the
    old value in that machine's store, and the hub sends it again after 6 hours (`hub.py`, `vault.py`). The old
    value also stays in each backup of the central vault that was made before the replace (`vault.py`). So a replace
    in the vault does not end the old key: only the service that made the key can end it.

## What the owner must do

1. **Protect the Mac.** The owner key and the recovery code are in its login Keychain, and the app uses the owner key
   with no prompt (`Sources/FleetCore/OwnerKey.swift`, `Sources/FleetCore/RecoveryCode.swift`).
2. **Run the root steps.** Only a root step installs and updates the central vault. The Mac app runs it over the
   owner's own SSH connection (`hubsetup.py`, `Sources/FleetCore/CentralVault.swift`). On a Mac with agents, the
   install of Fleet Vault needs an administrator, because it runs as root (`Vault/install.py`). After that install,
   the root step of `WORKER-INSTALL.md`, "Vault broker (macOS)", gives Fleet Vault the owner's public keys. That step
   turns handovers on for the Mac, which hands no login over without them (limit 6). For a machine whose
   host key the Mac does not know yet, the owner connects to it once with ssh from Terminal
   (`Sources/Founderizer/CentralVaultSection.swift`).
3. **Give each secret on purpose.** The app makes the recovery key and the pins of the servers itself
   (`Sources/FleetCore/CentralVaultPlan.swift`). An agent gets a secret when the owner gives it, and the app signs that
   grant (`Sources/Founderizer/GrantSigning.swift`), or when the fleet manager gives it a secret of the pool
   (`Sources/FleetCore/OwnerKey.swift`). Put a secret into the pool only if any agent may have it. "Reads it" puts an
   API key in the agent's sessions, so give it only to an agent that must have the key itself
   (`Sources/Founderizer/SecretEntryView.swift`). For a key that swaps, name the exact host of the service's API as
   its site. Do not name a host that sends a request back in its answer, or a host that the service shares with
   other customers, because the agent can send the key in a request to each path of that host. Give the key the
   smallest rights at its service (`hub.py`, `vault.py`).
4. **Put keys in the vault, never in a chat.** Use Add secret. An agent asks for a key with a form, never in words
   (`RULES.md`). If a key went into a chat, replace it at its service (`RULES.md`).
5. **Delete an export file.** After an import, select **Delete export file**, or delete the file in Finder and empty
   the Trash (`Sources/Founderizer/SecretImportView.swift`). Delete each other copy of the file too, for example in a
   backup.
6. **Keep the recovery code.** It is only in the Mac's login Keychain and on a phone that enrolled after the Mac had
   the code (`Sources/FleetCore/RecoveryCode.swift`, `Sources/Founderizer/RecoveryCopy.swift`). Without it, a backup
   of the central vault cannot be opened (`vault.py`).
7. **Know what a new Mac changes.** The root step from a new Mac makes its key the only owner key of the central vault
   (`hubsetup.py`, `Sources/FleetCore/OwnerKey.swift`). The recovery key does not change: a backup still opens only
   with the lost Mac's code, which only a phone that took a copy has (`Sources/FleetCore/CentralVaultPlan.swift`,
   `Sources/Founderizer/RecoveryCopy.swift`). A Linux broker, and Fleet Vault on a Mac that has the owner's keys,
   keep the old owner key until a root step on that machine changes it (`hubsetup.py`, `Vault/install.py`). Do that
   root step on each such machine soon. Within 7 days the new Mac signs the pin of each machine again with its own
   key, and such a broker refuses each pin that the new key signed. So that machine's broker hands no login over
   until its root step (`Sources/FleetCore/CentralVaultPlan.swift`, `vault.py`). Keep Founderizer running on a Mac:
   it signs each pin again after 7 days, and a pin lives 90 days. When the Mac stops, handovers go on for at least 83
   more days, and the System status page warns 30 days before the end (`hub.py`). A server that
   you removed on another Mac, or with `remove_machine`, is not in this Mac's record of removed servers. A server that
   you removed on this Mac and add again another way has a row on the Secrets page: select Try again there to trust it
   (limit 7).
8. **Replace a key after the end of "Reads it".** When you take "Reads it" from an agent, replace the key at its
   service. A session of the agent that runs keeps the old value until it ends, and the agent could copy the value
   while it had the grant (`fleet.py`, `hub.py`). A key that swaps is different: the agent had only a placeholder,
   so the end of the grant stops its use (`vault.py`). Replace such a key when a session held its value at an
   earlier time: before the key swapped, or on a machine that does not swap keys. Replace it also when its site can
   send a key back in an answer (limit 1). If the service lets a key make more keys, look there for keys that the
   agent made. Then save the new key with Add secret under the same variable name: the app puts it in the place of
   the old value, and the same agents keep it (`Sources/Founderizer/SecretEntryView.swift`). End the old key at its
   service too, because the vault cannot end it (limit 22).
