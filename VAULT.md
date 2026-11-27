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
- **Made key**: an API key that the central vault makes itself (`vault.py` `make`), for a route that an agent of the
  fleet built for other agents. No person types it. The route's checker gets the key's hash.
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
- **The hub does not have the value of a made key.** The central vault answers with the key's hash and fingerprints,
  which open nothing, and never with the value (`vault.py` `make`).
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
  `Sources/FleetCore/RecoveryCode.swift`). A central vault with the list of the owner's devices makes no backup (see
  "The list of the owner's devices").

"What the vault does not protect", below, tells where these results stop.

## Where a value goes

### On the owner's Mac

- The owner adds a secret in Founderizer for Mac, with **Settings › Secrets › Add secret** or **Import**. The app seals
  the value to the central vault's key in its own process. It uses age's format: X25519, HKDF-SHA-256 and
  ChaCha20-Poly1305 (`Sources/FleetCore/AgeSeal.swift`, `Sources/Founderizer/SecretEntryView.swift`).
- The value is only in the memory of the form. The app clears it when the hub has the reference, at Cancel, and when
  the form closes. No draft and no log gets it (`Sources/Founderizer/SecretEntryView.swift`).
- The app seals only to the key that the central vault's install printed on the machine that the hub names as its own.
  Root reads that key on that machine from the public key line of the vault's own key file. The vault's status, which
  the install asks as the hub's user with `python3 -I`, must name the same key, or the install stops and prints no key
  (`hubsetup.py` `central_status`). So no program of the hub's user decides the key that the Mac pins.
  That key comes to the Mac over the owner's SSH connection, which accepts only a known host key. The machine's name,
  and its address when the Mac has no saved connection to it, come from the hub. The app seals only while the hub names
  the same key (`Sources/FleetCore/CentralVault.swift`, `Sources/Founderizer/CentralVaultSection.swift`).
  **Who the Mac logs in as, and where.** A root step logs in as root, or as the user of a connection that this Mac
  keeps from its own install. It never takes another user from the hub's record of a server, because that user's own
  files can answer in root's place (`Sources/FleetCore/ServerRecords.swift`). A server counts as a Mac, whose vault the
  app reads as the user of its agents, only when the hub calls it a Mac and this Mac's own Tailscale reports its system
  as macOS too; each other server is read as root. The hub's own machine must be the Tailscale device that this Mac
  reaches at its hub address, by its node ID or its whole name. A first host key is taken only at port 22 or at a port
  that the owner typed (`Sources/FleetCore/MachineInstall.swift`, `Sources/FleetCore/MacNetwork.swift`,
  `Sources/Founderizer/CentralVaultSection.swift`).
  **The hub's own server, when the Mac keeps no connection to it** (another Mac or an older build installed the hub,
  the hub moved, or the Mac lost its settings): a root step there, and the trust step of that server, logs in as root,
  whatever user the hub's record names, at the record's port. It does so only after the Mac's own Tailscale names the
  record's address and the hub address as one device and gives that device's system as Linux, and it connects to that
  device's own Tailscale address. It reads the host key from the Mac's `known_hosts` line for that device: the line of
  its Tailscale address, else the line of its whole MagicDNS name, never the record's string or a first label; the
  connection that it keeps reads the same line. It offers two
  keys, each alone and with the strict host key rule above, and only
  where the key file is there right before the login: first the Mac's own key, `~/.ssh/founderizer_ed25519`; then,
  only when root refused that key, the fleet's owner access key from the Mac's keychain. That key goes into a file of
  mode 600, in a folder of mode 700 of its own, for that one login, and the folder is removed after it (one that a
  crash left goes before the next such login). The owner access key's session adds the Mac's own key to root's
  `authorized_keys`, and the Mac then logs in with its own key once more. When root answers the Mac's probe, which
  changes nothing, with the Mac's own key, the Mac keeps the connection, as an install keeps one. Where the route does
  not reach root, a record of root goes on with the owner's own keys, as before; for a record of another user, the step
  stops, and where root refused the keys its words give the owner's step: at port 22,
  `ssh-copy-id -i ~/.ssh/founderizer_ed25519.pub root@<address>` where the owner still has a
  way in, else that key into `/root/.ssh/authorized_keys` in the server provider's console, on a server that lets root
  log in with a key. A host key that the Mac does not know yet stops it with the command `ssh root@<address>` at port
  22, and at another port with the step of the port on the server's page: the words never give a command at the
  record's port, where a user other than root can listen. A stop
  holds for 10 minutes for that server, so the other root steps of a round make no more logins that root refuses, and
  each press of the owner's ends the hold (`Sources/FleetCore/HubRootRoute.swift`,
  `Sources/Founderizer/CentralVaultSection.swift`).
  **Only the owner's Set up and a first install write the pin.** An install or an update that prints another key
  stops, and the pin stays.
  **A limit:** a hub address that is a name outside the private network is no Tailscale device, so the central vault's
  install and update, the hub's TCP step and the root steps of the owner's pages on the hub's server (the connected
  apps, one server for all) stop on such a fleet, until the owner gives the hub's address on the private network.
  **A limit:** the root route is for the hub's own Linux server only. On a server that is not the hub, and on a hub's
  server that is a Mac, a record that names a user other than root, with no connection that the Mac keeps, still stops
  a root step with the words of no record. On a hub's server whose host key the Mac does not know, the route stops and
  offers no key there.
  **A limit:** the hub names the server under which the Mac keeps the route's connection, and the fleet whose owner
  access key the Mac offers. A hub that is broken into can keep root's connection of its own server under the name of
  another server: that server's root steps then stop at the Tailscale check of that server's name, and no secret
  leaves the Mac. It can make the Mac offer the owner access key of another fleet
  that this Mac runs, to its own server: SSH gives that server no private key, only the attempt.
- With the sealed copy, the hub gets the secret's name, its catalog entry and salted SHA-256 fingerprints of the value
  (`Sources/Founderizer/SecretEntryView.swift`). An import sends these for all its items in one command, and the hub
  puts them into the catalog with one commit (`Sources/Founderizer/SecretImportView.swift`, `hub.py`). A title that
  holds a value, of the catalog or of the same import, is refused before the hub keeps the command (`hub.py`).
- The catalog takes no second API key with the variable name of another one, also not from one import (`hub.py`).
  The successor of a GitHub App's key on a fleet with a door is no replace: it stands beside the old key under a
  reference and a name of its own, the first that the catalog does not have (`GITHUB_APP_<OWNER>_2_KEY`)
  (`Sources/FleetCore/GitHubAppKey.swift`). When GitHub refuses the old key, the hub takes it back from the door and
  removes its entry from the catalog by itself (`hub.py` `door_key_retire`; `UI-API.md`, version 1.103, says
  when); the owner's signed grant of it to the door stays in the central vault, and nothing ends that grant today
  (limit 25).
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
- **A made key goes only to a vault that keeps it out of sessions.** The hub plans the copy of a made key only for a
  machine whose helper reports that its vault says `made_keys: true`. For each other machine, it plans only a reference
  that its last read of the central vault's status names as a value that the central vault holds and did not make
  (`stored` less `made`), so a key that was made after that read goes there in no case. The delivery of each other
  reference has the mark `central:made:` in its request id, and the hub gives that copy only to a request in which the
  vault itself says `made_keys: true`: a process of the agent can forge its helper's report, but not the request of a
  vault program from before the rule. The hub's request of each seal for such a vault says `made_keys: true`, the word
  without which the central vault seals no made key. A made key that a machine of the other kind holds from before
  (its vault was put back to an older program) goes back with a withdrawal, when that vault gives copies back and the
  central vault's status names the key as made; a status that cannot say (none, or one whose lists do not read) takes
  nothing away. A process of the agent can stop the withdrawal with a forged report, but an older program finds no
  key in the stored form all the same (`hub.py` `central_plan`, `central_named`, `central_deliver`,
  `central_reconcile`, `helper_deposit`; limit 35).

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
- It refuses another value under a reference that it holds. There are two exceptions. The first is a copy that comes
  with the owner's `replace` statement: the statement names the reference and the SHA-256 of that sealed copy, so the
  hub cannot put a copy of its own under it. The central vault keeps the newest statement of each reference and refuses
  an older one, so an earlier copy cannot come back. It writes the record of the statement first and then the store,
  which is one file that takes the place of the old one whole. A replace that stops between the two leaves the old value
  whole, and the same statement again ends it (`vault.py`). The second is a new value of a key that the vault made
  itself (`make` with `replaces`, below), which comes from no copy. A restore of an older backup of the store brings
  back the value of that time, of a key of the owner's and of a made key alike (limit 22).
- A replace changes the key and not the address of its service. When the stored value has an address and the new
  value names none, the central vault keeps the address and the user name of the stored value, so a vault can still
  send the key for an agent that uses it. An address in the new value takes the place of the old one (`vault.py`).
- It seals a copy of a value for a machine only when the owner signed a pin of that machine's key, and also signed a
  grant of the value to an agent on that machine, or put the value into the pool. It seals a value of the pool to
  each machine whose key the owner pinned (`vault.py`, `Sources/FleetCore/OwnerKey.swift`).
- It removes a value only while no grant and no pool entry that the owner signed names it (`vault.py`). It removes a
  made key only after a signed `unpool` of it, also when no pool entry named the key; the owner's Mac signs that
  `unpool` with no step of the owner's when the hub lists the key as due out of the pool (limit 34). A reference whose
  value it removed takes no value and no made key again.
- **It makes a key** (`make`) when the hub asks, and it needs no statement of the owner's for that. The hub gives a new
  reference, the site of the route, the salts of the fingerprints and a request id. The site is an `https` origin with a
  DNS name. The vault refuses a reference that it holds or that it removed, and one about which it has a statement of
  the owner's. The key is 32 random bytes as base64url text of 43 characters. It is an item of the store with the note
  `made`, with the site as its address and with no user name. The answer has the reference, the key's hash in the form
  `{SHA}` (the base64 of the SHA-1 of the key, as nginx reads it) and the fingerprints, and never the value. No log line
  has the value.
- One request id gives one answer. The same request again gives the same reference, hash and fingerprints, and the vault
  makes nothing. The record of each request is inside the item, so one write of the store saves the value and its
  record together, and a backup has both.
- **A new value of a made key** (`make` with `replaces`) comes under the same reference and keeps the site. The vault
  makes it only for an item with the note `made`, so nothing types over a value of the owner's. The value before it is
  in the store no more, and it cannot come back: an intake never writes to the reference of a made key, with or without
  a `replace` statement, and an earlier request makes nothing again.
- **The mark.** A sealed copy of a made key is `{"made": {"password": ..., "url": ...}}`: the key is inside the member
  `made`, and nothing is beside it. The member `made` is the mark: it says that the fleet made the key. It comes from
  the item's note, which only `make` writes, so the hub can neither put it on a copy nor take it off. A sealed copy of
  each other item is the value as it was, with no mark: an intake keeps only the members of a login or a key, and
  drops each other one. A vault program from before this form finds no password in the copy and refuses it: an older
  `vault.py` reads a password beside an address (`check_value`, `check_login`), and so does Fleet Vault on a Mac
  (`Sources/FleetVaultCore/VaultProtocol.swift` `VaultDeposit.value`, `VaultSecret`).
- It seals a made key only for a request in which the hub says `made_keys: true`: the hub's word that the vault which
  takes the copy keeps a made key out of each session and check. A hub from before that word never says it, and the
  hub says it for no request of the door, so neither gets a copy of a made key. It seals no made key for the door, also
  with the word, so a hub that is broken into cannot bring one there either (`vault.py` `seal`).
- Its store keeps a made key in the same form as the copy, `{"made": {"password": ..., "url": ...}, "requests": [...]}`.
  A central vault that is put back to an older program finds no password at the top of such an item: the program of
  the first made keys seals nothing, and the program from before `make` seals the item as it is, a copy in which no
  older broker and no Fleet Vault finds a key (`vault.py` `made_key`, `make`).
- Its status names each made key, with the hash of its value now and the request that made that value (`vault.py`).
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
- **A made key.** The broker keeps a delivered copy of a made key in its store in the copy's own form,
  `{"made": {"password": ..., "url": ...}}`, so a broker that is put back to an older program finds no key in it.
  Only the copy's own text gives that form, never the hub's answer beside it, and the broker refuses a copy whose
  member `made` has another form (`vault.py` `made_login`, `deposit`). The broker gives a made key to no session and
  no check as a value. On a server that swaps keys, it gives a placeholder, and only when the site that the hub names
  is the address in the key's own value; else it leaves the key out, and its answer names the variable in `made`
  (`vault.py` `read`). The swap proxy gets the value only for a request to that address, also when a delivery put the
  made key under the reference of a placeholder of another site (`swap_value`). The broker hands no made key over to
  another agent, and types none into a page (`handover`, `signin`). `call_api` sends it to its own address, as each
  key (`send`). The broker's status says `made_keys: true`, and each of its requests for a delivered copy says the
  same word to the hub (`vault.py` `deposit`).

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
- It does not say `made_keys` yet, so the hub gives it no made key (`hub.py`). A copy of a made key that it got all the
  same holds no password at the place where it reads one, so it refuses the copy
  (`Sources/FleetVaultCore/VaultProtocol.swift` `VaultDeposit.value`).

### In the door

- The central vault seals each secret that the owner signed for the door to the door's pinned key (`hub.py`). The hub
  asks for no copy of a made key for the door, and of no reference that the central vault's last status does not name
  as another value, and the list of what the door keeps names no key that the status names as made (`hub.py`
  `door_reconcile`, `door_sealed`). The door writes each value that it holds into an app's setting on a host, and it
  takes a copy that has no password at its top as one whole key, but it refuses a copy that holds a `made` member: it
  writes no value of it and confirms no such copy (`door.py` `item_secret`, since 26 November 2026). So three walls
  keep a made key from the door: the hub's two filters, the central vault, which seals no made key for the door, also
  with the word (`vault.py` `seal`; the hub's request for the door says no `made_keys`), and the door's own refusal.
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
| Owner key | ECDSA P-256 | The owner's Mac. In the Secure Enclave when the Mac has one, else a software key. One item of the login Keychain for each fleet, not synchronized. The app writes it with "when unlocked, this device only", but into the file-based login keychain (it does not ask for the data-protection keychain), where that rule has no effect: see limit 13. | Founderizer for Mac, to sign the owner's statements (`Sources/FleetCore/OwnerKey.swift`) |
| Central vault key | age (X25519) | `/var/lib/fleet-vault-central/age.key`, mode 600, user `founderizer-vault` | The central vault, to open what the owner sealed (`hubsetup.py`, `vault.py`) |
| Central store key | age (X25519) | `/var/lib/fleet-vault-central/store.key` | The central vault (`hubsetup.py`) |
| Broker store key | age (X25519) | Linux: `/var/lib/fleet-vault/store.key`, mode 600, user `fleet-vault`. Mac: the Keychain item `store`. | The broker (`hubsetup.py`, `Sources/FleetVaultCore/VaultLocalStore.swift`) |
| Broker handover key | age (X25519) | Linux: `/var/lib/fleet-vault/age.key`, mode 600. Mac: the Keychain item `age`. Made one time and never replaced. The hub pins its public half. | The broker, to open copies that are sealed to its machine (`hubsetup.py`, `Sources/FleetVaultCore/VaultPrograms.swift`) |
| Recovery code | 26 symbols of Crockford's base32 (130 random bits) | The owner's Mac, in the login Keychain, and a phone that enrolled after the Mac had the code | The central vault seals its backup to an age key that comes from this code with HKDF-SHA-256 (`Sources/FleetCore/RecoveryCode.swift`, `Sources/Founderizer/RecoveryCopy.swift`). It opens nothing new once the vault has the list of the owner's devices (`vault.py`) |
| Sign key, list key and save key of a device | ECDSA P-256, public halves only | `/var/lib/fleet-vault-central/clients.json`, mode 600, user `founderizer-vault`: the list of the owner's devices, when the vault has one | The central vault, to check who signs the owner's decisions and who changes the list (`vault.py`). No app makes a list key yet |
| Fingerprint key | 32 random bytes | The hub's database | The hub, to make the salt of each fingerprint (`hub.py`) |
| Google file key | 32 random bytes | `/var/lib/fleet-vault-central/hub-google.key`, mode 600, user `founderizer-vault`. On a hub with no central vault of this program yet, and on a Mac: `~/.config/founderizer/google-file.key` of the hub's user, outside `~/.fleet`. | The hub, to seal its Google file with ChaCha20-Poly1305 (`vault.py` `hub_key`, `hub.py`, `atrest.py`) |

## The stores

- The central vault and each broker keep their secrets in one file that age locks. The file holds
  `{"v": 1, "items": {...}}` in ASCII armor, encrypted to the public half of the store key with X25519 and
  ChaCha20-Poly1305 (`vault.py`, `Sources/FleetVaultCore/VaultLocalStore.swift`).
- Each item has a note that says where its value came from. In the central vault's store it is `taken from the owner`
  or `made`. The value of a made key is `{"made": {"password": ..., "url": ...}, "requests": [...]}`: the key inside the
  mark, and the record of its requests (the request id, the hash and the fingerprints of each value that the key had),
  and no value from before. A restored store has the same notes, so a made
  key stays a made key (`vault.py`).
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
  signed. So only the owner's recovery code opens the backup. A vault with the list of the owner's devices makes none
  (`vault.py`).
- Beside its state, the central vault keeps two files of its own, mode 600: `clients.json`, the list of the owner's
  devices with the set of the keys that ended, and `signers.json`, who signed each record that is in force, and when
  the vault took it. The state and the configuration keep the members that they had before, so the program from before
  these files runs again when an update puts it back. While it runs, it reads the `owner_keys` of the configuration
  (`vault.py`).

## The owner's signatures

- The central vault reads eight kinds of statement that the owner key signs: `pin` and `unpin` (the key of a
  machine), `recovery` (the key of the backup, which a vault with the list of the owner's devices refuses), `grant` and
  `ungrant` (a secret for an agent on a machine), `pool`
  and `unpool` (a secret that the fleet manager can give to an agent on any machine), and `replace` (a new value
  under a reference that the vault holds, for one sealed copy) (`vault.py`, `Sources/FleetCore/OwnerKey.swift`).
  Three more are about the list of the owner's devices: `client-add`, `client-end` and `client-first` (`vault.py`).
- Each statement is the canonical JSON text of exactly its own fields, and it names the fleet and a time. The
  signature is ECDSA over SHA-256 of the statement's bytes (`vault.py`, `Sources/FleetCore/OwnerKey.swift`).
- The central vault checks each statement itself, with the owner's public key. It refuses a statement of another
  fleet. It keeps a dated record of each machine, recovery key, grant and pool entry, also after its end, and of the
  newest replace of each reference, and it refuses a statement that is not newer than that record. So the hub cannot
  send an old statement again (`vault.py`).
- **The owner's keys of the central vault.** The central vault takes a statement that one of its owner keys signed,
  and it holds 1 to 8 of them (`vault.py`). Only root on the hub's server writes them, with the root step
  `hubsetup.py central-vault`. A run of that step keeps the keys as they are when its own key is one of them, with
  `--keep-owner` or without, so the step of one Mac of the owner never takes the key of another Mac away. A run whose
  key is not one of them writes its own key alone, so a run from a new Mac takes the place of the key of a lost Mac.
  On a vault whose keys hold the run's own key, `--add-owner-key` adds one key at the end of the list, and
  `--remove-owner-key` takes one key out, also a key that is no point of the curve, but never the last one. Each form
  starts the vault again also when the list is already as the form makes it, so the same form again finishes a run
  that a lost connection cut after its write. On any other vault each form changes nothing, because the run would
  first write its own key alone. The step checks the list before it writes anything: 1 to 8 keys, each a point of the
  curve. A run that changes the keys starts the central vault again, because the vault reads its keys only at its
  start. One run at a time: a run holds a lock of root's from its first read to its end, and a second run at the same
  time changes nothing, so no update writes back a key that a remove took out (`hubsetup.py`). No step of the app adds
  a second key yet. A step that gives a second Mac its key must use the add form, from a Mac whose key is in the list,
  and never the Set up from the second Mac: the Set up writes the second Mac's key alone and takes the key of each
  other Mac away.
  **What stays after the removal of a key.** The central vault refuses each new statement of the removed key, of each
  kind. Each record that the removed key signed before stays in force: a pin, a grant, a pool entry, the recovery key
  and the newest replace of a reference, with the value that the replace put in the store. The vault keeps who signed
  each record that it took since it has `signers.json`, and when it took it; no route gives that yet. It checks no
  signature again when it seals a copy or makes a backup (`vault.py`). A record
  that the removed key dated after the vault's clock stops each newer statement of its kind until that time: one day
  at most for each kind but a replace, which has no such bound (limit 24). The pin that the hub keeps of a machine
  keeps the removed key's signature: a broker that no longer holds the key refuses it, and a broker that still holds
  the key takes it until it is 90 days old (`hub.py`, `vault.py`). The door checks each signature again at each use,
  with the keys of its own access file, so there the removed key's statements end only when that file no longer names
  the key (`door.py`); the root step of the central vault does not change that file. No step of the app cleans these
  records yet. The app signs a recovery key only when the vault holds none
  (`Sources/FleetCore/CentralVaultPlan.swift`), and it has no step that signs the end of a record that the hub's
  records do not hold. So after a removal, until such a step: the recovery key that the removed key signed stays, and
  each backup (`export`, which the hub's user can ask for) is locked to it; each value that a replace of the removed
  key put in stays in the store; and each pin, grant and pool entry that the removed key signed stays in force, but
  for a pin that the app signs again with a key that stays.
- **The list of the owner's devices.** The central vault can hold a list of the owner's devices in place of its owner
  keys (`vault.py` `held_clients`). No app makes such a list yet: without it, each fleet stays as the rest of this
  document says. An entry has the device's name, kind and label and its public keys: the sign key, which signs the
  owner's decisions (an iPhone's save key in its place), and the list key, which signs only `client-add` and
  `client-end`. Each entry and each end keeps the hash of the key that signed it, and the vault's own time.
  - **From the moment when the list is there, the vault reads the `owner_keys` of its configuration no more.** So the
    root step's owner keys change nothing then: neither a Set up from a new Mac nor the forms that add or remove a key.
    When each listed device is lost, no command of this release gives the vault a new device yet.
  - **The first list key** comes one time, by root on the hub's server and with a signature of the owner key that it
    is for (`vault.py owner`, the statement `client-first`). Each other owner key comes into the list with no list key.
    A second first list key is refused, so nobody with the Mac's root puts a list key of their own into the list. The
    command runs only as the installed program, with the vault's own configuration and as the vault's own user.
  - **An add** needs a list key of the list. The list holds at most 8 devices, and each key is one device's. A device
    with a key that ended is refused for ever.
  - **An end** needs a list key of the list, and it counts at once, whatever its time. It ends the whole device, and it
    never names the device that signs it. A key that the vault never held ends too, so a hub that holds an add back
    cannot bring it after the end: at most 16 such keys for one list key. The set of ended keys only grows. It holds at
    most 1,024 keys, and an add is refused before the end of a listed device could have no room. No limit refuses the
    end of a listed device.
  - **What an ended device signed stays**: its pins, grants, pool entries and replaces, and the devices that it added.
  - **The recovery key ends with the list.** The vault takes no `recovery` statement and makes no backup, the copy of
    the fleet carries no store of the vault (`hub.py` `central_backup`), and the hub keeps no new copy of the recovery
    code for a phone. Copies from before, on the Mac, in iCloud and in Time Machine, still open with the old code.
- **No statement from ahead.** The central vault keeps no pin, unpin, recovery, grant, ungrant, pool or unpool
  statement of the owner's, and none about the list of their devices, that is dated more than one day after its own
  clock, and the record before it stays (`vault.py` `not_ahead`). A replace statement is not checked so (limit 24). The
  app dates no grant, ungrant, pool, unpool or replace statement more than 23 hours after the Mac's clock: a later time
  of a clock that ran ahead once is not followed (`Sources/FleetCore/OwnerKey.swift` `GrantClock`). A statement from ahead would stay its
  record's newest until its time, so no statement dated right could end it (choice C50).
- **Each signed grant and pooled secret has its standing at the hub.** `GET /ui/vault` says beside each grant that the
  owner signed, and each secret that the owner signed into the pool, whether the hub's own records still hold it,
  while the hub's reading of the central vault is fresh and was made after each grant, ungrant, pool and unpool
  statement that the hub passed on (`hub.py` `central_standing` and `central_statement`, owner API 1.219): a reading
  from before can miss the statement. A grant is held
  while an agent of any role on its machine holds the secret, the manager too, and a grant for the door while the door
  holds it; the hub sends a copy only to a worker or a lead (`machine_secrets`, `central_plan`), so "held" does not
  say that a copy goes there. A pooled
  secret is held while the hub's grantable pool has it; once its unpool reaches the central vault, the hub takes the
  secret back from each machine that held it only through the pool (`central_plan`). The hub signs nothing.
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
  the outcome (`Sources/FleetVaultCore/VaultBrowser.swift`, `Sources/FleetVaultCore/VaultBroker.swift`). On a Linux
  server the broker does the same in the agent's own Chrome, over DevTools on 127.0.0.1 and the agent's port of
  root's ports file, only where each socket that listens there, and the far end of its own connection, is of the
  agent's own user. Its scripts run in a world of their own and reach the page only through that world's prototypes,
  so neither a script nor the markup of the page changes what they read. The whole fill has one minute, and the
  broker's other work goes on meanwhile. It records the origins of the sign-in's top-level pages and the cookies of
  other sites that the sign-in created (their names, never a value), and the hub has the agent's helper clear them in
  that browser when the agent's use of the login ends (`vault.py` `signin`, `hub.py` `signin_clear_sweep`; build plan
  04, S5). Item 26 says what this does not protect.
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
- **A made key, never as a value.** With "Reads it" of a made key, a session and a check of the agent get a
  placeholder on a Linux server that swaps keys, when the hub names the key's own site there (see "Which key swaps"),
  and nothing elsewhere: no variable and no value. With "Uses it", `call_api` sends the key to its site. No sign-in
  and no handover takes a made key (`vault.py`; see "In a broker on a Linux server"). A Mac gets no made key. The
  vault's answer names such a key in `made`, the helper reports it apart and reads no more for it, and the manager
  gets its own words once, for a key that the central vault's status names as made: give "Uses it" in place of
  "Reads it" where no placeholder works (`fleet.py`, `hub.py`).
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
- **Who runs the step.** A new server's install runs it after the vault step (`join.sh`, and `hub.sh` for a hub's own
  server that takes agents, through `hubsetup.py key-swap`), and so does root's step for a hub's own server that takes
  agents later (`hubsetup.py one-server`, only while no agent runs there: else the owner's Mac's rule switches it, which
  asks the owner first where an agent reads a key with a site). An install goes on when the step stops: it says why, and
  the server then gives each key as a value. The owner's Mac runs it on each joined Linux server, the hub's own server
  with its server service included (UI-API.md 1.183 and 1.327). `hubsetup.py vault --swap` runs it too. No rule of a
  server's sudoers file reaches it: the service user's root commands are other programs (on the hub's server also the
  command of the hub's ports, `ports.py`), and its other right is to run a command as an agent user, which the step
  refuses (`hubsetup.py`).
- **Off.** `vault.py configure --swap off` takes the part away, restarts the broker and stops the proxy. Each session
  that runs on that server with a placeholder then gets no key until its next start, because the proxy stops with
  the switch.
- **The owner's keys and the fleet.** The same step adds owner keys to a vault (`--add-owner-key`) and never takes one
  away, so the step of one Mac of the owner does not take the handovers of another Mac. Only its remove form,
  `--remove-owner-key`, takes a key out, in a run that adds none and never the last key, and the broker then starts
  again with the keys that stay, also when the key is gone from the file already. The broker's state stays as it is
  ("The owner's keys of the central vault"). `hubsetup.py vault --owner-key` also adds the keys that it is given to
  the broker's keys, and keeps none of a vault of another fleet. On a Mac, `Vault/install.py --owner-keys-only` writes
  the keys that it is given in place of the list: it is the remove form there, so give it each key that stays. The
  step sets the fleet's ID (`--fleet`) where the vault has none, and it refuses a vault of another fleet.
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
  key in the place of the placeholder only as the whole credential, and only in the one form of that key: in the
  `Authorization` header as `Bearer`, `token`, `Key` (as FAL takes a key), or the user name or the password of
  `Basic`; or, for the form `header:<name>`, as the whole value of the one request header of that name (as
  ElevenLabs takes a key in `xi-api-key`). The form is `Bearer` when the key's catalog entry names no other
  (`vault.py`, `lifecycle.py`). A header form's name is 1 to 64 small letters, digits and `-`, holds `key`, `token`,
  `secret` or `auth` (a site sends many other request headers back, so a list of refused names alone would not do),
  and is not `authorization`, `proxy-authorization`, a header that the proxy does not pass, a `sec-*` name, or a
  name that holds `idempoten`, `csrf`, `xsrf` or `authenticat`. The proxy refuses a request whose head has a
  placeholder in another place or in another form, a second header of a header form's name with any value (also
  one with `_` for `-`, which some sites read as the same header and can join to the first), two placeholders that
  each could be a key, and a `TRACE` request with a placeholder, because a server sends such a request back. It sends the request on a TLS connection of its own, which checks
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
  keys, it sends a key that the hub names with a site only as the proxy does: to that site, and in the key's own
  form (`bearer` as `call_api`'s bearer, the password of `Basic` as its basic, and a header form as its
  `header:<Name>` of the same name in any case). A key whose form is `token`, `Key` or the user name of `Basic` goes
  through the proxy only (`vault.py`, `hub.py`).
- **Older programs.** A broker of a release from before the forms `key` and `header:<name>` leaves a key of such a
  form out of a session (neither the key nor a placeholder) until its program is updated, and it refuses its whole
  list of placeholders when one entry has such a form, so a vault program that is put back to such a release swaps
  no key on that server. An older proxy refuses a request with `Key <placeholder>` or a header form (400) until the
  new broker's first answer starts its hand-over (`vault.py`). A hub of such a release does not load a `team.json`
  with such a form (its `validate_team` refuses the form), and then refuses each write of `team.json`. So before a
  hub is put back to such a release, the owner takes each such form away (`save_login` with `form` `""`, or with an
  older form); each of these writes is still taken by this release. From this release on, a later release's new
  form of the Authorization header (any plain word) or a later refused header name keeps a `team.json` loadable
  (`lifecycle.key_form`, the shape only).
- **The model's own calls.** The variable `NO_PROXY` names the hosts of the provider of the agent's own program,
  the hub and the machine itself, so the calls to them do not go through the proxy (`lifecycle.py`, `fleet.py`).
  For a check, it names only the hub and the machine itself (`fleet.py`).
- **The proxy and the outgoing gate.** On a server with the outgoing gate (the next section), the proxy connects to
  no host by itself: it sends `CONNECT <host>:<port>` with the UID of the agent's OS user to the gate's relay port,
  and the gate looks the host up, connects and counts as for the agent itself. The kernel lets the proxy's user reach
  that port and nothing else, also no name server. The proxy knows the gate by its root-owned rules file
  (`/etc/founderizer-egress/rules.nft`); with no such file it connects as before (`vault.py`, `swap_reach`). While the
  gate does not run, a session that holds a placeholder has no HTTPS through the proxy.

## The outgoing gate

On a Linux server where root ran the step, the kernel sends each TCP connection and each DNS question of an agent's OS
user to one process, the gate, which runs as a user of its own (`founderizer-egress`) and records where each agent
connects. It is the network part of `agent-outgoing-connections-proposal.md`; this is its step 1, which refuses no
host.

- **The step.** `vault.py configure --egress on`, as root and only as the installed program, as the key swap's step
  (`vault.py`). A new Linux server takes it at its install after the key swap (`join.sh`, and `hub.sh` for a hub's own
  server that takes agents, through `hubsetup.py egress`), and so does a hub's own server that takes agents later
  (`hubsetup.py one-server`); an install goes on when it stops. The owner's Mac runs it on the hub's own server after
  each keys step of the key swap there, so a hub that took agents before these steps gets the gate at the Mac's next
  round (UI-API.md 1.327). It makes the gate's user,
  its root-owned files (`/etc/founderizer-egress/`, the launcher and a safe copy of the vault program in
  `/usr/local/lib/founderizer-egress/`), its units, and the drop-ins of the closures; it starts the gate, and only
  then loads the kernel rules, so no connection meets a table without a gate. A gate that does not start leaves no
  table: each agent then connects as before. It stops where each user can listen on the gate's ports (877 to 880).
  A second run changes nothing. `--egress off` takes the table first, then the rules file, the gate, its units, the
  drop-ins and the closures; it keeps `/etc/founderizer-egress/egress.json`. The owner's Mac's step on the hub's own
  server runs `--egress on` only where that file is not there, so root's off stays there too (UI-API.md 1.327).
- **A gate that does not run.** The table stays (`agent-outgoing-connections-proposal.md`, section 5.4): an agent's DNS
  and TCP fail at once, and the hub and each other Tailscale machine still answer. Nothing falls back to a direct connection, because a gap with no
  table would let an agent open a connection that it keeps after the gate is back. The unit starts the gate again in 2
  seconds; a new program comes by the hand-over with no cut, and one that does not start is not taken; at a cold start
  the launcher runs the installed program, or the safe copy when that program fails its start check. The unit's
  ExecStopPost counts each end of the gate that nobody asked for (a crash, a kill, a start that failed, also for a cause
  outside the program, as a port that another program holds) against the program that ran; while a program has three
  such ends in the last hour since boot, neither the launcher nor a hand-over runs it, so a program that passes its
  check and stops later does not keep the gate down. A program does not serve in the place of a stored policy that it
  does not take (a later program's), so this fallback never drops a later step's refusals: then no gate serves, and the
  table stays. Each later gate program takes every older policy, and stores an older one that the hub gives after a
  release that goes back; a program that goes back on purpose past a policy that it does not take needs root to remove
  `/var/lib/founderizer-egress/policy.json` (the gate's words say so). A later root step whose gate does not start keeps
  the table and the rules file of a gate that the server had already; only a first install takes them back. While root's
  rules file is there, the server's service posts the gate's state with each reading, also when the gate never started
  (then with root's word on the table); when it finds no gate in two reports in a row, or no table in the kernel in two
  reports in a row, the hub tells the manager once, and once when a report ends it (`hub.py` `egress_troubles`, the
  server watch). A server with no gate posts nothing: on the hub's own server of a hub that takes agents, which root's
  steps give a gate, that is a gate that is missing, and the hub tells the manager that its table is not loaded, with
  the step that makes a gate. Root's own `--egress off` there is told to the manager in the same words, once. Root's
  file `/run/founderizer-egress-table` names the version of the table that the
  kernel has, and the gate's state (`table` in `GET /ui/hosts`) reads it. `nftables.service` flushes every table of the
  kernel at its start, its reload and its stop (the stock `/etc/nftables.conf` begins with `flush ruleset`): a drop-in
  of that unit runs the rules' step after each of them, which loads the table again. A timer runs the step every 5
  minutes too, for a flush that no unit saw (`nft flush ruleset` or `nft -f /etc/nftables.conf` by hand) and for a load
  that failed. In the second or so after a flush by `nftables.service`, and until the timer's next run after one by
  hand, an agent connects with no rule, and a connection that it opens then stays outside the records for its life.
- **The kernel rules.** One nftables table, `inet founderizer_egress`, matches each packet by the UID of the socket
  that made it, so it holds for each process of an agent's OS user: a session, a cron job, a program that ignores
  proxy variables. The hub's address with its port and its git port goes direct, also while the gate does not run,
  and so does the swap proxy on `127.0.0.1:876`, and an agent's connection to its own browser's DevTools port on the
  loopback address (`/etc/fleet-browser/ports`): the browsers' own table lets that port reach only its own agent's
  user, by that user's UID, which a connection through the gate would not keep; another agent's connection to it goes
  through the gate, which records it. A TCP connection to another Tailscale machine goes direct too, and the gate
  does not record it: Tailscale's own rule drops each packet from its IPv4 range that does not come in on
  `tailscale0`, which each answer of the gate to an agent did (19 November 2026: until this line, no agent reached
  the door). This machine's own Tailscale address, tailscaled's own address `100.100.100.100` and Tailscale's IPv6
  range, which has no such rule, stay with the gate. Each DNS
  question, to any name server, goes to the gate's resolver; each other TCP connection goes to the gate; every other
  packet of an agent user is refused (UDP other than DNS, ICMP). Each packet of a sub-uid of an agent user
  (`/etc/subuid`) is refused: `newuidmap` can give a process of the agent such a UID in a user namespace of its own,
  in the server's network, where none of the agent's rules would match it. The UID of each user of the server is cut
  out of a range that holds it. A connection that was open before the rules loaded goes on to its end. Root's unit
  `fleet-egress-rules.service` loads the whole table with its sets at boot, before the users' services and cron, and
  again at each change of `/etc/group`, `/etc/subuid` or `/etc/fleet-browser/ports` (a path unit for each, and once
  more when one changed while the step ran) and every 5 minutes, with the agents of the group `fleet-agents`; it also
  takes each agent's OS user out of the groups `docker`, `lxd`, `incus` and `libvirt`, whose daemons would run a
  container for it outside the rules. A sub-uid range of an agent that holds the UID of a user of the server is named
  in the step's answer: a process of that agent can take that UID.
  Each agent user makes at most 200 new connections and 200 DNS questions a second (2,000 at once), in the kernel. The
  socket families whose transport is a socket of the kernel itself (RxRPC, SMC, RDS, TIPC) carry no agent's UID, so
  their modules cannot load (`/etc/modprobe.d/founderizer-egress.conf`): the step takes a loaded one out, and names a
  family that is built into the kernel or in use.
- **The closures.** A local service that resolves or connects for any user would be a way around the rules. So no
  agent's OS user can connect to the Varlink socket of `systemd-resolved` or ask its D-Bus name, connect to the
  socket of `tailscaled`, or to the sockets of `snapd`: an ACL entry of the group `fleet-agents` with no write, and a
  D-Bus policy. A drop-in puts each one back at each start of the service, before it opens its socket. Proved on a
  real server on 17 November 2026: without them, an agent resolved names through `systemd-resolved` and opened a
  connection through `tailscaled` that the rules never saw. A file system that keeps no ACL cannot hold a closure; the
  step then names it, and the rest of the gate goes on.
- **The gate.** The gate reads the original destination and the agent's UID from the kernel (its exact lookup of one
  socket, `sock_diag`; the tables in `/proc` only on a kernel where that lookup does not work), reads the host's name
  from the first bytes (a TLS ClientHello or an HTTP request head) or from what its resolver gave this agent, connects,
  and counts. It reads no byte after the first ones, and it never ends TLS. In this step it connects to the address that
  the program chose; when that address does not answer, it also tries the name's other addresses, because the program's
  own fallback from IPv6 to IPv4 cannot run behind it. It answers only the service user on its control socket. The
  service user takes its counts with each reading and posts them to the hub, which keeps one row for each agent,
  registrable domain, port and verdict (UI-API.md 1.220; the owner reads them with `fleet_read hosts`). An agent cannot
  write a record: the gate counts, and the service user carries the counts with its own key. The record can miss a host,
  so a host list made from it must be checked: the counts that the gate gave the service when the service did not get
  them, rows past 20,000 that wait for the hub, the rows that wait at a restart of the service, the counts of a gate
  that ended with no hand-over, and the hosts of a UID that is no agent's (it counts only as another user); a part of a
  report whose answer is lost counts twice.
- **A new program.** The gate's code is the vault program, so each release brings it with `fleet-vault-program`. At
  the service user's word after that, the installed program takes over as a new process with no cut, as the swap
  proxy does; a program that does not start is not taken, and gets its next try later. At a cold start, the launcher
  runs the installed program when it passes its own start check, and else the safe copy, which matches the kernel
  rules, because only the step changes either.

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
   - A site that sends the request's headers back in its answer (as some test and echo services do) shows the key to
     the session: the proxy reads no byte of an answer (`vault.py`).
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
   - A site that sends the key back gives it to the session: an answer that repeats the `Authorization` header, or
     the header of a key's header form. The proxy does not look for the key in an answer (`vault.py`).
   - The key goes only in its own form: in the `Authorization` header as `Bearer`, `token`, `Key` or `Basic`, or as
     the whole value of the one header that a header form names. A program that needs the key in another place gets
     no key. When the placeholder is in another header or in the address of a request to the key's site, the proxy
     refuses the request. When a program puts the placeholder in a body, makes a signature from it, sends it to
     another host, or does not use HTTPS, the placeholder goes out as it is (`vault.py`).
   - A key's site is one host. A service that takes one key at two hosts (FAL's `fal.run` and `queue.fal.run`) gets
     the key at the site's host only. The proxy passes no `Upgrade` to a key's site, so no websocket to a key's site
     opens through it at all (ElevenLabs' streaming over a websocket does not work there) (`vault.py`).
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
   (`Sources/Founderizer/FleetView.swift`). The same holds for a value that an agent writes into a field of a fleet tool
   and that the hub does not know: the record of that call keeps the field as it came, and a refusal of another tool can
   quote a field (`hub.py`). The hub masks only registered values. Its leak check finds the record after the owner
   registers the value.
4. **Root, and the vault's own OS user.** On a Linux server, only file owners and modes protect the keys and the
   stores, so root and the vault user can read them (`vault.py`, `hubsetup.py`). On a Mac, root installs and replaces
   Fleet Vault (`Vault/install.py`). Root on the hub's server can also write the list of the owner's devices.
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
   Macs, until a root step on that machine takes them out (`vault.py configure --remove-owner-key`, and on a Mac
   `Vault/install.py --owner-keys-only`), and it refuses a pin that another key signed (`hubsetup.py`,
   `Vault/install.py`). The central vault keeps each record that a removed owner key signed ("The owner's keys of the
   central vault"). A broker and the door read no list of the owner's devices yet: an end at the central vault ends
   nothing there ("The list of the owner's devices").
   The app signs each kept pin again with the new Mac's owner key, so such a broker then refuses
   handovers until that root step (`Sources/FleetCore/CentralVaultPlan.swift`).
8. **The end of a grant.** The end of a grant, of a pin and of a pool entry reaches the central vault only through
   the hub. A hub that is broken into can hold it back, and the central vault then still seals that secret
   (`Sources/Founderizer/GrantSigning.swift`). The same is true of an add and an end of one of the owner's devices
   (`hub.py` `ui_vault_client`).
9. **The pool.** A value in the pool needs no grant. The fleet manager can give it to an agent on any machine, and the
   central vault seals it to each machine whose key the owner pinned (`Sources/FleetCore/OwnerKey.swift`, `vault.py`).
10. **Agents of one Mac.** All agents of a Mac run as one OS user, and the hub key of each agent is a file of that user
    (`fleet.py`). So an agent can use the grants of another agent of the same Mac.
    It can also get a key of its own pinned as that Mac's vault key. The owner's Mac pins a Mac's vault key when the
    answer of Fleet Vault's socket, asked over SSH as the agents' user (`CentralVaultRemote.readMacVaultKey`), is the
    key that the hub bound for that Mac at its first grant (`store_key`, `hub.py`). A program of that user can answer in
    Fleet Vault's place, on the socket or in the SSH session itself, because that user owns its `authorized_keys` and
    its `~/.zshenv`. So the pin is only as true as the bound key. A report of another key later moves neither the bound
    key nor the pin (`vault_store_mismatch`), and an older signed build gets nothing (limit 6). The bound key is the
    agents' word in limit 21's three ways, and after the owner removes that Mac by another way than the owner's Mac's
    Remove server and adds it again. A hub that is broken into can bind any key at any time, and with one agent of that
    Mac that key gets the owner's pin at a first pin of that Mac: when the owner's Mac has no record of it, or under a
    new Tailscale name where its agents' user runs that Mac's Tailscale. The owner's Mac keeps the key that it last
    signed for each Mac server, and signs no other key for it on the socket's or the hub's word, until the owner removes
    that server on the owner's Mac and adds it again (`Sources/FleetCore/MacVaultPin.swift`). For a Mac that the owner's
    Mac pinned before this guard, the record starts at a run's read of the app, when the hub's pin, the bound key and
    the read key are one key, or at its next signature, when the hub's pin of it is 7 days old. The owner's Mac keeps
    the record by the hub's address, so the same hub at another address starts with no record. A machine with no server
    record takes its kind from its helper's reading, so its agents can make the hub call it a Linux server. The app
    reads a server as a Mac only when the hub and the owner's Mac's Tailscale both say so, and the guard covers a server
    that either of them names a Mac. When an agent's key gets the pin, the central vault seals each copy for that Mac to
    the agent's key: the values of each agent there, "Uses it" values and logins too, and the pool. A fix is planned (22
    November 2026), not built: root on that Mac reads the key with its own copy of Fleet Vault and signs a line with
    that Mac's SSH host key, and the owner's Mac pins only the key of such a line (`mac-server-pin-design.md`, with its
    validation).
11. **The release key.** Releases change the vault's code on each server and in the central vault without a step from
    the owner (see "How the vault's code is updated"). So the holder of a release key can change every broker and the
    central vault (`hubsetup.py`, `hub.py`). On a Mac, a build with the team's Apple signature can replace Fleet Vault
    (`Vault/update.zsh`). Its hourly root update checks the build's SHA-256 against the release manifest, the team's
    signature and a higher build number, but not the manifest's own signature, which the app's own update checks
    (`Sources/FleetCore/AppUpdate.swift`). So a release channel's host that is broken into can give each Mac a newer
    build of the team's that the owner did not approve for customers, and root installs it.
12. **A page in the browser.** On a Mac, Fleet Vault types the password and the code into the page in the Chrome that
    the agent uses (`Sources/FleetVaultCore/VaultBrowser.swift`, `rules/logins.md`). A program that can run a script
    in that page can read them, and it can use the session's cookies after the sign-in. The code says that it protects
    the vault's keys, not the browser's session (`Sources/FleetVaultCore/VaultBrowser.swift`).
13. **The owner's Mac while it is unlocked.** The app signs with the owner key with no Touch ID or password prompt
    (`Sources/FleetCore/OwnerKey.swift`). So a person or a program that controls the Mac as the owner can sign
    statements: with the app's own controls, or through the app's link, where the tool `grant_secret` of the
    app's own program makes the app sign a grant of a secret to an agent, or its end. The tool `share_secret`
    makes it sign a secret into the grantable pool, or out of it. The tool `answer_secret_request` makes it sign
    a grant of a secret to each agent that the call names, and then answer an agent's request for that secret.
    None of the three asks the owner (`Sources/FleetOwnerAPI/OwnerGrantSecret.swift`, `OwnerShareSecret.swift`,
    `OwnerAnswerSecret.swift`; OWNER-MCP-BOUNDARY.md, section 7b).
    What a secret in the pool gives is limit 9. A copy of the app with a different signature must first get the
    owner's login password from macOS to read the key's item (`Sources/FleetCore/OwnerKey.swift`). The hub takes
    each call from the Mac's address that
    carries the Mac's own key for the hub, which is a file of the owner's user (`hub.py`, SECURITY.md, "How the hub
    knows the owner's computer"). So a program that runs on the Mac as the owner uses every owner route. A VM or a
    container on the Mac has the Mac's address and not that file, and the hub refuses it, unless the owner gives it
    the folder `~/.founderizer`.
    The app's own Keychain items are in the file-based login keychain (`login.keychain-db`), not in the
    data-protection keychain (`FleetKeychainItem` in `Sources/FleetCore/OwnerKey.swift` sets no
    `kSecUseDataProtectionKeychain`; checked on the owner's Mac on 22 November 2026 for the recovery code). There,
    "this device only" has no effect. So the recovery code, the access key, the software form of the owner key and
    the app's other items are in each Time Machine backup of the Mac, locked by the Mac's login password. A key in
    the Secure Enclave is not: only a reference to it is in the file, and it opens on no other Mac.
14. **The hub's own sign-ins.** The Google refresh tokens and their client secret, the GitHub App private key, the
    credentials of the MCP servers and the Discord and Telegram bot tokens are not in the vault. They are files of the hub's OS user
    on the hub's server, so a person who controls that user has them (`hub.py`, `channels.py`). The Google file is
    sealed with ChaCha20-Poly1305 under a key that the central vault keeps and gives to the hub's user, so a copy of
    the hub user's files does not open it (`hub.py`, `atrest.py`, `vault.py` `hub_key`). Until a central vault serves
    that key, and on a Mac, the key is in a second file of the hub's user outside the hub's data folder, so only a copy
    of that folder alone does not open it. Neither protects the file from that user, who can ask the vault, or from a
    copy of the whole disk.
15. **The door's secrets.** The door keeps each secret that it opened, and each key that it made itself, in a file of
    its own OS user, not in an age store. The hub keeps an SHA-256 of each secret that the door opened, with no salt
    (`door.py`, `hub.py`).
    The door keeps each copy that its own key opens, and nothing signs the copy: age does not say who sealed it, and
    the hub knows the door's pinned key. So a hub that is broken into can put a value of its own under each name of
    the door's file, with no step of the owner, and the door then works with that value, for example in the account
    of another person at a provider (`fetch_sealed` in `door.py`). The same hub can also make the door delete a value
    that it holds (the `keep` list). It can also send the sealed copy of one key again under the reference of another,
    because the door keeps an opened copy under the `login` that the hub names and the central vault seals only the
    value: so a provider's key that the door has not held under its provider's name (the door's record, below) can
    reach an app's setting, and the door writes it onto a host. A signature of the central vault on each copy, which
    names its reference and which the door checks before it keeps the copy, closes the first and the last of these; it
    is planned (22 November 2026), not built.
    The names in the door's file are the hub's word too. The Mac writes each card credential's name, the reference of
    the secret behind it, and the providers of each agent as the hub's view gives them (`DoorAccess.swift`). So the same
    hub can drop a credential, and the door then deletes its value. It can also point a credential of an app's setting
    (`app:<app>:<NAME>`) at the reference of another key, and give that credential to an agent that it steers. A
    signature on the copy does not stop this, because the value is the right one. So the door keeps a record of its own,
    which no later file changes: the first name of each reference that its file names, and a mark (an SHA-256 with no
    salt) of each value that it holds under a provider's first name. Both stay after the credential and its value are
    gone. The door gives a key to an app's setting only when that setting is the first name of the key's reference, and
    never a provider's key of that record or the key of a GitHub App. While the door cannot read or write the record, or
    the record is full, it gives no saved key to an app, and its calls to the providers go on (`keep_names` and
    `setting` in `door.py`). A key that the door knew first under another name cannot become an app's setting: the owner
    ends the door's hold of that key (the owner tool `grant_access`, resource `secret:<reference>`, agent `door`, no
    level), then removes the key in Secrets, and the next key card of that setting makes a new reference, under which
    the door gives the key. A provider's key stays out of the app then too, and the owner makes another key for it. The
    same value under a new reference is refused only for a provider's key: the value of an app's key, or of a database's
    login, can come again under another app's new reference. While the record is full or cannot be read, the owner puts
    an earlier copy of it back on the door's server, or removes it, after they checked the hub and replaced at its
    provider each provider key that the door held: the record then forgets what came after, and a hub that is broken
    into can fill it on purpose, because it can seal any value to the door. What stays open: the first name of a new key
    is the hub's word, and so is the reference of a value that the door has not held yet. The record begins with the
    file and the values of the day of the door's update, or of its install, so it knows no move from before that day.
    The login of a database (`db:<name>`) has a first name and no mark, because a person can choose its password: so a
    broken hub can send that login's copy again under the reference of an app's new setting, and the door then writes it
    onto a host. The fix is planned with the signed copies (22 November 2026), not built: the owner's grant to the door
    names its credential, and the door keeps and gives a value only under that name.

    The door's own server is a server at a provider. If a credential of the door is a server provider's token, and the
    project of that token also holds the door's server, whoever reads the central vault's store (limit 4) can take the
    door's server with the provider's rescue system, and so can write the door's file. The door's server belongs in a
    project (an account) of its own, for which the fleet holds no token. This is a limit of today, and no code checks
    it.
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
    connect. On a Linux server with the outgoing gate (see "The outgoing gate"), the gate records each host
    that each agent connects to, and the kernel refuses an agent's UDP other than DNS and its ICMP; it refuses no
    host yet, so the rest of this limit holds there too, with a record. The helper starts each session as a program of the agent's OS user (`fleet.py`). A task session
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
23. **The server of a Give is the hub's.** The app signs a grant for the server that the hub names for the agent at
    the moment of the Give (`Sources/Founderizer/GrantSigning.swift`). A hub that is broken into can name another
    server there, but only a server whose key the owner pinned, because the central vault seals a copy only to a
    pinned key (`vault.py` `seal`). So such a hub can send a secret that the owner gives to one of the owner's servers
    to another of them, and to no other machine (choice C50).
24. **A statement from ahead.** Before the hub release of owner API 1.219, the central vault kept a grant, ungrant,
    pool, unpool or recovery statement that was dated more than one day after its own clock, when the owner's Mac had
    a clock that ran ahead. It still keeps such a replace statement (`vault.py` `intake`). Such a record stays its
    newest until its time, and no statement dated right can end it before then: for a replace, the owner cannot put a
    new value under that reference until that time (`vault.py`).
25. **A signed grant that the hub no longer holds.** The central vault keeps each grant that the owner signed, and seals
    the secret to that grant's machine, until the owner's ungrant reaches it, also after the agent was deleted,
    renamed or moved, or after a take-back that signed no ungrant (`vault.py` `sealable`). The hub marks such a grant
    as not held (`GET /ui/vault` `standing`), and an honest hub asks the vault for no copy of it, but a hub that is
    broken into can ask, and the vault then seals the secret to that machine's pinned key (choice C50). The vault keeps
    one record of each secret and agent name: after a rename, the grant stays under the old name, and when a new agent
    later gets that name and the same secret, the record moves to the new agent's machine, so the renamed agent's
    machine loses the secret until the owner gives it again, and no mark shows it.
26. **A page in the agent's own browser on a Linux server** (build plan 04, S5 and section 6). The broker types the
    password and the code into the page of the agent's own Chrome, so the agent's own programs can reach them:
    - An agent with the Shell box can run a program as its own user. That program can connect to its own DevTools
      port and read a filled field before its submit, or the request that sends it. With its Chrome stopped, it can
      also be the listener on that port itself and get the vault's script, password included: the broker's check of
      the listener's user stops only another user.
    - The broker types into each tab of the login's origin that it tries (three at most), and any page of that origin
      gets what it types: a page of the site that the agent opened there, a page of the site's own users' content
      too.
    - The browser's "show password" control and a snapshot of the page can show a field that stays filled; the
      broker empties each password and code field of a sign-in that it could not confirm, also after an error, as far
      as its DevTools connection to that browser still works.
    - The page's CSS: the vault types a secret only into a readonly field whose size and glyphs it read back from the
      computed style, with no transition or animation on it. A shadow root's `::slotted` rule whose condition comes
      true after that look (a container query after an animation, `:target`, the focus that the page's script gives,
      a class), while the secret stays in the page (a handler of the page took the submit, or a dialog form), can
      still give another site a password's length or a code's digits (the comment of `VaultBrowser.dom`).
    - A listener of the page can hide a submit from the vault, which then answers that the form sent nothing, though
      the browser may have sent it to the login's own origin. The broker then watches that tab as after a submit
      (a sign-in that went counts, and the record keeps where it went) and types the secret into no other tab; so
      after a fill that gave no answer, whose script can still run in the page.
    - With no keyring on a server, Chrome keeps its cookies where the agent's own programs can read them, so a
      signed-in session can be copied, and a copy works until the site ends that session: the owner's step is the
      site's "sign out everywhere" or a new password.
    - The end of the agent's use of a login clears the sign-in's sites in its browser at the hub's next pass (within a
      minute) while that browser runs, else at its next start, which waits for the clear. The owner's grant ends that
      use at once; a login that the task made, and a sealed copy, end with their task. The agent's own processes can
      post a record of a sign-in job, which the hub cannot tell from the broker's, so an agent can keep a site of its
      own sign-in out of the clear, as it can copy its cookies.
    - The port rule has a gap of one reading after a flush of the nftables ruleset by hand (at most five minutes),
      and an agent can start a Chrome of its own outside its unit, its memory cap and its port, as any program of its
      own. A page of a loopback address (an agent's own development server) reaches the vault's swap proxy port, which
      answers each request that is not a CONNECT line with 405 (`SWAP_ONLY_CONNECT`), and a page cannot send CONNECT.
      The blocked providers' sites come from the owner's app, so a new provider's site is blocked on a server only
      after that app has the new list.
    - During a take-over the agent can see what the owner types.

27. **What a session writes on its own machine.** Each session of an agent runs as the agent's OS user, and that user
    owns the agent's whole home folder: the helper's code and its service, the agent's hub key, the programs that each
    session starts, and the settings that each runtime reads. So a session that follows hostile text, and code that an
    agent runs, can change what each later session of that agent, its checks and its helper read and run, and can
    leave a program that runs with no session. Founderizer does not stop such a change. The machine's service records,
    by name, size and digest, the files of that home that later sessions and the helper read and run (the checkout,
    the user's units, `~/.local/bin`, the Python user site, the shell and tool files, each runtime's settings), the
    crontab, the processes and the listening ports (`home_reading.py`, the owner's page `homes`). That record stops
    nothing, and a program of the same user can change what it says. The change stays inside that one agent: another
    agent's OS user, the hub and the vault's stores are out of its reach. One effect goes further: on the owner's own
    fleet, a session can hold a release from every customer until a newer release (`autopublish.fleet_took`). It can
    write a refusal of that release as its machine's start check before the machine takes it, or a check of it that
    did not end in time while its helper's update is failed, or stop its helper after the release was applied. On a
    Mac its server service runs as the same user, so the session can write the service's record too, and a service's
    check that did not end shows nothing on the owner's page. The hub names the releases on the owner's page from its
    own records, so such a session cannot put words of its own there. The repair is to remove the agent and add it
    again.

28. **The first program of a new server.** A server that joins runs the join script that the hub serves, as root (a
    Mac runs it as root in the installer, or else as the user of its agents). Its first checkout comes from the hub's
    repository with no check by a release key; each later update of that checkout is checked (`join.sh`, `hub.py`). So
    a hub that is broken into at the time of a join can give the machine another program. On a Linux server that
    program is root, and it can know the key of the broker that it installs, which the owner's Mac then reads there
    and pins. The hub can then open each value that the owner gives to an agent of that server. A machine that joined
    before does not change by this, nor does the hub's own server, which installs from GitHub (`hub.sh`). Root's step
    that gives a hub that runs one server for all (`hubsetup.py one-server`) runs from root's own clone, and it clones
    the server service's checkout from the hub's own bare repository by its path, never over `git://`, which proves no
    server; only then is that checkout's origin the `git://` address.
    **An installer that runs again** on a server runs root steps from the checkout of the service's own user: on the
    hub's server the agents' users and their list, and where agents share it the vault, the key swap and the outgoing
    gate (`hub.sh`); on a joined server also the firewall and the hardening (`join.sh`). If that user is broken into, root
    runs that user's code, and on the hub's server it can read the vault's store. The second claim of a lost Mac
    (`HUB-INSTALL.md`) is such a run. The check of a later update of the checkout is that user's program too.

29. **The hub's ports on a server that also runs agents.** The hub listens on its port (8765, or the port of `hub.sh
    --port`) and its git service on 9418, as the hub's user, and the connect gate on 127.0.0.1:8767, as its own user.
    Each port is above 1024, so each user of that server can listen there while the program does not run: a crash, a
    restart by hand, a start of the server, a release that changes the text of a service's unit, a second claim. Root's
    step of the hub's server (`hub.sh` in its firewall step, and `hubsetup.py one-server` before its other parts) puts a
    kernel rule in place (`ports.py`): each packet from the hub's port or 9418 whose socket is not of the hub's user or
    root, and each packet from 127.0.0.1 or ::1 port 8767 whose socket is not of the gate's user or root, is dropped, in
    IPv4 and IPv6; so is each SYN-ACK from those ports that no socket of the port's own user or root sends, because the
    kernel sends the SYN-ACK of a SYN cookie with no socket, and an agent's listener that filled its own queue would
    else complete a client's handshake by cookie and read its first data. So a listener of an agent's user there gives
    no client a handshake: the server's broker, the other servers' helpers and brokers, the door and Funnel get no
    answer from it. Under a SYN flood the port's own program then answers no new client by cookie either, which is a
    denial only. A unit of root's loads the rule at each start of the server, before the users' services, again at each
    change of `/etc/passwd` and after each start, reload and stop of `nftables.service`; no user's services, no connect
    gate, no vault broker of that server and no cron or at job start when it does not load, so the broker sends no
    agent's key to a port that has no rule and no agent's job takes the port (root's own cron jobs wait as well); and no
    agent user logs in by SSH there (a file of sshd's with `DenyGroups fleet-agents`, because an agent owns its home and
    could put a key of its own in it; the step stops where sshd's own reading, `sshd -T`, does not deny that group). A
    root command with no argument, which the hub's user and the gate's user may run with sudo, ends such a listener: it
    stops each process that holds it and whose real UID is neither root's nor the port's own user's, and each process
    that a fork gave the listener in the meantime, then ends them all; it ends no process whose real UID is root's or
    the port's own user's. The units of the hub, of its git service and of the gate run it before each start (the git
    service's unit of a hub that got the rule only from `hubsetup.py one-server` gets that line at its next `hub.sh`;
    the hub's unit moves to it by itself), and root's unit at each load of the rule. What stays: when the rule does not
    load at a start of the server (the boot unit's line in the journal says why), the hub stays down, and only root and
    the hub's user can log in by SSH, for a repair; a listener of an agent's user can hold a port that it took while the
    program did not run, and answer nobody, until the next start of that program by its unit; a socket of an agent's
    user that is bound to one of these ports and does not listen is in no table of the kernel's listeners, so the
    command does not see it, and it keeps the program's bind out (a denial only); an agent that keeps another of its
    processes sending SIGCONT to the stopped holders, or that traces them, can fork past the command's looks, and a
    socket that waits only in a UNIX socket's queue has no process to end: both keep the program's port taken, also a
    denial only; a flush of the kernel's rules by hand (`nft flush ruleset`) takes the rule away until the next change
    of `/etc/passwd`, the next start of the gate or the next start of the server; a sub-uid range of an agent that holds
    the hub user's UID lets a process of that agent take that UID (the outgoing gate's step names such a range); and a
    hub's server that no root step reached since this release has no rule until its next one (`hubsetup.py one-server`,
    or `hub.sh` again). Where the step cannot take back a file of sshd's that sshd refused, that file stays in sshd's
    folder, and the step's words say that it could not be taken back; sshd then does not start again until root removes
    it; and `--check` reads sshd's files, not the running sshd, which takes them at the step's next run. A `Match` block
    of sshd's settings that sets `DenyGroups` again for some connections (for example `Match Address 127.0.0.1` with
    `DenyGroups nobody`) lets an agent user in by such a connection, while `sshd -T`, which the step reads with no
    connection, still names the deny; the fleet writes no such block. Root and the hub's own user are trusted for these
    ports. A hub on a server with no agents does not have this limit (`ports.py`, `hub.py`, `vault.py`, `lifecycle.py`).

30. **A hub's own server that took agents before its key swap and its gate.** A hub whose owner chose one server for all
    after its install, with a release before this one, or that was installed with that word before 16 and 17 November
    2026, has no key swap or no outgoing gate on its own server until the owner's Mac runs its next key swap round
    there, or root runs `hubsetup.py key-swap` and `hubsetup.py egress`. Where an agent runs there already, `hubsetup.py
    one-server` leaves the key swap to the Mac, whose rule waits for the owner's yes on its card when an agent there
    reads a key with a site. The Mac's gate step runs only where `/etc/founderizer-egress/egress.json` is not there, and
    only after a keys step of the Mac there; the Mac keeps no record of it, so a gate step that failed comes again only
    with the next keys step (for example a new `vault.py`, a new owner key of the central vault, the pin's weekly
    signature, or a switch that the table wants). So the Mac leaves a gate that root turned off (`--egress off` keeps
    that file), and a first gate step that stopped after it wrote that file (its gate did not start) keeps the file, so
    there only root's `hubsetup.py egress` makes the gate. A Mac with no root connection to the hub's server tries the
    root route of the hub's server (see "Who the Mac logs in as, and where"); where root refuses its keys, it counts a
    try on the hub's row, and after six the Secrets page says that root refused the Mac's key and that the owner adds
    that key to root's `authorized_keys`. A fleet with no Mac round keeps that hole. Until then each agent there gets each API key of the pool as a value, and no gate records where it
    connects. For a hub that takes agents and whose own server has its server service, the hub tells the manager that
    the gate's table is not loaded there. Each step also goes on when it stops, as at an install (`hubsetup.py`,
    `hub.py` `egress_troubles`, `KeySwapPlan.swift`, `vault.py` `configure_egress`).

31. **An API key with the name GH_TOKEN.** A task session's environment is the agent's keys first, and then the
    variables that Fleet sets for the task itself (`fleet.py`): for an agent with repositories, GH_TOKEN is the fleet's
    own GitHub token. So a key that the owner saves with the name GH_TOKEN does not reach that agent's task sessions:
    the fleet's token takes its place, and nothing says so. Its owner-chat sessions get the key. The Secrets page and
    `save_secret` take that name today. Give such a key another name, as `GITHUB_TOKEN` (`fleet.py`, `lifecycle.py`
    `FLEET_KEYS`).

32. **The pool holds each secret by default.** Since owner API 1.328 (the owner, 24 November 2026: "I think the manager
    should be able to do that!", and "the goal is to minimize Needs you cards") the fleet manager may give each resource
    that the fleet holds, each secret of the catalog included, and the owner's standing only narrows it (`hub.py`
    `resource_standing`). The owner's Mac signs a `default_pool` statement for each such secret by itself, a few at each
    round, with no step of the owner's (`Sources/Founderizer/GrantSigning.swift` `pools`), and the central vault then
    seals it to each machine whose key the owner pinned. A hub that is broken into directs the agents on those machines,
    so it can read each pooled secret.

    What stays out of the default: a secret whose variable is one of Fleet's own keys (`FLEET_KEYS`) or a GitHub App's
    key (`GITHUB_APP_<X>_KEY`), a secret that an account names, a key of the door's (`door.secrets`: its providers and
    the settings of production apps), a Stripe secret key, live or test, which the vault finds by its value (`vault.py`
    `MONEY_KEYS`), an MCP server with an OAuth sign-in of a payment, code, cloud, DNS or gateway host (`kept_app`,
    `KEPT_APP_HOSTS`: the host or a subdomain of its url, or of the issuer or the token endpoint that its connection
    named at Connect, or the form of the token that its Connect got, as GitHub's `gho_` and Stripe's `sk_live_`; Stripe,
    PayPal, the exchanges and brokers of the list, Plaid and Shopify move money, GitHub, GitLab and Bitbucket give the
    owner's own user token with write to each repository of the account, and GitHub Enterprise Cloud at `ghe.com` too, a
    cloud, hosting or DNS provider reaches their servers and domains, and a hosted MCP gateway (Zapier, Composio,
    Pipedream, Smithery, Make, n8n) reaches GitHub, Stripe and the rest through the owner's connections there, and a
    secrets manager's app (Doppler, Infisical, 1Password) reads their secrets) or one connected with an administrator's
    or an organization-wide scope (`ADMIN_SCOPE`: Slack's `admin.*`, GitHub's `admin:*`, Google Workspace's
    `admin.directory.*`, Microsoft's tenant-wide scopes (of its directory, roles, applications, policies, groups and
    their members, Teams channel messages, reports and security events, `User.Read.All`, and each `.ReadWrite.All`,
    `.FullControl.All` and `.Manage.All`) and its `.default`, Atlassian's `manage:*`, Okta's `okta.*.manage`; not a
    one-user reader such as `Files.Read.All`), a repository that an Operator holds or that
    the door syncs (`door.gitops`), and each resource that the owner keeps with "Only you" (`resource_kept`). Against a
    hub that is broken into, the vault itself keeps out what the owner took out of the pool, a key that moves money, a
    key that they gave the door, and a name with no value: it refuses a `default_pool` of each, and only their own
    `pool` puts one back; a key that they gave the door it seals only by a grant, never by the pool. The rest of that
    list the hub reads from its catalog, so it holds against the manager, not against such a hub.

    What the default still reaches, at read: each other key that moves money (a restricted Stripe key with write rights,
    another payment provider's key, a login to a bank, a broker or the Stripe dashboard), each account or deploy token
    under another name (a GitHub token saved as `GITHUB_TOKEN`, as limit 31 suggests; cloud, DNS, registrar and deploy
    keys, which reach the kept repositories and deployments), a key of a service that sends (SMTP, SendGrid,
    Twilio), and, since 26 November 2026, an MCP server with an OAuth sign-in that can send or post as the owner (a mail
    or an automation app: its one level `use` gives what a Gmail's `send` would), one at a host that the list cannot
    match (a self-managed GitLab or a GitHub Enterprise Server at a company's own host), and a gateway or any other app
    at a host that the list does not name, which can reach a payment, code or cloud account for the owner. The hub sees
    an app's host and the scopes that its connection names, not what the provider lets those scopes do, so an admin's
    scope of another name is in the default too. An app is judged again at each read and at each session's start: a hold
    that the default gave before its Connect named a kept issuer, scope or token, or before a new Connect, gives no
    session its token while the app is kept (`mcp_hold_kept`); no session of a hold that the owner did not give gets a
    token whose own form is GitHub's or Stripe's, also of a connection from before; such a hold counts as no hold for a
    card or a question, so the agent's ask goes up and the owner's Give, or their own tick on the Tools page, opens it.
    A running session keeps a token that it got before, and a GitHub token does not expire: after a new Connect makes an
    app kept, the owner revokes the old token at GitHub. While the hub cannot read its file of connections each app is
    kept. A server address is ASCII only, with no backslash, so the host that the hub judges is the one that a session
    connects to. Every app at `googleapis.com` is kept, so a Google sign-in app comes to the owner as a card. Keep such
    a key or app with "Only you" on its row.

    A repository goes by the default at `read` only (`DEFAULT_TOP`, the supervisor's decision of 26 November 2026,
    after the Door area's read A4); a Gmail goes up to `write`, each other kind to its top. A write token pushes a
    branch, a tag or a commit, and what the repository already runs takes that code beside its own secrets and runners:
    its GitHub Actions workflows (on a push, a tag, a pull request, a schedule, and those of any older commit that a new
    branch or tag points at), Dependabot with its own secrets for the registries that a file of the repository names,
    and builders and servers that the fleet's GitHub App cannot see (Vercel, Netlify, Cloudflare, Argo CD, a server
    with a deploy key or a webhook). No read of the App shows that none of them is there, so a door that read the
    workflows at each grant would still leave a hole, and it would close nearly every repository of a fleet anyway. A
    repository's `write` and `deploy`, and a Gmail's `send`, come only with the owner's own level on its row: to trust
    one repository, the owner sets its row's "At most" from Read (the default, with "You and the fleet manager") to
    Write in Settings, one choice, and the manager then gives write of it with no card for each grant. That level is
    the owner's own risk, as above. Two limits of that choice: a repository that only the App reaches and that no
    agent holds has no row until the manager's first grant of it (`resource_ids`), so the owner cannot set its level
    before; and once an agent that holds a server through the door holds a repository, it is kept as `fleet` for every
    other agent, whatever the row says. A repository counts as one that the fleet holds also when the newest reading of
    the fleet's GitHub App reaches it (`github_reaches`: by its name, or by an account whose installation has all of its
    repositories; since 26 November 2026), and one that an agent holds counts with no reading of the App too. So with an
    installation of all of an account's repositories, each private repository of that account is in the pool at read
    from the start (it has no row before its first grant, above): the owner narrows one with "Only you" on its row after
    that grant, or leaves it out of the App on GitHub's own page. A repository of such an account counts only when the
    hub's list of the last minute names it (`github_repo_list`), so a name that does not exist is not in the pool, and
    an account with more repositories than the hub reads counts only by those that it read. The product's private source
    (`product_source`: `founderizer-source` under any account, also after a transfer) is in no default, ever: developer
    agents get it through the agents' own App, and it is kept as the owner's (`source`), so the owner's own level on its
    row, or their Give on a card, gives it. A plan of `change_team` is refused a repository of an all-repositories
    account that the hub's list of the last minute does not name; with no list it passes, while the default gives such a
    repository only once the list names it. The hub reads that list before a lock in a thread of its own, waits for it
    at most 4 seconds, and reads it at most once a minute, also after a failed read (`github_repo_list_ahead`).
    A repository that the door made keeps new-projects plan N3: the manager
    gives it up to write to an agent that holds no server, and its workflow files go through the door. An agent that
    holds a server through the door gets any other repository only under the owner's own level of write or deploy,
    because the door commits for it to each repository that it holds, at any level. That check is at the grant only.
    Since the Door area's commit targets (`door_commit_holds`, owner API 1.364), the hub names to the Mac app as commit
    targets only a hold at write or deploy, or one whose newest `resource_grants` row is not of the level that it holds
    now. So a read that the default or the manager gave, and an owner's Give at read, stay reads, also once the agent
    has a server and also for an Operator whose business has no ready host. The owner's page writes no row, so a read
    that the owner sets there stays a commit target (the supervisor's decision of 26 November 2026), also when it lowers
    a write that a row records. Known limits: a row that a stop of the hub left out (the same Give press, or the same
    grant_access request, again writes it), a database older than its `team.json`, and a revert or an undo of
    `team.json` to an older state: each such hold whose newest row is of another level, or that no row names, reads as
    the owner's own and is a commit target. Holds at write or deploy that the
    default gave from hub 2026.11.812 to this release stay as they are (none on the owner's fleet). On 26 November
    2026 the default had given no repository at write or deploy since it came (hub 2026.11.812), so nothing was taken
    back. The hub reads the door's targets from `team.json`, not from the door's file, so a target that the file
    holds with no such grant (an Operator with no ready host, a target with fields of its own after its grant ended, a
    hand-written one) is not kept (none on 24 November 2026).

    Each `unpool` that the Mac's round signs lasts as the owner's own does: only their own `pool` puts it back (it fails
    closed). A secret out of the catalog gets one too, because the hub reads that as their removal and the vault removes
    no value that a pool names. While the hub runs on a `team.json` that breaks its own rules, the round owes no such
    unpool and no new pool, and the hub removes no value from the central vault; but a restore of an older `team.json`
    that keeps those rules is read as it is, so each secret that it lacks is unpooled and its value removed. Their "Only
    you" from before 1.328, which took the entry out when no entry meant theirs, became `{"owner": true}` at the first
    start of 1.328 (`pool_default_keep_seed`).

33. **A copy that the app saves holds the fleet's owner access key, and nothing replaces that key.** Each copy that the
    Founderizer app saves, with Save a copy or by itself (at least the 7 newest stay in the folder, iCloud Drive unless
    the owner chose another one), is a plain zip with the member `owner-access.key`: the private half of the fleet's
    owner access key, as an OpenSSH key file with no passphrase (`Sources/FleetCore/OwnerAccessKey.swift`,
    `OwnerAccess.withKey`).
    Its public half is a line of root's `authorized_keys` on each Linux server of the fleet, the hub's own included
    (`OwnerAccessSweep`). So whoever holds such a copy and reaches a server's SSH port (over the tailnet, or at a public
    address that the server's installer did not close yet) logs in there as root, and root on the hub's server can read
    every secret of the central vault; the recovery code, which the copy does not hold, is not needed for that. The key
    is in the copy so that a new Mac reaches the fleet's servers after the owner's Mac is lost. No step replaces it after
    a copy leaked: the app makes one key for each fleet and never a second (`OwnerAccessKeychain`), so the line stays a
    way in until it is taken out of root's `authorized_keys` on each server by hand. A copy from the owner tool
    `take_backup` holds no such key.

34. **A made key and a hub that is broken into.** The central vault makes a key, and a new value of a made key, when the
    hub asks, with no signature of the owner's (`vault.py` `make`). So a hub that is broken into can ask:
    - for new keys, with no count. Such a key opens nothing until a route's checker has its hash. Each key and each new
      value takes room in the store, which holds 4 MiB at most: a full store takes no new secret of the owner's either.
    - for a new value of a made key. Its readers then have a value that the route's checker does not know, so the route
      refuses them until its checker has the new hash. A value of the owner's is never touched.

    It can also name a site of its own for a new key, and it can have a made key of the pool sealed to each machine
    whose key the owner pinned, as each value of the pool (limit 9). It can also have a made key taken away: the removal
    needs the owner's signed `unpool`, but the owner's Mac signs the `unpool` of each secret that the hub lists as due
    out of the pool, with no step of the owner's (`Sources/Founderizer/GrantSigning.swift` `pools`), as an honest
    removal needs it (the design's 4.5). The harm is a route whose readers fail until a new key is made, as a new value
    already causes. It can also fill the store with made keys or new values (about 8,400 keys, or 17,600 new values of
    one key, reach its 4 MiB), and no code of an honest hub takes them out afterwards; each key keeps the records of its
    newest 16 requests only. Today only root on the central vault's server repairs a full store; the hub that asks for
    made keys (a later piece) owes an `unpool` of each made key that its catalog lacks, so that the owner's app signs it
    and the vault removes the key.

    A machine that took a copy of a made key keeps the old value until it takes a copy of the new one, as after a
    replace (limit 22). The route takes the old value until its checker has the old hash no more.

    The broker of a Linux server reads the mark, and the hub delivers a made key only to a vault that says that it
    keeps such a key out of sessions (limit 35). Fleet Vault on a Mac does not say it yet, so a Mac gets no made key.
    No hub asks the central vault for a made key yet.

35. **A made key on a machine.** The rule that a made key is never a value in a session or a check is in the vault
    program of the machine (`vault.py` `read`, `swap_value`, `handover`, `signin`). The central vault seals a made key
    only for a request with the hub's word `made_keys` (`vault.py` `seal`), and the hub says it only for a vault that
    keeps the rule, never for the door (`hub.py` `central_plan`, `central_reconcile`, `helper_deposit`,
    `door_reconcile`). A vault program from before the rule refuses a made key by itself: the key is inside the member
    `made` of the copy and of the stored value, where no older program reads a key (`vault.py` `copy_text`,
    `made_login`). Where it stops:
    - Root on a machine reads each made key that the hub delivered there, as each key there.
    - A central vault that is put back to an older program: the program of the first made keys finds no password at
      the top of a made item and seals nothing. The program from before `make` says no `makes` in its status, takes no
      word, and seals a made item as its store holds it, with the key inside `made`: no vault program finds a key in
      such a copy, and the door refuses it, because it holds a `made` member (`door.py` `item_secret`). Such a status
      names no made key, so the hub (also one of this release) can have such a copy sealed for the door, for a key that
      the owner pooled or gave the door, and the door's refusal is then the one wall. The hub's catalog can name a made key itself from the piece
      that makes keys (`make_key`) on, and then keep it from the door also so.
    - A hub that is broken into says the word for each machine whose key the owner pinned. A copy that it gets so for
      an older vault program or for Fleet Vault on a Mac is refused there (the form above). The central vault seals no
      made key for the door, also with the word.
    - "Read only" is the route's own rule. `call_api` takes each path and the methods GET, POST, PUT, PATCH and DELETE,
      and the swap proxy each method but TRACE, TRACK and CONNECT; the key opens what the route's checker lets through
      at the key's site. So the piece that makes keys (`make_key`) gives each route a key of its own (one hash in one
      checker), its checker takes only reads, and no other program on that host takes the key.
    - With "Uses it", `call_api` sends the key to its own site. A site that sends the key back in another form than
      the key itself (for example as base64 of the bare key) shows it in the answer to the agent. With "Reads it", the
      swap proxy reads no byte of an answer, so a site that sends the request's header back shows the key to the session
      (limit 1). The core's checker of a route clears the header with the key before the request goes on, and sends
      nothing of it back.

## What the owner must do

1. **Protect the Mac.** The owner key and the recovery code are in its login Keychain, and the app uses the owner key
   with no prompt (`Sources/FleetCore/OwnerKey.swift`, `Sources/FleetCore/RecoveryCode.swift`).
2. **Run the root steps.** Only a root step installs and updates the central vault. The Mac app runs it over the
   owner's own SSH connection (`hubsetup.py`, `Sources/FleetCore/CentralVault.swift`). On a Mac with agents, the
   install of Fleet Vault needs an administrator, because it runs as root (`Vault/install.py`). After that install,
   the root step of `WORKER-INSTALL.md`, "Vault broker (macOS)", gives Fleet Vault the owner's public keys. That step
   turns handovers on for the Mac, which hands no login over without them (limit 6). For a machine whose
   host key the Mac does not know yet, the owner connects to it once with ssh from Terminal
   (`Sources/Founderizer/CentralVaultSection.swift`). For a hub's server whose root refuses the Mac's keys, the owner
   adds `~/.ssh/founderizer_ed25519.pub` to `/root/.ssh/authorized_keys` there, for example in the server provider's
   console (`Sources/FleetCore/HubRootRoute.swift`).
3. **Give each secret on purpose.** The app makes the recovery key and the pins of the servers itself
   (`Sources/FleetCore/CentralVaultPlan.swift`). After a real change of a Mac server's vault key (a lost Keychain, a new
   install of Fleet Vault), its row says that the key is not the one that the hub reports, and Try again does not pass:
   remove that server on the Mac and add it again. An agent gets a secret when the owner gives it, and the app signs
   that grant (`Sources/Founderizer/GrantSigning.swift`), or when the fleet manager gives it a secret of the pool
   (`Sources/FleetCore/OwnerKey.swift`). Put a secret into the pool only if any agent may have it. "Reads it" puts an
   API key in the agent's sessions, so give it only to an agent that must have the key itself
   (`Sources/Founderizer/SecretEntryView.swift`). For a key that swaps, name the exact host of the service's API as its
   site. Do not name a host that sends a request back in its answer, or a host that the service shares with other
   customers, because the agent can send the key in a request to each path of that host. Give the key the smallest
   rights at its service (`hub.py`, `vault.py`).
4. **Put keys in the vault, never in a chat.** Use Add secret. An agent asks for a key with a form, never in words
   (`RULES.md`). If a key went into a chat, replace it at its service (`RULES.md`).
5. **Delete an export file.** After an import, select **Delete export file**, or delete the file in Finder and empty
   the Trash (`Sources/Founderizer/SecretImportView.swift`). Delete each other copy of the file too, for example in a
   backup.
6. **Keep the recovery code.** It is only in the Mac's login Keychain and on a phone that enrolled after the Mac had
   the code (`Sources/FleetCore/RecoveryCode.swift`, `Sources/Founderizer/RecoveryCopy.swift`). Without it, a backup
   of the central vault cannot be opened (`vault.py`). A vault with the list of the owner's devices makes no new backup.
7. **Know what a new Mac changes.** The root step from a new Mac, whose key is not one of the central vault's owner
   keys, makes its key the only owner key of the central vault (`hubsetup.py`, `Sources/FleetCore/OwnerKey.swift`),
   while the vault has no list of the owner's devices. A Mac that Migration Assistant or a Time Machine restore made
   from another Mac takes the same path: the old Mac's owner key comes with the login keychain, but this Mac's chip
   refuses to sign with it while a new key of the same chip signs (a locked Mac or a token daemon that restarts fails
   that control and keeps the key), so Founderizer holds no owner key there, the Vault row says Set up, and only the
   owner's Set up makes this Mac's own key in its place: no automatic round of the vault, and no Try again, replaces an
   owner key. The first old item stays aside as "Founderizer · owner key of another Mac", so its form is not lost
   (`Sources/FleetCore/OwnerKey.swift`, `Sources/Founderizer/CentralVaultSection.swift`). A token daemon that does not
   answer keeps the key, and the Vault's steps stop with "The keychain refused the key (-25291)."; only a damaged item
   stops them with -26275, and only then take "Founderizer · owner key" away in Keychain Access, then Set up. A virtual
   machine has no enclave of its own, so an owner key that a copy of a Mac brings into one stops them with -25291 for
   good: there, take the item away too, and Set up makes a software key. A run of the root step from a Mac whose key is
   one of them keeps all of them. The recovery key does not change: a backup still opens only with the lost Mac's code,
   which only a phone that took a copy has (`Sources/FleetCore/CentralVaultPlan.swift`,
   `Sources/Founderizer/RecoveryCopy.swift`). A Linux broker, and Fleet Vault on a Mac that has the owner's keys, keep
   the old owner key until a root step on that machine changes their keys: on Linux, `vault.py configure` adds the new
   key (`--add-owner-key`) and takes the old one out (`--remove-owner-key`); on a Mac,
   `Vault/install.py --owner-keys-only` with the new key alone (`vault.py`, `Vault/install.py`). Do that root step on
   each such machine soon. Within 7 days the new Mac signs the pin of each machine again with its own key, and such a
   broker refuses each pin that the new key signed. So that machine's broker hands no login over until its root step
   (`Sources/FleetCore/CentralVaultPlan.swift`, `vault.py`). Keep Founderizer running on a Mac: it signs each pin again
   after 7 days, and a pin lives 90 days. When the Mac stops, handovers go on for at least 83 more days, and the System
   status page warns 30 days before the end (`hub.py`). A server that you removed on another Mac, or with
   `remove_machine`, is not in this Mac's record of removed servers. A server that you removed on this Mac and add again
   another way has a row on the Secrets page: select Try again there to trust it (limit 7).
8. **Replace a key after the end of "Reads it".** When you take "Reads it" from an agent, replace the key at its
   service. A session of the agent that runs keeps the old value until it ends, and the agent could copy the value
   while it had the grant (`fleet.py`, `hub.py`). A key that swaps is different: the agent had only a placeholder,
   so the end of the grant stops its use (`vault.py`). Replace such a key when a session held its value at an
   earlier time: before the key swapped, or on a machine that does not swap keys. Replace it also when its site can
   send a key back in an answer (limit 1). If the service lets a key make more keys, look there for keys that the
   agent made. Then save the new key with Add secret under the same variable name: the app puts it in the place of
   the old value, and the same agents keep it (`Sources/Founderizer/SecretEntryView.swift`). End the old key at its
   service too, because the vault cannot end it (limit 22).
