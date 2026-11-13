# wa-link

wa-link holds one WhatsApp linked-device session for the Fleet bridge (`channels.py`). It uses [whatsmeow](https://github.com/tulir/whatsmeow) and keeps the session in one SQLite file. The protocol is in `CHAT-APPS.md` section 15.12.

## Build and test

Go 1.26 or later (`brew install go`). The builds use no C compiler.

```sh
cd wa-link
go vet ./... && go test -race ./...
GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o bin/wa-link-linux-amd64 .
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/wa-link-darwin-arm64 .
```

## Run

```sh
wa-link --db ~/.fleet/chat-apps/whatsapp-main.db
```

The bridge starts wa-link and writes JSON lines to its standard input. wa-link writes events to standard output and logs to standard error. The logs never hold message text. The database file and its `-wal` and `-shm` files have mode 600. The folder must exist.

## Protocol details

These details add to section 15.12.

- **Start.** With no device in the database, the first event is `state` `logged_out`. With a device, it is `state` `connecting`, then `linked` when WhatsApp accepts the session. whatsmeow reconnects by itself after a lost connection.
- **pair.** The first `qr` code has `timeout` 60, the next ones 20. After the last code, the event is `state` `logged_out` with the error "the QR code was not scanned in time". A `pair` on a linked database gives the last `state` again and starts nothing: `linked` only while the connection is up, because the bridge sends only then.
- **ack.** A `message` event waits for its `ack`. whatsmeow sends the delivery acknowledgement to WhatsApp only after that (`SynchronousAck`). Without an ack in 10 seconds (the bridge could not write it to its journal), wa-link does not confirm the message, logs a warning and goes on with the next one; WhatsApp keeps it (14 days, by whatsmeow's count) and delivers it again after the next connection. When wa-link stops before the ack (the input ends, a signal, the output fails), it does not confirm the message either, and WhatsApp delivers it again after the next start. The decrypted-event buffer in the database lets wa-link read it again.
- **sent.** An `error` that starts with `unknown: ` means that the message can have arrived (a timeout, a lost connection, a stop). The bridge then reports `unknown`. Every other error means that WhatsApp did not take the message: the bridge reports `failed`.
- **send, read, typing.** wa-link accepts only the JID of a person (`<number>@s.whatsapp.net` or `<id>@lid`, with no device part). Message IDs have 1 to 128 letters and digits. A text has 1 to 65,536 bytes.
- **First message (CHAT-APPS.md 16.4).** A `send` can go to a person who never wrote to this number, in either JID form. For a phone-number JID, wa-link gets the person's hidden ID first: from the LID store, else from WhatsApp (whatsmeow's `GetUserInfo`, a usync query that saves the ID). whatsmeow then sends to the hidden ID with the phone number as `peer_recipient_pn`, as for every phone-number send. A number that is not on WhatsApp, or a lookup that fails, gives the error `not sent: …`, and no message went out. A hidden-ID JID goes as it is; when this number's LID store does not know the person's phone number (each account has its own database), the message has no `peer_recipient_pn`. Use the phone-number form for a first message when you know it.
- **reply_to.** wa-link keeps the last 1,000 inbound direct messages in memory. When `reply_to` is one of them, from the chat with `to`, the message quotes it. Otherwise, and after a restart, it is a plain message.
- **typing.** `on: true` sets the presence to available and the chat state to composing. `on: false` sets the chat state to paused and the presence to unavailable.
- **logout.** When WhatsApp does not answer, wa-link deletes the local session all the same and gives `state` `logged_out` with an error. The phone then still lists the device until the owner removes it there.
- **message.** `kind` is `text` (plain and extended text), `image`, `audio`, `file` (documents) or `other` (video, sticker, location, contact, poll, event). Captions go in `text`. `sender` and `sender_alt` have no device part.
- **Ignored.** Status updates and broadcast lists (`@broadcast`), channels, Meta AI bots, edits, reactions, revokes and other protocol messages, history sync, and undecryptable messages give no event. Receipts give events only for `delivered` and `read` in direct chats.

## On the hub machine

The bridge builds wa-link itself (`wa_link_program` in `channels.py`): the first time a WhatsApp account runs, and again when a release changes this source or the bridge's Go pin. It takes Go's own archive (`GO_VERSION`, held to the SHA-256 that go.dev publishes) and the modules that `go.sum` pins, from proxy.golang.org only, and builds at a low priority with one package at a time. It keeps only the program, `~/.fleet/bin/wa-link`, and beside it `wa-link.source`, the SHA-256 of what it was built from; the toolchain, the modules and the build cache go after the build. A failed build is tried again after 10 minutes, or at once when the owner asks for a link. While a build runs, a link request waits, and its QR code follows the build.

`FLEET_WA_LINK` names another program, which the bridge then starts as it is and never builds.
