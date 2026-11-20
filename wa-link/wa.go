package main

// The real Client: one whatsmeow client on the session database.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type waClient struct {
	container *sqlstore.Container
	log       waLog.Logger
	handler   whatsmeow.EventHandlerWithSuccessStatus

	mu  sync.Mutex
	cli *whatsmeow.Client
}

func newWAClient(ctx context.Context, container *sqlstore.Container, log waLog.Logger) (*waClient, error) {
	dev, err := container.GetFirstDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the device: %w", err)
	}
	w := &waClient{container: container, log: log}
	w.cli = w.newClient(dev)
	return w, nil
}

func (w *waClient) newClient(dev *store.Device) *whatsmeow.Client {
	cli := whatsmeow.NewClient(dev, w.log)
	// The acknowledgement of a message waits until the handlers return,
	// and a handler that returns false stops it. The buffer keeps the
	// decrypted text until then, so a delivery again after a restart can
	// be read although the Signal session moved on.
	cli.SynchronousAck = true
	cli.EnableDecryptedEventBuffer = true
	cli.EnableAutoReconnect = true
	cli.InitialAutoReconnect = true
	cli.AddEventHandlerWithSuccessStatus(func(evt any) bool {
		if w.handler == nil {
			return true
		}
		return w.handler(evt)
	})
	return cli
}

func (w *waClient) client() *whatsmeow.Client {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cli
}

func (w *waClient) HasDevice() bool {
	return w.client().Store.ID != nil
}

func (w *waClient) OwnJID() types.JID {
	id := w.client().Store.ID
	if id == nil {
		return types.EmptyJID
	}
	return id.ToNonAD()
}

func (w *waClient) Connect() error {
	return w.client().Connect()
}

func (w *waClient) Pair(ctx context.Context) (<-chan whatsmeow.QRChannelItem, error) {
	w.mu.Lock()
	cli := w.cli
	if cli.Store.ID != nil {
		w.mu.Unlock()
		return nil, errors.New("already linked")
	}
	if cli.Store.Deleted {
		// After a logout, a new link needs a new device with new keys.
		cli.Disconnect()
		cli = w.newClient(w.container.NewDevice())
		w.cli = cli
	}
	w.mu.Unlock()
	cli.Disconnect()
	ch, err := cli.GetQRChannel(ctx)
	if err != nil {
		return nil, err
	}
	if err := cli.Connect(); err != nil {
		return nil, err
	}
	return ch, nil
}

// Send sends one message to a phone-number JID or a hidden-ID (@lid) JID.
// whatsmeow sends to a phone number through its hidden ID: from the LID
// store, else from a usync query to WhatsApp, which also works for a first
// message to a number that never wrote to this account. wa-link does that
// lookup first, so that a number that is not on WhatsApp gives a definite
// error (no message went out) and not "unknown". A hidden ID goes as it is.
func (w *waClient) Send(ctx context.Context, to types.JID, id types.MessageID, msg *waE2E.Message) error {
	cli := w.client()
	if to.Server == types.DefaultUserServer && cli.Store.ID != nil {
		if err := lidFor(ctx, cli.Store.LIDs, cli.GetUserInfo, to); err != nil {
			return err
		}
	}
	_, err := cli.SendMessage(ctx, to, msg, whatsmeow.SendRequestExtra{ID: id})
	return err
}

// lidFor makes sure that the LID store has the hidden ID of a phone number.
// lookup is whatsmeow's GetUserInfo, which saves the IDs that it finds.
func lidFor(ctx context.Context, lids store.LIDStore, lookup func(context.Context, []types.JID) (map[types.JID]types.UserInfo, error), pn types.JID) error {
	lid, err := lids.GetLIDForPN(ctx, pn)
	if err != nil {
		return fmt.Errorf("%w: reading the LID store failed: %v", errNotSent, err)
	}
	if !lid.IsEmpty() {
		return nil
	}
	info, err := lookup(ctx, []types.JID{pn})
	if err != nil {
		return fmt.Errorf("%w: looking up the number failed: %v", errNotSent, err)
	}
	if info[pn].LID.IsEmpty() {
		return fmt.Errorf("%w: the number is not on WhatsApp", errNotSent)
	}
	return nil
}

// Upload encrypts the file with a new media key and puts it on WhatsApp's media servers. Nothing is sent yet: the
// message that names the upload goes with Send.
func (w *waClient) Upload(ctx context.Context, data []byte, kind whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	return w.client().Upload(ctx, data, kind)
}

// Download fetches a message's media from WhatsApp's media servers into file: whatsmeow checks the encrypted file's
// hash and HMAC, decrypts it in place and checks the plain hash.
func (w *waClient) Download(ctx context.Context, msg whatsmeow.DownloadableMessage, file whatsmeow.File) error {
	return w.client().DownloadToFile(ctx, msg, file)
}

func (w *waClient) MarkRead(ctx context.Context, chat, sender types.JID, ids []types.MessageID) error {
	return w.client().MarkRead(ctx, ids, time.Now(), chat, sender)
}

// Typing shows "typing…" in the chat. WhatsApp shows it only for a client
// that is online, so wa-link is online while it types.
func (w *waClient) Typing(ctx context.Context, chat types.JID, on bool) error {
	cli := w.client()
	if on {
		if err := cli.SendPresence(ctx, types.PresenceAvailable); err != nil {
			w.log.Warnf("Setting the presence to available failed: %v", err)
		}
		return cli.SendChatPresence(ctx, chat, types.ChatPresenceComposing, "")
	}
	err := cli.SendChatPresence(ctx, chat, types.ChatPresencePaused, "")
	if perr := cli.SendPresence(ctx, types.PresenceUnavailable); perr != nil {
		w.log.Warnf("Setting the presence to unavailable failed: %v", perr)
	}
	return err
}

// Logout unlinks the device. When WhatsApp does not answer, it deletes the
// local session all the same; the phone then still lists the device until
// the owner removes it there.
func (w *waClient) Logout(ctx context.Context) error {
	cli := w.client()
	err := cli.Logout(ctx)
	if err == nil {
		return nil
	}
	cli.Disconnect()
	dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if derr := cli.Store.Delete(dctx); derr != nil {
		return fmt.Errorf("logout failed (%v) and deleting the local session failed (%v)", err, derr)
	}
	return fmt.Errorf("logout request failed (%v); the local session is deleted, remove the device on the phone", err)
}

func (w *waClient) Disconnect() {
	w.client().Disconnect()
}
