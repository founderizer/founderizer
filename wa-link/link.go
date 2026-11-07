package main

// The protocol layer of wa-link (CHAT-APPS.md section 15.12): JSON-lines
// commands on standard input, JSON-lines events on standard output. It
// talks to WhatsApp only through the Client interface, so tests drive it
// with a fake client.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

const (
	ackWait      = 10 * time.Second
	maxLine      = 1 << 20 // the hub's body limit
	maxText      = 65536
	maxError     = 300
	recentLimit  = 1000
	opsQueueSize = 1024
)

// Client is the part of whatsmeow that wa-link uses.
type Client interface {
	HasDevice() bool
	OwnJID() types.JID // non-AD, empty when not linked
	Connect() error
	Pair(ctx context.Context) (<-chan whatsmeow.QRChannelItem, error)
	Send(ctx context.Context, to types.JID, id types.MessageID, msg *waE2E.Message) error
	MarkRead(ctx context.Context, chat, sender types.JID, ids []types.MessageID) error
	Typing(ctx context.Context, chat types.JID, on bool) error
	Logout(ctx context.Context) error
	Disconnect()
}

type command struct {
	Op      string   `json:"op"`
	ID      string   `json:"id"`
	To      string   `json:"to"`
	Text    string   `json:"text"`
	ReplyTo *string  `json:"reply_to"`
	Chat    string   `json:"chat"`
	Sender  string   `json:"sender"`
	IDs     []string `json:"ids"`
	On      *bool    `json:"on"`
}

type stateEvent struct {
	Ev    string  `json:"ev"`
	State string  `json:"state"`
	JID   *string `json:"jid"`
	Error *string `json:"error"`
}

type qrEvent struct {
	Ev      string `json:"ev"`
	Code    string `json:"code"`
	Timeout int    `json:"timeout"`
}

type messageEvent struct {
	Ev        string  `json:"ev"`
	ID        string  `json:"id"`
	Chat      string  `json:"chat"`
	Sender    string  `json:"sender"`
	SenderAlt *string `json:"sender_alt"`
	PushName  string  `json:"push_name"`
	Group     bool    `json:"group"`
	FromMe    bool    `json:"from_me"`
	Kind      string  `json:"kind"`
	Text      string  `json:"text"`
	TS        float64 `json:"ts"`
}

type sentEvent struct {
	Ev    string  `json:"ev"`
	ID    string  `json:"id"`
	OK    bool    `json:"ok"`
	Error *string `json:"error"`
}

type receiptEvent struct {
	Ev   string   `json:"ev"`
	IDs  []string `json:"ids"`
	Type string   `json:"type"`
}

// recent is an inbound message that a send can quote.
type recent struct {
	jids []types.JID // chat, sender and sender_alt
	msg  *waE2E.Message
}

// Link runs the protocol. NewLink, then Run.
type Link struct {
	cli     Client
	log     waLog.Logger
	ackWait time.Duration

	ctx    context.Context // ends at shutdown
	cancel context.CancelFunc

	outMu sync.Mutex
	out   *json.Encoder

	stateMu sync.Mutex
	state   stateEvent // the last state sent: a pair on a linked database repeats it

	mu      sync.Mutex
	pending map[types.MessageID]chan struct{}
	pairing bool
	recent  map[types.MessageID]recent
	order   []types.MessageID

	ops chan command
}

func NewLink(cli Client, out io.Writer, log waLog.Logger) *Link {
	ctx, cancel := context.WithCancel(context.Background())
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return &Link{
		cli:     cli,
		log:     log,
		ackWait: ackWait,
		ctx:     ctx,
		cancel:  cancel,
		out:     enc,
		pending: map[types.MessageID]chan struct{}{},
		recent:  map[types.MessageID]recent{},
		ops:     make(chan command, opsQueueSize),
	}
}

// Run connects when the database has a device, then reads commands until
// the input ends, the output fails or ctx ends. Then it disconnects.
// Messages that still wait for their ack are not confirmed to WhatsApp, so
// WhatsApp delivers them again after the next start.
func (l *Link) Run(ctx context.Context, in io.Reader) {
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		l.worker()
	}()
	l.ops <- command{Op: "start"}
	go func() {
		l.readCommands(in)
		l.cancel()
	}()
	select {
	case <-ctx.Done():
		l.log.Infof("Stopping: %v", context.Cause(ctx))
	case <-l.ctx.Done():
	}
	l.cancel()
	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		l.log.Warnf("The last command did not end in 5 seconds")
	}
	l.cli.Disconnect()
}

func (l *Link) emit(v any) error {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	err := l.out.Encode(v)
	if err != nil && l.ctx.Err() == nil {
		l.log.Errorf("Writing an event failed, stopping: %v", err)
		l.cancel()
	}
	return err
}

func (l *Link) emitState(state string, jid types.JID, errText string) {
	ev := stateEvent{Ev: "state", State: state}
	if !jid.IsEmpty() {
		s := jid.ToNonAD().String()
		ev.JID = &s
	}
	if errText != "" {
		s := clip(errText)
		ev.Error = &s
	}
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	l.state = ev
	l.emit(ev)
}

func (l *Link) emitSent(id string, err error) {
	ev := sentEvent{Ev: "sent", ID: id, OK: err == nil}
	if err != nil {
		s := clip(sendError(err))
		ev.Error = &s
	}
	l.emit(ev)
}

// sendError gives an error after which the message may have arrived (a
// timeout, a lost connection, a stop) the prefix "unknown: ". The other
// errors mean that WhatsApp did not take the message.
func sendError(err error) string {
	if errors.Is(err, errInvalid) || errors.Is(err, errNotSent) ||
		errors.Is(err, whatsmeow.ErrNotConnected) ||
		errors.Is(err, whatsmeow.ErrNotLoggedIn) ||
		errors.Is(err, whatsmeow.ErrServerReturnedError) {
		return err.Error()
	}
	return "unknown: " + err.Error()
}

func clip(s string) string {
	if len(s) <= maxError {
		return s
	}
	s = s[:maxError]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// readCommands reads one JSON object for each line. A bad line is logged
// without its content and skipped.
func (l *Link) readCommands(in io.Reader) {
	r := bufio.NewReaderSize(in, 64*1024)
	for {
		line, err := readLine(r)
		if errors.Is(err, errLineTooLong) {
			l.log.Warnf("Skipped a command line longer than %d bytes", maxLine)
			continue
		} else if err != nil {
			if !errors.Is(err, io.EOF) {
				l.log.Errorf("Reading commands failed: %v", err)
			} else {
				l.log.Infof("The command input ended")
			}
			return
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var c command
		if err := json.Unmarshal(line, &c); err != nil {
			l.log.Warnf("Skipped a bad command line (%d bytes): %s", len(line), jsonError(err))
			continue
		}
		switch c.Op {
		case "ack":
			l.ack(types.MessageID(c.ID))
		case "pair", "send", "read", "typing", "logout":
			select {
			case l.ops <- c:
			default:
				l.log.Errorf("The command queue is full, skipped a %s command", c.Op)
				if c.Op == "send" {
					l.emitSent(c.ID, fmt.Errorf("%w: wa-link is busy", errInvalid))
				}
			}
		default:
			l.log.Warnf("Skipped a command with an unknown op (%d bytes)", len(c.Op))
		}
	}
}

var errLineTooLong = errors.New("line too long")

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		part, isPrefix, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 && !tooLong {
				return line, nil
			}
			return nil, err
		}
		if !tooLong {
			line = append(line, part...)
			if len(line) > maxLine {
				tooLong, line = true, nil
			}
		}
		if !isPrefix {
			if tooLong {
				return nil, errLineTooLong
			}
			return line, nil
		}
	}
}

// jsonError describes a decoding error without the input.
func jsonError(err error) string {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return fmt.Sprintf("bad JSON at byte %d", syntax.Offset)
	case errors.As(err, &typ):
		return fmt.Sprintf("field %q has the wrong type", typ.Field)
	}
	return "bad JSON"
}

func (l *Link) worker() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case c := <-l.ops:
			l.do(c)
		}
	}
}

var (
	errInvalid = errors.New("invalid command")
	errNotSent = errors.New("not sent") // no message went to WhatsApp
)

func (l *Link) do(c command) {
	switch c.Op {
	case "start":
		if !l.cli.HasDevice() {
			l.emitState("logged_out", types.EmptyJID, "")
			return
		}
		l.emitState("connecting", l.cli.OwnJID(), "")
		if err := l.cli.Connect(); err != nil {
			l.emitState("error", l.cli.OwnJID(), "connect failed: "+err.Error())
		}
	case "pair":
		l.pair()
	case "send":
		l.emitSent(c.ID, l.send(c))
	case "read":
		if err := l.read(c); err != nil {
			l.log.Warnf("Read receipt failed: %v", err)
		}
	case "typing":
		if err := l.typing(c); err != nil {
			l.log.Warnf("Typing failed: %v", err)
		}
	case "logout":
		l.logout()
	}
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

// userJID parses the JID of a person. wa-link never writes to a group, a
// broadcast or a channel.
func userJID(s string) (types.JID, error) {
	jid, err := types.ParseJID(s)
	if err != nil || jid.User == "" || jid.Device != 0 ||
		(jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer) {
		return types.EmptyJID, fmt.Errorf("%w: %q is not the JID of a person", errInvalid, clip(s))
	}
	return jid, nil
}

func (l *Link) send(c command) error {
	if !validID(c.ID) {
		return fmt.Errorf("%w: bad id", errInvalid)
	}
	to, err := userJID(c.To)
	if err != nil {
		return err
	}
	if c.Text == "" || len(c.Text) > maxText {
		return fmt.Errorf("%w: text must have 1 to %d bytes", errInvalid, maxText)
	}
	msg := &waE2E.Message{Conversation: proto.String(c.Text)}
	if c.ReplyTo != nil && *c.ReplyTo != "" {
		if q, ok := l.quoted(types.MessageID(*c.ReplyTo), to); ok {
			msg = &waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text: proto.String(c.Text),
				ContextInfo: &waE2E.ContextInfo{
					StanzaID:      proto.String(*c.ReplyTo),
					Participant:   proto.String(q.jids[1].String()),
					QuotedMessage: q.msg,
				},
			}}
		} else {
			l.log.Infof("Message %s to quote is not known, sending %s without a quote", clip(*c.ReplyTo), c.ID)
		}
	}
	ctx, cancel := context.WithTimeout(l.ctx, 90*time.Second)
	defer cancel()
	return l.cli.Send(ctx, to, types.MessageID(c.ID), msg)
}

func (l *Link) read(c command) error {
	chat, err := userJID(c.Chat)
	if err != nil {
		return err
	}
	var sender types.JID
	if c.Sender != "" {
		if sender, err = userJID(c.Sender); err != nil {
			return err
		}
	}
	if len(c.IDs) == 0 || len(c.IDs) > 100 {
		return fmt.Errorf("%w: ids must have 1 to 100 items", errInvalid)
	}
	ids := make([]types.MessageID, len(c.IDs))
	for i, id := range c.IDs {
		if !validID(id) {
			return fmt.Errorf("%w: bad id", errInvalid)
		}
		ids[i] = types.MessageID(id)
	}
	ctx, cancel := context.WithTimeout(l.ctx, 20*time.Second)
	defer cancel()
	return l.cli.MarkRead(ctx, chat, sender, ids)
}

func (l *Link) typing(c command) error {
	chat, err := userJID(c.Chat)
	if err != nil {
		return err
	}
	if c.On == nil {
		return fmt.Errorf("%w: on is missing", errInvalid)
	}
	ctx, cancel := context.WithTimeout(l.ctx, 20*time.Second)
	defer cancel()
	return l.cli.Typing(ctx, chat, *c.On)
}

func (l *Link) pair() {
	if l.cli.HasDevice() {
		// The state again, and not "linked": the bridge sends while the state
		// is linked, so only a connection that is up may say it.
		l.log.Infof("Pair: this database already has a linked device")
		l.stateMu.Lock()
		defer l.stateMu.Unlock()
		l.emit(l.state)
		return
	}
	l.mu.Lock()
	if l.pairing {
		l.mu.Unlock()
		l.log.Infof("Pair: pairing already runs")
		return
	}
	l.pairing = true
	l.mu.Unlock()
	ch, err := l.cli.Pair(l.ctx)
	if err != nil {
		l.setPairing(false)
		l.emitState("error", types.EmptyJID, "pairing failed: "+err.Error())
		return
	}
	l.emitState("connecting", types.EmptyJID, "")
	go l.watchQR(ch)
}

func (l *Link) setPairing(on bool) {
	l.mu.Lock()
	l.pairing = on
	l.mu.Unlock()
}

func (l *Link) watchQR(ch <-chan whatsmeow.QRChannelItem) {
	defer l.setPairing(false)
	for item := range ch {
		switch item.Event {
		case whatsmeow.QRChannelEventCode:
			l.emit(qrEvent{Ev: "qr", Code: item.Code, Timeout: int(item.Timeout / time.Second)})
		case whatsmeow.QRChannelSuccess.Event:
			// events.PairSuccess and events.Connected report the state.
		case whatsmeow.QRChannelTimeout.Event:
			l.emitState("logged_out", types.EmptyJID, "the QR code was not scanned in time")
		case whatsmeow.QRChannelEventError:
			l.emitState("error", types.EmptyJID, fmt.Sprintf("pairing failed: %v", item.Error))
		default:
			l.emitState("error", types.EmptyJID, "pairing failed: "+item.Event)
		}
	}
}

func (l *Link) logout() {
	if !l.cli.HasDevice() {
		l.emitState("logged_out", types.EmptyJID, "")
		return
	}
	ctx, cancel := context.WithTimeout(l.ctx, 30*time.Second)
	defer cancel()
	if err := l.cli.Logout(ctx); err != nil {
		l.emitState("logged_out", types.EmptyJID, err.Error())
		return
	}
	l.emitState("logged_out", types.EmptyJID, "")
}

// HandleEvent receives every whatsmeow event. whatsmeow sends the
// delivery acknowledgement of a message only after this returns true
// (Client.SynchronousAck), and none when it returns false.
func (l *Link) HandleEvent(evt any) bool {
	switch e := evt.(type) {
	case *events.Message:
		return l.onMessage(e)
	case *events.Receipt:
		l.onReceipt(e)
	case *events.Connected:
		l.emitState("linked", l.cli.OwnJID(), "")
	case *events.Disconnected:
		if l.cli.HasDevice() {
			l.emitState("connecting", l.cli.OwnJID(), "")
		}
	case *events.PairSuccess:
		l.emitState("connecting", e.ID, "")
	case *events.LoggedOut:
		l.emitState("logged_out", types.EmptyJID, "logged out: "+e.Reason.String())
	case *events.StreamReplaced:
		l.emitState("error", l.cli.OwnJID(), "another client replaced this session")
	case *events.TemporaryBan:
		l.emitState("error", l.cli.OwnJID(), "temporary ban: "+e.String())
	case *events.ClientOutdated:
		l.emitState("error", l.cli.OwnJID(), "WhatsApp says that this client is outdated: update whatsmeow")
	case *events.ConnectFailure:
		l.emitState("error", l.cli.OwnJID(), fmt.Sprintf("connect failure %d %s", int(e.Reason), e.Message))
	case *events.PairError:
		l.emitState("error", types.EmptyJID, fmt.Sprintf("pairing failed: %v", e.Error))
	}
	return true
}

func (l *Link) onMessage(e *events.Message) bool {
	if l.ctx.Err() != nil {
		return false
	}
	ev, ok := convertMessage(e)
	if !ok {
		return true
	}
	if !ev.Group && !ev.FromMe {
		l.remember(e)
	}
	id := e.Info.ID
	wait := l.expect(id)
	defer l.forget(id, wait)
	if l.emit(ev) != nil {
		return false
	}
	timer := time.NewTimer(l.ackWait)
	defer timer.Stop()
	select {
	case <-wait:
		return true
	case <-timer.C:
		// The bridge did not journal it. WhatsApp keeps a message that is not
		// confirmed and delivers it again after the next connection.
		l.log.Warnf("No ack for message %s in %s, so it is not confirmed; WhatsApp delivers it again after the next connection", id, l.ackWait)
		return false
	case <-l.ctx.Done():
		l.log.Infof("Stopping before the ack of message %s; WhatsApp delivers it again", id)
		return false
	}
}

// convertMessage gives the event for a message, or false for a message
// that wa-link ignores.
func convertMessage(e *events.Message) (messageEvent, bool) {
	info := e.Info
	switch {
	case info.Chat.Server == types.BroadcastServer, // status updates and broadcast lists
		info.Chat.Server == types.NewsletterServer,
		info.Chat.Server == types.BotServer,
		info.Sender.Server == types.BotServer,
		e.IsEdit, info.Edit != types.EditAttributeEmpty:
		return messageEvent{}, false
	}
	kind, text, ok := classify(e.Message)
	if !ok {
		return messageEvent{}, false
	}
	ev := messageEvent{
		Ev:       "message",
		ID:       info.ID,
		Chat:     info.Chat.ToNonAD().String(),
		Sender:   info.Sender.ToNonAD().String(),
		PushName: info.PushName,
		Group:    info.IsGroup,
		FromMe:   info.IsFromMe,
		Kind:     kind,
		Text:     text,
		TS:       float64(info.Timestamp.UnixMilli()) / 1000,
	}
	if !info.SenderAlt.IsEmpty() {
		s := info.SenderAlt.ToNonAD().String()
		ev.SenderAlt = &s
	}
	return ev, true
}

// classify gives the kind and text of a message that a person sees in the
// chat, or false for reactions, protocol messages and others.
func classify(m *waE2E.Message) (kind, text string, ok bool) {
	switch {
	case m == nil:
		return "", "", false
	case m.GetConversation() != "":
		return "text", m.GetConversation(), true
	case m.ExtendedTextMessage != nil:
		return "text", m.GetExtendedTextMessage().GetText(), true
	case m.ImageMessage != nil:
		return "image", m.GetImageMessage().GetCaption(), true
	case m.AudioMessage != nil:
		return "audio", "", true
	case m.DocumentMessage != nil:
		return "file", m.GetDocumentMessage().GetCaption(), true
	case m.VideoMessage != nil:
		return "other", m.GetVideoMessage().GetCaption(), true
	case m.PtvMessage != nil, m.StickerMessage != nil, m.LocationMessage != nil,
		m.LiveLocationMessage != nil, m.ContactMessage != nil, m.ContactsArrayMessage != nil,
		m.PollCreationMessage != nil, m.PollCreationMessageV2 != nil, m.PollCreationMessageV3 != nil,
		m.EventMessage != nil:
		return "other", "", true
	}
	return "", "", false
}

func (l *Link) onReceipt(e *events.Receipt) {
	if e.IsGroup || e.Chat.Server == types.BroadcastServer || len(e.MessageIDs) == 0 {
		return
	}
	var typ string
	switch e.Type {
	case types.ReceiptTypeDelivered:
		typ = "delivered"
	case types.ReceiptTypeRead:
		typ = "read"
	default:
		return
	}
	ids := make([]string, len(e.MessageIDs))
	for i, id := range e.MessageIDs {
		ids[i] = string(id)
	}
	l.emit(receiptEvent{Ev: "receipt", IDs: ids, Type: typ})
}

func (l *Link) expect(id types.MessageID) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	ch, ok := l.pending[id]
	if !ok {
		ch = make(chan struct{})
		l.pending[id] = ch
	}
	return ch
}

func (l *Link) forget(id types.MessageID, ch chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending[id] == ch {
		delete(l.pending, id)
	}
}

func (l *Link) ack(id types.MessageID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ch, ok := l.pending[id]; ok {
		close(ch)
		delete(l.pending, id)
	}
}

func (l *Link) remember(e *events.Message) {
	msg := proto.Clone(e.Message).(*waE2E.Message)
	msg.MessageContextInfo = nil
	r := recent{jids: []types.JID{e.Info.Chat.ToNonAD(), e.Info.Sender.ToNonAD()}, msg: msg}
	if !e.Info.SenderAlt.IsEmpty() {
		r.jids = append(r.jids, e.Info.SenderAlt.ToNonAD())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.recent[e.Info.ID]; !ok {
		l.order = append(l.order, e.Info.ID)
	}
	l.recent[e.Info.ID] = r
	for len(l.order) > recentLimit {
		delete(l.recent, l.order[0])
		l.order = l.order[1:]
	}
}

// quoted gives a known inbound message of the chat with to.
func (l *Link) quoted(id types.MessageID, to types.JID) (recent, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.recent[id]
	if !ok {
		return recent{}, false
	}
	for _, j := range r.jids {
		if j == to {
			return r, true
		}
	}
	return recent{}, false
}
