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
	"os"
	"path/filepath"
	"regexp"
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

	// A file of a send (CHAT-APPS.md 20): at most maxFile bytes, the hub's own limit. A PNG or a JPEG of at most
	// maxImage bytes goes as a picture, every other file as a document with its name. The upload and the send of
	// one file end within fileTimeout, under the bridge's wait for the "sent" event.
	maxFile     = 25 << 20
	maxImage    = 16 << 20
	maxFileName = 200
	fileTimeout = 110 * time.Second

	// A download of a message's media (CHAT-APPS.md 8.1), on the bridge's command after the hub took its sender: at
	// most maxDownloads at a time, each in downloadTime unless the command gives its own time (at most
	// downloadLongest). The encrypted file is the plain one, its AES-CBC padding (1 to 16 bytes) and its 10-byte MAC,
	// so no write of a download may pass maxEncrypted; the plain file has at most maxFile bytes.
	maxDownloads    = 2
	maxEncrypted    = maxFile + 16 + 10
	maxDirectPath   = 2048
	downloadTime    = 60 * time.Second
	downloadLongest = 120 * time.Second
)

// The types that a send can carry: the hub's own list (hub.py CHAT_FILE_TYPES).
var fileTypes = map[string]bool{
	"application/pdf": true, "image/png": true, "image/jpeg": true, "text/csv": true, "text/plain": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
}

// Client is the part of whatsmeow that wa-link uses.
type Client interface {
	HasDevice() bool
	OwnJID() types.JID // non-AD, empty when not linked
	Connect() error
	Pair(ctx context.Context) (<-chan whatsmeow.QRChannelItem, error)
	Send(ctx context.Context, to types.JID, id types.MessageID, msg *waE2E.Message) error
	Upload(ctx context.Context, data []byte, kind whatsmeow.MediaType) (whatsmeow.UploadResponse, error)
	Download(ctx context.Context, msg whatsmeow.DownloadableMessage, file whatsmeow.File) error
	MarkRead(ctx context.Context, chat, sender types.JID, ids []types.MessageID) error
	Typing(ctx context.Context, chat types.JID, on bool) error
	Logout(ctx context.Context) error
	Disconnect()
}

type command struct {
	Op      string     `json:"op"`
	ID      string     `json:"id"`
	To      string     `json:"to"`
	Text    string     `json:"text"`
	ReplyTo *string    `json:"reply_to"`
	Chat    string     `json:"chat"`
	Sender  string     `json:"sender"`
	IDs     []string   `json:"ids"`
	On      *bool      `json:"on"`
	File    *fileSpec  `json:"file"`
	Media   *mediaSpec `json:"media"`
	Seconds float64    `json:"seconds"`
}

// mediaSpec is the media of an inbound message as its event describes it, and as a download command gives it back:
// what whatsmeow needs to fetch it later, never its bytes. The keys and hashes stay on the hub machine: the bridge
// keeps them in its journal and sends none of them to the hub.
type mediaSpec struct {
	Kind          string `json:"kind"` // image, audio, voice (a voice note), video, document or sticker
	Mime          string `json:"mime"`
	Size          uint64 `json:"size"` // as the message says: WhatsApp's FileLength
	Name          string `json:"name"` // a document's own name, else empty
	DirectPath    string `json:"direct_path"`
	MediaKey      []byte `json:"media_key"`
	FileSHA256    []byte `json:"file_sha256"`
	FileEncSHA256 []byte `json:"file_enc_sha256"`
}

// fileSpec is the file of a send: a file that the bridge wrote into the outbox folder beside the database, and the
// name and type that the person sees. Its bytes never travel in a line.
type fileSpec struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Mime string `json:"mime"`
}

type stateEvent struct {
	Ev    string  `json:"ev"`
	State string  `json:"state"`
	JID   *string `json:"jid"`
	Error *string `json:"error"`
}

// helloEvent is the first line of a wa-link: what this build can do, so that a bridge never gives a file to a
// wa-link that would send its caption alone and report it sent (CHAT-APPS.md 20).
type helloEvent struct {
	Ev       string   `json:"ev"`
	Features []string `json:"features"`
}

// features is what a hello says: "file", a send can carry a file; "download", a message's media comes on the
// bridge's download command (a bridge reads a wa-link without it as one that cannot fetch a file).
var features = []string{"file", "download"}

type qrEvent struct {
	Ev      string `json:"ev"`
	Code    string `json:"code"`
	Timeout int    `json:"timeout"`
}

type messageEvent struct {
	Ev        string     `json:"ev"`
	ID        string     `json:"id"`
	Chat      string     `json:"chat"`
	Sender    string     `json:"sender"`
	SenderAlt *string    `json:"sender_alt"`
	PushName  string     `json:"push_name"`
	Group     bool       `json:"group"`
	FromMe    bool       `json:"from_me"`
	Kind      string     `json:"kind"`
	Text      string     `json:"text"`
	TS        float64    `json:"ts"`
	Media     *mediaSpec `json:"media,omitempty"` // a direct message's picture, voice note, sound, video, file or sticker
}

// downloadedEvent answers a download command: the file inbox/<id> has size bytes, or nothing is there and error says
// why in fixed words (never an address: a Go error of a request holds its URL). too_large: it has more than maxFile.
type downloadedEvent struct {
	Ev       string  `json:"ev"`
	ID       string  `json:"id"`
	OK       bool    `json:"ok"`
	Size     *int64  `json:"size"`
	TooLarge bool    `json:"too_large"`
	Error    *string `json:"error"`
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
	outbox  string           // the one folder that a send's file may be in: outbox beside the database
	inbox   string           // the one folder that a download writes into: inbox beside the database
	now     func() time.Time // the time of a file's media key

	ctx    context.Context // ends at shutdown
	cancel context.CancelFunc

	// The downloads that run, each in a goroutine of its own and never in the worker, so that a send never waits
	// behind one; slots holds at most maxDownloads at a time. closing (under mu) refuses a download once the stop began.
	downloads sync.WaitGroup
	slots     chan struct{}
	closing   bool

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
		now:     time.Now,
		ctx:     ctx,
		cancel:  cancel,
		out:     enc,
		pending: map[types.MessageID]chan struct{}{},
		recent:  map[types.MessageID]recent{},
		ops:     make(chan command, opsQueueSize),
		slots:   make(chan struct{}, maxDownloads),
	}
}

// Run connects when the database has a device, then reads commands until
// the input ends, the output fails or ctx ends. Then it disconnects.
// Messages that still wait for their ack are not confirmed to WhatsApp, so
// WhatsApp delivers them again after the next start.
func (l *Link) Run(ctx context.Context, in io.Reader) {
	l.emit(helloEvent{Ev: "hello", Features: features})
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
	l.mu.Lock()
	l.closing = true // no download starts after this, so the wait below ends
	l.mu.Unlock()
	done := make(chan struct{})
	go func() {
		<-workerDone
		l.downloads.Wait() // a download ends at once with the stop, and removes its file
		close(done)
	}()
	select {
	case <-done:
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

// clip gives an error text of an event: no address (a Go error of a request holds its URL, and an upload's URL holds
// the media connection's auth), at most maxError bytes.
func clip(s string) string {
	s = withoutAddresses(s)
	if len(s) <= maxError {
		return s
	}
	s = s[:maxError]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// webAddress is an address of the web as an error or a log line holds one: whatsmeow's media requests name the media's
// direct path and hash, and an upload's the media connection's auth too.
var webAddress = regexp.MustCompile(`(?i)\b(?:https?|wss?)://\S*`)

// withoutAddresses gives s with each web address replaced by <address>.
func withoutAddresses(s string) string {
	return webAddress.ReplaceAllString(s, "<address>")
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
		case "download":
			l.startDownload(c)
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
	if c.File != nil {
		return l.sendFile(c, to)
	}
	if c.Text == "" || len(c.Text) > maxText {
		return fmt.Errorf("%w: text must have 1 to %d bytes", errInvalid, maxText)
	}
	msg := &waE2E.Message{Conversation: proto.String(c.Text)}
	if quote := l.quoteInfo(c, to); quote != nil {
		msg = &waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: proto.String(c.Text), ContextInfo: quote}}
	}
	ctx, cancel := context.WithTimeout(l.ctx, 90*time.Second)
	defer cancel()
	return l.cli.Send(ctx, to, types.MessageID(c.ID), msg)
}

// quoteInfo quotes reply_to when it is a known inbound message of the chat with to, else nil.
func (l *Link) quoteInfo(c command, to types.JID) *waE2E.ContextInfo {
	if c.ReplyTo == nil || *c.ReplyTo == "" {
		return nil
	}
	q, ok := l.quoted(types.MessageID(*c.ReplyTo), to)
	if !ok {
		l.log.Infof("Message %s to quote is not known, sending %s without a quote", clip(*c.ReplyTo), c.ID)
		return nil
	}
	return &waE2E.ContextInfo{
		StanzaID:      proto.String(*c.ReplyTo),
		Participant:   proto.String(q.jids[1].String()),
		QuotedMessage: q.msg,
	}
}

// sendFile uploads the file of a send to WhatsApp's media servers and sends it as a picture or a document, with the
// text as its caption (which can be empty). An upload that fails sent nothing, so its error is "not sent"; the send
// after it has the errors of a text.
func (l *Link) sendFile(c command, to types.JID) error {
	if len(c.Text) > maxText {
		return fmt.Errorf("%w: a caption has at most %d bytes", errInvalid, maxText)
	}
	f := c.File
	if !fileTypes[f.Mime] {
		return fmt.Errorf("%w: a file of the type %q cannot be sent", errInvalid, clip(f.Mime))
	}
	if !validFileName(f.Name) {
		return fmt.Errorf("%w: a file name has 1 to %d bytes, and no path or control character", errInvalid, maxFileName)
	}
	data, err := l.readFile(f.Path)
	if err != nil {
		return err
	}
	image := (f.Mime == "image/png" || f.Mime == "image/jpeg") && len(data) <= maxImage
	kind := whatsmeow.MediaDocument
	if image {
		kind = whatsmeow.MediaImage
	}
	ctx, cancel := context.WithTimeout(l.ctx, fileTimeout)
	defer cancel()
	l.log.Infof("Uploading the file of %s (%d bytes)", c.ID, len(data))
	up, err := l.cli.Upload(ctx, data, kind)
	if err != nil {
		return fmt.Errorf("%w: the upload of the file failed: %v", errNotSent, err)
	}
	return l.cli.Send(ctx, to, types.MessageID(c.ID), fileMessage(up, f, c.Text, l.quoteInfo(c, to), image, l.now()))
}

func validFileName(name string) bool {
	if name == "" || len(name) > maxFileName || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\") ||
		strings.HasPrefix(name, ".") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// readFile reads a send's file: a regular file, directly in the outbox folder, of 1 to maxFile bytes.
func (l *Link) readFile(path string) ([]byte, error) {
	if l.outbox == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != l.outbox {
		return nil, fmt.Errorf("%w: the file is not in the outbox folder of wa-link", errInvalid)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: the file cannot be read: %v", errNotSent, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: the file is not a regular file", errInvalid)
	}
	if st.Size() < 1 || st.Size() > maxFile {
		return nil, fmt.Errorf("%w: a file has 1 to %d bytes", errInvalid, maxFile)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: the file cannot be read: %v", errNotSent, err)
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxFile+1))
	if err != nil {
		return nil, fmt.Errorf("%w: the file cannot be read: %v", errNotSent, err)
	}
	if len(data) != int(st.Size()) {
		return nil, fmt.Errorf("%w: the file changed while it was read", errNotSent)
	}
	return data, nil
}

// fileMessage is the message of an uploaded file: a picture, or a document with its name.
func fileMessage(up whatsmeow.UploadResponse, f *fileSpec, caption string, quote *waE2E.ContextInfo, image bool, at time.Time) *waE2E.Message {
	var text *string
	if caption != "" {
		text = proto.String(caption)
	}
	if image {
		return &waE2E.Message{ImageMessage: &waE2E.ImageMessage{
			URL: proto.String(up.URL), DirectPath: proto.String(up.DirectPath), MediaKey: up.MediaKey,
			Mimetype: proto.String(f.Mime), FileEncSHA256: up.FileEncSHA256, FileSHA256: up.FileSHA256,
			FileLength: proto.Uint64(up.FileLength), MediaKeyTimestamp: proto.Int64(at.Unix()),
			Caption: text, ContextInfo: quote,
		}}
	}
	doc := &waE2E.DocumentMessage{
		URL: proto.String(up.URL), DirectPath: proto.String(up.DirectPath), MediaKey: up.MediaKey,
		Mimetype: proto.String(f.Mime), FileEncSHA256: up.FileEncSHA256, FileSHA256: up.FileSHA256,
		FileLength: proto.Uint64(up.FileLength), MediaKeyTimestamp: proto.Int64(at.Unix()),
		FileName: proto.String(f.Name), Title: proto.String(f.Name), Caption: text, ContextInfo: quote,
	}
	if text == nil {
		return &waE2E.Message{DocumentMessage: doc}
	}
	// A document with a caption goes in the form that WhatsApp's own apps send it in, which a phone shows with its
	// words; whatsmeow sends that form (send.go) and unwraps it on receipt (events.Message.UnwrapRaw).
	return &waE2E.Message{DocumentWithCaptionMessage: &waE2E.FutureProofMessage{Message: &waE2E.Message{DocumentMessage: doc}}}
}

var (
	errTooLarge = errors.New("too large")
	errStopped  = errors.New("wa-link stops")
)

// startDownload runs a download command (CHAT-APPS.md 8.1) in a goroutine of its own, never in the worker: a send
// never waits behind a download. Its answer is one downloaded event.
func (l *Link) startDownload(c command) {
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		l.emitDownloaded(c.ID, 0, errStopped)
		return
	}
	l.downloads.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.downloads.Done()
		size, err := l.download(c)
		l.emitDownloaded(c.ID, size, err)
	}()
}

func (l *Link) emitDownloaded(id string, size int64, err error) {
	ev := downloadedEvent{Ev: "downloaded", ID: id, OK: err == nil}
	if err == nil {
		ev.Size = &size
		l.log.Infof("Downloaded the media for %s (%d bytes)", clip(id), size)
	} else {
		words := clip(downloadError(err))
		ev.TooLarge, ev.Error = errors.Is(err, errTooLarge), &words
		l.log.Warnf("The download for %s failed: %s", clip(id), words)
	}
	l.emit(ev)
}

// downloadError gives an error of a download in fixed words: never the error's own text, which can hold the URL of a
// media request (its direct path and hash). The refusals of a command are wa-link's own words.
func downloadError(err error) string {
	switch {
	case errors.Is(err, errInvalid), errors.Is(err, errStopped):
		return err.Error()
	case errors.Is(err, errTooLarge):
		return fmt.Sprintf("too large: the file has more than %d bytes", maxFile)
	case errors.Is(err, context.DeadlineExceeded):
		return "the download did not end in its time"
	case errors.Is(err, context.Canceled):
		return errStopped.Error()
	case errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith404), errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith410):
		return "the media is no longer on WhatsApp's servers"
	case errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith403):
		return "WhatsApp's media servers refused the download"
	case errors.Is(err, whatsmeow.ErrInvalidMediaHMAC), errors.Is(err, whatsmeow.ErrInvalidMediaEncSHA256),
		errors.Is(err, whatsmeow.ErrInvalidMediaSHA256), errors.Is(err, whatsmeow.ErrTooShortFile):
		return "the downloaded file does not match its message"
	case errors.Is(err, whatsmeow.ErrNotConnected), errors.Is(err, whatsmeow.ErrNotLoggedIn):
		return "wa-link is not connected to WhatsApp"
	case errors.Is(err, os.ErrExist), errors.Is(err, os.ErrNotExist), errors.Is(err, os.ErrPermission):
		return "wa-link cannot write the file into its inbox folder"
	}
	return "the download failed"
}

// download fetches the media that a command describes into inbox/<id>, a new file of mode 600, and gives its size.
// On any failure nothing stays there. The bridge sends it only after the hub took the message's sender (CHAT-APPS.md
// 8.1), so wa-link never fetches a stranger's file by itself.
func (l *Link) download(c command) (int64, error) {
	if !validID(c.ID) {
		return 0, fmt.Errorf("%w: bad id", errInvalid)
	}
	m := c.Media
	if m == nil {
		return 0, fmt.Errorf("%w: media is missing", errInvalid)
	}
	msg, err := downloadable(m)
	if err != nil {
		return 0, err
	}
	if m.Size > maxFile {
		return 0, errTooLarge
	}
	if l.inbox == "" {
		return 0, fmt.Errorf("%w: wa-link has no inbox folder", errInvalid)
	}
	wait := downloadTime
	if c.Seconds > 0 {
		wait = min(max(time.Duration(c.Seconds*float64(time.Second)), time.Second), downloadLongest)
	}
	ctx, cancel := context.WithTimeout(l.ctx, wait)
	defer cancel()
	select { // at most maxDownloads at a time; a download that waits for a slot waits within its own time
	case l.slots <- struct{}{}:
		defer func() { <-l.slots }()
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	path := filepath.Join(l.inbox, c.ID)
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // never over a file, never through a link
	if err != nil {
		return 0, err
	}
	l.log.Infof("Downloading the media for %s (%d bytes)", c.ID, m.Size)
	size, err := fetchInto(ctx, cancel, l.cli, msg, fh)
	if cerr := fh.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return 0, err
	}
	return size, nil
}

// fetchInto downloads msg into fh through capFile, and gives the size of the plain file. A write past the limit ends
// the download's context (cancel): whatsmeow tries its next media host after any other error, and with the context
// ended that request ends at once.
func fetchInto(ctx context.Context, cancel context.CancelFunc, cli Client, msg whatsmeow.DownloadableMessage, fh *os.File) (int64, error) {
	file := &capFile{f: fh, most: maxEncrypted, cancel: cancel}
	err := cli.Download(ctx, msg, file)
	if file.over {
		return 0, errTooLarge
	}
	if err != nil {
		return 0, err
	}
	st, err := fh.Stat()
	if err != nil {
		return 0, err
	}
	if st.Size() > maxFile { // 1 to 15 bytes past it have the encrypted size of maxFile itself
		return 0, errTooLarge
	}
	return st.Size(), nil
}

// downloadable gives the message part that whatsmeow downloads, of the class of its kind, with the media's direct
// path, key and hashes, after the checks of a command: whatsmeow takes the media type from the class.
func downloadable(m *mediaSpec) (whatsmeow.DownloadableMessage, error) {
	if len(m.DirectPath) < 2 || len(m.DirectPath) > maxDirectPath || m.DirectPath[0] != '/' {
		return nil, fmt.Errorf("%w: a direct path starts with / and has at most %d bytes", errInvalid, maxDirectPath)
	}
	if !directPath.MatchString(m.DirectPath) {
		return nil, fmt.Errorf("%w: a direct path has the characters of an address only", errInvalid)
	}
	if len(m.MediaKey) != 32 || len(m.FileSHA256) != 32 || len(m.FileEncSHA256) != 32 {
		return nil, fmt.Errorf("%w: a media key and its two hashes have 32 bytes each", errInvalid)
	}
	path, key, plain, enc := proto.String(m.DirectPath), m.MediaKey, m.FileSHA256, m.FileEncSHA256
	switch m.Kind {
	case "image":
		return &waE2E.ImageMessage{DirectPath: path, MediaKey: key, FileSHA256: plain, FileEncSHA256: enc}, nil
	case "audio", "voice":
		return &waE2E.AudioMessage{DirectPath: path, MediaKey: key, FileSHA256: plain, FileEncSHA256: enc}, nil
	case "video":
		return &waE2E.VideoMessage{DirectPath: path, MediaKey: key, FileSHA256: plain, FileEncSHA256: enc}, nil
	case "document":
		return &waE2E.DocumentMessage{DirectPath: path, MediaKey: key, FileSHA256: plain, FileEncSHA256: enc}, nil
	case "sticker":
		return &waE2E.StickerMessage{DirectPath: path, MediaKey: key, FileSHA256: plain, FileEncSHA256: enc}, nil
	}
	return nil, fmt.Errorf("%w: a media kind is image, audio, voice, video, document or sticker", errInvalid)
}

// directPath is the form of a media's direct path: the characters that an address holds without quoting (RFC 3986),
// but no quote. whatsmeow puts it after a fixed host of its own.
var directPath = regexp.MustCompile(`^/[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]*$`)

// capFile is the file of a download, held to most bytes. whatsmeow writes the encrypted file into it, checks it and
// decrypts it in place (DownloadToFile); its own Download would read a whole answer into memory, whatever size the
// message gave. capFile is no *os.File, so whatsmeow does not reserve the answer's length on the disk, and it has no
// ReadFrom, so io.Copy writes through Write, which refuses a byte past most.
type capFile struct {
	f      *os.File
	most   int64
	cancel context.CancelFunc // ends the download at the first write past most
	over   bool               // a write went past most
}

func (c *capFile) refuse() error {
	c.over = true
	if c.cancel != nil {
		c.cancel()
	}
	return errTooLarge
}

func (c *capFile) Read(p []byte) (int, error)                { return c.f.Read(p) }
func (c *capFile) ReadAt(p []byte, off int64) (int, error)   { return c.f.ReadAt(p, off) }
func (c *capFile) Seek(off int64, whence int) (int64, error) { return c.f.Seek(off, whence) }
func (c *capFile) Stat() (os.FileInfo, error)                { return c.f.Stat() }

func (c *capFile) Write(p []byte) (int, error) {
	at, err := c.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	if at+int64(len(p)) > c.most {
		return 0, c.refuse()
	}
	return c.f.Write(p)
}

func (c *capFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > c.most {
		return 0, c.refuse()
	}
	return c.f.WriteAt(p, off)
}

func (c *capFile) Truncate(size int64) error {
	if size > c.most {
		return c.refuse()
	}
	return c.f.Truncate(size)
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
	// the hub takes no file of a group's message or of the number's own; and a picture, a video or a voice note that
	// its sender let be seen only once is never kept as a file (its words still come)
	if !ev.Group && !ev.FromMe && !viewOnce(e) {
		ev.Media = describeMedia(e.Message)
	}
	return ev, true
}

// viewOnce tells a message that its sender let be seen only once: whatsmeow unwraps its wrapper and says so, and an
// older form says it in the media itself.
func viewOnce(e *events.Message) bool {
	m := e.Message
	return e.IsViewOnce || m.GetImageMessage().GetViewOnce() || m.GetVideoMessage().GetViewOnce() ||
		m.GetPtvMessage().GetViewOnce() || m.GetAudioMessage().GetViewOnce()
}

// describeMedia gives what a download needs of a message's picture, voice note, sound, video (a round video note
// too), document or sticker, or nil for a message with none. It describes what the message says, also a part that is
// missing: the download then fails, and the agent reads that the file could not be fetched.
func describeMedia(m *waE2E.Message) *mediaSpec {
	spec := func(kind, mime string, size uint64, name string, d whatsmeow.DownloadableMessage) *mediaSpec {
		return &mediaSpec{Kind: kind, Mime: mime, Size: size, Name: name, DirectPath: d.GetDirectPath(),
			MediaKey: d.GetMediaKey(), FileSHA256: d.GetFileSHA256(), FileEncSHA256: d.GetFileEncSHA256()}
	}
	switch {
	case m == nil:
		return nil
	case m.ImageMessage != nil:
		i := m.GetImageMessage()
		return spec("image", i.GetMimetype(), i.GetFileLength(), "", i)
	case m.AudioMessage != nil:
		a, kind := m.GetAudioMessage(), "audio"
		if a.GetPTT() {
			kind = "voice"
		}
		return spec(kind, a.GetMimetype(), a.GetFileLength(), "", a)
	case m.DocumentMessage != nil:
		d := m.GetDocumentMessage()
		return spec("document", d.GetMimetype(), d.GetFileLength(), d.GetFileName(), d)
	case m.VideoMessage != nil:
		v := m.GetVideoMessage()
		return spec("video", v.GetMimetype(), v.GetFileLength(), "", v)
	case m.PtvMessage != nil:
		v := m.GetPtvMessage()
		return spec("video", v.GetMimetype(), v.GetFileLength(), "", v)
	case m.StickerMessage != nil:
		s := m.GetStickerMessage()
		return spec("sticker", s.GetMimetype(), s.GetFileLength(), "", s)
	}
	return nil
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
