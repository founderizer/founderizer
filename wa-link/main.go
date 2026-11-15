// wa-link holds one WhatsApp linked-device session for the Fleet bridge.
//
//	wa-link --db <path>
//
// Commands come as JSON lines on standard input, events go as JSON lines to
// standard output, and logs go to standard error without message text.
// CHAT-APPS.md section 15.12 is the protocol.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "", "path of the session database")
	flag.Parse()
	if *dbPath == "" || flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: wa-link --db <path>")
		os.Exit(2)
	}
	if err := run(*dbPath); err != nil {
		fmt.Fprintln(os.Stderr, "wa-link:", err)
		os.Exit(1)
	}
}

func run(dbPath string) error {
	syscall.Umask(0o077) // the database and its -wal and -shm files: mode 600
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := newLogger(os.Stderr, "wa-link")

	container, err := openStore(ctx, dbPath, log.Sub("DB"))
	if err != nil {
		return err
	}
	defer container.Close()
	store.DeviceProps.Os = proto.String("Fleet") // the name in Linked devices on the phone

	w, err := newWAClient(ctx, container, log.Sub("WhatsApp"))
	if err != nil {
		return err
	}
	link := NewLink(w, os.Stdout, log.Sub("Link"))
	// The bridge writes the file of a send here, beside the database, and a send takes a file from here only.
	if abs, err := filepath.Abs(dbPath); err == nil {
		link.outbox = filepath.Join(filepath.Dir(abs), "outbox")
	}
	w.handler = link.HandleEvent
	link.Run(ctx, os.Stdin)
	return nil
}

func openStore(ctx context.Context, path string, log waLog.Logger) (*sqlstore.Container, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("the database path must not hold ? or #")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	container, err := sqlstore.New(ctx, "sqlite", dsn, log)
	if err != nil {
		return nil, fmt.Errorf("opening the database: %w", err)
	}
	return container, nil
}

// logger writes INFO and higher to standard error. whatsmeow logs IDs and
// JIDs at these levels, never message text.
type logger struct {
	mu  *sync.Mutex
	w   io.Writer
	mod string
}

func newLogger(w io.Writer, mod string) waLog.Logger {
	return &logger{mu: &sync.Mutex{}, w: w, mod: mod}
}

func (l *logger) printf(level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s [%s] %s\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), level, l.mod, fmt.Sprintf(msg, args...))
}

func (l *logger) Errorf(msg string, args ...any) { l.printf("ERROR", msg, args...) }
func (l *logger) Warnf(msg string, args ...any)  { l.printf("WARN", msg, args...) }
func (l *logger) Infof(msg string, args ...any)  { l.printf("INFO", msg, args...) }
func (l *logger) Debugf(string, ...any)          {}
func (l *logger) Sub(mod string) waLog.Logger {
	return &logger{mu: l.mu, w: l.w, mod: l.mod + "/" + mod}
}
