"""The gate of the remote MCP address (connected apps): the one program that faces the Internet.

Tailscale Funnel ends TLS on the hub's machine and sends each request of https://<name>/ to this program on
127.0.0.1:8767. The gate forwards only the routes of the hub's OAuth server and MCP endpoint, with only a short list of
headers, over HTTP on the hub's Unix socket. Everything else gets an answer of the gate's own and reaches nothing.

What it is not allowed to have, so that a fault in it gives away nothing:

- no state: no database, no file of the hub, no key, no token logic, nothing kept from one request to the next (it
  counts the open requests of each address, and the count of a request ends with it);
- no TCP client connection: it listens on 127.0.0.1 and connects only to the hub's Unix socket (test_connect_gate.py
  reads this file's syntax tree for that), and its systemd unit allows no other address;
- no other module than the standard library.

It runs as the system user founderizer-connect, from a root-owned copy in /usr/local/lib/founderizer-connect/ that
`hubsetup.py connect on` installs, so a hub release cannot change the code that faces the Internet.

The limits: a request line of 4 KiB (414), headers of 16 KiB (431), a body of 64 KiB on /mcp and 8 KiB elsewhere (413),
128 connections at a time and 8 open requests from one address or IPv6 /64 (503), 2 seconds to read the request line
and the headers, and a body that has 2 seconds and then as much more time as its bytes take at 8 KiB a second, up to
its own size's (408). One request on each connection: the answer closes it. A slow, cut or malformed request ends only
its own connection. Funnel sends the gate a request's whole head at once, so a request whose body never comes ends
after 2 seconds, and one address holds at most 8 places while its bodies come. A 503 says Retry-After, and the log
says when all places are full.

What the limits do not do: 16 addresses (or 16 IPv6 /64s, which one person with a /48 of their own has) that each
open about 4 requests a second with no body still keep all 128 places full, and the gate cannot tell the owner's own
calls from theirs, because it holds no token logic, by design. A process on the hub's machine can connect to
127.0.0.1:8767 itself and write any X-Forwarded-For. A process of another user there can listen on that port while the
gate is stopped and so keep it from its bind, but it completes no handshake (ports.py drops its SYN-ACK), so it reads
nothing; the gate's unit ends it before each start (ports.py's holder). A form that a phone sends at a sign-in (POST /authorize) has 2
seconds of slack beside its bytes, where the gate gave 10 seconds before.

    python3 -I gate.py --name hub-1.tail0000.ts.net [--port 8767] [--socket /var/lib/founderizer-connect/hub.sock]
"""

import argparse
import ipaddress
import re
import socket
import sys
import threading
import time

VERSION = "1"                   # X-Gate-Version: the hub compares it with its GATE_VERSION
LISTEN = "127.0.0.1"
PORT = 8767                     # 8765 is the hub, 8766 the door
SOCKET = "/var/lib/founderizer-connect/hub.sock"
LINE_MAX = 4096                 # bytes of the request line, and of any one header line
HEAD_MAX = 16384                # bytes of all the header lines together
BODY_MAX = 8192                 # bytes of a body, except on /mcp
MCP_BODY_MAX = 65536            # bytes of a body on /mcp
CONNECTIONS = 128               # connections at a time; one more gets 503. A connection that waits for its client holds
#                                 only a thread, and the hub gets whole requests only
HEAD_TIME = 2                   # seconds to read the request line and the headers
BODY_TIME = 2                   # seconds that a body may wait before its bytes and between them
BODY_RATE = 8192                # each byte of a body that came gives it 1/BODY_RATE seconds more, up to its size's
PER_SOURCE = 8                  # open requests from one address or IPv6 /64 (X-Forwarded-For's last); one more: 503. Every
#                                 request of an owner's AI client comes from its provider's few addresses, some of them
#                                 side by side, so one address has room for more than one call at a time
RETRY_AFTER = 2                 # seconds, in a 503: the time of a body that never comes
FULL_EVERY = 60                 # seconds between two log lines that say that all places are full
TRAILERS_MAX = HEAD_MAX         # bytes of a chunked body's trailers, which the gate drops (431 over it)
HUB_TIME = 60                   # seconds of silence from the hub, or from a client that reads the answer, before the
#                                 gate gives up on that connection
# The only routes that reach the hub, and their methods. A path is compared exactly: no trailing slash, no case, no
# percent sign.
ROUTES = {
    "/.well-known/oauth-protected-resource": ("GET",),
    "/.well-known/oauth-protected-resource/mcp": ("GET",),
    "/.well-known/oauth-authorization-server": ("GET",),
    "/authorize": ("GET", "POST"),
    "/token": ("POST",),
    "/register": ("POST",),
    "/revoke": ("POST",),
    "/mcp": ("GET", "POST", "DELETE"),
}
# The only headers that reach the hub, by their lowercase name, as they are written to the hub. Content-Length is the
# gate's own, from the body that it read. Every other header of a request is dropped.
KEPT = {"host": "Host", "authorization": "Authorization", "content-type": "Content-Type", "accept": "Accept",
        "origin": "Origin", "mcp-protocol-version": "MCP-Protocol-Version", "mcp-session-id": "Mcp-Session-Id"}
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")      # a header name (RFC 9110 5.6.2)
REQUEST_LINE = re.compile(r"([A-Z]{1,16}) (/[\x21-\x7e]*) HTTP/1\.([01])")
VALUE = re.compile(r"[\x20-\x7e\t]*")                  # a kept header's value: visible ASCII, space and tab
REASONS = {400: "Bad Request", 404: "Not Found", 408: "Request Timeout", 411: "Length Required",
           413: "Content Too Large", 414: "URI Too Long", 421: "Misdirected Request",
           431: "Request Header Fields Too Large", 501: "Not Implemented", 502: "Bad Gateway",
           503: "Service Unavailable"}


class Answer(Exception):
    """A request that the gate answers itself, with no forward."""
    def __init__(self, status, text):
        super().__init__(text)
        self.status, self.text = status, text


def plain(status, text):
    """The bytes of one of the gate's own answers. A 503 says when to try again."""
    body = (text + "\n").encode("ascii", "replace")
    later = f"Retry-After: {RETRY_AFTER}\r\n" if status == 503 else ""
    return (f"HTTP/1.1 {status} {REASONS.get(status, 'Error')}\r\nContent-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\n{later}Connection: close\r\n\r\n").encode() + body


class Reader:
    """The bytes of one connection, read against one deadline. Every wait is a socket timeout of what is left. After
    `budget`, each chunk that comes moves the deadline on by its own time at the rate, up to the cap."""
    def __init__(self, conn, deadline):
        self.conn, self.deadline, self.data = conn, deadline, bytearray()
        self.rate, self.cap = None, None

    def budget(self, start, size, rate):
        """The body's deadline: `start` seconds from now, and each byte that is here or comes 1/rate seconds more, up to
        the time of `size` bytes. So a body that stalls ends after `start`, and a whole one never takes longer than
        start + size/rate."""
        now = time.monotonic()
        self.rate, self.cap = rate, now + start + size / rate
        self.deadline = min(self.cap, now + start + len(self.data) / rate)

    def more(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Answer(408, "the request took too long")
        self.conn.settimeout(left)
        try:
            chunk = self.conn.recv(65536)
        except socket.timeout:
            raise Answer(408, "the request took too long") from None
        if not chunk:
            raise ConnectionResetError("the client went away")
        self.data += chunk
        if self.rate:
            self.deadline = min(self.cap, self.deadline + len(chunk) / self.rate)

    def take(self, size):
        while len(self.data) < size:
            self.more()
        out = bytes(self.data[:size])
        del self.data[:size]
        return out

    def line(self, limit, status):
        """One line without its CRLF, at most limit bytes."""
        while True:
            end = self.data.find(b"\r\n")
            bare = self.data.find(b"\n")
            if 0 <= bare and (bare == 0 or self.data[bare - 1] != 13):
                raise Answer(400, "a line of the request ends with a bare LF")
            if 0 <= end:
                if end > limit:
                    raise Answer(status, "a line of the request is too long")
                out = bytes(self.data[:end])
                del self.data[:end + 2]
                return out
            if len(self.data) > limit + 1:
                raise Answer(status, "a line of the request is too long")
            self.more()


def read_head(reader):
    """(method, target, [(lowercase name, value)]) of one request. Answer for a request line over 4 KiB (414), header
    lines over 4 KiB each or 16 KiB together (431), and a malformed request (400): a bare CR or LF, a control
    character, a header line that folds, a space before a colon, a name that is not a token."""
    line = reader.line(LINE_MAX, 414)
    m = REQUEST_LINE.fullmatch(line.decode("latin-1"))
    if not m:
        raise Answer(400, "the request line is malformed")
    method, target = m.group(1), m.group(2)
    headers, total = [], 0
    while True:
        one = reader.line(LINE_MAX, 431)
        if not one:
            return method, target, headers
        total += len(one) + 2
        if total > HEAD_MAX:
            raise Answer(431, "the request's headers are too large")
        text = one.decode("latin-1")
        if "\r" in text or "\n" in text or "\x00" in text:
            raise Answer(400, "a header holds a line break or a NUL")
        name, colon, value = text.partition(":")
        if not colon or not TOKEN.fullmatch(name):
            raise Answer(400, "a header line is malformed")
        headers.append((name.lower(), value.strip(" \t")))


def one_value(headers, name):
    """The value of a header that may come once, or None. Answer 400 when it comes two times."""
    found = [v for k, v in headers if k == name]
    if len(found) > 1:
        raise Answer(400, f"the header {KEPT.get(name, name)} is there two times")
    return found[0] if found else None


def source(headers):
    """The last address of X-Forwarded-For, for the hub's logs and the count of each address, or None when it is not
    one address. Tailscale Funnel's proxy (tailscaled's ReverseProxy Rewrite) deletes the client's own header and sets
    the connection's source, so a client from the Internet never chooses it; the last address is taken all the same."""
    found = [v for k, v in headers if k == "x-forwarded-for"]
    if not found:
        return None
    last = found[-1].split(",")[-1].strip()
    try:
        return str(ipaddress.ip_address(last))
    except ValueError:
        return None


def read_body(reader, headers, limit):
    """The body of a request, at most limit bytes: by Content-Length, or chunked (RFC 9112 7.1; its trailers are
    dropped). Answer 400 for both at once or a broken framing, 501 for another transfer coding, 413 over the limit."""
    length, coding = one_value(headers, "content-length"), one_value(headers, "transfer-encoding")
    if coding is not None:
        if length is not None:
            raise Answer(400, "a request has Content-Length or Transfer-Encoding, not both")
        if coding.lower() != "chunked":
            raise Answer(501, "the only transfer coding is chunked")
        body = bytearray()
        while True:
            size_line = reader.line(64, 400).split(b";", 1)[0].strip()
            if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size_line):
                raise Answer(400, "a chunk of the body is malformed")
            size = int(size_line, 16)
            if size == 0:
                total = 0
                while True:                         # the trailers, which are dropped, and no more of them than headers
                    trailer = reader.line(LINE_MAX, 431)
                    if not trailer:
                        return bytes(body)
                    total += len(trailer) + 2
                    if total > TRAILERS_MAX:
                        raise Answer(431, "the body's trailers are too large")
            if len(body) + size > limit:
                raise Answer(413, f"the body is larger than {limit} bytes")
            body += reader.take(size)
            if reader.take(2) != b"\r\n":
                raise Answer(400, "a chunk of the body is malformed")
    if length is None:
        return b""
    if not re.fullmatch(r"[0-9]{1,10}", length):
        raise Answer(400, "Content-Length is malformed")
    if int(length) > limit:
        raise Answer(413, f"the body is larger than {limit} bytes")
    return reader.take(int(length))


def source_key(came_from):
    """What the count of open requests is by: an IPv4 address, or the /64 of an IPv6 one, which one host holds whole."""
    if came_from is None:
        return "-"
    address = ipaddress.ip_address(came_from)
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return came_from


def body_size(headers, limit):
    """The bytes that a body's deadline allows for: its Content-Length when that is one number within the limit, else
    the limit (a chunked body, or a length that read_body refuses)."""
    found = [v for k, v in headers if k == "content-length"]
    if len(found) == 1 and re.fullmatch(r"[0-9]{1,10}", found[0]) and int(found[0]) <= limit:
        return int(found[0])
    return limit


def hub_connection(path, timeout):
    """A connection to the hub's Unix socket: the one connection that the gate opens."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(path)
    except BaseException:
        s.close()
        raise
    return s


def forwarded(method, target, headers, body, came_from):
    """The bytes that go to the hub: the request line, the kept headers, the gate's own two, and the body."""
    lines = [f"{method} {target} HTTP/1.1"]
    for name in KEPT:
        value = one_value(headers, name) if name != "accept" else \
            (", ".join(v for k, v in headers if k == "accept") or None)
        if value is None:
            continue
        if not VALUE.fullmatch(value):
            raise Answer(400, f"the header {KEPT[name]} holds a byte that is not ASCII")
        lines.append(f"{KEPT[name]}: {value}")
    lines.append(f"X-Gate-Version: {VERSION}")
    if came_from:
        lines.append(f"X-Gate-Source: {came_from}")
    lines += [f"Content-Length: {len(body)}", "Connection: close", "", ""]
    return "\r\n".join(lines).encode("ascii") + body


class Gate:
    """The listener and its connections. Gate(name).serve_forever() runs it; close() stops it. port 0 takes a free
    port, which .port then holds (for a test)."""

    def __init__(self, name, socket_path=SOCKET, port=PORT, connections=CONNECTIONS, head_time=HEAD_TIME,
                 body_time=BODY_TIME, body_rate=BODY_RATE, per_source=PER_SOURCE, hub_time=HUB_TIME, log=None):
        if not isinstance(name, str) or len(name) > 253 or not NAME.fullmatch(name):
            raise ValueError("--name must be the hub's full lowercase DNS name")
        self.name, self.socket_path = name, socket_path
        self.head_time, self.body_time, self.body_rate, self.hub_time = head_time, body_time, body_rate, hub_time
        self.slots = threading.BoundedSemaphore(connections)
        self.per_source, self.sources, self.counting = per_source, {}, threading.Lock()
        self.full_said = -FULL_EVERY
        self.log = log if log is not None else (lambda line: print("gate: " + line, file=sys.stderr, flush=True))
        self.stopped = False
        self.sock = listening_socket(port)
        self.port = self.sock.getsockname()[1]

    def close(self):
        self.stopped = True
        try:
            self.sock.close()
        except OSError:
            pass

    def serve_forever(self):
        while not self.stopped:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                if self.stopped:
                    return
                time.sleep(0.05)            # out of files for a moment: never a loop that spins
                continue
            if not self.slots.acquire(blocking=False):
                self.busy(conn, "all places are full")
                continue
            try:
                threading.Thread(target=self.one, args=(conn,), daemon=True).start()
            except RuntimeError:
                self.slots.release()
                self.busy(conn, "a thread could not start")

    def busy(self, conn, why):
        """503 to one connection over the limit, without a wait: the accept loop never blocks on a client. The log says
        why once a minute at most, while it lasts."""
        now = time.monotonic()
        if now >= self.full_said + FULL_EVERY:
            self.full_said = now
            self.log(f"{why}: a connection got 503")
        try:
            conn.setblocking(False)
            conn.send(plain(503, "the gate is busy; try again"))
        except OSError:
            pass
        finally:
            conn.close()

    def take_source(self, came_from):
        """One more open request of this address, or 503 when it has as many as one address may."""
        key = source_key(came_from)
        with self.counting:
            if self.sources.get(key, 0) >= self.per_source:
                raise Answer(503, "this address has as many requests open as the gate takes from one; try again")
            self.sources[key] = self.sources.get(key, 0) + 1
        return key

    def give_source(self, key):
        with self.counting:
            left = self.sources[key] - 1
            if left:
                self.sources[key] = left
            else:
                del self.sources[key]

    def one(self, conn):
        status, method, path, held = 0, "-", "-", None
        try:
            try:
                reader = Reader(conn, time.monotonic() + self.head_time)
                method, target, headers = read_head(reader)
                path = target.split("?", 1)[0]
                came_from = source(headers)
                held = self.take_source(came_from)  # counted as soon as its head says where it is from
                hosts = [v for k, v in headers if k == "host"]
                if len(hosts) != 1:
                    raise Answer(400, "a request has one Host header")
                if hosts[0].lower() not in (self.name, self.name + ":443"):
                    raise Answer(421, "this address serves another name")
                if method not in ROUTES.get(path, ()):
                    raise Answer(404, "not found")
                limit = MCP_BODY_MAX if path == "/mcp" else BODY_MAX
                reader.budget(self.body_time, body_size(headers, limit), self.body_rate)
                body = read_body(reader, headers, limit)
                request = forwarded(method, target, headers, body, came_from)
            except Answer as e:
                status = e.status
                if held is not None:                # the count ends with the request, before the linger
                    self.give_source(held)
                    held = None
                conn.settimeout(5)
                conn.sendall(plain(e.status, e.text))
                linger(conn)
                return
            status = self.forward(conn, request)
        except (OSError, ValueError):
            pass                                # the client went away, or stopped reading: only this connection ends
        except Exception as e:                  # never a fault that ends the gate
            self.log(f"fault {type(e).__name__} on {method} {path}")
        finally:
            self.slots.release()
            if held is not None:
                self.give_source(held)
            try:
                conn.close()
            except OSError:
                pass
            if status:
                self.log(f"{status} {method} {path[:200]}")     # a path's first 200 characters

    def forward(self, conn, request):
        """The request to the hub, and the hub's answer back, byte for byte, until the hub closes. 502 when the hub's
        socket does not answer. Returns the status of the answer, for the log line."""
        try:
            hub = hub_connection(self.socket_path, self.hub_time)
        except OSError:
            conn.settimeout(5)
            conn.sendall(plain(502, "the hub does not answer"))
            return 502
        status = 0
        try:
            hub.sendall(request)
            conn.settimeout(self.hub_time)
            while True:
                chunk = hub.recv(65536)
                if not chunk:
                    return status
                if not status:
                    m = re.match(rb"HTTP/1\.[01] ([0-9]{3})", chunk)
                    status = int(m.group(1)) if m else 0
                conn.sendall(chunk)
        finally:
            hub.close()


def linger(conn, seconds=1, limit=MCP_BODY_MAX):
    """After one of the gate's own answers: the sending side closed, then what the client still sends read and
    dropped for a moment, so that the close does not reset the connection before the client reads the answer."""
    try:
        conn.shutdown(socket.SHUT_WR)
        end, read = time.monotonic() + seconds, 0
        while read < limit:
            left = end - time.monotonic()
            if left <= 0:
                return
            conn.settimeout(left)
            chunk = conn.recv(65536)
            if not chunk:
                return
            read += len(chunk)
    except OSError:
        pass


def listening_socket(port):
    """The gate's one TCP socket: a listener on 127.0.0.1, which never connects anywhere."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN, port))
        s.listen(128)
    except BaseException:
        s.close()
        raise
    return s


def main(argv=None):
    ap = argparse.ArgumentParser(description="The gate of the hub's remote MCP address")
    ap.add_argument("--name", required=True, help="the hub's full DNS name, for example hub-1.tail0000.ts.net")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--socket", default=SOCKET, help="the hub's Unix socket")
    args = ap.parse_args(argv)
    try:
        gate = Gate(args.name.lower(), socket_path=args.socket, port=args.port)
    except (ValueError, OSError) as e:
        print("gate: " + str(e), file=sys.stderr)
        return 1
    print(f"gate: version {VERSION} on {LISTEN}:{gate.port} for {gate.name}", file=sys.stderr, flush=True)
    gate.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
