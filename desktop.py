"""Task-scoped desktop frames. No recording, input control, or worker listener."""
import base64
import json
import os
from pathlib import Path
import selectors
import subprocess
import threading
import time
import urllib.parse

MAX_FRAME = 1024 * 1024
LEASE_SECONDS = 8
FRAME_SECONDS = 5
STATUSES = {"waiting", "live", "permission_required", "unavailable", "locked"}


class Frames:
    """The hub owns one replaceable frame per viewed task, in RAM only."""
    def __init__(self):
        self.rows = {}

    def prune(self, now):
        self.rows = {key: row for key, row in self.rows.items() if row["lease"] > now}

    def view(self, key, now):
        self.prune(now)
        row = self.rows.setdefault(key, {"lease": now, "status": "waiting", "image": None, "captured_at": None})
        row["lease"] = now + LEASE_SECONDS
        if row["captured_at"] is not None and now - row["captured_at"] > FRAME_SECONDS:
            row.update(status="waiting", image=None, captured_at=None)
        return {k: row[k] for k in ("status", "image", "captured_at")}

    def watching(self, key, now):
        self.prune(now)
        return key in self.rows

    def put(self, key, data, now):
        if not self.watching(key, now):
            return False
        if set(data) != {"status", "image", "captured_at"} or data["status"] not in STATUSES:
            raise ValueError("invalid desktop frame")
        image, captured = data["image"], data["captured_at"]
        if data["status"] == "live":
            if not isinstance(image, str) or len(image) > (MAX_FRAME * 4 // 3 + 4):
                raise ValueError("invalid image size")
            raw = base64.b64decode(image, validate=True)
            if len(raw) > MAX_FRAME or not raw.startswith(b"\xff\xd8\xff") or not raw.endswith(b"\xff\xd9"):
                raise ValueError("invalid JPEG")
            if isinstance(captured, bool) or not isinstance(captured, (float, int)) or not now - FRAME_SECONDS <= captured <= now + 2:
                raise ValueError("stale frame")
            previous = self.rows[key]["captured_at"]
            if previous is not None and captured < previous:
                raise ValueError("out of order frame")
        elif image is not None or captured is not None:
            raise ValueError("status must not contain an image")
        self.rows[key].update(data)
        return True

    def drop(self, key):
        self.rows.pop(key, None)


class Publisher:
    """Capture only while an owner view renews its lease and this attempt is active."""
    def __init__(self, agent, task, context, http, command=None):
        self.path = f"/helper/desktop/{agent}/{task}"
        self.context, self.http = context, http
        self.command = command or str(Path.home() / ".fleet/Fleet Worker.app/Contents/MacOS/FleetWorker")
        self.stop = threading.Event()
        self.thread = None
        self.process = None
        self.reader = None
        self.buffer = b""
        self.ended = None       # the hub's 403, 404 or 409 that ended it: a new publisher would get the same

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name="desktop-preview")
        self.thread.start()

    def close_capture(self):
        if self.reader:
            self.reader.close()
            self.reader = None
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            self.process.stdout.close()
            self.process = None
        self.buffer = b""

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=8)

    def frame(self):
        if not Path(self.command).is_file():
            return {"status": "unavailable", "image": None, "captured_at": None}
        if not self.process:
            self.process = subprocess.Popen([self.command, "--capture"], stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, start_new_session=True)
            self.reader = selectors.DefaultSelector()
            self.reader.register(self.process.stdout, selectors.EVENT_READ)
        latest = None
        deadline = time.monotonic() + 1.2
        while time.monotonic() < deadline and not self.stop.is_set():
            if not self.reader.select(0.1):
                continue
            part = os.read(self.process.stdout.fileno(), 65536)
            if not part:
                self.close_capture()
                break
            self.buffer += part
            if len(self.buffer) > MAX_FRAME * 2:
                raise ValueError("frame too large")
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                latest = json.loads(line)
            if latest:
                break
        return latest

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    code, data = self.http("GET", self.path + "?" + urllib.parse.urlencode(self.context), timeout=3)
                    if code != 200 or not data.get("watching"):
                        self.close_capture()
                    else:
                        frame = self.frame()
                        if frame:
                            code, _ = self.http("POST", self.path, dict(self.context, frame=frame), timeout=3)
                            if code != 200:
                                self.close_capture()
                    if code in (403, 404, 409):
                        self.ended = code
                        return
                except (OSError, ValueError, subprocess.SubprocessError):
                    self.close_capture()
                self.stop.wait(0.5)
        finally:
            self.close_capture()
