"""Local launcher/application control; deliberately has no network endpoint."""

import json
import os
import time
import uuid
from pathlib import Path


class RuntimeControl:
    def __init__(self, node, directory: str | Path, release: int, token: str, lease_timeout: float = 90):
        self.node = node
        self.directory = Path(directory)
        if not self.directory.is_dir() or not token:
            raise ValueError("launcher runtime directory and token are required")
        # An optional file the launcher may drop in this (fresh, per-launch) directory before
        # starting the child, so a newer launcher can hand a newer app a tuned value without a
        # CLI flag that an older, already-installed release wouldn't recognize.
        try:
            configured = json.loads((self.directory / "launch-config.json").read_text(encoding="utf-8"))
            value = configured.get("lease_timeout")
            if isinstance(value, (int, float)) and value > 0:
                lease_timeout = value
        except (OSError, ValueError):
            pass
        self.release, self.token, self.lease_timeout = release, token, lease_timeout
        self.counter = 0

    def poll(self) -> None:
        lease = self.directory / "lease.json"
        try:
            valid_lease = (json.loads(lease.read_text(encoding="utf-8")).get("token") == self.token
                           and time.time() - lease.stat().st_mtime < self.lease_timeout)
        except (OSError, ValueError):
            valid_lease = False
        if not valid_lease:
            self.node.stop_event.set()
        control = self.directory / "control.json"
        try:
            request = json.loads(control.read_text(encoding="utf-8"))
            if request == {"command": "stop", "token": self.token}:
                self.node.update_status(availability="draining")
                self.node.stop_event.set()
        except FileNotFoundError:
            pass
        self.counter += 1
        data = {"pid": os.getpid(), "release": self.release, "token": self.token,
                "counter": self.counter, "phase": "draining" if self.node.stop_event.is_set() else "ready",
                "instance_id": self.node.local_profile["instance_id"]}
        temporary = self.directory / (uuid.uuid4().hex + ".tmp")
        try:
            temporary.write_text(json.dumps(data), encoding="utf-8")
            os.replace(temporary, self.directory / "health.json")
        finally:
            temporary.unlink(missing_ok=True)

    def close(self) -> None:
        temporary = self.directory / (uuid.uuid4().hex + ".tmp")
        try:
            temporary.write_text(json.dumps({"token": self.token, "pid": os.getpid()}), encoding="utf-8")
            os.replace(temporary, self.directory / "exit.json")
        finally:
            temporary.unlink(missing_ok=True)
