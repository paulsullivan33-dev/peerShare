"""Cross-platform supervisor with signed releases, health checks, and rollback."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

from release_tools import (InstanceLock, atomic_json, public_key, regular, replace_file,
                           safe_directory, stage_package, verify_directory, verify_package)

# How stale health.json/lease.json can get before being considered failed. Generous enough to
# tolerate a busy host stalling the process for a while (e.g. swap thrashing) without a false
# failure, while still catching a genuinely hung or dead process in reasonable time.
DEFAULT_HEARTBEAT_TIMEOUT = 30
# How long a newly started release may take to report healthy before it counts as failed.
# Windows gets longer: first starts from freshly written release files can be slowed well past
# 30s (e.g. by on-access antivirus scanning). A healthy start still passes as soon as it has
# been stable for stabilize_seconds; the deadline only delays rolling back a broken release.
DEFAULT_HEALTH_TIMEOUT = 120 if os.name == "nt" else 30
MAX_CRASH_BACKOFF_SECONDS = 60
# Keep the installation's own files bounded on long-running nodes.
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_KEEP = 5                # application.log plus application.log.1 ... .5
LOG_CHECK_SECONDS = 60
KEEP_RUNTIME_DIRS = 5       # the current launch's runtime folder plus the most recent others
INBOX_GRACE_SECONDS = 600   # never prune a queued package younger than this


def log(message: str) -> None:
    print(f"[launcher] {message}", file=sys.stderr, flush=True)


def read_json(path: Path) -> dict:
    regular(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid {path.name}")
    return value


def rotate_log(path: Path, max_bytes: int = LOG_MAX_BYTES, keep: int = LOG_KEEP) -> bool:
    """Copy-and-truncate rotation: PATH -> PATH.1 -> ... -> PATH.KEEP, dropping the oldest. The
    child writes through an append-mode handle, so truncating the file in place is safe while it
    runs (at worst a line written during the copy is lost)."""
    try:
        if path.stat().st_size < max_bytes:
            return False
    except FileNotFoundError:
        return False
    for number in range(keep - 1, 0, -1):
        older = path.with_name(f"{path.name}.{number}")
        if older.exists():
            replace_file(older, path.with_name(f"{path.name}.{number + 1}"))
    shutil.copyfile(path, path.with_name(path.name + ".1"))
    with path.open("r+b") as handle:
        handle.truncate(0)
    return True


def contains(container: Path, other: Path) -> bool:
    """True if `other` is `container` or lies inside it, resolved but without requiring existence."""
    container, other = container.resolve(strict=False), other.resolve(strict=False)
    return container == other or container in other.parents


def check_shared_dir(root: Path, shared_dir: Path) -> None:
    # A shared directory that is, or contains, the install root/state/releases would let
    # file replication read (and hand to peers) the node's identity, keys, and update history.
    if contains(shared_dir, root):
        raise ValueError("shared directory must not be the installation root or one of its ancestors")
    for reserved in (root / "state", root / "releases"):
        if contains(shared_dir, reserved) or contains(reserved, shared_dir):
            raise ValueError("shared directory must not overlap the installation's state or releases directories")


def initialize(root: Path, package: Path, trusted_key: Path, port: int, app_args: list[str],
               auto_update: bool = False, health_timeout: float = DEFAULT_HEALTH_TIMEOUT,
               stabilize_seconds: float = 3, stop_timeout: float = 20,
               shared_dir: Path | None = None, heartbeat_timeout: float = DEFAULT_HEARTBEAT_TIMEOUT) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not (1 <= health_timeout <= 300 and 0 <= stabilize_seconds < health_timeout and 1 <= stop_timeout <= 120):
        raise ValueError("invalid health, stabilization, or stop timeout")
    if not 5 <= heartbeat_timeout <= 300:
        raise ValueError("heartbeat timeout must be between 5 and 300 seconds")
    reserved = {"--port", "--shared-dir", "--node-id-file", "--runtime-dir", "--release-id",
               "--lease-timeout", "--query-service"}
    if any(argument.split("=", 1)[0] in reserved for argument in app_args):
        raise ValueError("launcher controls port, data paths, runtime options, and service mode")
    if shared_dir is not None:
        check_shared_dir(root, shared_dir)
    # The initial release must have the same authorization as any subsequent release.
    key = public_key(trusted_key)
    verify_package(package, key)
    root = safe_directory(root)
    if any(root.iterdir()):
        raise ValueError("initialize requires an empty installation directory")
    for name in ("state", "state/runtime", "state/logs", "state/inbox", "releases"):
        safe_directory(root / name)
    shared_path = safe_directory(shared_dir) if shared_dir is not None else safe_directory(root / "shared")
    safe_directory(shared_path / "updates")
    shutil.copyfile(trusted_key, root / "state/trusted-release-key.pem")
    for name in ("launcher.py", "release_tools.py", "requirements-updater.txt"):
        shutil.copyfile(Path(__file__).parent / name, root / name)
    release = stage_package(package, root / "releases", key)["release"]
    atomic_json(root / "state/config.json", {
        "format": 1, "node_args": ["--port", str(port), *app_args], "auto_update": auto_update,
        "health_timeout": health_timeout, "stabilize_seconds": stabilize_seconds,
        "stop_timeout": stop_timeout, "shared_dir": str(shared_path) if shared_dir is not None else None,
        "heartbeat_timeout": heartbeat_timeout,
    })
    atomic_json(root / "state/active-release.json", {
        "active": release, "previous": None, "highest": release, "pending": None, "failed": {},
    })


def queue_update(root: Path, package: Path) -> None:
    root = safe_directory(root)
    key = public_key(root / "state/trusted-release-key.pem")
    release = verify_package(package, key)[0]["release"]
    state = read_json(root / "state/active-release.json")
    if release <= state["highest"]:
        raise ValueError("release must be newer than every previously attempted release")
    data = package.read_bytes()
    name = hashlib.sha256(data).hexdigest() + ".phupdate"
    inbox = safe_directory(root / "state/inbox")
    target = inbox / name
    temporary = inbox / (uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    # The running launcher re-verifies the copied bytes before installation.
    atomic_json(root / "state/update-request.json", {"package": name})
    log(f"queued signed release {release}; start the launcher if it is not running")


def initialize_source(root: Path, source: Path, trusted_key: Path | None, port: int,
                      app_args: list[str], auto_update: bool = False,
                      shared_dir: Path | None = None, heartbeat_timeout: float = DEFAULT_HEARTBEAT_TIMEOUT) -> None:
    """Trust the explicitly installed local source, independently of update authority."""
    from release_tools import generate_keys, build_package
    if trusted_key is not None:
        public_key(trusted_key)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        private, public = directory / 'private.pem', directory / 'public.pem'
        package = directory / 'initial.phupdate'
        generate_keys(private, public)
        build_package(source, private, 1, package)
        initialize(root, package, public, port, app_args, auto_update, shared_dir=shared_dir,
                  heartbeat_timeout=heartbeat_timeout)
        (root / 'state/trusted-release-key.pem').rename(root / 'state/bootstrap-key.pem')
        if trusted_key is not None:
            shutil.copyfile(trusted_key, root / 'state/trusted-release-key.pem')
        config = read_json(root / 'state/config.json')
        config['bootstrap_release'] = 1
        atomic_json(root / 'state/config.json', config)
    if trusted_key is None:
        print('Source installed. Signed updates await a trusted public key; use launcher.py trust-key.')


class Launcher:
    def __init__(self, root: Path):
        self.root = safe_directory(root)
        self.state_dir = safe_directory(self.root / "state")
        self.releases = safe_directory(self.root / "releases")
        key_path = self.state_dir / "trusted-release-key.pem"
        self.key = public_key(key_path) if key_path.exists() else None
        self.config = read_json(self.state_dir / "config.json")
        self.shared_dir = (Path(self.config["shared_dir"]) if self.config.get("shared_dir")
                          else self.root / "shared")
        self.heartbeat_timeout = self.config.get("heartbeat_timeout", DEFAULT_HEARTBEAT_TIMEOUT)
        self.state_path = self.state_dir / "active-release.json"
        self.state = read_json(self.state_path)
        self.stop_event = threading.Event()
        self.session = uuid.uuid4().hex
        self.child = None
        self.runtime = None
        self.token = None
        self.last_health = None
        self.output = None
        self.seen_packages = {}
        self.update_cursor = 0

    def save(self) -> None:
        atomic_json(self.state_path, self.state)

    def fail_release(self, release: int, reason: str) -> None:
        self.state["failed"][str(release)] = reason[:300]
        while len(self.state["failed"]) > 32:
            del self.state["failed"][next(iter(self.state["failed"]))]

    def recover_transaction(self) -> None:
        pending = self.state["pending"]
        if pending is not None:
            self.fail_release(pending["candidate"], "launcher stopped before update health check committed")
            self.state["active"] = pending["previous"]
            self.state["pending"] = None
            self.save()
            log("recovered interrupted update; restored previous release")

    def recover_orphan(self) -> None:
        path = self.state_dir / "child.json"
        if not path.exists():
            return
        record = read_json(path)
        if not re.fullmatch("[0-9a-f]{32}", record.get("runtime", "")):
            raise ValueError("invalid saved runtime path")
        runtime = safe_directory(self.state_dir / "runtime" / record["runtime"])
        atomic_json(runtime / "control.json", {"command": "stop", "token": record["token"]})
        deadline = time.monotonic() + self.config["stop_timeout"]
        while time.monotonic() < deadline:
            exit_path = runtime / "exit.json"
            if exit_path.exists() and read_json(exit_path).get("token") == record["token"]:
                path.unlink(missing_ok=True)
                return
            health = runtime / "health.json"
            if (not health.exists() or
                    time.time() - health.stat().st_mtime > self.heartbeat_timeout + 25):
                # No live heartbeat remains; a new process still must acquire the file lock and TCP port.
                path.unlink(missing_ok=True)
                return
            if self.stop_event.wait(.2):
                return
        raise ValueError("previous child has not stopped; wait for its lease to expire before restarting")

    def lease(self) -> None:
        control = self.state_dir / "launcher-control.json"
        request = None
        try:
            request = read_json(control)
            control.unlink(missing_ok=True)
        except FileNotFoundError:
            pass
        except ValueError:
            try:
                control.unlink(missing_ok=True)  # Malformed request: discard rather than crash.
            except OSError:
                pass
        except OSError:
            pass  # Being replaced right now (Windows); read it on the next tick.
        if request is not None and request.get("session") == self.session and request.get("command") == "stop":
            self.stop_event.set()
        if self.runtime is not None:
            try:
                atomic_json(self.runtime / "lease.json", {"token": self.token})
            except OSError as error:
                # The child tolerates a lease up to 3x the heartbeat timeout old; the next tick
                # (0.2s later) renews it, so one failed renewal must not stop the launcher.
                log(f"could not renew lease: {error}")

    def prune_runtime(self) -> None:
        """Keep the current launch's runtime folder and the few most recent others."""
        protected = {self.runtime}
        try:
            record = read_json(self.state_dir / "child.json")
            protected.add(self.state_dir / "runtime" / str(record.get("runtime")))
        except (OSError, ValueError):
            pass
        root = self.state_dir / "runtime"
        folders = [path for path in root.iterdir() if re.fullmatch("[0-9a-f]{32}", path.name)
                   and path.is_dir() and not path.is_symlink() and path not in protected]
        folders.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        for path in folders[KEEP_RUNTIME_DIRS - 1:]:
            shutil.rmtree(path, ignore_errors=True)

    def prune_inbox(self) -> None:
        """Remove queued packages that were already processed (their request is gone), keeping
        the one still queued and anything young enough to be part of a queue in progress."""
        queued = None
        request = self.state_dir / "update-request.json"
        if request.exists():
            try:
                queued = read_json(request).get("package")
            except (OSError, ValueError):
                return
        cutoff = time.time() - INBOX_GRACE_SECONDS
        for path in (self.state_dir / "inbox").iterdir():
            if (re.fullmatch("[0-9a-f]{64}\\.phupdate|[0-9a-f]{32}\\.tmp", path.name) and
                    path.name != queued and path.stat().st_mtime < cutoff):
                path.unlink(missing_ok=True)

    def start_child(self, release: int) -> None:
        directory = self.releases / str(release)
        key = (public_key(self.state_dir / 'bootstrap-key.pem')
               if release == self.config.get('bootstrap_release') else self.key)
        if key is None:
            raise ValueError('no trusted release key configured')
        if verify_directory(directory, key)["release"] != release:
            raise ValueError("installed release number does not match its directory")
        self.runtime = safe_directory(self.state_dir / "runtime" / uuid.uuid4().hex)
        self.token = uuid.uuid4().hex
        self.last_health = None
        self.lease()
        try:
            self.prune_runtime()
            rotate_log(safe_directory(self.state_dir / "logs") / "application.log")
        except OSError as error:
            log(f"could not tidy runtime folders or logs: {error}")
        # Handed to the child via a file rather than a CLI flag, since a rollback can start an
        # older release whose peer_handshake.py predates any given flag and would reject it. The
        # child gives up on an unresponsive launcher only well after the launcher would itself
        # have already noticed and restarted an unresponsive child (see health()); an older
        # release that never reads this file just keeps its own built-in default instead.
        atomic_json(self.runtime / "launch-config.json", {"lease_timeout": self.heartbeat_timeout * 3})
        command = [sys.executable, "-E", "-s", "-B", "-u", str(directory / "peer_handshake.py"),
                   *self.config["node_args"], "--node-id-file", str(self.state_dir / "node.id"),
                   "--shared-dir", str(safe_directory(self.shared_dir)), "--runtime-dir", str(self.runtime),
                   "--release-id", str(release)]
        environment = dict(os.environ, PEER_LAUNCH_TOKEN=self.token)
        self.output = (safe_directory(self.state_dir / "logs") / "application.log").open("ab", buffering=0)
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
        try:
            self.child = subprocess.Popen(command, cwd=directory, env=environment,
                                          stdin=subprocess.DEVNULL, stdout=self.output, stderr=self.output, **options)
        except Exception:
            self.output.close()
            self.output = None
            raise
        atomic_json(self.state_dir / "child.json", {"pid": self.child.pid, "runtime": self.runtime.name,
                                                    "token": self.token, "release": release})
        log(f"started release {release}, pid {self.child.pid}")

    def health(self, release: int) -> dict | None:
        if self.child is None or self.child.poll() is not None:
            return None
        path = self.runtime / "health.json"
        try:
            value, modified = read_json(path), path.stat().st_mtime
            self.last_health = (value, modified)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            # Unreadable right now, e.g. Windows denies access while the child replaces it.
            # Judge the last heartbeat actually read instead; it still goes stale on schedule.
            if self.last_health is None:
                return None
            value, modified = self.last_health
        if (value.get("pid") == self.child.pid and value.get("token") == self.token and
                value.get("release") == release and value.get("phase") == "ready" and
                time.time() - modified < self.heartbeat_timeout):
            return value
        return None

    def wait_ready(self, release: int) -> bool:
        deadline = time.monotonic() + self.config["health_timeout"]
        first_ready = None
        first_counter = None
        while time.monotonic() < deadline and not self.stop_event.is_set():
            if self.child.poll() is not None:
                return False
            self.lease()
            health = self.health(release)
            if health:
                if first_ready is None:
                    first_ready, first_counter = time.monotonic(), health.get("counter")
                if (time.monotonic() - first_ready >= self.config["stabilize_seconds"] and
                        health.get("counter") != first_counter):
                    return True
            else:
                first_ready = None
            self.stop_event.wait(.2)
        return False

    def stop_child(self) -> None:
        if self.child is None:
            return
        try:
            if self.child.poll() is None:
                try:
                    atomic_json(self.runtime / "control.json", {"command": "stop", "token": self.token})
                except OSError as error:
                    # Still stop it: fall through to waiting, then terminate/kill.
                    log(f"could not request graceful stop: {error}")
                try:
                    self.child.wait(timeout=self.config["stop_timeout"])
                except subprocess.TimeoutExpired:
                    self.child.terminate()
                    try:
                        self.child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.child.kill()
                        self.child.wait(timeout=5)
        finally:
            if self.child.poll() is not None:
                (self.state_dir / "child.json").unlink(missing_ok=True)
            if self.output is not None:
                self.output.close()
            self.output = self.child = None

    def launch_ready(self, release: int) -> bool:
        try:
            self.start_child(release)
            if self.wait_ready(release):
                return True
        except (OSError, ValueError) as error:
            log(f"release {release} could not start: {error}")
        self.stop_child()
        return False

    def apply_update(self, package: Path) -> bool:
        manifest = stage_package(package, self.releases, self.key)
        candidate, previous = manifest["release"], self.state["active"]
        if candidate <= self.state["highest"]:
            raise ValueError("refusing a reused or older release number")
        self.state["highest"] = candidate
        self.state["pending"] = {"candidate": candidate, "previous": previous}
        self.state["active"] = candidate
        self.save()  # Recoverable transaction is durable before stopping the working process.
        self.stop_child()
        if self.launch_ready(candidate):
            self.state["previous"] = previous
            self.state["pending"] = None
            self.save()
            log(f"release {candidate} passed health checks and is active")
            return True
        self.fail_release(candidate, "startup health check failed")
        self.state["active"] = previous
        self.state["pending"] = None
        self.save()
        log(f"release {candidate} failed; rolling back to {previous}")
        if not self.stop_event.is_set():
            restored = self.launch_ready(previous)
            if not restored and not self.stop_event.is_set():
                raise RuntimeError("rollback release also failed to start; inspect application.log")
        return False

    def next_update(self) -> Path | None:
        if self.key is None:
            key_path = self.state_dir / 'trusted-release-key.pem'
            if not key_path.exists():
                return None
            self.key = public_key(key_path)
        request_path = self.state_dir / "update-request.json"
        if request_path.exists():
            request = read_json(request_path)
            request_path.unlink()
            name = request.get("package", "")
            if not re.fullmatch("[0-9a-f]{64}\\.phupdate", name):
                raise ValueError("invalid queued update path")
            return self.state_dir / "inbox" / name
        if not self.config["auto_update"]:
            return None
        shared = safe_directory(self.shared_dir)
        updates = safe_directory(shared / "updates")
        candidates = []
        paths = sorted([*updates.glob("*.phupdate"),
                        *(shared / "replica-conflicts").glob("*/*/updates/*.phupdate")])
        if not paths:
            return None
        self.update_cursor %= len(paths)
        batch = (paths[self.update_cursor:] + paths[:self.update_cursor])[:128]
        self.update_cursor = (self.update_cursor + len(batch)) % len(paths)
        for path in batch:
            stamp = None
            cache_key = path.relative_to(shared).as_posix()
            try:
                safe_directory(path.parent)
                if not path.resolve().is_relative_to(shared):
                    raise ValueError("update path escapes shared directory")
                regular(path)
                stamp = (path.stat().st_size, path.stat().st_mtime_ns)
                cached = self.seen_packages.get(cache_key)
                if cached and cached[0] == stamp:
                    release = cached[1]
                else:
                    release = verify_package(path, self.key)[0]["release"]
                    self.seen_packages[cache_key] = (stamp, release)
                if release > self.state["highest"]:
                    candidates.append((release, path))
            except (OSError, ValueError, zipfile.BadZipFile) as error:
                log(f"ignored update {path.name}: {error}")
                if stamp is not None:
                    self.seen_packages[cache_key] = (stamp, 0)
            while len(self.seen_packages) > 256:
                del self.seen_packages[next(iter(self.seen_packages))]
        return max(candidates, default=(0, None), key=lambda item: item[0])[1]

    def run(self) -> None:
        with InstanceLock(self.state_dir / "launcher.lock"):
            atomic_json(self.state_dir / "launcher-session.json", {"session": self.session})
            self.recover_orphan()
            self.recover_transaction()
            try:
                self.prune_inbox()
            except OSError as error:
                log(f"could not tidy the update inbox: {error}")
            last_update_check = last_log_check = 0
            crash_backoff = 1
            try:
                while not self.stop_event.is_set():
                    self.lease()
                    if not self.health(self.state["active"]):
                        # No child just means nothing is started yet (e.g. launcher startup after a
                        # reboot); only a child that went unhealthy, or one that fails to start,
                        # counts against the active release.
                        unhealthy = self.child is not None
                        self.stop_child()
                        previous = self.state["previous"]
                        if not unhealthy and self.launch_ready(self.state["active"]):
                            crash_backoff = 1
                        elif self.stop_event.is_set():
                            return
                        elif previous is not None:
                            reason = "runtime health check failed" if unhealthy else "startup health check failed"
                            self.fail_release(self.state["active"], reason)
                            log(f"release {self.state['active']} {reason}; rolling back to {previous}")
                            self.state["active"], self.state["previous"] = previous, None
                            self.save()
                            crash_backoff = 1  # The next pass starts the restored release.
                        elif unhealthy and self.launch_ready(self.state["active"]):
                            crash_backoff = 1
                        else:
                            if self.stop_event.is_set():
                                return
                            # A host under transient resource pressure (e.g. swap thrashing) can
                            # stall the process past the heartbeat window without it ever truly
                            # crashing; keep retrying with backoff rather than giving up, since
                            # giving up here just forces systemd to redo this same work anyway.
                            log(f"release {self.state['active']} is not healthy; retrying in {crash_backoff}s")
                            if self.stop_event.wait(crash_backoff):
                                return
                            crash_backoff = min(crash_backoff * 2, MAX_CRASH_BACKOFF_SECONDS)
                    if time.monotonic() - last_update_check >= 2:
                        last_update_check = time.monotonic()
                        update = None
                        try:
                            update = self.next_update()
                            if update is not None:
                                self.apply_update(update)
                        except (OSError, ValueError, zipfile.BadZipFile) as error:
                            log(f"update rejected: {error}")
                        finally:
                            # A queued package has served its purpose once processed.
                            if update is not None and update.parent == self.state_dir / "inbox":
                                update.unlink(missing_ok=True)
                    if time.monotonic() - last_log_check >= LOG_CHECK_SECONDS:
                        last_log_check = time.monotonic()
                        try:
                            rotate_log(self.state_dir / "logs" / "application.log")
                        except OSError as error:
                            log(f"could not rotate application.log: {error}")
                    self.stop_event.wait(.2)
            finally:
                self.stop_child()


def reconfigure(root: Path, *, port: int | None = None, app_args: list[str] | None = None,
                auto_update: bool | None = None, health_timeout: float | None = None,
                stabilize_seconds: float | None = None, stop_timeout: float | None = None,
                shared_dir: Path | None = None, clear_shared_dir: bool = False,
                heartbeat_timeout: float | None = None) -> None:
    """Update an existing installation's saved settings. `app_args` (network/name/etc.)
    is replaced wholesale when given, matching how `state/config.json` already works;
    omit it to leave the current application arguments untouched."""
    if shared_dir is not None and clear_shared_dir:
        raise ValueError("--shared-dir and --clear-shared-dir are mutually exclusive")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if heartbeat_timeout is not None and not 5 <= heartbeat_timeout <= 300:
        raise ValueError("heartbeat timeout must be between 5 and 300 seconds")
    if app_args is not None:
        reserved = {"--port", "--shared-dir", "--node-id-file", "--runtime-dir", "--release-id",
                   "--lease-timeout", "--query-service"}
        if any(argument.split("=", 1)[0] in reserved for argument in app_args):
            raise ValueError("launcher controls port, data paths, runtime options, and service mode")
    root = safe_directory(root)
    if shared_dir is not None:
        check_shared_dir(root, shared_dir)
    # Holding the same lock the running launcher uses both prevents a start racing this
    # write and gives the familiar "another launcher owns this installation" refusal.
    with InstanceLock(root / "state/launcher.lock"):
        config = read_json(root / "state/config.json")
        if app_args is not None:
            effective_port = port if port is not None else int(config["node_args"][1])
            config["node_args"] = ["--port", str(effective_port), *app_args]
        elif port is not None:
            config["node_args"][1] = str(port)
        if auto_update is not None:
            config["auto_update"] = auto_update
        if health_timeout is not None:
            config["health_timeout"] = health_timeout
        if stabilize_seconds is not None:
            config["stabilize_seconds"] = stabilize_seconds
        if stop_timeout is not None:
            config["stop_timeout"] = stop_timeout
        if heartbeat_timeout is not None:
            config["heartbeat_timeout"] = heartbeat_timeout
        if not (1 <= config["health_timeout"] <= 300 and 0 <= config["stabilize_seconds"] < config["health_timeout"]
                and 1 <= config["stop_timeout"] <= 120):
            raise ValueError("invalid health, stabilization, or stop timeout")
        if clear_shared_dir:
            config["shared_dir"] = None
        elif shared_dir is not None:
            config["shared_dir"] = str(safe_directory(shared_dir))
        atomic_json(root / "state/config.json", config)
        shared_path = Path(config["shared_dir"]) if config.get("shared_dir") else root / "shared"
        safe_directory(shared_path / "updates")


def running(root: Path) -> bool:
    try:
        with InstanceLock(root / "state/launcher.lock"):
            return False
    except ValueError as error:
        if str(error) == "another launcher owns this installation":
            return True
        raise


def request_stop(root: Path) -> None:
    if not running(root):
        print("Node is stopped.")
        return
    record = read_json(root / "state/launcher-session.json")
    atomic_json(root / "state/launcher-control.json", {"command": "stop", "session": record["session"]})
    print("Stop requested.")


def main() -> None:
    parser = argparse.ArgumentParser(description="peerHandshake release launcher (Windows/Linux)")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize_parser = commands.add_parser("init")
    initialize_parser.add_argument("--root", type=Path, required=True)
    initialize_parser.add_argument("--package", type=Path, required=True)
    initialize_parser.add_argument("--trusted-key", type=Path, required=True)
    initialize_parser.add_argument("--port", type=int, required=True)
    initialize_parser.add_argument("--shared-dir", type=Path)
    initialize_parser.add_argument("--auto-update", action="store_true")
    initialize_parser.add_argument("--health-timeout", type=float, default=DEFAULT_HEALTH_TIMEOUT)
    initialize_parser.add_argument("--stabilize-seconds", type=float, default=3)
    initialize_parser.add_argument("--stop-timeout", type=float, default=20)
    initialize_parser.add_argument("--heartbeat-timeout", type=float, default=DEFAULT_HEARTBEAT_TIMEOUT)
    initialize_parser.add_argument("app_args", nargs=argparse.REMAINDER)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    source_parser = commands.add_parser('init-source')
    source_parser.add_argument('--root', type=Path, required=True)
    source_parser.add_argument('--source', type=Path, default=Path(__file__).parent)
    source_parser.add_argument('--trusted-key', type=Path)
    source_parser.add_argument('--port', type=int, required=True)
    source_parser.add_argument('--shared-dir', type=Path)
    source_parser.add_argument('--auto-update', action='store_true')
    source_parser.add_argument('--heartbeat-timeout', type=float, default=DEFAULT_HEARTBEAT_TIMEOUT)
    source_parser.add_argument('app_args', nargs=argparse.REMAINDER)
    reconfigure_parser = commands.add_parser('reconfigure')
    reconfigure_parser.add_argument('--root', type=Path, required=True)
    reconfigure_parser.add_argument('--port', type=int)
    reconfigure_parser.add_argument('--shared-dir', type=Path)
    reconfigure_parser.add_argument('--heartbeat-timeout', type=float)
    reconfigure_parser.add_argument('--clear-shared-dir', action='store_true')
    reconfigure_parser.add_argument('--auto-update', action=argparse.BooleanOptionalAction, default=None)
    reconfigure_parser.add_argument('--health-timeout', type=float)
    reconfigure_parser.add_argument('--stabilize-seconds', type=float)
    reconfigure_parser.add_argument('--stop-timeout', type=float)
    reconfigure_parser.add_argument('app_args', nargs=argparse.REMAINDER)
    trust_parser = commands.add_parser('trust-key')
    trust_parser.add_argument('--root', type=Path, default=Path(__file__).parent)
    trust_parser.add_argument('--trusted-key', type=Path, required=True)
    for command in ("stop", "status"):
        control = commands.add_parser(command)
        control.add_argument("--root", type=Path, default=Path(__file__).parent)
    update_parser = commands.add_parser("update")
    update_parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    update_parser.add_argument("--package", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            extra = args.app_args[1:] if args.app_args[:1] == ["--"] else args.app_args
            initialize(args.root, args.package, args.trusted_key, args.port, extra, args.auto_update,
                       args.health_timeout, args.stabilize_seconds, args.stop_timeout, args.shared_dir,
                       args.heartbeat_timeout)
        elif args.command == 'init-source':
            extra = args.app_args[1:] if args.app_args[:1] == ['--'] else args.app_args
            initialize_source(args.root, args.source, args.trusted_key, args.port, extra, args.auto_update,
                              args.shared_dir, args.heartbeat_timeout)
        elif args.command == 'reconfigure':
            if args.app_args[:1] == ['--']:
                extra = args.app_args[1:]
            elif args.app_args:
                parser.error('reconfigure network arguments must follow --')
            else:
                extra = None
            reconfigure(args.root, port=args.port, app_args=extra, auto_update=args.auto_update,
                       health_timeout=args.health_timeout, stabilize_seconds=args.stabilize_seconds,
                       stop_timeout=args.stop_timeout, shared_dir=args.shared_dir,
                       clear_shared_dir=args.clear_shared_dir, heartbeat_timeout=args.heartbeat_timeout)
            print('Settings updated. Restart the node for changes to take effect.')
        elif args.command == 'trust-key':
            public_key(args.trusted_key)
            target = args.root / 'state/trusted-release-key.pem'
            with target.open('xb') as output:
                output.write(args.trusted_key.read_bytes())
            print('Trusted update key installed.')
        elif args.command == "update":
            queue_update(args.root, args.package)
        elif args.command == "stop":
            request_stop(args.root)
        elif args.command == "status":
            active = running(args.root)
            print("Launcher running." if active else "Node stopped.")
            raise SystemExit(0 if active else 1)
        else:
            launcher = Launcher(args.root)
            signal.signal(signal.SIGINT, lambda *_: launcher.stop_event.set())
            signal.signal(signal.SIGTERM, lambda *_: launcher.stop_event.set())
            launcher.run()
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
