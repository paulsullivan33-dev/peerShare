"""Pull-based, content-verified replication of immutable file versions."""

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import threading
import time
import uuid
from pathlib import Path

from peer_protocol import integer

CHUNK_BYTES = 32768
MANIFEST_PAGE = 32
MAX_FILES = 10000
DEFAULT_MAX_FILE_BYTES = 1024**3
DEFAULT_MAX_SHARED_BYTES = 10 * 1024**3
SYNC_INTERVAL_SECONDS = 15
# Unchanged files (same size/mtime/ctime/inode) are trusted between scans; every tracked
# file is still fully rehashed this often, and once after each start, to catch silent damage.
FULL_VERIFY_SECONDS = 3600
FILE_DEADLINE_SECONDS = 300
MAX_DOWNLOADS_PER_PASS = 32
REQUEST_TYPES = ("file-manifest", "file-chunk")
RESPONSE_TYPES = ("file-manifest-result", "file-chunk-result", "file-error")
RESERVED = {".peer-sync", "replica-conflicts"}
# An empty file "PATH.delete" is stamped with its creation time and replicated; while active,
# every node deletes all versions of PATH (a file, or everything under a folder) and refuses to
# download or import them again. It expires MARKER_TTL_SECONDS after creation, measured from the
# stamp so all nodes agree; then each node removes it and remembers it as retired. A node offline
# for longer than that can reintroduce the deleted files.
DELETE_SUFFIX = ".delete"
MARKER_TTL_SECONDS = 86400
MAX_MARKER_BYTES = 512
MAX_RETIRED_MARKERS = 10000
MARKER_FIELDS = {"peerhandshake-delete", "created", "id"}


def logical_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ValueError("file path must contain 1 through 240 characters")
    for part in value.split("/"):
        if (not part or part in (".", "..") or len(part) > 100 or
                part.rstrip(" .") != part or any(ord(c) < 32 or c in '\\:<>"|?*' for c in part) or
                part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", "CLOCK$",
                                               *(f"COM{i}" for i in range(10)),
                                               *(f"LPT{i}" for i in range(10))}):
            raise ValueError("unsafe or nonportable file path")
    if value.split("/")[0].casefold() in RESERVED:
        raise ValueError("reserved replication directory")
    return value


def digest(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("invalid SHA-256 digest")
    return value


def entry(value: object, max_file_bytes: int) -> dict:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size"}:
        raise ValueError("file entry requires path, sha256, and size")
    return {"path": logical_path(value["path"]), "sha256": digest(value["sha256"]),
            "size": integer(value["size"], "file size", 0, max_file_bytes)}


def key(item: dict) -> str:
    return item["path"] + "\0" + item["sha256"]


def marker_target(path: str) -> str | None:
    """The logical path a PATH.delete marker removes, or None if it cannot be a marker."""
    if not path.endswith(DELETE_SUFFIX):
        return None
    try:
        return logical_path(path[:-len(DELETE_SUFFIX)])
    except ValueError:
        return None  # e.g. "folder/.delete": would target a folder's root or an invalid path


def covers(target: str, path: str) -> bool:
    return path == target or path.startswith(target + "/")


def marker_bytes(created: int) -> bytes:
    return (json.dumps({"peerhandshake-delete": 1, "created": created, "id": str(uuid.uuid4())},
                       sort_keys=True) + "\n").encode()


def marker_created(data: bytes) -> int | None:
    """Creation time stamped in a marker, or None when the bytes are not a stamped marker."""
    if len(data) > MAX_MARKER_BYTES:
        return None
    try:
        value = json.loads(data.decode("utf-8"))
        if (not isinstance(value, dict) or set(value) != MARKER_FIELDS or
                value["peerhandshake-delete"] != 1 or type(value["created"]) is not int or
                value["created"] <= 0 or not isinstance(value["id"], str)):
            return None
        uuid.UUID(value["id"])
    except ValueError:
        return None
    return value["created"]


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def fingerprint(path: Path, max_size: int) -> tuple[str, int]:
    before = path.lstat()
    if is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("only regular, unlinked files can be shared")
    if before.st_size > max_size:
        raise ValueError("file exceeds size limit")
    total = 0
    result = hashlib.sha256()
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("file changed while opening")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if total > max_size:
                raise ValueError("file exceeds size limit")
            result.update(block)
        after = os.fstat(source.fileno())
    # Compare fstat to fstat: Windows path-stat and handle-stat ctime semantics differ.
    if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) !=
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
            (before.st_size, before.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns) or
            total != before.st_size):
        raise ValueError("file changed while hashing")
    return result.hexdigest(), total


class FileStore:
    def __init__(self, directory: str | Path, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 max_shared_bytes: int = DEFAULT_MAX_SHARED_BYTES, max_files: int = MAX_FILES):
        self._owner = None
        self.root = Path(directory).absolute()
        self.max_file_bytes = integer(max_file_bytes, "max file bytes", 1, 2**63 - 1)
        self.max_shared_bytes = integer(max_shared_bytes, "max shared bytes", 1, 2**63 - 1)
        self.max_files = integer(max_files, "max files", 1, MAX_FILES)
        self.lock = threading.RLock()
        # Refuse existing symlink/junction ancestors, even if their targets exist.
        for path in reversed((self.root, *self.root.parents)):
            if path.exists() and is_link(path.lstat()):
                raise ValueError("shared directory cannot use symlinks or junctions")
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve()
        self.state = self.safe_path(".peer-sync", internal=True)
        self.state.mkdir(exist_ok=True)
        self.temp = self.safe_path(".peer-sync/tmp", internal=True)
        self.temp.mkdir(exist_ok=True)
        self.index_path = self.safe_path(".peer-sync/index.json", internal=True)
        self.records: dict[str, dict] = {}
        self.intact: set[str] = set()
        # Stat signature of each record's destination when its bytes last hashed correctly.
        self.verified: dict[str, tuple] = {}
        self.last_full_verify = float("-inf")
        # Delete markers: expired marker versions never to download again (oldest first), the
        # targets of currently active markers, and each marker record's parsed creation time
        # (0 for a file that merely ends in .delete but is not a stamped marker).
        self.retired_markers: dict[str, None] = {}
        self.deleting: tuple[str, ...] = ()
        self.marker_times: dict[str, int] = {}
        self.log = lambda message: None
        if self.index_path.exists():
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("files"), list):
                raise ValueError("invalid replication index; refusing to replace it")
            if len(raw["files"]) > self.max_files:
                raise ValueError("replication index exceeds max files")
            destinations = set()
            for record in raw["files"]:
                if (not isinstance(record, dict) or set(record) != {"file", "destination"} or
                        not isinstance(record["destination"], str)):
                    raise ValueError("invalid replication index; refusing to replace it")
                item = entry(record["file"], self.max_file_bytes)
                destination = record["destination"]
                if destination not in (item["path"], self.conflict_path(item)):
                    raise ValueError("invalid stored file destination")
                self.safe_path(destination, internal=True)
                if key(item) in self.records or destination.casefold() in destinations:
                    raise ValueError("duplicate entry in replication index")
                destinations.add(destination.casefold())
                self.records[key(item)] = {"file": item, "destination": destination}
            retired = raw.get("retired_markers", [])  # Absent in indexes written before markers.
            if not isinstance(retired, list) or len(retired) > MAX_RETIRED_MARKERS:
                raise ValueError("invalid replication index; refusing to replace it")
            for identifier in retired:
                if not isinstance(identifier, str) or identifier.count("\0") != 1:
                    raise ValueError("invalid replication index; refusing to replace it")
                path, sha = identifier.split("\0")
                logical_path(path)
                digest(sha)
                self.retired_markers[identifier] = None

        owner_path = self.safe_path(".peer-sync/owner.lock", internal=True)
        owner = owner_path.open("a+b")
        try:
            if owner.seek(0, os.SEEK_END) == 0:
                owner.write(b"0")
                owner.flush()
            owner.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(owner.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            owner.close()
            raise ValueError("shared directory is already owned by another node") from error
        self._owner = owner
        # Only our reserved temporary filenames are removed after a crashed transfer.
        for candidate in self.temp.iterdir():
            if re.fullmatch(r"[0-9a-f]{32}\.part", candidate.name):
                self.safe_path(".peer-sync/tmp/" + candidate.name, internal=True).unlink()

    def ensure_layout(self) -> None:
        """Recreate the shared root and its internal .peer-sync/tmp directories if anything
        deleted them while running, so that doesn't permanently stop replication."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.safe_path(".peer-sync", internal=True).mkdir(exist_ok=True)
        self.safe_path(".peer-sync/tmp", internal=True).mkdir(exist_ok=True)
        if not self.index_path.exists():
            self.save()

    def close(self) -> None:
        if self._owner is not None:
            self._owner.close()
            self._owner = None

    def __del__(self):
        owner = getattr(self, "_owner", None)
        if owner is not None:
            owner.close()

    def safe_path(self, relative: str, internal: bool = False) -> Path:
        if not internal:
            logical_path(relative)
        if relative.startswith("/") or "\\" in relative or ":" in relative:
            raise ValueError("unsafe file path")
        candidate = self.root
        if is_link(self.root.lstat()):
            raise ValueError("shared root was replaced with a link")
        for part in relative.split("/"):
            if part in ("", ".", ".."):
                raise ValueError("unsafe path component")
            candidate = candidate / part
            try:
                info = candidate.lstat()
            except (FileNotFoundError, NotADirectoryError):
                continue
            if is_link(info) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                raise ValueError("links are not allowed in the shared directory")
        if not candidate.resolve().is_relative_to(self.root):
            raise ValueError("path escapes shared directory")
        return candidate

    @staticmethod
    def conflict_path(item: dict) -> str:
        path_id = hashlib.sha256(item["path"].encode()).hexdigest()[:16]
        return "replica-conflicts/" + item["sha256"] + "/" + path_id + "/" + item["path"]

    def save(self) -> None:
        self.safe_path(".peer-sync/index.json", internal=True)
        temporary = self.safe_path(".peer-sync/" + uuid.uuid4().hex + ".index", internal=True)
        try:
            with temporary.open("x", encoding="utf-8") as output:
                json.dump({"version": 1, "files": list(self.records.values()),
                           "retired_markers": list(self.retired_markers)}, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.index_path)
        finally:
            temporary.unlink(missing_ok=True)

    def verify(self, record: dict) -> bool:
        try:
            path = self.safe_path(record["destination"], internal=True)
            sha, size = fingerprint(path, self.max_file_bytes)
            return (sha, size) == (record["file"]["sha256"], record["file"]["size"])
        except (OSError, ValueError):
            return False

    @staticmethod
    def signature(path: Path) -> tuple:
        info = path.lstat()
        return info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino, info.st_dev

    def verify_cached(self, identifier: str, record: dict, full: bool) -> bool:
        """Rehash only when the file's stat signature changed, unless a full pass is due."""
        try:
            before = self.signature(self.safe_path(record["destination"], internal=True))
        except (OSError, ValueError):
            self.verified.pop(identifier, None)
            return False
        if not full and self.verified.get(identifier) == before:
            return True
        if self.verify(record):
            self.verified[identifier] = before
            return True
        self.verified.pop(identifier, None)
        return False

    def scan(self) -> None:
        """Recheck tracked copies; new paths are imports, changed tracked bytes are damaged.

        Hashing happens outside self.lock so manifest/chunk requests from peers are not
        blocked behind a long scan."""
        with self.lock:
            self.ensure_layout()
            records = dict(self.records)
        started = time.monotonic()
        full = started - self.last_full_verify >= FULL_VERIFY_SECONDS
        intact = {identifier for identifier, record in records.items()
                  if self.verify_cached(identifier, record, full)}
        if full:
            self.last_full_verify = started
        tracked = {record["destination"].casefold() for record in records.values()}
        imports = []
        for parent, directories, files in os.walk(self.root, followlinks=False):
            safe_directories = []
            for name in directories:
                try:
                    if name.casefold() not in RESERVED and not is_link((Path(parent) / name).lstat()):
                        safe_directories.append(name)
                except OSError:
                    continue  # A directory may disappear during the scan.
            directories[:] = sorted(safe_directories)
            for filename in sorted(files):
                relative = (Path(parent) / filename).relative_to(self.root).as_posix()
                if relative.casefold() in tracked or len(records) + len(imports) >= self.max_files:
                    continue
                try:
                    path = self.safe_path(relative)
                    if marker_target(relative) is not None and path.lstat().st_size == 0:
                        self.stamp_marker(path)
                    before = self.signature(path)
                    sha, size = fingerprint(path, self.max_file_bytes)
                except (OSError, ValueError):
                    continue
                imports.append(({"path": relative, "sha256": sha, "size": size}, before))
                tracked.add(relative.casefold())
        imports = self.convert_renames(imports, records)
        with self.lock:
            # Records installed while hashing keep the status install() gave them.
            self.intact = intact | {identifier for identifier in self.intact if identifier not in records}
            occupied = {record["destination"].casefold() for record in self.records.values()}
            changed = False
            for item, before in imports:
                if (key(item) in self.records or item["path"].casefold() in occupied or
                        len(self.records) >= self.max_files):
                    continue
                self.records[key(item)] = {"file": item, "destination": item["path"]}
                self.intact.add(key(item))
                self.verified[key(item)] = before
                occupied.add(item["path"].casefold())
                changed = True
            if changed:
                self.save()
        self.apply_markers()

    def convert_renames(self, imports: list, records: dict) -> list:
        """Treat a new X.delete that is a renamed (or copied) X as a request to delete X: a file
        whose bytes match a tracked version of X, or a folder whose every file matches the
        tracked file at the same place under X. Those imports become stamped markers instead of
        new shared content; anything that does not match exactly stays an ordinary import."""
        versions = {(r["file"]["path"], r["file"]["sha256"], r["file"]["size"]) for r in records.values()}
        result, folders = [], {}
        for item, before in imports:
            parts = item["path"].split("/")
            inside = next((i for i in range(len(parts) - 1)
                           if marker_target("/".join(parts[:i + 1])) is not None), None)
            if inside is not None:  # A file under a folder named *.delete.
                folders.setdefault("/".join(parts[:inside + 1]), []).append(
                    (item, before, "/".join(parts[inside + 1:])))
                continue
            target = marker_target(item["path"])
            if (target is not None and item["size"] > 0 and
                    (target, item["sha256"], item["size"]) in versions):
                try:
                    path = self.safe_path(item["path"])
                    self.stamp_marker(path, lambda: self.signature(path) == before)
                    before = self.signature(path)
                    sha, size = fingerprint(path, self.max_file_bytes)
                except (OSError, ValueError):
                    continue  # Changed meanwhile: look again on the next scan.
                self.log(f"{item['path']} is a renamed copy of {target}: converted to a delete marker")
                item = {"path": item["path"], "sha256": sha, "size": size}
            result.append((item, before))
        for prefix, members in folders.items():
            result.extend(self.convert_folder(prefix, members, versions))
        return result

    def convert_folder(self, prefix: str, members: list, versions: set) -> list:
        """Imports to use for folder PREFIX (a *.delete folder): the members unchanged when it is
        not an exact renamed copy of its target, otherwise a single stamped marker at PREFIX."""
        target = marker_target(prefix)
        if (not any(path.startswith(target + "/") for path, _, _ in versions) or
                any((target + "/" + rel, item["sha256"], item["size"]) not in versions
                    for item, _, rel in members)):
            return [(item, before) for item, before, _ in members]
        try:
            folder = self.safe_path(prefix)
            # Nothing else may be inside: no extra, skipped or linked entries.
            on_disk = set()
            for parent, directories, files in os.walk(folder, followlinks=False):
                if any(is_link((Path(parent) / name).lstat()) for name in directories):
                    raise ValueError("folder contains a link")
                on_disk.update((Path(parent) / name).relative_to(folder).as_posix() for name in files)
            if on_disk != {rel for _, _, rel in members}:
                raise ValueError("folder has entries that are not copies of the target")
            for item, before, _ in members:
                if self.signature(self.safe_path(item["path"])) != before:
                    raise ValueError("folder changed while scanning")
        except (OSError, ValueError):
            return [(item, before) for item, before, _ in members]
        try:
            # Its files are exact copies of what the marker deletes everywhere anyway.
            shutil.rmtree(folder)
            self.stamp_marker(folder, lambda: not os.path.lexists(folder))
            before = self.signature(folder)
            sha, size = fingerprint(folder, self.max_file_bytes)
        except (OSError, ValueError) as error:
            self.log(f"could not convert {prefix}/ to a delete marker: {error}")
            return []  # Its copies are (partly) gone; the next scan sees what remains.
        self.log(f"{prefix}/ is a renamed copy of {target}/: converted to a delete marker")
        return [({"path": prefix, "sha256": sha, "size": size}, before)]

    def stamp_marker(self, path: Path, unchanged=None) -> None:
        """Write a marker (creation time and unique ID) at PATH.delete, so all nodes expire it at
        the same moment and each new marker is a distinct version. By default PATH.delete must be
        a newly created empty file; `unchanged` replaces that check for converted renames."""
        temporary = self.safe_path(".peer-sync/tmp/" + uuid.uuid4().hex + ".part", internal=True)
        try:
            with temporary.open("xb") as output:
                output.write(marker_bytes(int(time.time())))
                output.flush()
                os.fsync(output.fileno())
            if not (unchanged() if unchanged else path.lstat().st_size == 0):
                raise ValueError("marker was written to while stamping")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        try:
            path.chmod(0o666)  # Same access for other local processes as replicated files.
        except OSError:
            pass

    def blocked(self, item: dict) -> bool:
        """True for a version an active marker deletes, or an expired marker already removed."""
        with self.lock:
            return (key(item) in self.retired_markers or
                    any(covers(target, item["path"]) for target in self.deleting))

    def apply_markers(self) -> None:
        """Delete everything active markers cover and remove markers that have expired."""
        now = time.time()
        with self.lock:
            active, expired = [], []
            for identifier, record in self.records.items():
                target = marker_target(record["file"]["path"])
                if target is None or identifier not in self.intact:
                    continue
                if identifier not in self.marker_times:
                    created = None
                    if record["file"]["size"] <= MAX_MARKER_BYTES:
                        try:
                            created = marker_created(
                                self.safe_path(record["destination"], internal=True).read_bytes())
                        except (OSError, ValueError):
                            continue  # Unreadable right now; try again on the next scan.
                    self.marker_times[identifier] = created or 0
                created = self.marker_times[identifier]
                if not created:
                    continue  # An ordinary file whose name happens to end in .delete.
                (expired if now >= created + MARKER_TTL_SECONDS else active).append((identifier, target))
            self.deleting = tuple(target for _, target in active)
            removed = []
            for identifier, _ in expired:
                self.retired_markers[identifier] = None
                removed.append((identifier, self.records[identifier], "expired marker"))
            while len(self.retired_markers) > MAX_RETIRED_MARKERS:
                del self.retired_markers[next(iter(self.retired_markers))]
            for identifier, record in self.records.items():
                if any(covers(target, record["file"]["path"]) for target in self.deleting):
                    removed.append((identifier, record, "deleted by marker"))
            if not removed:
                return
            for identifier, _, _ in removed:
                self.records.pop(identifier, None)
                self.intact.discard(identifier)
                self.verified.pop(identifier, None)
                self.marker_times.pop(identifier, None)
            # Forget the versions first: a crash before unlinking leaves untracked files that
            # the next scan imports and the still-active marker deletes again.
            self.save()
            for _, record, reason in removed:
                try:
                    path = self.safe_path(record["destination"], internal=True)
                    path.unlink(missing_ok=True)
                    self.remove_empty_parents(path)
                except (OSError, ValueError) as error:
                    self.log(f"could not remove {record['destination']}: {error}")
                    continue
                self.log(f"{reason}: removed {record['destination']}")

    def remove_empty_parents(self, path: Path) -> None:
        for parent in path.parents:
            if parent == self.root or parent == self.state or not parent.is_relative_to(self.root):
                return
            try:
                parent.rmdir()
            except OSError:
                return  # Not empty (or gone): stop here.

    def manifest(self, after: str = "", generation: str | None = None) -> dict:
        with self.lock:
            files = [self.records[identifier]["file"] for identifier in sorted(self.intact)]
        current = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        if generation is not None and generation != current:
            raise ValueError("manifest changed; restart pagination")
        page = [item for item in files if key(item) > after][:MANIFEST_PAGE]
        last = key(page[-1]) if page else after
        more = any(key(item) > last for item in files)
        return {"files": page, "generation": current, "next_after": last if more else None}

    def validate_request(self, request: dict) -> None:
        if request["type"] == "file-manifest":
            after = request.get("after", "")
            if not isinstance(after, str) or len(after) > 305:
                raise ValueError("invalid manifest cursor")
            if after:
                path, sha = after.split("\0")
                logical_path(path)
                digest(sha)
            if request.get("generation") is not None:
                digest(request["generation"])
        elif request["type"] == "file-chunk":
            item = entry(request.get("file"), self.max_file_bytes)
            integer(request.get("offset"), "chunk offset", 0, max(0, item["size"] - 1))
        else:
            raise ValueError("unsupported file request")

    def chunk(self, item: dict, offset: int) -> dict:
        with self.lock:
            record = self.records.get(key(item))
            if record is None or key(item) not in self.intact or record["file"] != item:
                raise ValueError("file unavailable")
            path = self.safe_path(record["destination"], internal=True)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != item["size"]:
                raise ValueError("file changed")
            with path.open("rb") as source:
                opened = os.fstat(source.fileno())
                if (info.st_ino, info.st_dev) != (opened.st_ino, opened.st_dev):
                    raise ValueError("file changed")
                source.seek(offset)
                data = source.read(min(CHUNK_BYTES, item["size"] - offset))
        return {"file": item, "offset": offset, "data": base64.b64encode(data).decode("ascii")}

    def has_copy(self, item: dict) -> bool:
        # Relies on the latest scan() or install() rather than rehashing per manifest entry.
        with self.lock:
            record = self.records.get(key(item))
            return record is not None and record["file"] == item and key(item) in self.intact

    def can_receive(self, item: dict) -> bool:
        with self.lock:
            known = key(item) in self.records
            if not known and len(self.records) >= self.max_files:
                return False
            total = sum(record["file"]["size"] for record in self.records.values())
            if total + (0 if known else item["size"]) > self.max_shared_bytes:
                return False
        return shutil.disk_usage(self.root).free >= item["size"] + 1024 * 1024

    def install(self, item: dict, temporary: Path) -> Path:
        # Check the whole file independently before any visible destination changes.
        if fingerprint(temporary, self.max_file_bytes) != (item["sha256"], item["size"]):
            raise ValueError("download failed integrity verification")
        with self.lock:
            if self.blocked(item):
                raise ValueError("removed by a .delete marker")
            if not self.can_receive(item):
                raise ValueError("replication storage limit exceeded")
            record = self.records.get(key(item))
            if record:
                relative = record["destination"]
            else:
                occupied = {value["destination"].casefold() for value in self.records.values()}
                relative = item["path"]
                destination = self.safe_path(relative)
                parent_is_file = any(path.exists() and not path.is_dir()
                                     for path in destination.parents if path != self.root)
                if relative.casefold() in occupied or destination.exists() or parent_is_file:
                    relative = self.conflict_path(item)
            destination = self.safe_path(relative, internal=True)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination = self.safe_path(relative, internal=True)
            if destination.exists():
                try:
                    already_intact = fingerprint(destination, self.max_file_bytes) == (item["sha256"], item["size"])
                except ValueError:
                    already_intact = False
                if already_intact:
                    temporary.unlink()
                    self.records[key(item)] = {"file": item, "destination": relative}
                    self.intact.add(key(item))
                    self.save()
                    return destination
                # Retain changed/damaged bytes locally rather than discarding them.
                quarantine = self.safe_path(".peer-sync/quarantine", internal=True)
                quarantine.mkdir(exist_ok=True)
                if shutil.disk_usage(self.root).free < destination.stat().st_size + 1024 * 1024:
                    raise ValueError("not enough space to preserve damaged bytes")
                shutil.copyfile(destination, quarantine / (uuid.uuid4().hex + ".bak"))
            old = self.records.get(key(item))
            self.records[key(item)] = {"file": item, "destination": relative}
            try:
                # Persist expected bytes first, so a crash cannot import a partial copy as new content.
                self.save()
                os.replace(temporary, destination)
            except Exception:
                if old is None:
                    self.records.pop(key(item), None)
                else:
                    self.records[key(item)] = old
                raise
            self.intact.add(key(item))
            # Other local processes need read/write access to replicas. Grant it only now, after
            # the bytes were verified and installed, so nobody can alter them before the check.
            try:
                destination.chmod(0o666)
            except OSError as error:
                raise OSError(f"installed, but could not make it world-writable: {error}") from error
            return destination


class FileReplicator:
    def __init__(self, node, store: FileStore, log):
        self.node, self.store, self.log = node, store, log
        store.log = log
        self.sync_lock = threading.Lock()
        # Last complete manifest fetched from each peer, keyed by peer: (generation, files).
        self.manifests: dict = {}

    def request(self, peer, kind: str, **fields) -> dict:
        request = self.node.message(kind)
        request.update(fields)
        reply = self.node.exchange(peer, request)
        if not isinstance(reply, dict) or reply.get("type") not in (kind + "-result", "file-error"):
            raise ValueError("unexpected file response")
        self.node.handle_message(reply, expected_peer=peer)
        if reply["type"] == "file-error":
            raise ValueError("peer could not serve file request")
        return reply

    def remote_manifest(self, peer) -> list[dict]:
        after = ""
        generation = None
        files = []
        while True:
            if self.node.stop_event.is_set():
                raise InterruptedError("replication stopped")
            response = self.request(peer, "file-manifest", after=after, generation=generation)
            current = digest(response.get("generation"))
            if generation is None:
                # The generation hashes the peer's whole manifest: if it matches the last complete
                # fetch, the list is identical, so skip the remaining pages and reuse it.
                cached = self.manifests.get(peer)
                if cached is not None and cached[0] == current:
                    return list(cached[1])
            elif generation != current:
                raise ValueError("manifest changed")
            generation = current
            page = response.get("files")
            if not isinstance(page, list) or len(page) > MANIFEST_PAGE:
                raise ValueError("invalid manifest page")
            parsed = [entry(value, 2**63 - 1) for value in page]
            for value in parsed:
                if key(value) <= after:
                    raise ValueError("unordered or repeated manifest entry")
                after = key(value)
                files.append(value)
            if len(files) > MAX_FILES:
                raise ValueError("manifest exceeds file limit")
            next_after = response.get("next_after")
            if next_after is None:
                self.manifests[peer] = (generation, files)
                return list(files)
            if not parsed or next_after != after:
                raise ValueError("invalid manifest continuation")

    def download(self, peer, item: dict) -> None:
        if not self.store.can_receive(item):
            raise ValueError("replication storage limit exceeded")
        self.store.ensure_layout()
        temporary = self.store.safe_path(".peer-sync/tmp/" + uuid.uuid4().hex + ".part", internal=True)
        deadline = time.monotonic() + FILE_DEADLINE_SECONDS
        sha = hashlib.sha256()
        try:
            # Owner-only until install() has verified and moved it into place.
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(descriptor, "wb") as output:
                offset = 0
                while offset < item["size"]:
                    if self.node.stop_event.is_set() or time.monotonic() >= deadline:
                        raise InterruptedError("file transfer interrupted or timed out")
                    response = self.request(peer, "file-chunk", file=item, offset=offset)
                    if response.get("file") != item or response.get("offset") != offset:
                        raise ValueError("file chunk does not match request")
                    encoded = response.get("data")
                    if not isinstance(encoded, str) or len(encoded) > 4 * ((CHUNK_BYTES + 2) // 3):
                        raise ValueError("invalid chunk size")
                    data = base64.b64decode(encoded, validate=True)
                    if len(data) != min(CHUNK_BYTES, item["size"] - offset):
                        raise ValueError("truncated file chunk")
                    output.write(data)
                    sha.update(data)
                    offset += len(data)
                output.flush()
                os.fsync(output.fileno())
            if sha.hexdigest() != item["sha256"]:
                raise ValueError("download SHA-256 mismatch")
            installed = self.store.install(item, temporary)
            self.log(f"replicated {item['path']} from {peer.address()} to {installed}")
        finally:
            temporary.unlink(missing_ok=True)

    def sync_once(self) -> None:
        if not self.sync_lock.acquire(blocking=False):
            return
        try:
            self.store.scan()
            with self.node.peers_lock:
                peers = [peer for peer, record in self.node.profiles.items()
                         if peer in self.node.confirmed and record["expires_at"] > time.monotonic()
                         and "file-replication" in record["profile"]["capabilities"]]
            self.manifests = {peer: cached for peer, cached in self.manifests.items() if peer in peers}
            for peer in peers:
                if self.node.stop_event.is_set():
                    return
                try:
                    manifest = self.remote_manifest(peer)
                    # Delete markers first, so this pass never fetches files a marker removes.
                    markers = [item for item in manifest if marker_target(item["path"]) is not None]
                    others = [item for item in manifest if marker_target(item["path"]) is None]
                    downloaded = 0
                    for batch in (markers, others):
                        for item in batch:
                            if self.node.stop_event.is_set():
                                return
                            if (item["size"] > self.store.max_file_bytes or self.store.has_copy(item) or
                                    self.store.blocked(item)):
                                continue
                            try:
                                self.download(peer, item)
                            except (OSError, ValueError, TypeError, KeyError) as error:
                                self.log(f"could not replicate {item['path']} from {peer.address()}: {error}")
                                continue
                            downloaded += 1
                            if downloaded >= MAX_DOWNLOADS_PER_PASS:
                                break
                        if batch is markers and markers:
                            self.store.apply_markers()
                        if downloaded >= MAX_DOWNLOADS_PER_PASS:
                            break
                except (OSError, ValueError, TypeError, KeyError) as error:
                    self.log(f"file sync with {peer.address()} failed: {error}")
        finally:
            self.sync_lock.release()

    def run(self) -> None:
        while not self.node.stop_event.is_set():
            try:
                self.sync_once()
            except Exception as error:
                # Never let one bad pass (or peer reply) stop replication for the node's lifetime.
                self.log(f"file sync pass failed: {error!r}")
            if self.node.stop_event.wait(SYNC_INTERVAL_SECONDS):
                return
