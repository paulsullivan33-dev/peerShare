"""Trusted release packaging and verification, shared by publisher and launcher."""

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import stat
import sys
import uuid
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LAUNCHER_VERSION = 1
APPLICATION = "peerHandshake"
APPLICATION_FILES = ("peer_handshake.py", "peer_protocol.py", "peer_files.py", "peer_runtime.py")
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as output:
            output.write(canonical(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def regular(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            getattr(info, "st_file_attributes", 0) & 0x400):
        raise ValueError(f"expected a regular unlinked file: {path.name}")


def safe_directory(path: Path) -> Path:
    path = path.absolute()
    for parent in (path, *path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("installation paths cannot contain links or junctions")
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


class InstanceLock:
    def __init__(self, path: Path):
        if path.exists():
            regular(path)
        self.handle = path.open("a+b")
        try:
            if self.handle.seek(0, os.SEEK_END) == 0:
                self.handle.write(b"0")
                self.handle.flush()
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.handle.close()
            raise ValueError("another launcher owns this installation") from error

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.handle.close()


def public_key(path: Path) -> Ed25519PublicKey:
    regular(path)
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("trusted release key must be Ed25519")
    return key


def generate_keys(private_path: Path, public_path: Path) -> None:
    if private_path.exists() or public_path.exists():
        raise ValueError("refusing to overwrite an existing signing key")
    key = Ed25519PrivateKey.generate()
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    with public_path.open("xb") as output:
        output.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))


def validate_manifest(manifest: object) -> dict:
    required = {"format", "application", "release", "platforms", "python_min", "launcher_min",
                "state_schema", "files"}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ValueError("invalid release manifest")
    for name, expected in (("format", 1), ("launcher_min", 1), ("state_schema", 1)):
        if type(manifest[name]) is not int or manifest[name] != expected:
            raise ValueError(f"unsupported {name}")
    if manifest["application"] != APPLICATION:
        raise ValueError("package is for a different application")
    if type(manifest["release"]) is not int or not 1 <= manifest["release"] <= 2**31 - 1:
        raise ValueError("release must be a positive increasing integer")
    if manifest["platforms"] != ["linux", "windows"] or manifest["python_min"] != [3, 10]:
        raise ValueError("release must support Linux and Windows on Python 3.10+")
    if platform.system().lower() not in manifest["platforms"] or sys.version_info[:2] < (3, 10):
        raise ValueError("unsupported operating system or Python runtime")
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != set(APPLICATION_FILES):
        raise ValueError("release must contain exactly the supported application files")
    for name, details in files.items():
        if (not isinstance(details, dict) or set(details) != {"size", "sha256"} or
                type(details["size"]) is not int or not 0 < details["size"] <= MAX_FILE_BYTES or
                not isinstance(details["sha256"], str) or len(details["sha256"]) != 64 or
                any(character not in "0123456789abcdef" for character in details["sha256"])):
            raise ValueError(f"invalid file metadata: {name}")
    if sum(item["size"] for item in files.values()) > MAX_PACKAGE_BYTES:
        raise ValueError("release is too large")
    return manifest


def build_package(source: Path, private_path: Path, release: int, destination: Path) -> None:
    regular(private_path)
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("release signing key must be Ed25519")
    contents = {}
    for name in APPLICATION_FILES:
        path = source / name
        regular(path)
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("application file exceeds size limit")
        contents[name] = path.read_bytes()
    manifest = validate_manifest({
        "format": 1, "application": APPLICATION, "release": release,
        "platforms": ["linux", "windows"], "python_min": [3, 10], "launcher_min": 1,
        "state_schema": 1,
        "files": {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in contents.items()},
    })
    payload = canonical(manifest)
    temporary = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", payload)
            archive.writestr("signature.ed25519", key.sign(payload))
            for name, data in contents.items():
                archive.writestr("files/" + name, data)
        if temporary.stat().st_size > MAX_PACKAGE_BYTES:
            raise ValueError("package exceeds size limit")
        # Exclusive publication prevents accidental reuse of an immutable release filename.
        with destination.open("xb") as output, temporary.open("rb") as source_file:
            shutil.copyfileobj(source_file, output)
    finally:
        temporary.unlink(missing_ok=True)


def verify_signature(payload: bytes, signature: bytes, key: Ed25519PublicKey) -> dict:
    if len(payload) > 16384 or len(signature) != 64:
        raise ValueError("invalid manifest or signature size")
    try:
        key.verify(signature, payload)
    except InvalidSignature as error:
        raise ValueError("release signature is not trusted") from error
    manifest = validate_manifest(json.loads(payload))
    if canonical(manifest) != payload:
        raise ValueError("manifest is not canonical JSON")
    return manifest


def verify_package(path: Path, key: Ed25519PublicKey) -> tuple[dict, dict[str, bytes], bytes, bytes]:
    regular(path)
    if path.stat().st_size > MAX_PACKAGE_BYTES:
        raise ValueError("package exceeds size limit")
    with path.open("rb") as source:
        data = source.read(MAX_PACKAGE_BYTES + 1)
    if len(data) > MAX_PACKAGE_BYTES:
        raise ValueError("package exceeds size limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        expected = {"manifest.json", "signature.ed25519", *("files/" + name for name in APPLICATION_FILES)}
        infos = archive.infolist()
        if len(infos) != len(expected) or {item.filename for item in infos} != expected:
            raise ValueError("unexpected, duplicate, or unsafe archive path")
        for item in infos:
            mode = item.external_attr >> 16
            if item.is_dir() or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError("archive contains a link or special file")
            limit = 16384 if item.filename == "manifest.json" else (64 if item.filename == "signature.ed25519" else MAX_FILE_BYTES)
            if item.file_size > limit or item.flag_bits & 1:
                raise ValueError("archive entry is oversized or encrypted")
        payload, signature = archive.read("manifest.json"), archive.read("signature.ed25519")
        manifest = verify_signature(payload, signature, key)
        contents = {}
        for name, metadata in manifest["files"].items():
            content = archive.read("files/" + name)
            if len(content) != metadata["size"] or hashlib.sha256(content).hexdigest() != metadata["sha256"]:
                raise ValueError(f"release content hash mismatch: {name}")
            contents[name] = content
    return manifest, contents, payload, signature


def verify_directory(directory: Path, key: Ed25519PublicKey) -> dict:
    safe_directory(directory)
    regular(directory / "manifest.json")
    regular(directory / "signature.ed25519")
    manifest = verify_signature((directory / "manifest.json").read_bytes(),
                                (directory / "signature.ed25519").read_bytes(), key)
    expected = set(APPLICATION_FILES) | {"manifest.json", "signature.ed25519"}
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError("installed release has unexpected files")
    for name, metadata in manifest["files"].items():
        path = directory / name
        regular(path)
        if path.stat().st_size != metadata["size"] or hashlib.sha256(path.read_bytes()).hexdigest() != metadata["sha256"]:
            raise ValueError("installed release integrity check failed")
    return manifest


def stage_package(path: Path, releases: Path, key: Ed25519PublicKey) -> dict:
    manifest, contents, payload, signature = verify_package(path, key)
    releases = safe_directory(releases)
    destination = releases / str(manifest["release"])
    if destination.exists():
        if verify_directory(destination, key) != manifest:
            raise ValueError("release number already has different content")
        return manifest
    temporary = releases / (".stage-" + uuid.uuid4().hex)
    temporary.mkdir()
    try:
        for name, content in {**contents, "manifest.json": payload, "signature.ed25519": signature}.items():
            with (temporary / name).open("xb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        temporary.rename(destination)
    finally:
        if temporary.exists():
            # Only the generated staging child can be removed; never a release or user directory.
            if temporary.parent.resolve() != releases or not temporary.name.startswith(".stage-"):
                raise ValueError("unsafe staging cleanup")
            shutil.rmtree(temporary)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Create signed peerHandshake releases")
    commands = parser.add_subparsers(dest="command", required=True)
    keys = commands.add_parser("keygen")
    keys.add_argument("--private-key", type=Path, required=True)
    keys.add_argument("--public-key", type=Path, required=True)
    build = commands.add_parser("build")
    build.add_argument("--source", type=Path, default=Path(__file__).parent)
    build.add_argument("--private-key", type=Path, required=True)
    build.add_argument("--release", type=int, required=True)
    build.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            generate_keys(args.private_key, args.public_key)
        else:
            build_package(args.source, args.private_key, args.release, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
