#!/usr/bin/env python3
"""Small peer-to-peer handshake service."""

import argparse
import heapq
import itertools
import json
import ipaddress
import queue
import socket
import sys
import os
import signal
import threading
import time
import uuid
from collections import OrderedDict
from pathlib import Path

from peer_protocol import (PROTOCOL_VERSION, PROFILE_TTL_SECONDS, MAX_QUERY_RESULTS,
                           AVAILABILITY, validate_profile, make_profile, load_node_id,
                           text, integer)
from dataclasses import dataclass
from peer_runtime import RuntimeControl
from peer_files import (FileStore, FileReplicator, REQUEST_TYPES, RESPONSE_TYPES,
                        DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_SHARED_BYTES)


DISCOVERY_INTERVAL_SECONDS = 30
CONFIRMATION_TTL_SECONDS = 90
PEER_TTL_SECONDS = 300
MAINTENANCE_INTERVAL_SECONDS = 5
DEFAULT_ALLOWED_NETWORKS = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
RETRY_COOLDOWN_SECONDS = 60
MAX_RETRIES = 10
RETRY_DELAY_SECONDS = 2
CONNECT_TIMEOUT_SECONDS = 3
HANDSHAKE_TIMEOUT_SECONDS = 5
MAX_MESSAGE_BYTES = 65536
MAX_PEERS = 128
MAX_INBOUND_CONNECTIONS = 32
MAX_RETRY_WORKERS = 8


def read_message(connection: socket.socket) -> object:
    # A total deadline also prevents slow clients from keeping a worker forever.
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT_SECONDS
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("handshake deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, MAX_MESSAGE_BYTES + 1 - len(data)))
        if not chunk:
            raise ValueError("connection closed before newline")
        data.extend(chunk)
        newline = data.find(b"\n")
        if newline >= 0:
            if newline + 1 > MAX_MESSAGE_BYTES:
                raise ValueError("message too large")
            try:
                return json.loads(data[:newline].decode("utf-8"))
            except RecursionError as error:
                # Deeply nested JSON fits within the size limit but exhausts the parser's stack.
                raise ValueError("message nesting too deep") from error
        if len(data) >= MAX_MESSAGE_BYTES:
            raise ValueError("message too large")


def timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def log(message: str) -> None:
    print(f"[{timestamp()}] {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True, order=True)
class Peer:
    host: str
    port: int

    def __post_init__(self) -> None:
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(self.host, str):
            raise ValueError("host must be a numeric IPv4 address")
        address = ipaddress.IPv4Address(self.host)
        if address.is_unspecified or address.is_multicast or int(address) == 0xffffffff:
            raise ValueError("peer host must be a unicast IPv4 address")

    def address(self) -> str:
        return f"{self.host}:{self.port}"


class PeerNode:
    def __init__(self, host: str, port: int, initial_peer: Peer | None,
                 advertise_host: str | None = None,
                 allowed_networks: list[str] | None = None, *,
                 node_id_file: str | Path | None = None, name: str | None = None,
                 capabilities: list[str] | None = None, services: list[dict] | None = None,
                 availability: str = "ready", resources: dict | None = None,
                 shared_dir: str | Path | None = None,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 max_shared_bytes: int = DEFAULT_MAX_SHARED_BYTES,
                 runtime_dir: str | Path | None = None, release_id: int = 0,
                 lease_timeout: float = 90) -> None:
        ipaddress.IPv4Address(host)  # Never resolve hostnames, including the bind address.
        advertised = advertise_host or host
        if ipaddress.IPv4Address(advertised).is_unspecified:
            raise ValueError("wildcard binding requires --advertise-host with this machine's reachable IPv4 address")
        self.allowed_networks = tuple(ipaddress.IPv4Network(value, strict=False)
                                     for value in (DEFAULT_ALLOWED_NETWORKS if allowed_networks is None
                                                   else allowed_networks))
        self.bind_host = host
        self.identity = Peer(advertised, port)
        if not self.host_allowed(self.identity.host):
            raise ValueError("advertised address is outside --allow-network ranges")
        if initial_peer and not self.host_allowed(initial_peer.host):
            raise ValueError("initial peer is outside --allow-network ranges")
        self.initial_peer = initial_peer
        self.peers: set[Peer] = set()
        # One lock keeps membership, expiry and retry bookkeeping consistent.
        self.peers_lock = threading.RLock()
        self.retrying_lock = self.peers_lock
        self.confirmed: set[Peer] = set()
        self.retry_after: dict[Peer, float] = {}
        self.last_seen: dict[Peer, float] = {}
        self.last_probe: dict[Peer, float] = {}
        self.retrying: set[Peer] = set()
        # Heap of (due time, sequence, peer, force, started, attempt) for delayed retry attempts.
        self.retry_schedule: list[tuple] = []
        self.retry_sequence = itertools.count()
        self.inbound_slots = threading.BoundedSemaphore(MAX_INBOUND_CONNECTIONS)
        self.retry_queue = queue.Queue(maxsize=MAX_PEERS)
        self.retry_workers_started = False
        self.stop_event = threading.Event()
        node_id = load_node_id(node_id_file) if node_id_file is not None else str(uuid.uuid4())
        capabilities = list(capabilities or [])
        services = list(services or [])
        if shared_dir is not None:
            if "file-replication" not in capabilities:
                capabilities.append("file-replication")
            services.append({"name": "replication", "capability": "file-replication", "port": port})
        self.local_profile = make_profile(node_id, name or self.identity.address(),
                                          capabilities, services, availability, resources)
        self.profiles: dict[Peer, dict] = {}
        self.retired_instances: OrderedDict[str, list[str]] = OrderedDict()
        self.shutting_down = False
        self.file_store = FileStore(shared_dir, max_file_bytes, max_shared_bytes) if shared_dir is not None else None
        self.file_replicator = FileReplicator(self, self.file_store, log) if self.file_store else None
        self.runtime_control = RuntimeControl(self, runtime_dir, release_id,
                                              os.environ.get("PEER_LAUNCH_TOKEN", ""),
                                              lease_timeout) if runtime_dir else None

    def host_allowed(self, host: str) -> bool:
        try:
            address = ipaddress.IPv4Address(host)
        except (ValueError, TypeError):
            return False
        return any(address in network for network in self.allowed_networks)

    def peer_list(self) -> list[dict[str, object]]:
        with self.peers_lock:
            peers = sorted(self.confirmed | {self.identity})
        return [{"host": peer.host, "port": peer.port} for peer in peers]

    def add_peer(self, peer: Peer) -> bool:
        if peer == self.identity or not self.host_allowed(peer.host):
            return False
        with self.peers_lock:
            is_new = peer not in self.peers
            if is_new and len(self.peers) >= MAX_PEERS:
                return False
            self.peers.add(peer)
            if is_new:
                self.last_seen[peer] = time.monotonic()
        if is_new:
            log(f"discovered {peer.address()}")
        return is_new

    def message(self, kind: str = "hello") -> dict[str, object]:
        with self.peers_lock:
            profile = validate_profile(self.local_profile)
        message = {"type": kind, "protocol_version": PROTOCOL_VERSION,
                   "host": self.identity.host, "port": self.identity.port,
                   "profile": profile}
        if kind == "hello":
            message["peers"] = self.peer_list()
        return message

    def update_status(self, *, availability: str | None = None,
                      resources: dict | None = None) -> None:
        with self.peers_lock:
            profile = dict(self.local_profile)
            if availability is not None:
                profile["availability"] = availability
            if resources is not None:
                profile["resources"] = resources
            profile["sequence"] += 1
            self.local_profile = validate_profile(profile)

    def exchange(self, peer: Peer, message: dict) -> object:
        if not self.host_allowed(peer.host):
            raise ValueError("peer is outside allowed networks")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(CONNECT_TIMEOUT_SECONDS)
            connection.bind((self.identity.host, 0))
            connection.connect((peer.host, peer.port))
            self.send_message(connection, message)
            return read_message(connection)

    def send_hello(self, peer: Peer, reason: str = "handshake") -> bool:
        log(f"{reason} -> {peer.address()}")
        try:
            reply = self.exchange(peer, self.message())
            if not isinstance(reply, dict) or reply.get("type") != "hello":
                raise ValueError("expected hello reply")
            self.handle_message(reply, expected_peer=peer)
            self.confirm_peer(peer)
            log(f"handshake succeeded with {peer.address()}")
            return True
        except (OSError, KeyError, TypeError, ValueError) as error:
            log(f"handshake failed with {peer.address()}: {error}")
            return False

    def send_status(self, peer: Peer) -> None:
        reply = self.exchange(peer, self.message("status"))
        if not isinstance(reply, dict) or reply.get("type") != "status":
            raise ValueError("expected status reply")
        self.handle_message(reply, expected_peer=peer)

    def send_message(self, connection: socket.socket, message: dict | None = None) -> None:
        data = (json.dumps(self.message() if message is None else message, allow_nan=False) + "\n").encode()
        if len(data) > MAX_MESSAGE_BYTES:
            raise ValueError("message too large")
        connection.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
        connection.sendall(data)

    def forget_peer(self, peer: Peer) -> None:
        # Call under the state lock; in-flight workers check membership before retrying.
        self.peers.discard(peer)
        self.confirmed.discard(peer)
        self.last_seen.pop(peer, None)
        self.last_probe.pop(peer, None)
        self.retry_after.pop(peer, None)
        self.profiles.pop(peer, None)

    def retire_instance(self, node_id: str, instance_id: str) -> None:
        retired = self.retired_instances.setdefault(node_id, [])
        if instance_id not in retired:
            retired.append(instance_id)
        del retired[:-8]
        self.retired_instances.move_to_end(node_id)
        while len(self.retired_instances) > MAX_PEERS:
            self.retired_instances.popitem(last=False)

    def service_results(self, capability: str, offset: int = 0, limit: int = MAX_QUERY_RESULTS) -> dict:
        text(capability, "capability")
        integer(offset, "offset", 0, MAX_PEERS + 1)
        integer(limit, "limit", 1, MAX_QUERY_RESULTS)
        now = time.monotonic()
        with self.peers_lock:
            records = [(self.identity, self.local_profile, PROFILE_TTL_SECONDS, "self")]
            for peer, record in self.profiles.items():
                ttl = int(record["expires_at"] - now)
                if peer in self.confirmed and ttl > 0:
                    records.append((peer, record["profile"], ttl, "direct"))
            matches = []
            for peer, profile, ttl, source in sorted(records, key=lambda item: item[0]):
                if capability not in profile["capabilities"]:
                    continue
                profile = validate_profile(profile)
                profile["ttl_seconds"] = min(ttl, PROFILE_TTL_SECONDS)
                matches.append({"host": peer.host, "port": peer.port, "profile": profile,
                                "source": source, "reported_by": self.local_profile["node_id"]})
        end = offset + limit
        return {"capability": capability, "results": matches[offset:end], "total": len(matches),
                "next_offset": end if end < len(matches) else None}

    def query_services(self, peer: Peer, capability: str, offset: int = 0,
                       limit: int = MAX_QUERY_RESULTS) -> dict:
        text(capability, "capability")
        integer(offset, "offset", 0, MAX_PEERS + 1)
        integer(limit, "limit", 1, MAX_QUERY_RESULTS)
        request = self.message("service-query")
        request.update(capability=capability, offset=offset, limit=limit)
        reply = self.exchange(peer, request)
        self.validate_service_reply(reply, peer, capability, offset, limit)
        self.handle_message(reply, expected_peer=peer)
        # Evidence is relative to this node, not the intermediary that replied.
        for result in reply["results"]:
            result["source"] = "direct" if result["source"] == "self" else "relayed"
        return reply

    def validate_service_reply(self, reply: object, peer: Peer, capability: str,
                               offset: int, limit: int) -> None:
        if not isinstance(reply, dict) or reply.get("type") != "service-result":
            raise ValueError("expected service-result reply")
        if reply.get("capability") != capability:
            raise ValueError("service reply capability mismatch")
        profile = validate_profile(reply.get("profile"))
        results = reply.get("results")
        if not isinstance(results, list) or len(results) > limit:
            raise ValueError("invalid service results")
        total = integer(reply.get("total"), "total", 0, MAX_PEERS + 1)
        expected_count = min(limit, max(0, total - offset))
        expected_next = offset + limit if offset + limit < total else None
        if len(results) != expected_count or reply.get("next_offset") != expected_next:
            raise ValueError("invalid service pagination")
        endpoints = set()
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("invalid service result")
            endpoint = Peer(result.get("host"), result.get("port"))
            result_profile = validate_profile(result.get("profile"))
            if (not self.host_allowed(endpoint.host) or endpoint in endpoints or
                    capability not in result_profile["capabilities"] or
                    result.get("source") not in ("self", "direct") or
                    result.get("reported_by") != profile["node_id"]):
                raise ValueError("invalid service result provenance")
            if result["source"] == "self" and (endpoint != peer or result_profile != profile):
                raise ValueError("invalid self-reported service result")
            endpoints.add(endpoint)

    def send_goodbye(self, peer: Peer) -> None:
        reply = self.exchange(peer, self.message("goodbye"))
        if (not isinstance(reply, dict) or reply.get("type") != "goodbye-ack" or
                reply.get("host") != peer.host or reply.get("port") != peer.port or
                reply.get("protocol_version") != PROTOCOL_VERSION):
            raise ValueError("invalid goodbye acknowledgement")

    def announce_shutdown(self) -> None:
        with self.peers_lock:
            if self.shutting_down:
                return
            self.shutting_down = True
            self.update_status(availability="draining")
            peers = list(self.confirmed)
        pending = queue.Queue()
        for peer in peers:
            pending.put(peer)

        def notify() -> None:
            while True:
                try:
                    peer = pending.get_nowait()
                except queue.Empty:
                    return
                try:
                    self.send_goodbye(peer)
                except (OSError, ValueError, TypeError):
                    pass  # Planned shutdown is best effort; TTL remains the fallback.
                finally:
                    pending.task_done()

        workers = [threading.Thread(target=notify, daemon=True)
                   for _ in range(min(MAX_RETRY_WORKERS, len(peers)))]
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + CONNECT_TIMEOUT_SECONDS
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))

    def retry_worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                job = self.retry_queue.get(timeout=self.release_due_retries())
            except queue.Empty:
                continue
            try:
                job()
            except Exception as error:
                log(f"retry worker failed: {error}")
            finally:
                self.retry_queue.task_done()

    def confirm_peer(self, peer: Peer) -> None:
        with self.peers_lock:
            if peer not in self.peers:
                return
            self.confirmed.add(peer)
            self.last_seen[peer] = time.monotonic()
            self.retry_after.pop(peer, None)

    def retry_peer(self, peer: Peer, force: bool = False) -> None:
        with self.peers_lock:
            if peer not in self.peers:
                return
            if (peer in self.retrying or (peer in self.confirmed and not force) or
                    time.monotonic() < self.retry_after.get(peer, 0)):
                return
            if len(self.retrying) >= MAX_PEERS:
                return
            if not self.retry_workers_started:
                for _ in range(MAX_RETRY_WORKERS):
                    threading.Thread(target=self.retry_worker, daemon=True).start()
                self.retry_workers_started = True
            self.retrying.add(peer)
            self.last_probe[peer] = time.monotonic()
            started = self.last_probe[peer]
        try:
            self.retry_queue.put_nowait(lambda: self.retry_attempt(peer, force, started, 1))
        except queue.Full:
            with self.retrying_lock:
                self.retrying.discard(peer)

    def retry_attempt(self, peer: Peer, force: bool, started: float, attempt: int) -> None:
        # Each job is one attempt, so an unreachable peer never holds a worker between attempts.
        finished = True
        try:
            if self.stop_event.is_set():
                return
            with self.retrying_lock:
                if peer not in self.peers or (peer in self.confirmed and not force):
                    return
            if self.send_hello(peer, f"retry {attempt}/{MAX_RETRIES}"):
                self.confirm_peer(peer)
                return
            if attempt < MAX_RETRIES:
                with self.retrying_lock:
                    heapq.heappush(self.retry_schedule, (time.monotonic() + RETRY_DELAY_SECONDS,
                                                         next(self.retry_sequence), peer, force,
                                                         started, attempt + 1))
                finished = False
                return
            with self.peers_lock:
                if self.last_seen.get(peer, 0) <= started:
                    self.confirmed.discard(peer)
            log(f"giving up on {peer.address()} after {MAX_RETRIES} attempts")
        finally:
            if finished:
                self.finish_retry(peer)

    def finish_retry(self, peer: Peer) -> None:
        with self.retrying_lock:
            self.retrying.discard(peer)
            if peer in self.peers and peer not in self.confirmed:
                self.retry_after[peer] = time.monotonic() + RETRY_COOLDOWN_SECONDS

    def release_due_retries(self) -> float:
        """Queue delayed attempts that are due, behind already-queued probes.

        Returns how long a worker may wait for work before checking again."""
        now = time.monotonic()
        due = []
        with self.retrying_lock:
            while self.retry_schedule and self.retry_schedule[0][0] <= now:
                due.append(heapq.heappop(self.retry_schedule))
            wait = self.retry_schedule[0][0] - now if self.retry_schedule else 1
        for _, _, peer, force, started, attempt in due:
            try:
                self.retry_queue.put_nowait(
                    lambda peer=peer, force=force, started=started, attempt=attempt:
                    self.retry_attempt(peer, force, started, attempt))
            except queue.Full:
                self.finish_retry(peer)
        return min(1, max(wait, 0.01))

    def handle_message(self, message: object, source_host: str | None = None,
                       expected_peer: Peer | None = None) -> dict:
        if not isinstance(message, dict):
            raise ValueError("message must be an object")
        kind = message.get("type")
        allowed = ("hello", "status", "service-query", "goodbye") + REQUEST_TYPES
        if kind not in allowed and not (kind in ("service-result",) + RESPONSE_TYPES and expected_peer is not None):
            raise ValueError("unsupported message type")
        legacy = kind == "hello" and "protocol_version" not in message and "profile" not in message
        profile = None
        if not legacy:
            integer(message.get("protocol_version"), "protocol_version", PROTOCOL_VERSION, PROTOCOL_VERSION)
            profile = validate_profile(message.get("profile"))
            if profile["node_id"] == self.local_profile["node_id"]:
                raise ValueError("remote node claims this node's identity")

        def parse_item(item: object) -> Peer:
            if not isinstance(item, dict) or "host" not in item or "port" not in item:
                raise ValueError("peer must contain host and port")
            return Peer(item["host"], item["port"])

        remote = parse_item(message)
        if not self.host_allowed(remote.host):
            raise ValueError("sender is outside allowed networks")
        if source_host is not None and remote.host != source_host:
            raise ValueError("advertised sender address does not match TCP source")
        if expected_peer is not None and remote != expected_peer:
            raise ValueError("reply identity does not match contacted peer")
        advertised = message.get("peers", [])
        if not isinstance(advertised, list) or len(advertised) > MAX_PEERS + 1:
            raise ValueError("peers must be a list of at most 129 endpoints")
        if kind != "hello" and advertised:
            raise ValueError("only hello can advertise peers")
        discovered_peers = [parse_item(item) for item in advertised]
        if any(not self.host_allowed(peer.host) for peer in discovered_peers):
            raise ValueError("advertisement contains a peer outside allowed networks")
        if kind == "service-query":
            text(message.get("capability"), "capability")
            integer(message.get("offset", 0), "offset", 0, MAX_PEERS + 1)
            integer(message.get("limit", MAX_QUERY_RESULTS), "limit", 1, MAX_QUERY_RESULTS)
        if kind in REQUEST_TYPES:
            if self.file_store is None:
                raise ValueError("file replication is not enabled")
            self.file_store.validate_request(message)
        # All structural and lifecycle checks precede state mutation.
        with self.peers_lock:
            if profile is not None:
                if profile["instance_id"] in self.retired_instances.get(profile["node_id"], []):
                    raise ValueError("message belongs to a retired instance")
                previous = next(((peer, record["profile"]) for peer, record in self.profiles.items()
                                 if record["profile"]["node_id"] == profile["node_id"]), None)
                if previous:
                    old_peer, old = previous
                    if old["instance_id"] == profile["instance_id"]:
                        if profile["sequence"] < old["sequence"]:
                            raise ValueError("stale profile sequence")
                        comparable = dict(profile, ttl_seconds=old["ttl_seconds"])
                        if profile["sequence"] == old["sequence"] and comparable != old:
                            raise ValueError("profile changed without increasing sequence")
                    if kind == "goodbye" and (old_peer != remote or old["instance_id"] != profile["instance_id"]):
                        raise ValueError("goodbye does not match current instance")
                if kind == "goodbye":
                    if previous:
                        self.forget_peer(remote)
                        self.retire_instance(profile["node_id"], profile["instance_id"])
                    return self.message("goodbye-ack")
                if previous:
                    old_peer, old = previous
                    if old["instance_id"] != profile["instance_id"]:
                        self.retire_instance(old["node_id"], old["instance_id"])
                    if old_peer != remote:
                        self.forget_peer(old_peer)
            self.add_peer(remote)
            self.confirm_peer(remote)
            if profile is not None and remote in self.peers:
                self.profiles[remote] = {"profile": profile,
                                         "expires_at": time.monotonic() + profile["ttl_seconds"]}
            for discovered in discovered_peers:
                self.add_peer(discovered)
        for discovered in discovered_peers:
            self.retry_peer(discovered)
        if kind == "service-query":
            with self.peers_lock:
                reply = self.message("service-result")
                reply.update(self.service_results(message["capability"], message.get("offset", 0),
                                                  message.get("limit", MAX_QUERY_RESULTS)))
                return reply
        if kind in REQUEST_TYPES:
            try:
                if kind == "file-manifest":
                    payload = self.file_store.manifest(message.get("after", ""), message.get("generation"))
                else:
                    payload = self.file_store.chunk(message["file"], message["offset"])
                reply = self.message(kind + "-result")
                reply.update(payload)
                return reply
            except (OSError, ValueError):
                reply = self.message("file-error")
                reply["error"] = "file or manifest unavailable; retry on the next sync"
                return reply
        return self.message("hello" if kind == "hello" else "status")

    def serve_connection(self, connection: socket.socket, address: tuple[str, int]) -> None:
        try:
            with connection:
                request = read_message(connection)
                reply = self.handle_message(request, source_host=address[0])
                self.send_message(connection, reply)
                if request["type"] not in REQUEST_TYPES:
                    log(f"{request['type']} received from {address[0]}:{address[1]}")
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            log(f"invalid handshake from {address[0]}:{address[1]}: {error}")

    def accept_connection(self, connection: socket.socket, address: tuple[str, int]) -> bool:
        if not self.host_allowed(address[0]) or not self.inbound_slots.acquire(blocking=False):
            connection.close()
            return False

        def serve() -> None:
            try:
                self.serve_connection(connection, address)
            finally:
                self.inbound_slots.release()

        try:
            threading.Thread(target=serve, daemon=True).start()
        except Exception:
            connection.close()
            self.inbound_slots.release()
            raise
        return True

    def maintain_peers(self) -> None:
        # A goodbye (e.g. the initial peer restarting for a release switch) forgets it via
        # forget_peer(); without this, a peer with no reverse --connect back to us would be
        # permanently unreachable afterward, since nothing else ever re-adds it.
        if self.initial_peer is not None:
            self.add_peer(self.initial_peer)
        now = time.monotonic()
        with self.peers_lock:
            for peer in list(self.peers):
                age = now - self.last_seen[peer]
                if age >= CONFIRMATION_TTL_SECONDS:
                    self.confirmed.discard(peer)
                if age >= PEER_TTL_SECONDS and peer not in self.retrying:
                    self.forget_peer(peer)
                    log(f"expired {peer.address()}")
            # Sort by oldest probe so busy networks do not starve some peers.
            due = sorted((peer for peer in self.peers
                          if now - self.last_probe.get(peer, float("-inf")) >= DISCOVERY_INTERVAL_SECONDS),
                         key=lambda peer: self.last_probe.get(peer, float("-inf")))
        for peer in due:
            self.retry_peer(peer, force=True)

    def maintenance_loop(self) -> None:
        while not self.stop_event.wait(MAINTENANCE_INTERVAL_SECONDS):
            self.maintain_peers()

    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_host, self.identity.port))
            server.listen()
            server.settimeout(1)
            log(f"listening on {self.bind_host}:{self.identity.port}; advertising {self.identity.address()}")
            if self.initial_peer:
                self.add_peer(self.initial_peer)
                self.retry_peer(self.initial_peer)
            threading.Thread(target=self.maintenance_loop, daemon=True).start()
            sync_thread = None
            if self.file_replicator is not None:
                sync_thread = threading.Thread(target=self.file_replicator.run, daemon=True)
                sync_thread.start()
                log(f"replicating shared directory {self.file_store.root}")
            try:
                while not self.stop_event.is_set():
                    if self.runtime_control is not None:
                        self.runtime_control.poll()
                        if self.stop_event.is_set():
                            break
                    try:
                        connection, address = server.accept()
                    except socket.timeout:
                        continue
                    self.accept_connection(connection, address)
            finally:
                self.stop_event.set()
                self.announce_shutdown()
                if sync_thread is not None:
                    sync_thread.join(CONNECT_TIMEOUT_SECONDS + 2 * HANDSHAKE_TIMEOUT_SECONDS + 1)
                    if not sync_thread.is_alive():
                        self.file_store.close()
                if self.runtime_control is not None:
                    self.runtime_control.close()


def parse_peer(value: str) -> Peer:
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("peer must use HOST:PORT")
    try:
        return Peer(host, int(port))
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a peer handshake service.", allow_abbrev=False)
    parser.add_argument("--host", default="127.0.0.1", help="numeric IPv4 bind address")
    parser.add_argument("--advertise-host", help="reachable local IPv4 address; required for wildcard binding")
    parser.add_argument("--port", type=int, required=True, help="local listen port")
    parser.add_argument(
        "--connect",
        type=parse_peer,
        help="initial peer to contact, in IPv4:PORT form",
    )
    parser.add_argument("--allow-network", action="append", metavar="CIDR",
                        help="allowed IPv4 range; repeat to allow multiple ranges. Overrides loopback/private defaults")
    parser.add_argument("--node-id-file", help="persistent identity file (default: .peer-node-PORT.id)")
    parser.add_argument("--name", help="human-readable node name")
    parser.add_argument("--capability", action="append", default=[], help="supported capability; repeatable")
    parser.add_argument("--service", action="append", default=[], metavar="NAME:CAPABILITY:PORT")
    parser.add_argument("--availability", choices=AVAILABILITY, default="ready")
    parser.add_argument("--resource", action="append", default=[], metavar="NAME=COUNT")
    parser.add_argument("--query-service", metavar="CAPABILITY", help="query --connect and print one page, then exit")
    parser.add_argument("--offset", type=int, default=0, help="service-query page offset")
    parser.add_argument("--shared-dir", help="send/receive directory (default: shared-PORT)")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES,
                        help="maximum replicated file size (default: 1 GiB)")
    parser.add_argument("--max-shared-bytes", type=int, default=DEFAULT_MAX_SHARED_BYTES,
                        help="replica download storage budget (default: 10 GiB)")
    parser.add_argument("--runtime-dir", help=argparse.SUPPRESS)
    parser.add_argument("--release-id", type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        services = []
        for value in args.service:
            service_name, capability, port = value.split(":")
            services.append({"name": service_name, "capability": capability, "port": int(port)})
        resources = {}
        for value in args.resource:
            key, count = value.split("=", 1)
            if key in resources:
                raise ValueError("duplicate resource name")
            resources[key] = int(count)
        node = PeerNode(args.host, args.port, args.connect, args.advertise_host, args.allow_network,
                        node_id_file=args.node_id_file or f".peer-node-{args.port}.id", name=args.name,
                        capabilities=args.capability, services=services,
                        availability=args.availability, resources=resources,
                        shared_dir=None if args.query_service else (args.shared_dir or f"shared-{args.port}"),
                        max_file_bytes=args.max_file_bytes, max_shared_bytes=args.max_shared_bytes,
                        runtime_dir=args.runtime_dir, release_id=args.release_id)
        if args.query_service:
            if args.connect is None:
                raise ValueError("--query-service requires --connect")
            print(json.dumps(node.query_services(args.connect, args.query_service, args.offset), indent=2))
            try:
                node.send_goodbye(args.connect)
            except (OSError, ValueError, TypeError):
                pass
            return
    except (ValueError, OSError) as error:
        parser.error(str(error))
    signal.signal(signal.SIGINT, lambda *_: node.stop_event.set())
    signal.signal(signal.SIGTERM, lambda *_: node.stop_event.set())
    node.run()


if __name__ == "__main__":
    main()
