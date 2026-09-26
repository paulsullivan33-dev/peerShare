# Peer handshake service

Python 3.10+ on Windows or Linux. The application and file replication use the standard library; the optional signed-update launcher and publisher also require `cryptography` (see `requirements-updater.txt`).

## Run locally

```sh
python3 peer_handshake.py --port 9101
python3 peer_handshake.py --port 9102 --connect 127.0.0.1:9101
```

## Run on a LAN

Use this machine's actual LAN IP for `--advertise-host` and another node's address for `--connect`:

```sh
python3 peer_handshake.py --host 0.0.0.0 --advertise-host 192.168.1.120 --port 9101 --connect 192.168.1.118:9101 --allow-network 192.168.1.0/24
```

All addresses must be numeric IPv4 addresses. Hostnames (including localhost) are rejected to avoid blocking DNS resolution. Binding to 0.0.0.0 requires a separate reachable advertised address. Ports must be 1 through 65535.

## Network policy

By default, only loopback and RFC 1918 private IPv4 ranges are allowed. Repeat `--allow-network CIDR` to replace those defaults with specific ranges. The policy applies to incoming TCP sources, the local advertised address, initial peers, and all discovered destinations. A greeting containing an out-of-policy endpoint is rejected before changing state. Sender addresses must match their TCP source, and replies must identify the endpoint contacted.

This is a trusted-network service: range restrictions are not authentication or encryption, and permitted clients can still advertise endpoints within the permitted ranges. Choose narrow ranges and restrict access with a firewall. Address translation that changes the advertised source address is not supported.

## Discovery and health

A maintenance pass runs every 5 seconds, scheduling peer-list exchanges when at least 30 seconds have elapsed since the last scheduled probe. Work uses the same bounded retry queue as initial discovery. Confirmations expire after 90 seconds without direct contact. Failed retry batches wait 60 seconds before another attempt; maintenance retries automatically without requiring another advertisement. Each queued job is a single connection attempt: a failed attempt waits its 2-second retry delay outside the worker pool and then rejoins the back of the queue, so unreachable peers cannot tie up workers or delay probes of healthy peers.

Peers with no direct contact for 5 minutes are removed, freeing capacity and deleting their health/retry metadata. Active or queued retries finish before their peer can be removed. Third-party advertisements do not refresh this lifetime. Only confirmed peers and this node's identity appear in outgoing peer lists. An expired peer can be rediscovered later; an isolated node with an empty peer list needs a new connection to rejoin.

Limits: 128 known peers, 32 inbound workers, 8 outbound workers, 64 KiB per message, a 5-second total read deadline, a 5-second send timeout, and a 3-second connection timeout. Health/discovery intervals are scheduling targets; a busy queue can delay probes. Ctrl+C stops maintenance and sends best-effort goodbye notices, with a shared 3-second shutdown wait budget.

## Tests

```sh
python3 -B -m unittest -v
```


## Node profiles

Version 1 greetings include a bounded profile:

- `node_id`: persistent UUID identifying the logical node.
- `instance_id`: a new UUID for each process instance, used to detect restarts.
- `name`: display name, up to 128 characters.
- `protocol_version`: currently `1`; unsupported versions are rejected before changing state.
- `capabilities`: up to 16 capability names, such as `file-search`, `file-transfer`, or `chat`.
- `services`: up to 16 objects containing `name`, `capability`, and `port`. Their host is the node's advertised IPv4 address. A service must reference a declared capability.
- `availability`: `ready`, `busy`, or `draining`.
- `resources`: up to 16 named nonnegative integer counters, such as `shared_files`, `free_bytes`, or `transfer_slots`. Name counters with their units where relevant.
- `sequence`: increases when local status changes; older updates and conflicting updates with the same sequence are rejected.
- `ttl_seconds`: freshness lifetime, at most 90 seconds, measured from receipt using the receiver's monotonic clock.

Profiles are limited to 4 KiB. Resource counters are self-reported summaries. File replication is implemented as described below; other advertised services, such as file search, are not launched or implemented by a profile declaration. Full inventories belong in separate paginated application requests.

The CLI saves a UUID in `.peer-node-PORT.id` in the working directory, so restarting on the same port preserves identity. Use `--node-id-file PATH` to retain identity when moving ports or working directories. Use a distinct file for each logical node; do not run two nodes concurrently with the same identity. A corrupt identity file causes a startup error rather than silently creating a new identity. Embedded `PeerNode` instances must pass `node_id_file` for persistence; otherwise identity is ephemeral.

Example:

```sh
python3 peer_handshake.py --port 9101 --name office-server --capability file-search --capability file-transfer --service search:file-search:9200 --service transfer:file-transfer:9201 --resource shared_files=1200 --resource transfer_slots=4
```

## Message types and service queries

Every versioned message carries `type`, `protocol_version`, `host`, `port`, and `profile`. One newline-delimited JSON request and response is exchanged per TCP connection.

| Request | Response | Purpose |
| --- | --- | --- |
| `hello` | `hello` | Exchange profiles and peer endpoints. |
| `status` | `status` | Exchange current profile/status without a peer list. |
| `service-query` | `service-result` | Find currently known nodes advertising a capability. |
| `goodbye` | `goodbye-ack` | Remove the departing instance immediately. |

Original unversioned `hello` messages remain accepted as legacy peers, with no invented profile or capabilities. Any new-style message must include both version and a complete valid profile. Service availability is advertised, not independently verified.

Query a running node from another unused logical node port:

```sh
python3 peer_handshake.py --port 9199 --connect 127.0.0.1:9101 --query-service file-search
```

JSON results go to stdout; logs go to stderr. `--query-service` does not start a listener and exits after the query and a best-effort goodbye. Use an unused `--port` and a distinct identity file, not those of a running node.

Queries contain `capability`, optional `offset` (default 0), and optional `limit` (default and maximum 8). Responses include `results`, `total`, and `next_offset`; use `--offset NEXT_OFFSET` for the next page. Pages reflect current state, so membership changes between requests may change ordering. A capability match can be busy or draining; inspect availability and resource counters before selecting it.

Results contain the endpoint, full profile, remaining `ttl_seconds`, `source`, and `reported_by` (the responding node's ID). On the wire, `source` is `self` or `direct`, relative to the responder. `query_services()` and CLI output convert those to `direct` or `relayed`, relative to the caller. Relayed information is not cached as direct evidence or used to refresh peer health. Profiles whose TTL expired, or whose peer is no longer confirmed, are excluded. The local node's own matching profile can also be returned.

For embedding, `update_status(availability="busy", resources={"transfer_slots": 0})` updates local status atomically and increments its sequence. `send_status(peer)` immediately sends that status; regular discovery exchanges also publish it. `query_services(peer, capability, offset=0, limit=8)` returns one validated page. `send_goodbye(peer)` sends a departure notice. `stop_event.set()` requests service shutdown and automatically announces departure.

A direct report with an existing node ID at a new endpoint replaces the old endpoint. A new instance ID replaces cached status from the prior startup. Recent retired instances are remembered (at most 8 per node across 128 node IDs), preventing delayed status/goodbye messages from replacing the current instance. These identifiers and provenance labels are not proof of ownership; authentication is still required outside a trusted network.


## Automatic file replication

Each running CLI node now has a send/receive directory, created automatically as `shared-PORT` in the working directory. Use `--shared-dir PATH` to select another directory. Each directory can be owned by only one active node. Service-query-only invocations do not enable replication. Embedded `PeerNode` objects enable it by passing `shared_dir`.

Start two local nodes in separate terminals:

```sh
python3 peer_handshake.py --port 9101 --name node-one --shared-dir ./node-one-files
python3 peer_handshake.py --port 9102 --name node-two --shared-dir ./node-two-files --connect 127.0.0.1:9101
```

Place a complete file in either directory. Each node scans its directory and compares manifests with replication-capable peers about every 15 seconds. Missing or damaged versions are pulled, verified, and then made available to other nodes. Add more nodes using `--connect` to any reachable member. Replication eventually spreads every intact version throughout a connected network, subject to each node's limits and available disk space. It does not depend on the original source staying online once another intact replica exists.

Nested directories, binary data, and zero-byte files are supported. For importing large files, finish writing them outside the shared directory and then move the complete file into it. Files changing during hashing are skipped until a later scan. Do not place private files or this program's identity file inside the shared directory: its supported regular files are intended to be shared with permitted peers.

### Integrity and version behavior

- A manifest entry contains a relative path, byte length, and SHA-256 hash. Both size and hash must match before a copy is considered intact.
- Each scan rehashes only tracked files whose size, timestamps, or file ID changed since they last verified. Every tracked file is fully rehashed once after startup and then hourly, so damage that leaves file metadata unchanged is detected within that interval. Hashing does not block peers' manifest or chunk requests.
- File versions are immutable after initial indexing. A changed tracked file is treated as damaged and repaired from a peer. Publish an intentional edit under a new filename. Replication does not decide which edits are newer.
- A deleted local copy is restored when another peer advertises it: simply deleting a file does not propagate. To delete a file or folder on every node, use a delete marker (below).
- Different contents at the same logical path are both preserved. The original local file stays in place; additional versions appear under `replica-conflicts/HASH/PATH-ID/original/path`. Nodes may retain different versions at the primary pathname, but their manifests converge on all versions. Conflict copies retain their original logical identity rather than recursively creating new filenames in manifests.
- Expected hashes and destination mappings persist in `.peer-sync/index.json`. Keep this index to detect corruption after a restart. If the index is invalid, startup fails rather than silently discarding it.
- Downloads are written to private `.peer-sync/tmp/*.part` files, fully hashed, and atomically installed only when intact. Failed/interrupted transfers leave no advertised partial file; they retry from the beginning on a later pass. Orphaned transfer files are removed at next startup. On Linux, a downloaded file's permissions are explicitly set to world-read/write (`rw-rw-rw-`) once installed; while downloading and being verified it stays owner-only (`rw-------`), so other users cannot alter it before its hash is checked — unlike the application's own code, keys, and local state, which keep the OS's normal (owner-restricted) defaults.
- When repairing changed bytes, the old bytes are preserved under `.peer-sync/quarantine` before replacement. These backups are local and are never replicated. Review/remove them manually when no longer needed; replication never silently purges them.

If every copy of a version is lost or corrupted, its expected hash can detect the loss but cannot reconstruct its contents. This is replication, not an independent backup or authenticity guarantee.

### Deleting files on every node

Create an **empty** file named after the file or folder plus `.delete`, in any node's shared directory:

```sh
touch shared/reports/q3.pdf.delete    # deletes reports/q3.pdf everywhere
touch shared/old-photos.delete        # deletes the folder old-photos/ and everything in it
```

- Within one scan (about 15 seconds) the node writes a small creation timestamp into the empty file, making it a delete marker. The marker replicates like any other file.
- While a marker is active, every node permanently deletes all versions of its target, including conflict copies under `replica-conflicts`, and removes folders left empty. Nodes will not download the target from peers that have not seen the marker yet, and a file recreated at that path is deleted again. Deleted bytes are not kept anywhere; this cannot be undone.
- A folder marker covers everything below that folder (`old-photos.delete` deletes `old-photos/...` but not `old-photos-2024/`). Markers cannot target the shared directory itself.
- **Expiry:** 1 day (24 hours) after its creation time, every node removes the marker and remembers it as retired, so a peer still holding it cannot restart it. The name can then be used again. A node that was offline for that whole day never sees the marker: it still has the old files and will replicate them back to every node when it reconnects. After bringing back a node that was down for more than a day, check for, and re-delete, anything that reappears.
- **Renaming works too.** Renaming (or copying) a shared file `X` to `X.delete` is a delete request when the new file's contents are byte-for-byte identical to a version of `X` that node holds: the node overwrites it with a marker before sharing it, so the contents never replicate. Renaming a shared folder `D` to `D.delete` is a delete request when every file inside is an exact copy of the file at the same place under `D` (nothing extra, edited or linked): the node removes the renamed folder and writes a marker file named `D.delete` in its place.
- Otherwise only empty `.delete` files become markers. A `.delete` file or folder whose contents do not exactly match its target (or whose target was never shared) is ordinary shared content, and so is an empty file named just `.delete`.
- Anyone who can write to any node's shared directory can delete files on every node this way; restrict access accordingly.
- Files a node never shares (for example over the size limit, or hard-linked) are not affected by markers.

### Transfer protocol and limits

Replication automatically advertises the `file-replication` capability and the `replication` service at the node's handshake port. No additional listener is needed. The reserved service name `replication` should not be supplied manually.

`file-manifest` / `file-manifest-result` exchanges use pages of at most 32 entries, an ordered cursor, and a generation hash. A changing manifest invalidates pagination so the next pass starts again. Each node remembers the last complete manifest it fetched from each peer; when the first page's generation still matches it, the remaining pages are skipped and the remembered list is used, so at rest each pass costs one page per peer however many files are shared. Missing or damaged local copies are still repaired from the remembered list. `file-chunk` / `file-chunk-result` requests specify the complete manifest entry and byte offset, returning at most 32 KiB of base64-encoded data. Requests carry the same validated node profile and source checks as other versioned messages. `file-error` reports unavailable or changed files without disclosing filesystem paths.

There is one outbound replication worker per node, so each node downloads one file at a time. Downloads have a deadline checked between chunks (5 minutes, stretched to 3x the time the rate limit needs for large files) and use the existing bounded socket timeouts.

**Download rate limit.** Each node paces its own downloads to at most 2 MiB/s by default (about 17 Mbit/s), so replication traffic across the whole network stays below the number of nodes times that, even when every node pulls a large new file at once. To change it for one node, create `SHARED/.peer-sync/limits.json` on that node, for example `{"max_download_bytes_per_second": 5242880}` for 5 MiB/s, or `0` for unlimited (minimum otherwise 65536). It is re-read every sync pass (about 15 seconds), so no restart is needed; the node logs the limit in effect whenever it changes, and an invalid file falls back to the default with a log message. `.peer-sync` is never replicated, so each node's limit is its own. The limit is a file rather than a command-line option on purpose: a node rolled back to an older release would refuse to start with an option that release does not know. Each peer contributes at most 32 successfully downloaded files per pass. A bad or oversized file does not prevent trying other files or peers. The existing bounded inbound workers serve manifests and chunks.

Defaults are 1 GiB per file, 10 GiB of indexed replica content, and 10,000 indexed file versions. Set `--max-file-bytes NUMBER` and `--max-shared-bytes NUMBER` to change the byte limits. The download budget counts indexed content; temporary downloads, metadata, quarantine backups, and files you add yourself also consume disk space. Downloads check free space and stop safely if writing fails. Oversized local files are not imported, and oversized remote versions are skipped. The scan/transfer work can take longer than 15 seconds for large directories.

Absolute paths, parent traversal, Windows alternate streams/device names, symbolic links, junctions, and hard links are rejected. Relative names must be portable, at most 240 characters overall and 100 per component. `.peer-sync` and `replica-conflicts` are reserved top-level directories. Share a directory with only this node's process; other local programs must not replace its directory structure with links while it is running.

The existing IP-range policy applies to file transfers. Peers in permitted ranges can read shared files and cause new replica files to be downloaded. SHA-256 verifies agreement with the advertised content, not the publisher's identity; authentication/encryption remain separate concerns.


## Windows/Linux launcher and signed self-updates

The same Python release package runs on Windows and Linux. The launcher supervises the application as a child process; it does not replace running application files or depend on symlinks, shell scripts, Windows services, or systemd. Run the launcher under your preferred OS startup/service manager if it should start at boot.

Use `python` in the commands below on Windows and `python3` on Linux, or use the Python executable from your virtual environment. Install the updater dependency on the publisher and on every machine running the launcher:

```sh
python -m pip install -r requirements-updater.txt
```

### Create the first signed release

On the publishing machine, create a release signing key once, then build a package:

```sh
python release_tools.py keygen --private-key publisher-private.pem --public-key release-public.pem
python release_tools.py build --private-key publisher-private.pem --release 1 --output release-1.phupdate
```

Keep `publisher-private.pem` on the publishing machine, outside every shared directory. Distribute `release-public.pem` to nodes through a trusted setup process. Ordinary peers need only the public key. The code uses the maintained `cryptography` implementation of [Ed25519 signing and verification](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/); it does not implement cryptography itself. Linux key creation requests owner-only permissions; on Windows, store the publisher key in a directory whose ACL restricts access to the publisher.

Release numbers are positive, monotonically increasing integers. A signed manifest binds the application name, release number, both supported platforms, minimum Python/launcher versions, state schema, and every application file's size and SHA-256 hash. The archive contains exactly the four application modules. It cannot overwrite the stable launcher, trusted key, node identity, shared data, or arbitrary filesystem paths. Package size is limited to 32 MiB and each source file to 10 MiB. The supported payload is portable Python source; this version does not install Python runtimes, dependencies, native executables, or state migrations.

### Initialize and start a node

Create a new installation directory from the signed package:

```sh
python launcher.py init --root node-9101 --package release-1.phupdate --trusted-key release-public.pem --port 9101 --auto-update -- --name office-node
python node-9101/launcher.py run
```

For a LAN node, append its normal network options after `--` during initialization:

```sh
python launcher.py init --root node-9102 --package release-1.phupdate --trusted-key release-public.pem --port 9102 --auto-update -- --host 0.0.0.0 --advertise-host 192.168.1.120 --connect 192.168.1.118:9101 --allow-network 192.168.1.0/24
```

Omit `--auto-update` for manual installation policy. The policy and application arguments are saved in `state/config.json`; change them only while the launcher is stopped. `--port`, `--node-id-file`, and runtime options are controlled by the launcher rather than forwarded application arguments. Each installation root belongs to one node.

By default the shared/replication directory is `<root>/shared`. Pass `--shared-dir PATH` to `launcher.py init`/`init-source` (before the trailing `--`, alongside `--port`, not after it) to use a different location, such as a larger disk or a directory an existing standalone node was already using. The chosen path is saved as `shared_dir` in `state/config.json` (`null` means the default) and can be changed later by editing that field directly while the launcher is stopped. It must not be, or contain, the installation's `state` or `releases` directories, or the installation root itself — the launcher rejects an overlapping path at init time.

```text
node-9101/
  launcher.py                  stable supervisor
  release_tools.py             trusted signature/package verifier
  releases/
    1/                         signed immutable application release
    2/                         staged or installed release
  state/
    trusted-release-key.pem
    config.json
    active-release.json        active/previous release and update journal
    node.id                    persistent node identity
    logs/application.log
    runtime/                   per-launch control and health files
    inbox/                     manually queued update packages
  shared/
    updates/                   replicated signed release packages
    .peer-sync/                persistent file hashes and replica metadata
    ...                        ordinary replicated files
```

To preserve an existing standalone node, stop it first. Initialize an empty launcher installation, then copy its old node-ID file to `state/node.id` and its complete old shared directory (including `.peer-sync`) into the new `shared` directory before the first launcher start. Do not run the old standalone process and the launcher on the same directory or listening port.

### Publish an update

After changing the application source and passing its tests, build a higher-numbered release outside the shared directory:

```sh
python release_tools.py build --private-key publisher-private.pem --release 2 --output release-2.phupdate
```

Move the completed package into any participating node's `shared/updates` directory. Use a new immutable filename for every release. Existing file replication transports it across Windows and Linux nodes. Nodes initialized with `--auto-update` verify the package signature, stage its files, drain the running application, switch releases, and restart automatically. Receiving an unsigned or tampered package never authorizes execution. The launcher also checks preserved conflict copies of update packages, so an invalid file using the same name cannot hide the signed release. Candidate scanning uses rotating bounded batches, and installed packages are always reverified. The first rollout should use a test node; this implementation does not coordinate fleet-wide update batches.

For manual policy, or to install a particular verified package without waiting for discovery:

```sh
python node-9101/launcher.py update --package release-2.phupdate
```

This queues a verified copy in the installation's private inbox. The running launcher installs it, or processes it on its next start. Manual requests are reverified before activation and follow the same health/rollback rules as automatic updates. No command is executed from a peer message or update manifest.

### Activation, health, and recovery

The launcher verifies installed release contents before every process start. It persists an update transaction before stopping the working application, and changes `active-release.json` atomically. Node identity, shared content, and replication metadata are always outside release directories.

The application opens its listener and replication state before reporting readiness through per-launch local health files. The launcher checks the expected child PID, release number, random launch token, and changing heartbeat counter. It requires a stable startup window (3 seconds by default) within a health deadline (30 seconds by default on Linux, 120 seconds on Windows, where first starts can be slowed by on-access antivirus scanning of newly written release files; a healthy start is accepted as soon as it is stable, so the longer deadline only delays rolling back a broken release), and — separately from that startup deadline — treats the heartbeat itself as failed once it goes stale for longer than the heartbeat timeout (30 seconds by default). These checks confirm local startup and responsiveness; they do not prove fleet connectivity or every application behavior. A health, lease, or control file that is momentarily unreadable or unwritable — Windows briefly denies access to a file while the other process is replacing it — is not treated as a failure on either side: writes are retried and a missed read falls back to the last one received, so only a heartbeat or lease that actually goes stale past its timeout stops or restarts anything.

If startup fails or the heartbeat stalls, the launcher stops the child and restores the previous known-good release, if one is available. Failed update numbers remain below the recorded highest attempted release and are never automatically retried; publish a new higher release number after fixing the problem. An interrupted update journal rolls back on launcher restart. A release with no earlier release to roll back to (including the very first one) is retried indefinitely with capped exponential backoff (1s, 2s, 4s, ... up to 60s between attempts) rather than giving up — a host under transient resource pressure (e.g. swap thrashing on a busy machine) can stall the heartbeat past the timeout without the process ever truly crashing, and giving up would only force the OS service manager to redo the same work anyway. Each attempt is logged, so a node stuck retrying is visible in its logs rather than silently spinning.

Graceful restarts use a local control file on both operating systems: the node marks itself draining, sends goodbye, and stops transfers safely. After the configured stop timeout (20 seconds by default), the launcher terminates/kills only its own child process. The application also stops if the launcher's local lease goes stale for 3x the heartbeat timeout (90 seconds by default) — deliberately longer than the launcher's own heartbeat timeout, so the launcher is expected to notice and restart an unresponsive child well before the child would ever conclude the launcher itself is gone. Startup attempts to stop an orphan child from a prior launcher crash before starting another process. Ctrl+C stops the launcher and its child; SIGTERM is also handled gracefully on Linux. A forced launcher termination relies on the child lease timeout instead.

Timeouts can be set during `init` (or later via `reconfigure`) using `--health-timeout`, `--stabilize-seconds`, `--stop-timeout`, and `--heartbeat-timeout`. Raise `--heartbeat-timeout` on a host that's shared with other heavy applications and prone to transient stalls, to avoid false-positive restarts; the tradeoff is slower detection of a genuinely hung process. Timeouts are saved in `state/config.json` at installation, so an existing Windows installation keeps its earlier 30-second health deadline until reconfigured, e.g. `launcher.py reconfigure --root node --health-timeout 120`. Inspect `state/logs/application.log` and `state/active-release.json` for application failures and rollback history. Old releases are retained for inspection; automatic deletion and launcher/key rotation are not implemented. Upgrade the small trusted launcher separately. Releases must preserve state schema 1 and backward compatibility for rollback; irreversible data migrations are intentionally unsupported.

### Cross-platform verification

Run the complete suite with the updater dependency installed:

```sh
python -B -m unittest -q
```

Tests cover signed-package verification, tampered archives and unsafe paths, manual and automatic updates, peer-distributed packages, process restart, failed-release rollback, interrupted update recovery, persistent identity/data, file replication, and platform-specific directory/process locks. The application and launcher have been exercised on native Windows and Ubuntu under WSL.


### Installing a node with helper scripts

Initial installation works directly from this source directory: no release
package or signing key is required. The installer snapshots the local application
into version 1 and records a local integrity signature. Its temporary private key
is discarded; it is never used to authorize network updates.

To install a prebuilt signed release instead, explicitly pass
`--package release-1.phupdate --trusted-key release-public.pem` to the installer.

Each node needs Python 3.10+ with venv/pip and internet access to install the
updater dependency. Run the installer from the extracted bundle:

```sh
# Linux, as your normal user (not sudo):
sh install.sh
```

```powershell
# Windows:
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

The installer asks for an installation directory, node name, reachable IPv4
address, listening port, shared files directory (blank for the default,
`<install directory>/shared`), optional initial peer (`IP:PORT`), and whether
to accept automatic signed application updates. Leave the peer blank on the
first node, then use its address for subsequent nodes. Allow the chosen TCP
port through your node firewall. A separate Python environment is created
alongside the node directory; keep both directories in place. Pass
`--shared-dir PATH` to skip the prompt (e.g. for unattended setup).

Linux requires systemd and an active user manager. Setup installs and starts a
user service, and enables lingering (possibly requesting sudo once). This keeps
the node running after terminal logout and starts it at boot under your normal
user. See [systemd lingering documentation](https://www.freedesktop.org/software/systemd/man/252/loginctl.html).
Use `sh node/start-node.sh`, `sh node/stop-node.sh`, and
`sh node/status-node.sh`. Logs are available with
`journalctl --user -u peerhandshake-9101.service -f`.

Windows is strictly on demand: setup leaves the node stopped and creates no
scheduled task, service, or login entry. Start it explicitly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\node\start-node.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\node\status-node.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\node\stop-node.ps1
```

The Windows start helper launches a hidden background process; closing the
terminal does not stop it. Signing out or rebooting requires starting it again.
The stop helper requests graceful shutdown; status reports whether the launcher
is running, not fleet connectivity. Launcher logs are in
`node/state/logs/launcher.stdout.log` and `launcher.stderr.log`; application logs
are in `node/state/logs/application.log`.

For unattended setup, run `python node_setup.py --yes --root ./node
--name node-2 --advertise-host 192.168.1.12 --connect 192.168.1.11:9101`
on one line. Add `--auto-update` to enable signed updates. `--no-start` defers
Linux's initial start (it still enables startup at boot). Windows never starts
during setup. Use distinct ports and `--service-name` values for multiple Linux
instances. If Linux service registration fails after initialization, resolve
the reported permission problem and rerun
`python node/node_setup.py --root ./node --register-only`.

The installed launcher's shared directory defaults to `node/shared`, or wherever
`--shared-dir` pointed during setup; standalone example scripts continue to
default to `./share`. Put a test file in one node's shared directory and
confirm it appears on the other nodes before distributing updates.

### Changing settings on an existing installation

Rerun the installer against an existing `--root` with `--reconfigure` instead
of hand-editing `state/config.json`. It re-prompts for each setting (node name,
advertise address, initial peer, port, shared directory, auto-update),
pre-filled with the installation's current values so pressing Enter keeps them
unchanged:

```sh
python node_setup.py --root ./node --reconfigure
```

Or set specific values non-interactively, e.g. to move the shared directory:

```sh
python node_setup.py --yes --root ./node --reconfigure --shared-dir /mnt/bigger-disk/shared
```

Pass `--clear-shared-dir` to restore the default (`<root>/shared`). The
service name (`--service-name`) cannot be changed this way; reinstall to
rename it. If the node is currently running, reconfigure refuses to proceed
unless you either stop it first or pass `--restart` (or answer yes to the
interactive prompt), which stops it, applies the change, and starts it again
automatically. Changes only take effect after that restart.

Under the hood this calls `launcher.py reconfigure`, which validates and
writes `state/config.json` while holding the same lock a running launcher
uses, so it safely refuses to run concurrently with one.


### Enabling signed updates after a source installation

A source installation can run immediately without an update key. If automatic
updates were selected, they remain pending until you install your fleet's trusted
Ed25519 public key. Generate the fleet signing key on your release-building
machine using the commands above; keep its private key there. Install the same
public key on each node:

```sh
./node-python/bin/python node/launcher.py trust-key --root ./node --trusted-key release-public.pem
```

On Windows, use `.\node-python\Scripts\python.exe` for the interpreter.
The running launcher picks up the key without restarting. This command only
adds a missing key; it refuses to overwrite an existing trust key. Publish the
first update with release number 2 or higher. The initial local version remains
available for rollback and cannot authorize downloaded updates. No public key is
implicitly trusted from the shared directory or another peer.
