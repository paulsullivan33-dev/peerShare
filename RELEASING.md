# Release procedure

How to ship a code change (`peer_handshake.py`, `peer_protocol.py`, `peer_files.py`, `peer_runtime.py`) to a running fleet of nodes via signed, auto-replicated updates.

This does **not** cover updating the launcher/installer files themselves (`launcher.py`, `release_tools.py`, `node_setup.py`, `requirements-updater.txt`) — those are the "stable launcher" and are deliberately excluded from this mechanism. See [Updating the launcher/installer](#updating-the-launcherinstaller-instead) at the bottom.

## One-time setup

### 1. Generate a fleet signing key

On your publishing machine only:

```sh
python release_tools.py keygen --private-key publisher-private.pem --public-key release-public.pem
```

- **`publisher-private.pem` never leaves the publishing machine.** Keep it outside every shared/replicated directory. It authorizes every future release for the whole fleet — treat it like any other root-of-trust private key.
- Only `release-public.pem` gets distributed to nodes.

### 2. Install the public key on every node

The public key must reach each node through a channel *you* trust (scp, config management, USB drive, copy-paste over SSH). It **cannot** be delivered through peer replication or the shared directory — the code refuses to trust a key that arrives that way, since anyone who could drop a file into `shared/` could otherwise plant their own trust root.

Per node:

```sh
scp release-public.pem you@node-host:/tmp/
ssh you@node-host
./node-python/bin/python node/launcher.py trust-key --root ./node --trusted-key /tmp/release-public.pem
rm /tmp/release-public.pem   # optional cleanup; the public key isn't sensitive
```

Notes:
- `trust-key` **refuses to overwrite an existing key**, so it's safe to run against a node that already has one — it just errors out instead of silently replacing it.
- This is a one-time step per node, not per release. Once installed, every future signed release verifies against the same stored key automatically.
- A node originally set up via the source-bootstrap install path (`init-source` / `bootstrap_release` present in `state/config.json`) is running on a throwaway, discarded key and has **no** real fleet key yet — `auto_update: true` won't pull anything until you complete this step on it.
- Key rotation isn't automated by this project; there's no built-in way to revoke or replace a fleet key across nodes.

## Shipping a new release

### 1. Find the next release number

Release numbers are positive integers that must strictly increase and are never reused. Check any node's currently-known highest attempt:

```sh
cat node/state/active-release.json   # look at the "highest" field
```

Use one higher than that.

### 2. Build the signed package

From the updated source directory:

```sh
python release_tools.py build --private-key publisher-private.pem --release <N> --output release-<N>.phupdate
```

This bundles exactly the four application files, hashes and signs the manifest, and refuses to build if any file exceeds the size limits (10 MiB/file, 32 MiB package).

### 3. Distribute it

Two options, not mutually exclusive:

- **Let replication carry it (if nodes have `--auto-update` on):** drop the package into any connected, auto-update-enabled node's shared directory:

  ```sh
  cp release-<N>.phupdate /path/to/node/shared/updates/
  ```

  Existing file replication spreads it to every reachable peer. Each auto-update node independently verifies the signature, stages the files, drains its running application, switches releases, and restarts — no manual restart needed anywhere.

- **Push it to one node explicitly** (works regardless of `--auto-update`, and doesn't wait for discovery):

  ```sh
  ./node-python/bin/python node/launcher.py update --package release-<N>.phupdate
  ```

  This queues a verified copy in that node's private inbox; the running launcher installs it (or processes it on its next start).

Use a new, unused filename for every release — filenames are treated as immutable.

### 4. Verify

Per node:

```sh
cat node/state/active-release.json     # "active" should now be <N>, "failed" should not contain <N>
tail node/state/logs/application.log   # check for startup errors on the new release
```

If a release fails its health check, the launcher automatically rolls back to the previous known-good release and records the failure — that release number is never retried; fix the problem and publish a new higher-numbered release instead.

**Roll out to one test node first.** This project doesn't coordinate fleet-wide update batches — updates propagate as replication naturally reaches each node.

## Updating the launcher/installer instead

If what changed is `launcher.py`, `release_tools.py`, `node_setup.py`, or `requirements-updater.txt` (not the four application files above), the signed-release mechanism doesn't apply — those files are intentionally frozen at install time and never touched by an update package. Instead, per node:

```sh
sh node/stop-node.sh
cp launcher.py release_tools.py requirements-updater.txt node_setup.py /path/to/node/
sh node/start-node.sh
```

Don't touch `node/state/`, `node/shared/`, or `node/releases/` — that's identity, keys, and data.
