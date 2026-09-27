import json
import hashlib
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch
from peer_runtime import RuntimeControl

import launcher as launch
import peer_handshake as app
import release_tools as release


def free_port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def wait_for(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(.05)
    raise AssertionError('launcher did not reach the expected state')


class ReleaseTests(unittest.TestCase):
    def test_source_bootstrap_without_update_key(self):
        root = self.directory / 'source-node'
        launch.initialize_source(root, Path(__file__).parent, None, free_port(), ['--host', '127.0.0.1'], True)
        supervisor = launch.Launcher(root)
        self.assertIsNone(supervisor.key)
        self.assertIsNone(supervisor.next_update())
        self.assertFalse((root / 'state/trusted-release-key.pem').exists())
        try:
            self.assertTrue(supervisor.launch_ready(1))
        finally:
            supervisor.stop_child()
        shutil.copyfile(self.public, root / 'state/trusted-release-key.pem')
        update = self.make_package(2)
        shutil.copyfile(update, root / 'shared/updates/release-2.phupdate')
        self.assertIsNotNone(supervisor.next_update())
        try:
            self.assertTrue(supervisor.apply_update(update))
            self.assertEqual(supervisor.state['active'], 2)
            supervisor.stop_child()
            self.assertTrue(supervisor.launch_ready(1))
        finally:
            supervisor.stop_child()

    def test_failed_update_and_failed_rollback_keep_launcher_alive(self):
        root = self.installation()
        supervisor = launch.Launcher(root)
        update = self.make_package(2)
        with patch.object(launch.Launcher, 'launch_ready', return_value=False):
            self.assertFalse(supervisor.apply_update(update))  # must not raise
        self.assertEqual(supervisor.state['active'], 1)
        self.assertIsNone(supervisor.state['pending'])
        self.assertIn('2', supervisor.state['failed'])
        self.assertIn('1', supervisor.state['failed'])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.private = self.directory / 'private.pem'
        self.public = self.directory / 'public.pem'
        release.generate_keys(self.private, self.public)
        self.package = self.directory / 'release-1.phupdate'
        release.build_package(Path(__file__).parent, self.private, 1, self.package)
        self.key = release.public_key(self.public)

    def tearDown(self):
        self.temporary.cleanup()

    def make_package(self, number, broken=False):
        source = Path(__file__).parent
        if broken:
            source = self.directory / ('broken-' + str(number))
            source.mkdir()
            for name in release.APPLICATION_FILES:
                shutil.copyfile(Path(__file__).parent / name, source / name)
            (source / 'peer_handshake.py').write_text('raise SystemExit(7)\n')
        package = self.directory / f'release-{number}.phupdate'
        release.build_package(source, self.private, number, package)
        return package

    def installation(self, automatic=False, arguments=None):
        root = self.directory / 'node'
        launch.initialize(root, self.package, self.public, free_port(), arguments or [],
                          auto_update=automatic, health_timeout=5, stabilize_seconds=.1, stop_timeout=5)
        return root

    def test_signed_package_is_portable_and_installed_unchanged(self):
        manifest, files, _, _ = release.verify_package(self.package, self.key)
        self.assertEqual(manifest['platforms'], ['linux', 'windows'])
        self.assertEqual(set(files), set(release.APPLICATION_FILES))
        target = self.directory / 'releases'
        release.stage_package(self.package, target, self.key)
        self.assertEqual(release.verify_directory(target / '1', self.key), manifest)
        release.stage_package(self.package, target, self.key)  # Idempotent identical content.
        (target / '1/peer_protocol.py').write_text('changed')
        with self.assertRaises(ValueError):
            release.verify_directory(target / '1', self.key)

    def test_signature_and_content_tampering_rejected(self):
        other_private = self.directory / 'other-private.pem'
        other_public = self.directory / 'other-public.pem'
        release.generate_keys(other_private, other_public)
        with self.assertRaises(ValueError):
            release.verify_package(self.package, release.public_key(other_public))
        damaged = self.directory / 'tampered.phupdate'
        with zipfile.ZipFile(self.package) as original, zipfile.ZipFile(damaged, 'w') as output:
            for name in original.namelist():
                data = original.read(name)
                if name == 'files/peer_handshake.py':
                    data += b'\n# unauthorized modification\n'
                output.writestr(name, data)
        with self.assertRaises(ValueError):
            release.verify_package(damaged, self.key)

    def test_unsafe_archive_and_links_are_rejected(self):
        for name in ('../launcher.py', '/etc/file', 'files/../../state/config.json'):
            damaged = self.directory / 'unsafe.phupdate'
            shutil.copyfile(self.package, damaged)
            with zipfile.ZipFile(damaged, 'a') as archive:
                archive.writestr(name, b'bad')
            with self.assertRaises(ValueError):
                release.verify_package(damaged, self.key)
        damaged = self.directory / 'link.phupdate'
        with zipfile.ZipFile(self.package) as original, zipfile.ZipFile(damaged, 'w') as output:
            for name in original.namelist():
                info = zipfile.ZipInfo(name)
                if name == 'files/peer_handshake.py':
                    info.create_system = 3
                    info.external_attr = 0o120777 << 16
                output.writestr(info, original.read(name))
        with self.assertRaises(ValueError):
            release.verify_package(damaged, self.key)

    def test_keys_and_immutable_package_names_are_not_overwritten(self):
        with self.assertRaises(ValueError):
            release.generate_keys(self.private, self.public)
        with self.assertRaises(FileExistsError):
            release.build_package(Path(__file__).parent, self.private, 1, self.package)
        if os.name != 'nt':
            self.assertEqual(self.private.stat().st_mode & 0o777, 0o600)

    def test_one_launcher_per_installation(self):
        root = self.installation()
        with release.InstanceLock(root / 'state/launcher.lock'):
            with self.assertRaises(ValueError):
                with release.InstanceLock(root / 'state/launcher.lock'):
                    self.fail('second lock must not succeed')

    def test_interrupted_update_rolls_back_without_reusing_release_number(self):
        root = self.installation()
        supervisor = launch.Launcher(root)
        supervisor.state.update(active=2, highest=2, pending={'candidate': 2, 'previous': 1})
        supervisor.save()
        supervisor = launch.Launcher(root)
        supervisor.recover_transaction()
        self.assertEqual(supervisor.state['active'], 1)
        self.assertEqual(supervisor.state['highest'], 2)
        self.assertIn('2', supervisor.state['failed'])
        with self.assertRaises(ValueError):
            launch.queue_update(root, self.make_package(2))

    def test_default_startup_health_deadline_is_longer_on_windows(self):
        self.assertEqual(launch.DEFAULT_HEALTH_TIMEOUT, 120 if os.name == 'nt' else 30)
        packaged = self.directory / 'packaged'
        launch.initialize(packaged, self.package, self.public, free_port(), [])
        source = self.directory / 'source'
        launch.initialize_source(source, Path(__file__).parent, None, free_port(), [])
        for root in (packaged, source):
            with self.subTest(root=root.name):
                self.assertEqual(launch.read_json(root / 'state/config.json')['health_timeout'],
                                 launch.DEFAULT_HEALTH_TIMEOUT)

    def test_heartbeat_timeout_is_configurable_and_flows_to_the_launcher(self):
        root = self.installation()
        self.assertEqual(launch.Launcher(root).heartbeat_timeout, launch.DEFAULT_HEARTBEAT_TIMEOUT)
        launch.reconfigure(root, heartbeat_timeout=45)
        self.assertEqual(launch.read_json(root / 'state/config.json')['heartbeat_timeout'], 45)
        self.assertEqual(launch.Launcher(root).heartbeat_timeout, 45)
        with self.assertRaises(ValueError):
            launch.reconfigure(root, heartbeat_timeout=1)
        with self.assertRaises(ValueError):
            launch.initialize(self.directory / 'bad-heartbeat', self.package, self.public, free_port(), [],
                              heartbeat_timeout=1000)

    def test_lease_timeout_is_handed_to_the_child_via_a_file_not_a_cli_flag(self):
        # A CLI flag would break rolling back to an older release built before the flag existed;
        # a file in the fresh per-launch runtime directory is silently ignored by old code instead.
        root = self.installation()
        launch.reconfigure(root, heartbeat_timeout=50)
        supervisor = launch.Launcher(root)
        try:
            self.assertTrue(supervisor.launch_ready(1))
            config = json.loads((supervisor.runtime / 'launch-config.json').read_text())
            self.assertEqual(config, {'lease_timeout': 150})
            self.assertNotIn('--lease-timeout', supervisor.child.args)
        finally:
            supervisor.stop_child()

    def test_repeatedly_failing_release_retries_with_backoff_instead_of_giving_up(self):
        root = self.directory / 'node'
        broken = self.make_package(2, broken=True)
        launch.initialize(root, broken, self.public, free_port(), [],
                          health_timeout=1, stabilize_seconds=.1, stop_timeout=1)
        supervisor = launch.Launcher(root)
        errors = []
        def run():
            try:
                supervisor.run()
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        with patch.object(launch, 'log'):
            thread.start()
            try:
                time.sleep(3)
                # Still alive and still trying, not raised/exited, despite the release never working.
                self.assertTrue(thread.is_alive())
                self.assertFalse(errors, errors)
            finally:
                supervisor.stop_event.set()
                thread.join(10)
                self.assertFalse(thread.is_alive())

    def test_shared_dir_overlap_with_root_state_or_releases_is_rejected(self):
        root = self.directory / 'root-check'
        for shared in (root, root / 'state', root / 'state/sub', root / 'releases',
                      root / 'releases/1', root.parent):
            with self.assertRaises(ValueError):
                launch.check_shared_dir(root, shared)
        launch.check_shared_dir(root, root / 'shared')
        launch.check_shared_dir(root, root / 'other-name')
        launch.check_shared_dir(root, self.directory / 'elsewhere')

    def test_custom_shared_dir_is_configured_and_used_by_the_child(self):
        root = self.directory / 'node'
        custom = self.directory / 'custom-shared'
        launch.initialize(root, self.package, self.public, free_port(), [], shared_dir=custom,
                          health_timeout=5, stabilize_seconds=.1, stop_timeout=5)
        config = launch.read_json(root / 'state/config.json')
        self.assertEqual(config['shared_dir'], str(custom.resolve()))
        self.assertFalse((root / 'shared').exists())
        self.assertTrue((custom / 'updates').is_dir())
        supervisor = launch.Launcher(root)
        self.assertEqual(supervisor.shared_dir, custom)
        try:
            self.assertTrue(supervisor.launch_ready(1))
        finally:
            supervisor.stop_child()
        with self.assertRaises(ValueError):
            launch.initialize(self.directory / 'overlapping', self.package, self.public, free_port(), [],
                              shared_dir=self.directory / 'overlapping' / 'state')

    def test_reconfigure_updates_settings_and_is_exclusive_with_a_running_launcher(self):
        root = self.installation()
        custom = self.directory / 'custom-shared'
        launch.reconfigure(root, app_args=['--name', 'renamed'], auto_update=True, shared_dir=custom,
                           health_timeout=10, stabilize_seconds=.5, stop_timeout=8)
        config = launch.read_json(root / 'state/config.json')
        self.assertEqual(config['node_args'], ['--port', config['node_args'][1], '--name', 'renamed'])
        self.assertTrue(config['auto_update'])
        self.assertEqual(config['shared_dir'], str(custom.resolve()))
        self.assertEqual((config['health_timeout'], config['stabilize_seconds'], config['stop_timeout']),
                         (10, .5, 8))
        supervisor = launch.Launcher(root)
        self.assertEqual(supervisor.shared_dir, custom)
        self.assertEqual(supervisor.config['node_args'][3], 'renamed')

        launch.reconfigure(root, clear_shared_dir=True)
        self.assertIsNone(launch.read_json(root / 'state/config.json')['shared_dir'])

        with self.assertRaises(ValueError):
            launch.reconfigure(root, shared_dir=root / 'state')
        with self.assertRaises(ValueError):
            launch.reconfigure(root, app_args=['--shared-dir', 'bad'])
        with self.assertRaises(ValueError):
            launch.reconfigure(root, shared_dir=custom, clear_shared_dir=True)
        with self.assertRaises(ValueError):
            launch.reconfigure(root, port=0)

        with release.InstanceLock(root / 'state/launcher.lock'):
            with self.assertRaises(ValueError):
                launch.reconfigure(root, auto_update=False)

    def test_runtime_paths_cannot_be_overridden_by_application_arguments(self):
        for argument in ('--node-id-file=bad', '--shared-dir', '--runtime-dir=bad', '--port=1'):
            with self.assertRaises(ValueError):
                self.installation(arguments=[argument])

    def test_invalid_packages_do_not_starve_valid_auto_updates(self):
        root = self.installation(automatic=True)
        updates = root / 'shared/updates'
        for number in range(129):
            (updates / f'a-{number:03}.phupdate').write_bytes(b'not a signed zip')
        valid = updates / 'z-valid.phupdate'
        shutil.copyfile(self.make_package(2), valid)
        supervisor = launch.Launcher(root)
        with patch.object(launch, 'log'):
            self.assertIsNone(supervisor.next_update())
            self.assertEqual(supervisor.next_update(), valid)
        self.assertLessEqual(len(supervisor.seen_packages), 256)

    def test_signed_conflict_copy_is_found_even_when_original_filename_is_invalid(self):
        root = self.installation(automatic=True)
        package = self.make_package(2)
        (root / 'shared/updates/release-2.phupdate').write_bytes(b'untrusted original')
        sha = hashlib.sha256(package.read_bytes()).hexdigest()
        relative = app.FileStore.conflict_path({'path': 'updates/release-2.phupdate', 'sha256': sha})
        conflict = root / 'shared' / relative
        conflict.parent.mkdir(parents=True)
        shutil.copyfile(package, conflict)
        with patch.object(launch, 'log'):
            self.assertEqual(launch.Launcher(root).next_update(), conflict)

    def test_application_stops_when_launcher_lease_expires(self):
        node = app.PeerNode('127.0.0.1', free_port(), None)
        runtime = self.directory / 'runtime'
        runtime.mkdir()
        release.atomic_json(runtime / 'lease.json', {'token': 'test-token'})
        control = RuntimeControl(node, runtime, 1, 'test-token')
        control.poll()
        self.assertFalse(node.stop_event.is_set())
        old = time.time() - 91
        os.utime(runtime / 'lease.json', (old, old))
        control.poll()
        self.assertTrue(node.stop_event.is_set())
        self.assertEqual(launch.read_json(runtime / 'health.json')['phase'], 'draining')
        control.close()
        self.assertEqual(launch.read_json(runtime / 'exit.json')['token'], 'test-token')

    def test_malformed_control_file_and_failed_heartbeat_write_do_not_stop_application(self):
        node = app.PeerNode('127.0.0.1', free_port(), None)
        runtime = self.directory / 'runtime'
        runtime.mkdir()
        release.atomic_json(runtime / 'lease.json', {'token': 'test-token'})
        control = RuntimeControl(node, runtime, 1, 'test-token')

        def poll_until_heartbeat_written():
            # On Windows another process (e.g. antivirus) can briefly deny replacing
            # health.json; poll() then skips that beat by design, so allow a few polls.
            for _ in range(5):
                control.poll()
                if launch.read_json(runtime / 'health.json')['counter'] == control.counter:
                    return
            self.fail('no heartbeat was written in 5 polls')

        for content in ('{not json', '"stop"', '[]', '\udcff'):
            with self.subTest(content=content):
                (runtime / 'control.json').write_text(content, encoding='utf-8', errors='surrogateescape')
                poll_until_heartbeat_written()
                self.assertFalse(node.stop_event.is_set())
        # Windows refuses to replace health.json while the launcher has it open for reading.
        with patch('peer_runtime.os.replace', side_effect=PermissionError(5, 'Access is denied')):
            control.poll()
        self.assertFalse(node.stop_event.is_set())
        self.assertEqual([path.name for path in runtime.glob('*.tmp')], [])
        poll_until_heartbeat_written()
        release.atomic_json(runtime / 'control.json', {'command': 'stop', 'token': 'test-token'})
        control.poll()
        self.assertTrue(node.stop_event.is_set())

    def test_briefly_unreadable_lease_does_not_stop_application(self):
        node = app.PeerNode('127.0.0.1', free_port(), None)
        runtime = self.directory / 'runtime'
        runtime.mkdir()
        release.atomic_json(runtime / 'lease.json', {'token': 'test-token'})
        control = RuntimeControl(node, runtime, 1, 'test-token', lease_timeout=90)
        control.poll()
        real_read = Path.read_text

        def denied(path, *args, **kwargs):
            if path.name == 'lease.json':
                raise PermissionError(5, 'Access is denied')  # Windows, mid-replace
            return real_read(path, *args, **kwargs)

        with patch.object(Path, 'read_text', autospec=True, side_effect=denied):
            control.poll()
            self.assertFalse(node.stop_event.is_set())
            # Still unreadable once the lease timeout has passed: the launcher is presumed gone.
            with patch('peer_runtime.time.monotonic', return_value=time.monotonic() + 91):
                control.poll()
            self.assertTrue(node.stop_event.is_set())

    def test_lease_with_wrong_token_stops_application_immediately(self):
        node = app.PeerNode('127.0.0.1', free_port(), None)
        runtime = self.directory / 'runtime'
        runtime.mkdir()
        release.atomic_json(runtime / 'lease.json', {'token': 'another-launch'})
        RuntimeControl(node, runtime, 1, 'test-token').poll()
        self.assertTrue(node.stop_event.is_set())

    def test_application_log_rotates_while_the_writer_keeps_appending(self):
        path = self.directory / 'application.log'
        writer = path.open('ab', buffering=0)  # like the child's inherited stdout
        try:
            for generation in range(7):
                writer.write(f'generation {generation}\n'.encode() * 10)
                self.assertTrue(launch.rotate_log(path, max_bytes=50, keep=3))
            writer.write(b'still writing\n')
        finally:
            writer.close()
        self.assertEqual(path.read_bytes(), b'still writing\n')  # continues at the start, no gap
        rotated = sorted(p.name for p in self.directory.glob('application.log.*'))
        self.assertEqual(rotated, ['application.log.1', 'application.log.2', 'application.log.3'])
        self.assertIn(b'generation 6', (self.directory / 'application.log.1').read_bytes())
        self.assertIn(b'generation 4', (self.directory / 'application.log.3').read_bytes())
        self.assertFalse(launch.rotate_log(path, max_bytes=50, keep=3))  # small: left alone
        self.assertFalse(launch.rotate_log(self.directory / 'missing.log'))

    def test_old_runtime_folders_are_pruned(self):
        supervisor = launch.Launcher(self.installation())
        root = supervisor.state_dir / 'runtime'
        folders = []
        for age in range(10):
            folder = root / uuid.uuid4().hex
            folder.mkdir()
            (folder / 'health.json').write_text('{}')
            os.utime(folder, (time.time() - 1000 * (age + 1),) * 2)
            folders.append(folder)
        unrelated = root / 'keep-me'
        unrelated.mkdir()
        orphan = folders[-1]  # oldest, but named in child.json: a child that may still run
        release.atomic_json(supervisor.state_dir / 'child.json', {'runtime': orphan.name})
        supervisor.runtime = root / uuid.uuid4().hex
        supervisor.runtime.mkdir()
        supervisor.prune_runtime()
        remaining = {path.name for path in root.iterdir()}
        expected = {supervisor.runtime.name, 'keep-me', orphan.name,
                    *(folder.name for folder in folders[:launch.KEEP_RUNTIME_DIRS - 1])}
        self.assertEqual(remaining, expected)

    def test_processed_and_stale_inbox_packages_are_removed(self):
        root = self.installation()
        inbox = root / 'state/inbox'
        stale, recent, queued = ('a' * 64 + '.phupdate', 'b' * 64 + '.phupdate', 'c' * 64 + '.phupdate')
        for name in (stale, recent, queued, 'd' * 32 + '.tmp', 'notes.txt'):
            (inbox / name).write_bytes(b'x')
        old = time.time() - 2 * launch.INBOX_GRACE_SECONDS
        for name in (stale, queued, 'd' * 32 + '.tmp', 'notes.txt'):
            os.utime(inbox / name, (old, old))
        release.atomic_json(root / 'state/update-request.json', {'package': queued})
        launch.Launcher(root).prune_inbox()
        self.assertEqual(sorted(path.name for path in inbox.iterdir()), sorted([recent, queued, 'notes.txt']))

    def test_atomic_json_retries_a_briefly_denied_replace(self):
        target = self.directory / 'state.json'
        real_replace = os.replace
        denied = PermissionError(5, 'Access is denied')
        outcomes = [denied, denied, None]

        def flaky_replace(source, destination):
            if outcomes.pop(0) is not None:
                raise denied
            real_replace(source, destination)

        with patch('release_tools.os.replace', side_effect=flaky_replace) as replace, \
             patch('release_tools.time.sleep'):
            release.atomic_json(target, {'value': 1})
        self.assertEqual(replace.call_count, 3)
        self.assertEqual(launch.read_json(target), {'value': 1})
        with patch('release_tools.os.replace', side_effect=denied), patch('release_tools.time.sleep'), \
             self.assertRaises(PermissionError):
            release.atomic_json(target, {'value': 2})
        self.assertEqual(launch.read_json(target), {'value': 1})
        self.assertEqual(list(self.directory.glob('*.tmp')), [])

    def test_briefly_unreadable_health_file_does_not_count_as_unhealthy(self):
        supervisor = launch.Launcher(self.installation())
        try:
            self.assertTrue(supervisor.launch_ready(1))
            real_read = launch.read_json

            def denied(path):
                if path.name == 'health.json':
                    raise PermissionError(5, 'Access is denied')  # child replacing it right now
                return real_read(path)

            with patch.object(launch, 'read_json', side_effect=denied):
                self.assertIsNotNone(supervisor.health(1))
                # The last heartbeat read still goes stale on schedule.
                with patch('launcher.time.time', return_value=time.time() + supervisor.heartbeat_timeout + 1):
                    self.assertIsNone(supervisor.health(1))
        finally:
            supervisor.stop_child()

    def test_failed_lease_renewal_and_malformed_stop_request_do_not_crash_launcher(self):
        supervisor = launch.Launcher(self.installation())
        supervisor.runtime = release.safe_directory(supervisor.state_dir / 'runtime' / uuid.uuid4().hex)
        supervisor.token = 'token'
        with patch.object(launch, 'atomic_json', side_effect=PermissionError(5, 'Access is denied')), \
             patch.object(launch, 'log') as log:
            supervisor.lease()
        self.assertIn('could not renew lease', log.call_args.args[0])
        control = supervisor.state_dir / 'launcher-control.json'
        control.write_text('{not json')
        supervisor.lease()
        self.assertFalse(control.exists())
        self.assertFalse(supervisor.stop_event.is_set())
        release.atomic_json(control, {'command': 'stop', 'session': supervisor.session})
        supervisor.lease()
        self.assertTrue(supervisor.stop_event.is_set())

    def test_child_is_still_stopped_when_stop_request_cannot_be_written(self):
        supervisor = launch.Launcher(self.installation())
        self.assertTrue(supervisor.launch_ready(1))
        child = supervisor.child
        with patch.object(launch, 'atomic_json', side_effect=PermissionError(5, 'Access is denied')), \
             patch.object(launch, 'log'):
            supervisor.stop_child()
        self.assertIsNotNone(child.poll())
        self.assertIsNone(supervisor.child)

    def test_manual_upgrade_restart_and_failed_release_rollback_preserve_data(self):
        root = self.installation()
        healthy = self.make_package(2)
        broken = self.make_package(3, broken=True)
        supervisor = launch.Launcher(root)
        errors = []
        def run():
            try:
                supervisor.run()
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            wait_for(lambda: supervisor.health(1) and supervisor.health(1)['counter'] >= 2)
            identity = (root / 'state/node.id').read_text()
            first_pid = supervisor.child.pid
            (root / 'shared/keep.txt').write_text('preserved across releases')
            launch.queue_update(root, healthy)
            wait_for(lambda: supervisor.state['active'] == 2 and supervisor.state['pending'] is None
                     and supervisor.health(2), timeout=16)
            self.assertNotEqual(supervisor.child.pid, first_pid)
            self.assertEqual((root / 'state/node.id').read_text(), identity)
            self.assertEqual((root / 'shared/keep.txt').read_text(), 'preserved across releases')
            self.assertEqual(supervisor.state['previous'], 1)
            wait_for(lambda: not list((root / 'state/inbox').iterdir()))  # processed: removed
            launch.queue_update(root, broken)
            wait_for(lambda: '3' in supervisor.state['failed'] and supervisor.state['active'] == 2
                     and supervisor.health(2), timeout=16)
            self.assertEqual(supervisor.state['highest'], 3)
            self.assertEqual((root / 'state/node.id').read_text(), identity)
            self.assertEqual((root / 'shared/keep.txt').read_text(), 'preserved across releases')
            self.assertTrue((root / 'releases/1').is_dir())
            self.assertTrue((root / 'releases/2').is_dir())
            wait_for(lambda: not list((root / 'state/inbox').iterdir()))  # rejected: removed too
            self.assertTrue(launch.running(root))
            launch.request_stop(root)
            thread.join(12)
            self.assertFalse(thread.is_alive())
            self.assertFalse(launch.running(root))
        finally:
            supervisor.stop_event.set()
            thread.join(12)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors, errors)
            self.assertFalse((root / 'state/child.json').exists())

    def start_launcher(self, root):
        supervisor = launch.Launcher(root)
        errors = []
        def run():
            try:
                supervisor.run()
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        def stop():
            supervisor.stop_event.set()
            thread.join(15)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors, errors)
        return supervisor, stop

    def updated_installation(self):
        root = self.installation()
        supervisor, stop = self.start_launcher(root)
        try:
            wait_for(lambda: supervisor.health(1))
            launch.queue_update(root, self.make_package(2))
            wait_for(lambda: supervisor.state['active'] == 2 and supervisor.state['pending'] is None
                     and supervisor.health(2), timeout=20)
        finally:
            stop()
        return root

    def test_launcher_restart_keeps_a_healthy_updated_release(self):
        # A fresh launcher has no child yet; that must not count as the active release failing.
        root = self.updated_installation()
        supervisor, stop = self.start_launcher(root)
        try:
            wait_for(lambda: supervisor.health(2), timeout=20)
            self.assertEqual(supervisor.state['active'], 2)
            self.assertEqual(supervisor.state['previous'], 1)
            self.assertEqual(supervisor.state['failed'], {})
        finally:
            stop()
        self.assertEqual(launch.read_json(root / 'state/active-release.json')['active'], 2)

    def test_launcher_restart_rolls_back_when_active_release_cannot_start(self):
        root = self.updated_installation()
        # Tampering makes release 2 fail verification, so it cannot start after the restart.
        (root / 'releases/2/peer_handshake.py').write_text('raise SystemExit(7)\n')
        supervisor, stop = self.start_launcher(root)
        try:
            wait_for(lambda: supervisor.state['active'] == 1 and supervisor.health(1), timeout=20)
            self.assertIn('2', supervisor.state['failed'])
            self.assertIsNone(supervisor.state['previous'])
        finally:
            stop()

    def test_auto_update_receives_package_through_peer_replication(self):
        donor = app.PeerNode('127.0.0.1', free_port(), None, shared_dir=self.directory / 'donor')
        server = threading.Thread(target=donor.run, daemon=True)
        server.start()
        root = self.installation(automatic=True, arguments=['--connect', donor.identity.address()])
        supervisor = launch.Launcher(root)
        errors = []
        def run():
            try:
                supervisor.run()
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            wait_for(lambda: supervisor.health(1))
            updates = donor.file_store.root / 'updates'
            updates.mkdir()
            package = self.make_package(2)
            shutil.copyfile(package, updates / package.name)
            donor.file_store.scan()
            wait_for(lambda: supervisor.state['active'] == 2 and supervisor.state['pending'] is None
                     and supervisor.health(2), timeout=40)
            self.assertEqual((root / 'shared/updates' / package.name).read_bytes(), package.read_bytes())
        finally:
            supervisor.stop_event.set()
            thread.join(15)
            donor.stop_event.set()
            server.join(16)
            self.assertFalse(thread.is_alive())
            self.assertFalse(server.is_alive())
            self.assertFalse(errors, errors)


if __name__ == '__main__':
    unittest.main()
