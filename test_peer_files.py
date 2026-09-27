import base64
import copy
import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import peer_handshake as m
import peer_files as f


def hidden_marker(node, path):
    """Bytes of NODE's hidden delete marker (in .peer-sync/markers) for PATH, or None."""
    store = node.file_store
    with store.lock:
        item = next((item for item in store.markers.values() if item['path'] == path), None)
    return None if item is None else store.marker_file(item).read_bytes()


class FileReplicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.left = m.PeerNode('127.0.0.1', 9101, None, shared_dir=self.root / 'left')
        self.right = m.PeerNode('127.0.0.1', 9102, None, shared_dir=self.root / 'right')
        self.left.handle_message(self.right.message())

    def tearDown(self):
        self.left.stop_event.set()
        self.right.stop_event.set()
        self.left.file_store.close()
        self.right.file_store.close()
        self.temporary.cleanup()

    def serve_right(self, peer, message):
        return self.right.handle_message(message, source_host='127.0.0.1')

    def test_directory_has_one_owner_and_orphan_downloads_are_cleaned(self):
        with self.assertRaises(ValueError):
            f.FileStore(self.left.file_store.root)
        temporary = self.left.file_store.temp / ('a' * 32 + '.part')
        temporary.write_bytes(b'partial')
        self.left.file_store.close()
        replacement = f.FileStore(self.left.file_store.root)
        self.left.file_store = replacement
        self.left.file_replicator.store = replacement
        self.assertFalse(temporary.exists())

    def test_deleted_tmp_directory_is_recreated_and_replication_continues(self):
        original = b'recovers after deletion'
        (self.right.file_store.root / 'recover.txt').write_bytes(original)
        self.right.file_store.scan()
        shutil.rmtree(self.left.file_store.temp)
        self.assertFalse(self.left.file_store.temp.exists())
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.left.file_replicator.sync_once()
        self.assertEqual((self.left.file_store.root / 'recover.txt').read_bytes(), original)
        self.assertTrue(self.left.file_store.temp.is_dir())

    def test_ensure_layout_recreates_a_fully_deleted_peer_sync_directory(self):
        store = self.left.file_store
        item = {'path': 'kept.txt', 'sha256': 'a' * 64, 'size': 0}
        store.records[f.key(item)] = {'file': item, 'destination': 'kept.txt'}
        store.close()  # release the owner-lock handle so the directory can be removed
        shutil.rmtree(store.state)
        self.assertFalse(store.state.exists())
        store.ensure_layout()
        self.assertTrue(store.state.is_dir())
        self.assertTrue(store.temp.is_dir())
        self.assertTrue(store.index_path.exists())
        self.assertIn('kept.txt', store.index_path.read_text())

    def test_multichunk_empty_and_nested_files(self):
        directory = self.right.file_store.root / 'documents'
        directory.mkdir()
        content = bytes(range(256)) * 400
        (directory / 'binary.dat').write_bytes(content)
        (directory / 'empty.txt').write_bytes(b'')
        self.right.file_store.scan()
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.left.file_replicator.sync_once()
        self.assertEqual((self.left.file_store.root / 'documents/binary.dat').read_bytes(), content)
        self.assertEqual((self.left.file_store.root / 'documents/empty.txt').read_bytes(), b'')
        self.assertEqual(len(self.left.file_store.intact), 2)
        self.assertFalse(list(self.left.file_store.temp.iterdir()))

    def test_damaged_and_deleted_copies_repair_using_persisted_index(self):
        original = b'original content'
        (self.right.file_store.root / 'data.txt').write_bytes(original)
        self.right.file_store.scan()
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.left.file_replicator.sync_once()
            target = self.left.file_store.root / 'data.txt'
            target.write_bytes(b'corrupted content')
            self.left.file_store.close()
            reopened = f.FileStore(self.left.file_store.root)
            reopened.scan()
            self.assertEqual(reopened.manifest()['files'], [])
            self.left.file_store = reopened
            self.left.file_replicator.store = reopened
            self.left.file_replicator.sync_once()
            self.assertEqual(target.read_bytes(), original)
            backups = list((reopened.state / 'quarantine').iterdir())
            self.assertEqual(backups[0].read_bytes(), b'corrupted content')
            target.unlink()
            self.left.file_replicator.sync_once()
            self.assertEqual(target.read_bytes(), original)

    def test_quarantine_backups_are_pruned_by_age_and_size(self):
        store = self.left.file_store
        quarantine = store.state / 'quarantine'
        quarantine.mkdir(exist_ok=True)
        aged = quarantine / 'aged.bak'
        aged.write_bytes(b'x' * 16)
        ancient = time.time() - (31 * 86400)
        os.utime(aged, (ancient, ancient))
        kept = quarantine / 'kept.bak'
        kept.write_bytes(b'y' * 16)
        store.prune_quarantine()
        self.assertFalse(aged.exists())
        self.assertTrue(kept.exists())
        now = time.time()
        os.utime(kept, (now, now + 10))  # Newest: the size cap must evict older ones first.
        for index, name in enumerate(('first.bak', 'second.bak', 'third.bak')):
            path = quarantine / name
            path.write_bytes(b'z' * 16)
            os.utime(path, (now, now + index))  # Distinct mtimes: first is oldest.
        with patch.object(f, 'QUARANTINE_MAX_BYTES', 48):
            store.prune_quarantine()
        remaining = {path.name for path in quarantine.iterdir()}
        # kept + 3 x 16 = 64 bytes over a 48-byte cap: the oldest goes first.
        self.assertEqual(remaining, {'kept.bak', 'second.bak', 'third.bak'})

    def test_slow_peer_does_not_starve_other_peers(self):
        third = m.PeerNode('127.0.0.1', 9103, None, shared_dir=self.root / 'third')
        self.addCleanup(third.file_store.close)
        self.addCleanup(third.stop_event.set)
        self.left.handle_message(third.message())
        slow = [{'path': f'slow-{i}.txt', 'sha256': 'a' * 64, 'size': 1} for i in range(50)]
        fast = [{'path': 'fast.txt', 'sha256': 'b' * 64, 'size': 1}]
        calls = []
        def fake_manifest(peer):
            return list(slow if peer.port == 9102 else fast)
        def fake_download(peer, item):
            calls.append(peer.port)
            time.sleep(0.2)
        replicator = self.left.file_replicator
        with patch.object(f.FileReplicator, 'remote_manifest', side_effect=fake_manifest), \
             patch.object(replicator, 'download', side_effect=fake_download), \
             patch.object(f, 'MAX_PEER_SECONDS_PER_PASS', 0.5):
            replicator.sync_once()
        slow_calls = [port for port in calls if port == 9102]
        self.assertLess(len(slow_calls), 32)  # The time budget cut it off, not the 32-file cap.
        self.assertIn(9103, calls)  # The fast peer was still served this pass.

    def test_conflicting_versions_converge_without_overwrite_or_new_alias_entries(self):
        (self.left.file_store.root / 'report.txt').write_bytes(b'left version')
        (self.right.file_store.root / 'report.txt').write_bytes(b'right version')
        self.left.file_store.scan()
        self.right.file_store.scan()
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.left.file_replicator.sync_once()
        with patch.object(self.right, 'exchange', side_effect=lambda peer, message: self.left.handle_message(message)):
            self.right.file_replicator.sync_once()
        for node in (self.left, self.right):
            node.file_store.scan()
            self.assertEqual(len(node.file_store.manifest()['files']), 2)
            content = {node.file_store.safe_path(record['destination'], internal=True).read_bytes()
                       for record in node.file_store.records.values()}
            self.assertEqual(content, {b'left version', b'right version'})
        self.assertEqual((self.left.file_store.root / 'report.txt').read_bytes(), b'left version')
        self.assertEqual((self.right.file_store.root / 'report.txt').read_bytes(), b'right version')

    def test_corrupt_and_interrupted_transfers_never_install_partial_files(self):
        (self.right.file_store.root / 'data.bin').write_bytes(b'x' * (f.CHUNK_BYTES + 10))
        self.right.file_store.scan()
        item = self.right.file_store.manifest()['files'][0]

        def corrupt(peer, request):
            response = self.serve_right(peer, request)
            if request['type'] == 'file-chunk':
                data = base64.b64decode(response['data'])
                response['data'] = base64.b64encode(b'y' + data[1:]).decode()
            return response

        with patch.object(self.left, 'exchange', side_effect=corrupt), self.assertRaises(ValueError):
            self.left.file_replicator.download(self.right.identity, item)
        self.assertFalse((self.left.file_store.root / 'data.bin').exists())
        self.assertFalse(list(self.left.file_store.temp.iterdir()))

        def interrupted(peer, request):
            if request.get('offset', 0) > 0:
                raise ConnectionError('connection interrupted')
            return self.serve_right(peer, request)

        with patch.object(self.left, 'exchange', side_effect=interrupted), self.assertRaises(ConnectionError):
            self.left.file_replicator.download(self.right.identity, item)
        self.assertFalse(list(self.left.file_store.temp.iterdir()))
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.left.file_replicator.download(self.right.identity, item)
        self.assertTrue(self.left.file_store.has_copy(item))

    def test_traversal_and_reserved_names_rejected_before_state_changes(self):
        for path in ('../secret', '/secret', 'C:/secret', 'sub/../../secret',
                     'sub\\secret', 'data:stream', '.peer-sync/index.json',
                     'replica-conflicts/file', 'CON.txt', 'folder./file'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                f.logical_path(path)
        before = copy.deepcopy(self.right.profiles)
        request = self.left.message('file-chunk')
        request.update(file={'path': '../secret', 'size': 10, 'sha256': 'a' * 64}, offset=0)
        with self.assertRaises(ValueError):
            self.right.handle_message(request)
        self.assertEqual(self.right.profiles, before)

    def test_hardlinks_not_shared(self):
        outside = self.root / 'secret.txt'
        outside.write_text('private')
        os.link(outside, self.left.file_store.root / 'link.txt')
        self.left.file_store.scan()
        self.assertEqual(self.left.file_store.manifest()['files'], [])

    def test_manifest_pagination_and_generation_change(self):
        for number in range(70):
            (self.right.file_store.root / f'{number:03}.txt').write_text(str(number))
        self.right.file_store.scan()
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.assertEqual(len(self.left.file_replicator.remote_manifest(self.right.identity)), 70)
        page = self.right.file_store.manifest()
        self.assertEqual(len(page['files']), f.MANIFEST_PAGE)
        (self.right.file_store.root / 'new.txt').write_text('new')
        self.right.file_store.scan()
        with self.assertRaises(ValueError):
            self.right.file_store.manifest(page['next_after'], page['generation'])

    def test_unchanged_remote_manifest_is_fetched_as_one_page_and_repairs_still_happen(self):
        for number in range(70):  # three manifest pages
            (self.right.file_store.root / f'{number:03}.txt').write_text(str(number))
        self.right.file_store.scan()
        requests = []

        def counting(peer, message):
            requests.append(message['type'])
            return self.serve_right(peer, message)

        def sync_counting():
            requests.clear()
            with patch.object(self.left, 'exchange', side_effect=counting):
                self.left.file_replicator.sync_once()
            return requests.count('file-manifest')

        # At most MAX_DOWNLOADS_PER_PASS files per peer per pass: later passes reuse the
        # remembered manifest (one page each) while the downloads continue.
        self.assertEqual(sync_counting(), 3)
        self.assertEqual(len(self.left.file_store.intact), f.MAX_DOWNLOADS_PER_PASS)
        self.assertEqual(sync_counting(), 1)
        self.assertEqual(sync_counting(), 1)
        self.assertEqual(len(self.left.file_store.intact), 70)
        # Nothing changed on the peer: only the first page is requested, and nothing downloaded.
        self.assertEqual(sync_counting(), 1)
        self.assertNotIn('file-chunk', requests)
        # A local copy that went missing is still repaired from the remembered manifest.
        (self.left.file_store.root / '042.txt').unlink()
        self.assertEqual(sync_counting(), 1)
        self.assertEqual((self.left.file_store.root / '042.txt').read_text(), '42')
        # A change on the peer changes its generation: the whole manifest is fetched again.
        (self.right.file_store.root / 'new.txt').write_text('new')
        self.right.file_store.scan()
        self.assertEqual(sync_counting(), 3)
        self.assertEqual((self.left.file_store.root / 'new.txt').read_text(), 'new')

    def test_storage_quota_and_oversize_file_do_not_block_smaller_files(self):
        (self.right.file_store.root / 'a-large').write_bytes(b'x' * 20)
        (self.right.file_store.root / 'b-small').write_bytes(b'y' * 4)
        self.right.file_store.scan()
        self.left.file_store.max_file_bytes = 10
        self.left.file_store.max_shared_bytes = 4
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.left.file_replicator.sync_once()
        self.assertFalse((self.left.file_store.root / 'a-large').exists())
        self.assertEqual((self.left.file_store.root / 'b-small').read_bytes(), b'yyyy')
        item = {'path': 'another', 'size': 1, 'sha256': hashlib.sha256(b'z').hexdigest()}
        self.assertFalse(self.left.file_store.can_receive(item))

    def test_unchanged_files_are_not_rehashed_and_scan_does_not_block_peers(self):
        store = self.left.file_store
        (store.root / 'keep.bin').write_bytes(b'k' * 1000)
        (store.root / 'edit.bin').write_bytes(b'e' * 1000)
        store.scan()
        items = {item['path']: item for item in store.manifest()['files']}
        hashed, lock_free = [], []
        real = f.fingerprint

        def counting(path, max_size):
            hashed.append(Path(path).name)
            # Another thread (an inbound peer request) must be able to take the store lock.
            probe = threading.Thread(target=lambda: lock_free.append(
                store.lock.acquire(timeout=1) and (store.lock.release() or True)))
            probe.start()
            probe.join()
            return real(path, max_size)

        with patch.object(f, 'fingerprint', side_effect=counting):
            store.scan()
            self.assertEqual(hashed, [])
            for item in items.values():
                self.assertTrue(store.has_copy(item))
            self.assertEqual(hashed, [])
            # A changed file is rehashed, found damaged, and no longer offered.
            (store.root / 'edit.bin').write_bytes(b'x' * 999)
            store.scan()
            self.assertEqual(hashed, ['edit.bin'])
            self.assertFalse(store.has_copy(items['edit.bin']))
            self.assertTrue(store.has_copy(items['keep.bin']))
            # Periodic full verification still rehashes unchanged files.
            hashed.clear()
            store.last_full_verify -= f.FULL_VERIFY_SECONDS
            store.scan()
            self.assertEqual(sorted(hashed), ['edit.bin', 'keep.bin'])
        self.assertTrue(lock_free and all(lock_free))
        self.assertEqual([item['path'] for item in store.manifest()['files']], ['keep.bin'])

    def test_download_is_private_until_verified_then_world_writable(self):
        content = b'p' * (f.CHUNK_BYTES + 5)
        (self.right.file_store.root / 'shared.bin').write_bytes(content)
        self.right.file_store.scan()
        item = self.right.file_store.manifest()['files'][0]
        target = self.left.file_store.root / 'shared.bin'
        opened, chmods, partial_modes = [], [], []
        real_open, real_chmod = os.open, Path.chmod

        def recording_open(path, flags, mode=0o777, *args, **kwargs):
            if str(path).endswith('.part'):
                opened.append(mode)
            return real_open(path, flags, mode, *args, **kwargs)

        def recording_chmod(path, mode, *args, **kwargs):
            chmods.append((Path(path).name, mode, Path(path).read_bytes() == content))
            return real_chmod(path, mode, *args, **kwargs)

        def serve(peer, request):
            partial_modes.extend(part.stat().st_mode & 0o777 for part in self.left.file_store.temp.iterdir())
            return self.serve_right(peer, request)

        with patch.object(f.os, 'open', side_effect=recording_open), \
             patch.object(Path, 'chmod', autospec=True, side_effect=recording_chmod), \
             patch.object(self.left, 'exchange', side_effect=serve):
            self.left.file_replicator.download(self.right.identity, item)
        self.assertEqual(opened, [0o600])
        # Only the verified, installed file is opened up; never the in-progress download.
        self.assertEqual(chmods, [('shared.bin', 0o666, True)])
        if os.name == 'posix':
            self.assertTrue(partial_modes and all(mode & 0o077 == 0 for mode in partial_modes))
            self.assertEqual(target.stat().st_mode & 0o777, 0o666)

    def test_malformed_index_records_fail_with_a_clean_error(self):
        good = {'file': {'path': 'a.txt', 'sha256': 'a' * 64, 'size': 1}, 'destination': 'a.txt'}
        for record in (1, None, [], {}, {'file': good['file']}, {'destination': 'a.txt'},
                       dict(good, destination=5), dict(good, destination=None), dict(good, extra=1),
                       dict(good, file='a.txt')):
            with self.subTest(record=record):
                directory = self.root / ('index-' + uuid.uuid4().hex)
                (directory / '.peer-sync').mkdir(parents=True)
                (directory / '.peer-sync/index.json').write_text(json.dumps({'version': 1, 'files': [record]}))
                with self.assertRaisesRegex(ValueError, 'index|file entry'):
                    f.FileStore(directory).close()

    def sync(self, node, *sources):
        by_port = {source.identity.port: source for source in sources}
        with patch.object(node, 'exchange', side_effect=lambda peer, message:
                          by_port[peer.port].handle_message(message, source_host='127.0.0.1')):
            node.file_replicator.sync_once()

    def manifest_paths(self, node):
        return sorted(item['path'] for item in node.file_store.manifest()['files'])

    def test_delete_marker_is_stamped_and_removes_the_file_on_every_node(self):
        (self.right.file_store.root / 'a.txt').write_bytes(b'remove me')
        (self.right.file_store.root / 'keep.txt').write_bytes(b'keep me')
        self.right.file_store.scan()
        self.sync(self.left, self.right)
        self.assertTrue((self.left.file_store.root / 'a.txt').exists())
        stale = m.PeerNode('127.0.0.1', 9103, None, shared_dir=self.root / 'stale')
        try:
            self.check_marker_removes_file_everywhere(stale)
        finally:
            stale.file_store.close()  # Before tearDown removes the directory (Windows locks).

    def check_marker_removes_file_everywhere(self, stale):
        (stale.file_store.root / 'a.txt').write_bytes(b'remove me')
        stale.file_store.scan()

        marker = self.right.file_store.root / 'a.txt.delete'
        marker.touch()
        self.right.file_store.scan()
        self.assertFalse(marker.exists())  # moved out of the shared folder...
        stamped = hidden_marker(self.right, 'a.txt.delete')
        self.assertIsNotNone(f.marker_created(stamped))  # ...into .peer-sync/markers, stamped
        self.assertFalse((self.right.file_store.root / 'a.txt').exists())
        self.assertEqual(self.manifest_paths(self.right), ['a.txt.delete', 'keep.txt'])

        self.sync(self.left, self.right)
        self.assertFalse((self.left.file_store.root / 'a.txt').exists())
        self.assertEqual(hidden_marker(self.left, 'a.txt.delete'), stamped)
        self.assertFalse((self.left.file_store.root / 'a.txt.delete').exists())  # never visible
        self.assertEqual(self.manifest_paths(self.left), ['a.txt.delete', 'keep.txt'])
        # A peer that has not seen the marker yet cannot bring the file back...
        self.left.handle_message(stale.message())
        self.sync(self.left, self.right, stale)
        self.assertFalse((self.left.file_store.root / 'a.txt').exists())
        # ...and neither can someone recreating it locally while the marker is active.
        (self.left.file_store.root / 'a.txt').write_bytes(b'recreated')
        self.left.file_store.scan()
        self.assertFalse((self.left.file_store.root / 'a.txt').exists())
        self.assertEqual(self.manifest_paths(self.left), ['a.txt.delete', 'keep.txt'])

    def test_folder_marker_removes_everything_under_it_and_the_emptied_folders(self):
        root = self.right.file_store.root
        (root / 'photos/sub').mkdir(parents=True)
        (root / 'photos/x.jpg').write_bytes(b'x')
        (root / 'photos/sub/y.jpg').write_bytes(b'y')
        (root / 'photosbook.txt').write_bytes(b'not inside the folder')
        (root / 'other.txt').write_bytes(b'other')
        self.right.file_store.scan()
        (root / 'photos.delete').touch()
        self.right.file_store.scan()
        self.assertFalse((root / 'photos').exists())
        self.assertEqual(self.manifest_paths(self.right), ['other.txt', 'photos.delete', 'photosbook.txt'])

    def test_marker_removes_conflict_copies_too(self):
        (self.left.file_store.root / 'report.txt').write_bytes(b'left version')
        (self.right.file_store.root / 'report.txt').write_bytes(b'right version')
        self.left.file_store.scan()
        self.right.file_store.scan()
        self.right.handle_message(self.left.message())
        self.sync(self.left, self.right)
        self.sync(self.right, self.left)
        self.assertEqual(len(self.left.file_store.manifest()['files']), 2)
        (self.right.file_store.root / 'report.txt.delete').touch()
        self.right.file_store.scan()
        self.sync(self.left, self.right)
        for node in (self.left, self.right):
            with self.subTest(node=node.identity.port):
                self.assertEqual(self.manifest_paths(node), ['report.txt.delete'])
                self.assertFalse((node.file_store.root / 'report.txt').exists())
                leftovers = [path for path in (node.file_store.root / 'replica-conflicts').rglob('*')
                             if path.is_file()] if (node.file_store.root / 'replica-conflicts').exists() else []
                self.assertEqual(leftovers, [])

    def test_marker_expires_everywhere_and_the_name_can_be_reused(self):
        store = self.right.file_store
        (store.root / 'a.txt').write_bytes(b'old')
        (store.root / 'a.txt.delete').touch()
        store.scan()
        marker_item = next(item for item in store.manifest()['files'] if item['path'] == 'a.txt.delete')
        self.assertFalse((store.root / 'a.txt').exists())
        later = time.time() + f.MARKER_TTL_SECONDS + 1
        with patch.object(f.time, 'time', return_value=later):
            store.scan()
            self.assertFalse((store.root / 'a.txt.delete').exists())
            self.assertIsNone(hidden_marker(self.right, 'a.txt.delete'))
            self.assertEqual(self.manifest_paths(self.right), [])
            self.assertTrue(store.blocked(marker_item))  # a peer still offering it is ignored
            # The name is free again: new content replicates normally.
            (store.root / 'a.txt').write_bytes(b'new')
            store.scan()
            self.sync(self.left, self.right)
        self.assertEqual((self.left.file_store.root / 'a.txt').read_bytes(), b'new')
        self.assertFalse((self.left.file_store.root / 'a.txt.delete').exists())
        store.close()
        reopened = f.FileStore(store.root)
        self.right.file_store = reopened
        self.assertTrue(reopened.blocked(marker_item))  # retirement survives a restart

    def test_ordinary_files_ending_in_delete_are_left_alone(self):
        root = self.right.file_store.root
        (root / 'notes').write_bytes(b'notes')
        (root / 'notes.delete').write_bytes(b'real data, not a marker')
        (root / 'sub').mkdir()
        (root / 'sub/.delete').touch()  # would target a folder's root: never a marker
        self.right.file_store.scan()
        self.assertEqual((root / 'notes').read_bytes(), b'notes')
        self.assertEqual((root / 'notes.delete').read_bytes(), b'real data, not a marker')
        self.assertEqual((root / 'sub/.delete').read_bytes(), b'')
        self.assertEqual(self.manifest_paths(self.right), ['notes', 'notes.delete', 'sub/.delete'])

    def test_renaming_a_file_to_delete_removes_it_everywhere(self):
        root = self.left.file_store.root
        (root / 'report.txt').write_bytes(b'quarterly numbers')
        (root / 'keep.txt').write_bytes(b'keep')
        self.left.file_store.scan()
        self.right.handle_message(self.left.message())
        self.sync(self.right, self.left)
        (root / 'report.txt').rename(root / 'report.txt.delete')
        self.left.file_store.scan()
        self.assertFalse((root / 'report.txt.delete').exists())
        self.assertIsNotNone(f.marker_created(hidden_marker(self.left, 'report.txt.delete')))
        self.sync(self.right, self.left)
        self.sync(self.left, self.right)
        for node in (self.left, self.right):
            with self.subTest(node=node.identity.port):
                self.assertFalse((node.file_store.root / 'report.txt').exists())
                self.assertEqual(self.manifest_paths(node), ['keep.txt', 'report.txt.delete'])
                # Both are gone from the folder; only the hidden marker remains, not the contents.
                self.assertFalse((node.file_store.root / 'report.txt.delete').exists())
                self.assertNotIn(b'quarterly', hidden_marker(node, 'report.txt.delete'))

    def test_renaming_a_folder_to_delete_removes_it_everywhere(self):
        root = self.left.file_store.root
        (root / 'photos/sub').mkdir(parents=True)
        (root / 'photos/x.jpg').write_bytes(b'x')
        (root / 'photos/sub/y.jpg').write_bytes(b'y')
        (root / 'other.txt').write_bytes(b'other')
        self.left.file_store.scan()
        self.right.handle_message(self.left.message())
        self.sync(self.right, self.left)
        self.assertTrue((self.right.file_store.root / 'photos/sub/y.jpg').exists())
        (root / 'photos').rename(root / 'photos.delete')
        self.left.file_store.scan()
        self.assertFalse((root / 'photos.delete').exists())
        self.assertIsNotNone(f.marker_created(hidden_marker(self.left, 'photos.delete')))
        self.sync(self.right, self.left)
        self.sync(self.left, self.right)
        for node in (self.left, self.right):
            with self.subTest(node=node.identity.port):
                self.assertFalse((node.file_store.root / 'photos').exists())
                self.assertEqual(self.manifest_paths(node), ['other.txt', 'photos.delete'])

    def test_delete_named_files_and_folders_that_are_not_exact_copies_stay_ordinary(self):
        root = self.left.file_store.root
        (root / 'report.txt').write_bytes(b'original')
        (root / 'photos').mkdir()
        (root / 'photos/x.jpg').write_bytes(b'x')
        self.left.file_store.scan()
        (root / 'report.txt.delete').write_bytes(b'different contents')
        (root / 'photos.delete').mkdir()
        (root / 'photos.delete/x.jpg').write_bytes(b'x')
        (root / 'photos.delete/extra.txt').write_bytes(b'not in photos/')
        (root / 'edited.delete').mkdir()
        (root / 'edited').mkdir()
        (root / 'edited/a.txt').write_bytes(b'a')
        self.left.file_store.scan()
        (root / 'edited.delete/a.txt').write_bytes(b'changed')
        (root / 'never-shared.delete').mkdir()
        (root / 'never-shared.delete/b.txt').write_bytes(b'b')
        self.left.file_store.scan()
        self.assertEqual(self.manifest_paths(self.left),
                         ['edited.delete/a.txt', 'edited/a.txt', 'never-shared.delete/b.txt',
                          'photos.delete/extra.txt', 'photos.delete/x.jpg', 'photos/x.jpg',
                          'report.txt', 'report.txt.delete'])
        self.assertEqual((root / 'report.txt.delete').read_bytes(), b'different contents')

    def test_visible_markers_from_older_releases_are_moved_into_hiding(self):
        # Before hidden markers, a stamped marker lived in the shared folder as an ordinary record.
        directory = self.root / 'upgraded'
        (directory / '.peer-sync').mkdir(parents=True)
        data = f.marker_bytes(int(time.time()))
        (directory / 'old.txt.delete').write_bytes(data)
        (directory / 'old.txt').write_bytes(b'should be deleted')
        item = {'path': 'old.txt.delete', 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        (directory / '.peer-sync/index.json').write_text(json.dumps(
            {'version': 1, 'files': [{'file': item, 'destination': 'old.txt.delete'}], 'retired_markers': []}))
        store = f.FileStore(directory)
        try:
            store.scan()
            self.assertFalse((directory / 'old.txt.delete').exists())
            self.assertFalse((directory / 'old.txt').exists())
            self.assertEqual(store.marker_file(item).read_bytes(), data)
            self.assertEqual([entry['path'] for entry in store.manifest()['files']], ['old.txt.delete'])
            index = json.loads((directory / '.peer-sync/index.json').read_text())
            self.assertEqual(index['files'], [])
            self.assertEqual(index['markers'], [{'file': item}])
        finally:
            store.close()
        reopened = f.FileStore(directory)  # the hidden marker survives a restart
        try:
            self.assertEqual(list(reopened.markers.values()), [item])
        finally:
            reopened.close()

    def test_missing_hidden_marker_is_dropped_and_fetched_again(self):
        (self.right.file_store.root / 'x.txt.delete').touch()
        self.right.file_store.scan()
        self.sync(self.left, self.right)
        item = next(i for i in self.left.file_store.markers.values() if i['path'] == 'x.txt.delete')
        self.left.file_store.marker_file(item).unlink()
        self.left.file_store.marker_times.clear()
        self.left.file_store.apply_markers()
        self.assertEqual(self.left.file_store.markers, {})
        self.sync(self.left, self.right)
        self.assertEqual(hidden_marker(self.left, 'x.txt.delete'), hidden_marker(self.right, 'x.txt.delete'))

    def test_delete_delete_still_undoes_a_hidden_marker(self):
        store = self.left.file_store
        (store.root / 'keep.txt').write_bytes(b'v1')
        (store.root / 'keep.txt.delete').touch()
        store.scan()
        self.assertFalse((store.root / 'keep.txt').exists())
        self.assertEqual(store.deleting, ('keep.txt',))
        (store.root / 'keep.txt.delete.delete').touch()
        store.scan()
        self.assertIsNone(hidden_marker(self.left, 'keep.txt.delete'))
        self.assertEqual(store.deleting, ('keep.txt.delete',))
        (store.root / 'keep.txt').write_bytes(b'v2')  # the name can be used again at once
        store.scan()
        self.assertIn('keep.txt', self.manifest_paths(self.left))
        self.assertEqual(sorted(p.name for p in store.root.iterdir() if p.is_file()), ['keep.txt'])

    def test_index_without_retired_markers_still_loads_and_bad_ones_are_rejected(self):
        for retired, valid in (((), True), ([], True), (['a.txt\0' + 'b' * 64], True),
                               ('nope', False), ([5], False), (['../x\0' + 'b' * 64], False),
                               (['a.txt'], False)):
            with self.subTest(retired=retired):
                directory = self.root / ('index-' + uuid.uuid4().hex)
                (directory / '.peer-sync').mkdir(parents=True)
                index = {'version': 1, 'files': []}
                if retired != ():
                    index['retired_markers'] = retired
                (directory / '.peer-sync/index.json').write_text(json.dumps(index))
                if valid:
                    f.FileStore(directory).close()
                else:
                    with self.assertRaisesRegex(ValueError, 'index|path|digest'):
                        f.FileStore(directory).close()

    def test_downloads_are_paced_to_the_rate_limit(self):
        content = os.urandom(4 * f.CHUNK_BYTES)
        (self.right.file_store.root / 'big.bin').write_bytes(content)
        self.right.file_store.scan()
        item = self.right.file_store.manifest()['files'][0]
        replicator = self.left.file_replicator
        replicator.download_rate = f.CHUNK_BYTES  # one chunk per second
        replicator.next_housekeeping = float('inf')  # this test is about pacing only
        clock = [time.monotonic()]  # simulated, but starting from the real reading
        waits = []

        def wait(seconds):  # a simulated clock: waiting advances it
            waits.append(seconds)
            clock[0] += seconds
            return False

        with patch.object(f.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.left.stop_event, 'wait', side_effect=wait), \
             patch.object(self.left, 'exchange', side_effect=self.serve_right):
            replicator.download(self.right.identity, item)
        self.assertEqual((self.left.file_store.root / 'big.bin').read_bytes(), content)
        self.assertEqual(waits, [1.0, 1.0, 1.0, 1.0])  # 4 chunks at 1 chunk/s
        # Idle time does not bank up a burst: after a long pause, pacing resumes at the rate.
        clock[0] += 3600
        waits.clear()
        with patch.object(f.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.left.stop_event, 'wait', side_effect=wait):
            replicator.pace(f.CHUNK_BYTES)
            replicator.pace(f.CHUNK_BYTES)
        self.assertEqual(waits, [1.0, 1.0])

    def long_download(self, on_chunk=None, others=()):
        """Download a 10-chunk file from right at 2 chunks/s (set through limits.json, which
        housekeeping re-reads) on a simulated clock, with a 2s sync interval.
        Returns (outcome, chunk offsets served, simulated times of scans on left, content)."""
        content = os.urandom(10 * f.CHUNK_BYTES)
        (self.right.file_store.root / 'big.bin').write_bytes(content)
        self.right.file_store.scan()
        item = next(i for i in self.right.file_store.manifest()['files'] if i['path'] == 'big.bin')
        (self.left.file_store.root / '.peer-sync/limits.json').write_text(
            json.dumps({'max_download_bytes_per_second': 2 * f.CHUNK_BYTES}))
        replicator = self.left.file_replicator
        replicator.refresh_rate()
        # Simulated, but starting from the real reading: peers' last-seen times use the real clock.
        start = time.monotonic()
        clock = [start]
        chunks, scans = [], []
        real_scan = self.left.file_store.scan

        def wait(seconds):
            clock[0] += seconds
            return False

        def serve(peer, message):
            other = next((node for node in others if node.identity == peer), None)
            if other is not None:
                return other.handle_message(message, source_host='127.0.0.1')
            reply = self.serve_right(peer, message)
            if message['type'] == 'file-chunk':
                chunks.append(message['offset'])
                if on_chunk:
                    on_chunk(len(chunks))
            return reply

        def counting_scan():
            scans.append(round(clock[0] - start, 6))  # seconds into the download
            return real_scan()

        with patch.object(f, 'SYNC_INTERVAL_SECONDS', 2), \
             patch.object(f.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.left.stop_event, 'wait', side_effect=wait), \
             patch.object(self.left.file_store, 'scan', side_effect=counting_scan), \
             patch.object(self.left, 'exchange', side_effect=serve):
            replicator.next_housekeeping = clock[0] + f.SYNC_INTERVAL_SECONDS
            try:
                replicator.download(self.right.identity, item)
                outcome = 'installed'
            except ValueError as error:
                outcome = str(error)
        return outcome, chunks, scans, content

    def test_long_download_keeps_housekeeping_on_schedule(self):
        outcome, chunks, scans, content = self.long_download()
        self.assertEqual(outcome, 'installed')
        self.assertEqual(len(chunks), 10)
        self.assertEqual(scans, [2.0, 4.0])  # once per 2s interval, not per chunk
        self.assertEqual((self.left.file_store.root / 'big.bin').read_bytes(), content)

    def test_marker_arriving_during_a_long_download_stops_it_and_local_files_are_picked_up(self):
        # The marker is created on another node; the source has not seen it and keeps serving.
        third = m.PeerNode('127.0.0.1', 9103, None, shared_dir=self.root / 'third')
        try:
            self.left.handle_message(third.message())

            def midway(served):
                if served == 2:
                    (third.file_store.root / 'big.bin.delete').touch()
                    third.file_store.scan()
                    (self.left.file_store.root / 'added-meanwhile.txt').write_bytes(b'new local file')

            outcome, chunks, scans, _ = self.long_download(on_chunk=midway, others=(third,))
        finally:
            third.file_store.close()  # Before tearDown removes the directory (Windows locks).
        self.assertTrue((self.right.file_store.root / 'big.bin').exists())  # source never saw it
        self.assertEqual(outcome, 'removed by a .delete marker while downloading')
        self.assertEqual(len(chunks), 4)  # stopped at the first housekeeping after the marker
        self.assertFalse((self.left.file_store.root / 'big.bin').exists())
        self.assertIsNotNone(f.marker_created(hidden_marker(self.left, 'big.bin.delete')))
        self.assertFalse((self.left.file_store.root / 'big.bin.delete').exists())
        self.assertIn('added-meanwhile.txt', self.manifest_paths(self.left))
        self.assertEqual(list(self.left.file_store.temp.iterdir()), [])

    def test_unlimited_rate_never_waits_and_shutdown_interrupts_pacing(self):
        replicator = self.left.file_replicator
        replicator.download_rate = 0
        with patch.object(self.left.stop_event, 'wait', side_effect=AssertionError('waited')):
            replicator.pace(10 * f.CHUNK_BYTES)
        replicator.download_rate = f.CHUNK_BYTES
        with patch.object(self.left.stop_event, 'wait', return_value=True), \
             self.assertRaises(InterruptedError):
            replicator.pace(f.CHUNK_BYTES)

    def test_download_deadline_stretches_with_the_rate_limit(self):
        replicator = self.left.file_replicator
        replicator.download_rate = 2 * 1024 * 1024
        self.assertEqual(replicator.deadline_for(1024), f.FILE_DEADLINE_SECONDS)
        self.assertEqual(replicator.deadline_for(1024 ** 3), 3 * 512)  # 1 GiB at 2 MiB/s = 512s
        replicator.download_rate = 0
        self.assertEqual(replicator.deadline_for(1024 ** 3), f.FILE_DEADLINE_SECONDS)

    def test_rate_limit_comes_from_limits_file_or_defaults(self):
        store, replicator = self.left.file_store, self.left.file_replicator
        limits = store.root / '.peer-sync/limits.json'
        messages = []
        replicator.log = messages.append
        self.assertEqual(store.download_rate(), (f.DEFAULT_MAX_DOWNLOAD_RATE, 'default'))
        replicator.refresh_rate()
        replicator.refresh_rate()
        self.assertEqual(messages, ['download rate limit: 2.00 MiB/s (default)'])  # logged once
        limits.write_text(json.dumps({'max_download_bytes_per_second': 5 * 1024 * 1024}))
        replicator.refresh_rate()
        self.assertEqual(replicator.download_rate, 5 * 1024 * 1024)
        self.assertIn('5.00 MiB/s', messages[-1])
        limits.write_text(json.dumps({'max_download_bytes_per_second': 0}))
        replicator.refresh_rate()
        self.assertEqual(replicator.download_rate, 0)
        self.assertIn('unlimited', messages[-1])
        for bad in ('{not json', '[]', '{"max_download_bytes_per_second": 100}',
                    '{"max_download_bytes_per_second": "fast"}', '{"other": 1}'):
            with self.subTest(bad=bad):
                limits.write_text(bad)
                rate, source = store.download_rate()
                self.assertEqual(rate, f.DEFAULT_MAX_DOWNLOAD_RATE)
                self.assertIn('default;', source)

    def test_briefly_denied_file_operations_are_retried(self):
        outcomes = [PermissionError(5, 'Access is denied'), PermissionError(5, 'Access is denied'), 'done']

        def action():
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        with patch.object(f.time, 'sleep') as sleep:
            self.assertEqual(f.retry_denied(action), 'done')
            self.assertEqual(sleep.call_count, 2)
            with self.assertRaises(PermissionError):
                f.retry_denied(lambda: (_ for _ in ()).throw(PermissionError(5, 'denied')))
        # A saved index survives a briefly locked index.json.
        real_replace = os.replace
        denied = [PermissionError(5, 'Access is denied')]

        def locked_once(source, destination):
            if denied:
                raise denied.pop()
            real_replace(source, destination)

        with patch.object(f.os, 'replace', side_effect=locked_once), patch.object(f.time, 'sleep'):
            (self.left.file_store.root / 'a.txt').write_bytes(b'a')
            self.left.file_store.scan()
        self.assertIn('a.txt', (self.left.file_store.root / '.peer-sync/index.json').read_text())

    def test_unexpected_error_does_not_stop_replication_thread(self):
        replicator = self.left.file_replicator
        calls = []

        def sync_once():
            calls.append(1)
            if len(calls) == 1:
                raise RecursionError('maximum recursion depth exceeded')
            self.left.stop_event.set()

        with patch.object(replicator, 'sync_once', side_effect=sync_once), \
             patch.object(f, 'SYNC_INTERVAL_SECONDS', 0), patch.object(replicator, 'log') as log:
            replicator.run()
        self.assertEqual(len(calls), 2)
        self.assertIn('RecursionError', log.call_args_list[0].args[0])

    def test_file_directory_collision_preserves_both(self):
        (self.left.file_store.root / 'folder').write_bytes(b'local file')
        (self.right.file_store.root / 'folder').mkdir()
        (self.right.file_store.root / 'folder/remote.txt').write_bytes(b'remote file')
        self.right.file_store.scan()
        with patch.object(self.left, 'exchange', side_effect=self.serve_right):
            self.left.file_replicator.sync_once()
        self.assertEqual((self.left.file_store.root / 'folder').read_bytes(), b'local file')
        self.assertEqual(len(self.left.file_store.manifest()['files']), 2)


class LiveReplicationTests(unittest.TestCase):
    def test_three_nodes_automatically_replicate_and_repair_without_original_source(self):
        nodes, threads = [], []

        def wait_for(predicate, timeout=10):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if predicate():
                    return
                time.sleep(.025)
            self.fail('replication did not converge')

        with tempfile.TemporaryDirectory() as directory, patch.object(f, 'SYNC_INTERVAL_SECONDS', .1):
            try:
                content = bytes(range(256)) * 300
                for number in range(3):
                    with socket.socket() as reservation:
                        reservation.bind(('127.0.0.1', 0))
                        port = reservation.getsockname()[1]
                    node = m.PeerNode('127.0.0.1', port, nodes[-1].identity if nodes else None,
                                      shared_dir=Path(directory) / str(number))
                    if number == 0:
                        (node.file_store.root / 'payload.bin').write_bytes(content)
                    nodes.append(node)
                    thread = threading.Thread(target=node.run, daemon=True)
                    threads.append(thread)
                    thread.start()
                    def ready():
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                return True
                        except OSError:
                            return False
                    wait_for(ready)
                def intact(node):
                    try:
                        return (node.file_store.root / 'payload.bin').read_bytes() == content
                    except OSError:
                        return False
                wait_for(lambda: all(intact(node) for node in nodes))
                nodes[0].stop_event.set()
                threads[0].join(16)
                self.assertFalse(threads[0].is_alive())
                damaged = nodes[1].file_store.root / 'payload.bin'
                damaged.write_bytes(b'broken')
                wait_for(lambda: intact(nodes[1]))
                self.assertTrue(intact(nodes[2]))
            finally:
                for node in nodes:
                    node.stop_event.set()
                for thread in threads:
                    thread.join(16)
                    self.assertFalse(thread.is_alive())


class LiveDeleteMarkerTests(unittest.TestCase):
    def test_marker_created_on_one_node_deletes_the_file_on_all_live_nodes(self):
        nodes, threads = [], []

        def wait_for(predicate, timeout=15):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if predicate():
                    return
                time.sleep(.025)
            self.fail('nodes did not converge')

        with tempfile.TemporaryDirectory() as directory, patch.object(f, 'SYNC_INTERVAL_SECONDS', .1):
            try:
                for number in range(3):
                    with socket.socket() as reservation:
                        reservation.bind(('127.0.0.1', 0))
                        port = reservation.getsockname()[1]
                    node = m.PeerNode('127.0.0.1', port, nodes[-1].identity if nodes else None,
                                      shared_dir=Path(directory) / str(number))
                    if number == 0:
                        (node.file_store.root / 'doomed.bin').write_bytes(b'd' * 5000)
                        (node.file_store.root / 'kept.bin').write_bytes(b'k' * 5000)
                    nodes.append(node)
                    threads.append(threading.Thread(target=node.run, daemon=True))
                    threads[-1].start()
                has = lambda node, name: (node.file_store.root / name).exists()
                wait_for(lambda: all(has(node, 'doomed.bin') and has(node, 'kept.bin') for node in nodes))
                (nodes[2].file_store.root / 'doomed.bin.delete').touch()
                wait_for(lambda: all(not has(node, 'doomed.bin') and not has(node, 'doomed.bin.delete')
                                     and hidden_marker(node, 'doomed.bin.delete')
                                     for node in nodes))
                time.sleep(.5)  # Several more sync passes: nothing may bring it back.
                self.assertFalse(any(has(node, 'doomed.bin') for node in nodes))
                self.assertTrue(all(has(node, 'kept.bin') for node in nodes))
                # Renaming a shared folder to *.delete removes it from every node too.
                (nodes[0].file_store.root / 'album').mkdir()
                (nodes[0].file_store.root / 'album/a.bin').write_bytes(b'a' * 3000)
                wait_for(lambda: all(has(node, 'album/a.bin') for node in nodes))
                (nodes[1].file_store.root / 'album').rename(nodes[1].file_store.root / 'album.delete')
                wait_for(lambda: all(not has(node, 'album') and not has(node, 'album.delete')
                                     and hidden_marker(node, 'album.delete')
                                     for node in nodes))
                time.sleep(.5)
                self.assertFalse(any(has(node, 'album') for node in nodes))
                self.assertTrue(all(has(node, 'kept.bin') for node in nodes))
            finally:
                for node in nodes:
                    node.stop_event.set()
                for thread in threads:
                    thread.join(16)
                    self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
