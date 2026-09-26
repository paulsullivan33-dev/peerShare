import base64
import copy
import hashlib
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import peer_handshake as m
import peer_files as f


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


if __name__ == '__main__':
    unittest.main()
