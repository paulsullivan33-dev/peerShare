import copy
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import peer_handshake as m
from peer_protocol import load_node_id, validate_profile, MAX_QUERY_RESULTS


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.local = m.PeerNode('127.0.0.1', 9101, None)
        self.remote = m.PeerNode('127.0.0.1', 9102, None, name='File server',
                                 capabilities=['file-search', 'file-transfer'],
                                 services=[{'name': 'search', 'capability': 'file-search', 'port': 9200}],
                                 resources={'shared_files': 42, 'transfer_slots': 4})

    def test_identity_persists_but_instance_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'node.id'
            first = m.PeerNode('127.0.0.1', 9101, None, node_id_file=path)
            second = m.PeerNode('127.0.0.1', 9103, None, node_id_file=path)
            self.assertEqual(first.local_profile['node_id'], second.local_profile['node_id'])
            self.assertNotEqual(first.local_profile['instance_id'], second.local_profile['instance_id'])
            path.write_text('invalid identity')
            with self.assertRaises(ValueError):
                load_node_id(path)
            self.assertEqual(path.read_text(), 'invalid identity')

    def test_profile_roundtrip_and_detached_state(self):
        message = self.remote.message()
        self.local.handle_message(message)
        record = self.local.profiles[self.remote.identity]['profile']
        self.assertEqual(record['name'], 'File server')
        self.assertEqual(record['resources']['shared_files'], 42)
        message['profile']['resources']['shared_files'] = 999
        self.assertEqual(record['resources']['shared_files'], 42)
        self.assertEqual(record['services'][0]['port'], 9200)

    def test_invalid_profiles_and_versions_do_not_change_state(self):
        profile = self.remote.local_profile
        invalid = [dict(profile, protocol_version=2), dict(profile, node_id='bad'),
                   dict(profile, availability='unknown'), dict(profile, sequence=True),
                   dict(profile, ttl_seconds=0), dict(profile, ttl_seconds=91),
                   dict(profile, capabilities=['chat', 'chat']),
                   dict(profile, resources={'files': -1}),
                   dict(profile, resources={'files': float('nan')}),
                   dict(profile, services=[{'name': 'search', 'capability': 'chat', 'port': 1}]),
                   dict(profile, name='x' * 5000)]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.local.handle_message(dict(self.remote.message(), profile=value))
            self.assertFalse(self.local.peers)
            self.assertFalse(self.local.profiles)
        with self.assertRaises(ValueError):
            self.local.handle_message(dict(self.remote.message(), protocol_version=2))
        self.assertFalse(self.local.peers)

    def test_status_sequence_prevents_rollback_and_update_is_atomic(self):
        original = self.remote.message()
        self.local.handle_message(original)
        self.remote.update_status(availability='busy', resources={'transfer_slots': 0})
        self.local.handle_message(self.remote.message('status'))
        current = copy.deepcopy(self.local.profiles)
        with self.assertRaises(ValueError):
            self.local.handle_message(original)
        self.assertEqual(self.local.profiles, current)
        before = copy.deepcopy(self.remote.local_profile)
        with self.assertRaises(ValueError):
            self.remote.update_status(resources={'transfer_slots': -1})
        self.assertEqual(self.remote.local_profile, before)
        changed = self.remote.message('status')
        changed['profile']['availability'] = 'ready'
        with self.assertRaises(ValueError):
            self.local.handle_message(changed)

    def test_restart_replaces_instance_and_rejects_old_messages(self):
        previous = self.remote.message()
        self.local.handle_message(previous)
        restarted = self.remote.message()
        restarted['profile']['instance_id'] = str(uuid.uuid4())
        self.local.handle_message(restarted)
        for kind in ('hello', 'status', 'goodbye'):
            old = dict(previous, type=kind)
            old.pop('peers', None)
            with self.assertRaises(ValueError):
                self.local.handle_message(old)
        self.assertEqual(self.local.profiles[self.remote.identity]['profile']['instance_id'],
                         restarted['profile']['instance_id'])

    def test_node_address_change_replaces_old_endpoint(self):
        self.local.handle_message(self.remote.message())
        moved = self.remote.message()
        moved['port'] = 9103
        moved['peers'] = []
        self.local.handle_message(moved)
        self.assertNotIn(self.remote.identity, self.local.peers)
        self.assertNotIn(self.remote.identity, self.local.profiles)
        self.assertIn(m.Peer('127.0.0.1', 9103), self.local.profiles)

    def test_profile_expiry_and_relay_provenance(self):
        with patch.object(m.time, 'monotonic', return_value=100) as clock:
            self.local.handle_message(self.remote.message())
            page = self.local.service_results('file-search')
            self.assertEqual(page['results'][0]['source'], 'direct')
            self.assertEqual(page['results'][0]['reported_by'], self.local.local_profile['node_id'])
            clock.return_value += 20
            self.assertEqual(self.local.service_results('file-search')['results'][0]['profile']['ttl_seconds'], 70)
            clock.return_value += 70
            self.assertEqual(self.local.service_results('file-search')['results'], [])
            self.local.handle_message(self.remote.message('status'))
            self.assertEqual(len(self.local.service_results('file-search')['results']), 1)

    def test_service_query_pagination_and_size_limit(self):
        for number in range(12):
            node = m.PeerNode('127.0.0.1', 9200 + number, None, capabilities=['chat'])
            self.local.handle_message(node.message())
        query = self.remote.message('service-query')
        query.update(capability='chat', limit=MAX_QUERY_RESULTS, offset=0)
        reply = self.local.handle_message(query)
        self.assertEqual(len(reply['results']), 8)
        self.assertEqual(reply['next_offset'], 8)
        self.assertLess(len(json.dumps(reply).encode()), m.MAX_MESSAGE_BYTES)
        query['offset'] = 8
        page = self.local.handle_message(query)
        self.assertEqual(len(page['results']), 4)
        self.assertIsNone(page['next_offset'])
        query['limit'] = 9
        with self.assertRaises(ValueError):
            self.local.handle_message(query)

    def test_relayed_results_do_not_become_direct_cached_profiles(self):
        intermediary = m.PeerNode('127.0.0.1', 9103, None)
        intermediary.handle_message(self.remote.message())
        with patch.object(self.local, 'exchange', side_effect=lambda peer, request: intermediary.handle_message(request)):
            response = self.local.query_services(intermediary.identity, 'file-search')
        self.assertEqual(response['results'][0]['source'], 'relayed')
        self.assertNotIn(self.remote.identity, self.local.profiles)
        self.assertEqual(response['results'][0]['reported_by'], intermediary.local_profile['node_id'])

    def test_invalid_service_response_does_not_mutate_client(self):
        response = self.remote.message('service-result')
        response.update(self.remote.service_results('file-search'))
        response['results'][0]['reported_by'] = str(uuid.uuid4())
        with patch.object(self.local, 'exchange', return_value=response), self.assertRaises(ValueError):
            self.local.query_services(self.remote.identity, 'file-search')
        self.assertFalse(self.local.peers)

    def test_goodbye_removes_current_instance_without_readding_it(self):
        self.local.handle_message(self.remote.message())
        response = self.local.handle_message(self.remote.message('goodbye'))
        self.assertEqual(response['type'], 'goodbye-ack')
        self.assertNotIn(self.remote.identity, self.local.peers)
        self.assertNotIn(self.remote.identity, self.local.profiles)
        with self.assertRaises(ValueError):
            self.local.handle_message(self.remote.message())

    def test_legacy_peer_has_no_invented_profile(self):
        self.local.handle_message({'type': 'hello', 'host': '127.0.0.1', 'port': 9102})
        self.assertIn(self.remote.identity, self.local.peers)
        self.assertNotIn(self.remote.identity, self.local.profiles)

    def test_tcp_status_query_and_goodbye(self):
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        server = m.PeerNode('127.0.0.1', port, None, capabilities=['chat'])
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 3
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        self.fail('server failed to start')
                    time.sleep(.01)
            self.assertTrue(self.remote.send_hello(server.identity))
            self.remote.update_status(availability='busy', resources={'transfer_slots': 0})
            self.remote.send_status(server.identity)
            self.assertEqual(server.profiles[self.remote.identity]['profile']['availability'], 'busy')
            result = self.remote.query_services(server.identity, 'chat')
            self.assertEqual(result['results'][0]['source'], 'direct')
            self.assertEqual(result['results'][0]['profile']['node_id'], server.local_profile['node_id'])
            self.remote.announce_shutdown()
            self.assertEqual(self.remote.local_profile['availability'], 'draining')
            self.assertNotIn(self.remote.identity, server.peers)
            with tempfile.TemporaryDirectory() as directory:
                command = [sys.executable, '-B', str(Path(m.__file__).resolve()),
                           '--port', '9199', '--connect', server.identity.address(),
                           '--query-service', 'chat']
                first = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=10)
                self.assertEqual(first.returncode, 0, first.stderr)
                page = json.loads(first.stdout)
                self.assertEqual(page['results'][0]['profile']['node_id'], server.local_profile['node_id'])
                identity = load_node_id(Path(directory) / '.peer-node-9199.id')
                second = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=10)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual(identity, load_node_id(Path(directory) / '.peer-node-9199.id'))
                self.assertNotIn(m.Peer('127.0.0.1', 9199), server.peers)
        finally:
            server.stop_event.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
