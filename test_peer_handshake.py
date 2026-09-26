import socket
import threading
import unittest
from unittest.mock import patch
import peer_handshake as m

class ResourceTests(unittest.TestCase):
    def test_identity(self):
        with self.assertRaises(ValueError):
            m.PeerNode('0.0.0.0', 9101, None)
        node = m.PeerNode('0.0.0.0', 9101, None, '192.168.1.20')
        self.assertEqual(node.bind_host, '0.0.0.0')
        self.assertEqual(node.message()['host'], '192.168.1.20')
        with self.assertRaises(ValueError):
            m.PeerNode('localhost', 9101, None)

    def test_read_limits_and_timeout(self):
        with patch.object(m, 'MAX_MESSAGE_BYTES', 32), patch.object(m, 'HANDSHAKE_TIMEOUT_SECONDS', .05):
            for data in (b'x' * 33, b'x' * 32 + b'\n', b''):
                a, b = socket.socketpair()
                with a, b:
                    if data:
                        a.sendall(data)
                    with self.assertRaises((ValueError, TimeoutError)):
                        m.read_message(b)

    def test_handshake_and_slot_release(self):
        node = m.PeerNode('127.0.0.1', 9101, None)
        a, b = socket.socketpair()
        with a:
            self.assertTrue(node.accept_connection(b, ('127.0.0.1', 1234)))
            a.sendall(b'{"type":"hello","host":"127.0.0.1","port":9102,"peers":[]}\n')
            self.assertEqual(m.read_message(a)['port'], 9101)
            a.settimeout(1)
            self.assertEqual(a.recv(1), b'')
        self.assertIn(m.Peer('127.0.0.1', 9102), node.peers)

    def test_inbound_cap(self):
        node = m.PeerNode('127.0.0.1', 9101, None)
        for _ in range(m.MAX_INBOUND_CONNECTIONS):
            self.assertTrue(node.inbound_slots.acquire(False))
        a, b = socket.socketpair()
        with a:
            self.assertFalse(node.accept_connection(b, ('127.0.0.1', 1)))
            self.assertEqual(a.recv(1), b'')

    def test_retry_and_peer_caps(self):
        node = m.PeerNode('127.0.0.1', 9101, None)
        with patch.object(m.threading, 'Thread') as thread:
            for i in range(m.MAX_PEERS + 20):
                peer = m.Peer('127.0.0.1', 10000 + i)
                node.add_peer(peer)
                node.retry_peer(peer)
            self.assertEqual(thread.call_count, m.MAX_RETRY_WORKERS)
            self.assertEqual(node.retry_queue.qsize(), m.MAX_PEERS)
            self.assertEqual(len(node.peers), m.MAX_PEERS)

class ValidationAndRetryTests(unittest.TestCase):
    def setUp(self):
        self.node = m.PeerNode('127.0.0.1', 9101, None)
        self.greeting = {'type': 'hello', 'host': '127.0.0.1', 'port': 9102,
                         'peers': [{'host': '127.0.0.1', 'port': 9103}]}

    def test_invalid_greetings_leave_all_state_unchanged(self):
        invalid = [None, [], {}, dict(self.greeting, peers='bad'),
                   dict(self.greeting, peers=self.greeting['peers'] + [{}]),
                   dict(self.greeting, peers=self.greeting['peers'] + [None]),
                   dict(self.greeting, peers=[{}] * (m.MAX_PEERS + 2))]
        for port in (0, -1, 65536, True, 1.5, '9102', None):
            invalid.append(dict(self.greeting, port=port))
        for host in ('', 'bad host', 'bad\nname', '-bad', 'bad..name',
                     'example..', '999.1.1.1', '0.0.0.0', '::1', None, 42):
            invalid.append(dict(self.greeting, host=host))
        for greeting in invalid:
            with self.subTest(greeting=greeting), patch.object(self.node, 'retry_peer') as retry:
                with self.assertRaises(ValueError):
                    self.node.handle_message(greeting)
                self.assertEqual(self.node.peers, set())
                self.assertEqual(self.node.confirmed, set())
                self.assertEqual(self.node.retry_after, {})
                retry.assert_not_called()

    def test_cli_and_constructor_port_validation(self):
        import argparse
        for port in (0, -1, 65536):
            with self.assertRaises(argparse.ArgumentTypeError):
                m.parse_peer(f'localhost:{port}')
            with self.assertRaises(ValueError):
                m.PeerNode('127.0.0.1', port, None)
        self.assertEqual(m.parse_peer('127.0.0.1:65535'), m.Peer('127.0.0.1', 65535))
        with self.assertRaises(ValueError):
            m.Peer('peer.example.', 1)

    def test_failed_peer_retries_after_cooldown_and_then_stops_on_success(self):
        peer = m.Peer('127.0.0.1', 9103)
        with patch.object(m.threading, 'Thread'), patch.object(m, 'MAX_RETRIES', 1), \
             patch.object(m.time, 'monotonic', return_value=100) as clock, \
             patch.object(self.node, 'send_hello', return_value=False) as send:
            self.node.handle_message(self.greeting)
            self.node.handle_message(self.greeting)
            self.assertEqual(self.node.retry_queue.qsize(), 1)
            self.node.retry_queue.get_nowait()()
            self.assertEqual(send.call_count, 1)
            self.assertNotIn(peer, self.node.retrying)
            self.node.handle_message(self.greeting)
            self.assertTrue(self.node.retry_queue.empty())
            clock.return_value = 100 + m.RETRY_COOLDOWN_SECONDS
            self.node.handle_message(self.greeting)
            self.assertEqual(self.node.retry_queue.qsize(), 1)
            send.return_value = True
            self.node.retry_queue.get_nowait()()
            self.assertIn(peer, self.node.confirmed)
            self.assertNotIn(peer, self.node.retry_after)
            clock.return_value += m.RETRY_COOLDOWN_SECONDS
            self.node.handle_message(self.greeting)
            self.assertTrue(self.node.retry_queue.empty())

    def test_unreachable_peer_does_not_hold_a_worker_between_attempts(self):
        dead, live = m.Peer('127.0.0.1', 9103), m.Peer('127.0.0.1', 9104)
        with patch.object(m.threading, 'Thread'), \
             patch.object(m.time, 'monotonic', return_value=100) as clock, \
             patch.object(self.node.stop_event, 'wait', side_effect=AssertionError('worker slept')), \
             patch.object(self.node, 'send_hello', side_effect=lambda peer, reason: peer == live) as send:
            for peer in (dead, live):
                self.node.add_peer(peer)
                self.node.retry_peer(peer)
            self.node.retry_queue.get_nowait()()  # dead peer: first attempt fails and returns
            self.assertIn(dead, self.node.retrying)
            self.node.retry_queue.get_nowait()()  # the live peer is not stuck behind it
            self.assertIn(live, self.node.confirmed)
            for attempt in range(2, m.MAX_RETRIES + 1):
                self.assertTrue(self.node.retry_queue.empty())
                self.node.release_due_retries()
                self.assertTrue(self.node.retry_queue.empty(), 'retry released before its delay')
                clock.return_value += m.RETRY_DELAY_SECONDS
                self.node.release_due_retries()
                self.node.retry_queue.get_nowait()()
            self.assertEqual([call.args[0] for call in send.call_args_list].count(dead), m.MAX_RETRIES)
            self.assertNotIn(dead, self.node.retrying)
            self.assertEqual(self.node.retry_after[dead], clock.return_value + m.RETRY_COOLDOWN_SECONDS)
            self.assertEqual(self.node.retry_schedule, [])

    def test_incoming_handshake_cancels_queued_retry(self):
        peer = m.Peer('127.0.0.1', 9103)
        with patch.object(m.threading, 'Thread'), patch.object(self.node, 'send_hello') as send:
            self.node.handle_message(self.greeting)
            self.node.handle_message({'type': 'hello', 'host': peer.host, 'port': peer.port})
            self.node.retry_queue.get_nowait()()
            send.assert_not_called()
            self.assertNotIn(peer, self.node.retrying)
            self.assertNotIn(peer, self.node.retry_after)

class MaintenanceAndPolicyTests(unittest.TestCase):
    def setUp(self):
        self.node = m.PeerNode('127.0.0.1', 9101, None)
        self.peer = m.Peer('127.0.0.1', 9102)

    def test_network_policy_and_sender_identity_are_atomic(self):
        valid = {'type': 'hello', 'host': '127.0.0.1', 'port': 9102}
        for message, kwargs in (
            (dict(valid, host='8.8.8.8'), {}),
            (dict(valid, peers=[{'host': '169.254.169.254', 'port': 80}]), {}),
            (valid, {'source_host': '127.0.0.2'}),
            (valid, {'expected_peer': m.Peer('127.0.0.1', 9103)}),
        ):
            with self.subTest(message=message, kwargs=kwargs), self.assertRaises(ValueError):
                self.node.handle_message(message, **kwargs)
            self.assertFalse(self.node.peers)
        restricted = m.PeerNode('127.0.0.1', 9101, None, allowed_networks=['127.0.0.1/32'])
        self.assertFalse(restricted.host_allowed('192.168.1.2'))
        explicit = m.PeerNode('127.0.0.1', 9101, None,
                              allowed_networks=['127.0.0.1/32', '8.8.8.8/32'])
        self.assertTrue(explicit.host_allowed('8.8.8.8'))
        with self.assertRaises(ValueError):
            m.PeerNode('127.0.0.1', 9101, m.Peer('8.8.8.8', 9101))

    def test_disallowed_connection_closed_without_starting_worker(self):
        connection = unittest.mock.Mock()
        with patch.object(m.threading, 'Thread') as thread:
            self.assertFalse(self.node.accept_connection(connection, ('8.8.8.8', 1234)))
            connection.close.assert_called_once()
            thread.assert_not_called()

    def test_no_dns_for_numeric_connections_and_hostname_rejected(self):
        with patch.object(m.socket, 'getaddrinfo', side_effect=AssertionError('DNS called')), \
             patch.object(m.socket, 'gethostbyname', side_effect=AssertionError('DNS called')), \
             patch.object(m.socket, 'socket') as sock, patch.object(m, 'read_message', return_value={
                 'type': 'hello', 'host': self.peer.host, 'port': self.peer.port}):
            self.node.add_peer(self.peer)
            self.assertTrue(self.node.send_hello(self.peer))
            sock.return_value.__enter__.return_value.connect.assert_called_once_with(('127.0.0.1', 9102))
            sock.return_value.__enter__.return_value.bind.assert_called_once_with(('127.0.0.1', 0))
            with self.assertRaises(ValueError):
                m.Peer('localhost', 9102)

    def test_confirmed_peer_periodically_rechecked_and_recovers(self):
        with patch.object(m.time, 'monotonic', return_value=100) as clock, \
             patch.object(m.threading, 'Thread'), patch.object(m, 'MAX_RETRIES', 1), \
             patch.object(self.node, 'send_hello', return_value=False) as send:
            self.node.add_peer(self.peer)
            self.node.confirm_peer(self.peer)
            self.node.maintain_peers()
            self.node.maintain_peers()
            self.assertEqual(self.node.retry_queue.qsize(), 1)
            self.node.retry_queue.get_nowait()()
            self.assertNotIn(self.peer, self.node.confirmed)
            clock.return_value += m.RETRY_COOLDOWN_SECONDS
            self.node.maintain_peers()
            send.return_value = True
            self.node.retry_queue.get_nowait()()
            self.assertIn(self.peer, self.node.confirmed)
            self.node.maintain_peers()
            self.assertTrue(self.node.retry_queue.empty())

    def test_gossip_cannot_keep_stale_peer_alive_and_cleanup_frees_capacity(self):
        with patch.object(m.time, 'monotonic', return_value=100) as clock, \
             patch.object(self.node, 'retry_peer'), patch.object(m, 'MAX_PEERS', 1):
            self.node.add_peer(self.peer)
            self.node.confirm_peer(self.peer)
            clock.return_value += m.CONFIRMATION_TTL_SECONDS
            self.node.maintain_peers()
            self.assertNotIn(self.peer, self.node.confirmed)
            self.node.handle_message({'type': 'hello', 'host': '127.0.0.1', 'port': 9103,
                                      'peers': [{'host': self.peer.host, 'port': self.peer.port}]})
            self.assertEqual(self.node.last_seen[self.peer], 100)
            self.node.retry_after[self.peer] = 9999
            self.node.last_probe[self.peer] = 100
            clock.return_value = 100 + m.PEER_TTL_SECONDS
            self.node.maintain_peers()
            for state in (self.node.peers, self.node.confirmed, self.node.retry_after,
                          self.node.last_seen, self.node.last_probe):
                self.assertNotIn(self.peer, state)
            self.assertTrue(self.node.add_peer(m.Peer('127.0.0.1', 9104)))

    def test_goodbye_from_initial_peer_does_not_strand_us_forever(self):
        # The initial peer is only added to self.peers once, at startup. If it has no --connect
        # back to us, a goodbye from it (e.g. a routine release restart) must not be permanent.
        node = m.PeerNode('127.0.0.1', 9101, self.peer)
        other = m.PeerNode('127.0.0.1', 9102, None)
        node.handle_message(other.message())
        self.assertIn(self.peer, node.peers)
        node.handle_message(other.message('goodbye'))
        self.assertNotIn(self.peer, node.peers)
        with patch.object(node, 'retry_peer'):
            node.maintain_peers()
        self.assertIn(self.peer, node.peers)

    def test_only_confirmed_peers_are_gossiped(self):
        self.node.add_peer(self.peer)
        self.assertEqual(self.node.peer_list(), [{'host': '127.0.0.1', 'port': 9101}])
        self.node.confirm_peer(self.peer)
        self.assertIn({'host': self.peer.host, 'port': self.peer.port}, self.node.peer_list())

    def test_periodic_discovery_over_real_tcp(self):
        import time
        nodes = []
        threads = []
        try:
            for _ in range(3):
                with socket.socket() as reservation:
                    reservation.bind(('127.0.0.1', 0))
                    port = reservation.getsockname()[1]
                node = m.PeerNode('127.0.0.1', port, None)
                thread = threading.Thread(target=node.run, daemon=True)
                thread.start()
                nodes.append(node)
                threads.append(thread)
                deadline = time.monotonic() + 3
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail('server did not start')
                        time.sleep(.01)
            first, middle, newcomer = nodes
            self.assertTrue(first.send_hello(middle.identity))
            # A new known endpoint at the middle node must propagate on refresh.
            middle.add_peer(newcomer.identity)
            middle.confirm_peer(newcomer.identity)
            first.maintain_peers()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                with first.peers_lock:
                    if newcomer.identity in first.confirmed:
                        break
                time.sleep(.01)
            with first.peers_lock:
                self.assertIn(newcomer.identity, first.confirmed)
        finally:
            for node in nodes:
                node.stop_event.set()
            for thread in threads:
                thread.join(5)
                self.assertFalse(thread.is_alive())

if __name__ == '__main__':
    unittest.main()
