import argparse
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import node_setup as setup


class SetupTests(unittest.TestCase):
    def test_parse_managed_args_recovers_fields_and_keeps_unmanaged_ones(self):
        node_args = ['--port', '9101', '--name', 'office', '--host', '0.0.0.0',
                    '--advertise-host', '192.168.1.5', '--connect', '192.168.1.6:9101',
                    '--allow-network', '192.168.1.0/24', '--capability', 'file-search']
        managed, extra = setup.parse_managed_args(node_args)
        self.assertEqual(managed['port'], 9101)
        self.assertEqual(managed['name'], 'office')
        self.assertEqual(managed['advertise_host'], '192.168.1.5')
        self.assertEqual(managed['connect'], '192.168.1.6:9101')
        self.assertEqual(managed['allow_network'], ['192.168.1.0/24'])
        self.assertEqual(extra, ['--capability', 'file-search'])

    def test_reconfigure_requires_an_existing_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(root=Path(temporary), yes=True, name=None, advertise_host=None,
                                      connect=None, port=None, shared_dir=None, clear_shared_dir=False,
                                      allow_network=None, service_name=None, auto_update=None, restart=False)
            with self.assertRaisesRegex(ValueError, 'not an initialized installation'):
                setup.reconfigure_existing(args)

    def test_reconfigure_flag_dispatches_instead_of_install(self):
        with patch('sys.argv', ['node_setup.py', '--reconfigure', '--root', 'somewhere', '--yes']), \
             patch.object(setup, 'reconfigure_existing') as reconfigure_existing, \
             patch.object(setup, 'install') as install:
            setup.main()
        reconfigure_existing.assert_called_once()
        install.assert_not_called()
    def test_default_install_does_not_request_package_or_key(self):
        with patch('sys.argv', ['node_setup.py']), patch.object(setup, 'prompt', side_effect=lambda label, default: default) as prompt, patch.object(setup, 'install') as install:
            setup.main()
        args = install.call_args.args[0]
        self.assertIsNone(args.package)
        self.assertIsNone(args.trusted_key)
        self.assertFalse(any('key' in call.args[0].lower() or 'package' in call.args[0].lower() for call in prompt.call_args_list))

    def test_shared_dir_is_prompted_for_and_cli_flag_skips_the_prompt(self):
        with patch('sys.argv', ['node_setup.py']), patch.object(setup, 'prompt', side_effect=lambda label, default: default) as prompt, patch.object(setup, 'install') as install:
            setup.main()
        args = install.call_args.args[0]
        self.assertIsNone(args.shared_dir)
        self.assertTrue(any('shared' in call.args[0].lower() for call in prompt.call_args_list))

        with patch('sys.argv', ['node_setup.py', '--shared-dir', '/tmp/custom-shared']), \
             patch.object(setup, 'prompt', side_effect=lambda label, default: default) as prompt, \
             patch.object(setup, 'install') as install:
            setup.main()
        args = install.call_args.args[0]
        self.assertEqual(args.shared_dir, Path('/tmp/custom-shared'))
        self.assertFalse(any('shared' in call.args[0].lower() for call in prompt.call_args_list))

    def test_windows_is_manual_and_hidden(self):
        scripts = setup.windows_scripts(Path('node space'), Path('python.exe'), 'node')
        self.assertEqual(set(scripts), {'start-node.ps1', 'stop-node.ps1', 'status-node.ps1'})
        self.assertNotIn('ScheduledTask', ''.join(scripts.values()))
        self.assertIn('-WindowStyle Hidden', scripts['start-node.ps1'])
        self.assertNotIn('-Wait', scripts['start-node.ps1'])
        with patch.object(setup.platform, 'system', return_value='Windows'), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'state').mkdir()
            (root / 'state/setup.json').write_text('{"platform":"Windows"}')
            with patch.object(setup, 'run') as run:
                setup.register_existing(root, False, True)
                run.assert_not_called()

    def test_systemd_quoting_and_shutdown(self):
        unit = setup.service_unit(Path('/home/test/a % $ node'), Path('/usr/bin/python3'))
        self.assertIn('%% $$ node', unit)
        self.assertIn('KillMode=mixed', unit)
        self.assertIn('WantedBy=default.target', unit)

    def test_linux_registers_lingering_and_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            setup.write_helpers(root, Path('/usr/bin/python3'), 'test-node', 'Linux')
            calls = []
            def execute(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, stdout='yes\n')
            with patch.object(setup.subprocess, 'run', side_effect=execute):
                setup.configure_linux(root, 'test-node', False, True, root / 'config')
            self.assertIn(['systemctl', '--user', 'enable', '--now', 'test-node.service'], calls)
            self.assertTrue((root / 'config/systemd/user/test-node.service').is_file())
            self.assertNotIn(b'\r', (root / 'start-node.sh').read_bytes())

    def test_linux_refuses_unconfirmed_lingering(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='no\n')):
            with self.assertRaisesRegex(ValueError, 'Lingering is not enabled'):
                setup.configure_linux(Path(temporary), 'node', False, True)

    def test_invalid_settings(self):
        for address, port, service in [('0.0.0.0', 9101, 'node'), ('127.0.0.1', 0, 'node'), ('127.0.0.1', 9101, '../node')]:
            with self.assertRaises(ValueError):
                setup.validate_settings(Path('node'), 'node', address, '', port, service)
        with self.assertRaises(ValueError):
            setup.validate_settings(Path('node'), 'node', '127.0.0.1', '', 9101, 'node',
                                    Path('bad\x01path'))
        setup.validate_settings(Path('node'), 'node', '127.0.0.1', '', 9101, 'node', Path('shared'))


if __name__ == '__main__':
    unittest.main()
