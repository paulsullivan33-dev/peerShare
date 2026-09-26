"""Interactive Windows/Linux node installation; no third-party bootstrap imports."""

import argparse
import getpass
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path


def write_text(path: Path, text: str) -> None:
    # Shell scripts and systemd units must keep LF even when the bundle is made on Windows.
    path.write_bytes(text.encode('utf-8'))


def ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def unit_quote(value: str, command: bool = False) -> str:
    if any(ord(character) < 32 for character in value):
        raise ValueError('service paths cannot contain control characters')
    value = value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    if command:
        value = value.replace('$', '$$')
    return '"' + value + '"'


def service_unit(root: Path, python: Path) -> str:
    command = ' '.join(unit_quote(str(value), command=True) for value in
                       (python, '-B', '-u', root / 'launcher.py', 'run', '--root', root))
    return f'''[Unit]
Description=peerHandshake node launcher
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
WorkingDirectory={str(root).replace('%', '%%')}
ExecStart={command}
Restart=on-failure
RestartSec=10
KillMode=mixed
TimeoutStopSec=45
UMask=0077
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
'''


def windows_scripts(root: Path, python: Path, name: str) -> dict[str, str]:
    arguments = subprocess.list2cmdline(['-B', '-u', str(root / 'launcher.py'), 'run', '--root', str(root)])
    invoke = f"& {ps_literal(str(python))} -B {ps_literal(str(root / 'launcher.py'))}"
    start = f'''$ErrorActionPreference = 'Stop'
{invoke} status --root {ps_literal(str(root))}
if ($LASTEXITCODE -eq 0) {{ Write-Host 'Already running.'; exit 0 }}
if ($LASTEXITCODE -ne 1) {{ throw 'Could not check node status.' }}
$process = Start-Process -FilePath {ps_literal(str(python))} -ArgumentList {ps_literal(arguments)} -WorkingDirectory {ps_literal(str(root))} -WindowStyle Hidden -RedirectStandardOutput {ps_literal(str(root / 'state/logs/launcher.stdout.log'))} -RedirectStandardError {ps_literal(str(root / 'state/logs/launcher.stderr.log'))} -PassThru
Start-Sleep -Seconds 1
if ($process.HasExited) {{ throw 'Launcher exited; inspect state/logs/launcher.stderr.log.' }}
Write-Host "Launcher started (PID $($process.Id))."
'''
    return {
        'start-node.ps1': start,
        'stop-node.ps1': f"{invoke} stop --root {ps_literal(str(root))}\nexit $LASTEXITCODE\n",
        'status-node.ps1': f"{invoke} status --root {ps_literal(str(root))}\nexit $LASTEXITCODE\n",
    }


def write_helpers(root: Path, python: Path, name: str, operating_system: str) -> None:
    if operating_system == 'Linux':
        write_text(root / (name + '.service'), service_unit(root, python))
        for action in ('start', 'stop', 'status'):
            text = '#!/bin/sh\nset -eu\nexec systemctl --user ' + action + ' ' + shlex.quote(name + '.service') + '\n'
            write_text(root / (action + '-node.sh'), text)
            (root / (action + '-node.sh')).chmod(0o700)
    else:
        for filename, text in windows_scripts(root, python, name).items():
            write_text(root / filename, text)


def run(command: list, **kwargs):
    return subprocess.run([str(value) for value in command], check=True, **kwargs)


def configure_linux(root: Path, name: str, no_start: bool, noninteractive: bool,
                    config_home: Path | None = None) -> None:
    user = getpass.getuser()
    run(['systemctl', '--user', 'show-environment'], stdout=subprocess.DEVNULL)
    result = run(['loginctl', 'show-user', user, '--property=Linger', '--value'], capture_output=True, text=True)
    if result.stdout.strip() != 'yes':
        print('Enabling systemd lingering so the node survives logout and starts at boot.')
        result = subprocess.run(['loginctl', 'enable-linger', user], capture_output=True, text=True)
        if result.returncode:
            if shutil.which('sudo') is None:
                raise ValueError(f'An administrator must run: loginctl enable-linger {user}')
            sudo = ['sudo', '-n'] if noninteractive else ['sudo']
            run([*sudo, 'loginctl', 'enable-linger', user])
        result = run(['loginctl', 'show-user', user, '--property=Linger', '--value'], capture_output=True, text=True)
        if result.stdout.strip() != 'yes':
            raise ValueError('Lingering is not enabled; refusing to report a logout-safe installation.')
    home = config_home or Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    units = home / 'systemd/user'
    units.mkdir(parents=True, exist_ok=True)
    source = root / (name + '.service')
    target = units / source.name
    if target.is_symlink() or (target.exists() and target.read_bytes() != source.read_bytes()):
        raise ValueError(f'A different service already exists at {target}; choose a unique --service-name.')
    shutil.copyfile(source, target)
    run(['systemctl', '--user', 'daemon-reload'])
    run(['systemctl', '--user', 'enable', *([] if no_start else ['--now']), name + '.service'])
    if not no_start:
        run(['systemctl', '--user', 'is-active', '--quiet', name + '.service'])
    print(f'Service installed: {name}.service')
    print(f'Logs: journalctl --user -u {name}.service -f')


def validate_settings(root: Path, name: str, address: str, peer: str, port: int, service: str,
                      shared_dir: Path | None = None) -> None:
    if not name.strip() or len(name) > 128 or any(ord(character) < 32 for character in name):
        raise ValueError('node name must contain 1 through 128 printable characters')
    parsed = ipaddress.IPv4Address(address)
    if parsed.is_unspecified or parsed.is_multicast:
        raise ValueError('advertise address must be this node\'s reachable IPv4 address')
    if not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')
    if peer:
        host, separator, peer_port = peer.rpartition(':')
        if not separator or not 1 <= int(peer_port) <= 65535:
            raise ValueError('initial peer must use IPv4:PORT')
        ipaddress.IPv4Address(host)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', service):
        raise ValueError('service name must contain only letters, digits, underscores, or hyphens')
    if any(ord(character) < 32 for character in str(root)):
        raise ValueError('installation path contains control characters')
    if shared_dir is not None and any(ord(character) < 32 for character in str(shared_dir)):
        raise ValueError('shared directory path contains control characters')


def register_existing(root: Path, no_start: bool, noninteractive: bool) -> None:
    settings = json.loads((root / 'state/setup.json').read_text(encoding='utf-8'))
    if settings['platform'] != platform.system():
        raise ValueError('registration must run on the installation\'s operating system')
    if platform.system() == 'Linux':
        configure_linux(root, settings['service'], no_start, noninteractive)
    else:
        print('Windows setup is on demand. Run start-node.ps1 when needed; no automatic startup is registered.')


def parse_managed_args(node_args: list) -> tuple[dict, list]:
    """Recover this installer's own flags from a saved node_args list, keeping
    anything it doesn't manage (capabilities, services, resources, ...) untouched."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--port', type=int)
    parser.add_argument('--name')
    parser.add_argument('--advertise-host')
    parser.add_argument('--connect', default='')
    parser.add_argument('--allow-network', action='append', default=[])
    managed, extra = parser.parse_known_args(node_args)
    # --host is always forced to 0.0.0.0 by this installer; drop any saved copy so it
    # isn't duplicated when the network arguments are rebuilt.
    extra = [value for index, value in enumerate(extra)
            if value != '--host' and (index == 0 or extra[index - 1] != '--host')]
    return vars(managed), extra


def launcher_running(python: Path, root: Path) -> bool:
    result = subprocess.run([str(python), str(root / 'launcher.py'), 'status', '--root', str(root)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def wait_for_stop(python: Path, root: Path, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not launcher_running(python, root):
            return
        time.sleep(0.5)
    raise ValueError('the node did not stop within the timeout; check its logs and try again')


def reconfigure_existing(args) -> None:
    root = args.root.expanduser().absolute()
    config_path, setup_path = root / 'state/config.json', root / 'state/setup.json'
    if not config_path.is_file() or not setup_path.is_file():
        raise ValueError(f'{root} is not an initialized installation; omit --reconfigure to install fresh')
    config = json.loads(config_path.read_text(encoding='utf-8'))
    settings = json.loads(setup_path.read_text(encoding='utf-8'))
    if settings['platform'] != platform.system():
        raise ValueError('reconfigure must run on the installation\'s operating system')
    if args.service_name and args.service_name != settings['service']:
        raise ValueError('reconfigure cannot rename the registered service; reinstall to change --service-name')
    python = Path(settings['python'])
    managed, extra = parse_managed_args(config.get('node_args', []))
    interactive = not args.yes
    choose = prompt if interactive else lambda label, default: default
    name = args.name or choose('Node name', managed.get('name') or socket.gethostname())
    advertise_host = args.advertise_host or choose('This node\'s IPv4 address',
                                                   managed.get('advertise_host') or guess_advertise_host())
    connect = (choose('Initial peer IPv4:PORT (blank for none)', managed.get('connect') or '')
              if args.connect is None else args.connect)
    port = args.port if args.port is not None else int(choose('Listening port', str(managed.get('port') or 9101)))
    if args.shared_dir is not None:
        shared_dir = args.shared_dir
    elif args.clear_shared_dir:
        shared_dir = None
    else:
        current = config.get('shared_dir') or ''
        entered = choose('Shared files directory (blank for default: <install directory>/shared)', current)
        shared_dir = Path(entered) if entered else None
    if args.auto_update is None:
        auto_update = choose('Automatically install trusted signed updates? y/N',
                            'y' if config.get('auto_update') else 'N').lower() in ('y', 'yes')
    else:
        auto_update = args.auto_update
    validate_settings(root, name, advertise_host, connect, port, settings['service'], shared_dir)
    network = ['--name', name, '--host', '0.0.0.0', '--advertise-host', advertise_host]
    if connect:
        network += ['--connect', connect]
    for value in (args.allow_network or managed.get('allow_network') or []):
        network += ['--allow-network', value]
    network += extra
    was_running = launcher_running(python, root)
    if was_running:
        allow_restart = args.restart or (interactive and choose(
            'Node is running. Stop it, apply changes, and restart now? y/N', 'N').lower() in ('y', 'yes'))
        if not allow_restart:
            raise ValueError('Stop the node first (its stop-node script), or rerun with --restart '
                             'to apply changes and restart automatically.')
        print('Stopping the running node to apply changes...')
        run([python, root / 'launcher.py', 'stop', '--root', root])
        wait_for_stop(python, root)
    command = [python, root / 'launcher.py', 'reconfigure', '--root', root, '--port', str(port),
              '--auto-update' if auto_update else '--no-auto-update']
    if shared_dir is not None:
        command += ['--shared-dir', shared_dir.expanduser().absolute()]
    elif args.clear_shared_dir:
        command.append('--clear-shared-dir')
    run([*command, '--', *network])
    print('Settings updated.')
    if was_running:
        print('Restarting the node...')
        if operating_system_start(root):
            print('Node restarted.')


def operating_system_start(root: Path) -> bool:
    if platform.system() == 'Linux':
        run(['sh', str(root / 'start-node.sh')])
    else:
        run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'start-node.ps1')])
    return True


def install(args, bundle: Path) -> None:
    operating_system = platform.system()
    if operating_system not in ('Linux', 'Windows') or sys.version_info < (3, 10):
        raise ValueError('Windows or Linux with Python 3.10+ is required')
    root = args.root.expanduser().absolute()
    if args.register_only:
        register_existing(root, args.no_start, args.yes)
        return
    validate_settings(root, args.name, args.advertise_host, args.connect, args.port, args.service_name,
                      args.shared_dir)
    required_files = [bundle / 'launcher.py', bundle / 'release_tools.py', bundle / 'requirements-updater.txt']
    if args.package is not None:
        if args.trusted_key is None:
            raise ValueError('--package requires --trusted-key')
        required_files.append(args.package)
    else:
        required_files.extend(bundle / name for name in ('peer_handshake.py', 'peer_protocol.py', 'peer_files.py', 'peer_runtime.py'))
    if args.trusted_key is not None:
        required_files.append(args.trusted_key)
    for required in required_files:
        if not required.is_file():
            raise ValueError(f'Required bundle file is missing: {required}')
    if root.exists() and any(root.iterdir()):
        raise ValueError('Choose an empty node directory, or use --register-only to finish service registration.')
    runtime = root.with_name(root.name + '-python')
    if runtime.exists():
        raise ValueError(f'The runtime directory already exists: {runtime}; choose a new --root.')
    if operating_system == 'Linux':
        if os.geteuid() == 0:
            raise ValueError('Run this installer as your normal user, not with sudo. It requests sudo only for lingering if necessary.')
        if not shutil.which('systemctl') or not shutil.which('loginctl'):
            raise ValueError('This background installer requires Linux with systemd and loginctl.')
        run(['systemctl', '--user', 'show-environment'], stdout=subprocess.DEVNULL)
    python = runtime / ('Scripts/python.exe' if operating_system == 'Windows' else 'bin/python')
    root.parent.mkdir(parents=True, exist_ok=True)
    print(f'Creating Python environment: {runtime}')
    run([sys.executable, '-m', 'venv', runtime])
    run([python, '-m', 'pip', 'install', '-r', bundle / 'requirements-updater.txt'])
    network = ['--name', args.name, '--host', '0.0.0.0', '--advertise-host', args.advertise_host]
    if args.connect:
        network += ['--connect', args.connect]
    for value in args.allow_network or []:
        network += ['--allow-network', value]
    command = [python, bundle / 'launcher.py', 'init' if args.package else 'init-source',
               '--root', root, '--port', str(args.port)]
    if args.package:
        command += ['--package', args.package.resolve()]
    else:
        command += ['--source', bundle]
    if args.trusted_key:
        command += ['--trusted-key', args.trusted_key.resolve()]
    if args.auto_update:
        command.append('--auto-update')
    shared_dir = args.shared_dir.expanduser().absolute() if args.shared_dir else None
    if shared_dir:
        command += ['--shared-dir', shared_dir]
    run([*command, '--', *network])
    write_helpers(root, python, args.service_name, operating_system)
    shutil.copyfile(bundle / 'node_setup.py', root / 'node_setup.py')
    write_text(root / 'state/setup.json', json.dumps({'platform': operating_system,
                                                    'service': args.service_name, 'python': str(python)}, indent=2))
    print(f'Node initialized. Shared files: {shared_dir or (root / "shared")}')
    try:
        register_existing(root, args.no_start, args.yes)
    except (OSError, ValueError, subprocess.CalledProcessError):
        print(f'Node files are ready. After resolving service permissions, finish with:\n'
              f'  python {root / "node_setup.py"} --root {root} --register-only', file=sys.stderr)
        raise
    print('Setup complete. Use the start-node, stop-node, and status-node scripts in the node directory.')


def prompt(label: str, default: str) -> str:
    value = input(f'{label} [{default}]: ').strip()
    return value or default


def guess_advertise_host() -> str:
    # UDP connect() only asks the OS which local address would route to the
    # destination; a documentation-range address (RFC 5737) keeps this from
    # depending on any real host, and no packet is ever sent.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('203.0.113.1', 1))
            address = probe.getsockname()[0]
        ipaddress.IPv4Address(address)
        if ipaddress.IPv4Address(address).is_loopback:
            raise ValueError('no non-loopback route')
    except (OSError, ValueError):
        return '127.0.0.1'
    return address


def main() -> None:
    bundle = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description='Install a background peerHandshake node on Windows or Linux')
    parser.add_argument('--root', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--trusted-key', type=Path)
    parser.add_argument('--name')
    parser.add_argument('--advertise-host')
    parser.add_argument('--connect')
    parser.add_argument('--port', type=int)
    parser.add_argument('--shared-dir', type=Path, help='send/receive directory (default: <root>/shared)')
    parser.add_argument('--clear-shared-dir', action='store_true',
                        help='reconfigure: restore the default shared directory')
    parser.add_argument('--allow-network', action='append')
    parser.add_argument('--service-name')
    parser.add_argument('--auto-update', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--yes', action='store_true', help='use defaults without prompting; sudo must already be authorized')
    parser.add_argument('--no-start', action='store_true', help='Linux: register startup but do not start immediately; Windows never starts during setup')
    parser.add_argument('--register-only', action='store_true', help='finish background registration for an initialized node')
    parser.add_argument('--reconfigure', action='store_true',
                        help='update an existing installation\'s settings instead of creating a new one')
    parser.add_argument('--restart', action='store_true',
                        help='reconfigure: stop, apply, and restart automatically if the node is running')
    args = parser.parse_args()
    try:
        interactive = not args.yes
        choose = prompt if interactive else lambda label, default: default
        args.root = args.root or Path(choose('Installation directory', str(Path.cwd() / 'node')))
        if args.reconfigure:
            reconfigure_existing(args)
            return
        if not args.register_only:
            args.name = args.name or choose('Node name', socket.gethostname())
            args.advertise_host = args.advertise_host or choose('This node\'s IPv4 address', guess_advertise_host())
            args.connect = choose('Initial peer IPv4:PORT (blank for the first node)', '') if args.connect is None else args.connect
            args.port = args.port if args.port is not None else int(choose('Listening port', '9101'))
            if args.shared_dir is None:
                entered = choose('Shared files directory (blank for default: <install directory>/shared)', '')
                args.shared_dir = Path(entered) if entered else None
            args.service_name = args.service_name or 'peerhandshake-' + str(args.port)
            if args.auto_update is None:
                args.auto_update = choose('Automatically install trusted signed updates? y/N', 'N').lower() in ('y', 'yes')
        install(args, bundle)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
