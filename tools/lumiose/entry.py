"""Start the packaged launcher, preparing Lumiose after initial game setup."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime
import shutil

ROOT = Path(__file__).resolve().parents[2]
GAME_CODE_REVISION = 'launcher-title-offset-null-guard-v1'
LAUNCHER_VERSION = 'v0.1.38'
sys.path[:0] = [str(ROOT / 'python-deps'), str(ROOT / 'tools' / 'lumiose')]
from auto_launch import launch
from platform_paths import EXECUTABLE, GAME_LIBRARY, lock_file
import invite_code
import profiles as profile_store


def log_event(message):
    try:
        logs = ROOT / 'logs'
        logs.mkdir(parents=True, exist_ok=True)
        with (logs / 'lumiose-launch.log').open('a', encoding='utf-8') as f:
            f.write(f'{datetime.now().isoformat(timespec="seconds")} {message}\n')
    except OSError:
        pass  # Diagnostics must not stop the launcher.


def desktop_notice(title, message, error=False):
    if os.name != 'nt': return
    command = shutil.which('kdialog') if error else shutil.which('notify-send')
    if command:
        args = [command, '--error', title + '\n\n' + message] if error else [command, title, message]
        try: subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError: pass


def _describe_server(settings):
    mode = settings['mode']
    if mode == 'host':
        pub = settings.get('host_public_address') or f"127.0.0.1:{settings['host_port']}"
        return f"Host Private Room (local UDP:{settings['host_port']} -> {pub})"
    if mode == 'join':
        code = settings.get('join_code')
        addr = settings.get('join_address') or '(not configured yet)'
        return f'Join Room ({code})' if code else f'Join Private Server ({addr})'
    return f"Official Public Server ({profile_store.OFFICIAL_SERVER})"


def _manage_profiles_menu(root: Path) -> None:
    while True:
        data, active = profile_store.get_active_profile(root)
        items = data['profiles']
        print('\n=== Trainer Profiles (Accounts) ===')
        for idx, item in enumerate(items, start=1):
            marker = '*' if item['id'] == active['id'] else ' '
            print(f"  [{idx}] {marker} {item['name']}  ({item['save_dir']})")
        print('  [N] Create new profile')
        print('  [R] Rename active profile')
        print('  [D] Remove a non-default profile from list (keeps save files)')
        print('  [B] Back')
        choice = input('Select profile action: ').strip()
        if not choice or choice.lower() == 'b':
            return
        if choice.isdigit():
            pos = int(choice) - 1
            if 0 <= pos < len(items):
                profile_store.set_active_profile(root, items[pos]['id'])
                return
            print('Invalid profile number.')
            continue
        low = choice.lower()
        if low == 'n':
            name = input('New trainer profile name (e.g. Partner / Second Run): ').strip()
            if name:
                _, created = profile_store.create_profile(root, name)
                print(f"Switched to new profile: {created['name']}")
                return
        elif low == 'r':
            new_name = input(f"New display name for '{active['name']}': ").strip()
            if new_name:
                profile_store.rename_profile(root, active['id'], new_name)
        elif low == 'd':
            target = input('Profile number to remove from launcher list: ').strip()
            if target.isdigit():
                pos = int(target) - 1
                if 0 <= pos < len(items):
                    try:
                        profile_store.delete_profile(root, items[pos]['id'])
                        print('Removed from list (save folder preserved on disk).')
                    except ValueError as exc:
                        print(f'Cannot remove: {exc}')


def _configure_host_wizard(root: Path, settings: dict) -> bool:
    print('\n=== Host Private Room Setup ===')
    raw_port = input(f"Local UDP port [{settings['host_port']}]: ").strip()
    if raw_port:
        try:
            port = int(raw_port)
            if not (1 <= port <= 65535):
                raise ValueError()
            settings['host_port'] = port
        except ValueError:
            print('Invalid port; keeping previous setting.')
            return False

    port = settings['host_port']
    print('\nHow should your partner reach your PC without a cloud VPS?')
    print('  [1] Playit.gg UDP Tunnel (Recommended - no router port forward, no VPN)')
    print('  [2] Router Auto-UPnP + Public IP (direct UDP, no Playit or VPN)')
    print('  [3] VPN Mesh / LAN IP (Tailscale, ZeroTier, Radmin, or local Wi-Fi)')
    tchoice = input('Choose connection method [1]: ').strip() or '1'

    if tchoice == '1':
        print(f'\nTip: In Playit.gg, add a UDP tunnel pointing to 127.0.0.1:{port},')
        print('then paste the public address Playit gives you (e.g. cat-dog.gl.at.ply.gg:12345).')
        default_pub = settings.get('host_public_address', '')
        prompt = f'Playit public address [{default_pub}]: ' if default_pub else 'Playit public address (host:port): '
        raw_pub = input(prompt).strip() or default_pub
        if not raw_pub:
            print('No address entered.')
            return False
        try:
            settings['host_public_address'] = profile_store.validate_host_port(raw_pub, default_port=port)
            settings['host_transport'] = 'playit'
        except ValueError as exc:
            print(f'Invalid Playit address: {exc}')
            return False
    elif tchoice == '2':
        local_ip = profile_store.get_primary_local_ip()
        if local_ip:
            print(f'Attempting UPnP UDP port forward for {local_ip}:{port}...')
            ok, msg = profile_store.try_upnp_forward(local_ip, port)
            print(f'  {msg}')
        else:
            print('Could not determine local LAN IP for UPnP.')
        pub_ip = profile_store.get_public_ipv4()
        if pub_ip:
            print(f'Detected public IP: {pub_ip}')
        raw_pub = input(f'Public IP or DDNS domain [{pub_ip or ""}]: ').strip() or (pub_ip or '')
        if not raw_pub:
            print('No public address provided.')
            return False
        try:
            settings['host_public_address'] = profile_store.validate_host_port(raw_pub, default_port=port)
            settings['host_transport'] = 'upnp'
        except ValueError as exc:
            print(f'Invalid address: {exc}')
            return False
    elif tchoice == '3':
        ips = profile_store.detect_local_ips()
        chosen = ''
        if ips:
            print('\nDetected VPN / LAN IPs:')
            for idx, ip in enumerate(ips, start=1):
                print(f'  [{idx}] {ip}')
            sel = input(f'Pick IP number or type host[:port] [1]: ').strip() or '1'
            if sel.isdigit() and 1 <= int(sel) <= len(ips):
                chosen = f'{ips[int(sel) - 1]}:{port}'
            else:
                chosen = sel
        else:
            chosen = input(f'Enter VPN or LAN IP[:{port}]: ').strip()
        try:
            settings['host_public_address'] = profile_store.validate_host_port(chosen, default_port=port)
            settings['host_transport'] = 'vpn'
        except ValueError as exc:
            print(f'Invalid address: {exc}')
            return False
    else:
        return False

    settings['mode'] = 'host'
    if not settings.get('room_secret'):
        settings['room_secret'] = invite_code.generate_secret_hex()
    profile_store.save_server_settings(root, settings)
    code = profile_store.write_room_code_file(root, settings)
    if code:
        profile_store.copy_to_clipboard(code)
        print(f'\nGenerated Invite Code (copied to clipboard & room-code.txt): {code}')
    return True


def _configure_server_menu(root: Path) -> None:
    settings = profile_store.load_server_settings(root)
    print('\n=== Online Server Mode ===')
    print(f"  [1] Host Private Room on this PC (generates Invite Code)")
    print("  [2] Join Partner's Room (paste Invite Code or host:port)")
    print(f"  [3] Official Public Server ({profile_store.OFFICIAL_SERVER})")
    print('  [B] Back')
    choice = input('Choose mode: ').strip().lower()
    if choice == '1':
        _configure_host_wizard(root, settings)
    elif choice == '2':
        current = settings.get('join_code') or settings.get('join_address') or ''
        prompt = f'Paste Invite Code (e.g. ZA1-... / ZA2-...) [{current}]: ' if current else 'Paste Invite Code (e.g. ZA1-... / ZA2-...): '
        raw = input(prompt).strip() or current
        if not raw:
            print('Invite code cannot be empty.')
            return
        if raw.upper().startswith('ZA'):
            try:
                host, port, secret = invite_code.decode_invite(raw)
                settings['join_code'] = invite_code.encode_invite(host, port, secret)
                settings['join_address'] = f'{host}:{port}'
                settings['join_secret'] = secret
                settings['mode'] = 'join'
                profile_store.save_server_settings(root, settings)
                print(f"Invite accepted! Target room: {host}:{port}")
                return
            except ValueError as exc:
                print(f'Invalid invite code: {exc}')
                return
        try:
            settings['join_address'] = profile_store.validate_host_port(
                raw, default_port=profile_store.DEFAULT_PORT
            )
            settings['join_code'] = ''
            settings['join_secret'] = ''
            settings['mode'] = 'join'
            profile_store.save_server_settings(root, settings)
        except ValueError as exc:
            print(f'Invalid address: {exc}')
    elif choice == '3':
        settings['mode'] = 'official'
        profile_store.save_server_settings(root, settings)


def run_launcher_menu(root: Path) -> tuple[dict, dict]:
    while True:
        _, active = profile_store.get_active_profile(root)
        settings = profile_store.load_server_settings(root)
        host_code = profile_store.build_host_invite_code(settings) if settings['mode'] == 'host' else None
        print('\n==================================================')
        print(f'  Lumiose Online {LAUNCHER_VERSION} - Private & Multi-Profile')
        print('==================================================')
        print(f"  Profile : {active['name']} ({active['save_dir']})")
        print(f"  Server  : {_describe_server(settings)}")
        if host_code:
            print(f'  Invite  : {host_code}')
        elif settings['mode'] == 'host':
            print('  Invite  : (Not set yet - choose [3] to set Playit / VPN / UPnP)')
        print('--------------------------------------------------')
        print('  [Enter / 1] Launch Game')
        print('  [2]         Switch / Manage Profiles')
        print('  [3]         Change Server Mode (Host / Join / Official)')
        if settings['mode'] == 'host':
            print('  [R]         Regenerate Room Invite Code')
        print('  [Q]         Quit')
        choice = input('> ').strip().lower()
        if choice in ('', '1'):
            if settings['mode'] == 'join' and not settings['join_address']:
                print('Please enter your partner invite code first.')
                _configure_server_menu(root)
                continue
            if settings['mode'] == 'host' and not settings.get('room_secret'):
                settings = profile_store.ensure_host_invite(root)
            return active, settings
        if choice == '2':
            _manage_profiles_menu(root)
        elif choice == '3':
            _configure_server_menu(root)
        elif choice == 'r' and settings['mode'] == 'host':
            settings = profile_store.ensure_host_invite(root, rotate=True)
            new_code = profile_store.write_room_code_file(root, settings)
            if new_code:
                profile_store.copy_to_clipboard(new_code)
                print(f'New Invite Code (copied to clipboard): {new_code}')
        elif choice == 'q':
            raise SystemExit(0)


def _apply_runtime_settings(root: Path, profile: dict, settings: dict) -> None:
    save_dir = profile_store.prepare_profile_directory(root, profile)
    if save_dir == (root / 'save').resolve():
        os.environ.pop('LARECOMP_SAVE_DIR', None)
    else:
        os.environ['LARECOMP_SAVE_DIR'] = str(save_dir)

    mode = settings['mode']
    if mode == 'host':
        os.environ['LUMIOSE_SERVER_OVERRIDE'] = f"127.0.0.1:{settings['host_port']}"
        secret = settings.get('room_secret', '').strip()
        if secret:
            os.environ['LUMIOSE_ROOM_SECRET'] = secret
        else:
            os.environ.pop('LUMIOSE_ROOM_SECRET', None)
    elif mode == 'join' and settings['join_address']:
        os.environ['LUMIOSE_SERVER_OVERRIDE'] = settings['join_address']
        secret = settings.get('join_secret', '').strip()
        if secret:
            os.environ['LUMIOSE_ROOM_SECRET'] = secret
        else:
            os.environ.pop('LUMIOSE_ROOM_SECRET', None)
    else:
        os.environ.pop('LUMIOSE_SERVER_OVERRIDE', None)
        os.environ.pop('LUMIOSE_ROOM_SECRET', None)


def main(interactive: bool | None = None):
    os.chdir(ROOT)
    # A runtime restarted by the launcher updater must return through this entry point once. Child runtimes inherit
    # this marker so they do not route back here again while the update notification still exists.
    os.environ['LUMIOSE_ENTRY_ACTIVE'] = LAUNCHER_VERSION
    os.environ['PYTHONPATH'] = str(ROOT / 'python-deps') + os.pathsep + os.environ.get('PYTHONPATH', '')
    mod = ROOT / 'lumiose'
    config = mod / 'config.json'
    state = mod / 'update-state.json'
    revision = mod / 'launcher-code-revision.txt'
    first_setup = not state.exists()
    current_revision = revision.read_text(encoding='utf-8').strip() if revision.is_file() else ''
    log_event(f'Launcher started; initial setup required: {first_setup}; game-code revision check required: {current_revision != GAME_CODE_REVISION}')
    if current_revision != GAME_CODE_REVISION:
        (ROOT / 'textures/prompts/.made').unlink(missing_ok=True)
    if first_setup or current_revision != GAME_CODE_REVISION:
        print('Checking game setup for this launcher. Keep this window open.', flush=True)
        if first_setup:
            print('Choose your own Pokémon Legends Z-A 2.0.2 game files; Lumiose will prepare automatically.', flush=True)
        env = os.environ.copy()
        env['LARECOMP_DATA_ROOT'] = str(ROOT)
        env['LUMIOSE_FIRST_SETUP'] = '1'
        for key in ('LUMIOSE_TEST_MODULE', 'LUMIOSE_TEST_LIBRARY', 'LARECOMP_GAME_LIB',
                    'LARECOMP_NO_LAUNCHER', 'LUMIOSE_TEST_OFFLINE_CAPTURE'):
            env.pop(key, None)
        if os.environ.get('LUMIOSE_RELEASE_TEST_PREPARE_ONLY') != '1':
            env.pop('LARECOMP_HIDDEN', None)
        with tempfile.TemporaryDirectory(prefix='game-check-', dir=mod) as temp:
            done = Path(temp) / 'ready'
            # The launcher changes to ROOT before writing this marker. A relative ASCII path also avoids passing a
            # potentially non-ASCII Windows installation path through the C runtime's narrow fopen().
            env['LUMIOSE_SETUP_DONE'] = os.path.relpath(done, ROOT)
            result = subprocess.run([str(ROOT / EXECUTABLE), str(ROOT / 'extracted')], cwd=ROOT, env=env)
            if result.returncode or not done.is_file() or not (ROOT / 'extracted' / (GAME_LIBRARY + '.id')).is_file():
                raise RuntimeError('Game setup was not completed. Start Lumiose Online again when you are ready.')
        log_event('Game setup check completed')
    if first_setup:
        log_event('Preparing bundled Lumiose for first launch')
        cmd = [sys.executable, str(ROOT / 'tools/lumiose/setup.py'), '--install', str(ROOT),
               '--zig', str(ROOT / 'zig'), '--server', '135.148.167.226:27777']
        desktop_notice('Lumiose Online', 'Preparing the online mod. This may take several minutes.')
        if subprocess.run(cmd, cwd=ROOT).returncode:
            raise RuntimeError('Lumiose preparation did not finish; see the message above.')
        log_event('Bundled Lumiose preparation completed')
    if not config.is_file():
        raise RuntimeError('Lumiose configuration is missing. Your save files have not been changed.')
    # Rewrite paths when the player moves the installed folder.
    import json
    cfg = json.loads(config.read_text(encoding='utf-8'))
    cfg.update(install=str(ROOT), reference=str(ROOT / 'lumiose/subsdk9'),
               vanilla=str(ROOT / 'extracted' / GAME_LIBRARY), zig=str(ROOT / 'zig'),
               cache=str(ROOT / 'extracted/.gamebuild'))
    config.write_text(json.dumps(cfg, indent=2) + '\n', encoding='utf-8')
    log_event('Checking active Lumiose build and updates')

    if interactive is None:
        interactive = (
            __name__ == '__main__'
            and sys.stdin.isatty()
            and os.environ.get('LUMIOSE_RELEASE_TEST_PREPARE_ONLY') != '1'
            and os.environ.get('LUMIOSE_NO_MENU') != '1'
        )

    prepare_only = os.environ.get('LUMIOSE_RELEASE_TEST_PREPARE_ONLY') == '1'
    server_proc = None
    if interactive and not prepare_only:
        active_profile, server_settings = run_launcher_menu(ROOT)
        _apply_runtime_settings(ROOT, active_profile, server_settings)
        if server_settings['mode'] == 'host':
            port = server_settings['host_port']
            secret = server_settings.get('room_secret', '').strip()
            code = profile_store.write_room_code_file(ROOT, server_settings)
            if code and profile_store.copy_to_clipboard(code):
                print(f'[lumiose] Invite Code copied to clipboard & room-code.txt: {code}', flush=True)
            elif code:
                print(f'[lumiose] Invite Code (saved in room-code.txt): {code}', flush=True)

            if profile_store.is_udp_port_in_use(port):
                print(f'[lumiose] Using already-running UDP server on port {port}.', flush=True)
            else:
                print(f'[lumiose] Starting private room server on UDP port {port}...', flush=True)
                srv_cmd = [sys.executable, str(ROOT / 'tools/lumiose/private_server.py'), '--port', str(port)]
                if secret:
                    srv_cmd += ['--room-secret', secret]
                server_proc = subprocess.Popen(srv_cmd, cwd=ROOT)
            print('[lumiose] Keep this window open while hosting so your partner stays connected.', flush=True)
    elif not prepare_only and (ROOT / 'lumiose' / 'private-server.json').is_file():
        _, active_profile = profile_store.get_active_profile(ROOT)
        server_settings = profile_store.load_server_settings(ROOT)
        _apply_runtime_settings(ROOT, active_profile, server_settings)

    game_process = launch(config, prepare_only=prepare_only)
    log_event('Lumiose preparation completed; launcher started')
    if current_revision != GAME_CODE_REVISION:
        tmp = revision.with_suffix('.tmp')
        tmp.write_text(GAME_CODE_REVISION + '\n', encoding='utf-8')
        os.replace(tmp, revision)

    if server_proc is not None and game_process is not None:
        try:
            game_process.wait()
        finally:
            if server_proc.poll() is None:
                server_proc.terminate()
                try:
                    server_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server_proc.kill()


if __name__ == '__main__':
    if os.name != 'nt' and not sys.stderr.isatty():
        log_dir = ROOT / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        log = (log_dir / 'lumiose-launch.log').open('a', encoding='utf-8', buffering=1)
        sys.stdout = sys.stderr = log
    try:
        lock_path = ROOT / 'lumiose' / 'update.lock'
        with lock_path.open('a+b') as lock:
            try: lock_file(lock)
            except OSError: raise RuntimeError('Another Lumiose launcher is already preparing an update')
            main()
    except SystemExit:
        raise
    except Exception as e:
        log_event('Launcher failed: ' + str(e))
        print('\nLumiose could not start:', e, file=sys.stderr, flush=True)
        desktop_notice('Lumiose Online could not start', str(e) + '\nDetails: logs/lumiose-launch.log', error=True)
        if sys.stdin.isatty(): input('Press Enter to close this window. ')
        sys.exit(1)
