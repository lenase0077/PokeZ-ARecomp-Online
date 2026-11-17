"""Multi-profile save isolation and private-server configuration for Lumiose Online."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import urllib.parse
import urllib.request
from xml.etree import ElementTree

import invite_code

OFFICIAL_SERVER = '135.148.167.226:27777'
DEFAULT_PORT = 27777

VALID_MODES = ('host', 'join', 'official')
VALID_TRANSPORTS = ('playit', 'vpn', 'upnp')


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    os.replace(tmp, path)


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def slugify_profile_id(name: str, existing_ids: set[str]) -> str:
    base = re.sub(r'[^a-z0-9_-]+', '-', name.strip().lower()).strip('-_')
    if not base:
        base = 'profile'
    if base == 'default':
        base = 'profile-2'
    candidate = base
    suffix = 2
    while candidate in existing_ids:
        candidate = f'{base}-{suffix}'
        suffix += 1
    return candidate


def load_profiles(root: Path) -> dict:
    store_path = root / 'lumiose' / 'profiles.json'
    data = _load_json(store_path)
    if data and isinstance(data.get('profiles'), list) and data['profiles']:
        ids = {p.get('id') for p in data['profiles'] if isinstance(p, dict) and p.get('id')}
        if 'default' in ids:
            if data.get('active') not in ids:
                data['active'] = 'default'
            return data

    default_data = {
        'active': 'default',
        'profiles': [
            {
                'id': 'default',
                'name': 'Default Trainer',
                'save_dir': 'save',
            }
        ],
    }
    return default_data


def save_profiles(root: Path, data: dict) -> None:
    _atomic_write_json(root / 'lumiose' / 'profiles.json', data)


def get_active_profile(root: Path) -> tuple[dict, dict]:
    data = load_profiles(root)
    active_id = data.get('active', 'default')
    for p in data['profiles']:
        if p.get('id') == active_id:
            return data, p
    return data, data['profiles'][0]


def create_profile(root: Path, display_name: str) -> tuple[dict, dict]:
    clean_name = display_name.strip()
    if not clean_name:
        raise ValueError('Profile name cannot be empty')
    data = load_profiles(root)
    existing_ids = {p['id'] for p in data['profiles']}
    pid = slugify_profile_id(clean_name, existing_ids)
    entry = {
        'id': pid,
        'name': clean_name,
        'save_dir': f'save/profiles/{pid}',
    }
    data['profiles'].append(entry)
    data['active'] = pid
    save_profiles(root, data)
    return data, entry


def rename_profile(root: Path, profile_id: str, new_name: str) -> dict:
    clean_name = new_name.strip()
    if not clean_name:
        raise ValueError('Profile name cannot be empty')
    data = load_profiles(root)
    for p in data['profiles']:
        if p['id'] == profile_id:
            p['name'] = clean_name
            save_profiles(root, data)
            return data
    raise KeyError(f'Unknown profile: {profile_id}')


def delete_profile(root: Path, profile_id: str) -> dict:
    """Remove profile metadata entry without deleting save files on disk."""
    if profile_id == 'default':
        raise ValueError('Cannot remove the default profile')
    data = load_profiles(root)
    kept = [p for p in data['profiles'] if p['id'] != profile_id]
    if len(kept) == len(data['profiles']):
        raise KeyError(f'Unknown profile: {profile_id}')
    data['profiles'] = kept
    if data.get('active') == profile_id:
        data['active'] = 'default'
    save_profiles(root, data)
    return data


def set_active_profile(root: Path, profile_id: str) -> tuple[dict, dict]:
    data = load_profiles(root)
    for p in data['profiles']:
        if p['id'] == profile_id:
            data['active'] = profile_id
            save_profiles(root, data)
            return data, p
    raise KeyError(f'Unknown profile: {profile_id}')


def prepare_profile_directory(root: Path, profile: dict) -> Path:
    """Ensure the profile save directory exists and shares save/sdcard."""
    rel = profile.get('save_dir', 'save')
    save_path = (root / rel).resolve()
    shared_sdcard = (root / 'save' / 'sdcard').resolve()
    shared_sdcard.mkdir(parents=True, exist_ok=True)
    save_path.mkdir(parents=True, exist_ok=True)

    target_sdcard = save_path / 'sdcard'
    if save_path != (root / 'save').resolve() and not target_sdcard.exists():
        if os.name == 'nt':
            # Use an NTFS directory junction so mod assets/updates stay shared without admin rights.
            res = subprocess.run(
                ['cmd', '/c', 'mklink', '/J', str(target_sdcard), str(shared_sdcard)],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0 and not target_sdcard.exists():
                raise RuntimeError(
                    f'Could not link shared sdcard folder for profile: {res.stderr or res.stdout}'
                )
        else:
            target_sdcard.symlink_to(shared_sdcard, target_is_directory=True)
    return save_path


def load_server_settings(root: Path) -> dict:
    path = root / 'lumiose' / 'private-server.json'
    data = _load_json(path) or {}
    mode = data.get('mode', 'host')
    if mode not in VALID_MODES:
        mode = 'host'
    port = data.get('host_port', DEFAULT_PORT)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        port = DEFAULT_PORT
    transport = data.get('host_transport', 'playit')
    if transport not in VALID_TRANSPORTS:
        transport = 'playit'
    room_secret = str(data.get('room_secret', '')).strip().upper()
    if len(room_secret) != 8:
        room_secret = ''
    return {
        'mode': mode,
        'host_port': port,
        'host_transport': transport,
        'host_public_address': str(data.get('host_public_address', '')).strip(),
        'room_secret': room_secret,
        'join_address': str(data.get('join_address', '')).strip(),
        'join_code': str(data.get('join_code', '')).strip().upper(),
        'join_secret': str(data.get('join_secret', '')).strip().upper(),
    }


def save_server_settings(root: Path, settings: dict) -> None:
    mode = settings.get('mode', 'host')
    if mode not in VALID_MODES:
        raise ValueError(f'Invalid mode: {mode}')
    port = int(settings.get('host_port', DEFAULT_PORT))
    if not (1 <= port <= 65535):
        raise ValueError(f'Invalid UDP port: {port}')
    transport = settings.get('host_transport', 'playit')
    if transport not in VALID_TRANSPORTS:
        transport = 'playit'
    clean = {
        'mode': mode,
        'host_port': port,
        'host_transport': transport,
        'host_public_address': str(settings.get('host_public_address', '')).strip(),
        'room_secret': str(settings.get('room_secret', '')).strip().upper(),
        'join_address': str(settings.get('join_address', '')).strip(),
        'join_code': str(settings.get('join_code', '')).strip().upper(),
        'join_secret': str(settings.get('join_secret', '')).strip().upper(),
    }
    _atomic_write_json(root / 'lumiose' / 'private-server.json', clean)


def validate_host_port(spec: str, default_port: int = DEFAULT_PORT) -> str:
    raw = spec.strip()
    if not raw:
        raise ValueError('Server address cannot be empty')
    if ':' not in raw:
        raw = f'{raw}:{default_port}'
    host, port_s = raw.rsplit(':', 1)
    host = host.strip()
    if not host or any(c.isspace() for c in host):
        raise ValueError('Invalid hostname or IP address')
    try:
        port = int(port_s)
    except ValueError as exc:
        raise ValueError('Port must be a number between 1 and 65535') from exc
    if not (1 <= port <= 65535):
        raise ValueError('Port must be between 1 and 65535')
    return f'{host}:{port}'


def detect_local_ips() -> list[str]:
    ips: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.') and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(('8.8.8.8', 80))
        ip = probe.getsockname()[0]
        probe.close()
        if not ip.startswith('127.') and ip not in ips:
            ips.insert(0, ip)
    except OSError:
        pass
    return ips


def is_udp_port_in_use(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', port))
        return False
    except OSError:
        return True
    finally:
        sock.close()


def get_primary_local_ip() -> str | None:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(('8.8.8.8', 80))
        ip = probe.getsockname()[0]
        probe.close()
        return None if ip.startswith('127.') else ip
    except OSError:
        return None


def get_public_ipv4(timeout: float = 2.0) -> str | None:
    for url in ('https://api.ipify.org', 'https://checkip.amazonaws.com'):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                candidate = resp.read().decode('ascii', 'ignore').strip()
                socket.inet_aton(candidate)
                return candidate
        except (OSError, ValueError):
            continue
    return None


def try_upnp_forward(internal_ip: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
    """Best-effort UPnP IGD UDP port mapping without external dependencies."""
    ssdp_req = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'
    ).encode('ascii')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    location = None
    try:
        sock.sendto(ssdp_req, ('239.255.255.250', 1900))
        while True:
            try:
                raw, _ = sock.recvfrom(4096)
            except socket.timeout:
                break
            for line in raw.decode('latin-1', 'replace').splitlines():
                if line.lower().startswith('location:'):
                    location = line.split(':', 1)[1].strip()
                    break
            if location:
                break
    except OSError as exc:
        return False, f'UPnP discovery failed: {exc}'
    finally:
        sock.close()

    if not location:
        return False, 'No UPnP router responded on the local network'

    try:
        with urllib.request.urlopen(location, timeout=timeout) as resp:
            desc_xml = ElementTree.fromstring(resp.read())
        control_url = None
        service_type = None
        for svc in desc_xml.iter():
            if svc.tag.endswith('service'):
                st = None
                cu = None
                for ch in svc:
                    if ch.tag.endswith('serviceType'):
                        st = (ch.text or '').strip()
                    elif ch.tag.endswith('controlURL'):
                        cu = (ch.text or '').strip()
                if st and cu and (
                    'WANIPConnection' in st or 'WANPPPConnection' in st
                ):
                    service_type = st
                    control_url = urllib.parse.urljoin(location, cu)
                    break
        if not control_url or not service_type:
            return False, 'Router UPnP gateway has no WANIP/WANPPP service'

        soap = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body>'
            f'<u:AddPortMapping xmlns:u="{service_type}">'
            '<NewRemoteHost></NewRemoteHost>'
            f'<NewExternalPort>{port}</NewExternalPort>'
            '<NewProtocol>UDP</NewProtocol>'
            f'<NewInternalPort>{port}</NewInternalPort>'
            f'<NewInternalClient>{internal_ip}</NewInternalClient>'
            '<NewEnabled>1</NewEnabled>'
            '<NewPortMappingDescription>Lumiose Online Private</NewPortMappingDescription>'
            '<NewLeaseDuration>0</NewLeaseDuration>'
            '</u:AddPortMapping>'
            '</s:Body></s:Envelope>'
        ).encode('utf-8')
        req = urllib.request.Request(
            control_url,
            data=soap,
            headers={
                'Content-Type': 'text/xml; charset="utf-8"',
                'SOAPAction': f'"{service_type}#AddPortMapping"',
            },
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if 200 <= resp.status < 300:
                return True, f'Mapped UDP port {port} -> {internal_ip}:{port} via UPnP'
            return False, f'UPnP router returned HTTP {resp.status}'
    except Exception as exc:
        return False, f'UPnP mapping failed: {exc}'


def ensure_host_invite(root: Path, *, rotate: bool = False) -> dict:
    settings = load_server_settings(root)
    changed = False
    if rotate or not settings.get('room_secret'):
        settings['room_secret'] = invite_code.generate_secret_hex()
        changed = True
    if not settings.get('host_public_address'):
        local = get_primary_local_ip()
        if local:
            settings['host_public_address'] = f"{local}:{settings['host_port']}"
            changed = True
    if changed:
        save_server_settings(root, settings)
    return settings


def build_host_invite_code(settings: dict) -> str | None:
    pub = settings.get('host_public_address', '').strip()
    secret = settings.get('room_secret', '').strip()
    if not pub or not secret:
        return None
    try:
        validated = validate_host_port(pub, default_port=settings.get('host_port', DEFAULT_PORT))
        host, port_s = validated.rsplit(':', 1)
        return invite_code.encode_invite(host, int(port_s), secret)
    except ValueError:
        return None


def write_room_code_file(root: Path, settings: dict) -> str | None:
    code = build_host_invite_code(settings)
    if code:
        (root / 'room-code.txt').write_text(code + '\n', encoding='utf-8')
    return code


def copy_to_clipboard(text: str) -> bool:
    if os.name != 'nt' or not text:
        return False
    try:
        res = subprocess.run(['clip'], input=text, text=True, capture_output=True)
        return res.returncode == 0
    except OSError:
        return False
