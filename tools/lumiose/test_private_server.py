"""Tests for private_server.py, profiles.py, and live winmm.dll UDP redirection."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import invite_code
import private_server as ps
import profiles

ROOT = Path(__file__).resolve().parents[2]


def make_hello(trainer_id: bytes, name: bytes, hashes: bytes | None = None) -> bytes:
    if hashes is None:
        hashes = bytes(range(104))
    assert len(trainer_id) == 14
    assert len(hashes) == 104
    return (
        ps.pack_header(ps.PKT_HELLO, 0)
        + trainer_id
        + b'\x01\x00\x00'
        + bytes([len(name)])
        + name
        + hashes
        + b'VM\x00\x00\x00\x00'
    )


def make_player_state(
    token: int,
    seq: int,
    *,
    area_id: int = 10,
    door_key: int = 1,
    flags: int = 0x05,
    x: float = 100.0,
    y: float = 20.0,
    z: float = -50.0,
    trailing: bytes = b'\xAA\xBB',
) -> bytes:
    floats = [x, y, z] + [0.0] * 9
    extra = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0] if (flags & 0x04) else []
    pkt = (
        ps.pack_header(ps.PKT_PLAYER_STATE, token)
        + struct.pack('<HIHHB', seq & 0xFFFF, 1234, area_id, door_key, flags)
        + struct.pack('<12f', *floats)
    )
    if extra:
        pkt += struct.pack('<6f', *extra)
    if trailing:
        pkt += bytes([len(trailing)]) + trailing
    return pkt


class PrivateServerProtocolTests(unittest.TestCase):
    def test_gate_beacon_short_hello_is_ignored(self):
        srv = ps.LumiosePrivateServer()
        beacon = ps.pack_header(ps.PKT_HELLO, 0) + b'\x00' * 14
        replies = srv.handle_packet(beacon, ('10.0.0.2', 50000), now=1.0)
        self.assertEqual(replies, [])
        self.assertEqual(len(srv.players), 0)

    def test_two_players_sync_chat_appearance_battlesync_and_leave(self):
        srv = ps.LumiosePrivateServer()
        hashes_a = b'\x11' * 104
        hashes_b = b'\x22' * 104

        r1 = srv.handle_packet(make_hello(b'A' * 14, b'Leandro', hashes_a), ('127.0.0.1', 40001), now=1.0)
        welcome_a = next(p for _, p in r1 if p[3] == ps.PKT_WELCOME)
        token_a = struct.unpack_from('<I', welcome_a, 4)[0]
        pid_a, caps_a, _, _, caps_ext_a = struct.unpack_from('<HBBBB', welcome_a, 16)
        self.assertEqual(len(welcome_a), 30)
        self.assertEqual(pid_a, 1)
        self.assertNotEqual(token_a, 0)
        self.assertEqual(caps_ext_a & 0x01, 0x01)
        self.assertTrue(any(p[3] == ps.PKT_DUEL_GRANT and len(p) == 16 for _, p in r1))

        # Second player joins
        r2 = srv.handle_packet(make_hello(b'B' * 14, b'Amorcito', hashes_b), ('127.0.0.1', 40002), now=1.1)
        welcome_b = next(p for dst, p in r2 if dst == ('127.0.0.1', 40002) and p[3] == ps.PKT_WELCOME)
        token_b = struct.unpack_from('<I', welcome_b, 4)[0]
        pid_b = struct.unpack_from('<H', welcome_b, 16)[0]
        self.assertEqual(pid_b, 2)

        # Player A receives INFO for Amorcito, Player B receives INFO for Leandro
        info_to_a = [p for dst, p in r2 if dst == ('127.0.0.1', 40001) and p[3] == ps.PKT_INFO]
        info_to_b = [p for dst, p in r2 if dst == ('127.0.0.1', 40002) and p[3] == ps.PKT_INFO]
        self.assertEqual(len(info_to_a), 1)
        self.assertEqual(len(info_to_b), 1)
        self.assertIn(b'Amorcito', info_to_a[0])
        self.assertIn(b'Leandro', info_to_b[0])

        # Player A uploads full outfit body via INFO_UPDATE (0x12) -> Player B gets 0x91 + 0x94
        body_blob = b'\x01' + b'\x55' * 20
        info_upd = (
            ps.pack_header(ps.PKT_INFO_UPDATE, token_a)
            + bytes([len(b'Leandro')])
            + b'Leandro'
            + hashes_a
            + b'\xB0'
            + struct.pack('<H', len(body_blob))
            + body_blob
        )
        upd_replies = srv.handle_packet(info_upd, ('127.0.0.1', 40001), now=1.2)
        self.assertTrue(any(dst == ('127.0.0.1', 40002) and p[3] == ps.PKT_BODY for dst, p in upd_replies))

        # Body request (0x13) from B for pid_a
        body_req = ps.pack_header(ps.PKT_BODY_REQUEST, token_b) + struct.pack('<BH', 1, pid_a)
        req_replies = srv.handle_packet(body_req, ('127.0.0.1', 40002), now=1.25)
        self.assertEqual(len(req_replies), 1)
        self.assertEqual(req_replies[0][1][3], ps.PKT_BODY)

        # Both send PLAYER_STATE (0x10) -> snapshot (0x90) includes peer and excludes self
        srv.handle_packet(make_player_state(token_a, seq=7, x=42.5, y=1.5, z=-9.0), ('127.0.0.1', 40001), now=1.3)
        srv.handle_packet(make_player_state(token_b, seq=9, x=-12.0, y=3.0, z=4.0), ('127.0.0.1', 40002), now=1.31)
        snaps = srv.flush_snapshots(now=1.33)
        snap_by_dst = dict(snaps)
        self.assertIn(('127.0.0.1', 40001), snap_by_dst)
        self.assertIn(('127.0.0.1', 40002), snap_by_dst)

        snap_to_a = snap_by_dst[('127.0.0.1', 40001)]
        self.assertEqual(snap_to_a[3], ps.PKT_SNAPSHOT)
        self.assertEqual(snap_to_a[10], 0x02)  # hdr_flags bit 1 set
        self.assertEqual(snap_to_a[11], 1)     # 1 peer
        peer_pid, peer_seq8, peer_flags, peer_area = struct.unpack_from('<HBBH', snap_to_a, 22)
        self.assertEqual(peer_pid, pid_b)
        self.assertEqual(peer_seq8, 9)
        self.assertEqual(peer_flags, 0x05)
        self.assertEqual(peer_area, 10)
        rx, ry, rz = struct.unpack_from('<3f', snap_to_a, 28)
        self.assertAlmostEqual(rx, -12.0, places=4)

        # Chat (0x30) from A -> B receives 0xB0
        msg = b'Hola amor!'
        chat_pkt = ps.pack_header(ps.PKT_CHAT, token_a) + struct.pack('<BB', 0, len(msg)) + msg
        chat_replies = srv.handle_packet(chat_pkt, ('127.0.0.1', 40001), now=1.4)
        self.assertEqual(len(chat_replies), 1)
        self.assertEqual(chat_replies[0][0], ('127.0.0.1', 40002))
        self.assertIn(b'Hola amor!', chat_replies[0][1])

        # BattleSync (0x50) -> 0xD0
        bsync = ps.pack_header(ps.PKT_BATTLESYNC, token_a) + b'\x77' * 19
        bs_replies = srv.handle_packet(bsync, ('127.0.0.1', 40001), now=1.5)
        self.assertEqual(len(bs_replies), 1)
        self.assertEqual(len(bs_replies[0][1]), 29)
        self.assertEqual(bs_replies[0][1][3], ps.PKT_BATTLESYNC_IN)

        # Leave (0x1f) removes B and sends 0-peer snapshot to A
        leave_replies = srv.handle_packet(ps.pack_header(ps.PKT_LEAVE, token_b), ('127.0.0.1', 40002), now=1.6)
        self.assertEqual(len(srv.players), 1)
        self.assertEqual(len(leave_replies), 1)
        self.assertEqual(leave_replies[0][1][11], 0)


class ProfileStoreTests(unittest.TestCase):
    def test_profile_lifecycle_and_shared_sdcard_junction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'lumiose').mkdir()
            data, active = profiles.get_active_profile(root)
            self.assertEqual(active['id'], 'default')

            data, p2 = profiles.create_profile(root, 'Mi Amorcito')
            self.assertEqual(data['active'], p2['id'])
            save_p2 = profiles.prepare_profile_directory(root, p2)
            self.assertTrue(save_p2.is_dir())
            self.assertTrue((save_p2 / 'sdcard').is_dir())

            # Writing a mod file in shared save/sdcard is visible through profile's sdcard link
            marker = root / 'save' / 'sdcard' / 'mod-marker.txt'
            marker.write_text('shared-ok', encoding='utf-8')
            self.assertEqual((save_p2 / 'sdcard' / 'mod-marker.txt').read_text(encoding='utf-8'), 'shared-ok')

            # Save data inside profile remains isolated
            (save_p2 / 'save_1').mkdir()
            (save_p2 / 'save_1' / 'trainer.bin').write_bytes(b'p2')
            self.assertFalse((root / 'save' / 'save_1').exists())

            # Deleting profile metadata keeps save folder intact on disk
            profiles.delete_profile(root, p2['id'])
            self.assertTrue((save_p2 / 'save_1' / 'trainer.bin').exists())

    def test_server_settings_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'lumiose').mkdir()
            self.assertEqual(profiles.validate_host_port('100.64.0.5'), '100.64.0.5:27777')
            self.assertEqual(profiles.validate_host_port('example.duckdns.org:28888'), 'example.duckdns.org:28888')
            with self.assertRaises(ValueError):
                profiles.validate_host_port('bad:99999')
            profiles.save_server_settings(root, {'mode': 'join', 'host_port': 27777, 'join_address': '100.64.0.5:27777'})
            loaded = profiles.load_server_settings(root)
            self.assertEqual(loaded['mode'], 'join')
            self.assertEqual(loaded['join_address'], '100.64.0.5:27777')


class LiveRedirectAndServerTests(unittest.TestCase):
    def test_winmm_dll_exists_and_redirects_udp_with_room_secret_knock(self):
        if sys.platform != 'win32':
            self.skipTest('Windows PE winmm.dll test')
        winmm_path = ROOT / 'winmm.dll'
        zig_root = next(
            (
                d for d in (
                    Path(os.environ.get('LUMIOSE_ZIG_DIR', '')) if os.environ.get('LUMIOSE_ZIG_DIR') else Path(),
                    ROOT / 'zig',
                    ROOT / 'build' / 'zig-slim',
                    ROOT / 'build' / 'zig',
                )
                if d and (d / 'zig.exe').is_file()
            ),
            None,
        )
        require_winmm = os.environ.get('LARECOMP_REQUIRE_WINMM') == '1'
        if not winmm_path.is_file() or zig_root is None:
            if require_winmm:
                self.fail(f'winmm.dll ({winmm_path}) or zig compiler ({zig_root}) missing with LARECOMP_REQUIRE_WINMM=1')
            self.skipTest('winmm.dll or zig not built in clean source checkout')
        zig = zig_root / 'zig.exe'
        rt = zig_root / 'rt'
        self.assertTrue(winmm_path.is_file())

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv_sock.bind(('127.0.0.1', 0))
        srv_sock.settimeout(5.0)
        port = srv_sock.getsockname()[1]
        room_secret = 'CAFE1234'
        server = ps.LumiosePrivateServer(room_secret=room_secret)
        stop = threading.Event()

        def serve_loop():
            while not stop.is_set():
                try:
                    data, addr = srv_sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                for dst, pkt in server.handle_packet(data, addr):
                    srv_sock.sendto(pkt, dst)

        th = threading.Thread(target=serve_loop, daemon=True)
        th.start()

        env = os.environ.copy()
        env['ZIG_LIB_DIR'] = str(zig_root / 'lib')
        env['LUMIOSE_SERVER_OVERRIDE'] = f'127.0.0.1:{port}'
        env['LUMIOSE_ROOM_SECRET'] = room_secret

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            shutil.copy2(winmm_path, t / 'winmm.dll')
            (t / 'winmm.def').write_text('LIBRARY WINMM.dll\nEXPORTS\n timeBeginPeriod\n', encoding='utf-8')
            (t / 'ws2_32.def').write_text(
                'LIBRARY WS2_32.dll\nEXPORTS\n WSAStartup\n WSACleanup\n socket\n sendto\n recvfrom\n closesocket\n',
                encoding='utf-8',
            )
            for name in ('winmm', 'ws2_32'):
                subprocess.run(
                    [str(zig), 'dlltool', '-m', 'i386:x86-64', '-d', str(t / f'{name}.def'), '-l', str(t / f'{name}.lib')],
                    env=env,
                    check=True,
                )

            hello = make_hello(b'T' * 14, b'Probe')
            byte_list = ','.join(str(b) for b in hello)
            probe_c = t / 'probe_hello.c'
            probe_c.write_text(
                f'''
#include <stddef.h>
#include <stdint.h>
typedef unsigned int UINT;
typedef uintptr_t SOCKET;
struct WSAData {{ uint8_t data[512]; }};
struct sockaddr_in {{ uint16_t fam; uint16_t port; uint32_t addr; char z[8]; }};
__declspec(dllimport) UINT __stdcall timeBeginPeriod(UINT);
__declspec(dllimport) int __stdcall WSAStartup(uint16_t, struct WSAData *);
__declspec(dllimport) int __stdcall WSACleanup(void);
__declspec(dllimport) SOCKET __stdcall socket(int, int, int);
__declspec(dllimport) int __stdcall sendto(SOCKET, const char*, int, int, const void*, int);
__declspec(dllimport) int __stdcall recvfrom(SOCKET, char*, int, int, void*, int*);
__declspec(dllimport) int __stdcall closesocket(SOCKET);
__declspec(dllimport) void __stdcall ExitProcess(UINT);

void *memcpy(void *dst, const void *src, size_t n) {{
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}}
void *memset(void *dst, int v, size_t n) {{
    volatile uint8_t *d = (volatile uint8_t *)dst;
    for (size_t i = 0; i < n; ++i) d[i] = (uint8_t)v;
    return dst;
}}

static const uint8_t kHello[] = {{ {byte_list} }};

void mainCRTStartup(void) {{
    UINT tp = timeBeginPeriod(1);
    struct WSAData wsa;
    WSAStartup(0x0202, &wsa);
    SOCKET s = socket(2, 2, 17);
    struct sockaddr_in dst = {{2, 0x816c, 0xe2a79487, {{0}}}}; // 135.148.167.226:27777
    int sent = sendto(s, (const char*)kHello, sizeof(kHello), 0, &dst, sizeof(dst));
    uint8_t buf[256] = {{0}};
    struct sockaddr_in frm = {{0}};
    int flen = sizeof(frm);
    int rcv = recvfrom(s, (char*)buf, sizeof(buf), 0, &frm, &flen);
    closesocket(s);
    WSACleanup();
    // Expect WELCOME packet (30 bytes, type 0x81, pid 1, reported from official 135.148.167.226:27777)
    int ok = (tp == 0 && sent == (int)sizeof(kHello) && rcv == 30 &&
              buf[0] == 'Z' && buf[1] == 'A' && buf[2] == 1 && buf[3] == 0x81 &&
              buf[16] == 1 && buf[21] == 0x01 &&
              frm.addr == 0xe2a79487u && frm.port == 0x816cu);
    ExitProcess(ok ? 0 : 99);
}}
''',
                encoding='utf-8',
            )
            subprocess.run(
                [str(zig), 'cc', '-target', 'x86_64-windows-gnu', '-ffreestanding', '-fno-builtin', '-Os', '-c', str(probe_c), '-o', str(t / 'probe.o')],
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    str(zig), 'lld-link', '-NOLOGO', '-MACHINE:X64', '-SUBSYSTEM:CONSOLE', '-ENTRY:mainCRTStartup',
                    '-OUT:' + str(t / 'probe.exe'), str(t / 'probe.o'),
                    str(t / 'winmm.lib'), str(t / 'ws2_32.lib'), str(rt / 'kernel32.lib'),
                ],
                env=env,
                check=True,
            )
            pr = subprocess.run([str(t / 'probe.exe')], cwd=t, env=env, timeout=5)
            stop.set()
            th.join(timeout=2)
            srv_sock.close()
            self.assertEqual(pr.returncode, 0)
            self.assertEqual(len(server.players), 1)
            self.assertEqual(server.players[1].name, b'Probe')

    def test_entry_runtime_settings_switches_env_cleanly(self):
        import entry
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'lumiose').mkdir()
            _, p_default = profiles.get_active_profile(root)
            _, p_custom = profiles.create_profile(root, 'Partner')
            orig_env = os.environ.copy()
            try:
                entry._apply_runtime_settings(
                    root, p_default, {'mode': 'host', 'host_port': 27777, 'room_secret': 'AABBCCDD', 'join_address': ''}
                )
                self.assertNotIn('LARECOMP_SAVE_DIR', os.environ)
                self.assertEqual(os.environ.get('LUMIOSE_SERVER_OVERRIDE'), '127.0.0.1:27777')
                self.assertEqual(os.environ.get('LUMIOSE_ROOM_SECRET'), 'AABBCCDD')

                entry._apply_runtime_settings(
                    root, p_custom, {'mode': 'join', 'host_port': 27777, 'join_address': '100.64.0.9:27777', 'join_secret': '11223344'}
                )
                self.assertEqual(Path(os.environ['LARECOMP_SAVE_DIR']), (root / p_custom['save_dir']).resolve())
                self.assertEqual(os.environ.get('LUMIOSE_SERVER_OVERRIDE'), '100.64.0.9:27777')
                self.assertEqual(os.environ.get('LUMIOSE_ROOM_SECRET'), '11223344')

                entry._apply_runtime_settings(
                    root, p_default, {'mode': 'official', 'host_port': 27777, 'join_address': ''}
                )
                self.assertNotIn('LUMIOSE_SERVER_OVERRIDE', os.environ)
                self.assertNotIn('LUMIOSE_ROOM_SECRET', os.environ)
            finally:
                os.environ.clear()
                os.environ.update(orig_env)


class InviteCodeAndRoomAuthTests(unittest.TestCase):
    def test_ipv4_and_playit_invite_code_roundtrip_and_checksum(self):
        code_ip = invite_code.encode_invite('100.64.12.34', 27777, 'A1B2C3D4')
        self.assertTrue(code_ip.startswith('ZA1-'))
        host, port, sec = invite_code.decode_invite(code_ip.lower().replace('-', ' '))
        self.assertEqual((host, port, sec), ('100.64.12.34', 27777, 'A1B2C3D4'))

        code_playit = invite_code.encode_invite('warm-cat.gl.at.ply.gg', 19450, 'DEADBEEF')
        self.assertTrue(code_playit.startswith('ZA2-'))
        self.assertLess(len(code_playit), 48)
        self.assertEqual(invite_code.decode_invite(code_playit), ('warm-cat.gl.at.ply.gg', 19450, 'DEADBEEF'))

        # Corrupted character fails checksum
        tampered = code_ip[:-1] + ('Z' if code_ip[-1] != 'Z' else 'Y')
        with self.assertRaises(ValueError):
            invite_code.decode_invite(tampered)

    def test_room_secret_blocks_unauthenticated_hello(self):
        srv = ps.LumiosePrivateServer(room_secret='1234ABCD')
        hello = make_hello(b'X' * 14, b'Stranger')
        # Without ZAKNOCK! -> rejected
        self.assertEqual(srv.handle_packet(hello, ('203.0.113.5', 40000), now=1.0), [])
        self.assertEqual(len(srv.players), 0)
        # Wrong knock -> rejected
        srv.handle_packet(b'ZAKNOCK!00000000', ('203.0.113.5', 40000), now=1.1)
        self.assertEqual(srv.handle_packet(hello, ('203.0.113.5', 40000), now=1.2), [])
        # Valid knock -> accepted
        srv.handle_packet(b'ZAKNOCK!1234abcd', ('203.0.113.5', 40000), now=1.3)
        res = srv.handle_packet(hello, ('203.0.113.5', 40000), now=1.4)
        self.assertTrue(any(p[3] == ps.PKT_WELCOME for _, p in res))


if __name__ == '__main__':
    unittest.main()
