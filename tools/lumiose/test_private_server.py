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
import private_coop as pc
import private_features as pf
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
        # Verify 0x91 layout: count=1, pid(2), rev(1), nlen(1), name[nlen], hashes[104]
        self.assertEqual(info_to_a[0][13 : 13 + len(b'Amorcito')], b'Amorcito')
        self.assertEqual(info_to_a[0][13 + len(b'Amorcito') : 13 + len(b'Amorcito') + 104], hashes_b)
        self.assertEqual(info_to_b[0][13 : 13 + len(b'Leandro')], b'Leandro')
        self.assertEqual(info_to_b[0][13 + len(b'Leandro') : 13 + len(b'Leandro') + 104], hashes_a)

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


class ExtensionProtocolTests(unittest.TestCase):
    def _join(self, srv: ps.LumiosePrivateServer, tid: bytes, name: bytes, addr: tuple[str, int]):
        replies = srv.handle_packet(make_hello(tid, name), addr, now=1.0)
        welcome = next(p for d, p in replies if d == addr and p[3] == ps.PKT_WELCOME)
        token = struct.unpack_from('<I', welcome, 4)[0]
        pid = struct.unpack_from('<H', welcome, 16)[0]
        return pid, token, replies

    def test_friends_lifecycle_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / 'private-room-state.json'
            wall = [1794960000.0]  # fixed UTC date 2026-11-18
            srv = ps.LumiosePrivateServer(state_path=state_file, wall_clock=lambda: wall[0])
            addr_a = ('127.0.0.1', 40101)
            addr_b = ('190.22.219.1', 40102)
            pid_a, tok_a, _ = self._join(srv, b'A' * 14, b'Leandro', addr_a)
            pid_b, tok_b, _ = self._join(srv, b'B' * 14, b'Amorcito', addr_b)

            # A requests B (0x78) -> B receives 0xF8
            req_pkt = ps.pack_header(pf.PKT_FRIEND_REQUEST, tok_a) + struct.pack('<HH', pid_b, 42)
            r_req = srv.handle_packet(req_pkt, addr_a, now=2.0)
            self.assertEqual(len(r_req), 1)
            self.assertEqual(r_req[0][0], addr_b)
            f8 = r_req[0][1]
            self.assertEqual(f8[3], pf.PKT_FRIEND_REQUEST_IN)
            from_pid, req_id, nlen = struct.unpack_from('<HHB', f8, 8)
            self.assertEqual((from_pid, req_id), (pid_a, 42))
            self.assertEqual(f8[13 : 13 + nlen], b'Leandro')

            # B accepts (0x79 answer=1) -> A gets 0xF9 code=1, both get 0xFA + 0xFB
            ans_pkt = ps.pack_header(pf.PKT_FRIEND_ANSWER, tok_b) + struct.pack('<HHB', pid_a, 42, 1)
            r_ans = srv.handle_packet(ans_pkt, addr_b, now=2.1)
            f9 = next(p for d, p in r_ans if d == addr_a and p[3] == pf.PKT_FRIEND_RESULT)
            self.assertEqual(struct.unpack_from('<HHB', f9, 8), (pid_b, 42, pf.FRIEND_CODE_ACCEPTED))
            fa_a = next(p for d, p in r_ans if d == addr_a and p[3] == pf.PKT_FRIEND_LIST)
            fb_a = next(p for d, p in r_ans if d == addr_a and p[3] == pf.PKT_FRIEND_STATUS_LIST)
            rev_fa, cnt_fa = struct.unpack_from('<IB', fa_a, 8)
            rev_fb = struct.unpack_from('<I', fb_a, 8)[0]
            self.assertEqual(cnt_fa, 1)
            self.assertEqual(rev_fa, rev_fb)
            self.assertIn(b'Amorcito', fa_a)

            # Duplicate request returns code=6 (ALREADY)
            r_dup = srv.handle_packet(req_pkt, addr_a, now=2.2)
            self.assertEqual(r_dup[0][1][12], pf.FRIEND_CODE_ALREADY)

            # Status update (0x7B) updates self & online friend with matching list_rev
            st_msg = b'Buscando shinies!'
            r_st = srv.handle_packet(
                ps.pack_header(pf.PKT_FRIEND_STATUS, tok_b) + bytes([len(st_msg)]) + st_msg,
                addr_b,
                now=2.3,
            )
            fb_to_a = next(p for d, p in r_st if d == addr_a and p[3] == pf.PKT_FRIEND_STATUS_LIST)
            self.assertEqual(struct.unpack_from('<I', fb_to_a, 8)[0], rev_fa)
            self.assertIn(st_msg, fb_to_a)

            # Restart server from saved JSON -> friendship and status persist; B offline shows pid=0
            srv2 = ps.LumiosePrivateServer(state_path=state_file, wall_clock=lambda: wall[0])
            pid_a2, tok_a2, _ = self._join(srv2, b'A' * 14, b'Leandro', addr_a)
            r_list = srv2.handle_packet(
                ps.pack_header(pf.PKT_FRIEND_LIST_REQ, tok_a2) + struct.pack('<I', 0),
                addr_a,
                now=3.0,
            )
            fa_2 = next(p for _, p in r_list if p[3] == pf.PKT_FRIEND_LIST)
            self.assertEqual(fa_2[12], 1)
            entry_pid = struct.unpack_from('<H', fa_2, 13)[0]
            self.assertEqual(entry_pid, 0)  # B is offline

            # Remove friend (0x7C) removes bidirectional friendship
            r_rem = srv2.handle_packet(
                ps.pack_header(pf.PKT_FRIEND_REMOVE, tok_a2)
                + struct.pack('<HB', 0, len(b'Amorcito'))
                + b'Amorcito',
                addr_a,
                now=3.1,
            )
            fa_empty = next(p for _, p in r_rem if p[3] == pf.PKT_FRIEND_LIST)
            self.assertEqual(fa_empty[12], 0)

    def test_daily_streak_shiny_charm_bag_and_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / 'private-room-state.json'
            wall = [1794960000.0]  # 2026-11-18T00:00:00Z
            srv = ps.LumiosePrivateServer(state_path=state_file, wall_clock=lambda: wall[0])
            addr = ('127.0.0.1', 40201)
            _, tok, join_replies = self._join(srv, b'C' * 14, b'Trainer', addr)

            # Initial FC 13 & FC 16 pushed on join
            fc13 = next(p for _, p in join_replies if p[3] == pf.PKT_EXTENSION_IN and p[8] == pf.SUBOP_DAILY_STREAK)
            fc16 = next(p for _, p in join_replies if p[3] == pf.PKT_EXTENSION_IN and p[8] == pf.SUBOP_LUMIOSE_BAG)
            self.assertEqual(len(fc13), 18)
            self.assertEqual(fc13[9], 1)

            # Ledger 0x40 -> 0xC0 status=1 enforce=0; 0x41 -> 0xC1 seq ack
            r_led = srv.handle_packet(ps.pack_header(pf.PKT_LEDGER_REPORT, tok) + b'\x01\x00\x00', addr, now=1.1)
            self.assertEqual(r_led[0][1][3], pf.PKT_LEDGER_STATUS)
            self.assertEqual((r_led[0][1][8], r_led[0][1][9]), (1, 0))
            r_ev = srv.handle_packet(ps.pack_header(pf.PKT_LEDGER_EVENTS, tok) + struct.pack('<H', 77), addr, now=1.2)
            self.assertEqual(r_ev[0][1][3], pf.PKT_LEDGER_ACK)
            self.assertEqual(struct.unpack_from('<HB', r_ev[0][1], 8), (77, 1))

            # Claim Days 1..5 across consecutive UTC days
            claim_req = ps.pack_header(pf.PKT_EXTENSION, tok) + bytes([0x13, 0, 0, 0, 0, 3])
            for expected_day in range(1, 6):
                r_cl = srv.handle_packet(claim_req, addr, now=2.0 + expected_day)
                st = next(p for _, p in r_cl if p[3] == pf.PKT_EXTENSION_IN and p[8] == 0x13)
                bag = next(p for _, p in r_cl if p[3] == pf.PKT_EXTENSION_IN and p[8] == 0x16)
                code, day, item_id, cd = struct.unpack_from('<BBHI', st, 10)
                self.assertEqual(code, 2)
                self.assertEqual(day, expected_day)
                self.assertGreater(cd, 0)
                if expected_day < 5:
                    self.assertEqual(item_id, 0)
                    # Same-day re-claim returns code=4 and does not increment day
                    r_again = srv.handle_packet(claim_req, addr, now=2.5 + expected_day)
                    st2 = next(p for _, p in r_again if p[3] == pf.PKT_EXTENSION_IN and p[8] == 0x13)
                    self.assertEqual(st2[10], 4)
                    self.assertEqual(st2[11], expected_day)
                    wall[0] += 86400.0
                else:
                    self.assertEqual(item_id, pf.ITEM_LUMIOSE_SHINY_CHARM)
                    self.assertEqual(bag[15], 1)  # 1 bag entry
                    bid, bqty, brem = struct.unpack_from('<HHI', bag, 16)
                    self.assertEqual((bid, bqty, brem), (1, 1, 0))

            # Activate Lumiose Shiny Charm (7D 13 00 00 00 00 04 01 00) -> code=3, 3600s left
            use_pkt = ps.pack_header(pf.PKT_EXTENSION, tok) + struct.pack('<BBBBHH', 0x13, 0, 0, 0, 0x0400, 1)
            r_use = srv.handle_packet(use_pkt, addr, now=10.0)
            bag_used = r_use[0][1]
            self.assertEqual(bag_used[12], 3)  # activated popup
            bid, bqty, brem = struct.unpack_from('<HHI', bag_used, 16)
            self.assertEqual((bid, bqty, brem), (1, 0, pf.SHINY_CHARM_DURATION_SECONDS))

            # Activating while already active returns code=5
            r_use2 = srv.handle_packet(use_pkt, addr, now=11.0)
            self.assertEqual(r_use2[0][1][12], 5)


class CoopAndEventsTests(unittest.TestCase):
    def _join(self, srv: ps.LumiosePrivateServer, tid: bytes, name: bytes, addr: tuple[str, int]):
        replies = srv.handle_packet(make_hello(tid, name), addr, now=1.0)
        welcome = next(p for d, p in replies if d == addr and p[3] == ps.PKT_WELCOME)
        token = struct.unpack_from('<I', welcome, 4)[0]
        pid = struct.unpack_from('<H', welcome, 16)[0]
        return pid, token, replies

    def _chat(self, tok: int, text: bytes) -> bytes:
        return ps.pack_header(ps.PKT_CHAT, tok) + bytes([1, len(text)]) + text

    def test_market_disabled_and_mystery_gift_with_event_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / 'private-room-state.json'
            srv = ps.LumiosePrivateServer(state_path=state_file, wall_clock=lambda: 1794960000.0)
            addr_a = ('127.0.0.1', 40301)
            addr_b = ('190.22.219.1', 40302)
            pid_a, tok_a, join_a = self._join(srv, b'M' * 14, b'Leandro', addr_a)
            self._join(srv, b'N' * 14, b'Amorcito', addr_b)

            # Market probe (0x68) never returns 0xE8 (market stays disabled)
            for op in (0x68, 0x69, 0x6E):
                res_m = srv.handle_packet(ps.pack_header(op, tok_a) + b'\x01\x00', addr_a, now=2.0)
                self.assertEqual(res_m, [])
            self.assertTrue(any(p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_SETTINGS for _, p in join_a))

            # Redeem built-in SHINYZA mystery gift -> FC 19 code=0 (success green) + Lumiose Bag charm
            gift_pkt = ps.pack_header(pf.PKT_EXTENSION, tok_a) + struct.pack('<BBBHBBB', pc.TX_SUBOP_MYSTERY_GIFT, 0, 0, 12, 1, 1, len(b'SHINYZA')) + b'SHINYZA'
            r_gift = srv.handle_packet(gift_pkt, addr_a, now=2.1)
            fc19 = next(p for _, p in r_gift if p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_MYSTERY_GIFT)
            fc16 = next(p for _, p in r_gift if p[3] == pf.PKT_EXTENSION_IN and p[8] == pf.SUBOP_LUMIOSE_BAG)
            ver, req_id, code, mlen = struct.unpack_from('<BHBH', fc19, 9)
            self.assertEqual((ver, req_id, code), (1, 12, 0))
            self.assertIn(b'Lumiose Shiny Charm', fc19[15 : 15 + mlen])
            self.assertEqual(fc16[15], 1)

            # Duplicate claim -> code=1
            r_dup = srv.handle_packet(gift_pkt, addr_a, now=2.2)
            self.assertEqual(r_dup[0][1][12], 1)

            # Admin toggles mystery_gift off via chat command -> not broadcast to chat, notifies both, blocks gift
            r_cmd = srv.handle_packet(self._chat(tok_a, b'/event mystery_gift off'), addr_a, now=2.3)
            self.assertTrue(any(d == addr_b and p[3] == ps.PKT_CHAT_IN and b'DESACTIVADO' in p for d, p in r_cmd))
            r_off = srv.handle_packet(gift_pkt, addr_a, now=2.4)
            self.assertEqual(r_off[0][1][12], 2)

            # Console command creates a custom gift code and re-enables event; persists across restart
            srv.handle_console_command('event mystery_gift on')
            srv.handle_console_command('gift add AMORVIP tickets 4')
            srv2 = ps.LumiosePrivateServer(state_path=state_file, wall_clock=lambda: 1794960000.0)
            self.assertTrue(srv2.extensions.coop.is_event_on('mystery_gift'))
            self.assertIn('AMORVIP', srv2.extensions.coop.gifts)

    def test_party_lifecycle_and_party_chat(self):
        srv = ps.LumiosePrivateServer(wall_clock=lambda: 1794960000.0)
        addr_a = ('127.0.0.1', 40401)
        addr_b = ('190.22.219.1', 40402)
        pid_a, tok_a, _ = self._join(srv, b'P' * 14, b'Leandro', addr_a)
        pid_b, tok_b, _ = self._join(srv, b'Q' * 14, b'Amorcito', addr_b)

        # A invites B (7D 28 00 00 req_id ver=1 act=1 target_pid=B)
        inv_pkt = ps.pack_header(pf.PKT_EXTENSION, tok_a) + struct.pack('<BBBHBBB', pc.TX_SUBOP_PARTY, 0, 0, 5, 1, 1, pid_b)
        r_inv = srv.handle_packet(inv_pkt, addr_a, now=2.0)
        fc30_b = next(p for d, p in r_inv if d == addr_b and p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_PARTY)
        self.assertEqual(fc30_b[9:11], bytes([1, 2]))  # ver=1, msg_type=2 invite received
        invite_id = struct.unpack_from('<I', fc30_b, 11)[0]

        # B accepts (act=2, invite_id, accept=1)
        acc_pkt = ps.pack_header(pf.PKT_EXTENSION, tok_b) + struct.pack('<BBBHBB', pc.TX_SUBOP_PARTY, 0, 0, 6, 1, 2) + struct.pack('<IB', invite_id, 1)
        r_acc = srv.handle_packet(acc_pkt, addr_b, now=2.1)
        roster_a = next(p for d, p in r_acc if d == addr_a and p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_PARTY and p[10] != 3)
        self.assertEqual(roster_a[21], 2)  # 2 members in party

        # Party chat /p goes only to B
        r_pchat = srv.handle_packet(self._chat(tok_a, b'/p Vamos al raid!'), addr_a, now=2.2)
        self.assertEqual(len(r_pchat), 1)
        self.assertEqual(r_pchat[0][0], addr_b)
        self.assertIn(b'Vamos al raid!', r_pchat[0][1])

        # B leaves (act=3) -> party disbanded cleanly
        leave_pkt = ps.pack_header(pf.PKT_EXTENSION, tok_b) + struct.pack('<BBBHBB', pc.TX_SUBOP_PARTY, 0, 0, 7, 1, 3)
        r_leave = srv.handle_packet(leave_pkt, addr_b, now=2.3)
        roster_a2 = next(p for d, p in r_leave if d == addr_a and p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_PARTY)
        self.assertEqual(roster_a2[21], 0)

    def test_raids_tickets_lobby_combat_and_toggle(self):
        srv = ps.LumiosePrivateServer(wall_clock=lambda: 1794960000.0)
        addr_a = ('127.0.0.1', 40501)
        addr_b = ('190.22.219.1', 40502)
        _, tok_a, _ = self._join(srv, b'R' * 14, b'Leandro', addr_a)
        _, tok_b, _ = self._join(srv, b'S' * 14, b'Amorcito', addr_b)

        # Toggle double_loot on via chat command
        srv.handle_packet(self._chat(tok_a, b'/event double_loot on'), addr_a, now=2.0)

        # Buy Raid Ticket (0x7D 0x29) -> increments ticket count
        buy_pkt = ps.pack_header(pf.PKT_EXTENSION, tok_a) + struct.pack('<BBBHBBB', pc.TX_SUBOP_RAID_TICKET, 0, 0, 11, 1, 1, 0)
        r_buy = srv.handle_packet(buy_pkt, addr_a, now=2.1)
        tkt_pkt = next(p for _, p in r_buy if p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_RAID_TICKET and p[12] == 1)
        self.assertEqual(tkt_pkt[14], 2)  # started with 1, now 2

        # Start raid (0x7D 0x1D act=4) -> spawns Boss for both A and B (0xFC 0x2E msg_type=5 & 1)
        start_pkt = ps.pack_header(pf.PKT_EXTENSION, tok_a) + struct.pack('<BBBHB', pc.TX_SUBOP_RAID_LOBBY, 0, 0, 12, 4)
        r_start = srv.handle_packet(start_pkt, addr_a, now=2.2)
        spawn_a = next(p for d, p in r_start if d == addr_a and p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_RAID_BOSS and p[10] == 1)
        spawn_b = next(p for d, p in r_start if d == addr_b and p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_RAID_BOSS and p[10] == 1)
        rid = struct.unpack_from('<I', spawn_a, 11)[0]
        self.assertGreater(rid, 0)
        self.assertEqual(struct.unpack_from('<I', spawn_b, 11)[0], rid)

        # Defeat boss via 0x7D 0x26 hit -> ends raid and awards double_loot bonus charm + tickets
        hit_pkt = ps.pack_header(pf.PKT_EXTENSION, tok_b) + struct.pack('<BBBBBBBIHH', pc.TX_SUBOP_RAID_COMBAT, 0, 0, 0, 0, 2, 1, rid, 1, 9999)
        r_hit = srv.handle_packet(hit_pkt, addr_b, now=2.3)
        end_b = next(p for d, p in r_hit if d == addr_b and p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_RAID_BOSS and p[10] == 3)
        self.assertEqual(end_b[16], 2)  # double reward=2
        self.assertTrue(any(d == addr_b and p[3] == pf.PKT_EXTENSION_IN and p[8] == pf.SUBOP_LUMIOSE_BAG for d, p in r_hit))

        # Turning raids off pushes disabled flag in 0xFC 0x31
        r_off = srv.handle_packet(self._chat(tok_a, b'/event raids off'), addr_a, now=2.4)
        off_b = next(p for d, p in r_off if d == addr_b and p[3] == pf.PKT_EXTENSION_IN and p[8] == pc.RX_SUBOP_RAID_TICKET and p[12] == 2)
        self.assertEqual(off_b[13], 0)

    def test_nursery_eggs_upload_claim_and_instant_hatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / 'private-room-state.json'
            wall = [1794960000.0]
            srv = ps.LumiosePrivateServer(state_path=state_file, wall_clock=lambda: wall[0])
            addr = ('127.0.0.1', 40601)
            _, tok, _ = self._join(srv, b'E' * 14, b'Criador', addr)

            # 0x46 upload (3 x 344B PKM blocks) -> lays egg in nursery
            pkm_parent1 = b'\x11' * pc.PKM_BLOCK_SIZE
            pkm_parent2 = b'\x22' * pc.PKM_BLOCK_SIZE
            pkm_egg = b'\xE9' * pc.PKM_BLOCK_SIZE
            upload_pkt = (
                ps.pack_header(pc.PKT_DAYCARE_UPLOAD, tok)
                + struct.pack('<HIB', 3, 500, 0)
                + struct.pack('<H', pc.PKM_BLOCK_SIZE) + pkm_parent1
                + struct.pack('<H', pc.PKM_BLOCK_SIZE) + pkm_parent2
                + struct.pack('<H', pc.PKM_BLOCK_SIZE) + pkm_egg
            )
            r_up = srv.handle_packet(upload_pkt, addr, now=2.0)
            c4 = next(p for _, p in r_up if p[3] == pc.PKT_DAYCARE_SLOTS)
            c6 = next(p for _, p in r_up if p[3] == pc.PKT_DAYCARE_TXN)
            self.assertEqual(c4[10], 1)  # 1 slot stored
            self.assertEqual(c6[10], 0)  # ok code=0

            # Before 60s hatch, claim (cmd=6) returns not-ready message
            claim_pkt = ps.pack_header(pc.PKT_DAYCARE_ACTION, tok) + struct.pack('<HBII', 4, 6, 0, 0)[:9]
            r_wait = srv.handle_packet(claim_pkt, addr, now=2.1)
            self.assertEqual(r_wait[0][1][10], 1)
            self.assertIn(b'not ready', r_wait[0][1])

            # Turn on instant_hatch event -> claim immediately returns exact 0x158 Egg PKM in 0xC6!
            srv.handle_console_command('event instant_hatch on')
            r_take = srv.handle_packet(claim_pkt, addr, now=2.2)
            c6_egg = r_take[0][1]
            self.assertEqual(c6_egg[10], 0)
            msg_len = c6_egg[29]
            pkm_len = struct.unpack_from('<H', c6_egg, 30 + msg_len)[0]
            self.assertEqual(pkm_len, pc.PKM_BLOCK_SIZE)
            self.assertEqual(c6_egg[32 + msg_len : 32 + msg_len + pkm_len], pkm_egg)

            # Settle commit clears slot cleanly and persists
            txn_id = struct.unpack_from('<I', c6_egg, 12)[0]
            settle_pkt = ps.pack_header(pc.PKT_DAYCARE_ACTION, tok) + struct.pack('<HBIH', 5, 0x4C, txn_id, 0)
            r_settle = srv.handle_packet(settle_pkt, addr, now=2.3)
            c4_after = next(p for _, p in r_settle if p[3] == pc.PKT_DAYCARE_SLOTS)
            self.assertEqual(c4_after[10], 0)


if __name__ == '__main__':
    unittest.main()
