"""Standalone Lumiose Online Private UDP Server for cooperative/duo play."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hmac
from pathlib import Path
import queue
import selectors
import secrets
import signal
import socket
import struct
import sys
import threading
import time
from typing import Callable

_LUMIOSE_DIR = str(Path(__file__).resolve().parent)
if _LUMIOSE_DIR not in sys.path:
    sys.path.insert(0, _LUMIOSE_DIR)

from private_features import RoomExtensions

MAGIC = b'ZA'
PROTO_VERSION = 1

# Client -> Server packet types
PKT_HELLO = 0x01
PKT_PLAYER_STATE = 0x10
PKT_INFO_UPDATE = 0x12
PKT_BODY_REQUEST = 0x13
PKT_LEAVE = 0x1F
PKT_CHAT = 0x30
PKT_CHAT_EXT = 0x31
PKT_BATTLESYNC = 0x50
PKT_DUEL_STATUS = 0x70

# Server -> Client packet types
PKT_WELCOME = 0x81
PKT_SNAPSHOT = 0x90
PKT_INFO = 0x91
PKT_BODY = 0x94
PKT_CHAT_IN = 0xB0
PKT_BATTLESYNC_IN = 0xD0
PKT_DUEL_GRANT = 0xF0

# Enable wild/area, ledger, wildroll, trade, friends bits + Z-A 2.0.2 compat flag
DEFAULT_CAPS = 0xFC
DEFAULT_CAPS_EXTRA = 0x01
MIN_HELLO_SIZE = 130
KNOCK_MAGIC = b'ZAKNOCK!'


@dataclass
class PlayerState:
    seq8: int = 0
    area_id: int = 0
    door_key: int = 0
    flags: int = 0
    core_48: bytes = b'\x00' * 48
    extra_24: bytes = b''
    trailing: bytes = b''
    updated_at: float = 0.0


@dataclass
class PlayerSession:
    pid: int
    token: int
    addr: tuple[str, int]
    trainer_id: bytes
    name: bytes
    hashes: bytes
    body: bytes = b''
    info_rev: int = 1
    state: PlayerState | None = None
    last_seen: float = field(default_factory=time.monotonic)
    duel_granted: bool = False


def pack_header(pkt_type: int, token: int) -> bytes:
    return struct.pack('<2sBBI', MAGIC, PROTO_VERSION, pkt_type & 0xFF, token & 0xFFFFFFFF)


def sanitize_name(raw: bytes) -> bytes:
    cleaned = bytes(b if (0x20 <= b != 0x7F) else 0x20 for b in raw[:24])
    return cleaned or b'Trainer'


def parse_hello(pkt: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Parse C->S 0x01 HELLO. Returns (trainer_id, name, hashes_104) or None for beacons."""
    if len(pkt) < MIN_HELLO_SIZE:
        return None
    trainer_id = pkt[8:22]
    raw_name_len = pkt[25]
    name_end = 26 + raw_name_len
    if name_end + 104 > len(pkt):
        return None
    name = sanitize_name(pkt[26:name_end])
    hashes = pkt[name_end : name_end + 104]
    return trainer_id, name, hashes


def parse_info_update(pkt: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Parse C->S 0x12 INFO_UPDATE -> (name, hashes_104, optional_body)."""
    if len(pkt) < 8 + 1 + 104:
        return None
    raw_name_len = pkt[8]
    hashes_start = 9 + raw_name_len
    if hashes_start + 104 > len(pkt):
        return None
    name = sanitize_name(pkt[9:hashes_start])
    hashes = pkt[hashes_start : hashes_start + 104]

    body = b''
    pos = hashes_start + 104
    if len(pkt) >= pos + 3 and pkt[pos] == 0xB0:
        blen = struct.unpack_from('<H', pkt, pos + 1)[0]
        if 3 <= blen <= 0x123 and len(pkt) >= pos + 3 + blen and pkt[pos + 3] == 1:
            body = pkt[pos + 3 : pos + 3 + blen]
    return name, hashes, body


def parse_player_state(pkt: bytes, now: float) -> PlayerState | None:
    """Parse C->S 0x10 PLAYER_STATE."""
    if len(pkt) < 67:
        return None
    seq = struct.unpack_from('<H', pkt, 8)[0]
    area_id, door_key = struct.unpack_from('<HH', pkt, 14)
    flags = pkt[18]
    core_48 = pkt[19:67]
    offset = 67

    extra_24 = b''
    if flags & 0x04:
        if len(pkt) < offset + 24:
            return None
        extra_24 = pkt[offset : offset + 24]
        offset += 24

    trailing = b''
    if len(pkt) > offset:
        tlen = min(pkt[offset], 0x40)
        if len(pkt) >= offset + 1 + tlen:
            trailing = pkt[offset + 1 : offset + 1 + tlen]

    return PlayerState(
        seq8=seq & 0xFF,
        area_id=area_id,
        door_key=door_key,
        flags=flags,
        core_48=core_48,
        extra_24=extra_24,
        trailing=trailing,
        updated_at=now,
    )


def build_welcome(token: int, pid: int, caps: int = DEFAULT_CAPS) -> bytes:
    return struct.pack(
        '<2sBBIQHBBBBQ',
        MAGIC,
        PROTO_VERSION,
        PKT_WELCOME,
        token,
        0,
        pid,
        caps & 0xFF,
        0,
        0,
        DEFAULT_CAPS_EXTRA,
        0,
    )


def build_duel_grant(token: int, area_m: int = 100, return_s: int = 15) -> bytes:
    return pack_header(PKT_DUEL_GRANT, token) + struct.pack('<BBHHH', 1, 1, 0, area_m, return_s)


def build_info_packet(recipient_token: int, players: list[PlayerSession]) -> bytes:
    out = bytearray(pack_header(PKT_INFO, recipient_token))
    out.append(len(players) & 0xFF)
    for p in players:
        out.extend(struct.pack('<HBB', p.pid, p.info_rev & 0x0F, len(p.name) & 0xFF))
        out.extend(p.name)
        out.extend(p.hashes)
    return bytes(out)


def build_body_packet(recipient_token: int, players: list[PlayerSession]) -> bytes | None:
    with_body = [p for p in players if p.body]
    if not with_body:
        return None
    out = bytearray(pack_header(PKT_BODY, recipient_token))
    out.append(len(with_body) & 0xFF)
    for p in with_body:
        out.extend(struct.pack('<HBH', p.pid, p.info_rev & 0x0F, len(p.body)))
        out.extend(p.body)
    return bytes(out)


def build_snapshot_packet(
    recipient_token: int, server_seq: int, clock_ms: int, peers: list[PlayerSession]
) -> bytes:
    active = [p for p in peers if p.state is not None]
    out = bytearray(pack_header(PKT_SNAPSHOT, recipient_token))
    # hdr_flags bit 1 (0x02): entries include trailing u8 len + bytes
    out.extend(struct.pack('<HBBIIH', server_seq & 0xFFFF, 0x02, len(active) & 0xFF, 0, clock_ms & 0xFFFFFFFF, 0))
    for p in active:
        st = p.state
        assert st is not None
        out.extend(struct.pack('<HBBH', p.pid, st.seq8, st.flags, st.area_id))
        out.extend(st.core_48)
        if st.flags & 0x04:
            out.extend(st.extra_24)
        out.append(len(st.trailing) & 0xFF)
        out.extend(st.trailing)
    return bytes(out)


def build_chat_in(recipient_token: int, sender: PlayerSession, msg: bytes) -> bytes:
    return (
        pack_header(PKT_CHAT_IN, recipient_token)
        + struct.pack('<HB', sender.pid, len(sender.name) & 0xFF)
        + sender.name
        + struct.pack('<B', len(msg) & 0xFF)
        + msg
    )


class LumiosePrivateServer:
    """In-memory protocol handler for private Lumiose Online UDP sessions."""

    def __init__(
        self,
        *,
        max_players: int = 8,
        timeout_seconds: float = 15.0,
        room_secret: str | None = None,
        state_path: Path | str | None = None,
        wall_clock: Callable[[], float] | None = None,
        verbose: bool = False,
        log_fn: Callable[[str], None] | None = None,
    ) -> None:
        self.max_players = max(2, max_players)
        self.timeout_seconds = max(3.0, timeout_seconds)
        self.room_secret = room_secret.strip().upper() if room_secret else None
        self.verbose = verbose
        self._log = log_fn or (lambda msg: print(f'[lumiose server] {msg}', flush=True))
        self.start_time = time.monotonic()
        self.server_seq = 1
        self.players: dict[int, PlayerSession] = {}
        self.addr_index: dict[tuple[str, int], int] = {}
        self.authorized_addrs: dict[tuple[str, int], float] = {}
        self._rejected_log: set[tuple[str, int]] = set()
        self._snapshot_dirty = False
        self.extensions = RoomExtensions(state_path=state_path, wall_clock=wall_clock)

    def _next_pid(self) -> int | None:
        for candidate in range(1, self.max_players + 1):
            if candidate not in self.players:
                return candidate
        return None

    def _clock_ms(self, now: float) -> int:
        return int((now - self.start_time) * 1000.0) & 0xFFFFFFFF

    def _find_by_token(self, addr: tuple[str, int], token: int) -> PlayerSession | None:
        pid = self.addr_index.get(addr)
        if pid is not None:
            player = self.players.get(pid)
            if player is not None and (token == 0 or player.token == token):
                return player
        for player in self.players.values():
            if token != 0 and player.token == token:
                # Peer IP/port changed (e.g. NAT rebind): refresh address mapping safely.
                old_addr = player.addr
                if old_addr != addr:
                    self.addr_index.pop(old_addr, None)
                    player.addr = addr
                    self.addr_index[addr] = player.pid
                return player
        return None

    def handle_packet(self, data: bytes, addr: tuple[str, int], now: float | None = None) -> list[tuple[tuple[str, int], bytes]]:
        if now is None:
            now = time.monotonic()
        if data.startswith(KNOCK_MAGIC):
            if self.room_secret:
                supplied = data[len(KNOCK_MAGIC) :].rstrip(b'\x00').decode('ascii', 'replace').upper()
                if hmac.compare_digest(supplied, self.room_secret):
                    self.authorized_addrs[addr] = now
                    self._rejected_log.discard(addr)
                elif self.verbose:
                    self._log(f'invalid room secret from {addr[0]}:{addr[1]}')
            return []
        if len(data) < 8 or data[:2] != MAGIC or data[2] != PROTO_VERSION:
            return []

        pkt_type = data[3]
        token = struct.unpack_from('<I', data, 4)[0]

        if pkt_type == PKT_HELLO:
            return self._handle_hello(data, addr, now)

        player = self._find_by_token(addr, token)
        if player is None:
            return []
        player.last_seen = now

        if pkt_type == PKT_PLAYER_STATE:
            st = parse_player_state(data, now)
            if st is not None:
                player.state = st
                self._snapshot_dirty = True
            return []

        if pkt_type == PKT_INFO_UPDATE:
            parsed = parse_info_update(data)
            if parsed is None:
                return []
            name, hashes, body = parsed
            player.name = name
            player.hashes = hashes
            if body:
                player.body = body
            player.info_rev = (player.info_rev + 1) & 0x0F
            return self._broadcast_info(player)

        if pkt_type == PKT_BODY_REQUEST:
            if len(data) < 9:
                return []
            cnt = data[8]
            targets: list[PlayerSession] = []
            for i in range(cnt):
                if 9 + i * 2 + 2 > len(data):
                    break
                req_pid = struct.unpack_from('<H', data, 9 + i * 2)[0]
                target = self.players.get(req_pid)
                if target is not None and target.body:
                    targets.append(target)
            pkt = build_body_packet(player.token, targets)
            return [(player.addr, pkt)] if pkt else []

        if pkt_type in (PKT_CHAT, PKT_CHAT_EXT):
            msg = self._parse_chat(pkt_type, data)
            if not msg:
                return []
            decoded = msg.decode('utf-8', 'replace')
            self._log(f'chat [{player.name.decode("utf-8", "replace")}]: {decoded}')
            cmd_replies = self.extensions.handle_chat(msg, player, self.players)
            if cmd_replies is not None:
                return cmd_replies
            return [
                (other.addr, build_chat_in(other.token, player, msg))
                for other in self.players.values()
                if other.pid != player.pid
            ]

        if pkt_type == PKT_BATTLESYNC and len(data) == 27:
            payload = data[8:27]
            return [
                (
                    other.addr,
                    pack_header(PKT_BATTLESYNC_IN, other.token)
                    + struct.pack('<H', player.pid)
                    + payload,
                )
                for other in self.players.values()
                if other.pid != player.pid
            ]

        if pkt_type == PKT_DUEL_STATUS:
            if not player.duel_granted:
                player.duel_granted = True
                return [(player.addr, build_duel_grant(player.token))]
            return []

        if pkt_type == PKT_LEAVE:
            leave_replies = self._remove_player(player.pid, reason='left')
            return leave_replies + self.flush_snapshots(now, force=True)

        ext_replies = self.extensions.handle_packet(pkt_type, data, player, self.players)
        if ext_replies is not None:
            return ext_replies

        if self.verbose:
            self._log(f'ignored packet 0x{pkt_type:02x} ({len(data)}B) from pid={player.pid}')
        return []

    def _parse_chat(self, pkt_type: int, data: bytes) -> bytes:
        if pkt_type == PKT_CHAT and len(data) >= 10:
            mlen = min(data[9], 120)
            msg = data[10 : 10 + mlen]
            return msg if msg else b''
        if pkt_type == PKT_CHAT_EXT and len(data) >= 12:
            mlen = min(data[11], 120)
            msg = data[12 : 12 + mlen]
            return msg if msg else b''
        return b''

    def _handle_hello(
        self, data: bytes, addr: tuple[str, int], now: float
    ) -> list[tuple[tuple[str, int], bytes]]:
        parsed = parse_hello(data)
        if parsed is None:
            # Gate beacon probes send tiny 0x01 packets without reading replies; ignore safely.
            return []
        if self.room_secret and addr not in self.authorized_addrs:
            if addr not in self._rejected_log:
                self._rejected_log.add(addr)
                self._log(f'blocked unauthorized join attempt from {addr[0]}:{addr[1]} (missing/invalid room code)')
            return []
        trainer_id, name, hashes = parsed

        existing = None
        for p in self.players.values():
            if p.addr == addr or p.trainer_id == trainer_id:
                existing = p
                break

        if existing is not None:
            self.addr_index.pop(existing.addr, None)
            existing.addr = addr
            existing.name = name
            existing.hashes = hashes
            existing.last_seen = now
            self.addr_index[addr] = existing.pid
            player = existing
        else:
            pid = self._next_pid()
            if pid is None:
                self._log(f'server full ({self.max_players} players); rejected {addr}')
                return []
            token = secrets.randbelow(0x7FFFFFFE) + 1
            player = PlayerSession(
                pid=pid,
                token=token,
                addr=addr,
                trainer_id=trainer_id,
                name=name,
                hashes=hashes,
                last_seen=now,
            )
            self.players[pid] = player
            self.addr_index[addr] = pid
            self._log(
                f'player joined: {name.decode("utf-8", "replace")} '
                f'(pid={pid}, from={addr[0]}:{addr[1]})'
            )

        out: list[tuple[tuple[str, int], bytes]] = [
            (player.addr, build_welcome(player.token, player.pid)),
            (player.addr, build_duel_grant(player.token)),
        ]
        player.duel_granted = True
        out.extend(self.extensions.on_player_join(player, self.players))

        others = [p for p in self.players.values() if p.pid != player.pid]
        if others:
            out.append((player.addr, build_info_packet(player.token, others)))
            body_pkt = build_body_packet(player.token, others)
            if body_pkt:
                out.append((player.addr, body_pkt))
            out.extend(self._broadcast_info(player))
            out.append(
                (
                    player.addr,
                    build_snapshot_packet(
                        player.token, self.server_seq, self._clock_ms(now), others
                    ),
                )
            )
            self.server_seq = (self.server_seq + 1) & 0xFFFF
        return out

    def _broadcast_info(self, source: PlayerSession) -> list[tuple[tuple[str, int], bytes]]:
        out: list[tuple[tuple[str, int], bytes]] = []
        for other in self.players.values():
            if other.pid == source.pid:
                continue
            out.append((other.addr, build_info_packet(other.token, [source])))
            if source.body:
                bpkt = build_body_packet(other.token, [source])
                if bpkt:
                    out.append((other.addr, bpkt))
        return out

    def _remove_player(self, pid: int, reason: str) -> list[tuple[tuple[str, int], bytes]]:
        removed = self.players.pop(pid, None)
        if removed is not None:
            self.addr_index.pop(removed.addr, None)
            self._snapshot_dirty = True
            self._log(
                f'player {reason}: {removed.name.decode("utf-8", "replace")} (pid={pid})'
            )
            return self.extensions.on_player_leave(removed, self.players)
        return []

    def prune_stale(self, now: float | None = None) -> list[tuple[tuple[str, int], bytes]]:
        if now is None:
            now = time.monotonic()
        stale = [
            pid
            for pid, p in self.players.items()
            if (now - p.last_seen) >= self.timeout_seconds
        ]
        out: list[tuple[tuple[str, int], bytes]] = []
        for pid in stale:
            out.extend(self._remove_player(pid, reason='timed out'))
        expired_auth = [
            addr
            for addr, ts in self.authorized_addrs.items()
            if addr not in self.addr_index and (now - ts) >= 120.0
        ]
        for addr in expired_auth:
            self.authorized_addrs.pop(addr, None)
        if stale:
            out.extend(self.flush_snapshots(now, force=True))
        return out

    def flush_snapshots(
        self, now: float | None = None, *, force: bool = False
    ) -> list[tuple[tuple[str, int], bytes]]:
        if now is None:
            now = time.monotonic()
        if not self._snapshot_dirty and not force:
            return []
        self._snapshot_dirty = False
        if not self.players:
            return []

        clock_ms = self._clock_ms(now)
        seq = self.server_seq
        self.server_seq = (self.server_seq + 1) & 0xFFFF
        out: list[tuple[tuple[str, int], bytes]] = []
        all_players = list(self.players.values())
        for recipient in all_players:
            peers = [p for p in all_players if p.pid != recipient.pid]
            if not peers and not force:
                continue
            out.append(
                (
                    recipient.addr,
                    build_snapshot_packet(recipient.token, seq, clock_ms, peers),
                )
            )
        return out

    def handle_console_command(self, line: str) -> list[tuple[tuple[str, int], bytes]]:
        replies, summary = self.extensions.handle_console_command(line, self.players)
        if summary:
            self._log(summary)
        return replies


def _send_replies(sock: socket.socket, replies: list[tuple[tuple[str, int], bytes]]) -> None:
    for dst, payload in replies:
        try:
            sock.sendto(payload, dst)
        except OSError:
            pass


def _start_console_reader() -> queue.SimpleQueue[str] | None:
    try:
        if sys.stdin is None or not sys.stdin.isatty():
            return None
    except Exception:
        return None
    cmd_q: queue.SimpleQueue[str] = queue.SimpleQueue()

    def _reader() -> None:
        while True:
            try:
                line = sys.stdin.readline()
            except Exception:
                break
            if not line:
                break
            stripped = line.strip()
            if stripped:
                cmd_q.put(stripped)

    threading.Thread(target=_reader, daemon=True, name='lumiose-console').start()
    return cmd_q


def run_server(
    host: str = '0.0.0.0',
    port: int = 27777,
    *,
    max_players: int = 8,
    tick_hz: float = 30.0,
    timeout_seconds: float = 15.0,
    room_secret: str | None = None,
    state_path: Path | str | None = None,
    verbose: bool = False,
) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.setblocking(False)

    bound_host, bound_port = sock.getsockname()
    server = LumiosePrivateServer(
        max_players=max_players,
        timeout_seconds=timeout_seconds,
        room_secret=room_secret,
        state_path=state_path,
        verbose=verbose,
    )
    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ)

    tick_interval = 1.0 / max(10.0, tick_hz)
    next_tick = time.monotonic() + tick_interval
    next_prune = time.monotonic() + 1.0
    running = True

    def stop_handler(_signum, _frame):
        nonlocal running
        running = False

    for sig in (signal.SIGINT, getattr(signal, 'SIGTERM', signal.SIGINT)):
        try:
            signal.signal(sig, stop_handler)
        except (OSError, ValueError):
            pass

    auth_mode = 'room-code locked' if server.room_secret else 'open'
    cmd_queue = _start_console_reader()
    print(
        f'[lumiose server] Listening on UDP {bound_host}:{bound_port} '
        f'(max_players={max_players}, access={auth_mode})',
        flush=True,
    )
    if cmd_queue is not None:
        print('[lumiose server] Console commands ready (type: events, event <name> <on|off>, gift list, help)', flush=True)

    try:
        while running:
            now = time.monotonic()
            wait = max(0.0, min(next_tick - now, next_prune - now, 0.05))
            events = sel.select(timeout=wait)
            for _key, _mask in events:
                while True:
                    try:
                        data, addr = sock.recvfrom(4096)
                    except BlockingIOError:
                        break
                    except OSError:
                        break
                    _send_replies(sock, server.handle_packet(data, addr, time.monotonic()))

            if cmd_queue is not None:
                while True:
                    try:
                        line = cmd_queue.get_nowait()
                    except queue.Empty:
                        break
                    _send_replies(sock, server.handle_console_command(line))

            now = time.monotonic()
            if now >= next_tick:
                _send_replies(sock, server.flush_snapshots(now))
                next_tick = now + tick_interval
            if now >= next_prune:
                _send_replies(sock, server.prune_stale(now))
                next_prune = now + 1.0
    finally:
        sel.close()
        sock.close()
    print('[lumiose server] Stopped.', flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Lumiose Online Private UDP Server')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=27777, help='UDP port (default: 27777)')
    parser.add_argument('--max-players', type=int, default=8, help='Maximum concurrent players')
    parser.add_argument('--tick-hz', type=float, default=30.0, help='Snapshot tick rate (Hz)')
    parser.add_argument('--timeout', type=float, default=15.0, help='Idle client timeout in seconds')
    parser.add_argument('--room-secret', default='', help='Require ZAKNOCK! room secret before HELLO')
    parser.add_argument('--from-config', action='store_true', help='Load port and room secret from lumiose/private-server.json')
    parser.add_argument('--state-file', default='', help='Path to persistent JSON room state (friends, daily streak, bag)')
    parser.add_argument('--verbose', action='store_true', help='Log unknown/unhandled opcodes')
    args = parser.parse_args(argv)

    port = args.port
    room_secret = args.room_secret.strip() or None
    state_path: Path | None = Path(args.state_file.strip()) if args.state_file.strip() else None
    if args.from_config:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import profiles as profile_store

        root = Path(__file__).resolve().parents[2]
        settings = profile_store.ensure_host_invite(root)
        port = settings['host_port']
        room_secret = settings['room_secret']
        if state_path is None:
            state_path = root / 'lumiose' / 'private-room-state.json'
        code = profile_store.write_room_code_file(root, settings)
        if code:
            print(f'[lumiose server] Invite Code (share with partner): {code}', flush=True)

    return run_server(
        host=args.host,
        port=port,
        max_players=args.max_players,
        tick_hz=args.tick_hz,
        timeout_seconds=args.timeout,
        room_secret=room_secret,
        state_path=state_path,
        verbose=args.verbose,
    )


if __name__ == '__main__':
    raise SystemExit(main())
