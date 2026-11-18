"""Server-side shared world clock, wild spawn RNG/relays, and catch synchronization."""

from __future__ import annotations

from collections import OrderedDict
import secrets
import struct
import time
from typing import Callable


PKT_EXTENSION = 0x7D
PKT_EXTENSION_OUT = 0xFC

PKT_WILD_CLAIM = 0x24
PKT_WILD_SEED_PUSH = 0x25
PKT_WILD_STATE = 0x26
PKT_WILD_GONE = 0x27
PKT_WILD_ROLL_REQ = 0x28
PKT_WILD_EXTRA = 0x29

PKT_WILD_CLAIM_OUT = 0xA4
PKT_WILD_SEED_PUSH_OUT = 0xA5
PKT_WILD_STATE_OUT = 0xA6
PKT_WILD_GONE_OUT = 0xA7
PKT_WILD_EXTRA_OUT = 0xA9

PKT_WORLD_CLOCK = 0xB1

SUBOP_CATCHSYNC_OUT = 0x0B
SUBOP_CATCHSYNC_IN = 0x0E
SUBOP_WILDROLL_DECISIONS = 0x11
SUBOP_CAPSYNC_IN = 0x2B
SUBOP_CAPSYNC_OUT = 0x36

WORLD_MASTER_PID = 0xFFFF
DEFAULT_DAY_REAL_S = 900
DEFAULT_NIGHT_REAL_S = 450
DEFAULT_DAY_START_MIN = 360   # 06:00
DEFAULT_NIGHT_START_MIN = 1080  # 18:00
DEFAULT_START_CLOCK_MIN = 480  # 08:00
CLOCK_BROADCAST_INTERVAL_S = 10.0
MAX_WILD_DECISIONS = 4096


MAGIC = b'ZA'
PROTO_VERSION = 1


def _pack_hdr(pkt_type: int, token: int) -> bytes:
    return struct.pack('<2sBBI', MAGIC, PROTO_VERSION, pkt_type & 0xFF, token & 0xFFFFFFFF)


def _pack_fc(token: int, subop: int, payload: bytes = b'') -> bytes:
    return _pack_hdr(PKT_EXTENSION_OUT, token) + bytes([subop & 0xFF]) + payload


class WorldAndSpawnHub:
    """Coordinates [world] day/night clock, [wildroll] shared spawns, and [catchsync]/[capsync]."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], float] | None = None,
        save_state: Callable[[], None] | None = None,
        notice_builder: Callable[[int, str], bytes] | None = None,
        is_admin_fn: Callable[[object], bool] | None = None,
    ) -> None:
        self.wall_clock = wall_clock or time.time
        self.save_state = save_state or (lambda: None)
        self.notice_builder = notice_builder
        self.is_admin_fn = is_admin_fn

        self.day_real_s: int = DEFAULT_DAY_REAL_S
        self.night_real_s: int = DEFAULT_NIGHT_REAL_S
        self.day_start_min: int = DEFAULT_DAY_START_MIN
        self.night_start_min: int = DEFAULT_NIGHT_START_MIN

        self.paused_game_sec: int | None = None
        self.phase_offset: float = 0.0
        self._init_default_offset()

        self._last_clock_broadcast: float = 0.0
        # (point_hash, epoch) -> (seed_u16, owner_pid, created_ts)
        self.roll_decisions: OrderedDict[tuple[int, int], tuple[int, int, float]] = OrderedDict()

    def _cycle_len_s(self) -> int:
        return max(60, int(self.day_real_s) + int(self.night_real_s))

    def _game_sec_to_phase_s(self, game_sec: int) -> float:
        gsec = int(game_sec) % 86400
        day_start_s = self.day_start_min * 60
        night_start_s = self.night_start_min * 60
        day_game_span = (night_start_s - day_start_s) % 86400 or 43200
        night_game_span = 86400 - day_game_span

        since_day = (gsec - day_start_s) % 86400
        if since_day < day_game_span:
            return (since_day / day_game_span) * float(self.day_real_s)
        since_night = since_day - day_game_span
        return float(self.day_real_s) + (since_night / max(1, night_game_span)) * float(self.night_real_s)

    def _phase_s_to_game_sec(self, phase_s: float) -> int:
        day_start_s = self.day_start_min * 60
        night_start_s = self.night_start_min * 60
        day_game_span = (night_start_s - day_start_s) % 86400 or 43200
        night_game_span = 86400 - day_game_span

        cycle_s = float(self._cycle_len_s())
        p = float(phase_s) % cycle_s
        if p < float(self.day_real_s):
            frac = p / max(1.0, float(self.day_real_s))
            return (day_start_s + int(round(frac * day_game_span))) % 86400
        frac = (p - float(self.day_real_s)) / max(1.0, float(self.night_real_s))
        return (night_start_s + int(round(frac * night_game_span))) % 86400

    def _init_default_offset(self) -> None:
        now = float(self.wall_clock())
        target_phase = self._game_sec_to_phase_s(DEFAULT_START_CLOCK_MIN * 60)
        cycle = float(self._cycle_len_s())
        self.phase_offset = (target_phase - (now % cycle)) % cycle

    def current_clock(self, now: float | None = None) -> tuple[int, int, int]:
        """Return (clock_min, clock_sec, zone) where zone 0=day, 1=night."""
        if self.paused_game_sec is not None:
            gsec = int(self.paused_game_sec) % 86400
        else:
            t = float(self.wall_clock() if now is None else now)
            cycle = float(self._cycle_len_s())
            phase_s = (t + self.phase_offset) % cycle
            gsec = self._phase_s_to_game_sec(phase_s)

        clock_min = (gsec // 60) % 1440
        clock_sec = gsec % 60
        zone = 0 if self.day_start_min <= clock_min < self.night_start_min else 1
        return clock_min, clock_sec, zone

    def export_state(self) -> dict:
        return {
            'phase_offset': round(float(self.phase_offset), 3),
            'paused_game_sec': self.paused_game_sec,
        }

    def load_state(self, raw: object) -> None:
        if not isinstance(raw, dict):
            return
        if 'phase_offset' in raw:
            try:
                self.phase_offset = float(raw['phase_offset']) % float(self._cycle_len_s())
            except (TypeError, ValueError):
                pass
        paused = raw.get('paused_game_sec')
        if paused is None:
            self.paused_game_sec = None
        else:
            try:
                self.paused_game_sec = int(paused) % 86400
            except (TypeError, ValueError):
                self.paused_game_sec = None

    def build_world_clock_packet(self, token: int, now: float | None = None) -> bytes:
        clock_min, clock_sec, zone = self.current_clock(now)
        return _pack_hdr(PKT_WORLD_CLOCK, token) + struct.pack(
            '<HHBBHBBHHHH',
            WORLD_MASTER_PID,
            clock_min & 0xFFFF,
            zone & 0xFF,
            0x03,  # bit0=valid, bit1=cycle ON
            0,     # age_ms
            1,     # cycle_ver
            clock_sec & 0xFF,
            self.day_real_s & 0xFFFF,
            self.night_real_s & 0xFFFF,
            (self.day_start_min & 0xFFFF) << 5,
            (self.night_start_min & 0xFFFF) << 5,
        )

    def build_wild_decisions_packet(
        self,
        token: int,
        entries: list[tuple[int, int, int, int]],
    ) -> bytes:
        """Build 0xFC 0x11 ver=1 packet from [(point_hash, epoch, seed_u16, owner_pid), ...]."""
        cnt = len(entries) & 0xFF
        body = bytearray(struct.pack('<BB', 1, cnt))
        for point_hash, epoch, seed_u16, owner_pid in entries[:255]:
            body.extend(struct.pack('<IIHB', point_hash & 0xFFFFFFFF, epoch & 0xFFFFFFFF, seed_u16 & 0xFFFF, owner_pid & 0xFF))
        return _pack_fc(token, SUBOP_WILDROLL_DECISIONS, bytes(body))

    def broadcast_clock(self, players_by_pid: dict[int, object], now: float | None = None) -> list[tuple[tuple[str, int], bytes]]:
        t = float(self.wall_clock() if now is None else now)
        self._last_clock_broadcast = t
        return [(p.addr, self.build_world_clock_packet(p.token, t)) for p in players_by_pid.values()]

    def on_player_join(self, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        if self._last_clock_broadcast == 0.0:
            self._last_clock_broadcast = float(self.wall_clock())
        out: list[tuple[tuple[str, int], bytes]] = [(player.addr, self.build_world_clock_packet(player.token))]
        if self.roll_decisions:
            recent = list(self.roll_decisions.items())[-64:]
            entries = [(ph, ep, seed, opid) for (ph, ep), (seed, opid, _) in recent]
            out.append((player.addr, self.build_wild_decisions_packet(player.token, entries)))
        return out

    def tick(self, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        if not players_by_pid:
            return []
        now = float(self.wall_clock())
        if now - self._last_clock_broadcast >= CLOCK_BROADCAST_INTERVAL_S:
            return self.broadcast_clock(players_by_pid, now)
        return []

    def _get_or_assign_decision(self, point_hash: int, epoch: int, requester_pid: int) -> tuple[int, int, bool]:
        key = (point_hash & 0xFFFFFFFF, epoch & 0xFFFFFFFF)
        now = float(self.wall_clock())
        existing = self.roll_decisions.get(key)
        if existing is not None:
            seed_u16, owner_pid, _ = existing
            self.roll_decisions.move_to_end(key)
            return seed_u16, owner_pid, False

        seed_u16 = secrets.randbelow(0xFFFF) + 1  # non-zero uint16
        owner_pid = (requester_pid & 0xFF) or 1
        self.roll_decisions[key] = (seed_u16, owner_pid, now)
        while len(self.roll_decisions) > MAX_WILD_DECISIONS:
            self.roll_decisions.popitem(last=False)
        return seed_u16, owner_pid, True

    def _relay_with_pid(
        self,
        out_pkt_type: int,
        pkt: bytes,
        stride_in: int,
        trim_to: int | None,
        player,
        players_by_pid: dict[int, object],
        *,
        append_pid: bool = True,
    ) -> list[tuple[tuple[str, int], bytes]]:
        if len(pkt) < 9:
            return []
        cnt = pkt[8]
        if cnt == 0 or len(pkt) < 9 + cnt * stride_in:
            return []
        pid_bytes = struct.pack('<H', player.pid & 0xFFFF)
        body = bytearray([cnt])
        pos = 9
        take = trim_to if trim_to is not None else stride_in
        for _ in range(cnt):
            chunk = pkt[pos:pos + take]
            if len(chunk) < take:
                chunk = chunk + b'\x00' * (take - len(chunk))
            body.extend(chunk)
            if append_pid:
                body.extend(pid_bytes)
            pos += stride_in
        raw_body = bytes(body)
        return [
            (other.addr, _pack_hdr(out_pkt_type, other.token) + raw_body)
            for other in players_by_pid.values()
            if other.pid != player.pid
        ]

    def handle_packet(
        self,
        pkt_type: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        if pkt_type == PKT_WILD_ROLL_REQ:
            if len(pkt) < 17:
                return []
            point_hash, epoch = struct.unpack_from('<II', pkt, 9)
            seed_u16, owner_pid, created = self._get_or_assign_decision(point_hash, epoch, player.pid)
            entries = [(point_hash, epoch, seed_u16, owner_pid)]
            if created:
                return [(p.addr, self.build_wild_decisions_packet(p.token, entries)) for p in players_by_pid.values()]
            return [(player.addr, self.build_wild_decisions_packet(player.token, entries))]

        if pkt_type == PKT_WILD_CLAIM:
            return self._relay_with_pid(PKT_WILD_CLAIM_OUT, pkt, 20, 10, player, players_by_pid, append_pid=True)

        if pkt_type == PKT_WILD_SEED_PUSH:
            return self._relay_with_pid(PKT_WILD_SEED_PUSH_OUT, pkt, 10, 10, player, players_by_pid, append_pid=False)

        if pkt_type == PKT_WILD_STATE:
            return self._relay_with_pid(PKT_WILD_STATE_OUT, pkt, 36, 36, player, players_by_pid, append_pid=True)

        if pkt_type == PKT_WILD_GONE:
            if len(pkt) < 9 or pkt[8] == 0:
                return []
            cnt = pkt[8]
            stride_in = 10 if len(pkt) >= 9 + cnt * 10 else 8
            if len(pkt) < 9 + cnt * stride_in:
                return []
            return self._relay_with_pid(PKT_WILD_GONE_OUT, pkt, stride_in, 10, player, players_by_pid, append_pid=True)

        if pkt_type == PKT_WILD_EXTRA:
            return self._relay_with_pid(PKT_WILD_EXTRA_OUT, pkt, 19, 19, player, players_by_pid, append_pid=True)

        return None

    def handle_extension(
        self,
        subop: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        if subop == SUBOP_CATCHSYNC_IN:
            # [8]=0x0E, [9..12]=0, [13..20]=copy_key_epoch(8B), [21]=state(1|2), [22..23]=ms_u16
            if len(pkt) < 24:
                return []
            payload = struct.pack('<H', player.pid & 0xFFFF) + pkt[13:24]
            return [
                (other.addr, _pack_fc(other.token, SUBOP_CATCHSYNC_OUT, payload))
                for other in players_by_pid.values()
                if other.pid != player.pid
            ]

        if subop == SUBOP_CAPSYNC_IN:
            # [8]=0x2B, [9..12]=0, [13..15]=meta, [16]=cnt(<=6), [17..20]=u32_time, [21..]=cnt*23B
            if len(pkt) < 21:
                return []
            cnt = pkt[16]
            expected = 21 + cnt * 23
            if cnt > 6 or len(pkt) < expected:
                return []
            payload = struct.pack('<H', player.pid & 0xFFFF) + pkt[13:expected]
            return [
                (other.addr, _pack_fc(other.token, SUBOP_CAPSYNC_OUT, payload))
                for other in players_by_pid.values()
                if other.pid != player.pid
            ]

        return None

    def _set_game_clock_seconds(self, game_sec: int, *, pause: bool | None = None) -> None:
        gsec = int(game_sec) % 86400
        if pause is True:
            self.paused_game_sec = gsec
        else:
            if pause is False:
                self.paused_game_sec = None
            now = float(self.wall_clock())
            cycle = float(self._cycle_len_s())
            target_phase = self._game_sec_to_phase_s(gsec)
            self.phase_offset = (target_phase - (now % cycle)) % cycle

    def format_status(self) -> str:
        cmin, _, zone = self.current_clock()
        hh, mm = divmod(cmin, 60)
        label = 'Dia' if zone == 0 else 'Noche'
        mode = 'PAUSADO' if self.paused_game_sec is not None else 'AUTO'
        return f'Reloj mundial: {hh:02d}:{mm:02d} ({label}, {mode})'

    def _notice(self, player, msg: str) -> list[tuple[tuple[str, int], bytes]]:
        if self.notice_builder is not None:
            return [(player.addr, self.notice_builder(player.token, msg))]
        return []

    def handle_command(
        self,
        cmd: str,
        args: str,
        player,
        players_by_pid: dict[int, object],
        *,
        from_console: bool = False,
    ) -> tuple[list[tuple[tuple[str, int], bytes]], str] | None:
        if cmd not in ('time', 'reloj'):
            return None
        spec = args.strip().lower()
        if not spec:
            msg = f'{self.format_status()} | Usa /time day|night|dawn|dusk|HH:MM|pause|auto'
            return (self._notice(player, msg) if player is not None else [], msg)

        if not from_console and self.is_admin_fn is not None and not self.is_admin_fn(player):
            msg = 'Solo el anfitrion puede cambiar la hora del servidor.'
            return (self._notice(player, msg) if player is not None else [], msg)

        presets = {
            'day': 8 * 3600,
            'dia': 8 * 3600,
            'noon': 12 * 3600,
            'mediodia': 12 * 3600,
            'dawn': 6 * 3600,
            'amanecer': 6 * 3600,
            'dusk': 18 * 3600,
            'atardecer': 18 * 3600,
            'night': 20 * 3600,
            'noche': 20 * 3600,
            'midnight': 0,
            'medianoche': 0,
        }
        if spec == 'pause':
            cmin, csec, _ = self.current_clock()
            self.paused_game_sec = cmin * 60 + csec
        elif spec == 'auto':
            if self.paused_game_sec is not None:
                self._set_game_clock_seconds(self.paused_game_sec, pause=False)
        elif spec in presets:
            self._set_game_clock_seconds(presets[spec], pause=False if self.paused_game_sec is None else None)
        elif ':' in spec:
            parts = spec.split(':', 1)
            try:
                hh = int(parts[0])
                mm = int(parts[1])
            except ValueError:
                msg = 'Formato invalido. Usa /time HH:MM o /time day|night|dawn|dusk|pause|auto'
                return (self._notice(player, msg) if player is not None else [], msg)
            if not (0 <= hh <= 23 and 0 <= mm <= 59):
                msg = 'Hora fuera de rango (00:00 a 23:59).'
                return (self._notice(player, msg) if player is not None else [], msg)
            self._set_game_clock_seconds(hh * 3600 + mm * 60, pause=None)
        else:
            msg = 'Uso: /time [day|night|dawn|dusk|HH:MM|pause|auto]'
            return (self._notice(player, msg) if player is not None else [], msg)

        self.save_state()
        out = self.broadcast_clock(players_by_pid)
        msg = self.format_status()
        if player is not None:
            out.extend(self._notice(player, msg))
        return out, msg
