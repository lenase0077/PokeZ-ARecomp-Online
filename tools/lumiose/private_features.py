"""Extension state and wire codecs for Friends, Daily Login / Bag, and Ledger."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import struct
import time

from private_coop import CoopHub, build_server_notice

MAGIC = b'ZA'
PROTO_VERSION = 1

# Client -> Server extension packet types
PKT_LEDGER_REPORT = 0x40
PKT_LEDGER_EVENTS = 0x41
PKT_FRIEND_REQUEST = 0x78
PKT_FRIEND_ANSWER = 0x79
PKT_FRIEND_LIST_REQ = 0x7A
PKT_FRIEND_STATUS = 0x7B
PKT_FRIEND_REMOVE = 0x7C
PKT_EXTENSION = 0x7D

# Server -> Client extension packet types
PKT_LEDGER_STATUS = 0xC0
PKT_LEDGER_ACK = 0xC1
PKT_FRIEND_REQUEST_IN = 0xF8
PKT_FRIEND_RESULT = 0xF9
PKT_FRIEND_LIST = 0xFA
PKT_FRIEND_STATUS_LIST = 0xFB
PKT_EXTENSION_IN = 0xFC

# Sub-protocols multiplexed inside 0x7D / 0xFC
SUBOP_DAILY_STREAK = 0x13
SUBOP_LUMIOSE_BAG = 0x16

# Daily streak & Lumiose Bag constants
MAX_FRIENDS = 40
MAX_FRIEND_NAME_LEN = 24
MAX_STATUS_LEN = 60
STREAK_CYCLE_DAYS = 5
ITEM_LUMIOSE_SHINY_CHARM = 1
SHINY_CHARM_DURATION_SECONDS = 3600

# Friend result codes (0xF9)
FRIEND_CODE_CANCELLED = 0
FRIEND_CODE_ACCEPTED = 1
FRIEND_CODE_DECLINED = 2
FRIEND_CODE_NO_ANSWER = 3
FRIEND_CODE_BUSY = 4
FRIEND_CODE_ALREADY = 6
FRIEND_CODE_LIST_FULL = 7


def _pack_hdr(pkt_type: int, token: int) -> bytes:
    return struct.pack('<2sBBI', MAGIC, PROTO_VERSION, pkt_type & 0xFF, token & 0xFFFFFFFF)


def sanitize_ascii(raw: bytes, max_len: int, *, fallback: bytes = b'') -> bytes:
    cleaned = bytes(b if (0x20 <= b != 0x7F) else 0x20 for b in raw[:max_len])
    return cleaned if cleaned else fallback


def _utc_ymd_and_reset_secs(wall_now: float) -> tuple[str, tuple[int, int, int], int]:
    dt = datetime.fromtimestamp(wall_now, tz=timezone.utc)
    next_midnight = datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc) + timedelta(days=1)
    secs_left = max(1, int((next_midnight - dt).total_seconds()))
    return dt.strftime('%Y-%m-%d'), (dt.year, dt.month, dt.day), secs_left


@dataclass
class PendingFriendRequest:
    sender_pid: int
    target_pid: int
    req_id: int
    sender_tid: str
    target_tid: str


@dataclass
class TrainerRecord:
    trainer_id: str
    name: str = 'Trainer'
    status: str = ''
    last_seen_ymd: list[int] = field(default_factory=lambda: [2026, 1, 1])
    friends: list[str] = field(default_factory=list)
    streak_day: int = 0
    streak_last_ymd: str = ''
    bag: dict[str, int] = field(default_factory=dict)
    active_effects: dict[str, int] = field(default_factory=dict)
    raid_tickets: int = 1
    nursery_slots: list[dict] = field(default_factory=list)


class RoomExtensions:
    """Handles Friends, Daily Login Streak, Bag, Ledger, and Co-op extensions."""

    def __init__(
        self,
        state_path: Path | str | None = None,
        *,
        wall_clock=None,
    ) -> None:
        self.state_path = Path(state_path) if state_path else None
        self.wall_clock = wall_clock or time.time
        self.list_rev: int = 1
        self.records: dict[str, TrainerRecord] = {}
        self.pending_requests: dict[tuple[int, int, int], PendingFriendRequest] = {}
        self.coop = CoopHub(
            wall_clock=self.wall_clock,
            ensure_record=self._ensure_record,
            find_online_by_tid=self._find_online_by_tid,
            save_state=self._save,
            build_bag_packet=self.build_bag_packet,
            records_ref=self.records,
        )
        try:
            from .private_world import WorldAndSpawnHub
        except ImportError:
            from private_world import WorldAndSpawnHub
        self.world = WorldAndSpawnHub(
            wall_clock=self.wall_clock,
            save_state=self._save,
            notice_builder=build_server_notice,
            is_admin_fn=self.coop.is_admin,
        )
        try:
            from .private_economy import MailHub, RaceHub, TradeHub, WonderHub
        except ImportError:
            from private_economy import MailHub, RaceHub, TradeHub, WonderHub
        self.mail = MailHub(
            wall_clock=self.wall_clock,
            find_online_by_tid=self._find_online_by_tid,
            save_state=self._save,
            records_ref=self.records,
            notice_builder=build_server_notice,
        )
        self.wonder = WonderHub(
            wall_clock=self.wall_clock,
            save_state=self._save,
            mail_hub=self.mail,
        )
        self.trade = TradeHub()
        self.race = RaceHub(
            wall_clock=self.wall_clock,
            save_state=self._save,
            mail_hub=self.mail,
            records_ref=self.records,
            notice_builder=build_server_notice,
            is_admin_fn=self.coop.is_admin,
        )
        self._load()

    def _load(self) -> None:
        if self.state_path is None or not self.state_path.is_file():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        self.list_rev = max(1, int(raw.get('list_rev', 1)))
        players = raw.get('players', {})
        if not isinstance(players, dict):
            return
        for tid, item in players.items():
            if not isinstance(tid, str) or not isinstance(item, dict):
                continue
            ymd = item.get('last_seen_ymd', [2026, 1, 1])
            if not isinstance(ymd, list) or len(ymd) != 3:
                ymd = [2026, 1, 1]
            self.records[tid] = TrainerRecord(
                trainer_id=tid,
                name=str(item.get('name', 'Trainer'))[:MAX_FRIEND_NAME_LEN],
                status=str(item.get('status', ''))[:MAX_STATUS_LEN],
                last_seen_ymd=[int(ymd[0]), int(ymd[1]), int(ymd[2])],
                friends=[str(f) for f in item.get('friends', []) if isinstance(f, str)][:MAX_FRIENDS],
                streak_day=max(0, min(STREAK_CYCLE_DAYS, int(item.get('streak_day', 0)))),
                streak_last_ymd=str(item.get('streak_last_ymd', '')),
                bag={str(k): max(0, int(v)) for k, v in dict(item.get('bag', {})).items()},
                active_effects={
                    str(k): int(v) for k, v in dict(item.get('active_effects', {})).items()
                },
                raid_tickets=max(0, min(10, int(item.get('raid_tickets', 1)))),
                nursery_slots=[dict(s) for s in item.get('nursery_slots', []) if isinstance(s, dict)],
            )
        self.coop.load_state(raw.get('coop'))
        self.world.load_state(raw.get('world'))
        self.mail.load_state(raw.get('mail'))
        self.wonder.load_state(raw.get('wonder'))
        self.race.load_state(raw.get('race'))

    def _save(self) -> None:
        if self.state_path is None:
            return
        payload = {
            'list_rev': self.list_rev,
            'coop': self.coop.export_state(),
            'world': self.world.export_state(),
            'mail': self.mail.export_state(),
            'wonder': self.wonder.export_state(),
            'race': self.race.export_state(),
            'players': {
                tid: {
                    'name': rec.name,
                    'status': rec.status,
                    'last_seen_ymd': rec.last_seen_ymd,
                    'friends': rec.friends,
                    'streak_day': rec.streak_day,
                    'streak_last_ymd': rec.streak_last_ymd,
                    'bag': rec.bag,
                    'active_effects': rec.active_effects,
                    'raid_tickets': rec.raid_tickets,
                    'nursery_slots': rec.nursery_slots,
                }
                for tid, rec in self.records.items()
            },
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        tmp.replace(self.state_path)

    def _ensure_record(self, trainer_id: bytes, name: bytes) -> TrainerRecord:
        tid = trainer_id.hex()
        clean_name = sanitize_ascii(name, MAX_FRIEND_NAME_LEN, fallback=b'Trainer').decode('ascii', 'replace')
        _, ymd_tuple, _ = _utc_ymd_and_reset_secs(self.wall_clock())
        rec = self.records.get(tid)
        if rec is None:
            rec = TrainerRecord(
                trainer_id=tid,
                name=clean_name,
                last_seen_ymd=list(ymd_tuple),
            )
            self.records[tid] = rec
            self._save()
        else:
            changed = False
            if rec.name != clean_name:
                rec.name = clean_name
                changed = True
            ymd_list = list(ymd_tuple)
            if rec.last_seen_ymd != ymd_list:
                rec.last_seen_ymd = ymd_list
                changed = True
            if changed:
                self._save()
        return rec

    def _find_online_by_tid(self, players_by_pid: dict[int, object], tid: str):
        for p in players_by_pid.values():
            if getattr(p, 'trainer_id', b'').hex() == tid:
                return p
        return None

    def _streak_status_fields(self, rec: TrainerRecord) -> tuple[int, int, int]:
        """Return (display_day, reward_item_id, cooldown_secs) for FC 13."""
        now = float(self.wall_clock())
        today_str, _, secs_left = _utc_ymd_and_reset_secs(now)
        if rec.streak_last_ymd == today_str:
            day = max(1, rec.streak_day)
            item_id = ITEM_LUMIOSE_SHINY_CHARM if day == STREAK_CYCLE_DAYS else 0
            return day, item_id, secs_left

        # Check if streak elapsed (>1 UTC day gap resets back to 0 so next claim is Day 1)
        if rec.streak_last_ymd:
            try:
                last_d = date.fromisoformat(rec.streak_last_ymd)
                today_d = date.fromisoformat(today_str)
                if (today_d - last_d).days > 1 or rec.streak_day >= STREAK_CYCLE_DAYS:
                    return 0, 0, 0
            except ValueError:
                return 0, 0, 0
        return rec.streak_day, 0, 0

    def _claim_daily_streak(self, rec: TrainerRecord) -> tuple[int, int, int, int]:
        """Advance streak if eligible today. Returns (code, day, item_id, cooldown_secs)."""
        now = float(self.wall_clock())
        today_str, _, secs_left = _utc_ymd_and_reset_secs(now)
        if rec.streak_last_ymd == today_str:
            day = max(1, rec.streak_day)
            item_id = ITEM_LUMIOSE_SHINY_CHARM if day == STREAK_CYCLE_DAYS else 0
            return 4, day, item_id, secs_left

        next_day = 1
        if rec.streak_last_ymd:
            try:
                last_d = date.fromisoformat(rec.streak_last_ymd)
                today_d = date.fromisoformat(today_str)
                if (today_d - last_d).days == 1 and 1 <= rec.streak_day < STREAK_CYCLE_DAYS:
                    next_day = rec.streak_day + 1
            except ValueError:
                next_day = 1

        rec.streak_day = next_day
        rec.streak_last_ymd = today_str
        reward_item = 0
        if next_day == STREAK_CYCLE_DAYS or self.coop.is_event_on('shiny_event'):
            reward_item = ITEM_LUMIOSE_SHINY_CHARM
            cur_qty = rec.bag.get(str(ITEM_LUMIOSE_SHINY_CHARM), 0)
            rec.bag[str(ITEM_LUMIOSE_SHINY_CHARM)] = min(99, cur_qty + 1)
        self._save()
        return 2, next_day, reward_item, secs_left

    def build_streak_packet(self, token: int, code: int, day: int, item_id: int, cooldown_secs: int) -> bytes:
        return _pack_hdr(PKT_EXTENSION_IN, token) + struct.pack(
            '<BBBBHI',
            SUBOP_DAILY_STREAK,
            1,
            code & 0xFF,
            day & 0xFF,
            item_id & 0xFFFF,
            cooldown_secs & 0xFFFFFFFF,
        )

    def build_bag_packet(
        self,
        token: int,
        rec: TrainerRecord,
        *,
        popup_code: int = 0,
        popup_item_id: int = 0,
    ) -> bytes:
        now = int(self.wall_clock())
        entries: list[tuple[int, int, int]] = []
        # Include shiny charm if player owns >= 1 or has active timer
        charm_qty = rec.bag.get(str(ITEM_LUMIOSE_SHINY_CHARM), 0)
        charm_exp = rec.active_effects.get(str(ITEM_LUMIOSE_SHINY_CHARM), 0)
        charm_rem = max(0, charm_exp - now)
        if charm_qty > 0 or charm_rem > 0:
            entries.append((ITEM_LUMIOSE_SHINY_CHARM, charm_qty, charm_rem))
        for k, qty in sorted(rec.bag.items()):
            iid = int(k)
            if iid == ITEM_LUMIOSE_SHINY_CHARM:
                continue
            rem = max(0, rec.active_effects.get(k, 0) - now)
            if qty > 0 or rem > 0:
                entries.append((iid, qty, rem))

        entries = entries[:16]
        out = bytearray(
            _pack_hdr(PKT_EXTENSION_IN, token)
            + struct.pack(
                '<BBBBBHB',
                SUBOP_LUMIOSE_BAG,
                1,
                0,
                0,
                popup_code & 0xFF,
                popup_item_id & 0xFFFF,
                len(entries) & 0xFF,
            )
        )
        for iid, qty, rem in entries:
            out.extend(struct.pack('<HHI', iid & 0xFFFF, qty & 0xFFFF, rem & 0xFFFFFFFF))
        return bytes(out)

    def build_friend_list_packets(
        self,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]]:
        rec = self._ensure_record(player.trainer_id, player.name)
        valid_friends = [ftid for ftid in rec.friends if ftid in self.records][:MAX_FRIENDS]

        # 0xFA: friend list + trailing YYYY-MM-DD dates
        fa = bytearray(_pack_hdr(PKT_FRIEND_LIST, player.token))
        fa.extend(struct.pack('<IB', self.list_rev & 0xFFFFFFFF, len(valid_friends) & 0xFF))
        dates = bytearray()
        fb_entries: list[tuple[int, int, bytes]] = []
        for ftid in valid_friends:
            frec = self.records[ftid]
            online = self._find_online_by_tid(players_by_pid, ftid)
            online_pid = online.pid if online is not None else 0
            fname = sanitize_ascii(
                online.name if online is not None else frec.name.encode('ascii', 'replace'),
                MAX_FRIEND_NAME_LEN,
                fallback=b'Trainer',
            )
            fa.extend(struct.pack('<HB', online_pid & 0xFFFF, len(fname) & 0xFF))
            fa.extend(fname)
            y, m, d = frec.last_seen_ymd
            dates.extend(struct.pack('<HBB', max(2000, y), max(1, min(12, m)), max(1, min(31, d))))
            fstatus = sanitize_ascii(frec.status.encode('ascii', 'replace'), MAX_STATUS_LEN)
            fb_entries.append((1 if online_pid else 0, online_pid, fstatus))
        fa.extend(dates)

        # 0xFB: own status + friend online statuses (must share list_rev with 0xFA!)
        my_status = sanitize_ascii(rec.status.encode('ascii', 'replace'), MAX_STATUS_LEN)
        fb = bytearray(_pack_hdr(PKT_FRIEND_STATUS_LIST, player.token))
        fb.extend(struct.pack('<IB', self.list_rev & 0xFFFFFFFF, len(my_status) & 0xFF))
        fb.extend(my_status)
        fb.append(len(fb_entries) & 0xFF)
        for is_online, opid, fstatus in fb_entries:
            fb.extend(struct.pack('<BHB', is_online, opid & 0xFFFF, len(fstatus) & 0xFF))
            fb.extend(fstatus)

        return [(player.addr, bytes(fa)), (player.addr, bytes(fb))]

    def _broadcast_friends_sync(
        self,
        tid: str,
        players_by_pid: dict[int, object],
        *,
        include_self: bool = True,
    ) -> list[tuple[tuple[str, int], bytes]]:
        out: list[tuple[tuple[str, int], bytes]] = []
        rec = self.records.get(tid)
        if rec is None:
            return out
        targets = list(rec.friends)
        if include_self:
            targets.append(tid)
        seen: set[str] = set()
        for t in targets:
            if t in seen:
                continue
            seen.add(t)
            peer = self._find_online_by_tid(players_by_pid, t)
            if peer is not None:
                out.extend(self.build_friend_list_packets(peer, players_by_pid))
        return out

    def on_player_join(
        self,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]]:
        rec = self._ensure_record(player.trainer_id, player.name)
        self.list_rev = (self.list_rev + 1) & 0xFFFFFFFF or 1
        out: list[tuple[tuple[str, int], bytes]] = []
        day, item_id, cooldown = self._streak_status_fields(rec)
        out.append((player.addr, self.build_streak_packet(player.token, 4, day, item_id, cooldown)))
        out.append((player.addr, self.build_bag_packet(player.token, rec)))
        out.extend(self._broadcast_friends_sync(rec.trainer_id, players_by_pid, include_self=True))
        out.extend(self.coop.on_player_join(player, players_by_pid))
        out.extend(self.world.on_player_join(player, players_by_pid))
        out.extend(self.mail.on_player_join(player, players_by_pid))
        out.extend(self.race.on_player_join(player, players_by_pid))
        if self.coop.is_admin(player):
            out.append((player.addr, build_server_notice(player.token, 'Server listo! Usa /events o /help para ver eventos.')))
        return out

    def on_player_leave(
        self,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]]:
        tid = player.trainer_id.hex()
        rec = self.records.get(tid)
        if rec is None:
            return self.coop.on_player_leave(player, players_by_pid)
        _, ymd_tuple, _ = _utc_ymd_and_reset_secs(self.wall_clock())
        rec.last_seen_ymd = list(ymd_tuple)
        self.list_rev = (self.list_rev + 1) & 0xFFFFFFFF or 1
        self._save()
        # Drop pending requests involving leaving pid
        stale_keys = [
            k
            for k, req in self.pending_requests.items()
            if req.sender_pid == player.pid or req.target_pid == player.pid
        ]
        for k in stale_keys:
            self.pending_requests.pop(k, None)
        out = self._broadcast_friends_sync(tid, players_by_pid, include_self=False)
        out.extend(self.coop.on_player_leave(player, players_by_pid))
        out.extend(self.trade.on_player_leave(player, players_by_pid))
        return out

    def _build_friend_result(self, token: int, peer_pid: int, req_id: int, code: int, name: bytes) -> bytes:
        cname = sanitize_ascii(name, MAX_FRIEND_NAME_LEN, fallback=b'Trainer')
        return (
            _pack_hdr(PKT_FRIEND_RESULT, token)
            + struct.pack('<HHBB', peer_pid & 0xFFFF, req_id & 0xFFFF, code & 0xFF, len(cname) & 0xFF)
            + cname
            + b'\x00'
        )

    def handle_packet(
        self,
        pkt_type: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        """Handle extension opcodes. Returns None if pkt_type is not handled here."""
        if pkt_type == PKT_LEDGER_REPORT:
            return [(_dst := player.addr, _pack_hdr(PKT_LEDGER_STATUS, player.token) + struct.pack('<BBIHB', 1, 0, 0, 0, 0))]

        if pkt_type == PKT_LEDGER_EVENTS:
            if len(pkt) >= 10:
                seq = struct.unpack_from('<H', pkt, 8)[0]
                return [(player.addr, _pack_hdr(PKT_LEDGER_ACK, player.token) + struct.pack('<HB', seq, 1))]
            return []

        if pkt_type == PKT_FRIEND_LIST_REQ:
            return self.build_friend_list_packets(player, players_by_pid)

        if pkt_type == PKT_FRIEND_STATUS:
            if len(pkt) < 9:
                return []
            slen = pkt[8]
            status_bytes = sanitize_ascii(pkt[9 : 9 + min(slen, MAX_STATUS_LEN)], MAX_STATUS_LEN)
            rec = self._ensure_record(player.trainer_id, player.name)
            rec.status = status_bytes.decode('ascii', 'replace')
            self._save()
            return self._broadcast_friends_sync(rec.trainer_id, players_by_pid, include_self=True)

        if pkt_type == PKT_FRIEND_REQUEST:
            if len(pkt) < 12:
                return []
            target_pid, req_id = struct.unpack_from('<HH', pkt, 8)
            target = players_by_pid.get(target_pid)
            if target is None or target.pid == player.pid:
                return [(player.addr, self._build_friend_result(player.token, target_pid, req_id, FRIEND_CODE_NO_ANSWER, b'Player'))]
            srec = self._ensure_record(player.trainer_id, player.name)
            trec = self._ensure_record(target.trainer_id, target.name)
            if trec.trainer_id in srec.friends:
                return [(player.addr, self._build_friend_result(player.token, target.pid, req_id, FRIEND_CODE_ALREADY, target.name))]
            if len(srec.friends) >= MAX_FRIENDS or len(trec.friends) >= MAX_FRIENDS:
                return [(player.addr, self._build_friend_result(player.token, target.pid, req_id, FRIEND_CODE_LIST_FULL, target.name))]
            key = (player.pid, target.pid, req_id)
            self.pending_requests[key] = PendingFriendRequest(
                sender_pid=player.pid,
                target_pid=target.pid,
                req_id=req_id,
                sender_tid=srec.trainer_id,
                target_tid=trec.trainer_id,
            )
            sname = sanitize_ascii(player.name, MAX_FRIEND_NAME_LEN, fallback=b'Trainer')
            f8 = (
                _pack_hdr(PKT_FRIEND_REQUEST_IN, target.token)
                + struct.pack('<HHB', player.pid & 0xFFFF, req_id & 0xFFFF, len(sname) & 0xFF)
                + sname
            )
            return [(target.addr, f8)]

        if pkt_type == PKT_FRIEND_ANSWER:
            if len(pkt) < 13:
                return []
            peer_pid, req_id, answer = struct.unpack_from('<HHB', pkt, 8)
            if answer == 3:
                # Requester cancelled outgoing request to peer_pid
                req = self.pending_requests.pop((player.pid, peer_pid, req_id), None)
                target = players_by_pid.get(peer_pid)
                if target is None:
                    return []
                return [(target.addr, self._build_friend_result(target.token, player.pid, req_id, FRIEND_CODE_CANCELLED, player.name))]

            # Answer (1=accept, 2=decline) from target (player) to requester (peer_pid)
            req = self.pending_requests.pop((peer_pid, player.pid, req_id), None)
            requester = players_by_pid.get(peer_pid)
            if answer == 1:
                srec = self._ensure_record(player.trainer_id, player.name)
                rtid = req.sender_tid if req is not None else (requester.trainer_id.hex() if requester else '')
                rrec = self.records.get(rtid)
                if rrec is None and requester is not None:
                    rrec = self._ensure_record(requester.trainer_id, requester.name)
                if rrec is None:
                    return []
                if len(srec.friends) >= MAX_FRIENDS or len(rrec.friends) >= MAX_FRIENDS:
                    out = [(player.addr, self._build_friend_result(player.token, peer_pid, req_id, FRIEND_CODE_LIST_FULL, rrec.name.encode('ascii')))]
                    if requester is not None:
                        out.append((requester.addr, self._build_friend_result(requester.token, player.pid, req_id, FRIEND_CODE_LIST_FULL, player.name)))
                    return out
                if rrec.trainer_id not in srec.friends:
                    srec.friends.append(rrec.trainer_id)
                if srec.trainer_id not in rrec.friends:
                    rrec.friends.append(srec.trainer_id)
                self.list_rev = (self.list_rev + 1) & 0xFFFFFFFF or 1
                self._save()
                out: list[tuple[tuple[str, int], bytes]] = []
                if requester is not None:
                    out.append((requester.addr, self._build_friend_result(requester.token, player.pid, req_id, FRIEND_CODE_ACCEPTED, player.name)))
                    out.extend(self.build_friend_list_packets(requester, players_by_pid))
                out.extend(self.build_friend_list_packets(player, players_by_pid))
                return out

            # Declined (answer == 2 or other)
            if requester is not None:
                return [(requester.addr, self._build_friend_result(requester.token, player.pid, req_id, FRIEND_CODE_DECLINED, player.name))]
            return []

        if pkt_type == PKT_FRIEND_REMOVE:
            if len(pkt) < 11:
                return []
            friend_pid, nlen = struct.unpack_from('<HB', pkt, 8)
            fname = sanitize_ascii(pkt[11 : 11 + min(nlen, MAX_FRIEND_NAME_LEN)], MAX_FRIEND_NAME_LEN).decode('ascii', 'replace')
            srec = self._ensure_record(player.trainer_id, player.name)
            removed_tid: str | None = None
            target_online = players_by_pid.get(friend_pid) if friend_pid > 0 else None
            if target_online is not None:
                cand = target_online.trainer_id.hex()
                if cand in srec.friends:
                    removed_tid = cand
            if removed_tid is None and fname:
                for ftid in srec.friends:
                    frec = self.records.get(ftid)
                    if frec is not None and frec.name == fname:
                        removed_tid = ftid
                        break
            if removed_tid is None:
                return self.build_friend_list_packets(player, players_by_pid)
            srec.friends = [f for f in srec.friends if f != removed_tid]
            frec = self.records.get(removed_tid)
            if frec is not None:
                frec.friends = [f for f in frec.friends if f != srec.trainer_id]
            self.list_rev = (self.list_rev + 1) & 0xFFFFFFFF or 1
            self._save()
            out = self.build_friend_list_packets(player, players_by_pid)
            other_online = self._find_online_by_tid(players_by_pid, removed_tid)
            if other_online is not None:
                out.extend(self.build_friend_list_packets(other_online, players_by_pid))
            return out

        if pkt_type == PKT_EXTENSION:
            if len(pkt) < 9:
                return []
            subop = pkt[8]
            if subop != SUBOP_DAILY_STREAK:
                for handler in (self.world, self.wonder, self.race, self.coop):
                    replies = handler.handle_extension(subop, pkt, player, players_by_pid)
                    if replies is not None:
                        return replies
                return []
            rec = self._ensure_record(player.trainer_id, player.name)
            # Use Lumiose Bag item: [0x13, 0, 0, 0, 0x00, 0x04, item_lo, item_hi]
            if len(pkt) >= 16 and pkt[12:14] == b'\x00\x04':
                item_id = struct.unpack_from('<H', pkt, 14)[0]
                now = int(self.wall_clock())
                key = str(item_id)
                qty = rec.bag.get(key, 0)
                rem = max(0, rec.active_effects.get(key, 0) - now)
                if rem > 0:
                    return [(player.addr, self.build_bag_packet(player.token, rec, popup_code=5, popup_item_id=item_id))]
                if qty <= 0 or item_id != ITEM_LUMIOSE_SHINY_CHARM:
                    return [(player.addr, self.build_bag_packet(player.token, rec, popup_code=4, popup_item_id=item_id))]
                rec.bag[key] = qty - 1
                rec.active_effects[key] = now + SHINY_CHARM_DURATION_SECONDS
                self._save()
                return [(player.addr, self.build_bag_packet(player.token, rec, popup_code=3, popup_item_id=item_id))]

            # Query (action == 2) or Claim (action == 3): [0x13, 0, 0, 0, 0, action]
            if len(pkt) >= 14:
                action = pkt[13]
                if action == 3:
                    code, day, reward_item, cooldown = self._claim_daily_streak(rec)
                    return [
                        (player.addr, self.build_streak_packet(player.token, code, day, reward_item, cooldown)),
                        (player.addr, self.build_bag_packet(player.token, rec)),
                    ]
                if action == 2:
                    day, item_id, cooldown = self._streak_status_fields(rec)
                    return [
                        (player.addr, self.build_streak_packet(player.token, 4, day, item_id, cooldown)),
                        (player.addr, self.build_bag_packet(player.token, rec)),
                    ]
            return []

        for handler in (self.world, self.mail, self.wonder, self.trade, self.race, self.coop):
            replies = handler.handle_packet(pkt_type, pkt, player, players_by_pid)
            if replies is not None:
                return replies
        return []

    def handle_chat(self, msg_bytes: bytes, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]] | None:
        text = msg_bytes.decode('utf-8', 'ignore').strip()
        if text.startswith('/'):
            parts = text[1:].split(None, 1)
            cmd = parts[0].lower() if parts else ''
            args = parts[1] if len(parts) > 1 else ''
            for handler in (self.world, self.race):
                res = handler.handle_command(cmd, args, player, players_by_pid, from_console=False)
                if res is not None:
                    return res[0]
        return self.coop.handle_chat(msg_bytes, player, players_by_pid)

    def handle_console_command(self, line: str, players_by_pid: dict[int, object]) -> tuple[list[tuple[tuple[str, int], bytes]], str]:
        text = line.strip()
        if text.startswith('/'):
            text = text[1:]
        if text:
            parts = text.split(None, 1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ''
            for handler in (self.world, self.race):
                res = handler.handle_command(cmd, args, None, players_by_pid, from_console=True)
                if res is not None:
                    return res
        return self.coop.handle_console_command(line, players_by_pid)

    def tick(self, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        return self.coop.tick(players_by_pid) + self.world.tick(players_by_pid)
