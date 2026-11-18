"""Co-op Party, Raids, Nursery (Eggs), Mystery Gift, Events, and Market-off handlers."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import struct
from typing import Callable

MAGIC = b'ZA'
PROTO_VERSION = 1

# Direct opcodes (outside 0x7D / 0xFC)
PKT_CHAT_IN = 0xB0
PKT_EXTENSION_IN = 0xFC

# Daycare / Nursery client -> server & server -> client opcodes
PKT_DAYCARE_PROBE = 0x44
PKT_DAYCARE_SYNC = 0x45
PKT_DAYCARE_UPLOAD = 0x46
PKT_DAYCARE_ACTION = 0x47
PKT_DAYCARE_SLOTS = 0xC4
PKT_DAYCARE_STATE = 0xC5
PKT_DAYCARE_TXN = 0xC6

# Lumiose Market opcodes (intentionally disabled when events['market'] is off)
MARKET_TX_OPCODES = frozenset(range(0x68, 0x6F))

# 0x7D Client -> Server subops
TX_SUBOP_SETTINGS = 0x14
TX_SUBOP_MYSTERY_GIFT = 0x17
TX_SUBOP_RAID_LOBBY = 0x1D
TX_SUBOP_RAID_COMBAT = 0x26
TX_SUBOP_PARTY = 0x28
TX_SUBOP_RAID_TICKET = 0x29

# 0xFC Server -> Client subops
RX_SUBOP_SETTINGS = 0x14
RX_SUBOP_MYSTERY_GIFT = 0x19
RX_SUBOP_RAID_SPOTS = 0x21
RX_SUBOP_RAID_ACK = 0x22
RX_SUBOP_RAID_BOSS = 0x2E
RX_SUBOP_PARTY = 0x30
RX_SUBOP_RAID_TICKET = 0x31
RX_SUBOP_RAID_LOBBY = 0x33
RX_SUBOP_RAID_READY = 0x34

PKM_BLOCK_SIZE = 0x158
MAX_RAID_TICKETS = 10
MAX_NURSERY_SLOTS = 8
DEFAULT_EGG_HATCH_SECS = 60

DEFAULT_AUTO_INTERVAL_SECS = 45 * 60
DEFAULT_AUTO_DURATION_SECS = 15 * 60
DEFAULT_AUTO_RAID_SECS = 30 * 60

AUTO_EVENT_ROTATION: tuple[str, ...] = ('shiny_event', 'instant_hatch', 'double_loot')
AUTO_EVENT_LABELS: dict[str, str] = {
    'shiny_event': 'Hora Shiny (Shiny Charm)',
    'instant_hatch': 'Guarderia Turbo (Eclosion instantanea)',
    'double_loot': 'Lluvia de Recompensas (Loot x2)',
}

DEFAULT_EVENTS: dict[str, bool] = {
    'raids': True,
    'nursery': True,
    'mystery_gift': True,
    'auto_events': True,
    'shiny_event': False,
    'instant_hatch': False,
    'double_loot': False,
}

EVENT_ALIASES: dict[str, str] = {
    'raid': 'raids',
    'raids': 'raids',
    'nursery': 'nursery',
    'huevos': 'nursery',
    'daycare': 'nursery',
    'egg': 'nursery',
    'eggs': 'nursery',
    'gift': 'mystery_gift',
    'gifts': 'mystery_gift',
    'mystery': 'mystery_gift',
    'mystery_gift': 'mystery_gift',
    'regalo': 'mystery_gift',
    'auto': 'auto_events',
    'auto_events': 'auto_events',
    'auto_event': 'auto_events',
    'programados': 'auto_events',
    'shiny': 'shiny_event',
    'shiny_event': 'shiny_event',
    'charm': 'shiny_event',
    'hatch': 'instant_hatch',
    'instant_hatch': 'instant_hatch',
    'instanthatch': 'instant_hatch',
    'loot': 'double_loot',
    'double_loot': 'double_loot',
    'doble': 'double_loot',
}

DEFAULT_GIFTS: dict[str, dict] = {
    'SHINYZA': {
        'kind': 'charm',
        'qty': 1,
        'label': 'Lumiose Shiny Charm x1',
        'active': True,
        'claimed_by': [],
    },
    'RAIDPARTY': {
        'kind': 'tickets',
        'qty': 3,
        'label': 'Raid Tickets x3',
        'active': True,
        'claimed_by': [],
    },
    'HOLAAMOR': {
        'kind': 'bundle',
        'qty': 2,
        'label': 'Lumiose Shiny Charm x2 + Raid Tickets x2',
        'active': True,
        'claimed_by': [],
    },
}

RAID_SPECIES_NAMES: dict[int, str] = {
    94: 'Gengar',
    130: 'Gyarados',
    445: 'Garchomp',
    609: 'Chandelure',
    681: 'Aegislash',
    706: 'Goodra',
}

# Curated Raid Boss presets (species, form, level, type1, type2, weak_mask, category, max_hp, spawner_key)
RAID_BOSS_PRESETS: tuple[tuple[int, int, int, int, int, int, int, int, int], ...] = (
    (94, 0, 65, 8, 4, 0x00031100, 1, 2400, 0x0101A001),   # Gengar
    (130, 0, 65, 11, 3, 0x00001020, 1, 2600, 0x0101A002),  # Gyarados
    (445, 0, 70, 16, 5, 0x00028000, 2, 3000, 0x0101A003),  # Garchomp
    (609, 0, 65, 8, 10, 0x00030A00, 1, 2500, 0x0101A004),  # Chandelure
    (681, 0, 70, 9, 8, 0x00021500, 2, 2900, 0x0101A005),   # Aegislash
    (706, 0, 72, 16, 0, 0x00028000, 2, 3200, 0x0101A006),  # Goodra
)


def _pack_hdr(pkt_type: int, token: int) -> bytes:
    return struct.pack('<2sBBI', MAGIC, PROTO_VERSION, pkt_type & 0xFF, token & 0xFFFFFFFF)


def _clean_ascii(raw: bytes, max_len: int) -> bytes:
    return bytes(b if (0x20 <= b != 0x7F) else 0x20 for b in raw[:max_len])


def build_server_notice(recipient_token: int, text: str, sender_name: bytes = b'[SERVER]') -> bytes:
    msg = text.encode('utf-8', 'replace')[:120]
    sname = _clean_ascii(sender_name, 24) or b'[SERVER]'
    return (
        _pack_hdr(PKT_CHAT_IN, recipient_token)
        + struct.pack('<HB', 0, len(sname))
        + sname
        + struct.pack('<B', len(msg))
        + msg
    )


@dataclass
class PartyInvite:
    invite_id: int
    sender_pid: int
    target_pid: int
    party_id: int


@dataclass
class PartyRoom:
    party_id: int
    leader_pid: int
    members: list[int] = field(default_factory=list)
    flags: int = 1


@dataclass
class RaidSession:
    rid: int
    key: int
    species: int
    form: int
    level: int
    type1: int
    type2: int
    weak_mask: int
    category: int
    max_hp: int
    hp: int
    driver_pid: int
    members: list[int] = field(default_factory=list)
    active: bool = True
    lobby_only: bool = True
    hit_seq: int = 0


class CoopHub:
    """Implements Co-op Party, Raids, Nursery (Eggs), Mystery Gift, Events, and Commands."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], float],
        ensure_record,
        find_online_by_tid,
        save_state: Callable[[], None],
        build_bag_packet,
        records_ref: dict,
    ) -> None:
        self.wall_clock = wall_clock
        self._ensure_record = ensure_record
        self._find_online_by_tid = find_online_by_tid
        self._save = save_state
        self._build_bag_packet = build_bag_packet
        self.records = records_ref

        self.events: dict[str, bool] = dict(DEFAULT_EVENTS)
        self.gifts: dict[str, dict] = {
            k: {**v, 'claimed_by': list(v.get('claimed_by', []))}
            for k, v in DEFAULT_GIFTS.items()
        }
        self.admins: set[str] = set()

        # Live room state (per active UDP session)
        self._next_party_id = 1
        self._next_invite_id = 1
        self.parties: dict[int, PartyRoom] = {}
        self.player_party: dict[int, int] = {}
        self.party_invites: dict[int, PartyInvite] = {}

        self._next_rid = 1
        self._raid_preset_idx = 0
        self.active_raid: RaidSession | None = None
        self.player_raid_joined: set[int] = set()

        self._next_nursery_id = 100
        self._next_nursery_txn = 500
        self.pending_nursery_txns: dict[int, tuple[int, str, str, int]] = {}

        # Automatic scheduled events & raids
        self.auto_interval_secs: int = DEFAULT_AUTO_INTERVAL_SECS
        self.auto_duration_secs: int = DEFAULT_AUTO_DURATION_SECS
        self.auto_raid_secs: int = DEFAULT_AUTO_RAID_SECS
        self.auto_idx: int = 0
        self.auto_active_event: str | None = None
        self.auto_ends_at: float = 0.0
        self.auto_next_event_at: float = 0.0
        self.auto_next_raid_at: float = 0.0

    def export_state(self) -> dict:
        return {
            'events': dict(self.events),
            'gifts': self.gifts,
            'admins': sorted(self.admins),
            'auto': {
                'interval_secs': self.auto_interval_secs,
                'duration_secs': self.auto_duration_secs,
                'raid_secs': self.auto_raid_secs,
                'idx': self.auto_idx,
                'active_event': self.auto_active_event,
                'ends_at': self.auto_ends_at,
                'next_event_at': self.auto_next_event_at,
                'next_raid_at': self.auto_next_raid_at,
            },
        }

    def load_state(self, raw: dict | None) -> None:
        if not isinstance(raw, dict):
            return
        ev = raw.get('events')
        if isinstance(ev, dict):
            for key in DEFAULT_EVENTS:
                if key in ev:
                    self.events[key] = bool(ev[key])
        gifts = raw.get('gifts')
        if isinstance(gifts, dict):
            loaded: dict[str, dict] = {}
            for code, entry in gifts.items():
                if not isinstance(code, str) or not isinstance(entry, dict):
                    continue
                norm = code.strip().upper()[:32]
                if not norm:
                    continue
                loaded[norm] = {
                    'kind': str(entry.get('kind', 'charm')),
                    'qty': max(1, int(entry.get('qty', 1))),
                    'label': str(entry.get('label', norm))[:80],
                    'active': bool(entry.get('active', True)),
                    'claimed_by': [str(t) for t in entry.get('claimed_by', []) if isinstance(t, str)],
                }
            if loaded:
                self.gifts = loaded
        admins = raw.get('admins')
        if isinstance(admins, list):
            self.admins = {str(a) for a in admins if isinstance(a, str)}
        auto = raw.get('auto')
        if isinstance(auto, dict):
            self.auto_interval_secs = max(60, int(auto.get('interval_secs', DEFAULT_AUTO_INTERVAL_SECS)))
            self.auto_duration_secs = max(60, int(auto.get('duration_secs', DEFAULT_AUTO_DURATION_SECS)))
            self.auto_raid_secs = max(0, int(auto.get('raid_secs', DEFAULT_AUTO_RAID_SECS)))
            self.auto_idx = max(0, int(auto.get('idx', 0)))
            active = auto.get('active_event')
            if isinstance(active, str) and active in AUTO_EVENT_ROTATION and self.events.get(active, False):
                self.auto_active_event = active
                self.auto_ends_at = float(auto.get('ends_at', 0.0))
            else:
                self.auto_active_event = None
                self.auto_ends_at = 0.0
            self.auto_next_event_at = float(auto.get('next_event_at', 0.0))
            self.auto_next_raid_at = float(auto.get('next_raid_at', 0.0))

    def is_event_on(self, name: str) -> bool:
        return bool(self.events.get(name, False))

    def is_admin(self, player) -> bool:
        tid = player.trainer_id.hex()
        if tid in self.admins:
            return True
        addr = getattr(player, 'addr', ('', 0))
        return getattr(player, 'pid', 0) == 1 or addr[0] in ('127.0.0.1', '::1', 'localhost')

    # --- Join / Leave lifecycle ---
    def on_player_join(self, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        rec = self._ensure_record(player.trainer_id, player.name)
        ticket_status = 0 if self.is_event_on('raids') else 6
        out: list[tuple[tuple[str, int], bytes]] = [
            (player.addr, self.build_settings_packet(player.token)),
            (player.addr, self.build_raid_ticket_packet(player.token, 0, action=1, status=ticket_status, tickets=rec.raid_tickets)),
        ]
        # Keep existing party roster fresh if player reconnected on same pid
        pid_num = self.player_party.get(player.pid)
        if pid_num is not None and pid_num in self.parties:
            out.append((player.addr, self.build_party_state_packet(player.token, 0, 1, self.parties[pid_num], players_by_pid)))
        if self.active_raid is not None and self.active_raid.active and self.is_event_on('raids'):
            out.extend(self.build_raid_spawn_packets(player.token, self.active_raid))
        return out

    def on_player_leave(self, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        out: list[tuple[tuple[str, int], bytes]] = []
        # Cancel outgoing/incoming party invites involving this pid
        stale_inv = [
            iid for iid, inv in self.party_invites.items()
            if inv.sender_pid == player.pid or inv.target_pid == player.pid
        ]
        for iid in stale_inv:
            inv = self.party_invites.pop(iid)
            other_pid = inv.target_pid if inv.sender_pid == player.pid else inv.sender_pid
            other = players_by_pid.get(other_pid)
            if other is not None:
                out.append((other.addr, self.build_party_invite_ended(other.token, inv.invite_id, 2, player.name)))

        out.extend(self._remove_from_party(player.pid, players_by_pid, notice='left the room'))
        self.player_raid_joined.discard(player.pid)
        if self.active_raid is not None and player.pid in self.active_raid.members:
            self.active_raid.members = [m for m in self.active_raid.members if m != player.pid]
            if self.active_raid.driver_pid == player.pid and self.active_raid.members:
                self.active_raid.driver_pid = self.active_raid.members[0]
            if not self.active_raid.members:
                self.active_raid = None
        return out

    # --- Settings (0xFC 0x14) ---
    def build_settings_packet(self, token: int) -> bytes:
        lines = [
            f'event.{k}={1 if v else 0}' for k, v in sorted(self.events.items())
        ]
        lines.append('market=0')
        body = ('\n'.join(lines) + '\n').encode('ascii')[:512]
        return _pack_hdr(PKT_EXTENSION_IN, token) + struct.pack('<BBBH', RX_SUBOP_SETTINGS, 1, 0, len(body)) + body

    # --- Mystery Gift (0x7D 0x17 <-> 0xFC 0x19) ---
    def build_mystery_gift_packet(self, token: int, req_id: int, code: int, msg: str) -> bytes:
        mbytes = msg.encode('utf-8', 'replace')[:195]
        return _pack_hdr(PKT_EXTENSION_IN, token) + struct.pack('<BBHBH', RX_SUBOP_MYSTERY_GIFT, 1, req_id & 0xFFFF, code & 0xFF, len(mbytes)) + mbytes

    def _handle_mystery_gift(self, pkt: bytes, player) -> list[tuple[tuple[str, int], bytes]]:
        if len(pkt) < 16:
            return []
        req_id = struct.unpack_from('<H', pkt, 11)[0]
        code_len = min(pkt[15], 32)
        if len(pkt) < 16 + code_len:
            return []
        gift_code = pkt[16 : 16 + code_len].decode('utf-8', 'replace').strip().upper()
        if not self.is_event_on('mystery_gift'):
            return [(player.addr, self.build_mystery_gift_packet(player.token, req_id, 2, 'Mystery Gift is turned off right now.'))]
        entry = self.gifts.get(gift_code)
        if not entry or not entry.get('active', True):
            return [(player.addr, self.build_mystery_gift_packet(player.token, req_id, 2, f'Unknown gift code: {gift_code or "?"}'))]

        rec = self._ensure_record(player.trainer_id, player.name)
        if rec.trainer_id in entry['claimed_by']:
            return [(player.addr, self.build_mystery_gift_packet(player.token, req_id, 1, f'You already claimed {gift_code}.'))]

        entry['claimed_by'].append(rec.trainer_id)
        kind = entry.get('kind', 'charm')
        qty = max(1, int(entry.get('qty', 1)))
        out: list[tuple[tuple[str, int], bytes]] = []
        if kind in ('charm', 'bundle'):
            rec.bag['1'] = min(99, rec.bag.get('1', 0) + qty)
            out.append((player.addr, self._build_bag_packet(player.token, rec, popup_code=0)))
        if kind in ('tickets', 'bundle'):
            rec.raid_tickets = min(MAX_RAID_TICKETS, rec.raid_tickets + qty)
            out.append((player.addr, self.build_raid_ticket_packet(player.token, 0, action=1, status=0, tickets=rec.raid_tickets)))
        self._save()
        label = entry.get('label', gift_code)
        out.insert(0, (player.addr, self.build_mystery_gift_packet(player.token, req_id, 0, f'Received {label}!')))
        return out

    # --- Party (0x7D 0x28 <-> 0xFC 0x30) ---
    def build_party_state_packet(
        self,
        token: int,
        req_id: int,
        code: int,
        party: PartyRoom | None,
        players_by_pid: dict[int, object],
        *,
        notice: str = '',
    ) -> bytes:
        members = party.members[:4] if party is not None else []
        out = bytearray(_pack_hdr(0xFC, token))
        out.extend(
            struct.pack(
                '<BBHBIIB',
                RX_SUBOP_PARTY,
                1,
                req_id & 0xFFFF,
                code & 0xFF,
                (party.party_id if party else 0) & 0xFFFFFFFF,
                (party.flags if party else 0) & 0xFFFFFFFF,
                len(members) & 0xFF,
            )
        )
        for mpid in members:
            member = players_by_pid.get(mpid)
            mname = _clean_ascii(member.name if member is not None else b'Trainer', 24) or b'Trainer'
            mflags = 0x08 if (party is not None and party.leader_pid == mpid) else 0x00
            out.extend(struct.pack('<BHBBB', mpid & 0xFF, mpid & 0xFFFF, 1, mflags, len(mname)))
            out.extend(mname)
        nbytes = notice.encode('utf-8', 'replace')[:120]
        out.append(len(nbytes) & 0xFF)
        out.extend(nbytes)
        return bytes(out)

    def build_party_invite_received(self, token: int, inv: PartyInvite, member_count: int, sender_name: bytes) -> bytes:
        sname = _clean_ascii(sender_name, 24) or b'Trainer'
        return (
            _pack_hdr(0xFC, token)
            + struct.pack('<BBBIHBBB', RX_SUBOP_PARTY, 1, 2, inv.invite_id & 0xFFFFFFFF, inv.sender_pid & 0xFFFF, member_count & 0xFF, 1, len(sname))
            + sname
        )

    def build_party_invite_ended(self, token: int, invite_id: int, why: int, peer_name: bytes) -> bytes:
        pname = _clean_ascii(peer_name, 24) or b'Trainer'
        return (
            _pack_hdr(0xFC, token)
            + struct.pack('<BBBIBB', RX_SUBOP_PARTY, 1, 3, invite_id & 0xFFFFFFFF, why & 0xFF, len(pname))
            + pname
        )

    def _broadcast_party(
        self,
        party: PartyRoom,
        players_by_pid: dict[int, object],
        *,
        req_id: int = 0,
        code: int = 1,
        notice: str = '',
    ) -> list[tuple[tuple[str, int], bytes]]:
        out: list[tuple[tuple[str, int], bytes]] = []
        for mpid in list(party.members):
            m = players_by_pid.get(mpid)
            if m is not None:
                out.append((m.addr, self.build_party_state_packet(m.token, req_id, code, party, players_by_pid, notice=notice)))
        return out

    def _remove_from_party(
        self,
        pid: int,
        players_by_pid: dict[int, object],
        *,
        req_id: int = 0,
        notice: str = '',
    ) -> list[tuple[tuple[str, int], bytes]]:
        pid_num = self.player_party.pop(pid, None)
        if pid_num is None:
            return []
        party = self.parties.get(pid_num)
        if party is None:
            return []
        party.members = [m for m in party.members if m != pid]
        out: list[tuple[tuple[str, int], bytes]] = []
        leaver = players_by_pid.get(pid)
        if leaver is not None:
            out.append((leaver.addr, self.build_party_state_packet(leaver.token, req_id, 1, None, players_by_pid, notice=notice)))
        if len(party.members) <= 1:
            for rem_pid in list(party.members):
                self.player_party.pop(rem_pid, None)
                rem = players_by_pid.get(rem_pid)
                if rem is not None:
                    out.append((rem.addr, self.build_party_state_packet(rem.token, 0, 1, None, players_by_pid, notice='Party disbanded.')))
            self.parties.pop(pid_num, None)
            return out
        if party.leader_pid == pid:
            party.leader_pid = party.members[0]
        out.extend(self._broadcast_party(party, players_by_pid, notice=notice))
        return out

    def _handle_party(self, pkt: bytes, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        if len(pkt) < 15:
            return []
        req_id = struct.unpack_from('<H', pkt, 11)[0]
        action = pkt[14]
        args = pkt[15:]

        if action == 1:  # Invite target_pid
            if not args:
                return []
            target_pid = args[0]
            target = players_by_pid.get(target_pid)
            if target is None or target.pid == player.pid:
                return [(player.addr, self.build_party_state_packet(player.token, req_id, 0, self.parties.get(self.player_party.get(player.pid, -1)), players_by_pid, notice='Player is not online.'))]
            if target.pid in self.player_party:
                return [(player.addr, self.build_party_state_packet(player.token, req_id, 0, self.parties.get(self.player_party.get(player.pid, -1)), players_by_pid, notice='Player is already in a party.'))]

            party_id = self.player_party.get(player.pid)
            if party_id is None:
                party_id = self._next_party_id
                self._next_party_id += 1
                party = PartyRoom(party_id=party_id, leader_pid=player.pid, members=[player.pid])
                self.parties[party_id] = party
                self.player_party[player.pid] = party_id
            else:
                party = self.parties[party_id]
                if len(party.members) >= 4:
                    return [(player.addr, self.build_party_state_packet(player.token, req_id, 0, party, players_by_pid, notice='Party is full.'))]

            invite_id = self._next_invite_id
            self._next_invite_id += 1
            inv = PartyInvite(invite_id=invite_id, sender_pid=player.pid, target_pid=target.pid, party_id=party_id)
            self.party_invites[invite_id] = inv
            return [
                (player.addr, self.build_party_state_packet(player.token, req_id, 1, party, players_by_pid, notice=f'Invited {target.name.decode("utf-8", "replace")}.')),
                (target.addr, self.build_party_invite_received(target.token, inv, len(party.members), player.name)),
            ]

        if action == 2:  # Accept (1) / Decline (0) invite
            if len(args) < 5:
                return []
            invite_id, accept = struct.unpack_from('<IB', args, 0)
            inv = self.party_invites.pop(invite_id, None)
            if inv is None or inv.target_pid != player.pid:
                return [(player.addr, self.build_party_state_packet(player.token, req_id, 0, None, players_by_pid))]
            sender = players_by_pid.get(inv.sender_pid)
            party = self.parties.get(inv.party_id)
            out: list[tuple[tuple[str, int], bytes]] = []
            if sender is not None:
                out.append((sender.addr, self.build_party_invite_ended(sender.token, invite_id, 1 if accept else 2, player.name)))
            if not accept or party is None or len(party.members) >= 4:
                return out
            if player.pid in self.player_party:
                out.extend(self._remove_from_party(player.pid, players_by_pid))
            if player.pid not in party.members:
                party.members.append(player.pid)
            self.player_party[player.pid] = party.party_id
            out.extend(self._broadcast_party(party, players_by_pid, req_id=req_id, notice=f'{player.name.decode("utf-8", "replace")} joined the party.'))
            return out

        if action == 3:  # Leave
            return self._remove_from_party(player.pid, players_by_pid, req_id=req_id, notice='Left party.')

        if action == 4:  # Kick target_pid
            if not args:
                return []
            target_pid = args[0]
            party = self.parties.get(self.player_party.get(player.pid, -1))
            if party is None or party.leader_pid != player.pid or target_pid == player.pid:
                return []
            return self._remove_from_party(target_pid, players_by_pid, req_id=req_id, notice='Removed from party.')

        if action == 5:  # Promote target_pid
            if not args:
                return []
            target_pid = args[0]
            party = self.parties.get(self.player_party.get(player.pid, -1))
            if party is None or party.leader_pid != player.pid or target_pid not in party.members:
                return []
            party.leader_pid = target_pid
            return self._broadcast_party(party, players_by_pid, req_id=req_id, notice='Party leader updated.')

        if action == 6:  # Query / Sync
            party = self.parties.get(self.player_party.get(player.pid, -1))
            return [(player.addr, self.build_party_state_packet(player.token, req_id, 1, party, players_by_pid))]

        return []

    # --- Co-op Raids (0x7D 0x1D / 0x26 / 0x29 <-> 0xFC 0x21 / 0x22 / 0x2E / 0x31 / 0x33) ---
    def build_raid_ticket_packet(
        self,
        token: int,
        req_id: int,
        *,
        action: int,
        status: int,
        tickets: int,
        raid_val: int = 0,
        w8: int | None = None,
    ) -> bytes:
        # 23 bytes after subop: ver(1), req_id(2), action(1), status(1), tickets(1), pad(5), d31(8), w8(4)
        extra = (1 if self.is_event_on('raids') else 0) if w8 is None else w8
        return _pack_hdr(0xFC, token) + struct.pack(
            '<BBHBBB5xQI',
            RX_SUBOP_RAID_TICKET,
            1,
            req_id & 0xFFFF,
            action & 0xFF,
            status & 0xFF,
            tickets & 0xFF,
            raid_val & 0xFFFFFFFFFFFFFFFF,
            extra & 0xFFFFFFFF,
        )

    def build_raid_spots_packet(self, token: int, boss: RaidSession | None) -> bytes:
        stamp = int(self.wall_clock()) & 0xFFFFFFFF
        spots = [boss] if (boss is not None and boss.active and self.is_event_on('raids')) else []
        out = bytearray(_pack_hdr(0xFC, token) + struct.pack('<BBHQB', RX_SUBOP_RAID_SPOTS, 1, 0, stamp, len(spots)))
        for b in spots:
            # 16-byte spot entry (0 rewards trailing)
            out.extend(struct.pack('<BBIIBIB', 1, 1, b.key & 0xFFFFFFFF, b.rid & 0xFFFFFFFF, 1, b.species & 0xFFFFFFFF, 0))
        return bytes(out)

    def build_raid_ack_packet(self, token: int, req_id: int, code: int) -> bytes:
        return _pack_hdr(0xFC, token) + struct.pack('<BBHI', RX_SUBOP_RAID_ACK, 1, req_id & 0xFFFF, code & 0xFFFFFFFF)

    def build_raid_lobby_packet(self, token: int, boss: RaidSession | None) -> bytes:
        members = boss.members[:12] if (boss is not None and boss.active and self.is_event_on('raids')) else []
        rid = boss.rid if boss is not None else 0
        state = 1 if (boss is not None and not boss.lobby_only) else 0
        out = bytearray(_pack_hdr(0xFC, token) + struct.pack('<BBHQBB', RX_SUBOP_RAID_LOBBY, 2, 0, rid & 0xFFFFFFFFFFFFFFFF, state, len(members)))
        for mpid in members:
            out.extend(struct.pack('<BBBBIIIBBBB', mpid & 0xFF, 1, 0, 1, mpid, 0, 0, 0, 0, 0, 0))
        return bytes(out)

    def build_raid_spawn_packets(self, token: int, boss: RaidSession) -> list[bytes]:
        # msg_type=5: Boss Info; msg_type=1: Boss Spawned
        info = _pack_hdr(0xFC, token) + struct.pack(
            '<BBBHBBBBIB',
            RX_SUBOP_RAID_BOSS,
            1,
            5,
            boss.species & 0xFFFF,
            boss.form & 0xFF,
            boss.level & 0xFF,
            boss.type1 & 0xFF,
            boss.type2 & 0xFF,
            boss.weak_mask & 0xFFFFFFFF,
            boss.category & 0xFF,
        )
        mcount = min(12, len(boss.members))
        spawn = bytearray(_pack_hdr(0xFC, token))
        spawn.extend(
            struct.pack(
                '<BBBIBHHIBBBBIIHB',
                RX_SUBOP_RAID_BOSS,
                1,
                1,
                boss.rid & 0xFFFFFFFF,
                boss.driver_pid & 0xFF,
                boss.species & 0xFFFF,
                boss.level & 0xFFFF,
                boss.key & 0xFFFFFFFF,
                boss.form & 0xFF,
                boss.category & 0xFF,
                1,
                1,
                boss.max_hp & 0xFFFFFFFF,
                boss.hp & 0xFFFFFFFF,
                boss.rid & 0xFFFF,
                mcount,
            )
        )
        for mpid in boss.members[:mcount]:
            spawn.extend(struct.pack('<BBB', mpid & 0xFF, 0, 0))
        return [info, bytes(spawn)]

    def build_raid_hp_packet(self, token: int, boss: RaidSession, ack_seq: int, by_pid: int) -> bytes:
        return _pack_hdr(0xFC, token) + struct.pack(
            '<BBBIIIHH',
            RX_SUBOP_RAID_BOSS,
            1,
            2,
            boss.rid & 0xFFFFFFFF,
            boss.hp & 0xFFFFFFFF,
            boss.max_hp & 0xFFFFFFFF,
            ack_seq & 0xFFFF,
            by_pid & 0xFFFF,
        )

    def build_raid_end_packet(self, token: int, rid: int, result: int, reward: int, notice: str = '') -> bytes:
        nbytes = notice.encode('utf-8', 'replace')[:120]
        return _pack_hdr(0xFC, token) + struct.pack('<BBBIBBB', RX_SUBOP_RAID_BOSS, 1, 3, rid & 0xFFFFFFFF, result & 0xFF, reward & 0xFF, len(nbytes)) + nbytes

    def build_raid_catch_packet(self, token: int, rid: int, outcome: int) -> bytes:
        return _pack_hdr(0xFC, token) + struct.pack('<BBBIB', RX_SUBOP_RAID_BOSS, 1, 4, rid & 0xFFFFFFFF, outcome & 0xFF)

    def spawn_new_raid(self, driver_pid: int, players_by_pid: dict[int, object], *, start_now: bool = False) -> list[tuple[tuple[str, int], bytes]]:
        preset = RAID_BOSS_PRESETS[self._raid_preset_idx % len(RAID_BOSS_PRESETS)]
        self._raid_preset_idx += 1
        rid = self._next_rid
        self._next_rid += 1
        species, form, lvl, t1, t2, weak, cat, mhp, key = preset
        members = [p.pid for p in players_by_pid.values()]
        if driver_pid not in members and driver_pid > 0:
            members.insert(0, driver_pid)
        self.active_raid = RaidSession(
            rid=rid,
            key=key,
            species=species,
            form=form,
            level=lvl,
            type1=t1,
            type2=t2,
            weak_mask=weak,
            category=cat,
            max_hp=mhp,
            hp=mhp,
            driver_pid=driver_pid,
            members=members or [1],
            active=True,
            lobby_only=not start_now,
        )
        out: list[tuple[tuple[str, int], bytes]] = []
        for p in players_by_pid.values():
            out.append((p.addr, self.build_raid_spots_packet(p.token, self.active_raid)))
            out.append((p.addr, self.build_raid_lobby_packet(p.token, self.active_raid)))
            if start_now:
                for pkt in self.build_raid_spawn_packets(p.token, self.active_raid):
                    out.append((p.addr, pkt))
        return out

    def _handle_raid_ticket(self, pkt: bytes, player) -> list[tuple[tuple[str, int], bytes]]:
        if len(pkt) < 15:
            return []
        req_id = struct.unpack_from('<H', pkt, 11)[0]
        action = pkt[14]
        rec = self._ensure_record(player.trainer_id, player.name)
        if not self.is_event_on('raids'):
            return [(player.addr, self.build_raid_ticket_packet(player.token, req_id, action=1, status=6, tickets=rec.raid_tickets))]

        # Step 1: UI asks to buy 1 ticket -> server sends action=2 ONCE so client debits $250,000 in save.
        if action == 1:
            if rec.raid_tickets >= MAX_RAID_TICKETS:
                return [(player.addr, self.build_raid_ticket_packet(player.token, req_id, action=1, status=2, tickets=rec.raid_tickets))]
            raid_val = (250000 << 32) | ((req_id or 1) & 0xFFFFFFFF)
            return [(player.addr, self.build_raid_ticket_packet(player.token, req_id, action=2, status=0, tickets=rec.raid_tickets, raid_val=raid_val, w8=0xFFFFFFFF))]

        # Step 2: client reports save-money debit result (len=20, pkt[19]==1 on success) -> silent action=1 sync.
        if action == 2:
            debit_ok = len(pkt) >= 20 and pkt[19] != 0
            if debit_ok and rec.raid_tickets < MAX_RAID_TICKETS:
                rec.raid_tickets += 1
                self._save()
            return [(player.addr, self.build_raid_ticket_packet(player.token, req_id, action=1, status=0, tickets=rec.raid_tickets))]

        return [(player.addr, self.build_raid_ticket_packet(player.token, req_id, action=1, status=0, tickets=rec.raid_tickets))]

    def _handle_raid_lobby(self, pkt: bytes, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        if len(pkt) < 14:
            return []
        req_id = struct.unpack_from('<H', pkt, 11)[0]
        action = pkt[13]
        if not self.is_event_on('raids'):
            rec = self._ensure_record(player.trainer_id, player.name)
            return [
                (player.addr, self.build_raid_ack_packet(player.token, req_id, 0)),
                (player.addr, self.build_raid_ticket_packet(player.token, 0, action=1, status=6, tickets=rec.raid_tickets)),
            ]

        out: list[tuple[tuple[str, int], bytes]] = [(player.addr, self.build_raid_ack_packet(player.token, req_id, 1))]
        if action == 1:
            out.append((player.addr, self.build_raid_spots_packet(player.token, self.active_raid)))
            out.append((player.addr, self.build_raid_lobby_packet(player.token, self.active_raid)))
            return out
        if action == 2:
            self.player_raid_joined.discard(player.pid)
            if self.active_raid is not None and player.pid in self.active_raid.members:
                self.active_raid.members = [m for m in self.active_raid.members if m != player.pid]
            out.append((player.addr, self.build_raid_lobby_packet(player.token, self.active_raid)))
            return out
        if action in (3, 4):
            self.player_raid_joined.add(player.pid)
            if self.active_raid is None or not self.active_raid.active:
                out.extend(self.spawn_new_raid(player.pid, players_by_pid, start_now=(action == 4)))
            else:
                if player.pid not in self.active_raid.members:
                    self.active_raid.members.append(player.pid)
                if action == 4:
                    self.active_raid.lobby_only = False
                for p in players_by_pid.values():
                    out.append((p.addr, self.build_raid_lobby_packet(p.token, self.active_raid)))
                    if not self.active_raid.lobby_only:
                        for spkt in self.build_raid_spawn_packets(p.token, self.active_raid):
                            out.append((p.addr, spkt))
            return out
        return out

    def _handle_raid_combat(self, pkt: bytes, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        if len(pkt) < 23:
            return []
        action = pkt[14]
        rid = struct.unpack_from('<I', pkt, 15)[0]
        boss = self.active_raid
        if boss is None or not boss.active or (rid != 0 and rid != boss.rid):
            return []

        out: list[tuple[tuple[str, int], bytes]] = []
        if action == 1:  # Boss damage hit
            hit_seq, dmg = struct.unpack_from('<HH', pkt, 19)
            boss.hp = max(0, boss.hp - max(0, dmg))
            for p in players_by_pid.values():
                out.append((p.addr, self.build_raid_hp_packet(p.token, boss, hit_seq, player.pid)))
            if boss.hp == 0:
                boss.active = False
                reward = 2 if self.is_event_on('double_loot') else 1
                for p in players_by_pid.values():
                    rec = self._ensure_record(p.trainer_id, p.name)
                    rec.raid_tickets = min(MAX_RAID_TICKETS, rec.raid_tickets + reward)
                    if self.is_event_on('double_loot'):
                        rec.bag['1'] = min(99, rec.bag.get('1', 0) + 1)
                        out.append((p.addr, self._build_bag_packet(p.token, rec)))
                    out.append((p.addr, self.build_raid_ticket_packet(p.token, 0, action=1, status=0, tickets=rec.raid_tickets)))
                    out.append((p.addr, self.build_raid_end_packet(p.token, boss.rid, 1, reward, 'Raid Boss defeated!')))
                self._save()
            return out

        if action == 2:  # Catch attempt / finish
            for p in players_by_pid.values():
                out.append((p.addr, self.build_raid_catch_packet(p.token, boss.rid, 1)))
            return out
        return []

    # --- Nursery / Huevos (0x44..0x47 <-> 0xC4..0xC6) ---
    def _build_daycare_slots_packet(self, token: int, rec) -> bytes:
        entries = rec.nursery_slots[:MAX_NURSERY_SLOTS]
        out = bytearray(_pack_hdr(PKT_DAYCARE_SLOTS, token) + struct.pack('<HB', 0, len(entries)))
        for entry in entries:
            out.extend(
                struct.pack(
                    '<IBIIIIHH',
                    int(entry['slot_id']) & 0xFFFFFFFF,
                    int(entry.get('flags', 1)) & 0xFF,
                    0,
                    0,
                    int(entry.get('deposited_at', 0)) & 0xFFFFFFFF,
                    int(entry.get('ready_at', 0)) & 0xFFFFFFFF,
                    int(entry.get('species', 0)) & 0xFFFF,
                    int(entry.get('form', 0)) & 0xFFFF,
                )
            )
        return bytes(out)

    def _build_daycare_state_packet(self, token: int, seq: int, rec, *, now_ts: int) -> bytes:
        entries = rec.nursery_slots[:MAX_NURSERY_SLOTS]
        wait_s = 0 if self.is_event_on('instant_hatch') else DEFAULT_EGG_HATCH_SECS
        out = bytearray(
            _pack_hdr(PKT_DAYCARE_STATE, token)
            + struct.pack('<HIHHHB', seq & 0xFFFF, max(1, now_ts) & 0xFFFFFFFF, MAX_NURSERY_SLOTS, wait_s, MAX_NURSERY_SLOTS, len(entries))
        )
        eggs: list[tuple[int, int]] = []
        for entry in entries:
            ready_at = int(entry.get('deposited_at', now_ts)) if self.is_event_on('instant_hatch') else int(entry.get('ready_at', now_ts))
            flags = int(entry.get('flags', 1))
            if entry.get('egg_b64') and now_ts >= ready_at:
                eggs.append((int(entry.get('species', 1)) & 0xFFFF, int(entry['slot_id']) & 0xFFFFFFFF))
            out.extend(
                struct.pack(
                    '<IIIHBBB',
                    int(entry['slot_id']) & 0xFFFFFFFF,
                    int(entry.get('deposited_at', now_ts)) & 0xFFFFFFFF,
                    ready_at & 0xFFFFFFFF,
                    int(entry.get('species', 0)) & 0xFFFF,
                    int(entry.get('form', 0)) & 0xFF,
                    int(entry.get('level', 1)) & 0xFF,
                    flags & 0xFF,
                )
            )
        # Compatible pairs count (u8) + eggs count (u8)
        out.append(0)
        out.append(len(eggs) & 0xFF)
        for sp, sid in eggs:
            out.extend(struct.pack('<HI', sp, sid))
        return bytes(out)

    def _build_daycare_txn_packet(
        self,
        token: int,
        seq: int,
        code: int,
        txn_id: int,
        *,
        amount: int = 0,
        flags: int = 1,
        msg: str = '',
        pkm: bytes = b'',
    ) -> bytes:
        mbytes = msg.encode('utf-8', 'replace')[:96]
        return (
            _pack_hdr(PKT_DAYCARE_TXN, token)
            + struct.pack('<HBBIIIIBB', seq & 0xFFFF, code & 0xFF, 0, txn_id & 0xFFFFFFFF, 0, amount & 0xFFFFFFFF, 0, flags & 0xFF, len(mbytes))
            + mbytes
            + struct.pack('<H', len(pkm) & 0xFFFF)
            + pkm
        )

    def _handle_daycare(self, pkt_type: int, pkt: bytes, player) -> list[tuple[tuple[str, int], bytes]]:
        rec = self._ensure_record(player.trainer_id, player.name)
        now_ts = max(1, int(self.wall_clock()))

        if not self.is_event_on('nursery'):
            seq = struct.unpack_from('<H', pkt, 8)[0] if len(pkt) >= 10 else 0
            if pkt_type == PKT_DAYCARE_SYNC:
                return [(player.addr, self._build_daycare_state_packet(player.token, seq, rec, now_ts=now_ts))]
            if pkt_type in (PKT_DAYCARE_UPLOAD, PKT_DAYCARE_ACTION):
                return [(player.addr, self._build_daycare_txn_packet(player.token, seq, 1, 0, msg='Lumiose Nursery is disabled right now.'))]
            return [(player.addr, self._build_daycare_slots_packet(player.token, rec))]

        if pkt_type == PKT_DAYCARE_PROBE:
            return [(player.addr, self._build_daycare_slots_packet(player.token, rec))]

        if pkt_type == PKT_DAYCARE_SYNC:
            seq = struct.unpack_from('<H', pkt, 8)[0] if len(pkt) >= 10 else 0
            return [(player.addr, self._build_daycare_state_packet(player.token, seq, rec, now_ts=now_ts))]

        if pkt_type == PKT_DAYCARE_UPLOAD:
            # Header(8) + seq(2) + fee(4) + flags(1) + 3 * (u16 len + PKM)
            if len(pkt) < 17:
                return []
            seq, fee, _flags = struct.unpack_from('<HIB', pkt, 8)
            pos = 15
            blocks: list[bytes] = []
            for _ in range(3):
                if pos + 2 > len(pkt):
                    break
                blen = struct.unpack_from('<H', pkt, pos)[0]
                pos += 2
                if pos + blen > len(pkt):
                    break
                blocks.append(pkt[pos : pos + blen])
                pos += blen
            egg_blob = next((b for b in reversed(blocks) if len(b) == PKM_BLOCK_SIZE), b'')
            if len(egg_blob) != PKM_BLOCK_SIZE or len(rec.nursery_slots) >= MAX_NURSERY_SLOTS:
                return [(player.addr, self._build_daycare_txn_packet(player.token, seq, 1, 0, msg='Nursery is full or invalid Pokemon data.'))]

            self._next_nursery_id += 1
            slot_id = self._next_nursery_id
            wait_s = 0 if self.is_event_on('instant_hatch') else DEFAULT_EGG_HATCH_SECS
            rec.nursery_slots.append({
                'slot_id': slot_id,
                'deposited_at': now_ts,
                'ready_at': now_ts + wait_s,
                'species': 1,
                'form': 0,
                'level': 1,
                'flags': 1,
                'egg_b64': base64.b64encode(egg_blob).decode('ascii'),
            })
            self._save()
            return [
                (player.addr, self._build_daycare_slots_packet(player.token, rec)),
                (player.addr, self._build_daycare_state_packet(player.token, seq, rec, now_ts=now_ts)),
                (player.addr, self._build_daycare_txn_packet(player.token, seq, 0, slot_id, amount=fee, msg='Egg laid in Nursery!')),
            ]

        if pkt_type == PKT_DAYCARE_ACTION:
            if len(pkt) < 17:
                return []
            seq, cmd = struct.unpack_from('<HB', pkt, 8)
            if cmd == 6:  # Request pending egg PKM
                slot_id = struct.unpack_from('<I', pkt, 11)[0] if len(pkt) >= 15 else 0
                target = next((s for s in rec.nursery_slots if slot_id == 0 or s['slot_id'] == slot_id), None)
                if target is None:
                    return [(player.addr, self._build_daycare_txn_packet(player.token, seq, 1, 0, msg='No egg waiting in Nursery.'))]
                ready_at = target['deposited_at'] if self.is_event_on('instant_hatch') else target['ready_at']
                if now_ts < ready_at:
                    rem = ready_at - now_ts
                    return [(player.addr, self._build_daycare_txn_packet(player.token, seq, 1, 0, msg=f'Egg not ready yet ({rem}s).'))]
                pkm_bytes = base64.b64decode(target.get('egg_b64', ''))
                if len(pkm_bytes) != PKM_BLOCK_SIZE:
                    return [(player.addr, self._build_daycare_txn_packet(player.token, seq, 1, 0, msg='Corrupt egg data.'))]
                self._next_nursery_txn += 1
                txn_id = self._next_nursery_txn
                self.pending_nursery_txns[txn_id] = (target['slot_id'], rec.trainer_id, target.get('egg_b64', ''), now_ts)
                return [(player.addr, self._build_daycare_txn_packet(player.token, seq, 0, txn_id, msg='Take Egg', pkm=pkm_bytes))]

            if cmd == 3:  # Cancel/Return slot
                slot_or_txn = struct.unpack_from('<I', pkt, 11)[0]
                rec.nursery_slots = [s for s in rec.nursery_slots if s['slot_id'] != slot_or_txn]
                self._save()
                return [
                    (player.addr, self._build_daycare_slots_packet(player.token, rec)),
                    (player.addr, self._build_daycare_txn_packet(player.token, seq, 0, slot_or_txn, msg='Nursery updated.')),
                ]

            # Settle commit (0x4C / 0 / 1) or rollback
            txn_id = struct.unpack_from('<I', pkt, 11)[0]
            pending = self.pending_nursery_txns.pop(txn_id, None)
            if pending is not None:
                sid, _, _, _ = pending
                rec.nursery_slots = [s for s in rec.nursery_slots if s['slot_id'] != sid]
                self._save()
            return [
                (player.addr, self._build_daycare_slots_packet(player.token, rec)),
                (player.addr, self._build_daycare_txn_packet(player.token, seq, 0, txn_id, msg='Confirmed.')),
            ]
        return []

    # --- Chat, Automatic Scheduler & Console Commands ---
    def _format_events_line(self) -> str:
        parts = [f'{k}={"ON" if v else "OFF"}' for k, v in sorted(self.events.items())]
        return 'Eventos: ' + ', '.join(parts)

    def _apply_event_change(
        self,
        ev_key: str,
        enabled: bool,
        players_by_pid: dict[int, object],
        *,
        notice: str,
    ) -> list[tuple[tuple[str, int], bytes]]:
        """Persist event toggle and push updated settings, raid access, and shiny charm."""
        self.events[ev_key] = enabled
        out: list[tuple[tuple[str, int], bytes]] = []
        for p in players_by_pid.values():
            rec = self._ensure_record(p.trainer_id, p.name)
            out.append((p.addr, self.build_settings_packet(p.token)))
            out.append((p.addr, build_server_notice(p.token, notice)))
            if ev_key == 'raids':
                t_status = 0 if enabled else 6
                out.append((p.addr, self.build_raid_ticket_packet(p.token, 0, action=1, status=t_status, tickets=rec.raid_tickets)))
            if ev_key == 'shiny_event' and enabled:
                rec.bag['1'] = min(99, rec.bag.get('1', 0) + 1)
                out.append((p.addr, self._build_bag_packet(p.token, rec)))
        self._save()
        return out

    def _stop_auto_bonus(
        self,
        players_by_pid: dict[int, object],
        now: float,
        *,
        notice_prefix: str = '[AUTO] Finalizo',
    ) -> list[tuple[tuple[str, int], bytes]]:
        ev_key = self.auto_active_event
        if not ev_key:
            return []
        self.auto_active_event = None
        self.auto_ends_at = 0.0
        self.auto_next_event_at = now + self.auto_interval_secs
        label = AUTO_EVENT_LABELS.get(ev_key, ev_key)
        return self._apply_event_change(ev_key, False, players_by_pid, notice=f'{notice_prefix} {label}.')

    def _start_auto_bonus(
        self,
        players_by_pid: dict[int, object],
        now: float,
    ) -> tuple[list[tuple[tuple[str, int], bytes]], str]:
        out: list[tuple[tuple[str, int], bytes]] = []
        if self.auto_active_event is not None:
            out.extend(self._stop_auto_bonus(players_by_pid, now, notice_prefix='[AUTO] Cambio de evento, finalizo'))
        ev_key = AUTO_EVENT_ROTATION[self.auto_idx % len(AUTO_EVENT_ROTATION)]
        self.auto_idx = (self.auto_idx + 1) % len(AUTO_EVENT_ROTATION)
        self.auto_active_event = ev_key
        self.auto_ends_at = now + self.auto_duration_secs
        self.auto_next_event_at = self.auto_ends_at + self.auto_interval_secs
        dur_min = max(1, round(self.auto_duration_secs / 60))
        label = AUTO_EVENT_LABELS.get(ev_key, ev_key)
        notice = f'[AUTO] Happy Hour: {label} activo por {dur_min} min!'
        out.extend(self._apply_event_change(ev_key, True, players_by_pid, notice=notice))
        return out, notice

    def _format_auto_status(self, now: float) -> str:
        state = 'ON' if self.is_event_on('auto_events') else 'OFF'
        int_m = max(1, round(self.auto_interval_secs / 60))
        dur_m = max(1, round(self.auto_duration_secs / 60))
        raid_m = round(self.auto_raid_secs / 60) if self.auto_raid_secs > 0 else 0
        if self.auto_active_event:
            rem_m = max(0, int((self.auto_ends_at - now + 59) // 60))
            bonus_txt = f'activo={self.auto_active_event} ({rem_m}m)'
        elif self.auto_next_event_at > now:
            wait_m = max(1, int((self.auto_next_event_at - now + 59) // 60))
            bonus_txt = f'proximo en {wait_m}m'
        else:
            bonus_txt = 'esperando jugadores'
        raid_txt = f'{raid_m}m' if raid_m > 0 else 'OFF'
        return f'AutoEventos={state} ({bonus_txt}) | cada {int_m}m x {dur_m}m | auto-raid={raid_txt}'

    def tick(self, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        """Advance automatic rotating bonus events and automatic raid spawns."""
        now = self.wall_clock()
        out: list[tuple[tuple[str, int], bytes]] = []

        if self.auto_active_event is not None and now >= self.auto_ends_at:
            out.extend(self._stop_auto_bonus(players_by_pid, now))

        if not self.is_event_on('auto_events') or not players_by_pid:
            return out

        dirty = False
        if self.auto_next_event_at <= 0.0:
            self.auto_next_event_at = now + self.auto_interval_secs
            dirty = True
        if self.auto_raid_secs > 0 and self.auto_next_raid_at <= 0.0:
            self.auto_next_raid_at = now + self.auto_raid_secs
            dirty = True

        if self.auto_active_event is None and now >= self.auto_next_event_at:
            bonus_out, _ = self._start_auto_bonus(players_by_pid, now)
            out.extend(bonus_out)
            dirty = False

        if self.auto_raid_secs > 0 and self.is_event_on('raids'):
            if self.active_raid is not None and self.active_raid.active:
                self.auto_next_raid_at = now + self.auto_raid_secs
            elif now >= self.auto_next_raid_at:
                driver = next(iter(players_by_pid), 1)
                out.extend(self.spawn_new_raid(driver, players_by_pid, start_now=False))
                boss = self.active_raid
                if boss is not None:
                    sname = RAID_SPECIES_NAMES.get(boss.species, f'#{boss.species}')
                    notice = f'[AUTO] Raid Boss disponible: {sname} Nv.{boss.level}!'
                    for p in players_by_pid.values():
                        out.append((p.addr, build_server_notice(p.token, notice)))
                self.auto_next_raid_at = now + self.auto_raid_secs
                dirty = True

        if dirty:
            self._save()
        return out

    def _apply_command(
        self,
        raw_cmd: str,
        players_by_pid: dict[int, object],
        *,
        sender=None,
    ) -> tuple[list[tuple[tuple[str, int], bytes]], str]:
        text = raw_cmd.strip()
        if text.startswith('/'):
            text = text[1:].strip()
        if not text:
            return [], ''
        parts = text.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ('help', 'ayuda', '?'):
            msg = 'Comandos: /events | /event <nombre> <on|off> | /autoevent [status|now|stop] | /time [day|night|HH:MM|pause|auto] | /race [reset] | /gift | /charm | /tickets | /raid | /say'
            return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg

        if cmd in ('events', 'eventos'):
            msg = self._format_events_line()
            return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg

        if cmd in ('autoevent', 'autoevents'):
            now = self.wall_clock()
            sub = args[0].lower() if args else 'status'
            if sub == 'status':
                msg = self._format_auto_status(now)
                return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg
            if sub in ('now', 'next', 'ya'):
                if not self.is_event_on('auto_events'):
                    self.events['auto_events'] = True
                out, msg = self._start_auto_bonus(players_by_pid, now)
                return out, msg
            if sub in ('stop', 'clear'):
                if self.auto_active_event is None:
                    msg = 'No hay ningun evento automatico activo ahora.'
                    return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg
                out = self._stop_auto_bonus(players_by_pid, now, notice_prefix='[AUTO] Detenido:')
                msg = 'Evento automatico detenido.'
                return out, msg
            if sub == 'interval' and len(args) >= 2 and args[1].isdigit():
                mins = max(1, min(1440, int(args[1])))
                self.auto_interval_secs = mins * 60
                self.auto_next_event_at = now + self.auto_interval_secs
                self._save()
                msg = f'[AUTO] Intervalo de eventos configurado cada {mins} min.'
                return [(p.addr, build_server_notice(p.token, msg)) for p in players_by_pid.values()], msg
            if sub == 'duration' and len(args) >= 2 and args[1].isdigit():
                mins = max(1, min(240, int(args[1])))
                self.auto_duration_secs = mins * 60
                self._save()
                msg = f'[AUTO] Duracion de eventos configurada en {mins} min.'
                return [(p.addr, build_server_notice(p.token, msg)) for p in players_by_pid.values()], msg
            if sub == 'raid' and len(args) >= 2 and args[1].isdigit():
                mins = max(0, min(1440, int(args[1])))
                self.auto_raid_secs = mins * 60
                self.auto_next_raid_at = (now + self.auto_raid_secs) if mins > 0 else 0.0
                self._save()
                msg = '[AUTO] Auto-raids desactivados.' if mins == 0 else f'[AUTO] Auto-raids cada {mins} min.'
                return [(p.addr, build_server_notice(p.token, msg)) for p in players_by_pid.values()], msg
            msg = 'Uso: /autoevent [status|now|stop|interval <min>|duration <min>|raid <min>]'
            return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg

        if cmd in ('event', 'evento'):
            if len(args) < 2:
                msg = 'Uso: /event <raids|nursery|gift|auto|shiny|hatch|loot> <on|off>'
                return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg
            a0, a1 = args[0].lower(), args[1].lower()
            if a0 in ('on', 'off', '1', '0', 'si', 'no'):
                state_tok, name_tok = a0, a1
            else:
                name_tok, state_tok = a0, a1
            ev_key = EVENT_ALIASES.get(name_tok)
            if ev_key is None or state_tok not in ('on', 'off', '1', '0', 'si', 'no', 'true', 'false'):
                msg = f'Evento o estado invalido. {self._format_events_line()}'
                return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg

            enabled = state_tok in ('on', '1', 'si', 'true')
            now = self.wall_clock()
            out: list[tuple[tuple[str, int], bytes]] = []
            if ev_key == 'auto_events':
                if enabled:
                    self.auto_next_event_at = now + self.auto_interval_secs
                    if self.auto_raid_secs > 0:
                        self.auto_next_raid_at = now + self.auto_raid_secs
                elif self.auto_active_event is not None:
                    out.extend(self._stop_auto_bonus(players_by_pid, now, notice_prefix='[AUTO] Detenido:'))
            elif not enabled and self.auto_active_event == ev_key:
                self.auto_active_event = None
                self.auto_ends_at = 0.0
                self.auto_next_event_at = now + self.auto_interval_secs

            notice = f'[EVENTO] {ev_key} -> {"ACTIVADO" if enabled else "DESACTIVADO"}'
            out.extend(self._apply_event_change(ev_key, enabled, players_by_pid, notice=notice))
            return out, notice

        if cmd == 'gift':
            if not args or args[0].lower() == 'list':
                codes = [f'{k}({v["kind"]}x{v["qty"]})' for k, v in sorted(self.gifts.items()) if v.get('active', True)]
                msg = 'Gifts activos: ' + (', '.join(codes) if codes else 'ninguno')
                return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg
            sub = args[0].lower()
            if sub == 'add' and len(args) >= 3:
                code = args[1].strip().upper()[:32]
                kind = args[2].strip().lower()
                if kind not in ('charm', 'tickets', 'bundle'):
                    msg = 'Tipo invalido (usa charm, tickets o bundle).'
                    return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg
                qty = max(1, min(10, int(args[3]))) if len(args) >= 4 and args[3].isdigit() else 1
                self.gifts[code] = {'kind': kind, 'qty': qty, 'label': f'{code} ({kind} x{qty})', 'active': True, 'claimed_by': []}
                self._save()
                msg = f'[EVENTO] Nuevo Mystery Gift: {code} ({kind} x{qty})'
                out = [(p.addr, build_server_notice(p.token, msg)) for p in players_by_pid.values()]
                return out, msg
            if sub in ('del', 'off', 'remove') and len(args) >= 2:
                code = args[1].strip().upper()[:32]
                if code in self.gifts:
                    self.gifts[code]['active'] = False
                    self._save()
                    msg = f'Gift {code} desactivado.'
                else:
                    msg = f'Gift {code} no encontrado.'
                return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg

        if cmd == 'charm':
            qty = max(1, min(10, int(args[0]))) if args and args[0].isdigit() else 1
            out = []
            for p in players_by_pid.values():
                rec = self._ensure_record(p.trainer_id, p.name)
                rec.bag['1'] = min(99, rec.bag.get('1', 0) + qty)
                out.append((p.addr, self._build_bag_packet(p.token, rec)))
                out.append((p.addr, build_server_notice(p.token, f'Lumiose Shiny Charm x{qty} entregado!')))
            self._save()
            return out, f'Lumiose Shiny Charm x{qty} entregado a {len(players_by_pid)} jugador(es).'

        if cmd == 'tickets':
            qty = max(1, min(10, int(args[0]))) if args and args[0].isdigit() else 1
            out = []
            for p in players_by_pid.values():
                rec = self._ensure_record(p.trainer_id, p.name)
                rec.raid_tickets = min(MAX_RAID_TICKETS, rec.raid_tickets + qty)
                out.append((p.addr, self.build_raid_ticket_packet(p.token, 0, action=1, status=0, tickets=rec.raid_tickets)))
                out.append((p.addr, build_server_notice(p.token, f'Raid Tickets +{qty} (total: {rec.raid_tickets})')))
            self._save()
            return out, f'Raid Tickets +{qty} entregado a {len(players_by_pid)} jugador(es).'

        if cmd == 'raid':
            sub = args[0].lower() if args else 'spawn'
            if sub == 'clear':
                self.active_raid = None
                out = [(p.addr, self.build_raid_spots_packet(p.token, None)) for p in players_by_pid.values()]
                for p in players_by_pid.values():
                    out.append((p.addr, build_server_notice(p.token, 'Raid cerrado.')))
                return out, 'Raid cerrado.'
            if not self.is_event_on('raids'):
                msg = 'Raids desactivados (/event raids on primero).'
                return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg
            driver = sender.pid if sender is not None else next(iter(players_by_pid), 1)
            out = self.spawn_new_raid(driver, players_by_pid, start_now=True)
            boss = self.active_raid
            if boss:
                sname = RAID_SPECIES_NAMES.get(boss.species, f'#{boss.species}')
                msg = f'[RAID] Aparecio {sname} Nv.{boss.level} (HP {boss.max_hp})!'
            else:
                msg = 'Raid iniciado.'
            for p in players_by_pid.values():
                out.append((p.addr, build_server_notice(p.token, msg)))
            return out, msg

        if cmd == 'say' and args:
            msg = ' '.join(args)
            return [(p.addr, build_server_notice(p.token, msg)) for p in players_by_pid.values()], f'[SERVER] {msg}'

        msg = f'Comando desconocido: /{cmd}. Usa /help.'
        return ([(sender.addr, build_server_notice(sender.token, msg))] if sender else []), msg

    def handle_chat(
        self,
        msg_bytes: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        """Intercept /commands and /p party chat. Returns None for ordinary global room chat."""
        text = msg_bytes.decode('utf-8', 'replace').strip()
        if not text.startswith('/'):
            return None

        if text.lower().startswith('/p '):
            body = text[3:].strip()
            if not body:
                return []
            party = self.parties.get(self.player_party.get(player.pid, -1))
            if party is None:
                return [(player.addr, build_server_notice(player.token, 'No estas en un Party.'))]
            pname = b'[Party] ' + _clean_ascii(player.name, 16)
            return [
                (m.addr, build_server_notice(m.token, body, sender_name=pname))
                for mpid in party.members
                if (m := players_by_pid.get(mpid)) is not None and m.pid != player.pid
            ]

        cmd_parts = text[1:].split()
        cmd_head = cmd_parts[0].lower() if cmd_parts else ''
        is_public_auto = cmd_head in ('autoevent', 'autoevents') and (len(cmd_parts) == 1 or cmd_parts[1].lower() == 'status')
        if cmd_head in ('help', 'ayuda', '?', 'events', 'eventos') or is_public_auto or self.is_admin(player):
            replies, _ = self._apply_command(text, players_by_pid, sender=player)
            return replies
        return [(player.addr, build_server_notice(player.token, 'Solo el host puede usar comandos de admin.'))]

    def handle_console_command(self, line: str, players_by_pid: dict[int, object]) -> tuple[list[tuple[tuple[str, int], bytes]], str]:
        return self._apply_command(line, players_by_pid, sender=None)

    def handle_packet(self, pkt_type: int, pkt: bytes, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]] | None:
        if pkt_type in MARKET_TX_OPCODES:
            # Market is intentionally disabled; keeping 0xE8 unacked makes client show unavailable.
            return []
        if pkt_type in (PKT_DAYCARE_PROBE, PKT_DAYCARE_SYNC, PKT_DAYCARE_UPLOAD, PKT_DAYCARE_ACTION):
            return self._handle_daycare(pkt_type, pkt, player)
        return None

    def handle_extension(self, subop: int, pkt: bytes, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]] | None:
        if subop == TX_SUBOP_SETTINGS:
            return [(player.addr, self.build_settings_packet(player.token))]
        if subop == TX_SUBOP_MYSTERY_GIFT:
            return self._handle_mystery_gift(pkt, player)
        if subop == TX_SUBOP_PARTY:
            return self._handle_party(pkt, player, players_by_pid)
        if subop == TX_SUBOP_RAID_TICKET:
            return self._handle_raid_ticket(pkt, player)
        if subop == TX_SUBOP_RAID_LOBBY:
            return self._handle_raid_lobby(pkt, player, players_by_pid)
        if subop == TX_SUBOP_RAID_COMBAT:
            return self._handle_raid_combat(pkt, player, players_by_pid)
        return None
