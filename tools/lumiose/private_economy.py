"""Server-side [mail], [trade], and [wonder] (Wonder Trade) hubs for Lumiose Private Server."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import struct
import time
from typing import Callable


PKT_EXTENSION = 0x7D
PKT_EXTENSION_OUT = 0xFC

# [mail] TX / RX
PKT_MAIL_HELLO = 0x58
PKT_MAIL_LIST_REQ = 0x59
PKT_MAIL_SEND = 0x5A
PKT_MAIL_ACTION = 0x5B
PKT_MAIL_DIR_REQ = 0x5C

PKT_MAIL_SUMMARY_OUT = 0xD8
PKT_MAIL_LIST_OUT = 0xD9
PKT_MAIL_DETAIL_OUT = 0xDA
PKT_MAIL_ACK_OUT = 0xDB
PKT_MAIL_NOTIFY_OUT = 0xDC
PKT_MAIL_DIR_OUT = 0xDD

# [wonder] TX / RX
PKT_WONDER_OP = 0x5E
SUBOP_WONDER_POLL_SETTLE = 0x1F
SUBOP_WONDER_OUT = 0x25

# [trade] TX / RX
PKT_TRADE_INVITE = 0x60
PKT_TRADE_RESPONSE = 0x61
PKT_TRADE_OFFER = 0x62
PKT_TRADE_READY = 0x63
PKT_TRADE_CHAT = 0x64
PKT_TRADE_DONE = 0x65
PKT_TRADE_CHUNK = 0x66

PKT_TRADE_STATUS_OUT = 0xE0
PKT_TRADE_START_OUT = 0xE1
PKT_TRADE_OFFER_OUT = 0xE2
PKT_TRADE_READY_OUT = 0xE3
PKT_TRADE_COMMIT_OUT = 0xE4
PKT_TRADE_DONE_OUT = 0xE5
PKT_TRADE_CHAT_OUT = 0xE6
PKT_TRADE_CHUNK_OUT = 0xE7

# [dexrace] & [story] TX / RX
PKT_STORY_REPORT = 0x38
SUBOP_STORY_PODIUM_OUT = 0x09
SUBOP_STORY_POLL = 0x16
SUBOP_DEXRACE_IN = 0x24
SUBOP_DEXRACE_BOARD_OUT = 0x2C
SUBOP_DEXRACE_CONGRATS_OUT = 0x37

# Mainline Z-A reward item IDs delivered via [mail]
ITEM_RARE_CANDY = 50
ITEM_ABILITY_CAPSULE = 645
ITEM_ABILITY_PATCH = 1606

PKM_BLOB_SIZE = 0x158  # 344 bytes
MAX_MAIL_INBOX = 100
MAX_MAIL_ITEMS = 3
MAX_MAIL_PKM = 3
MAX_MAIL_MSG = 200
MAX_MAIL_SUBJECT = 43

# Standard PK8/PK9 block position permutation table: slot index containing Block A (index 0)
_BLOCK_A_SLOT = (
    0, 0, 0, 0, 0, 0,
    1, 1, 2, 3, 2, 3,
    1, 1, 2, 3, 2, 3,
    1, 1, 2, 3, 2, 3,
    0, 0, 0, 0, 0, 0,
    1, 1,
)


MAGIC = b'ZA'
PROTO_VERSION = 1


def _pack_hdr(pkt_type: int, token: int) -> bytes:
    return struct.pack('<2sBBI', MAGIC, PROTO_VERSION, pkt_type & 0xFF, token & 0xFFFFFFFF)


def _pack_fc(token: int, subop: int, payload: bytes = b'') -> bytes:
    return _pack_hdr(PKT_EXTENSION_OUT, token) + bytes([subop & 0xFF]) + payload


def extract_pkm_ids(blob: bytes) -> tuple[int, int, int]:
    """Extract (ec, pid, species) from a 344-byte Gen 8/9 encrypted PKM blob."""
    if len(blob) < PKM_BLOB_SIZE:
        return 0, 0, 0
    ec = struct.unpack_from('<I', blob, 0)[0]
    if ec == 0:
        return 0, 0, 0
    # Decrypt 0x140 bytes starting at offset 8
    raw = bytearray(blob[8:8 + 0x140])
    seed = ec
    for off in range(0, len(raw), 2):
        seed = (seed * 0x41C64E6D + 0x6073) & 0xFFFFFFFF
        word = struct.unpack_from('<H', raw, off)[0] ^ ((seed >> 16) & 0xFFFF)
        struct.pack_into('<H', raw, off, word)
    block_a_idx = _BLOCK_A_SLOT[(ec >> 13) & 0x1F]
    block_a = raw[block_a_idx * 0x50:(block_a_idx + 1) * 0x50]
    species = struct.unpack_from('<H', block_a, 0)[0]
    pid = struct.unpack_from('<I', block_a, 0x14)[0]
    return ec, pid, species


def _clean_text_bytes(raw: bytes, maxlen: int) -> bytes:
    filtered = bytes(b if 32 <= b < 127 else 0x20 for b in raw[:maxlen])
    return filtered


class MailHub:
    """Persistent [mail] inbox/sentbox, contacts directory, and attachments delivery."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], float],
        find_online_by_tid: Callable[[dict[int, object], str], object | None],
        save_state: Callable[[], None],
        records_ref: dict[str, object],
        notice_builder: Callable[[int, str], bytes] | None = None,
    ) -> None:
        self.wall_clock = wall_clock
        self.find_online_by_tid = find_online_by_tid
        self.save_state = save_state
        self.records_ref = records_ref
        self.notice_builder = notice_builder

        self.next_mail_id: int = 1
        self.inbox: dict[str, list[dict]] = {}
        self.sent: dict[str, list[dict]] = {}

    def export_state(self) -> dict:
        return {
            'next_mail_id': self.next_mail_id,
            'inbox': self.inbox,
            'sent': self.sent,
        }

    def load_state(self, raw: object) -> None:
        if not isinstance(raw, dict):
            return
        self.next_mail_id = max(1, int(raw.get('next_mail_id', 1)))
        for box_name in ('inbox', 'sent'):
            src = raw.get(box_name, {})
            if not isinstance(src, dict):
                continue
            dst: dict[str, list[dict]] = {}
            for tid, items in src.items():
                if isinstance(tid, str) and isinstance(items, list):
                    dst[tid] = [dict(m) for m in items if isinstance(m, dict)][:MAX_MAIL_INBOX]
            setattr(self, box_name, dst)

    def unread_count(self, tid: str) -> int:
        return sum(1 for m in self.inbox.get(tid, []) if (int(m.get('flags', 0)) & 1) == 0)

    def build_summary_packet(self, token: int, tid: str) -> bytes:
        unread = min(255, self.unread_count(tid))
        return _pack_hdr(PKT_MAIL_SUMMARY_OUT, token) + struct.pack('<BBBB', 1, unread, 0, 0)

    def build_notify_packet(self, token: int, sender_name: str, unread: int) -> bytes:
        sb = _clean_text_bytes(sender_name.encode('ascii', 'replace'), 24) or b'Server'
        return _pack_hdr(PKT_MAIL_NOTIFY_OUT, token) + struct.pack('<IBB', 0, min(255, unread), len(sb)) + sb

    def _build_list_packet(self, token: int, seq: int, box: int, offset: int, tid: str) -> bytes:
        items = self.sent.get(tid, []) if box == 1 else self.inbox.get(tid, [])
        # Show newest first
        ordered = list(reversed(items))
        total = len(ordered)
        page = ordered[offset:offset + 12]
        next_off = offset + len(page) if (offset + len(page)) < total else 0
        unread = min(255, self.unread_count(tid))
        has_more = 1 if next_off > 0 else 0
        body = bytearray(
            struct.pack(
                '<HIBHHBB',
                seq & 0xFFFF,
                total & 0xFFFFFFFF,
                box & 0xFF,
                offset & 0xFFFF,
                next_off & 0xFFFF,
                has_more if box == 1 else unread,
                len(page) & 0xFF,
            )
        )
        for m in page:
            peer = m.get('to_name', 'Trainer') if box == 1 else m.get('from_name', 'Server')
            peer_b = _clean_text_bytes(str(peer).encode('ascii', 'replace'), 24)
            msg_s = str(m.get('msg', ''))
            subj_b = _clean_text_bytes(msg_s.encode('ascii', 'replace'), MAX_MAIL_SUBJECT)
            body.extend(
                struct.pack(
                    '<IIBIB',
                    int(m.get('id', 0)) & 0xFFFFFFFF,
                    int(m.get('ts', 0)) & 0xFFFFFFFF,
                    int(m.get('flags', 0)) & 0xFF,
                    int(m.get('money', 0)) & 0xFFFFFFFF,
                    len(peer_b) & 0xFF,
                )
            )
            body.extend(peer_b)
            body.append(len(subj_b) & 0xFF)
            body.extend(subj_b)
        return _pack_hdr(PKT_MAIL_LIST_OUT, token) + bytes(body)

    def _build_detail_packet(self, token: int, seq: int, status: int, mail: dict | None) -> bytes:
        if mail is None or status != 0:
            return _pack_hdr(PKT_MAIL_DETAIL_OUT, token) + struct.pack('<HBIIBIBBB', seq & 0xFFFF, status & 0xFF, 0, 0, 0, 0, 0, 0, 0)

        items = mail.get('items', [])[:MAX_MAIL_ITEMS]
        msg_b = _clean_text_bytes(str(mail.get('msg', '')).encode('ascii', 'replace'), 100)
        pkm_b64s = mail.get('pkm_blobs_b64', [])[:MAX_MAIL_PKM]
        pkm_blobs = []
        for b64 in pkm_b64s:
            try:
                raw = base64.b64decode(b64)
                if len(raw) == PKM_BLOB_SIZE:
                    pkm_blobs.append(raw)
            except ValueError:
                continue

        body = bytearray(
            struct.pack(
                '<HBIIBIB',
                seq & 0xFFFF,
                0,
                int(mail.get('id', 0)) & 0xFFFFFFFF,
                int(mail.get('ts', 0)) & 0xFFFFFFFF,
                int(mail.get('flags', 0)) & 0xFF,
                int(mail.get('money', 0)) & 0xFFFFFFFF,
                len(items) & 0xFF,
            )
        )
        for item_id, qty in items:
            body.extend(struct.pack('<HH', int(item_id) & 0xFFFF, int(qty) & 0xFFFF))
        body.append(len(msg_b) & 0xFF)
        body.extend(msg_b)
        body.append(len(pkm_blobs) & 0xFF)
        for blob in pkm_blobs:
            body.extend(struct.pack('<H', PKM_BLOB_SIZE))
            body.extend(blob)
        return _pack_hdr(PKT_MAIL_DETAIL_OUT, token) + bytes(body)

    def _build_ack_packet(self, token: int, seq: int, status: int, mail: dict | None) -> bytes:
        if mail is None or status != 0:
            return _pack_hdr(PKT_MAIL_ACK_OUT, token) + struct.pack('<HBIIBIBBBBBB', seq & 0xFFFF, status & 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        items = mail.get('items', [])[:MAX_MAIL_ITEMS]
        from_b = _clean_text_bytes(str(mail.get('from_name', 'Server')).encode('ascii', 'replace'), 24)
        to_b = _clean_text_bytes(str(mail.get('to_name', 'Trainer')).encode('ascii', 'replace'), 24)
        msg_b = _clean_text_bytes(str(mail.get('msg', '')).encode('ascii', 'replace'), MAX_MAIL_MSG)
        pkm_b64s = mail.get('pkm_blobs_b64', [])[:MAX_MAIL_PKM]
        pkm_summaries: list[tuple[int, int, int, bytes]] = []
        for b64 in pkm_b64s:
            try:
                raw = base64.b64decode(b64)
            except ValueError:
                continue
            if len(raw) == PKM_BLOB_SIZE:
                _, _, species = extract_pkm_ids(raw)
                pkm_summaries.append((species or 1, 50, 0, b'Pokemon'))

        body = bytearray(
            struct.pack(
                '<HBIIBIB',
                seq & 0xFFFF,
                0,
                int(mail.get('id', 0)) & 0xFFFFFFFF,
                int(mail.get('ts', 0)) & 0xFFFFFFFF,
                int(mail.get('flags', 0)) & 0xFF,
                int(mail.get('money', 0)) & 0xFFFFFFFF,
                len(items) & 0xFF,
            )
        )
        for item_id, qty in items:
            body.extend(struct.pack('<HH', int(item_id) & 0xFFFF, int(qty) & 0xFFFF))
        body.append(len(from_b) & 0xFF)
        body.extend(from_b)
        body.append(len(to_b) & 0xFF)
        body.extend(to_b)
        body.append(len(msg_b) & 0xFF)
        body.extend(msg_b)
        body.append(len(pkm_summaries) & 0xFF)
        for spec, lvl, flags, nick_b in pkm_summaries:
            body.extend(struct.pack('<HHBB', spec & 0xFFFF, lvl & 0xFFFF, flags & 0xFF, len(nick_b) & 0xFF))
            body.extend(nick_b)
        return _pack_hdr(PKT_MAIL_ACK_OUT, token) + bytes(body)

    def _build_directory_packet(self, token: int, seq: int, sender_tid: str, players_by_pid: dict[int, object]) -> bytes:
        entries = []
        for tid, rec in self.records_ref.items():
            if tid == sender_tid:
                continue
            name = getattr(rec, 'name', 'Trainer')
            peer = self.find_online_by_tid(players_by_pid, tid)
            online = 1 if peer is not None else 0
            tid_raw = bytes.fromhex(tid) if len(tid) == 32 else tid.encode('ascii', 'replace')
            tid_u64 = int.from_bytes((tid_raw + b'\x00' * 8)[:8], 'little')
            entries.append((tid_u64, online, name))
            if len(entries) >= 40:
                break
        body = bytearray(struct.pack('<HB', seq & 0xFFFF, len(entries) & 0xFF))
        for tid_u64, online, name in entries:
            nb = _clean_text_bytes(str(name).encode('ascii', 'replace'), 24)
            body.extend(struct.pack('<QHB', tid_u64, online & 0xFFFF, len(nb) & 0xFF))
            body.extend(nb)
        return _pack_hdr(PKT_MAIL_DIR_OUT, token) + bytes(body)

    def send_system_mail(
        self,
        *,
        to_tid: str,
        sender_name: str,
        msg: str,
        money: int = 0,
        items: list[tuple[int, int]] | None = None,
        pkm_blobs: list[bytes] | None = None,
        players_by_pid: dict[int, object] | None = None,
    ) -> tuple[dict, list[tuple[tuple[str, int], bytes]]]:
        """Deliver a server/system mail into `to_tid`'s inbox and push notification if online."""
        rec = self.records_ref.get(to_tid)
        to_name = getattr(rec, 'name', 'Trainer') if rec is not None else 'Trainer'
        mail_id = self.next_mail_id
        self.next_mail_id += 1
        entry = {
            'id': mail_id,
            'ts': int(self.wall_clock()),
            'from_tid': 'server',
            'from_name': sender_name[:24],
            'to_tid': to_tid,
            'to_name': str(to_name)[:24],
            'flags': 0,
            'money': max(0, int(money)),
            'items': [[int(i), max(1, int(q))] for i, q in (items or [])[:MAX_MAIL_ITEMS]],
            'pkm_blobs_b64': [
                base64.b64encode(b).decode('ascii')
                for b in (pkm_blobs or [])[:MAX_MAIL_PKM]
                if len(b) == PKM_BLOB_SIZE
            ],
            'msg': msg[:MAX_MAIL_MSG],
        }
        box = self.inbox.setdefault(to_tid, [])
        box.append(entry)
        if len(box) > MAX_MAIL_INBOX:
            del box[:-MAX_MAIL_INBOX]
        self.save_state()

        pushes: list[tuple[tuple[str, int], bytes]] = []
        if players_by_pid is not None:
            peer = self.find_online_by_tid(players_by_pid, to_tid)
            if peer is not None:
                pushes.append((peer.addr, self.build_notify_packet(peer.token, sender_name, self.unread_count(to_tid))))
                pushes.append((peer.addr, self.build_summary_packet(peer.token, to_tid)))
        return entry, pushes

    def _resolve_recipient_tid(self, to_name: str, players_by_pid: dict[int, object]) -> tuple[str | None, str]:
        needle = to_name.strip().lower()
        if not needle:
            return None, ''
        for p in players_by_pid.values():
            pname = p.name.decode('ascii', 'ignore').strip()
            if pname.lower() == needle:
                return p.trainer_id.hex(), pname
        for tid, rec in self.records_ref.items():
            rname = str(getattr(rec, 'name', '')).strip()
            if rname.lower() == needle:
                return tid, rname
        return None, ''

    def _find_mail(self, tid: str, mail_id: int) -> tuple[dict | None, str]:
        for box_name, container in (('inbox', self.inbox), ('sent', self.sent)):
            for m in container.get(tid, []):
                if int(m.get('id', 0)) == mail_id:
                    return m, box_name
        return None, ''

    def on_player_join(self, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        tid = player.trainer_id.hex()
        return [(player.addr, self.build_summary_packet(player.token, tid))]

    def handle_packet(
        self,
        pkt_type: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        tid = player.trainer_id.hex()
        if pkt_type == PKT_MAIL_HELLO:
            return [(player.addr, self.build_summary_packet(player.token, tid))]

        if pkt_type == PKT_MAIL_LIST_REQ:
            if len(pkt) < 13:
                return []
            seq = struct.unpack_from('<H', pkt, 8)[0]
            box = pkt[10]
            offset = struct.unpack_from('<H', pkt, 11)[0]
            return [(player.addr, self._build_list_packet(player.token, seq, box, offset, tid))]

        if pkt_type == PKT_MAIL_DIR_REQ:
            if len(pkt) < 10:
                return []
            seq = struct.unpack_from('<H', pkt, 8)[0]
            return [(player.addr, self._build_directory_packet(player.token, seq, tid, players_by_pid))]

        if pkt_type == PKT_MAIL_SEND:
            if len(pkt) < 18:
                return []
            seq = struct.unpack_from('<H', pkt, 8)[0]
            pos = 10
            to_len = pkt[pos]
            pos += 1
            if pos + to_len + 1 > len(pkt):
                return [(player.addr, self._build_detail_packet(player.token, seq, 1, None))]
            to_name = pkt[pos:pos + to_len].decode('ascii', 'ignore')
            pos += to_len
            msg_len = pkt[pos]
            pos += 1
            if pos + msg_len + 5 > len(pkt):
                return [(player.addr, self._build_detail_packet(player.token, seq, 1, None))]
            msg_str = pkt[pos:pos + msg_len].decode('ascii', 'ignore')
            pos += msg_len
            money = struct.unpack_from('<I', pkt, pos)[0]
            pos += 4
            item_cnt = pkt[pos]
            pos += 1
            if item_cnt > MAX_MAIL_ITEMS or pos + item_cnt * 4 + 1 > len(pkt):
                return [(player.addr, self._build_detail_packet(player.token, seq, 1, None))]
            items = []
            for _ in range(item_cnt):
                item_id, qty = struct.unpack_from('<HH', pkt, pos)
                items.append([int(item_id), int(qty)])
                pos += 4
            pkm_cnt = pkt[pos]
            pos += 1
            pkm_blobs_b64 = []
            if pkm_cnt <= MAX_MAIL_PKM:
                for _ in range(pkm_cnt):
                    if pos + 2 > len(pkt):
                        break
                    plen = struct.unpack_from('<H', pkt, pos)[0]
                    pos += 2
                    if plen == PKM_BLOB_SIZE and pos + plen <= len(pkt):
                        pkm_blobs_b64.append(base64.b64encode(pkt[pos:pos + plen]).decode('ascii'))
                        pos += plen
                    else:
                        break

            target_tid, resolved_name = self._resolve_recipient_tid(to_name, players_by_pid)
            if target_tid is None:
                return [(player.addr, self._build_detail_packet(player.token, seq, 1, None))]

            sender_name = player.name.decode('ascii', 'ignore').strip() or 'Trainer'
            mail_id = self.next_mail_id
            self.next_mail_id += 1
            entry = {
                'id': mail_id,
                'ts': int(self.wall_clock()),
                'from_tid': tid,
                'from_name': sender_name[:24],
                'to_tid': target_tid,
                'to_name': (resolved_name or to_name)[:24],
                'flags': 0,
                'money': int(money),
                'items': items,
                'pkm_blobs_b64': pkm_blobs_b64,
                'msg': msg_str[:MAX_MAIL_MSG],
            }
            ibox = self.inbox.setdefault(target_tid, [])
            ibox.append(dict(entry))
            if len(ibox) > MAX_MAIL_INBOX:
                del ibox[:-MAX_MAIL_INBOX]

            sbox = self.sent.setdefault(tid, [])
            sbox.append({**entry, 'flags': 1})
            if len(sbox) > MAX_MAIL_INBOX:
                del sbox[:-MAX_MAIL_INBOX]
            self.save_state()

            out: list[tuple[tuple[str, int], bytes]] = [
                (player.addr, self._build_detail_packet(player.token, seq, 0, entry)),
            ]
            peer = self.find_online_by_tid(players_by_pid, target_tid)
            if peer is not None:
                out.append((peer.addr, self.build_notify_packet(peer.token, sender_name, self.unread_count(target_tid))))
                out.append((peer.addr, self.build_summary_packet(peer.token, target_tid)))
            return out

        if pkt_type == PKT_MAIL_ACTION:
            if len(pkt) < 15:
                return []
            seq = struct.unpack_from('<H', pkt, 8)[0]
            action = pkt[10]
            mail_id = struct.unpack_from('<I', pkt, 11)[0]
            mail, box_name = self._find_mail(tid, mail_id)
            if mail is None:
                if action in (3, 7):
                    return [(player.addr, self._build_detail_packet(player.token, seq, 1, None))]
                return [(player.addr, self._build_ack_packet(player.token, seq, 1, None))]

            if action == 6:  # DELETE
                target_box = self.inbox.get(tid, []) if box_name == 'inbox' else self.sent.get(tid, [])
                target_box[:] = [m for m in target_box if int(m.get('id', 0)) != mail_id]
                self.save_state()
                return [
                    (player.addr, self._build_ack_packet(player.token, seq, 0, mail)),
                    (player.addr, self.build_summary_packet(player.token, tid)),
                ]

            if action in (3, 7):  # OPEN / READ
                if box_name == 'inbox' and (int(mail.get('flags', 0)) & 1) == 0:
                    mail['flags'] = int(mail.get('flags', 0)) | 1
                    self.save_state()
                return [
                    (player.addr, self._build_detail_packet(player.token, seq, 0, mail)),
                    (player.addr, self.build_summary_packet(player.token, tid)),
                ]

            # CLAIM (action 1, 2, 4, 5)
            already_claimed = (int(mail.get('flags', 0)) & 2) != 0
            if already_claimed:
                return [(player.addr, self._build_ack_packet(player.token, seq, 1, None))]
            mail['flags'] = int(mail.get('flags', 0)) | 3
            self.save_state()
            return [
                (player.addr, self._build_ack_packet(player.token, seq, 0, mail)),
                (player.addr, self.build_summary_packet(player.token, tid)),
            ]

        return None


class WonderHub:
    """Persistent [wonder] Wonder Trade pool paired with [mail] delivery."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], float],
        save_state: Callable[[], None],
        mail_hub: MailHub,
    ) -> None:
        self.wall_clock = wall_clock
        self.save_state = save_state
        self.mail_hub = mail_hub

        self.next_offer_id: int = 1
        self.pending_settle: dict[int, dict] = {}
        self.pool: list[dict] = []

    def export_state(self) -> dict:
        return {
            'next_offer_id': self.next_offer_id,
            'pool': self.pool,
        }

    def load_state(self, raw: object) -> None:
        if not isinstance(raw, dict):
            return
        self.next_offer_id = max(1, int(raw.get('next_offer_id', 1)))
        pool = raw.get('pool', [])
        if isinstance(pool, list):
            self.pool = [dict(p) for p in pool if isinstance(p, dict)]

    def _build_resp(
        self,
        token: int,
        seq: int,
        op: int,
        status: int,
        offer_id: int,
        *,
        entries: list[tuple[int, int, int, int]] | None = None,
        msg: str = '',
    ) -> bytes:
        ents = entries or []
        msg_b = _clean_text_bytes(msg.encode('ascii', 'replace'), 100)
        body = bytearray(
            struct.pack(
                '<BHBBIB',
                1,
                seq & 0xFFFF,
                op & 0xFF,
                status & 0xFF,
                offer_id & 0xFFFFFFFF,
                len(ents) & 0xFF,
            )
        )
        for pid, st, ec, oid in ents[:20]:
            body.extend(struct.pack('<IBII', pid & 0xFFFFFFFF, st & 0xFF, ec & 0xFFFFFFFF, oid & 0xFFFFFFFF))
        body.append(len(msg_b) & 0xFF)
        body.extend(msg_b)
        return _pack_fc(token, SUBOP_WONDER_OUT, bytes(body))

    def handle_packet(
        self,
        pkt_type: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        if pkt_type != PKT_WONDER_OP:
            return None
        if len(pkt) < 12:
            return []
        tid = player.trainer_id.hex()
        action = pkt[8]
        seq = struct.unpack_from('<H', pkt, 10)[0]

        if action == 1:
            if len(pkt) < 8 + 0x15C:
                return [(player.addr, self._build_resp(player.token, seq, 0, 1, 0, msg='Invalid offer data.'))]
            blob = pkt[12:12 + PKM_BLOB_SIZE]
            ec, pkm_pid, species = extract_pkm_ids(blob)
            offer_id = self.next_offer_id
            self.next_offer_id += 1
            self.pending_settle[offer_id] = {
                'offer_id': offer_id,
                'owner_tid': tid,
                'owner_name': player.name.decode('ascii', 'ignore').strip() or 'Trainer',
                'ec': ec,
                'pkm_pid': pkm_pid,
                'species': species,
                'blob_b64': base64.b64encode(blob).decode('ascii'),
                'ts': int(self.wall_clock()),
            }
            return [(
                player.addr,
                self._build_resp(
                    player.token,
                    seq,
                    0,
                    0,
                    offer_id,
                    entries=[(pkm_pid, 1, ec, offer_id)],
                ),
            )]

        if action == 2:
            offer_id = struct.unpack_from('<I', pkt, 12)[0] if len(pkt) >= 16 else 0
            if offer_id in self.pending_settle and self.pending_settle[offer_id]['owner_tid'] == tid:
                self.pending_settle.pop(offer_id, None)
            self.pool = [e for e in self.pool if not (int(e.get('offer_id', 0)) == offer_id and e.get('owner_tid') == tid)]
            self.save_state()
            return [(player.addr, self._build_resp(player.token, seq, 0, 0, offer_id, msg='Wonder Trade offer cancelled.'))]

        return [(player.addr, self._build_resp(player.token, seq, 0, 1, 0))]

    def handle_extension(
        self,
        subop: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        if subop != SUBOP_WONDER_POLL_SETTLE:
            return None
        if len(pkt) < 14:
            return []
        tid = player.trainer_id.hex()
        seq = struct.unpack_from('<H', pkt, 11)[0]
        action = pkt[13]

        if action == 1:  # POLL
            pool_entries = [
                (int(e.get('pkm_pid', 0)), 0, int(e.get('ec', 0)), int(e.get('offer_id', 0)))
                for e in self.pool
                if e.get('owner_tid') == tid
            ]
            return [(player.addr, self._build_resp(player.token, seq, 0, 0, 0, entries=pool_entries))]

        if action == 2 and len(pkt) >= 18:  # SETTLE
            offer_id = struct.unpack_from('<I', pkt, 14)[0]
            offer = self.pending_settle.pop(offer_id, None)
            if offer is None or offer.get('owner_tid') != tid:
                return [(player.addr, self._build_resp(player.token, seq, 0, 1, offer_id, msg='Offer expired or missing.'))]

            partner_idx = next((i for i, e in enumerate(self.pool) if e.get('owner_tid') != tid), None)
            if partner_idx is None:
                self.pool.append(offer)
                self.save_state()
                return [(
                    player.addr,
                    self._build_resp(
                        player.token,
                        seq,
                        0,
                        0,
                        offer_id,
                        msg='Added to Wonder Pool. You will receive a match by Mail.',
                    ),
                )]

            partner = self.pool.pop(partner_idx)
            self.save_state()
            my_blob = base64.b64decode(offer['blob_b64'])
            partner_blob = base64.b64decode(partner['blob_b64'])
            out: list[tuple[tuple[str, int], bytes]] = []
            _, pushes_me = self.mail_hub.send_system_mail(
                to_tid=tid,
                sender_name='Wonder Trade',
                msg='Wonder Trade complete! Claim your Pokemon in Mail.',
                pkm_blobs=[partner_blob],
                players_by_pid=players_by_pid,
            )
            _, pushes_partner = self.mail_hub.send_system_mail(
                to_tid=str(partner['owner_tid']),
                sender_name='Wonder Trade',
                msg='Wonder Trade complete! Claim your Pokemon in Mail.',
                pkm_blobs=[my_blob],
                players_by_pid=players_by_pid,
            )
            out.append((
                player.addr,
                self._build_resp(
                    player.token,
                    seq,
                    0,
                    0,
                    offer_id,
                    msg='Wonder Trade paired! Check your Mail.',
                ),
            ))
            out.extend(pushes_me)
            out.extend(pushes_partner)
            return out

        return []


def _parse_offer_slots(payload_after_sid_rev_cnt: bytes) -> tuple[list[bytes], int] | None:
    """Split a 0x62 offer tail [cnt, slot0, ..., u32 money] into raw entry chunks + money."""
    if not payload_after_sid_rev_cnt:
        return None
    cnt = payload_after_sid_rev_cnt[0]
    if cnt > 18:
        return None
    pos = 1
    entries: list[bytes] = []
    for _ in range(cnt):
        if pos >= len(payload_after_sid_rev_cnt):
            return None
        kind = payload_after_sid_rev_cnt[pos]
        if kind == 1:
            if pos + 10 > len(payload_after_sid_rev_cnt):
                return None
            nlen = payload_after_sid_rev_cnt[pos + 9]
            end = pos + 10 + nlen
            if end > len(payload_after_sid_rev_cnt):
                return None
            entries.append(payload_after_sid_rev_cnt[pos:end])
            pos = end
        elif kind == 2:
            if pos + 5 > len(payload_after_sid_rev_cnt):
                return None
            entries.append(payload_after_sid_rev_cnt[pos:pos + 5])
            pos += 5
        else:
            return None
    money = 0
    if pos + 4 <= len(payload_after_sid_rev_cnt):
        money = struct.unpack_from('<I', payload_after_sid_rev_cnt, pos)[0]
    return entries, money


@dataclass
class TradeSession:
    sid: int
    pid_a: int
    pid_b: int
    state: int = 1  # 1=invited, 2=active, 4=confirming, 5=committed
    offer_entries: dict[int, list[bytes]] = field(default_factory=dict)
    offer_money: dict[int, int] = field(default_factory=dict)
    offer_rev: dict[int, int] = field(default_factory=dict)
    ready: dict[int, int] = field(default_factory=dict)
    commit: dict[int, int] = field(default_factory=dict)
    done: set[int] = field(default_factory=set)

    def other_pid(self, pid: int) -> int:
        return self.pid_b if pid == self.pid_a else self.pid_a


class TradeHub:
    """In-memory live player-to-player [trade] broker (0x60..0x66 <-> 0xE0..0xE7)."""

    def __init__(self) -> None:
        self.next_sid: int = 1
        self.pending_invites: dict[tuple[int, int], int] = {}  # (inviter_pid, target_pid) -> ts_s
        self.sessions: dict[int, TradeSession] = {}
        self.pid_to_sid: dict[int, int] = {}

    def _cleanup_pid(self, pid: int, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        out: list[tuple[tuple[str, int], bytes]] = []
        dead_inv = [k for k in self.pending_invites if k[0] == pid or k[1] == pid]
        for inv_pid, tgt_pid in dead_inv:
            self.pending_invites.pop((inv_pid, tgt_pid), None)
            other_pid = tgt_pid if inv_pid == pid else inv_pid
            other = players_by_pid.get(other_pid)
            if other is not None:
                out.append((other.addr, _pack_hdr(PKT_TRADE_STATUS_OUT, other.token) + struct.pack('<HB', pid & 0xFFFF, 3)))

        sid = self.pid_to_sid.pop(pid, None)
        if sid is not None:
            sess = self.sessions.pop(sid, None)
            if sess is not None:
                other_pid = sess.other_pid(pid)
                self.pid_to_sid.pop(other_pid, None)
                other = players_by_pid.get(other_pid)
                if other is not None:
                    out.append((other.addr, _pack_hdr(PKT_TRADE_STATUS_OUT, other.token) + struct.pack('<HB', pid & 0xFFFF, 3)))
        return out

    def on_player_leave(self, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        return self._cleanup_pid(player.pid, players_by_pid)

    def _send_ready_sync(self, sess: TradeSession, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        out: list[tuple[tuple[str, int], bytes]] = []
        for pid in (sess.pid_a, sess.pid_b):
            p = players_by_pid.get(pid)
            if p is None:
                continue
            opid = sess.other_pid(pid)
            flags = (sess.commit.get(opid, 0) & 1) | ((sess.commit.get(pid, 0) & 1) << 1)
            payload = struct.pack(
                '<IBBHHB',
                sess.sid & 0xFFFFFFFF,
                sess.ready.get(opid, 0) & 0xFF,
                sess.state & 0xFF,
                sess.offer_rev.get(opid, 0) & 0xFFFF,
                sess.offer_rev.get(pid, 0) & 0xFFFF,
                flags & 0xFF,
            )
            out.append((p.addr, _pack_hdr(PKT_TRADE_READY_OUT, p.token) + payload))
        return out

    def handle_packet(
        self,
        pkt_type: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        if pkt_type == PKT_TRADE_INVITE:
            if len(pkt) < 10:
                return []
            target_pid = struct.unpack_from('<H', pkt, 8)[0]
            target = players_by_pid.get(target_pid)
            if target is None or target.pid == player.pid or target_pid in self.pid_to_sid:
                return [(player.addr, _pack_hdr(PKT_TRADE_STATUS_OUT, player.token) + struct.pack('<HB', target_pid, 2))]
            self.pending_invites[(player.pid, target_pid)] = int(time.time())
            return [(target.addr, _pack_hdr(PKT_TRADE_STATUS_OUT, target.token) + struct.pack('<HB', player.pid & 0xFFFF, 1))]

        if pkt_type == PKT_TRADE_RESPONSE:
            if len(pkt) < 11:
                return []
            peer_pid = struct.unpack_from('<H', pkt, 8)[0]
            accept = pkt[10]
            peer = players_by_pid.get(peer_pid)
            self.pending_invites.pop((peer_pid, player.pid), None)
            self.pending_invites.pop((player.pid, peer_pid), None)
            if accept != 1 or peer is None:
                if peer is not None:
                    return [(peer.addr, _pack_hdr(PKT_TRADE_STATUS_OUT, peer.token) + struct.pack('<HB', player.pid & 0xFFFF, 3))]
                return []

            out = self._cleanup_pid(player.pid, players_by_pid) + self._cleanup_pid(peer_pid, players_by_pid)
            sid = self.next_sid
            self.next_sid += 1
            sess = TradeSession(
                sid=sid,
                pid_a=peer_pid,
                pid_b=player.pid,
                state=4,
                offer_entries={peer_pid: [], player.pid: []},
                offer_money={peer_pid: 0, player.pid: 0},
                offer_rev={peer_pid: 0, player.pid: 0},
                ready={peer_pid: 0, player.pid: 0},
                commit={peer_pid: 0, player.pid: 0},
            )
            self.sessions[sid] = sess
            self.pid_to_sid[peer_pid] = sid
            self.pid_to_sid[player.pid] = sid

            for receiver, other in ((peer, player), (player, peer)):
                oname = _clean_text_bytes(other.name, 24) or b'Trainer'
                payload = struct.pack('<IHB', sid, other.pid & 0xFFFF, len(oname)) + oname + b'\x00'
                out.append((receiver.addr, _pack_hdr(PKT_TRADE_START_OUT, receiver.token) + payload))
            return out

        if pkt_type == PKT_TRADE_OFFER:
            if len(pkt) < 15:
                return []
            sid = struct.unpack_from('<I', pkt, 8)[0]
            sess = self.sessions.get(sid)
            if sess is None or player.pid not in (sess.pid_a, sess.pid_b):
                return []
            rev = struct.unpack_from('<H', pkt, 12)[0]
            parsed = _parse_offer_slots(pkt[14:])
            if parsed is None:
                return []
            entries, money = parsed
            sess.offer_entries[player.pid] = entries
            sess.offer_money[player.pid] = money
            sess.offer_rev[player.pid] = rev
            sess.ready[sess.pid_a] = 0
            sess.ready[sess.pid_b] = 0
            sess.commit[sess.pid_a] = 0
            sess.commit[sess.pid_b] = 0
            other = players_by_pid.get(sess.other_pid(player.pid))
            out: list[tuple[tuple[str, int], bytes]] = []
            if other is not None:
                out.append((other.addr, _pack_hdr(PKT_TRADE_OFFER_OUT, other.token) + pkt[8:]))
            out.extend(self._send_ready_sync(sess, players_by_pid))
            return out

        if pkt_type == PKT_TRADE_READY:
            if len(pkt) < 15:
                return []
            sid = struct.unpack_from('<I', pkt, 8)[0]
            sess = self.sessions.get(sid)
            if sess is None or player.pid not in (sess.pid_a, sess.pid_b):
                return []
            ready_val = 1 if pkt[12] else 0
            rev = struct.unpack_from('<H', pkt, 13)[0]
            commit_val = 1 if (len(pkt) >= 16 and pkt[15]) else 0
            sess.ready[player.pid] = ready_val
            sess.offer_rev[player.pid] = rev
            sess.commit[player.pid] = commit_val if ready_val else 0
            if ready_val == 0:
                sess.commit[sess.pid_a] = 0
                sess.commit[sess.pid_b] = 0

            out = self._send_ready_sync(sess, players_by_pid)
            if (
                sess.ready.get(sess.pid_a) == 1
                and sess.ready.get(sess.pid_b) == 1
                and sess.commit.get(sess.pid_a) == 1
                and sess.commit.get(sess.pid_b) == 1
            ):
                sess.state = 5
                for pid in (sess.pid_a, sess.pid_b):
                    p = players_by_pid.get(pid)
                    if p is None:
                        continue
                    opid = sess.other_pid(pid)
                    give_entries = sess.offer_entries.get(pid, [])
                    get_entries = sess.offer_entries.get(opid, [])
                    give_m = sess.offer_money.get(pid, 0)
                    get_m = sess.offer_money.get(opid, 0)
                    plan = bytearray(struct.pack('<IB', sid & 0xFFFFFFFF, len(give_entries) & 0xFF))
                    for e in give_entries:
                        plan.extend(e)
                    plan.append(len(get_entries) & 0xFF)
                    for e in get_entries:
                        plan.extend(e)
                    plan.extend(struct.pack('<II', give_m & 0xFFFFFFFF, get_m & 0xFFFFFFFF))
                    out.append((p.addr, _pack_hdr(PKT_TRADE_COMMIT_OUT, p.token) + bytes(plan)))
            return out

        if pkt_type == PKT_TRADE_CHUNK:
            if len(pkt) < 19:
                return []
            sid = struct.unpack_from('<I', pkt, 8)[0]
            sess = self.sessions.get(sid)
            if sess is None or player.pid not in (sess.pid_a, sess.pid_b):
                return []
            other = players_by_pid.get(sess.other_pid(player.pid))
            if other is None:
                return []
            return [(other.addr, _pack_hdr(PKT_TRADE_CHUNK_OUT, other.token) + pkt[8:])]

        if pkt_type == PKT_TRADE_CHAT:
            if len(pkt) < 14:
                return []
            sid = struct.unpack_from('<I', pkt, 8)[0]
            sess = self.sessions.get(sid)
            if sess is None or player.pid not in (sess.pid_a, sess.pid_b):
                return []
            other = players_by_pid.get(sess.other_pid(player.pid))
            out: list[tuple[tuple[str, int], bytes]] = []
            if other is not None:
                out.append((other.addr, _pack_hdr(PKT_TRADE_CHAT_OUT, other.token) + pkt[8:]))
            if pkt[12] == 2:  # cancel / close
                self.sessions.pop(sid, None)
                self.pid_to_sid.pop(sess.pid_a, None)
                self.pid_to_sid.pop(sess.pid_b, None)
            return out

        if pkt_type == PKT_TRADE_DONE:
            if len(pkt) < 13:
                return []
            sid = struct.unpack_from('<I', pkt, 8)[0]
            sess = self.sessions.get(sid)
            if sess is None or player.pid not in (sess.pid_a, sess.pid_b):
                return []
            sess.done.add(player.pid)
            other = players_by_pid.get(sess.other_pid(player.pid))
            if len(sess.done) >= 2:
                self.sessions.pop(sid, None)
                self.pid_to_sid.pop(sess.pid_a, None)
                self.pid_to_sid.pop(sess.pid_b, None)
                out = [(player.addr, _pack_hdr(PKT_TRADE_DONE_OUT, player.token) + struct.pack('<IB', sid, 5))]
                if other is not None:
                    out.append((other.addr, _pack_hdr(PKT_TRADE_DONE_OUT, other.token) + struct.pack('<IB', sid, 5)))
                return out
            if other is not None:
                return [(other.addr, _pack_hdr(PKT_TRADE_DONE_OUT, other.token) + pkt[8:])]
            return []

        return None


class RaceHub:
    """Tracks [dexrace] & [story] progression, podiums (1st-3rd), and [mail] rewards."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], float],
        save_state: Callable[[], None],
        mail_hub: MailHub,
        records_ref: dict[str, object],
        notice_builder: Callable[[int, str], bytes] | None = None,
        is_admin_fn: Callable[[object], bool] | None = None,
    ) -> None:
        self.wall_clock = wall_clock
        self.save_state = save_state
        self.mail_hub = mail_hub
        self.records_ref = records_ref
        self.notice_builder = notice_builder
        self.is_admin_fn = is_admin_fn

        self.dex_winners: list[dict] = []
        self.dex_progress: dict[str, int] = {}
        self.story_winners: list[dict] = []
        self.story_progress: dict[str, int] = {}

    def export_state(self) -> dict:
        return {
            'dex_winners': self.dex_winners,
            'dex_progress': self.dex_progress,
            'story_winners': self.story_winners,
            'story_progress': self.story_progress,
        }

    def load_state(self, raw: object) -> None:
        if not isinstance(raw, dict):
            return
        dw = raw.get('dex_winners', [])
        if isinstance(dw, list):
            self.dex_winners = [dict(x) for x in dw if isinstance(x, dict)][:10]
        dp = raw.get('dex_progress', {})
        if isinstance(dp, dict):
            self.dex_progress = {str(k): max(0, int(v)) for k, v in dp.items()}
        sw = raw.get('story_winners', [])
        if isinstance(sw, list):
            self.story_winners = [dict(x) for x in sw if isinstance(x, dict)][:10]
        sp = raw.get('story_progress', {})
        if isinstance(sp, dict):
            self.story_progress = {str(k): max(0, int(v)) for k, v in sp.items()}

    def _place_of(self, winners: list[dict], tid: str) -> int:
        for idx, entry in enumerate(winners[:3], start=1):
            if entry.get('tid') == tid:
                return idx
        return 0

    def build_story_podium_packet(self, token: int, tid: str) -> bytes:
        top3 = self.story_winners[:3]
        my_place = self._place_of(self.story_winners, tid)
        body = bytearray([len(top3) & 0xFF])
        for idx, entry in enumerate(top3, start=1):
            nb = _clean_text_bytes(str(entry.get('name', 'Trainer')).encode('ascii', 'replace'), 24)
            body.append(idx & 0xFF)
            body.append(len(nb) & 0xFF)
            body.extend(nb)
        body.append(my_place & 0xFF)
        body.append(0)  # flags (bit0=0 -> prize ready in mail)
        return _pack_fc(token, SUBOP_STORY_PODIUM_OUT, bytes(body))

    def build_dex_board_packet(self, token: int, tid: str) -> bytes:
        top3 = self.dex_winners[:3]
        my_place = self._place_of(self.dex_winners, tid)
        best_count = max(self.dex_progress.values(), default=0)
        header_u32 = (best_count & 0xFFFF) | ((my_place & 0xFF) << 16)
        body = bytearray(struct.pack('<BIB', 1, header_u32, len(top3) & 0xFF))
        for idx, entry in enumerate(top3, start=1):
            nb = _clean_text_bytes(str(entry.get('name', 'Trainer')).encode('ascii', 'replace'), 24)
            body.append(idx & 0xFF)
            body.append(len(nb) & 0xFF)
            body.extend(nb)

        # Up to 5 top progress entries (winners first, then highest counts)
        ranked = sorted(
            self.dex_progress.items(),
            key=lambda kv: (-(self._place_of(self.dex_winners, kv[0]) or 99), -kv[1]),
        )[:5]
        body.append(len(ranked) & 0xFF)
        for rtid, cnt in ranked:
            rec = self.records_ref.get(rtid)
            rname = getattr(rec, 'name', 'Trainer') if rec is not None else 'Trainer'
            nb = _clean_text_bytes(str(rname).encode('ascii', 'replace'), 24)
            place = self._place_of(self.dex_winners, rtid)
            body.extend(struct.pack('<HBB', cnt & 0xFFFF, place & 0xFF, len(nb) & 0xFF))
            body.extend(nb)
        return _pack_fc(token, SUBOP_DEXRACE_BOARD_OUT, bytes(body))

    def build_dex_congrats_packet(self, token: int, tid: str, count: int) -> bytes:
        top3 = self.dex_winners[:3]
        my_place = self._place_of(self.dex_winners, tid)
        body = bytearray(struct.pack('<BHBB', 1, count & 0xFFFF, my_place & 0xFF, len(top3) & 0xFF))
        for idx, entry in enumerate(top3, start=1):
            nb = _clean_text_bytes(str(entry.get('name', 'Trainer')).encode('ascii', 'replace'), 24)
            body.append(idx & 0xFF)
            body.append(len(nb) & 0xFF)
            body.extend(nb)
        return _pack_fc(token, SUBOP_DEXRACE_CONGRATS_OUT, bytes(body))

    def on_player_join(self, player, players_by_pid: dict[int, object]) -> list[tuple[tuple[str, int], bytes]]:
        tid = player.trainer_id.hex()
        return [
            (player.addr, self.build_story_podium_packet(player.token, tid)),
            (player.addr, self.build_dex_board_packet(player.token, tid)),
        ]

    def _broadcast_notices(self, players_by_pid: dict[int, object], text: str) -> list[tuple[tuple[str, int], bytes]]:
        if self.notice_builder is None:
            return []
        return [(p.addr, self.notice_builder(p.token, text)) for p in players_by_pid.values()]

    def handle_packet(
        self,
        pkt_type: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        if pkt_type != PKT_STORY_REPORT:
            return None
        if len(pkt) < 14:
            return []
        tid = player.trainer_id.hex()
        progress = struct.unpack_from('<I', pkt, 8)[0]
        done = pkt[12]
        prev = self.story_progress.get(tid, 0)
        changed = progress > prev
        if changed:
            self.story_progress[tid] = progress

        out: list[tuple[tuple[str, int], bytes]] = []
        if done and not any(w.get('tid') == tid for w in self.story_winners):
            place = len(self.story_winners) + 1
            name = player.name.decode('ascii', 'ignore').strip() or 'Trainer'
            self.story_winners.append({
                'tid': tid,
                'name': name[:24],
                'progress': progress,
                'ts': int(self.wall_clock()),
                'place': place,
            })
            self.save_state()
            if place == 1:
                items, money = [(ITEM_ABILITY_PATCH, 2)], 50000
                prize_txt = 'Ability Patch x2 + $50.000'
            elif place == 2:
                items, money = [(ITEM_ABILITY_PATCH, 1)], 25000
                prize_txt = 'Ability Patch + $25.000'
            elif place == 3:
                items, money = [(ITEM_ABILITY_CAPSULE, 1)], 10000
                prize_txt = 'Ability Capsule + $10.000'
            else:
                items, money = [(ITEM_RARE_CANDY, 3)], 5000
                prize_txt = 'Rare Candy x3 + $5.000'

            _, mail_pushes = self.mail_hub.send_system_mail(
                to_tid=tid,
                sender_name='Story Race',
                msg=f'Felicidades puesto #{place} en Historia! Premio: {prize_txt}',
                money=money,
                items=items,
                players_by_pid=players_by_pid,
            )
            out.extend(mail_pushes)
            for p in players_by_pid.values():
                out.append((p.addr, self.build_story_podium_packet(p.token, p.trainer_id.hex())))
            out.extend(self._broadcast_notices(players_by_pid, f'[Historia] {name} completo la historia (#{place})! Premio enviado al Correo.'))
            return out

        if changed:
            self.save_state()
        out.append((player.addr, self.build_story_podium_packet(player.token, tid)))
        return out

    def handle_extension(
        self,
        subop: int,
        pkt: bytes,
        player,
        players_by_pid: dict[int, object],
    ) -> list[tuple[tuple[str, int], bytes]] | None:
        tid = player.trainer_id.hex()
        if subop == SUBOP_STORY_POLL:
            return [(player.addr, self.build_story_podium_packet(player.token, tid))]

        if subop == SUBOP_DEXRACE_IN:
            if len(pkt) < 16:
                return []
            action = pkt[13]
            count = struct.unpack_from('<H', pkt, 14)[0]
            if count > self.dex_progress.get(tid, 0):
                self.dex_progress[tid] = count
                self.save_state()

            out: list[tuple[tuple[str, int], bytes]] = []
            if action == 2 and count > 0 and not any(w.get('tid') == tid for w in self.dex_winners):
                place = len(self.dex_winners) + 1
                name = player.name.decode('ascii', 'ignore').strip() or 'Trainer'
                self.dex_winners.append({
                    'tid': tid,
                    'name': name[:24],
                    'count': count,
                    'ts': int(self.wall_clock()),
                    'place': place,
                })
                self.save_state()
                if place == 1:
                    items, money = [(ITEM_ABILITY_PATCH, 2), (ITEM_RARE_CANDY, 5)], 50000
                    prize_txt = 'Ability Patch x2, Rare Candy x5 + $50.000'
                elif place == 2:
                    items, money = [(ITEM_ABILITY_CAPSULE, 2), (ITEM_RARE_CANDY, 3)], 25000
                    prize_txt = 'Ability Capsule x2, Rare Candy x3 + $25.000'
                elif place == 3:
                    items, money = [(ITEM_ABILITY_CAPSULE, 1), (ITEM_RARE_CANDY, 1)], 10000
                    prize_txt = 'Ability Capsule, Rare Candy + $10.000'
                else:
                    items, money = [(ITEM_RARE_CANDY, 3)], 5000
                    prize_txt = 'Rare Candy x3 + $5.000'

                _, mail_pushes = self.mail_hub.send_system_mail(
                    to_tid=tid,
                    sender_name='Pokedex Race',
                    msg=f'Felicidades puesto #{place} en Pokedex ({count})! Premio: {prize_txt}',
                    money=money,
                    items=items,
                    players_by_pid=players_by_pid,
                )
                out.extend(mail_pushes)
                out.append((player.addr, self.build_dex_congrats_packet(player.token, tid, count)))
                for p in players_by_pid.values():
                    out.append((p.addr, self.build_dex_board_packet(p.token, p.trainer_id.hex())))
                out.extend(self._broadcast_notices(players_by_pid, f'[Pokedex] {name} completo la Pokedex (#{place})! Premio enviado al Correo.'))
                return out

            out.append((player.addr, self.build_dex_board_packet(player.token, tid)))
            out.append((player.addr, self.build_dex_congrats_packet(player.token, tid, count)))
            return out

        return None

    def format_status(self) -> str:
        dex_str = ', '.join(f"#{i} {w['name']}({w.get('count', 0)})" for i, w in enumerate(self.dex_winners[:3], 1)) or 'sin ganadores'
        story_str = ', '.join(f"#{i} {w['name']}" for i, w in enumerate(self.story_winners[:3], 1)) or 'sin ganadores'
        return f'Carrera Pokedex: [{dex_str}] | Historia: [{story_str}]'

    def handle_command(
        self,
        cmd: str,
        args: str,
        player,
        players_by_pid: dict[int, object],
        *,
        from_console: bool = False,
    ) -> tuple[list[tuple[tuple[str, int], bytes]], str] | None:
        if cmd not in ('race', 'carrera'):
            return None
        sub = args.strip().lower()
        if sub == 'reset':
            if not from_console and self.is_admin_fn is not None and not self.is_admin_fn(player):
                msg = 'Solo el anfitrion puede reiniciar las carreras.'
                out = [(player.addr, self.notice_builder(player.token, msg))] if (player and self.notice_builder) else []
                return out, msg
            self.dex_winners.clear()
            self.story_winners.clear()
            self.save_state()
            out = []
            for p in players_by_pid.values():
                tid = p.trainer_id.hex()
                out.append((p.addr, self.build_story_podium_packet(p.token, tid)))
                out.append((p.addr, self.build_dex_board_packet(p.token, tid)))
            msg = 'Carreras de Pokedex e Historia reiniciadas.'
            if player is not None and self.notice_builder is not None:
                out.append((player.addr, self.notice_builder(player.token, msg)))
            return out, msg

        msg = self.format_status()
        out = [(player.addr, self.notice_builder(player.token, msg))] if (player and self.notice_builder) else []
        return out, msg

