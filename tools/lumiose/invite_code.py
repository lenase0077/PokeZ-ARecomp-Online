"""Compact, checksummed invite-code codec for Lumiose Online private rooms."""
from __future__ import annotations

import ipaddress
import secrets
import struct

# Crockford Base32 alphabet (avoids I, L, O, U ambiguity when sharing codes)
ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
_DECODE_MAP = {ch: idx for idx, ch in enumerate(ALPHABET)}
_DECODE_MAP.update({'O': 0, 'I': 1, 'L': 1, 'U': _DECODE_MAP['V']})

PLAYIT_SUFFIX = '.gl.at.ply.gg'
FMT_IPV4 = 1
FMT_HOST = 2


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def b32_encode(raw: bytes) -> str:
    bits = 0
    bit_count = 0
    out = []
    for byte in raw:
        bits = (bits << 8) | byte
        bit_count += 8
        while bit_count >= 5:
            bit_count -= 5
            out.append(ALPHABET[(bits >> bit_count) & 0x1F])
    if bit_count > 0:
        out.append(ALPHABET[(bits << (5 - bit_count)) & 0x1F])
    return ''.join(out)


def b32_decode(text: str) -> bytes:
    cleaned = text.strip().upper().replace('-', '').replace(' ', '')
    if not cleaned:
        raise ValueError('Empty code')
    bits = 0
    bit_count = 0
    out = bytearray()
    for ch in cleaned:
        val = _DECODE_MAP.get(ch)
        if val is None:
            raise ValueError(f'Invalid character in invite code: {ch!r}')
        bits = (bits << 5) | val
        bit_count += 5
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    # Any remaining padding bits (< 5) must be zero.
    if bit_count > 0 and (bits & ((1 << bit_count) - 1)) != 0:
        raise ValueError('Corrupted invite code padding')
    return bytes(out)


def format_groups(prefix: str, body: str, group_size: int = 4) -> str:
    groups = [body[i : i + group_size] for i in range(0, len(body), group_size)]
    return f'{prefix}-' + '-'.join(groups)


def generate_secret_hex() -> str:
    return secrets.token_hex(4).upper()


def _normalize_secret(secret_hex: str) -> bytes:
    raw = bytes.fromhex(secret_hex.strip())
    if len(raw) != 4:
        raise ValueError('Room secret must be 4 bytes (8 hex characters)')
    return raw


def encode_invite(host: str, port: int, secret_hex: str) -> str:
    clean_host = host.strip().lower()
    if not clean_host or any(c.isspace() for c in clean_host):
        raise ValueError('Invalid host address')
    if not (1 <= port <= 65535):
        raise ValueError('Port must be between 1 and 65535')
    secret = _normalize_secret(secret_hex)

    try:
        ip_obj = ipaddress.IPv4Address(clean_host)
    except ipaddress.AddressValueError:
        ip_obj = None

    if ip_obj is not None:
        payload = struct.pack('<B4sH4s', FMT_IPV4, ip_obj.packed, port, secret)
        prefix = 'ZA1'
    else:
        flags = 0
        encoded_host = clean_host
        if clean_host.endswith(PLAYIT_SUFFIX) and len(clean_host) > len(PLAYIT_SUFFIX):
            flags |= 0x01
            encoded_host = clean_host[: -len(PLAYIT_SUFFIX)]
        host_bytes = encoded_host.encode('ascii')
        if len(host_bytes) > 250:
            raise ValueError('Hostname is too long for an invite code')
        payload = (
            struct.pack('<BBH4sB', FMT_HOST, flags, port, secret, len(host_bytes))
            + host_bytes
        )
        prefix = 'ZA2'

    packet = payload + struct.pack('<H', crc16_ccitt(payload))
    return format_groups(prefix, b32_encode(packet))


def decode_invite(code: str) -> tuple[str, int, str]:
    """Decode an invite code into (host, port, secret_hex)."""
    raw_code = code.strip().upper()
    if '-' in raw_code:
        head, _, rest = raw_code.partition('-')
        if head in ('ZA1', 'ZA2'):
            raw_bytes = b32_decode(rest)
        else:
            raw_bytes = b32_decode(raw_code)
    else:
        if raw_code.startswith(('ZA1', 'ZA2')) and len(raw_code) > 4:
            raw_bytes = b32_decode(raw_code[3:])
        else:
            raw_bytes = b32_decode(raw_code)

    if len(raw_bytes) < 5:
        raise ValueError('Invite code is too short')
    payload, crc_bytes = raw_bytes[:-2], raw_bytes[-2:]
    expected_crc = struct.unpack('<H', crc_bytes)[0]
    if crc16_ccitt(payload) != expected_crc:
        raise ValueError('Invalid invite code (checksum mismatch)')

    fmt = payload[0]
    if fmt == FMT_IPV4:
        if len(payload) != 11:
            raise ValueError('Invalid IPv4 invite code length')
        _, ip_packed, port, secret = struct.unpack('<B4sH4s', payload)
        host = str(ipaddress.IPv4Address(ip_packed))
        return host, port, secret.hex().upper()

    if fmt == FMT_HOST:
        if len(payload) < 9:
            raise ValueError('Invalid host invite code length')
        _, flags, port, secret, hlen = struct.unpack_from('<BBH4sB', payload, 0)
        if len(payload) != 9 + hlen:
            raise ValueError('Corrupted host invite code length')
        host = payload[9:].decode('ascii')
        if flags & 0x01:
            host = host + PLAYIT_SUFFIX
        return host, port, secret.hex().upper()

    raise ValueError(f'Unsupported invite code format: {fmt}')
