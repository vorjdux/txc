#!/usr/bin/env python3
"""The recovery key of a txc synced vault, without txc.

A vault's recovery secret is the SLIP-39 master secret of its three sheets,
with the card as the SLIP-39 passphrase. The recovery key is that 32-byte
secret, used as the seed of an age post-quantum identity: Bech32 (not
Bech32m, and without the 90-character limit) with the human-readable part
"age-secret-key-pq-", written in capitals. With it, age 1.3 or later reads
an offline backup:

    age -d -i key.txt txc-backup-NAME-DATE.age

Give the master secret, as hexadecimal, from any SLIP-39 tool, for example
Trezor's reference implementation:

    pip install shamir-mnemonic
    shamir recover -p        # type two sheets, then the card as passphrase
    python3 recovery-key.py MASTER_SECRET_HEX > key.txt

Type the card exactly as printed: lowercase words, single spaces.

This script needs nothing but Python 3. It is written from the description
above, not from txc's code, so the two check each other.
"""

import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
HRP = "age-secret-key-pq-"


def polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for bit in range(5):
            checksum ^= generator[bit] if (top >> bit) & 1 else 0
    return checksum


def expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def to_five_bits(data):
    accumulator, bits, out = 0, 0, []
    for byte in data:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((accumulator >> bits) & 31)
    if bits:
        out.append((accumulator << (5 - bits)) & 31)
    return out


def bech32(hrp, data):
    words = to_five_bits(data)
    check = polymod(expand(hrp) + words + [0] * 6) ^ 1
    words += [(check >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[w] for w in words)


def recovery_key(master_secret):
    if len(master_secret) != 32:
        raise ValueError("a txc recovery secret is 32 bytes")
    return bech32(HRP, master_secret).upper()


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        secret = bytes.fromhex(argv[1].strip())
        print(recovery_key(secret))
    except ValueError as error:
        print(f"recovery-key: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
