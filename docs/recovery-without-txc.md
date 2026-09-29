# Recovering a synced vault without txc

A synced vault stays readable if txc itself is gone: two recovery sheets,
the card, an offline backup and the `age` tool are enough. This page is the
whole procedure; nothing in it needs txc's code.

## What you need

- Two of the three recovery sheets, and the card.
- An offline backup: a `txc-backup-NAME-DATE.age` file that
  `txc vault backup` wrote to separate media.
- [age](https://age-encryption.org) 1.3 or later, which reads post-quantum
  (`mlkem768x25519`) keys.
- Any SLIP-39 tool, such as Trezor's reference implementation
  (`pip install shamir-mnemonic`), and Python 3 for the small script in
  [`scripts/recovery-key.py`](../scripts/recovery-key.py).

Do this on a computer you trust, offline if you can.

## 1. The recovery secret, from two sheets and the card

Each sheet holds one SLIP-39 share, of a 2-of-3 split. The card is the
SLIP-39 passphrase. Type it exactly as printed: lowercase words, single
spaces, nothing before or after.

```sh
shamir recover -p
```

Type the words of two sheets when asked, then the card as the passphrase.
The tool prints the master secret, 32 bytes, as hexadecimal.

## 2. The recovery key, from the recovery secret

The recovery key is an age identity whose 32-byte seed is the master
secret. It is written in Bech32, the original variant rather than Bech32m,
without Bech32's 90-character limit, with the human-readable part
`age-secret-key-pq-`, and then in capitals: `AGE-SECRET-KEY-PQ-1...`.

```sh
python3 scripts/recovery-key.py MASTER_SECRET_HEX > key.txt
```

The script is about fifty lines with no dependency, written from this
description; txc's tests check that it agrees with txc.

## 3. The vault, from the backup

```sh
age -d -i key.txt txc-backup-NAME-DATE.age > vault.json
```

Then delete `key.txt`, and `vault.json` once you are done with it: both
are secret.

## The backup's contents

`vault.json` is the whole vault, as `txc-backup-v1`:

```json
{
  "format": "txc-backup-v1",
  "vault": "personal",
  "written": "2026-09-30T12:00:00Z",
  "entries": [
    {
      "name": "github",
      "kind": "login",
      "tags": ["code"],
      "favourite": true,
      "sensitivity": "normal",
      "fields": [
        { "name": "username", "value": "octocat", "secret": false },
        { "name": "password", "value": "hunter2", "secret": true }
      ]
    }
  ],
  "removed": [
    { "name": "old", "removed": "2026-09-20T08:00:00Z", "fields": [] }
  ]
}
```

- `sensitivity` is `normal`, `protected`, `root-grade` or `operation-only`.
- A protected field has, instead of `value`, `"protected"`: the value as
  an age file, base64-encoded, sealed to the vault's security keys and to
  the same recovery key. Decode it and run `age -d -i key.txt` on it.
- `removed` lists entries removed less than 30 days before the backup, with
  the values their removal kept.

A signature by the device that wrote the backup sits beside it, in
`txc-backup-NAME-DATE.age.sig`; with txc, `txc vault backup --verify FILE`
checks it against the vault's devices.
