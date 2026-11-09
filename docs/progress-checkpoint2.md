# Checkpoint 2 progress note

Javid Malikzade, ICS0022 Secure Programming, Password Manager

## What works now

All the planned commands work: `init`, `add`, `get`, `list`, `update`, `delete`, `generate`
and `change-master`. How to install and run it is in the README.

| Requirement | Where | How |
|---|---|---|
| Vault storage | `storage.py` | One JSON file at `~/.pwmanager/vault.json`. It is written to a temp file first, then `fsync` and `os.replace`, so a crash can't break the vault. Folder is 0700 and file is 0600. Symlinks are refused. |
| Encrypted at rest | `crypto.py` | Key from Argon2id (3 iterations, 64 MiB, 4 lanes) with a random 16-byte salt. Entries are encrypted with AES-256-GCM. The header is the associated data, and every save uses a new nonce. Entry names are encrypted too. |
| Master password | `vault.py` | Read with `getpass` only. The vault opens only if GCM decryption works. No hash of the password is stored. A wrong password and a changed file give the same error, "could not unlock vault". |
| Passwords never printed | `cli.py`, `clipboard.py` | `get` shows `********`. `get --copy` and `generate` copy the password to the clipboard and clear it after 20 seconds. |
| Input validation | `cli.py`, `crypto.py` | Entry names must match `[A-Za-z0-9._@-]{1,64}`. `--length` must be 8 to 128. Text fields have a maximum length and can't have control characters. The vault path must end in `.json`. The header is checked strictly before anything is decrypted. |

## Changes from the design

- I dropped `get --show`. The checkpoint says the interface must never print passwords in
  cleartext, so the clipboard is the only way to get a password out.
- The KDF settings in the header now also have an upper limit, not only the minimum from V3.
  Without it, someone could edit the header to make the program use a huge amount of memory.
- `generate` copies the password instead of printing it, for the same reason as `--show`.
- On Windows the clipboard code asks Windows not to keep the password in clipboard history
  (Win+V) or the cloud clipboard.

## Testing

There are 74 pytest tests, one file per module. They cover a wrong password, a changed
ciphertext, a changed header, weak or huge KDF settings, nonce reuse, symlinks, file
permissions, bad input, and checking that no password ends up in the output or in the file.
All of them pass on Linux (WSL). On Windows 72 pass, and the 2 permission and symlink tests are
skipped. I also ran the real program in a terminal on Linux and checked the file modes and that
no plain text was in the vault file.

## Not done yet (Checkpoint 3)

- Static analysis (bandit) and maybe fuzzing the vault file reader
- A limit or delay after several wrong master passwords
- Locking the vault file so two `pwm` commands can't write at the same time
- File permissions on Windows (0600 does nothing there, it uses ACLs instead)
- R1 is still only partly fixed: the key bytes are zeroed on lock, but Python strings with
  passwords can't be wiped
