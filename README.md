# password-manager

Command-line password manager for the ICS0022 Secure Programming course.

## Scope

A local password manager for one user. All entries are stored in one encrypted vault file,
and the vault is unlocked with a master password.

Planned features:
- create a vault with a master password
- add, view, edit, list and delete entries (name, username, password, notes)
- generate random passwords
- change the master password
- detect if the vault file was modified
- copy a password to the clipboard and clear it after a few seconds

Not planned:
- syncing between devices
- browser extension / autofill
- multiple users per vault
- GUI

## Commands

```
pwm init                   create a new vault
pwm add <name>             add an entry
pwm get <name>             show an entry (--show to print the password, --copy to copy it)
pwm list                   list entry names
pwm update <name>          edit an entry
pwm delete <name>          delete an entry
pwm generate [--length N]  generate a password (default length 20)
pwm change-master          change the master password
```

The master password is always typed at a hidden prompt. It is never passed as an argument,
because arguments end up in the shell history and can be seen in the process list.

## Language and libraries

Python 3.11+

- `cryptography`: AES-256-GCM for encrypting the vault
- `argon2-cffi`: Argon2id to derive the key from the master password
- standard library: `argparse`, `getpass`, `secrets`, `json`

The design and threat model are in [docs/design.md](docs/design.md).

## Build and run

```
git clone https://github.com/Javid-co/password-manager.git
cd password-manager
python -m venv .venv
.venv\Scripts\activate          (Linux: source .venv/bin/activate)
pip install -r requirements.txt
python -m pwmanager init
```

## Status

Checkpoint 1: design and repo setup. The implementation starts after this.
