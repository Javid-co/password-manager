# password-manager

Command-line password manager for the ICS0022 Secure Programming course.

## Scope

A local password manager for one user. All entries are stored in one encrypted vault file,
and the vault is unlocked with a master password.

Features:
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
pwm init                              create a new vault
pwm add <name> [--generate]           add an entry (--generate makes a random password)
pwm get <name> [--copy]               show an entry, the password stays hidden
                                      (--copy puts it on the clipboard for 20 seconds)
pwm list                              list entry names and usernames
pwm update <name> [--generate]        edit an entry
pwm delete <name>                     delete an entry (asks first)
pwm generate [--length N]             generate a password and copy it (default length 20)
pwm change-master                     change the master password
```

`--length` can be 8 to 128 and also works with `add` and `update`. All commands take
`--vault PATH` before the command name to use a different vault file (it must end in `.json`).
The default vault is `~/.pwmanager/vault.json`.

The master password is always typed at a hidden prompt. It is never passed as an argument,
because arguments end up in the shell history and can be seen in the process list.
The program never prints a password. `get --copy` and `generate` copy it to the clipboard,
and the clipboard is cleared after 20 seconds (or right away with Ctrl+C).

## Language and libraries

Python 3.10+

- `cryptography`: AES-256-GCM for encrypting the vault
- `argon2-cffi`: Argon2id to derive the key from the master password
- standard library: `argparse`, `getpass`, `secrets`, `json`

The design and threat model are in [docs/design.md](docs/design.md).

## Build and run

You need Python 3.10 or newer and git.

Windows (PowerShell):

```
git clone https://github.com/Javid-co/password-manager.git
cd password-manager
python -m venv .venv
Set-ExecutionPolicy -Scope Process RemoteSigned -Force
.venv\Scripts\activate
pip install .
pwm init
```

The `Set-ExecutionPolicy` line only applies to the open PowerShell window. Without it, Windows
refuses to run the activate script of the venv.

Linux / macOS:

```
git clone https://github.com/Javid-co/password-manager.git
cd password-manager
python3 -m venv .venv
source .venv/bin/activate
pip install .
pwm init
```

On Debian/Ubuntu you may need `sudo apt install python3-venv` first. For the clipboard on
Linux, install one of `wl-clipboard`, `xclip` or `xsel`. Without one of them everything works
except `--copy` and `generate`.

`python -m pwmanager` works the same as `pwm`.

Example:

```
pwm init
pwm add github
pwm list
pwm get github --copy
```

### Running the tests

```
pip install -e ".[dev]"
python -m pytest
bandit -r src
```

There are 243 tests. A few only run on Linux/macOS (file modes, symlinks) or only on Windows
(page locking), so on Windows 239 pass and 4 are skipped, and on Linux 242 pass and 1 is skipped.

### Files pwm creates

Next to the vault (by default in `~/.pwmanager/`):

- `vault.json`: the encrypted vault
- `vault.json.lock`: an empty file that is locked while a command uses the vault
- `pwm.log`: the audit log, one JSON event per line, never contains secrets

All of them can only be accessed by the user who owns them (0600 on Linux, a private ACL on
Windows). pwm refuses to use a file that belongs to another user.

## Project layout

```
src/pwmanager/
  cli.py        commands, prompts, error handling
  vault.py      user management: create, unlock, record operations, change master password
  crypto.py     Argon2id and AES-256-GCM, vault format checks
  storage.py    reading and writing the vault file safely, vault lock
  validate.py   input validation rules for every field
  access.py     per-user access control (file owner and permissions)
  audit.py      structured audit log
  secmem.py     locked key buffer and wiping secrets from memory
  clipboard.py  copy and clear the clipboard
  errors.py     base error class
tests/          pytest tests for each module, plus a fuzz test
docs/           design document, report draft and progress notes
```

## Status

- Checkpoint 1: design and repo setup (done)
- Checkpoint 2: core features working, see [docs/progress-checkpoint2.md](docs/progress-checkpoint2.md)
- Checkpoint 3: near-final, see [docs/progress-checkpoint3.md](docs/progress-checkpoint3.md)
  and the draft report [docs/report-draft.md](docs/report-draft.md)
