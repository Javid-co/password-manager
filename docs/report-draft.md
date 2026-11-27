# Password manager: project report (draft)

Javid Malikzade, ICS0022 Secure Programming, TalTech, autumn 2026

Draft for Checkpoint 3. The final version will be handed in with the code before Week 14.

## 1. Introduction

For the project I made `pwm`, a password manager that runs in the terminal. It keeps all
entries (name, username, password, notes) in one encrypted file. You open the file with a
master password. The program can add, show, list, change and delete entries, generate random
passwords and change the master password. It never prints a password. When you need one, it is
copied to the clipboard and removed again after 20 seconds.

I kept the list of features short and spent the time on using what we learned in the course
on a small real program: threat modelling (Week 2), safe file handling (Week 3), input validation
(Week 4), error handling (Week 9), protecting secrets (Week 10), multi-user systems (Week 11)
and static and dynamic analysis (Week 12).

I wrote it in Python 3.10+ with two libraries: `cryptography` for AES-256-GCM and
`argon2-cffi` for Argon2id. I don't write any crypto myself.

The tool is for one person on their own computer. Syncing, a browser extension, a GUI and
sharing a vault between people are out of scope. Malware running as the same user, a
keylogger, or someone with admin or root rights are also out of scope, because a local program
can't protect against them. The full threat model is in `docs/design.md`.

## 2. Implementation

### 2.1 Structure

The code is in `src/pwmanager/`, about 1650 lines in 10 modules.

| Module | What it does |
|---|---|
| `cli.py` | Commands, prompts, error handling at the top level |
| `vault.py` | Create, unlock, lock, and all record operations |
| `crypto.py` | Argon2id, AES-256-GCM, checks on the vault header |
| `storage.py` | Reading and writing the vault file, the vault lock |
| `validate.py` | Rules for every input field |
| `access.py` | File owner and permission checks (Linux and Windows) |
| `audit.py` | The audit log |
| `secmem.py` | Locked key buffer and wiping secrets |
| `clipboard.py` | Copy and clear the clipboard |
| `errors.py` | `PwmError`, the base class for our own errors |

A command always goes the same way. The CLI checks the arguments, asks for the master password
at a hidden prompt, and the vault module unlocks the vault. The command runs inside a `with`
block. At the end of the block the vault is locked again: the key and all fields are wiped and
the file lock is released.

### 2.2 Encryption and vault format

When a vault is created, a random 16-byte salt is made. The key is derived with Argon2id
(3 iterations, 64 MiB of memory, 4 lanes, 32-byte output). The entries are turned into JSON and
encrypted with AES-256-GCM. A new random 12-byte nonce is made on every save, so a nonce is
never used twice with the same key.

The vault file is JSON with a readable header (format, version, KDF settings, salt, nonce) and
the ciphertext. The header is passed to GCM as associated data, so changing any part of it
makes decryption fail. No hash of the master password is stored. The vault simply opens if
GCM decryption works. A wrong password and a changed file give the same error, so the error
message doesn't help an attacker.

Before anything is decrypted, the header is checked strictly: exact set of keys, known format
and version, salt and nonce of the right length, and KDF settings between a minimum (my own
default settings) and a maximum. The minimum stops someone from editing the header to make
guessing cheaper. The maximum stops a changed header from making the program use gigabytes of
memory.

### 2.3 Storage

The vault is saved atomically. The data is written to a temp file in the same folder, the file
is synced to disk with `fsync`, and then `os.replace` puts it in place of the old vault. A crash
in the middle leaves the old vault untouched. Symlinks are refused, the file is opened with
`O_NOFOLLOW` on Linux, and the vault may be at most 10 MiB.

While a command uses the vault, it holds an exclusive lock on `vault.json.lock` (`flock` on
Linux, `msvcrt.locking` on Windows). Without it, two commands started at the same time could
both load the vault, and the second save would remove what the first one added.

### 2.4 Input validation

All rules are in `validate.py`. The CLI uses them when it reads input, and the vault uses them
again inside every record operation, so code that calls the vault directly can't skip them.
The vault also checks every record it reads after decrypting.

- Entry names: allow-list `[A-Za-z0-9._@-]{1,64}`. This also stops path characters and shell
  characters.
- `--length`: ASCII digits only, 8 to 128. `int()` alone would accept `" 20"`, `"2_0"`, `"+20"`
  and even Arabic-Indic digits, so the text is checked with a regular expression first.
- Username and notes: at most 256 and 1024 characters, normalised to NFC.
- Passwords: at most 1024 characters, not normalised, because a stored password has to stay
  exactly as the website expects it.
- Master password: 12 to 1024 characters.
- Vault path: no control characters, resolved with `realpath` so `..` is removed before the
  check, must end in `.json`.

For the free text fields an allow-list of characters would be too strict (names with "ü" or
"名" are fine), so I block Unicode categories instead: control characters (Cc), invisible
format characters (Cf), lone surrogates (Cs), private use (Co), unassigned code points (Cn),
and line and paragraph separators. This stops terminal escape sequences like `ESC[2J` that
would change the screen when the field is printed. It also stops characters like U+202E
(right-to-left override) and U+200B (zero-width space). They can make a username look like
something else.

### 2.5 Per-user access control

The vault is personal, so "user" means the operating system account. Every file pwm uses (the
vault, the lock file, the log, and the `~/.pwmanager` folder) has to belong to the current user,
and nobody else may have access to it.

On Linux the owner uid must be the effective uid of the process, and the group and other bits
must be 0 (0600 for files, 0700 for folders). The check is done with `fstat` on the open file,
so it checks the file that was actually opened.

On Windows file modes don't mean anything, so I used the Win32 security API through `ctypes`.
The owner SID of the file must be the SID of the current user. The ACL may only contain entries
for that user. New files and folders get a protected ACL with a single entry: full control for
the current user. This removes the entries Windows normally inherits (SYSTEM, Administrators,
Users). After the change, `icacls` shows only `JAVID\melik:(F)` on the vault.

A file that belongs to another user is refused. A file that is ours but has too open
permissions (for example a vault made by the Checkpoint 2 version) is fixed and the fix is
logged. I chose to fix it instead of refusing, because if someone could read the file before,
refusing now would not undo that. Fixing it stops it from happening again.

Inside the program, every record operation (list, read, add, update, delete, save, change
master) starts with `_authorize()`. It refuses if the vault is already locked, or if the process
is no longer running as the user who unlocked it.

### 2.6 Logging and error handling

Key events are logged to `pwm.log` next to the vault, one JSON object per line:

```json
{"ts": "2026-11-27T16:25:41.512Z", "level": "WARNING", "event": "vault.unlock", "outcome": "fail", "reason": "bad_password_or_changed_file", "command": "list", "user": "1000", "pid": 2412}
```

The events are vault created, unlocked (and failed unlocks), saved, entry added, read, listed,
updated, deleted and copied, password generated, master password changed, access denied,
permissions fixed, input rejected, command cancelled, and unexpected errors.

To keep secrets out, the log only takes event names from a fixed list and fields from a fixed
list (`reason`, `file`, `count`), and every value has to match a pattern. Anything else is
written as `"invalid"`. So there is simply no way to log free text. Entry names are not logged
either, because the vault encrypts them on purpose. The log file is private like the vault.
If writing the log fails, the command still works and nothing is printed.

Errors: only errors the program raises on purpose (`PwmError` and its subclasses) show their
message to the user. Any other exception prints `error: unexpected error`, and the log only gets
its class name, never the message, because a library message could contain internal details.
No traceback is ever shown. After a wrong master password the program waits 2 seconds.

### 2.7 Memory handling

Python doesn't give direct control over memory, so I did what is possible:

- The key is kept in a `SecretBytes` object: one fixed `bytearray` that is locked in RAM with
  `VirtualLock` on Windows or `mlock` on Linux, so it is not written to the swap file. On lock it
  is overwritten with `ctypes.memset`.
- Argon2id is called through the low-level C function, so it writes the key straight into that
  buffer. The normal `hash_secret_raw` returns the key as a `bytes` object and copies the
  password into a buffer that is freed without being wiped.
- `bytes` and `str` objects can't be changed in Python, but in CPython their characters are
  stored at a known place inside the object. `secmem.wipe()` overwrites them there with zeros. I
  use it for the encoded master password, the decrypted plaintext, the JSON text, the typed
  passwords and the clipboard buffers.
- The vault keeps its own copy of every field, and `lock()` wipes all of them. Because they are
  copies, wiping can never change a string that other code is still using.
- Core dumps are turned off on Linux.

`wipe()` refuses strings shorter than 2 characters (Python shares those between all code) and
non-ASCII strings (they are stored differently). Overwriting a shared string would break the
interpreter, so this limit matters.

### 2.8 Testing

There are 243 pytest tests:

| File | Tests | What they cover |
|---|---|---|
| `test_validate.py` | 108 | Edge cases for every field: lengths at the limit and one over, escape sequences, U+202E, zero-width characters, surrogates, NFC, odd number formats, bad stored records |
| `test_cli.py` | 33 | Every command, wrong password, passwords never printed, bad arguments, no traceback |
| `test_access.py` | 27 | Private new files, fixing open permissions, refusing another user's file, symlinks, every record operation when locked or for another user, the vault lock |
| `test_crypto.py` | 18 | Round trip, wrong password, changed ciphertext or header, weak or huge KDF settings, nonce reuse |
| `test_secmem.py` | 18 | Wiping bytes, strings and buffers, the key wiped on lock and on a failed unlock, plaintext wiped after encrypt and decrypt, every typed secret wiped by the CLI |
| `test_storage.py` | 14 | Atomic save, no temp files left, permissions, bad paths, symlinks, size limit |
| `test_audit.py` | 12 | JSON format, all key events present, no secret in any file after using every command, log injection, a broken log doesn't break the program |
| `test_vault.py` | 9 | Create, unlock, change master password, no hash or plaintext on disk |
| `test_fuzz.py` | 4 | About 900 randomly changed vault files and payloads |

On Windows 239 pass and 4 are skipped (Linux-only checks). In WSL Ubuntu 242 pass and 1 is
skipped (a Windows-only check). I also ran the real program in a terminal on Linux with a pty:
the password prompts don't echo, the folder is 0700, the vault, lock and log files are 0600,
and none of the secrets appear in any file.

## 3. Security analysis

### 3.1 Threats and how they are handled

`docs/design.md` lists 31 threats in six groups (master password, vault at rest, vault in
memory, interface, access control, logging). The most important ones:

| Threat | Handled by | Tested |
|---|---|---|
| Offline guessing of the master password | Argon2id with 64 MiB, random salt, at least 12 characters | weak KDF settings refused |
| Reading the vault file | AES-256-GCM, entry names encrypted too | no plaintext in any file |
| Changing the vault file or header | GCM tag, header as associated data, strict header checks | changed ciphertext, salt, settings; fuzzing |
| Nonce reuse | new random nonce on every save | two saves give different nonces |
| Crash while saving | temp file, `fsync`, `os.replace` | failed write keeps the old vault |
| Symlink attacks | `lstat`, `O_NOFOLLOW`, `O_EXCL` temp files | symlink refused |
| Other users reading or planting files | owner check and private permissions on every file | A1-A2 tests on both systems |
| Two commands at once | vault lock | second unlock refused |
| Password shown on screen | never printed, clipboard cleared after 20 s | output checked in every CLI test |
| Bad input, escape sequences, look-alike text | `validate.py` in the CLI and the vault | 108 validation tests |
| Secrets in logs or error messages | allow-list log, generic errors | every command run, all files searched |
| Secrets left in memory | `SecretBytes`, `wipe()`, own copies wiped on lock | 18 memory tests |

### 3.2 Static analysis

I ran `bandit -r src`. It found 7 low severity issues, and I checked each one:

- B404, B603: `subprocess` is used for the Linux clipboard tools. The command is always one of
  the fixed lists in the code, there is no shell, and the password goes through stdin, not the
  command line. So command injection isn't possible.
- B105: it read `"password": 1024` as a hard-coded password. It is the maximum length.
- B110 (three times): `try/except/pass` in `__del__` and in the log handler. Here it is on
  purpose. `__del__` must not raise, and a broken log must not stop the command or print a
  traceback.

Each of them has a `# nosec` comment and a short reason in the code. After that bandit reports
no issues.

### 3.3 Dynamic analysis

`test_fuzz.py` is a simple fuzzer. It takes a valid vault and changes it at random: flipped
bits, removed and inserted bytes, cut files, changed header fields with wrong types, 200 000
levels of nested brackets, and correctly encrypted payloads with the wrong structure. The only
allowed result is that the vault opens or one of our own errors comes out. One case worth
mentioning is deep nesting: `json.loads` raises `RecursionError` for it, which is not a JSON
error, so without a separate `except` it would have ended as "unexpected error". `storage.py`
catches it and gives "could not unlock vault" like for any other broken file, and the fuzz test
checks that.

### 3.4 What is still not protected

- **Python strings (R1).** Non-ASCII strings can't be wiped, and the JSON encoder and the
  libraries make short-lived copies I can't reach. OpenSSL also keeps its own copy of the AES
  key while it is in use. The secrets only live for the length of one command, which limits
  this.
- **Rollback (V8).** Someone who can write to the folder can put an older copy of the vault
  back. They still need the master password to read it, so they only gain old data.
- **Same-user malware.** Anything running as the same user can read the process memory, the
  clipboard and the keyboard. This was out of scope from the start.
- **Administrators.** On Windows an administrator can take ownership of any file, and root can
  read anything on Linux. The private ACL and the 0600 mode don't stop them.
- **The 2 second delay** only slows someone typing at the prompt. A copied vault file is
  attacked offline, where only Argon2id helps.
- **Clipboard managers.** On Windows the program asks Windows not to keep the password in the
  clipboard history, but a third party clipboard manager may ignore that.

## 4. Conclusion

The password manager does what I planned in Checkpoint 1. The vault is encrypted with a modern
scheme, the master password is never stored, passwords are never printed, and every file
belongs to and can only be read by its user. Every input field is validated in one place, the
important events are logged without secrets, and the error messages don't show internals.

The part that took the most work was memory handling. Python protects you from buffer
overflows, but it also makes it hard to remove a secret from memory, because strings are
immutable and copies are made everywhere. Writing into the objects with `ctypes` works, but only
with care, and I had to make sure the vault only wipes its own copies.

The Windows access control was also harder than I expected. `chmod 600` has no effect there,
so I had to read and write ACLs through the Win32 API.

If I continued the project, I would add a counter in the vault header to detect rollback, look
at moving the decrypted entries into locked memory too, and run a real coverage-guided fuzzer
like Atheris on the vault reader.
