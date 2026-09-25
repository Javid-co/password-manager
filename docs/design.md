# Design document

Password manager, ICS0022 Secure Programming, Checkpoint 1.

## 1. Architecture

The program has four parts:

- **CLI**: parses commands, reads the master password with `getpass` (not echoed) and prints results.
  All user input goes through here and gets validated before it reaches the other modules.
- **User management**: handles unlocking the vault, changing the master password and locking
  the vault again when the command finishes. It never stores the master password. A password is
  correct when the vault decrypts successfully.
- **Encryption module**: derives the key from the master password with Argon2id, and encrypts or
  decrypts the vault with AES-256-GCM. This is the only module that uses the crypto libraries.
- **Storage layer**: reads and writes the vault file. It does not know anything about the
  contents; it only handles bytes, file permissions and safe writing.

```mermaid
flowchart LR
    user([User])

    subgraph proc [pwm process - trusted]
        cli[CLI<br/>argparse, getpass,<br/>input validation]
        um[User management<br/>unlock, lock,<br/>change master password]
        enc[Encryption module<br/>Argon2id + AES-256-GCM]
        mem[(Decrypted entries<br/>+ key, in memory only)]
        store[Storage layer<br/>read/write vault file]
    end

    disk[(vault.json on disk<br/>salt, nonce, ciphertext)]
    clip[[System clipboard]]

    user -- "command + master password" --> cli
    cli --> um
    um -- "master password" --> enc
    enc -- "key" --> mem
    um -- "load / save" --> store
    store -- "encrypted bytes" --> enc
    enc -- "encrypted bytes" --> store
    store <--> disk
    cli -- "copy password" --> clip
    mem --> cli
```

### Data flow

Unlocking (for example `pwm get github`):
1. The CLI asks for the master password at a hidden prompt.
2. User management asks the storage layer for the vault file.
3. The storage layer reads `vault.json` and returns it.
4. The encryption module takes the salt and the KDF settings from the file, derives the key with
   Argon2id and decrypts the ciphertext with AES-GCM.
5. If decryption fails, the password is wrong or the file was changed. The user gets the same
   error message in both cases.
6. If it works, the entries are kept in memory, the command runs, and the result is printed.

Saving (after `add`, `update`, `delete`):
1. The entries are turned into JSON and encrypted with the same key and a new random nonce.
2. The storage layer writes the result to a temporary file in the same folder with permissions
   0600, and then replaces the old vault with it. A crash in the middle cannot leave a
   half-written vault.

### Where data lives

| Data | Where | Protected by |
|---|---|---|
| Vault (all entries) | `~/.pwmanager/vault.json` | AES-256-GCM, file mode 0600 |
| Salt, nonce, KDF settings | inside `vault.json`, not encrypted | not secret, but covered by the GCM tag so changes are detected |
| Encryption key | process memory only | never written to disk, removed when the command ends |
| Master password | process memory only, only during unlock | never stored anywhere |
| Decrypted entries | process memory only | removed when the command ends |
| Copied password | system clipboard | cleared after 20 seconds |

### Trust boundaries

1. **User / terminal to CLI.** Everything typed in is untrusted: command names, entry names,
   lengths. The CLI validates it before passing it on.
2. **Disk to storage layer.** The vault file can be read, copied, changed, or replaced (for
   example by a symlink) by someone else. It is not trusted until the GCM tag has been verified.
3. **Clipboard.** Other programs can read it, so a password only stays there for a short time.

Everything inside the `pwm` process is treated as trusted. Attacks on the machine itself, like
malware running as the same user or a keylogger, are out of scope. There is more on this in the
threat model.

## 2. Threat model

I followed the steps from the Week 2 lecture: identify the assets, describe the architecture,
break the app into parts, then identify, document and rate the threats. The architecture and the
parts are in section 1, so this section starts with the assets.

### Assets

- A1: the master password
- A2: the stored credentials (usernames, passwords, notes)
- A3: the encryption key derived from the master password
- A4: the vault file itself (it has to stay intact and usable)

### Attackers I considered

- Someone who gets a copy of `vault.json` (stolen laptop, backup, cloud sync folder)
- Another user on the same machine
- Someone looking at the screen
- The user making mistakes (typing something wrong, the program crashing while saving)

Out of scope: malware running as the same user, keyloggers, and someone with root or admin
access. If the machine is compromised like that, a local password manager can't protect the
vault.

### Rating

Each threat is rated High, Medium or Low, based on how likely it is and how bad the result
would be.

### 2.1 Master password

| ID | Threat | Rating | Mitigation |
|---|---|---|---|
| M1 | Attacker with a copy of the vault guesses the master password offline (brute force or wordlist) | High | Key is derived with Argon2id (64 MiB memory, 3 iterations), so every guess is slow. A random 16-byte salt per vault stops precomputed tables. `init` requires at least 12 characters. |
| M2 | Master password is visible while typing | Low | Read with `getpass`, so it is not echoed. |
| M3 | Master password ends up in shell history or the process list | Medium | There is no option to pass it as an argument. It is only read from the prompt. |
| M4 | Master password or key leaks through an error message or traceback | Medium | Exceptions are caught at the top of the program and only a short generic message is printed. Nothing secret is logged. |
| M5 | Error messages tell an attacker whether the password was wrong or the file was changed | Low | The same message is printed for both: "could not unlock vault". |

### 2.2 Vault at rest

| ID | Threat | Rating | Mitigation |
|---|---|---|---|
| V1 | Someone reads the vault file | High | All entries are encrypted with AES-256-GCM. Only the salt, nonce and KDF settings are stored in plain text, and they are not secret. |
| V2 | Someone modifies the vault file (ciphertext or header) | High | GCM authenticates the ciphertext. The header (version, salt, KDF settings) is passed as associated data, so changing it also makes decryption fail. |
| V3 | Attacker lowers the KDF settings in the header to make guessing faster | Medium | The program refuses to open a vault with settings below the minimum values it uses itself. |
| V4 | The same nonce is used twice with the same key, which breaks GCM | High | A new random 12-byte nonce is made with `os.urandom` on every save. |
| V5 | Another user on the machine reads the file | Medium | The vault folder is created with mode 0700 and the file with 0600. |
| V6 | The program crashes while saving and leaves a broken vault | Medium | It writes to a temporary file in the same folder, calls `fsync`, and then uses `os.replace`, which is atomic. The old vault stays until the new one is complete. |
| V7 | Symlink attack: the vault or temp file path is replaced with a link to another file (Week 3) | Medium | The temp file is created with `tempfile.mkstemp` (uses `O_CREAT \| O_EXCL`). Before opening, the vault path is checked with `os.lstat` and rejected if it is a symlink. On Linux it is opened with `O_NOFOLLOW`. |
| V8 | An older copy of the vault is put back (rollback) | Low | Not fully prevented. The old copy still needs the master password, so the attacker only gets old data back. I accept this risk for this project. |

### 2.3 Vault in memory

| ID | Threat | Rating | Mitigation |
|---|---|---|---|
| R1 | Key and decrypted entries stay in memory longer than needed | Medium | Each command unlocks, does its job and exits, so secrets only live for the length of one command. The key is kept in a `bytearray` and overwritten with zeros when done. Python strings can't be wiped, so this is only partly possible. That limitation is accepted. |
| R2 | Secrets are written to disk in a crash dump | Low | On Linux, core dumps are disabled at startup with `resource.setrlimit(RLIMIT_CORE, 0)`. |
| R3 | Secrets appear in a traceback on screen | Medium | Same as M4: exceptions are handled at the top level and tracebacks are not shown to the user. |

### 2.4 Interface (CLI)

| ID | Threat | Rating | Mitigation |
|---|---|---|---|
| I1 | Bad or very long input (entry names, field values, numbers) causes errors or unexpected behaviour | Medium | Input is validated with an allow-list (Week 4). Entry names must match `[A-Za-z0-9._@-]{1,64}`. Other fields have a maximum length. `--length` must be a number between 8 and 128. Anything else is rejected. |
| I2 | Path traversal through a custom vault path (`../`) | Medium | The vault path is turned into an absolute path with `os.path.realpath` and must end in `.json`. It is only opened after this check. |
| I3 | Password shown on screen | Low | `get` hides the password by default. It is only printed with `--show`. |
| I4 | Password stays in the clipboard and other programs read it | Medium | The clipboard is cleared after 20 seconds, but only if it still holds the copied password. |
| I5 | Generated passwords are predictable | High | They are made with the `secrets` module, not `random`. |
| I6 | An entry or the vault is deleted by mistake | Low | `delete` asks for confirmation. `init` refuses to overwrite an existing vault. |

## 3. Design decisions

### Language and libraries

I chose Python because it lets me spend the time on the security parts instead of memory
management. Most of the memory bugs from the lectures (buffer overflows, off-by-one errors,
missing null terminators) can't happen in normal Python code. The downside is that I have less
control over memory, so secrets can't be fully wiped (see R1).

- `cryptography`: well maintained and uses OpenSSL underneath. I use its `AESGCM` class. I don't
  use `Fernet`, because it is AES-128-CBC + HMAC and doesn't support associated data, which I
  need for the header (V2).
- `argon2-cffi`: Argon2id is memory-hard, so guessing with GPUs is much more expensive than with
  PBKDF2. I use the low-level `hash_secret_raw` function to get a raw 32-byte key.
- `secrets` and `os.urandom` for all random values (salt, nonce, generated passwords).
- I don't write any crypto myself.

### Crypto scheme

1. On `init`, a random 16-byte salt is generated.
2. key = Argon2id(master password, salt, time_cost=3, memory_cost=64 MiB, parallelism=4,
   output 32 bytes)
3. On every save, a new random 12-byte nonce is generated.
4. ciphertext = AES-256-GCM(key, nonce, plaintext = entries as JSON, associated data = header)
5. On load, the same key is derived from the salt in the file. If decryption or the tag check
   fails, the vault is not opened.

Changing the master password makes a new salt and a new key and re-encrypts everything.

### Vault format

The vault is one JSON file. The header is readable but authenticated. Everything else is inside
the ciphertext, so an attacker can't even see the entry names or how many entries there are.

```json
{
  "header": {
    "format": "pwm-vault",
    "version": 1,
    "kdf": "argon2id",
    "kdf_params": { "time_cost": 3, "memory_cost": 65536, "parallelism": 4 },
    "salt": "<base64, 16 bytes>",
    "cipher": "aes-256-gcm",
    "nonce": "<base64, 12 bytes>"
  },
  "ciphertext": "<base64, encrypted entries + 16-byte GCM tag>"
}
```

The header is turned into bytes with `json.dumps(header, sort_keys=True, separators=(",", ":"))`
and used as the associated data. This way the bytes are always the same when the file is read
back.

After decryption, the plaintext looks like this:

```json
{
  "entries": {
    "github": {
      "username": "javid",
      "password": "...",
      "notes": "",
      "created": "2026-09-25T18:00:00Z",
      "modified": "2026-09-25T18:00:00Z"
    }
  }
}
```

The `version` field is there so the format can change later without breaking old vaults.

I also considered SQLite with encrypted fields. I didn't choose it because entry names and the
number of entries would be visible, and it adds more code. Encrypting the whole file is simpler
and hides more. The downside is that the whole vault is rewritten on every save, which is fine
for a personal vault with a few hundred entries.
