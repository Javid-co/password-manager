# Checkpoint 3 progress note

Javid Malikzade, ICS0022 Secure Programming, Password Manager

The draft report is in [report-draft.md](report-draft.md). The design doc has new threat
groups for access control (A1-A4) and logging (L1-L4), and M6.

| Requirement | Where | How |
|---|---|---|
| Secure memory handling | `secmem.py`, `crypto.py`, `vault.py`, `cli.py` | The key is in a `SecretBytes` buffer locked in RAM and wiped on lock. Argon2id writes into it directly. The plaintext, JSON text, typed passwords and the vault's copies of all fields are overwritten in place. |
| Input validation on all fields | `validate.py` | One module for every field. Used by the CLI, by every vault operation, and on the records read from a decrypted vault. Blocks control and invisible Unicode characters, NFC for text, exact limits. |
| Structured logging, secure error handling | `audit.py`, `cli.py` | JSON lines in `pwm.log`. Only known events and fields, every value must match a pattern, so no secrets. Only our own error messages are shown, other errors are "unexpected error" and logged by class name. 2 s delay after a wrong password. |
| Per-user access control on every record operation | `access.py`, `storage.py`, `vault.py` | Every file must belong to the current user and be private (0600/0700 on Linux, private ACL on Windows). Every record operation starts with `_authorize()`. A lock file stops two commands at once. |
| Tests | `tests/` | 243 tests, including 108 validation edge cases, 18 memory checks and a fuzz test. Windows: 239 passed, 4 skipped. WSL Ubuntu: 242 passed, 1 skipped. |
| Draft report | `docs/report-draft.md` | Introduction, Implementation, Security Analysis, Conclusion. |

Also done: `bandit -r src` reports no issues (7 low findings checked and marked with a reason),
and a real terminal run on Linux to check that prompts don't echo and file modes are right.

## Still to do before the final hand-in

- Finish the report and add screenshots
- Prepare the presentation (why Argon2id, why no stored hash, header tampering, nonce reuse,
  how the ACL check works)
