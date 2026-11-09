"""Command-line interface for pwm.

Everything typed in is untrusted (trust boundary 1 in docs/design.md), so it
is checked here before it reaches the other modules. Passwords are never
printed: get and generate copy them to the clipboard instead.
"""

import argparse
import getpass
import re
import secrets
import string
import sys
import time

from . import clipboard, storage
from .crypto import VaultError
from .vault import Vault

NAME_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}")
LENGTH_RE = re.compile(r"[0-9]{1,3}")
MIN_GEN_LEN, MAX_GEN_LEN, DEFAULT_GEN_LEN = 8, 128, 20
MAX_USERNAME_LEN = 256
MAX_PASSWORD_LEN = 1024
MAX_NOTES_LEN = 1024
CLIPBOARD_SECONDS = 20

# argparse itself exits with 2 for bad arguments.
EXIT_OK, EXIT_ERROR, EXIT_CANCELLED = 0, 1, 130


class UserError(Exception):
    """An error with a message that is safe to show to the user."""


# ---------------------------------------------------------------- validation (I1)

def entry_name(value):
    if not NAME_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "entry name must be 1-64 characters: letters, digits, . _ @ -")
    return value


def gen_length(value):
    # int() alone would also accept " 20", "2_0" and "+20", so check the text first.
    if not LENGTH_RE.fullmatch(value) or not MIN_GEN_LEN <= int(value) <= MAX_GEN_LEN:
        raise argparse.ArgumentTypeError(
            f"length must be a whole number from {MIN_GEN_LEN} to {MAX_GEN_LEN}")
    return int(value)


def check_field(label, value, max_len):
    if len(value) > max_len:
        raise UserError(f"{label} is too long (max {max_len} characters)")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise UserError(f"{label} must not contain control characters")
    return value


# ---------------------------------------------------------------- prompts

def ask(prompt, label, max_len):
    return check_field(label, input(prompt), max_len)


def ask_secret(prompt, label="password", max_len=MAX_PASSWORD_LEN):
    # M2, M3: only ever read at a hidden prompt.
    return check_field(label, getpass.getpass(prompt), max_len)


def ask_new_password(label):
    first = ask_secret(f"{label}: ", label)
    if not first:
        raise UserError(f"{label} must not be empty")
    if ask_secret(f"Repeat {label.lower()}: ", label) != first:
        raise UserError("the passwords do not match")
    return first


def confirm(prompt):
    return input(prompt + " [y/N] ").strip().lower() in ("y", "yes")


# ---------------------------------------------------------------- helpers

def generate_password(length):
    """I5: uses secrets, and makes sure every character class is present."""
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw


def copy_and_clear(password, what="Password"):
    """Copy to the clipboard, wait, then clear it (I4)."""
    clipboard.copy(password)
    print(f"{what} copied to the clipboard. It will be cleared in "
          f"{CLIPBOARD_SECONDS} seconds (Ctrl+C to clear now).")
    try:
        time.sleep(CLIPBOARD_SECONDS)
    except KeyboardInterrupt:
        pass
    finally:
        clipboard.clear_if_unchanged(password)
    print("Clipboard cleared.")


def unlock(args):
    master = getpass.getpass("Master password: ")
    return Vault.unlock(args.vault, master)


# ---------------------------------------------------------------- commands

def cmd_init(args):
    if storage.exists(args.vault):
        raise UserError("a vault already exists at " + args.vault)
    print("Choose a master password (at least 12 characters). It cannot be recovered.")
    master = ask_new_password("Master password")
    with Vault.create(args.vault, master):
        pass
    print("Created a new vault at " + args.vault)


def cmd_add(args):
    with unlock(args) as v:
        if args.name in v.entries:
            raise UserError(f"an entry called '{args.name}' already exists (use update)")
        username = ask("Username: ", "username", MAX_USERNAME_LEN)
        if args.generate:
            password = generate_password(args.length)
        else:
            password = ask_new_password("Password")
        notes = ask("Notes (optional): ", "notes", MAX_NOTES_LEN)
        v.add(args.name, username, password, notes)
        v.save()
    print(f"Added '{args.name}'.")
    if args.generate:
        print("A random password was generated. Use 'pwm get --copy "
              f"{args.name}' to copy it.")


def cmd_get(args):
    with unlock(args) as v:
        entry = dict(v.get(args.name))
    print(f"name:      {args.name}")
    print(f"username:  {entry.get('username', '')}")
    print("password:  ******** (hidden, use --copy)")
    print(f"notes:     {entry.get('notes', '')}")
    print(f"created:   {entry.get('created', '')}")
    print(f"modified:  {entry.get('modified', '')}")
    if args.copy:
        copy_and_clear(entry.get("password", ""))


def cmd_list(args):
    with unlock(args) as v:
        rows = sorted((name, e.get("username", "")) for name, e in v.entries.items())
    if not rows:
        print("The vault is empty.")
        return
    width = max(len(name) for name, _ in rows)
    for name, username in rows:
        print(f"{name:<{width}}  {username}")
    print(f"{len(rows)} entr{'y' if len(rows) == 1 else 'ies'}")


def cmd_update(args):
    with unlock(args) as v:
        entry = v.get(args.name)
        print("Press Enter to keep the current value.")
        username = ask(f"Username [{entry.get('username', '')}]: ", "username", MAX_USERNAME_LEN)
        if args.generate:
            password = generate_password(args.length)
        elif confirm("Change the password?"):
            password = ask_new_password("New password")
        else:
            password = None
        notes = ask("Notes: ", "notes", MAX_NOTES_LEN)
        v.update(args.name, username=username or None, password=password, notes=notes or None)
        v.save()
    print(f"Updated '{args.name}'.")


def cmd_delete(args):
    with unlock(args) as v:
        v.get(args.name)
        if not confirm(f"Delete '{args.name}'? This cannot be undone."):
            print("Nothing deleted.")
            return
        v.delete(args.name)
        v.save()
    print(f"Deleted '{args.name}'.")


def cmd_generate(args):
    copy_and_clear(generate_password(args.length), "Generated password")


def cmd_change_master(args):
    with unlock(args) as v:
        new = ask_new_password("New master password")
        v.change_master(new)
    print("Master password changed. The vault was encrypted again with a new key.")


# ---------------------------------------------------------------- parser

def build_parser():
    p = argparse.ArgumentParser(
        prog="pwm", description="Secure command-line password manager (ICS0022).")
    p.add_argument("--vault", metavar="PATH", default=None,
                   help=f"vault file (default {storage.DEFAULT_PATH})")
    sub = p.add_subparsers(dest="command", metavar="command", required=True)

    def length_arg(sp):
        sp.add_argument("--length", type=gen_length, default=DEFAULT_GEN_LEN,
                        help=f"generated length, {MIN_GEN_LEN}-{MAX_GEN_LEN} "
                             f"(default {DEFAULT_GEN_LEN})")

    s = sub.add_parser("init", help="create a new vault")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("add", help="add an entry")
    s.add_argument("name", type=entry_name)
    s.add_argument("--generate", action="store_true", help="generate a random password")
    length_arg(s)
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("get", help="show an entry (the password stays hidden)")
    s.add_argument("name", type=entry_name)
    s.add_argument("--copy", action="store_true", help="copy the password to the clipboard")
    s.set_defaults(func=cmd_get)

    s = sub.add_parser("list", help="list entry names")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("update", help="edit an entry")
    s.add_argument("name", type=entry_name)
    s.add_argument("--generate", action="store_true", help="replace the password with a random one")
    length_arg(s)
    s.set_defaults(func=cmd_update)

    s = sub.add_parser("delete", help="delete an entry")
    s.add_argument("name", type=entry_name)
    s.set_defaults(func=cmd_delete)

    s = sub.add_parser("generate", help="generate a password and copy it to the clipboard")
    length_arg(s)
    s.set_defaults(func=cmd_generate)

    s = sub.add_parser("change-master", help="change the master password")
    s.set_defaults(func=cmd_change_master)
    return p


def disable_core_dumps():
    """R2: no core dump with secrets in it (Linux/macOS only)."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


def main(argv=None):
    disable_core_dumps()
    args = build_parser().parse_args(argv)

    # M4, R3: catch everything, print a short message, never a traceback.
    try:
        args.vault = storage.resolve_path(args.vault)
        args.func(args)
        return EXIT_OK
    except VaultError:
        print("error: could not unlock vault", file=sys.stderr)
    except (UserError, storage.StorageError, clipboard.ClipboardError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
    except KeyError as e:
        print(f"error: {e.args[0]}", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print("\ncancelled", file=sys.stderr)
        return EXIT_CANCELLED
    except Exception:
        print("error: unexpected error", file=sys.stderr)
    return EXIT_ERROR
