"""Command-line interface for pwm.

Everything typed in is untrusted (trust boundary 1 in docs/design.md), so it
is checked with the validate module before it reaches the other modules.
Passwords are never printed: get and generate copy them to the clipboard.

Error handling (M4, L2): only errors we raise on purpose (PwmError) show
their message. Anything else prints "unexpected error" and is logged by its
class name only, never with its message, because a library message could
contain internal details. No traceback is ever shown.
"""

import argparse
import getpass
import secrets
import string
import sys
import time

from . import audit, clipboard, secmem, storage, validate
from .access import AccessDenied
from .crypto import VaultError
from .errors import PwmError
from .validate import DEFAULT_GEN_LEN, MAX_GEN_LEN, MIN_GEN_LEN, ValidationError
from .vault import Vault

CLIPBOARD_SECONDS = 20
# M6: wait after a wrong master password, so guessing at the prompt is slow.
# (Offline guessing is slowed down by Argon2id, see M1.)
FAIL_DELAY_SECONDS = 2

# argparse itself exits with 2 for bad arguments.
EXIT_OK, EXIT_ERROR, EXIT_CANCELLED = 0, 1, 130


class UserError(PwmError):
    """An error with a message that is safe to show to the user."""


# ---------------------------------------------------------------- argparse types

def _arg_type(check):
    def convert(value):
        try:
            return check(value)
        except ValidationError as e:
            raise argparse.ArgumentTypeError(str(e)) from None
    convert.__name__ = check.__name__
    return convert


entry_name = _arg_type(validate.entry_name)
gen_length = _arg_type(validate.gen_length)


# ---------------------------------------------------------------- prompts

def ask(prompt, check):
    return check(input(prompt))


def ask_secret(prompt, check):
    """M2, M3: secrets are only ever read at a hidden prompt."""
    value = getpass.getpass(prompt)
    try:
        return check(value)
    except BaseException:
        secmem.wipe(value)
        raise


def ask_new_password(label, check):
    first = ask_secret(f"{label}: ", lambda v: check(v, label.lower()))
    second = getpass.getpass(f"Repeat {label.lower()}: ")
    a, b = first.encode("utf-8"), second.encode("utf-8")
    try:
        same = secrets.compare_digest(a, b)
    finally:
        secmem.wipe_all(a, b, second)
    if not same:
        secmem.wipe(first)
        raise UserError("the passwords do not match")
    return first


def confirm(prompt):
    return ask(prompt + " [y/N] ", validate.answer) in ("y", "yes")


# ---------------------------------------------------------------- helpers

def generate_password(length):
    """I5: uses secrets, and makes sure every character class is present."""
    length = validate.gen_length(length)
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw
        secmem.wipe(pw)


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
    master = ask_secret("Master password: ", validate.master_password_attempt)
    try:
        return Vault.unlock(args.vault, master)
    except VaultError:
        time.sleep(FAIL_DELAY_SECONDS)
        raise
    finally:
        secmem.wipe(master)


def ask_entry_password(args):
    if args.generate:
        return generate_password(args.length)
    return ask_new_password("Password", validate.password)


# ---------------------------------------------------------------- commands
# Everything that uses data from the vault happens inside the with block,
# because lock() overwrites the strings at the end of it.

def cmd_init(args):
    if storage.exists(args.vault):
        raise UserError("a vault already exists at " + args.vault)
    print(f"Choose a master password (at least {validate.MIN_MASTER_LEN} characters). "
          "It cannot be recovered.")
    master = ask_new_password("Master password", validate.master_password)
    try:
        with Vault.create(args.vault, master):
            pass
    finally:
        secmem.wipe(master)
    print("Created a new vault at " + args.vault)


def cmd_add(args):
    with unlock(args) as v:
        if v.exists(args.name):
            raise UserError(f"an entry called '{args.name}' already exists (use update)")
        username = ask("Username: ", validate.username)
        password = ask_entry_password(args)
        try:
            notes = ask("Notes (optional): ", validate.notes)
            v.add(args.name, username, password, notes)
            v.save()
        finally:
            secmem.wipe(password)
    print(f"Added '{args.name}'.")
    if args.generate:
        print("A random password was generated. Use 'pwm get --copy "
              f"{args.name}' to copy it.")


def cmd_get(args):
    with unlock(args) as v:
        entry = v.get(args.name)
        print(f"name:      {args.name}")
        print(f"username:  {entry['username']}")
        print("password:  ******** (hidden, use --copy)")
        print(f"notes:     {entry['notes']}")
        print(f"created:   {entry['created']}")
        print(f"modified:  {entry['modified']}")
        if args.copy:
            audit.event("entry.copy")
            copy_and_clear(entry["password"])


def cmd_list(args):
    with unlock(args) as v:
        rows = v.names()
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
        username = ask(f"Username [{entry['username']}]: ", validate.username)
        if args.generate or confirm("Change the password?"):
            password = ask_entry_password(args)
        else:
            password = None
        try:
            notes = ask("Notes: ", validate.notes)
            v.update(args.name, username=username or None, password=password,
                     notes=notes or None)
            v.save()
        finally:
            if password is not None:
                secmem.wipe(password)
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
    password = generate_password(args.length)
    try:
        audit.event("password.generate")
        copy_and_clear(password, "Generated password")
    finally:
        secmem.wipe(password)


def cmd_change_master(args):
    with unlock(args) as v:
        new = ask_new_password("New master password", validate.master_password)
        try:
            v.change_master(new)
        finally:
            secmem.wipe(new)
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


def _error(message):
    print(f"error: {message}", file=sys.stderr)
    return EXIT_ERROR


def main(argv=None):
    disable_core_dumps()
    args = build_parser().parse_args(argv)

    # M4, R3, L2: catch everything, print a short message, never a traceback.
    try:
        args.vault = storage.resolve_path(args.vault)
        audit.setup(args.vault, args.command)
        args.func(args)
        return EXIT_OK
    except VaultError:
        # Already logged by the vault. Same message for every reason (M5).
        return _error("could not unlock vault")
    except AccessDenied as e:
        audit.event("access.denied", "denied", reason=type(e).__name__)
        return _error(e)
    except ValidationError as e:
        audit.event("input.rejected", "fail")
        return _error(e)
    except PwmError as e:
        audit.event("error", "fail", reason=type(e).__name__)
        return _error(e)
    except (KeyboardInterrupt, EOFError):
        audit.event("command.cancelled", "fail")
        print("\ncancelled", file=sys.stderr)
        return EXIT_CANCELLED
    except Exception as e:
        audit.event("error", "fail", reason=type(e).__name__)
        return _error("unexpected error")
    finally:
        audit.shutdown()
