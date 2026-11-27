"""Structured audit log of key events (M4, L1-L3 in docs/design.md).

Every event is one JSON object on its own line in pwm.log, in the same
folder as the vault, for example:

{"ts": "2026-11-27T18:00:00.123Z", "level": "WARNING", "event": "vault.unlock",
 "outcome": "fail", "reason": "bad_password_or_changed_file", "command": "get",
 "user": "1000", "pid": 4242}

How secrets are kept out of the log:
- Only event names from EVENTS can be logged.
- Extra fields must be in FIELDS, and each value has to match a strict
  pattern. A value that does not match is written as "invalid". So the log
  can never contain free text, and so no password, username, note, entry
  name or error message can end up in it.
- Entry names are not logged at all, because the vault encrypts them on
  purpose (see "Vault format" in docs/design.md).

The log file gets the same protection as the vault: owned by the current
user, 0600 / private ACL, no symlinks. Writing the log must never stop the
program or print anything, so all errors while logging are ignored.
"""

import datetime
import json
import logging
import os
import re

from . import access

LOG_NAME = "pwm.log"
MAX_LOG_SIZE = 1024 * 1024  # then pwm.log is moved to pwm.log.1

EVENTS = frozenset({
    "vault.init", "vault.unlock", "vault.save",
    "entry.add", "entry.read", "entry.list", "entry.update", "entry.delete", "entry.copy",
    "password.generate", "master.change",
    "access.denied", "access.fixed", "input.rejected", "command.cancelled", "error",
})
OUTCOMES = frozenset({"ok", "fail", "denied"})

_WORD = re.compile(r"[A-Za-z0-9_]{1,40}")
FIELDS = {
    "reason": _WORD,
    "file": re.compile(r"vault|folder|lock|log"),
    "count": int,
}

_logger = logging.getLogger("pwmanager.audit")
_logger.propagate = False
_logger.setLevel(logging.INFO)
# Without any handler, logging would print warnings to stderr ("last resort"
# handler). The NullHandler stops that when setup() was not called.
_logger.addHandler(logging.NullHandler())
_context = {}


def _clean(name, value):
    rule = FIELDS[name]
    if rule is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    else:
        ok = isinstance(value, str) and rule.fullmatch(value) is not None
    return value if ok else "invalid"


def event(name, outcome="ok", /, **fields):
    """Log one event. Unknown event or field names are a bug, so they raise."""
    if name not in EVENTS or outcome not in OUTCOMES:
        raise ValueError("unknown audit event")
    record = {"event": name, "outcome": outcome}
    for key, value in fields.items():
        if key not in FIELDS:
            raise ValueError("unknown audit field")
        record[key] = _clean(key, value)
    level = logging.INFO if outcome == "ok" else logging.WARNING
    _logger.log(level, name, extra={"audit": record})


class JsonFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc)
        data = {"ts": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
                "level": record.levelname}
        data.update(getattr(record, "audit", {"event": "invalid"}))
        data.update(_context)
        data["pid"] = os.getpid()
        # ensure_ascii and no newlines inside, so one event is always one line.
        return json.dumps(data, ensure_ascii=True)


class SecureFileHandler(logging.Handler):
    """Appends each event to the log. Opens the file for every event, so it
    is checked every time and never kept open."""

    def __init__(self, path):
        super().__init__(logging.INFO)
        self.path = path
        self.setFormatter(JsonFormatter())

    def emit(self, record):
        try:
            line = (self.format(record) + "\n").encode("ascii")
            self._rotate()
            fd, _fixed = access.open_private(self.path, os.O_WRONLY | os.O_APPEND)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
        # A broken log must not stop the command or print anything.
        except Exception:  # nosec B110
            pass

    def handleError(self, record):
        pass  # the default prints a traceback to stderr

    def _rotate(self):
        try:
            if os.lstat(self.path).st_size > MAX_LOG_SIZE:
                os.replace(self.path, self.path + ".1")
        except OSError:
            pass


def log_path(vault_path):
    return os.path.join(os.path.dirname(vault_path), LOG_NAME)


def setup(vault_path, command):
    """Send events to pwm.log next to the vault for this command."""
    shutdown()
    _logger.addHandler(SecureFileHandler(log_path(vault_path)))
    _context["command"] = command if _WORD.fullmatch(command.replace("-", "_")) else "invalid"
    try:
        _context["user"] = access.current_user()
    except Exception:
        _context["user"] = "unknown"


def shutdown():
    for handler in list(_logger.handlers):
        if isinstance(handler, SecureFileHandler):
            _logger.removeHandler(handler)
            handler.close()
    _context.clear()
