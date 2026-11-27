"""Base error class.

Every error the program raises on purpose is a PwmError. Its message is
written by us and is safe to show to the user. Any other exception is a bug
or comes from a library, so the CLI only prints "unexpected error" for it.
"""


class PwmError(Exception):
    pass
