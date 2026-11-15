"""Errors for Phase 3. `hint` tells the user what to try."""


class EventProfileError(Exception):
    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


class ValidationError(EventProfileError):
    """Raised when output files fail a consistency check."""
