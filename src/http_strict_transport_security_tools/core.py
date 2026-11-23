"""Parse HTTP Strict Transport Security headers.

HSTS is a response header that tells a user agent to only contact the
origin over HTTPS for a period of time.  The header is a semicolon
separated list of directives, the only required one being ``max-age``.

This module deliberately keeps parsing simple and strict: it does not
attempt to validate the origin, normalise case, or merge multiple
headers.  That is left to the caller so that the result is a faithful
representation of what was received.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HSTSPolicy:
    """The parsed value of an HSTS header.

    Attributes:
        max_age: The ``max-age`` directive in seconds.  ``None`` means the
            directive was absent; ``-1`` means it was present but not a
            non-negative integer.
        include_subdomains: True if the ``includeSubDomains`` directive was
            present (case-insensitive).
        preload: True if the ``preload`` directive was present.
    """

    max_age: int | None
    include_subdomains: bool
    preload: bool


_DIRECTIVES = {
    "includesubdomains": "include_subdomains",
    "preload": "preload",
}


def parse_hsts(value: str | None) -> HSTSPolicy:
    """Parse an HSTS header value into an :class:`HSTSPolicy`.

    The parser is intentionally tolerant of whitespace and casing, but it
    does not try to correct malformed input.  A missing or malformed
    ``max-age`` is recorded rather than raising, because callers often
    need to inspect the header as received (for logging, for example)
    even when it is invalid.

    Args:
        value: The raw header value, or ``None`` if the header was absent.

    Returns:
        An :class:`HSTSPolicy`.  If *value* is ``None`` or empty, the
        result has ``max_age=None`` and both flags ``False``.
    """
    if value is None:
        return HSTSPolicy(max_age=None, include_subdomains=False, preload=False)

    max_age: int | None = None
    include_subdomains = False
    preload = False

    for raw_part in value.split(";"):
        part = raw_part.strip()
        if not part:
            continue

        if "=" in part:
            name, _, val = part.partition("=")
            name = name.strip().lower()
            val = val.strip()
            if name == "max-age":
                try:
                    parsed = int(val, 10)
                except ValueError:
                    # A non-numeric max-age is not a valid directive, but we
                    # still want to surface that it was present and broken.
                    max_age = -1
                else:
                    # Negative values are not valid per RFC 6797; treat them
                    # the same as a malformed value so callers can detect it.
                    max_age = parsed if parsed >= 0 else -1
            # Unknown directives with values are ignored.
        else:
            name = part.lower()
            attr = _DIRECTIVES.get(name)
            if attr == "include_subdomains":
                include_subdomains = True
            elif attr == "preload":
                preload = True
            # Unknown flag directives are ignored.

    return HSTSPolicy(
        max_age=max_age,
        include_subdomains=include_subdomains,
        preload=preload,
    )
