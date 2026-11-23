# http_strict_transport_security_tools

Parse the HTTP Strict Transport Security header into its `max-age`, `includeSubDomains`, and `preload` values.

## Usage

```python
from http_strict_transport_security_tools import parse_hsts

policy = parse_hsts("max-age=31536000; includeSubDomains; preload")
assert policy.max_age == 31536000
assert policy.include_subdomains is True
assert policy.preload is True
```

`parse_hsts` accepts `None` and returns an `HSTSPolicy` with `max_age=None` and both flags `False`.  A malformed or negative `max-age` is reported as `-1` so callers can distinguish "missing" from "present but invalid".

## Why this exists

HSTS headers are often parsed ad hoc, and the resulting code tends to conflate "the header was absent" with "the header was present but had no usable `max-age`".  This library makes that distinction explicit: `None` means absent, `-1` means present but invalid, and any non-negative integer is the parsed value.  The trade-off is that the parser does not attempt to repair malformed input or enforce RFC 6797 strictly; it reports what it saw.  That keeps the parser small and predictable, at the cost of pushing validation decisions to the caller.

## Edge cases

Directive names are matched case-insensitively, and surrounding whitespace is trimmed.  Unknown directives are ignored.  If `max-age` appears more than once, the last occurrence wins.  A `max-age` with a leading plus sign is accepted because Python's `int()` accepts it; this is documented behaviour rather than an accident.
