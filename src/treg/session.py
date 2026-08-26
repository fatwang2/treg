"""Compatibility alias for :mod:`treg.domain.identity.session`."""

import sys as _sys

from .domain.identity import session as _implementation

_sys.modules[__name__] = _implementation
