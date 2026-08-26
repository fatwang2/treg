"""Compatibility alias for :mod:`treg.domain.identity.mcp_oauth`."""

import sys as _sys

from .domain.identity import mcp_oauth as _implementation

_sys.modules[__name__] = _implementation
