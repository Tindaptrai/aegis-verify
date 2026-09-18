"""Read-only local server that hands CLI reports to the results dashboard."""

from .server import DEFAULT_HOST, DEFAULT_PORT, ReportStore, build_index, make_server, serve

__all__ = ["DEFAULT_HOST", "DEFAULT_PORT", "ReportStore", "build_index", "make_server", "serve"]
