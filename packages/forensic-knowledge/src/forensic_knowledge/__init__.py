"""Forensic knowledge: community-curated artifact, tool, and discipline data."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("forensic-knowledge")
except PackageNotFoundError:  # source tree / dist not installed — avoid import-time crash
    __version__ = "0.0.0.dev0"
