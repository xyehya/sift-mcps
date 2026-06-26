"""sift-core: shared case I/O, identity, approval auth, and HMAC verification."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sift-core")
except PackageNotFoundError:
    __version__ = "0.0.0.dev0"
