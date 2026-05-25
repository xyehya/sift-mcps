"""Real-time inotify watcher for evidence/ directory (Phase 17d).

Immediately invalidates the evidence gate cache when any filesystem event
occurs under case_dir/evidence/. Complements the 30s TTL: tampering is
detected at next tool call rather than up to 30 seconds later.

Graceful fallback when inotify is unavailable (NTFS/NFS/FUSE/non-Linux).
"""
from __future__ import annotations

import asyncio
import ctypes
import logging
import os

logger = logging.getLogger(__name__)

# inotify event mask
_IN_MODIFY  = 0x00000002
_IN_CREATE  = 0x00000100
_IN_DELETE  = 0x00000200
_IN_MOVED   = 0x000000C0  # IN_MOVED_FROM | IN_MOVED_TO
_WATCH_MASK = _IN_MODIFY | _IN_CREATE | _IN_DELETE | _IN_MOVED

try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    _libc.inotify_init1.argtypes = [ctypes.c_int]
    _libc.inotify_init1.restype  = ctypes.c_int
    _libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    _libc.inotify_add_watch.restype  = ctypes.c_int
    _libc.inotify_rm_watch.argtypes  = [ctypes.c_int, ctypes.c_int]
    _libc.inotify_rm_watch.restype   = ctypes.c_int
except OSError:
    _libc = None


async def watch_evidence_dir(case_dir_str: str, on_change_fn) -> None:
    """Background asyncio task: call on_change_fn(case_dir_str) on any evidence/ change.

    Exits cleanly on CancelledError. Falls back to TTL-only invalidation if
    inotify is unavailable or the evidence directory does not exist.
    """
    if _libc is None:
        logger.warning("evidence_watcher: libc.so.6 not available — TTL-only invalidation")
        return

    evidence_dir = os.path.join(case_dir_str, "evidence")
    if not os.path.isdir(evidence_dir):
        logger.warning("evidence_watcher: evidence dir not found: %s — TTL-only", evidence_dir)
        return

    O_CLOEXEC = getattr(os, "O_CLOEXEC", 524288)

    # Blocking fd: os.read in a thread pool blocks until an event arrives.
    # Closing fd at shutdown unblocks the thread with EBADF.
    fd = _libc.inotify_init1(O_CLOEXEC)
    if fd < 0:
        errno = ctypes.get_errno()
        logger.warning("evidence_watcher: inotify_init1 failed (errno=%d) — TTL-only", errno)
        return

    wd = _libc.inotify_add_watch(fd, evidence_dir.encode(), _WATCH_MASK)
    if wd < 0:
        errno = ctypes.get_errno()
        logger.warning(
            "evidence_watcher: inotify_add_watch failed on %s (errno=%d, NTFS/NFS?) — TTL-only",
            evidence_dir, errno,
        )
        os.close(fd)
        return

    logger.info("evidence_watcher: watching %s (inotify fd=%d)", evidence_dir, fd)
    loop = asyncio.get_running_loop()

    try:
        while True:
            # Blocks in thread until event arrives or fd is closed (EBADF at shutdown)
            data = await loop.run_in_executor(None, lambda: os.read(fd, 4096))
            if data:
                await asyncio.to_thread(on_change_fn, case_dir_str)
                logger.info("evidence_watcher: change detected — gate cache invalidated")
    except asyncio.CancelledError:
        pass
    except OSError:
        pass  # EBADF when fd closed at shutdown — exit cleanly
    finally:
        try:
            _libc.inotify_rm_watch(fd, wd)
            os.close(fd)
        except OSError:
            pass
        logger.info("evidence_watcher: stopped for %s", case_dir_str)
