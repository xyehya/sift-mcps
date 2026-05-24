"""FastMCP backend for SIFT-local Windows baseline validation."""

from __future__ import annotations

import hashlib
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from sift_common.instructions import WINDOWS_TRIAGE as _INSTRUCTIONS
from sift_common.oplog import setup_logging

from .db import BaselineDB, basename, normalize_windows_path

STARTED_AT = time.monotonic()
MAX_INPUT = 4096

SUSPICIOUS_PIPE_MARKERS = (
    "msagent_",
    "postex_",
    "status_",
    "mojo.",
    "metasploit",
    "cobalt",
)
DOUBLE_EXTENSIONS = {
    ".doc.exe",
    ".docx.exe",
    ".pdf.exe",
    ".txt.exe",
    ".xls.exe",
    ".xlsx.exe",
    ".jpg.exe",
    ".png.exe",
    ".zip.exe",
}


def _validate(value: str | None, field: str, required: bool = False) -> str:
    if required and not value:
        raise ValueError(f"{field} is required")
    value = value or ""
    if len(value) > MAX_INPUT:
        raise ValueError(f"{field} exceeds {MAX_INPUT} characters")
    if "\x00" in value:
        raise ValueError(f"{field} contains invalid null byte")
    return value


def _unknown(reason: str, db: BaselineDB | None = None) -> dict[str, Any]:
    result = {
        "status": "degraded" if db is not None and not db.available else "ok",
        "verdict": "UNKNOWN",
        "confidence": "low",
        "reasons": [reason],
    }
    if db is not None:
        result["db_available"] = db.available
    return result


def _match_os(record: dict[str, Any], os_version: str | None) -> bool:
    expected = str(record.get("os_version", "")).casefold()
    requested = (os_version or "").casefold()
    return not expected or not requested or expected in requested or requested in expected


def _hash_value(value: str | None) -> str:
    return (value or "").strip().casefold().removeprefix("sha256:")


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key not in {"internal_notes"} and isinstance(value, str | int | float | bool | list)
    }


class WindowsTriageServer:
    def __init__(self, db: BaselineDB | None = None) -> None:
        self.db = db or BaselineDB()
        self.mcp = FastMCP("windows-triage-mcp", instructions=_INSTRUCTIONS)
        self._register_tools()

    def _register_tools(self) -> None:
        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_file(path: str, hash: str = "", os_version: str = "") -> dict[str, Any]:
            """Validate a Windows file path/hash against the local baseline."""
            return self.check_file(path=path, hash=hash, os_version=os_version)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_process_tree(
            process_name: str,
            parent_name: str = "",
            path: str = "",
            user: str = "",
        ) -> dict[str, Any]:
            """Validate process parent, path, and user context."""
            return self.check_process_tree(process_name, parent_name, path, user)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_service(
            service_name: str,
            binary_path: str = "",
            os_version: str = "",
        ) -> dict[str, Any]:
            """Validate a Windows service name/path by OS version."""
            return self.check_service(service_name, binary_path, os_version)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_scheduled_task(task_path: str, os_version: str = "") -> dict[str, Any]:
            """Validate a scheduled task path by OS version."""
            return self.check_scheduled_task(task_path, os_version)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_autorun(
            key_path: str,
            value_name: str = "",
            os_version: str = "",
        ) -> dict[str, Any]:
            """Validate a registry autorun entry by OS version."""
            return self.check_autorun(key_path, value_name, os_version)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_registry(
            key_path: str,
            value_name: str = "",
            hive: str = "",
            os_version: str = "",
        ) -> dict[str, Any]:
            """Validate a registry key/value against the full local baseline."""
            return self.check_registry(key_path, value_name, hive, os_version)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_hash(hash: str) -> dict[str, Any]:
            """Check a hash against the local LOLDrivers vulnerable driver set."""
            return self.check_hash(hash)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def analyze_filename(filename: str) -> dict[str, Any]:
            """Detect filename deception such as homoglyphs and double extensions."""
            return self.analyze_filename(filename)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_lolbin(filename: str) -> dict[str, Any]:
            """Check whether a binary is a known LOLBin."""
            return self.check_lolbin(filename)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_hijackable_dll(dll_name: str) -> dict[str, Any]:
            """Check whether a DLL is known for search-order hijack risk."""
            return self.check_hijackable_dll(dll_name)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def check_pipe(pipe_name: str) -> dict[str, Any]:
            """Check a named pipe against baseline and C2 patterns."""
            return self.check_pipe(pipe_name)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def get_db_stats() -> dict[str, Any]:
            """Report local baseline database coverage and metadata."""
            return self.get_db_stats()

        @self.mcp.tool(annotations={"readOnlyHint": True})
        def get_health() -> dict[str, Any]:
            """Report backend/database health."""
            return self.get_health()

    def check_file(self, path: str, hash: str = "", os_version: str = "") -> dict[str, Any]:
        path = _validate(path, "path", required=True)
        file_hash = _hash_value(_validate(hash, "hash"))
        os_version = _validate(os_version, "os_version")
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        normalized = normalize_windows_path(path)
        found_name = basename(path)
        lolbin = self._find_lolbin(found_name)
        for record in self.db.files:
            if normalize_windows_path(record.get("path")) != normalized:
                continue
            if not _match_os(record, os_version):
                continue
            expected_hash = _hash_value(record.get("sha256") or record.get("hash"))
            if file_hash and expected_hash and file_hash != expected_hash:
                return {
                    "status": "ok",
                    "verdict": "SUSPICIOUS",
                    "confidence": "high",
                    "reasons": ["path matched baseline but hash differs"],
                    "db_available": True,
                    "matched_record": _public_record(record),
                }
            verdict = "EXPECTED_LOLBIN" if lolbin else "EXPECTED"
            reasons = ["path matched Windows baseline"]
            if lolbin:
                reasons.append("binary is a LOLBin; validate execution context")
            return {
                "status": "ok",
                "verdict": verdict,
                "confidence": "high",
                "reasons": reasons,
                "is_lolbin": bool(lolbin),
                "db_available": True,
                "matched_record": _public_record(record),
            }
        if lolbin and not normalized.startswith("\\windows\\") and "\\windows\\" not in normalized:
            return {
                "status": "ok",
                "verdict": "SUSPICIOUS",
                "confidence": "medium",
                "reasons": ["LOLBin name appears outside the Windows directory"],
                "is_lolbin": True,
                "db_available": True,
            }
        return _unknown("file path/hash not found in local baseline", self.db)

    def check_process_tree(
        self, process_name: str, parent_name: str = "", path: str = "", user: str = ""
    ) -> dict[str, Any]:
        process_name = basename(_validate(process_name, "process_name", required=True))
        parent_name = basename(_validate(parent_name, "parent_name"))
        path = _validate(path, "path")
        user = _validate(user, "user")
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        for record in self.db.process_trees:
            if basename(record.get("process_name")) != process_name:
                continue
            if parent_name and basename(record.get("parent_name")) != parent_name:
                continue
            if path and record.get("path") and normalize_windows_path(record.get("path")) != normalize_windows_path(path):
                continue
            if user and record.get("user") and str(record.get("user")).casefold() != user.casefold():
                continue
            return {
                "status": "ok",
                "verdict": "EXPECTED",
                "confidence": "high",
                "reasons": ["process context matched baseline"],
                "db_available": True,
                "matched_record": _public_record(record),
            }
        return _unknown("process context not found in local baseline", self.db)

    def check_service(self, service_name: str, binary_path: str = "", os_version: str = "") -> dict[str, Any]:
        service_name = _validate(service_name, "service_name", required=True).casefold()
        binary_path = _validate(binary_path, "binary_path")
        os_version = _validate(os_version, "os_version")
        if not os_version:
            raise ValueError("os_version is required")
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        for record in self.db.services:
            if str(record.get("service_name", "")).casefold() != service_name:
                continue
            if not _match_os(record, os_version):
                continue
            if binary_path and record.get("binary_path") and normalize_windows_path(record.get("binary_path")) != normalize_windows_path(binary_path):
                return {
                    "status": "ok",
                    "verdict": "SUSPICIOUS",
                    "confidence": "high",
                    "reasons": ["service name matched baseline but binary path differs"],
                    "db_available": True,
                    "matched_record": _public_record(record),
                }
            return {
                "status": "ok",
                "verdict": "EXPECTED",
                "confidence": "high",
                "reasons": ["service matched baseline"],
                "db_available": True,
                "matched_record": _public_record(record),
            }
        return _unknown("service not found in local baseline for requested OS", self.db)

    def check_scheduled_task(self, task_path: str, os_version: str = "") -> dict[str, Any]:
        return self._check_path_collection(
            "scheduled task",
            self.db.scheduled_tasks,
            "task_path",
            task_path,
            os_version,
            os_required=True,
        )

    def check_autorun(self, key_path: str, value_name: str = "", os_version: str = "") -> dict[str, Any]:
        key_path = _validate(key_path, "key_path", required=True)
        value_name = _validate(value_name, "value_name").casefold()
        os_version = _validate(os_version, "os_version")
        if not os_version:
            raise ValueError("os_version is required")
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        normalized = normalize_windows_path(key_path)
        for record in self.db.autoruns:
            if normalize_windows_path(record.get("key_path")) != normalized:
                continue
            if value_name and str(record.get("value_name", "")).casefold() != value_name:
                continue
            if not _match_os(record, os_version):
                continue
            return {
                "status": "ok",
                "verdict": "EXPECTED",
                "confidence": "high",
                "reasons": ["autorun entry matched baseline"],
                "db_available": True,
                "matched_record": _public_record(record),
            }
        return _unknown("autorun entry not found in local baseline", self.db)

    def check_registry(
        self, key_path: str, value_name: str = "", hive: str = "", os_version: str = ""
    ) -> dict[str, Any]:
        key_path = _validate(key_path, "key_path", required=True)
        value_name = _validate(value_name, "value_name").casefold()
        hive = _validate(hive, "hive").casefold()
        os_version = _validate(os_version, "os_version")
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        normalized = normalize_windows_path(key_path)
        for record in self.db.registry:
            if normalize_windows_path(record.get("key_path")) != normalized:
                continue
            if value_name and str(record.get("value_name", "")).casefold() != value_name:
                continue
            if hive and str(record.get("hive", "")).casefold() != hive:
                continue
            if not _match_os(record, os_version):
                continue
            return {
                "status": "ok",
                "verdict": "EXPECTED",
                "confidence": "high",
                "reasons": ["registry key/value matched baseline"],
                "db_available": True,
                "matched_record": _public_record(record),
            }
        return _unknown("registry key/value not found in local baseline", self.db)

    def check_hash(self, hash: str) -> dict[str, Any]:
        hash_value = _hash_value(_validate(hash, "hash", required=True))
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        for record in self.db.loldrivers:
            record_hashes = [record.get("hash"), record.get("sha256"), record.get("sha1"), record.get("md5")]
            if hash_value in {_hash_value(v) for v in record_hashes if v}:
                return {
                    "status": "ok",
                    "verdict": "SUSPICIOUS",
                    "confidence": "high",
                    "reasons": ["hash matched local LOLDrivers vulnerable driver data"],
                    "db_available": True,
                    "matched_record": _public_record(record),
                }
        return _unknown("hash not found in local LOLDrivers data", self.db)

    def analyze_filename(self, filename: str) -> dict[str, Any]:
        filename = _validate(filename, "filename", required=True)
        leaf = Path(normalize_windows_path(filename)).name or basename(filename)
        normalized = unicodedata.normalize("NFKC", leaf)
        reasons: list[str] = []
        lower = leaf.casefold()
        if normalized != leaf:
            reasons.append("filename changes under Unicode NFKC normalization")
        if any(ord(ch) > 127 for ch in leaf):
            reasons.append("filename contains non-ASCII characters")
        if any(lower.endswith(ext) for ext in DOUBLE_EXTENSIONS):
            reasons.append("filename has a deceptive double extension")
        if lower in {"svch0st.exe", "expl0rer.exe", "lsasss.exe", "rundl132.exe"}:
            reasons.append("filename resembles a Windows system binary typo")
        verdict = "SUSPICIOUS" if reasons else "UNKNOWN"
        return {
            "status": "ok",
            "verdict": verdict,
            "confidence": "medium" if reasons else "low",
            "reasons": reasons or ["no filename deception pattern matched"],
            "normalized": normalized,
            "db_available": self.db.available,
        }

    def check_lolbin(self, filename: str) -> dict[str, Any]:
        filename = basename(_validate(filename, "filename", required=True))
        match = self._find_lolbin(filename)
        if match:
            return {
                "status": "ok",
                "verdict": "EXPECTED_LOLBIN",
                "confidence": "high",
                "reasons": ["binary is listed as a LOLBin"],
                "is_lolbin": True,
                "db_available": self.db.available,
                "matched_record": _public_record(match),
            }
        return _unknown("binary is not listed as a LOLBin", self.db)

    def check_hijackable_dll(self, dll_name: str) -> dict[str, Any]:
        dll_name = basename(_validate(dll_name, "dll_name", required=True))
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        for record in self.db.hijackable_dlls:
            if basename(record.get("dll_name") or record.get("name")) == dll_name:
                return {
                    "status": "ok",
                    "verdict": "SUSPICIOUS",
                    "confidence": "medium",
                    "reasons": ["DLL is listed as search-order hijackable"],
                    "db_available": True,
                    "matched_record": _public_record(record),
                }
        return _unknown("DLL is not listed as hijackable", self.db)

    def check_pipe(self, pipe_name: str) -> dict[str, Any]:
        pipe_name = _validate(pipe_name, "pipe_name", required=True)
        normalized = normalize_windows_path(pipe_name).lstrip("\\")
        for marker in SUSPICIOUS_PIPE_MARKERS:
            if marker in normalized:
                return {
                    "status": "ok",
                    "verdict": "SUSPICIOUS",
                    "confidence": "medium",
                    "reasons": [f"pipe name matched suspicious marker: {marker}"],
                    "db_available": self.db.available,
                }
        if self.db.available:
            for record in self.db.pipes:
                if normalize_windows_path(record.get("pipe_name") or record.get("name")).lstrip("\\") == normalized:
                    return {
                        "status": "ok",
                        "verdict": "EXPECTED",
                        "confidence": "medium",
                        "reasons": ["pipe matched local baseline"],
                        "db_available": True,
                        "matched_record": _public_record(record),
                    }
        return _unknown("pipe not found in local baseline or C2 pattern list", self.db)

    def get_db_stats(self) -> dict[str, Any]:
        stats = self.db.stats()
        status = "ok" if stats["db_available"] else "degraded"
        return {"status": status, **stats}

    def get_health(self) -> dict[str, Any]:
        stats = self.db.stats()
        return {
            "status": "ok" if stats["db_available"] else "degraded",
            "service": "windows-triage-mcp",
            "uptime_seconds": round(time.monotonic() - STARTED_AT, 3),
            "db_available": stats["db_available"],
            "db_dir": stats["db_dir"],
            "total_records": stats["total_records"],
            "message": "baseline database loaded" if stats["db_available"] else "baseline database is not installed",
        }

    def _check_path_collection(
        self,
        label: str,
        records: list[dict[str, Any]],
        field: str,
        path: str,
        os_version: str = "",
        os_required: bool = False,
    ) -> dict[str, Any]:
        path = _validate(path, field, required=True)
        os_version = _validate(os_version, "os_version")
        if os_required and not os_version:
            raise ValueError("os_version is required")
        if not self.db.available:
            return _unknown("baseline database is not installed", self.db)
        normalized = normalize_windows_path(path)
        for record in records:
            if normalize_windows_path(record.get(field)) != normalized:
                continue
            if not _match_os(record, os_version):
                continue
            return {
                "status": "ok",
                "verdict": "EXPECTED",
                "confidence": "high",
                "reasons": [f"{label} matched baseline"],
                "db_available": True,
                "matched_record": _public_record(record),
            }
        return _unknown(f"{label} not found in local baseline", self.db)

    def _find_lolbin(self, filename: str) -> dict[str, Any] | None:
        normalized = basename(filename)
        for record in self.db.lolbins:
            names = [record.get("filename"), record.get("name"), *(record.get("aliases") or [])]
            if normalized in {basename(str(name)) for name in names if name}:
                return record
        built_in = {
            "cmd.exe": ["command execution"],
            "powershell.exe": ["script execution"],
            "rundll32.exe": ["DLL execution"],
            "regsvr32.exe": ["scriptlet execution"],
            "mshta.exe": ["HTML application execution"],
            "certutil.exe": ["download/encode/decode"],
            "bitsadmin.exe": ["file transfer"],
            "wmic.exe": ["remote execution and discovery"],
        }
        if normalized in built_in:
            return {"filename": normalized, "capabilities": built_in[normalized], "source": "built-in"}
        return None

    def run(self) -> None:
        self.mcp.run()


_server = WindowsTriageServer()
mcp = _server.mcp


def _print_help() -> None:
    print("Usage: windows-triage-mcp [--help]")
    print()
    print("SIFT-local Windows baseline validation MCP backend.")
    print(f"Database dir: {_server.db.root}")
    print()
    print("Tools:")
    for tool in mcp._tool_manager.list_tools():
        print(f"  {tool.name}")


def main() -> None:
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        _print_help()
        return
    setup_logging("windows-triage-mcp")
    _server.run()


if __name__ == "__main__":
    main()

