"""Tests for sift_common.oplog — structured logging setup."""

from __future__ import annotations

import json
import logging
import os
from unittest import mock

from sift_common.oplog import _StructuredFormatter, setup_logging


class TestStructuredFormatter:
    def test_basic_format_is_json(self):
        fmt = _StructuredFormatter("test-svc")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="f.py",
            lineno=1, msg="hello %s", args=("world",), exc_info=None,
        )
        output = fmt.format(record)
        data = json.loads(output)
        assert data["message"] == "hello world"
        assert data["service"] == "test-svc"
        assert data["level"] == "INFO"
        assert "ts" in data

    def test_warning_includes_location(self):
        fmt = _StructuredFormatter("svc")
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="foo.py",
            lineno=42, msg="warn", args=(), exc_info=None,
        )
        data = json.loads(fmt.format(record))
        assert "location" in data
        assert data["location"]["line"] == 42

    def test_info_excludes_location(self):
        fmt = _StructuredFormatter("svc")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="foo.py",
            lineno=1, msg="info", args=(), exc_info=None,
        )
        data = json.loads(fmt.format(record))
        assert "location" not in data

    def test_exception_info(self):
        fmt = _StructuredFormatter("svc")
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="f.py",
            lineno=1, msg="err", args=(), exc_info=exc_info,
        )
        data = json.loads(fmt.format(record))
        assert data["exception"]["type"] == "ValueError"
        assert "boom" in data["exception"]["message"]


class TestSetupLogging:
    def test_json_format_stderr_only(self):
        setup_logging("test-oplog-svc", json_format=True, log_to_file=False)
        logger = logging.getLogger("test_oplog_svc")
        assert len(logger.handlers) >= 1
        assert logger.propagate is False

    def test_text_format(self):
        setup_logging("test-oplog-text", json_format=False, log_to_file=False)
        logger = logging.getLogger("test_oplog_text")
        handler = logger.handlers[0]
        assert not isinstance(handler.formatter, _StructuredFormatter)

    def test_file_logging_creates_file(self, tmp_path):
        with mock.patch("sift_common.oplog.Path.home", return_value=tmp_path):
            setup_logging("test-file-svc", json_format=True, log_to_file=True)
            logger = logging.getLogger("test_file_svc")
            assert len(logger.handlers) == 2
            log_file = tmp_path / ".sift" / "logs" / "test-file-svc.jsonl"
            assert log_file.parent.exists()

    def test_env_defaults(self):
        env = os.environ.copy()
        env["SIFT_LOG_FORMAT"] = "text"
        env["SIFT_LOG_FILE"] = "false"
        with mock.patch.dict(os.environ, env, clear=True):
            setup_logging("test-env-svc")
            logger = logging.getLogger("test_env_svc")
            assert len(logger.handlers) >= 1
            for h in logger.handlers:
                assert not isinstance(h, logging.FileHandler)

    def test_env_json_default(self):
        env = os.environ.copy()
        env.pop("SIFT_LOG_FORMAT", None)
        env["SIFT_LOG_FILE"] = "false"
        with mock.patch.dict(os.environ, env, clear=True):
            setup_logging("test-env-json-svc")
            logger = logging.getLogger("test_env_json_svc")
            assert isinstance(logger.handlers[0].formatter, _StructuredFormatter)
