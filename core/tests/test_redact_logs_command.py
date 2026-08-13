"""Tests for the redact_logs management command."""

import os
import shutil
import tempfile

from django.core.management import call_command
from django.test import SimpleTestCase, override_settings


class RedactLogsCommandTests(SimpleTestCase):
    def setUp(self):
        self.log_dir = tempfile.mkdtemp(prefix="dispatcharr-logtest-")
        self.addCleanup(shutil.rmtree, self.log_dir, ignore_errors=True)

    def _write(self, name, content):
        with open(os.path.join(self.log_dir, name), "w") as f:
            f.write(content)

    def _read(self, name):
        with open(os.path.join(self.log_dir, name)) as f:
            return f.read()

    def test_masks_credentials_in_rotated_files(self):
        self._write(
            "dispatcharr.log.1",
            "line one\nStarting stream for URL: "
            "http://host/live/joe/s3cret/1.ts\nline three\n",
        )
        self._write("dispatcharr.log", "current http://host/live/a/b/2.ts\n")
        with override_settings(LOG_FILE_DIR=self.log_dir):
            call_command("redact_logs")
        self.assertNotIn("s3cret", self._read("dispatcharr.log.1"))
        self.assertIn("line three", self._read("dispatcharr.log.1"))
        self.assertNotIn("/a/b/", self._read("dispatcharr.log"))

    def test_is_idempotent_and_leaves_clean_files(self):
        self._write("dispatcharr.log.2", "Scanning disk for The Crash Reel\n")
        before = self._read("dispatcharr.log.2")
        with override_settings(LOG_FILE_DIR=self.log_dir):
            call_command("redact_logs")
            call_command("redact_logs")  # second pass is a no-op
        self.assertEqual(self._read("dispatcharr.log.2"), before)

    def test_no_log_dir_is_a_noop(self):
        with override_settings(LOG_FILE_DIR="/nonexistent/path/xyz"):
            call_command("redact_logs")  # must not raise
