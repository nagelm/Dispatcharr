"""Mask credentials in log files written before the redacting formatter shipped."""

import glob
import os

from django.conf import settings
from django.core.management.base import BaseCommand

from core.redaction import redact_text


class Command(BaseCommand):
    help = "Mask provider credentials in existing dispatcharr.log* files."

    def handle(self, *args, **options):
        log_dir = getattr(settings, "LOG_FILE_DIR", None)
        if not log_dir or not os.path.isdir(log_dir):
            return
        swept = 0
        for path in glob.glob(os.path.join(log_dir, "dispatcharr.log*")):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    original = f.read()
            except OSError:
                continue
            redacted = redact_text(original)
            if redacted == original:
                continue
            try:
                # Rewrite in place to preserve the inode of the live file.
                with open(path, "w", encoding="utf-8") as f:
                    f.write(redacted)
                swept += 1
            except OSError:
                continue
        if swept:
            self.stdout.write(f"Redacted credentials in {swept} log file(s).")
