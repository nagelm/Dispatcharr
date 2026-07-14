"""Run a channel's StreamProfile command over a provider catch-up URL.

Timeshift normally proxies the provider archive verbatim. A channel whose
live stream needs a StreamProfile treatment (SEI stripping, transcoding)
needs the identical treatment on its archive: the archive is a recording of
the same encoder output, so a stream that a client's decoder cannot play
live is equally unplayable time-shifted.

Process handling mirrors the live input manager (apps/proxy/live_proxy/
input/manager.py): ``os.posix_spawn`` because fork-based subprocess
creation hangs in gevent's atfork handlers under gevent+uWSGI, and
``select`` + ``os.read`` so pipe reads stay cooperative under gevent.
"""

import logging
import os
import select
import shutil
import signal
import time

logger = logging.getLogger(__name__)

_TERM_GRACE_SECONDS = 2.0


class ProfileTranscodeProcess:
    """A spawned stream-profile command emitting MPEG-TS on stdout.

    Duck-types ``close()`` so it can sit in the active-upstream registry in
    place of a requests response object.
    """

    def __init__(self, command):
        self.command = list(command)
        self.pid = None
        self._read_fd = None
        self._closed = False

    def start(self):
        read_fd, write_fd = os.pipe()
        try:
            executable = shutil.which(self.command[0]) or self.command[0]
            self.pid = os.posix_spawn(
                executable,
                self.command,
                os.environ,
                file_actions=[
                    (os.POSIX_SPAWN_OPEN, 0, "/dev/null", os.O_RDONLY, 0),
                    (os.POSIX_SPAWN_DUP2, write_fd, 1),
                    # stderr to /dev/null: the timeshift path has no
                    # log-parser thread, and an undrained pipe would stall
                    # the process once the kernel buffer fills.
                    (os.POSIX_SPAWN_OPEN, 2, "/dev/null", os.O_WRONLY, 0),
                    (os.POSIX_SPAWN_CLOSE, write_fd),
                ],
            )
        except Exception:
            os.close(read_fd)
            raise
        finally:
            os.close(write_fd)
        self._read_fd = read_fd
        return self

    def read(self, chunk_size, timeout):
        """Read up to *chunk_size* bytes; ``None`` on timeout, ``b''`` on EOF."""
        if self._read_fd is None:
            return b""
        try:
            ready, _, _ = select.select([self._read_fd], [], [], timeout)
        except (ValueError, OSError):
            return b""
        if not ready:
            return None
        try:
            return os.read(self._read_fd, chunk_size)
        except OSError:
            return b""

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._read_fd is not None:
            try:
                os.close(self._read_fd)
            except OSError:
                pass
            self._read_fd = None
        if self.pid is None:
            return
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            self._reap()
            return
        except OSError:
            return
        deadline = time.time() + _TERM_GRACE_SECONDS
        while time.time() < deadline:
            if self._reap():
                return
            time.sleep(0.1)
        try:
            os.kill(self.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        self._reap()

    def _reap(self):
        """Collect the child if it has exited; True when no zombie remains."""
        try:
            pid, _status = os.waitpid(self.pid, os.WNOHANG)
            return pid == self.pid
        except ChildProcessError:
            return True
        except OSError:
            return True
