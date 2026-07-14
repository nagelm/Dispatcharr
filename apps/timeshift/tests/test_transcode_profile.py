"""Tests for stream-profile application on the timeshift path.

A channel whose live stream needs a StreamProfile treatment (SEI stripping,
transcoding) needs the identical treatment on its archive - the archive is
a recording of the same encoder output. These tests cover the profile
resolution rules, the transcode branch of ``_stream_from_provider``, and
the process iterator's stop handling.
"""

from unittest.mock import MagicMock, patch

from django.test import RequestFactory, TestCase

from apps.timeshift import views
from apps.timeshift.tests.test_views import _fake_upstream


def _fake_profile(name="strip-sei", command=None, proxy=False, redirect=False):
    profile = MagicMock()
    profile.name = name
    profile.is_proxy = MagicMock(return_value=proxy)
    profile.is_redirect = MagicMock(return_value=redirect)
    profile.build_command = MagicMock(
        return_value=list(command) if command is not None else []
    )
    return profile


def _fake_channel(profile=None):
    channel = MagicMock()
    channel.stream_profile_id = getattr(profile, "id", 1) if profile else None
    channel.stream_profile = profile
    return channel


class ChannelTranscodeProfileTests(TestCase):
    """Only explicitly assigned, command-bearing profiles trigger transcode."""

    def test_no_explicit_profile_returns_none(self):
        self.assertIsNone(views._channel_transcode_profile(_fake_channel(None)))

    def test_proxy_profile_returns_none(self):
        channel = _fake_channel(_fake_profile(proxy=True))
        self.assertIsNone(views._channel_transcode_profile(channel))

    def test_redirect_profile_returns_none(self):
        channel = _fake_channel(_fake_profile(redirect=True))
        self.assertIsNone(views._channel_transcode_profile(channel))

    def test_command_profile_returned(self):
        profile = _fake_profile(command=["ffmpeg", "-i", "{streamUrl}"])
        channel = _fake_channel(profile)
        self.assertIs(views._channel_transcode_profile(channel), profile)


class _FakeTranscodeProcess:
    """Stands in for ProfileTranscodeProcess: yields fixed chunks, then EOF."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.pid = 4242
        self.closed = False
        self.started_with = None

    def start(self):
        return self

    def read(self, chunk_size, timeout):
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def close(self):
        self.closed = True


class StreamFromProviderTranscodeTests(TestCase):
    """The transcode branch pipes the winning URL through the profile command."""

    def setUp(self):
        self.factory = RequestFactory()
        self.kwargs = dict(
            candidate_urls=[
                "http://example.test/timeshift/u/p/60/2026-05-12:17-00/1.ts",
            ],
            user_agent="test-agent",
            client_user_agent="test-client-agent",
            range_header=None,
            virtual_channel_id="1_2026-05-12-17-00_1",
            client_id="test123",
            client_ip="127.0.0.1",
            user=None,
            channel_display_name="Test",
            timestamp_utc="2026-05-12:17-00",
            channel_logo_id=None,
            m3u_profile_id=None,
            channel_id=1,
            channel_uuid="00000000-0000-0000-0000-000000000001",
            debug=False,
        )

    @patch.object(views, "_open_upstream")
    def test_profile_command_streams_process_output(self, mocked_open):
        upstream = _fake_upstream(200)
        mocked_open.return_value = upstream

        profile = _fake_profile(command=["ffmpeg", "-i", "url", "-c", "copy"])
        fake_proc = _FakeTranscodeProcess([b"\x47" + b"\x00" * 187])

        with patch.object(
            views, "ProfileTranscodeProcess", return_value=fake_proc
        ) as proc_cls, patch.object(views, "_register_stats_client"), patch.object(
            views, "_heartbeat_stats_client"
        ):
            response = views._stream_from_provider(
                channel_stream_profile=profile, **self.kwargs
            )
            self.assertEqual(response.status_code, 200)
            body = b"".join(response.streaming_content)

        # The command was built from the winning provider URL.
        profile.build_command.assert_called_once_with(
            self.kwargs["candidate_urls"][0], "test-agent"
        )
        proc_cls.assert_called_once_with(profile.build_command.return_value)
        # The probe connection was handed off to the process.
        upstream.close.assert_called()
        # Client received the process output, not the probe peek bytes.
        self.assertEqual(body, b"\x47" + b"\x00" * 187)
        # Generated output makes no byte-length promises.
        self.assertFalse(response.has_header("Content-Length"))
        self.assertFalse(response.has_header("Content-Range"))

    @patch.object(views, "_open_upstream")
    def test_no_profile_keeps_raw_path(self, mocked_open):
        mocked_open.return_value = _fake_upstream(200)

        with patch.object(views, "ProfileTranscodeProcess") as proc_cls, patch.object(
            views, "_register_stats_client"
        ), patch.object(views, "_heartbeat_stats_client"):
            response = views._stream_from_provider(
                channel_stream_profile=None, **self.kwargs
            )
            self.assertEqual(response.status_code, 200)
            # The fake upstream streams forever; don't consume the body
            # (matching the other raw-path tests), just close it.
            response.close()

        proc_cls.assert_not_called()

    @patch.object(views, "_open_upstream")
    def test_profile_spawn_failure_returns_error(self, mocked_open):
        mocked_open.return_value = _fake_upstream(200)
        profile = _fake_profile(command=["ffmpeg", "-i", "url"])

        with patch.object(
            views, "ProfileTranscodeProcess",
            side_effect=OSError("spawn failed"),
        ), patch.object(views, "_register_stats_client"):
            response = views._stream_from_provider(
                channel_stream_profile=profile, **self.kwargs
            )
        self.assertEqual(response.status_code, 400)

    @patch.object(views, "_open_upstream")
    def test_provider_404_fails_before_any_spawn(self, mocked_open):
        mocked_open.return_value = _fake_upstream(404)
        profile = _fake_profile(command=["ffmpeg", "-i", "url"])

        with patch.object(views, "ProfileTranscodeProcess") as proc_cls:
            response = views._stream_from_provider(
                channel_stream_profile=profile, **self.kwargs
            )
        self.assertEqual(response.status_code, 404)
        proc_cls.assert_not_called()


class IterProcessWithStopTests(TestCase):
    """The process iterator honors stop keys and closes the process."""

    def test_yields_until_eof(self):
        proc = _FakeTranscodeProcess([b"a", b"b"])
        chunks = list(
            views._iter_process_with_stop(proc, 1024, None, "stop-key", 1)
        )
        self.assertEqual(chunks, [b"a", b"b"])

    def test_stop_key_closes_process(self):
        proc = _FakeTranscodeProcess([b"a", b"b", b"c"])
        redis = MagicMock()

        with patch.object(
            views, "_stream_stop_requested",
            side_effect=[(False, False), (True, False)],
        ):
            chunks = list(
                views._iter_process_with_stop(proc, 1024, redis, "stop-key", 1)
            )
        self.assertEqual(chunks, [b"a"])
        self.assertTrue(proc.closed)
