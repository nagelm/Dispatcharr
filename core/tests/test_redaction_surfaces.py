"""Tests for redaction of structured payloads: events, stats, webhooks."""

from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from core.redaction import redact_mapping, redact_url


class RedactUrlTests(SimpleTestCase):
    def test_reduces_to_scheme_and_host(self):
        self.assertEqual(
            redact_url("http://host.tld/live/joe/s3cret/1.ts"),
            "http://host.tld/...",
        )

    def test_drops_userinfo(self):
        self.assertEqual(
            redact_url("http://joe:s3cret@host.tld/x"), "http://host.tld/..."
        )

    def test_drops_userinfo_with_at_in_username(self):
        # Split on the last '@' so an email-shaped username doesn't leak the password.
        self.assertEqual(
            redact_url("http://joe@mail.com:s3cret@host.tld/x"),
            "http://host.tld/...",
        )

    def test_non_url_passthrough(self):
        self.assertEqual(redact_url("not a url"), "not a url")
        self.assertEqual(redact_url(None), None)


class RedactMappingTests(SimpleTestCase):
    def test_masks_sensitive_keys(self):
        out = redact_mapping(
            {
                "username": "joe",
                "password": "s3cret",
                "xc_password": "s3cret",
                "api_token": "abc",
                "channel_name": "CNN",
            }
        )
        self.assertEqual(out["password"], "[password]")
        self.assertEqual(out["xc_password"], "[xc_password]")
        self.assertEqual(out["api_token"], "[api_token]")
        self.assertEqual(out["channel_name"], "CNN")  # non-sensitive kept

    def test_masks_hyphenated_and_authorization_keys(self):
        out = redact_mapping(
            {
                "X-Api-Key": "sk-secret",
                "Authorization": "Bearer eyJ",
                "Accept": "application/json",
            }
        )
        self.assertEqual(out["X-Api-Key"], "[x-api-key]")
        self.assertEqual(out["Authorization"], "[authorization]")
        self.assertEqual(out["Accept"], "application/json")

    def test_url_valued_key_masked_by_content_not_key_name(self):
        out = redact_mapping(
            {"stream_url": "http://host.tld/live/joe/s3cret/1.ts"}
        )
        self.assertNotIn("s3cret", out["stream_url"])
        self.assertIn("host.tld", out["stream_url"])

    def test_url_keys_reduced_to_host_only(self):
        out = redact_mapping(
            {
                "logo_url": "http://host.tld/logos/cnn.png",
                "webhook_url": "http://host.tld/api/webhook/fakeslug9988",
            }
        )
        self.assertEqual(out["logo_url"], "http://host.tld/...")
        self.assertEqual(out["webhook_url"], "http://host.tld/...")
        self.assertNotIn("fakeslug9988", out["webhook_url"])  # slug dropped

    def test_masks_signature_and_sig_dict_keys(self):
        out = redact_mapping({"signature": "RAWSIG==", "sig": "abc123"})
        self.assertEqual(out["signature"], "[signature]")
        self.assertEqual(out["sig"], "[sig]")
        # sig_alg / signature_version are metadata, not secrets.
        meta = redact_mapping({"sig_alg": "RS256", "signature_version": "1.0"})
        self.assertEqual(meta["sig_alg"], "RS256")
        self.assertEqual(meta["signature_version"], "1.0")

    def test_preserves_type_of_non_string_sensitive_values(self):
        # A sensitive-keyed non-string is metadata about a secret; keep it and its type.
        out = redact_mapping(
            {
                "has_password": True,
                "is_secret": False,
                "token_count": 42,
                "token_bucket": {"capacity": 10, "rate": 5},
            }
        )
        self.assertIs(out["has_password"], True)
        self.assertIs(out["is_secret"], False)
        self.assertEqual(out["token_count"], 42)
        self.assertEqual(out["token_bucket"], {"capacity": 10, "rate": 5})

    def test_still_masks_real_secret_keys(self):
        out = redact_mapping(
            {"secret_key": "django-insecure-x", "access_token": "A.B.C"}
        )
        self.assertEqual(out["secret_key"], "[secret_key]")
        self.assertEqual(out["access_token"], "[access_token]")

    def test_masks_cookie_keys(self):
        out = redact_mapping({"Cookie": "sessionid=abc", "set_cookie": "x=y"})
        self.assertEqual(out, {"Cookie": "[cookie]", "set_cookie": "[set_cookie]"})

    def test_masks_bare_pass_and_passphrase_keys(self):
        # "pass"/"passphrase" are sensitive as whole words; lookalikes must survive.
        out = redact_mapping(
            {
                "pass": "s3cret",
                "xc_pass": "s3cret",
                "passphrase": "correct-horse",
                "passenger_count": 4,
                "compass_heading": "NW",
            }
        )
        self.assertEqual(out["pass"], "[pass]")
        self.assertEqual(out["xc_pass"], "[xc_pass]")
        self.assertEqual(out["passphrase"], "[passphrase]")
        self.assertEqual(out["passenger_count"], 4)  # lookalike kept
        self.assertEqual(out["compass_heading"], "NW")  # lookalike kept

    def test_masks_scalar_secrets_in_sensitive_list(self):
        # A sensitive key proves the whole value secret; lists mask element-wise.
        out = redact_mapping(
            {
                "tokens": ["abc123", "def456"],
                "api_keys": ("sk-one", "sk-two"),
                "credentials": [{"password": "p1"}, "raw-secret"],
            }
        )
        self.assertEqual(out["tokens"], ["[tokens]", "[tokens]"])
        self.assertEqual(out["api_keys"], ("[api_keys]", "[api_keys]"))
        self.assertIsInstance(out["api_keys"], tuple)  # type preserved
        self.assertEqual(out["credentials"][0]["password"], "[password]")
        self.assertEqual(out["credentials"][1], "[credentials]")

    def test_does_not_mask_lookalike_keys(self):
        # Whole-word key matching: sensitive substrings alone must not trigger.
        out = redact_mapping(
            {
                "secretary": "Jane Smith",
                "tokenizer": "bpe",
                "hourly_rate": 25,
                "curling_channel": "Winter Sports",
                "user_agent": "TiviMate/5.0",
                "username": "joe",
            }
        )
        self.assertEqual(out["secretary"], "Jane Smith")
        self.assertEqual(out["tokenizer"], "bpe")
        self.assertEqual(out["hourly_rate"], 25)
        self.assertEqual(out["curling_channel"], "Winter Sports")
        self.assertEqual(out["user_agent"], "TiviMate/5.0")
        self.assertEqual(out["username"], "joe")  # deliberate: identifier kept

    def test_sweeps_non_sensitive_string_values(self):
        out = redact_mapping(
            {"message": "connect http://host/live/joe/s3cret/1.ts failed"}
        )
        self.assertNotIn("s3cret", out["message"])

    def test_recurses_nested_structures(self):
        out = redact_mapping(
            {"a": {"password": "s3cret"}, "b": [{"token": "t"}, "clean"]}
        )
        self.assertEqual(out["a"]["password"], "[password]")
        self.assertEqual(out["b"][0]["token"], "[token]")
        self.assertEqual(out["b"][1], "clean")

    def test_does_not_mutate_input(self):
        source = {"password": "s3cret"}
        redact_mapping(source)
        self.assertEqual(source["password"], "s3cret")


class LogSystemEventRedactionTests(TestCase):
    """Call-site redaction for system events and the Connect dispatch."""

    @patch("core.utils._dispatch_system_event_integrations")
    def test_event_details_are_redacted_at_write(self, mock_dispatch):
        from core.models import SystemEvent
        from core.utils import log_system_event

        log_system_event(
            "stream_switch",
            channel_name="CNN",
            new_url="http://host.tld/live/joe/s3cret/1.ts",
            note="switch password=hunter2",
        )

        event = SystemEvent.objects.get(event_type="stream_switch")
        self.assertEqual(event.details["new_url"], "http://host.tld/...")
        self.assertEqual(event.details["note"], "switch password=[password]")

        # The same redacted details go out to integrations, not the raw ones.
        _, dispatch_kwargs = mock_dispatch.call_args
        self.assertEqual(dispatch_kwargs["new_url"], "http://host.tld/...")
        self.assertNotIn("hunter2", dispatch_kwargs["note"])

    @patch("apps.connect.utils.trigger_event")
    def test_dispatch_redacts_db_rederived_stream_url(self, mock_trigger):
        # dispatch_event_system re-derives Stream.url from the DB after
        # log_system_event redacted, so exercise the real dispatch body.
        from apps.channels.models import Stream
        from core.utils import dispatch_event_system

        stream = Stream.objects.create(
            name="CNN", url="http://host.tld/live/joe/s3cret/1.ts"
        )
        dispatch_event_system("stream_switch", stream_id=stream.id)

        self.assertTrue(mock_trigger.called)
        _, payload = mock_trigger.call_args[0]
        self.assertNotIn("s3cret", str(payload))
        self.assertEqual(payload.get("stream_url"), "http://host.tld/...")
        self.assertEqual(payload.get("channel_url"), "http://host.tld/...")
