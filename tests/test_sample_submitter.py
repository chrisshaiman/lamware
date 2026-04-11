"""
Unit tests for sample_submitter.py — pure validation logic only.

No AWS calls are made. boto3 is patched at import time because the module
initialises _s3 and _sqs clients at module level.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Patch boto3 before importing the module so the module-level
# boto3.client() calls don't try to reach AWS.
with patch("boto3.client", return_value=MagicMock()):
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    import sample_submitter as ss


# ---------------------------------------------------------------------------
# _validate — filename
# ---------------------------------------------------------------------------

class TestValidateFilename:
    def _body(self, **kwargs):
        base = {"filename": "malware.exe", "sha256": "a" * 64}
        base.update(kwargs)
        return base

    def test_valid_filename(self):
        fname, _, _ = ss._validate(self._body())
        assert fname == "malware.exe"

    def test_missing_filename(self):
        body = {"sha256": "a" * 64}
        try:
            ss._validate(body)
            assert False, "expected ValueError"
        except ValueError as e:
            assert "filename" in str(e)

    def test_filename_not_string(self):
        try:
            ss._validate(self._body(filename=123))
        except ValueError as e:
            assert "filename" in str(e)

    def test_path_traversal_stripped(self):
        # os.path.basename strips the path — result is the bare filename, not an error
        fname, _, _ = ss._validate(self._body(filename="../../../etc/passwd"))
        assert fname == "passwd"

    def test_path_traversal_empty_after_strip(self):
        # A pure directory traversal with no filename component becomes empty
        try:
            ss._validate(self._body(filename="../../"))
        except ValueError as e:
            assert "empty" in str(e)

    def test_filename_too_long(self):
        try:
            ss._validate(self._body(filename="a" * 256))
        except ValueError as e:
            assert "filename" in str(e)

    def test_filename_max_length_accepted(self):
        fname, _, _ = ss._validate(self._body(filename="a" * 255))
        assert len(fname) == 255


# ---------------------------------------------------------------------------
# _validate — sha256
# ---------------------------------------------------------------------------

class TestValidateSha256:
    def _body(self, **kwargs):
        base = {"filename": "sample.bin", "sha256": "a" * 64}
        base.update(kwargs)
        return base

    def test_valid_sha256(self):
        _, sha, _ = ss._validate(self._body())
        assert sha == "a" * 64

    def test_missing_sha256(self):
        try:
            ss._validate({"filename": "x.exe"})
        except ValueError as e:
            assert "sha256" in str(e)

    def test_sha256_uppercase_normalised(self):
        _, sha, _ = ss._validate(self._body(sha256="A" * 64))
        assert sha == "a" * 64

    def test_sha256_too_short(self):
        try:
            ss._validate(self._body(sha256="a" * 63))
        except ValueError as e:
            assert "sha256" in str(e)

    def test_sha256_too_long(self):
        try:
            ss._validate(self._body(sha256="a" * 65))
        except ValueError as e:
            assert "sha256" in str(e)

    def test_sha256_non_hex(self):
        try:
            ss._validate(self._body(sha256="g" * 64))
        except ValueError as e:
            assert "sha256" in str(e)

    def test_sha256_with_spaces(self):
        # strip() is called — padded with spaces should still fail (wrong length after strip)
        try:
            ss._validate(self._body(sha256=" " + "a" * 63))
        except ValueError as e:
            assert "sha256" in str(e)


# ---------------------------------------------------------------------------
# _validate — tags
# ---------------------------------------------------------------------------

class TestValidateTags:
    def _body(self, **kwargs):
        base = {"filename": "sample.bin", "sha256": "b" * 64}
        base.update(kwargs)
        return base

    def test_no_tags_defaults_empty(self):
        _, _, tags = ss._validate(self._body())
        assert tags == []

    def test_valid_tags(self):
        _, _, tags = ss._validate(self._body(tags=["doc", "macro"]))
        assert tags == ["doc", "macro"]

    def test_too_many_tags(self):
        try:
            ss._validate(self._body(tags=["t"] * (ss.MAX_TAGS + 1)))
        except ValueError as e:
            assert "tags" in str(e)

    def test_max_tags_accepted(self):
        _, _, tags = ss._validate(self._body(tags=["t"] * ss.MAX_TAGS))
        assert len(tags) == ss.MAX_TAGS

    def test_tag_too_long(self):
        try:
            ss._validate(self._body(tags=["x" * (ss.MAX_TAG_LENGTH + 1)]))
        except ValueError as e:
            assert "tag" in str(e)

    def test_max_tag_length_accepted(self):
        _, _, tags = ss._validate(self._body(tags=["x" * ss.MAX_TAG_LENGTH]))
        assert len(tags[0]) == ss.MAX_TAG_LENGTH

    def test_tags_not_a_list(self):
        try:
            ss._validate(self._body(tags="doc"))
        except ValueError as e:
            assert "tags" in str(e)

    def test_tag_not_a_string(self):
        try:
            ss._validate(self._body(tags=[1, 2]))
        except ValueError as e:
            assert "tag" in str(e)


# ---------------------------------------------------------------------------
# _parse_body
# ---------------------------------------------------------------------------

class TestParseBody:
    def test_valid_json_body(self):
        event = {"body": json.dumps({"filename": "x.exe"})}
        result = ss._parse_body(event)
        assert result == {"filename": "x.exe"}

    def test_missing_body(self):
        try:
            ss._parse_body({})
        except ValueError as e:
            assert "body" in str(e).lower()

    def test_invalid_json(self):
        try:
            ss._parse_body({"body": "not-json{"})
        except ValueError as e:
            assert "json" in str(e).lower()

    def test_empty_body_string(self):
        try:
            ss._parse_body({"body": ""})
        except ValueError as e:
            assert "body" in str(e).lower()


# ---------------------------------------------------------------------------
# _is_s3_event
# ---------------------------------------------------------------------------

class TestIsS3Event:
    def test_s3_event_recognised(self):
        event = {"Records": [{"eventSource": "aws:s3"}]}
        assert ss._is_s3_event(event) is True

    def test_api_gw_event_not_s3(self):
        assert ss._is_s3_event({"body": "{}"}) is False

    def test_empty_records(self):
        assert ss._is_s3_event({"Records": []}) is False

    def test_non_s3_event_source(self):
        event = {"Records": [{"eventSource": "aws:sqs"}]}
        assert ss._is_s3_event(event) is False


# ---------------------------------------------------------------------------
# _error
# ---------------------------------------------------------------------------

class TestError:
    def test_status_code_in_response(self):
        resp = ss._error(400, "bad request")
        assert resp["statusCode"] == 400

    def test_message_in_body(self):
        resp = ss._error(400, "bad request")
        body = json.loads(resp["body"])
        assert body["error"] == "bad request"

    def test_content_type_header(self):
        resp = ss._error(500, "oops")
        assert resp["headers"]["Content-Type"] == "application/json"
