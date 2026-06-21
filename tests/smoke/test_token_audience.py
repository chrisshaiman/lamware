"""Post-deploy check: the access token carries the dedicated lamware-api audience.

Confirms the Keycloak `lamware-web` audience mapper is live — a fresh login stamps
`lamware-api` into the access-token `aud`. This is the regression gate for the JWT
audience-validation control (`api/app/auth.py` validates `aud` against an allowlist):
if the mapper is ever removed, strict aud validation would lock out the app, and
this test catches it here (smoke) before that bites in production.

Reuses the session `viewer_token` fixture (conftest), which lifts a real access
token off an authenticated /api/* request via the PKCE login — so this needs no
devtools and no manual token handling. Decoding does not verify the signature
(the API already does that); we only inspect the aud claim.

Author: Christopher Shaiman
License: Apache 2.0
"""

import base64
import json

EXPECTED_AUDIENCE = "lamware-api"


def _decode_aud(token: str) -> list[str]:
    """Return the JWT's aud claim as a list (no signature verification)."""
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    aud = claims.get("aud", [])
    return [aud] if isinstance(aud, str) else aud


def test_access_token_carries_lamware_api_audience(viewer_token):
    """A freshly issued access token must include the lamware-api audience."""
    auds = _decode_aud(viewer_token)
    assert EXPECTED_AUDIENCE in auds, (
        f"AUDIENCE MAPPER MISSING: access token aud={auds!r} does not contain "
        f"{EXPECTED_AUDIENCE!r}. The Keycloak lamware-web audience mapper is not "
        f"active — strict JWT aud validation would lock out the app."
    )
