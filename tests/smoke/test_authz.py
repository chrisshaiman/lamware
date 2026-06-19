"""Post-deploy negative-authorization checks: a viewer is denied privileged actions.

Replays the live viewer Bearer token (see conftest: viewer_token / viewer_api) against
role-gated endpoints, asserting 403. SAFETY: every target uses a bogus ID or empty body so a
*regressed* (broken-authz) system fails harmlessly — DELETE/POST hit 404/422 instead of acting.
`feeder/pause` is chosen over `resume` because an unexpected pause fails safe (halts) while an
unexpected resume fails open (could trigger detonation). No remediation is performed.

Author: Christopher Shaiman
License: Apache 2.0
"""

import pytest

# (APIRequestContext method, path, kwargs). Bogus IDs (999999999) and the empty submit body
# keep a regressed system harmless; the 403 must come from require_role before the handler.
PRIVILEGED = [
    ("delete", "/api/analyses/999999999", {}),            # admin-gated (regressed -> 404)
    ("post", "/api/samples/submit", {}),                  # analyst-gated (no file -> 422 if regressed)
    ("post", "/api/investigate/999999999/sessions", {}),  # analyst-gated (bogus analysis -> 404)
    ("post", "/api/feeder/pause", {}),                    # analyst-gated (pause fails safe)
]


@pytest.mark.parametrize("method,path,kwargs", PRIVILEGED, ids=[p[1] for p in PRIVILEGED])
def test_viewer_denied(viewer_api, method, path, kwargs):
    """A viewer token must be denied (403) on every role-gated endpoint."""
    resp = getattr(viewer_api, method)(path, **kwargs)
    assert resp.status == 403, (
        f"AUTHZ REGRESSION: viewer was NOT denied on {method.upper()} {path} "
        f"(got {resp.status}, expected 403)"
    )
