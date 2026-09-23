import io
from unittest.mock import Mock

from platform_audit.github import GitHubLinks


def test_code_link_is_not_an_operator_and_preserves_missing_identity():
    resolver = GitHubLinks(["ANIMO-TECH/DotAI"])
    response = Mock()
    response.__enter__ = Mock(
        return_value=io.BytesIO(b'[{"number":248,"user":{"login":"someone"}}]')
    )
    response.__exit__ = Mock(return_value=False)
    resolver.opener.open = Mock(return_value=response)
    original = {"actor": None, "repository": "ANIMO-TECH/DotAI", "commit": "a" * 40}
    result = resolver.enrich(original)
    assert result["actor"] is None
    assert (
        result["github"]["pull_requests"][0]["url"]
        == "https://github.com/ANIMO-TECH/DotAI/pull/248"
    )
    assert "someone" not in str(result) and "github" not in original


def test_unapproved_repo_never_sends_the_token_or_makes_a_request():
    resolver = GitHubLinks(["ANIMO-TECH/DotAI"])
    resolver.opener.open = Mock()
    assert resolver.lookup("another/private-repo", "a" * 40)["status"] == "not_allowed"
    resolver.opener.open.assert_not_called()
