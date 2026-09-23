"""Optional read-time code links; never turn a code author into an operator."""

import json
import os
import re
import urllib.error
import urllib.request
from functools import lru_cache


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHubLinks:
    def __init__(self, repositories):
        self.repositories = set(repositories)
        if any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", x)
            for x in self.repositories
        ):
            raise ValueError("invalid GitHub repository allowlist")
        self.opener = urllib.request.build_opener(NoRedirect())

    @lru_cache(maxsize=128)
    def lookup(self, repository, sha):
        if repository not in self.repositories or not re.fullmatch(
            r"[a-f0-9]{40}", sha
        ):
            return {"status": "not_allowed", "pull_requests": []}
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "platform-audit-readonly",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token := os.getenv("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/commits/{sha}/pulls?per_page=100",
            headers=headers,
        )
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    return {"status": "response_too_large", "pull_requests": []}
                values = json.loads(raw)
            if not isinstance(values, list):
                return {"status": "invalid_response", "pull_requests": []}
            links = []
            for item in values:
                number = item.get("number")
                if not isinstance(number, int) or number <= 0:
                    continue
                links.append(
                    {
                        "number": number,
                        "url": f"https://github.com/{repository}/pull/{number}",
                        "relation": "commit_associated_pr",
                    }
                )
            return {
                "status": "found" if links else "no_associated_pr",
                "pull_requests": links,
                "may_have_more": len(values) == 100,
                "scope": "code relationship; operator unchanged",
            }
        except (OSError, ValueError, urllib.error.HTTPError):
            return {"status": "unavailable", "pull_requests": []}

    def enrich(self, event):
        result = dict(event)
        repo, sha = event.get("repository"), event.get("commit")
        if isinstance(repo, str) and isinstance(sha, str):
            result["github"] = self.lookup(repo, sha)
        return result
