"""
Commit Verifier Service

Verifies that a target URL serves a specific commit SHA by checking
a version endpoint at /.well-known/scanguard-version
"""

from __future__ import annotations

import httpx
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)


class CommitVerifier:
    """Verifies that a target_url serves a specific commit SHA."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def verify_deployment(
        self,
        target_url: str,
        expected_sha: str,
    ) -> Tuple[str, Optional[str]]:
        """
        Check if target_url serves the expected commit SHA.

        Returns:
            (status, message) where status is:
            - "verified": deployment matches expected SHA
            - "commit_mismatch": deployment has different SHA
            - "verification_error": endpoint missing or error
        """
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                # Basic reachability check (GET target URL).
                base_url = target_url.rstrip("/") or target_url
                reachability = await client.get(base_url)

                if reachability.status_code >= 500 or reachability.status_code == 429:
                    return (
                        "verification_error",
                        f"Target returned {reachability.status_code} during reachability check",
                    )

                # Try standard version endpoint (optional)
                resp = await client.get(
                    f"{base_url}/.well-known/scanguard-version"
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except ValueError:
                        return (
                            "verification_error",
                            "Version endpoint returned non-JSON response",
                        )
                    actual_sha = data.get("commit_sha", "").strip()

                    if not actual_sha:
                        return (
                            "verification_error",
                            "Version endpoint exists but no commit_sha in response",
                        )

                    # Compare first 7 chars (short SHA) or full SHA
                    expected_short = expected_sha[:7]
                    actual_short = actual_sha[:7]

                    if expected_sha == actual_sha or expected_short == actual_short:
                        logger.info(
                            f"✅ Deployment verified: {target_url} serves commit {actual_sha}"
                        )
                        return "verified", f"Deployment serves commit {actual_sha}"
                    else:
                        logger.warning(
                            f"❌ Commit mismatch: expected {expected_sha}, deployment has {actual_sha}"
                        )
                        return (
                            "commit_mismatch",
                            f"Expected {expected_sha}, got {actual_sha}",
                        )

                elif resp.status_code == 404:
                    return (
                        "verification_error",
                        "Version endpoint not found (/.well-known/scanguard-version)",
                    )
                elif resp.status_code >= 500 or resp.status_code == 429:
                    return (
                        "verification_error",
                        f"Version endpoint returned {resp.status_code}",
                    )
                else:
                    return (
                        "verification_error",
                        f"Version endpoint returned {resp.status_code}",
                    )

            except httpx.TimeoutException:
                return "verification_error", f"Timeout connecting to {target_url}"
            except httpx.HTTPError as e:
                logger.warning(f"HTTP error verifying deployment: {e}")
                return "verification_error", f"HTTP error: {str(e)}"
            except Exception as e:
                logger.exception(f"Error verifying deployment: {e}")
                return "verification_error", f"Verification failed: {str(e)}"
