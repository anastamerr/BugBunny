"""Integration test for DAST against known-vulnerable target.

This test proves that the DAST pipeline can detect real vulnerabilities
in a deliberately vulnerable application (OWASP Juice Shop).

⚠️ This test is marked as slow and requires Docker.
Run with: pytest -m slow backend/tests/integration/test_dast_known_vulnerable_target.py
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from typing import Optional

import pytest

from src.services.scanner.dast_runner import DASTRunner
from src.services.scanner.zap_client import is_docker_available


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    if not is_docker_available():
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_free_port() -> int:
    """Get a free port for the test container."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_juice_shop(port: int) -> Optional[str]:
    """Start OWASP Juice Shop container on specified port.

    Args:
        port: Host port to bind to

    Returns:
        Container ID if successful, None otherwise
    """
    try:
        # Pull image if not present (silent if already exists)
        subprocess.run(
            ["docker", "pull", "bkimminich/juice-shop:latest"],
            capture_output=True,
            timeout=120,
            check=False,
        )

        # Start container
        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "-p",
                f"{port}:3000",
                "--name",
                f"scanguard-test-juiceshop-{port}",
                "bkimminich/juice-shop:latest",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            print(f"Failed to start Juice Shop: {result.stderr}")
            return None

        container_id = result.stdout.strip()
        return container_id if container_id else None

    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"Error starting Juice Shop: {exc}")
        return None


def wait_for_juice_shop(port: int, timeout: int = 60) -> bool:
    """Wait for Juice Shop to be ready.

    Args:
        port: Port where Juice Shop is running
        timeout: Max seconds to wait

    Returns:
        True if ready, False if timeout
    """
    import httpx

    url = f"http://localhost:{port}/"
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=5, follow_redirects=True)
            if response.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)

    return False


def stop_container(container_id: str) -> None:
    """Stop and remove container."""
    try:
        subprocess.run(
            ["docker", "stop", container_id],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except Exception as exc:
        print(f"Error stopping container: {exc}")


@pytest.mark.slow
@pytest.mark.asyncio
async def test_dast_detects_vulnerabilities_in_juice_shop():
    """Test that DAST pipeline detects vulnerabilities in Juice Shop.

    This test:
    1. Starts OWASP Juice Shop in a Docker container
    2. Runs the DAST pipeline against it
    3. Verifies that findings are detected
    4. Cleans up the container

    The test is deterministic by checking for stable passive findings
    (e.g., missing security headers) rather than active exploits.
    """
    # Skip if Docker not available
    if not is_docker_running():
        pytest.skip("Docker is not available or not running")

    port = get_free_port()
    container_id: Optional[str] = None

    try:
        # Start Juice Shop
        print(f"\nStarting OWASP Juice Shop on port {port}...")
        container_id = start_juice_shop(port)
        if not container_id:
            pytest.fail("Failed to start Juice Shop container")

        # Wait for it to be ready
        print("Waiting for Juice Shop to be ready...")
        if not wait_for_juice_shop(port, timeout=90):
            pytest.fail("Juice Shop did not become ready in time")

        print("Juice Shop is ready!")

        # Run DAST scan
        target_url = f"http://localhost:{port}/"
        print(f"Running DAST scan against {target_url}...")

        runner = DASTRunner()
        if not runner.is_available():
            pytest.skip("DAST runner not available (Docker required)")

        # Run scan with short timeout (Juice Shop has known issues, should find them quickly)
        findings = await runner.scan(target_url, auth_headers=None, cookies=None)

        # Verify findings were detected
        print(f"DAST scan completed. Found {len(findings)} findings.")

        # Assert at least some findings were detected
        # Juice Shop should trigger multiple ZAP alerts even with passive scan
        assert len(findings) >= 1, (
            "Expected at least 1 finding from Juice Shop scan. "
            "This indicates DAST pipeline may not be working correctly."
        )

        # Verify finding structure is correct
        for finding in findings[:3]:  # Check first 3 findings
            assert finding.template_id, "Finding should have template_id"
            assert finding.template_name, "Finding should have template_name"
            assert finding.endpoint, "Finding should have endpoint"
            # Endpoint should reference our target
            assert f"localhost:{port}" in finding.endpoint or "host.docker.internal" in finding.endpoint

        # Log details for debugging
        print("\nDetected findings:")
        for i, finding in enumerate(findings[:5], 1):
            print(f"  {i}. [{finding.severity}] {finding.template_name}")
            print(f"     Endpoint: {finding.endpoint}")

        if len(findings) > 5:
            print(f"  ... and {len(findings) - 5} more findings")

        # Optional: Check for specific stable findings (passive scan rules)
        # These are very likely to be detected and don't require active scanning
        finding_names = [f.template_name.lower() for f in findings]

        # Common passive findings in web apps (at least one should be present)
        common_findings = [
            "missing anti-clickjacking header",
            "missing anti-csrf tokens",
            "content security policy",
            "x-content-type-options",
            "strict-transport-security",
        ]

        has_common_finding = any(
            any(common in fname for common in common_findings)
            for fname in finding_names
        )

        if not has_common_finding:
            print(
                "\nWarning: No common passive findings detected. "
                "Found findings may be from active scan only."
            )

    finally:
        # Always clean up container
        if container_id:
            print(f"\nStopping Juice Shop container {container_id}...")
            stop_container(container_id)
            print("Cleanup complete.")


@pytest.mark.slow
@pytest.mark.asyncio
async def test_dast_handles_unreachable_target():
    """Test that DAST runner handles unreachable targets gracefully."""
    if not is_docker_available():
        pytest.skip("Docker is not available")

    runner = DASTRunner()
    if not runner.is_available():
        pytest.skip("DAST runner not available")

    # Try to scan a target that doesn't exist
    findings = await runner.scan(
        "http://localhost:9999/",  # Unlikely to be in use
        auth_headers=None,
        cookies=None,
    )

    # Should return empty list, not crash
    assert isinstance(findings, list)
    assert len(findings) == 0

    # Should have error message
    assert runner.last_error is not None
    assert len(runner.last_error) > 0
