# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in browser E2E for the complete synthetic MailGate owner flow.

Run only in a disposable environment with ``MAILGATE_RUN_E2E=1``. The harness
creates a uniquely named Compose project and temporary synthetic secrets, then
removes both. It deliberately records no screenshots, videos, HARs or traces.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from scripts.create_local_secrets import (
    SECRET_NAMES,
    create_credential_keyring,
    create_fernet_key,
    create_secret,
)

try:
    from axe_playwright_python.sync_playwright import Axe
    from playwright.sync_api import sync_playwright

    BROWSER_DEPENDENCIES_AVAILABLE = True
except ModuleNotFoundError:
    Axe = None
    sync_playwright = None
    BROWSER_DEPENDENCIES_AVAILABLE = False

RUN_E2E = os.getenv("MAILGATE_RUN_E2E") == "1"
EXPECTED_VERSIONS = {
    "playwright": "1.61.0",
    "axe-playwright-python": "0.1.7",
}
SUBJECT = "MailGate E2E synthetic message"
MAILBOX_NAME = "Synthetic E2E mailbox"
ACCESS_LABEL = "Synthetic Hermes access"


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _write_known_secret(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)
        handle.write("\n")
    if os.name != "nt":
        path.chmod(0o444)


class ComposeHarness:
    def __init__(self, repository: Path):
        self.repository = repository.resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix="mailgate-e2e-")
        self.root = Path(self.temporary.name)
        self.secret_directory = self.root / "secrets"
        self.ca_directory = self.root / "imap-ca"
        self.secret_directory.mkdir(mode=0o700)
        self.ca_directory.mkdir(mode=0o700)
        if os.name != "nt":
            self.secret_directory.chmod(0o700)
            # The non-root synthetic server must create the public certificate.
            self.ca_directory.chmod(0o777)
        self.setup_token = secrets.token_urlsafe(32)
        self._create_secrets()
        self.port = _free_port()
        self.project = f"mailgate-e2e-{secrets.token_hex(4)}"
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "MAILGATE_ALLOWED_HOSTS": "localhost,127.0.0.1",
                "MAILGATE_ENVIRONMENT": "development",
                "MAILGATE_HTTP_PORT": str(self.port),
                "MAILGATE_IMAP_ALLOWED_HOST": "imap.example.test",
                "MAILGATE_SECRETS_DIR": self.secret_directory.as_posix(),
                "MAILGATE_E2E_CA_DIR": self.ca_directory.as_posix(),
                "MAILGATE_WORKER_POLL_INTERVAL_SECONDS": "1",
            }
        )
        self.started = False

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _create_secrets(self) -> None:
        for name in SECRET_NAMES:
            path = self.secret_directory / name
            if name in {"master_key", "backup_key"}:
                create_fernet_key(path)
            elif name == "master_keyring":
                create_credential_keyring(path)
            elif name == "setup_token":
                _write_known_secret(path, self.setup_token)
            else:
                create_secret(path, 64 if name == "django_secret_key" else 48)

    def _command(self, *arguments: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
        command = [
            "docker",
            "compose",
            "--project-name",
            self.project,
            "--profile",
            "integration",
            "--file",
            str(self.repository / "compose.yaml"),
            "--file",
            str(self.repository / "tests/e2e/compose.e2e.yaml"),
            *arguments,
        ]
        return subprocess.run(  # noqa: S603 -- fixed executable and controlled argument set
            command,
            cwd=self.repository,
            env=self.environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

    def start(self) -> None:
        configured = self._command("config", "--quiet", timeout=60)
        if configured.returncode != 0:
            raise RuntimeError("Synthetic E2E Compose configuration is invalid")
        # Mark cleanup as required before `up`; Compose may create partial state on failure.
        self.started = True
        started = self._command(
            "up",
            "--build",
            "--detach",
            "--wait",
            "test-imap-upstream",
            "web",
            "api",
            "worker",
            "proxy",
        )
        if started.returncode != 0:
            raise RuntimeError("Synthetic E2E Compose stack did not become healthy")
        self._wait_for_http()

    def _wait_for_http(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                request = urllib.request.Request(  # noqa: S310 -- fixed local HTTP endpoint
                    f"{self.base_url}/health/ready", method="GET"
                )
                with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.5)
        raise RuntimeError("Synthetic E2E HTTP endpoint did not become ready")

    def assert_no_mutation_attempts(self) -> None:
        if not self.started:
            return
        logs = self._command("logs", "--no-color", "test-imap-upstream", timeout=30)
        if logs.returncode != 0:
            raise AssertionError("Synthetic IMAP logs could not be checked")
        if "MUTATION_ATTEMPT" in logs.stdout or "MUTATION_ATTEMPT" in logs.stderr:
            raise AssertionError("MailGate attempted a mutating IMAP command")

    def close(self) -> None:
        mutation_error = None
        try:
            self.assert_no_mutation_attempts()
        except AssertionError as exc:
            mutation_error = exc
        finally:
            if self.started:
                self._command("down", "--volumes", "--remove-orphans", timeout=120)
                self.started = False
            self.temporary.cleanup()
        if mutation_error is not None:
            raise mutation_error


@unittest.skipUnless(
    RUN_E2E and BROWSER_DEPENDENCIES_AVAILABLE,
    "set MAILGATE_RUN_E2E=1 with pinned Playwright/Axe dependencies to run browser E2E",
)
class MailGateBrowserE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for distribution, expected in EXPECTED_VERSIONS.items():
            actual = importlib.metadata.version(distribution)
            if actual != expected:
                raise RuntimeError(f"{distribution} must be pinned to {expected}")

        cls.repository = Path(__file__).resolve().parents[2]
        cls.harness = ComposeHarness(cls.repository)
        cls.playwright = None
        cls.browser = None
        cls.context = None
        cls.addClassCleanup(cls._cleanup)
        cls.harness.start()
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True)
        # No tracing, screenshots, videos, HARs or persistent browser profiles.
        cls.context = cls.browser.new_context(
            locale="en-US", viewport={"width": 1280, "height": 900}
        )
        cls.page = cls.context.new_page()
        cls.page.set_default_timeout(15_000)
        cls.page.set_default_navigation_timeout(30_000)
        cls.axe = Axe()

    @classmethod
    def _cleanup(cls):
        cleanup_errors = []
        for resource in (cls.context, cls.browser, cls.playwright):
            if resource is None:
                continue
            try:
                resource.close() if hasattr(resource, "close") else resource.stop()
            except Exception as exc:  # Cleanup must continue to remove Compose state.
                cleanup_errors.append(exc)
        try:
            cls.harness.close()
        finally:
            if cleanup_errors:
                raise cleanup_errors[0]

    def _url(self, path: str) -> str:
        return f"{self.harness.base_url}{path}"

    def _secret_fill(self, selector: str, value: str) -> None:
        # Passing the value as an evaluate argument keeps it out of Playwright action logs.
        self.page.locator(selector).evaluate(
            """(element, secret) => {
                element.value = secret;
                element.dispatchEvent(new Event('input', {bubbles: true}));
                element.dispatchEvent(new Event('change', {bubbles: true}));
            }""",
            value,
        )

    def _assert_accessible(self, label: str) -> None:
        result = self.axe.run(self.page)
        response = result.response
        if isinstance(response, str):
            response = json.loads(response)
        violations = response.get("violations", []) if isinstance(response, dict) else []
        safe_rule_ids = sorted(
            str(item.get("id", "unknown")) for item in violations if isinstance(item, dict)
        )
        self.assertEqual(
            result.violations_count,
            0,
            f"Axe WCAG violations on {label}: {', '.join(safe_rule_ids)}",
        )

    def _wait_for_ingestion(self) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            self.page.goto(self._url("/messages/?state=quarantined"))
            if self.page.get_by_role("link", name=SUBJECT, exact=True).count() == 1:
                return
            self.page.wait_for_timeout(500)
        self.fail("Synthetic message was not quarantined within the bounded wait")

    def _api_get(self, path: str, token: str) -> tuple[int, dict[str, object]]:
        request = urllib.request.Request(  # noqa: S310 -- fixed local HTTP endpoint
            self._url(path),
            method="GET",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                body = response.read(1_000_000)
                return response.status, json.loads(body)
        except urllib.error.HTTPError as exc:
            body = exc.read(1_000_000)
            document = json.loads(body) if body else {}
            return exc.code, document

    def test_complete_synthetic_owner_flow(self):
        owner_password = "E2E-" + secrets.token_urlsafe(24)
        mailbox_password = "E2E-" + secrets.token_urlsafe(24)
        rotated_password = "E2E-" + secrets.token_urlsafe(24)

        self.page.goto(self._url("/about/"))
        self._assert_accessible("public about")
        self.page.goto(self._url("/setup/"))
        self._assert_accessible("owner setup")
        self.page.locator("#id_username").fill("synthetic-owner")
        self._secret_fill("#id_setup_token", self.harness.setup_token)
        self._secret_fill("#id_password1", owner_password)
        self._secret_fill("#id_password2", owner_password)
        self.page.get_by_role("button", name="Create owner", exact=True).click()
        self.page.wait_for_url("**/mailboxes/new/")
        self._assert_accessible("mailbox setup English")

        self.page.locator("#language-select").select_option("de")
        self.page.locator(".language-form button").click()
        self.assertEqual(self.page.locator("html").get_attribute("lang"), "de")
        self._assert_accessible("mailbox setup German")
        self.page.locator("#language-select").select_option("en")
        self.page.locator(".language-form button").click()
        self.assertEqual(self.page.locator("html").get_attribute("lang"), "en")

        self.page.locator("#id_name").fill(MAILBOX_NAME)
        self.page.locator("#id_provider_key").select_option("generic_imaps")
        self.page.locator("#id_host").fill("imap.example.test")
        self.page.locator("#id_port").fill("993")
        self.page.locator("#id_username").fill("owner@example.test")
        self._secret_fill("#id_password", mailbox_password)
        self.page.locator("#id_enabled").check()
        self.page.get_by_role("button", name="Save mailbox", exact=True).click()
        self.page.wait_for_url(self._url("/"))
        self._assert_accessible("dashboard")

        self._wait_for_ingestion()
        self._assert_accessible("quarantine list")
        self.page.get_by_role("link", name=SUBJECT, exact=True).click()
        self._assert_accessible("quarantined message detail")
        self.assertIn(
            "synthetic MailGate browser E2E message", self.page.locator("pre").inner_text()
        )
        self.page.get_by_role("button", name="Approve safe text", exact=True).click()
        self.assertEqual(self.page.get_by_role("button", name="Approve safe text").count(), 0)

        self.page.goto(self._url("/tokens/"))
        self._assert_accessible("token management without displayed secret")
        self.page.locator("#id_name").fill(ACCESS_LABEL)
        self.page.locator("#id_lifetime_days").fill("1")
        self.page.get_by_role("button", name="Issue token", exact=True).click()
        raw_token = self.page.locator(".secret code").inner_text().strip()
        if not raw_token.startswith("mg_") or len(raw_token) > 200:
            self.fail("Issued API token has an unexpected format")
        # Immediately navigate away so the one-time token no longer remains in the DOM.
        self.page.goto(self._url("/"))

        status, message_list = self._api_get("/api/v1/messages?state=approved", raw_token)
        self.assertEqual(status, 200, "Approved-message API did not authorize the issued token")
        items = message_list.get("items", [])
        self.assertEqual(len(items), 1, "Approved-message API returned an unexpected item count")
        self.assertEqual(items[0].get("subject"), SUBJECT)

        self.page.goto(self._url("/tokens/"))
        token_row = self.page.locator(".token-row", has_text=ACCESS_LABEL)
        token_row.get_by_role("button", name="Revoke", exact=True).click()
        status, _document = self._api_get("/api/v1/messages", raw_token)
        self.assertEqual(status, 401, "Revoked token remained authorized")
        raw_token = ""

        self.page.goto(self._url("/"))
        self.page.get_by_role("link", name="Edit", exact=True).click()
        self._assert_accessible("mailbox credential rotation")
        self._secret_fill("#id_password", rotated_password)
        self.page.get_by_role("button", name="Save changes", exact=True).click()
        self.page.get_by_role("link", name="Edit", exact=True).click()
        self.page.locator("#id_enabled").uncheck()
        self.page.get_by_role("button", name="Save changes", exact=True).click()
        self.assertIn("disabled", self.page.locator("main").inner_text())

        self.page.get_by_role("link", name="Edit", exact=True).click()
        self.page.get_by_role("link", name="Delete this mailbox connection", exact=True).click()
        self._assert_accessible("local mailbox deletion")
        challenge_match = re.search(r"DELETE \d+", self.page.locator("main").inner_text())
        self.assertIsNotNone(challenge_match, "Deletion challenge is missing")
        self.page.locator("#id_confirmation").fill(challenge_match.group(0))
        self.page.get_by_role("button", name="Delete local mailbox data", exact=True).click()
        self.assertIn("No mailbox configured", self.page.locator("main").inner_text())

        self.page.goto(self._url("/audit/"))
        self._assert_accessible("audit trail")
        self.harness.assert_no_mutation_attempts()


if __name__ == "__main__":
    unittest.main()
