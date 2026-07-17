# SPDX-License-Identifier: AGPL-3.0-only

from django.test import Client, TestCase


class HealthEndpointTests(TestCase):
    def test_liveness_is_content_minimal(self):
        response = Client().get("/health/live")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_readiness_checks_database(self):
        response = Client().get("/health/ready")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ready"})

    def test_health_endpoints_reject_writes(self):
        response = Client().post("/health/live", data={})

        self.assertEqual(response.status_code, 405)

    def test_security_headers_are_present(self):
        response = Client().get("/health/live")

        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("camera=()", response.headers["Permissions-Policy"])
