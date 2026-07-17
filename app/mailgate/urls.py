# SPDX-License-Identifier: AGPL-3.0-only

from django.urls import path

from mailgate import health

urlpatterns = [
    path("health/live", health.live, name="health-live"),
    path("health/ready", health.ready, name="health-ready"),
]
