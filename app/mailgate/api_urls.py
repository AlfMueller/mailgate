# SPDX-License-Identifier: AGPL-3.0-only

from django.urls import path
from gateway import api

from mailgate import health

urlpatterns = [
    path("health/live", health.live, name="health-live"),
    path("health/ready", health.ready, name="health-ready"),
    path("api/v1/messages", api.messages, name="api-messages"),
    path(
        "api/v1/messages/<uuid:message_id>/summary",
        api.message_summary,
        name="api-message-summary",
    ),
    path("api/v1/categories", api.categories, name="api-categories"),
]
