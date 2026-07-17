# SPDX-License-Identifier: AGPL-3.0-only

from django.contrib.auth import views as auth_views
from django.urls import include, path
from gateway import views

from mailgate import health

urlpatterns = [
    path("health/live", health.live, name="health-live"),
    path("health/ready", health.ready, name="health-ready"),
    path("setup/", views.setup_owner, name="setup-owner"),
    path("login/", auth_views.LoginView.as_view(template_name="gateway/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", views.dashboard, name="dashboard"),
    path("mailboxes/new/", views.mailbox_create, name="mailbox-create"),
    path("mailboxes/<int:mailbox_id>/edit/", views.mailbox_edit, name="mailbox-edit"),
    path("mailboxes/<int:mailbox_id>/delete/", views.mailbox_delete, name="mailbox-delete"),
    path("security-tests/", views.security_test, name="security-test"),
    path("about/", views.about, name="about"),
    path("i18n/", include("django.conf.urls.i18n")),
    path("messages/", views.message_list, name="message-list"),
    path("messages/<uuid:message_id>/", views.message_detail, name="message-detail"),
    path("messages/<uuid:message_id>/decision/", views.message_decide, name="message-decide"),
    path("tokens/", views.tokens, name="tokens"),
    path("tokens/<int:token_id>/revoke/", views.token_revoke, name="token-revoke"),
    path("audit/", views.audit_log, name="audit"),
]
