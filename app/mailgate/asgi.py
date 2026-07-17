# SPDX-License-Identifier: AGPL-3.0-only

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mailgate.settings")

application = get_asgi_application()
