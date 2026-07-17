# SPDX-License-Identifier: AGPL-3.0-only

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mailgate.settings")

application = get_wsgi_application()
