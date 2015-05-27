from django.apps import AppConfig

from django.utils.translation import ugettext_lazy as _


class RestAllAuthConfig(AppConfig):
    name = 'rest_allauth'
    verbose_name = _("REST AllAuth")
