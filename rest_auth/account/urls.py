from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"^signup/$", views.signup, name="rest_signup"),
    url(r"^login/$", views.login, name="rest_login"),
    url(r"^logout/$", views.logout, name="rest_logout"),

    url(r"^password/change/$", views.password_change,
        name="rest_change_password"),
    # url(r"^password/set/$", views.password_set, name="rest_set_password"),

    # E-mail
    # url(r"^email/$", views.email, name="rest_email"),
    url(r"^confirm-email/(?P<key>\w+)/$", views.confirm_email,
        name="rest_confirm_email"),

    # password reset
    url(r"^password/reset/$", views.password_reset,
        name="rest_reset_password"),
    url(r"^password/reset/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$",
        views.password_reset_from_key,
        name="rest_reset_password_from_key"),
]
