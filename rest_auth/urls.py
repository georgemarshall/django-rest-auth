from django.conf.urls import include, url

# urlpatterns = patterns('',
#     # URLs that do not require a session or valid token
#     url(r'^password/reset/$', PasswordResetView.as_view(),
#         name='rest_password_reset'),
#     url(r'^password/reset/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', PasswordResetFromKeyView.as_view(),
#         name='rest_password_reset_confirm'),
#     url(r'^login/$', LoginView.as_view(), name='rest_login'),
#     # URLs that require a user to be logged in with a valid session / token.
#     url(r'^logout/$', LogoutView.as_view(), name='rest_logout'),
#     url(r'^user/$', UserDetails.as_view(), name='rest_user_details'),
#     url(r'^password/change/$', PasswordChangeView.as_view(),
#         name='rest_password_change'),
# )

urlpatterns = [
    url(r'^', include('rest_auth.account.urls'))
]
