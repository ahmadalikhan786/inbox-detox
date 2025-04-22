# gmailtool/urls.py

from django.urls import path
from . import views

urlpatterns = [
    # Authentication Flow
    path('login/', views.login, name='login'),
    path('oauth2callback/', views.oauth2callback, name='oauth2callback'), # Handles google response ONLY
    path('logout/', views.logout, name='logout'),

    # View to display data
    path('senders/', views.show_senders, name='show_senders'), # Displays the list

    # Deletion Actions
    path('delete/now/', views.delete_now, name='delete_now'),
    path('delete/later/', views.delete_later, name='delete_later'),

    # Optional: Redirect root URL?
    path('', lambda request: redirect(reverse('login')), name='home'), # Example: root redirects to login
]