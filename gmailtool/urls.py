# gmailtool/urls.py

from django.urls import path
from django.shortcuts import redirect, reverse
from . import views

urlpatterns = [
    path('', views.index_page, name='index_page'),
    
    path('login/', views.login, name='login'),
    path('oauth2callback/', views.oauth2callback, name='oauth2callback'),
    path('logout/', views.logout, name='logout'),

    
    path('senders/', views.show_senders, name='show_senders'),
    path('loading/', views.loading_page, name='loading_page'),

    
    path('delete/now/', views.delete_now, name='delete_now'),
    
    path('schedule-deletion/', views.schedule_sender_deletion_view, name='schedule_sender_deletion'),
    path('unschedule-deletion/', views.unschedule_sender_deletion_view, name='unschedule_sender_deletion'),

    
    path('run-my-scheduled/', views.run_my_scheduled_deletions_now_view, name='run_my_scheduled_deletions_now'),
    
]