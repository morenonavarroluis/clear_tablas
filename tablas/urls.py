
from django.urls import path
from .views import *
urlpatterns = [
    path('', inicio ,name='login'),
    path('iniciar', iniciar ,name='iniciar'),
    path('home', home ,name='home'),
    path('register_switches', register_switches ,name='register_switches'),
    path('clear_switch/<int:switch_id>/', clear_switch_security ,name='clear_switch_security'), 
    path('editar_switch/<int:switch_id>/', editar_switch ,name='editar_switch'),
    path('logout', logout_view ,name='logout'),
]