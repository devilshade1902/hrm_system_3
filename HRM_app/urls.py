from django.urls import path
from .views import view_departments, add_department, update_department, toggle_department_status,custom_login, custom_logout,add_role, view_roles,update_role,toggle_roles_status,dashboard,add_employee,update_employee,delete_employee,permission_denied,forgot_password,verify_otp,reset_password

urlpatterns = [
    path('', view_departments, name='view_departments'),  # Non-admin view
    path('add/', add_department, name='add_department'),  # Admin only
    path('update/<int:dept_id>/', update_department, name='update_department'),  # Admin only
    path('toggle_status/<int:dept_id>/', toggle_department_status, name='delete_department'),  # Admin only
    path('accounts/login/', custom_login, name='login'),
    path('accouts/logout ', custom_logout, name='logout'),
    path('add_role/', add_role, name='add_role'),
    path('view_roles/', view_roles, name='view_roles'),
    path('update_role/<int:role_id>/', update_role, name='update_role'),
    path('toggle_role_status/<int:role_id>/', toggle_roles_status, name='delete_role'),
    path('dashboard/', dashboard, name='dashboard'),
    path('add_employee/', add_employee, name='add_employee'),
    path('update_emp/<int:emp_id>/', update_employee, name='update_employee'),
    path('delete_emp/<int:emp_id>/', delete_employee, name='delete_employee'),
    path('permission-denied/', permission_denied, name='permission_denied'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('reset-password/', reset_password, name='reset_password'),
]