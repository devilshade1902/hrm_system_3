from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test, login_required
from .models import Department , Roles , User
from .forms import DepartmentForm , RoleForm , EmployeeForm
from django.contrib.auth import authenticate, login , logout
from django.core.mail import send_mail
from django.conf import settings
import random
import string

def is_admin(user):
    return user.is_superuser  


@login_required
def view_departments(request):
    departments = Department.objects.all()
    return render(request, 'view_departments.html', {'departments': departments})


@user_passes_test(is_admin)
def add_department(request):
    if request.method == "POST":
        form = DepartmentForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('view_departments')
    else:
        form = DepartmentForm()
    return render(request, 'add_department.html', {'form': form})


@user_passes_test(is_admin)
def update_department(request, dept_id):
    department = get_object_or_404(Department, id=dept_id)
    if request.method == "POST":
        form = DepartmentForm(request.POST, instance=department)
        if form.is_valid():
            form.save()
            return redirect('view_departments')
    else:
        form = DepartmentForm(instance=department)
    return render(request, 'update_department.html', {'form': form})



@user_passes_test(is_admin)
def toggle_department_status(request, dept_id):
    department = get_object_or_404(Department, id=dept_id)
    department.status = not department.status  # Toggle status
    department.save()
    return redirect('view_departments')


def custom_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            if is_hr_or_admin(user):
                return redirect('dashboard')
            return redirect('view_departments')
        else:
            return render(request, "login.html", {"error": "Invalid username or password"})
    return render(request, "login.html")

def custom_logout(request):
    logout(request)
    return redirect('login') 


@login_required
def view_roles(request):
    roles = Roles.objects.all()
    return render(request, 'view_roles.html', {'roles': roles})


@user_passes_test(is_admin)
def add_role(request):
    if request.method == "POST":
        form = RoleForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('view_roles')
    else:
        form = RoleForm()
    return render(request, 'add_role.html', {'form': form})


@user_passes_test(is_admin)
def update_role(request, role_id):
    role = get_object_or_404(Roles, id=role_id)
    if request.method == "POST":
        form = RoleForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            return redirect('view_roles')
    else:
        form = RoleForm(instance=role)
    return render(request, 'update_role.html', {'form': form})



@user_passes_test(is_admin)
def toggle_roles_status(request, role_id):
    role = get_object_or_404(Roles, id=role_id)
    role.status = not role.status  # Toggle status
    role.save()
    return redirect('view_roles')



def is_hr_or_admin(user):
    if user.is_superuser:  # Allow admin without a role
        return True
    return hasattr(user, 'role') and user.role and user.role.role_name.lower() == 'hr'

def permission_denied(request):
    return render(request, 'permission_denied.html', {
        'message': "Only admin or HR can access this page."})

@login_required
@user_passes_test(is_hr_or_admin , login_url='permission_denied')
def dashboard(request):
    employees = User.objects.filter(is_superuser=False)
    return render(request, 'dashboard.html', {'employees': employees})

@login_required
@user_passes_test(is_hr_or_admin)
def add_employee(request):
    if request.method == "POST":
        form = EmployeeForm(request.POST)
        if form.is_valid():
            if not form.cleaned_data.get("password"):  # Check if password is provided
                form.add_error('password', "Password is required for new employees.")
                return render(request, 'add_employee.html', {'form': form})
            form.save()
            return redirect('dashboard')
    else:
        form = EmployeeForm()
    return render(request, 'add_employee.html', {'form': form})

@login_required
@user_passes_test(is_hr_or_admin)
def update_employee(request, emp_id):
    employee = get_object_or_404(User, employee_id=emp_id)
    if request.method == "POST":
        form = EmployeeForm(request.POST, instance=employee)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = EmployeeForm(instance=employee)
    return render(request, 'update_employee.html', {'form': form})

@login_required
@user_passes_test(is_hr_or_admin)
def delete_employee(request, emp_id):
    employee = get_object_or_404(User, employee_id=emp_id)
    if employee == request.user:
        # Prevent deleting the current user
        return render(request, 'delete_employee.html', {
            'employee': employee,
            'error': "You cannot delete yourself while logged in."
        })
    if request.method == "POST":
        employee.delete()  # Hard delete: removes the employee from the database
        return redirect('dashboard')
    return render(request, 'delete_employee.html', {'employee': employee})




def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)
            # Generate a 6-digit OTP
            otp = ''.join(random.choices(string.digits, k=6))
            # Store OTP in session
            request.session['reset_otp'] = otp
            request.session['reset_email'] = email
            # Send OTP email
            send_mail(
                subject='HRM System Password Reset OTP',
                message=f'Your OTP for password reset is: {otp}. It is valid for 10 minutes.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            return redirect('verify_otp')
        except User.DoesNotExist:
            return render(request, "forgot_password.html", {"error": "Email not registered."})
    return render(request, "forgot_password.html")

def verify_otp(request):
    if request.method == "POST":
        entered_otp = request.POST.get("otp")
        stored_otp = request.session.get('reset_otp')
        if entered_otp == stored_otp:
            return redirect('reset_password')
        else:
            return render(request, "verify_otp.html", {"error": "Invalid OTP. Please try again."})
    return render(request, "verify_otp.html")

def reset_password(request):
    if 'reset_email' not in request.session:
        return redirect('forgot_password')  # Prevent direct access
    if request.method == "POST":
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")
        if new_password == confirm_password:
            email = request.session.get('reset_email')
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            # Clear session data
            del request.session['reset_otp']
            del request.session['reset_email']
            return redirect('login')
        else:
            return render(request, "reset_password.html", {"error": "Passwords do not match."})
    return render(request, "reset_password.html")