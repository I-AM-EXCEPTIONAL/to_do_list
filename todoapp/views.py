from django.shortcuts import render, redirect , HttpResponse 
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import todo
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password

# Create your views here.
def register(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if len(password) < 4:
            messages.error(request, 'Password must be at least 3 characters')
            return redirect('register')

        get_all_users_by_username = User.objects.filter(username=username)
        if get_all_users_by_username:
            messages.error(request, 'Error, username already exists, User another.')
            return redirect('register')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists. Please use another email address.')
            return redirect('register')
        
        new_user = User.objects.create_user(username=username, email=email, password=password)
        new_user.save()

        messages.success(request, 'User successfully created, login now')
        return redirect('login')
    return render(request, 'register.html', {})



def loginpage(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        username = request.POST.get('uname')
        password = request.POST.get('pass')

        validate_user = authenticate(username=username, password=password)
        if validate_user is not None:
            login(request, validate_user)
            return redirect('home')
        else:
            messages.error(request, 'Error, wrong user details or user does not exist')
            return redirect('login')
        
    return render(request, 'login.html', {})



@login_required
def home(request):
    if request.method == 'POST':
        task = request.POST.get('task')
        new_todo = todo(user=request.user, todo_name=task)
        new_todo.save()

    all_todos = todo.objects.filter(user=request.user)
    context = {
        'todos': all_todos
    }
    return render(request, 'todo.html', context)


def LogoutView(request):
    logout(request)
    return redirect('login')


@login_required
def DeleteTask(request, name):
    get_todo = todo.objects.get(user=request.user, todo_name=name)
    get_todo.delete()
    return redirect('home')

@login_required
def Update(request, name):
    get_todo = todo.objects.get(user=request.user, todo_name=name)
    get_todo.status = True
    get_todo.save()
    return redirect('home')




def reset_password(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        new_password = request.POST.get('password')

        # Retrieve the user by username
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, 'User does not exist')
            return redirect('reset_password')

        # Update the user's password
        user.password = make_password(new_password)
        user.save()

        messages.success(request, 'Password reset successfully')
        return redirect('login')  # Redirect to the login page after successful password reset
    else:
        return render(request, 'reset_pass.html')