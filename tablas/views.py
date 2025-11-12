from django.contrib import messages
from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .utils import decrypt_password, _clear_port_security, load_key, encrypt_password
import threading
from .models import Switch, CleanLog
from django.http import JsonResponse
# Create your views here.
def inicio(request):
    return render(request, 'pages/inicio.html')

def iniciar(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        print(user)
        if user is not None:
            login(request, user)
            encrypted_login_pass = encrypt_password(password)
            request.session['login_username'] = username
            request.session['login_password_enc'] = encrypted_login_pass
       
            return redirect('home')
        else:
            messages.error(request, 'Credenciales inválidas. Por favor, inténtalo de nuevo.')
            return render(request, 'pages/inicio.html')
    else:
        
        return redirect('inicio')

@login_required
def home(request):
    Switches = Switch.objects.all()

    logs_finalizados = CleanLog.objects.filter(
        user=request.user, 
        status__in=['SUCCESS', 'FAILED'],
        message_shown=False
    ).select_related('switch') 
   
    logs_a_marcar = []
    
    for log in logs_finalizados:
        if log.status == 'SUCCESS':
            messages.success(request, f"✅ Tarea Finalizada en {log.switch.nombre}: Limpieza exitosa.")
        elif log.status == 'FAILED':
           
            error_msg = (log.log_output or "Verifique el log para más detalles.").split('\n')[-2] 
            messages.error(request, f"❌ Tarea Fallida en {log.switch.nombre}: {error_msg}")
        logs_a_marcar.append(log.pk)
    if logs_a_marcar:
        CleanLog.objects.filter(pk__in=logs_a_marcar).update(message_shown=True)
    
    
    contexto = {
        'switches': Switches
        # Opcional: pasar todos los logs para una tabla de historial en home.html
        # 'historial_logs': CleanLog.objects.filter(user=request.user).order_by('-timestamp')[:10]
    }
    return render(request, 'pages/home.html', contexto)
load_key() 

@login_required
def verificar_logs_finalizados(request):
    logs_finalizados = CleanLog.objects.filter(
        user=request.user, 
        status__in=['SUCCESS', 'FAILED'],
        message_shown=False
    ).select_related('switch')

    logs_a_marcar_pks = []
    mensajes = []

    for log in logs_finalizados:
        mensaje_base = f"Tarea en {log.switch.nombre}"
        
        if log.status == 'SUCCESS':
            mensajes.append({
                'tipo': 'success',
                'icono': '✅',
                'texto': f"{mensaje_base}: Limpieza exitosa."
            })
        elif log.status == 'FAILED':
            error_msg = (log.log_output or "Verifique el log para más detalles.").split('\n')[-2].strip()
            mensajes.append({
                'tipo': 'error',
                'icono': '❌',
                'texto': f"{mensaje_base} fallida: {error_msg}"
            })
            
        logs_a_marcar_pks.append(log.pk)

    if logs_a_marcar_pks:
        # 3. Marcar los logs como mostrados
        CleanLog.objects.filter(pk__in=logs_a_marcar_pks).update(message_shown=True)

    # 4. Devolver los mensajes como JSON
    return JsonResponse({'mensajes': mensajes})

def register_switches(request):
    if not request.user.is_authenticated:
        return redirect('login') 
        
    if request.method == 'POST':
        nombre = request.POST.get('nombre')
        ip = request.POST.get('ip')
        # NUEVOS: Capturar credenciales SSH del formulario
        ssh_username = request.POST.get('ssh_username') 
        ssh_password = request.POST.get('ssh_password') 
        
        try:
            # 1. ENCRIPTAR LA CONTRASEÑA
            encrypted_pass = encrypt_password(ssh_password)
            
            new_switch = Switch(
                nombre=nombre, 
                ip_address=ip, 
                ssh_username=ssh_username, # Guardar el usuario SSH
                encrypted_password=encrypted_pass, # Guardar la contraseña encriptada
                administrador=request.user 
            )
        
            new_switch.save()
            messages.success(request, f'El Switch "{nombre}" ha sido registrado exitosamente.')
            return redirect('home')

        except Exception as e:
            messages.error(request, f'Error al registrar el switch. Detalles: {e}')
            return redirect('home')
    else:
        # Debes asegurarte de que tu template 'pages/home.html' tenga el formulario
        # con los campos 'ssh_username' y 'ssh_password'.
        return render(request, 'pages/home.html')
    
@login_required
def clear_switch_security(request, switch_id):
    # 1. Recuperar el Switch
    try:
        switch = Switch.objects.get(pk=switch_id)
    except Switch.DoesNotExist:
        messages.error(request, "Switch no encontrado.")
        return redirect('home')

    # 2. Recuperar y desencriptar credenciales de la SESIÓN (del usuario autenticado)
    session_username = request.session.get('login_username')
    encrypted_session_pass = request.session.get('login_password_enc')
    decrypted_pass_from_session = None

    if session_username and encrypted_session_pass:
        # Desencriptar la contraseña de la sesión
        decrypted_pass_from_session = decrypt_password(encrypted_session_pass)
        print(f"Contraseña desencriptada de sesión: {decrypted_pass_from_session}")
    # 3. Verificar la obtención de la contraseña
    # Si decrypted_pass_from_session es None, significa que no se pudo obtener o desencriptar
    if decrypted_pass_from_session is None:
        messages.error(request, 'Error: No se pudo obtener o desencriptar las credenciales SSH del usuario. Por favor, vuelva a iniciar sesión.')
        return redirect('home')

    # 4. Crear el log
    new_log = CleanLog.objects.create(
        switch=switch,
        user=request.user,
        status='RUNNING'
    )
    
    log_id = new_log.pk
    switch_brand = getattr(switch, 'brand', 'Cisco') 

    # 5. Iniciar la tarea en un hilo (usando credenciales de la sesión)
    thread = threading.Thread(
        target=_clear_port_security, 
        # Utilizamos las credenciales obtenidas de la sesión para la conexión:
        args=(switch.ip_address, session_username, decrypted_pass_from_session, switch_brand, log_id) 
    )
    thread.start()
    
    messages.info(request, f"Iniciando limpieza de {switch.nombre} ({switch.ip_address}) en segundo plano.")
    
    return redirect('home')

def editar_switch(request, switch_id):
    if not request.user.is_authenticated:
        return redirect('login') 
        
    try:
        switch = Switch.objects.get(pk=switch_id)
    except Switch.DoesNotExist:
        messages.error(request, "Switch no encontrado.")
        return redirect('home')
        
    if request.method == 'POST':
        ssh_username = request.POST.get('username') 
        ssh_password = request.POST.get('password') 
        
        try:
           
            encrypted_pass = encrypt_password(ssh_password)
            
           
            if encrypted_pass is None:
                messages.error(request, 'Error: No se pudo encriptar la contraseña. Verifica que "key.key" se haya cargado correctamente.')
                return redirect('home')
            
            
            switch.ssh_username = ssh_username
            switch.encrypted_password = encrypted_pass
            switch.save()
            print(ssh_username, ssh_password)
            messages.success(request, f'El Switch ha sido actualizado exitosamente.')
            return redirect('home')

        except Exception as e:
            messages.error(request, f'Error al actualizar el switch. Detalles: {e}')
            return redirect('home')
    else:
        return redirect('home')

def delete_switch(request, switch_id):
    if not request.user.is_authenticated:
        return redirect('login') 
        
    try:
        switch = Switch.objects.get(pk=switch_id)
        switch.delete()
        messages.success(request, f'El Switch ha sido eliminado exitosamente.')
        return redirect('home')

    except Switch.DoesNotExist:
        messages.error(request, "Switch no encontrado.")
        return redirect('home')

def logout_view(request):
    logout(request)
    return redirect('login')