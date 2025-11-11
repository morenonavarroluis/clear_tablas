# tablas/utils.py (CORREGIDO)
from django.contrib import messages

import os
import sys
import paramiko
import threading
import time
import re
from cryptography.fernet import Fernet


KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.key")

cipher_suite = None

def load_key():
    """Carga la clave de encriptación desde un archivo."""
    global cipher_suite
    try:
        if not os.path.exists(KEY_FILE):
            print(f" Error de Clave: El archivo '{KEY_FILE}' no se encontró.")
            return None
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
            cipher_suite = Fernet(key)
            return cipher_suite
    except Exception as e:
        print(f" Error al cargar la clave de encriptación: {e}")
        return None

def decrypt_password(encrypted_password):
    """Desencripta una contraseña usando la clave Fernet."""
    global cipher_suite
    if cipher_suite is None:
        load_key() 
    
    if not encrypted_password:
        return ""
    try:
        # Asegúrate de que la cadena se convierte a bytes antes de desencriptar
        decrypted_pass = cipher_suite.decrypt(encrypted_password.encode()) 
        return decrypted_pass.decode()
    except Exception as e:
        print(f" Error al desencriptar la contraseña: {e}")
        return None
    

def encrypt_password(password):
    """Encripta una contraseña usando la clave Fernet."""
    global cipher_suite
    if cipher_suite is None:
        load_key()
    
    if not password:
        return ""
    try:
        encrypted_pass = cipher_suite.encrypt(password.encode())
        # Convertir a str para guardar en la base de datos (TextField)
        return encrypted_pass.decode() 
    except Exception as e:
        print(f" Error al encriptar la contraseña: {e}")
        return None
    

# ---------------- NUEVAS FUNCIONES DE LOG -----------------
def log_message_to_db(log_id, message, is_final=False, success=None):
    """Guarda el mensaje en la BD y actualiza el estado final."""
    from .models import CleanLog # Importación local
    try:
        log = CleanLog.objects.get(pk=log_id)
        # Añade el mensaje al campo log_output
        log.log_output = (log.log_output or "") + message + "\n"
        
        if is_final:
            log.status = 'SUCCESS' if success else 'FAILED'
        
        log.save()
    except Exception as e:
        print(f"ERROR AL GUARDAR LOG EN BD: {e}")


# ---------------- _clear_port_security MODIFICADA -----------------
# ACEPTA log_id como último argumento
def _clear_port_security(hostname, username, password, brand, log_id):
    """Conecta por SSH, ejecuta comandos y registra el resultado en la BD."""
    client = None
    
    def log_message(msg, final=False, status_success=None):
        log_message_to_db(log_id, f"[{time.strftime('%H:%M:%S')}] SSH ({hostname}): {msg}", final, status_success)
        print(f"[{time.strftime('%H:%M:%S')}] SSH ({hostname}): {msg}") # Mantiene el log en consola

    try:
        log_message(f"Intentando conectar a {hostname} ({brand})...")
        
        client = paramiko.SSHClient()
       
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            hostname=hostname, 
            username=username, 
            password=password, 
            timeout=10 
        )
        log_message("Conexión SSH establecida con éxito.")

        
        shell = client.invoke_shell()
        log_message("Sesión interactiva iniciada. Enviando comandos...")
        
       
        time.sleep(1) 
        
       
        commands = [
            'enable',
            'terminal length 0', 
            'configure terminal',
            'no switchport port-security' 
        ]
        
        output = ""
        for cmd in commands:
            shell.send(cmd + '\n')
            time.sleep(0.5) 
            
            
            while shell.recv_ready():
                 output += shell.recv(65535).decode('utf-8')
        
        
        shell.send('end\n')
        shell.send('write memory\n') 
        time.sleep(2)
        
        
        final_output = output + shell.recv(65535).decode('utf-8')
        log_message(f"Comandos ejecutados. Salida: \n{final_output[:500]}...", final=False) 
        
        
        log_message(f" Limpieza de Port-Security exitosa en {hostname}.", final=True, status_success=True)
        return True

    except paramiko.AuthenticationException:
        log_message(f"❌ Error de autenticación en {hostname}.", final=True, status_success=False)
        return False
    except paramiko.SSHException as e:
        log_message(f" Error SSH en {hostname}: {e}.", final=True, status_success=False)
        return False
    except Exception as e:
        # Aquí se capturarán errores de conexión o cualquier otro error inesperado
        log_message(f" Error inesperado en {hostname}: {e}", final=True, status_success=False)
        return False
    finally:
        if client:
            try:
                client.close()
                log_message(f"Conexión a {hostname} cerrada.")
            except Exception as e:
                log_message(f" Advertencia: No se pudo cerrar la conexión SSH a {hostname}: {e}")