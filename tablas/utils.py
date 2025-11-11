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
        from .models import CleanLog # Aseguramos la importación local si es necesario
        log_message_to_db(log_id, f"[{time.strftime('%H:%M:%S')}] SSH ({hostname}): {msg}", final, status_success)
        print(f"[{time.strftime('%H:%M:%S')}] SSH ({hostname}): {msg}")

    try:
        log_message(f"Intentando conectar a {hostname} ({brand})...")
        
        # 1. Conexión (OK)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            hostname=hostname, 
            username=username, 
            password=password, 
            timeout=10 
        )
        log_message("Conexión SSH establecida con éxito.")

        # 2. Ejecución de comandos
        shell = client.invoke_shell()
        log_message("Sesión interactiva iniciada. Enviando comandos de limpieza...")
        
        # Esperar a que el shell cargue
        time.sleep(1) 
        
        # 🟢 CORRECCIÓN 1: Usar comandos EXEC y de configuración correctos.
        #    Se usará 'clear port-security sticky' que limpia las MACs aprendidas.
        
        # Comandos en modo EXEC
        commands = [
            'enable',
            'terminal length 0', 
            'clear port-security sticky', # Comando correcto para limpiar MACs en Cisco
            'write memory'                # Guardar la configuración
        ]
        
        output = ""
        
        for cmd in commands:
            log_message(f"Ejecutando: {cmd}")
            shell.send(cmd + '\n')
            time.sleep(1) # Aumentamos el tiempo de espera por comando para dar tiempo a procesar y recibir
            
            # Capturar la salida del comando actual
            current_output = ""
            while shell.recv_ready():
                current_output += shell.recv(65535).decode('utf-8')

            # 🟢 CORRECCIÓN 2: Verificar errores de comandos de Cisco
            if "% Invalid input detected" in current_output or "Error" in current_output:
                 log_message(f"❌ Error de Sintaxis o Ejecución. Comando: {cmd}. Salida: {current_output}", final=False)
                 # Lanzamos una excepción para que caiga en el bloque 'except Exception' y marque como FAILED
                 raise Exception(f"Comando fallido en switch: {cmd}")
            
            output += current_output

        # 🟢 CORRECCIÓN 3: Limpiar el búfer final y registrar
        # No es necesario enviar 'end' y 'write memory' de nuevo si ya están en 'commands'
        time.sleep(1) 
        final_output = output + shell.recv(65535).decode('utf-8')
        log_message(f"Comandos ejecutados. Salida inicial: \n{final_output[:500]}...", final=False) 
        
        
        # MENSAJE DE ÉXITO FINAL
        log_message(f"✅ Limpieza de Port-Security exitosa en {hostname}.", final=True, status_success=True)
       
        return True

    except paramiko.AuthenticationException:
        log_message(f"❌ Error de autenticación en {hostname}.", final=True, status_success=False)
        return False
    except paramiko.SSHException as e:
        log_message(f"❌ Error SSH en {hostname}: {e}.", final=True, status_success=False)
        return False
    except Exception as e:
        # Captura errores de conexión, errores lanzados manualmente, o errores de Python.
        log_message(f"❌ Error al ejecutar tarea en {hostname}: {e}", final=True, status_success=False)
        return False
    finally:
        if client:
            try:
                client.close()
                log_message(f"Conexión a {hostname} cerrada.")
            except Exception as e:
                log_message(f"⚠️ Advertencia: No se pudo cerrar la conexión SSH a {hostname}: {e}")