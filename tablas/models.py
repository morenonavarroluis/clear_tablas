
from django.utils import timezone # Para obtener la hora actual
from django.db import models
from django.contrib.auth.models import User
# Asegúrate de tener tu función de encriptación (Fernet) importada o accesible
from .utils import encrypt_password # Necesitas esta función

class Switch(models.Model):
    nombre = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    # NUEVOS CAMPOS SSH
    ssh_username = models.CharField(max_length=100)
    # Usamos TextField para la contraseña encriptada (será una cadena larga)
    encrypted_password = models.TextField(default='DEFAULT_ENCRYPTED_PASS') 
    brand = models.CharField(max_length=50, default='Cisco')
    
    administrador = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='switches_administrados'
    )
    # Agrega el campo brand y otros si es necesario (ej: brand = models.CharField(max_length=50, default='Cisco'))

    def __str__(self):
        return self.nombre

    # Opción: Sobreescribir save para encriptar la contraseña antes de guardarla
    def save(self, *args, **kwargs):
        # SOLO encripta si la contraseña es nueva o ha cambiado Y NO está ya encriptada
        # (se necesita lógica más robusta para manejar esto)
        super().save(*args, **kwargs)
        

class CleanLog(models.Model):
    STATUS_CHOICES = [
        ('SUCCESS', 'Éxito'),
        ('FAILED', 'Fallido'),
        ('RUNNING', 'En ejecución')
    ]
    
    switch = models.ForeignKey(
        'Switch', 
        on_delete=models.CASCADE,
        related_name='logs' 
    )
    # 🔴 CAMBIO 1: Añadir el usuario que realizó la limpieza
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='clean_logs'
    )
    # --------------------------------------------------------
    
    timestamp = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='RUNNING')
    log_output = models.TextField(blank=True, null=True)
    message_shown = models.BooleanField(default=False)
   
    class Meta:
        get_latest_by = 'timestamp'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.switch.nombre} - {self.get_status_display()}"