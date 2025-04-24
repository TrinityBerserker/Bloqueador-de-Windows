import os
import subprocess
import socket
from scapy.all import sniff, DNSQR, DNS

# Lista negra de dominios peligrosos (puedes ampliar con listas reales)
dominios_maliciosos = [
    "malicious-site.com",
    "bad-phishing.com",
    "ransomware-fakebank.net"
]

# Verifica si el script se está ejecutando como administrador
def verificar_admin():
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Intenta obtener la IP del dominio
def resolver_ip(dominio):
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None

# Bloquea la IP usando el firewall de Windows
def bloquear_ip_windows(ip, dominio):
    regla = f"netsh advfirewall firewall add rule name=\"Bloqueo {dominio}\" dir=out action=block remoteip={ip} enable=yes"
    subprocess.run(regla, shell=True)
    print(f"\n[ALERTA] Se ha BLOQUEADO el acceso a:\n - Dominio: {dominio}\n - IP: {ip}")
    print("Motivo: Este sitio está marcado como phishing o ransomware.")
    print("Recomendación: No intentes acceder nuevamente.\n")

# Analiza paquetes DNS y bloquea si es malicioso
def analizar_paquete(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dominio = packet.getlayer(DNSQR).qname.decode('utf-8').rstrip('.')
        print(f"[*] Detectando intento de conexión a: {dominio}")
        for malicioso in dominios_maliciosos:
            if malicioso in dominio:
                ip = resolver_ip(dominio)
                if ip:
                    bloquear_ip_windows(ip, dominio)
                else:
                    print("[!] No se pudo resolver la IP del dominio.")
                break

# Inicio del programa
if __name__ == "__main__":
    if not verificar_admin():
        print("Este script debe ejecutarse como ADMINISTRADOR.")
        input("Presiona Enter para salir...")
        exit(1)

    print("Iniciando monitoreo de conexiones DNS. Presiona CTRL+C para detener.")
    print("-----------------------------------------------------------\n")
    try:
        sniff(filter="udp port 53", prn=analizar_paquete, store=0)
    except KeyboardInterrupt:
        print("\nDetenido por el usuario.")
