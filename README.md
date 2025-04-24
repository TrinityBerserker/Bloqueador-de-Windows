# 🛡️ Bloqueador DNS Antiphishing & Ransomware (Linux/Windows)

> 🐍 Software en Python para detectar y bloquear conexiones a sitios maliciosos en tiempo real.

## 🚨 ¿Qué hace este proyecto?

Este script monitorea de forma **activa y en tiempo real** las consultas DNS que realiza tu PC. Si detecta que intentas acceder a un dominio marcado como **phishing**, **ransomware** o **sitio engañoso**, lo:

- 🔍 Detecta automáticamente mediante inspección DNS.
- 🧠 Resuelve la IP del dominio malicioso.
- ⛔️ **Bloquea la IP en tu sistema operativo** (usando `iptables` en Linux o `netsh advfirewall` en Windows).
- ⚠️ Lanza una alerta en consola explicando el riesgo y la razón del bloqueo.

Todo esto **sin necesidad de software adicional**, y utilizando las herramientas nativas del sistema.

---

## ⚙️ Funcionalidades

- ✅ Protección en tiempo real contra phishing y ransomware.
- 📡 Monitoreo pasivo de tráfico DNS.
- 🔒 Integración con el firewall del sistema (Linux y Windows).
- 📢 Alertas inmediatas al usuario.
- 📝 Fácil de configurar y expandir con más dominios maliciosos.

---

## 🚀 Cómo usarlo

1. **Clona el repositorio**
   ```bash
   git clone https://github.com/tuusuario/bloqueador-antiphishing.git
   cd bloqueador-antiphishing
