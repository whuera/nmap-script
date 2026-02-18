# Nmap Script - Detector de Vulnerabilidades y Puertos Abiertos

Script automatizado para detectar vulnerabilidades y puertos abiertos utilizando Nmap.

## 📋 Descripción

Este repositorio contiene scripts para realizar escaneos de seguridad automatizados usando Nmap. Los scripts permiten:

- 🔍 Escanear puertos abiertos
- 🛡️ Detectar vulnerabilidades conocidas
- 🔧 Identificar versiones de servicios
- 💻 Realizar detección de sistema operativo
- 📊 Generar reportes detallados

## ⚠️ Advertencia Legal

**IMPORTANTE**: Estos scripts deben usarse únicamente en sistemas para los cuales tienes permiso explícito de escanear. El escaneo no autorizado de redes o sistemas puede ser ilegal y puede resultar en consecuencias legales.

El uso de estas herramientas es bajo tu propia responsabilidad. Los autores no se hacen responsables del mal uso de estos scripts.

## 📦 Requisitos

- **Nmap**: El escáner de red debe estar instalado
- **Python 3.x** (para el script Python)
- **Bash** (para el script Shell)
- **Permisos**: Algunos escaneos requieren privilegios de root/sudo

### Instalación de Nmap

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**CentOS/RHEL:**
```bash
sudo yum install nmap
```

**macOS:**
```bash
brew install nmap
```

## 🚀 Uso

Hay dos versiones del script disponibles:

### Script Python (scan_vulnerabilities.py)

#### Uso básico:
```bash
# Escaneo completo
./scan_vulnerabilities.py 192.168.1.1

# Ver ayuda
./scan_vulnerabilities.py --help

# Escaneo específico
./scan_vulnerabilities.py 192.168.1.1 --scan vuln

# Directorio de salida personalizado
./scan_vulnerabilities.py 192.168.1.1 --output mis_resultados
```

#### Opciones disponibles:
- `--scan basic`: Escaneo básico de puertos
- `--scan service`: Detección de versiones de servicios
- `--scan vuln`: Escaneo de vulnerabilidades
- `--scan os`: Detección de sistema operativo
- `--scan aggressive`: Escaneo agresivo completo
- `--scan full`: Suite completa de escaneos (default)
- `--output DIR`: Directorio para guardar resultados

### Script Bash (scan_vulnerabilities.sh)

#### Uso básico:
```bash
# Escaneo completo
./scan_vulnerabilities.sh -t 192.168.1.1

# Ver ayuda
./scan_vulnerabilities.sh --help

# Escaneo específico
./scan_vulnerabilities.sh -t 192.168.1.1 -s vuln

# Directorio de salida personalizado
./scan_vulnerabilities.sh -t 192.168.1.1 -o mis_resultados
```

#### Opciones disponibles:
- `-t, --target TARGET`: IP o dominio del objetivo (requerido)
- `-s, --scan TYPE`: Tipo de escaneo (basic, service, vuln, os, aggressive, quick, full)
- `-o, --output DIR`: Directorio para guardar resultados
- `-h, --help`: Mostrar ayuda

## 📊 Tipos de Escaneo

### 1. Escaneo Básico (basic)
Escanea todos los puertos TCP del objetivo.
```bash
./scan_vulnerabilities.py 192.168.1.1 --scan basic
```

### 2. Escaneo de Servicios (service)
Detecta versiones de servicios y ejecuta scripts por defecto.
```bash
./scan_vulnerabilities.py 192.168.1.1 --scan service
```

### 3. Escaneo de Vulnerabilidades (vuln)
Ejecuta scripts NSE de detección de vulnerabilidades.
```bash
./scan_vulnerabilities.py 192.168.1.1 --scan vuln
```

### 4. Detección de SO (os)
Intenta identificar el sistema operativo del objetivo (requiere sudo).
```bash
./scan_vulnerabilities.py 192.168.1.1 --scan os
```

### 5. Escaneo Agresivo (aggressive)
Combina detección de SO, versiones, scripts y traceroute.
```bash
./scan_vulnerabilities.py 192.168.1.1 --scan aggressive
```

### 6. Escaneo Rápido (quick) - Solo Bash
Escanea solo los puertos más comunes para resultados rápidos.
```bash
./scan_vulnerabilities.sh -t 192.168.1.1 -s quick
```

### 7. Escaneo Completo (full)
Ejecuta una suite completa de escaneos (básico + servicios + vulnerabilidades).
```bash
./scan_vulnerabilities.py 192.168.1.1 --scan full
```

## 📁 Estructura de Salida

Los resultados se guardan por defecto en el directorio `scan_results/` con el siguiente formato:

```
scan_results/
├── basic_scan_20240218_120000.txt
├── service_scan_20240218_120500.txt
├── vuln_scan_20240218_121000.txt
└── os_scan_20240218_121500.txt
```

Cada archivo contiene los resultados detallados del escaneo correspondiente.

## 🔧 Ejemplos de Uso

### Ejemplo 1: Escaneo básico de un servidor web
```bash
./scan_vulnerabilities.py ejemplo.com --scan service
```

### Ejemplo 2: Búsqueda de vulnerabilidades en una IP
```bash
./scan_vulnerabilities.py 192.168.1.100 --scan vuln
```

### Ejemplo 3: Análisis completo con salida personalizada
```bash
./scan_vulnerabilities.py 10.0.0.1 --scan full --output analisis_completo
```

### Ejemplo 4: Escaneo rápido usando Bash
```bash
./scan_vulnerabilities.sh -t scanme.nmap.org -s quick
```

## 🛠️ Características de los Scripts

### Script Python
- ✅ Manejo de errores robusto
- ✅ Timeouts configurables
- ✅ Validación de nmap instalado
- ✅ Creación automática de directorios
- ✅ Timestamps en archivos de salida
- ✅ Advertencias de seguridad
- ✅ Salida formateada y colorida

### Script Bash
- ✅ Interfaz colorida en terminal
- ✅ Opción de escaneo rápido
- ✅ Confirmación antes de escanear
- ✅ Manejo de privilegios sudo
- ✅ Validación de argumentos
- ✅ Mensajes informativos detallados

## 🔐 Mejores Prácticas

1. **Siempre obtén permiso**: Nunca escanees redes o sistemas sin autorización explícita.

2. **Escaneos graduales**: Comienza con escaneos menos invasivos (basic) antes de ejecutar escaneos agresivos.

3. **Horarios apropiados**: Ejecuta escaneos completos durante ventanas de mantenimiento para minimizar el impacto.

4. **Revisa los resultados**: Analiza cuidadosamente los reportes generados para identificar problemas de seguridad.

5. **Mantén logs**: Conserva los archivos de salida para comparaciones futuras y auditorías.

6. **Actualiza regularmente**: Mantén nmap actualizado para tener las últimas definiciones de vulnerabilidades.

## 📚 Recursos Adicionales

- [Documentación oficial de Nmap](https://nmap.org/book/man.html)
- [Scripts NSE](https://nmap.org/nsedoc/)
- [Guía de Nmap](https://nmap.org/book/toc.html)

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crea un Pull Request

## 📄 Licencia

Este proyecto es de código abierto y está disponible bajo una licencia permisiva. Úsalo responsablemente.

## ⚠️ Descargo de Responsabilidad

Estos scripts son herramientas educativas y de auditoría de seguridad. Los usuarios son completamente responsables de cualquier uso que hagan de estas herramientas. El autor no se hace responsable de ningún daño o consecuencia legal derivada del uso indebido de estos scripts.

## 👤 Autor

Desarrollado para ayudar en tareas legítimas de auditoría y seguridad de redes.