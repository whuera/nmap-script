# Ejemplos de Uso - Nmap Vulnerability Scanner

Este documento proporciona ejemplos prácticos de cómo usar los scripts de escaneo.

## Ejemplos Básicos

### 1. Escaneo de Puertos Comunes (Rápido)
```bash
# Usando script Bash
./scan_vulnerabilities.sh -t scanme.nmap.org -s quick

# Este escaneo toma menos de 1 minuto y verifica los puertos más comunes
```

### 2. Escaneo de Todos los Puertos
```bash
# Usando script Python
./scan_vulnerabilities.py scanme.nmap.org --scan basic

# Usando script Bash
./scan_vulnerabilities.sh -t scanme.nmap.org -s basic
```

### 3. Detección de Servicios y Versiones
```bash
# Python
./scan_vulnerabilities.py 192.168.1.1 --scan service

# Bash
./scan_vulnerabilities.sh -t 192.168.1.1 -s service
```

## Ejemplos Avanzados

### 4. Búsqueda de Vulnerabilidades Específicas
```bash
# Escaneo de vulnerabilidades conocidas
./scan_vulnerabilities.py target.example.com --scan vuln

# Guarda resultados con vulnerabilidades detectadas en formato detallado
```

### 5. Análisis Completo de Seguridad
```bash
# Ejecuta todos los tipos de escaneo
./scan_vulnerabilities.py 10.0.0.100 --scan full --output analisis_20240218

# Esto ejecutará:
# - Escaneo de puertos
# - Detección de servicios
# - Búsqueda de vulnerabilidades
```

### 6. Escaneo de Múltiples Objetivos
```bash
# Crear un script simple para múltiples objetivos
for ip in 192.168.1.{1..10}; do
    ./scan_vulnerabilities.py $ip --scan service --output scan_subnet
    sleep 5  # Pausa entre escaneos
done
```

## Ejemplos por Caso de Uso

### Auditoría de Servidor Web

```bash
# 1. Primero, escaneo rápido para identificar puertos
./scan_vulnerabilities.sh -t webserver.example.com -s quick

# 2. Luego, análisis detallado de servicios
./scan_vulnerabilities.py webserver.example.com --scan service

# 3. Finalmente, búsqueda de vulnerabilidades
./scan_vulnerabilities.py webserver.example.com --scan vuln
```

### Análisis de Seguridad de Red Local

```bash
# Escaneo completo de la red local (requiere permisos)
./scan_vulnerabilities.py 192.168.1.0/24 --scan aggressive --output red_local

# Nota: Este puede tomar mucho tiempo
```

### Verificación de Servidor de Base de Datos

```bash
# Escanear puertos de bases de datos comunes
./scan_vulnerabilities.py db.example.com --scan service

# Revisar específicamente puertos: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB)
```

## Interpretación de Resultados

### Puertos Abiertos
Los archivos de salida mostrarán algo como:
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
```

### Vulnerabilidades Detectadas
```
| vulners:
|   CVE-2021-XXXXX
|     CVSS: 7.5
|     https://vulners.com/cve/CVE-2021-XXXXX
```

### Versiones de Servicios
```
80/tcp   open  http     Apache httpd 2.4.41
443/tcp  open  ssl/http Apache httpd 2.4.41
```

## Comandos Útiles de Nmap (Manual)

### Escaneo Sigiloso
```bash
# SYN scan (requiere root)
sudo nmap -sS target.com
```

### Escaneo de Puertos Específicos
```bash
# Escanear solo puertos web
nmap -p 80,443,8080,8443 target.com
```

### Guardar en Múltiples Formatos
```bash
# Salida en XML y texto
nmap -oX scan.xml -oN scan.txt target.com
```

## Tips y Trucos

1. **Usa scanme.nmap.org para pruebas**: Es un servidor proporcionado por nmap.org específicamente para practicar.

2. **Empieza con escaneos menos invasivos**: Usa `-s quick` o `-s basic` antes de ejecutar escaneos completos.

3. **Revisa los logs regularmente**: Los archivos en `scan_results/` contienen información detallada.

4. **Combina con otras herramientas**: Usa los resultados de nmap como input para otras herramientas de seguridad.

5. **Mantén un histórico**: Compara escaneos a lo largo del tiempo para detectar cambios.

## Solución de Problemas

### Error: "nmap no está instalado"
```bash
sudo apt-get update
sudo apt-get install nmap
```

### Error: "Permission denied"
```bash
# Dar permisos de ejecución
chmod +x scan_vulnerabilities.py
chmod +x scan_vulnerabilities.sh
```

### Timeout en escaneos
```bash
# Usa un escaneo más rápido o específico
./scan_vulnerabilities.py target.com --scan quick
```

### Requiere sudo para detección de OS
```bash
# Algunos comandos requieren privilegios
sudo ./scan_vulnerabilities.py target.com --scan os
```

## Recursos Adicionales

- Documentación de Nmap: https://nmap.org/docs.html
- NSE Scripts: https://nmap.org/nsedoc/
- Nmap Cheat Sheet: https://www.stationx.net/nmap-cheat-sheet/
