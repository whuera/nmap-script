# Quick Start Guide

## Instalación Rápida

1. **Instalar Nmap**:
```bash
sudo apt-get update
sudo apt-get install nmap
```

2. **Clonar el repositorio**:
```bash
git clone https://github.com/whuera/nmap-script.git
cd nmap-script
```

3. **Dar permisos de ejecución**:
```bash
chmod +x scan_vulnerabilities.py
chmod +x scan_vulnerabilities.sh
```

## Uso Básico

### Opción 1: Script Python
```bash
./scan_vulnerabilities.py <IP_o_dominio> [--scan TIPO] [--output DIRECTORIO]
```

### Opción 2: Script Bash
```bash
./scan_vulnerabilities.sh -t <IP_o_dominio> [-s TIPO] [-o DIRECTORIO]
```

## Ejemplos Rápidos

**Escaneo rápido de puertos comunes:**
```bash
./scan_vulnerabilities.sh -t 192.168.1.1 -s quick
```

**Buscar vulnerabilidades:**
```bash
./scan_vulnerabilities.py 192.168.1.1 --scan vuln
```

**Escaneo completo:**
```bash
./scan_vulnerabilities.py 192.168.1.1
```

## Tipos de Escaneo

| Tipo | Descripción | Tiempo Estimado |
|------|-------------|-----------------|
| `quick` | Puertos comunes | < 1 min |
| `basic` | Todos los puertos | 2-5 min |
| `service` | Detección de servicios | 1-3 min |
| `vuln` | Búsqueda de vulnerabilidades | 5-15 min |
| `os` | Detección de SO | 2-5 min |
| `aggressive` | Escaneo agresivo completo | 5-10 min |
| `full` | Suite completa | 10-30 min |

## ⚠️ Importante

- Solo escanea sistemas para los cuales tienes permiso
- El escaneo no autorizado puede ser ilegal
- Usa `scanme.nmap.org` para practicar

## Ver Resultados

Los resultados se guardan automáticamente en el directorio `scan_results/`:
```bash
ls -lh scan_results/
cat scan_results/vuln_scan_*.txt
```

## Ayuda

Para ver todas las opciones disponibles:
```bash
./scan_vulnerabilities.py --help
./scan_vulnerabilities.sh --help
```

## Solución de Problemas

**Error: nmap no está instalado**
```bash
sudo apt-get install nmap
```

**Error: Permission denied**
```bash
chmod +x scan_vulnerabilities.py scan_vulnerabilities.sh
```

**Necesitas permisos root para detección de SO**
```bash
sudo ./scan_vulnerabilities.py target --scan os
```
