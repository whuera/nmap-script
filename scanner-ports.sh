#!/bin/bash

echo "============================================"
echo " Creado por William Huera"
echo "============================================"
echo ""

# Validar que nmap esté instalado
if ! command -v nmap &> /dev/null; then
    echo "[-] Error: nmap no está instalado"
    exit 1
fi

read -p "Introduce la IP o dominio a escanear: " TARGET

# Validar que se ingresó un objetivo
if [ -z "$TARGET" ]; then
    echo "[-] Error: Debes ingresar una IP o dominio"
    exit 1
fi

# Sanitizar el nombre para usarlo en archivos
SANITIZED=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9.-]/_/g')

echo ""
echo "[+] Iniciando escaneo rápido de puertos..."
nmap -F "$TARGET" -oN "rapido_${SANITIZED}.txt" && echo "[✓] Escaneo rápido completado"

echo ""
echo "[+] Escaneo completo de puertos..."
nmap -p- "$TARGET" -oN "completo_${SANITIZED}.txt" && echo "[✓] Escaneo completo completado"

echo ""
echo "[+] Detección de servicios y versiones..."
nmap -sV -sC "$TARGET" -oN "servicios_${SANITIZED}.txt" && echo "[✓] Detección completada"

echo ""
echo "[+] Buscando vulnerabilidades (scripts NSE vuln)..."
nmap --script vuln "$TARGET" -oN "vulnerabilidades_${SANITIZED}.txt" && echo "[✓] Búsqueda de vulnerabilidades completada"

echo ""
echo "[+] ¡Escaneo finalizado! Revisa los archivos generados."