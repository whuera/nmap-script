#!/bin/bash
#
# Script para detectar vulnerabilidades y puertos abiertos
# Utiliza nmap para realizar diferentes tipos de escaneos
#

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
TARGET=""
OUTPUT_DIR="scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Función para mostrar banner
show_banner() {
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}    ESCÁNER DE VULNERABILIDADES Y PUERTOS - NMAP${NC}"
    echo -e "${BLUE}============================================================${NC}"
}

# Función para verificar si nmap está instalado
check_nmap() {
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}[!] Error: nmap no está instalado${NC}"
        echo -e "${YELLOW}[*] Instala nmap con: sudo apt-get install nmap${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] nmap encontrado: $(nmap --version | head -1)${NC}"
}

# Función para crear directorio de salida
create_output_dir() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        echo -e "${GREEN}[+] Directorio creado: $OUTPUT_DIR${NC}"
    fi
}

# Función para escaneo básico de puertos
basic_port_scan() {
    echo -e "\n${BLUE}[*] Iniciando escaneo básico de puertos...${NC}"
    local output_file="$OUTPUT_DIR/basic_scan_${TIMESTAMP}.txt"
    
    nmap -p- -T4 -oN "$output_file" "$TARGET"
    
    echo -e "${GREEN}[+] Escaneo básico completado${NC}"
    echo -e "${GREEN}[+] Resultados guardados en: $output_file${NC}"
}

# Función para escaneo de versiones de servicios
service_version_scan() {
    echo -e "\n${BLUE}[*] Iniciando detección de versiones de servicios...${NC}"
    local output_file="$OUTPUT_DIR/service_scan_${TIMESTAMP}.txt"
    
    nmap -sV -sC -T4 -oN "$output_file" "$TARGET"
    
    echo -e "${GREEN}[+] Detección de servicios completada${NC}"
    echo -e "${GREEN}[+] Resultados guardados en: $output_file${NC}"
}

# Función para escaneo de vulnerabilidades
vulnerability_scan() {
    echo -e "\n${BLUE}[*] Iniciando escaneo de vulnerabilidades...${NC}"
    local output_file="$OUTPUT_DIR/vuln_scan_${TIMESTAMP}.txt"
    
    nmap -sV --script vuln -T4 -oN "$output_file" "$TARGET"
    
    echo -e "${GREEN}[+] Escaneo de vulnerabilidades completado${NC}"
    echo -e "${GREEN}[+] Resultados guardados en: $output_file${NC}"
}

# Función para detección de sistema operativo
os_detection_scan() {
    echo -e "\n${BLUE}[*] Iniciando detección de sistema operativo...${NC}"
    local output_file="$OUTPUT_DIR/os_scan_${TIMESTAMP}.txt"
    
    echo -e "${YELLOW}[*] Nota: La detección de SO puede requerir privilegios root${NC}"
    sudo nmap -O -sV -T4 -oN "$output_file" "$TARGET"
    
    echo -e "${GREEN}[+] Detección de SO completada${NC}"
    echo -e "${GREEN}[+] Resultados guardados en: $output_file${NC}"
}

# Función para escaneo agresivo
aggressive_scan() {
    echo -e "\n${BLUE}[*] Iniciando escaneo agresivo completo...${NC}"
    local output_file="$OUTPUT_DIR/aggressive_scan_${TIMESTAMP}.txt"
    
    nmap -A -T4 -oN "$output_file" "$TARGET"
    
    echo -e "${GREEN}[+] Escaneo agresivo completado${NC}"
    echo -e "${GREEN}[+] Resultados guardados en: $output_file${NC}"
}

# Función para escaneo rápido de puertos comunes
quick_scan() {
    echo -e "\n${BLUE}[*] Iniciando escaneo rápido de puertos comunes...${NC}"
    local output_file="$OUTPUT_DIR/quick_scan_${TIMESTAMP}.txt"
    
    nmap -F -T4 -oN "$output_file" "$TARGET"
    
    echo -e "${GREEN}[+] Escaneo rápido completado${NC}"
    echo -e "${GREEN}[+] Resultados guardados en: $output_file${NC}"
}

# Función para escaneo completo
full_scan() {
    echo -e "\n${BLUE}[*] Ejecutando suite completa de escaneos...${NC}"
    
    basic_port_scan
    service_version_scan
    vulnerability_scan
    
    echo -e "\n${GREEN}============================================================${NC}"
    echo -e "${GREEN}[+] ESCANEO COMPLETO FINALIZADO${NC}"
    echo -e "${GREEN}[+] Todos los resultados guardados en: $OUTPUT_DIR/${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

# Función para mostrar ayuda
show_help() {
    echo "Uso: $0 [OPCIONES] <TARGET>"
    echo ""
    echo "Script para detectar vulnerabilidades y puertos abiertos usando nmap"
    echo ""
    echo "Opciones:"
    echo "  -t, --target TARGET      IP o dominio del objetivo (requerido)"
    echo "  -s, --scan TYPE          Tipo de escaneo: basic, service, vuln, os, aggressive, quick, full"
    echo "  -o, --output DIR         Directorio para guardar resultados (default: scan_results)"
    echo "  -h, --help               Mostrar esta ayuda"
    echo ""
    echo "Ejemplos:"
    echo "  $0 -t 192.168.1.1                    # Escaneo completo"
    echo "  $0 -t 192.168.1.1 -s basic           # Solo escaneo de puertos"
    echo "  $0 -t scanme.nmap.org -s vuln        # Solo vulnerabilidades"
    echo "  $0 -t 192.168.1.1 -o mis_resultados  # Directorio personalizado"
    echo ""
}

# Función para mostrar advertencia legal
show_warning() {
    echo -e "\n${RED}============================================================${NC}"
    echo -e "${RED}                    ADVERTENCIA LEGAL${NC}"
    echo -e "${RED}============================================================${NC}"
    echo -e "${YELLOW}Este script debe usarse solo en sistemas para los cuales${NC}"
    echo -e "${YELLOW}tienes permiso explícito de escanear.${NC}"
    echo -e "${YELLOW}El escaneo no autorizado puede ser ILEGAL.${NC}"
    echo -e "${RED}============================================================${NC}\n"
}

# Procesar argumentos
SCAN_TYPE="full"

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -s|--scan)
            SCAN_TYPE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# Validar argumentos
if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Error: Debes especificar un objetivo${NC}\n"
    show_help
    exit 1
fi

# Mostrar banner y advertencia
show_banner
show_warning

# Pedir confirmación
read -p "¿Deseas continuar con el escaneo de $TARGET? (s/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[SsYy]$ ]]; then
    echo -e "${YELLOW}[*] Escaneo cancelado${NC}"
    exit 0
fi

# Verificar nmap
check_nmap

# Crear directorio de salida
create_output_dir

echo -e "\n${BLUE}Target: $TARGET${NC}"
echo -e "${BLUE}Tipo de escaneo: $SCAN_TYPE${NC}"
echo -e "${BLUE}Directorio de salida: $OUTPUT_DIR${NC}"
echo -e "${BLUE}Timestamp: $TIMESTAMP${NC}\n"

# Ejecutar el tipo de escaneo seleccionado
case $SCAN_TYPE in
    basic)
        basic_port_scan
        ;;
    service)
        service_version_scan
        ;;
    vuln)
        vulnerability_scan
        ;;
    os)
        os_detection_scan
        ;;
    aggressive)
        aggressive_scan
        ;;
    quick)
        quick_scan
        ;;
    full)
        full_scan
        ;;
    *)
        echo -e "${RED}[!] Error: Tipo de escaneo no válido: $SCAN_TYPE${NC}"
        show_help
        exit 1
        ;;
esac

echo -e "\n${GREEN}[+] Proceso completado${NC}"
