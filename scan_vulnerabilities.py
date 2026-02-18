#!/usr/bin/env python3
"""
Nmap Vulnerability Scanner
Script para detectar vulnerabilidades y puertos abiertos

Este script utiliza nmap para:
- Escanear puertos abiertos
- Detectar versiones de servicios
- Identificar vulnerabilidades conocidas
- Realizar detección de sistema operativo
"""

import subprocess
import argparse
import json
import sys
import os
from datetime import datetime

class NmapScanner:
    def __init__(self, target, output_dir="scan_results"):
        self.target = target
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Crear directorio de salida si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def check_nmap_installed(self):
        """Verificar si nmap está instalado"""
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def basic_port_scan(self):
        """Escaneo básico de puertos"""
        print(f"\n[*] Iniciando escaneo básico de puertos en {self.target}...")
        output_file = os.path.join(self.output_dir, f"basic_scan_{self.timestamp}.txt")
        
        cmd = [
            "nmap",
            "-p-",  # Todos los puertos
            "-T4",  # Velocidad agresiva
            "-oN", output_file,  # Salida normal
            self.target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            print(result.stdout)
            print(f"[+] Resultados guardados en: {output_file}")
            return result.stdout
        except subprocess.TimeoutExpired:
            print("[!] Timeout en escaneo básico")
            return None
        except Exception as e:
            print(f"[!] Error en escaneo básico: {e}")
            return None
    
    def service_version_scan(self):
        """Escaneo de versiones de servicios"""
        print(f"\n[*] Iniciando detección de versiones de servicios en {self.target}...")
        output_file = os.path.join(self.output_dir, f"service_scan_{self.timestamp}.txt")
        
        cmd = [
            "nmap",
            "-sV",  # Detección de versiones
            "-sC",  # Scripts por defecto
            "-T4",
            "-oN", output_file,
            self.target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            print(result.stdout)
            print(f"[+] Resultados guardados en: {output_file}")
            return result.stdout
        except subprocess.TimeoutExpired:
            print("[!] Timeout en escaneo de servicios")
            return None
        except Exception as e:
            print(f"[!] Error en escaneo de servicios: {e}")
            return None
    
    def vulnerability_scan(self):
        """Escaneo de vulnerabilidades usando scripts NSE"""
        print(f"\n[*] Iniciando escaneo de vulnerabilidades en {self.target}...")
        output_file = os.path.join(self.output_dir, f"vuln_scan_{self.timestamp}.txt")
        
        cmd = [
            "nmap",
            "-sV",
            "--script", "vuln",  # Scripts de vulnerabilidades
            "-T4",
            "-oN", output_file,
            self.target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            print(result.stdout)
            print(f"[+] Resultados guardados en: {output_file}")
            return result.stdout
        except subprocess.TimeoutExpired:
            print("[!] Timeout en escaneo de vulnerabilidades")
            return None
        except Exception as e:
            print(f"[!] Error en escaneo de vulnerabilidades: {e}")
            return None
    
    def os_detection_scan(self):
        """Detección de sistema operativo"""
        print(f"\n[*] Iniciando detección de sistema operativo en {self.target}...")
        output_file = os.path.join(self.output_dir, f"os_scan_{self.timestamp}.txt")
        
        cmd = [
            "nmap",
            "-O",  # Detección de SO
            "-sV",
            "-T4",
            "-oN", output_file,
            self.target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            print(result.stdout)
            print(f"[+] Resultados guardados en: {output_file}")
            return result.stdout
        except subprocess.TimeoutExpired:
            print("[!] Timeout en detección de SO")
            return None
        except Exception as e:
            print(f"[!] Error en detección de SO: {e}")
            return None
    
    def aggressive_scan(self):
        """Escaneo agresivo completo"""
        print(f"\n[*] Iniciando escaneo agresivo en {self.target}...")
        output_file = os.path.join(self.output_dir, f"aggressive_scan_{self.timestamp}.txt")
        
        cmd = [
            "nmap",
            "-A",  # Escaneo agresivo (OS, versiones, scripts, traceroute)
            "-T4",
            "-oN", output_file,
            self.target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            print(result.stdout)
            print(f"[+] Resultados guardados en: {output_file}")
            return result.stdout
        except subprocess.TimeoutExpired:
            print("[!] Timeout en escaneo agresivo")
            return None
        except Exception as e:
            print(f"[!] Error en escaneo agresivo: {e}")
            return None
    
    def run_full_scan(self):
        """Ejecutar escaneo completo"""
        print("="*60)
        print(f"ESCANEO DE VULNERABILIDADES Y PUERTOS")
        print(f"Target: {self.target}")
        print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        if not self.check_nmap_installed():
            print("[!] Error: nmap no está instalado")
            print("[!] Instala nmap con: sudo apt-get install nmap")
            return False
        
        # Ejecutar diferentes tipos de escaneo
        self.basic_port_scan()
        self.service_version_scan()
        self.vulnerability_scan()
        
        print("\n" + "="*60)
        print("[+] Escaneo completo finalizado")
        print(f"[+] Resultados guardados en: {self.output_dir}/")
        print("="*60)
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description='Script para detectar vulnerabilidades y puertos abiertos usando nmap',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:
  %(prog)s 192.168.1.1                    # Escaneo completo
  %(prog)s 192.168.1.1 --scan basic       # Solo escaneo de puertos
  %(prog)s 192.168.1.1 --scan vuln        # Solo vulnerabilidades
  %(prog)s scanme.nmap.org --output mis_resultados  # Directorio personalizado
        '''
    )
    
    parser.add_argument('target', help='IP o dominio del objetivo a escanear')
    parser.add_argument('--scan', choices=['basic', 'service', 'vuln', 'os', 'aggressive', 'full'],
                       default='full', help='Tipo de escaneo a realizar (default: full)')
    parser.add_argument('--output', default='scan_results',
                       help='Directorio para guardar resultados (default: scan_results)')
    
    args = parser.parse_args()
    
    # Validación básica del objetivo
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Advertencia de uso legal
    print("\n" + "!"*60)
    print("ADVERTENCIA: Este script debe usarse solo en sistemas")
    print("para los cuales tienes permiso explícito de escanear.")
    print("El escaneo no autorizado puede ser ilegal.")
    print("!"*60 + "\n")
    
    response = input("¿Deseas continuar? (s/n): ")
    if response.lower() not in ['s', 'si', 'y', 'yes']:
        print("Escaneo cancelado.")
        sys.exit(0)
    
    # Crear scanner y ejecutar
    scanner = NmapScanner(args.target, args.output)
    
    # Ejecutar el tipo de escaneo seleccionado
    if args.scan == 'basic':
        scanner.basic_port_scan()
    elif args.scan == 'service':
        scanner.service_version_scan()
    elif args.scan == 'vuln':
        scanner.vulnerability_scan()
    elif args.scan == 'os':
        scanner.os_detection_scan()
    elif args.scan == 'aggressive':
        scanner.aggressive_scan()
    else:  # full
        scanner.run_full_scan()

if __name__ == "__main__":
    main()
