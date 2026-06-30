#!/usr/bin/env python3
import re
import json
import os
from datetime import datetime
from collections import Counter

def analizar_ssh():
    # Rutas relativas obligatorias según la estructura del examen
    ruta_log = "lab1/auth.log" if os.path.exists("lab1/auth.log") else "auth.log"
    ruta_salida = "lab1/reporte_ssh.json" if os.path.exists("lab1") else "reporte_ssh.json"

    if not os.path.exists(ruta_log):
        print(f"[-] Error: No se encontró el archivo en {ruta_log}")
        return

    # Regex para extraer la IP de intentos fallidos
    patron_ssh = re.compile(r'Failed password .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    intentos_fallidos = []

    with open(ruta_log, 'r', errors='ignore') as f:
        for linea in f:
            match = patron_ssh.search(linea)
            if match:
                intentos_fallidos.append(match.group(1))

    total_fallidos = len(intentos_fallidos)
    conteo_ips = Counter(intentos_fallidos)
    
    # Ranking ordenado Top 10
    top_10 = conteo_ips.most_common(10)
    print("\n=== RANKING TOP 10 IPS - INTENTOS FALLIDOS SSH ===")
    for puesto, (ip, intentos) in enumerate(top_10, 1):
        print(f"{puesto}. IP: {ip} - Intentos: {intentos}")

    print("\n=== ALERTAS EN CONSOLA ===")
    ips_sospechosas_lista = []
    for ip, intentos in conteo_ips.items():
        alerta_activa = intentos > 50
        if alerta_activa:
            # Mensaje exacto exigido por la guía de evaluación
            print(f"[ALERTA] IP: {ip} — {intentos} intentos fallidos — Posible ataque de fuerza bruta")
        
        ips_sospechosas_lista.append({
            "ip": ip,
            "intentos": intentos,
            "alerta": alerta_activa
        })

    # Estructura del formato JSON solicitada
    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total_fallidos,
        "ips_sospechosas": ips_sospechosas_lista
    }

    with open(ruta_salida, 'w', encoding='utf-8') as jf:
        json.dump(reporte, jf, indent=4, ensure_ascii=False)
    print(f"\n[+] Archivo exportado exitosamente en: {ruta_salida}")

if __name__ == "__main__":
    analizar_ssh()
