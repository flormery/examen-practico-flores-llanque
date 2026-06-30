#!/usr/bin/env python3
import re
import json
import os
from datetime import datetime

def analizar_web():
    # Rutas relativas obligatorias requeridas por el examen
    ruta_log = "lab1/access.log" if os.path.exists("lab1/access.log") else "access.log"
    ruta_salida = "lab1/reporte_web.json" if os.path.exists("lab1") else "reporte_web.json"

    if not os.path.exists(ruta_log):
        print(f"[-] Error: No se encontró el archivo en {ruta_log}")
        return

    # Regex para Combined Log Format de Apache
    # Captura: IP, timestamp, Método, Ruta, Código de Estado
    patron_apache = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d{3})')
    
    # Patrones SQL Injection requeridos por la guía
    patrones_sqli = [r"UNION", r"SELECT", r"--", r"OR\s+\d+=\d+", r"'"]
    
    ips_errores = {}            # Agrupación 4xx y 5xx
    historial_peticiones = {}   # IP: [(timestamp_objeto, ruta), ...]
    detecciones_sqli = []
    escaneos_directorios = {}

    with open(ruta_log, 'r', errors='ignore') as f:
        for linea in f:
            match = patron_apache.match(linea)
            if match:
                ip, fecha_str, metodo, ruta, codigo = match.groups()
                
                # Convertir tiempo de Apache a objeto datetime para la ventana temporal
                try:
                    fecha_obj = datetime.strptime(fecha_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                except:
                    continue

                # 1. Identificar peticiones con códigos de respuesta 4xx y 5xx agrupadas por IP
                if codigo.startswith(('4', '5')):
                    if ip not in ips_errores:
                        ips_errores[ip] = {}
                    ips_errores[ip][codigo] = ips_errores[ip].get(codigo, 0) + 1

                # 2. Detectar posibles intentos de SQL Injection
                for patron in patrones_sqli:
                    if re.search(patron, ruta, re.IGNORECASE):
                        detecciones_sqli.append({
                            "ip": ip,
                            "ruta_atacada": ruta,
                            "patron_detectado": patron
                        })
                        break

                # 3. Guardar marcas de tiempo para escaneo de directorios
                if ip not in historial_peticiones:
                    historial_peticiones[ip] = []
                historial_peticiones[ip].append((fecha_obj, ruta))

    # 4. Algoritmo para escaneo de directorios (>20 rutas distintas en menos de 60s)
    for ip, peticiones in historial_peticiones.items():
        peticiones.sort(key=lambda x: x[0])  # Ordenar cronológicamente
        rutas_distintas_totales = set()
        
        for i in range(len(peticiones)):
            tiempo_inicio = peticiones[i][0]
            rutas_en_ventana = {peticiones[i][1]}
            
            for j in range(i + 1, len(peticiones)):
                delta = (peticiones[j][0] - tiempo_inicio).total_seconds()
                if delta <= 60:
                    rutas_en_ventana.add(peticiones[j][1])
                else:
                    break
            
            if len(rutas_en_ventana) > 20:
                rutas_distintas_totales.update(rutas_en_ventana)
        
        if len(rutas_distintas_totales) > 20:
            escaneos_directorios[ip] = len(rutas_distintas_totales)

    # Impresión de hallazgos en consola
    print("\n=== DETECCIONES DE ESCANEO WEB ===")
    for ip, cant in escaneos_directorios.items():
        print(f"[ALERTA WEB] IP: {ip} realizó escaneo con {cant} rutas distintas.")

    print(f"\n=== DETECCIONES SQLi ===\nTotal intentos detectados: {len(detecciones_sqli)}")

    # Estructura del archivo reporte_web.json con los hallazgos
    reporte_web = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "escaneo_directorios": [{"ip": k, "rutas_distintas": v} for k, v in escaneos_directorios.items()],
        "errores_4xx_5xx_por_ip": ips_errores,
        "posibles_intentos_sqli": detecciones_sqli
    }

    with open(ruta_salida, 'w', encoding='utf-8') as jf:
        json.dump(reporte_web, jf, indent=4, ensure_ascii=False)
    print(f"\n[+] Archivo exportado exitosamente en: {ruta_salida}")

if __name__ == "__main__":
    analizar_web()
