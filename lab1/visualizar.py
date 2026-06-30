#!/usr/bin/env python3
import json
import os
import re
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime

# Asegurar las rutas correctas para almacenar las imágenes
os.makedirs("lab1/graficas", exist_ok=True)
ruta_graficas = "lab1/graficas/"

# --- 1. Gráfico de barras: Top 10 IPs SSH ---
ruta_ssh = "lab1/reporte_ssh.json"
if os.path.exists(ruta_ssh):
    with open(ruta_ssh, 'r') as f:
        data = json.load(f)
    ips = [x['ip'] for x in data['ips_sospechosas']][:10]
    intentos = [x['intentos'] for x in data['ips_sospechosas']][:10]
    
    if ips:
        plt.figure(figsize=(10, 5))
        sns.barplot(x=intentos, y=ips, palette="flare_r")
        plt.title("Top 10 IPs con más intentos fallidos SSH")
        plt.xlabel("Número de Intentos")
        plt.ylabel("Direcciones IP")
        plt.tight_layout()
        plt.savefig(f"{ruta_graficas}top10_ssh.png")
        plt.close()
        print("[+] Gráfica generada: top10_ssh.png")

# --- Parseo cronológico de access.log para líneas temporales y mapas de calor ---
ruta_web_log = "lab1/access.log"
datos_tiempo = []

if os.path.exists(ruta_web_log):
    patron_apache = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d{3})')
    with open(ruta_web_log, 'r', errors='ignore') as f:
        for linea in f:
            match = patron_apache.match(linea)
            if match:
                _, fecha_str, _, _, codigo = match.groups()
                try:
                    fecha_obj = datetime.strptime(fecha_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                    datos_tiempo.append({"Hora": fecha_obj.hour, "Codigo": codigo})
                except:
                    continue

if datos_tiempo:
    df = pd.DataFrame(datos_tiempo)
    
    # --- 2. Línea de tiempo: Peticiones HTTP por hora ---
    peticiones_por_hora = df.groupby('Hora').size().reindex(range(0, 24), fill_value=0)
    plt.figure(figsize=(10, 4))
    plt.plot(peticiones_por_hora.index, peticiones_por_hora.values, marker='o', color='crimson', linestyle='-')
    plt.title("Línea de tiempo - Número de peticiones HTTP por hora")
    plt.xlabel("Hora del Día")
    plt.ylabel("Total de Peticiones")
    plt.grid(True, linestyle='--')
    plt.xticks(range(0, 24))
    plt.tight_layout()
    plt.savefig(f"{ruta_graficas}timeline_http.png")
    plt.close()
    print("[+] Gráfica generada: timeline_http.png")

    # --- 3. Mapa de calor (Heatmap): Hora vs Código de respuesta ---
    df_filtrado = df[df['Codigo'].isin(['200', '301', '404', '500'])]
    pivot_table = pd.crosstab(df_filtrado['Codigo'], df_filtrado['Hora']).reindex(columns=range(0, 24), fill_value=0)
    
    plt.figure(figsize=(12, 5))
    sns.heatmap(pivot_table, annot=True, fmt="d", cmap="YlOrRd", cbar=True)
    plt.title("Mapa de Calor - Peticiones HTTP por hora y código de respuesta")
    plt.xlabel("Hora del Día")
    plt.ylabel("Código de Respuesta (HTTP Status)")
    plt.tight_layout()
    plt.savefig(f"{ruta_graficas}heatmap_http.png")
    plt.close()
    print("[+] Gráfica generada: heatmap_http.png")
