import sys
import pandas as pd
import joblib

if len(sys.argv) < 2:
    print("Uso correcto: python lab3/predecir.py nuevo_trafico.csv")
    sys.exit(1)

archivo_nuevo = sys.argv[1]

try:
    # Cargar modelo y escalador
    clf = joblib.load('lab3/modelo_anomalias.pkl')
    scaler = joblib.load('lab3/scaler.pkl')
    
    # Leer datos nuevos
    df_new = pd.read_csv(archivo_nuevo)
    
    # Preprocesamiento rápido e idéntico
    df_new['ratio_bytes'] = df_new['bytes_sent'] / (df_new['bytes_recv'] + 1)
    df_new['bytes_por_segundo'] = df_new['bytes_sent'] / (df_new['duration_sec'] + 1)
    
    features_num = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets', 'ratio_bytes', 'bytes_por_segundo']
    X_scaled = scaler.transform(df_new[features_num])
    
    # Predicción y score
    df_new['pred'] = clf.predict(X_scaled)
    df_new['score'] = clf.decision_function(X_scaled)
    
    # Filtrar solo anomalías (-1)
    anomalas = df_new[df_new['pred'] == -1]
    
    print(f"\n--- REGISTROS CLASIFICADOS COMO ANOMALÍA ({len(anomalas)}) ---")
    if not anomalas.empty:
        print(anomalas[['src_ip', 'dst_ip', 'dst_port', 'bytes_sent', 'score']].to_string())
    else:
        print("No se encontraron anomalías en el archivo provisto.")

except Exception as e:
    print(f"Error al procesar el archivo: {e}")
