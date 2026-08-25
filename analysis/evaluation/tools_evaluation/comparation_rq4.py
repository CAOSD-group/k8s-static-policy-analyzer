import pandas as pd
from pathlib import Path

# --- 1. CONFIGURACIÓN DE RUTAS ---
CSV_TRIVY = Path("../../../evaluation/validation_results_trivy_final.csv")
CSV_POLARIS = Path("../../../evaluation/validation_results_polaris-cli_final.csv")
CSV_KYVERNO = Path("../../../evaluation/validation_results_kyverno_final_02.csv")
# Asegúrate de poner el nombre correcto de tu CSV del Dual-Oracle
CSV_KUBESEC = Path("../remediation_benchmark_results01_AST_Complete_V2.csv") # remediation_benchmark_results01_AST_Complete_V2
OUTPUT_CSV = Path("../../../evaluation/rq4_divergence_and_latency.csv")

def run_rq4_analysis():
    print("[INFO] Cargando datasets con tolerancia a errores de formato...")
    
    # Usamos on_bad_lines='skip' para evitar el ParserError si hay filas corruptas
    df_trivy = pd.read_csv(CSV_TRIVY, on_bad_lines='skip', low_memory=False)[['file', 'valid', 'avg_validation_time_ms']]
    df_trivy.rename(columns={'valid': 'Trivy_Valid', 'avg_validation_time_ms': 'Trivy_Time'}, inplace=True)
    
    df_polaris = pd.read_csv(CSV_POLARIS, on_bad_lines='skip', low_memory=False)[['file', 'valid', 'avg_validation_time_ms']]
    df_polaris.rename(columns={'valid': 'Polaris_Valid', 'avg_validation_time_ms': 'Polaris_Time'}, inplace=True)
    
    df_kyverno = pd.read_csv(CSV_KYVERNO, on_bad_lines='skip', low_memory=False)[['file', 'valid', 'avg_validation_time_ms']]
    df_kyverno.rename(columns={'valid': 'Kyverno_Valid', 'avg_validation_time_ms': 'Kyverno_Time'}, inplace=True)
    
    df_kubesec = pd.read_csv(CSV_KUBESEC, on_bad_lines='skip', low_memory=False)[['Filename', 'Total_Initial_Alerts', 'T_Detection_ms']]
    df_kubesec.rename(columns={'Filename': 'file', 'T_Detection_ms': 'KubeSec_Time'}, inplace=True)
    
    # Creamos la columna KubeSec_Valid basada en los errores iniciales
    df_kubesec['KubeSec_Valid'] = df_kubesec['Total_Initial_Alerts'] == 0
    
    
    print("[INFO] Fusionando resultados por archivo...")
    # --- 3. MERGE (Cruce de datos por nombre de archivo) ---
    df = df_kubesec.merge(df_trivy, on='file', how='inner')
    df = df.merge(df_polaris, on='file', how='inner')
    df = df.merge(df_kyverno, on='file', how='inner')
    
    # --- 4. CÁLCULO DE LATENCIA ---
    df['SotP_Total_Time'] = df['Trivy_Time'] + df['Polaris_Time'] + df['Kyverno_Time']
    df['Latency_Saved_ms'] = df['SotP_Total_Time'] - df['KubeSec_Time']
    
    # --- 5. CÁLCULO DE CONSENSO BINARIO Y DIVERGENCIA ---
    # Normalizar valores booleanos solo para la industria (KubeSec_Valid ya es booleano real)
    for col in ['Trivy_Valid', 'Polaris_Valid', 'Kyverno_Valid']:
        df[col] = df[col].astype(str).str.lower() == 'true'

    # Consenso de la industria (las tres herramientas dicen lo mismo)
    df['Industry_Consensus'] = (df['Trivy_Valid'] == df['Polaris_Valid']) & (df['Polaris_Valid'] == df['Kyverno_Valid'])
    
    # ¿Hay divergencia entre la industria?
    df['Has_Divergence'] = ~df['Industry_Consensus']

    # --- NUEVO: COMPARATIVA KUBESEC VS INDUSTRIA ---
    
    # 1. ¿KubeSec coincide cuando la industria tiene un consenso claro?
    # Solo evaluamos donde Industry_Consensus es True. Si coinciden, KubeSec_Valid debe ser igual a Trivy_Valid (que a su vez es igual al resto)
    df['KubeSec_Matches_Consensus'] = df.apply(
        lambda row: (row['KubeSec_Valid'] == row['Trivy_Valid']) if row['Industry_Consensus'] else None,
        axis=1
    )

    # 2. Sensibilidad Global (Security Posture):
    # ¿Considera la industria que hay una vulnerabilidad (al menos una herramienta da False)?
    df['Industry_Detects_Flaw'] = ~(df['Trivy_Valid'] & df['Polaris_Valid'] & df['Kyverno_Valid'])
    
    # ¿Considera KubeSec que hay una vulnerabilidad?
    df['KubeSec_Detects_Flaw'] = ~df['KubeSec_Valid']

    # ¿Detecta KubeSec los fallos de forma unificada igual o mejor que tener las 3 herramientas separadas?
    df['KubeSec_Matches_Industry_Sensitivity'] = df['KubeSec_Detects_Flaw'] == df['Industry_Detects_Flaw']


    # --- 6. EXPORTACIÓN ---
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"[OK] Análisis completado. Resultados guardados en: {OUTPUT_CSV}")
    
    # --- 7. RESUMEN POR CONSOLA ---
    print("\n" + "="*50)
    print(" 📊 RESUMEN PARA LA RQ4 (COSE) ")
    print("="*50)
    
    print("\n--- RENDIMIENTO (LATENCIA) ---")
    print(f"Media de tiempo Industria (SotP): {df['SotP_Total_Time'].mean():.2f} ms")
    print(f"Media de tiempo Kube-Sec (AST):   {df['KubeSec_Time'].mean():.2f} ms")
    speedup = df['SotP_Total_Time'].mean() / df['KubeSec_Time'].mean() if df['KubeSec_Time'].mean() > 0 else 0
    print(f"El Dual-Oracle es aprox. {speedup:.1f}x más rápido.")
    
    print("\n--- DIVERGENCIA BINARIA ---")
    total_files = len(df)
    divergent_files = df['Has_Divergence'].sum()
    divergence_pct = (divergent_files / total_files) * 100
    print(f"Total de manifiestos evaluados: {total_files}")
    print(f"Archivos con divergencia de criterio: {divergent_files} ({divergence_pct:.2f}%)")
    print("="*50 + "\n")

    print(f"KubeSec coincide con el consenso en: {df['KubeSec_Matches_Consensus'].sum()} archivos")
    print(f"KubeSec detecta vulnerabilidades de forma consistente con la industria en: {df['KubeSec_Matches_Industry_Sensitivity'].sum()} archivos")
if __name__ == "__main__":
    run_rq4_analysis()