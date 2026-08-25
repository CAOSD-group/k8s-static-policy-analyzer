import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Configuración de estilo académico para COSE
sns.set_theme(style="whitegrid", context="paper")
plt.rcParams.update({'font.size': 10, 'pdf.fonttype': 42})

CSV_PATH = "z3_vs_ast_comparison_03.csv" # Reemplaza con el nombre real de tu primer CSV

def generate_performance_plots():
    if not os.path.exists(CSV_PATH):
        print(f"Error: No se encuentra {CSV_PATH}")
        return

    # FAIL-FAST FIX: Instruct pandas to gracefully skip rows that violate
    # the 16-column contract (like the 26-column STRUCTURAL_UNSAT artifacts).
    try:
        df = pd.read_csv(
            CSV_PATH,
            on_bad_lines='skip',
            engine='python' # Python engine handles parsing anomalies robustly
        )
    except Exception as e:
        print(f"[CRITICAL] Error initializing data frame: {e}")
        return
    
    # Clean mapping errors
    if 'Error_Mapping' in df.columns:
        df = df[df['Error_Mapping'].isna()]
    
    # Limpieza: descartamos filas con errores de mapeo
    df = df[df['Error_Mapping'].isna()]

    # 1. KPI de Equivalencia Lógica
    total_evals = len(df)
    matches = df['Is_Match'].sum()
    match_percentage = (matches / total_evals) * 100
    print(f"=== EQUIVALENCIA LÓGICA ===")
    print(f"Total configuraciones evaluadas: {total_evals}")
    print(f"Coincidencia exacta (Z3 == FlattenedStateValidator): {match_percentage:.2f}%")
    print(f"Falsos Positivos: {df['False_Positives_AST'].astype(str).str.len().sum() > 0}")
    print(f"Falsos Negativos: {df['False_Negatives_AST'].astype(str).str.len().sum() > 0}\n")

    # 2. Gráfico de Dispersión: Escalabilidad Computacional (Escala Logarítmica)
    plt.figure(figsize=(8, 5))
    
    sns.scatterplot(data=df, x='N_Features', y='T_Z3_ms', color='red', marker='x', label='Z3 SMT Solver', alpha=0.7)
    sns.scatterplot(data=df, x='N_Features', y='T_AST_ms', color='blue', marker='o', label='FlattenedStateValidator', alpha=0.7)

    plt.yscale('log')
    plt.title('Execution Time Comparison: Z3 vs. Native Validator (Log Scale)', fontsize=12, fontweight='bold')
    plt.xlabel('Structural Complexity (Number of Features)', fontsize=11)
    plt.ylabel('Execution Time (ms)', fontsize=11)
    plt.legend(title='Validation Engine')
    plt.tight_layout()
    
    output_file = "Fig1_Performance_Comparison.pdf"
    plt.savefig(output_file, format='pdf', bbox_inches='tight')
    print(f"Gráfico guardado: {output_file}")
    plt.close()

if __name__ == "__main__":
    generate_performance_plots()