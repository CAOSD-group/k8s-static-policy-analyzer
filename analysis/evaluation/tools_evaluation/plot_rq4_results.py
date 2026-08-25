import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Configuración de estilo académico
sns.set_theme(style="whitegrid")
plt.rcParams.update({'font.size': 12, 'pdf.fonttype': 42})

INPUT_CSV = Path("../../../evaluation/rq4_divergence_and_latency.csv")
OUTPUT_DIR = Path("../../../evaluation/plots")

def generate_plots():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("[INFO] Cargando datos para graficar...")
    df = pd.read_csv(INPUT_CSV)
    
    # ---------------------------------------------------------
    # GRÁFICO 1: Comparativa de Latencia (Boxplot)
    # ---------------------------------------------------------
    print("[INFO] Generando Boxplot de Latencia...")
    plt.figure(figsize=(8, 6))
    
    # Preparamos los datos para Seaborn
    latency_data = pd.DataFrame({
        'State of the Practice\n(Trivy + Polaris + Kyverno)': df['SotP_Total_Time'],
        'Dual-Oracle Analyzer\n(AST + Z3)': df['KubeSec_Time']
    })
    
    # showfliers=False oculta los valores atípicos extremos para que la caja sea legible
    ax = sns.boxplot(data=latency_data, palette=["#FF9999", "#99CC99"], showfliers=False, width=0.5)
    plt.ylabel('Execution Time (ms)', fontweight='bold')
    plt.title('Execution Overhead: Industry Tools vs. Dual-Oracle', pad=20)
    
    # Guardar en PDF vectorial (ideal para LaTeX) y PNG
    plt.savefig(OUTPUT_DIR / 'rq4_latency_boxplot.pdf', bbox_inches='tight')
    plt.savefig(OUTPUT_DIR / 'rq4_latency_boxplot.png', dpi=300, bbox_inches='tight')
    plt.close()

    # ---------------------------------------------------------
    # GRÁFICO 2: Análisis de Divergencia (Bar Chart)
    # ---------------------------------------------------------
    print("[INFO] Generando Gráfico de Divergencia...")
    plt.figure(figsize=(7, 6))
    
    total_files = len(df)
    divergent = df['Has_Divergence'].sum()
    consensus = total_files - divergent
    
    categories = ['Industry Consensus', 'Industry Divergence (Blind Spots)']
    counts = [consensus, divergent]
    percentages = [c / total_files * 100 for c in counts]
    
    bars = plt.bar(categories, percentages, color=['#4C72B0', '#C44E52'], width=0.6)
    
    plt.ylabel('Percentage of Manifests (%)', fontweight='bold')
    plt.title('Security Assessment Consistency', pad=20)
    plt.ylim(0, 100)
    
    # Añadir las etiquetas con el número exacto encima de cada barra
    for bar, count in zip(bars, counts):
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 2, f'{yval:.1f}%\n(n={count})', ha='center', va='bottom', fontsize=10)

    plt.savefig(OUTPUT_DIR / 'rq4_divergence_barchart.pdf', bbox_inches='tight')
    plt.savefig(OUTPUT_DIR / 'rq4_divergence_barchart.png', dpi=300, bbox_inches='tight')
    plt.close()

    print(f"[OK] Gráficos exportados con éxito en: {OUTPUT_DIR}")

if __name__ == "__main__":
    generate_plots()