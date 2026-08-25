import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

# Academic style configuration for COSE journal
sns.set_theme(style="whitegrid", context="paper")
plt.rcParams.update({'font.size': 11, 'pdf.fonttype': 42, 'ps.fonttype': 42})

CSV_PATH = "remediation_benchmark_results01_AST_Complete_V2.csv"  # Ensure this matches your local file

def generate_remediation_analysis():
    if not os.path.exists(CSV_PATH):
        print(f"[ERROR] File not found: {CSV_PATH}")
        return

    # Fail-Fast Ingestion: Skip malformed lines automatically
    try:
        df = pd.read_csv(CSV_PATH, on_bad_lines='skip', engine='python')
    except Exception as e:
        print(f"[CRITICAL] Error reading CSV: {e}")
        return

    # 1. DATA CLEANING & DOMAIN SEGREGATION
    # Filter out structural failures (SCHEMA_ERROR, ERROR_MAP) to isolate security logic performance
    df_valid = df[~df['Policies_Evaluated'].isin(['SCHEMA_ERROR', 'ERROR_MAP'])].copy()

    # Ensure critical columns are strictly numeric
    numeric_cols = [
        'Total_Initial_Alerts', 'Security_Score', 'Risk_Deduction_Score',
        'Patch_Similarity_%', 'Comments_Retention_%',
        'T_Detection_ms', 'T_AST_Remed_ms', 'N_Features'
    ]
    for col in numeric_cols:
        df_valid[col] = pd.to_numeric(df_valid[col], errors='coerce')

    # Drop any remaining rows with NaN in essential score metrics
    df_valid = df_valid.dropna(subset=['Total_Initial_Alerts', 'Security_Score', 'Risk_Deduction_Score'])

    print(f"Total valid configurations for analysis: {len(df_valid)}")

    # ---------------------------------------------------------
    # PLOT 1: The Risk Dilution Effect (Line Plot)
    # ---------------------------------------------------------
    plt.figure(figsize=(7, 5))
    
    # Group by the number of initial alerts to calculate the mean scores
    trend_df = df_valid.groupby('Total_Initial_Alerts')[['Security_Score', 'Risk_Deduction_Score']].mean().reset_index()
    
    sns.lineplot(
        data=trend_df, x='Total_Initial_Alerts', y='Security_Score',
        marker='o', color='gray', label='Proportional Security Score', linestyle='--'
    )
    sns.lineplot(
        data=trend_df, x='Total_Initial_Alerts', y='Risk_Deduction_Score',
        marker='s', color='darkred', label='Additive Risk Deduction Score'
    )

    plt.title('The Risk Dilution Effect: Proportional vs. Additive Scoring', fontweight='bold')
    plt.xlabel('Total Security Violations Detected')
    plt.ylabel('Evaluated Security Posture (0-100)')
    plt.legend(loc='lower left')
    plt.tight_layout()
    plt.savefig("Fig2_Risk_Dilution.pdf", format='pdf', bbox_inches='tight')
    plt.close()

    # ---------------------------------------------------------
    # PLOT 2: Semantic Preservation (Violin Plot)
    # ---------------------------------------------------------
    plt.figure(figsize=(6, 5))
    
    # Filter only configurations where remediation took place (Rem_Alerts > 0 or Patch_Similarity > 0)
    df_preservation = df_valid[(df_valid['Patch_Similarity_%'] > 0)][['Patch_Similarity_%', 'Comments_Retention_%']].dropna()
    
    # Melt dataframe for Seaborn categorical plotting
    df_melted = df_preservation.melt(var_name='Metric', value_name='Percentage (%)')
    
    sns.violinplot(data=df_melted, x='Metric', y='Percentage (%)', inner="quartile", palette="Set2")
    
    plt.title('Semantic Preservation During Automated Remediation', fontweight='bold')
    plt.ylabel('Preservation (%)')
    plt.xlabel('')
    plt.xticks([0, 1], ['Structural Similarity', 'Comments Retention'])
    plt.ylim(0, 105)
    plt.tight_layout()
    plt.savefig("Fig3_Semantic_Preservation.pdf", format='pdf', bbox_inches='tight')
    plt.close()

    # ---------------------------------------------------------
    # PLOT 3: Dual-Oracle Pipeline Latency (Stacked Bar Chart)
    # ---------------------------------------------------------
    plt.figure(figsize=(7, 5))
    
    # Categorize structural complexity into logical bins
    df_valid['Complexity_Bin'] = pd.cut(
        df_valid['N_Features'],
        bins=[0, 15, 30, 50, np.inf],
        labels=['Low (0-15)', 'Medium (16-30)', 'High (31-50)', 'Extreme (50+)']
    )
    
    # Calculate mean latencies per bin
    latency_df = df_valid.groupby('Complexity_Bin', observed=True)[['T_Detection_ms', 'T_AST_Remed_ms']].mean().reset_index()
    
    # Plotting stacked bars
    plt.bar(latency_df['Complexity_Bin'], latency_df['T_Detection_ms'], color='#4c72b0', label='Detection Phase (ms)')
    plt.bar(
        latency_df['Complexity_Bin'], latency_df['T_AST_Remed_ms'],
        bottom=latency_df['T_Detection_ms'], color='#dd8452', label='Remediation Phase (ms)'
    )

    plt.title('End-to-End Pipeline Latency by Structural Complexity', fontweight='bold')
    plt.xlabel('Structural Complexity (Features)')
    plt.ylabel('Average Latency (ms)')
    plt.legend(loc='upper left')
    plt.tight_layout()
    plt.savefig("Fig4_Pipeline_Latency.pdf", format='pdf', bbox_inches='tight')
    plt.close()

    print("[SUCCESS] All evaluation figures have been generated and saved as PDFs.")

if __name__ == "__main__":
    generate_remediation_analysis()