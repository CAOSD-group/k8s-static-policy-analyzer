import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

# Academic style configuration for COSE journal
sns.set_theme(style="whitegrid", context="paper")
plt.rcParams.update({
    'font.size': 11,
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'legend.fontsize': 10
})

CSV_PATH = "remediation_benchmark_results01_AST_Complete_V2.csv"

def generate_cose_analysis():
    if not os.path.exists(CSV_PATH):
        print(f"[CRITICAL] Evaluation dataset not found: {CSV_PATH}")
        return

    # Fail-Fast Ingestion: Gracefully skip structural anomalies (e.g., SCHEMA_ERROR)
    try:
        df = pd.read_csv(CSV_PATH, on_bad_lines='skip', engine='python')
    except Exception as e:
        print(f"[CRITICAL] Error parsing CSV contract: {e}")
        return

    # 1. DATA CLEANING & DOMAIN SEGREGATION
    # Isolate valid security evaluations from pure structural failures
    df_valid = df[~df['Policies_Evaluated'].isin(['SCHEMA_ERROR', 'ERROR_MAP'])].copy()

    # Cast critical analytical columns to strict numeric types
    numeric_cols = [
        'Total_Initial_Alerts', 'Security_Score', 'Risk_Deduction_Score',
        'Patch_Similarity_%', 'Comments_Retention_%',
        'T_Detection_ms', 'T_AST_Remed_ms', 'N_Features'
    ]
    for col in numeric_cols:
        df_valid[col] = pd.to_numeric(df_valid[col], errors='coerce')

    # Drop rows with corrupted core metrics
    df_valid = df_valid.dropna(subset=['Total_Initial_Alerts', 'Security_Score', 'Risk_Deduction_Score', 'N_Features'])
    print(f"[INFO] Total valid configurations ingested for empirical analysis: {len(df_valid)}")

    # ---------------------------------------------------------
    # PLOT 1: Structural Complexity vs. Pipeline Latency
    # (Evolution of ARES RQ3 applied to Dual-Oracle performance)
    # ---------------------------------------------------------
    plt.figure(figsize=(7, 5))
    
    # Categorize structural complexity into logical bins derived from feature counts
    df_valid['Complexity_Bin'] = pd.cut(
        df_valid['N_Features'],
        bins=[0, 15, 30, 50, np.inf],
        labels=['Low\n(0-15)', 'Medium\n(16-30)', 'High\n(31-50)', 'Extreme\n(50+)']
    )
    
    latency_df = df_valid.groupby('Complexity_Bin', observed=True)[['T_Detection_ms', 'T_AST_Remed_ms']].mean().reset_index()
    
    # Stacked bar chart demonstrating O(1) stability in the remediation phase
    plt.bar(latency_df['Complexity_Bin'], latency_df['T_Detection_ms'], color='#4c72b0', label='Detection Phase (ms)')
    plt.bar(
        latency_df['Complexity_Bin'], latency_df['T_AST_Remed_ms'],
        bottom=latency_df['T_Detection_ms'], color='#dd8452', label='Remediation Phase (ms)'
    )

    plt.title('End-to-End Pipeline Latency by Structural Complexity', fontweight='bold')
    plt.xlabel('Structural Complexity (Total Declared Features)')
    plt.ylabel('Average Execution Latency (ms)')
    plt.legend(loc='upper left')
    plt.tight_layout()
    plt.savefig("Fig1_Complexity_vs_Latency02.pdf", format='pdf', bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Generated Fig1_Complexity_vs_Latency02.pdf")

    # ---------------------------------------------------------
    # PLOT 2: The Risk Dilution Effect
    # (Evolution of ARES RQ4: Proportional vs Additive Risk Scoring)
    # ---------------------------------------------------------
    plt.figure(figsize=(7, 5))
    
    # Group by the number of initial alerts to map the divergence in scoring models
    trend_df = df_valid.groupby('Total_Initial_Alerts')[['Security_Score', 'Risk_Deduction_Score']].mean().reset_index()
    
    sns.lineplot(
        data=trend_df, x='Total_Initial_Alerts', y='Security_Score',
        marker='o', color='darkblue', label='Proportional Security Score', linestyle='--'
    )
    sns.lineplot(
        data=trend_df, x='Total_Initial_Alerts', y='Risk_Deduction_Score',
        marker='s', color='darkred', label='Additive Risk Deduction Score'
    )

    plt.title('The Risk Dilution Effect: Proportional vs. Additive Models', fontweight='bold')
    plt.xlabel('Total Security Violations Detected')
    plt.ylabel('Evaluated Security Posture (0-100)')
    plt.legend(loc='lower left')
    plt.tight_layout()
    plt.savefig("Fig2_Risk_Dilution02.pdf", format='pdf', bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Generated Fig2_Risk_Dilution02.pdf")

    # ---------------------------------------------------------
    # PLOT 3: Semantic Preservation & Principle of Minimal Change
    # (Novel contribution validating Context-Aware Remediation)
    # ---------------------------------------------------------
    plt.figure(figsize=(6, 5))
    
    # Filter configurations where active dynamic patching occurred
    df_preservation = df_valid[(df_valid['Patch_Similarity_%'] > 0)][['Patch_Similarity_%', 'Comments_Retention_%']].dropna()
    
    # Melt dataframe for seaborn categorical plotting
    df_melted = df_preservation.melt(var_name='Metric', value_name='Percentage (%)')
    
    #sns.violinplot(data=df_melted, x='Metric', y='Percentage (%)', inner="quartile", palette="Set2")
    
    sns.violinplot(
        data=df_melted, x='Metric',y='Percentage (%)', hue='Metric', legend=False, inner="quartile", palette="Set2"
    )
    
    plt.title('Semantic Integrity During Automated Remediation', fontweight='bold')
    plt.ylabel('Preservation Ratio (%)')
    plt.xlabel('')
    plt.xticks([0, 1], ['Structural Similarity', 'Comments Retention'])
    plt.ylim(0, 105)
    plt.tight_layout()
    plt.savefig("Fig3_Semantic_Preservation02.pdf", format='pdf', bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Generated Fig3_Semantic_Preservation02.pdf")

if __name__ == "__main__":
    generate_cose_analysis()