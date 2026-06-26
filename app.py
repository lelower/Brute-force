import streamlit as st
import pandas as pd
import time
import os

st.set_page_config(page_title="pySOC - Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ pySOC - Monitoramento de Rede em Tempo Real")
st.markdown("Análise de tráfego e telemetria de ataques rodando nativamente no Linux.")

LOG_FILE = "alerts_log.csv"

# Inicializar contadores padrões
total_ddos, total_portscan, total_overflow, total_brute = 0, 0, 0, 0
df_alertas = pd.DataFrame(columns=["Horário", "Tipo", "Origem", "Descrição"])

# Carregar alertas direto do log em disco gerado pelo sniffer
if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
    try:
        df_alertas = pd.read_csv(LOG_FILE)
        # Inverte a ordem para exibir os alertas mais recentes no topo do painel
        df_alertas = df_alertas.iloc[::-1]
        
        # Filtragem de métricas via Pandas
        total_ddos = df_alertas[df_alertas['Tipo'].str.contains('DDOS', na=False)].shape[0]
        total_portscan = df_alertas[df_alertas['Tipo'].str.contains('PORT', na=False)].shape[0]
        total_overflow = df_alertas[df_alertas['Tipo'].str.contains('OVERFLOW', na=False)].shape[0]
        total_brute = df_alertas[df_alertas['Tipo'].str.contains('BRUTE', na=False)].shape[0]
    except Exception:
        pass

# --- METRIC CARDS ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric(label="🚨 Alertas de DDoS", value=total_ddos) 
with col2:
    st.metric(label="🔍 Port Scans Detectados", value=total_portscan)
with col3:
    st.metric(label="⚠️ Buffer Overflows", value=total_overflow)
with col4:
    st.metric(label="🔨 Tentativas de Força Bruta", value=total_brute)

# --- TABELA PRINCIPAL DO SOC ---
st.subheader("📋 Histórico Global de Alertas (Live SOC Feed)")
if not df_alertas.empty:
    st.dataframe(df_alertas, use_container_width=True)
else:
    st.success("Nenhuma anomalia ou ataque detectado na rede até o momento. Sistema operando em nível seguro.")

# Auto-refresh do Streamlit a cada 1 segundo para atualizar as métricas
time.sleep(1)
st.rerun()