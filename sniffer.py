import time
import os
import pandas as pd
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ARP, Raw

# --- ARQUIVO DE LOGS ---
LOG_FILE = "alerts_log.csv"

# --- MEMÓRIA DO SOC / RASTREAMENTO EM TEMPO REAL ---
trafego_ips = {}          # DDoS: {IP: [timestamp_inicial, contador_pacotes]}
varredura_portas = {}     # Port Scan: {IP: set(portas_tentadas)}
tentativas_bruteforce = {} # Brute Force: {IP: [timestamp_inicial, contador_tentativas]}
contador_protocolos = Counter()

# --- THRESHOLDS (LIMITES DE DETECÇÃO) ---
LIMITE_DDOS_PACOTES = 80
INTERVALO_DDOS_TEMPO = 1.0
LIMITE_BUFFER_OVERFLOW = 3000
LIMITE_PORT_SCAN = 15
LIMITE_BRUTE_FORCE = 5     
INTERVALO_BRUTE_FORCE = 5.0 
PALAVRAS_CHAVE_CREDENCIAIS = [b"password", b"passwd", b"senha", b"user", b"username", b"login"]

def registrar_alerta(tipo, origem, descricao):
    """Salva o alerta imediatamente no arquivo CSV para o Streamlit ler"""
    novo_alerta = {
        "Horário": time.strftime("%H:%M:%S"),
        "Tipo": tipo,
        "Origem": origem,
        "Descrição": descricao
    }
    df = pd.DataFrame([novo_alerta])
    # Se o arquivo não existir, cria com cabeçalho. Se existir, apenas adiciona no final (append)
    if not os.path.exists(LOG_FILE):
        df.to_csv(LOG_FILE, index=False)
    else:
        df.to_csv(LOG_FILE, mode='a', header=False, index=False)

def analisar_pacote(pacote):
    global contador_protocolos, tentativas_bruteforce

    # 1. CONTADOR DE PROTOCOLOS
    if pacote.haslayer(ARP):
        contador_protocolos['ARP'] += 1
    elif pacote.haslayer(IP):
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst

        if pacote.haslayer(TCP):
            p_sport, p_dport = pacote[TCP].sport, pacote[TCP].dport
            if p_sport == 443 or p_dport == 443:
                contador_protocolos['HTTPS (Criptografado)'] += 1
            elif p_sport == 80 or p_dport == 80:
                contador_protocolos['HTTP (Não Seguro)'] += 1
            else:
                contador_protocolos['Outros TCP'] += 1

            # 2. DETECÇÃO DE PORT SCAN
            if ip_origem not in varredura_portas:
                varredura_portas[ip_origem] = set()
            varredura_portas[ip_origem].add(p_dport)

            if len(varredura_portas[ip_origem]) > LIMITE_PORT_SCAN:
                registrar_alerta("🔍 PORT SCAN", ip_origem, f"Varredura detectada. {len(varredura_portas[ip_origem])} portas visadas.")
                varredura_portas[ip_origem] = set()

        elif pacote.haslayer(UDP):
            p_sport, p_dport = pacote[UDP].sport, pacote[UDP].dport
            if p_sport == 53 or p_dport == 53:
                contador_protocolos['DNS (Resolução de Nome)'] += 1
            else:
                contador_protocolos['Outros UDP'] += 1
        else:
            contador_protocolos['Outros IP'] += 1

        # 3. DETECÇÃO DE DDOS FLOOD
        tempo_atual = time.time()
        if ip_origem not in trafego_ips:
            trafego_ips[ip_origem] = [tempo_atual, 1]
        else:
            tempo_inicial, total_pacotes = trafego_ips[ip_origem]
            if tempo_atual - tempo_inicial <= INTERVALO_DDOS_TEMPO:
                trafego_ips[ip_origem][1] += 1
                if trafego_ips[ip_origem][1] == LIMITE_DDOS_PACOTES: # Dispara uma vez por rajada
                    registrar_alerta("🚨 DDOS FLOOD", ip_origem, "Rajada de flood ativa detectada em alta frequência.")
            else:
                trafego_ips[ip_origem] = [tempo_atual, 1]

        # 4. DEEP PACKET INSPECTION (OVERFLOW E FORÇA BRUTA)
        if pacote.haslayer(Raw):
            payload = pacote[Raw].load
            tamanho_payload = len(payload)

            # A. Buffer Overflow
            if tamanho_payload > LIMITE_BUFFER_OVERFLOW:
                if b'A' * 50 in payload or b'\x90' * 10 in payload:
                    registrar_alerta("🔥 EXPLOIT OVERFLOW", ip_origem, f"Assinatura maliciosa. Tamanho payload: {tamanho_payload} bytes.")

            # B. Credenciais & Brute Force (Foco na Porta HTTP 80)
            if pacote.haslayer(TCP) and (pacote[TCP].dport == 80 or pacote[TCP].sport == 80):
                payload_minusculo = payload.lower()
                contem_credencial = any(palavra in payload_minusculo for palavra in PALAVRAS_CHAVE_CREDENCIAIS)
                
                if contem_credencial:
                    if ip_origem not in tentativas_bruteforce:
                        tentativas_bruteforce[ip_origem] = [tempo_atual, 1]
                    else:
                        tempo_ini_bf, qtd_bf = tentativas_bruteforce[ip_origem]
                        if tempo_atual - tempo_ini_bf <= INTERVALO_BRUTE_FORCE:
                            tentativas_bruteforce[ip_origem][1] += 1
                            total_tentativas = tentativas_bruteforce[ip_origem][1]
                            
                            if total_tentativas == LIMITE_BRUTE_FORCE:
                                registrar_alerta("🔨 BRUTE FORCE DETECTED", ip_origem, f"Ataque de força bruta: {total_tentativas} requisições de login seguidas.")
                                tentativas_bruteforce[ip_origem] = [tempo_atual, 0] # Reseta janela
                        else:
                            tentativas_bruteforce[ip_origem] = [tempo_atual, 1]

                    # Alerta base de credencial trafegando exposta
                    registrar_alerta("🔓 CREDENCIAL HTTP", ip_origem, "Dados de autenticação trafegando sem criptografia.")

    # Exibição básica inline no terminal de execução do sniffer
    resumo = " | ".join([f"{k}: {v}" for k, v in contador_protocolos.items()])
    print(f"[PAINEL PRINCIPAL] {resumo}", end="\r")

def iniciar_sniffer():
    print("="*70)
    print("        pySOC-IDS v1.2 - Monitoramento Ativo (Ambiente Pop!_OS)")
    print("="*70)
    # Limpa logs antigos ao iniciar uma nova sessão do sniffer para evitar lixo de sessões anteriores
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        
    # Importante: Escutando a interface local 'lo' (localhost) para capturar o simulador
    sniff(iface="lo", prn=analisar_pacote, store=0)

if __name__ == "__main__":
    iniciar_sniffer()