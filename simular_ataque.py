import time
import sys
from scapy.all import IP, TCP, Raw, send

# Destino local padrão para testes internos seguros
ip_alvo = "127.0.0.1" 

def simular_brute_force():
    print(f"\n[*] Disparando 6 tentativas de Força Bruta contra {ip_alvo} na Porta 80...")
    for i in range(6):
        payload = f"POST /login HTTP/1.1\r\nHost: {ip_alvo}\r\nContent-Length: 35\r\n\r\nuser=admin&password=SenhaIncorreta{i}".encode()
        pacote = IP(dst=ip_alvo) / TCP(dport=80, sport=55000+i) / Raw(load=payload)
        send(pacote, verbose=False)
        time.sleep(0.1)
    print("[+] Simulação de Força Bruta enviada.")

def simular_overflow():
    print(f"\n[*] Disparando carga maliciosa de Buffer Overflow (3050 bytes) contra {ip_alvo}...")
    payload_malicioso = b"GET / " + b"A" * 3000 + b"\x90" * 50
    pacote = IP(dst=ip_alvo) / TCP(dport=80, sport=54321) / Raw(load=payload_malicioso)
    send(pacote, verbose=False)
    print("[+] Payload de Overflow enviado.")

if __name__ == "__main__":
    print("="*60)
    print("           Simulador de Ataques e Vetores - pySOC")
    print("="*60)
    
    simular_brute_force()
    time.sleep(1.5)
    simular_overflow()
    
    print("\n[+] Todos os testes foram injetados. Monitore seu app do Streamlit!")