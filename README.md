# 🛡️ pySOC - Brute Force Detection IDS

Um Sistema de Detecção de Intrusão (IDS) em tempo real voltado para a análise de tráfego de rede e mitigação de ataques de **Força Bruta (Brute Force)** na camada HTTP. O projeto conta com um motor de captura baseado em sockets brutos com Scapy e um painel visual dinâmico desenvolvido em Streamlit.

---

## 🚀 Funcionalidades

* **Deep Packet Inspection (DPI):** Inspeção minuciosa de payloads HTTP em busca de dados de autenticação expostos.
* **Detecção de Brute Force:** Algoritmo baseado em janelas de tempo que identifica múltiplos acessos sequenciais inválidos vindos da mesma origem.
* **Live SOC Feed:** Dashboard interativo que atualiza em tempo real sem a necessidade de banco de dados físico (processamento direto em memória).

---

## 🛠️ Arquitetura do Projeto

* `sniffer.py`: O motor do IDS responsável por colocar a interface de rede em modo de escuta e aplicar as regras de correlação de eventos.
* `app.py`: Painel gráfico em Streamlit que consome a telemetria gerada pelo sniffer.
* `simular_ataque.py`: Script automatizado para injeção de pacotes maliciosos na interface local para validação das regras do SOC.

---

## ⚙️ Como Executar (Ambiente Linux / Pop!_OS)

### 1. Clonar o repositório e configurar o Ambiente Virtual
```bash
git clone [https://github.com/lelower/Brute-force.git](https://github.com/lelower/Brute-force.git)
cd Brute-force
python3 -m venv venv
source venv/bin/activate
pip install scapy streamlit pandas,